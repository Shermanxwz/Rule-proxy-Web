"""Pure DNS byte and fake-owned-resource cases; no network or resolver calls."""
import importlib.util
from pathlib import Path
import socket
import struct
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_fixture_test',ROOT/'.github/windows_dns_fixture.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
NONCE='a'*32
NAME=f.query_name(NONCE)
def query(*,edns=False,name=NAME,flags=0x100):
    q=b''.join(bytes((len(label),))+label.encode() for label in name.split('.'))+b'\0\0\1\0\1'
    return struct.pack('!6H',123,flags,1,0,0,int(edns))+q+(b'\0'+struct.pack('!HHIH',41,1232,0,0) if edns else b'')
class ParserTests(unittest.TestCase):
    def test_exact_nonce_a_answer_transaction_question_and_ttl(self):
        for edns in (False,True):
            q=query(edns=edns);r=f.answer_query(q,NAME)
            self.assertEqual(struct.unpack('!6H',r[:12]),(123,0x8500,1,1,0,int(edns)))
            if edns:
                self.assertEqual(r[-11:],b'\0'+struct.pack('!HHIH',41,1232,0,0))
                r=r[:-11]
            self.assertEqual(r[-16:],b'\xc0\x0c'+struct.pack('!HHIH',1,1,0,4)+bytes((192,0,2,123)))
            self.assertEqual(r[12:-16],query()[12:])
    def test_name_case_is_dns_case_insensitive_but_nonce_exact(self):
        self.assertTrue(f.answer_query(query(name=NAME.upper()),NAME))
        with self.assertRaises(ValueError):f.answer_query(query(name='b'*32+'.n0a.invalid'),NAME)
    def test_malformed_header_compression_bounds_and_trailing(self):
        raw=query()
        cases=[b'',raw[:11],raw+b'X',b'x'*1233,raw[:12]+b'\xc0\x0c'+raw[-4:]]
        for flags in (0x8000,0x200,0x400,0x800,1,0x40):cases.append(query(flags=flags))
        for field in (2,3,4,5):
            fields=[123,0x100,1,0,0,0];fields[field]=2;cases.append(struct.pack('!6H',*fields)+raw[12:])
        for value in cases:
            with self.subTest(size=len(value)),self.assertRaises(ValueError):f.answer_query(value,NAME)
    def test_edns_unknown_options_version_and_extended_rcode_rejected(self):
        base=query(edns=True)[:-11]
        for opt in [b'\xc0\x0c'+struct.pack('!HHIH',41,1232,0,0),b'\0'+struct.pack('!HHIH',41,1232,0x10000,0),
                    b'\0'+struct.pack('!HHIH',41,1232,0x1000000,0),b'\0'+struct.pack('!HHIH',41,1232,0,4)+b'\0'*4,
                    b'\0'+struct.pack('!HHIH',41,511,0,0)]:
            with self.assertRaises(ValueError):f.answer_query(base+opt,NAME)
        self.assertTrue(f.answer_query(base+b'\0'+struct.pack('!HHIH',41,4096,0x8000,0),NAME))
    def test_only_a_in_not_other_question(self):
        for value in [query()[:-4]+b'\0\x1c\0\1',query()[:-4]+b'\0\1\0\3']:
            with self.assertRaises(ValueError):f.answer_query(value,NAME)
class FakeSocket:
    def __init__(self,owner,events,send_error=False):self.owner=owner;self.events=list(events);self.sent=[];self.send_error=send_error;self.closed=False
    def recvfrom(self,size):
        if not self.events:self.owner.stop.set();raise OSError('fixture end')
        value=self.events.pop(0)
        if isinstance(value,BaseException):raise value
        return value,('127.0.0.1',45000)
    def sendto(self,data,peer):
        if self.send_error:raise OSError('PRIVATE_SENTINEL')
        self.sent.append(data);return len(data)
    def settimeout(self,value):pass
    def close(self):self.closed=True
    def fileno(self):return -1 if self.closed else 7
class LifecycleTests(unittest.TestCase):
    def fixture(self,mode='answer'):
        with patch.object(f.time,'monotonic',return_value=0):return f.DnsFixture.for_test(NONCE,deadline=60,mode=mode)
    def serve(self,events,mode='answer',send_error=False):
        o=self.fixture(mode);o.socket=FakeSocket(o,events,send_error)
        with patch.object(f.time,'monotonic',return_value=1):o._serve()
        return o
    def test_idle_timeout_not_count_and_all_datagrams_count(self):
        o=self.serve([socket.timeout(),b'',b'x'*1233,query()])
        self.assertEqual(o.counts['datagrams'],3);self.assertEqual(o.counts['rejected'],1)
        self.assertEqual(o.counts['oversized'],1);self.assertEqual(o.counts['matched_queries'],1)
        self.assertEqual(o.counts['answers_sent'],1)
    def test_cap_stops_no_unbounded_receive(self):
        o=self.serve([b'']*40)
        self.assertEqual(o.counts['datagrams'],32);self.assertEqual(o.error,'bound');self.assertEqual(len(o.socket.events),8)
    def test_query_observation_sticky_on_send_failure_drop_wrong_answer_rcode(self):
        for mode in ('answer','drop','wrong_address','rcode'):
            o=self.serve([query()],mode,send_error=mode=='answer')
            self.assertEqual(o.counts['matched_queries'],1)
            if mode=='drop':self.assertEqual(o.counts['answers_sent'],0)
            if mode=='wrong_address':self.assertEqual(o.socket.sent[0][-4:],bytes((192,0,2,124)))
            if mode=='rcode':self.assertEqual(struct.unpack('!6H',o.socket.sent[0][:12])[3],0);self.assertEqual(o.socket.sent[0][3]&15,3)
            if mode=='answer':self.assertEqual(o.error,'send');self.assertEqual(o.counts['send_failed'],1)
    def test_windows_oversize_is_counted_not_parsed(self):
        error=OSError('PRIVATE');error.winerror=10040
        o=self.serve([error,query()]);self.assertEqual(o.counts['datagrams'],2);self.assertEqual(o.counts['oversized'],1)
    def test_finish_absolute_no_renewal_unknown_thread_counts_unavailable(self):
        o=self.fixture();o.socket=Mock();o.socket.fileno.return_value=-1;o.thread=Mock();o.thread.is_alive.return_value=True
        with patch.object(f.time,'monotonic',return_value=59):result=o.finish(deadline=100)
        o.thread.join.assert_called_once_with(1)
        self.assertFalse(result['cleanup_confirmed']);self.assertIsNone(result['counts']);self.assertFalse(result['broker_cancellation_proven'])
    def test_close_uncertainty_sticky_and_raw_not_exported(self):
        o=self.fixture();o.socket=Mock();o.socket.close.side_effect=[OSError('PRIVATE'),None];o.socket.fileno.return_value=-1
        with patch.object(f.time,'monotonic',return_value=1):
            first=o.finish(deadline=50);second=o.finish(deadline=50)
        self.assertFalse(first['cleanup_confirmed']);self.assertFalse(second['cleanup_confirmed'])
        self.assertNotIn('PRIVATE',str(first));self.assertNotIn(NONCE,str(first))
    def test_start_registers_before_bind_and_thread_failure(self):
        o=self.fixture();sock=Mock();sock.getsockname.return_value=('127.0.0.1',50000);sock.fileno.return_value=-1
        thread=Mock();thread.start.side_effect=RuntimeError('PRIVATE');thread.join.side_effect=RuntimeError('not started');thread.is_alive.return_value=False
        with patch.object(f.socket,'socket',return_value=sock),patch.object(f.threading,'Thread',return_value=thread):
            with self.assertRaises(RuntimeError):o.start()
        self.assertIs(o.socket,sock);self.assertIs(o.thread,thread);sock.bind.assert_called_once_with(('127.0.0.1',0))
        with patch.object(f.time,'monotonic',return_value=1):self.assertTrue(o.finish(deadline=50)['cleanup_confirmed'])
if __name__=='__main__':unittest.main()
