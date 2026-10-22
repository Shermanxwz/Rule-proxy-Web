"""Fake socket/thread/clock only; never binds or sends a real DNS packet."""
import importlib.util
from pathlib import Path
import socket
import struct
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_cases_fixture_pure',ROOT/'.github/windows_identity_dns_cases_fixture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
NONCES={'before':'1'*32,'selected':'2'*32,'after':'3'*32}
PEER=('127.0.0.1',51001)


def query(case='selected',*,name=None,edns=False):
    name=name or NONCES[case]+'.n0a.invalid'
    question=b''.join(bytes((len(label),))+label.encode('ascii') for label in name.split('.'))+b'\0\0\1\0\1'
    return struct.pack('!6H',7,0x100,1,0,0,int(edns))+question+(b'\0'+struct.pack('!HHIH',41,1232,0x8000,0) if edns else b'')


class Clock:
    def __init__(self):self.now=0
    def __call__(self):return self.now


class FakeSocket:
    def __init__(self,owner,clock,events,*,send_error=None,close_error=False,fileno_error=False,short_send=False,
                 on_receive=None,on_send=None,bind_error=False,exclusive=1):
        self.owner=owner;self.clock=clock;self.events=list(events);self.send_error=send_error
        self.close_error=close_error;self.fileno_error=fileno_error;self.short_send=short_send
        self.on_receive=on_receive;self.on_send=on_send;self.bind_error=bind_error;self.exclusive=exclusive
        self.options=[];self.bound=[];self.timeouts=[];self.received_sizes=[];self.sent=[];self.close_calls=0;self.closed=False
    def setsockopt(self,*args):self.options.append(args)
    def getsockopt(self,*args):return self.exclusive
    def bind(self,address):
        self.bound.append(address)
        if self.bind_error:raise OSError('fake bind failure')
    def getsockname(self):return ('127.0.0.1',53)
    def settimeout(self,value):self.timeouts.append(value)
    def recvfrom(self,size):
        self.received_sizes.append(size)
        if not self.events:self.owner.stop.set();raise OSError('fake stopped')
        value=self.events.pop(0)
        if self.on_receive:self.on_receive(self.owner,self.clock)
        if isinstance(value,Exception):raise value
        return value
    def sendto(self,data,peer):
        # This observer is independent of counters/answer parsing.
        if self.on_send:self.on_send(self.owner,self.clock)
        if self.send_error:raise self.send_error
        self.sent.append((data,peer))
        return len(data)-1 if self.short_send else len(data)
    def close(self):
        self.close_calls+=1
        if self.close_error:raise OSError('fake close failure')
        self.closed=True
    def fileno(self):
        if self.fileno_error:raise OSError('fake close readback failure')
        return -1 if self.closed else 123


class FakeThread:
    def __init__(self,target,*,daemon,mode='run',join_error=False):
        self.target=target;self.daemon=daemon;self.mode=mode;self.join_error=join_error;self.joins=[];self.alive=False
    def start(self):
        if self.mode=='start-error':raise RuntimeError('fake start unknown')
        if self.mode=='alive':self.alive=True;self.target.__self__.ready.set();return
        self.target()
    def join(self,seconds):
        self.joins.append(seconds)
        if self.join_error:raise RuntimeError('fake join unknown')
    def is_alive(self):return self.alive


class DnsCasesFixtureTests(unittest.TestCase):
    def make(self,events=(),*,clock=None,thread_mode='run',join_error=False,**socket_options):
        clock=clock or Clock();owned={}
        def socket_factory(family,kind):
            self.assertEqual((family,kind),(socket.AF_INET,socket.SOCK_DGRAM))
            owned['socket']=FakeSocket(owned['fixture'],clock,events,**socket_options);return owned['socket']
        def thread_factory(*,target,daemon):
            owned['thread']=FakeThread(target,daemon=daemon,mode=thread_mode,join_error=join_error);return owned['thread']
        fixture=m.DnsCasesFixture(dict(NONCES),deadline=60,socket_factory=socket_factory,thread_factory=thread_factory,clock=clock)
        owned['fixture']=fixture
        return fixture,owned,clock

    def test_constructor_exact_three_distinct_fresh_names_and_original_deadline(self):
        for value in ({},dict(NONCES,unknown='4'*32),dict(NONCES,after=NONCES['before']),dict(NONCES,selected='G'*32),list(NONCES)):
            with self.subTest(value=value),self.assertRaises(ValueError):m.DnsCasesFixture(value,deadline=60,clock=lambda:0)
        for deadline in (True,0,-1,121,float('nan'),float('inf')):
            with self.subTest(deadline=deadline),self.assertRaises(ValueError):m.DnsCasesFixture(NONCES,deadline=deadline,clock=lambda:0)
        fixture,_,_=self.make();self.assertEqual(fixture.names,{key:value+'.n0a.invalid' for key,value in NONCES.items()})
        self.assertEqual((fixture.bind_address,fixture.bind_port,fixture.allowed_peers),('127.0.0.1',53,('127.0.0.1',)))
        with self.assertRaises(AttributeError):fixture.deadline=120

    def test_one_exclusive_socket_three_independent_answers_and_no_default_change(self):
        fixture,owned,_=self.make([(query(key,edns=key=='selected'),PEER) for key in m.CASES])
        self.assertEqual(fixture.start(),53);snapshot=fixture.snapshot(deadline=59)
        self.assertEqual(snapshot['counts'],dict(datagrams=3,bytes=sum(len(query(key,edns=key=='selected')) for key in m.CASES),
            matched_queries=3,answers_sent=3,rejected=0,oversized=0,send_failed=0))
        for key in m.CASES:
            self.assertEqual(snapshot['cases'][key],dict(matched_queries=1,answers_sent=1,rejected=0,send_failed=0))
            self.assertTrue(snapshot['case_query_observed'][key])
        self.assertTrue(snapshot['selected_query_observed'])
        sock=owned['socket'];self.assertEqual(sock.bound,[('127.0.0.1',53)])
        self.assertEqual(sock.options,[(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)])
        self.assertTrue(all(size==m.MAX_DATAGRAM+1 for size in sock.received_sizes))
        for (raw,_),key in zip(sock.sent,m.CASES):self.assertEqual(raw,m.parser.answer_query(query(key,edns=key=='selected'),fixture.names[key]))
        report=fixture.finish(deadline=60);self.assertTrue(report['cleanup_confirmed']);self.assertEqual(sock.close_calls,1)
        self.assertTrue(report['byte_count_is_observed_lower_bound']);self.assertFalse(report['broker_cancellation_proven'])
        with self.assertRaises(ValueError):fixture.start()

    def test_unknown_malformed_peer_and_non_a_questions_rejected_once_only(self):
        bad_type=query()[:-4]+b'\0\x1c\0\1'
        values=[(query(name='4'*32+'.n0a.invalid'),PEER),(b'broken',PEER),(bad_type,PEER),
                (query(),('127.0.0.2',51001)),(query(),('127.0.0.1',True)),(query(),('127.0.0.1',0))]
        fixture,owned,_=self.make(values);fixture.start();report=fixture.finish(deadline=60)
        self.assertEqual(report['counts']['rejected'],len(values));self.assertEqual(report['counts']['matched_queries'],0)
        self.assertEqual(owned['socket'].sent,[])
        for key in m.CASES:
            self.assertEqual(report['cases'][key],dict.fromkeys(m.CASE_COUNT_KEYS,0));self.assertFalse(report['case_query_observed'][key])

    def test_edns_malformed_and_compression_use_original_strict_parser(self):
        base=query();bad_opt=base[:10]+b'\0\1'+base[12:]+b'\0'+struct.pack('!HHIH',41,1232,0x10000,0)
        compressed=base[:12]+b'\xc0\x0c'+base[-4:]
        fixture,_,_=self.make([(bad_opt,PEER),(compressed,PEER),(query(edns=True),PEER)])
        fixture.start();report=fixture.finish(deadline=60)
        self.assertEqual((report['counts']['matched_queries'],report['counts']['rejected']),(1,2))
        self.assertEqual(report['cases']['selected']['answers_sent'],1)

    def test_selected_event_is_set_before_send_and_survives_send_failure(self):
        seen=[]
        def on_send(owner,clock):seen.append(owner.case_query_observed['selected'].is_set())
        for error,short in ((OSError('fake send'),False),(None,True)):
            fixture,owned,_=self.make([(query(),PEER)],send_error=error,short_send=short,on_send=on_send)
            fixture.start();report=fixture.finish(deadline=60)
            self.assertTrue(report['selected_query_observed']);self.assertEqual(report['error'],'send')
            self.assertEqual(report['cases']['selected'],dict(matched_queries=1,answers_sent=0,rejected=0,send_failed=1))
            self.assertEqual(report['counts']['send_failed'],1)
        self.assertEqual(seen,[True,True])

    def test_selected_event_survives_unexpected_thread_operation_exception(self):
        def on_send(owner,clock):raise RuntimeError('fake operation failure')
        fixture,_,_=self.make([(query(),PEER)],on_send=on_send);fixture.start();report=fixture.finish(deadline=60)
        self.assertTrue(report['selected_query_observed']);self.assertEqual(report['error'],'operation')
        self.assertEqual(report['cases']['selected']['matched_queries'],1);self.assertEqual(report['cases']['selected']['answers_sent'],0)

    def test_late_received_selected_stays_observed_without_answer_or_deadline_renewal(self):
        def late(owner,clock):clock.now=60
        fixture,owned,_=self.make([(query(),PEER)],on_receive=late);fixture.start();report=fixture.finish(deadline=600)
        self.assertEqual(fixture.deadline,60);self.assertTrue(report['selected_query_observed'])
        self.assertEqual(report['error'],'deadline');self.assertEqual(report['cases']['selected']['matched_queries'],1)
        self.assertEqual(report['cases']['selected']['answers_sent'],0);self.assertEqual(owned['socket'].sent,[])
        self.assertEqual(owned['thread'].joins,[0])

    def test_late_actual_answer_remains_counted(self):
        def late(owner,clock):clock.now=60
        fixture,_,_=self.make([(query(),PEER)],on_send=late);fixture.start();report=fixture.finish(deadline=60)
        self.assertTrue(report['selected_query_observed']);self.assertEqual(report['cases']['selected']['answers_sent'],1)
        self.assertEqual(report['error'],'deadline')

    def test_global_datagram_bound_not_multiplied_per_case(self):
        fixture,owned,_=self.make([(query(),PEER)]*33);fixture.start();report=fixture.finish(deadline=60)
        self.assertEqual(report['error'],'bound');self.assertEqual(report['counts']['datagrams'],32)
        self.assertEqual(report['cases']['selected']['matched_queries'],32);self.assertEqual(len(owned['socket'].events),1)

    def test_oversized_datagrams_and_windows_message_size_are_aggregate_only(self):
        error=OSError('fake message size');error.winerror=10040
        fixture,_,_=self.make([(b'x'*1233,PEER),error]);fixture.start();report=fixture.finish(deadline=60)
        self.assertEqual(report['counts']['datagrams'],2);self.assertEqual(report['counts']['oversized'],2)
        self.assertEqual(report['counts']['rejected'],2);self.assertEqual(report['counts']['bytes'],2*1233)
        self.assertEqual(report['counts']['matched_queries'],0);self.assertFalse(any(report['case_query_observed'].values()))

    def test_byte_bound_cannot_make_counts_grow_past_global_cap(self):
        fixture,_,_=self.make([(query(),PEER)]);fixture.counts['bytes']=m.MAX_BYTES-1;fixture.start();report=fixture.finish(deadline=60)
        self.assertEqual(report['counts']['bytes'],m.MAX_BYTES);self.assertEqual(report['error'],'bound')

    def test_close_is_consumed_once_and_uncertainty_never_washed_green(self):
        for options in ({},{'close_error':True},{'fileno_error':True}):
            fixture,owned,_=self.make([(query(),PEER)],**options);fixture.start()
            first=fixture.finish(deadline=60);second=fixture.finish(deadline=60)
            self.assertEqual(owned['socket'].close_calls,1);self.assertTrue(first['socket_close_attempted'])
            self.assertTrue(first['selected_query_observed'] and second['selected_query_observed'])
            self.assertEqual(first['cleanup_confirmed'],not options);self.assertEqual(second['cleanup_confirmed'],not options)
            self.assertEqual(second['socket_close_uncertain'],bool(options))

    def test_unknown_thread_hides_counters_but_keeps_all_independent_events(self):
        fixture,owned,_=self.make(thread_mode='alive');fixture.start()
        for key in m.CASES:fixture.case_query_observed[key].set()
        report=fixture.finish(deadline=600)
        self.assertFalse(report['thread_stopped'] or report['cleanup_confirmed'])
        self.assertIsNone(report['counts']);self.assertIsNone(report['cases'])
        self.assertTrue(all(report['case_query_observed'].values()));self.assertTrue(report['selected_query_observed'])
        self.assertEqual(owned['thread'].joins,[60]);self.assertEqual(owned['socket'].close_calls,1)

    def test_start_or_join_unknown_never_cleanup_green(self):
        fixture,owned,_=self.make(thread_mode='start-error')
        with self.assertRaises(RuntimeError):fixture.start()
        report=fixture.finish(deadline=60);self.assertFalse(report['cleanup_confirmed']);self.assertIsNone(report['counts'])
        self.assertEqual(owned['socket'].close_calls,1)
        fixture,_,_=self.make([(query(),PEER)],join_error=True);fixture.start();report=fixture.finish(deadline=60)
        self.assertTrue(report['selected_query_observed']);self.assertFalse(report['thread_stopped'] or report['cleanup_confirmed'])
        self.assertIsNone(report['cases'])

    def test_failed_exclusive_or_bind_is_owned_and_closed_without_retry(self):
        for options in ({'exclusive':0},{'bind_error':True}):
            fixture,owned,_=self.make(**options)
            with self.assertRaises((ValueError,OSError)):fixture.start()
            report=fixture.finish(deadline=60);self.assertTrue(report['cleanup_confirmed'])
            self.assertFalse(report['ready']);self.assertEqual(report['error'],'operation')
            self.assertEqual(owned['socket'].close_calls,1)

    def test_snapshot_is_detached_and_does_not_erase_sticky_events(self):
        fixture,_,_=self.make([(query(),PEER)]);fixture.start();first=fixture.snapshot(deadline=60)
        first['counts']['matched_queries']=0;first['cases']['selected']['matched_queries']=0;first['case_query_observed']['selected']=False
        second=fixture.snapshot(deadline=60)
        self.assertEqual(second['cases']['selected']['matched_queries'],1);self.assertTrue(second['selected_query_observed'])
        fixture.finish(deadline=60)


if __name__=='__main__':unittest.main()
