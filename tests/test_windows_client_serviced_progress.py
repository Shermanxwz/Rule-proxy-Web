import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('progress_host_test',ROOT/'.github/windows_identity_serviced_stage0.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)

def record(**kwargs):
    value=dict(v=1,s='system',p='entry',m=None,n=None,f=None);value.update(kwargs);return value

def line(**kwargs):return b'RPS2 '+json.dumps(record(**kwargs),separators=(',',':')).encode('ascii')+b'\n'

class ParserTests(unittest.TestCase):
    def test_all_role_stage_pairs_and_all_chunk_records(self):
        parser=host.ProgressSerial()
        payload=b''.join(line(s=role,p=stage) for role,stages in host.PROGRESS_STAGES.items() for stage in stages)
        parser.feed(payload)
        self.assertEqual(parser.accepted,12);self.assertEqual(parser.rejected,0)
        self.assertEqual(len(parser.records),12)
    def test_fragments_overlong_recovery_nonascii_and_bounded_tail(self):
        parser=host.ProgressSerial();data=line()
        for byte in data:parser.feed(bytes([byte]))
        parser.feed(b'x'*257);self.assertEqual(len(parser.tail),0)
        parser.feed(b'\n'+line()+b'\xffbad\n'+line())
        self.assertEqual(parser.accepted,3);self.assertEqual(parser.rejected,2)
        parser.feed(b'a'*256);self.assertLessEqual(len(parser.tail),256)
    def test_duplicate_extra_missing_types_rejected(self):
        self.assertIsNone(host.parse_progress(b'RPS2 {"v":1,"v":1,"s":"system","p":"entry","m":null,"n":null,"f":null}'))
        for key,bad in [('v',True),('s','PRIVATE'),('p','PRIVATE'),('m',True),('m',8),('n',True),('n',2),('f','PRIVATE')]:
            value=record(p='failed');value[key]=bad
            self.assertIsNone(host.parse_progress(b'RPS2 '+json.dumps(value).encode()))
        for value in ({**record(),'private':'PRIVATE'},dict(v=1),[],None):
            self.assertIsNone(host.parse_progress(b'RPS2 '+json.dumps(value).encode()))
    def test_stage_irrelevance_and_closed_failure(self):
        self.assertIsNone(host.parse_progress(line(m=1).rstrip()))
        for mask in range(8):
            value=host.parse_progress(line(p='failed',m=mask,n=1,f='reboot_still_pending').rstrip())
            self.assertEqual(value['m'],mask)
        self.assertIsNotNone(host.parse_progress(line(s='ordinary',p='report_attempt',m=7,n=1,f='dism_failed').rstrip()))
    def test_first32_nooverwrite_saturation_and_no_raw_export(self):
        parser=host.ProgressSerial();parser.feed(line()*40)
        self.assertEqual(len(parser.records),32);self.assertEqual(parser.dropped,8)
        parser.accepted=parser.rejected=parser.dropped=65535
        parser.feed(line()+b'PRIVATE_PATH_SID\n')
        self.assertEqual((parser.accepted,parser.rejected,parser.dropped),(65535,65535,65535))
        self.assertNotIn('PRIVATE',json.dumps(parser.snapshot()))
    def test_host_wiring_no_control_consumes_advisory(self):
        import ast
        tree=ast.parse((ROOT/'.github/windows_identity_serviced_stage0.py').read_text())
        funcs={n.name:ast.unparse(n) for n in tree.body if isinstance(n,ast.FunctionDef)}
        for name in ('validate_guest','observe_bootstrap','prepare_servicing','merge_serviced_result'):
            self.assertNotIn('progress',funcs[name])
        self.assertIn('ringbuf,id=progressbuf,size=65536',funcs['host'])
        self.assertIn('diag-qmp.sock',funcs['host'])
        self.assertIn('windows-identity-serviced-telemetry.ps1',funcs['host'])

class ScriptedSocket:
    def __init__(self,mode):self.mode=mode;self.data=b'';self.closed=False;self.sent=[]
    def settimeout(self,value):self.timeout=value
    def sendall(self,data):
        self.sent.append(json.loads(data));identity=self.sent[-1]['id']
        if self.mode=='valid':self.data=json.dumps({'return':base64.b64encode(line()).decode(),'id':identity}).encode()+b'\n'
        elif self.mode=='malformed':self.data=b'{broken\n'
        elif self.mode=='oversized':self.data=b'X'*(host.PROGRESS_FRAME+1)
        elif self.mode=='duplicate':self.data=b'{"return":"","return":"","id":1}\n'
        elif self.mode=='wrong_id':self.data=b'{"return":"","id":999}\n'
        elif self.mode=='bad_base64':self.data=json.dumps({'return':'%%%','id':identity}).encode()+b'\n'
        elif self.mode=='events':self.data=b'{"event":"RESUME"}\n'*9
        elif self.mode=='truncated':self.data=b'{"return":' 
    def recv(self,maximum):
        if self.mode=='timeout':raise TimeoutError('synthetic timeout')
        value=self.data[:maximum];self.data=self.data[maximum:];return value
    def shutdown(self,how):pass
    def close(self):self.closed=True
    def fileno(self):return -1 if self.closed else 7

class MonitorTests(unittest.TestCase):
    def fixture(self,mode):
        qmp=host.ProgressQmp.__new__(host.ProgressQmp)
        qmp.socket=ScriptedSocket(mode);qmp.buffer=bytearray();qmp.sequence=0;qmp.closed=False
        return qmp
    def test_valid_read_and_independent_close(self):
        qmp=self.fixture('valid');self.assertEqual(qmp.read(),line())
        self.assertEqual(qmp.socket.sent[0]['arguments'],{'device':'progressbuf','size':65536,'format':'base64'})
        qmp.close();self.assertTrue(qmp.closed)
    def test_malformed_duplicate_oversize_timeout_disable_and_close(self):
        for mode in ('malformed','duplicate','oversized','timeout','closed','wrong_id','bad_base64','events','truncated'):
            with self.subTest(mode=mode):
                qmp=self.fixture(mode)
                with self.assertRaises(Exception):qmp.read()
                self.assertTrue(qmp.closed);self.assertEqual(qmp.socket.fileno(),-1)
    def test_reader_failure_is_advisory_and_no_reconnect(self):
        qmp=self.fixture('malformed')
        factory=Mock(return_value=qmp)
        fake=type('QmpFactory',(),{'__new__':factory})
        qmp.__init__=Mock(return_value=None)
        with patch.object(host,'ProgressQmp',fake):
            reader=host.start_progress(Path('/unused'),Path('/unused'),time.monotonic()+5)
            reader.thread.join(1);result=reader.finish();factory.assert_called_once()
        self.assertTrue(result['disabled']);self.assertTrue(result['reader_stopped']);self.assertTrue(result['socket_closed'])
        self.assertTrue(result['unauthenticated'])
    def test_constructor_failure_keeps_connection_owned_for_cleanup(self):
        qmp=self.fixture('valid')
        fake=type('QmpFactory',(),{'__new__':Mock(return_value=qmp)})
        qmp.__init__=Mock(side_effect=OSError('PRIVATE'))
        with patch.object(host,'ProgressQmp',fake):
            reader=host.start_progress(Path('/unused'),Path('/unused'),time.monotonic()+5)
            reader.thread.join(1);result=reader.finish()
        self.assertIs(reader.connection,qmp)
        self.assertTrue(qmp.closed);self.assertTrue(result['socket_closed'])
        self.assertTrue(result['disabled']);self.assertNotIn('PRIVATE',json.dumps(result))

    def test_actual_finish_reports_thread_or_close_uncertainty(self):
        reader=host.ProgressReader(Path('/unused'),Path('/unused'),time.monotonic()+1)
        reader.thread=Mock();reader.thread.ident=1;reader.thread.is_alive.return_value=True
        reader.connection=Mock();reader.connection.closed=False
        reader.connection.close.side_effect=OSError('PRIVATE')
        result=reader.finish()
        self.assertTrue(result['disabled']);self.assertFalse(result['reader_stopped'])
        self.assertFalse(result['socket_closed']);self.assertNotIn('PRIVATE',json.dumps(result))
        reader.thread.join.assert_called_once_with(timeout=1)

    def test_unconfirmed_reader_or_socket_retains_work_and_cannot_pass(self):
        for state in ({'reader_stopped':False,'socket_closed':True},
                      {'reader_stopped':True,'socket_closed':False},None):
            progress=Mock()
            if state is None:progress.finish.side_effect=OSError('PRIVATE')
            else:progress.finish.return_value={'unauthenticated':True,'disabled':True,**state}
            public={'stage0_passed':True}
            with patch.object(host,'cleanup_owned',return_value=True) as cleanup:
                host.finalize_owned(public,Mock(),Path('/owned'),progress=progress)
            self.assertTrue(cleanup.call_args.kwargs['retain_work'])
            self.assertFalse(public['vm_destroyed']);self.assertFalse(public['stage0_passed'])
            self.assertNotIn('PRIVATE',json.dumps(public))
        public={'stage0_passed':True};progress=Mock()
        progress.finish.return_value={'unauthenticated':True,'disabled':True,'reader_stopped':True,'socket_closed':True}
        with patch.object(host,'cleanup_owned',return_value=True) as cleanup:
            host.finalize_owned(public,Mock(),Path('/owned'),progress=progress)
        self.assertFalse(cleanup.call_args.kwargs['retain_work'])
        self.assertTrue(public['vm_destroyed']);self.assertTrue(public['stage0_passed'])

    @unittest.skipUnless(os.name=='posix','POSIX socket ownership required')
    def test_nonowned_or_regular_path_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);work.chmod(0o700);path=work/'file';path.write_text('PRIVATE')
            with self.assertRaises(ValueError):host.ProgressQmp(path,work)

if __name__=='__main__':unittest.main()
