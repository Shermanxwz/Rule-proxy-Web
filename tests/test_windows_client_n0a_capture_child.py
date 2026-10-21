import copy
import array
from types import SimpleNamespace
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('capture_child_tests',ROOT/'.github/windows_n0a_capture_child.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
HEADER=struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,n.primitive.SNAPLEN,1)
def packet(data=b'abc'):return struct.pack('<IIII',1,1,len(data),len(data))+data

def producer(path,data=HEADER+packet(),suffix=''):
    code='import os,sys,time,signal;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));f=os.open(sys.argv[1],os.O_WRONLY);v=memoryview(bytes.fromhex(sys.argv[2]))\nwhile v:\n k=os.write(f,v);v=v[k:]\n'+suffix+'\ntime.sleep(30)'
    return [sys.executable,'-c',code,str(path),data.hex()]

def status(seq=1,phase='reader_open'):
    return dict(v=1,seq=seq,phase=phase,header=False,authorized=False,reader_closed=False,fifo_eof=False,stderr_eof=False,
        overflow=False,retained=0,drained=0,records=0,stderr_bytes=0,flushed=False,closed=False,structure=False,
        qemu_dump_write_error=False,errors=[])

class ProtocolTests(unittest.TestCase):
    def test_exact_frame_bound_ascii_duplicates_unknown_and_msgtrunc(self):
        good=n.encode(status());self.assertEqual(n.decode(good),status())
        for data,flags in ((b'{}',socket.MSG_TRUNC),(b'x'*2049,0),(b'{"v":1,"v":1}',0),(b'\xff',0),(b'[]',0)):
            with self.assertRaises((ValueError,UnicodeError)):n.decode(data,flags)
        for change in ({'extra':'PRIVATE'},{'seq':True},{'retained':True},{'errors':['PRIVATE']},{'header':1}):
            value=status();value.update(change)
            with self.assertRaises(ValueError):n.valid_status(value)
    def test_sequence_phase_terminal_cumulative_facts_and_budget(self):
        first=status();second=status(3,'ready');self.assertEqual(n.valid_status(second,first),second)
        for seq in (1,2,65):
            value=status(seq,'ready')
            with self.assertRaises(ValueError):n.valid_status(value,second)
        for key in ('header','overflow','fifo_eof','stderr_eof','authorized','qemu_dump_write_error'):
            before=status(2,'ready');before[key]=True
            with self.assertRaises(ValueError):n.valid_status(status(3,'ready'),before)
        before=status(2,'final')
        with self.assertRaises(ValueError):n.valid_status(status(3,'final'),before)
        before=status(2,'ready');before['errors']=['write']
        with self.assertRaises(ValueError):n.valid_status(status(3,'ready'),before)
    def test_control_fixed_shape_and_max8(self):
        self.assertEqual(n.valid_command(dict(v=1,seq=1,op='arm'),0)['op'],'arm')
        for value in (dict(v=1,seq=9,op='arm'),dict(v=True,seq=1,op='arm'),dict(v=1,seq=1,op='PRIVATE'),dict(v=1,seq=1,op='arm',extra=0)):
            with self.assertRaises(ValueError):n.valid_command(value,0)
    def test_stderr_total_bound_and_fragmented_exact_error(self):
        worker=object.__new__(n.DrainWorker)
        worker.stderr_fd=123;worker.stderr_pending=bytearray();worker.stderr_bytes=0
        worker.authorized=True;worker.errors=set();worker.qemu_dump_write_error=False;worker.emit=Mock()
        line=b'qemu-system-x86_64: network dump write error - stopping dump\n'
        for fragment in (line[:13],line[13:]):
            with patch.object(n.os,'read',return_value=fragment):worker.stderr()
        self.assertTrue(worker.qemu_dump_write_error)
        worker.errors.clear();worker.stderr_bytes=0
        benign=b'qemu-system-x86_64: terminating on signal 15 from pid 123 (python)\n'
        with patch.object(n.os,'read',return_value=benign*2000):worker.stderr()
        self.assertIn('stderr_bound',worker.errors)
        self.assertGreater(worker.stderr_bytes,n.MAX_STDERR)
    def test_complete_status_bound_and_no_private_content(self):
        value=status(64,'final');value['errors']=sorted(n.ERRORS)
        value.update(retained=n.primitive.CAPTURE_LIMIT,drained=2**64-1,records=2**32-1,stderr_bytes=2**32-1)
        self.assertLessEqual(len(n.encode(value)),2048)
        self.assertNotIn('PRIVATE',str(value))

@unittest.skipUnless(sys.platform=='linux','Linux owned child / FIFO mechanics')
class ChildTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.owner=n.CaptureOwner(self.root,deadline=time.monotonic()+15)
    def tearDown(self):
        self.owner.finish(cleanup_deadline=time.monotonic()+2)
        self.temp.cleanup()
    def start(self,data=HEADER+packet(),suffix=''):
        self.owner.start();self.owner.spawn(producer(self.owner.fifo_path,data,suffix))
        self.assertTrue(self.owner.wait_header(time.monotonic()+2))
    def test_normal_exact_child_exit_final_and_qemu_exit_required(self):
        self.start();self.assertIsNone(self.owner.dummy_fd)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertTrue(result['drain_complete'],result)
        self.assertEqual(result['execution_model'],'owned_child');self.assertTrue(result['child_exit_observed'])
        self.assertTrue(result['final_status_observed']);self.assertEqual(self.owner.output_path.read_bytes(),HEADER+packet())
        self.assertFalse(result['packet_absence_proven'])
    def test_actual_separate_process_and_minimal_inheritance(self):
        self.owner.start()
        self.assertNotEqual(self.owner.child.pid,os.getpid());self.assertTrue(self.owner.ready_observed)
        self.assertIsNone(self.owner.stderr_read);self.assertIsNone(self.owner.child_channel);self.assertIsNone(self.owner.root_fd)
        self.assertIsNotNone(self.owner.stderr_write);self.assertIsNotNone(self.owner.dummy_fd)
    def test_overflow_retains_cap_keeps_drain_and_reports(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,byte_limit=64)
        self.owner.start();self.owner.spawn(producer(self.owner.fifo_path,HEADER+packet(b'x'*1000)))
        until=time.monotonic()+2
        while time.monotonic()<until:
            current=self.owner.poll_status(time.monotonic()+.05)
            if current and current['overflow']:break
        self.assertTrue(current['overflow']);self.assertEqual(current['retained'],64)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(result['capture']['drained'],1040)
    def test_fixture_reader_close_keeps_stderr_live_exact_error(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='close_reader')
        self.start(HEADER,"time.sleep(.2);os.write(2,b'qemu-system-x86_64: network dump write error - stopping dump\\n')")
        self.assertTrue(self.owner.fixture_close_reader(time.monotonic()+1))
        until=time.monotonic()+2
        while time.monotonic()<until:
            current=self.owner.poll_status(time.monotonic()+.05)
            if current and current['qemu_dump_write_error']:break
        self.assertTrue(current['qemu_dump_write_error']);self.assertIsNone(self.owner.process.poll())
        result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
    def test_full_status_socket_does_not_block_fifo_drain(self):
        parent,child=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        child.setblocking(False);readfd,writefd=os.pipe();errread,errwrite=os.pipe()
        rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        worker=n.DrainWorker(rootfd,errread,child.detach(),time.monotonic()+5)
        worker.read_fd=readfd;worker.output_fd=os.open(self.root/'private-test.pcap',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        worker.channel.setblocking(False)
        try:
            for _ in range(1024):
                try:worker.channel.send(b'x'*n.MAX_FRAME)
                except BlockingIOError:break
            else:self.fail('fixture socket did not reach bound')
            worker.emit();self.assertIn('ipc',worker.errors)
            data=HEADER+packet(b'x'*1000);os.write(writefd,data);worker.capture()
            self.assertEqual(worker.drained,len(data));self.assertEqual(worker.retained,len(data))
            self.assertTrue(worker.structure.complete())
        finally:
            for name in ('root_fd','stderr_fd','read_fd','output_fd'):worker._close_fd(name)
            worker.channel.close();parent.close();os.close(writefd);os.close(errwrite)
    def test_fixture_fault_unavailable_on_normal_owner(self):
        with self.assertRaises(ValueError):self.owner.fixture_close_reader(time.monotonic()+1)
    def test_child_exit_without_final_is_incomplete(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='exit_without_final')
        self.start();result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertFalse(result['drain_complete']);self.assertFalse(result['final_status_observed'])
        self.assertTrue(result['child_exit_observed']);self.assertTrue(result['cleanup_confirmed'])
    def test_final_status_does_not_replace_exit_observation(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='final_before_exit')
        self.start();result=self.owner.finish(cleanup_deadline=time.monotonic()+4)
        self.assertTrue(result['final_status_observed']);self.assertTrue(result['child_forced'])
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
    def test_final_followed_by_trailing_invalid_frame_cannot_complete(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='trailing_frame')
        self.start();result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertTrue(result['final_status_observed']);self.assertTrue(result['child_exit_observed'])
        self.assertEqual(result['child_exit_code'],0);self.assertIn('ipc',result['errors'])
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
    def test_blocked_child_fsync_killed_within_same_deadline(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='stall_fsync')
        self.start();deadline=time.monotonic()+4
        result=self.owner.finish(cleanup_deadline=deadline)
        self.assertTrue(result['child_forced']);self.assertFalse(result['drain_complete'])
        self.assertTrue(result['child_exit_observed']);self.assertLess(time.monotonic(),deadline+.5)
    def test_lost_status_channel_still_stops_owned_processes(self):
        self.start();self.owner.channel.shutdown(socket.SHUT_RDWR)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+4)
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
        self.assertIn('ipc',result['errors'])
    def test_partial_child_spawn_failure_keeps_fd_cleanup(self):
        with patch.object(n.subprocess,'Popen',side_effect=OSError('PRIVATE')):
            with self.assertRaises(OSError):self.owner.start()
        result=self.owner.finish(cleanup_deadline=time.monotonic()+1)
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
        self.assertNotIn('PRIVATE',str(result))
    def test_lost_shutdown_ack_forbids_complete_but_cleans(self):
        self.start()
        with patch.object(self.owner,'command',return_value=False):
            result=self.owner.finish(cleanup_deadline=time.monotonic()+4)
        self.assertIn('authorization',result['errors']);self.assertFalse(result['shutdown_authorized'])
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
    def test_unknown_kill_and_exit_retains_owner_and_work(self):
        class Process:
            def poll(self):return None
            def send_signal(self,_):raise OSError('PRIVATE')
            def kill(self):raise OSError('PRIVATE')
            def wait(self,timeout):raise OSError('PRIVATE')
        self.owner.process=Process();self.owner.child=Process()
        result=self.owner.finish(cleanup_deadline=time.monotonic()+.1)
        self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
        self.assertFalse(result['qemu_exit_observed']);self.assertFalse(result['child_exit_observed'])
        self.assertIsNone(self.owner.final);self.assertFalse(result['root_removal_attempted'])
        self.owner.process=self.owner.child=None
    def test_status_frame_rejections_use_actual_seqpacket_transport(self):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET);left.setblocking(False);left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        self.owner.channel=left;self.owner.child=SimpleNamespace(pid=os.getpid(),poll=lambda:0)
        try:
            right.send(n.encode(status()));self.owner.poll_status()
            self.assertEqual(self.owner.status['seq'],1)
            right.send(b'x'*(n.MAX_FRAME+2));self.owner.poll_status()
            self.assertIn('ipc',self.owner.errors)
            self.assertFalse(self.owner.wait(lambda s:s is not None,time.monotonic()+.1))
            self.owner.errors.clear();self.owner.status_frames=n.MAX_FRAMES
            right.send(n.encode(status(2,'ready')));self.owner.poll_status()
            self.assertIn('ipc_budget',self.owner.errors)
        finally:right.close();self.owner.child=None
    def test_deep_json_ipc_cannot_bypass_owned_process_cleanup(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='nested_frame')
        self.start();result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertIn('ipc',result['errors']);self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(result['drain_complete']);self.assertTrue(result['child_exit_observed'])
    def test_actual_child_empty_record_cannot_hide_trailing_frame(self):
        self.owner=n.CaptureOwner.for_test(self.root,deadline=time.monotonic()+15,mode='empty_trailing_frame')
        self.start();result=self.owner.finish(cleanup_deadline=time.monotonic()+5)
        self.assertTrue(result['final_status_observed']);self.assertEqual(result['child_exit_code'],0)
        self.assertIn('ipc',result['errors']);self.assertFalse(result['drain_complete'])
        self.assertTrue(result['cleanup_confirmed'])
    def test_selector_observation_error_is_closed_not_cleanup_escape(self):
        self.start()
        with patch.object(n.selectors,'DefaultSelector',side_effect=OSError('PRIVATE')):
            self.owner.poll_status(time.monotonic()+.1)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+4)
        self.assertIn('ipc',result['errors']);self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(result['drain_complete'])
    def test_unknown_nonzero_and_early_zero_producer_exit_incomplete(self):
        self.owner.start();self.owner.spawn(producer(self.owner.fifo_path,HEADER+packet(),'os.close(f);sys.exit(0)'))
        self.owner.wait_header(time.monotonic()+.5) # early EOF may already make the handshake fail closed
        self.owner.process.wait(timeout=2)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+4)
        self.assertFalse(result['producer_live_at_shutdown']);self.assertFalse(result['drain_complete'])
        self.assertTrue(result['cleanup_confirmed'])
    def test_qemu_spawn_failure_closes_stderr_writer_and_child(self):
        self.owner.start()
        with patch.object(n.subprocess,'Popen',side_effect=OSError('PRIVATE')):
            with self.assertRaises(OSError):self.owner.spawn(['missing'])
        self.assertIsNone(self.owner.stderr_write)
        result=self.owner.finish(cleanup_deadline=time.monotonic()+2)
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])

@unittest.skipUnless(sys.platform=='linux','Linux per-message credentials and descriptor ownership')
class CredentialTests(unittest.TestCase):
    def pair(self,credentials=True):
        left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
        if credentials:left.setsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        return left,right
    def test_empty_record_is_not_eof_and_following_record_remains(self):
        left,right=self.pair();ledger=n.CloseLedger();expected=(os.getpid(),os.getuid(),os.getgid())
        try:
            right.send(b'final');right.send(b'');right.send(b'tail');right.close()
            self.assertEqual(n.receive(left,expected,ledger),b'final')
            with self.assertRaises(ValueError):n.receive(left,expected,ledger)
            self.assertEqual(n.receive(left,expected,ledger),b'tail')
            self.assertIsNone(n.receive(left,expected,ledger))
        finally:left.close();right.close()
    def test_wrong_sender_and_missing_credentials_fail_closed(self):
        for enabled,expected in ((True,(os.getpid()+1,os.getuid(),os.getgid())),(False,(os.getpid(),os.getuid(),os.getgid()))):
            left,right=self.pair(enabled)
            try:
                right.send(b'frame')
                with self.assertRaises(ValueError):n.receive(left,expected,n.CloseLedger())
            finally:left.close();right.close()
    def test_truncated_duplicate_unknown_ancillary_fail_closed(self):
        expected=(os.getpid(),os.getuid(),os.getgid())
        credential=(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('=iII',*expected))
        for ancillary,flags in (([credential],socket.MSG_CTRUNC),([credential,credential],0),
                                ([(socket.SOL_SOCKET,999,b'PRIVATE')],0),
                                ([(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,b'x')],0)):
            channel=Mock();channel.recvmsg.return_value=(b'frame',ancillary,flags,None)
            with self.assertRaises(ValueError):n.receive(channel,expected,n.CloseLedger())
            self.assertEqual(channel.recvmsg.call_args.args[2],socket.MSG_CMSG_CLOEXEC)
    def test_rights_rejected_and_received_duplicate_closed(self):
        left,right=self.pair(False);source=os.open('/dev/null',os.O_RDONLY);ledger=n.CloseLedger()
        before=len(os.listdir('/proc/self/fd'))
        try:
            right.sendmsg([b'bad'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[source]))])
            with self.assertRaises(ValueError):n.receive(left,(os.getpid(),os.getuid(),os.getgid()),ledger)
            self.assertEqual(len(os.listdir('/proc/self/fd')),before);self.assertFalse(ledger.uncertain)
        finally:left.close();right.close();os.close(source)
    def test_close_then_error_never_retries_reused_fd(self):
        with tempfile.TemporaryDirectory() as temp:
            owner=n.CaptureOwner(temp,deadline=time.monotonic()+5)
            owner.root_fd=os.open('/dev/null',os.O_RDONLY);original_fd=owner.root_fd;replacement=[];realclose=os.close
            def close(fd):
                realclose(fd);replacement.append(os.open('/dev/null',os.O_RDONLY))
                raise OSError('PRIVATE close observation')
            with patch.object(n.os,'close',side_effect=close):owner._close('root_fd')
            self.assertIsNone(owner.root_fd);self.assertEqual(replacement,[original_fd])
            result=owner.finish(cleanup_deadline=time.monotonic()+1)
            self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
            os.fstat(replacement[0]);realclose(replacement[0])
    def test_rights_close_uncertainty_never_retries_replacement(self):
        left,right=self.pair(False);source=os.open('/dev/null',os.O_RDONLY);ledger=n.CloseLedger();replacement=[];realclose=os.close
        try:
            right.sendmsg([b'bad'],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[source]))])
            def close(fd):
                realclose(fd);replacement.append(os.open('/dev/null',os.O_RDONLY));raise OSError('PRIVATE')
            with patch.object(n.os,'close',side_effect=close):
                with self.assertRaises(ValueError):n.receive(left,(os.getpid(),os.getuid(),os.getgid()),ledger)
            self.assertTrue(ledger.uncertain);self.assertEqual(len(replacement),1)
            os.fstat(replacement[0])
        finally:
            left.close();right.close();realclose(source)
            for fd in replacement:realclose(fd)

if __name__=='__main__':unittest.main()
