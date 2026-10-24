import importlib.util
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('n0a_capture_test',ROOT/'.github/windows_n0a_capture.py')
n=importlib.util.module_from_spec(spec);spec.loader.exec_module(n)
HEADER=struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,n.SNAPLEN,1)
def packet(data=b'abc'):
    return struct.pack('<IIII',1,2,len(data),len(data))+data

def producer(path, data, suffix=''):
    # Synthetic local-only producer; no VM, sockets or packet egress.
    code='import os,sys,time,signal;signal.signal(signal.SIGTERM,lambda *_:sys.exit(0));f=os.open(sys.argv[1],os.O_WRONLY);data=bytes.fromhex(sys.argv[2]);'\
         'v=memoryview(data)\nwhile v:\n k=os.write(f,v);v=v[k:]\n'+suffix+'\ntime.sleep(30)'
    return [sys.executable,'-c',code,str(path),data.hex()]

class StructureTests(unittest.TestCase):
    def test_fragmented_header_records_and_big_endian(self):
        for data in (HEADER+packet(),struct.pack('>IHHiIII',0xa1b2c3d4,2,4,0,0,n.SNAPLEN,1)+struct.pack('>IIII',1,2,3,3)+b'abc'):
            parser=n.PcapStructure()
            for b in data:parser.feed(bytes([b]))
            self.assertTrue(parser.complete());self.assertEqual(parser.records,1)
    def test_malformed_and_truncated_not_complete(self):
        for data in (b'bad!',HEADER[:-1],HEADER+packet()[:-1],HEADER+struct.pack('<IIII',0,1000000,0,0),
                     HEADER+struct.pack('<IIII',0,0,n.SNAPLEN+1,n.SNAPLEN+1),HEADER+struct.pack('<IIII',0,0,2,1),HEADER+struct.pack('<IIII',0,0,1,2)+b'x',
                     HEADER+struct.pack('<IIII',0,0,0,0)):
            parser=n.PcapStructure();parser.feed(data);self.assertFalse(parser.complete())
    def test_no_unbounded_packet_storage(self):
        parser=n.PcapStructure();parser.feed(HEADER+struct.pack('<IIII',1,1,n.SNAPLEN,n.SNAPLEN))
        for _ in range(n.SNAPLEN//1024):parser.feed(b'X'*1024)
        self.assertTrue(parser.complete());self.assertLessEqual(len(parser.pending),24)
    def test_stderr_categories_never_raw(self):
        with tempfile.TemporaryDirectory() as temp:
            sink=n.CaptureSink(temp,deadline=time.monotonic()+10)
            sink.shutdown_requested=True
            sink._stderr_line(b'qemu-system-x86_64: terminating on signal 15 from pid 123 (python3)')
            self.assertFalse(sink.errors)
            sink._stderr_line(b'network dump write error - stopping dump PRIVATE')
            sink._stderr_line(b'PRIVATE unknown')
            self.assertEqual(sink.errors,{'stderr_capture','stderr_unknown'})

@unittest.skipUnless(sys.platform=='linux','actual Linux FIFO/owned-process fixtures')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.sink=n.CaptureSink(self.root,deadline=time.monotonic()+20)
    def tearDown(self):
        self.sink.finish(cleanup_deadline=time.monotonic()+2)
        self.temp.cleanup()
    def test_normal_header_ready_before_spawn_and_complete_drain(self):
        self.sink.start();self.assertTrue(self.sink.ready.is_set());self.assertIsNone(self.sink.process)
        self.sink.spawn(producer(self.sink.fifo_path,HEADER+packet()))
        self.assertTrue(self.sink.wait_header(time.monotonic()+2))
        result=self.sink.finish(cleanup_deadline=time.monotonic()+3)
        self.assertTrue(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(self.sink.output_path.read_bytes(),HEADER+packet())
        self.assertEqual(result,self.sink.finish(cleanup_deadline=time.monotonic()+1))
        self.assertFalse(result['packet_absence_proven'])
        self.assertEqual(result['execution_model'],'owner_threads')
    def test_overflow_sticky_drains_and_retains_exact_cap(self):
        self.sink=n.CaptureSink.for_test(self.root,deadline=time.monotonic()+20,byte_limit=64)
        self.sink.start();data=HEADER+packet(b'x'*4000)
        self.sink.spawn(producer(self.sink.fifo_path,data))
        self.assertTrue(self.sink.overflow_event.wait(2))
        result=self.sink.finish(cleanup_deadline=time.monotonic()+3)
        self.assertTrue(result['overflow']);self.assertEqual(result['retained_bytes'],64)
        self.assertEqual(result['drained_bytes'],len(data));self.assertEqual(self.sink.output_path.stat().st_size,64)
        self.assertFalse(result['drain_complete']);self.assertTrue(result['cleanup_confirmed'])
    def test_header_then_capture_writer_closes_while_producer_alive(self):
        self.sink.start();self.sink.spawn(producer(self.sink.fifo_path,HEADER,'os.close(f)'))
        self.assertTrue(self.sink.failure_event.wait(2));self.assertIn('early_eof',self.sink.errors)
        self.assertIsNone(self.sink.dummy_fd)
        self.assertFalse(self.sink.finish(cleanup_deadline=time.monotonic()+3)['drain_complete'])
    def test_natural_exit_zero_before_shutdown_cannot_be_complete(self):
        self.sink.start()
        self.sink.spawn(producer(self.sink.fifo_path,HEADER+packet(),'os.close(f);sys.exit(0)'))
        self.sink.process.wait(timeout=2)
        self.assertTrue(self.sink.failure_event.wait(2))
        result=self.sink.finish(cleanup_deadline=time.monotonic()+2)
        self.assertEqual(result['process_exit_code'],0)
        self.assertIn('early_eof',result['errors'])
        self.assertFalse(result['producer_live_at_shutdown']);self.assertFalse(result['drain_complete'])
    def test_header_error_stderr_and_truncated_capture_failclosed(self):
        self.sink.start();self.sink.spawn(producer(self.sink.fifo_path,HEADER+packet()[:-1],"os.write(2,b'network dump write error - stopping dump PRIVATE\\n')"))
        self.assertTrue(self.sink.failure_event.wait(2))
        result=self.sink.finish(cleanup_deadline=time.monotonic()+3)
        self.assertFalse(result['structure_complete']);self.assertIn('stderr_capture',result['errors'])
        self.assertNotIn('PRIVATE',str(result))
    def test_create_new_conflicts_no_overwrite_and_partial_cleanup(self):
        self.sink.fifo_path.write_bytes(b'owned-existing')
        with self.assertRaises(FileExistsError):self.sink.start()
        result=self.sink.finish(cleanup_deadline=time.monotonic()+1)
        self.assertEqual(self.sink.fifo_path.read_bytes(),b'owned-existing')
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
    def test_reader_start_failure_keeps_partial_resources_owned(self):
        with patch.object(n.threading.Thread,'start',side_effect=RuntimeError('PRIVATE')):
            with self.assertRaises(RuntimeError):self.sink.start()
        result=self.sink.finish(cleanup_deadline=time.monotonic()+1)
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
        self.assertIn('thread',result['errors'])
    def test_stderr_reader_start_failure_still_stops_exact_producer(self):
        self.sink.start()
        with patch.object(n.threading.Thread,'start',side_effect=RuntimeError('PRIVATE')):
            with self.assertRaises(RuntimeError):self.sink.spawn(producer(self.sink.fifo_path,HEADER))
        owned=self.sink.process
        self.assertIsNotNone(owned)
        result=self.sink.finish(cleanup_deadline=time.monotonic()+2)
        self.assertIsNotNone(owned.poll());self.assertTrue(result['cleanup_confirmed'])
        self.assertFalse(result['drain_complete']);self.assertIn('thread',result['errors'])
    def test_spawn_failure_registered_and_cleanup(self):
        self.sink.start()
        with patch.object(n.subprocess,'Popen',side_effect=OSError('PRIVATE')):
            with self.assertRaises(OSError):self.sink.spawn(['missing'])
        self.assertTrue(self.sink.spawn_attempted)
        result=self.sink.finish(cleanup_deadline=time.monotonic()+2)
        self.assertTrue(result['cleanup_confirmed']);self.assertIn('spawn',result['errors'])
    def test_fsync_failure_is_closed_and_incomplete(self):
        self.sink.start();self.sink.spawn(producer(self.sink.fifo_path,HEADER));self.assertTrue(self.sink.wait_header(time.monotonic()+2))
        with patch.object(n.os,'fsync',side_effect=OSError('PRIVATE')):
            result=self.sink.finish(cleanup_deadline=time.monotonic()+3)
        self.assertFalse(result['drain_complete']);self.assertIn('flush',result['errors'])
    def test_write_failure_keeps_draining_without_raw_error(self):
        self.sink.start()
        original=n.os.write
        def write(fd,data):
            if fd==self.sink.output_fd:raise OSError('PRIVATE')
            return original(fd,data)
        with patch.object(n.os,'write',side_effect=write):
            self.sink.spawn(producer(self.sink.fifo_path,HEADER+packet(b'x'*4000)))
            self.assertTrue(self.sink.failure_event.wait(2))
            result=self.sink.finish(cleanup_deadline=time.monotonic()+3)
        self.assertEqual(result['drained_bytes'],4040)
        self.assertIn('write',result['errors']);self.assertFalse(result['drain_complete'])
    def test_forced_kill_uses_remaining_deadline_and_stays_incomplete(self):
        class Process:
            stderr=None
            code=None
            waits=[]
            def poll(self):return self.code
            def send_signal(self,sig):self.signal=sig
            def kill(self):self.code=-9
            def wait(self,timeout):
                self.waits.append(timeout)
                if self.code is None:raise subprocess.TimeoutExpired('private',timeout)
                return self.code
        process=Process();self.sink.process=process;self.sink.spawn_attempted=True
        result=self.sink.finish(cleanup_deadline=time.monotonic()+0.5)
        self.assertLessEqual(max(process.waits),0.5)
        self.assertTrue(result['forced_kill']);self.assertTrue(result['process_exit_observed'])
        self.assertFalse(result['drain_complete'])
    def test_wait_oserror_still_kills_exact_owned_producer_and_closes_fds(self):
        class Process:
            stderr=None
            code=None
            killed=False
            waits=[]
            def poll(self):return self.code
            def send_signal(self,sig):pass
            def kill(self):self.killed=True;self.code=-9
            def wait(self,timeout):
                self.waits.append(timeout)
                if self.code is None:raise OSError('PRIVATE observation failure')
                return self.code
        self.sink.start();process=Process();self.sink.process=process;self.sink.spawn_attempted=True
        result=self.sink.finish(cleanup_deadline=time.monotonic()+0.5)
        self.assertTrue(process.killed);self.assertLessEqual(max(process.waits),0.5)
        self.assertIn('process_wait',result['errors']);self.assertTrue(result['forced_kill'])
        self.assertTrue(result['process_exit_observed']);self.assertTrue(result['descriptors_closed'])
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['drain_complete'])
        self.assertNotIn('PRIVATE',str(result))
    def test_live_reader_and_close_error_never_claim_cleanup(self):
        class Thread:
            def join(self,timeout):pass
            def is_alive(self):return True
        self.sink.output_fd=os.open(self.sink.output_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        self.sink.reader=Thread();fd=self.sink.output_fd
        result=self.sink.finish(cleanup_deadline=time.monotonic())
        self.assertFalse(result['cleanup_confirmed']);self.assertEqual(self.sink.output_fd,fd)
        self.sink.reader=None
        original=n.os.close
        def close(value):
            if value==fd:raise OSError('PRIVATE')
            return original(value)
        with patch.object(n.os,'close',side_effect=close):
            result=self.sink.finish(cleanup_deadline=time.monotonic()+1)
        self.assertFalse(result['descriptors_closed']);self.assertFalse(result['cleanup_confirmed'])
        self.assertEqual(self.sink.output_fd,fd)
    def test_private_root_and_fixture_limits(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):self.sink.start()
        self.root.chmod(0o700)
        for value in (True,23,n.CAPTURE_LIMIT+1):
            with self.assertRaises(ValueError):n.CaptureSink.for_test(self.root,deadline=time.monotonic()+10,byte_limit=value)
    def test_unconfirmed_process_thread_or_close_retains_owned_state(self):
        class Process:
            stderr=None
            def poll(self):return None
            def send_signal(self,_):raise OSError('PRIVATE')
            def kill(self):raise OSError('PRIVATE')
            def wait(self,timeout):raise subprocess.TimeoutExpired('private',timeout)
        self.sink.process=Process();self.sink.spawn_attempted=True
        result=self.sink.finish(cleanup_deadline=time.monotonic())
        self.assertFalse(result['cleanup_confirmed']);self.assertTrue(result['forced_kill'])
        self.assertFalse(result['root_removal_attempted']);self.assertFalse(result['drain_complete'])
        self.assertIsNone(self.sink.final)
        self.sink.process=None

if __name__=='__main__':unittest.main()
