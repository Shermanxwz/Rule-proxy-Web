import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('progress_gate_test',ROOT/'.github/test_windows_serviced_progress_qmp.py')
gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)

class GateTests(unittest.TestCase):
    def test_explicit_tiny_machine_no_os_network_or_kvm(self):
        argv=gate.command('qemu',Path('/owned'))
        self.assertEqual(argv[argv.index('-accel')+1],'tcg')
        self.assertEqual(argv[argv.index('-nic')+1],'none')
        self.assertEqual(argv.count('-qmp'),2)
        self.assertNotIn('-drive',argv);self.assertNotIn('-cdrom',argv)
        self.assertIn('ringbuf,id=serialbuf,size=65536',argv)
        self.assertIn('ringbuf,id=progressbuf,size=65536',argv)
        self.assertLessEqual(gate.MAX_SECONDS,30)
    def test_actual_cont_stop_and_read_commands(self):
        control=Mock();control.execute.side_effect=[{}, {}, {'running':False}, {}, 'CONTROL\n']
        gate.control_roundtrip(control)
        self.assertEqual([c.args[0] for c in control.execute.call_args_list],['cont','stop','query-status','ringbuf-write','ringbuf-read'])
    def test_fault_wrappers_delegate_owned_close(self):
        for mode in ('malformed','timeout'):
            owned=Mock();wrapper=gate.FaultSocket(owned,mode)
            if mode=='timeout':
                with self.assertRaises(TimeoutError):wrapper.recv(10)
            else:self.assertEqual(wrapper.recv(10),b'{malformed\n')
            wrapper.close();owned.close.assert_called_once()
    def test_uncertain_owned_handles_or_watchdog_retain_work(self):
        import threading
        for failure in ('control','diagnostic','watchdog'):
            result=dict(passed=True,process_exited=False,control_closed=False,
                diagnostic_sockets_closed=failure!='diagnostic',work_removed=False)
            process=Mock();process.poll.return_value=0
            control=Mock();control.file.closed=failure!='control'
            control.socket.fileno.return_value=-1 if failure!='control' else 7
            if failure=='control':control.close.side_effect=OSError('private')
            watchdog=Mock();watchdog.is_alive.return_value=failure=='watchdog'
            with patch.object(gate.shutil,'rmtree') as remove:
                gate.cleanup_gate(result,Path('/owned'),process,control,watchdog,threading.Event())
                remove.assert_not_called()
            self.assertFalse(result['passed']);self.assertFalse(result['work_removed'])
            control.socket.close.assert_called_once()

    def test_cli_no_optin_cannot_execute(self):
        with patch.object(gate,'run_actual') as actual:
            with self.assertRaises(SystemExit):gate.main(['--output','unused.json'])
            actual.assert_not_called()

if __name__=='__main__':unittest.main()
