import importlib.util
import json
import re
from pathlib import Path
import socket
import tempfile
import types
import unittest
from unittest.mock import Mock, patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('serviced_diagnostics',ROOT/'.github/windows_identity_serviced_stage0.py')
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)


class EarlySerialTests(unittest.TestCase):
    def diagnostic(self):
        return dict(schema=1,phase='installed_boot_gate',operation='gate',failure_category='installed_boot_gate',
                    hresult=-2146233087,gates={key:None for key in host.EARLY_GATES})
    def line(self, value=None):
        return 'RPDIAG1 '+json.dumps(self.diagnostic() if value is None else value,separators=(',',':'))+'\r\n'
    def test_exact_fragmented_payload_survives_over256_bytes(self):
        raw=self.line();self.assertGreater(len(raw),256);observer=host.EarlyGuestSerial();result=None
        for i in range(0,len(raw),7):
            value=observer.feed(raw[i:i+7])
            if value is not None:result=value
        self.assertEqual(result,self.diagnostic());self.assertEqual(observer.pending,'')
    def test_fatal_is_observation_only_and_revokes_pass(self):
        public={'stage0_passed':True}
        with self.assertRaises(host.EarlyGuestFailure):host.observe_guest_serial(public,host.EarlyGuestSerial(),self.line())
        self.assertFalse(public['stage0_passed']);self.assertEqual(public['host_wait_failure'],'guest_launcher_failure')
        self.assertEqual(set(public),{'stage0_passed','early_guest_diagnostic','host_wait_failure'})
    def test_post_network_failure_retains_diagnostic_without_interrupting_http(self):
        public={'stage0_passed':True}
        host.observe_guest_serial(public,host.EarlyGuestSerial(),self.line(),fail_fast=False)
        self.assertFalse(public['stage0_passed'])
        self.assertEqual(public['early_guest_diagnostic'],self.diagnostic())
        self.assertEqual(set(public),{'stage0_passed','early_guest_diagnostic','host_wait_failure'})
    def test_guest_protocol_enum_parity(self):
        source=(ROOT/'.github/windows-identity-serviced-stage0-run.ps1').read_text()
        block=source.split('function Get-ClosedEarlyDiagnostic {',1)[1].split('function ',1)[0]
        def values(name):
            match=re.search(r'\$'+name+r'=\s*@\((.*?)\)',block,re.S)
            self.assertIsNotNone(match,name)
            return set(re.findall(r"'([^']*)'",match.group(1)))
        self.assertEqual(values('phases'),set(host.LAUNCHER_PHASES)-{'not_observed','stock_build'})
        self.assertEqual(values('operations'),set(host.EARLY_OPERATIONS))
        self.assertEqual(values('categories'),set(host.LAUNCHER_FAILURES))
    def test_serial_failure_cannot_be_replaced_by_later_success(self):
        public={'early_guest_diagnostic':self.diagnostic(),'stage0_passed':True}
        with patch.object(host,'project_stage0',return_value={key:{} for key in ('diagnostics','guest_diagnostic','launcher_diagnostic','servicing_diagnostic')}), patch.object(host,'validate_guest',return_value={'stage0_passed':True}) as validate:
            with self.assertRaises(host.EarlyGuestFailure):
                host.merge_serviced_result(public,{},'a'*64,True)
            validate.assert_not_called()
        self.assertFalse(public['stage0_passed'])
        self.assertIn('servicing_diagnostic',public)
    def test_setup_wait_failure_is_accepted(self):
        value=self.diagnostic();value.update(phase='installed_setup_wait',operation='waiting_setup',failure_category='installed_setup_deadline')
        self.assertEqual(host.parse_early_guest(self.line(value).strip()),value)
    def test_reject_extra_missing_wrong_types_and_enum(self):
        for key,bad in [('schema',True),('schema',2),('phase','SECRET'),('operation','SECRET'),('failure_category','SECRET'),('hresult',True),('hresult',2**31)]:
            value=self.diagnostic();value[key]=bad
            self.assertIsNone(host.parse_early_guest(self.line(value).strip()))
        value=self.diagnostic();value['SECRET']='SECRET';self.assertIsNone(host.parse_early_guest(self.line(value).strip()))
        value=self.diagnostic();del value['hresult'];self.assertIsNone(host.parse_early_guest(self.line(value).strip()))
        for bad in (1,'true',[],{}):
            value=self.diagnostic();value['gates']['fixed_drive']=bad
            self.assertIsNone(host.parse_early_guest(self.line(value).strip()))
        value=self.diagnostic();value['gates']['SECRET']=True;self.assertIsNone(host.parse_early_guest(self.line(value).strip()))
    def test_all_gate_tristates_preserved(self):
        for state in (True,False,None):
            value=self.diagnostic();value['gates']={key:state for key in host.EARLY_GATES}
            self.assertEqual(host.parse_early_guest(self.line(value).strip()),value)
    def test_duplicate_keys_rejected(self):
        raw=self.line().strip().replace('"schema":1','"schema":1,"schema":1')
        self.assertIsNone(host.parse_early_guest(raw))
    def test_oversize_line_discarded_until_newline(self):
        observer=host.EarlyGuestSerial()
        self.assertIsNone(observer.feed('RPDIAG1 '+('x'*4000)))
        self.assertTrue(observer.dropping);self.assertEqual(observer.pending,'')
        self.assertIsNone(observer.feed(self.line()))
        self.assertEqual(observer.feed(self.line()),self.diagnostic())
    def test_unknown_serial_not_exported_and_partial_boundary(self):
        observer=host.EarlyGuestSerial();public={}
        host.observe_guest_serial(public,observer,'SECRET RAW\n')
        self.assertEqual(public,{})
        self.assertIsNone(observer.feed(self.line()[:-1]));self.assertEqual(observer.feed('\n'),self.diagnostic())
    def test_nonascii_and_nonstring_chunks_rejected(self):
        value=self.diagnostic();value['phase']='秘密'
        self.assertIsNone(host.parse_early_guest('RPDIAG1 '+json.dumps(value,ensure_ascii=False)))
        observer=host.EarlyGuestSerial();self.assertIsNone(observer.feed(None));self.assertTrue(observer.dropping)
    def test_brokenpipe_class_retained_without_text(self):
        result=host.closed_failure(BrokenPipeError(32,'SECRET'))
        self.assertEqual(result['type'],'BrokenPipeError');self.assertEqual(result['errno'],32)
        self.assertNotIn('SECRET',json.dumps(result))


class IndependentCleanupFactsTests(unittest.TestCase):
    def test_absent_resources_not_attempted_and_work_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'work';work.mkdir();facts=host.new_teardown_facts()
            self.assertTrue(host.cleanup_owned(Mock(),work,diagnostics=facts))
            self.assertIsNone(facts['qmp_close_succeeded']);self.assertIsNone(facts['qemu_exit_confirmed'])
            self.assertIsNone(facts['server_close_succeeded']);self.assertTrue(facts['work_removed'])
            self.assertTrue(facts['work_remove_attempted']);self.assertEqual(facts['error_count'],0)
    @unittest.skipUnless(host.sys.platform == 'linux', 'Linux buffered socket errno32 reproduction')
    def test_actual_buffered_epipe_still_closes_socket_but_not_acceptance(self):
        left,right=socket.socketpair();file=left.makefile('rwb');right.close()
        class Qmp:
            def __init__(self):self.file=file;self.socket=left
            def close(self):self.file.close();self.socket.close()
        try:
            file.write(b'pending request\n')
            with self.assertRaises(BrokenPipeError):file.flush()
            with tempfile.TemporaryDirectory() as directory:
                work=Path(directory)/'work';work.mkdir();facts=host.new_teardown_facts()
                self.assertFalse(host.cleanup_owned(Mock(),work,qmp=Qmp(),diagnostics=facts))
                self.assertFalse(facts['qmp_close_succeeded']);self.assertTrue(facts['qmp_file_closed'])
                self.assertTrue(facts['qmp_socket_closed']);self.assertTrue(facts['work_removed'])
                self.assertEqual(facts['first_failed_stage'],'qmp_close')
                self.assertEqual(facts['errors'][0]['type'],'BrokenPipeError');self.assertEqual(facts['errors'][0]['errno'],32)
        finally:
            try:file.close()
            except OSError:pass
            left.close()
    @unittest.skipUnless(host.sys.platform == 'linux', 'Linux-only finalizer requires SIGXFSZ')
    def test_failed_server_close_distinct_from_vm_exit_and_work_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'work';work.mkdir();qemu=Mock();qemu.poll.return_value=0
            server=Mock();server.server_close.side_effect=OSError(5,'SECRET');thread=Mock();thread.is_alive.return_value=False
            public={'stage0_passed':True,'status':'passed'}
            host.finalize_owned(public,Mock(),work,qemu=qemu,server=server,thread=thread)
            facts=public['teardown_diagnostic'];self.assertFalse(public['vm_destroyed']);self.assertFalse(public['stage0_passed'])
            self.assertTrue(facts['qemu_exit_confirmed']);self.assertEqual(facts['qemu_exit_before_cleanup'],0)
            self.assertTrue(facts['server_shutdown_succeeded']);self.assertFalse(facts['server_close_succeeded'])
            self.assertTrue(facts['server_thread_stopped']);self.assertTrue(facts['work_removed'])
            self.assertNotIn('SECRET',json.dumps(public))
    def test_qmp_close_success_without_confirmed_handles_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'work';work.mkdir();qmp=Mock();qmp.file.closed=False;qmp.socket.fileno.return_value=3
            facts=host.new_teardown_facts()
            self.assertFalse(host.cleanup_owned(Mock(),work,qmp=qmp,diagnostics=facts))
            self.assertTrue(facts['qmp_close_succeeded']);self.assertFalse(facts['qmp_file_closed'])
            self.assertFalse(facts['qmp_socket_closed']);self.assertTrue(facts['work_removed'])
    def test_work_delete_failure_not_hidden(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'work';work.mkdir();facts=host.new_teardown_facts()
            with patch.object(host.shutil,'rmtree',side_effect=PermissionError(13,'SECRET')):
                self.assertFalse(host.cleanup_owned(Mock(),work,diagnostics=facts))
            self.assertFalse(facts['work_removed']);self.assertEqual(facts['first_failed_stage'],'work_remove')
    def test_live_thread_retains_work(self):
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory)/'work';work.mkdir();facts=host.new_teardown_facts();thread=Mock();thread.is_alive.return_value=True
            self.assertFalse(host.cleanup_owned(Mock(),work,thread=thread,diagnostics=facts))
            self.assertFalse(facts['server_thread_stopped']);self.assertTrue(facts['work_retained'])
            self.assertFalse(facts['work_remove_attempted']);self.assertFalse(facts['work_removed'])
    def test_error_list_bounded_and_closed(self):
        facts=host.new_teardown_facts()
        for _ in range(20):host.teardown_error(facts,'SECRET',RuntimeError('SECRET'))
        self.assertEqual(facts['error_count'],20);self.assertEqual(len(facts['errors']),8)
        self.assertNotIn('SECRET',json.dumps(facts))

if __name__=='__main__':unittest.main()
