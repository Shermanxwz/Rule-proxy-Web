"""Pure hosted-gate contracts, fake processes only; actual Windows is opt-in."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_request3_gate',ROOT/'.github/test_windows_dns_request3.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
def report(pending=False):
    return dict(schema=1,test_only=True,request_version=3,custom_server_count=1,custom_udp=True,custom_flags_zero=True,legacy_server_list_null=True,callback_null=True,api_called=not pending,pending=pending,api_status=9506 if pending else 0,result_status=None if pending else 0,record_count=None if pending else 1,answer_match=not pending,records_freed=not pending,context_retained=pending,runtime_acceptance=False)
def raw(value):return json.dumps(value).encode()
class Contracts(unittest.TestCase):
    def test_native_completed_and_injected_pending_exact_shape(self):
        for pending in (True,False):self.assertEqual(g.native_report(raw(report(pending))),report(pending))
    def test_no_type_coercion_unknown_duplicate_nested_and_raw_sentinel(self):
        for field,value in [('schema',True),('api_status',True),('record_count',18),('answer_match',1),('runtime_acceptance',True),('context_retained',True),('unknown','PRIVATE')]:
            r=report();r[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):g.native_report(raw(r))
        for value in (b'{"schema":1,"schema":1}',b'['*1100+b']'*1100,b'X'*4097,b'\xff'):
            with self.assertRaises(ValueError):g.native_report(value)
    def test_pending_must_retain_and_not_free_or_claim_answer(self):
        for key,value in [('records_freed',True),('answer_match',True),('context_retained',False),('api_status',0),('result_status',0)]:
            r=report(True);r[key]=value
            with self.assertRaises(ValueError):g.native_report(raw(r))
    def test_failed_api_still_valid_observation_not_success(self):
        r=report();r.update(api_status=9003,result_status=9003,record_count=0,answer_match=False,records_freed=False)
        self.assertFalse(g.native_report(raw(r))['answer_match'])
    def test_manifest_production_or_bad_pin_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);actor=root/'windows_n0a_DNS_TEST_ONLY_fixture.exe';actor.write_bytes(b'fixture')
            manifest=root/'DNS-TEST-ONLY-manifest.json'
            value=dict(schemaVersion=1,testOnly=True,deployable=False,compileOnly=True,requestVersion=3,customServerType='UDP',installedSdkVersion='10.0.26100.0',sourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_dns_fixture.cpp').read_bytes()).hexdigest(),sdkHeaders=[dict(name=name,sha256='a'*64) for name in ('windns.h','windnsdef.h','ws2ipdef.h','ws2tcpip.h')],executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            manifest.write_bytes(raw(value));self.assertTrue(g.verify(actor,manifest))
            for key,bad in [('testOnly',False),('deployable',True),('sourceSha256','0'*64),('executableSha256','0'*64),('requestVersion',True)]:
                changed=dict(value);changed[key]=bad;manifest.write_bytes(raw(changed))
                with self.assertRaises(ValueError):g.verify(actor,manifest)
    def test_off_platform_does_not_launch(self):
        with patch.object(g.os,'name','posix'),patch.object(g.subprocess,'Popen') as launch:
            result=g.run(Path('actor'),Path('manifest'))
        launch.assert_not_called();self.assertEqual(result['failure'],'platform');self.assertFalse(result['mechanism_positive'])
    def test_output_error_is_closed_without_private_path_traceback(self):
        import io
        output=io.StringIO()
        with patch('sys.argv',['gate','--run-actual-windows','--actor','actor','--manifest','manifest','--output','PRIVATE']),patch.object(g,'run',return_value=dict(mechanism_positive=False)),patch.object(Path,'write_text',side_effect=OSError('PRIVATE_SENTINEL')),patch('sys.stdout',output):
            self.assertEqual(g.main(),1)
        value=json.loads(output.getvalue());self.assertEqual(value['failure'],'output');self.assertNotIn('PRIVATE',output.getvalue())
    def test_nrpt_readonly_effective_closed_token(self):
        self.assertIn('Get-DnsClientNrptPolicy -Effective -ErrorAction Stop',g.NRPT_SCRIPT)
        self.assertIn('Select-Object -First 1',g.NRPT_SCRIPT)
        self.assertNotIn('Format-',g.NRPT_SCRIPT);self.assertNotIn('Set-',g.NRPT_SCRIPT)
    def test_native_uses_official_sdk_no_default_fallback_and_pending_retention(self):
        source=(ROOT/'.github/native/windows_n0a_dns_fixture.cpp').read_text()
        build=(ROOT/'.github/build_windows_n0a_dns_fixture.ps1').read_text()
        for text in ('DNS_QUERY_REQUEST3','DNS_CUSTOM_SERVER','DNS_QUERY_REQUEST_VERSION3','retainedPendingContext = context.release()','for (;;) Sleep(INFINITE)','N0A_DNS_TEST_ONLY'):self.assertIn(text,source)
        self.assertLess(source.index('#include <ws2tcpip.h>'),source.index('#include <windns.h>'))
        self.assertNotIn('DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE',source)
        self.assertIn('N0A_DNS_TEST_ONLY=1',build)
        self.assertIn('DNS-TEST-ONLY-manifest.json',build)
class ChildTests(unittest.TestCase):
    def test_owned_before_spawn_failure_and_output_create_new(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=g.Child(Path(tmp),'test')
            with patch.object(g.subprocess,'Popen',side_effect=OSError('PRIVATE')):
                with self.assertRaises(OSError):c.start(['fixture'])
            self.assertIsNotNone(c.stream);self.assertTrue(c.finish(g.time.monotonic()+1)['cleanup_confirmed'])
            with self.assertRaises(FileExistsError):c.start(['fixture'])
    def test_exact_kill_absolute_wait_unknown_exit_handle_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=g.Child(Path(tmp),'test');p=Mock();p.poll.return_value=None;p.wait.side_effect=OSError('PRIVATE');c.process=p
            with patch.object(g.time,'monotonic',return_value=59):result=c.finish(60)
            p.kill.assert_called_once_with();p.wait.assert_called_once_with(timeout=1)
            p._handle.Close.assert_not_called();self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['handles_closed'])
    def test_exited_process_not_killed_and_handle_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=g.Child(Path(tmp),'test');p=Mock();p.poll.return_value=0;c.process=p
            result=c.finish(0);p.kill.assert_not_called();p._handle.Close.assert_called_once_with();self.assertTrue(result['cleanup_confirmed'])
    def test_pending_report_observed_while_process_alive_then_exact_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=g.Child(Path(tmp),'test');c.path.write_bytes(raw(report(True))+b'\n');p=Mock();p.poll.side_effect=[None,None,0];c.process=p
            with patch.object(g.time,'monotonic',return_value=1):self.assertFalse(c.wait(3,pending=True));result=c.finish(4)
            self.assertTrue(result['killed']);self.assertTrue(result['exited']);p.wait.assert_called_once_with(timeout=3)
    def test_poll_or_kill_error_never_skips_remaining_owned_observation(self):
        for error_kind in ('poll','kill'):
            with tempfile.TemporaryDirectory() as tmp:
                c=g.Child(Path(tmp),'test');p=Mock();c.process=p
                p.poll.side_effect=[OSError('PRIVATE') if error_kind=='poll' else None,0]
                if error_kind=='kill':p.kill.side_effect=OSError('PRIVATE')
                with patch.object(g.time,'monotonic',return_value=59):result=c.finish(60)
                p.kill.assert_called_once_with();p.wait.assert_called_once_with(timeout=1)
                self.assertTrue(result['exited']);self.assertFalse(result['cleanup_confirmed'])
    def test_output_bound_does_not_parse_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            c=g.Child(Path(tmp),'test');c.path.write_bytes(b'x'*4097);c.process=Mock()
            with self.assertRaises(ValueError):c.wait(g.time.monotonic()+1)
            with self.assertRaises(ValueError):g.read_bounded(c.path)
class CompositionTests(unittest.TestCase):
    def exercise(self, *, api_error=False, unknown=False, nrpt=b'NRPT_EMPTY'):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        fixture=Mock();fixture.start.return_value=45000;fixture.query_observed.is_set.return_value=True
        fixture.finish.return_value=dict(cleanup_confirmed=not unknown,counts=dict(matched_queries=1,answers_sent=1,rejected=0,oversized=0,send_failed=0),error='none')
        module=Mock();module.DnsFixture.return_value=fixture
        spec=Mock();spec.loader.exec_module=lambda value:None
        children=[]
        class FakeChild:
            def __init__(self,root,name):self.name=name;self.path=root/(name+'.out');self.process=Mock();self.process.returncode=0;children.append(self)
            def start(self,argv):
                value=report(self.name=='pending')
                if api_error and self.name=='query':value.update(api_status=9003,result_status=9003,record_count=0,answer_match=False,records_freed=False)
                self.path.write_bytes(nrpt if self.name=='nrpt' else raw(value)+b'\n')
                self.process.poll.return_value=None if self.name=='pending' else 0
            def wait(self,deadline,**kwargs):return self.name!='pending'
            def finish(self,deadline):return dict(exited=not unknown,killed=self.name=='pending',handles_closed=not unknown,cleanup_confirmed=not unknown)
        # Patch the module's OS reference rather than global os.name (Path uses it).
        with patch.object(g,'os',Mock(name='nt')) as fake_os,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(Path(temp.name)/'owned')),patch.object(g.importlib.util,'spec_from_file_location',return_value=spec),patch.object(g.importlib.util,'module_from_spec',return_value=module):
            fake_os.name='nt';(Path(temp.name)/'owned').mkdir()
            result=g.run(Path('actor'),Path('manifest'))
        return result,fixture,children
    def test_actual_shaped_positive_and_injected_pending_are_separate(self):
        result,fixture,children=self.exercise()
        self.assertTrue(result['mechanism_positive']);self.assertTrue(result['injected_pending_control'])
        self.assertEqual(len(children),3);self.assertTrue(result['work_removed'])
        self.assertFalse(result['runtime_acceptance']);self.assertFalse(result['broker_cancellation_proven'])
    def test_api_error_and_cleanup_unknown_do_not_erase_query_observation(self):
        for kwargs in (dict(api_error=True),dict(unknown=True)):
            result,_,_=self.exercise(**kwargs)
            self.assertTrue(result['query_observed']);self.assertFalse(result['mechanism_positive'])
            if kwargs.get('unknown'):self.assertFalse(result['work_removed']);self.assertFalse(result['cleanup_confirmed'])
    def test_nrpt_present_prevents_socket_or_api_start(self):
        result,fixture,children=self.exercise(nrpt=b'NRPT_PRESENT')
        self.assertEqual(result['failure'],'nrpt');self.assertEqual(len(children),1);fixture.start.assert_not_called()

if __name__=='__main__':unittest.main()
