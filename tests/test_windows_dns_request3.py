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
    return dict(schema=1,test_only=True,request_version=3,custom_server_count=1,custom_udp=True,custom_flags_zero=True,legacy_server_list_null=True,callback_null=True,api_called=not pending,pending=pending,api_status=9506 if pending else 0,result_status=None if pending else 0,record_count=None if pending else 1,answer_match=not pending,records_freed=not pending,context_retained=pending,runtime_acceptance=False,cancellation_handle_null=False,custom_port53=False,endpoint_kind='none' if pending else 'high_port',endpoint_address_kind='loopback1')
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
    def exercise(self, *, api_error=False, unknown=False, nrpt=b'NRPT_EMPTY', baseline_pending=False, statuses=None):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        fixture=Mock();fixture.start.return_value=45000;fixture.query_observed.is_set.return_value=True
        fixture.snapshot.side_effect=lambda **kwargs:dict(fixture.counts)
        fixture.counts=dict(datagrams=0,bytes=0,matched_queries=0,answers_sent=0,rejected=0,oversized=0,send_failed=0);fixture.error='none'
        fixture.finish.return_value=dict(cleanup_confirmed=not unknown,counts=dict(matched_queries=1,answers_sent=1,rejected=0,oversized=0,send_failed=0),error='none')
        module=Mock();module.DnsFixture.return_value=fixture
        spec=Mock();spec.loader.exec_module=lambda value:None
        children=[]
        class FakeChild:
            def __init__(self,root,name):self.name=name;self.path=root/(name+'.out');self.process=Mock();self.process.returncode=0;children.append(self)
            def start(self,argv):
                self.argv=argv
                value=report(self.name=='pending' or (baseline_pending and self.name=='baseline'));value['cancellation_handle_null']=self.name=='null_cancel'
                if statuses and self.name in statuses and statuses[self.name]!=0:value.update(api_status=statuses[self.name],result_status=statuses[self.name],record_count=0,answer_match=False,records_freed=False)
                if api_error and self.name in ('baseline','null_cancel'):value.update(api_status=9003,result_status=9003,record_count=0,answer_match=False,records_freed=False)
                self.path.write_bytes(nrpt if self.name=='nrpt' else raw(value)+b'\n')
                if self.name in ('baseline','null_cancel') and not (statuses and statuses.get(self.name,0)!=0):
                    fixture.counts['matched_queries']+=1;fixture.counts['answers_sent']+=1
                self.process.poll.return_value=None if self.name=='pending' or (baseline_pending and self.name=='baseline') else 0
            def wait(self,deadline,**kwargs):return self.name!='pending' and not (baseline_pending and self.name=='baseline')
            def finish(self,deadline):return dict(exited=not unknown,killed=self.name=='pending',handles_closed=not unknown,cleanup_confirmed=not unknown)
        # Patch the module's OS reference rather than global os.name (Path uses it).
        with patch.object(g,'os',Mock(name='nt')) as fake_os,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(Path(temp.name)/'owned')),patch.object(g.importlib.util,'spec_from_file_location',return_value=spec),patch.object(g.importlib.util,'module_from_spec',return_value=module):
            fake_os.name='nt';(Path(temp.name)/'owned').mkdir()
            result=g.run(Path('actor'),Path('manifest'))
        return result,fixture,children
    def test_actual_shaped_positive_and_injected_pending_are_separate(self):
        result,fixture,children=self.exercise()
        self.assertTrue(result['mechanism_positive']);self.assertTrue(result['injected_pending_control'])
        self.assertEqual(len(children),4);self.assertTrue(result['work_removed'])
        self.assertFalse(result['runtime_acceptance']);self.assertFalse(result['broker_cancellation_proven'])
    def test_api_error_and_cleanup_unknown_do_not_erase_query_observation(self):
        for kwargs in (dict(api_error=True),dict(unknown=True)):
            result,_,_=self.exercise(**kwargs)
            self.assertTrue(result['query_observed']);self.assertFalse(result['mechanism_positive'])
            if kwargs.get('unknown'):self.assertFalse(result['work_removed']);self.assertFalse(result['cleanup_confirmed'])
    def test_controlled_87_then_success_and_both87_no_fallback(self):
        for null_status in (0,87):
            result,_,children=self.exercise(statuses={'baseline':87,'null_cancel':null_status})
            baseline=result['cases']['baseline'];null=result['cases']['null_cancel']
            self.assertEqual(baseline['api_report']['api_status'],87)
            self.assertEqual(baseline['receiver_delta']['matched_queries'],0);self.assertFalse(baseline['positive'])
            self.assertEqual(null['api_report']['api_status'],null_status)
            self.assertEqual(null['receiver_delta']['matched_queries'],int(null_status==0))
            self.assertEqual(result['mechanism_positive'],null_status==0)
            self.assertEqual([c.name for c in children],['nrpt','baseline','null_cancel','pending'])
    def test_pair_same_endpoint_nonce_fresh_children_and_no_second_after_pending(self):
        result,fixture,children=self.exercise()
        self.assertEqual(children[1].argv[2:],children[2].argv[2:])
        self.assertEqual(children[1].argv[1],'--query');self.assertEqual(children[2].argv[1],'--query-null-cancel')
        fixture.start.assert_called_once_with()
        for case in result['cases'].values():self.assertEqual(case['receiver_delta']['matched_queries'],1)
        result,_,children=self.exercise(baseline_pending=True)
        self.assertEqual(len(children),2);self.assertNotIn('null_cancel',result['cases']);self.assertEqual(result['failure'],'pair_incomplete')
        result,_,children=self.exercise(unknown=True)
        self.assertEqual(len(children),2);self.assertNotIn('null_cancel',result['cases'])
    def test_nrpt_present_prevents_socket_or_api_start(self):
        result,fixture,children=self.exercise(nrpt=b'NRPT_PRESENT')
        self.assertEqual(result['failure'],'nrpt');self.assertEqual(len(children),1);fixture.start.assert_not_called()

def descriptor():
    return dict(schema=1,test_only=True,mode='describe',api_called=False,runtime_acceptance=False,
        layout={key:[0]*count for key,count in g.DESCRIBE_LAYOUT.items()},
        initialized={key:False for key in g.DESCRIBE_INITIALIZED},module_existing=True,
        system_path_verified=True,version_available=True,dnsapi_file_version=[10,0,26100,1])
class DescribeTests(unittest.TestCase):
    def test_exact_closed_observations_not_layout_acceptance(self):
        value=descriptor();self.assertEqual(g.describe_report(raw(value)),value)
        value.update(version_available=False,dnsapi_file_version=None,system_path_verified=False)
        self.assertEqual(g.describe_report(raw(value)),value)
    def test_reject_extra_raw_values_bool_numbers_and_shape(self):
        for mutate in [lambda v:v.update(raw_path='PRIVATE'),lambda v:v.update(api_called=True),lambda v:v['layout']['sizes'].append(1),lambda v:v['layout']['sizes'].__setitem__(0,True),lambda v:v['initialized'].update(ipv4=1),lambda v:v.update(dnsapi_file_version=[1,2,3,65536]),lambda v:v.update(version_available=False)]:
            value=descriptor();mutate(value)
            with self.assertRaises(ValueError):g.describe_report(raw(value))
    def test_only_describe_child_and_unknown_cleanup_retains_work(self):
        for unknown in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'owned';root.mkdir();calls=[]
                class FakeChild:
                    def __init__(self,root,name):self.path=root/'describe.out';self.process=Mock(returncode=0)
                    def start(self,argv):calls.append(argv);self.path.write_bytes(raw(descriptor()))
                    def wait(self,deadline):return True
                    def finish(self,deadline):return dict(cleanup_confirmed=not unknown,exited=not unknown,handles_closed=not unknown,killed=False)
                with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g,'run',side_effect=AssertionError('query dispatch')),patch.object(g.importlib.util,'module_from_spec',side_effect=AssertionError('fixture import')):
                    fakeos.name='nt';result=g.run_describe(Path('actor'),Path('manifest'))
                self.assertEqual(calls,[['actor','--describe']]);self.assertEqual(result['diagnostics_complete'],not unknown)
                self.assertEqual(root.exists(),unknown);self.assertFalse(result['api_called'])
    def test_cli_dispatch_is_explicit_mutually_exclusive(self):
        import io
        output=io.StringIO()
        with patch('sys.argv',['gate','--run-no-query-diagnostics','--actor','actor','--manifest','manifest','--output','out']),patch.object(g,'run',side_effect=AssertionError('query')),patch.object(g,'run_describe',return_value=dict(diagnostics_complete=True)) as describe,patch.object(Path,'write_text'),patch('sys.stdout',output):
            self.assertEqual(g.main(),0);describe.assert_called_once()
        with patch('sys.argv',['gate','--run-no-query-diagnostics','--run-actual-windows','--actor','a','--manifest','m','--output','o']),patch('sys.stderr',io.StringIO()),self.assertRaises(SystemExit):g.main()

class PortPairTests(unittest.TestCase):
    def exercise(self,control_failure=None,unknown_cleanup=None,misroute=False,second_timeout=False,bind_error=False,statuses=None):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'owned';root.mkdir();children=[];fixtures={}
            for name in ('high_port','standard_port'):
                f=Mock();f.counts=dict(datagrams=0,bytes=0,matched_queries=0,answers_sent=0,rejected=0,oversized=0,send_failed=0)
                f.snapshot.side_effect=lambda f=f,**kwargs:dict(f.counts)
                f.start.return_value=45000 if name=='high_port' else 53
                f.finish.return_value=dict(cleanup_confirmed=True,error='none',counts=f.counts)
                f.query_observed.is_set.side_effect=lambda f=f:f.counts['matched_queries']>0
                fixtures[name]=f
            if bind_error:fixtures['standard_port'].start.side_effect=OSError('PRIVATE collision')
            module=Mock();module.DnsFixture.return_value=fixtures['high_port'];module.DnsFixture.for_port53.return_value=fixtures['standard_port']
            spec=Mock();spec.loader.exec_module=lambda value:None
            class FakeChild:
                def __init__(self,root,name):self.name=name;self.path=root/(name+'.out');self.process=Mock(returncode=0);children.append(self)
                def start(self,argv):
                    self.argv=argv
                    if self.name in ('nrpt','preflight','ownership'):
                        token={'nrpt':b'NRPT_EMPTY','preflight':b'UDP53_EMPTY','ownership':b'UDP53_OWNED'}[self.name]
                        self.path.write_bytes(b'UNCONFIRMED' if control_failure==self.name else token)
                    else:
                        value=report();value['endpoint_kind']=self.name;value['custom_port53']=self.name=='standard_port'
                        if statuses and statuses.get(self.name,0)!=0:value.update(api_status=statuses[self.name],result_status=statuses[self.name],record_count=0,answer_match=False,records_freed=False)
                        self.path.write_bytes(raw(value))
                        target='standard_port' if misroute and self.name=='high_port' else self.name
                        if not statuses or statuses.get(self.name,0)==0:
                            for key in ('datagrams','bytes','matched_queries','answers_sent'):fixtures[target].counts[key]+=1
                def wait(self,deadline,**kwargs):return not(second_timeout and self.name=='standard_port')
                def finish(self,deadline):return dict(exited=unknown_cleanup!=self.name,killed=False,handles_closed=unknown_cleanup!=self.name,cleanup_confirmed=unknown_cleanup!=self.name)
            with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g.importlib.util,'spec_from_file_location',return_value=spec),patch.object(g.importlib.util,'module_from_spec',return_value=module):
                fakeos.name='nt';fakeos.getpid.return_value=1234;result=g.run_port_pair(Path('actor'),Path('manifest'))
            retained=root.exists()
            return result,children,fixtures,retained
    def test_both_owned_before_api_same_nonce_fixed53_and_crossendpoint_deltas(self):
        result,children,fixtures,_=self.exercise()
        self.assertTrue(result['pair_complete']);self.assertTrue(result['mechanism_positive'])
        self.assertEqual([c.name for c in children],['nrpt','preflight','ownership','high_port','standard_port'])
        self.assertEqual(children[3].argv[2],children[4].argv[2]);self.assertEqual(children[4].argv[1],'--query-port53');self.assertEqual(len(children[4].argv),3)
        for case in result['cases'].values():self.assertEqual(set(case['receiver_delta']),{'high_port','standard_port'})
    def test_busy_unknown_or_control_cleanup_failure_refuses_api(self):
        for stage in ('nrpt','preflight','ownership'):
            for kwargs in ({'control_failure':stage},{'unknown_cleanup':stage}):
                result,children,_,_=self.exercise(**kwargs)
                self.assertEqual(result['cases'],{});self.assertFalse(result['mechanism_positive'])
                self.assertNotIn('high_port',[c.name for c in children])
    def test_bind_collision_cleanup_and_misroute_not_expected_positive(self):
        result,children,fixtures,_=self.exercise(bind_error=True)
        self.assertEqual(result['cases'],{});fixtures['high_port'].finish.assert_called_once();fixtures['standard_port'].finish.assert_called_once()
        result,_,_,_=self.exercise(misroute=True)
        self.assertFalse(result['mechanism_positive'])
        case=result['cases']['high_port'];self.assertTrue(case['other_endpoint_observed']);self.assertFalse(case['positive']);self.assertEqual(case['receiver_delta']['standard_port']['matched_queries'],1)
    def test_partial_second_case_never_overall_success_preserves_first(self):
        result,_,_,_=self.exercise(second_timeout=True)
        self.assertTrue(result['cases']['high_port']['positive']);self.assertFalse(result['pair_complete']);self.assertFalse(result['mechanism_positive']);self.assertTrue(result['query_observed'])
    def test_both87_zero_queries_stops_at_exact_pair(self):
        result,children,_,_=self.exercise(statuses={'high_port':87,'standard_port':87})
        self.assertTrue(result['pair_complete']);self.assertFalse(result['mechanism_positive']);self.assertFalse(result['query_observed'])
        self.assertEqual(len(children),5)
        for case in result['cases'].values():self.assertEqual(case['api_report']['api_status'],87)
    def test_ownership_script_is_readonly_exact_pid_no_policy_output(self):
        pre=g.ownership_script(False,1234);post=g.ownership_script(True,1234)
        self.assertIn('Get-NetUDPEndpoint -ErrorAction Stop',pre);self.assertIn('$_.LocalPort -eq 53',pre)
        self.assertIn("LocalAddress -ceq '127.0.0.1'",post);self.assertIn('OwningProcess -eq 1234',post)
        for pid in (True,'1234',0,-1):
            with self.assertRaises(ValueError):g.ownership_script(True,pid)

class PreflightOnlyTests(unittest.TestCase):
    def test_exact_pipeline_retained_and_tokens_closed(self):
        pipeline='Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53} | Select-Object -First 2'
        self.assertIn(pipeline,g.ownership_script(False,1234));self.assertIn(pipeline,g.PREFLIGHT_SCRIPT)
        self.assertNotIn('SilentlyContinue',g.PREFLIGHT_SCRIPT)
        for count in range(3):self.assertEqual(g.preflight_token(('UDP53_COUNT_'+str(count)).encode())['matches_capped_at_two'],count)
        self.assertEqual(g.preflight_token(b'UDP53_ENUMERATION_ERROR_other')['status'],'enumeration_error')
        for value in (b'',b'UDP53_ENUMERATION_ERROR_PRIVATE',b'UDP53_ENUMERATION_ERROR',b'UDP53_COUNT_3',b'UDP53_COUNT_0\n',b'PRIVATE',b'x'*4097):
            with self.assertRaises(ValueError):g.preflight_token(value)
    def test_error_class_allowlist_never_emits_raw_exception_name(self):
        for name in ('CimException','CimJobException','CommandNotFoundException','UnauthorizedAccessException','other'):
            result=g.preflight_token(('UDP53_ENUMERATION_ERROR_'+name).encode())
            self.assertEqual(result['enumeration_error_class'],name)
        self.assertIsNone(g.preflight_token(b'UDP53_COUNT_0')['enumeration_error_class'])
        self.assertIn("$kind='other'",g.PREFLIGHT_SCRIPT)
        self.assertNotIn('.Message',g.PREFLIGHT_SCRIPT);self.assertNotIn('FullyQualifiedErrorId',g.PREFLIGHT_SCRIPT)
    def exercise(self,raw_output,exit_code,ended=True,clean=True):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'owned';root.mkdir();calls=[]
            class FakeChild:
                def __init__(self,root,name):self.path=root/'preflight.out';self.process=Mock();self.process.poll.return_value=exit_code
                def start(self,argv):calls.append(argv);self.path.write_bytes(raw_output)
                def wait(self,deadline):return ended
                def finish(self,deadline):return dict(exited=clean,killed=not ended,handles_closed=clean,cleanup_confirmed=clean)
            with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g.importlib.util,'module_from_spec',side_effect=AssertionError('fixture')):
                fakeos.name='nt';result=g.run_preflight_only(Path('actor'),Path('manifest'))
            self.assertEqual(len(calls),1);self.assertEqual(calls[0][0],'powershell.exe');self.assertEqual(calls[0][-1],g.PREFLIGHT_SCRIPT)
            self.assertFalse(result['api_called']);self.assertFalse(result['bind_attempted']);self.assertNotIn('PRIVATE',json.dumps(result))
            self.assertEqual(root.exists(),not clean)
            return result
    def test_successful_zero_nonzero_and_capped_counts_do_not_bind(self):
        for count in range(3):
            result=self.exercise(('UDP53_COUNT_'+str(count)).encode(),0)
            self.assertTrue(result['enumeration_success']);self.assertTrue(result['diagnostics_complete'])
            self.assertEqual(result['matches_capped_at_two'],count);self.assertEqual(result['status'],'empty' if count==0 else 'present')
    def test_error_timeout_nonzero_parse_unknown_and_cleanup_distinct(self):
        result=self.exercise(b'UDP53_ENUMERATION_ERROR_other',2)
        self.assertEqual(result['status'],'enumeration_error');self.assertEqual(result['child_exit_code'],2);self.assertTrue(result['diagnostics_complete']);self.assertFalse(result['enumeration_success'])
        result=self.exercise(b'UDP53_COUNT_0',7)
        self.assertFalse(result['enumeration_success']);self.assertEqual(result['child_exit_code'],7)
        result=self.exercise(b'PRIVATE',0)
        self.assertEqual(result['status'],'parse_unknown');self.assertFalse(result['diagnostics_complete'])
        result=self.exercise(b'',None,ended=False)
        self.assertTrue(result['timed_out']);self.assertIsNone(result['child_exit_code']);self.assertFalse(result['enumeration_success'])
        result=self.exercise(b'UDP53_COUNT_1',0,clean=False)
        self.assertEqual(result['matches_capped_at_two'],1);self.assertFalse(result['diagnostics_complete']);self.assertFalse(result['cleanup_confirmed'])
    def test_cli_preflight_only_does_not_dispatch_other_modes(self):
        import io
        with patch('sys.argv',['gate','--run-port-preflight-only','--actor','a','--manifest','m','--output','o']),patch.object(g,'run',side_effect=AssertionError()),patch.object(g,'run_describe',side_effect=AssertionError()),patch.object(g,'run_port_pair',side_effect=AssertionError()),patch.object(g,'run_preflight_only',return_value=dict(diagnostics_complete=True)) as run,patch.object(Path,'write_text'),patch('sys.stdout',io.StringIO()):
            self.assertEqual(g.main(),0);run.assert_called_once()

def inventory(rows,status='complete'):
    return raw(dict(schema=1,status=status,rows=rows))
def endpoint(address='127.0.0.1',pid=100):return dict(a=address,p=pid,l=53)
class Loopback2Tests(unittest.TestCase):
    def test_inventory_complete_cap_multiset_and_all_unknown_refused(self):
        row=endpoint();value=g.private_inventory(inventory([row,row]))
        self.assertEqual(value[g.Counter({('127.0.0.1',4,53,100):1}).most_common()[0][0]],2)
        self.assertEqual(sum(g.private_inventory(inventory([row]*64)).values()),64)
        bad=[inventory([row]*65),inventory([],status='truncated'),inventory([],status='error'),b'X'*4097]
        for address in ('0.0.0.0','::','::1','::ffff:127.0.0.1','PRIVATE','127.000.0.1'):bad.append(inventory([endpoint(address)]))
        for key,value in [('p',True),('p',0),('l',54),('l',True),('private','secret')]:
            changed=endpoint();changed[key]=value;bad.append(inventory([changed]))
        for data in bad:
            with self.assertRaises(ValueError):g.private_inventory(data)
    def exercise(self,baseline=None,post=None,after=None,timeout_first=False,misroute=False,unknown_control=None,second_bind_error=False,fixture_cleanup_unknown=False):
        base=[endpoint() ] if baseline is None else baseline
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'owned';root.mkdir();children=[];fixtures={}
            for name in ('high_port','standard_port'):
                f=Mock();f.counts=dict(datagrams=0,bytes=0,matched_queries=0,answers_sent=0,rejected=0,oversized=0,send_failed=0)
                f.snapshot.side_effect=lambda f=f,**kwargs:dict(f.counts);f.start.return_value=45000 if name=='high_port' else 53
                f.finish.return_value=dict(cleanup_confirmed=not fixture_cleanup_unknown,error='none',counts=f.counts)
                f.query_observed.is_set.side_effect=lambda f=f:f.counts['matched_queries']>0;fixtures[name]=f
            if second_bind_error:fixtures['standard_port'].start.side_effect=OSError('PRIVATE bind collision')
            module=Mock();module.DnsFixture.for_loopback2.side_effect=lambda *a,**k:fixtures['standard_port' if k.get('standard_port') else 'high_port']
            spec=Mock();spec.loader.exec_module=lambda value:None
            class FakeChild:
                def __init__(self,root,name):self.name=name;self.path=root/(name+'.out');self.process=Mock(returncode=0);children.append(self)
                def start(self,argv):
                    self.argv=argv
                    if self.name=='nrpt':data=b'NRPT_EMPTY'
                    elif self.name=='baseline':data=inventory(base)
                    elif self.name=='postbind':data=inventory(base+[endpoint('127.0.0.2',1234)] if post is None else post)
                    elif self.name=='afterclose':data=inventory(base if after is None else after)
                    else:
                        v=report();v.update(endpoint_kind=self.name,endpoint_address_kind='loopback2',custom_port53=self.name=='standard_port');data=raw(v)
                        target='standard_port' if misroute and self.name=='high_port' else self.name
                        for key in ('datagrams','bytes','matched_queries','answers_sent'):fixtures[target].counts[key]+=1
                    self.path.write_bytes(data)
                def wait(self,deadline,**kwargs):return not(timeout_first and self.name=='high_port')
                def finish(self,deadline):return dict(cleanup_confirmed=self.name!=unknown_control,exited=self.name!=unknown_control,handles_closed=self.name!=unknown_control,killed=False)
            with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Child',FakeChild),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g.importlib.util,'spec_from_file_location',return_value=spec),patch.object(g.importlib.util,'module_from_spec',return_value=module):
                fakeos.name='nt';fakeos.getpid.return_value=1234;result=g.run_loopback2_pair(Path('actor'),Path('manifest'))
            return result,children,fixtures
    def test_fixed_pair_complete_private_baseline_preserved_and_closed(self):
        result,children,fixtures=self.exercise()
        self.assertTrue(result['mechanism_positive']);self.assertTrue(result['afterclose_preserved'])
        self.assertEqual(result['baseline_count'],1)
        self.assertEqual([c.name for c in children],['nrpt','baseline','postbind','high_port','standard_port','afterclose'])
        self.assertEqual(children[3].argv[1],'--query-loopback2');self.assertEqual(children[4].argv[1],'--query-loopback2-port53')
        self.assertEqual(children[3].argv[2],children[4].argv[2])
        self.assertNotIn('127.0.0.1',json.dumps(result));self.assertNotIn('1234',json.dumps(result));self.assertFalse(result['continuous_service_liveness_proven'])
        for f in fixtures.values():f.finish.assert_called_once()
    def test_conflicting_pre_or_changed_post_refuses_api_no_takeover(self):
        for base in ([endpoint('0.0.0.0')],[endpoint('::1')],[endpoint('127.0.0.2')]):
            result,children,_=self.exercise(baseline=base)
            self.assertEqual(result['cases'],{});self.assertFalse(result['mechanism_positive'])
            self.assertNotIn('high_port',[c.name for c in children])
        for post in ([],[endpoint(),endpoint('127.0.0.2',999)],[endpoint(),endpoint('127.0.0.2',1234),endpoint('192.0.2.1',5)]):
            result,children,_=self.exercise(post=post)
            self.assertEqual(result['cases'],{});self.assertFalse(result['owned_target_verified'])
    def test_afterclose_failure_and_crossroute_keep_observation_not_success(self):
        result,_,_=self.exercise(after=[])
        self.assertFalse(result['afterclose_preserved']);self.assertTrue(result['query_observed']);self.assertFalse(result['mechanism_positive'])
        result,_,_=self.exercise(misroute=True)
        self.assertTrue(result['cases']['high_port']['other_endpoint_observed']);self.assertFalse(result['mechanism_positive'])
    def test_new_path_unknown_controls_bind_and_fixture_cleanup_independent(self):
        for name in ('baseline','postbind'):
            result,children,_=self.exercise(unknown_control=name)
            self.assertEqual(result['cases'],{});self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['work_removed'])
            self.assertNotIn('high_port',[c.name for c in children])
        result,children,fixtures=self.exercise(second_bind_error=True)
        self.assertEqual(result['cases'],{});self.assertIn('afterclose',[c.name for c in children])
        for fixture in fixtures.values():fixture.finish.assert_called_once()
        self.assertTrue(result['afterclose_preserved'])
        result,children,_=self.exercise(fixture_cleanup_unknown=True)
        self.assertIn('afterclose',[c.name for c in children]);self.assertTrue(result['query_observed'])
        self.assertFalse(result['mechanism_positive']);self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['work_removed'])
    def test_first_timeout_prevents_second_but_still_closes_and_checks_baseline(self):
        result,children,_=self.exercise(timeout_first=True)
        self.assertNotIn('standard_port',[c.name for c in children]);self.assertFalse(result['pair_complete'])
        self.assertTrue(result['afterclose_preserved']);self.assertTrue(result['cleanup_confirmed'])

if __name__=='__main__':unittest.main()
