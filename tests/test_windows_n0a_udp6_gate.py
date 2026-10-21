import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_gate_test',ROOT/'.github/test_windows_n0a_udp6.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class PinTests(unittest.TestCase):
    def test_manifest_test_only_cannot_be_production_or_wrong_source(self):
        for fixture in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);actor=root/('windows_n0a_UDP6_TEST_ONLY_fixture.exe' if fixture else 'windows_n0a_udp6_actor.exe');actor.write_bytes(b'owned-test')
                manifest=root/('UDP6-TEST-ONLY-manifest.json' if fixture else 'N0A-UDP6-manifest.json')
                value=dict(schemaVersion=1,testOnly=fixture,deployable=not fixture,compileOnly=True,actorSourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp6_actor.cpp').read_bytes()).hexdigest(),identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
                if fixture:value['fixtureSourceSha256']=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp6_fixture.cpp').read_bytes()).hexdigest()
                manifest.write_text(json.dumps(value));self.assertTrue(g.verify(actor,manifest,fixture))
                for key,bad in [('testOnly',not fixture),('deployable',fixture),('actorSourceSha256','0'*64),('executableSha256','0'*64),('schemaVersion',True)]:
                    changed=dict(value);changed[key]=bad;manifest.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):g.verify(actor,manifest,fixture)
    def test_off_platform_no_process_or_endpoint(self):
        with patch.object(g,'os',Mock()) as fake,patch.object(g.subprocess,'Popen') as launch,patch.object(g.u,'Udp6Endpoint') as endpoint:
            fake.name='posix';value=g.run(Path('p'),Path('pm'),Path('f'),Path('fm'))
        self.assertEqual(value['failure'],'platform');launch.assert_not_called();endpoint.assert_not_called()
    def test_bounded_read_no_prefix_or_reparse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'x';path.write_bytes(b'x'*11)
            with self.assertRaises(ValueError):g.read(path,10)
class OwnedTests(unittest.TestCase):
    def test_poll_and_kill_error_do_not_skip_later_wait_and_unknown_retains_handle(self):
        for fail in ('poll','kill','wait'):
            child=g.Owned(Path('unused'));proc=Mock();child.process=proc
            proc.poll.side_effect=[OSError('PRIVATE') if fail=='poll' else None,None if fail=='wait' else 0]
            if fail=='kill':proc.kill.side_effect=OSError('PRIVATE')
            if fail=='wait':proc.wait.side_effect=OSError('PRIVATE')
            with patch.object(g.time,'monotonic',return_value=59):value=child.finish(60)
            proc.kill.assert_called_once_with();proc.wait.assert_called_once_with(timeout=1);self.assertFalse(value['cleanup_confirmed'])
            if fail=='wait':proc._handle.Close.assert_not_called();self.assertFalse(value['handles_closed'])
    def test_already_exited_never_resignalled(self):
        child=g.Owned(Path('unused'));child.process=Mock();child.process.poll.return_value=0
        self.assertTrue(child.finish(0)['cleanup_confirmed']);child.process.kill.assert_not_called()
    def test_child_wait_absolute_and_oversize_private_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            child=g.Owned(Path(tmp)/'report');child.process=Mock();child.process.poll.return_value=None
            with patch.object(g.time,'monotonic',return_value=60):self.assertFalse(child.wait(60))
            child.path.write_bytes(b'x'*(g.u.MAX_REPORT+1))
            with patch.object(g.time,'monotonic',return_value=1),self.assertRaises(ValueError):child.wait(60)
    def test_create_new_path_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'report';path.write_bytes(b'old');child=g.Owned(path)
            with patch.object(g.subprocess,'Popen') as launch,self.assertRaises(ValueError):child.start(Path('actor'),'a'*32,45000,'before')
            launch.assert_not_called()
    def test_spawn_uncertainty_cannot_claim_cleanup(self):
        child=g.Owned(Path('absent'))
        with patch.object(g.subprocess,'Popen',side_effect=OSError('PRIVATE')):
            with self.assertRaises(OSError):child.start_arguments(['fixture'])
        facts=child.finish(60)
        self.assertFalse(facts['cleanup_confirmed']);self.assertFalse(facts['process_exited'])
    def test_close_error_is_one_shot_and_sticky(self):
        child=g.Owned(Path('absent'));child.process=Mock();child.process.poll.return_value=0
        child.process._handle.Close.side_effect=OSError('PRIVATE')
        self.assertFalse(child.finish(60)['cleanup_confirmed'])
        self.assertFalse(child.finish(60)['cleanup_confirmed'])
        child.process._handle.Close.assert_called_once_with()

class CompositionTests(unittest.TestCase):
    def exercise(self,unknown_cleanup=False,bad_echo=False,bad_v6only_contract=False):
        spec=importlib.util.spec_from_file_location('udp_synthetic',ROOT/'tests/test_windows_client_n0a_udp6.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'owned';root.mkdir();commands=[];endpoint_count=[]
            class Endpoint:
                def __init__(self,*args,wrong=False):self.wrong=wrong;endpoint_count.append(self)
                @classmethod
                def for_test_wrong_echo(cls,*args):return cls(*args,wrong=True)
                def start(self):return 40000
                def finish(self,deadline):
                    return dict(cleanup_confirmed=not unknown_cleanup,error=False,counts=dict(verified=1 if self.wrong else 8,rejected=0,oversized=0,send_errors=0),verified_indices={'contained':[] if self.wrong else [0,1,2]})
            class Owned:
                def __init__(self,path):self.path=path;self.process=Mock(pid=123,returncode=0)
                def start(self,actor,nonce,port,phase):
                    commands.append((str(actor),phase))
                    starts={'before':[10],'sample':[100,600,1800],'contained':[500,1000,1500],'after':[2000]}[phase]
                    value=helper.network(phase,starts,False,False)
                    for row in value['attempts']:row['sendBytes']=len(g.u.frame(nonce,phase,row['index']))
                    if self.path.stem=='wrong-echo':value['attempts'][0].update(nonceMatched=bad_echo,failure='none' if bad_echo else 'echo_payload')
                    self.path.write_text(json.dumps(dict(mode='actor-n0a-udp6',nonce=nonce,pid=123,queriesSucceeded=True,errors=[],udp6=value)))
                def start_arguments(self,argv):
                    commands.append(tuple(argv))
                    if '--profile-only' in argv:
                        self.path.write_text(json.dumps(dict(mode='actor-n0a-udp6-profile',nonce=argv[2],pid=123,queriesSucceeded=True,errors=[],tokenElevated=True,profile=dict(testOnly=True,ordinaryMatched=False,containedMatched=False,networkApiCalled=False,v6OnlyContractVerified=not bad_v6only_contract))))
                    else:self.process.returncode=2
                def wait(self,deadline):return True
                report=g.Owned.report
                def finish(self,deadline):return dict(cleanup_confirmed=not unknown_cleanup,process_exited=not unknown_cleanup,killed=False,handles_closed=not unknown_cleanup)
            with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Owned',Owned),patch.object(g.u,'Udp6Endpoint',Endpoint),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g.time,'sleep'):
                fakeos.name='nt';result=g.run(Path('production'),Path('pm'),Path('fixture'),Path('fm'))
            return result,commands,len(endpoint_count),root.exists()
    def test_full_fixture_mechanics_wrong_echo_and_safe_profile_control(self):
        value,commands,count,retained=self.exercise()
        self.assertTrue(value['hosted_mechanics_complete']);self.assertEqual(count,2);self.assertFalse(retained)
        self.assertTrue(value['wrong_echo_send_accepted']);self.assertTrue(value['wrong_echo_rejected'])
        self.assertTrue(value['actual_admin_profile_rejected']);self.assertTrue(value['production_invalid_cli_rejected'])
        self.assertEqual([row for row in commands if row[0]=='production'],[('production','--invalid-mechanics-control')])
        self.assertFalse(value['production_network_guard_executed']);self.assertFalse(value['ordinary_nonadmin_tested']);self.assertFalse(value['packet_egress_tested'])
    def test_cleanup_unknown_keeps_observations_but_retains_owned_work(self):
        value,_,_,retained=self.exercise(unknown_cleanup=True)
        self.assertFalse(value['hosted_mechanics_complete']);self.assertFalse(value['cleanup_confirmed']);self.assertTrue(retained)
        self.assertTrue(value['wrong_echo_send_accepted']);self.assertTrue(value['fixture_echo_controls'])
    def test_wrong_echo_must_not_be_treated_as_positive(self):
        value,_,_,_=self.exercise(bad_echo=True)
        self.assertTrue(value['wrong_echo_send_accepted']);self.assertFalse(value['wrong_echo_rejected']);self.assertFalse(value['hosted_mechanics_complete'])

    def test_native_helper_contract_false_does_not_pass_mechanics(self):
        value,_,_,_=self.exercise(bad_v6only_contract=True)
        self.assertTrue(value['actual_admin_profile_rejected'])
        self.assertFalse(value['v6only_contract_verified']);self.assertFalse(value['hosted_mechanics_complete'])

class DiagnosticTests(unittest.TestCase):
    def network(self,phase='contained',count=3):
        spec=importlib.util.spec_from_file_location('udp6_diag_synthetic',ROOT/'tests/test_windows_client_n0a_udp6.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        return helper.network(phase,[100+i*100 for i in range(count)],False,False)
    def test_closed_projection_preserves_setup_and_send_errors_without_private_fields(self):
        for failure in ('socket','v6only_set','v6only_get','exclusive','bind','getsockname','deadline','sendto','recvfrom','echo_payload'):
            network=self.network();row=network['attempts'][0]
            row.update(failure=failure,win32Error=10013,sendAccepted=False,sendBytes=-1,nonceMatched=False)
            if failure not in ('sendto','recvfrom','echo_payload'):
                row.update(attempted=False,sendStartQpc=0,sendEndQpc=0)
            network['attempts'][0]['v6OnlyGetValue']=0xffffffff
            value=g.network_diagnostic(network,'a'*32,'contained',40000)
            self.assertEqual(value['attempts'][0]['v6only_get_value'],0xffffffff)
            self.assertIsNone(value['attempts'][0]['v6only_get_error'])
            self.assertEqual(value['attempts'][0]['failure'],failure)
            self.assertEqual(value['attempts'][0]['win32_error'],10013)
            self.assertEqual(value['attempts'][0]['send_invoked'],row['attempted'])
            text=json.dumps(value)
            for forbidden in ('localIpv6','localPort','localScopeId','Qpc','pid','nonce','40000','aaaaaaaa'):
                self.assertNotIn(forbidden,text)
        network=self.network();network.update(startupError=10093,attempts=[])
        value=g.network_diagnostic(network,'a'*32,'contained',40000)
        self.assertEqual(value['startup_error'],10093);self.assertEqual(value['attempt_count'],0)
    def test_full_40_row_private_native_report_remains_within_existing_cap(self):
        value=self.network('sample',40);base=2**63-100000
        value.update(windowStartQpc=base,windowEndQpc=base+3902,socketsCleanupConfirmed=False)
        for index,row in enumerate(value['attempts']):
            row.update(localPort=65535,localIpv6='f'*32,v6OnlyGetValue=0xffffffff,
                       sendStartQpc=base+index*100,sendEndQpc=base+index*100+1,
                       exchangeEndQpc=base+index*100+2,closeQpc=2**63-1,
                       nonceMatched=False,failure='recv_select',win32Error=2**32-1,closed=False,closeError=2**32-1)
        g.u.validate_network(value,'a'*32,'sample',40000,'fixture-loopback-v6',True)
        report=dict(schemaVersion=1,mode='actor-n0a-udp6',nonce='a'*32,pid=2**32-1,
                    tokenUserSid='S-1-5-'+('-'.join(['4294967295']*15)),tokenIsAppContainer=False,
                    tokenAppContainerSid=None,tokenElevated=False,isProcessInJob=False,
                    tokenCapabilities=[],queriesSucceeded=True,errors=[],udp6=value)
        raw=(json.dumps(report,separators=(',',':'))+'\n').encode('ascii')
        self.assertLessEqual(len(raw),g.u.MAX_REPORT);self.assertGreater(len(raw),24000)
        self.assertEqual(g.u.parse(raw),report)
    def test_invalid_native_schema_cannot_enter_diagnostics(self):
        value=self.network();value['attempts'][0]['failure']='PRIVATE/path'
        with self.assertRaises(ValueError):g.network_diagnostic(value,'a'*32,'contained',40000)
        value=self.network();value['attempts'][0]['win32Error']=True
        with self.assertRaises(ValueError):g.network_diagnostic(value,'a'*32,'contained',40000)
    def test_actual_composed_maximum_closed_output_and_missing_reports(self):
        result,_,_,_=CompositionTests().exercise()
        for key in g.DIAGNOSTIC_CASES:
            phase='before' if key=='wrong_echo' else key
            network=self.network(phase,40 if phase=='sample' else 3 if phase=='contained' else 1)
            network['startupError']=2**32-1;network['socketsCleanupConfirmed']=False
            for row in network['attempts']:
                row.update(win32Error=2**32-1,closeError=2**32-1,closed=False,
                           sendAccepted=False,nonceMatched=False,sendBytes=-1,v6OnlyVerified=False,
                           bindSucceeded=False,attempted=False,localPort=0,sendStartQpc=0,sendEndQpc=0,
                           socketCreated=True,v6OnlySet=True,v6OnlyGetStage='api_error',v6OnlyGetReturn=-1,
                           v6OnlyGetError=2**32-1,v6OnlyGetLength=-2**31,v6OnlyGetValue=None,failure='v6only_get')
            result['network_diagnostics'][key]=g.network_diagnostic(network,'a'*32,phase,40000)
        for receiver in result['receivers']:
            receiver['counts']={k:128*129 if k=='observed_bytes' else 128 for k in ('datagrams','observed_bytes','verified','echoed','rejected','oversized','send_errors')}
            receiver['verified_indices']={p:list(range(40 if p=='sample' else 3 if p=='contained' else 1)) for p in g.u.PHASES}
        def longest_bools(value):
            if type(value) is bool:return False
            if type(value) is dict:return {key:longest_bools(item) for key,item in value.items()}
            if type(value) is list:return [longest_bools(item) for item in value]
            return value
        result=longest_bools(result);result['failure']='endpoint_setup'
        encoded=g.public_json(result).encode('ascii')
        self.assertLessEqual(len(encoded),32768);self.assertGreater(len(encoded),10000)
        with self.assertRaises(ValueError):g.public_json({'x':'x'*32768})
        with patch.object(g,'os',Mock()) as fake:
            fake.name='posix';missing=g.run(Path('p'),Path('pm'),Path('f'),Path('fm'))
        self.assertEqual(missing['network_diagnostics'],dict.fromkeys(g.DIAGNOSTIC_CASES))
    def test_cleanup_failure_keeps_all_validated_case_diagnostics(self):
        result,_,_,_=CompositionTests().exercise(unknown_cleanup=True)
        self.assertFalse(result['cleanup_confirmed'])
        self.assertTrue(all(result['network_diagnostics'][key] is not None for key in g.DIAGNOSTIC_CASES))
        self.assertEqual(result['network_diagnostics']['contained']['attempt_count'],3)
        self.assertTrue(result['network_diagnostics']['wrong_echo']['attempts'][0]['send_accepted'])

if __name__=='__main__':unittest.main()
