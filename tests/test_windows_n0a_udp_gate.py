import importlib.util
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_gate_test',ROOT/'.github/test_windows_n0a_udp.py');g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
class PinTests(unittest.TestCase):
    def test_manifest_test_only_cannot_be_production_or_wrong_source(self):
        for fixture in (False,True):
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);actor=root/('windows_n0a_UDP_TEST_ONLY_fixture.exe' if fixture else 'windows_n0a_udp_actor.exe');actor.write_bytes(b'owned-test')
                manifest=root/('UDP-TEST-ONLY-manifest.json' if fixture else 'N0A-UDP-manifest.json')
                value=dict(schemaVersion=1,testOnly=fixture,deployable=not fixture,compileOnly=True,actorSourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_actor.cpp').read_bytes()).hexdigest(),identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
                if fixture:value['fixtureSourceSha256']=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_fixture.cpp').read_bytes()).hexdigest()
                manifest.write_text(json.dumps(value));self.assertTrue(g.verify(actor,manifest,fixture))
                for key,bad in [('testOnly',not fixture),('deployable',fixture),('actorSourceSha256','0'*64),('executableSha256','0'*64),('schemaVersion',True)]:
                    changed=dict(value);changed[key]=bad;manifest.write_text(json.dumps(changed))
                    with self.assertRaises(ValueError):g.verify(actor,manifest,fixture)
    def test_off_platform_no_process_or_endpoint(self):
        with patch.object(g,'os',Mock()) as fake,patch.object(g.subprocess,'Popen') as launch,patch.object(g.u,'UdpEndpoint') as endpoint:
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
class CompositionTests(unittest.TestCase):
    def exercise(self,unknown_cleanup=False,bad_echo=False):
        spec=importlib.util.spec_from_file_location('udp_synthetic',ROOT/'tests/test_windows_client_n0a_udp.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
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
                    self.path.write_text(json.dumps(dict(mode='actor-n0a-udp',nonce=nonce,pid=123,queriesSucceeded=True,errors=[],udp=value)))
                def start_arguments(self,argv):
                    commands.append(tuple(argv))
                    if '--profile-only' in argv:
                        self.path.write_text(json.dumps(dict(mode='actor-n0a-udp-profile',nonce=argv[2],pid=123,queriesSucceeded=True,errors=[],tokenElevated=True,profile=dict(testOnly=True,ordinaryMatched=False,containedMatched=False,networkApiCalled=False))))
                    else:self.process.returncode=2
                def wait(self,deadline):return True
                report=g.Owned.report
                def finish(self,deadline):return dict(cleanup_confirmed=not unknown_cleanup,process_exited=not unknown_cleanup,killed=False,handles_closed=not unknown_cleanup)
            with patch.object(g,'os',Mock()) as fakeos,patch.object(g,'verify',return_value=True),patch.object(g,'Owned',Owned),patch.object(g.u,'UdpEndpoint',Endpoint),patch.object(g.tempfile,'mkdtemp',return_value=str(root)),patch.object(g.time,'sleep'):
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

if __name__=='__main__':unittest.main()
