"""UDP-only guest dispatch and executable owned-cleanup failure contracts."""
import ast
import hashlib
import io
import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path
import types
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'.github/windows_n0a_udp6_guest.py').read_text()
TREE=ast.parse(SOURCE)
CLASS=next(n for n in TREE.body if isinstance(n,ast.ClassDef))

class Handle:
    def __init__(self,fail=False):self.calls=0;self.fail=fail
    def Close(self):
        self.calls+=1
        if self.fail:raise OSError('fixture')
class Process:
    def __init__(self,*,poll_failure=False,kill_failure=False,wait_failure=False,alive=False,handle_failure=False):
        self.poll_failure=poll_failure;self.kill_failure=kill_failure;self.wait_failure=wait_failure
        self.alive=alive;self._handle=Handle(handle_failure);self.calls=[]
    def poll(self):
        self.calls.append('poll')
        if self.poll_failure:self.poll_failure=False;raise OSError('fixture')
        return None if self.alive else 0
    def kill(self):
        self.calls.append('kill')
        if self.kill_failure:raise OSError('fixture')
        self.alive=False
    def wait(self,timeout):
        self.calls.append('wait')
        if self.wait_failure:raise OSError('fixture')
        self.alive=False;return 0

class UDPGuest(unittest.TestCase):
    def cleanup(self,process,deadline=100):
        method=next(n for n in CLASS.body if isinstance(n,ast.FunctionDef) and n.name=='close_owned')
        scope={'time':types.SimpleNamespace(monotonic=lambda:10)}
        exec(compile(ast.Module(body=[method],type_ignores=[]),'fixture','exec'),scope)
        self.fn=scope['close_owned'];self.owner=types.SimpleNamespace(deadline=deadline)
        self.owned={'process':process,'out':io.BytesIO(),'err':io.BytesIO()}
        return self.fn(self.owner,self.owned)
    def test_exact_override_surface(self):
        self.assertEqual({n.name for n in CLASS.body if isinstance(n,ast.FunctionDef)},
                         {'__init__','endpoint_case','close_owned','start','envelope','invoke'})
        self.assertEqual(ast.unparse(CLASS.bases[0]),'base.WindowsExecution')
    def test_udp_only_commands_and_modes(self):
        self.assertIn("actor.get('mode')!='actor-n0a-udp6'",SOURCE)
        self.assertNotIn("'actor-n0a'",SOURCE)
        self.assertNotIn('engine.NonceEndpoint',SOURCE)
        self.assertNotIn('engine.Binding(',SOURCE)
        self.assertIn('engine.command(self.actor,report,self.binding,phase)',SOURCE)
        self.assertIn("phase in ('before','after')",SOURCE)
        self.assertIn("role=='contained' and phase=='contained'",SOURCE)
    def test_manifest_before_executor_and_default_off(self):
        run=next(n for n in TREE.body if isinstance(n,ast.FunctionDef) and n.name=='run')
        text=ast.get_source_segment(SOURCE,run)
        self.assertLess(text.index('if not engine.EXECUTION_ENABLED'),text.index('qpc_budget'))
        self.assertLess(text.index('verify_production'),text.index('engine.verify_binding'))
        self.assertIn("'testOnly':False,'deployable':True",SOURCE)
        self.assertIn("'actorSourceSha256'",SOURCE)
    def test_actual_exit_cleanup(self):
        p=Process(alive=True);self.assertTrue(self.cleanup(p))
        self.assertEqual(p.calls,['poll','kill','wait','poll'])
        self.assertEqual(p._handle.calls,1)
        self.assertTrue(self.owned['out'].closed);self.assertTrue(self.owned['err'].closed)
        calls=list(p.calls)
        self.assertTrue(self.fn(self.owner,self.owned));self.assertEqual(p._handle.calls,1)
        self.assertEqual(p.calls,calls)
    def test_kill_failure_does_not_skip_wait_or_final_poll(self):
        p=Process(alive=True,kill_failure=True)
        self.assertFalse(self.cleanup(p));self.assertEqual(p.calls,['poll','kill','wait','poll'])
        self.assertEqual(p._handle.calls,1)
        self.assertFalse(self.fn(self.owner,self.owned))
    def test_poll_failure_does_not_skip_owned_stop(self):
        p=Process(poll_failure=True,alive=True)
        self.assertFalse(self.cleanup(p));self.assertIn('kill',p.calls);self.assertIn('wait',p.calls)
        self.assertEqual(p._handle.calls,1)
    def test_wait_failure_still_observes_exit_and_closes(self):
        p=Process(alive=True,wait_failure=True)
        self.assertFalse(self.cleanup(p));self.assertEqual(p.calls[-1],'poll');self.assertEqual(p._handle.calls,1)
    def test_handle_close_is_one_shot_and_uncertainty_sticky(self):
        p=Process(handle_failure=True);self.assertFalse(self.cleanup(p));self.assertFalse(self.fn(self.owner,self.owned))
        self.assertEqual(p._handle.calls,1)
    def test_expired_budget_no_wait_and_live_handle_retained(self):
        p=Process(alive=True,kill_failure=True)
        self.assertFalse(self.cleanup(p,deadline=9));self.assertNotIn('wait',p.calls)
        self.assertEqual(p._handle.calls,0)
    def test_partial_spawn_closes_both_streams(self):
        self.assertFalse(self.cleanup(None));self.assertTrue(self.owned['out'].closed);self.assertTrue(self.owned['err'].closed)
    def test_stream_failure_does_not_skip_other_stream(self):
        self.cleanup(None)
        class Bad:
            closed=False
            def close(self):raise OSError('fixture')
        self.owned={'process':None,'out':Bad(),'err':io.BytesIO()}
        self.assertFalse(self.fn(self.owner,self.owned));self.assertTrue(self.owned['err'].closed)
    def test_dedicated_audit_identity_and_snapshot_unchanged(self):
        self.assertIn("(state.st_dev,state.st_ino)!=owned['audit_identity']",SOURCE)
        self.assertIn("base.engine.audit_exit(bounded_bytes(audit,base.engine.MAX_AUDIT),actor.get('pid'),owned['process'].pid)",SOURCE)
        self.assertIn('self.snapshots[id(actor)]=snapshot',SOURCE)
        self.assertNotIn('shutil.rmtree',SOURCE)
class InheritedDispatch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec=importlib.util.spec_from_file_location('udp6_guest_under_test',ROOT/'.github/windows_n0a_udp6_guest.py')
        cls.module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=cls.module;spec.loader.exec_module(cls.module)
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.g=self.module.WindowsExecution.__new__(self.module.WindowsExecution)
        self.g.deadline=time.monotonic()+20;self.g.owned=[];self.g.sequence=0;self.g.capture=False;self.g.snapshots={}
        self.g.binding=types.SimpleNamespace(nonce='a'*32,actor_sha256='b'*64,executor_sha256='c'*64,build=26300,ubr=9457)
        self.g.cases={'runner-v6':{'directory':self.root,'profile':self.root,'probe':{'selected':True},'probe_exit':0}}
        self.g.pin=lambda:None
    def test_inherited_methods_are_exact_objects(self):
        for name in ('remaining','pin','spawn','completed','probe','wait','finish'):
            self.assertIs(getattr(self.module.WindowsExecution,name),getattr(self.module.base.WindowsExecution,name))
    def test_actual_spawn_partial_failure_calls_udp_cleanup(self):
        with mock.patch.object(self.module.base.subprocess,'Popen',side_effect=OSError('fixture')):
            with self.assertRaises(OSError):self.g.spawn(['fixture'],self.root,'ordinary','before','runner-v6')
        self.assertEqual(len(self.g.owned),1);self.assertFalse(self.g.owned[0]['cleanup'])
        self.assertTrue(self.g.owned[0]['out_close_attempted']);self.assertTrue(self.g.owned[0]['err_close_attempted'])
    def test_actual_wait_preserves_report_after_wait_error(self):
        p=Process(wait_failure=True);p.pid=42;p.returncode=0
        actor={'nonce':'a'*32,'mode':'actor-n0a-udp6','pid':42}
        path=self.root/'report.json';path.write_text(json.dumps(actor))
        owned={'process':p,'out':io.BytesIO(),'err':io.BytesIO(),'role':'ordinary','endpoint':'runner-v6',
               'report':path,'timed_out':False,'cleanup':False}
        self.g.owned.append(owned)
        with mock.patch.object(self.module.base.engine,'read_report',return_value=actor):result=self.g.wait(owned,1)
        self.assertIs(result['actor'],actor);self.assertTrue(result['pid_verified'])
        self.assertTrue(result['harness_error']);self.assertEqual(result['child_exit_code'],0)
        self.assertTrue(self.g.finish());self.assertEqual(p._handle.calls,1)
    def test_finish_evaluates_every_owned_cleanup(self):
        a=Process(handle_failure=True);b=Process()
        self.g.owned=[{'process':p,'out':io.BytesIO(),'err':io.BytesIO()} for p in (a,b)]
        self.assertFalse(self.g.finish());self.assertEqual(a._handle.calls,1);self.assertEqual(b._handle.calls,1)
    def test_actual_wait_preserves_dedicated_audit_after_cleanup_error(self):
        p=Process(handle_failure=True);p.pid=40;p.returncode=0
        actor={'nonce':'a'*32,'mode':'actor-n0a-udp6','pid':42}
        report=self.root/'report.json';report.write_text(json.dumps(actor))
        event={'event':'mxc.ProcessExited','backend':'processcontainer','identity':'redacted',
               'tier':'base-container','pid':42,'exit_code':0}
        audit=self.root/'audit.private';audit.write_bytes(('[123] '+json.dumps(event)+'\n').encode('utf-8'))
        st=audit.stat()
        owned={'process':p,'out':io.BytesIO(),'err':io.BytesIO(),'role':'contained','endpoint':'runner-v6',
               'report':report,'audit':audit,'audit_identity':(st.st_dev,st.st_ino),'timed_out':False,'cleanup':False}
        self.g.owned.append(owned)
        result=self.g.wait(owned,1)
        self.assertTrue(result['harness_error']);self.assertTrue(result['pid_verified'])
        self.assertEqual(result['pid_binding'],'executor_audit');self.assertEqual(result['actual_tiers'],['base-container'])
        self.assertEqual(result['actor'],actor);self.assertFalse(self.g.finish());self.assertEqual(p._handle.calls,1)
    def test_audit_fixture_exact_bytes_and_platform_newline_discriminator(self):
        event={'event':'mxc.ProcessExited','backend':'processcontainer','identity':'redacted',
               'tier':'base-container','pid':42,'exit_code':0}
        line='[123] '+json.dumps(event)+'\n'
        text=self.root/'text-default';text.write_text(line,encoding='utf-8')
        exact=self.root/'exact-bytes';exact.write_bytes(line.encode('utf-8'))
        observed=text.read_bytes()
        expected=line.replace('\n',os.linesep).encode('utf-8')
        self.assertEqual(observed,expected)
        self.assertEqual(exact.read_bytes(),line.encode('utf-8'))
        parser=self.module.base.engine.audit_exit
        self.assertIsNotNone(parser(exact.read_bytes(),42,40))
        self.assertEqual(parser(observed,42,40) is not None,os.linesep=='\n')
        # Preserve the strict source-bound logger grammar on every platform.
        self.assertIsNone(parser(line.replace('\n','\r\n').encode('utf-8'),42,40))
    def test_actual_inherited_probe_uses_udp_endpoint_policy(self):
        p=Process();p.pid=40;p.returncode=0
        output=self.root/'probe';output.write_text('{}')
        owned={'process':p,'out':io.BytesIO(),'err':io.BytesIO(),'out_path':output,'timed_out':False,'cleanup':False}
        self.g.executor=self.root/'g.exe'
        case=self.g.cases['runner-v6'];case['policy']=self.root/'udp-policy.json'
        with mock.patch.object(self.g,'endpoint_case',return_value=case) as endpoint, mock.patch.object(self.g,'spawn',return_value=owned) as spawn:
            with mock.patch.object(self.module.base.engine,'proof_helpers',return_value=types.SimpleNamespace(smoke=types.SimpleNamespace(base_container_selected=lambda value,code:True))):
                self.g.probe('runner-v6',12345,1)
        endpoint.assert_called_once_with('runner-v6',12345)
        self.assertEqual(spawn.call_args.args[0],[self.g.executor,'--probe','--config',case['policy']])
        self.assertEqual(case['probe'],{});self.assertEqual(case['probe_exit'],0)
    def test_manifest_fixture_rejected_before_execution(self):
        actor=self.root/'actor';actor.write_bytes(b'x'*512)
        value={'schemaVersion':1,'testOnly':True,'deployable':False,'compileOnly':True,
               'actorSourceSha256':'a'*64,'identitySourceSha256':'b'*64,'executableSha256':hashlib.sha256(actor.read_bytes()).hexdigest()}
        path=self.root/'manifest';path.write_text(json.dumps(value))
        config={'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'actor_source_sha256':'a'*64,
                'identity_source_sha256':'b'*64,'actor_sha256':value['executableSha256']}
        with self.assertRaises(ValueError):self.module.verify_production(config,actor,path)

    def test_production_manifest_exact_bytes_and_source_pins(self):
        actor=self.root/'production';actor.write_bytes(b'MZ'+b'x'*510)
        value={'schemaVersion':1,'testOnly':False,'deployable':True,'compileOnly':True,
               'actorSourceSha256':'a'*64,'identitySourceSha256':'b'*64,'executableSha256':hashlib.sha256(actor.read_bytes()).hexdigest()}
        path=self.root/'production-manifest';path.write_bytes(json.dumps(value).encode('ascii'))
        config={'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'actor_source_sha256':'a'*64,
                'identity_source_sha256':'b'*64,'actor_sha256':value['executableSha256']}
        self.assertEqual(self.module.verify_production(config,actor,path),value)
        for key in ('actor_source_sha256','identity_source_sha256','manifest_sha256','actor_sha256'):
            bad=dict(config);bad[key]='0'*64
            with self.assertRaises(ValueError):self.module.verify_production(bad,actor,path)
        actor.write_bytes(b'MZ'+b'y'*510)
        with self.assertRaises(ValueError):self.module.verify_production(config,actor,path)

if __name__=='__main__':unittest.main()
