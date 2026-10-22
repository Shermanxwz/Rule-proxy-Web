"""Pure Stage0b integration tests; no Windows process/profile or network calls."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module

g = load('stage0b_guest_test', ROOT / '.github/windows_identity_stage0b_guest.py')
l = g.launcher_module()
t = load('ordinary_test_fixture', ROOT / 'tests/test_windows_identity_ordinary_launcher.py')
p = load('pipe_test_fixture', ROOT / 'tests/test_windows_identity_pipe_probe.py')
D, F = 1120000, 1000


def path_tail(path, *components):
    """Match owned fixture roles independent of platform separator spelling."""
    return path.parts[-len(components):] == components



class API(t.FakeAPI):
    def __init__(self, **kwargs):
        super().__init__(child=t.ordinary(), **kwargs)
        self.now = 1000000
        self.pid = 32
        self.after_resume = None
        self.empty = True
    def qpc(self): return self.now
    def qpc_frequency(self): return F
    def sleep_ms(self, value): self.event('sleep', value); self.now += value
    def job_empty(self, job): self.event('job_empty', job); return self.empty
    def current_token(self): self.event('current_token'); return 100
    def identity(self, token): self.event('identity', token); return copy.deepcopy(self.child)
    def compartment(self): self.event('compartment'); return 1
    def create_suspended(self, info, command, work, stdio, token):
        super().create_suspended(info, command, work, stdio, token)
        info.dwProcessId = self.pid
        self.command, self.work = command, work
    def resume(self, thread):
        super().resume(thread)
        if self.after_resume: self.after_resume()


def inner_launch(pid=33):
    return {'started': True, 'resumed': True, 'child_pid': pid, 'exit_code': 0,
            'native_identity_verified_before_resume': True,
            'cleanup': {'job_closed': True, 'job_empty': True, 'handles_closed': True,
                        'process_exit_confirmed': True, 'close_uncertain': False, 'errors': []}}


def evidence(config, controller_pid=33):
    value = p.good()
    value.update(schema_version=1, stage='0b', nonce=config['case_nonce'],
                 actor_sha256=config['actor_sha256'], copied_actor_sha256=config['actor_sha256'],
                 deadline_qpc=D, qpc_frequency=F)
    value['actor']['nonce'] = config['case_nonce']
    value['controller_identity'].update(pid=controller_pid, elevated=False, appcontainer=False, cid=1)
    return value


def report(config):
    return {'schema_version': 2, 'stage': 'current-ordinary-stage0b-launcher',
            'case_nonce': config['case_nonce'], 'actor_sha256': config['actor_sha256'],
            'deadline_qpc': D, 'qpc_frequency': F, 'current_ordinary_only': True,
            'current_ordinary_verified': True, 'controller_pid': 32,
            'controller_sid': t.ordinary()['sid'], 'launch': inner_launch(),
            'cleanup': {'token_handles_closed': True, 'errors': []}}


class BudgetTests(unittest.TestCase):
    def test_original_qpc_offsets_caps_and_no_renewal(self):
        api = API(); b = l.QpcBudget(api, D, F)
        self.assertEqual([b.cutoff(n) for n in (30,10,5,0)], [1090000,1110000,1115000,1120000])
        self.assertEqual(b.require_ms(b.cutoff(30),15000),15000)
        api.now=1089999
        self.assertEqual(b.require_ms(b.cutoff(30),15000),1)
        api.now+=1
        with self.assertRaises(l.GateFailure): b.require_ms(b.cutoff(30))
        self.assertEqual(b.deadline,D)
        self.assertEqual(b.remaining_ms(b.cutoff(10),5000),5000)

    def test_frequency_overflow_expiry_bool_and_backwards(self):
        for deadline, freq in ((True,F),(D,True),(2**63,F),(D,0),(D,10**9+1),(D,F+1),(999999,F),(1120001,F)):
            with self.subTest(deadline=deadline,freq=freq),self.assertRaises(l.GateFailure):
                l.QpcBudget(API(),deadline,freq)
        api=API(); b=l.QpcBudget(api,D,F);api.now-=1
        with self.assertRaises(l.GateFailure):b.read()


class ScopedLifecycleTests(unittest.TestCase):
    def launch(self,api):
        b=l.QpcBudget(api,D,F)
        return l.launch_owned(api,['python.exe','fixed.py'],Path('owned'),t.ordinary(),t.ordinary(),
                              qpc_budget=b,work_cutoff=b.cutoff(10),cleanup_cutoff=b.cutoff(5))
    def test_assignment_image_token_before_resume_and_clipped_wait(self):
        api=API();value=self.launch(api)
        self.assertTrue(g.cleanup_verified(value))
        names=[x[0] for x in api.events]
        for name in ('assign_job','verify_job','verify_image','child_identity'):
            self.assertLess(names.index(name),names.index('resume'))
        self.assertIn(('create_suspended',None),api.events)
        self.assertIn(('wait',30,110000),api.events)
        self.assertEqual(sum(x==('close',10) for x in api.events),1)
    def test_each_failure_closes_once_and_never_fallback(self):
        for failure in ('open_stdio_file','create_suspended','assign_job','verify_job','verify_image','child_identity','resume','wait','exit_code','terminate_job','job_empty','close'):
            api=API(fail=failure);value=self.launch(api)
            with self.subTest(failure=failure):
                closes=[x[1] for x in api.events if x[0]=='close']
                self.assertEqual(len(closes),len(set(closes)))
                self.assertLessEqual(sum(x[0]=='create_suspended' for x in api.events),1)
                self.assertFalse(value['cleanup']['errors']==[] and 'error' not in value)
                if failure in ('assign_job','verify_job','verify_image','child_identity'):
                    self.assertFalse(value['resumed'])
    def test_wait_and_signal_errors_do_not_suppress_final_observation(self):
        api=API(fail='wait');value=self.launch(api)
        self.assertGreaterEqual(sum(x[0]=='wait' for x in api.events),3)
        self.assertIn(('terminate_job',10),api.events)
        self.assertFalse(value['cleanup']['process_exit_confirmed'])
        self.assertFalse(value['cleanup']['handles_closed'])
        self.assertNotIn(('close',30),api.events)
    def test_job_close_exception_is_not_retried(self):
        api=API(); original=api.close
        def close(handle):
            original(handle)
            if handle==10:raise OSError('private')
        api.close=close;value=self.launch(api)
        self.assertEqual(api.events.count(('close',10)),1)
        self.assertTrue(value['cleanup']['close_uncertain'])
        self.assertFalse(value['cleanup']['handles_closed'])
    def test_expired_before_launch_creates_nothing(self):
        api=API(); b=l.QpcBudget(api,D,F);api.now=b.cutoff(10)
        value=l.launch_owned(api,['python.exe'],Path('owned'),t.ordinary(),t.ordinary(),qpc_budget=b,
                             work_cutoff=b.cutoff(10),cleanup_cutoff=b.cutoff(5))
        self.assertFalse(value['started']);self.assertNotIn(('create_job',),api.events)
    def test_nonempty_job_wait_stays_original_cleanup_cutoff(self):
        api=API();api.now=1114990;api.empty=False
        b=l.QpcBudget(api,D,F)
        value=l.launch_owned(api,['python.exe'],Path('owned'),t.ordinary(),t.ordinary(),qpc_budget=b,
                             work_cutoff=1114995,cleanup_cutoff=1115000)
        self.assertEqual(api.now,1115000)
        self.assertFalse(value['cleanup']['job_empty'])
        self.assertIn(('close',10),api.events)
    def test_late_signaled_wait_keeps_exit_but_fails_work_deadline(self):
        api=API();original=api.wait
        def wait(process, milliseconds):
            value=original(process,milliseconds)
            if milliseconds>0:api.now=1110001
            return value
        api.wait=wait;value=self.launch(api)
        self.assertTrue(value['cleanup']['process_exit_confirmed'])
        self.assertEqual(value['exit_code'],0)
        self.assertEqual(value['error']['reason'],'qpc_expired')
    def test_late_job_empty_observation_keeps_fact_but_fails_cleanup(self):
        api=API()
        def empty(job):api.now=1115001;return True
        api.job_empty=empty;value=self.launch(api)
        self.assertTrue(value['cleanup']['job_empty'])
        self.assertTrue(value['cleanup']['process_exit_confirmed'])
        self.assertTrue(value['cleanup']['errors'])
        self.assertFalse(g.cleanup_verified(value))

    def test_current_only_rejects_before_choose_or_linked(self):
        api=API();api.child=t.elevated()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);args=SimpleNamespace(disposable_ci=True,approved_security_test=True,
                current_ordinary_only=True,case_nonce='a'*32,actor_sha256='a'*64,deadline_qpc=D,qpc_frequency=F)
            with patch.object(l,'os',SimpleNamespace(name='nt',getpid=lambda:32)), \
                 patch.object(l,'validate_inputs',return_value=(Path('python.exe'),l.PROBE,Path('actor.exe'),root/'work')), \
                 patch.object(l,'NativeAPI',return_value=api),patch.object(l,'choose_mode',side_effect=AssertionError('fallback')):
                self.assertEqual(l.run_scoped(args),1)
            private=json.loads((root/'work/report.json').read_text())
            self.assertFalse(private['current_ordinary_verified'])
            self.assertNotIn('launch',private)
            self.assertFalse(any(x[0]=='create_suspended' for x in api.events))
    def test_legacy_launch_body_ast_is_unchanged(self):
        import ast
        tree=ast.parse((ROOT/'.github/windows_identity_ordinary_launcher.py').read_text())
        fn=next(node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name=='launch_owned')
        # Skip docstring and two explicit optional-QPC dispatch/refusal guards.
        old=ast.dump(ast.Module(body=fn.body[3:],type_ignores=[]),include_attributes=False)
        self.assertEqual(hashlib.sha256(old.encode()).hexdigest(),
                         '23eec8530ccf6998d5a24f3d0f22c74f9d8a9039bccc5cd991264c1c055ce0cf')

    def test_scoped_cli_requires_all_fields_without_changing_legacy(self):
        with patch.object(l,'run',return_value=7) as run:
            self.assertEqual(l.main(['--actor','x','--actor-sha256','a'*64,'--work','w','--report','r']),7)
            self.assertFalse(run.call_args.args[0].current_ordinary_only)
        with patch.object(l,'run_scoped',return_value=8) as run, patch.object(l,'emit_scoped_diagnostic'):
            self.assertEqual(l.main(['--actor','x','--actor-sha256','a'*64,'--work','w','--report','r',
                '--current-ordinary-only','--case-nonce','a'*32,'--deadline-qpc',str(D),'--qpc-frequency',str(F)]),8)
            self.assertTrue(run.call_args.args[0].current_ordinary_only)


class ProjectionTests(unittest.TestCase):
    def config(self):return dict(enabled=True,case_nonce='a'*32,actor_sha256='b'*64)
    def projection(self, mutate=None):
        config=self.config();value=evidence(config);r=report(config);outer=inner_launch(32)
        public=g.default_public(config['case_nonce'],config['actor_sha256']);public['current_ordinary_verified']=True
        if mutate:mutate(value,r,outer)
        g.project_private(public,l,outer,r,value,config,t.ordinary()['sid'],D,F,native=copy.deepcopy(value['actor']))
        return public
    def test_actual_probe_launcher_adapter_composition(self):
        self.assertTrue(all(self.projection()[key] for key in g.REQUIRED_FACTS))
    def test_cleanup_downgrade_preserves_bound_echo(self):
        value=self.projection(lambda p,r,o:p['cleanup'].update(profile_deleted=False))
        self.assertTrue(value['pipe_echo_verified']);self.assertFalse(value['nested_cleanup_verified'])
        value=self.projection(lambda p,r,o:o['cleanup'].update(handles_closed=False))
        self.assertTrue(value['pipe_echo_verified']);self.assertFalse(value['adapter_cleanup_verified'])
    def test_nested_pid_nonce_sid_hash_image_and_deadline_bindings(self):
        mutations=(lambda p,r,o:r.update(controller_pid=99),lambda p,r,o:r.update(current_ordinary_only=False),
            lambda p,r,o:p['controller_identity'].update(pid=999),lambda p,r,o:p.update(nonce='b'*32),
            lambda p,r,o:p['actor'].update(pid=43),lambda p,r,o:p['actor'].update(tokenUserSid='S-1-5-99'),
            lambda p,r,o:p.update(copied_actor_sha256='c'*64),lambda p,r,o:p.update(image_verified_before_resume=False),
            lambda p,r,o:p.update(deadline_qpc=D+1),lambda p,r,o:p.update(qpc_frequency=F+1))
        for mutate in mutations:
            self.assertFalse(self.projection(mutate)['pipe_echo_verified'])
    def test_every_pipe_field_exact_and_eof_exit_independent(self):
        for key in evidence(self.config())['actor']['pipe']:
            value=self.projection(lambda p,r,o,k=key:p['actor']['pipe'].pop(k))
            self.assertFalse(value['pipe_echo_verified'])
        for key in ('bytesRead','bytesWritten','win32Error'):
            self.assertFalse(self.projection(lambda p,r,o,k=key:p['actor']['pipe'].update({k:True}))['pipe_echo_verified'])
        value=self.projection(lambda p,r,o:p.update(pipe_eof_observed=False,exit_code=1))
        self.assertTrue(value['pipe_echo_verified']);self.assertFalse(value['pipe_eof_verified']);self.assertFalse(value['actor_exit_verified'])
    def test_public_exact_privacy_and_joint_wrapper_bound(self):
        config=self.config();value=self.projection();value.update(stage0b_passed=True,status='passed')
        self.assertEqual(g.validate_public(value,config['case_nonce'],config['actor_sha256']),value)
        for field in g.BOOL_FIELDS:
            bad=copy.deepcopy(value);bad[field]=1
            with self.assertRaises(ValueError):g.validate_public(bad,config['case_nonce'],config['actor_sha256'])
        value=g.default_public(config['case_nonce'],config['actor_sha256']);value['failure']='configuration'
        wrapper={'schema_version':1,'stage0b':value,'launcher':{'phase':'configuration','failure':'work_budget_exhausted','python_exit_code':-2147483648,'process_exit_confirmed':False,'timed_out':False,'budget_exhausted':False}}
        raw=(json.dumps(wrapper,indent=2)+'\n').encode()
        self.assertLessEqual(len(raw),4096)
        self.assertNotIn(config['case_nonce'].encode(),raw);self.assertNotIn(b'S-1-',raw)
        self.assertNotIn(b'controller_pid',raw)
    def test_old_report_and_capabilities_cannot_pass(self):
        self.assertFalse(self.projection(lambda p,r,o:r.update(schema_version=1))['launcher_identity_verified'])
        self.assertFalse(self.projection(lambda p,r,o:p['actor'].update(tokenCapabilities=['S-1-15-3-3']))['actor_identity_verified'])


class CapacityAndIOTests(unittest.TestCase):
    def test_copy_is_create_new_rehashed_and_capacity_is_two_actual_copies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve(strict=True);source=root/'actor.exe';data=b'MZ'+b'x'*510;source.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest();target=root/'windows_identity_actor.exe'
            self.assertEqual(g.stage_actor(source,target,digest,l),512)
            self.assertEqual(g.capacity_requirement(512,100),1024+100+1048576)
            with self.assertRaises(FileExistsError):g.stage_actor(source,target,digest,l)
            with self.assertRaises(ValueError):g.stage_actor(source,root/'bad.exe','a'*64,l)
            with patch.object(g.shutil,'disk_usage',return_value=SimpleNamespace(free=1)):
                with self.assertRaises(ValueError):g.ensure_space(root,2)
    def test_private_duplicate_nonfinite_recursion_and_bounds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve(strict=True)/'report.json'
            for raw,reason in ((b'{"x":1,"x":2}','duplicate'),(b'{"x":NaN}','nonfinite'),
                    (b'['*20000+b']'*20000,'json'),(b'x'*131073,'bound'),
                    ('{} '.encode('utf-16'),'utf8'),('{} '.encode('utf-32'),'utf8')):
                path.write_bytes(raw)
                with self.assertRaisesRegex(l.GateFailure,'^private_report_'+reason+'$'):l.read_private(path)
    def test_private_close_error_is_closed_and_attempted_once(self):
        stream=SimpleNamespace(read=lambda n:b'{}',close=lambda:None)
        calls=[]
        def close():calls.append(1);raise OSError('private path')
        stream.close=close
        with patch.object(l,'checked_path'),patch.object(Path,'open',return_value=stream):
            with self.assertRaisesRegex(l.GateFailure,'^private_report_close_uncertain$'):l.read_private(Path('x'))
        self.assertEqual(calls,[1])
        self.assertTrue(any(owner is stream for owner in l._RETAINED_PRIVATE_STREAMS))
        with self.assertRaises(l.GateFailure):l.close_private_once(stream)
        self.assertEqual(calls,[1])
    def test_write_close_uncertainty_retains_exact_owner_without_retry(self):
        calls=[]
        stream=SimpleNamespace(write=lambda data:len(data),flush=lambda:None)
        def close():calls.append(1);raise OSError('private writer')
        stream.close=close
        with patch.object(Path,'open',return_value=stream):
            with self.assertRaisesRegex(l.GateFailure,'private_report_close_uncertain'):
                l.write_private_bytes(Path('fresh'),b'fixed')
        self.assertEqual(calls,[1])
        self.assertTrue(any(owner is stream for owner in l._RETAINED_PRIVATE_STREAMS))
        with self.assertRaises(l.GateFailure):l.close_private_once(stream)
        self.assertEqual(calls,[1])
    def test_every_conflicting_config_key_is_rejected_by_presence(self):
        config={'stage0b':dict(enabled=True,case_nonce='a'*32,actor_sha256='b'*64)}
        for key in ('n0a','n0a_udp','n0a_udp_parent','n0a_udp6','capture'):
            for bad in (None,{},False,{'enabled':False},{'enabled':1},'bad'):
                value=dict(config);value[key]=bad
                with patch.object(g,'bounded',return_value=json.dumps(value).encode()):
                    with self.assertRaises(ValueError):g.configuration(r'C:\RuleProxyCI\ruleproxy-vm-config.json')
    def test_native_report_duplicate_and_oversize_never_normalized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve(strict=True)/'actor.json'
            for data,reason in ((b'{"pid":42,"pid":42}','duplicate'),
                    (b'{"pipeSucceeded":true,"pipeSucceeded":true}','duplicate'),
                    (b' '*8193,'bound'),('{"pid":42}'.encode('utf-16'),'utf8')):
                path.write_bytes(data)
                with self.assertRaisesRegex(l.GateFailure,'^private_report_'+reason+'$'):l.read_private(path,8192)

    def test_default_off_constructs_no_native_api(self):
        with patch.object(g,'EXECUTION_ENABLED',False),patch.object(g,'launcher_module',side_effect=AssertionError('native')):
            value=g.execute(dict(enabled=True,case_nonce='a'*32,actor_sha256='a'*64),D,F)
        self.assertEqual(value['failure'],'disabled');self.assertFalse(value['launcher_creation_observed'])


class ActualModuleCompositionTests(unittest.TestCase):
    def compose(self, mutation=None, after_copy=None, inner_close_late=False):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();(root/'.github').mkdir();(root/'ruleproxy').mkdir();(root/'runtime').mkdir()
            for name in ('windows_identity_ordinary_launcher.py','windows_identity_pipe_probe.py',
                         'windows_identity_proof.py','windows_psec_compartment_smoke.py','windows_identity_stage0b_guest.py'):
                (root/'.github'/name).write_bytes((ROOT/'.github'/name).read_bytes())
            (root/'ruleproxy/windows_app_process.py').write_bytes((ROOT/'ruleproxy/windows_app_process.py').read_bytes())
            (root/'runtime/python.exe').write_bytes(b'fixture')
            actor=b'MZ'+b'x'*510;(root/'actor.exe').write_bytes(actor)
            config=dict(enabled=True,case_nonce='a'*32,actor_sha256=hashlib.sha256(actor).hexdigest())
            outer,inner=API(),API();inner.pid=33
            def probe_run():
                command=inner.command
                self.assertEqual(command[command.index('--deadline-qpc')+1],str(D))
                self.assertEqual(command[command.index('--qpc-frequency')+1],str(F))
                self.assertEqual(command[command.index('--case-nonce')+1],config['case_nonce'])
                work=Path(command[command.index('--work')+1]);work.mkdir();(work/'output').mkdir()
                value=evidence(config);native=copy.deepcopy(value['actor'])
                if mutation:mutation(value,native)
                (work/'report.json').write_text(json.dumps(value))
                (work/'output/actor.json').write_text(json.dumps(native))
            inner.after_resume=probe_run
            if inner_close_late:
                original_close=inner.close
                def close(handle):
                    original_close(handle)
                    if handle==100:inner.now=D-5*F+1
                inner.close=close
            def launcher_run():
                import io,contextlib
                stdout=io.StringIO()
                with patch.object(l,'NativeAPI',return_value=inner),contextlib.redirect_stdout(stdout):
                    self.launcher_code=l.main(outer.command[5:])
                (outer.work/'controller.stdout').write_text(stdout.getvalue())
            outer.after_resume=launcher_run
            original_stage=g.stage_actor
            def stage(*args):
                result=original_stage(*args)
                if after_copy:after_copy(outer)
                return result
            fakeos=SimpleNamespace(name='nt',path=os.path,getpid=lambda:32)
            with patch.object(g,'EXECUTION_ENABLED',True),patch.object(g,'os',fakeos), \
                 patch.object(l,'os',fakeos),patch.object(g,'launcher_module',return_value=l), \
                 patch.object(l,'ROOT',root),patch.object(l,'PROBE',root/'.github/windows_identity_pipe_probe.py'), \
                 patch.object(g.sys,'base_prefix',str(root/'runtime')),patch.object(g.sys,'executable',str(root/'runtime/python.exe')), \
                 patch.object(g,'stage_actor',side_effect=stage):
                result=g.execute(config,D,F,root=root,api=outer)
            return result,outer,inner

    def test_real_adapter_launcher_probe_checks_and_native_read_compose(self):
        result,outer,inner=self.compose()
        self.assertTrue(result['stage0b_passed'],result)
        self.assertEqual(self.launcher_code,0)
        self.assertEqual(sum(e[0]=='create_suspended' for e in outer.events),1)
        self.assertEqual(sum(e[0]=='create_suspended' for e in inner.events),1)
        self.assertNotIn('existing_linked_limited_token',json.dumps(result))
    def test_native_embedded_report_mismatch_cannot_claim_echo(self):
        result,_,_=self.compose(lambda value,native:native['pipe'].update(bytesRead=31))
        self.assertFalse(result['stage0b_passed']);self.assertFalse(result['pipe_echo_verified'])
        self.assertTrue(result['launcher_creation_observed'])
    def test_good_echo_survives_nested_profile_cleanup_failure(self):
        result,_,_=self.compose(lambda value,native:value['cleanup'].update(profile_deleted=False))
        self.assertFalse(result['stage0b_passed']);self.assertTrue(result['pipe_echo_verified'])
        self.assertFalse(result['nested_cleanup_verified'])
    def test_late_launcher_token_close_cannot_report_pass_but_echo_survives(self):
        result,_,_=self.compose(inner_close_late=True)
        self.assertEqual(self.launcher_code,1)
        self.assertFalse(result['stage0b_passed'])
        self.assertTrue(result['pipe_echo_verified'])
        self.assertFalse(result['nested_cleanup_verified'])

    def test_copy_latency_cannot_borrow_probe_cleanup_reserve(self):
        result,outer,_=self.compose(after_copy=lambda api:setattr(api,'now',1090000))
        self.assertFalse(result['stage0b_passed'])
        self.assertFalse(any(e[0]=='create_suspended' for e in outer.events))



class ClosedDiagnosticTests(unittest.TestCase):
    def test_windows_component_dispatch_and_canonical_parent_boundary(self):
        import io,stat
        for components in (('probe','report.json'),('launcher','report.json'),('output','actor.json'),('controller.stdout',)):
            windows=PureWindowsPath('C:/owned').joinpath(*components)
            self.assertFalse(str(windows).endswith('/'+'/'.join(components)))
            self.assertTrue(path_tail(windows,*components))
            self.assertFalse(path_tail(windows,*components[:-1],'different'))
        class AliasPath(PureWindowsPath):
            def lstat(self):return SimpleNamespace(st_mode=stat.S_IFREG,st_file_attributes=0)
            def resolve(self,strict=False):return AliasPath(str(self).replace('RUNNER~1','runneradmin'))
            def is_file(self):return True
            def open(self,mode):return io.BytesIO(b'{}')
        raw=AliasPath('C:/Users/RUNNER~1/AppData/Local/Temp/owned/report')
        with patch.object(l,'Path',AliasPath),patch.object(l.os.path,'abspath',side_effect=lambda p:p):
            with self.assertRaisesRegex(l.GateFailure,'^path_outside_owned_root$'):
                l.read_private(raw,32)
            self.assertEqual(g.read_diagnostic_file(l,raw,32),(None,'read_error'))
            self.assertEqual(g.read_diagnostic_file(l,raw.resolve(strict=True),32),({},'parsed'))

    def test_all_private_read_states_are_distinct_and_strict(self):
        fixtures=[(b'{}','parsed'),(b'{"a":1,"a":2}','duplicate'),(b'{"a":NaN}','nonfinite'),
                  (b'[]','not_object'),(b'{}{}','json'),(b'{}trailing','json'),
                  ('{}'.encode('utf-16'),'utf8'),(b'\xff','utf8'),(b'x'*33,'overbound')]
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp).resolve(strict=True)/'report'
            for raw,expected in fixtures:
                path.write_bytes(raw)
                value,state=g.read_diagnostic_file(l,path,32)
                self.assertEqual(state,expected)
                self.assertEqual(value is not None,state=='parsed')
            path.unlink()
            self.assertEqual(g.read_diagnostic_file(l,path,32),(None,'missing'))
        with patch.object(l,'read_private',side_effect=PermissionError('PRIVATE')):
            self.assertEqual(g.read_diagnostic_file(l,Path('unused'),32),(None,'read_error'))
        with patch.object(l,'read_private',side_effect=l.GateFailure('private_report_close_uncertain')):
            self.assertEqual(g.read_diagnostic_file(l,Path('unused'),32),(None,'close_uncertain'))

    def test_missing_later_file_does_not_erase_earlier_bound_identity(self):
        original=l.read_private
        for role in ('probe','native'):
            def read(path,limit=l.MAX_REPORT):
                if (role=='probe' and path_tail(path,'probe','report.json') or role=='native' and path_tail(path,'output','actor.json')):
                    raise FileNotFoundError('private')
                return original(path,limit)
            with patch.object(l,'read_private',side_effect=read):
                value,_,_=ActualModuleCompositionTests().compose()
            self.assertTrue(value['launcher_identity_verified'])
            self.assertTrue(value['probe_creation_observed'])
            self.assertEqual(value['probe_identity_verified'],role=='native')
            self.assertFalse(value['stage0b_passed']);self.assertFalse(value['pipe_echo_verified'])
            self.assertEqual(value['diagnostic']['reads'][1 if role=='probe' else 2],'missing')

    def test_missing_launcher_report_retains_only_owned_stdout_observation(self):
        original=l.read_private
        def read(path,limit=l.MAX_REPORT):
            if path_tail(path,'launcher','report.json'):
                raise FileNotFoundError('private')
            return original(path,limit)
        with patch.object(l,'read_private',side_effect=read):
            value,_,_=ActualModuleCompositionTests().compose()
        self.assertFalse(value['launcher_identity_verified'])
        self.assertFalse(value['probe_identity_verified'])
        self.assertEqual(value['diagnostic']['reads'][0],'missing')
        self.assertEqual(value['diagnostic']['execution_sources'][1],'owned_stdout')
        self.assertEqual(value['diagnostic']['execution_sources'][2],'none')
        self.assertFalse(value['stage0b_passed'])

    def test_report_close_uncertainty_is_not_hidden_by_projection(self):
        original=l.read_private
        def read(path,limit=l.MAX_REPORT):
            if path_tail(path,'output','actor.json'):
                raise l.GateFailure('private_report_close_uncertain')
            return original(path,limit)
        with patch.object(l,'read_private',side_effect=read):
            value,_,_=ActualModuleCompositionTests().compose()
        self.assertTrue(value['launcher_identity_verified'])
        self.assertFalse(value['adapter_cleanup_verified'])
        self.assertFalse(value['stage0b_passed'])
        self.assertEqual(value['diagnostic']['reads'][2],'close_uncertain')

    def test_stdout_close_failure_retains_echo_but_forbids_cleanup(self):
        original=l.read_private
        def read(path,limit=l.MAX_REPORT):
            if path_tail(path,'controller.stdout'):
                raise l.GateFailure('private_report_close_uncertain')
            return original(path,limit)
        with patch.object(l,'read_private',side_effect=read):
            value,_,_=ActualModuleCompositionTests().compose()
        self.assertTrue(value['pipe_echo_verified'])
        self.assertFalse(value['adapter_cleanup_verified'])
        self.assertFalse(value['stage0b_passed'])
        self.assertEqual(value['diagnostic']['stdout_reads'],['close_uncertain']*2)

    def test_owned_stdout_binding_is_not_private_report_identity(self):
        import io,contextlib
        args=SimpleNamespace(case_nonce='a'*32,actor_sha256='b'*64,deadline_qpc=D,qpc_frequency=F)
        stream=io.StringIO();record=l.diagnostic_new();l.diagnostic_stage(record,'initial_token')
        l.diagnostic_error(record,l.NativeFailure('OpenProcessToken',5))
        with contextlib.redirect_stdout(stream):l.emit_scoped_diagnostic(args,record)
        raw=stream.getvalue().encode();self.assertLessEqual(len(raw),1024)
        value=json.loads(raw);launch=inner_launch()
        config=dict(case_nonce=args.case_nonce,actor_sha256=args.actor_sha256)
        self.assertEqual(g.owned_stdout_execution(value,launch,config,D,F,l),record)
        self.assertNotIn(args.case_nonce,stream.getvalue())
        for key,bad in [('case_nonce_sha256','0'*64),('actor_sha256','0'*64),('deadline_qpc',D-1),('qpc_frequency',F+1),('schema_version',True)]:
            altered=copy.deepcopy(value);altered[key]=bad
            self.assertIsNone(g.owned_stdout_execution(altered,launch,config,D,F,l))
        for key in ('native_identity_verified_before_resume',):
            altered=copy.deepcopy(launch);altered[key]=False
            self.assertIsNone(g.owned_stdout_execution(value,altered,config,D,F,l))
        launch['cleanup']['process_exit_confirmed']=False
        self.assertIsNone(g.owned_stdout_execution(value,launch,config,D,F,l))

    def test_emission_preserves_original_exception_exit_and_invalid_nonce_unknown(self):
        import io,contextlib
        args=['--actor','x','--actor-sha256','b'*64,'--work','w','--report','r','--current-ordinary-only','--case-nonce','a'*32,'--deadline-qpc',str(D),'--qpc-frequency',str(F)]
        class Broken:
            def write(self,*a):raise OSError('PRIVATE')
        with patch.object(l,'run_scoped',return_value=9),patch.object(l.sys,'stdout',Broken()):
            self.assertEqual(l.main(args),9)
        original=ValueError('PRIVATE')
        with patch.object(l,'run_scoped',side_effect=original),patch.object(l.sys,'stdout',Broken()):
            with self.assertRaises(ValueError) as raised:l.main(args)
            self.assertIs(raised.exception,original)
        stream=io.StringIO()
        invalid=SimpleNamespace(case_nonce='private-unvalidated',actor_sha256='b'*64,deadline_qpc=D,qpc_frequency=F)
        with contextlib.redirect_stdout(stream):l.emit_scoped_diagnostic(invalid,l.diagnostic_new())
        self.assertEqual(stream.getvalue(),'')

    def test_diagnostic_enums_types_and_native_error_domain(self):
        d=g.default_diagnostic();g.validate_diagnostic(d)
        changes=[lambda d:d.update(v=True),lambda d:d['held'].update(exit_code=True),
                 lambda d:d['held'].update(resumed=True),lambda d:d['held'].update(exit_observed=True),lambda d:d['reads'].__setitem__(0,'PRIVATE'),
                 lambda d:d['bindings'].__setitem__(0,'PRIVATE'),lambda d:d['stdout_reads'].append('parsed'),
                 lambda d:d['execution_sources'].__setitem__(0,'owned_stdout')]
        for change in changes:
            value=copy.deepcopy(d);change(value)
            with self.assertRaises((ValueError,l.GateFailure)):g.validate_diagnostic(value)
        for exc,operation in [(ValueError('PRIVATE'),None),(l.GateFailure('qpc_expired'),None),(OSError('PRIVATE'),'profile')]:
            record=l.diagnostic_new();l.diagnostic_error(record,exc,operation)
            self.assertIsNone(record[4]);self.assertNotIn('PRIVATE',json.dumps(record));l.validate_execution(record)
        record=l.diagnostic_new();l.diagnostic_stage(record,'token');l.diagnostic_error(record,l.NativeFailure('OpenProcessToken',5))
        l.diagnostic_stage(record,'cleanup');l.diagnostic_error(record,l.NativeFailure('CloseHandle',6))
        self.assertEqual(record,['cleanup','token','native','token',5])

    def test_binding_stages_and_optional_bad_diagnostic_do_not_change_core_pass(self):
        config=dict(case_nonce='a'*32,actor_sha256='a'*64);launch=inner_launch(32)
        for field,value,stage in [('schema_version',True,'schema'),('case_nonce','b'*32,'nonce'),('actor_sha256','b'*64,'hash'),('deadline_qpc',D-1,'deadline'),('controller_pid',99,'identity')]:
            r=report(config);r[field]=value
            self.assertEqual(g.launcher_binding_stage(r,launch,config,t.ordinary()['sid'],D,F),stage)
        def mutation(probe,native):probe['diagnostic_execution']=['PRIVATE']
        value,_,_=ActualModuleCompositionTests().compose(mutation)
        self.assertTrue(value['stage0b_passed'])
        self.assertNotIn('PRIVATE',json.dumps(value))

    def test_full_wrapper_worst_bound_preserves_all_old_fields(self):
        v=g.default_public('a'*32,'f'*64);v['failure']='configuration'
        longest=lambda seq:max(seq,key=len)
        d=v['diagnostic'];d['held'].update(created=True,resumed=False,exit_observed=True,exit_code=0xffffffff)
        d['reads']=['parsed']*3;d['stdout_reads']=['parsed']*2
        d['bindings']=['verified']*3
        d['execution_sources']=['owner','owned_stdout','owned_stdout']
        d['execution']=[[longest(l.DIAGNOSTIC_STAGES),longest(l.DIAGNOSTIC_STAGES),'native',longest(l.DIAGNOSTIC_OPERATIONS),0xffffffff] for _ in range(3)]
        g.validate_public(v,'a'*32,'f'*64)
        envelope=dict(schema_version=1,stage0b=v,launcher=dict(phase='configuration',failure='work_budget_exhausted',python_exit_code=-2147483648,process_exit_confirmed=False,timed_out=False,budget_exhausted=False))
        host=dict(schema_version=1,stage='stage0b-host',report=envelope,report_validation='unavailable',original_stage0_passed=False,vm_destroyed=False,product_acceptance=False,stage0b_ipc_qualified=False)
        for obj in (v,envelope,host):self.assertLessEqual(len((json.dumps(obj,ensure_ascii=True,indent=2)+'\n').encode()),4096)
        self.assertTrue(set(g.BOOL_FIELDS).issubset(v))
        self.assertNotIn('a'*32,json.dumps(host))
        # Independent maxima ceiling, intentionally not a jointly valid report.
        d['held'].update(created=False,exit_observed=False,exit_code=-2147483648)
        d['reads']=[longest(g.READ_STATES)]*3;d['stdout_reads']=[longest(g.READ_STATES)]*2
        d['bindings']=[longest(g.BINDING_STATES)]*3
        d['execution_sources']=[longest(g.EXECUTION_SOURCES)]*3
        d['execution']=[[longest(l.DIAGNOSTIC_STAGES),longest(l.DIAGNOSTIC_STAGES),longest(l.DIAGNOSTIC_CATEGORIES),longest(l.DIAGNOSTIC_OPERATIONS),0xffffffff] for _ in range(3)]
        self.assertEqual([len((json.dumps(obj,ensure_ascii=True,indent=2)+'\n').encode()) for obj in (v,envelope,host)],[1922,2335,2740])

    def test_actual_isolated_production_import_and_projection_composition(self):
        import subprocess,sys
        script="""import importlib.util,sys,json
from pathlib import Path, PureWindowsPath
r=Path(ROOT_LITERAL)
def load(n,p):
 s=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
support=load('windows_identity_test_support',r/'tests/windows_identity_test_support.py');sys.modules['windows_identity_test_support']=support
fixture=load('isolated_stage0b_fixture',r/'tests/test_windows_identity_stage0b_guest.py')
v,_,_=fixture.ActualModuleCompositionTests().compose()
assert v['stage0b_passed'] and v['diagnostic']['reads']==['parsed']*3
assert v['diagnostic']['execution_sources'][1]=='owned_stdout'
assert str(r) not in sys.path
sys.stdout.buffer.write(b'isolated_composition_ok'+bytes([10]));sys.stdout.buffer.flush()
""".replace('ROOT_LITERAL',repr(str(ROOT)))
        try:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',script],capture_output=True,timeout=10,check=False)
        except (OSError,subprocess.TimeoutExpired):
            self.fail('isolated composition unavailable')
        self.assertEqual(result.returncode,0,'isolated composition failed')
        self.assertEqual(result.stdout,b'isolated_composition_ok\n')


if __name__=='__main__':unittest.main()
