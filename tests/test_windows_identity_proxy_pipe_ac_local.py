"""Pure fake-clock/Win32 tests. No native process/profile/ACL/network is used."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_ac_test', ROOT / '.github/windows_identity_proxy_pipe_ac_local.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def ordinary():
    return dict(sid='S-1-5-21-1-2-3-1001', session_id=1, token_type=1, elevation_type=1,
        elevated=False, integrity_rid=8192, admin_attributes=None, appcontainer=False,
        appcontainer_sid=None, capability_count=0, ui_access=False)


def plan(source='5'*64):
    return dict(schema_version=1, scope='one-local-zero-cap-pair-no-network-v1', device_sha256='1'*64,
        actor_sha256='3'*64, manifest_sha256='4'*64, source_sha256=source,
        recovery_reference='device owner reviewed recovery journal and external backup reference',
        residue_review_acknowledged=True)


def positive(pair_config):
    value = m.guest.default_public(pair_config)
    value['facts'] = {key: True for key in m.guest.FACTS}
    value.update(status='passed', ac_pipe_passed=True,
        pair=dict(case=0, admitted=True, created=3, resumed=3, exit_observed=3, identity_verified=3,
            parent_data_closed=True, reports_bound=3, observations=[177,78], core_failure=[0,0],
            pipe_eof=[True,True], native_close=[True,True], cleanup_confirmed=True, job_empty=True,
            watchdog_stop=False, expected_outcome=True, failure=None),
        diagnostic=dict(phase='complete', error_domain='none', error_code=None, controller_report='bound'))
    return m.guest.validate_public(value, pair_config)


class ClockAPI:
    def __init__(self):
        self.now = 10000; self.closed = []; self.atomic_job_requested = False; self.created = []
    def qpc_frequency(self): return 1000
    def qpc(self): return self.now
    def current_token(self): return 41
    def identity(self, token): return ordinary()
    def compartment(self): return 1
    def close(self, handle): self.closed.append(handle)
    def windows_x64(self): return True
    def device_sha256(self): return '1'*64
    def private_directory(self, path, sid): self.created.append(path); path.mkdir()


class LocalTests(unittest.TestCase):
    def test_default_cli_only_calls_readonly_preflight(self):
        value=m.blank('preflight'); value['failure']='inputs'
        with mock.patch.object(m, 'preflight', return_value=value) as pre, \
             mock.patch.object(m, 'run_local') as run, mock.patch.object(m.sys, 'stdout'):
            self.assertEqual(m.main([]), 1)
        pre.assert_called_once(); run.assert_not_called()

    def test_runtime_flag_without_approval_never_constructs_native_api(self):
        with mock.patch.object(m, 'LocalNativeAPI') as api:
            value=m.run_local(None,None,None,None,None,None)
        api.assert_not_called(); self.assertEqual(value['failure'],'platform')
        self.assertFalse(value['local_ipc_qualified'])

    def test_recovery_plan_closed_device_artifact_source_bindings(self):
        expected=dict(device='1'*64, actor_hash='3'*64, manifest_hash='4'*64, source_hash='5'*64)
        self.assertEqual(m.valid_plan(plan(), **expected), plan())
        for key, bad in [('schema_version', True),('scope','other'),('residue_review_acknowledged',1),
                         ('device_sha256','f'*64),('source_sha256','a'*64),('recovery_reference','')]:
            value=plan(); value[key]=bad
            with self.subTest(key=key), self.assertRaises(ValueError):m.valid_plan(value,**expected)
        with self.assertRaises(ValueError):m.valid_plan(dict(plan(), snapshot_verified=True),**expected)

    def test_preflight_creates_no_directory_and_rejects_nonordinary(self):
        api=ClockAPI()
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
             mock.patch.object(m,'source_snapshot',return_value=({}, {}, '5'*64)), \
             mock.patch.object(m,'admitted_inputs',return_value=({}, {}, '5'*64, None,None,None)), \
             mock.patch.object(m,'bounded',return_value=m.encode(plan())):
            value=m.preflight('actor','manifest','3'*64,'4'*64,'parent','plan',api=api)
        self.assertEqual(value['status'],'ready'); self.assertEqual(api.created,[])
        self.assertEqual(api.closed,[41]); self.assertFalse(value['local_ipc_qualified'])
        api.identity=lambda token:dict(ordinary(),elevated=True)
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')):
            value=m.preflight(api=api)
        self.assertEqual(value['failure'],'identity'); self.assertEqual(api.created,[])

    def test_x64_is_native_not_pointer_size_alone(self):
        api=ClockAPI(); api.windows_x64=lambda:False
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')):
            value=m.preflight(api=api)
        self.assertEqual(value['failure'],'platform'); self.assertFalse(value['checks']['windows_x64'])

    def exercise(self, *, setup_ms=0, unknown_exit=False, missing=False, report_mutation=None,
                 cleanup_bad=False, worker_failure=False, late=False, interrupt=False, changed_plan=False):
        api=ClockAPI(); calls={}
        files={name:b'# fixed fixture\n' for name in m.SOURCES}
        hashes={name:m.sha(raw) for name,raw in files.items()}; source=m.sha(m.encode(hashes))
        recovery=plan(source)
        ready=m.blank('preflight'); ready.update(status='ready',checks={k:True for k in ready['checks']},
            source_sha256=source,device_bound=True,actor_sha256='3'*64,manifest_sha256='4'*64,
            recovery_plan_sha256=m.sha(m.encode(recovery)))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); actor=root/'windows_identity_proxy_pipe_actor.exe'; actor.write_bytes(b'MZ'+b'x'*510)
            manifest=root/'identity-proxy-pipe-manifest.json'; manifest.write_bytes(b'{}\n')
            recovery_path=root/'plan.json'; recovery_path.write_bytes(m.encode(recovery))
            def admit(*args,**kwargs):
                api.now += setup_ms
                if changed_plan:recovery_path.write_bytes(m.encode(dict(recovery,recovery_reference='changed')))
                return files,hashes,source,actor,manifest,root
            def launch(unused_api,command,work,parent,expected,**kwargs):
                calls.update(command=command,kwargs=kwargs); api.atomic_job_requested=True
                stage=work.parent; config=m.guest.decode((stage/'worker-config.json').read_bytes()); calls['config']=config
                record=dict(started=True,resumed=True,native_identity_verified_before_resume=True,child_pid=123,
                    exit_code=0,timed_out=False,cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,
                        process_exit_confirmed=not unknown_exit,close_uncertain=False,errors=[]))
                if cleanup_bad:record['cleanup']['job_empty']=False
                if worker_failure:record['exit_code']=1
                report=m.worker_expected(config,parent,record); report['result']=positive(config['pair'])
                if report_mutation:report_mutation(report)
                if not missing:(stage/'worker-report.json').write_bytes(m.encode(report))
                if late:api.now=config['root_deadline_qpc']+1
                if interrupt:raise KeyboardInterrupt()
                return record
            with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
                 mock.patch.object(m,'preflight',return_value=ready),mock.patch.object(m,'admitted_inputs',side_effect=admit), \
                 mock.patch.object(m.controller,'verify_ac_artifact',side_effect=lambda a, *_:(a,'3'*64)), \
                 mock.patch.object(m.launcher,'launch_owned',side_effect=launch):
                value=m.run_local(actor,manifest,'3'*64,'4'*64,root,recovery_path,approved=True,api=api,root=root,
                    ids=lambda size: 'a'*32 if not api.created else 'b'*32)
            calls['created']=list(api.created)
            calls['remaining_trees']=list(root.glob('local-ac-*'))
            return value,api,calls

    def test_guard_worker_success_uses_original_epoch_and_reserved_deadlines(self):
        value,api,calls=self.exercise(setup_ms=7000)
        self.assertTrue(value['local_ipc_qualified']); self.assertEqual(value['status'],'passed')
        config=calls['config']; self.assertEqual(config['root_deadline_qpc'],130000)
        self.assertEqual(config['worker_deadline_qpc'],125000)
        self.assertEqual(config['qpc_frequency'],1000)
        self.assertEqual(calls['kwargs']['work_cutoff'],127000)
        self.assertEqual(calls['kwargs']['cleanup_cutoff'],130000)
        self.assertTrue(value['cleanup']['tree_retained']); self.assertFalse(value['cleanup']['recovery_required'])
        text=m.encode(value).decode('ascii')
        for secret in ('a'*32,ordinary()['sid'],'worker_pid','worker_deadline_qpc','local-ac-','device_sha256','1'*64):
            self.assertNotIn(secret,text)
        self.assertLessEqual(len(text),4096)

    def test_setup_consumes_budget_and_no_worker_is_created_if_it_cannot_fit(self):
        value,api,calls=self.exercise(setup_ms=90000)
        self.assertFalse(value['local_ipc_qualified']); self.assertNotIn('command',calls)
        self.assertEqual(value['failure'],'staging')
        self.assertFalse(value['cleanup']['recovery_required']);self.assertEqual(calls['created'],[])

    def test_unknown_exit_or_missing_report_is_not_cleanup_or_ipc_success(self):
        for options in ({'unknown_exit':True},{'missing':True}):
            value,api,calls=self.exercise(**options)
            self.assertIsNone(value['ipc']);self.assertFalse(value['local_ipc_qualified'])
            self.assertTrue(value['cleanup']['recovery_required']);self.assertEqual(len(calls['remaining_trees']),1)

    def test_partial_positive_survives_late_or_outer_cleanup_failure(self):
        for options in ({'late':True},{'cleanup_bad':True},{'worker_failure':True}):
            value,_,_=self.exercise(**options)
            self.assertFalse(value['local_ipc_qualified'])
            self.assertEqual(value['ipc']['result']['pair']['observations'],[177,78])
        value,_,_=self.exercise(cleanup_bad=True)
        self.assertTrue(value['cleanup']['recovery_required'])

    def test_worker_report_must_bind_pid_sid_deadlines_and_config(self):
        for key,bad in (('worker_pid',999),('worker_sid','S-1-5-21-9-9-9-1001'),
                        ('worker_deadline_qpc',130000),('config_sha256','e'*64),('qpc_frequency',1001)):
            value,_,_=self.exercise(report_mutation=lambda v,k=key,b=bad:v.update({k:b}))
            self.assertFalse(value['local_ipc_qualified']);self.assertIsNone(value['ipc'])
            self.assertTrue(value['cleanup']['recovery_required'])

    def test_changed_recovery_plan_stops_before_worker(self):
        value,_,calls=self.exercise(changed_plan=True)
        self.assertFalse(value['local_ipc_qualified']);self.assertNotIn('command',calls)

    def test_interrupt_is_inconclusive_and_retains_recovery(self):
        value,_,_=self.exercise(interrupt=True)
        self.assertFalse(value['local_ipc_qualified']);self.assertTrue(value['cleanup']['recovery_required'])

    def test_public_schema_cannot_add_raw_identity_or_mutate_nested_guest_facts(self):
        value,_,_=self.exercise()
        for mutate in (lambda v:v.update(raw_sid='private'),lambda v:v['checks'].update(ordinary=1),
                       lambda v:v['ipc']['result']['facts'].update(images_verified=1),
                       lambda v:v['ipc']['result'].update(product_acceptance=True)):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_public(changed)

    def test_public_ready_and_passed_require_all_corresponding_commitments(self):
        ready=m.blank('preflight');ready.update(status='ready',checks={k:True for k in ready['checks']})
        with self.assertRaises(ValueError):m.validate_public(ready)
        value,_,_=self.exercise()
        for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','run_nonce_sha256','device_bound'):
            changed=copy.deepcopy(value);changed[key]=None
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(changed)
        changed=copy.deepcopy(value);changed['cleanup']['tree_retained']=False
        with self.assertRaises(ValueError):m.validate_public(changed)

    def test_source_snapshot_is_closed_and_current_native_manifest_binding(self):
        _,hashes,source=m.source_snapshot()
        self.assertEqual(set(hashes),set(m.SOURCES));self.assertEqual(source,m.sha(m.encode(hashes)))
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in (*m.SOURCES,*m.NATIVE_SOURCES.values()):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'fixed')
            actor=root/'windows_identity_proxy_pipe_actor.exe';actor.write_bytes(b'MZ'+b'x'*510)
            manifest=root/'identity-proxy-pipe-manifest.json'
            manifest.write_bytes(m.encode({key:'f'*64 for key in m.NATIVE_SOURCES}))
            with mock.patch.object(m.controller,'verify_ac_artifact',return_value=(actor,'3'*64)):
                with self.assertRaisesRegex(ValueError,'native_source_binding'):
                    m.admitted_inputs(actor,manifest,'3'*64,'4'*64,root,root=root)

    def test_worker_in_regular_checkout_is_rejected_before_api_or_execute(self):
        config=dict(schema_version=1,stage='local-proxy-pipe-ac-worker-input',pair=dict(enabled=True,
            run_nonce='a'*32,case_nonce='b'*32,actor_sha256='3'*64,manifest_sha256='4'*64),
            root_deadline_qpc=130000,worker_deadline_qpc=125000,qpc_frequency=1000,
            source_hashes={},source_sha256='5'*64,device_sha256='1'*64,recovery_plan_sha256='6'*64,
            guard_job_name='Local\\RuleProxy.LocalGuard.'+'a'*32)
        with mock.patch.object(m.launcher,'checked_path',return_value=m.ROOT/'worker-config.json'), \
             mock.patch.object(m,'bounded',return_value=m.encode(config)),mock.patch.object(m.launcher,'NativeAPI') as api, \
             mock.patch.object(m.guest,'execute') as execute:
            with self.assertRaisesRegex(ValueError,'fresh_local_stage_required'):m.worker(m.ROOT/'worker-config.json')
        api.assert_not_called();execute.assert_not_called()

    def test_worker_original_clock_exact_guard_close_precedes_all_security_setup(self):
        config=dict(schema_version=1,stage='local-proxy-pipe-ac-worker-input',pair=dict(enabled=True,
            run_nonce='a'*32,case_nonce='b'*32,actor_sha256='3'*64,manifest_sha256='4'*64),
            root_deadline_qpc=130000,worker_deadline_qpc=125000,qpc_frequency=1000,
            source_hashes={},source_sha256='5'*64,device_sha256='1'*64,recovery_plan_sha256=m.sha(m.encode(plan())),
            guard_job_name='Local\\RuleProxy.LocalGuard.'+'a'*32)
        api=ClockAPI();events=[];stage=Path('C:/fixture/local-ac-'+'a'*32)
        def read(path,limit):return m.encode(plan()) if Path(path).name=='recovery-plan.json' else m.encode(config)
        def execute(pair,deadline,frequency,**kwargs):
            events.append(('execute',deadline,frequency));return positive(pair)
        with mock.patch.object(m,'ROOT',stage),mock.patch.object(m.launcher,'checked_path',return_value=stage/'worker-config.json'), \
             mock.patch.object(m,'bounded',side_effect=read),mock.patch.object(m.launcher,'NativeAPI',return_value=api), \
             mock.patch.object(m,'source_snapshot',return_value=({}, {}, '5'*64)), \
             mock.patch.object(m.LocalNativeAPI,'device_sha256',return_value='1'*64), \
             mock.patch.object(m.LocalNativeAPI,'verify_private_directory',side_effect=lambda *a:events.append(('private_readback',))), \
             mock.patch.object(m,'verify_guard_job',side_effect=lambda *a:events.append(('exact_job_query_closed',))), \
             mock.patch.object(m.guest,'execute',side_effect=execute),mock.patch.object(m.launcher,'write_private_bytes') as write:
            self.assertEqual(m.worker(stage/'worker-config.json'),0)
        self.assertEqual(events,[('private_readback',),('exact_job_query_closed',),('execute',125000,1000)])
        report=m.guest.decode(write.call_args.args[1])
        self.assertEqual(report['root_deadline_qpc'],130000);self.assertEqual(report['worker_deadline_qpc'],125000)

    def test_worker_wrong_guard_breakaway_or_uncertain_query_close_never_runs_guest(self):
        config=dict(schema_version=1,stage='local-proxy-pipe-ac-worker-input',pair=dict(enabled=True,
            run_nonce='a'*32,case_nonce='b'*32,actor_sha256='3'*64,manifest_sha256='4'*64),
            root_deadline_qpc=130000,worker_deadline_qpc=125000,qpc_frequency=1000,
            source_hashes={},source_sha256='5'*64,device_sha256='1'*64,recovery_plan_sha256=m.sha(m.encode(plan())),
            guard_job_name='Local\\RuleProxy.LocalGuard.'+'a'*32)
        stage=Path('C:/fixture/local-ac-'+'a'*32)
        def read(path,limit):return m.encode(plan()) if Path(path).name=='recovery-plan.json' else m.encode(config)
        for options in ({'member':False},{'limits':0x2800},{'close_fail':True}):
            api=ClockAPI();guard_api,events=AtomicWin32Tests().guard_api(**options)
            api.k=guard_api.k;api.proc=guard_api.proc
            api.close=lambda handle:guard_api.close(handle) if handle==70 else None
            api.check=guard_api.check
            with mock.patch.object(m,'ROOT',stage),mock.patch.object(m.launcher,'checked_path',return_value=stage/'worker-config.json'), \
                 mock.patch.object(m,'bounded',side_effect=read),mock.patch.object(m.launcher,'NativeAPI',return_value=api), \
                 mock.patch.object(m,'source_snapshot',return_value=({}, {}, '5'*64)), \
                 mock.patch.object(m.LocalNativeAPI,'device_sha256',return_value='1'*64), \
                 mock.patch.object(m.LocalNativeAPI,'verify_private_directory'),mock.patch.object(m.guest,'execute') as execute:
                with self.subTest(options=options),self.assertRaises((ValueError,OSError)):
                    m.worker(stage/'worker-config.json')
            execute.assert_not_called();self.assertEqual(events.count(('close',70)),1)


class Function:
    def __init__(self, fn):self.fn=fn
    def __call__(self,*args):return self.fn(*args)


class AtomicWin32Tests(unittest.TestCase):
    def api(self, *, fail_attribute=None, fail_create=False):
        api=m.LocalNativeAPI.__new__(m.LocalNativeAPI)
        api.worker_job=70;api.worker_create_attempted=False;api.atomic_job_requested=False
        api.proc=types.SimpleNamespace(_StartupInfoEx=type('Startup', (C.Structure,), {'_fields_':[
            ('StartupInfo',type('Basic',(C.Structure,),{'_fields_':[('cb',C.c_uint32),('dwFlags',C.c_uint32),
                ('hStdInput',C.c_void_p),('hStdOutput',C.c_void_p),('hStdError',C.c_void_p)]})),('lpAttributeList',C.c_void_p)]}),
            _CREATE_SUSPENDED=4,_CREATE_UNICODE_ENVIRONMENT=0x400,_EXTENDED_STARTUPINFO_PRESENT=0x80000)
        events=[]
        def initialize(attrs,count,flags,size):
            events.append(('init',count))
            if attrs is None:C.cast(size,C.POINTER(C.c_size_t))[0]=128;return 0
            return 1
        def update(attrs,flags,kind,data,size,*rest):
            count=size//C.sizeof(C.c_void_p);values=list(C.cast(data,C.POINTER(C.c_void_p))[:count])
            events.append(('attr',kind,values))
            return 0 if kind==fail_attribute else 1
        def create(*args):events.append(('create',args[5]));return 0 if fail_create else 1
        api.k=types.SimpleNamespace(InitializeProcThreadAttributeList=Function(initialize),
            UpdateProcThreadAttribute=Function(update),CreateProcessW=Function(create),
            DeleteProcThreadAttributeList=Function(lambda attrs:events.append(('delete',))))
        api.check=lambda ok,op:None if ok else (_ for _ in ()).throw(OSError(op))
        api.environment=lambda work:'SystemRoot=C:\\Windows\0\0'
        api.verify_job=lambda job,process:events.append(('verify',job,process))
        return api,events

    def test_create_time_job_attribute_excludes_job_from_inherited_handle_list(self):
        api,events=self.api(); info=C.c_uint64()
        api.create_suspended(info,['python.exe','worker.py'],Path('work'),[11,12,13],None)
        self.assertIn(('attr',0x20002,[11,12,13]),events)
        self.assertIn(('attr',m.JOB_LIST,[70]),events)
        self.assertEqual(sum(event[0]=='create' for event in events),1)
        self.assertEqual(events[-1],('delete',));self.assertTrue(api.atomic_job_requested)
        api.assign_job(70,100)
        self.assertEqual(events[-1],('verify',70,100))

    def test_unsupported_job_attribute_has_no_process_or_assign_fallback(self):
        api,events=self.api(fail_attribute=m.JOB_LIST)
        with self.assertRaises(OSError):api.create_suspended(C.c_uint64(),['python.exe'],Path('work'),[11,12,13],None)
        self.assertFalse(any(event[0]=='create' for event in events))
        self.assertFalse(api.atomic_job_requested);self.assertEqual(events[-1],('delete',))

    def test_exact_job_assignment_only_and_single_create_attempt(self):
        api,events=self.api()
        with self.assertRaises(m.launcher.GateFailure):api.assign_job(70,100)
        api.create_suspended(C.c_uint64(),['python.exe'],Path('work'),[11,12,13],None)
        with self.assertRaises(m.launcher.GateFailure):api.assign_job(71,100)
        with self.assertRaises(m.launcher.GateFailure):api.create_suspended(C.c_uint64(),['python.exe'],Path('work'),[11,12,13],None)

    def guard_api(self, *, member=True, limits=0x2000, close_fail=False):
        events=[]
        class Limits(C.Structure):_fields_=[('BasicLimitInformation',type('BasicLimit',(C.Structure,),{'_fields_':[('LimitFlags',C.c_uint32)]}))]
        def is_job(process,job,result):events.append(('member',job));C.cast(result,C.POINTER(C.c_int))[0]=int(member);return 1
        def query(job,kind,result,size,returned):events.append(('limits',job));C.cast(result,C.POINTER(Limits))[0].BasicLimitInformation.LimitFlags=limits;return 1
        def close(job):
            events.append(('close',job))
            if close_fail:raise OSError('uncertain')
        api=types.SimpleNamespace(k=types.SimpleNamespace(OpenJobObjectW=Function(lambda access,inherit,name:events.append(('open',access,inherit,name)) or 70),
            IsProcessInJob=Function(is_job),QueryInformationJobObject=Function(query),GetCurrentProcess=lambda:100),
            proc=types.SimpleNamespace(_JobExtendedLimitInfo=Limits),close=close,
            check=lambda ok,op:None if ok else (_ for _ in ()).throw(OSError(op)))
        return api,events

    def test_worker_exact_job_is_query_only_and_closed_before_return(self):
        api,events=self.guard_api();m.verify_guard_job(api,'Local\\RuleProxy.LocalGuard.'+'a'*32)
        self.assertEqual(events[0][1:3],(4,False));self.assertEqual(events[-1],('close',70))
        self.assertEqual([event[0] for event in events],['open','member','limits','close'])

    def test_wrong_job_or_breakaway_or_unknown_query_close_fails_closed_once(self):
        for options in ({'member':False},{'limits':0x2000|0x800},{'close_fail':True}):
            api,events=self.guard_api(**options)
            with self.assertRaises((ValueError,OSError)):m.verify_guard_job(api,'guard')
            self.assertEqual(events.count(('close',70)),1)

    def test_existing_named_job_is_closed_without_modifying_or_terminating_it(self):
        api=m.LocalNativeAPI.__new__(m.LocalNativeAPI);api.worker_job=None
        api.worker_job_name='Local\\RuleProxy.LocalGuard.'+'a'*32;api.worker_sid=ordinary()['sid']
        events=[]
        api.private_descriptor=lambda sid,**kwargs:60;api.close=lambda handle:events.append(('close',handle))
        api.check=lambda ok,op:None if ok else (_ for _ in ()).throw(OSError(op))
        api.k=types.SimpleNamespace(CreateJobObjectW=Function(lambda security,name:events.append(('create',name)) or 70),
            LocalFree=Function(lambda handle:events.append(('free',handle)) or 0),
            SetInformationJobObject=mock.Mock(),TerminateJobObject=mock.Mock())
        with mock.patch.object(m.C,'set_last_error',create=True),mock.patch.object(m.C,'get_last_error',return_value=183,create=True):
            with self.assertRaisesRegex(m.launcher.GateFailure,'fresh_guard_job_required'):api.create_job()
        self.assertEqual(events.count(('close',70)),1);self.assertEqual(events.count(('free',60)),1)
        api.k.SetInformationJobObject.assert_not_called();api.k.TerminateJobObject.assert_not_called()

    def test_private_directory_is_created_with_protected_dacl_and_read_back_before_return(self):
        api=m.LocalNativeAPI.__new__(m.LocalNativeAPI);events=[]
        api.private_descriptor=lambda sid:60
        api.check=lambda ok,op:None if ok else (_ for _ in ()).throw(OSError(op))
        def create(path,security):
            events.append(('create',path,security._obj.security,security._obj.inherit));return 1
        api.k=types.SimpleNamespace(CreateDirectoryW=Function(create),LocalFree=Function(lambda handle:events.append(('free',handle)) or 0))
        api.verify_private_directory=lambda path,sddl:events.append(('readback',sddl))
        api.private_directory(Path('fresh'),ordinary()['sid'])
        self.assertEqual([event[0] for event in events],['create','readback','free'])
        self.assertEqual(events[0][2:],(60,0));self.assertTrue(events[1][1].startswith('D:P'))
        self.assertEqual(events[-1],('free',60))


if __name__=='__main__':unittest.main()
