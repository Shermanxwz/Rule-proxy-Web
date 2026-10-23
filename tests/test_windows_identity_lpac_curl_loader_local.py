"""Inert tests of the new guard, with injected inner/file-reader adapters.

These tests never construct a Windows backend, load a DLL, run curl, or assert
that the injected core reports prove the real loader mechanism.
"""
import copy
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('curl_loader_local_test',ROOT/'.github/windows_identity_lpac_curl_loader_local.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
F,T=100,10000
PARENT=dict(sid='S-1-5-21-1-2-3-1001',session_id=1,token_type=1,elevation_type=3,elevated=False,integrity_rid=8192,
    admin_attributes=16,appcontainer=False,appcontainer_sid=None,capability_count=0,ui_access=False)


def observed():
    r=dict.fromkeys((*m.core.OBS_BOOLS,*m.core.FALSE_CLAIMS),False)
    r.update(dict.fromkeys(m.core.OBS_BOOLS,True));r.update(failure=None,selected_exit_code=0)
    return r

class FakeAPI:
    atomic_job_requested=True
    def __init__(self):self.now=T;self.created=[];self.native=self;self.partial=False
    def windows_x64(self):return True
    def qpc_frequency(self):return F
    def qpc(self):return self.now
    def device_sha256(self):return '1'*64
    def private_directory(self,path,sid):
        path.mkdir();self.created.append(path)
        if self.partial:raise OSError('inert partial create-directory failure')

class GuardTests(unittest.TestCase):
    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        root=Path(td.name).resolve();(root/'private').mkdir()
        files={name:b'# inert copied source; never imported as a worker\n' for name in m.SOURCES}
        hashes={k:m.sha(v) for k,v in files.items()};source=m.sha(m.encode(hashes))
        paths={k:root/name for k,name in (('wrapper',m.core.WRAPPER),('marker',m.core.MARKER),('manifest',m.core.MANIFEST),('curl','curl.exe'))}
        for k,p in paths.items():p.write_bytes(b'inert-'+k.encode())
        artifacts={k:dict(bytes=p.stat().st_size,sha256=m.sha(p.read_bytes())) for k,p in paths.items()}
        # Fixed curl release validation remains production code, but this fixture
        # exercises guard transport with a small inert file and an explicit pin adapter.
        artifacts['curl']=dict(bytes=m.core.CURL_BYTES,sha256=m.core.CURL_SHA256)
        plan=dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,run='1'*32,before_case='2'*32,selected_case='3'*32,after_case='4'*32,
            device_sha256='1'*64,source_sha256=source,artifacts=artifacts,curl_path=str(paths['curl']),recovery_reference='inert exact recovery source commitment '*12,
            **dict.fromkeys(m.core.ACKS,True))
        planpath=root/'plan.json';planpath.write_bytes(m.encode(plan));api=FakeAPI();capture={};launches=[]
        return dict(root=root,paths=paths,artifacts=artifacts,files=files,hashes=hashes,source=source,plan=plan,planpath=planpath,api=api,capture=capture,launches=launches)
    def args(self,f):
        return tuple(f['paths'][k] for k in ('wrapper','marker','manifest','curl'))+(f['artifacts'],f['root']/'private',f['planpath'])
    def config(self,f):
        return dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,**{k:f['plan'][k] for k in m.core.NONCES},start_qpc=T,frequency=F,
            root_deadline_qpc=T+120*F,deadline_qpc=T+115*F,guard_job_name='Local\\RuleProxy.LocalGuard.'+f['plan']['run'],
            source_hashes=f['hashes'],source_sha256=f['source'],device_sha256='1'*64,recovery_plan_sha256=m.sha(f['planpath'].read_bytes()),
            artifacts=f['artifacts'],curl_path=str(f['paths']['curl']))
    def fake_inner(self,private,c,*,parent,root):
        if type(private) is not dict or set(private)!={'observation'}:raise ValueError('injected malformed worker')
        m.validate_observation(private['observation']);return private
    def controls(self,root,c,parent):
        r={}
        for role in ('before','after'):
            try:r[role]=m.decode((Path(root)/('control-'+role+'.json')).read_bytes())=={'inert_positive':True}
            except (ValueError,OSError):r[role]=False
        return r
    def launch(self,f,fault):
        def go(api,argv,cwd,parent,child,**kw):
            f['launches'].append(argv);stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());m.core.config_validate(c)
            self.assertEqual((c['start_qpc'],c['deadline_qpc'],c['root_deadline_qpc'],kw['cleanup_cutoff']),(T,T+115*F,T+120*F,T+120*F))
            self.assertEqual(kw['work_cutoff'],T+117*F)
            self.assertEqual(argv[1:4],['-I','-S','-B']);self.assertEqual(argv[-2:],[ '--worker',str(stage/'worker-config.json')])
            self.assertFalse((stage/'curl.exe').exists());self.assertEqual(c['curl_path'],str(f['paths']['curl']))
            for role in ('before','after'):(stage/('control-'+role+'.json')).write_bytes(m.encode({'inert_positive':True}))
            report=dict(schema_version=1,stage='curl-loader-worker',config=c,worker_pid=77,worker_identity=parent,result={'observation':observed()})
            if fault=='bad-worker':report['result']={'bad':True}
            if fault=='worker-pid':report['worker_pid']=78
            if fault!='missing-worker':(stage/'worker-report.json').write_bytes(m.encode(report))
            (stage/'worker-result-forensic.json').write_bytes(m.encode(report))
            if fault=='late':api.now=T+120*F
            launch=dict(started=True,resumed=True,child_pid=77,child_identity=m.launcher.safe_identity(parent,parent),native_identity_verified_before_resume=True,
                timed_out=False,exit_code=1 if fault=='bad-exit' else 0,cleanup=dict(process_exit_confirmed=True,job_empty_confirmed=True,handles_closed=True))
            f['capture'].update(stage=stage,c=c,report=report,launch=launch)
            return launch
        return go
    def patches(self,f,fault=None):
        stack=ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(m.core,'ACTUAL_READY',True))
        stack.enter_context(patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])))
        stack.enter_context(patch.object(m,'inputs',return_value=f['paths']))
        stack.enter_context(patch.object(m.local,'ordinary',return_value=PARENT))
        stack.enter_context(patch.object(m.core,'verify_artifacts'))
        stack.enter_context(patch.object(m.core,'verify_system_curl',return_value=f['paths']['curl']))
        stack.enter_context(patch.object(m.core,'ordinary_controls',side_effect=self.controls,create=True))
        stack.enter_context(patch.object(m.core,'validate_result',side_effect=self.fake_inner,create=True))
        stack.enter_context(patch.object(m.core,'project',side_effect=lambda j,c,**kw:copy.deepcopy(j['observation']),create=True))
        stack.enter_context(patch.object(m.local.guest,'cleanup_verified',return_value=True))
        stack.enter_context(patch.object(m.launcher,'launch_owned',side_effect=self.launch(f,fault)))
        stack.enter_context(patch.object(m.sys,'executable',str(f['root']/'python.exe')))
        stack.enter_context(patch.object(m.sys,'base_prefix',str(f['root'])))
        (f['root']/'python.exe').write_bytes(b'inert-not-an-executable')
        return stack
    def run_guard(self,fault=None):
        f=self.fixture();f['api'].partial=fault=='partial-directory';self.patches(f,fault)
        value=m.run_local(*self.args(f),approved=True,api=f['api'],root=f['root']);return f,value
    def test_metadata_and_public_broad_claims_remain_false(self):
        self.assertIs(type(m.core.ACTUAL_READY),bool);m.validate_public(m.blank('preflight'))
        for key in m.core.FALSE_CLAIMS:
            value=m.blank('preflight');value[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(value)
    def test_default_CLI_is_inert_and_exact_worker_args_reject_mixed_modes(self):
        with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('forbidden backend')),patch('builtins.print'):
            self.assertEqual(m.main([]),1)
            with self.assertRaisesRegex(ValueError,'exact_worker_args'):m.main(['--worker','unused','--output','unused'])
    def test_explicit_false_ready_stops_before_any_factory_or_stage(self):
        with patch.object(m.core,'ACTUAL_READY',False),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('forbidden backend')):
            value=m.run_local(*(None,)*7,approved=True)
        self.assertEqual(value['failure'],'disabled');self.assertFalse(value['tree_retained']);self.assertFalse(value['recovery_required'])
    def test_preflight_bad_ack_never_constructs_API(self):
        f=self.fixture();f['plan'][m.core.ACKS[0]]=False;f['planpath'].write_bytes(m.encode(f['plan']))
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),patch.object(m,'inputs'),\
                patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('forbidden backend')):
            value=m.preflight(*self.args(f),root=f['root'])
        self.assertEqual(value['failure'],'plan');self.assertFalse(value['checks']['ordinary'])
    def test_preflight_false_ready_without_injection_is_file_only(self):
        f=self.fixture()
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),patch.object(m,'inputs'),\
                patch.object(m.core,'ACTUAL_READY',False),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('forbidden backend')):
            value=m.preflight(*self.args(f),root=f['root'])
        self.assertEqual(value['failure'],'disabled');self.assertTrue(value['checks']['sources']);self.assertFalse(value['checks']['ordinary'])
    def test_snapshot_checks_physical_LF_and_exact_hashes(self):
        f=self.fixture();path=f['root']/'one.py';path.write_bytes(b'x=1\n')
        with patch.object(m,'SOURCES',('one.py',)):
            files,hashes,digest=m.snapshot(f['root']);self.assertEqual(files['one.py'],b'x=1\n');self.assertEqual(digest,m.sha(m.encode(hashes)))
            path.write_bytes(b'x=1\r\n')
            with self.assertRaisesRegex(ValueError,'source_lf'):m.snapshot(f['root'])
    def test_raw_input_pin_mismatch_precedes_manifest_interpretation(self):
        f=self.fixture();bad=copy.deepcopy(f['artifacts']);bad['wrapper']['sha256']='0'*64
        with patch.object(m.core,'verify_input_artifacts',side_effect=AssertionError('must not interpret')):
            with self.assertRaisesRegex(ValueError,'input_pin'):m.inputs(*(f['paths'][k] for k in ('wrapper','marker','manifest','curl')),bad,root=f['root'])
    def test_full_guard_staging_original_epoch_and_physical_outer_commitment(self):
        f,value=self.run_guard();self.assertEqual(value['status'],'observed');self.assertTrue(value['observation_complete']);self.assertFalse(value['recovery_required'])
        self.assertEqual(len(f['launches']),1);self.assertTrue(all(value['ordinary_controls'].values()))
        self.assertEqual(value['outer_launch_report_sha256'],m.sha((f['capture']['stage']/'outer-launch-report.json').read_bytes()))
        self.assertFalse(any(value[k] for k in m.core.FALSE_CLAIMS));self.assertEqual(list((f['capture']['stage']/'selected-output').iterdir()),[])
    def test_partial_staging_is_retained_unknown_and_never_launches(self):
        f,value=self.run_guard('partial-directory');self.assertFalse(f['launches']);self.assertEqual(value['failure'],'staging')
        self.assertTrue(value['tree_retained']);self.assertTrue(value['recovery_required'])
    def test_missing_worker_never_uses_valid_forensic_and_keeps_controls(self):
        f,value=self.run_guard('missing-worker');self.assertEqual(value['status'],'inconclusive');self.assertIsNone(value['observation'])
        self.assertFalse(value['checks']['worker_bound']);self.assertTrue(value['recovery_required']);self.assertTrue(all(value['ordinary_controls'].values()))
        self.assertTrue((f['capture']['stage']/'worker-result-forensic.json').is_file())
    def test_malformed_worker_or_wrong_pid_cannot_erase_independent_controls(self):
        for fault in ('bad-worker','worker-pid'):
            with self.subTest(fault=fault):
                f,value=self.run_guard(fault);self.assertFalse(value['observation_complete']);self.assertTrue(value['recovery_required'])
                self.assertIsNone(value['observation']);self.assertTrue(all(value['ordinary_controls'].values()))
    def test_late_or_bad_outer_exit_clears_qualification_but_preserves_observed_facts(self):
        for fault in ('late','bad-exit'):
            with self.subTest(fault=fault):
                f,value=self.run_guard(fault);self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['observation_complete'])
                self.assertFalse(value['checks']['mechanism']);self.assertFalse(value['observation']['version_behavior_observed'])
                self.assertTrue(value['observation']['selected_version_positive']);self.assertTrue(all(value['ordinary_controls'].values()))
                self.assertFalse(value['recovery_required'])
    def test_outer_physical_tamper_or_report_config_mismatch_rejects_binding(self):
        f,value=self.run_guard();cap=f['capture'];r=m.blank('runtime');r['outer_launch_report_sha256']=value['outer_launch_report_sha256']
        r['checks'].update(guard=True,worker_exit=True,outer_cleanup=True)
        path=cap['stage']/'outer-launch-report.json';old=path.read_bytes();path.write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'outer_physical'):m.bind_report(cap['report'],cap['c'],PARENT,cap['launch'],r,root=cap['stage'])
        path.write_bytes(old);report=copy.deepcopy(cap['report']);report['config']['run']='5'*32
        with self.assertRaisesRegex(ValueError,'worker_binding'):m.bind_report(report,cap['c'],PARENT,cap['launch'],r,root=cap['stage'])
    def test_public_complete_cannot_borrow_missing_control_or_cleanup(self):
        f,value=self.run_guard()
        for kind in ('control','cleanup'):
            bad=copy.deepcopy(value)
            if kind=='control':bad['ordinary_controls']['before']=False
            else:bad['observation'][m.core.CLEAN_KEYS[-1]]=False
            with self.subTest(kind=kind),self.assertRaises(ValueError):m.validate_public(bad)
    def test_retained_unknown_stage_cannot_claim_no_recovery(self):
        value=m.blank('runtime');value['tree_retained']=True
        with self.assertRaisesRegex(ValueError,'unknown_cleanup'):m.validate_public(value)
        value['recovery_required']=True;m.validate_public(value)
    def test_hidden_worker_source_ready_gate_precedes_backend_construction(self):
        f=self.fixture();c=self.config(f);stage=f['root']/m.core.stage_name(c['run']);stage.mkdir();path=stage/'worker-config.json';path.write_bytes(m.encode(c))
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),patch.object(m.core,'ACTUAL_READY',False),\
                patch.object(m.core,'NativeAPI',side_effect=AssertionError('forbidden backend'),create=True):
            with self.assertRaisesRegex(ValueError,'source_ready'):m.worker(path,root=stage)
    def test_hidden_worker_plan_binding_precedes_backend_construction(self):
        f=self.fixture();c=self.config(f);stage=f['root']/m.core.stage_name(c['run']);stage.mkdir();path=stage/'worker-config.json';path.write_bytes(m.encode(c))
        (stage/'recovery-plan.json').write_bytes(m.encode({**f['plan'],'run':'5'*32}))
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),patch.object(m.core,'ACTUAL_READY',True),\
                patch.object(m.core,'NativeAPI',side_effect=AssertionError('forbidden backend'),create=True):
            with self.assertRaisesRegex(ValueError,'worker_plan'):m.worker(path,root=stage)
    def test_worker_writes_forensic_before_rejecting_invalid_private_report(self):
        f=self.fixture();c=self.config(f);stage=f['root']/m.core.stage_name(c['run']);stage.mkdir();path=stage/'worker-config.json';path.write_bytes(m.encode(c))
        (stage/'recovery-plan.json').write_bytes(f['planpath'].read_bytes());api=f['api']
        with ExitStack() as stack:
            for obj,name,kwargs in ((m,'snapshot',dict(return_value=(f['files'],f['hashes'],f['source']))),(m.core,'ACTUAL_READY',dict(new=True)),
                (m.core,'verify_artifacts',{}),(m.local,'ordinary',dict(return_value=PARENT)),(m.local.LocalNativeAPI,'device_sha256',dict(return_value='1'*64)),
                (m.core,'verify_system_curl',dict(return_value=f['paths']['curl'])),
                (m.local.LocalNativeAPI,'verify_private_directory',{}),(m.local,'verify_guard_job',{}),
                (m.core,'execute',dict(return_value={'bad':True},create=True)),(m.core,'validate_result',dict(side_effect=ValueError('invalid private'),create=True))):
                stack.enter_context(patch.object(obj,name,**kwargs))
            with self.assertRaisesRegex(ValueError,'invalid private'):m.worker(path,api=api,root=stage)
        self.assertTrue((stage/'worker-result-forensic.json').is_file());self.assertFalse((stage/'worker-report.json').exists())
    def test_real_core_fake_coordinator_projects_and_binds_without_borrowing_bad_worker(self):
        spec=importlib.util.spec_from_file_location('curl_loader_guard_real_core_fixture',Path(__file__).with_name('test_windows_identity_lpac_curl_loader.py'))
        f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
        fixture=f.LoaderTests('test_real_owner_fake_backend_complete_and_control_artifact_gates')
        fixture.setUp();self.addCleanup(fixture.doCleanups)
        root,c,api,owner=fixture.fixture();private=owner.run()
        # The core fixture substitutes a synthetic curl hash and fake syscall
        # methods, while forbidding NativeAPI and WinDLL construction. Use that
        # exact module for the real pure validator/project/control readers.
        with patch.object(m,'core',f.m):
            observation=f.m.project(private,c,parent=f.b.PARENT,root=root)
            launch=dict(started=True,resumed=True,child_pid=77,child_identity=m.launcher.safe_identity(f.b.PARENT,f.b.PARENT),
                native_identity_verified_before_resume=True,cleanup=dict(process_exit_confirmed=True))
            raw=m.encode(launch);(root/'outer-launch-report.json').write_bytes(raw)
            report=dict(schema_version=1,stage='curl-loader-worker',config=c,worker_pid=77,worker_identity=f.b.PARENT,result=private)
            result=m.blank('runtime');result['outer_launch_report_sha256']=m.sha(raw)
            result['checks'].update(guard=True,worker_exit=True,outer_cleanup=True)
            m.bind_report(report,c,f.b.PARENT,launch,result,root=root)
            self.assertEqual(result['observation'],observation);self.assertTrue(result['checks']['worker_bound'])
            self.assertTrue(result['checks']['mechanism']);self.assertTrue(all(result['ordinary_controls'].values()))
            bad=copy.deepcopy(report);bad['result']={'not_a_valid_core_result':True}
            partial=m.blank('runtime');partial['outer_launch_report_sha256']=m.sha(raw)
            partial['checks'].update(guard=True,worker_exit=True,outer_cleanup=True)
            m.harvest_controls(partial,c,f.b.PARENT,root=root)
            with self.assertRaises(ValueError):m.bind_report(bad,c,f.b.PARENT,launch,partial,root=root)
            self.assertTrue(all(partial['ordinary_controls'].values()));self.assertFalse(partial['checks']['worker_bound'])
            self.assertIsNone(partial['observation']);self.assertFalse(partial['observation_complete'])

if __name__=='__main__':unittest.main()
