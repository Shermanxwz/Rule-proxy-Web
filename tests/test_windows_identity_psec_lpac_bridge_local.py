"""Pure CPSE guard/worker gates; no native library, child or state mutation."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('cpse_guard_tests',ROOT/'.github/windows_identity_psec_lpac_bridge_local.py')
f=load('cpse_inner_pure_fixture',Path(__file__).with_name('test_windows_identity_psec_lpac_bridge.py'))
H=f.b.H;F=f.F;T=f.T;D=T+120*F
PARENT=f.b.PARENT

def observation():
    v=dict.fromkeys(m.OBS_BOOLS,True);v.update(failure=None,opaque_outcome_unknown=False,ac_granted_access=[3,0,1,2],lpac_granted_access=[2,0,0,2]);return v
class API:
    def __init__(self):self.now=T;self.atomic_job_requested=True;self.private_calls=[];self.mkdir_fail=False
    def qpc_frequency(self):return F
    def qpc(self):return self.now
    def device_sha256(self):return H
    def windows_x64(self):return True
    def private_directory(self,path,sid):
        self.private_calls.append(path);path.mkdir()
        if self.mkdir_fail:raise OSError('fake mkdir succeeded but DACL readback failed')

class GuardTests(unittest.TestCase):
    def setUp(self):
        # File lifecycle fakes use POSIX temp paths on non-Windows CI. This is
        # fixture syntax only; never a production path fallback or a test skip.
        if os.name!='nt':self.enterContext(patch.object(m.core.spec,'path',side_effect=lambda value:value))
    def inputs(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir()
        (root/'python.exe').write_bytes(b'pure fake executable; never launched')
        files={k:b'# fixed input\n' for k in m.SOURCES};hashes={k:m.sha(v) for k,v in files.items()};source=m.sha(m.encode(hashes))
        for name in (m.live.ACTOR,m.live.MANIFEST,m.core.DLL,m.core.DLL_MANIFEST):(root/name).write_bytes(b'{}')
        (root/m.core.DLL_MANIFEST).write_bytes(m.encode(dict(sources={},dependencies={})))
        plan=dict(schema_version=1,scope=m.SCOPE,variant=m.core.VARIANT,**{n:'%032x'%(i+1) for i,n in enumerate(m.core.NONCES)},
            device_sha256=H,source_sha256=source,actor_sha256=H,manifest_sha256=H,dll_sha256=H,dll_manifest_sha256=H,
            processmodel_sha256=H,spec_sha256=None,never_resume_acknowledged=True,deny_all_not_proxy_acknowledged=True,
            opaque_unknown_recovery_acknowledged=True,recovery_reference='pure recovery record')
        raw=m.core.spec.build(str(root/'private'/m.core.stage_name(plan['run'])/'inputs'));(root/'spec.bin').write_bytes(raw);plan['spec_sha256']=m.sha(raw)
        (root/'plan.json').write_bytes(m.encode(plan));args=(root/m.live.ACTOR,root/m.live.MANIFEST,H,H,root/m.core.DLL,root/m.core.DLL_MANIFEST,H,H,H,root/'spec.bin',root/'plan.json',root/'private')
        ready=m.blank('preflight');ready.update(status='ready',source_sha256=source,recovery_plan_sha256=m.sha(m.encode(plan)))
        for key in ('actor','manifest','dll','dll_manifest','processmodel'):ready[key+'_sha256']=H
        ready['spec_sha256']=plan['spec_sha256'];ready['checks'].update(dict.fromkeys(m.CHECKS[:7],True))
        return root,files,hashes,plan,args,ready
    def guard(self,fault=None):
        root,files,hashes,plan,args,ready=self.inputs();api=API();api.mkdir_fail=fault=='private-directory';calls=[]
        def launch(native,argv,cwd,parent,child,**kw):
            calls.append((argv,kw));self.assertIs(api,native);self.assertEqual(argv[1:4],['-I','-S','-B'])
            stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());m.core.config_validate(c)
            self.assertEqual(c['run'],plan['run']);self.assertEqual(c['start_qpc'],T);self.assertEqual(c['root_deadline_qpc'],D);self.assertEqual(c['deadline_qpc'],D-5*F)
            self.assertEqual(kw['work_cutoff'],D-3*F);self.assertEqual(kw['cleanup_cutoff'],D);self.assertEqual(kw['qpc_budget'].deadline,D)
            self.assertFalse((stage/'tools').exists());self.assertFalse((stage/'journal').exists());self.assertEqual((stage/'spec.bin').read_bytes(),(root/'spec.bin').read_bytes())
            if fault=='unknown':raise OSError('unknown guard create')
            report=dict(schema_version=1,stage='cpse-matched-identity-worker',config=c,worker_pid=77,worker_identity=copy.deepcopy(PARENT),result={'pure':True})
            if fault=='wrong-pid':report['worker_pid']=78
            if fault=='wrong-config':report['config']=c|{'deadline_qpc':D}
            if fault=='wrong-parent':report['worker_identity']['session_id']=2
            (stage/'worker-report.json').write_bytes(m.encode(report))
            if fault=='late':api.now=D
            return dict(started=True,resumed=True,child_pid=77,native_identity_verified_before_resume=True,
                timed_out=fault=='timeout',exit_code=1 if fault=='bad-exit' else 0,
                cleanup=dict(process_exit_confirmed=True,job_closed=True,job_empty=True,handles_closed=True,close_uncertain=False,errors=[]))
        obs=observation()
        if fault=='opaque':obs.update(opaque_outcome_unknown=True,api_obligations_closed=False,module_unbound=False,inner_complete=False,failure='environment')
        with patch.object(m,'os',NS(name='nt')),patch.object(m.core,'ACTUAL_READY',True),patch.object(m.local,'LocalNativeAPI',return_value=api),\
                patch.object(m,'sys',NS(executable=str(root/'python.exe'),base_prefix=str(root))),\
                patch.object(m,'preflight',return_value=ready),patch.object(m.local,'ordinary',return_value=copy.deepcopy(PARENT)),\
                patch.object(m,'snapshot',return_value=(files,hashes,plan['source_sha256'])),patch.object(m.base,'fixed_catalog',return_value=copy.deepcopy(f.b.CATALOG)),\
                patch.object(m.live,'verify_actor'),patch.object(m.core,'verify_manifest'),patch.object(m.launcher,'launch_owned',side_effect=launch),\
                patch.object(m.core,'project',return_value=obs):
            value=m.run_local(*args,approved=True,root=root)
        return value,api,calls
    def test_default_missing_inputs_and_worker_role_never_construct_backend(self):
        for args in ([],['--run-local-cpse-lpac-identity']):
            output=NS(buffer=io.BytesIO())
            with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('no backend')),patch.object(m.core,'Bridge',side_effect=AssertionError('no DLL')),patch.object(m.sys,'stdout',output):
                self.assertEqual(m.main(args),1)
            value=json.loads(output.buffer.getvalue());self.assertEqual(value['failure'],'inputs');m.validate_public(value)
        for args in (['--worker','config','--run-local-cpse-lpac-identity'],['--worker','config','--dll','candidate.dll']):
            with patch.object(m,'worker',side_effect=AssertionError('worker forbidden')),self.assertRaises(ValueError):m.main(args)
    def test_explicit_optin_and_unreviewed_candidate_block_before_backend(self):
        with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend forbidden')):
            self.assertEqual(m.run_local(*([None]*12),approved=False)['failure'],'inputs')
            with patch.object(m.core,'ACTUAL_READY',False):self.assertEqual(m.run_local(*([None]*12),approved=True)['failure'],'inputs')
    def test_preflight_only_reads_original_spec_and_rejects_existing_stage_and_wrong_spec(self):
        root,files,hashes,plan,args,ready=self.inputs();api=API();model=root/'processmodel.dll';model.write_bytes(b'fake')
        changed=list(args);changed[8]=m.sha(b'fake');plan['processmodel_sha256']=changed[8];(root/'plan.json').write_bytes(m.encode(plan))
        with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'ordinary',return_value=PARENT),patch.object(m,'snapshot',return_value=(files,hashes,plan['source_sha256'])),\
                patch.object(m.live,'verify_actor'),patch.object(m.core,'verify_manifest'),patch.object(m.core.NativeAPI,'processmodel_path',return_value=model),\
                patch.object(m.core,'pe_x64'),patch.object(m.core,'Bridge',side_effect=AssertionError('preflight cannot load DLL')):
            self.assertEqual(m.preflight(*changed,api=api,root=root)['status'],'ready');self.assertEqual(api.private_calls,[])
            (root/'spec.bin').write_bytes(m.core.spec.build(str(root/'private'/'wrong'/'inputs')))
            self.assertEqual(m.preflight(*changed,api=api,root=root)['failure'],'plan')
            (root/'spec.bin').write_bytes(m.core.spec.build(str(root/'private'/m.core.stage_name(plan['run'])/'inputs')))
            (root/'private'/m.core.stage_name(plan['run'])).mkdir()
            self.assertEqual(m.preflight(*changed,api=api,root=root)['failure'],'plan')
    def test_complete_staged_guard_original_epoch_fixed_worker_and_bound_report(self):
        v,api,calls=self.guard();self.assertEqual(v['status'],'observed');self.assertTrue(v['observation_complete']);self.assertFalse(v['recovery_required'])
        self.assertFalse(v['broker_outcome_unknown']);self.assertEqual(len(calls),1);self.assertEqual(len(api.private_calls),1)
        raw=(api.private_calls[0]/'outer-launch-report.json').read_bytes();self.assertEqual(m.sha(raw),v['outer_launch_sha256'])
        self.assertEqual(m.decode(raw)['child_pid'],77)
    def test_unknown_or_mismatched_worker_keeps_opaque_unknown_and_recovery(self):
        for fault in ('unknown','wrong-pid','wrong-config','wrong-parent'):
            with self.subTest(fault=fault):
                v,_,_=self.guard(fault);self.assertEqual(v['status'],'inconclusive');self.assertTrue(v['recovery_required']);self.assertTrue(v['broker_outcome_unknown'])
    def test_partial_private_directory_retains_tree_and_does_not_spawn(self):
        v,api,calls=self.guard('private-directory');self.assertEqual(v['failure'],'staging');self.assertEqual(calls,[])
        self.assertTrue(v['tree_retained']);self.assertTrue(v['recovery_required']);self.assertTrue(api.private_calls[0].is_dir());self.assertFalse(v['broker_outcome_unknown'])
    def test_outer_timeout_bad_exit_and_rootlate_never_promote_known_inner_complete(self):
        for fault in ('timeout','bad-exit','late'):
            with self.subTest(fault=fault):
                v,_,_=self.guard(fault);self.assertEqual(v['status'],'inconclusive');self.assertFalse(v['observation_complete'])
                self.assertEqual(v['recovery_required'],fault=='late');self.assertEqual(v['broker_outcome_unknown'],fault=='late')
    def test_inner_unknown_survives_successful_worker_and_job_cleanup(self):
        v,_,_=self.guard('opaque');self.assertTrue(v['checks']['outer_cleanup']);self.assertTrue(v['broker_outcome_unknown']);self.assertTrue(v['recovery_required']);self.assertFalse(v['observation_complete'])
    def test_closed_public_digests_matrices_runtime_scope_and_unknown_not_washable(self):
        v,_,_=self.guard();m.validate_public(v)
        for change in ({'identity_observation':None},{'dll_sha256':None},{'spec_sha256':None},{'external_environment_absence_verified':True},
                {'broker_cancellation_proven':True},{'network_tested':True},{'tree_retained':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_public(v|change)
        bad=copy.deepcopy(v);bad['identity_observation']['lpac_granted_access']=[0,0,0,0]
        with self.assertRaises(ValueError):m.validate_public(bad)
        bad,_,_=self.guard('opaque');bad['broker_outcome_unknown']=False
        with self.assertRaises(ValueError):m.validate_public(bad)
        ready=m.blank('preflight');ready['identity_observation']=observation()
        with self.assertRaises(ValueError):m.validate_public(ready)
    def test_source36_old_native9_and_fixed_dependency31_names_are_exact(self):
        self.assertEqual(len(m.SOURCES),36);self.assertEqual(len(set(m.SOURCES)),36);self.assertEqual(len(m.live.NATIVE_SOURCES),9)
        self.assertEqual(len(m.core.DEPENDENCY_NAMES),31);self.assertIn('vendor/flatbuffers/LICENSE',m.core.DEPENDENCY_NAMES)
        files,hashes,source=m.snapshot(ROOT);self.assertEqual(set(files),set(m.SOURCES));self.assertEqual(source,m.sha(m.encode(hashes)))
    def staged_worker(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);parent=Path(td.name).resolve()
        stage=parent/m.core.stage_name('%032x'%1);stage.mkdir();(stage/'inputs').mkdir();c=f.config(stage)
        plan={k:c[k] for k in ('schema_version','scope','variant',*m.core.NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256',
            'dll_sha256','dll_manifest_sha256','processmodel_sha256','spec_sha256')}
        plan.update(never_resume_acknowledged=True,deny_all_not_proxy_acknowledged=True,opaque_unknown_recovery_acknowledged=True,recovery_reference='pure worker restore')
        if fault=='plan-nonce':plan['ac_nonce']='a'*32
        raw=m.encode(plan);c['recovery_plan_sha256']=m.sha(raw);(stage/'recovery-plan.json').write_bytes(raw)
        (stage/'worker-config.json').write_bytes(m.encode(c));(stage/'spec.bin').write_bytes(m.core.spec.build(str(stage/'inputs')))
        events=[];api=API();api.native=NS()
        hashes=c['source_hashes'] if fault!='source' else {**c['source_hashes'],m.MODULE:'2'*64}
        def source():events.append('sources');return {},hashes,m.sha(m.encode(hashes))
        def backend():events.append('backend');return api
        def guard(native,name):
            events.append('guard');self.assertEqual(name,c['guard_job_name'])
            if fault=='guard':raise ValueError('fake wrong named guard Job')
        def execute(root,config,parent,native,budget):
            events.append('execute');self.assertEqual(root,stage);self.assertEqual(config,c);self.assertEqual(parent,PARENT)
            self.assertEqual(budget.deadline,D-5*F);self.assertEqual(budget.frequency,F);return {'pure':True}
        error=None
        with patch.object(m,'ROOT',stage),patch.object(m,'snapshot',side_effect=source),patch.object(m.core,'ACTUAL_READY',True),\
                patch.object(m.core,'NativeAPI',side_effect=backend),patch.object(m.local,'ordinary',return_value=PARENT),\
                patch.object(m.local.LocalNativeAPI,'device_sha256',return_value=H),\
                patch.object(m.local.LocalNativeAPI,'verify_private_directory',side_effect=lambda *a:events.append('private-dacl')),\
                patch.object(m.local,'verify_guard_job',side_effect=guard),patch.object(m.live,'verify_actor',side_effect=lambda *a,**kw:events.append('actor')),\
                patch.object(m.core,'verify_manifest',side_effect=lambda *a,**kw:events.append('dll')),\
                patch.object(m.base,'fixed_catalog',side_effect=lambda:events.append('catalog') or f.b.CATALOG),\
                patch.object(m.core,'execute',side_effect=execute),patch.object(m.core,'validate_result',side_effect=lambda *a,**kw:
                    (_ for _ in ()).throw(ValueError('fake final validator failure')) if fault=='validator' else events.append('validate-result')),\
                patch.object(m,'os',NS(getpid=lambda:77)):
            try:self.assertEqual(m.worker(stage/'worker-config.json'),0)
            except ValueError as e:error=e
        return stage,c,events,error
    def test_worker_source_private_dacl_exact_guard_plan_spec_and_artifacts_precede_core(self):
        stage,c,events,error=self.staged_worker();self.assertIsNone(error)
        self.assertEqual(events,['sources','backend','private-dacl','guard','actor','dll','catalog','execute','validate-result'])
        report=m.decode((stage/'worker-report.json').read_bytes());self.assertEqual(report['config'],c);self.assertEqual(report['worker_pid'],77)
        self.assertEqual(report['stage'],'cpse-matched-identity-worker');self.assertEqual(report['worker_identity'],PARENT)
    def test_worker_wrong_source_or_named_job_or_plan_nonce_cannot_enter_cpse(self):
        for fault in ('source','guard','plan-nonce'):
            with self.subTest(fault=fault):
                stage,_,events,error=self.staged_worker(fault);self.assertIsNotNone(error);self.assertNotIn('execute',events)
                self.assertFalse((stage/'worker-report.json').exists())
                if fault=='source':self.assertNotIn('backend',events)
    def test_final_validator_failure_preserves_unvalidated_forensic_without_report(self):
        stage,_,events,error=self.staged_worker('validator');self.assertIsNotNone(error);self.assertIn('execute',events)
        self.assertEqual(m.decode((stage/'worker-result-forensic.json').read_bytes()),{'pure':True})
        self.assertFalse((stage/'worker-report.json').exists())
if __name__=='__main__':unittest.main()
