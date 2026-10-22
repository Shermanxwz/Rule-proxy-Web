"""Pure guard/worker binding tests; no native API, child, actor or network."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('identity_local_tests',ROOT/'.github/windows_identity_lpac_identity_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
H='1'*64;F=1000;T=10000;D=T+120*F
PARENT=dict(sid='S-1-5-21-1-2-3-1000',session_id=1,token_type=1,elevation_type=3,elevated=False,appcontainer=False,
    appcontainer_sid=None,integrity_rid=8192,ui_access=False,capability_count=0,admin_attributes=16)
CATALOG={'AgenticAppContainer':'S-1-15-3-1024-1-2-3-4-5-6-7-8','privateNetworkClientServer':m.live.PNCS}

def observation(*,complete=True):
    value=dict.fromkeys(m.OBSERVATION_BOOLS,True)
    value.update(failure=None,ac_granted_access=[3,0,1,2],lpac_granted_access=[2,0,0,2],inner_complete=complete)
    return value

def public_runtime():
    value=m.blank('runtime');value.update(source_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=H,tree_retained=True)
    value['checks']=dict.fromkeys(m.CHECKS,True);value['identity_observation']=observation()
    value.update(observation_complete=True,status='observed');return value

def worker_config():
    hashes=dict.fromkeys(m.SOURCES,H)
    return dict(schema_version=1,scope=m.SCOPE,**{name:'%032x'%(index+1) for index,name in enumerate(m.NONCES)},
        start_qpc=T,frequency=F,root_deadline_qpc=D,deadline_qpc=D-5*F,guard_job_name='Local\\RuleProxy.LocalGuard.'+'%032x'%1,
        source_hashes=hashes,source_sha256=m.sha(m.encode(hashes)),device_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=H,
        capability_catalog=copy.deepcopy(CATALOG))

class GuardAPI:
    def __init__(self):self.now=T;self.atomic_job_requested=True;self.private_calls=[];self.mkdir_then_raise=False
    def windows_x64(self):return True
    def qpc_frequency(self):return F
    def qpc(self):return self.now
    def device_sha256(self):return H
    def private_directory(self,path,sid):
        self.private_calls.append((path,sid));path.mkdir() # pure fake; never change a real ACL
        if self.mkdir_then_raise:raise OSError('pure descriptor readback failure after mkdir')

class IdentityLocalTests(unittest.TestCase):
    def test_default_and_opt_in_with_missing_inputs_never_construct_backend_or_spawn(self):
        for args in ([],['--run-local-lpac-identity']):
            output=NS(buffer=io.BytesIO())
            with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend forbidden')),patch.object(m.launcher,'launch_owned',side_effect=AssertionError('spawn forbidden')),patch.object(m.sys,'stdout',output):
                self.assertEqual(m.main(args),1)
            value=json.loads(output.buffer.getvalue());m.validate_public(value)
            self.assertEqual(value['failure'],'inputs');self.assertFalse(value['network_tested']);self.assertFalse(value['actor_resume_authorized'])

    def test_runtime_requires_explicit_opt_in_before_any_backend(self):
        with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend forbidden')):
            value=m.run_local(None,None,None,None,None,None,approved=False)
        self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['recovery_required'])

    def test_worker_role_refuses_public_runtime_arguments_before_worker_backend(self):
        with patch.object(m,'worker',side_effect=AssertionError('worker forbidden')):
            for args in (['--worker','config','--run-local-lpac-identity'],['--worker','config','--actor','image.exe'],['--worker','config','--output','public.json']):
                with self.assertRaises(ValueError):m.main(args)

    def test_source_closure_is_exact34_and_retains_old_native9_and_owner06(self):
        self.assertEqual(len(m.SOURCES),34);self.assertEqual(len(set(m.SOURCES)),34)
        self.assertIn('.github/windows_identity_lpac_dns_local.py',m.SOURCES)
        self.assertIn('.github/windows_identity_lpac_accesscheck.py',m.SOURCES)
        self.assertIn('.github/windows_identity_lpac_identity_cell.py',m.SOURCES)
        self.assertIn(m.MODULE,m.SOURCES);self.assertEqual(len(m.live.NATIVE_SOURCES),9)
        files,hashes,closure=m.snapshot(ROOT);self.assertEqual(set(files),set(m.SOURCES));self.assertEqual(closure,m.sha(m.encode(hashes)))

    def test_public_preflight_cannot_carry_runtime_or_network_or_false_observed_claim(self):
        ready=m.blank('preflight');ready.update(status='ready',source_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=H)
        ready['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan'),True));m.validate_public(ready)
        for change in ({'identity_observation':observation()},{'network_tested':True},{'actor_resume_authorized':True},{'status':'observed'}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_public(ready|change)
        valid=public_runtime();m.validate_public(valid)
        for change in ({'identity_observation':None},{'source_sha256':None},{'tree_retained':False},{'recovery_required':True}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_public(valid|change)
        for field in ('ac_granted_access','lpac_granted_access'):
            damaged=copy.deepcopy(valid);damaged['identity_observation'][field]=[0,0,0,0]
            with self.assertRaises(ValueError):m.validate_public(damaged)

    def test_full_preflight_validates_new_semantics_plan_read_only_and_rejects_dns_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'private').mkdir();api=GuardAPI()
            value=dict(schema_version=1,scope=m.SCOPE,device_sha256=H,source_sha256=H,actor_sha256=H,manifest_sha256=H,
                fresh_profile_owned_acl_acknowledged=True,never_resume_acknowledged=True,semantics_only_acknowledged=True,recovery_reference='pure recovery')
            plan=root/'plan.json';plan.write_bytes(m.encode(value))
            with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'ordinary',return_value=PARENT),\
                    patch.object(m,'snapshot',return_value=({}, {},H)),patch.object(m.live,'verify_actor'),\
                    patch.object(m.launcher,'launch_owned',side_effect=AssertionError('read-only preflight must not spawn')):
                result=m.preflight(None,None,H,H,root/'private',plan,api=api,root=root)
                self.assertEqual(result['status'],'ready');self.assertEqual(api.private_calls,[])
                plan.write_bytes(m.encode(value|{'scope':m.base.SCOPE}))
                result=m.preflight(None,None,H,H,root/'private',plan,api=api,root=root)
                self.assertEqual(result['failure'],'plan');self.assertFalse(result['checks']['plan']);self.assertEqual(api.private_calls,[])

    def guard(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir()
        actor=root/m.live.ACTOR;manifest=root/m.live.MANIFEST;actor.write_bytes(b'x'*512);manifest.write_bytes(b'{}')
        files={name:b'# fixed source\n' for name in m.SOURCES};hashes={name:m.sha(raw) for name,raw in files.items()};source=m.sha(m.encode(hashes))
        plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=H,source_sha256=source,actor_sha256=m.sha(actor.read_bytes()),manifest_sha256=m.sha(manifest.read_bytes()),
            fresh_profile_owned_acl_acknowledged=True,never_resume_acknowledged=True,semantics_only_acknowledged=True,recovery_reference='pure owner recovery')
        plan_path=root/'plan.json';plan_path.write_bytes(m.encode(plan));api=GuardAPI();calls=[]
        api.mkdir_then_raise=fault=='private-directory'
        ready=m.blank('preflight');ready.update(source_sha256=source,actor_sha256=plan['actor_sha256'],manifest_sha256=plan['manifest_sha256'],recovery_plan_sha256=m.sha(plan_path.read_bytes()),status='ready')
        ready['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan'),True))
        def launch(native,argv,cwd,parent,child,**kw):
            calls.append((argv,kw));self.assertIs(native,api)
            self.assertEqual(argv[1:4],['-I','-S','-B']);self.assertEqual(argv[-2],'--worker')
            stage=cwd.parent;config=m.decode((stage/'worker-config.json').read_bytes())
            self.assertEqual(config['start_qpc'],T);self.assertEqual(config['root_deadline_qpc'],D);self.assertEqual(config['deadline_qpc'],D-5*F)
            self.assertEqual(kw['work_cutoff'],D-3*F);self.assertEqual(kw['cleanup_cutoff'],D)
            self.assertEqual(set(config['source_hashes']),set(m.SOURCES));self.assertTrue(stage.name.startswith('local-lpac-identity-'))
            self.assertFalse(any((stage/name).exists() for name in ('health','lpac-control','health-control')))
            if fault=='unknown':raise OSError('pure unknown create')
            report=dict(schema_version=1,stage='matched-ac-lpac-identity-worker',config=config,worker_pid=77,worker_identity=copy.deepcopy(PARENT),result={'pure':True})
            if fault=='wrong-pid':report['worker_pid']=78
            if fault=='wrong-config':report['config']=config|{'deadline_qpc':D}
            if fault=='wrong-identity':report['worker_identity']['session_id']=2
            (stage/'worker-report.json').write_bytes(m.encode(report))
            if fault=='late':api.now=D
            return dict(started=True,resumed=True,child_pid=77,native_identity_verified_before_resume=True,timed_out=fault=='timeout',exit_code=1 if fault=='timeout' else 0,
                cleanup=dict(process_exit_confirmed=True,job_closed=True,job_empty=True,handles_closed=True,close_uncertain=False,errors=[]))
        projected=observation()
        if fault=='inner-failure':projected.update(failure='accesscheck',inner_complete=False,ac_accesscheck_verified=False,ac_granted_access=[0,0,0,0])
        with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),patch.object(m,'preflight',return_value=ready),\
                patch.object(m.local,'ordinary',return_value=copy.deepcopy(PARENT)),patch.object(m,'snapshot',return_value=(files,hashes,source)),\
                patch.object(m.base,'fixed_catalog',return_value=copy.deepcopy(CATALOG)),patch.object(m.live,'verify_actor'),\
                patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m.core,'validate_result',side_effect=lambda private,config,**kw:self.assertEqual(private,{'pure':True})),\
                patch.object(m.core,'project',return_value=projected):
            value=m.run_local(actor,manifest,plan['actor_sha256'],plan['manifest_sha256'],root/'private',plan_path,approved=True,root=root)
        return value,api,calls

    def test_real_guard_staging_fixed_worker_command_original120_115_and_closed_report_projection(self):
        value,api,calls=self.guard();m.validate_public(value)
        self.assertEqual(value['status'],'observed');self.assertTrue(value['observation_complete']);self.assertFalse(value['recovery_required'])
        self.assertEqual(len(calls),1);self.assertEqual(len(api.private_calls),1)
        self.assertFalse(value['network_tested']);self.assertFalse(value['dns_api_called']);self.assertFalse(value['g_psec_tested']);self.assertFalse(value['product_acceptance'])
        self.assertNotIn(PARENT['sid'],m.encode(value).decode('ascii'))

    def test_unknown_worker_or_mismatched_report_retains_recovery_and_never_observed(self):
        for fault in ('unknown','wrong-pid','wrong-config','wrong-identity'):
            with self.subTest(fault=fault):
                value,api,calls=self.guard(fault);self.assertEqual(value['status'],'inconclusive')
                self.assertTrue(value['recovery_required']);self.assertFalse(value['observation_complete']);self.assertTrue(value['tree_retained'])

    def test_private_directory_mkdir_then_raise_retains_possible_tree_and_recovery_without_worker(self):
        value,api,calls=self.guard('private-directory')
        self.assertEqual(value['status'],'inconclusive');self.assertEqual(value['failure'],'staging')
        self.assertTrue(value['tree_retained']);self.assertTrue(value['recovery_required']);self.assertEqual(calls,[])
        self.assertEqual(len(api.private_calls),1);self.assertTrue(api.private_calls[0][0].is_dir())
        self.assertFalse(value['checks']['guard']);self.assertFalse(value['checks']['worker_bound'])

    def test_outer_timeout_late_root_and_clean_inner_semantic_failure_do_not_promote(self):
        for fault in ('timeout','late','inner-failure'):
            with self.subTest(fault=fault):
                value,api,calls=self.guard(fault);self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['observation_complete'])
                self.assertFalse(value['recovery_required']);self.assertTrue(value['checks']['outer_cleanup'])

    def staged_worker(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);parent=Path(td.name).resolve();config=worker_config()
        stage=parent/('local-lpac-identity-'+config['run']);stage.mkdir();events=[];api=GuardAPI();api.native=NS()
        plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=H,source_sha256=config['source_sha256'],actor_sha256=H,manifest_sha256=H,
            fresh_profile_owned_acl_acknowledged=True,never_resume_acknowledged=True,semantics_only_acknowledged=True,recovery_reference='pure worker recovery')
        raw=m.encode(plan);config['recovery_plan_sha256']=m.sha(raw);(stage/'recovery-plan.json').write_bytes(raw)
        (stage/'worker-config.json').write_bytes(m.encode(config))
        hashes=config['source_hashes'] if fault!='source' else {**config['source_hashes'],m.MODULE:'2'*64}
        def sources():events.append('sources');return {},hashes,m.sha(m.encode(hashes))
        def backend():events.append('backend');return api
        def guard(native,name):
            events.append('exact-guard')
            self.assertIs(native,api.native);self.assertEqual(name,config['guard_job_name'])
            if fault=='guard':raise ValueError('exact guard not admitted')
        def dacl(native,path,sddl):
            events.append('private-dacl');self.assertEqual(path,stage)
            self.assertEqual(sddl,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+PARENT['sid']+')')
        def execute(root,c,parent,api,budget):
            events.append('execute');self.assertEqual(root,stage);self.assertEqual(c,config);self.assertEqual(parent,PARENT)
            self.assertEqual(budget.deadline,D-5*F);self.assertEqual(budget.frequency,F);return {'pure':True}
        caught=None
        with patch.object(m,'ROOT',stage),patch.object(m,'snapshot',side_effect=sources),patch.object(m.core,'IdentityAPI',side_effect=backend),\
                patch.object(m.local,'ordinary',return_value=PARENT),patch.object(m.local.LocalNativeAPI,'device_sha256',return_value=H),\
                patch.object(m.local.LocalNativeAPI,'verify_private_directory',side_effect=dacl),patch.object(m.local,'verify_guard_job',side_effect=guard),\
                patch.object(m.live,'verify_actor',side_effect=lambda *a,**kw:events.append('artifact')),patch.object(m.core,'execute',side_effect=execute),\
                patch.object(m.core,'validate_result',side_effect=lambda *a,**kw:events.append('validate-result')),patch.object(m,'os',NS(getpid=lambda:77)),\
                patch.object(m.launcher,'launch_owned',side_effect=AssertionError('worker must not relaunch guard')):
            try:self.assertEqual(m.worker(stage/'worker-config.json'),0)
            except ValueError as error:caught=error
        return stage,config,events,caught

    def test_worker_source_private_dacl_exact_guard_and_artifact_precede_core_and_report(self):
        stage,config,events,error=self.staged_worker();self.assertIsNone(error)
        self.assertEqual(events,['sources','backend','private-dacl','exact-guard','artifact','execute','validate-result'])
        report=m.decode((stage/'worker-report.json').read_bytes())
        self.assertEqual(set(report),{'schema_version','stage','config','worker_pid','worker_identity','result'})
        self.assertEqual(report['config'],config);self.assertEqual(report['worker_pid'],77);self.assertEqual(report['worker_identity'],PARENT)

    def test_worker_unknown_source_or_exact_guard_failure_cannot_enter_core_or_write_report(self):
        for fault in ('source','guard'):
            with self.subTest(fault=fault):
                stage,config,events,error=self.staged_worker(fault);self.assertIsNotNone(error)
                self.assertNotIn('execute',events);self.assertFalse((stage/'worker-report.json').exists())
                if fault=='source':self.assertNotIn('backend',events)

if __name__=='__main__':unittest.main()
