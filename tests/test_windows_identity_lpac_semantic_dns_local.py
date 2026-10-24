"""Pure semantic-DNS guard tests; all native/process/network seams are inert."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('semantic_local_tests',ROOT/'.github/windows_identity_lpac_semantic_dns_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
H='1'*64;F=1000;T=10000;D=T+120*F
PARENT=dict(sid='S-1-5-21-1-2-3-1000',session_id=1,token_type=1,elevation_type=3,elevated=False,appcontainer=False,
    appcontainer_sid=None,integrity_rid=8192,ui_access=False,capability_count=0,admin_attributes=16)
CATALOG={'AgenticAppContainer':'S-1-15-3-1024-1-2-3-4-5-6-7-8','privateNetworkClientServer':m.live.PNCS}

def plan(source=H,actor=H,manifest=H):
    return dict(schema_version=1,scope=m.SCOPE,identity_basis=m.IDENTITY_BASIS,device_sha256=H,source_sha256=source,actor_sha256=actor,manifest_sha256=manifest,
        standard53_impact_acknowledged=True,fresh_lpac_acl_profile_acknowledged=True,residue_review_acknowledged=True,
        semantic_identity_acknowledged=True,recovery_reference='pure bounded recovery')
def config():
    hashes=dict.fromkeys(m.SOURCES,H)
    return dict(schema_version=1,scope=m.SCOPE,identity_basis=m.IDENTITY_BASIS,**{name:'%032x'%(index+1) for index,name in enumerate(m.NONCES)},
        start_qpc=T,frequency=F,root_deadline_qpc=D,deadline_qpc=D-5*F,guard_job_name='Local\\RuleProxy.LocalGuard.'+'%032x'%1,
        source_hashes=hashes,source_sha256=m.sha(m.encode(hashes)),device_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=H,
        capability_catalog=copy.deepcopy(CATALOG))
def api5():
    return dict(called=True,completed=True,pending=False,api_status=5,query_status=0,query_status_success_verified=False,answer_match=False,
        within_deadline=True,record_count=0,records_released=True,context_retained=False,timely_verified=True)

class GuardAPI:
    def __init__(self):self.now=T;self.atomic_job_requested=True;self.private_calls=[];self.mkdir_then_raise=False
    def windows_x64(self):return True
    def qpc_frequency(self):return F
    def qpc(self):return self.now
    def device_sha256(self):return H
    def private_directory(self,path,sid):
        self.private_calls.append((path,sid));path.mkdir()
        if self.mkdir_then_raise:raise OSError('pure descriptor readback failed after mkdir')

class SemanticLocalTests(unittest.TestCase):
    def test_default_and_incomplete_explicit_entry_do_not_create_backend_or_child(self):
        for args in ([],['--run-local-lpac-semantic-dns']):
            output=NS(buffer=io.BytesIO())
            with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('no backend')),patch.object(m.launcher,'launch_owned',side_effect=AssertionError('no spawn')),patch.object(m.sys,'stdout',output):
                self.assertEqual(m.main(args),1)
            value=json.loads(output.buffer.getvalue());m.core.validate_public(value)
            self.assertEqual(value['failure'],'inputs');self.assertFalse(value['network_tested']);self.assertFalse(value['token_class46_queried'])

    def test_worker_mixed_arguments_and_unapproved_runtime_stop_before_backend(self):
        with patch.object(m,'worker',side_effect=AssertionError('no worker')):
            for args in (['--worker','config','--run-local-lpac-semantic-dns'],['--worker','config','--actor','image.exe'],['--worker','config','--output','public.json']):
                with self.assertRaises(ValueError):m.main(args)
        with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('no backend')):
            value=m.run_local(None,None,None,None,None,None,approved=False)
        self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['recovery_required'])

    def test_source35_includes_semantics_and_old_native9_but_not_identity_local_entry(self):
        self.assertEqual(len(m.SOURCES),35);self.assertEqual(len(set(m.SOURCES)),35)
        self.assertIn('.github/windows_identity_lpac_accesscheck.py',m.SOURCES)
        self.assertIn('.github/windows_identity_lpac_identity_cell.py',m.SOURCES)
        self.assertIn('.github/windows_identity_lpac_semantic_dns.py',m.SOURCES);self.assertIn(m.MODULE,m.SOURCES)
        self.assertNotIn('.github/windows_identity_lpac_identity_local.py',m.SOURCES);self.assertEqual(len(m.live.NATIVE_SOURCES),9)
        files,hashes,source=m.snapshot(ROOT);self.assertEqual(set(files),set(m.SOURCES));self.assertEqual(source,m.sha(m.encode(hashes)))

    def test_preflight_enforces_new_basis_and_impact_plan_without_staging_or_spawning(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();(root/'private').mkdir();api=GuardAPI();p=root/'plan.json';p.write_bytes(m.encode(plan()))
            with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'ordinary',return_value=PARENT),\
                    patch.object(m,'snapshot',return_value=({}, {},H)),patch.object(m.live,'verify_actor'),\
                    patch.object(m.launcher,'launch_owned',side_effect=AssertionError('read-only no spawn')):
                self.assertEqual(m.preflight(None,None,H,H,root/'private',p,api=api,root=root)['status'],'ready')
                for change in ({'scope':m.base.SCOPE},{'semantic_identity_acknowledged':False},{'standard53_impact_acknowledged':False},{'identity_basis':'class46'}):
                    p.write_bytes(m.encode(plan()|change));value=m.preflight(None,None,H,H,root/'private',p,api=api,root=root)
                    self.assertEqual(value['failure'],'plan');self.assertFalse(value['checks']['plan'])
            self.assertEqual(api.private_calls,[])

    def guard(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir()
        actor=root/m.live.ACTOR;manifest=root/m.live.MANIFEST;actor.write_bytes(b'x'*512);manifest.write_bytes(b'{}')
        files={name:b'# fixed source\n' for name in m.SOURCES};hashes={name:m.sha(raw) for name,raw in files.items()};source=m.sha(m.encode(hashes))
        p=plan(source,m.sha(actor.read_bytes()),m.sha(manifest.read_bytes()));plan_path=root/'plan.json';plan_path.write_bytes(m.encode(p))
        api=GuardAPI();api.mkdir_then_raise=fault=='private-directory';calls=[]
        ready=m.core.blank('preflight');ready.update(status='ready',source_sha256=source,actor_sha256=p['actor_sha256'],manifest_sha256=p['manifest_sha256'],recovery_plan_sha256=m.sha(plan_path.read_bytes()))
        ready['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan'),True))
        def launch(native,argv,cwd,parent,child,**kw):
            calls.append((argv,kw));self.assertIs(native,api);self.assertEqual(argv[1:4],['-I','-S','-B']);self.assertEqual(argv[-2],'--worker')
            stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());self.assertEqual(c['root_deadline_qpc'],D);self.assertEqual(c['deadline_qpc'],D-5*F)
            self.assertEqual(c['identity_basis'],m.IDENTITY_BASIS);self.assertEqual(set(c['source_hashes']),set(m.SOURCES))
            self.assertEqual(kw['work_cutoff'],D-3*F);self.assertEqual(kw['cleanup_cutoff'],D)
            self.assertTrue(stage.name.startswith('local-lpac-semantic-dns-'))
            for name in ('lpac-report/temp','health/temp','guard/temp'):self.assertTrue((stage/name).is_dir())
            if fault=='unknown':raise OSError('pure unknown create')
            report=dict(schema_version=1,stage='standalone-lpac-semantic-dns-worker',config=c,worker_pid=77,worker_identity=copy.deepcopy(PARENT),result={'pure':True})
            if fault=='wrong-pid':report['worker_pid']=78
            if fault=='wrong-config':report['config']=c|{'identity_basis':'class46'}
            (stage/'worker-report.json').write_bytes(m.encode(report))
            if fault in ('late','wire-late'):api.now=D
            timed_out=fault in ('timeout','wire-timeout');bad_exit=timed_out or fault=='wire-bad-exit'
            return dict(started=True,resumed=True,child_pid=77,native_identity_verified_before_resume=True,timed_out=timed_out,exit_code=1 if bad_exit else 0,
                cleanup=dict(process_exit_confirmed=True,job_closed=True,job_empty=True,handles_closed=True,close_uncertain=False,errors=[]))
        def project(private,c,v,*,parent):
            self.assertEqual(private,{'pure':True});self.assertEqual(parent,PARENT)
            if fault=='malformed-wire':v.update(selected_wire_query_observed=True,network_tested=True,status='failed');raise ValueError('malformed native')
            v['checks'].update(dict.fromkeys(v['checks'],True));v.update(selected_api=api5(),network_tested=True,semantic_check_count=3,
                selected_semantic_matrix=[2,0,0,2],status='observed',observation_complete=True,access_denial_observed=True,recovery_required=False)
            if fault in ('wire-late','wire-timeout','wire-bad-exit'):
                v['selected_api'].update(api_status=0,query_status_success_verified=True,answer_match=True,record_count=1)
                v.update(selected_wire_query_observed=True,status='failed',access_denial_observed=False)
            return v
        with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),patch.object(m,'preflight',return_value=ready),\
                patch.object(m.local,'ordinary',return_value=copy.deepcopy(PARENT)),patch.object(m,'snapshot',return_value=(files,hashes,source)),\
                patch.object(m.base,'fixed_catalog',return_value=copy.deepcopy(CATALOG)),patch.object(m.live,'verify_actor'),\
                patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m.core,'public_result',side_effect=project):
            value=m.run_local(actor,manifest,p['actor_sha256'],p['manifest_sha256'],root/'private',plan_path,approved=True,root=root)
        return value,api,calls

    def test_real_guard_stage_layout_original_budget_config_and_safe_semantic_projection(self):
        value,api,calls=self.guard();m.core.validate_public(value)
        self.assertEqual(value['status'],'observed');self.assertFalse(value['recovery_required']);self.assertTrue(value['observation_complete'])
        self.assertEqual(len(calls),1);self.assertEqual(value['identity_basis'],m.IDENTITY_BASIS);self.assertFalse(value['token_class46_queried'])
        self.assertFalse(value['g_psec_tested']);self.assertFalse(value['product_acceptance']);self.assertNotIn(PARENT['sid'],m.encode(value).decode('ascii'))

    def test_partial_private_directory_unknown_worker_and_wrong_report_preserve_recovery(self):
        for fault in ('private-directory','unknown','wrong-pid','wrong-config'):
            with self.subTest(fault=fault):
                value,api,calls=self.guard(fault);self.assertEqual(value['status'],'inconclusive');self.assertTrue(value['recovery_required']);self.assertTrue(value['tree_retained'])
                self.assertFalse(value['observation_complete'])
                if fault=='private-directory':self.assertEqual(calls,[]);self.assertTrue(api.private_calls[0][0].is_dir())

    def test_original_deadline_and_outer_timeout_cannot_promote_semantic_dns_denial(self):
        for fault in ('late','timeout'):
            with self.subTest(fault=fault):
                value,api,calls=self.guard(fault);self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['observation_complete'])
                self.assertFalse(value['access_denial_observed']);self.assertFalse(value['recovery_required']);self.assertTrue(value['network_tested'])

    def test_bound_independent_wire_hit_survives_malformed_private_projection(self):
        value,api,calls=self.guard('malformed-wire');self.assertEqual(value['status'],'failed')
        self.assertTrue(value['selected_wire_query_observed']);self.assertTrue(value['network_tested']);self.assertTrue(value['recovery_required'])
        self.assertFalse(value['access_denial_observed']);self.assertFalse(value['observation_complete'])

    def test_wire_hit_remains_failed_but_cannot_retain_completion_after_outer_timeout_bad_exit_or_root_deadline(self):
        for fault in ('wire-late','wire-timeout','wire-bad-exit'):
            with self.subTest(fault=fault):
                value,api,calls=self.guard(fault);self.assertEqual(value['status'],'failed')
                self.assertTrue(value['selected_wire_query_observed']);self.assertTrue(value['network_tested'])
                self.assertFalse(value['observation_complete']);self.assertFalse(value['access_denial_observed'])
                self.assertFalse(value['recovery_required']);self.assertIn(value['failure'],('deadline','report'))

    def staged_worker(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();c=config()
        stage=root/('local-lpac-semantic-dns-'+c['run']);stage.mkdir();events=[];api=GuardAPI();api.native=NS()
        raw=m.encode(plan(c['source_sha256']));c['recovery_plan_sha256']=m.sha(raw)
        (stage/'recovery-plan.json').write_bytes(raw);(stage/'worker-config.json').write_bytes(m.encode(c))
        def sources():events.append('sources');return {},c['source_hashes'] if fault!='source' else {},c['source_sha256']
        def backend():events.append('backend');return api
        def guard(native,name):
            events.append('exact-guard');self.assertEqual(name,c['guard_job_name'])
            if fault=='guard':raise ValueError('unbound guard')
        def execute(root,c,parent,api,budget):events.append('execute');self.assertEqual(budget.deadline,D-5*F);return {'selected_wire_query_observed':True,'malformed':True}
        error=None
        with patch.object(m,'ROOT',stage),patch.object(m,'snapshot',side_effect=sources),patch.object(m.core,'IdentityAPI',side_effect=backend),\
                patch.object(m.local,'ordinary',return_value=PARENT),patch.object(m.local.LocalNativeAPI,'device_sha256',return_value=H),\
                patch.object(m.local.LocalNativeAPI,'verify_private_directory',side_effect=lambda *a:events.append('private-dacl')),\
                patch.object(m.local,'verify_guard_job',side_effect=guard),patch.object(m.live,'verify_actor',side_effect=lambda *a,**kw:events.append('artifact')),\
                patch.object(m.core,'execute',side_effect=execute),patch.object(m.core,'validate_result',side_effect=AssertionError('do not erase independent wire before report')),patch.object(m,'os',NS(getpid=lambda:77)):
            try:self.assertEqual(m.worker(stage/'worker-config.json'),0)
            except ValueError as caught:error=caught
        return stage,c,events,error

    def test_worker_pins_source_and_private_guard_before_core_preserves_exact_partial_receiver_result(self):
        stage,c,events,error=self.staged_worker();self.assertIsNone(error)
        self.assertEqual(events,['sources','backend','private-dacl','exact-guard','artifact','execute'])
        report=m.decode((stage/'worker-report.json').read_bytes());self.assertEqual(report['config'],c);self.assertEqual(report['worker_pid'],77)
        self.assertEqual(report['result'],{'selected_wire_query_observed':True,'malformed':True})

    def test_worker_bad_source_or_guard_never_enters_core_or_writes_report(self):
        for fault in ('source','guard'):
            with self.subTest(fault=fault):
                stage,c,events,error=self.staged_worker(fault);self.assertIsNotNone(error);self.assertNotIn('execute',events)
                self.assertFalse((stage/'worker-report.json').exists())
                if fault=='source':self.assertNotIn('backend',events)

if __name__=='__main__':unittest.main()
