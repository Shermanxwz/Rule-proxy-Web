"""Source/plan/worker/public guard composition with a fake native backend."""
import copy
import ctypes as C
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('zero_loopback_local_tests',ROOT/'.github/windows_identity_lpac_loopback_local.py')
f=load('zero_loopback_core_fixtures',Path(__file__).with_name('test_windows_identity_lpac_loopback.py'))
H='1'*64

def plan(source=H,actor=H,manifest=H):
    return dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,**{n:'%032x'%(i+1) for i,n in enumerate(m.core.NONCES)},
        ports=dict(frontend=49153,ordinary=49154),device_sha256=H,source_sha256=source,actor_sha256=actor,manifest_sha256=manifest,
        **dict.fromkeys(m.core.ACKS,True),recovery_reference='predeclared exact owned residue review')

class GuardAPI:
    atomic_job_requested=True
    def __init__(self,fault=None):self.fault=fault;self.calls=[]
    def windows_x64(self):return True
    def qpc_frequency(self):return f.F
    def qpc(self):return f.T
    def device_sha256(self):return H
    def private_directory(self,path,sid):
        path.mkdir();self.calls.append(path)
        if self.fault=='partial-directory':raise OSError('private mkdir returned but readback unknown')

class LocalTests(unittest.TestCase):
    def test_default_and_missing_flag_inputs_never_instantiate_backend(self):
        for args in ([],['--run-local-zero-cap-same-sid-loopback']):
            output=NS(buffer=io.BytesIO())
            with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend')),patch.object(m.sys,'stdout',output):self.assertEqual(m.main(args),1)
            v=m.decode(output.buffer.getvalue());m.validate_public(v);self.assertEqual(v['failure'],'inputs')
    def test_unreviewed_or_unapproved_runtime_stops_before_backend(self):
        for ready,approved in ((False,True),(True,False)):
            with patch.object(m.core,'ACTUAL_READY',ready),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend')):
                v=m.run_local(None,None,None,None,None,None,approved=approved)
            self.assertFalse(v['recovery_required']);self.assertEqual(v['failure'],'inputs')
    def test_worker_cli_rejects_other_run_or_public_options(self):
        for extra in (['--run-local-zero-cap-same-sid-loopback'],['--actor','x'],['--output','x']):
            with patch.object(m,'worker',side_effect=AssertionError('worker')),self.assertRaises(ValueError):m.main(['--worker','x',*extra])
    def test_source_closure_is_exact_and_keeps_old_runtime_bytes(self):
        self.assertEqual(len(m.SOURCES),37);self.assertEqual(len(set(m.SOURCES)),37)
        files,hashes,source=m.snapshot(ROOT);self.assertEqual(set(files),set(m.SOURCES));self.assertEqual(source,m.sha(m.encode(hashes)))
        self.assertIn('.github/windows_identity_lpac_accesscheck.py',m.SOURCES);self.assertIn('.github/windows_identity_lpac_identity_cell.py',m.SOURCES)
        self.assertEqual(set(m.core.NATIVE_SOURCES),{'.github/native/windows_identity_lpac_loopback_actor.cpp','.github/native/windows_identity_lpac_loopback_contract.hpp'})
    def test_plan_exact_nonce_ports_scope_and_ack_no_cap_fallback(self):
        p=plan();m.core.validate_plan(p,device=H,source=H,actor=H,manifest=H)
        for change in ({'scope':m.base.SCOPE},{'profile':'pncs'}, {'front_boot':p['run']},{'ports':dict(frontend=49153,ordinary=49153)},
                {'zero_capabilities_no_fallback_acknowledged':False},{'capability_catalog':{}}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.core.validate_plan(p|change,device=H,source=H,actor=H,manifest=H)
    def test_preflight_only_reads_new_plan_and_never_spawns(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();(root/'private').mkdir();p=root/'plan';p.write_bytes(m.encode(plan()));api=GuardAPI()
            with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'ordinary',return_value=f.b.PARENT),patch.object(m,'snapshot',return_value=({}, {},H)),\
                    patch.object(m.core,'verify_actor'),patch.object(m.launcher,'launch_owned',side_effect=AssertionError('spawn')):
                v=m.preflight(None,None,H,H,root/'private',p,api=api,root=root)
                self.assertEqual(v['status'],'ready');self.assertEqual(api.calls,[])
                p.write_bytes(m.encode(plan()|{'same_sid_shared_principal_acknowledged':False}))
                self.assertEqual(m.preflight(None,None,H,H,root/'private',p,api=api,root=root)['failure'],'plan')
    def run_guard(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir()
        actor=root/m.core.ACTOR;manifest=root/m.core.MANIFEST;actor.write_bytes(b'x'*512);manifest.write_bytes(b'{}')
        files={n:b'# pure fixed source\n' for n in m.SOURCES};hashes={n:m.sha(raw) for n,raw in files.items()};source=m.sha(m.encode(hashes))
        p=plan(source,m.sha(actor.read_bytes()),m.sha(manifest.read_bytes()));plan_path=root/'plan';plan_path.write_bytes(m.encode(p));api=GuardAPI(fault);calls=[];capture={}
        ready=m.blank('preflight');ready.update(status='ready',source_sha256=source,actor_sha256=p['actor_sha256'],manifest_sha256=p['manifest_sha256'],recovery_plan_sha256=m.sha(plan_path.read_bytes()))
        ready['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan'),True))
        def launch(native,argv,cwd,parent,child,*,qpc_budget,work_cutoff,cleanup_cutoff):
            self.assertIs(native,api);self.assertEqual(argv[1:4],['-I','-S','-B']);self.assertEqual(argv[-2],'--worker');calls.append(argv)
            stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());m.core.config_validate(c)
            self.assertEqual({n:c[n] for n in m.core.NONCES},{n:p[n] for n in m.core.NONCES});self.assertEqual(c['ports'],p['ports'])
            self.assertEqual((c['start_qpc'],c['root_deadline_qpc'],c['deadline_qpc'],work_cutoff,cleanup_cutoff),(f.T,f.T+120*f.F,f.D,f.T+117*f.F,f.T+120*f.F))
            if fault=='unknown-worker':raise OSError('unknown spawn')
            tool=stage/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool')
            fake=f.API(stage,'front10013' if fault=='front10013' else None);owner=m.core.Owner(stage,c,parent,fake,m.launcher.QpcBudget(fake,c['deadline_qpc'],c['frequency']));fake.owner=owner
            private=owner.execute();m.core.validate_result(private,c,parent=parent,root=stage)
            report=dict(schema_version=1,stage='zero-cap-same-sid-loopback-worker',config=c,worker_pid=77,worker_identity=parent,result=private)
            (stage/'worker-report.json').write_bytes(m.encode(report));capture.update(stage=stage,config=c,report=report,owner=owner)
            if fault=='bad-report':report['worker_pid']=78;(stage/'worker-report.json').write_bytes(m.encode(report))
            return dict(started=True,resumed=True,child_pid=77,native_identity_verified_before_resume=True,timed_out=False,exit_code=0,
                cleanup=dict(process_exit_confirmed=True,job_empty_confirmed=True,handles_closed=True))
        with patch.object(m.core,'ACTUAL_READY',True),patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),\
                patch.object(m.local,'ordinary',return_value=f.b.PARENT),patch.object(m,'snapshot',return_value=(files,hashes,source)),\
                patch.object(m,'preflight',return_value=ready),patch.object(m.core,'verify_actor'),patch.object(m.local.guest,'cleanup_verified',return_value=True),\
                patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m.sys,'executable',str(root/'python.exe')),patch.object(m.sys,'base_prefix',str(root)):
            (root/'python.exe').write_bytes(b'pure')
            r=m.run_local(actor,manifest,p['actor_sha256'],p['manifest_sha256'],root/'private',plan_path,approved=True,root=root)
        return r,calls,api,capture
    def test_real_owner_guard_composition_full_success_original_clock_and_false_claims(self):
        r,calls,_,capture=self.run_guard();self.assertEqual(len(calls),1);self.assertEqual(r['status'],'observed');self.assertFalse(r['recovery_required'])
        self.assertTrue(r['loopback_observation']['reachability_verified']);self.assertTrue((capture['stage']/'outer-launch-report.json').exists())
        self.assertFalse(any(r[k] for k in m.core.FALSE_CLAIMS));self.assertFalse(any(r['loopback_observation'][k] for k in m.core.FALSE_CLAIMS))
    def test_front10013_preserves_setup_observation_and_after_but_never_claims_reachability(self):
        r,_,_,capture=self.run_guard('front10013');o=r['loopback_observation'];self.assertEqual(r['status'],'inconclusive')
        self.assertFalse(r['recovery_required']);self.assertTrue(o['ordinary_before'] and o['ordinary_after']);self.assertFalse(o['reachability_verified'])
        self.assertEqual((o['frontend_setup']['observed'],o['frontend_setup']['failure'],o['frontend_setup']['wsa_error']),(True,'bind',10013))
        self.assertFalse(capture['owner'].tasks['selected-client']['resumed']);self.assertTrue(all(o[k] for k in m.core.CLEAN_KEYS))
    def test_partial_stage_or_unknown_worker_retains_unknown_cleanup(self):
        for fault in ('partial-directory','unknown-worker','bad-report'):
            with self.subTest(fault=fault):
                r,calls,_,_=self.run_guard(fault);self.assertTrue(r['tree_retained']);self.assertTrue(r['recovery_required']);self.assertFalse(r['observation_complete'])
                self.assertEqual(len(calls),0 if fault=='partial-directory' else 1)
    def test_independent_binding_rejects_worker_or_physical_raw_mismatch(self):
        r,_,_,cap=self.run_guard();launch=m.decode((cap['stage']/'outer-launch-report.json').read_bytes())
        for report in (cap['report']|{'worker_pid':78},cap['report']|{'config':cap['config']|{'deadline_qpc':f.D+1}}):
            with self.assertRaises(ValueError):m.bind_report(report,cap['config'],f.b.PARENT,launch,copy.deepcopy(r),root=cap['stage'])
        outer=cap['stage']/'outer-launch-report.json';raw=outer.read_bytes();outer.write_bytes(raw+b'x')
        with self.assertRaises(ValueError):m.bind_report(cap['report'],cap['config'],f.b.PARENT,launch,copy.deepcopy(r),root=cap['stage'])
        outer.write_bytes(raw)
        path=cap['stage']/'tcp-observations/withheld.bin';path.write_bytes(path.read_bytes()+b'x')
        with self.assertRaises(ValueError):m.bind_report(cap['report'],cap['config'],f.b.PARENT,launch,copy.deepcopy(r),root=cap['stage'])
    def test_public_unknown_and_shared_sid_tamper_claims_cannot_be_promoted(self):
        r,_,_,_=self.run_guard();m.validate_public(r)
        for k in m.core.FALSE_CLAIMS:
            with self.subTest(k=k),self.assertRaises(ValueError):m.validate_public(r|{k:True})
        for change in ({'recovery_required':True},{'tree_retained':False},{'loopback_observation':None},{'source_sha256':None}):
            with self.assertRaises(ValueError):m.validate_public(r|change)
        altered=copy.deepcopy(r);altered['loopback_observation']['frontend_setup']=m.empty_setup()
        with self.assertRaises(ValueError):m.validate_public(altered)
        v=m.blank('preflight');v['loopback_observation']=r['loopback_observation']
        with self.assertRaises(ValueError):m.validate_public(v)

if __name__=='__main__':unittest.main()
