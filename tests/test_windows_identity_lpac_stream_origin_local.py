"""Inert source/plan/worker/root-bound physical evidence tests."""
import copy
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
m=load('stream_guard_tests',ROOT/'.github/windows_identity_lpac_stream_origin_local.py')
f=load('stream_guard_core_fake',Path(__file__).with_name('test_windows_identity_lpac_stream_origin.py'))
H='1'*64
def plan(source=H,actor=H,manifest=H,network=H,network_manifest=H):
    return dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,run='1'*32,case='2'*32,device_sha256=H,source_sha256=source,actor_sha256=actor,manifest_sha256=manifest,network_actor_sha256=network,network_manifest_sha256=network_manifest,challenges=copy.deepcopy(f.CHALLENGES),**dict.fromkeys(m.core.ACKS,True),recovery_reference='predeclared exact owned review')
class GuardAPI:
    atomic_job_requested=True
    def __init__(self,fault=None):self.fault=fault;self.calls=[]
    def windows_x64(self):return True
    def qpc_frequency(self):return f.F
    def qpc(self):return f.T
    def device_sha256(self):return H
    def private_directory(self,path,sid):
        path.mkdir();self.calls.append(path)
        if self.fault=='partial-directory':raise OSError('directory creation returned, readback unknown')
class GuardTests(unittest.TestCase):
    def test_default_cli_and_missing_inputs_never_construct_backend(self):
        for args in ([],['--run-local-lpac-stream-origin']):
            stream=io.StringIO()
            with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend')),patch.object(m.sys,'stdout',stream):self.assertEqual(m.main(args),1)
            self.assertEqual(m.decode(stream.getvalue().encode())['failure'],'inputs')
    def test_false_ready_or_no_explicit_optin_stops_before_backend(self):
        for ready,approved in ((False,True),(True,False)):
            with patch.object(m.core,'ACTUAL_READY',ready),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend')):
                v=m.run_local(*([None]*12),approved=approved)
            self.assertEqual(v['failure'],'inputs');self.assertFalse(v['recovery_required'])
    def test_hidden_worker_also_honors_false_ready_before_api(self):
        with tempfile.TemporaryDirectory() as td:
            c=f.config();root=Path(td).resolve()/m.core.stage_name(c['run']);root.mkdir();p=root/'worker-config.json';p.write_bytes(m.encode(c))
            with patch.object(m,'ROOT',root),patch.object(m,'snapshot',return_value=({},c['source_hashes'],c['source_sha256'])),patch.object(m.core,'ACTUAL_READY',False),patch.object(m.core,'API',side_effect=AssertionError('backend')),self.assertRaisesRegex(ValueError,'^stream_worker_source_ready$'):m.worker(p)
    def test_exact_worker_args_no_public_or_runtime_flags(self):
        for extra in (['--run-local-lpac-stream-origin'],['--actor','x'],['--output','x']):
            with patch.object(m,'worker',side_effect=AssertionError('worker')),self.assertRaises(ValueError):m.main(['--worker','x',*extra])
    def test_plan_scope_nonce_ack_and_dual_artifacts_are_closed(self):
        kw=dict(device=H,source=H,actor=H,manifest=H,network_actor=H,network_manifest=H,challenges=f.CHALLENGES);m.core.validate_plan(plan(),**kw)
        for change in ({'scope':m.base.SCOPE},{'case':'1'*32},{'inherited_pipe_authority_acknowledged':False},{'network_actor_sha256':'2'*64},{'capability_catalog':{}},{'challenges':f.CHALLENGES|{'request':f.CHALLENGES['request']|{'bytes':8192}}}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.core.validate_plan(plan()|change,**kw)
    def test_actual_import_and_native_dependency_closure_is_computed(self):
        files,hashes,source=m.snapshot(ROOT);self.assertEqual(len(files),len(m.SOURCES));self.assertEqual(source,m.sha(m.encode(hashes)));self.assertEqual(len(set(m.SOURCES)),len(m.SOURCES))
        self.assertIn('.github/native/windows_identity_lpac_stream_contract.hpp',files);self.assertIn('.github/windows_identity_lpac_accesscheck.py',files)
    def test_preflight_is_readonly_and_never_launches(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();(root/'private').mkdir();p=root/'plan';p.write_bytes(m.encode(plan()));api=GuardAPI()
            with patch.object(m,'os',NS(name='nt')),patch.object(m.local,'ordinary',return_value=f.b.PARENT),patch.object(m,'snapshot',return_value=({}, {},H)),patch.object(m.core,'verify_actor'),patch.object(m.core,'challenge_inputs',return_value=f.CHALLENGES),patch.object(m.launcher,'launch_owned',side_effect=AssertionError('spawn')):
                v=m.preflight(None,None,H,H,None,None,H,H,root/'request',root/'response',root/'private',p,api=api,root=root)
            self.assertEqual(v['status'],'ready');self.assertFalse(api.calls)
    def run_guard(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir()
        inputs=[root/n for n in (m.core.ACTOR,m.core.MANIFEST,m.core.NETWORK_ACTOR,m.core.NETWORK_MANIFEST)]
        for p,raw in zip(inputs,(b'x'*512,b'{}',b'b'*512,b'{"old":true}')):p.write_bytes(raw)
        files={n:b'# fixed pure source\n' for n in m.SOURCES};hashes={n:m.sha(raw) for n,raw in files.items()};source=m.sha(m.encode(hashes));digests=[m.sha(p.read_bytes()) for p in inputs]
        request=root/'request';response=root/'response';request.write_bytes(f.REQUEST);response.write_bytes(f.RESPONSE)
        p=plan(source,*digests);pp=root/'plan';pp.write_bytes(m.encode(p));api=GuardAPI(fault);calls=[];cap={}
        pre=m.blank('preflight');pre.update(status='ready',source_sha256=source,actor_sha256=digests[0],manifest_sha256=digests[1],network_actor_sha256=digests[2],network_manifest_sha256=digests[3],recovery_plan_sha256=m.sha(pp.read_bytes()));pre['challenges']=copy.deepcopy(f.CHALLENGES);pre['checks'].update(dict.fromkeys(m.CHECKS[:4],True))
        def launch(native,argv,cwd,parent,child,*,qpc_budget,work_cutoff,cleanup_cutoff):
            calls.append(argv);self.assertIs(native,api);self.assertEqual(argv[1:4],['-I','-S','-B']);stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());m.core.config_validate(c)
            self.assertEqual((c['start_qpc'],c['root_deadline_qpc'],c['deadline_qpc'],work_cutoff,cleanup_cutoff),(f.T,f.T+120*f.F,f.D,f.T+117*f.F,f.T+120*f.F))
            if fault=='unknown-worker':raise OSError('unknown spawn')
            tool=stage/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool');fake=f.API(stage,'selected-malformed' if fault=='bad-native' else None);owner=m.core.Owner(stage,c,parent,fake,m.launcher.QpcBudget(fake,c['deadline_qpc'],c['frequency']));fake.owner=owner
            private=owner.execute();m.core.validate_result(private,c,parent=parent,root=stage);report=dict(schema_version=1,stage='lpac-stream-origin-worker',config=c,worker_pid=77,worker_identity=parent,result=private)
            if fault=='bad-worker':report['worker_pid']=78
            (stage/'worker-report.json').write_bytes(m.encode(report));cap.update(stage=stage,c=c,report=report,owner=owner)
            return dict(started=True,resumed=True,child_pid=77,child_identity=m.launcher.safe_identity(parent,parent),native_identity_verified_before_resume=True,timed_out=False,exit_code=0,cleanup=dict(process_exit_confirmed=True,job_empty_confirmed=True,handles_closed=True))
        with patch.object(m.core,'ACTUAL_READY',True),patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),patch.object(m.local,'ordinary',return_value=f.b.PARENT),patch.object(m,'snapshot',return_value=(files,hashes,source)),patch.object(m,'preflight',return_value=pre),patch.object(m.core,'verify_artifacts'),patch.object(m.local.guest,'cleanup_verified',return_value=True),patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m.sys,'executable',str(root/'python.exe')),patch.object(m.sys,'base_prefix',str(root)):
            (root/'python.exe').write_bytes(b'pure');v=m.run_local(inputs[0],inputs[1],digests[0],digests[1],inputs[2],inputs[3],digests[2],digests[3],request,response,root/'private',pp,approved=True,root=root)
        return v,calls,api,cap
    def test_real_coordinator_guard_composition_original_epoch_and_all_false_claims(self):
        v,calls,api,cap=self.run_guard();self.assertEqual(v['status'],'observed');self.assertEqual(len(calls),1);self.assertFalse(v['recovery_required']);self.assertTrue(v['observation']['cleanup_known']);self.assertFalse(any(v[k] for k in m.core.FALSE_CLAIMS))
    def test_partial_stage_unknown_worker_bad_report_never_qualify(self):
        for fault in ('partial-directory','unknown-worker','bad-worker'):
            with self.subTest(fault=fault):
                v,calls,api,cap=self.run_guard(fault);self.assertEqual(v['status'],'inconclusive');self.assertTrue(v['tree_retained']);self.assertTrue(v['recovery_required']);self.assertEqual(len(calls),0 if fault=='partial-directory' else 1)
    def test_bad_native_can_preserve_origin_positive_without_unknown_cleanup(self):
        v,_,_,_=self.run_guard('bad-native');self.assertEqual(v['status'],'inconclusive');self.assertFalse(v['recovery_required']);self.assertTrue(v['observation']['origin_response_observed']);self.assertEqual(v['observation']['native_report_status']['selected'],'invalid')
    def test_physical_outer_or_return_mismatch_rejected(self):
        v,_,_,cap=self.run_guard();root=cap['stage'];launch=m.decode((root/'outer-launch-report.json').read_bytes())
        for name in ('outer-launch-report.json','returns/lpac-pipe-front.json'):
            path=root/name;raw=path.read_bytes();path.write_bytes(raw+b'x')
            with self.assertRaises(ValueError):m.bind_report(cap['report'],cap['c'],f.b.PARENT,launch,copy.deepcopy(v),root=root)
            path.write_bytes(raw)
    def test_public_never_promotes_missing_reports_or_product_claims(self):
        v,_,_,_=self.run_guard()
        for k in m.core.FALSE_CLAIMS:
            with self.subTest(k=k),self.assertRaises(ValueError):m.validate_public(v|{k:True})
        for change in ({'outer_launch_report_sha256':None},{'observation':None},{'recovery_required':True}):
            with self.assertRaises(ValueError):m.validate_public(v|change)
        bad=copy.deepcopy(v);bad['observation']['failure']=None;bad['observation']['origin_response_observed']=1
        with self.assertRaises(ValueError):m.validate_public(bad)
if __name__=='__main__':unittest.main()
