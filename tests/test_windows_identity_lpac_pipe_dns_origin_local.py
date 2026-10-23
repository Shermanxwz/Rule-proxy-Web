"""New explicit guard/schema/held-worker binding, inert filesystem only."""
import copy
import io
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('pipe_dns_guard_tests',ROOT/'.github/windows_identity_lpac_pipe_dns_origin_local.py')
f=load('pipe_dns_flow_for_guard',Path(__file__).with_name('test_windows_identity_lpac_pipe_dns_origin.py'))
class GuardTests(unittest.TestCase):
 def test_default_missing_inputs_and_False_runtime_never_construct_backend(self):
  with patch.object(m.core,'ACTUAL_READY',False),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('backend')),patch.object(m.sys,'stdout',io.StringIO()):
   self.assertEqual(m.main([]),1)
   v=m.run_local(*([None]*14),approved=True);self.assertEqual(v['status'],'inconclusive');self.assertEqual(v['failure'],'inputs');self.assertFalse(v['tree_retained'])
 def test_exact_45_source_snapshot_and_hash_before_any_backend(self):
  files,hashes,h=m.snapshot();self.assertEqual(len(files),45);self.assertEqual(h,m.sha(m.encode(hashes)));self.assertEqual(set(files),set(m.SOURCES));self.assertTrue(all(b'\r' not in b for b in files.values()))
 def test_hidden_False_worker_stops_at_exact_readiness_gate(self):
  c=f.config()
  with tempfile.TemporaryDirectory() as td:
   root=Path(td).resolve()/m.core.stage_name(c['run']);root.mkdir();p=root/'worker-config.json';p.write_bytes(m.encode(c))
   with patch.object(m.core,'ACTUAL_READY',False),patch.object(m,'ROOT',root),patch.object(m,'snapshot',return_value=({},c['source_hashes'],c['source_sha256'])),patch.object(m.core,'API',side_effect=AssertionError('backend')),self.assertRaisesRegex(ValueError,'^ipc_worker_source_ready$'):m.worker(p)
 def test_worker_rejects_any_runtime_or_artifact_extra_flags(self):
  for extra in (['--run-local-lpac-pipe-dns-origin'],['--control-actor','x'],['--output','x']):
   with self.subTest(extra=extra),patch.object(m,'worker',side_effect=AssertionError('worker')),self.assertRaises(ValueError):m.main(['--worker','x',*extra])
 def binding(self,j,o):
  parent=f.f.b.PARENT;launch=dict(started=True,resumed=True,native_identity_verified_before_resume=True,child_pid=901,child_identity=m.launcher.safe_identity(parent,parent),cleanup=dict(process_exit_confirmed=True));raw=m.encode(launch);(o.root/'outer-launch-report.json').write_bytes(raw)
  pub=m.blank('runtime');pub.update(source_sha256=o.c['source_sha256'],actor_sha256=o.c['actor_sha256'],manifest_sha256=o.c['manifest_sha256'],origin_actor_sha256=o.c['origin_actor_sha256'],origin_manifest_sha256=o.c['origin_manifest_sha256'],control_actor_sha256=o.c['control_actor_sha256'],control_manifest_sha256=o.c['control_manifest_sha256'],recovery_plan_sha256=o.c['recovery_plan_sha256'],outer_launch_report_sha256=m.sha(raw));pub['checks'].update({k:True for k in ('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup')})
  report=dict(schema_version=1,stage='lpac-pipe-dns-origin-worker',config=o.c,worker_pid=901,worker_identity=parent,result=j);return parent,launch,pub,report
 def test_real_closed_result_binds_worker_public_and_tampered_PID_rejected(self):
  case=f.FlowTests();self.addCleanup(case.doCleanups);o,api,j=case.owner();parent,launch,pub,report=self.binding(j,o)
  m.bind_report(report,o.c,parent,launch,pub,root=o.root);pub.update(status='observed',observation_complete=True);m.validate_public(pub);self.assertTrue(pub['selected_dns_api_tested']);self.assertTrue(pub['observation']['access_denial_observed'])
  report['worker_pid']+=1
  with self.assertRaises(ValueError):m.bind_report(report,o.c,parent,launch,pub,root=o.root)
 def test_bound_independent_wire_survives_bad_result_without_forensic_fallback(self):
  case=f.FlowTests();self.addCleanup(case.doCleanups);o,api,j=case.owner('wire');parent,launch,pub,report=self.binding(j,o);report['result']['unknown_extra']=1
  with self.assertRaises(ValueError):m.bind_report(report,o.c,parent,launch,pub,root=o.root)
  self.assertTrue(pub['selected_wire_query_observed']);self.assertEqual(pub['status'],'failed');pub.update(failure='report',recovery_required=True);m.validate_public(pub);self.assertIsNone(pub['observation']);self.assertFalse(pub['observation_complete'])
 def test_bound_public_cannot_erase_called_or_unknown_or_independent_wire(self):
  for fault,key in ((None,'selected_dns_api_tested'),('pending','api_lifecycle_unknown'),('wire','selected_wire_query_observed')):
   case=f.FlowTests();self.addCleanup(case.doCleanups);o,api,j=case.owner(fault);parent,launch,pub,report=self.binding(j,o);m.bind_report(report,o.c,parent,launch,pub,root=o.root)
   if fault is None:pub.update(status='observed',observation_complete=True)
   m.validate_public(pub);pub[key]=False
   with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(pub)
 def test_outer_timeout_bad_exit_or_root_expiry_downgrades_complete_without_erasing_wire(self):
  sample=f.FlowTests();self.addCleanup(sample.doCleanups);o,_,j=sample.owner();observation=m.core.project(j,o.c,parent=f.f.b.PARENT,root=o.root)
  for fault in ('timeout','bad-exit','root-expiry'):
   for hit in (False,True):
    with self.subTest(fault=fault,hit=hit),tempfile.TemporaryDirectory() as td:
     root=Path(td).resolve();(root/'private').mkdir();inputs=[root/n for n in (m.core.ACTOR,m.core.MANIFEST,m.core.origin.ACTOR,m.core.origin.MANIFEST,m.core.CONTROL_ACTOR,m.core.CONTROL_MANIFEST)]
     for index,p in enumerate(inputs):p.write_bytes(bytes([index+1])*512)
     digests=[m.sha(p.read_bytes()) for p in inputs];files={n:b'# inert source\n' for n in m.SOURCES};hashes={n:m.sha(raw) for n,raw in files.items()};source=m.sha(m.encode(hashes));c=f.config()
     plan=dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,**{k:c[k] for k in m.core.NONCES},device_sha256='1'*64,source_sha256=source,**dict(zip(('actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256'),digests)),recovery_reference='fixed inert plan',**dict.fromkeys(m.core.ACKS,True));pp=root/'plan';pp.write_bytes(m.encode(plan))
     now=[f.T];api=NS(windows_x64=lambda:True,qpc_frequency=lambda:f.F,qpc=lambda:now[0],device_sha256=lambda:'1'*64,private_directory=lambda p,s:p.mkdir(),atomic_job_requested=True)
     pre=m.blank('preflight');pre.update(status='ready',source_sha256=source,recovery_plan_sha256=m.sha(pp.read_bytes()),**dict(zip(('actor_sha256','manifest_sha256','origin_actor_sha256','origin_manifest_sha256','control_actor_sha256','control_manifest_sha256'),digests)));pre['checks'].update(dict.fromkeys(m.CHECKS[:4],True))
     def launch(api,argv,cwd,*a,**kw):
      (cwd.parent/'worker-report.json').write_bytes(b'{}')
      if fault=='root-expiry':now[0]=f.T+120*f.F
      return dict(started=True,resumed=True,native_identity_verified_before_resume=True,timed_out=fault=='timeout',exit_code=1 if fault=='bad-exit' else 0,cleanup=dict(process_exit_confirmed=True))
     def bind(report,c,parent,launch,result,*,root):
      v=copy.deepcopy(observation)
      if hit:v.update(selected_wire_query_observed=True,access_denial_observed=False,observation_complete=False)
      result.update(observation=v,selected_wire_query_observed=hit,selected_dns_api_tested=True,recovery_required=False);result['checks'].update(worker_bound=True,mechanism=v['access_denial_observed'])
     (root/'python.exe').write_bytes(b'python')
     with patch.object(m.core,'ACTUAL_READY',True),patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),patch.object(m.local,'ordinary',return_value=f.f.b.PARENT),patch.object(m,'snapshot',return_value=(files,hashes,source)),patch.object(m,'preflight',return_value=pre),patch.object(m.core,'verify_artifacts'),patch.object(m.local.guest,'cleanup_verified',return_value=True),patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m,'bind_report',side_effect=bind),patch.object(m.sys,'executable',str(root/'python.exe')),patch.object(m.sys,'base_prefix',str(root)):
      value=m.run_local(*sum(([inputs[i],inputs[i+1],digests[i],digests[i+1]] for i in (0,2,4)),[]),root/'private',pp,approved=True,root=root)
     self.assertEqual(value['status'],'failed' if hit else 'inconclusive');self.assertFalse(value['observation_complete']);self.assertFalse(value['observation']['access_denial_observed']);self.assertFalse(value['checks']['mechanism']);self.assertEqual(value['selected_wire_query_observed'],hit)
 def test_preflight_cannot_carry_wire_unknown_or_tested_runtime_facts(self):
  for key in ('selected_wire_query_observed','selected_dns_api_tested','api_lifecycle_unknown'):
   v=m.blank('preflight');v[key]=True
   if key=='selected_wire_query_observed':v['status']='failed'
   with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(v)
if __name__=='__main__':unittest.main()
