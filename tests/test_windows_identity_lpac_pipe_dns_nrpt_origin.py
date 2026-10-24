"""Actual new coordinator with inert OS/receiver fakes. No actor or socket."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('pipe_dns_pure',ROOT/'.github/windows_identity_lpac_pipe_dns_nrpt_origin.py')
f=load('pipe_dns_old_inert',Path(__file__).with_name('test_windows_identity_lpac_pipe_origin.py'))
pf=load('pipe_dns_policy_fixtures',Path(__file__).with_name('test_windows_identity_dns_exact_nrpt_inventory.py'))
F,T,D=f.F,f.T,f.D

def config():
 c=f.config();c.update(scope=m.SCOPE,profile=m.PROFILE,policy_mode=m.POLICY_MODE,control_actor_sha256=m.sha(b'c'*512),control_manifest_sha256=f.b.H)
 for index,k in enumerate(m.NONCES,1):c[k]=('%032x'%index)
 c['guard_job_name']='Local\\RuleProxy.LocalGuard.'+c['run'];c['source_hashes']=dict.fromkeys(m.SOURCES,f.b.H);c['source_hashes'][m.INVENTORY]=m.sha(b'PS');c['source_sha256']=m.sha(m.encode(c['source_hashes']));return c

class Event:
 def __init__(self):self.value=False
 def set(self):self.value=True
 def is_set(self):return self.value
class Fixture:
 bind_address='127.0.0.1';bind_port=53
 def __init__(self):self.events={k:Event() for k in ('before','selected','after')};self.query_observed=self.events['selected'];self.done=False
 def start(self):return 53
 def mark(self,key):self.events[key].set()
 def snapshot(self,*,deadline):
  cases={k:dict(matched_queries=int(v.value),answers_sent=int(v.value),rejected=0,send_failed=0) for k,v in self.events.items()};n=sum(x['matched_queries'] for x in cases.values())
  return dict(ready=True,error='none',counts=dict(datagrams=n,bytes=n*62,matched_queries=n,answers_sent=n,rejected=0,oversized=0,send_failed=0),cases=cases,case_query_observed={k:v.value for k,v in self.events.items()},selected_query_observed=self.query_observed.value,byte_count_is_observed_lower_bound=True,broker_cancellation_proven=False)
 def finish(self,*,deadline):self.done=True;return dict(self.snapshot(deadline=deadline),socket_close_attempted=True,socket_close_uncertain=False,socket_closed=True,thread_stopped=True,cleanup_confirmed=True)

class API(f.API):
 def __init__(self,root,fault=None):super().__init__(root);self.special=fault;self.fixture=None;self.query_count=0
 def atomic_spawn(self,info,argv,*args,**kw):
  super().atomic_spawn(info,argv,*args,**kw)
  if info.hProcess:self.rows[info.hProcess]['argv']=list(argv)
 def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
  assert len(argv)==(19 if profile_pointer else 14) and tuple(int(x) for x in argv[5:7])==tuple(ends)
  self.atomic_spawn(info,argv,cwd,job,owners,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=None)
  self.rows[info.hProcess]['role']='lpac-pipe-front' if profile_pointer else 'ordinary-pipe-relay';state.update(raw_return=1,raw_error=None,raw_pi=m.info_values(info),returned_qpc=self.now,creation_unknown=False);on_return(state.copy())
 def resume(self,thread):
  h=thread-1;r=self.rows[h];argv=r['argv'];c=self.owner.c
  if 'role' in r:
   role=r['role'];self.resume_roles.append(role);r['resumed']=True
   if role=='ordinary-origin-fixture':
    v=dict(schema_version=1,stage='bridge-origin-ready',run_id=c['run'],case_id=c['case'],pid=h,port=54321,qpc_frequency=F,deadline_qpc=m.work_cutoff(c),loopback_ipv4=True);(self.root/m.REPORT_PATHS['ready']).write_bytes(m.encode(v));return
   if role=='lpac-pipe-front':
    assert self.owner.j['proof']['qualified'] and self.owner.pipes.confirmed_closed
    self.finish_reports();self.rows[h]['exited']=False
    p=self.root/m.REPORT_PATHS['selected'];v=m.decode(p.read_bytes());v['stage']='lpac-pipe-dns-ipc-complete';v['dns_case_id']=c['dns_selected_case']
    if self.special=='ipc-fail':v['ipc_mechanics']['pipe']['eof_observed']=False
    p.write_bytes(m.encode(v))
    if self.special=='stale':self.now+=6*F
    if self.special=='physical-policy-change':
     p=self.root/'tools/inventory/stdout';value=m.decode(p.read_bytes());value['effective_nrpt_rules'][0]['Namespace']='changed.unrelated.example';p.write_bytes(m.encode(value))
   return
  super().resume(thread)
  name=Path(argv[0]).name.casefold();work=self.root/'tools'/('inventory' if name=='powershell.exe' else 'dns-'+('before' if argv[1]==c['dns_before_case'] else 'after'))
  if name=='powershell.exe':
   rows=[pf.row(),pf.row('fe3cr.delivery.mp.microsoft.com')]
   if self.special=='policy-match':rows[0]['Namespace']=c['dns_selected_case']+'.n0a.invalid'
   if self.special=='policy-suffix':rows[0]['Namespace']='.unrelated.example'
   if self.special=='policy-loopback':rows[0]['NameServers']=['127.0.0.1']
   if self.special=='policy-da':rows[0]['DirectAccessEnabled']=True
   value=dict(schema_version=1,stage=m.policy.STAGE,run=c['inventory_run'],pid=h,qpc_frequency=F,start_qpc=c['start_qpc'],deadline_qpc=c['deadline_qpc'],begin_qpc=self.now,end_qpc=self.now,read_only=True,dns_servers=['192.0.2.53'],effective_nrpt_count=2,effective_nrpt_rules=rows,udp53_count=0,tcp53_count=0)
  elif name==m.CONTROL_ACTOR.casefold():
   label='before' if argv[1]==c['dns_before_case'] else 'after';self.fixture.mark(label);self.now+=2;r2=dict(configured=True,called=True,completed=True,pending=False,answer_match=True,records_released=True,context_retained=False,within_deadline=True,api_status=0,query_status=0,record_count=1,start_qpc=self.now-1,end_qpc=self.now)
   i=f.native_identity(dict(identity=self.identity(h+2),pid=h),c);i['nonce']=argv[1]
   value=dict(schema_version=1,stage='dns-standard-native',identity=i,server_constructor='official-v1-zero-port',qpc_frequency=F,deadline_qpc=int(argv[3]),result=r2)
  else:return
  (work/'stdout').write_bytes(m.encode(value));(work/'stderr').write_bytes(b'');r['exited']=True
 def statistics(self,token,kind,label):
  raw,size=super().statistics(token,kind,label)
  if self.special=='modified-after-IPC' and self.rows.get(token-2,{}).get('role')=='lpac-pipe-front' and self.rows[token-2].get('resumed'):
   st=m.access.TOKEN_STATISTICS.from_buffer(raw);st.ModifiedId.LowPart+=1
  return raw,size
 def access_api(self):
  self.probe_calls=getattr(self,'probe_calls',0)+1
  if self.special=='second-proof-close' and self.probe_calls==2:self.probe_fault='close-false'
  if self.special=='second-proof-throw' and self.probe_calls==2:raise OSError('observer did not return a proof')
  return super().access_api()
 def on_go(self,path,raw):
  c=self.owner.c;j=self.owner.j;front=self.owner.tasks['lpac-pipe-front'];h=front['pid'];self.now+=4
  if raw[5]==6:
   self.query_count+=1;end=int.from_bytes(raw[88:96],'little');status=0 if self.special in ('wire','wire-malformed') else 87 if self.special=='87' else 5
   if self.special in ('wire','wire-malformed'):self.fixture.mark('selected')
   pending=self.special=='pending';r=dict(configured=True,called=True,completed=not pending,pending=pending,answer_match=status==0,records_released=not pending,context_retained=pending,within_deadline=True,api_status=9506 if pending else status,query_status=0,record_count=int(status==0),start_qpc=self.now-2,end_qpc=self.now-1)
   value=dict(schema_version=1,stage='lpac-pipe-dns-dns-result',role='lpac-pipe-front',run_id=c['run'],http_case_id=c['case'],dns_case_id=c['dns_selected_case'],pid=h,sequence=1,pair_qpc=[F,j['pair']['start'],j['pair']['end']],phase_qpc=[self.now-3,end,self.now],command_close_verified=True,identity=f.native_identity(front,c),dns=dict(server_constructor='official-v1-zero-port',server_address='127.0.0.1',server_port=53,query_name=c['dns_selected_case']+'.n0a.invalid',query_type=1,query_options=m.dns.OPTIONS,result=r),failure='dns-pending' if pending else None,selected_socket_api_tested=False,proxy_tested=False,product_acceptance=False)
   (self.root/'selected-report/dns.json').write_bytes(b'{bad' if self.special=='wire-malformed' else m.encode(value))
  else:
   phase=m.decode((self.root/'selected-report/dns.json').read_bytes());value=dict(schema_version=1,stage='lpac-pipe-dns-final',role='lpac-pipe-front',run_id=c['run'],http_case_id=c['case'],dns_case_id=c['dns_selected_case'],pid=h,pair_qpc=[F,j['pair']['start'],j['pair']['end']],last_qpc=self.now,ipc_report_sha256=j['reports']['selected']['sha256'],dns_report_sha256=j['dns_report']['sha256'],dns_called=phase['dns']['result']['called'],dns_pending=False,finish_admitted=True,command_close_verified=True,failure=None,selected_socket_api_tested=False,proxy_tested=False,product_acceptance=False);(self.root/'selected-report/final.json').write_bytes(m.encode(value));self.rows[h].update(exited=True,exitcode=0)

class FlowTests(unittest.TestCase):
 def owner(self,fault=None):
  td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
  for n in ('inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report'):(root/n).mkdir()
  for n in ('health','relay-report','origin-report'):(root/n/'temp').mkdir()
  for n,raw in ((m.ACTOR,b'x'*512),(m.origin.ACTOR,b'b'*512),(m.CONTROL_ACTOR,b'c'*512)):(root/'inputs'/n).write_bytes(raw)
  p=root/m.INVENTORY;p.parent.mkdir(exist_ok=True);p.write_bytes(b'PS')
  for name in ('icacls.exe','WindowsPowerShell/v1.0/powershell.exe'):
   p=root/'win/System32'/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'tool')
  c=config();api=API(root,fault);fixture=Fixture();api.fixture=fixture;o=m.Owner(root,c,f.b.PARENT,api,m.launcher.QpcBudget(api,D,F),fixture_factory=lambda cases,deadline:fixture);api.owner=o
  original=m.publish
  def publish(path,raw,budget,end):original(path,raw,budget,end);api.on_go(path,raw)
  with patch.object(m,'publish',side_effect=publish):j=o.execute()
  return o,api,j
 def test_same_real_coordinator_IPC_then_API5_before_after_and_cleanup(self):
  o,api,j=self.owner();m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);v=m.project(j,o.c,parent=f.b.PARENT,root=o.root)
  self.assertIsNone(j['failure']);self.assertTrue(v['access_denial_observed']);self.assertEqual(api.query_count,1);self.assertEqual([x['label'] for x in j['inventory_gates']],['bind','before','selected','after']);self.assertTrue(all(j[k] for k in m.CLEAN_KEYS));self.assertTrue(j['fixture_cleanup']);self.assertEqual(len(j['dns_go']),2);self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS));self.assertTrue(v['selected_dns_api_tested'])
  self.assertEqual(v['policy_inventory']['effective_nrpt_count'],2);self.assertEqual(v['policy_inventory']['exact_nonmatching_rule_count'],2);self.assertEqual(v['policy_inventory']['matched_query_count'],0);self.assertEqual(len(j['policy_decisions']),4)
  self.assertTrue(all(d['projection']['raw_sha256']==j['inventory']['sha256'] and m.policy.inventory_safe(d['projection']) for d in j['policy_decisions']))
 def test_matching_unknown_or_loopback_effective_policy_stops_before_fixture_and_pair(self):
  for fault in ('policy-match','policy-suffix','policy-loopback','policy-da'):
   with self.subTest(fault=fault):
    o,api,j=self.owner(fault);m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);v=m.project(j,o.c,parent=f.b.PARENT,root=o.root)
    self.assertEqual(j['failure'],'inventory');self.assertEqual(api.query_count,0);self.assertEqual(j['dns_go'],[]);self.assertFalse(j['fixture_attempted']);self.assertNotIn('lpac-pipe-front',api.resume_roles);self.assertFalse(v['access_denial_observed'])
    if fault in ('policy-match','policy-da'):self.assertEqual(v['policy_inventory']['effective_nrpt_count'],2);self.assertFalse(m.policy.inventory_safe(v['policy_inventory']))
    else:self.assertEqual(v['policy_inventory'],m.policy.unknown_inventory())
 def test_every_gate_rechecks_same_physical_stdout_without_recollecting(self):
  o,api,j=self.owner('physical-policy-change');self.assertEqual(j['failure'],'inventory');self.assertEqual(api.query_count,0);self.assertEqual(j['dns_go'],[])
  self.assertEqual(len([r for r in j['tasks'] if r['name']=='inventory']),1)
  with self.assertRaisesRegex(ValueError,'pipe_dns_policy_physical_stdout'):m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
 def test_policy_mode_projection_decision_and_raw_count_forgery_rejected(self):
  o,api,j=self.owner();m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
  for mutation in ('mode','count','drop-decision','gate-clock'):
   bad=copy.deepcopy(j)
   if mutation=='mode':bad['policy_mode']='strict-count-zero'
   elif mutation=='count':bad['policy_inventory']['effective_nrpt_count']=0
   elif mutation=='drop-decision':bad['policy_decisions'].pop()
   else:bad['policy_decisions'][-1]['qpc']+=6*F
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=f.b.PARENT,root=o.root)
 def test_policy_inventory_requires_held_natural_process_and_closed_source_command(self):
  o,api,j=self.owner();m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
  for mutation in ('not-resumed','exit1','command','exit-clock'):
   bad=copy.deepcopy(j);row=next(r for r in bad['tasks'] if r['name']=='inventory')
   if mutation=='not-resumed':row['resumed']=False
   elif mutation=='exit1':row['exit_code']=1
   elif mutation=='command':row['command'][6]=str(o.root/'not-the-inventory.ps1')
   else:row['exit_observed_qpc']=row['resume_qpc']-1
   with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=f.b.PARENT,root=o.root)
 def test_API87_is_inconclusive_not_denial_but_finishes_after_control(self):
  o,api,j=self.owner('87');m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);v=m.project(j,o.c,parent=f.b.PARENT,root=o.root);self.assertFalse(v['access_denial_observed']);self.assertTrue(v['ordinary_after']);self.assertEqual(v['selected_api']['api_status'],87);self.assertFalse(v['selected_api']['query_status_success_verified'])
 def test_selected_wire_positive_stays_bound_and_never_denial(self):
  o,api,j=self.owner('wire');m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);v=m.project(j,o.c,parent=f.b.PARENT,root=o.root);self.assertTrue(v['selected_wire_query_observed']);self.assertFalse(v['access_denial_observed']);self.assertFalse(v['observation_complete'])
 def test_malformed_native_after_independent_wire_stays_a_valid_partial_failure(self):
  o,api,j=self.owner('wire-malformed');m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);v=m.project(j,o.c,parent=f.b.PARENT,root=o.root);self.assertTrue(v['selected_wire_query_observed']);self.assertIsNone(v['selected_api']);self.assertEqual(j['dns_report_status'],'invalid');self.assertTrue(j['api_lifecycle_unknown']);self.assertFalse(v['access_denial_observed'])
 def test_pending_retains_unknown_and_prevents_profile_deletion(self):
  o,api,j=self.owner('pending');m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);self.assertTrue(j['api_lifecycle_unknown']);self.assertFalse(j['profile_deleted']);self.assertFalse(m.diagnostic(j,o.c,f.b.PARENT))
 def test_IPC_failure_or_once_inventory_stale_never_queries_selected(self):
  for fault in ('ipc-fail','stale'):
   with self.subTest(fault=fault):
    o,api,j=self.owner(fault);m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);self.assertEqual(api.query_count,0);self.assertEqual(j['dns_go'],[]);self.assertFalse(m.diagnostic(j,o.c,f.b.PARENT))
 def test_live_ModifiedId_change_or_second_observer_unknown_blocks_DNS_GO(self):
  for fault in ('modified-after-IPC','second-proof-close'):
   with self.subTest(fault=fault):
    o,api,j=self.owner(fault);m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root);self.assertEqual(api.query_count,0);self.assertEqual(j['dns_go'],[]);self.assertFalse(m.diagnostic(j,o.c,f.b.PARENT))
    if fault=='second-proof-close':self.assertFalse(j['observer_resources_cleanup_verified']);self.assertFalse(j['profile_deleted'])
 def test_physical_backdating_GO_or_final_or_wrong_selected_PID_rejected(self):
  o,api,j=self.owner();m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
  for mutation in ('go','dns-pid','final-hash'):
   v=copy.deepcopy(j);restore=[]
   if mutation=='go':v['dns_go'][0]['sha256']='f'*64
   else:
    key='dns_report' if mutation=='dns-pid' else 'dns_final';p=o.root/'selected-report'/('dns.json' if key=='dns_report' else 'final.json');raw=p.read_bytes();restore.append((p,raw));value=m.decode(raw)
    if mutation=='dns-pid':value['pid']+=100
    else:value['ipc_report_sha256']='f'*64
    raw=m.encode(value);p.write_bytes(raw);v[key]=dict(text=raw.decode('ascii'),sha256=m.sha(raw))
   try:
    with self.subTest(mutation=mutation),self.assertRaises(ValueError):m.validate_result(v,o.c,parent=f.b.PARENT,root=o.root)
   finally:
    for p,raw in restore:p.write_bytes(raw)
 def test_second_observer_exception_retains_unknown_and_blocks_profile_deletion(self):
  o,api,j=self.owner('second-proof-throw');m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
  self.assertIsNone(j['dns_proof']);self.assertTrue(j['proof']['qualified']);self.assertTrue(j['proof']['resource_cleanup_verified']);self.assertTrue(o.tasks['lpac-pipe-front']['resumed']);self.assertFalse(j['observer_resources_cleanup_verified']);self.assertTrue(api.controls_uncertain);self.assertFalse(j['profile_deleted']);self.assertEqual(api.query_count,0);self.assertEqual(j['dns_go'],[])
  bad=copy.deepcopy(j);bad['observer_resources_cleanup_verified']=True
  with self.assertRaisesRegex(ValueError,'pipe_dns_second_observer_unknown_resources'):m.validate_result(bad,o.c,parent=f.b.PARENT,root=o.root)
 def test_controls_and_same_token_statistics_cannot_be_physically_backdated_or_changed(self):
  o,api,j=self.owner();m.validate_result(j,o.c,parent=f.b.PARENT,root=o.root)
  for what in ('control-exit','control-after-selected','finish-after-control','modified-id','stats-size'):
   v=copy.deepcopy(j)
   if what=='control-exit':next(r for r in v['tasks'] if r['name']=='dns-after')['exit_observed_qpc']=v['ordinary_reports']['after']['issued_qpc']
   elif what=='control-after-selected':
    # A digest alone cannot authorize a backdated inventory gate/control.
    tick=v['dns_go'][0]['issued_qpc'];v['ordinary_reports']['after']['issued_qpc']=tick;v['inventory_gates'][-1]['qpc']=tick
   elif what=='finish-after-control':next(r for r in v['tasks'] if r['name']=='dns-after')['exit_observed_qpc']=v['dns_go'][1]['issued_qpc']+1
   elif what=='modified-id':next(r for r in v['tasks'] if r['role']=='lpac-pipe-front')['held_checks'][-1]['token_statistics']['modified_id']+=1
   else:next(r for r in v['tasks'] if r['role']=='lpac-pipe-front')['expected_statistics']['unknown']=0
   with self.subTest(what=what),self.assertRaises(ValueError):m.validate_result(v,o.c,parent=f.b.PARENT,root=o.root)
 def test_safe_schema_cannot_promote_missing_API_or_controls(self):
  o,api,j=self.owner();v=m.project(j,o.c,parent=f.b.PARENT,root=o.root)
  for field in ('selected_api','ordinary_before','ordinary_after','same_selected_process_verified'):
   x=copy.deepcopy(v);x[field]=None if field=='selected_api' else False
   with self.subTest(field=field),self.assertRaises(ValueError):m.validate_projection(x)
 def test_late_unknown_APIclock_not_converted_to_denial(self):
  o,api,j=self.owner();v=m.decode(j['dns_report']['text'].encode());v['dns']['result'].update(within_deadline=False,end_qpc=0);v['failure']='qpc';self.assertEqual(m.dns_report(v,j,o.c,f.b.PARENT)['dns']['result']['end_qpc'],0)
  j['dns_report']=dict(text=m.encode(v).decode('ascii'),sha256=m.sha(m.encode(v)));self.assertFalse(m.diagnostic(j,o.c,f.b.PARENT))



Function=f.Function
b=f.b
class NativeConstructorTests(unittest.TestCase):
 setUp=f.ConstructorTests.setUp
 def constructor(self,selected=True,shape='ok',late=False,receipt_fail=False):
     api=m.API.__new__(m.API);api.controls_uncertain=False;api.proc=b.proc;api.process_info=b.proc._ProcessInfo;calls=[];attrs=[];closed=[];now=[T+1]
     def check(ok,op):
         if not ok:raise OSError(op)
     api.native=NS(check=check);api.pipe_flags=lambda h:1;api.pipe_type=lambda h:3
     def init(ptr,count,flags,size):C.cast(size,C.POINTER(C.c_size_t))[0]=512;calls.append(('init',ptr is None,count));return int(ptr is not None)
     def update(a,flags,kind,value,size,old,returned):
         if kind==m.base.JOB_LIST:payload=list(C.cast(value,C.POINTER(C.c_void_p*1)).contents)
         elif kind==0x20002:payload=list(C.cast(value,C.POINTER(C.c_void_p*2)).contents)
         elif kind==m.base.SECURITY_CAPABILITIES:
             cap=C.cast(value,C.POINTER(b.proc._SecurityCapabilities)).contents;payload=[cap.AppContainerSid,cap.Capabilities,cap.CapabilityCount,cap.Reserved]
         else:payload=C.cast(value,C.POINTER(C.c_uint32))[0]
         attrs.append((kind,size,payload));return 1
     def create(app,command,ps,ts,inherit,flags,env,cwd,start,pi):
         calls.append(('create',inherit,flags));p=C.cast(pi,C.POINTER(b.proc._ProcessInfo)).contents
         values=[701,702,703,704] if shape=='ok' else [991,991,55,56] if shape=='false-garbage' else [0,0,0,0] if shape in ('false-zero','error0') else [701,0,703,0]
         p.hProcess,p.hThread,p.dwProcessId,p.dwThreadId=values
         if late:now[0]=T+10000
         if shape=='exception':raise OSError('unknown return')
         self.error[0]=0 if shape=='error0' else 5;return 0 if shape in ('false-garbage','false-zero','error0') else 1
     api.k=NS(InitializeProcThreadAttributeList=Function(init),UpdateProcThreadAttribute=Function(update),CreateProcessW=Function(create),DeleteProcThreadAttributeList=Function(lambda p:calls.append(('delete',))))
     owners=m.helpers.OneShotHandles(closed.append);budget=m.launcher.QpcBudget(NS(qpc=lambda:now[0],qpc_frequency=lambda:F),T+10000,F);state=dict(creation_attempted=False);info=api.process_info();received=[]
     def returned(s):
         self.assertFalse(owners.pending);self.assertEqual(m.info_values(info),[0]*4);received.append(copy.deepcopy(s));calls.append(('receipt',))
         if receipt_fail:raise OSError('disk unknown')
     argv=[m.ACTOR if selected else m.origin.ACTOR,'pipe-dns-front' if selected else 'pipe-relay','1'*32,'2'*32,'report','101','102','10000','1000','20000','S-1-5-21-1','S-1-15-2-1-2-3-4-5-6-7' if selected else 'none','0','54321'];argv+=['3'*32,'go','dns','finish','final'] if selected else []
     exc=None
     try:api.pair_spawn(info,argv,Path('.'),'SystemRoot=x\0LOCALAPPDATA=y\0\0' if selected else 'SystemRoot=x\0\0',91,owners,state,ends=(101,102),pipe_pending={101,102},profile_pointer=77 if selected else None,budget=budget,end=T+10000,on_return=returned)
     except BaseException as e:exc=e
     return api,info,state,owners,calls,attrs,received,exc
 def test_real_new_constructor_exact_four_attributes_and_zero_caps(self):
  api,info,state,owners,calls,attrs,received,e=self.constructor();self.assertIsNone(e);self.assertEqual(len(attrs),4);self.assertEqual(attrs[2][2],[77,None,0,0]);self.assertEqual(attrs[3][2],1);self.assertLess(next(i for i,v in enumerate(calls) if v[0]=='receipt'),len(calls));self.assertEqual(len(owners.pending),2)
 def test_false_partial_exception_and_lateTRUE_keep_distinct_authority(self):
  for shape in ('false-garbage','exception','partial','false-zero'):
   with self.subTest(shape=shape):
    api,info,state,owners,calls,attrs,received,e=self.constructor(shape=shape);self.assertIsNotNone(e);self.assertEqual(len(owners.pending),0);self.assertEqual(state['creation_unknown'],shape!='false-zero');self.assertEqual(m.info_values(info),[0]*4)
  for kw in (dict(late=True),dict(receipt_fail=True)):
   with self.subTest(kw=kw):
    api,info,state,owners,calls,attrs,received,e=self.constructor(**kw);self.assertIsNotNone(e);self.assertFalse(state['creation_unknown']);self.assertEqual(len(owners.pending),2)
 def test_plain_ordinary_relay_keeps_only_Job_and_exact_HANDLELIST2(self):
  api,info,state,owners,calls,attrs,received,e=self.constructor(selected=False);self.assertIsNone(e);self.assertEqual(len(attrs),2);self.assertEqual(attrs[1][2],[101,102])

class PurePlanTests(unittest.TestCase):
 def test_47closure_and_no_old_source_rebinding(self):
  c=config();m.config_validate(c);self.assertEqual(len(m.SOURCES),47);self.assertEqual(len(set(m.SOURCES)),47);self.assertIs(type(m.ACTUAL_READY),bool);self.assertEqual(len(m.NATIVE_SOURCES),6)
  for k in ('dns_before_case','dns_after_case'):
   v=copy.deepcopy(c);v[k]=v['dns_selected_case']
   with self.subTest(k=k),self.assertRaises(ValueError):m.config_validate(v)
 def test_cold_pending_readback_never_reopens_published_hot_GO(self):
  with tempfile.TemporaryDirectory() as td:
   root=Path(td).resolve();path=root/'dns-go.bin';now=NS(qpc=lambda:T+1,qpc_frequency=lambda:F);budget=m.launcher.QpcBudget(now,D,F);original=m.local.bounded;seen=[]
   def read(p,n):
    seen.append(Path(p).name)
    if Path(p)==path:raise OSError(32,'hot GO sharing')
    return original(p,n)
   with patch.object(m.local,'bounded',side_effect=read):m.publish(path,b'x'*128,budget,D)
   self.assertEqual(path.read_bytes(),b'x'*128);self.assertEqual(seen,['dns-go.bin.pending','dns-go.bin.pending'])
  with tempfile.TemporaryDirectory() as td:
   path=Path(td).resolve()/'dns-go.bin'
   with patch.object(m.local,'bounded',return_value=b'wrong'),self.assertRaises(ValueError):m.publish(path,b'x'*128,budget,D)
   self.assertFalse(path.exists())

if __name__=='__main__':unittest.main()
