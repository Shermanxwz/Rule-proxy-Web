"""Pure LPAC launcher/owner tests; no Win32 process, socket, DNS or ACL APIs."""
import copy
import ctypes as C
import io
import importlib.util
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('standalone_lpac',ROOT/'.github/windows_identity_lpac_dns_local.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
s=importlib.util.spec_from_file_location('lpac_process_structures',ROOT/'ruleproxy/windows_app_process.py')
proc=importlib.util.module_from_spec(s);s.loader.exec_module(proc)
F=1000;T=10000;D=T+115*F;SID='S-1-5-21-1-2-3-1000';ACSID='S-1-15-2-1-2-3-4-5-6-7';H='1'*64
CATALOG={'AgenticAppContainer':'S-1-15-3-1024-1-2-3-4-5-6-7-8','privateNetworkClientServer':m.live.PNCS}
PARENT=dict(sid=SID,session_id=1,token_type=1,elevation_type=3,elevated=False,appcontainer=False,appcontainer_sid=None,
    integrity_rid=8192,ui_access=False,capability_count=0,admin_attributes=16)

def config():
    hashes=dict.fromkeys(m.SOURCES,H)
    return dict(schema_version=1,scope=m.SCOPE,**{n:('%032x'%(i+1)) for i,n in enumerate(m.NONCES)},start_qpc=T,frequency=F,
        deadline_qpc=D,root_deadline_qpc=T+120*F,guard_job_name='Local\\RuleProxy.LocalGuard.'+('%032x'%1),source_hashes=hashes,
        source_sha256=m.sha(m.encode(hashes)),actor_sha256=m.sha(b'x'*512),manifest_sha256=H,device_sha256=H,recovery_plan_sha256=H,
        capability_catalog=copy.deepcopy(CATALOG))

def public_base():
    v=m.blank('runtime');v.update(source_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=H,tree_retained=True)
    v['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound'),True))
    return v

def native_identity(task,c):
    i=task['identity']
    return dict(schemaVersion=1,mode='actor',nonce=c['run'],pid=task['pid'],tokenUserSid=i['sid'],tokenIsAppContainer=i['appcontainer'],
        tokenAppContainerSid=i['appcontainer_sid'],tokenElevated=False,isProcessInJob=True,tokenCapabilities=task['capabilities'],queriesSucceeded=True,errors=[])

def ready(task,c,name):
    return dict(schema_version=1,stage='proxy-c-client-ready',role='selected-client' if name=='selected' else 'health-client',run_id=c['run'],
        boot_case_id=c[name+'_boot'],pid=task['pid'],identity=native_identity(task,c),capability_profile='agentic-pncs' if name=='selected' else 'ordinary',
        capability_profile_verified=True,catalog_cleanup_verified=True,qpc=[F,T,D,T+100],admission_nonce=c[name+'_admission'],ready=True,network_initialized=False,failure=None)

def phase(task,c,name,label,fields,status):
    now=fields['phase_deadline']-1000
    r=dict(configured=True,called=True,completed=True,pending=False,answer_match=status==0,records_released=True,context_retained=False,
        within_deadline=True,api_status=status,query_status=0,record_count=1 if status==0 else 0,start_qpc=now+10,end_qpc=now+20)
    return dict(schema_version=1,stage='proxy-c-client-phase',role='selected-client' if name=='selected' else 'health-client',run_id=c['run'],
        boot_case_id=c[name+'_boot'],case_id=c[label+'_case'],pid=task['pid'],sequence=fields['sequence'],operation='dns-query',target_port=53,
        admission_nonce=c[name+'_admission'],identity=native_identity(task,c),root_qpc=[F,T,D],phase_qpc=[now,fields['phase_deadline'],now+30],
        command_close_verified=True,dns=dict(server_constructor='official-v1-zero-port',server_address='127.0.0.1',server_port=53,
        query_name=c[label+'_case']+'.n0a.invalid',query_type=1,query_options=0x19e8,result=r),failure=None,proxy_tested=False,product_acceptance=False)

def final(task,c,name):
    r=ready(task,c,name)
    for k in ('admission_nonce','ready','network_initialized'):r.pop(k)
    r.update(stage='proxy-c-client-final',phase_count=1 if name=='selected' else 2,finished=True,network_initialized_before_go=False,
        network_initialized=True,command_close_verified=True,proxy_tested=False,product_acceptance=False)
    return r

class FakeFixture:
    bind_address='127.0.0.1';bind_port=53
    def __init__(self,cases,**kw):
        self.query_observed=threading.Event();self.seen=dict.fromkeys(('before','selected','after'),0);self.cleanup_error=False
    def start(self):return 53
    def snapshot(self,**kw):
        total=sum(self.seen.values());rows={k:dict(matched_queries=n,answers_sent=n,rejected=0,send_failed=0) for k,n in self.seen.items()}
        return dict(ready=True,error='none',counts=dict(datagrams=total,bytes=62*total,matched_queries=total,answers_sent=total,rejected=0,oversized=0,send_failed=0),
            cases=rows,case_query_observed={k:n>0 for k,n in self.seen.items()},selected_query_observed=self.query_observed.is_set(),
            byte_count_is_observed_lower_bound=True,broker_cancellation_proven=False)
    def finish(self,**kw):
        if self.cleanup_error:self.query_observed.set();raise OSError('fake unknown cleanup')
        return self.snapshot()|dict(socket_close_attempted=True,socket_close_uncertain=False,socket_closed=True,thread_stopped=True,cleanup_confirmed=True)

class API:
    def __init__(self,root,fault=None):
        self.root=root;self.fault=fault;self.now=T+100;self.next=100;self.rows={};self.closed=[];self.events=[];self.controls_uncertain=False
        self.profile_sid=ACSID;self.granted=False;self.removed=False;self.deleted=False
        self.native=NS(environment=lambda work:'SystemRoot='+str(root/'win')+'\0TEMP='+str(work/'temp')+'\0TMP='+str(work/'temp')+'\0\0')
    def qpc(self):return self.now
    def qpc_frequency(self):return F
    def process_info(self):return NS(hProcess=None,hThread=None,dwProcessId=0)
    def close(self,h):
        if h in self.closed:raise AssertionError('duplicate close')
        self.closed.append(h)
        if self.fault=='stdio-close' and h>10000 and not hasattr(self,'stdio_failed'):
            self.stdio_failed=True;raise OSError('one close unknown')
    def owned_job(self,owners):self.next+=10;owners.add(self.next);return self.next
    def catalog(self):return CATALOG
    def create_profile(self,name,state):state.update(attempted=True,returned=True,created=True,pointer=77,sid=ACSID);return ACSID
    def derive_profile_sid(self,name):return ACSID
    def delete_profile(self,name):self.deleted=True;self.events.append('delete-profile')
    def release_profile_sid(self,state):state['pointer']=None
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def atomic_spawn(self,info,argv,cwd,job,owners,state,**kw):
        state['creation_attempted']=True
        if self.fault=='unknowncreate' and kw['profile_pointer']:
            self.events.append('unknowncreate');raise OSError('unknown create')
        self.next+=10;info.hProcess=self.next;info.hThread=self.next+1;info.dwProcessId=self.next
        owners.add(info.hProcess);owners.add(info.hThread)
        self.rows[info.hProcess]=dict(argv=argv,job=job,lpac=kw['profile_pointer'] is not None,exited=False,kwargs=kw)
    def creation_time(self,h):return 5000+h
    def verify_job(self,job,h):
        if self.rows[h]['job']!=job:raise ValueError('wrong job')
    def verify_outer(self,name,h):
        self.events.append(('outer',h))
        if self.fault=='outerjob' and self.rows[h]['lpac']:raise ValueError('outer')
    def verify_image(self,h,path):assert self.rows[h]['argv'][0]==str(path)
    def token_for_process(self,h):return h+2
    def identity(self,token):
        r=copy.deepcopy(PARENT)
        if self.rows[token-2]['lpac']:r.update(appcontainer=True,appcontainer_sid=ACSID,integrity_rid=4096,capability_count=2)
        if self.fault=='sid' and self.rows[token-2]['lpac']:r['appcontainer_sid']=ACSID+'-1'
        if self.fault=='medium' and self.rows[token-2]['lpac']:r['integrity_rid']=8192
        return r
    def groups(self,token,*args):return [(CATALOG[k],4) for k in ('AgenticAppContainer','privateNetworkClientServer')] if self.rows[token-2]['lpac'] else []
    def lpac_flag(self,token):
        selected=self.rows[token-2]['lpac'];self.events.append(('lpac-query',selected))
        if self.fault in ('ordinary46-87','selected46-87'):
            native=m.launcher.NativeAPI.__new__(m.launcher.NativeAPI)
            def information(held_token,kind,value,size,returned):
                assert held_token==token and kind==46 and size==4
                if (not selected and self.fault=='ordinary46-87') or (selected and self.fault=='selected46-87'):
                    C.set_last_error(87);return 0
                C.cast(value,C.POINTER(C.c_uint32))[0]=1;C.cast(returned,C.POINTER(C.c_uint32))[0]=4;return 1
            native.a=NS(GetTokenInformation=information)
            adapter=m.LPACAPI.__new__(m.LPACAPI);adapter.native=native
            return adapter.lpac_flag(token)
        if selected and self.fault in ('lpac0','lpacgo'):
            if self.fault=='lpac0' or any(isinstance(x,tuple) and x[0]=='go' for x in self.events):return 0
        return int(selected)
    def resume(self,thread):
        h=thread-1;r=self.rows[h];self.events.append(('resume',r['lpac']));argv=r['argv']
        if '/grant' in argv:self.granted=True;r['exited']=True
        elif '/remove:g' in argv:self.removed=True;r['exited']=True;self.events.append('remove-acl')
        elif '-File' in argv:
            out=self.root/'tools/inventory';inv=dict(schema_version=1,stage='dns-standard-readonly-inventory',run=self.owner.c['inventory_run'],pid=h,
                qpc_frequency=F,start_qpc=T,deadline_qpc=D,begin_qpc=self.now,end_qpc=self.now,read_only=True,dns_servers=['192.0.2.1'],
                effective_nrpt_count=0,udp53_count=0,tcp53_count=0)
            (out/'stdout').write_bytes(m.encode(inv));r['exited']=True
    def open_stdio_file(self,path,**kw):
        path.write_bytes(b'');self.next+=1;return self.next+10000
    def wait(self,h,ms):
        if ms and not self.rows[h]['exited'] and self.rows[h]['argv'][1] in ('selected-client','health-client'):
            name='selected' if self.rows[h]['lpac'] else 'health';control=self.root/('lpac-control' if name=='selected' else 'health-control')
            seq=2 if name=='selected' else 3
            if (control/('phase-%04d.bin'%seq)).exists():self.rows[h]['exited']=True
        return self.rows[h]['exited']
    def exit_code(self,h):return 0
    def terminate_job(self,job):
        self.events.append('terminate-job')
        for r in self.rows.values():
            if r['job']==job:r['exited']=True
    def terminate_process(self,h):self.rows[h]['exited']=True
    def job_empty(self,job):return not any(not r['exited'] and r['job']==job for r in self.rows.values())
    def sleep_ms(self,n):self.now+=n

class LPACOwnerTests(unittest.TestCase):
    def owner(self,fault=None,status=5):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for n in ('inputs','lpac-report','lpac-control','health','health-control','tools'):(root/n).mkdir()
        (root/'inputs'/m.live.ACTOR).write_bytes(b'x'*512)
        for n in ('icacls.exe','WindowsPowerShell/v1.0/powershell.exe'):
            p=root/'win/System32'/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'tool')
        script=root/m.live.dns.INVENTORY;script.parent.mkdir(parents=True);script.write_bytes(b'fixed readonly inventory')
        c=config();c['source_hashes'][m.live.dns.INVENTORY]=m.sha(script.read_bytes());c['source_sha256']=m.sha(m.encode(c['source_hashes']))
        api=API(root,fault);owner=m.Owner(root,c,PARENT,api,m.launcher.QpcBudget(api,D,F),fixture_factory=FakeFixture);api.owner=owner
        def read(api,budget,path,process,cutoff):
            name='selected' if path.parent.name=='lpac-report' else 'health';task=owner.tasks[name]
            if path.name=='ready.json':value=ready(task,c,name)
            else:
                ticket=owner.j['go'][-1];label=ticket['label'];fields=ticket['fields'];api.events.append(('go',label))
                if fault=='malformed' and label=='selected':owner.fixture.seen['selected']=1;owner.fixture.query_observed.set();raise ValueError('malformed native')
                value=phase(task,c,name,label,fields,status if label=='selected' else 0)
                if label!='selected' or status==0:owner.fixture.seen[label]+=1
                if label=='selected' and status==0:owner.fixture.query_observed.set()
                if fault=='fixture-cleanup':owner.fixture.cleanup_error=True
            raw=m.encode(value);path.write_bytes(raw);return value,raw
        original_wait=owner.wait
        def wait(row,end,code=0):
            if row['name'] in ('selected','health'):
                name=row['name'];p=root/('lpac-report' if name=='selected' else 'health')/'final.json';p.write_bytes(m.encode(final(row,c,name)))
            return original_wait(row,end,code)
        owner.wait=wait
        with patch.object(m.contracts,'read_when_closed',side_effect=read):j=owner.execute()
        return owner,api,j

    def test_real_owner_flow_exact_lpac_gate_go_controls_finish_and_profile_cleanup(self):
        owner,api,j=self.owner();m.validate_result(j,owner.c)
        self.assertIsNone(j['failure']);self.assertTrue(j['selected_access_denial']);self.assertTrue(j['natural_exits'])
        self.assertEqual([(x['role'],x['fields']['opcode']) for x in j['go']],[('health',6),('selected',6),('health',6),('selected',255),('health',255)])
        self.assertEqual([x['label'] for x in j['inventory_gates']],['bind','before','selected','after'])
        self.assertLess(api.events.index('remove-acl'),api.events.index('delete-profile'));self.assertTrue(api.deleted)
        self.assertTrue(all(j[k] for k in ('workload_cleanup','fixture_cleanup','acl_removed','cleanup_tools','profile_deleted','sid_released')))

    def test_wrong_lpac_flag_fresh_sid_low_il_or_outer_job_never_resume_selected_or_go(self):
        for fault in ('lpac0','sid','medium','outerjob'):
            with self.subTest(fault=fault):
                owner,api,j=self.owner(fault);self.assertFalse(j['selected_lpac_held']);self.assertEqual(j['go'],[])
                self.assertNotIn(('resume',True),api.events);self.assertTrue(j['profile_deleted']);m.validate_result(j,owner.c)

    def test_lpac_token_is_rechecked_before_every_go_not_only_constructor(self):
        owner,api,j=self.owner('lpacgo');self.assertTrue(j['selected_lpac_held'])
        self.assertEqual([x['label'] for x in j['go']],['before']);self.assertFalse(j['selected_access_denial'])
        m.validate_result(j,owner.c)

    def test_ordinary_class46_api87_is_never_called_after_exact_nonac_identity(self):
        owner,api,j=self.owner('ordinary46-87');m.validate_result(j,owner.c)
        self.assertIsNone(j['failure']);self.assertTrue(j['natural_exits']);self.assertTrue(j['profile_deleted'])
        self.assertNotIn(('lpac-query',False),api.events)
        self.assertTrue(all(r['lpac'] is None for r in j['tasks']+j['cleanup_tasks'] if r['name']!='selected'))
        self.assertTrue(next(r for r in j['tasks'] if r['name']=='selected')['lpac']==1)

    def test_selected_class46_api87_still_prevents_resume_and_every_go(self):
        owner,api,j=self.owner('selected46-87');m.validate_result(j,owner.c)
        self.assertFalse(j['selected_lpac_held']);self.assertEqual(j['go'],[])
        self.assertNotIn(('resume',True),api.events);self.assertIn(('lpac-query',True),api.events)
        self.assertTrue(j['profile_deleted'])

    def test_ordinary_report_cannot_fabricate_a_class46_zero_readback(self):
        owner,api,j=self.owner();m.validate_result(j,owner.c)
        for field,index in (('tasks',0),('tasks',5),('cleanup_tasks',0)):
            value=copy.deepcopy(j);value[field][index]['lpac']=0
            with self.subTest(field=field,index=index),self.assertRaises(ValueError):m.validate_result(value,owner.c)

    def test_unknown_create_preserves_profile_and_does_not_fake_cleanup(self):
        owner,api,j=self.owner('unknowncreate');self.assertFalse(j['workload_cleanup']);self.assertFalse(j['profile_deleted'])
        self.assertFalse(api.deleted);self.assertEqual(j['go'],[]);m.validate_result(j,owner.c)

    def test_independent_wire_survives_malformed_native_and_outer_projection(self):
        owner,api,j=self.owner('malformed');self.assertTrue(j['selected_wire_query_observed']);m.validate_result(j,owner.c)
        v=public_base()
        v=m.public_result(j,owner.c,v);self.assertEqual(v['status'],'failed');self.assertTrue(v['selected_wire_query_observed']);m.validate_public(v)

    def test_successful_lpac_wire_is_leak_not_product_or_psec_success(self):
        owner,api,j=self.owner(status=0);m.validate_result(j,owner.c)
        v=public_base()
        v=m.public_result(j,owner.c,v);m.validate_public(v)
        self.assertEqual(v['status'],'failed');self.assertFalse(v['dns_isolation_qualified']);self.assertFalse(v['g_psec_tested'])

    def test_closed_journal_go_clock_inventory_and_resume_mutations_rejected(self):
        owner,api,j=self.owner()
        for mutate in (lambda x:x.update(extra=True),lambda x:x['go'][1]['fields'].update(opcode=7),
            lambda x:x['inventory_gates'][2].update(qpc=D),lambda x:x['tasks'][4].update(lpac=0),
            lambda x:x['tasks'][4].update(resume_qpc=T-1)):
            bad=copy.deepcopy(j);mutate(bad)
            with self.assertRaises((ValueError,TypeError)):m.validate_result(bad,owner.c)

    def test_acl_scope_is_only_four_owned_paths_and_inheritance(self):
        root=Path('/owned');self.assertEqual(m.expected_acl(root,root),[(0,0x1200a9)])
        self.assertEqual(m.expected_acl(root,root/'inputs'),[(3,0x1200a9)])
        self.assertEqual(m.expected_acl(root,root/'.github/private.py'),[])
        self.assertEqual(m.expected_acl(root,root/'health'),[])

    def test_default_entry_missing_inputs_never_instantiates_any_backend(self):
        with patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('must not spawn or instantiate')),patch.object(m.sys,'stdout',NS(buffer=io.BytesIO())):
            self.assertEqual(m.main([]),1)

    def test_api_error_zero_query_status_is_not_valid_success_or_unattempted(self):
        owner,api,j=self.owner(status=87)
        v=public_base()
        v=m.public_result(j,owner.c,v);m.validate_public(v)
        self.assertEqual(v['status'],'inconclusive');self.assertTrue(v['network_tested']);self.assertFalse(v['selected_api']['query_status_success_verified'])
        self.assertFalse(v['access_denial_observed']);self.assertFalse(v['selected_wire_query_observed'])

    def test_actual_cleanup_failure_keeps_sticky_wire_and_requires_resource_recovery(self):
        owner,api,bad=self.owner('fixture-cleanup',status=0)
        v=public_base()
        v=m.public_result(bad,owner.c,v);m.validate_public(v)
        self.assertEqual(v['status'],'failed');self.assertTrue(v['recovery_required']);self.assertFalse(v['observation_complete'])

    def test_stdio_close_uncertainty_attempts_other_handles_and_blocks_profile_removal(self):
        owner,api,j=self.owner('stdio-close');m.validate_result(j,owner.c)
        self.assertTrue(api.controls_uncertain);self.assertFalse(j['profile_deleted']);self.assertFalse(api.deleted)
        self.assertGreaterEqual(sum(h>10000 for h in api.closed),3)

    def test_public_observed_and_complete_require_commitments_network_and_typed_api5(self):
        # Reproduce the independent review's exact four-empty-commitment/no API probe.
        forged=m.blank('runtime');forged['checks']=dict.fromkeys(forged['checks'],True)
        forged.update(status='observed',observation_complete=True,access_denial_observed=True)
        with self.assertRaises(ValueError):m.validate_public(forged)
        owner,api,j=self.owner();valid=m.public_result(j,owner.c,public_base());m.validate_public(valid)
        for change in ({'selected_api':None},{'actor_sha256':None},{'manifest_sha256':None},{'source_sha256':None},
            {'recovery_plan_sha256':None},{'network_tested':False},{'tree_retained':False}):
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_public(copy.deepcopy(valid)|change)
        for key,bad in (('api_status',87),('answer_match',True),('record_count',1),('records_released',False),
            ('context_retained',True),('timely_verified',False),('within_deadline',False),('completed',False),('pending',True)):
            v=copy.deepcopy(valid);v['selected_api'][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(v)

    def test_complete_and_admitted_result_require_owned_profile_and_acl_intent(self):
        owner,api,j=self.owner()
        for key in ('profile_created','acl_attempted'):
            v=copy.deepcopy(j);v[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_result(v,owner.c)
        # Legitimate failure before profile/ACL work remains a valid partial result.
        owner,api,j=self.owner('unknowncreate');m.validate_result(j,owner.c)

    def test_selfconsistent_wrong_or_disabled_native_caps_cannot_replace_outer_catalog(self):
        owner,api,j=self.owner()
        for wrong_sid,attributes in ((False,0),(True,4),(True,0)):
            v=copy.deepcopy(j);row=next(x for x in v['tasks'] if x['name']=='selected')
            caps=copy.deepcopy(row['capabilities'])
            for entry in caps:entry['attributes']=attributes
            if wrong_sid:caps[0]['sid']='S-1-15-3-1024-9-8-7-6-5-4-3-2'
            row['capabilities']=caps
            for report in v['native']:
                if report['path'].startswith('selected/'):
                    value=m.decode(report['text'].encode('ascii'));value['identity']['tokenCapabilities']=caps
                    raw=m.encode(value);report.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            with self.subTest(wrong_sid=wrong_sid,attributes=attributes),self.assertRaises(ValueError):m.validate_result(v,owner.c)

    def test_native_phase_and_api_start_cannot_precede_the_actual_issued_go(self):
        owner,api,j=self.owner()
        for role,sequence,label in (('health',1,'before'),('selected',1,'selected'),('health',2,'after')):
            v=copy.deepcopy(j);issued=next(x['issued_qpc'] for x in v['go'] if x['label']==label)
            report=next(x for x in v['native'] if x['path']==role+'/phase-%04d.json'%sequence)
            value=m.decode(report['text'].encode('ascii'));value['phase_qpc'][0]=issued-1
            value['dns']['result'].update(start_qpc=issued-1,end_qpc=issued)
            raw=m.encode(value);report.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            with self.subTest(label=label),self.assertRaises(ValueError):m.validate_result(v,owner.c)

class ConstructorTests(unittest.TestCase):
    def test_actual_constructor_sets_exact_optout_two_caps_atomic_job_and_no_inherited_handles(self):
        seen={};freed=[];sidmem=[]
        class Func:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        def init(attrs,count,flags,size):C.cast(size,C.POINTER(C.c_size_t))[0]=256;return int(attrs is not None)
        def convert(text,out):
            buf=C.create_string_buffer(32);sidmem.append(buf);C.cast(out,C.POINTER(C.c_void_p))[0]=C.addressof(buf);seen.setdefault('sids',[]).append(text);return 1
        def update(attrs,flags,kind,value,size,*unused):
            if kind==m.ALL_APPLICATION_PACKAGES_POLICY:seen['policy']=C.cast(value,C.POINTER(C.c_uint32))[0];seen['policy_size']=size
            elif kind==m.SECURITY_CAPABILITIES:
                cap=C.cast(value,C.POINTER(proc._SecurityCapabilities)).contents;seen['cap_count']=cap.CapabilityCount
                entries=C.cast(cap.Capabilities,C.POINTER(m.launcher.SIDAndAttributes));seen['attrs']=[entries[i].Attributes for i in range(2)]
            elif kind==m.JOB_LIST:seen['job']=C.cast(value,C.POINTER(C.c_void_p))[0]
            seen.setdefault('keys',[]).append(kind);return 1
        def create(image,command,sa,ta,inherit,flags,env,cwd,startup,info):
            seen.update(inherit=inherit,flags=flags);p=C.cast(info,C.POINTER(proc._ProcessInfo)).contents;p.hProcess=11;p.hThread=12;p.dwProcessId=13;return 1
        api=m.LPACAPI.__new__(m.LPACAPI);api.proc=proc;api.controls_uncertain=False
        api.native=NS(check=lambda ok,label: m.require(ok,label))
        api.k=NS(InitializeProcThreadAttributeList=init,UpdateProcThreadAttribute=update,DeleteProcThreadAttributeList=lambda attrs:seen.update(deleted=True),
            CreateProcessW=create,LocalFree=lambda p:freed.append(p.value) or None)
        api.a=NS(ConvertStringSidToSidW=Func(convert));owners=m.helpers.OneShotHandles(lambda h:None);state={};info=proc._ProcessInfo()
        api.atomic_spawn(info,['fixed.exe'],'owned',77,owners,state,environment='SystemRoot=C:\\Windows\0\0',profile_pointer=55,catalog=CATALOG)
        self.assertEqual(seen['keys'],[m.JOB_LIST,m.SECURITY_CAPABILITIES,m.ALL_APPLICATION_PACKAGES_POLICY])
        self.assertEqual((seen['policy'],seen['policy_size'],seen['cap_count'],seen['attrs'],seen['job']),(1,4,2,[4,4],77))
        self.assertFalse(seen['inherit']);self.assertTrue(seen['deleted']);self.assertEqual(len(freed),2)
        self.assertTrue(state['creation_attempted']);self.assertEqual(set(owners.pending),{11,12})
        freed.clear();state={};owners=m.helpers.OneShotHandles(lambda h:None);api.controls_uncertain=False
        def badfree(p):freed.append(p.value);return p.value if len(freed)==1 else None
        api.k.LocalFree=badfree
        with self.assertRaises(ValueError):api.atomic_spawn(proc._ProcessInfo(),['fixed.exe'],'owned',77,owners,state,
            environment='SystemRoot=C:\\Windows\0\0',profile_pointer=55,catalog=CATALOG)
        self.assertEqual(len(freed),2);self.assertTrue(api.controls_uncertain);self.assertTrue(state['creation_attempted'])
        self.assertEqual(set(owners.pending),{11,12})
        api.k.UpdateProcThreadAttribute=lambda *args:0;api.k.CreateProcessW=lambda *args: self.fail('no fallback spawn')
        state={}
        with self.assertRaises(ValueError):api.atomic_spawn(proc._ProcessInfo(),['fixed.exe'],'owned',77,m.helpers.OneShotHandles(lambda h:None),state,
            environment='SystemRoot=C:\\Windows\0\0',profile_pointer=55,catalog=CATALOG)
        self.assertFalse(state.get('creation_attempted',False))

    def test_external_token46_uses_existing_exact_dword_parser_and_rejects_nonboolean(self):
        api=m.LPACAPI.__new__(m.LPACAPI);calls=[]
        api.native=NS(scalar=lambda token,kind,label:calls.append((token,kind,label)) or 1)
        self.assertEqual(api.lpac_flag(7),1);self.assertEqual(calls[0][1],46)
        api.native.scalar=lambda *args:2
        with self.assertRaises(ValueError):api.lpac_flag(7)

    def test_actual_existing_scalar_rejects_non_dword_lpactoken_response(self):
        native=m.launcher.NativeAPI.__new__(m.launcher.NativeAPI)
        def information(token,kind,value,size,returned):
            C.cast(value,C.POINTER(C.c_uint32))[0]=1;C.cast(returned,C.POINTER(C.c_uint32))[0]=8;return 1
        native.a=NS(GetTokenInformation=information);native.check=lambda ok,label:m.require(ok,label)
        api=m.LPACAPI.__new__(m.LPACAPI);api.native=native
        with self.assertRaises(m.launcher.GateFailure):api.lpac_flag(7)

    def test_worker_role_rejects_mixed_public_runtime_arguments_before_backend(self):
        with patch.object(m,'worker',side_effect=AssertionError('worker must not execute')):
            with self.assertRaises(ValueError):m.main(['--worker','config.json','--run-local-lpac-dns'])

    def test_plan_and_source_config_are_closed_bound_and_distinct_scope(self):
        c=config();m.config_validate(c)
        v=dict(schema_version=1,scope=m.SCOPE,device_sha256=H,source_sha256=c['source_sha256'],actor_sha256=c['actor_sha256'],manifest_sha256=H,
            standard53_impact_acknowledged=True,fresh_lpac_acl_profile_acknowledged=True,residue_review_acknowledged=True,recovery_reference='pure review')
        m.plan(v,device=H,source=c['source_sha256'],actor=c['actor_sha256'],manifest=H)
        for mutate in ({'scope':m.live.dns.PROFILE},{'fresh_lpac_acl_profile_acknowledged':False},{'extra':True}):
            with self.assertRaises(ValueError):m.plan(v|mutate,device=H,source=c['source_sha256'],actor=c['actor_sha256'],manifest=H)
        for mutate in ({'deadline_qpc':D+1},{'selected_case':c['before_case']},{'source_sha256':H}):
            with self.assertRaises(ValueError):m.config_validate(c|mutate)

if __name__=='__main__':unittest.main()
