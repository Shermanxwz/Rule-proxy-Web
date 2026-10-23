"""Inert API-shaped construction and actual coordinator; no Windows APIs."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('ipc_owner_tests',ROOT/'.github/windows_identity_lpac_pipe_origin.py')
b=load('ipc_old_api_fake',Path(__file__).with_name('test_windows_identity_lpac_dns_local.py'))
af=load('ipc_access_fake',Path(__file__).with_name('test_windows_identity_lpac_accesscheck.py'))
F,T,D=b.F,b.T,b.D
def config():
    c={k:v for k,v in b.config().items() if k not in (*b.m.NONCES,'capability_catalog')}
    c.update(scope=m.SCOPE,profile=m.PROFILE,run='1'*32,case='2'*32,origin_actor_sha256=m.sha(b'b'*512),origin_manifest_sha256=b.H)
    c['guard_job_name']='Local\\RuleProxy.LocalGuard.'+c['run'];c['source_hashes']=dict.fromkeys(m.SOURCES,b.H);c['source_sha256']=m.sha(m.encode(c['source_hashes']));return c

class Probe(af.FakeAPI):
    def __init__(self,parent):super().__init__();self.parent=parent
    def qpc(self):self.parent.now+=1;return self.parent.now
    def frequency(self):return F
    def verify_process(self,process,pid,creation):return not self.parent.wait(process,0) and pid==process and creation==self.parent.creation_time(process)
    def open_token(self,process,rights):self.process=process;self.role='lpac';self.fault=self.parent.probe_fault;return super().open_token(process,rights)
    def identity(self,token):
        self.identities+=1
        value=copy.deepcopy(self.parent.owner.tasks['lpac-pipe-front']['expected_primary'])
        if token==12:value.update(token_type=2,impersonation_level=1,token_id=value['token_id']+1)
        elif self.fault=='primary-changed-after' and self.identities>=3:value['token_id']+=1
        return value

def native_identity(row,c):
    i=row['identity'];return dict(schemaVersion=1,mode='actor',nonce=c['run'],pid=row['pid'],tokenUserSid=i['sid'],tokenIsAppContainer=i['appcontainer'],tokenAppContainerSid=i['appcontainer_sid'],tokenElevated=False,isProcessInJob=True,tokenCapabilities=[],queriesSucceeded=True,errors=[])
def mechanics(row,c,pair,now):
    front=row['role']=='lpac-pipe-front';mask=7 if front else 56
    return dict(schema_version=1,stage='bridge-pipe-test',role='pipe-front' if front else 'pipe-relay',run_id=c['run'],case_id=c['case'],pid=row['pid'],identity=native_identity(row,c),qpc=[F,pair['start'],pair['end'],now],
        pipe=dict(read_bytes=96 if front else 144,write_bytes=144 if front else 96,read_frames=2 if front else 3,write_frames=3 if front else 2,inheritance_cleared=True,eof_observed=True,reader_close='confirmed',writer_close='confirmed',requires_controller_timeout=True),
        core=dict(failure=0,observations=177 if front else 78,requested=mask,confirmed=mask,uncertain=0),synthetic_http=dict(request_checked=True,response_checked=True,client_sink_checked=front),failure=None,win32_error=None,network_tested=False,proxy_tested=False,product_acceptance=False)

class API(b.API):
    def __init__(self,root,fault=None,probe_fault=None):
        super().__init__(root,fault);self.probe_fault=probe_fault;self.labels={};self.resume_roles=[];self.pipe_handles=[];self.killed=False;self.native.query=self.statistics
    def process_id(self,h):return h
    def statistics(self,token,kind,label):
        assert kind==10;st=m.access.TOKEN_STATISTICS();st.TokenType=1;st.TokenId.LowPart=10000+token;st.AuthenticationId.LowPart=20
        return C.create_string_buffer(C.string_at(C.byref(st),C.sizeof(st))),C.sizeof(st)
    def identity(self,token):
        v=super().identity(token)
        if self.rows[token-2]['lpac']:v['capability_count']=0
        return v
    def groups(self,token,*args):return []
    def lpac_flag(self,token):raise AssertionError('class46 forbidden')
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def label_read(self,path):
        if self.fault=='label-readback' and path in self.labels and self.labels[path] is not None:raise OSError('unknown label readback')
        if self.fault=='label-restore' and getattr(self,'restoring',False):return m.zero.LOW_LABEL
        return self.labels.get(path)
    def label_set(self,path,value):
        if value is None:self.restoring=True
        self.labels[path]=value
    def access_api(self):return Probe(self)
    def atomic_spawn(self,info,argv,cwd,job,owners,state,**kw):
        super().atomic_spawn(info,argv,cwd,job,owners,state,**kw)
        if info.hProcess:
            info.dwThreadId=info.dwProcessId+2000
            if argv[1]=='origin-fixture':self.rows[info.hProcess]['role']='ordinary-origin-fixture'
    def allocate_pipe(self,owners,other_pending,sid,state,budget,end):
        state.update(attempted=True,returned=True,api_success=True,error=None,raw_outputs=None,unknown=False,adopted=False,readback=False,return_qpc=self.now)
        if self.fault=='pipe-false':state.update(api_success=False,error=5,raw_outputs=[0,0],unknown=True);raise OSError('indeterminate')
        self.next+=10;v=[self.next,self.next+1];state['raw_outputs']=v
        for h in v:owners.add(h)
        self.pipe_handles+=v;state.update(adopted=True,readback=True);return tuple(v)
    def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
        assert len(argv)==14 and tuple(int(x) for x in argv[5:7])==tuple(ends) and set(ends)<=set(pipe_pending)
        self.atomic_spawn(info,argv,cwd,job,owners,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=None)
        self.rows[info.hProcess]['role']='lpac-pipe-front' if profile_pointer else 'ordinary-pipe-relay';state.update(raw_return=1,raw_error=None,raw_pi=m.info_values(info),returned_qpc=self.now,creation_unknown=False);on_return(state.copy())
    def close(self,h):
        if h in self.pipe_handles and self.fault=='parent-close' and not hasattr(self,'close_fault'):self.close_fault=True;self.closed.append(h);raise OSError('close uncertain')
        return super().close(h)
    def resume(self,thread):
        h=thread-1;r=self.rows[h]
        if 'role' not in r:return super().resume(thread)
        role=r['role'];self.resume_roles.append(role);r['resumed']=True;c=self.owner.c
        if role=='ordinary-origin-fixture':
            v=dict(schema_version=1,stage='bridge-origin-ready',run_id=c['run'],case_id=c['case'],pid=h,port=54321,qpc_frequency=F,deadline_qpc=m.work_cutoff(c),loopback_ipv4=True)
            (self.root/m.REPORT_PATHS['ready']).write_bytes(m.encode(v));return
        assert self.owner.j['proof']['qualified'] and self.owner.pipes.confirmed_closed and len(self.owner.j['parent_pipe_close_attempts'])==4
        if role=='lpac-pipe-front':self.finish_reports()
    def finish_reports(self):
        c=self.owner.c;pair=self.owner.j['pair'];self.now+=20;req,res=m.origin.payloads(c['case'],54321)
        for role in m.ROLES:
            row=self.owner.tasks[role];r=self.rows[row['pid']];r.update(exited=True,exitcode=0)
            if role=='ordinary-origin-fixture':
                v=dict(schema_version=1,stage='bridge-origin-fixture',run_id=c['run'],case_id=c['case'],pid=row['pid'],identity=native_identity(row,c),qpc=[F,self.owner.j['origin_start']+1,m.work_cutoff(c),self.now],socket=dict(**dict.fromkeys(m.origin.FIXTURE_BOOLS,True),port=54321,peer_port=55000,request_bytes=len(req),response_bytes=len(res),listener_close='confirmed',connection_close='confirmed'),ready_published=True,failure=None,wsa_error=None,network_scope='ordinary-loopback-origin',network_tested=True,proxy_tested=False,product_acceptance=False)
                if self.fault=='tuple':v['socket']['peer_port']=55001
                if self.fault=='origin-late':r['exited']=False
                key='origin'
            elif role=='lpac-pipe-front':
                v=dict(schema_version=1,stage='lpac-ipc-origin-selected',role=role,run_id=c['run'],case_id=c['case'],pid=row['pid'],ipc_mechanics=mechanics(row,c,pair,self.now),admitted_qpc=row['resume_intent_qpc'],read_handle_inherit_cleared=True,write_handle_inherit_cleared=True,identity_basis='external-held-four-descriptor-required',network_tested=False,proxy_tested=False,product_acceptance=False);key='selected'
                if self.fault=='selected-malformed':v['extra']=1
                if self.fault=='retained-writer':v['ipc_mechanics']['pipe']['eof_observed']=False
            else:
                relay=dict(port=54321,**dict.fromkeys(m.origin.RELAY_BOOLS,True),local_port=55000,peer_port=54321,request_bytes=len(req),response_bytes=len(res),socket_close='confirmed',failure=None,wsa_error=None)
                v=dict(schema_version=1,stage='bridge-origin-pipe-test',role='pipe-relay',run_id=c['run'],case_id=c['case'],pid=row['pid'],ipc_mechanics=mechanics(row,c,pair,self.now),origin=relay,http_boundary=m.origin.BOUNDARY,network_tested=True,proxy_tested=False,product_acceptance=False);key='relay'
            (self.root/m.REPORT_PATHS[key]).write_bytes(m.encode(v))
    def wait(self,h,ms):
        if self.fault=='origin-late' and ms and self.rows[h].get('role')=='ordinary-origin-fixture':self.now=self.owner.j['pair']['end'];self.rows[h]['exited']=True
        return self.rows[h]['exited']
    def exit_code(self,h):return self.rows[h].get('exitcode',0)
    def terminate_job(self,job):self.killed=True;return super().terminate_job(job)

class CoordinatorTests(unittest.TestCase):
    def owner(self,fault=None,probe_fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for n in ('inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report'):(root/n).mkdir()
        for n in ('health','relay-report','origin-report'):(root/n/'temp').mkdir()
        (root/'inputs'/m.ACTOR).write_bytes(b'x'*512);(root/'inputs'/m.origin.ACTOR).write_bytes(b'b'*512)
        tool=root/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool')
        c=config();api=API(root,fault,probe_fault);o=m.Owner(root,c,b.PARENT,api,m.launcher.QpcBudget(api,D,F));api.owner=o;j=o.execute()
        m.validate_result(j,c,parent=b.PARENT,root=root);return o,api,j,m.project(j,c,parent=b.PARENT,root=root)
    def test_real_coordinator_positive_exact_mapping_proof_closes_and_scope(self):
        o,api,j,p=self.owner();self.assertIsNone(j['failure']);self.assertTrue(p['mechanism_verified']);self.assertTrue(p['semantic_lpac_verified'])
        self.assertEqual(api.resume_roles,list(reversed(m.ROLES)));self.assertEqual(len(j['pipe_allocations']),2);self.assertEqual(len(j['parent_pipe_close_attempts']),4)
        self.assertTrue(all(j[k] for k in m.CLEAN_KEYS));self.assertFalse(any(p[k] for k in m.FALSE_CLAIMS));self.assertFalse(api.killed)
    def test_failed_pipe_zero_outputs_unknown_never_deletes_profile(self):
        o,api,j,p=self.owner('pipe-false');self.assertTrue(j['pipe_allocation_unknown']);self.assertFalse(j['profile_deleted']);self.assertFalse(p['mechanism_verified']);self.assertEqual(len(j['pipe_allocations']),1)
    def test_all_parent_ends_attempted_even_one_uncertain_no_pair_resume(self):
        o,api,j,p=self.owner('parent-close');self.assertEqual(len(j['parent_pipe_close_attempts']),4);self.assertEqual(api.resume_roles,['ordinary-origin-fixture']);self.assertFalse(j['profile_deleted'])
    def test_tuple_or_eof_failure_never_qualifies(self):
        for fault in ('tuple','retained-writer'):
            with self.subTest(fault=fault):o,api,j,p=self.owner(fault);self.assertFalse(p['mechanism_verified']);self.assertTrue(p['origin_accepted_observed'])
    def test_bad_selected_report_keeps_independent_origin_and_relay_facts(self):
        o,api,j,p=self.owner('selected-malformed');self.assertEqual(p['native_report_status']['selected'],'invalid');self.assertTrue(p['origin_response_observed'] and p['relay_connect_observed']);self.assertFalse(p['mechanism_verified'])
    def test_final_origin_wait_return_after_original_pair_end_not_success(self):
        o,api,j,p=self.owner('origin-late');self.assertFalse(j['natural_exits']);self.assertFalse(p['mechanism_verified']);self.assertEqual(o.j['pair']['end'],api.now)
    def test_unknown_label_or_observer_cleanup_prevents_resume_and_profile_delete(self):
        for fault,probe in (('label-readback',None),('label-restore',None),(None,'close-raise')):
            with self.subTest(fault=fault,probe=probe):
                o,api,j,p=self.owner(fault,probe);self.assertFalse(j['profile_deleted']);self.assertFalse(p['mechanism_verified'])
    def test_physical_create_receipt_or_native_tamper_rejected(self):
        o,api,j,p=self.owner();(o.root/'returns/lpac-pipe-front.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):m.validate_result(j,o.c,parent=b.PARENT,root=o.root)
    def test_external_identity_and_proof_failures_stop_both_pair_resumes(self):
        for fault,probe in (('sid',None),('medium',None),('outerjob',None),(None,'wrong-mask'),(None,'primary-changed-after')):
            with self.subTest(fault=fault,probe=probe):
                o,api,j,p=self.owner(fault,probe);self.assertFalse(p['mechanism_verified']);self.assertEqual(api.resume_roles,['ordinary-origin-fixture'])
    def test_physical_closed_direction_and_resume_epoch_cannot_be_reinterpreted(self):
        o,api,j,p=self.owner()
        for change in ('ends','early-proof','image'):
            v=copy.deepcopy(j);r=next(r for r in v['tasks'] if r['role']=='lpac-pipe-front')
            if change=='ends':r['ends'].reverse()
            elif change=='early-proof':v['proof']['start_qpc']=T
            else:r['image_sha256']='f'*64
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_result(v,o.c,parent=b.PARENT,root=o.root)
    def test_complete_evidence_requires_owned_profile_label_tools_raw_pid_and_causal_clocks(self):
        o,api,j,p=self.owner()
        for change in ('profile','label','receipt','raw-pid','relay-final','completion','remove','grants','late-resume','exit-clock','pipe-receipt','pipe-clock','admission-clock'):
            v=copy.deepcopy(j);restores=[];front=next(r for r in v['tasks'] if r['role']=='lpac-pipe-front')
            if change=='profile':v['profile_state']['created']=False
            elif change=='label':v['labels']=[]
            elif change=='receipt':front['receipt']=None
            elif change=='raw-pid':
                r=front['receipt'];value=m.decode(r['text'].encode('ascii'));value['pi'][2]+=100;raw=m.encode(value);path=o.root/'returns'/r['name'];restores.append((path,path.read_bytes()));path.write_bytes(raw);r.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            elif change=='relay-final':
                r=v['reports']['relay'];value=m.decode(r['text'].encode('ascii'));value['ipc_mechanics']['qpc'][3]=v['pair']['start'];raw=m.encode(value);path=o.root/m.REPORT_PATHS['relay'];restores.append((path,path.read_bytes()));path.write_bytes(raw);r.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            elif change=='completion':v['completion_qpc']=v['pair']['start']
            elif change=='remove':v['cleanup_tasks']=[]
            elif change=='grants':v['tasks']=[r for r in v['tasks'] if r['role'] in m.ROLES]
            elif change=='late-resume':front['resume_qpc']=v['pair']['end']+1
            elif change=='exit-clock':front['exit_observed_qpc']=v['completion_qpc']+1
            elif change=='pipe-receipt':v['pipe_allocations'][0]['receipt']=None
            elif change=='pipe-clock':v['pipe_allocations'][0]['return_qpc']=v['pair']['end']+1
            else:front['admission_qpc']=v['pair']['start']-1
            try:
                with self.subTest(change=change),self.assertRaises(ValueError):m.validate_result(v,o.c,parent=b.PARENT,root=o.root)
            finally:
                for path,raw in restores:path.write_bytes(raw)
    def test_native_final_after_own_held_exit_observation_cannot_qualify(self):
        o,api,j,p=self.owner()
        for key,role in (('selected','lpac-pipe-front'),('relay','ordinary-pipe-relay'),('origin','ordinary-origin-fixture')):
            v=copy.deepcopy(j);row=next(r for r in v['tasks'] if r['role']==role);r=v['reports'][key];value=m.decode(r['text'].encode('ascii'))
            q=value['qpc'] if key=='origin' else value['ipc_mechanics']['qpc'];q[3]=row['exit_observed_qpc']+1;v['completion_qpc']=q[3]+1
            raw=m.encode(value);path=o.root/m.REPORT_PATHS[key];original=path.read_bytes();path.write_bytes(raw);r.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            try:
                with self.subTest(role=role),self.assertRaises(ValueError):m.validate_result(v,o.c,parent=b.PARENT,root=o.root)
            finally:path.write_bytes(original)

class Function:
    def __init__(self,fn):self.fn=fn
    def __call__(self,*a):return self.fn(*a)

class ConstructorTests(unittest.TestCase):
    def setUp(self):
        state=[0];self.error=state
        for name,fn in (('get_last_error',lambda:state[0]),('set_last_error',lambda value:state.__setitem__(0,value))):
            p=patch.object(C,name,fn,create=True);p.start();self.addCleanup(p.stop)
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
        argv=[m.ACTOR if selected else m.origin.ACTOR,'pipe-front' if selected else 'pipe-relay']
        exc=None
        try:api.pair_spawn(info,argv,Path('.'),'SystemRoot=x\0LOCALAPPDATA=y\0\0' if selected else 'SystemRoot=x\0\0',91,owners,state,ends=(101,102),pipe_pending={101,102},profile_pointer=77 if selected else None,budget=budget,end=T+10000,on_return=returned)
        except BaseException as e:exc=e
        return api,info,state,owners,calls,attrs,received,exc
    def test_api_shaped_exact_attributes_raw_receipt_precedes_adoption(self):
        for selected in (True,False):
            api,info,state,owners,calls,attrs,received,exc=self.constructor(selected);self.assertIsNone(exc);self.assertEqual(owners.pending,{701,702});self.assertEqual(received[0]['raw_pi'],[701,702,703,704])
            self.assertEqual([x[0] for x in attrs],[m.base.JOB_LIST,0x20002]+([m.base.SECURITY_CAPABILITIES,m.base.ALL_APPLICATION_PACKAGES_POLICY] if selected else []));self.assertEqual(attrs[1][1:],(16,[101,102]));self.assertTrue(calls[2][1]);self.assertEqual(calls[-1][0],'delete')
            if selected:self.assertEqual(attrs[2][2],[77,None,0,0]);self.assertEqual(attrs[3][1:],(4,1))
    def test_false_garbage_exception_partial_outputs_never_adopted(self):
        for shape in ('false-garbage','exception','partial','error0'):
            with self.subTest(shape=shape):
                api,info,state,owners,*rest=self.constructor(shape=shape);self.assertFalse(owners.pending);self.assertEqual(m.info_values(info),[0]*4);self.assertTrue(state['creation_unknown']);self.assertIsNotNone(rest[-1])
    def test_known_false_empty_is_nochild_but_success_late_retains_handles(self):
        api,info,state,owners,*rest=self.constructor(shape='false-zero');self.assertFalse(state['creation_unknown']);self.assertFalse(owners.pending)
        api,info,state,owners,*rest=self.constructor(late=True);self.assertEqual(owners.pending,{701,702});self.assertFalse(state['creation_unknown']);self.assertIsNotNone(rest[-1])
    def test_receipt_failure_keeps_successful_cleanup_authority_no_admission(self):
        api,info,state,owners,*rest=self.constructor(receipt_fail=True);self.assertEqual(owners.pending,{701,702});self.assertTrue(api.controls_uncertain);self.assertIsNotNone(rest[-1])
    def test_createpipe_failed_outputs_never_adopted_closed_or_retried(self):
        for outputs,throws in (([0,0],False),([991,992],False),([991,992],True)):
            with self.subTest(outputs=outputs,throws=throws):
                api=m.API.__new__(m.API);api.controls_uncertain=False;api.pipe_descriptor=lambda sid:(77,'D:');calls=[];freed=[]
                def create(rd,wr,sa,n):
                    calls.append(1);C.cast(rd,C.POINTER(C.c_void_p))[0]=outputs[0];C.cast(wr,C.POINTER(C.c_void_p))[0]=outputs[1]
                    if throws:raise OSError('unknown allocation')
                    self.error[0]=5;return 0
                api.k=NS(CreatePipe=create,LocalFree=lambda p:freed.append(p) or 0);state={};closed=[];owners=m.helpers.OneShotHandles(closed.append);budget=m.launcher.QpcBudget(NS(qpc=lambda:T+1,qpc_frequency=lambda:F),T+10000,F)
                with self.assertRaises(BaseException):api.allocate_pipe(owners,set(),b.SID,state,budget,T+10000)
                self.assertTrue(state['unknown']);self.assertFalse(owners.pending);self.assertFalse(closed);self.assertEqual(calls,[1]);self.assertEqual(freed,[77])
    def test_filetype_uses_pointer_width_prototype(self):
        api=m.API.__new__(m.API);seen=[];fn=Function(lambda h:seen.append(h) or 3);api.k=NS(GetFileType=fn);self.assertEqual(api.pipe_type(0x100000001),3);self.assertEqual(fn.argtypes,[C.c_void_p]);self.assertEqual(seen,[0x100000001])
    def test_descriptor_failed_outputs_are_not_dereferenced_or_freed(self):
        for stage in ('create','get','text','exception'):
            with self.subTest(stage=stage):
                api=m.API.__new__(m.API);api.controls_uncertain=False;freed=[];api.k=NS(LocalFree=lambda p:freed.append(p) or 0)
                def create(text,revision,out,size):C.cast(out,C.POINTER(C.c_void_p))[0]=991;return 0
                def get(h,kind,flags,o,g,d,s,out):
                    C.cast(out,C.POINTER(C.c_void_p))[0]=992
                    if stage=='exception':raise OSError('unknown')
                    return 5 if stage=='get' else 0
                def convert(sd,revision,flags,out,size):C.cast(out,C.POINTER(C.c_void_p))[0]=993;return 0
                api.a=NS(ConvertStringSecurityDescriptorToSecurityDescriptorW=Function(create),GetSecurityInfo=Function(get),ConvertSecurityDescriptorToStringSecurityDescriptorW=Function(convert))
                with self.assertRaises(BaseException):api.pipe_descriptor(b.SID) if stage=='create' else api.pipe_sddl(11)
                self.assertTrue(api.controls_uncertain);self.assertEqual(freed,[992] if stage=='text' else [])
    def test_descriptor_success_alias_is_not_dereferenced_or_double_freed(self):
        api=m.API.__new__(m.API);api.controls_uncertain=False;freed=[];api.k=NS(LocalFree=lambda p:freed.append(p) or 0)
        def get(h,kind,flags,o,g,d,s,out):C.cast(out,C.POINTER(C.c_void_p))[0]=992;return 0
        def text(sd,revision,flags,out,size):C.cast(out,C.POINTER(C.c_void_p))[0]=992;return 1
        api.a=NS(GetSecurityInfo=Function(get),ConvertSecurityDescriptorToStringSecurityDescriptorW=Function(text))
        with self.assertRaises(ValueError):api.pipe_sddl(11)
        self.assertEqual(freed,[992]);self.assertTrue(api.controls_uncertain)
    def test_third_missing_aliased_handle_list_is_not_inheritance_authority(self):
        for value in ((1,), (1,2,3),(1,1),(1,999)):
            with self.subTest(value=value),self.assertRaises(ValueError):m.handle_list(value,{1,2})

if __name__=='__main__':unittest.main()
