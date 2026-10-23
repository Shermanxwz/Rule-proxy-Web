"""Injected Python/ctypes buffers only: no actors, sockets, token or ACL APIs."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('zero_cap_core_tests',ROOT/'.github/windows_identity_lpac_loopback.py')
b=load('zero_cap_old_fake',Path(__file__).with_name('test_windows_identity_lpac_dns_local.py'))
af=load('zero_cap_access_fake',Path(__file__).with_name('test_windows_identity_lpac_accesscheck.py'))
F,T,D=b.F,b.T,b.D

def config():
    c={k:v for k,v in b.config().items() if k not in (*b.m.NONCES,'capability_catalog')}
    c.update(scope=m.SCOPE,profile=m.PROFILE,**{n:'%032x'%(i+1) for i,n in enumerate(m.NONCES)},ports=dict(frontend=49153,ordinary=49154))
    c['source_hashes']=dict.fromkeys(m.SOURCES,b.H);c['source_sha256']=m.sha(m.encode(c['source_hashes']));return c

class Probe(af.FakeAPI):
    def __init__(self,parent):super().__init__();self.parent=parent;self.process=None
    def qpc(self):self.parent.now+=1;return self.parent.now
    def frequency(self):return F
    def verify_process(self,process,pid,creation):return not self.parent.wait(process,0) and pid==process and creation==self.parent.creation_time(process)
    def open_token(self,process,rights):
        self.process=process;self.role=m.SEMANTICS[self.parent.rows[process]['role']];self.fault=self.parent.probe_fault
        return super().open_token(process,rights)
    def identity(self,token):
        value=copy.deepcopy(self.parent.owner.tasks[self.parent.rows[self.process]['role']]['expected_primary'])
        if token==12:value.update(token_type=2,impersonation_level=1,token_id=value['token_id']+1)
        return value

def common(row,c,kind):
    return dict(schema_version=1,stage=m.REPORT_STAGES[kind],role=row['role'],run_id=c['run'],boot_case_id=c[m.BOOT_KEYS[row['role']]],
        pid=row['pid'],token=m.native_token(row['expected_primary']),root_qpc=[F,T,c['root_deadline_qpc']])

def ready(row,c,now):
    listener=row['role'].endswith('listener');v=common(row,c,'ready')
    v.update(ready_qpc=now,ports=c['ports'],case_ids=dict(before=c['before_case'],selected=c['selected_case'],after=c['after_case']),listener=listener,
        port=c['ports']['frontend' if row['role']=='front-listener' else 'ordinary'] if listener else None,socket_held=listener,wsa_started=listener,
        token_close_confirmed=True,failure=None,network_tested=False,product_acceptance=False);return v

def phase(row,c,seq,end,now):
    v=common(row,c,'phase');v.update(sequence=seq,case_id=c['selected_case'] if row['role']=='selected-client' else c['before_case'] if seq==1 else c['after_case'],
        phase_deadline_qpc=end,flow_qpc=[now,now+1],target_port=c['ports']['frontend' if row['role']=='selected-client' else 'ordinary'],local_port=50000+seq,
        connect_attempted=True,connect_completed=True,send_attempted=True,request_bytes=64,request_exact=True,send_shutdown=True,response_bytes=64,response_exact=True,
        response_eof=True,socket_close='confirmed',wsa_cleanup='confirmed',within_deadline=True,failure=None,wsa_error=None,win32_error=None,
        control_close_verified=True,network_tested=True,product_acceptance=False);return v

def receipt(row,c,seq,end,now,held=False):
    front=row['role']=='front-listener';v=common(row,c,'received' if held else 'receipt')
    v.update(index=seq,case_id=c['selected_case'] if front else c['before_case'] if seq==1 else c['after_case'],phase_deadline_qpc=end,
        flow_qpc=[now,now+1,now+2],port=c['ports']['frontend' if front else 'ordinary'],peer_port=50000+seq,request_bytes=64,request_exact=True,request_eof=True,
        response_bytes=0 if held else 64,response_complete=not held,send_shutdown=not held,response_withheld=front,socket_held=held,
        connection_close='held' if held else 'confirmed',release_verified=front and not held,release_qpc=now+1 if front and not held else 0,
        within_deadline=True,failure=None,wsa_error=None,win32_error=None,control_close_verified=True,network_tested=True,product_acceptance=False);return v

def final(row,c,now,failure=None):
    listener=row['role'].endswith('listener');count=1 if row['role'] in m.SEMANTICS else 2;v=common(row,c,'final')
    v.update(flow_qpc=[T+1,now],ports=c['ports'],case_ids=dict(before=c['before_case'],selected=c['selected_case'],after=c['after_case']),
        listening_verified=listener and failure is None,listen_port=c['ports']['frontend' if row['role']=='front-listener' else 'ordinary'] if listener and failure is None else None,
        listen_close='confirmed' if listener else 'not-created',wsa_started=True,wsa_cleanup='confirmed',token_close_confirmed=True,control_close_verified=True,
        socket_resources_closed=True,accepted_count=count if listener and failure is None else 0,receipt_count=count if listener and failure is None else 0,
        phase_count=0 if listener else count,within_deadline=True,failure=failure,wsa_error=10013 if failure else None,win32_error=None,
        network_tested=failure is None,product_acceptance=False);return v

def tcp_raw(rows):
    out=bytearray(struct.pack('<I',len(rows)))
    port=lambda v:int.from_bytes(v.to_bytes(2,'big')+bytes(2),'little')
    for state,pid,lp,rp,la,ra in rows:out+=struct.pack('<6I',state,int.from_bytes(bytes.fromhex(la),'little'),port(lp),int.from_bytes(bytes.fromhex(ra),'little'),port(rp),pid)
    return bytes(out)

class API(b.API):
    def __init__(self,root,fault=None,probe_fault=None):
        super().__init__(root,fault);self.probe_fault=probe_fault;self.native.query=self.statistics;self.labels={};self.done=set();self.resume_roles=[];self.killed=False
    def process_id(self,h):return h
    def statistics(self,token,kind,label):
        assert kind==10;st=m.access.TOKEN_STATISTICS();st.TokenType=1;st.TokenId.LowPart=10000+token;st.AuthenticationId.LowPart=20
        return C.create_string_buffer(C.string_at(C.byref(st),C.sizeof(st))),C.sizeof(st)
    def atomic_spawn(self,info,argv,cwd,job,owners,state,**kw):
        super().atomic_spawn(info,argv,cwd,job,owners,state,**kw)
        if info.hProcess and len(argv)==15:self.rows[info.hProcess]['role']=argv[1]
    def create_zero_suspended(self,info,argv,cwd,environment,job,owners,state,*,profile_pointer,policy,budget,cutoff):
        assert policy==m.POLICIES[argv[1]]
        try:self.atomic_spawn(info,argv,cwd,job,owners,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=None)
        finally:state['returned_qpc']=self.now if state['create_status'] in ('returned_false','returned_true') else None
    def identity(self,token):
        v=super().identity(token)
        if self.rows[token-2]['lpac']:v['capability_count']=0
        return v
    def groups(self,token,*args):return []
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def label_read(self,path):
        if self.fault=='label-readback' and path.name=='front-report' and path in self.labels:raise OSError('unknown label readback')
        if self.fault=='label-restore' and getattr(self,'restoring',False) and path.name=='front-report':return m.LOW_LABEL
        return self.labels.get(path)
    def label_set(self,path,value):
        if value is None:self.restoring=True
        self.labels[path]=value
    def access_api(self):return Probe(self)
    def lpac_flag(self,token):raise AssertionError('class46 forbidden')
    def write(self,role,name,value):(self.root/m.ACTOR_DIRS[role][0]/name).write_bytes(m.encode(value))
    def resume(self,thread):
        h=thread-1;r=self.rows[h]
        if 'role' not in r:return super().resume(thread)
        role=r['role'];self.resume_roles.append(role);self.events.append(('resume-role',role));row=self.owner.tasks[role];c=self.owner.c
        assert len(self.owner.j['proofs'])==2 and all(p['qualified'] for p in self.owner.j['proofs'])
        if role=='front-listener' and self.fault=='front10013':self.write(role,'final.json',final(row,c,self.now,'bind'));r.update(exited=True,exitcode=5)
        else:self.write(role,'ready.json',ready(row,c,self.now))
    def advance(self):
        if not hasattr(self,'owner'):return
        c=self.owner.c
        for server,client,seq in (('ordinary-listener','ordinary-client',1),('front-listener','selected-client',1),('ordinary-listener','ordinary-client',2)):
            key=(server,seq);paths=[self.root/m.ACTOR_DIRS[r][1]/('phase-%02d.bin'%seq) for r in (server,client)]
            if not all(p.exists() for p in paths) or key in self.done:continue
            end=struct.unpack_from('<Q',paths[0].read_bytes(),80)[0];self.now+=5
            if server=='front-listener':
                r=self.owner.tasks[server];received=receipt(r,c,1,end,self.now,True)
                if self.fault=='withheld-response':received['response_bytes']=1
                received_path=self.root/m.ACTOR_DIRS[server][0]/'received.json'
                if not received_path.exists():self.write(server,'received.json',received)
                if self.fault=='main-timeout':self.done.add(key);self.now=end;return
                if not (self.root/m.ACTOR_DIRS[server][1]/'release.bin').exists():continue
            self.write(server,'receipt-%02d.json'%seq,receipt(self.owner.tasks[server],c,seq,end,self.now))
            self.write(client,'phase-%02d.json'%seq,phase(self.owner.tasks[client],c,seq,end,self.now));self.done.add(key)
            if server=='front-listener' or seq==2:
                for role in (server,client):
                    self.write(role,'final.json',final(self.owner.tasks[role],c,self.now));self.rows[self.owner.tasks[role]['pid']].update(exited=True,exitcode=0)
    def wait(self,h,ms):
        self.advance()
        if ms and not self.rows[h]['exited']:self.now+=min(ms,10)
        return self.rows[h]['exited']
    def exit_code(self,h):return self.rows[h].get('exitcode',0)
    def terminate_job(self,job):self.killed=True;return super().terminate_job(job)
    def tcp_snapshot(self,budget,cutoff):
        self.advance();p=self.owner.c['ports']['frontend'];front=self.owner.tasks['front-listener']['pid'];selected=self.owner.tasks['selected-client']['pid'];L='7f000001'
        rows=[(2,front,p,0,L,'00000000')]
        if (self.root/'front-report/received.json').exists():rows += [(6,selected,50001,p,L,L),(8,front,p,50001,L,L)]
        if self.fault=='wrong-tcp-pid':rows[0]=(2,front+1,p,0,L,'00000000')
        return tcp_raw(rows)

class CoreTests(unittest.TestCase):
    def owner(self,fault=None,probe_fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('inputs','tools','guard',*(p for pair in m.ACTOR_DIRS.values() for p in pair)):(root/name).mkdir()
        for name in ('origin-report','ordinary-report'):(root/name/'temp').mkdir()
        (root/'inputs'/m.ACTOR).write_bytes(b'x'*512);tool=root/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool')
        c=config();api=API(root,fault,probe_fault);owner=m.Owner(root,c,b.PARENT,api,m.launcher.QpcBudget(api,D,F));api.owner=owner
        j=owner.execute();m.validate_result(j,c,parent=b.PARENT,root=root);return owner,api,j,m.project(j,c,parent=b.PARENT,root=root)
    def test_real_owner_full_shape_all_roles_matched_zero_caps_complete_flow(self):
        owner,api,j,p=self.owner();self.assertIsNone(j['failure']);self.assertTrue(p['reachability_verified'])
        self.assertEqual(p['ac_granted_access'],[3,0,1,2]);self.assertEqual(p['lpac_granted_access'],[2,0,0,2])
        self.assertEqual(api.resume_roles,['ordinary-listener','ordinary-client','front-listener','selected-client'])
        self.assertTrue(j['main_request_observed'] and j['main_connect_observed']);self.assertEqual(len(j['go']),7)
        self.assertTrue(all(j[k] for k in m.CLEAN_KEYS));self.assertFalse(any(p[k] for k in m.FALSE_CLAIMS));self.assertEqual(owner.budget.deadline,D)
    def test_front_explicit_10013_harvests_final_and_never_resumes_selected_then_after(self):
        _,api,j,p=self.owner('front10013');self.assertEqual(j['failure'],'loopback');self.assertNotIn('selected-client',api.resume_roles)
        self.assertTrue(j['ordinary_before'] and j['ordinary_after']);self.assertFalse(p['reachability_verified'])
        raw=[r['value'] for r in j['native'] if r['role']=='front-listener' and r['kind']=='final'][0]
        self.assertEqual((raw['failure'],raw['wsa_error']),('bind',10013));self.assertFalse(raw['network_tested'])
        self.assertTrue(all(j[k] for k in m.CLEAN_KEYS))
    def test_matrix_mismatch_and_unknown_observer_prevent_all_actor_resume(self):
        for fault in ('wrong-mask','open-unknown','close-false'):
            with self.subTest(fault=fault):
                _,api,j,p=self.owner(probe_fault=fault);self.assertEqual(api.resume_roles,[]);self.assertFalse(p['reachability_verified'])
                if fault!='wrong-mask':self.assertFalse(j['observer_resources_cleanup_verified']);self.assertFalse(api.deleted)
    def test_label_readback_and_restoration_failure_never_delete_profile(self):
        for fault in ('label-readback','label-restore'):
            with self.subTest(fault=fault):
                _,api,j,p=self.owner(fault);self.assertFalse(j['labels_restored']);self.assertFalse(api.deleted);self.assertFalse(p['reachability_verified'])
    def test_wrong_tcp_or_early_response_never_release(self):
        for fault in ('wrong-tcp-pid','withheld-response'):
            with self.subTest(fault=fault):
                _,_,j,p=self.owner(fault);self.assertFalse(j['release_published']);self.assertFalse(any(g['release'] for g in j['go']));self.assertFalse(p['reachability_verified'])
    def test_main_timeout_keeps_original_deadline_and_after_is_best_effort_only(self):
        owner,_,j,p=self.owner('main-timeout');self.assertEqual(j['failure'],'loopback');self.assertFalse(j['release_published'])
        self.assertFalse(p['reachability_verified']);self.assertEqual(owner.budget.deadline,D);self.assertTrue(j['ordinary_after'])
    def test_real_label_adapter_queries_only_label_consumes_free_once_and_preserves_unknown(self):
        api=m.API.__new__(m.API);api.controls_uncertain=False;held=C.create_string_buffer(m.LOW_LABEL);calls=[]
        def get(path,kind,security,owner,group,dacl,sacl,sd):
            self.assertEqual((kind,security,owner,group,dacl),(1,16,None,None,None));sacl._obj.value=C.addressof(held);sd._obj.value=55;return 0
        def set_label(path,kind,security,owner,group,dacl,sacl):
            self.assertEqual((kind,security,owner,group,dacl),(1,16,None,None,None));head=C.string_at(sacl,8);size=struct.unpack_from('<H',head,2)[0]
            calls.append(C.string_at(sacl,size));return 0
        class Fn:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        freed=[];api.a=NS(GetNamedSecurityInfoW=Fn(get),SetNamedSecurityInfoW=Fn(set_label));api.k=NS(LocalFree=lambda p:freed.append(p) or 0)
        self.assertEqual(api.label_read(Path('fresh')),m.LOW_LABEL);self.assertEqual(freed,[55])
        api.label_set(Path('fresh'),m.LOW_LABEL);api.label_set(Path('fresh'),None);self.assertEqual(calls,[m.LOW_LABEL,m.EMPTY_LABEL])
        api.k.LocalFree=lambda p:1
        with self.assertRaises(ValueError):api.label_read(Path('fresh'))
        self.assertTrue(api.controls_uncertain)
    def test_root_physical_go_report_intent_tamper_rejected(self):
        owner,_,j,_=self.owner()
        for path in (owner.root/'front-control/phase-01.bin',owner.root/'selected-report/phase-01.json',owner.root/'tcp-observations/withheld.bin',owner.root/'journal'/j['intents'][0]['name']):
            raw=path.read_bytes();path.write_bytes(raw+b'x')
            with self.assertRaises(ValueError):m.validate_result(j,owner.c,parent=b.PARENT,root=owner.root)
            path.write_bytes(raw)
        for change in (lambda x:x['tcp'][1]['value']['client'].update(state=5),lambda x:x['tcp'][0].update(raw_sha256='0'*64)):
            bad=copy.deepcopy(j);change(bad)
            with self.assertRaises(ValueError):m.validate_result(bad,owner.c,parent=b.PARENT,root=owner.root)
    def test_selected_and_ordinary_closed_phase_cannot_predate_its_go(self):
        owner,_,j,_=self.owner()
        for role in ('selected-client','ordinary-client'):
            value=copy.deepcopy(j);row=next(r for r in value['native'] if r['role']==role and r['kind']=='phase' and r['sequence']==1)
            go=next(g for g in value['go'] if g['role']==role and not g['release'] and g['sequence']==1)
            row['value']['flow_qpc']=[go['issued']-2,go['issued']-1];raw=m.encode(row['value']);row.update(text=raw.decode('ascii'),sha256=m.sha(raw))
            path=owner.root/m.ACTOR_DIRS[role][0]/row['name'];original=path.read_bytes();path.write_bytes(raw)
            try:
                with self.assertRaises(ValueError):m.validate_result(value,owner.c,parent=b.PARENT,root=owner.root)
            finally:path.write_bytes(original)
    def test_main_response_requires_release_and_received_clock_causality(self):
        owner,_,j,_=self.owner();release=next(g for g in j['go'] if g['release'])
        def release_backdated(value):value['release_qpc']=release['issued']-1
        def response_before_release(value):
            go=next(g for g in j['go'] if g['role']=='selected-client' and not g['release'])
            value['flow_qpc']=[go['issued']+1,release['issued']-1]
        def withheld_after_response(value):
            receipt=next(r['value'] for r in j['native'] if r['role']=='front-listener' and r['kind']=='receipt')
            value['flow_qpc']=[value['flow_qpc'][0],receipt['flow_qpc'][1]+1,receipt['flow_qpc'][-1]+1]
        for kind,role,change in (('receipt','front-listener',release_backdated),('phase','selected-client',response_before_release),('received','front-listener',withheld_after_response)):
            value=copy.deepcopy(j);row=next(r for r in value['native'] if r['kind']==kind and r['role']==role);change(row['value'])
            raw=m.encode(row['value']);row.update(text=raw.decode('ascii'),sha256=m.sha(raw));path=owner.root/m.ACTOR_DIRS[role][0]/row['name'];original=path.read_bytes();path.write_bytes(raw)
            try:
                with self.assertRaises(ValueError):m.validate_result(value,owner.c,parent=b.PARENT,root=owner.root)
            finally:path.write_bytes(original)
    def test_closed_report_read_retries_only_sharing_violation_with_original_budget(self):
        original=m.base.contracts.live.local.bounded;calls=[]
        def read(path,limit):
            if Path(path).name=='ready.json' and not calls:
                calls.append(Path(path));error=OSError('pure sharing');error.winerror=32;raise error
            return original(path,limit)
        with patch.object(m.base.contracts.live.local,'bounded',side_effect=read):owner,_,j,p=self.owner()
        self.assertEqual(len(calls),1);self.assertTrue(p['reachability_verified']);self.assertEqual(owner.budget.deadline,D)
    def test_native_nullable_failure_and_late_positive_remain_typed_never_qualify(self):
        owner,_,j,_=self.owner();row=owner.tasks['selected-client'];v=phase(row,owner.c,1,T+500,T+100)
        v.update(flow_qpc=[T+100,T+501],within_deadline=False,failure='deadline')
        m.validate_native(v,'phase',row,owner.c,sequence=1,case=owner.c['selected_case'],end=T+500)
        self.assertTrue(v['connect_completed']);self.assertFalse(m.phase_passed(v))
        v=final(owner.tasks['front-listener'],owner.c,T+100,'bind');v['token']=None;v['failure']='deadline'
        m.validate_native(v,'final',owner.tasks['front-listener'],owner.c);self.assertFalse(m.final_passed(v))
    def test_closed_result_rejects_laundered_matrix_go_identity_cleanup_or_claim(self):
        owner,_,j,_=self.owner()
        for mutate in (lambda x:x.update(product_acceptance=True),lambda x:x.update(labels_restored=False),lambda x:x.update(main_tuple_verified=False),
                lambda x:x['tasks'][-1]['expected_primary'].update(capabilities=[dict(sid=m.live.PNCS,attributes=4)]),
                lambda x:x['go'][-1].update(end=x['go'][-1]['end']+1),lambda x:x['proofs'][1]['calls'][0].update(granted_access=3)):
            v=copy.deepcopy(j);mutate(v)
            with self.assertRaises(ValueError):m.validate_result(v,owner.c,parent=b.PARENT)
    def test_control_packet_canonical_exact_fields_and_no_deadline_renewal(self):
        c=config();raw=m.control(c,'front-listener',1,c['selected_case'],T+1,T+8001)
        self.assertEqual(len(raw),128);self.assertEqual(raw[:4],b'ZCL1');self.assertEqual(raw[104:],bytes(24));self.assertEqual(len(m.packet(c,c['selected_case'])),64)
        for args in (('selected-client',1,c['before_case'],T+1,T+100),('front-listener',1,c['selected_case'],T+1,T+8002)):
            with self.assertRaises(ValueError):m.control(c,*args)
    def test_tcp_exact_pid_address_state_and_ports_are_required(self):
        L='7f000001';rows=[(2,11,49153,0,L,'00000000'),(7,22,50001,49153,L,L),(8,11,49153,50001,L,L)]
        m.exact_tcp(tcp_raw(rows),11,49153,client_pid=22,client_port=50001)
        for index,column,value in ((0,1,12),(1,0,5),(2,0,5),(2,3,50002),(1,4,'00000000')):
            bad=copy.deepcopy(rows);r=list(bad[index]);r[column]=value;bad[index]=tuple(r)
            with self.assertRaises(ValueError):m.exact_tcp(tcp_raw(bad),11,49153,client_pid=22,client_port=50001)
    def test_real_constructor_shape_zero_cap_pointer_job_aap_and_no_inheritance(self):
        for policy in (0,1):
            api=m.API.__new__(m.API);api.proc=b.proc;api.controls_uncertain=False;seen=[]
            def initialize(buf,count,flags,size):self.assertEqual(count,3);size._obj.value=256;return int(buf is not None)
            def update(buf,flags,kind,value,size,previous,returned):
                seen.append(kind)
                if kind==m.base.SECURITY_CAPABILITIES:self.assertEqual((value._obj.AppContainerSid,value._obj.Capabilities,value._obj.CapabilityCount,value._obj.Reserved),(77,None,0,0))
                elif kind==m.base.JOB_LIST:self.assertEqual(C.cast(value,C.POINTER(C.c_void_p))[0],99)
                else:self.assertEqual(value._obj.value,policy)
                return 1
            def create(actor,cmd,sa,ta,inherit,flags,env,cwd,start,info):
                self.assertFalse(inherit);self.assertTrue(flags&4);info._obj.hProcess=201;info._obj.hThread=202;info._obj.dwProcessId=203;return 1
            api.k=NS(InitializeProcThreadAttributeList=initialize,UpdateProcThreadAttribute=update,DeleteProcThreadAttributeList=lambda _:None,CreateProcessW=create)
            api.native=NS(check=lambda x,label:m.require(x,label));info=b.proc._ProcessInfo();owners=m.helpers.OneShotHandles(lambda _:None);state={'creation_attempted':False}
            budget=m.launcher.QpcBudget(NS(qpc=lambda:T+100,qpc_frequency=lambda:F),D,F)
            api.create_zero_suspended(info,[m.ACTOR],Path('inputs'),'SystemRoot=C:\\Windows\0LOCALAPPDATA=x\0\0',99,owners,state,
                profile_pointer=77,policy=policy,budget=budget,cutoff=D-30*F)
            self.assertEqual(seen,[m.base.JOB_LIST,m.base.SECURITY_CAPABILITIES,m.base.ALL_APPLICATION_PACKAGES_POLICY]);self.assertEqual(set(owners.pending),{201,202})
    def test_zero_access_identity_four_byte_empty_header_and_short_header_rejected(self):
        api=m.ZeroAccessAPI.__new__(m.ZeroAccessAPI);retained=[]
        def info(token,kind):
            if kind==30:return C.create_string_buffer(bytes(4)),4
            if kind==10:
                st=m.access.TOKEN_STATISTICS();st.TokenType=1;return C.create_string_buffer(C.string_at(C.byref(st),C.sizeof(st))),C.sizeof(st)
            raw=C.create_string_buffer(32);retained.append(raw);C.cast(raw,C.POINTER(C.c_void_p))[0]=C.addressof(raw)+8;return raw,32
        api._information=info;api._scalar=lambda token,kind:{8:1,29:1,20:0,26:0,12:1}[kind]
        api._sid=lambda ptr,start,n:'S-1-16-4096' if len(retained)==1 else b.ACSID if len(retained)==3 else b.SID
        self.assertEqual(api.identity(1)['capabilities'],[])
        good=api._information
        for size in (0,1,3):
            api._information=lambda token,kind,size=size:(C.create_string_buffer(4),size) if kind==30 else good(token,kind)
            with self.assertRaises(ValueError):api.identity(1)
        api._information=lambda token,kind:(C.create_string_buffer(struct.pack('<I',1)),4) if kind==30 else good(token,kind)
        with self.assertRaises(ValueError):api.identity(1)

if __name__=='__main__':unittest.main()
