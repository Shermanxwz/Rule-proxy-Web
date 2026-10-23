"""Production-owner injection tests; no Windows/native/network calls."""
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
m=load('stream_owner_tests',ROOT/'.github/windows_identity_lpac_stream_origin.py')
f=load('stream_immutable_resource_fakes',Path(__file__).with_name('test_windows_identity_lpac_pipe_origin.py'))
b=f.b;F,T,D=f.F,f.T,f.D
Function=f.Function
REQUEST=b'RPS1'+bytes(range(256))*31+bytes(range(252))+b'!'
RESPONSE=bytes(range(256))*47+b'RPS1'+bytes(range(252))+b'?'
assert len(REQUEST)==8193 and len(RESPONSE)==12289
CHALLENGES={'request':dict(bytes=len(REQUEST),sha256=m.sha(REQUEST)),'response':dict(bytes=len(RESPONSE),sha256=m.sha(RESPONSE))}
def config():
    c=f.config();c.update(scope=m.SCOPE,profile=m.PROFILE,challenges=copy.deepcopy(CHALLENGES))
    c['network_actor_sha256']=c.pop('origin_actor_sha256');c['network_manifest_sha256']=c.pop('origin_manifest_sha256')
    c['source_hashes']=dict.fromkeys(m.SOURCES,b.H);c['source_sha256']=m.sha(m.encode(c['source_hashes']));return c

def file_state(n,source=False):return dict(attempted=True,opened=True,bytes=n,flushed=not source,close='confirmed')
def stream_state(selected):
    req,res=len(REQUEST),len(RESPONSE);tx,rx=(req,res) if selected else (res,req)
    return dict(**dict.fromkeys(m.STREAM_FLAGS,True),tx_frames=24,rx_frames=24,tx_payload_bytes=tx,rx_payload_bytes=rx,local_source_bytes=tx,local_sink_bytes=rx,
        tx_credit_received=tx,rx_credit_sent=rx,tx_outstanding=0,rx_outstanding=0,tx_window_available=4096,local_buffered=0,peer_buffered=0,partial_frame_bytes=0,pending_frame_bytes=0,failure=None)

class API(f.API):
    def access_api(self):
        if self.fault=='challenge-after-admission':(self.root/m.CHALLENGE_PATHS['request']).write_bytes(REQUEST[:-1]+b'?')
        return f.Probe(self)
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def atomic_spawn(self,info,argv,cwd,job,owners,state,**kw):
        super().atomic_spawn(info,argv,cwd,job,owners,state,**kw)
        if info.hProcess and argv[1]=='stream-origin':self.rows[info.hProcess]['role']='ordinary-origin-fixture'
    def pair_spawn(self,info,argv,cwd,environment,job,owners,state,*,ends,pipe_pending,profile_pointer,budget,end,on_return):
        assert len(argv)==15 and tuple(int(x) for x in argv[5:7])==tuple(ends) and set(ends)<=set(pipe_pending)
        self.atomic_spawn(info,argv,cwd,job,owners,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=None)
        self.rows[info.hProcess]['role']='lpac-pipe-front' if profile_pointer else 'ordinary-pipe-relay';state.update(raw_return=1,raw_error=None,raw_pi=m.info_values(info),returned_qpc=self.now,creation_unknown=False);on_return(state.copy())
    def resume(self,thread):
        h=thread-1;r=self.rows[h]
        if 'role' not in r:return super(f.API,self).resume(thread)
        role=r['role'];self.resume_roles.append(role);r['resumed']=True;c=self.owner.c
        if role=='ordinary-origin-fixture':
            if self.fault=='response-locked':self.origin_response_handle_held=True
            ready=dict(schema_version=1,stage='lpac-stream-origin-ready',run_id=c['run'],case_id=c['case'],pid=h,port=54321,qpc_frequency=F,start_qpc=T,deadline_qpc=m.work_cutoff(c),loopback_ipv4=True)
            (self.root/m.REPORT_PATHS['ready']).write_bytes(m.encode(ready));return
        assert self.owner.j['proof']['qualified'] and self.owner.pipes.confirmed_closed
        if role=='lpac-pipe-front':self.finish_reports()
    def finish_reports(self):
        c=self.owner.c;pair=self.owner.j['pair'];self.now+=20
        for key,name in m.SINK_PATHS.items():(self.root/name).write_bytes(REQUEST if key in ('relay_request','origin_request') else RESPONSE)
        for role in m.ROLES:
            row=self.owner.tasks[role];r=self.rows[row['pid']];r.update(exited=True,exitcode=0);selected=role=='lpac-pipe-front';origin=role=='ordinary-origin-fixture';key='selected' if selected else 'origin' if origin else 'relay'
            st=None if origin else stream_state(selected)
            files=dict(source=file_state(len(REQUEST) if selected else len(RESPONSE),True) if selected or origin else None,request_sink=None if selected else file_state(len(REQUEST)),response_sink=file_state(len(RESPONSE)))
            pipe=None if origin else dict(read_bytes=24*64+st['rx_payload_bytes'],write_bytes=24*64+st['tx_payload_bytes'],read_calls=333,write_calls=421,peek_calls=444,eof_observed=True,reader_close='confirmed',writer_close='confirmed',inheritance_cleared=True)
            net=None
            if not selected:
                net=dict(**dict.fromkeys(m.NETWORK_FLAGS,False),port=54321,local_port=54321 if origin else 55000,peer_port=55000 if origin else 54321,bytes_sent=len(RESPONSE) if origin else len(REQUEST),bytes_received=len(REQUEST) if origin else len(RESPONSE),socket_close='confirmed',listener_close='confirmed' if origin else 'not_attempted')
                net.update(dict.fromkeys(('wsa_startup','wsa_cleanup','socket_created','peer_loopback','send_shutdown','receive_eof'),True));net.update(dict.fromkeys(('listener_created','exclusive','bind_loopback','accepted') if origin else ('connect_attempted','connect_completed'),True))
            v=dict(schema_version=1,stage='lpac-stream-actor',role='stream-front' if selected else 'stream-origin' if origin else 'stream-relay',run_id=c['run'],case_id=c['case'],pid=row['pid'],identity=f.native_identity(row,c),qpc=[F,T if origin else pair['start'],m.work_cutoff(c) if origin else pair['end'],self.now],limits=dict(payload_max=1024,window=4096,total_max=65536,frames_max=256,request_bytes=len(REQUEST),response_bytes=len(RESPONSE)),files=files,stream=st,pipe=pipe,network=net,admitted_qpc=None if origin else row['resume_intent_qpc'],read_handle_inherit_cleared=not origin,write_handle_inherit_cleared=not origin,failure=None,win32_error=None,wsa_error=None,selected_socket_api_tested=False,network_tested=not selected,proxy_tested=False,product_acceptance=False)
            if self.fault=='selected-malformed' and selected:v['unexpected']=True
            if self.fault=='tuple' and origin:net['peer_port']+=1
            (self.root/m.REPORT_PATHS[key]).write_bytes(m.encode(v))
        self.origin_response_handle_held=False

class CoordinatorTests(unittest.TestCase):
    def owner(self,fault=None,probe_fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for n in ('inputs','selected-inputs','ordinary-inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report'):(root/n).mkdir()
        for n in ('health','relay-report','origin-report'):(root/n/'temp').mkdir()
        (root/m.CHALLENGE_PATHS['request']).write_bytes(REQUEST);(root/m.CHALLENGE_PATHS['response']).write_bytes(RESPONSE)
        (root/'inputs'/m.ACTOR).write_bytes(b'x'*512);(root/'inputs'/m.NETWORK_ACTOR).write_bytes(b'b'*512)
        tool=root/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool')
        c=config();m.config_validate(c);api=API(root,fault,probe_fault);o=m.Owner(root,c,b.PARENT,api,m.launcher.QpcBudget(api,D,F));api.owner=o
        actual_bounded=m.local.bounded
        def bounded(path,limit):
            if getattr(api,'origin_response_handle_held',False) and Path(path)==root/m.CHALLENGE_PATHS['response']:
                e=OSError('origin owns share-zero response input');e.winerror=32;raise e
            return actual_bounded(path,limit)
        with patch.object(m.local,'bounded',side_effect=bounded):j=o.execute()
        m.validate_result(j,c,parent=b.PARENT,root=root);return o,api,j,m.project(j,c,parent=b.PARENT,root=root)
    def test_actual_new_owner_composes_held_proof_original_budget_and_five_sinks(self):
        o,api,j,v=self.owner();self.assertIsNone(j['failure']);self.assertTrue(v['mechanism_verified']);self.assertTrue(v['payloads_verified']);self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS));self.assertEqual(api.resume_roles,list(reversed(m.ROLES)));self.assertEqual(len(j['physical_sinks']),5);self.assertTrue(all(j[k] for k in m.CLEAN_KEYS));self.assertFalse(api.killed)
        self.assertEqual(j['pair']['end']-j['pair']['start'],10*F);self.assertEqual(j['challenges'],CHALLENGES)
    def test_origin_live_share_zero_response_input_is_never_reopened_before_pair_resume(self):
        o,api,j,v=self.owner('response-locked');self.assertTrue(v['mechanism_verified']);self.assertTrue(v['payloads_verified'])
        self.assertEqual(api.resume_roles,list(reversed(m.ROLES)));self.assertFalse(api.origin_response_handle_held)
        self.assertEqual(j['challenges'],CHALLENGES);self.assertTrue(all(j[k] for k in m.CLEAN_KEYS))
    def test_request_pin_rechecked_after_matrix_before_either_pair_resume(self):
        _,api,j,v=self.owner_without_final_physical_read('challenge-after-admission')
        self.assertEqual(api.resume_roles,['ordinary-origin-fixture']);self.assertFalse(j['mechanism_verified']);self.assertFalse(v)
    def owner_without_final_physical_read(self,fault):
        # The raw result remains a failure when an independently rechecked
        # input changed. A root physical validator must reject that altered pin.
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for n in ('inputs','selected-inputs','ordinary-inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report'):(root/n).mkdir()
        for n in ('health','relay-report','origin-report'):(root/n/'temp').mkdir()
        (root/m.CHALLENGE_PATHS['request']).write_bytes(REQUEST);(root/m.CHALLENGE_PATHS['response']).write_bytes(RESPONSE)
        (root/'inputs'/m.ACTOR).write_bytes(b'x'*512);(root/'inputs'/m.NETWORK_ACTOR).write_bytes(b'b'*512)
        tool=root/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool');c=config();api=API(root,fault);o=m.Owner(root,c,b.PARENT,api,m.launcher.QpcBudget(api,D,F));api.owner=o;j=o.execute()
        m.validate_result(j,c,parent=b.PARENT)
        with self.assertRaises(ValueError):m.validate_result(j,c,parent=b.PARENT,root=root)
        return o,api,j,j['mechanism_verified']
    def test_rehashed_raw_pi_other_pid_is_not_the_held_actor(self):
        o,_,j,_=self.owner();bad=copy.deepcopy(j);row=next(r for r in bad['tasks'] if r['role']=='lpac-pipe-front');v=m.decode(row['receipt']['text'].encode());v['pi'][2]+=1
        raw=m.encode(v);row['receipt'].update(text=raw.decode(),sha256=m.sha(raw));(o.root/'returns'/row['receipt']['name']).write_bytes(raw)
        with self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=b.PARENT,root=o.root)
    def test_response_and_ordinary_raws_are_outside_all_lpac_rx_or_modify_subtrees(self):
        o,_,_,_=self.owner()
        for path in ('ordinary-inputs','ordinary-inputs/response.bin','origin-report/request.raw','relay-report/request-sent.raw'):self.assertEqual(m.expected_acl(o.root,o.root/path),[])
        self.assertEqual(m.expected_acl(o.root,o.root/'selected-inputs/request.bin'),[(16,0x1200a9)])
    def test_failed_pipe_allocation_sticky_unknown_even_zero_output_blocks_delete(self):
        o,api,j,v=self.owner('pipe-false');self.assertTrue(j['pipe_allocation_unknown']);self.assertFalse(j['profile_deleted']);self.assertFalse(v['mechanism_verified']);self.assertFalse(api.resume_roles[1:])
    def test_every_parent_close_attempted_and_no_pair_resume_after_unknown_close(self):
        o,api,j,v=self.owner('parent-close');self.assertEqual(len(j['parent_pipe_close_attempts']),4);self.assertEqual(api.resume_roles,['ordinary-origin-fixture']);self.assertFalse(j['profile_deleted']);self.assertFalse(v['mechanism_verified'])
    def test_real_accesscheck_negative_stops_pair_before_resume(self):
        o,api,j,v=self.owner(probe_fault='wrong-mask');self.assertFalse(v['mechanism_verified']);self.assertEqual(api.resume_roles,['ordinary-origin-fixture'])
    def test_partial_bad_selected_report_preserves_independent_origin_and_cleanup(self):
        _,_,j,v=self.owner('selected-malformed');self.assertFalse(v['mechanism_verified']);self.assertEqual(v['native_report_status']['selected'],'invalid');self.assertTrue(v['origin_request_observed']);self.assertTrue(v['cleanup_known'])
    def test_wrong_peer_tuple_does_not_qualify(self):
        _,_,_,v=self.owner('tuple');self.assertFalse(v['mechanism_verified']);self.assertTrue(v['origin_request_observed'])
    def rewrite(self,o,j,key,value):
        raw=m.encode(value);j['reports'][key]=dict(text=raw.decode(),sha256=m.sha(raw));(o.root/m.REPORT_PATHS[key]).write_bytes(raw)
    def test_physical_sink_and_rehashed_different_bytes_cannot_claim_success(self):
        o,_,j,_=self.owner();path=o.root/m.SINK_PATHS['relay_request'];path.write_bytes(REQUEST[:-1]+b'?')
        with self.assertRaises(ValueError):m.validate_result(j,o.c,parent=b.PARENT,root=o.root)
        k=j['physical_sinks']['relay_request'];k.update(bytes=path.stat().st_size,sha256=m.sha(path.read_bytes()))
        with self.assertRaises(ValueError):m.validate_result(j,o.c,parent=b.PARENT,root=o.root)
    def test_input_tamper_rejected_physically_even_with_all_matching_sinks(self):
        o,_,j,_=self.owner();(o.root/m.CHALLENGE_PATHS['response']).write_bytes(RESPONSE[:-1]+b'!')
        with self.assertRaises(ValueError):m.validate_result(j,o.c,parent=b.PARENT,root=o.root)
    def test_claimed_owned_profile_label_grants_or_raw_pi_mutations_rejected(self):
        o,_,j,_=self.owner()
        for change in ('profile','label','grant','receipt'):
            bad=copy.deepcopy(j)
            if change=='profile':bad['profile_state']['created']=False
            elif change=='label':bad['labels']=[]
            elif change=='grant':bad['tasks']=[r for r in bad['tasks'] if r['name']!='grant-selected-inputs']
            else:next(r for r in bad['tasks'] if r['role']=='lpac-pipe-front')['receipt']=None
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=b.PARENT,root=o.root)
    def test_final_after_held_exit_or_completion_before_final_rejected(self):
        o,_,j,_=self.owner()
        for role,key in zip(m.ROLES,('selected','relay','origin')):
            bad=copy.deepcopy(j);native=m.decode(bad['reports'][key]['text'].encode());row=next(r for r in bad['tasks'] if r['role']==role);native['qpc'][3]=row['exit_observed_qpc']+1;self.rewrite(o,bad,key,native)
            with self.subTest(role=role),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=b.PARENT,root=o.root)
            (o.root/m.REPORT_PATHS[key]).write_bytes(j['reports'][key]['text'].encode())
    def test_credit_window_and_native_file_count_inconsistency_rejected(self):
        o,_,j,_=self.owner()
        for change in ('credit','byte_count','frames','socket','limit-type'):
            bad=copy.deepcopy(j);v=m.decode(bad['reports']['relay']['text'].encode())
            if change=='credit':v['stream']['tx_outstanding']=4097
            elif change=='byte_count':v['files']['request_sink']['bytes']-=1
            elif change=='frames':v['stream']['tx_frames']-=1
            elif change=='socket':v['network']['bytes_sent']-=1
            else:v['limits']['payload_max']=1024.0
            self.rewrite(o,bad,'relay',v)
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=b.PARENT,root=o.root)
            (o.root/m.REPORT_PATHS['relay']).write_bytes(j['reports']['relay']['text'].encode())
    def test_challenge_format_and_independent_pins_are_closed(self):
        o,_,_,_=self.owner();request=o.root/m.CHALLENGE_PATHS['request'];response=o.root/m.CHALLENGE_PATHS['response'];m.challenge_inputs(request,response,CHALLENGES)
        request.write_bytes(b'x'*8193)
        with self.assertRaises(ValueError):m.challenge_inputs(request,response)
        with self.assertRaises(ValueError):m.challenge_meta(dict(request=CHALLENGES['request'],response=CHALLENGES['response']|{'sha256':CHALLENGES['request']['sha256']}))

class ConstructorTests(unittest.TestCase):
    def test_verify_actor_single_bom_preserves_original_hash_and_strict_schema(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();build=root/'build';build.mkdir();actor=build/m.ACTOR;actor.write_bytes(b'MZ'+b'x'*510);ah=m.sha(actor.read_bytes());manifest=build/m.MANIFEST
            value=dict(schemaVersion=1,compileOnly=True,runtimeAcceptance=False,interfaceVersion=1,executableSha256=ah)
            for i,(key,name) in enumerate(m.NATIVE_SOURCES.items()):
                path=root/name;path.parent.mkdir(parents=True,exist_ok=True);raw=('native-source-%d\n'%i).encode();path.write_bytes(raw);value[key]=m.sha(raw)
            body=m.encode(value);bom=b'\xef\xbb\xbf'
            for raw in (body,bom+body):
                manifest.write_bytes(raw);self.assertEqual(m.verify_actor(actor,manifest,ah,m.sha(raw),root=root),actor)
            manifest.write_bytes(bom+body)
            with self.assertRaises(ValueError):m.verify_actor(actor,manifest,ah,m.sha(body),root=root)
            for raw in (bom+bom+body,m.encode(value|{'extra':True}),m.encode(value|{'actorSourceSha256':'f'*64}),body.replace(b'"schemaVersion":1',b'"schemaVersion":1,"schemaVersion":1'),body.replace(b'"schemaVersion":1',b'"schemaVersion":NaN')):
                manifest.write_bytes(raw)
                with self.subTest(raw_prefix=raw[:3]),self.assertRaises(ValueError):m.verify_actor(actor,manifest,ah,m.sha(raw),root=root)

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
        argv=[m.ACTOR if selected else m.NETWORK_ACTOR,'stream-front' if selected else 'stream-relay']
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

if __name__=='__main__':unittest.main()
