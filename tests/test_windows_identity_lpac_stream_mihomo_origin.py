"""A2 pure contracts and eventually the injected real coordinator; no actor."""
from pathlib import Path
import importlib.util
import ctypes as C
import copy
import struct
from types import SimpleNamespace as NS
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('a2_owner_pure',ROOT/'.github/windows_identity_lpac_stream_mihomo_origin.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('a2_process_structures',ROOT/'ruleproxy/windows_app_process.py')
proc=importlib.util.module_from_spec(spec);spec.loader.exec_module(proc)
CASE='2'*32;O=54321
M=O+1;T=100000;F=1000

class Function:
    def __init__(self,fn):self.fn=fn
    def __call__(self,*args):return self.fn(*args)

def budget(now=None,end=T+10000):
    now=now or [T+1]
    return m.launcher.QpcBudget(NS(qpc=lambda:now[0],qpc_frequency=lambda:F),end,F)

def tcp_raw(rows):
    def addr(s):return int.from_bytes(bytes(int(x) for x in s.split('.')),'little')
    def port(p):return int.from_bytes(p.to_bytes(2,'big')+b'\0\0','little')
    return struct.pack('<I',len(rows))+b''.join(struct.pack('<6I',state,addr(la),port(lp),addr(ra),port(rp),pid) for state,la,lp,ra,rp,pid in rows)

def tcp_fixture():
    return [(2,'127.0.0.1',M,'0.0.0.0',0,102),(2,'127.0.0.1',O,'0.0.0.0',0,103),
        (5,'127.0.0.1',52001,'127.0.0.1',M,101),(5,'127.0.0.1',M,'127.0.0.1',52001,102),
        (5,'127.0.0.1',52002,'127.0.0.1',O,102),(5,'127.0.0.1',O,'127.0.0.1',52002,103)]

def independent_message(response):
    total,digits=(12289,5) if response else (8193,4)
    if response:
        template=('HTTP/1.1 200 OK\r\nContent-Length: '+'0'*digits+'\r\nConnection: close\r\nX-RuleProxy-Case: '+CASE+'\r\n\r\n').encode()
    else:
        template=('POST /ruleproxy-a2/'+CASE+' HTTP/1.1\r\nHost: 127.0.0.1:'+str(O)+'\r\nContent-Length: '+'0'*digits+'\r\nConnection: close\r\n\r\n').encode()
    length=total-len(template)
    assert len(str(length))==digits
    header=template.replace(b'0'*digits,str(length).encode())
    prefix=(bytes(reversed(range(256))) if response else bytes(range(256)))+b'RPS1'
    body=(prefix+bytes((i*31+7)%256 for i in range(length)))[:length]
    return header+body,header,body

class PureMessageTests(unittest.TestCase):
    def test_actual_binary_HTTP_files_match_independent_header_and_lengths(self):
        self.assertIs(type(m.ACTUAL_READY),bool)
        for response in (False,True):
            raw,header,body=independent_message(response)
            with self.subTest(response=response):
                self.assertEqual(m.canonical_header(response,CASE,O,len(raw)),header)
                self.assertEqual(m.build_challenge(body,response=response,case=CASE,origin_port=O),raw)
                self.assertEqual(m.http_challenge(raw,response=response,case=CASE,origin_port=O),dict(bytes=len(raw),sha256=m.sha(raw)))

    def test_HTTP_header_case_Host_status_and_body_tampering_cannot_pass(self):
        for response in (False,True):
            raw,header,body=independent_message(response)
            changes=[raw+b'x',raw[:-1],raw.replace(CASE.encode(),b'3'*32,1),raw.replace(b'Content-Length',b'Content-LEngth',1)]
            changes.append(raw.replace(b'200 OK',b'301 OK',1) if response else raw.replace(b'127.0.0.1:54321',b'127.0.0.1:54322',1))
            for changed in changes:
                with self.subTest(response=response,sha=m.sha(changed)),self.assertRaises(ValueError):m.http_challenge(changed,response=response,case=CASE,origin_port=O)
            with self.assertRaisesRegex(ValueError,'a2_independent_binary_body'):m.http_challenge(header+b'x'*len(body),response=response,case=CASE,origin_port=O)

    def test_only_cold_selected_request_reopened_before_pair_resume(self):
        request,_,_=independent_message(False);response,_,_=independent_message(True)
        expected={name:dict(bytes=len(raw),sha256=m.sha(raw)) for name,raw in (('request',request),('response',response))}
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();p=root/'request.bin';p.write_bytes(request);r=root/'response.bin';r.write_bytes(response)
            m.challenge_inputs(p,r,expected,case=CASE,origin_port=O)
            read=m.local.bounded;paths=[]
            def closed(path,limit):
                paths.append(Path(path))
                if Path(path)==r:raise OSError('live origin owns share0 response input')
                return read(path,limit)
            with patch.object(m.local,'bounded',side_effect=closed):m.request_before_pair_resume(p,expected,case=CASE,origin_port=O)
            self.assertEqual(paths,[p])
            p.write_bytes(request[:-1]+bytes([request[-1]^1]))
            with self.assertRaisesRegex(ValueError,'a2_selected_request_changed'):m.request_before_pair_resume(p,expected,case=CASE,origin_port=O)

    def test_two_ports_are_declared_distinct_exact_high_integers(self):
        self.assertEqual(m.ports(dict(origin_port=O,proxy_port=O+1)),dict(origin_port=O,proxy_port=O+1))
        for value in (dict(origin_port=O,proxy_port=O),dict(origin_port=True,proxy_port=O),dict(origin_port=49152,proxy_port=O),dict(origin_port=O,proxy_port=65536),dict(origin_port=O,proxy_port=O+1,extra=0)):
            with self.subTest(value=value),self.assertRaises(ValueError):m.ports(value)


class KernelTableTests(unittest.TestCase):
    def parse(self,rows):return m.exact_two_hop(tcp_raw(rows),relay_pid=101,proxy_pid=102,origin_pid=103,declared=dict(origin_port=O,proxy_port=M),origin_peer_port=52002)
    def test_all_four_owned_rows_and_both_unique_listeners_are_required(self):
        rows=tcp_fixture();found=self.parse(rows);self.assertEqual(found['proxy_out']['local_port'],52002)
        for index in range(len(rows)):
            with self.subTest(missing=index),self.assertRaises(ValueError):self.parse(rows[:index]+rows[index+1:])
        for index in range(2,6):
            for column,value in ((0,6),(1,'0.0.0.0'),(3,'127.0.0.2'),(5,999)):
                bad=rows.copy();r=list(bad[index]);r[column]=value;bad[index]=tuple(r)
                with self.subTest(index=index,column=column),self.assertRaises(ValueError):self.parse(bad)
        with self.assertRaises(ValueError):self.parse(rows+[rows[4]])

    def test_physical_kernel_raw_hash_and_recomputed_rows_cannot_be_substituted(self):
        rows=tcp_fixture();raw=tcp_raw(rows);parsed=self.parse(rows)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();(root/'tcp').mkdir();path=root/'tcp/two-hop.bin';path.write_bytes(raw)
            value=m.tcp_record(raw,parsed,name='two-hop.bin',before_qpc=T+1,after_qpc=T+2)
            self.assertEqual(m.validate_tcp_record(value,root=root,expected_rows=parsed),raw)
            bad=copy.deepcopy(value);bad['rows']['proxy_out']['pid']=101
            with self.assertRaises(ValueError):m.validate_tcp_record(bad,root=root,expected_rows=parsed)
            path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
            with self.assertRaises(ValueError):m.validate_tcp_record(value,root=root,expected_rows=parsed)


class ConstructorTests(unittest.TestCase):
    def setUp(self):
        self.error=[0]
        self.patch=patch.object(C,'get_last_error',lambda:self.error[0],create=True);self.patch.start();self.addCleanup(self.patch.stop)
    def create(self,role,shape='true',late=False,receipt_fail=False):
        api=m.API.__new__(m.API);api.controls_uncertain=False;api.proc=proc;api.process_info=api.proc._ProcessInfo;api.pipe_flags=lambda h:1;api.pipe_type=lambda h:3
        calls=[];attrs=[];now=[T+1];api.native=NS(check=lambda value,label:m.require(bool(value),label))
        selected=role==m.ROLES[0];core=role in m.CORE_ROLES;pair=role in m.ROLES[:2];ends=(101,102,103) if core else (101,102) if pair else ()
        def init(pointer,count,flags,size):C.cast(size,C.POINTER(C.c_size_t))[0]=512;return int(pointer is not None)
        def update(pointer,flags,kind,data,size,old,length):
            if kind==m.base.JOB_LIST:value=list(C.cast(data,C.POINTER(C.c_void_p*1)).contents)
            elif kind==0x20002:value=list(C.cast(data,C.POINTER(C.c_void_p*len(ends))).contents)
            elif kind==m.base.SECURITY_CAPABILITIES:
                cap=C.cast(data,C.POINTER(api.proc._SecurityCapabilities)).contents;value=[cap.AppContainerSid,cap.Capabilities,cap.CapabilityCount,cap.Reserved]
            else:value=C.cast(data,C.POINTER(C.c_uint32))[0]
            attrs.append((kind,size,value));return 1
        def physical(app,cmd,ps,ts,inherit,flags,environment,cwd,start,pi):
            si=C.cast(start,C.POINTER(api.proc._StartupInfoEx)).contents
            calls.append(dict(inherit=inherit,stdio=[si.StartupInfo.hStdInput,si.StartupInfo.hStdOutput,si.StartupInfo.hStdError],flags=si.StartupInfo.dwFlags))
            p=C.cast(pi,C.POINTER(api.proc._ProcessInfo)).contents
            values=[701,702,703,704] if shape=='true' else [901,901,903,904] if shape=='false-garbage' else [701,0,703,0] if shape=='partial' else [0,0,0,0]
            p.hProcess,p.hThread,p.dwProcessId,p.dwThreadId=values
            if late:now[0]=T+10000
            if shape=='exception':raise OSError('unknown physical return')
            self.error[0]=5;return 0 if shape.startswith('false') else 1
        api.k=NS(InitializeProcThreadAttributeList=Function(init),UpdateProcThreadAttribute=Function(update),CreateProcessW=Function(physical),DeleteProcThreadAttributeList=Function(lambda p:calls.append('delete')))
        owners=m.helpers.OneShotHandles(lambda h:calls.append(('close',h)));info=api.process_info();state=dict(creation_attempted=False);received=[]
        def returned(value):
            self.assertFalse(owners.pending);self.assertEqual(m.legacy.info_values(info),[0]*4);received.append(copy.deepcopy(value))
            if receipt_fail:raise OSError('private receipt failed')
        name=m.ACTOR if selected else 'mihomo.exe' if core else m.NETWORK_ACTOR
        caught=None
        try:api.captured_spawn(info,[name,'placeholder'],Path('.'),'SystemRoot=x\0LOCALAPPDATA=y\0\0' if selected else 'SystemRoot=x\0\0',91,owners,state,
            role=role,ends=ends,other_pending=set(ends),profile_pointer=77 if selected else None,budget=budget(now),end=T+10000,on_return=returned)
        except BaseException as e:caught=e
        return api,info,state,owners,received,calls,attrs,caught

    def test_true_native_shape_uses_exact_new_role_attributes_and_stdio(self):
        for role in (*m.ROLES,*m.CORE_ROLES):
            with self.subTest(role=role):
                api,info,state,owners,received,calls,attrs,error=self.create(role);self.assertIsNone(error);self.assertEqual(owners.pending,{701,702});self.assertEqual(received[0]['raw_pi'],[701,702,703,704])
                expected=[m.base.JOB_LIST]+([0x20002] if role!=m.ROLES[2] else [])+([m.base.SECURITY_CAPABILITIES,m.base.ALL_APPLICATION_PACKAGES_POLICY] if role==m.ROLES[0] else [])
                self.assertEqual([r[0] for r in attrs],expected)
                if role in m.CORE_ROLES:self.assertEqual(calls[0]['stdio'],[101,102,103]);self.assertEqual(calls[0]['flags']&0x100,0x100)
                else:self.assertEqual(calls[0]['flags']&0x100,0)
                self.assertEqual(calls[0]['inherit'],role!=m.ROLES[2])

    def test_unknown_false_or_partial_never_adopts_success_late_still_cleans(self):
        for shape in ('false-garbage','partial','exception'):
            api,info,state,owners,*tail=self.create(m.CORE_ROLES[1],shape);self.assertFalse(owners.pending);self.assertEqual(m.legacy.info_values(info),[0]*4);self.assertTrue(state['creation_unknown']);self.assertIsNotNone(tail[-1])
        api,info,state,owners,*tail=self.create(m.CORE_ROLES[1],'false-zero');self.assertFalse(state['creation_unknown']);self.assertFalse(owners.pending)
        for late,failed in ((True,False),(False,True)):
            api,info,state,owners,*tail=self.create(m.CORE_ROLES[1],late=late,receipt_fail=failed);self.assertEqual(owners.pending,{701,702});self.assertFalse(state['creation_unknown']);self.assertIsNotNone(tail[-1])
            if failed:self.assertTrue(api.controls_uncertain)

    def test_controlled_stop_records_raw_before_error_and_never_retries(self):
        api=m.API.__new__(m.API);calls=[];api.k=NS(TerminateProcess=Function(lambda h,code:(calls.append((h,code)),0)[1]));self.error[0]=5;receipt=[]
        with self.assertRaisesRegex(ValueError,'a2_controlled_stop_failed'):api.terminate_core(701,budget(),T+10000,receipt.append)
        self.assertEqual(calls,[(701,1)]);self.assertEqual(receipt[0]['raw_return'],0);self.assertEqual(receipt[0]['error'],5)


class FakeLeaseBackend:
    INVALID=(1<<64)-1
    def __init__(self,*,bad=None,now=None):self.bad=bad;self.now=now;self.calls=[];self.next=iter((0,11));self.bound={}
    def startup(self):self.calls.append(('startup',));return 0,0
    def make(self):
        h=next(self.next);self.calls.append(('socket',h))
        if self.bad=='late' and self.now:self.now[0]=T+10000
        return h,0
    def exclusive(self,h):self.calls.append(('exclusive',h));return 0,0
    def exclusive_read(self,h):return (0,0,0 if self.bad=='option' else 1,4)
    def bind(self,h,port):self.calls.append(('bind',h,port));self.bound[h]=port;return 0,0
    def name(self,h):return 0,0,dict(family=2,port=self.bound[h],address='7f000001',size=16)
    def close(self,h):self.calls.append(('close',h));return (-1,10038) if self.bad=='close' and h==0 else (0,0)
    def cleanup(self):self.calls.append(('cleanup',));return 0,0

class LeaseTests(unittest.TestCase):
    def test_socket_zero_valid_two_exclusive_fixed_leases_no_listen_or_traffic(self):
        backend=FakeLeaseBackend();leases=m.PortLeases(backend,budget(),T+10000,dict(origin_port=O,proxy_port=M)).acquire()
        self.assertEqual(leases.pending,{0:'origin_port',11:'proxy_port'})
        leases.release('origin_port');leases.release('proxy_port');leases.close_all();leases.close_all()
        self.assertTrue(leases.confirmed_closed);self.assertEqual([r for r in backend.calls if r[0]=='close'],[('close',0),('close',11)])
        self.assertEqual(backend.calls.count(('cleanup',)),1)
    def test_option_failure_late_return_and_uncertain_close_keep_once_obligations(self):
        for kind in ('option','late'):
            now=[T+1];backend=FakeLeaseBackend(bad=kind,now=now);leases=m.PortLeases(backend,budget(now),T+10000,dict(origin_port=O,proxy_port=M))
            with self.subTest(kind=kind),self.assertRaises(Exception):leases.acquire()
            self.assertEqual([r for r in backend.calls if r[0]=='close'],[('close',0)]);self.assertFalse(leases.pending)
        backend=FakeLeaseBackend(bad='close');leases=m.PortLeases(backend,budget(),T+10000,dict(origin_port=O,proxy_port=M)).acquire();leases.close_all();leases.close_all()
        self.assertFalse(leases.confirmed_closed);self.assertTrue(leases.unknown);self.assertEqual([r for r in backend.calls if r[0]=='close'],[('close',0),('close',11)])

    def test_single_unknown_return_clock_stops_next_lease_and_keeps_raw_close_values(self):
        class Clock:
            def __init__(self):self.count=0
            def require_ms(self,end,*args):return 1
            def read(self):
                self.count+=1
                if self.count==2:raise ValueError('transient QPC failure after known socket')
                return T+self.count
        backend=FakeLeaseBackend();leases=m.PortLeases(backend,Clock(),T+10000,dict(origin_port=O,proxy_port=M))
        with self.assertRaisesRegex(ValueError,'a2_lease_return_clock_unknown'):leases.acquire()
        self.assertEqual([r for r in backend.calls if r[0]=='socket'],[('socket',0)])
        self.assertEqual([r for r in backend.calls if r[0]=='close'],[('close',0)]);self.assertTrue(leases.unknown)
        self.assertEqual(leases.calls[1]['value'],(0,0));self.assertIsNone(leases.calls[1]['return_qpc'])
        self.assertEqual(leases.closed[0]['value'],(0,0));self.assertEqual(leases.calls[-1]['value'],(0,0))
        self.assertFalse(leases.confirmed_closed)


class BarrierTests(unittest.TestCase):
    def setUp(self):
        self.c=dict(run='1'*32,case=CASE,frequency=F,start_qpc=T,root_deadline_qpc=T+120*F,ports=dict(origin_port=O,proxy_port=M))
        self.pair=dict(start=T+F,end=T+11*F,frequency=F);self.issued=T+F+1;self.tick=T+F+100
    def ack(self):
        return dict(schema_version=1,stage='lpac-stream-mihomo-origin-request-held',role='stream-a2-origin',run_id='1'*32,case_id=CASE,pid=103,
            qpc=[F,T,T+85*F,self.tick],pair_qpc=[self.pair['start'],self.pair['end']],ports=self.c['ports'],accepted_count=1,local_port=O,peer_port=52002,
            peer_loopback=True,request_bytes=8193,request_message_complete=True,request_eof_observed=False,response_bytes_sent=0,socket_held=True,
            phase_command_close_verified=True,phase_issued_qpc=self.issued,wait_deadline_qpc=self.tick+2*F,failure=None)
    def test_independent_fixed_offsets_and_original_absolute_bound(self):
        raw=m.barrier_control(self.c,self.pair,self.issued);self.assertEqual(len(raw),128)
        self.assertEqual(raw[:8],b'M2B1\x01\0\x01\0');self.assertEqual(raw[8:40],bytes.fromhex('1'*32+CASE))
        self.assertEqual(struct.unpack_from('<5Q',raw,40),(F,T,T+85*F,self.pair['start'],self.pair['end']))
        self.assertEqual(struct.unpack_from('<4H',raw,80),(O,M,8193,12289));self.assertEqual(struct.unpack_from('<Q',raw,88)[0],self.issued);self.assertEqual(raw[96:],bytes(32))
        ack=m.validate_ack(self.ack(),self.c,self.pair,origin_pid=103,arm_issued=self.issued)
        release=m.barrier_control(self.c,self.pair,self.tick+1,release=True,ack=ack)
        self.assertEqual(release[6],2);self.assertEqual(struct.unpack_from('<QIH',release,96),(self.tick,103,52002));self.assertEqual(release[110:],bytes(18))
        with self.assertRaises(ValueError):m.barrier_control(self.c,self.pair,self.tick+2*F,release=True,ack=ack)
    def test_ACK_positive_payload_or_wrong_identity_never_authorizes_release(self):
        for key,value in (('response_bytes_sent',1),('socket_held',False),('pid',104),('peer_port',0),('request_bytes',8192),('request_message_complete',False),('wait_deadline_qpc',self.tick+2*F+1)):
            bad=self.ack();bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_ack(bad,self.c,self.pair,origin_pid=103,arm_issued=self.issued)
    def test_early_failure_unknown_barrier_observation_not_fake_zero_or_positive(self):
        value=dict.fromkeys(m.BARRIER_KEYS,None)
        for key in m.BARRIER_FLAGS:value[key]=False
        value['failure']='phase';self.assertEqual(m.validate_barrier(value,self.c,self.pair),value)
        value.update(phase_admitted=True,phase_command_closed=True,phase_issued_qpc=self.issued,pair_start_qpc=self.pair['start'],pair_deadline_qpc=self.pair['end'],
            request_held_ack_published=True,socket_held_at_ack=True,ack_qpc=self.tick,wait_deadline_qpc=self.tick+2*F)
        with self.assertRaises(ValueError):m.validate_barrier(value,self.c,self.pair)


class ConfigurationTests(unittest.TestCase):
    def test_fixed_closed_config_does_not_depend_on_ignored_json_rule_or_UDP_default(self):
        cfg=m.mihomo_configuration(dict(origin_port=O,proxy_port=M));self.assertEqual(m.decode(m.encode(cfg)),cfg)
        self.assertTrue(all(cfg[k]==0 for k in ('port','socks-port','mixed-port','redir-port','tproxy-port')))
        self.assertEqual(cfg['listeners'][0]['port'],str(M));self.assertFalse(cfg['listeners'][0]['udp']);self.assertEqual(cfg['listeners'][0]['listen'],'127.0.0.1')
        self.assertNotIn('rule',cfg);self.assertIn('no-resolve',cfg['rules'][0]);self.assertTrue(cfg['rules'][0].endswith('(DST-PORT,'+str(O)+')),DIRECT'))
        self.assertEqual(cfg['rules'][-1],'MATCH,REJECT');self.assertEqual(cfg['dns']['default-nameserver'],['udp://127.0.0.1:1']);self.assertFalse(cfg['dns']['enable'])
        for k in ('nameserver','fallback','proxy-server-nameserver','direct-nameserver'):self.assertEqual(cfg['dns'][k],[])
        self.assertFalse(cfg['tun']['enable']);self.assertFalse(cfg['tun']['auto-route']);self.assertEqual(cfg['tun']['dns-hijack'],[])
        self.assertFalse(cfg['profile']['store-selected']);self.assertFalse(cfg['ntp']['write-to-system'])


def load_test(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file));v=importlib.util.module_from_spec(s);s.loader.exec_module(v);return v
prior=load_test('a2_inert_resource_fixtures','test_windows_identity_lpac_stream_origin.py')

class ComposedAPI(prior.API):
    def lease_backend(self):return FakeLeaseBackend(bad='close' if self.fault=='lease-close' else None)
    def captured_spawn(self,info,argv,cwd,environment,job,owners,state,*,role,ends,other_pending,profile_pointer,budget,end,on_return):
        self.captured_roles=getattr(self,'captured_roles',[])+[role]
        assert set(ends)<=set(other_pending)
        temporary=self.process_info();ledger=m.helpers.OneShotHandles(self.close)
        self.atomic_spawn(temporary,argv,cwd,job,ledger,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=None)
        temporary.dwThreadId=temporary.dwProcessId+2000
        state.update(raw_return=1,raw_error=None,raw_pi=m.info_values(temporary),returned_qpc=self.now,creation_unknown=False);on_return(state.copy())
        info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId=state['raw_pi']
        for h in state['raw_pi'][:2]:owners.add(h)
        self.rows[info.hProcess]['role']=role
    def open_stdio_file(self,path,**kwargs):
        core=Path(path).parent.name in m.CORE_ROLES
        if self.fault=='stdio-alias' and core:return self.owner.job
        h=super().open_stdio_file(path,**kwargs)
        if core:self.core_stdio_handles=getattr(self,'core_stdio_handles',set())|{h}
        return h
    def close(self,h):
        if self.fault=='stdio-alias' and h==self.owner.job and self.owner.j['failure'] is None:self.early_job_close=True
        if self.fault=='stdio-close' and h not in getattr(self,'core_stdio_handles',set()):
            fault,self.fault=self.fault,None
            try:return super().close(h)
            finally:self.fault=fault
        return super().close(h)
    def resume(self,thread):
        h=thread-1;r=self.rows[h]
        if 'role' not in r:return super(prior.f.API,self).resume(thread)
        role=r['role'];self.resume_roles.append(role);r['resumed']=True;c=self.owner.c
        if role==m.CORE_ROLES[0]:
            r.update(exited=True,exitcode=0)
            if self.fault=='config-after-check':(self.root/'core-home/config.json').write_bytes(b'changed-config')
            return
        if role==m.CORE_ROLES[1]:return
        if role==m.ROLES[2]:
            self.origin_response_handle_held=True
            v=dict(schema_version=1,stage='lpac-stream-mihomo-origin-ready',run_id=c['run'],case_id=c['case'],pid=h,port=O,proxy_port=M,qpc_frequency=prior.F,start_qpc=prior.T,deadline_qpc=m.work_cutoff(c),loopback_ipv4=True,exclusive=True)
            (self.root/m.REPORT_PATHS['ready']).write_bytes(m.encode(v));return
        assert self.owner.j['proof']['qualified'] and self.owner.pipes.confirmed_closed
        if role==m.ROLES[0]:
            self.now+=10;pair=self.owner.j['pair'];issued=self.owner.j['barrier_commands']['arm']['issued_qpc'];origin=self.owner.tasks[m.ROLES[2]]
            v=dict(schema_version=1,stage='lpac-stream-mihomo-origin-request-held',role='stream-a2-origin',run_id=c['run'],case_id=c['case'],pid=origin['pid'],
                qpc=[prior.F,prior.T,m.work_cutoff(c),self.now],pair_qpc=[pair['start'],pair['end']],ports=c['ports'],accepted_count=1,local_port=O,peer_port=52002,
                peer_loopback=True,request_bytes=8193,request_message_complete=True,request_eof_observed=False,response_bytes_sent=0,socket_held=True,
                phase_command_close_verified=True,phase_issued_qpc=issued,wait_deadline_qpc=min(pair['end'],self.now+2*prior.F),failure=None)
            (self.root/m.BARRIER_PATHS['ack']).write_bytes(m.encode(v))
    def tcp_snapshot(self,budget,end):
        p=self.owner.tasks;relay=p.get(m.ROLES[1]);proxy=p[m.CORE_ROLES[1]];origin=p[m.ROLES[2]]
        rows=tcp_fixture()
        if relay is None:rows=rows[:2]
        actual={101:relay['pid'] if relay else 999,102:proxy['pid'],103:origin['pid']}
        rows=[(*r[:5],actual[r[5]]) for r in rows]
        if self.fault=='tcp-wrong-owner' and relay:rows[-1]=(*rows[-1][:5],99999)
        return tcp_raw(rows)
    def wait(self,h,ms):
        if ms and self.rows[h].get('role') in m.ROLES and (self.root/m.BARRIER_PATHS['release']).exists() and not getattr(self,'finished',False):
            self.finished=True;self.finish_reports()
        return self.rows[h]['exited']
    def terminate_core(self,h,budget,end,on_return):
        self.terminate_calls=getattr(self,'terminate_calls',[])+[h]
        value=dict(attempted=True,returned=True,raw_return=0 if self.fault=='stop-false' else 1,error=5 if self.fault=='stop-false' else 0,returned_qpc=self.now,exception=None)
        on_return(value)
        if self.fault=='stop-false':raise ValueError('a2_controlled_stop_failed')
        self.rows[h].update(exited=True,exitcode=1)
    def finish_reports(self):
        o=self.owner;c=o.c;pair=o.j['pair'];self.now+=20
        req=(self.root/m.CHALLENGE_PATHS['request']).read_bytes();res=(self.root/m.CHALLENGE_PATHS['response']).read_bytes()
        for key,name in m.SINK_PATHS.items():(self.root/name).write_bytes(req if key in ('relay_request','origin_request') else res)
        for role in m.ROLES:
            row=o.tasks[role];self.rows[row['pid']].update(exited=True,exitcode=0);selected=role==m.ROLES[0];origin=role==m.ROLES[2]
            st=None if origin else prior.stream_state(selected);files=dict(source=prior.file_state(len(req) if selected else len(res),True) if selected or origin else None,
                request_sink=None if selected else prior.file_state(len(req)),response_sink=prior.file_state(len(res)))
            pipe=None if origin else dict(read_bytes=24*64+st['rx_payload_bytes'],write_bytes=24*64+st['tx_payload_bytes'],read_calls=333,write_calls=421,peek_calls=444,
                eof_observed=True,reader_close='confirmed',writer_close='confirmed',inheritance_cleared=True)
            net=None
            if not selected:
                net=dict(**dict.fromkeys(m.stream.NETWORK_FLAGS,False),port=O if origin else M,local_port=O if origin else 52001,peer_port=52002 if origin else M,
                    bytes_sent=len(res) if origin else len(req)+13,bytes_received=len(req) if origin else len(res)+12,socket_close='confirmed',listener_close='confirmed' if origin else 'not_attempted')
                net.update(dict.fromkeys(('wsa_startup','wsa_cleanup','socket_created','peer_loopback','send_shutdown'),True))
                net.update(dict.fromkeys(('listener_created','exclusive','bind_loopback','accepted') if origin else ('connect_attempted','connect_completed','receive_eof'),True))
            v=dict(schema_version=1,stage='lpac-stream-actor' if selected else 'lpac-stream-mihomo-http-actor',role='stream-front' if selected else 'stream-a2-origin' if origin else 'stream-a2-relay',
                run_id=c['run'],case_id=c['case'],pid=row['pid'],identity=prior.f.native_identity(row,c),qpc=[prior.F,prior.T if origin else pair['start'],m.work_cutoff(c) if origin else pair['end'],self.now],
                limits=dict(payload_max=1024,window=4096,total_max=65536,frames_max=256,request_bytes=len(req),response_bytes=len(res)),files=files,stream=st,pipe=pipe,network=net,
                admitted_qpc=None if origin else row['resume_intent_qpc'],read_handle_inherit_cleared=not origin,write_handle_inherit_cleared=not origin,failure=None,win32_error=None,wsa_error=None,
                selected_socket_api_tested=False,network_tested=not selected,proxy_tested=False,product_acceptance=False)
            if not selected:
                parsers={}
                for name,response in (('request',False),('response',True)):
                    total=12289 if response else 8193;header=m.canonical_header(response,c['case'],O,total)
                    parsers[name]=dict(configured=True,header_verified=True,header_bytes=len(header),body_bytes=total-len(header),total_bytes=total,expected_total_bytes=total,
                        content_length=total-len(header),message_complete=True,eof_observed=not origin,failure=None)
                adapter=dict.fromkeys(m.ORIGIN_ADAPTER if origin else m.RELAY_ADAPTER,True);adapter['request_eof_observed' if origin else 'request_fin_is_tcp_fin']=False
                socks=None if origin else dict(greeting_bytes_sent=3,method_bytes_received=2,connect_bytes_sent=10,reply_bytes_received=10,handshake_wire_sent=13,handshake_wire_received=12,
                    method_noauth_verified=True,reply_ipv4_loopback_listener_verified=True,handshake_complete=True,origin_dial_proven=False,failure=None)
                barrier=None
                if origin:
                    ack=m.decode(o.j['barrier_ack']['text'].encode());release=o.j['barrier_commands']['release']['issued_qpc']
                    barrier=dict(**dict.fromkeys(m.BARRIER_FLAGS,True),phase_issued_qpc=o.j['barrier_commands']['arm']['issued_qpc'],pair_start_qpc=pair['start'],pair_deadline_qpc=pair['end'],
                        ack_qpc=ack['qpc'][3],wait_deadline_qpc=ack['wait_deadline_qpc'],response_bytes_before_release=0,release_issued_qpc=release,release_admitted_qpc=release,response_started_qpc=release+1,failure=None)
                v.update(ports=c['ports'],socks=socks,http=dict(**parsers,adapter=adapter),message_boundary='deferred-shutdown-after-http-message-and-response-eof',
                    network_scope='ordinary-relay-to-held-mihomo-to-owned-origin-only',barrier=barrier)
            if self.fault=='selected-malformed' and selected:v['extra']=True
            key='selected' if selected else 'origin' if origin else 'relay';(self.root/m.REPORT_PATHS[key]).write_bytes(m.encode(v))
        self.origin_response_handle_held=False


class ComposedOwnerTests(unittest.TestCase):
    def owner(self,fault=None,physical=True):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);parent=Path(td.name).resolve();c=prior.config();c.update(scope=m.SCOPE,profile=m.PROFILE,ports=dict(origin_port=O,proxy_port=M),
            mihomo_sha256=m.MIHOMO_SHA256,mihomo_bytes=m.MIHOMO_BYTES,mihomo_bundle=m.bundle_name(c['run']))
        root=parent/m.stage_name(c['run']);root.mkdir();bundle=parent/m.bundle_name(c['run']);bundle.mkdir();(bundle/'mihomo.exe').write_bytes(b'inert-Mihomo-not-executable')
        for name in ('inputs','selected-inputs','ordinary-inputs','tools','guard','journal','returns','health','selected-report','relay-report','origin-report','origin-control','core-home','tcp',*m.CORE_ROLES):(root/name).mkdir()
        for name in ('health','relay-report','origin-report',*m.CORE_ROLES):(root/name/'temp').mkdir()
        for name,response in (('request',False),('response',True)):
            raw,header,body=independent_message(response);(root/m.CHALLENGE_PATHS[name]).write_bytes(raw)
        c['challenges']={name:dict(bytes=len((root/path).read_bytes()),sha256=m.sha((root/path).read_bytes())) for name,path in m.CHALLENGE_PATHS.items()}
        (root/'inputs'/m.ACTOR).write_bytes(b'x'*512);(root/'inputs'/m.NETWORK_ACTOR).write_bytes(b'b'*512)
        cfg=m.encode(m.mihomo_configuration(c['ports']));(root/'core-home/config.json').write_bytes(cfg);c['mihomo_config_sha256']=m.sha(cfg)
        c['source_hashes']=dict.fromkeys(m.SOURCES,prior.b.H);c['source_sha256']=m.sha(m.encode(c['source_hashes']));m.config_validate(c)
        tool=root/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool');api=ComposedAPI(root,fault);o=m.Owner(root,c,prior.b.PARENT,api,m.launcher.QpcBudget(api,prior.D,prior.F));api.owner=o
        bounded=m.local.bounded
        def closed(path,limit):
            if getattr(api,'origin_response_handle_held',False) and Path(path)==root/m.CHALLENGE_PATHS['response']:
                e=OSError('origin share0');e.winerror=32;raise e
            return bounded(path,limit)
        with patch.object(m,'verify_mihomo',side_effect=lambda path,digest:Path(path)),patch.object(m.local,'bounded',side_effect=closed):j=o.execute()
        m.validate_result(j,c,parent=prior.b.PARENT,root=root if physical else None);return o,api,j,m.project(j,c,parent=prior.b.PARENT,root=root if physical else None)
    def test_real_new_coordinator_composes_5_roles_barrier_rawTCP_and_explicit_core_stop(self):
        o,api,j,v=self.owner();self.assertIsNone(j['failure']);self.assertTrue(v['mechanism_verified']);self.assertTrue(v['finite_core_integration_observed']);self.assertTrue(v['kernel_tcp_snapshot_observed'])
        self.assertTrue(all(j[k] for k in m.CLEAN_KEYS));self.assertFalse(j['workload_stop']);self.assertFalse(api.killed);self.assertEqual(len(api.terminate_calls),1)
        self.assertEqual(api.resume_roles,[m.CORE_ROLES[0],m.ROLES[2],m.CORE_ROLES[1],m.ROLES[1],m.ROLES[0]])
        self.assertEqual(j['pair']['end']-j['pair']['start'],10*prior.F);self.assertEqual(set(j['physical_sinks']),set(m.SINK_PATHS));self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS))
    def test_lease_or_stdio_unknown_stops_before_protocol_and_retains_profile(self):
        for fault in ('lease-close','stdio-close'):
            with self.subTest(fault=fault):
                o,api,j,v=self.owner(fault);self.assertFalse(j['profile_deleted']);self.assertFalse(v['mechanism_verified']);self.assertNotIn(m.ROLES[0],api.resume_roles)
    def test_failed_explicit_core_stop_does_not_waive_Jobkill_or_qualify(self):
        _,api,j,v=self.owner('stop-false');self.assertTrue(j['core_integration_observed']);self.assertFalse(v['mechanism_verified']);self.assertTrue(j['workload_stop']);self.assertEqual(len(api.terminate_calls),1)
    def test_new_stdio_alias_never_enters_Create_or_closes_original_owner_early(self):
        _,api,j,v=self.owner('stdio-alias');self.assertTrue(api.controls_uncertain);self.assertFalse(j['profile_deleted']);self.assertFalse(v['mechanism_verified'])
        self.assertFalse(getattr(api,'captured_roles',[]));self.assertFalse(getattr(api,'early_job_close',False))
    def test_changed_configuration_after_configcheck_exit_stops_every_runtime_role(self):
        o,api,j,v=self.owner('config-after-check',physical=False);self.assertEqual(api.resume_roles,[m.CORE_ROLES[0]]);self.assertFalse(v['mechanism_verified'])
        self.assertEqual(j['failure'],'core-check')
        with self.assertRaisesRegex(ValueError,'a2_frozen_core_config'):m.validate_result(j,o.c,parent=prior.b.PARENT,root=o.root)
    def test_raw_close_cleanup_option_or_QPC_cannot_be_overridden_by_confirmed_flags(self):
        o,api,j,v=self.owner()
        for change in ('close','cleanup','exclusive','bind','endpoint','clock','delete'):
            bad=copy.deepcopy(j);lease=bad['port_lease']
            if change=='close':lease['closes'][0]['value']=[-1,10038]
            elif change=='cleanup':lease['calls'][-1]['value']=[-1,10093]
            elif change=='exclusive':next(r for r in lease['calls'] if r['operation']=='read-exclusive-origin_port')['value']=[0,0,0,4]
            elif change=='bind':next(r for r in lease['calls'] if r['operation']=='bind-proxy_port')['value']=[-1,10048]
            elif change=='endpoint':next(r for r in lease['calls'] if r['operation']=='name-proxy_port')['value']=[0,0,dict(family=2,port=M+1,address='7f000001',size=16)]
            elif change=='clock':lease['calls'][1]['return_qpc']=None
            else:bad.update(failure='cleanup',port_leases_closed=False);lease['unknown']=True
            with self.subTest(change=change),self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=prior.b.PARENT,root=o.root)
    def test_physical_TCP_wrong_owner_or_backdated_response_cannot_qualify(self):
        o,api,j,v=self.owner();bad=copy.deepcopy(j);raw=(o.root/'tcp/two-hop.bin').read_bytes();rows=m.zero.tcp_rows(raw)
        rows[-1]['pid']+=1000
        def wire(row):return (row['state'],'.'.join(str(x) for x in bytes.fromhex(row['local_address'])),row['local_port'],'.'.join(str(x) for x in bytes.fromhex(row['remote_address'])),row['remote_port'],row['pid'])
        changed=tcp_raw([wire(r) for r in rows]);(o.root/'tcp/two-hop.bin').write_bytes(changed);bad['tcp']['two_hop'].update(bytes=len(changed),sha256=m.sha(changed))
        with self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=prior.b.PARENT,root=o.root)
        (o.root/'tcp/two-hop.bin').write_bytes(raw);bad=copy.deepcopy(j);native=m.decode(bad['reports']['origin']['text'].encode());native['barrier']['response_started_qpc']=native['barrier']['release_issued_qpc']-1
        raw=m.encode(native);bad['reports']['origin']=dict(text=raw.decode(),sha256=m.sha(raw));(o.root/m.REPORT_PATHS['origin']).write_bytes(raw)
        with self.assertRaises(ValueError):m.validate_result(bad,o.c,parent=prior.b.PARENT,root=o.root)

if __name__=='__main__':unittest.main()
