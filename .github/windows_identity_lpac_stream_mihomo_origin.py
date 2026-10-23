"""WORK-only A2 finite HTTP-message adapter through a held fixed Mihomo.

The selected RPS1 actor and the successful A-min resource primitives are
immutable dependencies. This separate scope does not grant application,
transparent-FIN, remote-proxy, DNS or product qualification.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
from pathlib import Path
import struct
import subprocess

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('a2_immutable_stream',Path(__file__).with_name('windows_identity_lpac_stream_origin.py'))
stream=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(stream)
legacy,zero,base,cell,access=stream.legacy,stream.zero,stream.base,stream.cell,stream.access
launcher,helpers,live,local=stream.launcher,stream.helpers,stream.live,stream.local
require,sha,encode,decode=stream.require,stream.sha,stream.encode,stream.decode

SCOPE='one-local-semantic-lpac-inherited-stream-mihomo-http-message-v1'
PROFILE='zero-cap-lpac-RPS1-fixed-SOCKS5-Mihomo-owned-HTTP-v1'
MODULE='.github/windows_identity_lpac_stream_mihomo_origin.py'
LOCAL_MODULE='.github/windows_identity_lpac_stream_mihomo_origin_local.py'
ACTUAL_READY=True
ACTOR,MANIFEST=stream.ACTOR,stream.MANIFEST
NETWORK_ACTOR='windows_identity_lpac_stream_mihomo_network_actor.exe'
NETWORK_MANIFEST='identity-lpac-stream-mihomo-network-manifest.json'
MIHOMO_VERSION='v1.19.32'
MIHOMO_BYTES=61276672
MIHOMO_SHA256='04f8d7fc2b314771e1ecbf15951d59f0e1cb7914503c88cfb6972ff6a824e314'
MIHOMO_ARCHIVE_SHA256='974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0'
MAX_MIHOMO=64*1024*1024
MAX_NATIVE=32768
MAX_REPORT=2*1024*1024
BARRIER_PATHS={'arm':'origin-control/phase.bin','ack':'origin-report/request-held.json','release':'origin-control/response-go.bin'}
NATIVE_SOURCES=stream.NATIVE_SOURCES
NETWORK_SOURCES={
 'actorSourceSha256':'.github/native/windows_identity_lpac_stream_mihomo_network_actor.cpp',
 'httpContractSha256':'.github/native/windows_identity_lpac_stream_mihomo_http.hpp',
 'networkBaseSourceSha256':'.github/native/windows_identity_lpac_stream_network_actor.cpp',
 'streamContractSha256':'.github/native/windows_identity_lpac_stream_contract.hpp',
 'identitySourceSha256':'.github/native/windows_identity_actor.cpp'}
SOURCES=tuple(dict.fromkeys((*stream.SOURCES,*NETWORK_SOURCES.values(),MODULE,LOCAL_MODULE)))
NONCES=('run','case')
ROLES=stream.ROLES
CORE_ROLES=('mihomo-config-check','mihomo-core')
CHALLENGE_PATHS=stream.CHALLENGE_PATHS
SINK_PATHS=stream.SINK_PATHS
REPORT_PATHS=stream.REPORT_PATHS
FALSE_CLAIMS=tuple(dict.fromkeys((*(k for k in stream.FALSE_CLAIMS if k not in ('core_mihomo_integration','kernel_tcp_snapshot_observed')),
 'transparent_TCP_FIN','concurrent_full_duplex','unmodified_application_support','browser_support',
 'remote_selected_proxy_qualification','PSEC_G','DNS_isolation','release_reproducible_build',
 'all_incidental_external_activity_excluded','mihomo_binary_exact_tag_source_proven','mihomo_listener_exclusivity_verified')))
ACKS=(*stream.ACKS,'real_mihomo_ordinary_core_acknowledged','finite_HTTP_message_adapter_acknowledged',
 'controlled_core_stop_acknowledged','initial_download_source_review_acknowledged')

def api_version():return 1
def stage_name(run):return 'local-lpac-stream-mihomo-origin-'+run
def bundle_name(run):
    require(base.ac.nonce(run),'a2_bundle_nonce');return 'mihomo-a2-private-bundle-'+run
work_cutoff=stream.work_cutoff
owned_tree=stream.owned_tree
GRANTS=stream.GRANTS
CLEAN_KEYS=(*stream.CLEAN_KEYS,'port_leases_closed','core_stdio_closed')
TASK_KEYS=stream.TASK_KEYS
info_values,task_projection=legacy.info_values,legacy.task_projection
record_value=legacy.record_value

def ports(value):
    require(type(value) is dict and set(value)=={'origin_port','proxy_port'}
        and all(base.ac.integer(v,49153,65535) for v in value.values())
        and value['origin_port']!=value['proxy_port'],'a2_distinct_fixed_ports')
    return value

def canonical_header(response,case,origin_port,total):
    require(type(response) is bool and base.ac.nonce(case) and base.ac.integer(origin_port,49153,65535)
        and base.ac.integer(total,1,65536),'a2_HTTP_header_parameters')
    body=total
    for _ in range(8):
        if response:
            text='HTTP/1.1 200 OK\r\nContent-Length: '+str(body)+'\r\nConnection: close\r\nX-RuleProxy-Case: '+case+'\r\n\r\n'
        else:
            text='POST /ruleproxy-a2/'+case+' HTTP/1.1\r\nHost: 127.0.0.1:'+str(origin_port)+'\r\nContent-Length: '+str(body)+'\r\nConnection: close\r\n\r\n'
        raw=text.encode('ascii');require(len(raw)<=512 and len(raw)<total,'a2_HTTP_header_bound')
        following=total-len(raw)
        if following==body:return raw
        body=following
    raise ValueError('a2_HTTP_length_fixed_point')

def http_challenge(raw,*,response,case,origin_port):
    total=12289 if response else 8193
    require(type(raw) is bytes and len(raw)==total,'a2_HTTP_exact_payload_length')
    header=canonical_header(response,case,origin_port,total)
    require(raw.startswith(header),'a2_HTTP_canonical_prefix')
    body=raw[len(header):]
    require(set(body)==set(range(256)) and b'RPS1' in body,'a2_independent_binary_body')
    return dict(bytes=total,sha256=sha(raw))

def build_challenge(body,*,response,case,origin_port):
    """Use caller-supplied independent bytes; never generate bytes from nonce."""
    total=12289 if response else 8193;header=canonical_header(response,case,origin_port,total)
    require(type(body) is bytes and len(body)==total-len(header),'a2_body_input_length')
    raw=header+body;http_challenge(raw,response=response,case=case,origin_port=origin_port);return raw

def challenge_inputs(request,response,expected,*,case,origin_port):
    rows={}
    for name,path,is_response in (('request',request,False),('response',response,True)):
        raw=local.bounded(launcher.checked_path(path),65536)
        rows[name]=http_challenge(raw,response=is_response,case=case,origin_port=origin_port)
    stream.challenge_meta(expected);require(rows==expected,'a2_actual_HTTP_challenge_pins');return rows

def request_before_pair_resume(path,expected,*,case,origin_port):
    # The live origin holds response.bin with share0. Pin both inputs before
    # origin Resume and after exit; only request can be reopened at this gate.
    raw=local.bounded(launcher.checked_path(path),65536)
    value=http_challenge(raw,response=False,case=case,origin_port=origin_port)
    require(value==stream.challenge_meta(expected)['request'],'a2_selected_request_changed');return value

def verify_mihomo(path,digest):
    path=launcher.checked_path(path)
    require(path.name=='mihomo.exe' and digest==MIHOMO_SHA256,'a2_fixed_Mihomo_name_and_pin')
    raw=local.bounded(path,MAX_MIHOMO)
    require(len(raw)==MIHOMO_BYTES and sha(raw)==MIHOMO_SHA256,'a2_fixed_Mihomo_large_input')
    return path


def exact_listeners(raw,*,proxy_pid,origin_pid,declared):
    """A raw owner-PID table establishes ownership, not socket options."""
    declared=ports(declared);rows=zero.tcp_rows(raw);result={}
    require(type(proxy_pid) is type(origin_pid) is int and 0<proxy_pid<1<<32
        and 0<origin_pid<1<<32 and proxy_pid!=origin_pid,'a2_listener_pids')
    for name,pid,key in (('proxy',proxy_pid,'proxy_port'),('origin',origin_pid,'origin_port')):
        matches=[r for r in rows if r['state']==2 and r['local_port']==declared[key]]
        require(len(matches)==1 and matches[0]['pid']==pid and matches[0]['local_address']=='7f000001'
            and matches[0]['ports_canonical'],'a2_exact_owned_listener')
        result[name]=matches[0]
    return result

def exact_two_hop(raw,*,relay_pid,proxy_pid,origin_pid,declared,origin_peer_port):
    """Require both directions of both established loopback connections.

    The request-held barrier makes this one successful table sample meaningful;
    neither a SOCKS BND reply nor a self-reported peer substitutes for a row.
    """
    declared=ports(declared);listeners=exact_listeners(raw,proxy_pid=proxy_pid,origin_pid=origin_pid,declared=declared)
    require(type(relay_pid) is int and 0<relay_pid<1<<32 and len({relay_pid,proxy_pid,origin_pid})==3
        and base.ac.integer(origin_peer_port,1,65535),'a2_two_hop_pids_or_port')
    rows=zero.tcp_rows(raw);loop='7f000001';M,O=declared['proxy_port'],declared['origin_port']
    def one(pid,local_port=None,remote_port=None):
        values=[r for r in rows if r['pid']==pid and (local_port is None or r['local_port']==local_port)
            and (remote_port is None or r['remote_port']==remote_port) and r['state']!=2]
        require(len(values)==1,'a2_exact_tcp_row')
        r=values[0];require(r['state']==5 and r['ports_canonical']
            and r['local_address']==r['remote_address']==loop and 0<r['local_port']<=65535
            and 0<r['remote_port']<=65535,'a2_established_loopback_row');return r
    relay=one(relay_pid,remote_port=M)
    proxy_in=one(proxy_pid,local_port=M,remote_port=relay['local_port'])
    proxy_out=one(proxy_pid,local_port=origin_peer_port,remote_port=O)
    origin=one(origin_pid,local_port=O,remote_port=origin_peer_port)
    require(relay['local_port'] not in (M,O) and origin_peer_port not in (M,O),'a2_endpoint_port_alias')
    return dict(listeners=listeners,relay=relay,proxy_in=proxy_in,proxy_out=proxy_out,origin=origin)

def tcp_record(raw,rows,*,name,before_qpc,after_qpc):
    require(type(raw) is bytes and 4<=len(raw)<=1048576 and name in ('listeners.bin','two-hop.bin')
        and base.ac.integer(before_qpc,1,(1<<63)-1) and base.ac.integer(after_qpc,before_qpc,(1<<63)-1),'a2_TCP_capture')
    return dict(name=name,bytes=len(raw),sha256=sha(raw),before_qpc=before_qpc,after_qpc=after_qpc,rows=rows)

def validate_tcp_record(v,*,root,expected_rows):
    require(type(v) is dict and set(v)=={'name','bytes','sha256','before_qpc','after_qpc','rows'}
        and v['name'] in ('listeners.bin','two-hop.bin'),'a2_TCP_record_schema')
    raw=local.bounded(launcher.checked_path(Path(root)/'tcp'/v['name'],inside=root),1048576)
    require(tcp_record(raw,expected_rows,name=v['name'],before_qpc=v['before_qpc'],after_qpc=v['after_qpc'])==v,
        'a2_TCP_physical_record');return raw


def creation_rights(state,pending,*,end):
    """Cleanup authority follows physical success, separately from admission."""
    v=state.get('raw_pi');returned=state.get('create_status')=='returned_true'
    complete=(type(v) is list and len(v)==4 and all(type(x) is int and 0<x<(1<<64 if i<2 else 1<<32)
        for i,x in enumerate(v)) and v[0]!=v[1] and not any(h in pending for h in v[:2]))
    known=returned and type(state.get('raw_return')) is int and state['raw_return']!=0 and complete
    tick=state.get('returned_qpc');timely=type(tick) is int and tick<end
    none=(state.get('create_status')=='returned_false' and state.get('raw_return')==0
        and type(state.get('raw_error')) is int and state['raw_error']>0 and type(v) is list and v==[0,0,0,0] and timely)
    return dict(known_success=bool(known),known_no_child=bool(none),unknown=not known and not none,timely=timely)

class API(stream.API):
    """New ordinary roles use captured returns; immutable legacy tools do not."""
    tcp_snapshot=zero.API.tcp_snapshot
    def lease_backend(self):return LeaseBackend()

    def captured_spawn(self,info,argv,cwd,environment,job,owners,state,*,role,ends,other_pending,
            profile_pointer,budget,end,on_return):
        selected=role=='lpac-pipe-front';core=role in CORE_ROLES;pair=role in ROLES[:2]
        expected=ACTOR if selected else 'mihomo.exe' if core else NETWORK_ACTOR
        require(Path(argv[0]).name==expected and job and (selected==bool(profile_pointer)),'a2_constructor_role')
        require(role in (*ROLES,*CORE_ROLES) and type(environment) is str and environment.endswith('\0\0'),'a2_constructor_environment')
        if selected:require({p.split('=',1)[0] for p in environment.rstrip('\0').split('\0')}=={'SystemRoot','LOCALAPPDATA'},'a2_selected_environment')
        ends=tuple(ends);count=3 if core else 2 if pair else 0
        require(len(ends)==count and len(set(ends))==count and all(type(h) is int and 0<h<1<<64 and h in other_pending for h in ends),'a2_exact_inherited_handles')
        for h in ends:
            require(self.pipe_flags(h)&1==1,'a2_inherited_handle_readback')
            if pair:require(self.pipe_type(h)==3,'a2_pair_pipe_type')
        state.update(create_status='not_entered',create_winerror=None,create_information='not_observed',create_exception_detail=None,returned_qpc=None)
        values=[];jobs=(C.c_void_p*1)(job);values.append((base.JOB_LIST,jobs))
        if count:handles=(C.c_void_p*count)(*ends);values.append((0x20002,handles))
        if selected:
            caps=self.proc._SecurityCapabilities(profile_pointer,None,0,0);aap=C.c_uint32(1)
            values.extend(((base.SECURITY_CAPABILITIES,caps),(base.ALL_APPLICATION_PACKAGES_POLICY,aap)))
        size=C.c_size_t();self.k.InitializeProcThreadAttributeList(None,len(values),0,C.byref(size));require(1<=size.value<=65536,'a2_attribute_size')
        attrs=C.create_string_buffer(size.value);self.native.check(self.k.InitializeProcThreadAttributeList(attrs,len(values),0,C.byref(size)),'InitializeProcThreadAttributeList(A2)')
        try:
            for kind,value in values:self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,kind,C.byref(value),C.sizeof(value),None,None),'UpdateProcThreadAttribute(A2)')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,C.c_void_p)
            if core:
                startup.StartupInfo.dwFlags|=0x100
                startup.StartupInfo.hStdInput,startup.StartupInfo.hStdOutput,startup.StartupInfo.hStdError=ends
            command=C.create_unicode_buffer(subprocess.list2cmdline(argv));env=C.create_unicode_buffer(environment);raw_info=self.process_info()
            budget.require_ms(end);state['creation_attempted']=True;physical_error=clock_error=receipt_error=None
            try:
                ok=self.k.CreateProcessW(argv[0],command,None,None,bool(count),self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT|0x08000000,env,str(cwd),C.byref(startup),C.byref(raw_info))
                error=0 if ok else C.get_last_error()
                state.update(create_status='returned_true' if ok else 'returned_false',create_winerror=None if ok else error,raw_return=int(ok),raw_error=None if ok else error)
            except BaseException as e:
                physical_error=e;state.update(create_status='exception',raw_return=None,raw_error=None,create_exception_detail=base.private_failure_detail(e,'CreateProcessW(A2)'))
            state['raw_pi']=legacy.info_values(raw_info);state['create_information']='nonzero' if any(state['raw_pi']) else 'all_zero'
            try:state['returned_qpc']=budget.read()
            except BaseException as e:clock_error=e
            try:on_return(state.copy())
            except BaseException as e:receipt_error=e;self.controls_uncertain=True
            rights=creation_rights(state,set(owners.pending)|set(other_pending),end=end);state['creation_unknown']=rights['unknown']
            if rights['known_success']:
                info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId=state['raw_pi']
                for h in state['raw_pi'][:2]:owners.add(h)
            if physical_error is not None:raise physical_error
            if clock_error is not None:raise clock_error
            if receipt_error is not None:raise receipt_error
            if not state['raw_return']:raise launcher.NativeFailure('CreateProcessW(A2)',state['raw_error'])
            require(rights['known_success'],'a2_unknown_process_outputs');budget.require_ms(end)
        finally:
            try:self.k.DeleteProcThreadAttributeList(attrs)
            except BaseException:self.controls_uncertain=True;raise

    def terminate_core(self,process,budget,end,on_return):
        """Only the owner may route its exact admitted core handle here."""
        self.k.TerminateProcess.argtypes=[C.c_void_p,C.c_uint32];self.k.TerminateProcess.restype=C.c_int
        budget.require_ms(end);r=dict(attempted=True,returned=False,raw_return=None,error=None,returned_qpc=None,exception=None)
        caught=None
        try:
            ok=self.k.TerminateProcess(process,1);error=0 if ok else C.get_last_error()
            r.update(returned=True,raw_return=int(ok),error=error)
        except BaseException as e:caught=e;r['exception']=base.private_failure_detail(e,'TerminateProcess(A2core)')
        clock_error=None
        try:r['returned_qpc']=budget.read()
        except BaseException as e:clock_error=e
        on_return(r.copy())
        if caught is not None:raise caught
        if clock_error is not None:raise clock_error
        require(r['returned'] and r['raw_return']!=0 and r['error']==0,'a2_controlled_stop_failed');budget.require_ms(end)
        return r


class LeaseBackend:
    """Two bound-only Winsock leases, with no connect, send, or accept API."""
    class Address(C.Structure):
        _fields_=[('family',C.c_uint16),('port',C.c_uint16),('address',C.c_ubyte*4),('zero',C.c_ubyte*8)]
    INVALID=(1<<(C.sizeof(C.c_void_p)*8))-1
    def __init__(self):
        self.w=C.WinDLL('ws2_32.dll',use_last_error=True,winmode=0x800)
        for name,args,result in (
            ('WSAStartup',[C.c_uint16,C.c_void_p],C.c_int),('WSACleanup',[],C.c_int),('WSAGetLastError',[],C.c_int),
            ('socket',[C.c_int,C.c_int,C.c_int],C.c_size_t),('closesocket',[C.c_size_t],C.c_int),
            ('setsockopt',[C.c_size_t,C.c_int,C.c_int,C.c_void_p,C.c_int],C.c_int),
            ('getsockopt',[C.c_size_t,C.c_int,C.c_int,C.c_void_p,C.POINTER(C.c_int)],C.c_int),
            ('bind',[C.c_size_t,C.c_void_p,C.c_int],C.c_int),
            ('getsockname',[C.c_size_t,C.c_void_p,C.POINTER(C.c_int)],C.c_int)):
            fn=getattr(self.w,name);fn.argtypes=args;fn.restype=result
    def startup(self):
        self.data=C.create_string_buffer(512);status=int(self.w.WSAStartup(0x202,self.data))
        return status, status
    def make(self):
        value=int(self.w.socket(2,1,6));return value,(int(self.w.WSAGetLastError()) if value==self.INVALID else 0)
    def exclusive(self,h):
        yes=C.c_int(1);status=int(self.w.setsockopt(h,0xffff,-5,C.byref(yes),C.sizeof(yes)))
        return status,(int(self.w.WSAGetLastError()) if status!=0 else 0)
    def exclusive_read(self,h):
        value=C.c_int();size=C.c_int(C.sizeof(value));status=int(self.w.getsockopt(h,0xffff,-5,C.byref(value),C.byref(size)))
        error=int(self.w.WSAGetLastError()) if status!=0 else 0
        return status,error,int(value.value),int(size.value)
    def bind(self,h,port):
        value=self.Address();value.family=2;value.port=int.from_bytes(port.to_bytes(2,'big'),'little');value.address[:]=(127,0,0,1)
        status=int(self.w.bind(h,C.byref(value),C.sizeof(value)));return status,(int(self.w.WSAGetLastError()) if status!=0 else 0)
    def name(self,h):
        value=self.Address();size=C.c_int(C.sizeof(value));status=int(self.w.getsockname(h,C.byref(value),C.byref(size)))
        error=int(self.w.WSAGetLastError()) if status!=0 else 0
        return status,error,dict(family=int(value.family),port=int.from_bytes(value.port.to_bytes(2,'little'),'big'),address=bytes(value.address).hex(),size=int(size.value))
    def close(self,h):
        status=int(self.w.closesocket(h));return status,(int(self.w.WSAGetLastError()) if status!=0 else 0)
    def cleanup(self):
        status=int(self.w.WSACleanup());return status,(int(self.w.WSAGetLastError()) if status!=0 else 0)


class PortLeases:
    """Live, separate once ledger. SOCKET zero is valid; failed outputs aren't."""
    def __init__(self,backend,budget,end,declared):
        self.backend,self.budget,self.end=backend,budget,end;self.declared=ports(declared)
        self.started=False;self.cleanup_attempted=False;self.cleanup_confirmed=False;self.unknown=False
        self.pending={};self.calls=[];self.closed=[]
    def call(self,name,fn):
        self.budget.require_ms(self.end);r=dict(operation=name,returned=False,value=None,return_qpc=None,exception=False)
        try:r['value']=fn();r['returned']=True
        except BaseException:r['exception']=True;self.unknown=True;raise
        finally:
            try:r['return_qpc']=self.budget.read()
            except BaseException:self.unknown=True
            self.calls.append(r)
        return r['value']
    def clock_gate(self):
        require(self.calls and not self.unknown and type(self.calls[-1]['return_qpc']) is int,'a2_lease_return_clock_unknown')
        self.budget.require_ms(self.end)
    def acquire(self):
        try:
            status,error=self.call('startup',self.backend.startup)
            require(type(status) is type(error) is int and status==error==0,'a2_lease_WSAStartup');self.started=True
            self.clock_gate()
            for key in ('origin_port','proxy_port'):
                value,error=self.call('socket-'+key,self.backend.make)
                valid=type(value) is int and 0<=value<self.backend.INVALID and type(error) is int and error==0
                if not valid:
                    # Only the documented INVALID_SOCKET is a known failed
                    # return; contradictory success-shaped outputs stay unknown.
                    self.unknown |= value!=self.backend.INVALID
                    raise ValueError('a2_lease_socket')
                if value in self.pending:self.unknown=True;raise ValueError('a2_lease_socket_alias')
                self.pending[value]=key
                self.clock_gate()
                for operation,fn in (('exclusive',lambda:self.backend.exclusive(value)),('bind',lambda:self.backend.bind(value,self.declared[key]))):
                    status,error=self.call(operation+'-'+key,fn);require(type(status) is type(error) is int and status==error==0,'a2_lease_'+operation);self.clock_gate()
                status,error,enabled,size=self.call('read-exclusive-'+key,lambda:self.backend.exclusive_read(value))
                require((status,error,enabled,size)==(0,0,1,4),'a2_lease_exclusive_readback')
                self.clock_gate()
                status,error,address=self.call('name-'+key,lambda:self.backend.name(value))
                require(status==error==0 and address==dict(family=2,port=self.declared[key],address='7f000001',size=16),'a2_lease_exact_bound_endpoint');self.clock_gate()
            return self
        except BaseException:
            self.close_all();raise
    def release(self,key):
        values=[h for h,k in self.pending.items() if k==key];require(len(values)==1,'a2_lease_release_once')
        h=values[0];del self.pending[h];r=dict(port_key=key,attempted=True,confirmed=False,value=None,return_qpc=None,exception=False);self.closed.append(r)
        try:
            r['value']=self.backend.close(h);r['return_qpc']=self.budget.read()
            require(r['value']==(0,0),'a2_lease_close');r['confirmed']=True
        except BaseException:r['exception']=True;self.unknown=True;raise
    def close_all(self):
        # Independently consume every known socket even after one uncertain close.
        for key in list(self.pending.values()):
            try:self.release(key)
            except BaseException:pass
        if self.started and not self.cleanup_attempted:
            self.cleanup_attempted=True
            r=dict(operation='cleanup',returned=False,value=None,return_qpc=None,exception=False);self.calls.append(r)
            try:
                r['value']=self.backend.cleanup();r['returned']=True
                r['return_qpc']=self.budget.read();require(r['value']==(0,0),'a2_lease_WSACleanup');self.cleanup_confirmed=True
            except BaseException:r['exception']=True;self.unknown=True
    @property
    def confirmed_closed(self):
        return not self.pending and not self.unknown and (not self.started or self.cleanup_confirmed) and all(r['confirmed'] for r in self.closed)


def barrier_control(c,pair,issued,*,release=False,ack=None):
    """Independent M2B1 tickets never reuse the selected actor's RPS1 bytes."""
    declared=ports(c['ports']);F,T,D=c['frequency'],c['start_qpc'],stream.work_cutoff(c);S,E=pair['start'],pair['end']
    require(base.ac.nonce(c['run']) and base.ac.nonce(c['case']) and c['run']!=c['case']
        and base.ac.integer(F,1,(1<<63)-1) and D==T+85*F and E==S+10*F and T<=S<=issued<E<=D,'a2_barrier_original_clock')
    ack_tick=pid=peer=0
    if release:
        require(type(ack) is dict,'a2_release_requires_ACK');ack_tick=ack['qpc'][3];pid=ack['pid'];peer=ack['peer_port']
        require(ack_tick<=issued<min(E,ack_tick+2*F) and base.ac.integer(pid,1,0xffffffff)
            and base.ac.integer(peer,1,65535),'a2_release_ACK_clock')
    else:require(ack is None,'a2_arm_has_no_ACK')
    # In the wire layout issued is at 88, after the four u16 endpoints/lengths.
    raw=struct.pack('<4sHBB16s16s5Q4H2QI H18s',b'M2B1',1,2 if release else 1,0,bytes.fromhex(c['run']),bytes.fromhex(c['case']),
        F,T,D,S,E,declared['origin_port'],declared['proxy_port'],8193,12289,issued,ack_tick,pid,peer,bytes(18))
    require(len(raw)==128,'a2_barrier_ticket_size');return raw

ACK_KEYS={'schema_version','stage','role','run_id','case_id','pid','qpc','pair_qpc','ports','accepted_count','local_port','peer_port','peer_loopback',
    'request_bytes','request_message_complete','request_eof_observed','response_bytes_sent','socket_held','phase_command_close_verified','phase_issued_qpc','wait_deadline_qpc','failure'}
BARRIER_KEYS={'phase_admitted','phase_command_closed','phase_issued_qpc','pair_start_qpc','pair_deadline_qpc','request_held_ack_published','ack_qpc',
    'wait_deadline_qpc','response_bytes_before_release','socket_held_at_ack','release_attempted','release_admitted','release_command_closed','release_issued_qpc',
    'release_admitted_qpc','response_started_qpc','failure'}
BARRIER_FLAGS={'phase_admitted','phase_command_closed','request_held_ack_published','socket_held_at_ack','release_attempted','release_admitted','release_command_closed'}

def validate_ack(v,c,pair,*,origin_pid,arm_issued):
    require(type(v) is dict and set(v)==ACK_KEYS and type(v['schema_version']) is int and v['schema_version']==1
        and v['stage']=='lpac-stream-mihomo-origin-request-held' and v['role']=='stream-a2-origin' and v['run_id']==c['run'] and v['case_id']==c['case']
        and type(v['pid']) is int and v['pid']==origin_pid,'a2_ACK_identity')
    q=v['qpc'];F=c['frequency'];S,E=pair['start'],pair['end']
    require(type(q) is list and len(q)==4 and q[:3]==[F,c['start_qpc'],stream.work_cutoff(c)]
        and base.ac.integer(q[3],arm_issued,E-1) and v['pair_qpc']==[S,E] and v['ports']==c['ports'],'a2_ACK_epoch')
    require(v['accepted_count']==1 and type(v['accepted_count']) is int and v['local_port']==c['ports']['origin_port']
        and base.ac.integer(v['peer_port'],1,65535) and v['peer_loopback'] is True and type(v['request_bytes']) is int and v['request_bytes']==8193
        and v['request_message_complete'] is True and type(v['request_eof_observed']) is bool and type(v['response_bytes_sent']) is int
        and v['response_bytes_sent']==0 and v['socket_held'] is True and v['phase_command_close_verified'] is True
        and type(v['phase_issued_qpc']) is int and v['phase_issued_qpc']==arm_issued and v['wait_deadline_qpc']==min(E,q[3]+2*F)
        and v['failure'] is None,'a2_ACK_held_zero_response');return v

def validate_barrier(v,c,pair):
    require(type(v) is dict and set(v)==BARRIER_KEYS and all(type(v[k]) is bool for k in BARRIER_FLAGS)
        and v['failure'] in (None,'phase','ack','release','deadline','qpc','close'),'a2_barrier_shape')
    for k in BARRIER_KEYS-BARRIER_FLAGS-{'failure','response_bytes_before_release'}:
        require(v[k] is None or base.ac.integer(v[k],0,c['root_deadline_qpc']+c['frequency']),'a2_barrier_clock_type')
    require(v['response_bytes_before_release'] is None or type(v['response_bytes_before_release']) is int and v['response_bytes_before_release']==0,'a2_no_response_before_release')
    if v['phase_admitted']:
        require(v['phase_command_closed'] and v['pair_start_qpc']==pair['start'] and v['pair_deadline_qpc']==pair['end']
            and base.ac.integer(v['phase_issued_qpc'],pair['start'],pair['end']-1),'a2_phase_admission')
    if v['request_held_ack_published']:
        require(v['phase_admitted'] and v['socket_held_at_ack'] and type(v['response_bytes_before_release']) is int and v['response_bytes_before_release']==0
            and base.ac.integer(v['ack_qpc'],v['phase_issued_qpc'],pair['end']-1)
            and v['wait_deadline_qpc']==min(pair['end'],v['ack_qpc']+2*c['frequency']),'a2_barrier_ACK')
    if v['release_admitted']:
        require(v['request_held_ack_published'] and v['release_attempted'] and v['release_command_closed']
            and base.ac.integer(v['release_issued_qpc'],v['ack_qpc'],v['wait_deadline_qpc']-1)
            and base.ac.integer(v['release_admitted_qpc'],v['release_issued_qpc'],v['wait_deadline_qpc']-1),'a2_release_admission')
    if v['response_started_qpc'] is not None:
        require(v['release_admitted'] and base.ac.integer(v['response_started_qpc'],v['release_admitted_qpc'],pair['end']-1),'a2_response_after_release')
    return v


def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','profile',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name','source_hashes','source_sha256','device_sha256',
        'actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256','recovery_plan_sha256','challenges','ports','mihomo_sha256','mihomo_bytes','mihomo_bundle','mihomo_config_sha256'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1 and c['scope']==SCOPE and c['profile']==PROFILE,'a2_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and c['run']!=c['case'],'a2_nonces');live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']==r'Local\RuleProxy.LocalGuard.'+c['run'],'a2_original_epoch')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names) and all(base.ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'a2_sources')
    require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')) and c['mihomo_sha256']==MIHOMO_SHA256 and type(c['mihomo_bytes']) is int
        and c['mihomo_bytes']==MIHOMO_BYTES and c['mihomo_bundle']==bundle_name(c['run']),'a2_fixed_core_binding')
    ports(c['ports']);stream.challenge_meta(c['challenges']);return c

def validate_plan(p,*,device,source,actor,manifest,network_actor,network_manifest,challenges,declared,configuration):
    keys={'schema_version','scope','profile',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256',
        'recovery_reference','challenges','ports','mihomo_sha256','mihomo_bytes','mihomo_bundle','mihomo_config_sha256',*ACKS}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1 and p['scope']==SCOPE and p['profile']==PROFILE,'a2_plan')
    require(all(p[k] is True for k in ACKS) and all(base.ac.nonce(p[k]) for k in NONCES) and p['run']!=p['case'],'a2_plan_ack')
    require([p[k] for k in ('device_sha256','source_sha256','actor_sha256','manifest_sha256','network_actor_sha256','network_manifest_sha256')]
        ==[device,source,actor,manifest,network_actor,network_manifest],'a2_plan_binding')
    require(p['challenges']==stream.challenge_meta(challenges) and p['ports']==ports(declared) and p['mihomo_sha256']==MIHOMO_SHA256
        and type(p['mihomo_bytes']) is int and p['mihomo_bytes']==MIHOMO_BYTES and p['mihomo_bundle']==bundle_name(p['run'])
        and p['mihomo_config_sha256']==sha(configuration),'a2_plan_inputs')
    require(type(p['recovery_reference']) is str and 1<=len(p['recovery_reference'])<=512 and not any(x in p['recovery_reference'] for x in '\r\n\0'),'a2_recovery_reference');return p

def verify_actor(actor,manifest,ah,mh,*,root,network=False):
    if not network:return stream.verify_actor(actor,manifest,ah,mh,root=root)
    actor,manifest=launcher.checked_path(actor),launcher.checked_path(manifest)
    require(actor.name==NETWORK_ACTOR and manifest.name==NETWORK_MANIFEST and actor.parent==manifest.parent,'a2_network_artifact_name')
    raw=local.bounded(manifest,8192);v=decode(raw.removeprefix(b'\xef\xbb\xbf'))
    require(type(v) is dict and set(v)=={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','executableSha256',*NETWORK_SOURCES}
        and type(v['schemaVersion']) is int and v['schemaVersion']==1 and type(v['interfaceVersion']) is int and v['interfaceVersion']==2
        and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['executableSha256']==ah and sha(raw)==mh,'a2_network_manifest')
    require(base.ac.digest(ah) and base.ac.digest(mh) and sha(local.bounded(actor,8*1024*1024))==ah,'a2_network_artifact_hash')
    for k,file in NETWORK_SOURCES.items():require(v[k]==sha(local.bounded(launcher.checked_path(Path(root)/file,inside=root),256*1024)),'a2_network_source_pin')
    return actor

def core_bundle(root,c):
    root=launcher.checked_path(root,is_file=False);require(root.name==stage_name(c['run']),'a2_bundle_stage')
    return launcher.checked_path(root.parent/bundle_name(c['run']),inside=root.parent,is_file=False)

def verify_artifacts(c,root):
    verify_actor(root/'inputs'/ACTOR,root/'inputs'/MANIFEST,c['actor_sha256'],c['manifest_sha256'],root=root)
    verify_actor(root/'inputs'/NETWORK_ACTOR,root/'inputs'/NETWORK_MANIFEST,c['network_actor_sha256'],c['network_manifest_sha256'],root=root,network=True)
    challenge_inputs(root/CHALLENGE_PATHS['request'],root/CHALLENGE_PATHS['response'],c['challenges'],case=c['case'],origin_port=c['ports']['origin_port'])
    verify_mihomo(core_bundle(root,c)/'mihomo.exe',c['mihomo_sha256'])
    verify_configuration(c,root)

def verify_configuration(c,root):
    raw=local.bounded(launcher.checked_path(Path(root)/'core-home/config.json',inside=root),32768)
    require(raw==encode(mihomo_configuration(c['ports'])) and sha(raw)==c['mihomo_config_sha256'],'a2_frozen_core_config');return raw


def mihomo_configuration(declared):
    """YAML-tag keys for fixed v1.19.32. JSON is its bounded YAML subset.

    Source review is conditional on these exact bytes. Disabled DNS still
    parses a nonempty numeric default; no absence of incidental I/O is claimed.
    """
    p=ports(declared);O,M=p['origin_port'],p['proxy_port']
    return {
        'port':0,'socks-port':0,'mixed-port':0,'redir-port':0,'tproxy-port':0,'ss-config':'','vmess-config':'',
        'inbound-tfo':False,'inbound-mptcp':False,'authentication':[],'skip-auth-prefixes':[],
        'lan-allowed-ips':['127.0.0.1/32'],'lan-disallowed-ips':[],'allow-lan':False,'bind-address':'127.0.0.1',
        'mode':'rule','unified-delay':False,'log-level':'error','ipv6':False,
        'external-controller':'','external-controller-routing-mark':0,'external-controller-pipe':'','external-controller-unix':'',
        'external-controller-tls':'','external-ui':'','external-ui-url':'','external-ui-name':'','external-doh-server':'','secret':'',
        'interface-name':'','routing-mark':0,'tunnels':[],'geo-auto-update':False,'geo-update-interval':24,
        'geodata-mode':False,'geodata-loader':'memconservative','geosite-matcher':'succinct','tcp-concurrent':False,'find-process-mode':'off',
        'proxy-providers':{},'rule-providers':{},'proxies':[],'proxy-groups':[],'sub-rules':{},'hosts':{},
        'rules':['AND,((NETWORK,TCP),(IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,'+str(O)+')),DIRECT','MATCH,REJECT'],
        'listeners':[{'type':'mixed','name':'ruleproxy-a2-owned','listen':'127.0.0.1','port':str(M),'udp':False,'users':[],
            'certificate':'','private-key':'','client-auth-type':'','client-auth-cert':'','ech-key':'','reality-config':{},'routing-mark':0,'proxy':'','rule':''}],
        'dns':{'enable':False,'prefer-h3':False,'ipv6':False,'ipv6-timeout':0,'use-hosts':False,'use-system-hosts':False,'respect-rules':False,
            'nameserver':[],'fallback':[],'fallback-filter':{'geoip':False,'geoip-code':'','ipcidr':[],'domain':[],'geosite':[]},'fallback-lazy-query':False,
            'listen':'','listen-routing-mark':0,'enhanced-mode':'normal','fake-ip-range':'','fake-ip-range6':'','fake-ip-filter':[],
            'fake-ip-filter-mode':'blacklist','fake-ip-ttl':0,'default-nameserver':['udp://127.0.0.1:1'],'cache-algorithm':'lru','cache-max-size':0,
            'nameserver-policy':{},'proxy-server-nameserver':[],'proxy-server-nameserver-policy':{},'direct-nameserver':[],'direct-nameserver-follow-policy':False},
        'ntp':{'enable':False,'server':'','port':123,'interval':30,'dialer-proxy':'','write-to-system':False},
        'tun':{'enable':False,'device':'','stack':'system','dns-hijack':[],'auto-route':False,'auto-detect-interface':False,'auto-redirect':False,
            'strict-route':False,'inet6-address':[],'route-address':[],'route-address-set':[],'route-exclude-address':[],'route-exclude-address-set':[]},
        'tuic-server':{'enable':False,'listen':'','token':[],'users':{},'certificate':'','private-key':'','congestion-controller':'',
            'max-idle-time':0,'authentication-timeout':0,'alpn':[],'max-udp-relay-packet-size':0,'cwnd':0},
        'iptables':{'enable':False,'inbound-interface':'','bypass':[],'dns-redirect':False},
        'experimental':{'fingerprints':[],'quic-go-disable-gso':True,'quic-go-disable-ecn':True,'dialer-ip4p-convert':False},
        'profile':{'store-selected':False,'store-fake-ip':False},'geox-url':{'geoip':'','mmdb':'','asn':'','geosite':''},
        'sniffer':{'enable':False,'override-destination':False,'sniffing':[],'force-domain':[],'skip-src-address':[],'skip-dst-address':[],
            'skip-domain':[],'port-whitelist':[],'force-dns-mapping':False,'parse-pure-ip':False,'sniff':{}},'tls':{}}


class Owner(stream.Owner):
    """Finite extension of qualified stream resource adapters, no global patch."""
    def __init__(self,root,c,parent,api,budget):
        super().__init__(root,c,parent,api,budget);self.leases=None;self.stdio=[]
        self.j.update(stage='lpac-stream-mihomo-origin-result',scope=SCOPE,profile=PROFILE,profile_name='ruleproxy-lpac-a2-'+c['run'],
            ports=c['ports'],core_check_completed=False,core_stop=None,core_stdio=[],port_lease=None,port_leases_closed=False,core_stdio_closed=True,
            tcp={},barrier_commands={},barrier_ack=None,barrier_released=False,core_integration_observed=False,kernel_tcp_snapshot_observed=False)
        self.j['port']=c['ports']['origin_port']
        self.j.update(dict.fromkeys(FALSE_CLAIMS,False))
        self.j.pop('core_mihomo_integration',None)

    def journal(self,label,**extra):
        allowed={'profile-create','acl-grant','label-lower','label-restore','acl-remove','profile-delete','workload-stop','pair-epoch','observe-lpac',
            'allocate-response','allocate-request','parent-pipe-close','resume-authorized','port-leases','barrier-arm','barrier-release','core-stop',
            *('spawn-'+role for role in (*ROLES,*CORE_ROLES)),*('spawn-grant-'+r[0] for r in GRANTS),'spawn-remove'}
        require(label in allowed and len(self.j['intents'])<48,'a2_intent')
        v=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label,extra=extra)
        raw=encode(v);p=self.root/'journal'/('%02d-%s.json'%(len(self.j['intents']),label));base.durable_private(p,raw)
        self.j['intents'].append(dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw)));return v['qpc']

    def held(self,row,end):
        self.budget.require_ms(end);h=row['info'].hProcess
        require(row['created'] is not None and not self.api.wait(h,0) and self.api.process_id(h)==row['pid'] and self.api.creation_time(h)==row['created'],'a2_held_generation')
        self.api.verify_job(self.job,h);self.api.verify_outer(self.c['guard_job_name'],h);image=Path(row['command'][0]);self.api.verify_image(h,image)
        if row['role'] in CORE_ROLES:verify_mihomo(image,row['image_sha256'])
        else:require(sha(local.bounded(image,8*1024*1024))==row['image_sha256'],'a2_held_native_hash')
        current=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,row['role']=='lpac-pipe-front')
        require(current==row['expected_primary'],'a2_held_primary')
        row['held_checks'].append(dict(qpc=self.budget.read(),pid=row['pid'],created=row['created'],image_sha256=row['image_sha256'],primary=current,inner_job=True,outer_job=True));self.budget.require_ms(end)
        # Readiness polling retains the first admission and most recent held
        # snapshots; this array is not a claim to list every native query.
        if len(row['held_checks'])>64:del row['held_checks'][1]

    def spawn(self,role,argv,end,ends=()):
        require(role in (*ROLES,*CORE_ROLES),'a2_spawn_role');selected=role==ROLES[0];core=role in CORE_ROLES
        image=launcher.checked_path(argv[0],inside=core_bundle(self.root,self.c) if core else self.root)
        expected=self.c['mihomo_sha256' if core else 'actor_sha256' if selected else 'network_actor_sha256']
        if core:verify_mihomo(image,expected);verify_configuration(self.c,self.root);self.budget.require_ms(end)
        else:require(sha(local.bounded(image,8*1024*1024))==expected,'a2_spawn_native_image')
        info=self.api.process_info();row=dict(name=role,role=role,info=info,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,created=None,token=None,identity=None,
            capabilities=None,lpac=None,lpac_expected=selected,process_returned=False,resumed=False,admitted=False,image_sha256=expected,admission_qpc=None,resume_qpc=None,go_qpc=[],command=argv,
            expected_primary=None,held_checks=[],ends=list(ends),receipt=None,resume_intent_qpc=None,exit_observed_qpc=None,
            create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',returned_qpc=None,work_cutoff=end,exception_detail=None))
        self.children.append(row);self.tasks[role]=row;state=dict(creation_attempted=False);self.journal('spawn-'+role)
        def record_return(s):
            o=dict(status=s.get('create_status','not_entered'),winerror=s.get('create_winerror'),process_information=s.get('create_information','not_observed'),
                returned_qpc=s.get('returned_qpc'),work_cutoff=end,exception_detail=s.get('create_exception_detail'))
            raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(self.c)),role=role,observation=o,raw_return=s.get('raw_return'),raw_error=s.get('raw_error'),pi=s.get('raw_pi',info_values(info))))
            p=self.root/'returns'/(role+'.json');base.durable_private(p,raw);row['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
        ledger=None;stdio_record=None
        if core:
            ledger=helpers.OneShotHandles(self.api.close);self.stdio.append(ledger);stdio_record=dict(role=role,opened=[],closes=[],confirmed=False);self.j['core_stdio'].append(stdio_record);self.j['core_stdio_closed']=False
        try:
            if core:
                handles=[]
                for name in ('stdin','stdout','stderr'):
                    h=self.api.open_stdio_file(self.root/role/name,read=name=='stdin')
                    try:
                        pending=set(self.owners.pending)|set(self.pipes.pending)
                        for current in self.stdio:pending.update(current.pending)
                        require(type(h) is int and 0<h<(1<<64)-1 and h not in pending,'a2_stdio_owned_handle_alias')
                        ledger.add(h)
                    except BaseException:self.api.controls_uncertain=True;raise
                    handles.append(h);stdio_record['opened'].append(h)
                ends=handles;row['ends']=list(ends)
            cwd=self.root/'inputs' if selected else self.root/('relay-report' if role==ROLES[1] else 'origin-report' if role==ROLES[2] else role)
            env=self.selected_environment if selected else self.api.native.environment(cwd)
            self.api.captured_spawn(info,argv,cwd,env,self.job,self.owners,state,role=role,ends=ends,
                other_pending=ledger.pending if core else self.pipes.pending,profile_pointer=self.profile['pointer'] if selected else None,
                budget=self.budget,end=end,on_return=record_return)
        finally:
            row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess));row['pid']=int(info.dwProcessId) if info.dwProcessId else None
            row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),process_information=state.get('create_information','not_observed'),
                returned_qpc=state.get('returned_qpc'),work_cutoff=end,exception_detail=state.get('create_exception_detail'))
            if state.get('creation_unknown'):self.j['creation_unknown']=True
            if ledger is not None:
                for h in tuple(ledger.pending):
                    close=dict(handle=h,attempted=True,confirmed=False,qpc=None);stdio_record['closes'].append(close)
                    try:ledger.close(h);close['qpc']=self.budget.read();close['confirmed']=True
                    except BaseException:self.api.controls_uncertain=True
                stdio_record['confirmed']=ledger.confirmed_closed and all(r['confirmed'] for r in stdio_record['closes']);self.j['core_stdio_closed']=all(r['confirmed'] for r in self.j['core_stdio'])
        require(not core or self.j['core_stdio_closed'],'a2_parent_stdio_once_closed')
        require(info.hProcess and info.hThread and row['pid'],'a2_partial_create');self.budget.require_ms(end)
        row['created']=self.api.creation_time(info.hProcess);self.api.verify_job(self.job,info.hProcess);self.api.verify_outer(self.c['guard_job_name'],info.hProcess);row['assigned']=True
        self.api.verify_image(info.hProcess,image);row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token']);row['identity']=self.api.identity(row['token'])
        row['expected_primary']=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,selected);row['capabilities']=[]
        self.held(row,end);row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row

    def resume(self,row):
        if row.get('role') not in (*ROLES,*CORE_ROLES):return legacy.Owner.resume(self,row)
        pair_role=row['role'] in ROLES[:2];end=self.j['pair']['end'] if pair_role else work_cutoff(self.c)
        self.held(row,end);require(row['admitted'] and not row['resumed'],'a2_resume_once')
        if pair_role:
            require(self.j['parent_pipe_handles_closed'] and self.pipes.confirmed_closed and not self.j['pipe_allocation_unknown'] and self.j['proof'] is not None
                and self.j['proof']['qualified'] and self.j['observer_resources_cleanup_verified'] and self.j['barrier_commands'].get('arm') is not None
                and all(self.tasks[k]['admitted'] for k in (*ROLES,CORE_ROLES[1])),'a2_pair_resume_gate')
        if row['role'] in CORE_ROLES:
            require(self.j['core_stdio_closed'],'a2_core_parent_stdio');verify_configuration(self.c,self.root);self.budget.require_ms(end)
        row['resume_intent_qpc']=self.journal('resume-authorized',role=row['role']);self.budget.require_ms(end)
        self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read();self.budget.require_ms(end)

    def wait(self,row,end,code=0):
        base.Owner.wait(self,row,end,code);row['exit_observed_qpc']=self.budget.read();self.budget.require_ms(end)
        if row.get('role') in CORE_ROLES:verify_configuration(self.c,self.root);self.budget.require_ms(end)

    def read_closed(self,path,row,end):
        while not path.exists():
            self.budget.require_ms(end);require(not self.api.wait(row['info'].hProcess,0),'a2_exit_before_report');self.api.sleep_ms(self.budget.require_ms(end,5))
        while True:
            try:raw=local.bounded(path,MAX_NATIVE);self.budget.require_ms(end);return raw
            except OSError as e:
                if getattr(e,'winerror',None)!=32:raise
                self.api.sleep_ms(self.budget.require_ms(end,5))

    def native(self,key):
        raw=local.bounded(self.root/REPORT_PATHS[key],MAX_NATIVE);self.j['reports'][key]=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status'][key]='invalid'
        self.j['tasks']=[task_projection(r) for r in self.children];value=validate_native(key,decode(raw),self.j,self.c,self.parent);self.j['report_status'][key]='valid';return value

    def origin_ready(self,row):
        raw=self.read_closed(self.root/REPORT_PATHS['ready'],row,work_cutoff(self.c));self.j['reports']['ready']=dict(text=raw.decode('ascii'),sha256=sha(raw));self.j['report_status']['ready']='invalid'
        self.j['tasks']=[task_projection(r) for r in self.children];validate_native('ready',decode(raw),self.j,self.c,self.parent);self.j['report_status']['ready']='valid';self.held(row,work_cutoff(self.c))

    def held_family(self,end):
        for role in (ROLES[1],ROLES[2],CORE_ROLES[1]):self.held(self.tasks[role],end)

    def listeners(self):
        end=work_cutoff(self.c)
        while True:
            for role in (ROLES[2],CORE_ROLES[1]):self.held(self.tasks[role],end)
            before=self.budget.read();raw=self.api.tcp_snapshot(self.budget,end);after=self.budget.read()
            try:rows=exact_listeners(raw,proxy_pid=self.tasks[CORE_ROLES[1]]['pid'],origin_pid=self.tasks[ROLES[2]]['pid'],declared=self.c['ports'])
            except ValueError:self.api.sleep_ms(self.budget.require_ms(end,10));continue
            for role in (ROLES[2],CORE_ROLES[1]):self.held(self.tasks[role],end)
            base.durable_private(self.root/'tcp/listeners.bin',raw);self.j['tcp']['listeners']=tcp_record(raw,rows,name='listeners.bin',before_qpc=before,after_qpc=after);self.budget.require_ms(end);return

    def publish_barrier(self,release=False,ack=None):
        key='release' if release else 'arm';pair=self.j['pair'];end=min(pair['end'],ack['wait_deadline_qpc']) if release else pair['end']
        intent=self.journal('barrier-'+key,ack_sha256=self.j['barrier_ack']['sha256'] if release else None,tcp_sha256=self.j['tcp'].get('two_hop',{}).get('sha256'))
        self.budget.require_ms(end);issued=self.budget.read();raw=barrier_control(self.c,pair,issued,release=release,ack=ack)
        record=dict(path=BARRIER_PATHS[key],hex=raw.hex(),sha256=sha(raw),issued_qpc=issued,intent_qpc=intent,published_qpc=None)
        # Save the physical return commitment before publication so a late
        # readback/rename failure cannot erase which immutable command existed.
        self.j['barrier_commands'][key]=record;zero.atomic_publish(self.root/BARRIER_PATHS[key],raw,self.budget,end)
        record['published_qpc']=self.budget.read();self.budget.require_ms(end);return issued

    def request_barrier(self):
        row=self.tasks[ROLES[2]];end=self.j['pair']['end'];raw=self.read_closed(self.root/BARRIER_PATHS['ack'],row,end)
        self.j['barrier_ack']=dict(text=raw.decode('ascii'),sha256=sha(raw));ack=validate_ack(decode(raw),self.c,self.j['pair'],origin_pid=row['pid'],arm_issued=self.j['barrier_commands']['arm']['issued_qpc'])
        end=ack['wait_deadline_qpc'];self.budget.require_ms(end);self.held_family(end)
        before=self.budget.read();table=self.api.tcp_snapshot(self.budget,end);after=self.budget.read()
        rows=exact_two_hop(table,relay_pid=self.tasks[ROLES[1]]['pid'],proxy_pid=self.tasks[CORE_ROLES[1]]['pid'],origin_pid=row['pid'],declared=self.c['ports'],origin_peer_port=ack['peer_port'])
        self.held_family(end);base.durable_private(self.root/'tcp/two-hop.bin',table)
        self.j['tcp']['two_hop']=tcp_record(table,rows,name='two-hop.bin',before_qpc=before,after_qpc=after);self.budget.require_ms(end)
        self.j['kernel_tcp_snapshot_observed']=True
        self.publish_barrier(True,ack);self.j['barrier_released']=True

    def stop_core(self):
        row=self.tasks[CORE_ROLES[1]];end=work_cutoff(self.c);intent=self.journal('core-stop',role=CORE_ROLES[1]);self.held(row,end)
        record=dict(role=CORE_ROLES[1],pid=row['pid'],created=row['created'],image_sha256=row['image_sha256'],intent_qpc=intent,receipt=None,observation=None,observed_exit_qpc=None,exit_code=None)
        self.j['core_stop']=record
        def returned(value):
            record['observation']=value
            raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(self.c)),role=CORE_ROLES[1],intent_qpc=intent,observation=value))
            p=self.root/'returns/core-stop.json';base.durable_private(p,raw);record['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
        self.api.terminate_core(row['info'].hProcess,self.budget,end,returned);self.wait(row,end,1)
        record.update(observed_exit_qpc=row['exit_observed_qpc'],exit_code=row['exit_code'])

    def run(self):
        self.setup();c=self.c;end=work_cutoff(c);self.phase='ports';self.journal('port-leases')
        self.leases=PortLeases(self.api.lease_backend(),self.budget,end,c['ports']);self.leases.acquire()
        self.phase='core-check';core=str(core_bundle(self.root,c)/'mihomo.exe');args=[core,'-d',str(self.root/'core-home'),'-f',str(self.root/'core-home/config.json')]
        check=self.spawn(CORE_ROLES[0],args+['-t'],end);self.resume(check);self.wait(check,end);self.j['core_check_completed']=True
        self.phase='origin';challenge_inputs(self.root/CHALLENGE_PATHS['request'],self.root/CHALLENGE_PATHS['response'],c['challenges'],case=c['case'],origin_port=c['ports']['origin_port'])
        self.j['origin_start']=self.budget.read();self.leases.release('origin_port')
        origin=self.spawn(ROLES[2],expected_argv(ROLES[2],self.j,c,self.root,self.parent),end);self.resume(origin);self.origin_ready(origin)
        self.phase='core';self.leases.release('proxy_port');self.leases.close_all();require(self.leases.confirmed_closed,'a2_released_port_leases')
        real=self.spawn(CORE_ROLES[1],args,end);self.resume(real);self.listeners()
        self.phase='pair';start=self.budget.read();pairE=start+10*c['frequency'];require(pairE<=end,'a2_pair_reserve');self.j['pair']=dict(start=start,end=pairE,frequency=c['frequency']);self.journal('pair-epoch',start=start,end=pairE)
        pairs=[]
        for label in ('response','request'):
            state=dict(name=label,receipt=None);self.j['pipe_allocations'].append(state);self.journal('allocate-'+label)
            try:pairs.append(self.api.allocate_pipe(self.pipes,self.owners.pending,self.parent['sid'],state,self.budget,pairE))
            finally:
                if state.get('unknown') or state.get('attempted') and not state.get('api_success'):self.j['pipe_allocation_unknown']=True
                raw=encode(dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=label,observation={k:v for k,v in state.items() if k not in ('name','receipt')}))
                try:p=self.root/'returns'/('pipe-'+label+'.json');base.durable_private(p,raw);state['receipt']=dict(name=p.name,text=raw.decode('ascii'),sha256=sha(raw))
                except BaseException:self.api.controls_uncertain=True;raise
        (front_read,relay_write),(relay_read,front_write)=pairs
        # Closed argv reconstructs from these exact raw pipe identities.
        for role,ends in ((ROLES[0],(front_read,front_write)),(ROLES[1],(relay_read,relay_write))):
            self.spawn(role,pair_argv(role,self.j,c,self.root,self.parent,ends),pairE,ends)
        front,relay=(self.tasks[r] for r in ROLES[:2]);self.held_family(pairE);self.held(front,pairE)
        self.phase='accesscheck';self.journal('observe-lpac');self.j['observer_attempted']=True;self.j['observer_resources_cleanup_verified']=False
        proof=zero.observe_held(self.api.access_api(),front['info'].hProcess,front['expected_primary'],expected_pid=front['pid'],expected_creation=front['created'],expected_role='lpac',frequency=c['frequency'],deadline=pairE)
        self.j['proof']=proof;zero.validate_proof(proof,expected_primary_identity=front['expected_primary'],expected_role='lpac',expected_pid=front['pid'],expected_creation=front['created'],frequency=c['frequency'],deadline=pairE)
        self.j['observer_resources_cleanup_verified']=proof['resource_cleanup_verified']
        if not self.j['observer_resources_cleanup_verified']:self.api.controls_uncertain=True
        require(proof['qualified'],'a2_lpac_matrix');self.held_family(pairE);self.held(front,pairE)
        request_before_pair_resume(self.root/CHALLENGE_PATHS['request'],c['challenges'],case=c['case'],origin_port=c['ports']['origin_port'])
        self.journal('parent-pipe-close');uncertain=False
        for h in (front_read,relay_write,relay_read,front_write):
            close=dict(handle=h,attempted=True,confirmed=False);self.j['parent_pipe_close_attempts'].append(close)
            try:self.pipes.close(h);close['confirmed']=True
            except BaseException:uncertain=True
        self.j['parent_pipe_handles_closed']=not uncertain and self.pipes.confirmed_closed;require(self.j['parent_pipe_handles_closed'],'a2_parent_pipe_closed')
        self.publish_barrier();self.phase='protocol';self.resume(relay);self.resume(front);self.request_barrier()
        for row in (front,relay,origin):self.wait(row,pairE)
        self.j['natural_exits']=True
        for key in ('selected','relay','origin'):self.native(key);self.budget.require_ms(pairE)
        self.sink_evidence();harvest(self.j,c,self.parent);self.j['completion_qpc']=self.budget.read();self.budget.require_ms(pairE)
        self.j['core_integration_observed']=positive(self.j,c,self.parent);require(self.j['core_integration_observed'],'a2_finite_mechanism')
        self.phase='core-stop';self.stop_core();self.j['mechanism_verified']=True

    def cleanup(self):
        if self.leases is not None:self.leases.close_all();self.j['port_leases_closed']=self.leases.confirmed_closed;self.j['port_lease']=dict(calls=self.leases.calls,closes=self.leases.closed,unknown=self.leases.unknown,started=self.leases.started,cleanup_attempted=self.leases.cleanup_attempted,cleanup_confirmed=self.leases.cleanup_confirmed)
        else:self.j['port_leases_closed']=True
        self.j['core_stdio_closed']=all(r['confirmed'] for r in self.j['core_stdio'])
        if not self.j['port_leases_closed'] or not self.j['core_stdio_closed']:self.api.controls_uncertain=True
        super().cleanup();harvest(self.j,self.c,self.parent)
        if self.j['workload_stop']:self.j['failure']=self.j['failure'] or 'cleanup'
        if not all(self.j[k] for k in CLEAN_KEYS):self.j['failure']=self.j['failure'] or 'cleanup'


def pair_argv(role,j,c,root,parent,ends):
    selected=role==ROLES[0];require(role in ROLES[:2],'a2_pair_argv_role');p=Path(root);pair=j['pair']
    value=[str(p/'inputs'/(ACTOR if selected else NETWORK_ACTOR)),'stream-front' if selected else 'stream-a2-relay',c['run'],c['case'],
        str(p/REPORT_PATHS['selected' if selected else 'relay']),*(str(h) for h in ends),str(pair['start']),str(c['frequency']),str(pair['end']),parent['sid'],
        j['profile_sid'] if selected else 'none','8193','12289',str(c['ports']['origin_port'])]
    return value if selected else value+[str(c['ports']['proxy_port'])]

def expected_argv(role,j,c,root,parent):
    p=Path(root)
    if role in CORE_ROLES:
        value=[str(core_bundle(p,c)/'mihomo.exe'),'-d',str(p/'core-home'),'-f',str(p/'core-home/config.json')]
        return value+['-t'] if role==CORE_ROLES[0] else value
    if role in ROLES[:2]:return pair_argv(role,j,c,root,parent,legacy.actor_rows(j)[role]['ends'])
    require(role==ROLES[2],'a2_expected_argv_role')
    return [str(p/'inputs'/NETWORK_ACTOR),'stream-a2-origin',c['run'],c['case'],str(p/REPORT_PATHS['origin']),str(p/REPORT_PATHS['ready']),
        str(c['start_qpc']),str(c['frequency']),str(work_cutoff(c)),parent['sid'],'8193','12289',str(c['ports']['origin_port']),str(c['ports']['proxy_port']),
        str(p/BARRIER_PATHS['arm']),str(p/BARRIER_PATHS['ack']),str(p/BARRIER_PATHS['release'])]

HTTP_FLAGS={'configured','header_verified','message_complete','eof_observed'}
HTTP_COUNTS={'header_bytes','body_bytes','total_bytes','expected_total_bytes'}
RELAY_ADAPTER={'request_fin_received','request_message_complete','request_sink_flushed','tcp_send_shutdown_deferred','response_message_complete','proxy_eof_observed',
    'send_shutdown_attempted','send_shutdown_confirmed','send_shutdown_after_response_eof','request_fin_is_tcp_fin'}
ORIGIN_ADAPTER={'request_message_complete','request_eof_observed','response_started_after_request_message','response_started_without_waiting_for_request_eof',
    'response_message_complete','source_eof_verified','send_shutdown_attempted','send_shutdown_confirmed','response_sent_complete'}
SOCKS_COUNTS={'greeting_bytes_sent','method_bytes_received','connect_bytes_sent','reply_bytes_received','handshake_wire_sent','handshake_wire_received'}
SOCKS_FLAGS={'method_noauth_verified','reply_ipv4_loopback_listener_verified','handshake_complete','origin_dial_proven'}

def http_parser(v,total):
    require(type(v) is dict and set(v)==HTTP_FLAGS|HTTP_COUNTS|{'content_length','failure'} and all(type(v[k]) is bool for k in HTTP_FLAGS)
        and all(base.ac.integer(v[k],0,65537) for k in HTTP_COUNTS) and v['expected_total_bytes']==total and v['header_bytes']<=512
        and (v['content_length'] is None or base.ac.integer(v['content_length'],0,65536)) and v['failure'] in (None,'configuration','header','overflow','early_eof','io','order'),'a2_HTTP_parser_shape')
    require(not v['message_complete'] or v['configured'] and v['header_verified'] and v['total_bytes']==total,'a2_HTTP_complete_shape');return v

def validate_native(key,v,j,c,parent):
    if key=='selected':return stream.validate_native(key,v,j,c,parent)
    rows=legacy.actor_rows(j);origin=key in ('ready','origin');row=rows[ROLES[2] if origin else ROLES[1]]
    if key=='ready':
        require(type(v) is dict and set(v)=={'schema_version','stage','run_id','case_id','pid','port','proxy_port','qpc_frequency','start_qpc','deadline_qpc','loopback_ipv4','exclusive'}
            and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-stream-mihomo-origin-ready' and v['run_id']==c['run'] and v['case_id']==c['case']
            and type(v['pid']) is int and v['pid']==row['pid'] and v['port']==c['ports']['origin_port'] and v['proxy_port']==c['ports']['proxy_port']
            and [v[k] for k in ('qpc_frequency','start_qpc','deadline_qpc')]==[c['frequency'],c['start_qpc'],work_cutoff(c)]
            and v['loopback_ipv4'] is v['exclusive'] is True,'a2_ready');return v
    require(key in ('relay','origin'),'a2_native_slot')
    fields={'schema_version','stage','role','run_id','case_id','pid','identity','qpc','limits','files','stream','pipe','network','admitted_qpc','read_handle_inherit_cleared','write_handle_inherit_cleared',
        'failure','win32_error','wsa_error','selected_socket_api_tested','network_tested','proxy_tested','product_acceptance','ports','socks','http','message_boundary','network_scope','barrier'}
    require(type(v) is dict and set(v)==fields and type(v['schema_version']) is int and v['schema_version']==1 and v['stage']=='lpac-stream-mihomo-http-actor'
        and v['role']==('stream-a2-origin' if origin else 'stream-a2-relay') and v['run_id']==c['run'] and v['case_id']==c['case'] and type(v['pid']) is int and v['pid']==row['pid'],'a2_native_wrapper')
    require(v['ports']==c['ports'] and v['message_boundary']=='deferred-shutdown-after-http-message-and-response-eof' and v['network_scope']=='ordinary-relay-to-held-mihomo-to-owned-origin-only'
        and v['failure'] in (*stream.NATIVE_FAILURES,'socks','http','phase','ack','release') and all(v[k] is False for k in ('selected_socket_api_tested','proxy_tested','product_acceptance'))
        and type(v['network_tested']) is bool and all(type(v[k]) is bool for k in ('read_handle_inherit_cleared','write_handle_inherit_cleared')),'a2_native_status')
    stream.native_identity(v['identity'],row,c,False)
    for k in ('win32_error','wsa_error'):require(v[k] is None or base.ac.integer(v[k],0,0xffffffff),'a2_native_error')
    q=v['qpc'];start,end=(c['start_qpc'],work_cutoff(c)) if origin else (j['pair']['start'],j['pair']['end'])
    require(type(q) is list and len(q)==4 and all(base.ac.integer(t,0,c['root_deadline_qpc']+c['frequency']) for t in q) and q[:3]==[c['frequency'],start,end]
        and (q[3]==0 and v['failure'] is not None or q[3]>=row['resume_intent_qpc']),'a2_native_clock')
    require(v['admitted_qpc'] is None or base.ac.integer(v['admitted_qpc'],row['resume_intent_qpc'],q[3]),'a2_native_admitted_clock')
    require(v['limits']==dict(payload_max=1024,window=4096,total_max=65536,frames_max=256,request_bytes=8193,response_bytes=12289)
        and all(type(x) is int for x in v['limits'].values()),'a2_native_limits')
    f=v['files'];require(type(f) is dict and set(f)=={'source','request_sink','response_sink'},'a2_native_files')
    for k,value in f.items():
        if not origin and k=='source':require(value is None,'a2_relay_no_source')
        else:stream.file_record(value,maximum=65536)
    if origin:
        require(v['pipe'] is v['stream'] is v['socks'] is v['admitted_qpc'] is None and v['read_handle_inherit_cleared'] is v['write_handle_inherit_cleared'] is False,'a2_origin_no_pipe')
        if v['barrier'] is not None:validate_barrier(v['barrier'],c,j['pair'])
        else:require(v['failure'] is not None,'a2_missing_origin_barrier')
    else:
        require(v['barrier'] is None,'a2_relay_no_barrier');st=v['stream'];pipe=v['pipe']
        require(type(st) is dict and set(st)=={*stream.STREAM_FLAGS,*stream.STREAM_COUNTS,'failure'} and all(type(st[k]) is bool for k in stream.STREAM_FLAGS)
            and st['failure'] in stream.CODEC_FAILURES,'a2_stream_shape')
        for k in stream.STREAM_COUNTS:
            bound=256 if k in ('tx_frames','rx_frames') else 4096 if k in ('tx_outstanding','rx_outstanding','tx_window_available','local_buffered','peer_buffered') else 1088 if k in ('partial_frame_bytes','pending_frame_bytes') else 65536
            require(base.ac.integer(st[k],0,bound),'a2_stream_count')
        require(type(pipe) is dict and set(pipe)=={'read_bytes','write_bytes','read_calls','write_calls','peek_calls','eof_observed','reader_close','writer_close','inheritance_cleared'}
            and all(type(pipe[k]) is bool for k in ('eof_observed','inheritance_cleared')) and all(pipe[k] in stream.CLOSE_VALUES for k in ('reader_close','writer_close')),'a2_pipe_shape')
        for k in ('read_bytes','write_bytes','read_calls','write_calls','peek_calls'):require(base.ac.integer(pipe[k],0,81920 if k.endswith('bytes') else 0xffffffff),'a2_pipe_count')
        socks=v['socks'];require(type(socks) is dict and set(socks)==SOCKS_COUNTS|SOCKS_FLAGS|{'failure'} and all(base.ac.integer(socks[k],0,13) for k in SOCKS_COUNTS)
            and all(type(socks[k]) is bool for k in SOCKS_FLAGS) and socks['origin_dial_proven'] is False
            and socks['failure'] in (None,'configuration','order','method','reply','bound','io','eof'),'a2_socks_shape')
    h=v['http'];require(type(h) is dict and set(h)=={'request','response','adapter'},'a2_HTTP_slots');http_parser(h['request'],8193);http_parser(h['response'],12289)
    adapter=h['adapter'];require(type(adapter) is dict and set(adapter)==(ORIGIN_ADAPTER if origin else RELAY_ADAPTER) and all(type(x) is bool for x in adapter.values()),'a2_HTTP_adapter')
    if not origin:require(adapter['request_fin_is_tcp_fin'] is False,'a2_no_transparent_FIN_claim')
    net=v['network'];require(type(net) is dict and set(net)=={*stream.NETWORK_FLAGS,'port','local_port','peer_port','bytes_sent','bytes_received','socket_close','listener_close'}
        and all(type(net[k]) is bool for k in stream.NETWORK_FLAGS) and all(net[k] in stream.CLOSE_VALUES for k in ('socket_close','listener_close')),'a2_network_shape')
    target=c['ports']['origin_port' if origin else 'proxy_port']
    require(net['port']==target or origin and net['port']==0 and v['failure'] is not None and not net['bind_loopback'],'a2_actual_target_port')
    for k in ('local_port','peer_port'):require(net[k] is None or base.ac.integer(net[k],1,65535),'a2_native_port')
    for k in ('bytes_sent','bytes_received'):require(base.ac.integer(net[k],0,65536+13),'a2_network_count')
    if origin:require(not net['connect_attempted'] and not net['connect_completed'] and v['network_tested']==net['accepted'],'a2_origin_not_client')
    else:require(not any(net[k] for k in ('listener_created','exclusive','bind_loopback','accepted')) and net['listener_close']=='not_attempted'
        and v['network_tested']==net['connect_attempted'],'a2_relay_not_server')
    return v

def validated_reports(j,c,parent):
    return {k:validate_native(k,legacy.record_value(r),j,c,parent) for k,r in j['reports'].items() if r is not None and j['report_status'][k]=='valid'}

def harvest(j,c,parent):
    for key,value in validated_reports(j,c,parent).items():
        if key=='selected':j['selected_ipc_observed']|=bool(value['pipe']['read_bytes'] or value['pipe']['write_bytes'])
        elif key=='relay':j['relay_connect_observed']|=value['network']['connect_completed']
        elif key=='origin':
            j['origin_accepted_observed']|=value['network']['accepted'];j['origin_request_observed']|=bool(value['files']['request_sink']['bytes']);j['origin_response_observed']|=bool(value['files']['response_sink']['bytes'])

def validate_sinks(j,c,*,root=None):
    require(j['challenges']==c['challenges'] and type(j['physical_sinks']) is dict and set(j['physical_sinks'])<=set(SINK_PATHS),'a2_sink_slots')
    for key,v in j['physical_sinks'].items():
        require(type(v) is dict and set(v)=={'path','bytes','sha256'} and v['path']==SINK_PATHS[key] and base.ac.integer(v['bytes'],0,65536) and base.ac.digest(v['sha256']),'a2_sink_metadata')
        if root is not None:
            raw=local.bounded(launcher.checked_path(Path(root)/v['path'],inside=root),65536);require(dict(bytes=len(raw),sha256=sha(raw))=={k:v[k] for k in ('bytes','sha256')},'a2_physical_sink')
    if root is not None:challenge_inputs(Path(root)/CHALLENGE_PATHS['request'],Path(root)/CHALLENGE_PATHS['response'],c['challenges'],case=c['case'],origin_port=c['ports']['origin_port'])
    return j['physical_sinks']

def payloads_passed(j,c,parent):
    try:
        sinks=validate_sinks(j,c);require(set(sinks)==set(SINK_PATHS),'a2_all_five_sinks')
        for key,value in sinks.items():require({k:value[k] for k in ('bytes','sha256')}==c['challenges']['request' if key in ('relay_request','origin_request') else 'response'],'a2_actual_file_bytes')
        reports=validated_reports(j,c,parent)
        for role,slot,kind in (('selected','source','request'),('selected','response_sink','response'),('relay','request_sink','request'),('relay','response_sink','response'),('origin','source','response'),('origin','request_sink','request'),('origin','response_sink','response')):
            f=reports[role]['files'][slot];require(f['attempted'] and f['opened'] and f['close']=='confirmed' and f['bytes']==c['challenges'][kind]['bytes'] and f['flushed']==(slot!='source'),'a2_file_completed')
        return True
    except (ValueError,KeyError,TypeError):return False


def positive(j,c,parent):
    """Finite data/identity facts before controlled core stop and cleanup."""
    try:
        rows={r['role']:r for r in j['tasks'] if r['role'] in (*ROLES,*CORE_ROLES)};reports=validated_reports(j,c,parent)
        require(set(rows)=={*ROLES,*CORE_ROLES} and set(reports)==set(REPORT_PATHS),'a2_positive_reports')
        state=j['profile_state'];require(all(state.values()) and base.ac.ac_profile_sid(j['profile_sid']) and len(j['labels'])==1
            and j['labels'][0]['attempted'] and j['labels'][0]['lowered'],'a2_positive_profile')
        grants={r['name']:r for r in j['tasks'] if r['role'] not in (*ROLES,*CORE_ROLES)}
        require(set(grants)=={'grant-'+r[0] for r in GRANTS} and all(all(r[k] for k in ('attempted','process_returned','assigned','admitted','resumed','exited'))
            and r['exit_code']==0 for r in grants.values()),'a2_positive_grants')
        require(j['proof'] is not None and j['proof']['qualified'] and j['observer_resources_cleanup_verified'] and j['parent_pipe_handles_closed']
            and not j['pipe_allocation_unknown'] and not j['creation_unknown'] and all(r['receipt'] is not None and r['create_observation']['status']=='returned_true' for r in rows.values()),'a2_positive_resources')
        require(len(j['pipe_allocations'])==2 and all(r['receipt'] is not None and r['adopted'] and r['readback']
            and base.ac.integer(r['return_qpc'],j['pair']['start'],j['pair']['end']-1) for r in j['pipe_allocations']),'a2_positive_pipes')
        front,relay,origin=(reports[k] for k in ('selected','relay','origin'))
        require(stream.protocol_passed(front,True,c) and stream.protocol_passed(relay,False,c) and payloads_passed(j,c,parent),'a2_payload_protocol')
        for a,b in (('read_bytes','write_bytes'),('write_bytes','read_bytes')):require(front['pipe'][a]==relay['pipe'][b],'a2_pipe_bytes')
        for a,b in (('tx_frames','rx_frames'),('rx_frames','tx_frames'),('tx_payload_bytes','rx_payload_bytes'),('rx_payload_bytes','tx_payload_bytes')):
            require(front['stream'][a]==relay['stream'][b],'a2_cross_stream_counts')
        for v in (front,relay):require(v['pipe']['write_bytes']==v['stream']['tx_frames']*64+v['stream']['tx_payload_bytes']
            and v['pipe']['read_bytes']==v['stream']['rx_frames']*64+v['stream']['rx_payload_bytes'],'a2_wire_count')
        socks=relay['socks'];require(socks['handshake_complete'] and socks['method_noauth_verified'] and socks['reply_ipv4_loopback_listener_verified'] and socks['origin_dial_proven'] is False
            and socks['failure'] is None and [socks[k] for k in ('greeting_bytes_sent','method_bytes_received','connect_bytes_sent','reply_bytes_received','handshake_wire_sent','handshake_wire_received')]==[3,2,10,10,13,12],'a2_exact_SOCKS_handshake')
        for v in (relay,origin):
            require(v['failure'] is None and v['win32_error'] is v['wsa_error'] is None,'a2_native_success')
            for kind,total in (('request',8193),('response',12289)):
                h=v['http'][kind];require(h['configured'] and h['header_verified'] and h['message_complete'] and h['failure'] is None
                    and h['total_bytes']==total and h['content_length']==h['body_bytes'] and h['header_bytes']+h['body_bytes']==total,'a2_exact_HTTP_message')
        ra,oa=relay['http']['adapter'],origin['http']['adapter']
        require(all(ra[k] for k in RELAY_ADAPTER-{'request_fin_is_tcp_fin'}) and ra['request_fin_is_tcp_fin'] is False
            and all(oa[k] for k in ORIGIN_ADAPTER-{'request_eof_observed'}) and oa['request_eof_observed'] is False,'a2_finite_message_boundary')
        rn,on=relay['network'],origin['network'];M,O=c['ports']['proxy_port'],c['ports']['origin_port']
        require(all(rn[k] for k in ('wsa_startup','wsa_cleanup','socket_created','connect_attempted','connect_completed','peer_loopback','send_shutdown','receive_eof'))
            and rn['socket_close']=='confirmed' and rn['listener_close']=='not_attempted' and rn['bytes_sent']==8193+13 and rn['bytes_received']==12289+12 and rn['peer_port']==M,'a2_proxy_transport')
        require(all(on[k] for k in ('wsa_startup','wsa_cleanup','listener_created','exclusive','bind_loopback','accepted','peer_loopback','send_shutdown'))
            and on['socket_close']==on['listener_close']=='confirmed' and on['bytes_sent']==12289 and on['bytes_received']==8193
            and on['local_port']==on['port']==O,'a2_origin_transport')
        require(j['core_check_completed'] and rows[CORE_ROLES[0]]['resumed'] and rows[CORE_ROLES[0]]['exited'] and rows[CORE_ROLES[0]]['exit_code']==0
            and rows[CORE_ROLES[1]]['admitted'] and rows[CORE_ROLES[1]]['resumed'] and j['core_stdio_closed'],'a2_core_roles')
        require(j['natural_exits'] and all(r['admitted'] and r['resumed'] and r['exited'] and r['exit_code']==0 for role,r in rows.items() if role in ROLES),'a2_native_natural_exits')
        require(set(j['barrier_commands'])=={'arm','release'} and j['barrier_released'] and j['barrier_ack'] is not None and j['kernel_tcp_snapshot_observed']
            and set(j['tcp'])=={'listeners','two_hop'},'a2_barrier_evidence')
        ack=validate_ack(legacy.record_value(j['barrier_ack']),c,j['pair'],origin_pid=rows[ROLES[2]]['pid'],arm_issued=j['barrier_commands']['arm']['issued_qpc'])
        barrier=validate_barrier(origin['barrier'],c,j['pair']);tcp=j['tcp']['two_hop'];release=j['barrier_commands']['release'];capture=tcp['rows']
        require(all(barrier[k] for k in BARRIER_FLAGS) and barrier['failure'] is None and barrier['ack_qpc']==ack['qpc'][3]
            and barrier['phase_issued_qpc']==ack['phase_issued_qpc'] and barrier['response_bytes_before_release']==0
            and barrier['release_issued_qpc']==release['issued_qpc'],'a2_response_release')
        require(ack['qpc'][3]<=tcp['before_qpc']<=tcp['after_qpc']<=release['intent_qpc']<=release['issued_qpc']<=barrier['release_admitted_qpc']
            <=barrier['response_started_qpc']<=origin['qpc'][3]<j['pair']['end'] and barrier['release_admitted_qpc']<ack['wait_deadline_qpc'],'a2_barrier_causal_order')
        require(rn['local_port']==capture['relay']['local_port'] and rn['peer_port']==capture['relay']['remote_port']
            and on['peer_port']==capture['proxy_out']['local_port']==ack['peer_port'] and on['local_port']==capture['origin']['local_port'],'a2_native_kernel_cross_binding')
        final_ticks=[v['qpc'][3] for v in (front,relay,origin)]+[j['proof']['end_qpc'],release['issued_qpc']]
        for role in ROLES:
            r=rows[role];v=reports[{ROLES[0]:'selected',ROLES[1]:'relay',ROLES[2]:'origin'}[role]]
            require(base.ac.integer(r['resume_qpc'],r['resume_intent_qpc'],j['pair']['end']-1)
                and base.ac.integer(r['exit_observed_qpc'],max(r['resume_qpc'],v['qpc'][3]),j['pair']['end']-1),'a2_held_exit_causal')
            final_ticks.extend((r['resume_qpc'],r['exit_observed_qpc']))
        require(base.ac.integer(j['completion_qpc'],max(final_ticks),j['pair']['end']-1),'a2_completion_causal');return True
    except (ValueError,KeyError,TypeError):return False


# The new scope keeps explicit source-bound validators; it does not reinterpret
# its ordinary actors as an old successful stream report.
RESULT_KEYS=(stream.RESULT_KEYS-set(stream.FALSE_CLAIMS))|set(FALSE_CLAIMS)|{'ports','core_check_completed','core_stop','core_stdio','port_lease','port_leases_closed','core_stdio_closed','tcp','barrier_commands','barrier_ack','barrier_released','core_integration_observed','kernel_tcp_snapshot_observed'}

def lease_facts(lease,c):
    planned=['startup',*(op+'-'+key for key in ('origin_port','proxy_port') for op in ('socket','exclusive','bind','read-exclusive','name'))]
    calls=lease['calls'];normal=[r for r in calls if r['operation']!='cleanup'];cleanup=[r for r in calls if r['operation']=='cleanup']
    require([r['operation'] for r in normal]==planned[:len(normal)] and len(normal)<=len(planned) and len(cleanup)<=1
        and (not cleanup or calls[-1] is cleanup[0]) and lease['cleanup_attempted']==bool(cleanup),'a2_lease_closed_operation_order')
    adopted={};handles=set();all_success=True
    for row in normal:
        value=row['value'];op=row['operation'];success=False
        if not row['returned']:
            require(value is None and row['exception'] and lease['unknown'],'a2_lease_unknown_API_return')
        else:
            require(type(value) in (tuple,list) and len(value)>=2 and all(type(x) is int for x in value[:2]),'a2_lease_raw_return_shape')
            status,error=value[:2]
            if op=='startup':
                require(len(value)==2,'a2_lease_startup_tuple');success=status==error==0
                require(lease['started']==success,'a2_lease_startup_ownership')
            elif op.startswith('socket-'):
                require(len(value)==2 and 0<=status<=LeaseBackend.INVALID,'a2_lease_socket_tuple');success=status!=LeaseBackend.INVALID and error==0 and status not in handles
                if success:adopted[op.removeprefix('socket-')]=status;handles.add(status)
                elif status!=LeaseBackend.INVALID:require(lease['unknown'],'a2_lease_indeterminate_socket')
            elif op.startswith('read-exclusive-'):
                require(len(value)==4 and all(type(x) is int for x in value),'a2_lease_option_tuple');success=list(value)==[0,0,1,4]
            elif op.startswith('name-'):
                key=op.removeprefix('name-');require(len(value)==3 and type(value[2]) is dict,'a2_lease_name_tuple')
                success=status==error==0 and value[2]==dict(family=2,port=c['ports'][key],address='7f000001',size=16)
            else:require(len(value)==2,'a2_lease_status_tuple');success=status==error==0
        if row['return_qpc'] is None:require(lease['unknown'],'a2_lease_unknown_return_QPC')
        # The producer may continue only after a successful, timely prior call.
        if row is not normal[-1]:require(success and not row['exception'] and row['return_qpc'] is not None and row['return_qpc']<work_cutoff(c),'a2_lease_no_continuation_after_failure')
        all_success &= success and not row['exception'] and row['return_qpc'] is not None and row['return_qpc']<work_cutoff(c)
    require({r['port_key'] for r in lease['closes']}==set(adopted) and len(lease['closes'])==len(adopted),'a2_lease_all_once_close_obligations')
    for row in lease['closes']:
        ok=type(row['value']) in (tuple,list) and list(row['value'])==[0,0] and all(type(x) is int for x in row['value']) and row['return_qpc'] is not None and not row['exception']
        require(not row['confirmed'] or ok,'a2_lease_close_not_boolean_override')
        if not ok:require(lease['unknown'],'a2_lease_close_unknown_sticky')
    if cleanup:
        r=cleanup[0];ok=r['returned'] and type(r['value']) in (tuple,list) and list(r['value'])==[0,0] and r['return_qpc'] is not None and not r['exception']
        require(lease['started'] and (not lease['cleanup_confirmed'] or ok),'a2_lease_cleanup_not_boolean_override')
        if not ok:require(lease['unknown'],'a2_lease_cleanup_unknown_sticky')
    else:require(not lease['cleanup_confirmed'] and not lease['started'],'a2_lease_missing_WSACleanup')
    known=not lease['unknown'] and (not lease['started'] or lease['cleanup_confirmed']) and all(r['confirmed'] for r in lease['closes'])
    return known,bool(all_success and len(normal)==len(planned)),cleanup

def validate_extension(j,c,*,parent,root,actions):
    require(j['ports']==c['ports'] and j['port']==c['ports']['origin_port'] and all(type(j[k]) is bool for k in ('core_check_completed','core_integration_observed','kernel_tcp_snapshot_observed','barrier_released','port_leases_closed','core_stdio_closed')),'a2_extension_flags')
    rows={r['name']:r for r in j['tasks']};pair=j['pair']
    if root is not None:verify_configuration(c,root)
    require(not j['profile_deleted'] or j['port_leases_closed'] and j['core_stdio_closed'],'a2_new_resources_before_profile_delete')
    require(type(j['core_stdio']) is list and len(j['core_stdio'])<=2,'a2_stdio_list');seen=set()
    for item in j['core_stdio']:
        require(type(item) is dict and set(item)=={'role','opened','closes','confirmed'} and item['role'] in CORE_ROLES and item['role'] not in seen
            and type(item['opened']) is list and len(item['opened'])<=3 and len(set(item['opened']))==len(item['opened'])
            and all(base.ac.integer(h,1,(1<<64)-1) for h in item['opened']) and type(item['confirmed']) is bool,'a2_stdio_state');seen.add(item['role'])
        closes=item['closes'];require(type(closes) is list and len(closes)<=3 and len({r['handle'] for r in closes})==len(closes),'a2_stdio_close_list')
        for r in closes:require(type(r) is dict and set(r)=={'handle','attempted','confirmed','qpc'} and r['handle'] in item['opened'] and r['attempted'] is True
            and type(r['confirmed']) is bool and (r['qpc'] is None or base.ac.integer(r['qpc'],c['start_qpc'],c['root_deadline_qpc'])),'a2_stdio_close')
        require(not item['confirmed'] or len(closes)==len(item['opened']) and all(r['confirmed'] for r in closes),'a2_stdio_confirmed')
        row=rows[item['role']]
        if row['admitted']:require(len(item['opened'])==3 and row['ends']==item['opened'] and item['confirmed']
            and all(base.ac.integer(r['qpc'],row['create_observation']['returned_qpc'],row['admission_qpc']) for r in closes),'a2_stdio_closed_before_admission')
    require(j['core_stdio_closed']==all(r['confirmed'] for r in j['core_stdio']),'a2_stdio_closed_recomputed')
    for role in CORE_ROLES:
        if rows.get(role,{}).get('admitted'):require(role in seen,'a2_admitted_core_stdio')
    lease=j['port_lease']
    if lease is not None:
        require(type(lease) is dict and set(lease)=={'calls','closes','unknown','started','cleanup_attempted','cleanup_confirmed'} and all(type(lease[k]) is bool for k in ('unknown','started','cleanup_attempted','cleanup_confirmed')),'a2_lease_record')
        require(type(lease['calls']) is list and len(lease['calls'])<=12 and type(lease['closes']) is list and len(lease['closes'])<=2,'a2_lease_record_bounds')
        for r in lease['calls']:require(type(r) is dict and set(r)=={'operation','returned','value','return_qpc','exception'} and type(r['operation']) is str
            and type(r['returned']) is type(r['exception']) is bool and (r['return_qpc'] is None or base.ac.integer(r['return_qpc'],c['start_qpc'],c['root_deadline_qpc'])),'a2_lease_call')
        for r in lease['closes']:require(type(r) is dict and set(r)=={'port_key','attempted','confirmed','value','return_qpc','exception'} and r['port_key'] in c['ports']
            and r['attempted'] is True and type(r['confirmed']) is type(r['exception']) is bool and (r['return_qpc'] is None or base.ac.integer(r['return_qpc'],c['start_qpc'],c['root_deadline_qpc'])),'a2_lease_close_record')
        known,successful,_=lease_facts(lease,c)
        require(j['port_leases_closed']==known,'a2_lease_cleanup_recomputed')
    else:require(not any(a['action']=='port-leases' for a in actions) or not j['core_integration_observed'],'a2_no_fabricated_lease_positive')
    if j['core_check_completed']:
        r=rows[CORE_ROLES[0]];require(all(r[k] for k in ('admitted','resumed','exited')) and r['exit_code']==0 and r['exit_observed_qpc']>=r['resume_qpc'],'a2_check_natural_exit')
    for role in (*ROLES,CORE_ROLES[1]):
        if rows.get(role,{}).get('resumed'):require(j['core_check_completed'] and rows[CORE_ROLES[0]]['exit_observed_qpc']<=rows[role]['resume_intent_qpc'],'a2_config_check_before_runtime_roles')
    require(type(j['tcp']) is dict and set(j['tcp'])<= {'listeners','two_hop'},'a2_TCP_slots')
    if j['tcp']:
        proxy,origin=rows[CORE_ROLES[1]],rows[ROLES[2]]
        for key,r in j['tcp'].items():
            require(type(r) is dict and r['name']==('listeners.bin' if key=='listeners' else 'two-hop.bin'),'a2_TCP_path')
            if root is not None:
                raw=local.bounded(launcher.checked_path(Path(root)/'tcp'/r['name'],inside=root),1048576)
                if key=='listeners':parsed=exact_listeners(raw,proxy_pid=proxy['pid'],origin_pid=origin['pid'],declared=c['ports'])
                else:
                    ack=legacy.record_value(j['barrier_ack']);parsed=exact_two_hop(raw,relay_pid=rows[ROLES[1]]['pid'],proxy_pid=proxy['pid'],origin_pid=origin['pid'],declared=c['ports'],origin_peer_port=ack['peer_port'])
                validate_tcp_record(r,root=root,expected_rows=parsed)
            require(base.ac.integer(r['before_qpc'],c['start_qpc'],work_cutoff(c)-1) and base.ac.integer(r['after_qpc'],r['before_qpc'],work_cutoff(c)-1),'a2_TCP_original_time')
            for role in (ROLES[2],CORE_ROLES[1],ROLES[1]) if key=='two_hop' else (ROLES[2],CORE_ROLES[1]):
                snapshots=rows[role]['held_checks'];require(any(h['qpc']<=r['before_qpc'] for h in snapshots) and any(h['qpc']>=r['after_qpc'] for h in snapshots),'a2_TCP_held_brackets')
    require(not j['kernel_tcp_snapshot_observed'] or 'two_hop' in j['tcp'],'a2_TCP_observed')
    commands=j['barrier_commands'];require(type(commands) is dict and set(commands)<={'arm','release'},'a2_command_slots')
    ack=None
    if j['barrier_ack'] is not None:
        ack=legacy.record_value(j['barrier_ack'],root=root,path=BARRIER_PATHS['ack'])
        validate_ack(ack,c,pair,origin_pid=rows[ROLES[2]]['pid'],arm_issued=commands['arm']['issued_qpc'])
    for key,r in commands.items():
        require(type(r) is dict and set(r)=={'path','hex','sha256','issued_qpc','intent_qpc','published_qpc'} and r['path']==BARRIER_PATHS[key]
            and type(r['hex']) is str and len(r['hex'])==256 and base.ac.digest(r['sha256']),'a2_command_record')
        raw=bytes.fromhex(r['hex']);require(sha(raw)==r['sha256'] and raw==barrier_control(c,pair,r['issued_qpc'],release=key=='release',ack=ack if key=='release' else None),'a2_command_bytes')
        entries=[a for a in actions if a['action']=='barrier-'+key];require(len(entries)==1 and entries[0]['qpc']==r['intent_qpc'] and r['intent_qpc']<=r['issued_qpc'],'a2_command_intent')
        if key=='release':require(entries[0]['extra']==dict(ack_sha256=j['barrier_ack']['sha256'],tcp_sha256=j['tcp']['two_hop']['sha256']),'a2_release_physical_commitments')
        else:require(entries[0]['extra']==dict(ack_sha256=None,tcp_sha256=None),'a2_arm_extra')
        if r['published_qpc'] is not None:
            require(base.ac.integer(r['published_qpc'],r['issued_qpc'],pair['end']-1),'a2_command_publication_clock')
            if root is not None:require(local.bounded(launcher.checked_path(Path(root)/r['path'],inside=root),128)==raw,'a2_command_physical_bytes')
    if any(rows.get(role,{}).get('resumed') for role in ROLES[:2]):
        require('arm' in commands and commands['arm']['published_qpc'] is not None and all(rows[role]['resume_intent_qpc']>=commands['arm']['published_qpc'] for role in ROLES[:2]),'a2_arm_before_pair_resume')
    require(not j['barrier_released'] or 'release' in commands and commands['release']['published_qpc'] is not None,'a2_release_published')
    stop=j['core_stop']
    if stop is not None:
        require(type(stop) is dict and set(stop)=={'role','pid','created','image_sha256','intent_qpc','receipt','observation','observed_exit_qpc','exit_code'} and stop['role']==CORE_ROLES[1],'a2_stop_schema')
        row=rows[CORE_ROLES[1]];require([stop[k] for k in ('pid','created','image_sha256')]==[row[k] for k in ('pid','created','image_sha256')],'a2_stop_exact_child')
        require(j['core_integration_observed'] and j['completion_qpc'] is not None and j['completion_qpc']<=stop['intent_qpc'],'a2_stop_after_completed_data_evidence')
        entries=[a for a in actions if a['action']=='core-stop'];require(len(entries)==1 and entries[0]['qpc']==stop['intent_qpc'] and entries[0]['extra']=={'role':CORE_ROLES[1]},'a2_stop_intent')
        if stop['observation'] is not None:
            v=stop['observation'];require(type(v) is dict and set(v)=={'attempted','returned','raw_return','error','returned_qpc','exception'} and v['attempted'] is True and type(v['returned']) is bool
                and (v['raw_return'] is None or base.ac.integer(v['raw_return'],0,0x7fffffff)) and (v['error'] is None or base.ac.integer(v['error'],0,0xffffffff))
                and (v['returned_qpc'] is None or base.ac.integer(v['returned_qpc'],stop['intent_qpc'],c['root_deadline_qpc'])),'a2_stop_raw_observation');base.validate_failure_detail(v['exception'])
            require(any(h['qpc']>=stop['intent_qpc'] and (v['returned_qpc'] is None or h['qpc']<=v['returned_qpc']) for h in row['held_checks']),'a2_stop_fresh_held_snapshot')
        if stop['receipt'] is not None:
            r=stop['receipt'];require(set(r)=={'name','text','sha256'} and r['name']=='core-stop.json','a2_stop_receipt_name')
            v=legacy.record_value({k:r[k] for k in ('text','sha256')},root=root,path='returns/'+r['name'])
            require(v==dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),role=CORE_ROLES[1],intent_qpc=stop['intent_qpc'],observation=stop['observation']),'a2_stop_physical_receipt')
        if stop['observed_exit_qpc'] is not None:require(row['exited'] and stop['exit_code']==row['exit_code']==1 and stop['observed_exit_qpc']==row['exit_observed_qpc'],'a2_stop_held_exit')
    require(not j['core_integration_observed'] or positive(j,c,parent),'a2_finite_integration_recomputed')
    if j['core_integration_observed']:
        require(lease is not None and lease['started'] and len(lease['closes'])==2 and {r['port_key'] for r in lease['closes']}==set(c['ports'])
            and len([a for a in actions if a['action']=='port-leases'])==1,'a2_both_fixed_port_leases')
        known,successful,cleanup=lease_facts(lease,c);require(known and successful,'a2_positive_lease_raw_success')
        for r in lease['closes']:
            role=ROLES[2] if r['port_key']=='origin_port' else CORE_ROLES[1]
            require(base.ac.integer(r['return_qpc'],c['start_qpc'],rows[role]['resume_intent_qpc']),'a2_lease_closed_before_listener')
        require(cleanup[0]['return_qpc']<=rows[CORE_ROLES[1]]['resume_intent_qpc'],'a2_lease_WSA_closed_before_core')
    if j['mechanism_verified']:
        require(j['core_integration_observed'] and stop is not None and stop['receipt'] is not None and stop['observation'] is not None,'a2_controlled_stop_required')
        v=stop['observation'];require(v['returned'] and v['raw_return']!=0 and v['error']==0 and v['exception'] is None
            and base.ac.integer(v['returned_qpc'],stop['intent_qpc'],work_cutoff(c)-1) and base.ac.integer(stop['observed_exit_qpc'],v['returned_qpc'],work_cutoff(c)-1)
            and stop['exit_code']==1,'a2_only_core_exit_exception')

def validate_result(j,c,*,parent,root=None):
    config_validate(c);require(launcher.token_is_ordinary(parent),'ipc_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1 and j['stage']=='lpac-stream-mihomo-origin-result'
        and j['scope']==SCOPE and j['profile']==PROFILE and j['config_sha256']==sha(encode(c)) and j['profile_name']=='ruleproxy-lpac-a2-'+c['run'],'ipc_result')
    require(j['failure'] is None or j['failure'] in ('setup','ports','core-check','origin','core','pair','accesscheck','protocol','core-stop','cleanup'),'ipc_failure');base.validate_failure_detail(j['failure_detail'])
    launcher.validate_child_environment(j['child_environment']);require(all(j[k] is False for k in FALSE_CLAIMS),'ipc_fixed_false')
    bools={'pipe_allocation_unknown','creation_unknown','observer_attempted','selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed','mechanism_verified','natural_exits','workload_stop',*CLEAN_KEYS}
    require(all(type(j[k]) is bool for k in bools),'ipc_bool_facts')
    state=j['profile_state'];require(type(state) is dict and set(state)=={'attempted','returned','created','sid_pointer_returned'} and all(type(v) is bool for v in state.values())
        and (not state['created'] or state['attempted'] and state['returned']) and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'ipc_profile_ownership')
    pair=j['pair']
    if pair is not None:require(type(pair) is dict and set(pair)=={'start','end','frequency'} and pair['frequency']==c['frequency'] and base.ac.integer(pair['start'],c['start_qpc'],work_cutoff(c))
        and pair['end']==pair['start']+10*c['frequency'] and pair['end']<=work_cutoff(c),'ipc_pair_clock')
    require(type(j['intents']) is list and len(j['intents'])<=48,'ipc_intent_list');actions=[];ticks=[]
    for i,r in enumerate(j['intents']):
        require(type(r) is dict and set(r)=={'name','text','sha256'} and r['name'].startswith('%02d-'%i) and '/' not in r['name'] and '\\' not in r['name'],'ipc_intent_name')
        v=record_value({k:r[k] for k in ('text','sha256')},root=root,path='journal/'+r['name'],limit=4096)
        require(set(v)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action','extra'} and v['schema_version']==1 and type(v['schema_version']) is int
            and v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['frequency']==c['frequency'] and v['deadline_qpc']==c['deadline_qpc']
            and base.ac.integer(v['qpc'],c['start_qpc'],c['root_deadline_qpc']) and type(v['extra']) is dict,'ipc_intent_binding')
        require(r['name']=='%02d-%s.json'%(i,v['action']),'ipc_intent_exact_name');actions.append(v);ticks.append(v['qpc'])
    require(ticks==sorted(ticks),'ipc_intent_order')
    require(type(j['tasks']) is list and type(j['cleanup_tasks']) is list and len(j['tasks'])<=9 and len(j['cleanup_tasks'])<=1,'ipc_task_bounds')
    rows={}
    for r in (*j['tasks'],*j['cleanup_tasks']):
        require(type(r) is dict and set(r)==TASK_KEYS and r['name'] not in rows and r['name'] in (*ROLES,*CORE_ROLES,*('grant-'+g[0] for g in GRANTS),'remove'),'ipc_task_schema');rows[r['name']]=r
        require(all(type(r[k]) is bool for k in ('attempted','assigned','exited','resumed','admitted','lpac_expected','process_returned')) and r['lpac'] is None and r['go_qpc']==[],'ipc_task_flags')
        require(r['exit_code'] is None or base.ac.integer(r['exit_code'],0,0xffffffff),'ipc_exit_code')
        require(not r['resumed'] or r['admitted'] and r['process_returned'] and r['assigned'],'ipc_task_resume_gate')
        require(not r['exited'] or r['process_returned'] and r['exit_code'] is not None,'ipc_task_exit')
        require((r['pid'] is None or base.ac.integer(r['pid'],1,0xffffffff)) and (r['created'] is None or base.ac.integer(r['created'],1,0x7fffffffffffffff)),'ipc_task_generation')
        o=r['create_observation'];require(type(o) is dict and set(o)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'} and o['status'] in ('not_entered','exception','returned_false','returned_true')
            and o['process_information'] in ('not_observed','all_zero','nonzero') and (o['winerror'] is None or base.ac.integer(o['winerror'],0,0xffffffff))
            and base.ac.integer(o['work_cutoff'],c['start_qpc'],c['deadline_qpc']) and (o['returned_qpc'] is None or base.ac.integer(o['returned_qpc'],c['start_qpc'],c['root_deadline_qpc'])),'ipc_create_observation')
        base.validate_failure_detail(o['exception_detail'])
        require(not r['admitted'] or r['assigned'] and r['process_returned'] and r['attempted'] and r['identity'] is not None and r['capabilities']==[]
            and r['created'] is not None and base.ac.integer(r['admission_qpc'],c['start_qpc'],o['work_cutoff']-1),'ipc_admission_clock')
        if r['role'] in (*ROLES,*CORE_ROLES):
            role=r['role'];require(r['name']==role and r['lpac_expected']==(role=='lpac-pipe-front'),'ipc_role')
            require(o['work_cutoff']==(pair['end'] if role in ROLES[:2] else work_cutoff(c)),'ipc_role_cutoff')
            require(r['exit_observed_qpc'] is None or r['exited'] and base.ac.integer(r['exit_observed_qpc'],c['start_qpc'],c['root_deadline_qpc']),'ipc_exit_observation')
            if r['expected_primary'] is not None:
                p=r['expected_primary'];zero.identity_shape(p)
                require(p['token_type']==1 and p['impersonation_level'] is None and p['capabilities']==[] and p['sid']==parent['sid'] and p['session_id']==parent['session_id']
                    and p['elevated'] is p['ui_access'] is False and p['appcontainer']==(role=='lpac-pipe-front') and p['appcontainer_sid']==(j['profile_sid'] if role=='lpac-pipe-front' else None),'ipc_primary_role')
                if role=='lpac-pipe-front':zero.identity(p,primary=True)
                else:require(p['integrity_rid']==parent['integrity_rid'],'ipc_ordinary_il')
            require(type(r['held_checks']) is list and len(r['held_checks'])<=64,'ipc_held_snapshots')
            for h in r['held_checks']:
                require(type(h) is dict and set(h)=={'qpc','pid','created','image_sha256','primary','inner_job','outer_job'} and h['pid']==r['pid'] and h['created']==r['created']
                    and h['image_sha256']==r['image_sha256'] and h['primary']==r['expected_primary'] and h['inner_job'] is h['outer_job'] is True
                    and base.ac.integer(h['qpc'],c['start_qpc'],(pair['end'] if pair and role in ROLES[:2] else work_cutoff(c))-1),'ipc_held_snapshot')
            if r['admitted']:
                require(r['expected_primary'] is not None and r['held_checks'] and r['identity'] is not None,'ipc_admitted_external_identity')
                require(base.ac.integer(o['returned_qpc'],pair['start'] if role in ROLES[:2] else c['start_qpc'],r['admission_qpc'])
                    and r['held_checks'][0]['qpc']>=o['returned_qpc'] and r['held_checks'][0]['qpc']<=r['admission_qpc']
                    and [h['qpc'] for h in r['held_checks']]==sorted(h['qpc'] for h in r['held_checks']),'ipc_admission_return_causality')
                require(all(r['identity'][k]==r['expected_primary'][k] for k in ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access'))
                    and r['identity']['capability_count']==0,'ipc_external_identity_consistency')
            require(type(r['command']) is list and all(type(a) is str for a in r['command']),'ipc_command_shape')
            command_root=Path(root) if root is not None else Path(r['command'][2]).parent if role in CORE_ROLES else Path(r['command'][0]).parent.parent
            require(r['command']==expected_argv(role,j,c,command_root,parent) and r['image_sha256']==c['mihomo_sha256' if role in CORE_ROLES else 'actor_sha256' if role=='lpac-pipe-front' else 'network_actor_sha256'],'ipc_closed_argv')
            receipt=r['receipt']
            if receipt is not None:
                require(set(receipt)=={'name','text','sha256'} and receipt['name']==role+'.json','ipc_create_receipt_name')
                v=record_value({k:receipt[k] for k in ('text','sha256')},root=root,path='returns/'+receipt['name'])
                require(set(v)=={'schema_version','scope','config_sha256','role','observation','raw_return','raw_error','pi'} and v['schema_version']==1 and type(v['schema_version']) is int
                    and v['scope']==SCOPE and v['config_sha256']==sha(encode(c)) and v['role']==role and v['observation']==r['create_observation']
                    and type(v['pi']) is list and len(v['pi'])==4 and all(base.ac.integer(x,0,(1<<64)-1 if i<2 else 0xffffffff) for i,x in enumerate(v['pi'])),'ipc_raw_pi_receipt')
                if r['process_returned']:require(v['observation']['status']=='returned_true' and all(v['pi']) and v['pi'][0]!=v['pi'][1] and v['pi'][2]==r['pid'],'ipc_trusted_pi_only_success')
                if r['attempted']:
                    require(v['raw_return'] is None or base.ac.integer(v['raw_return'],0,0x7fffffff),'ipc_pair_raw_bool')
                    require(v['raw_error'] is None or base.ac.integer(v['raw_error'],0,0xffffffff),'ipc_pair_raw_error')
                    if r['admitted']:require(v['raw_return'] is not None and v['raw_return']!=0 and v['raw_error'] is None,'ipc_admitted_true_api_return')
                    known_success=v['raw_return'] is not None and v['raw_return']!=0 and v['observation']['status']=='returned_true' and all(v['pi']) and v['pi'][0]!=v['pi'][1]
                    known_none=base.known_no_child(r,start=c['start_qpc'])
                    require(not (not known_success and not known_none) or j['creation_unknown'],'ipc_unknown_creation_sticky')
            if r['resumed']:
                entries=[a for a in actions if a['action']=='resume-authorized' and a['extra']=={'role':role}]
                require(len(entries)==1 and r['resume_intent_qpc']==entries[0]['qpc'] and r['resume_qpc']>=r['resume_intent_qpc'],'ipc_resume_physical_intent')
            if r['admitted']:require(receipt is not None,'ipc_admitted_return_receipt')
    require(type(j['pipe_allocations']) is list and len(j['pipe_allocations'])<=2,'ipc_pipe_allocations')
    allocated=[]
    for i,r in enumerate(j['pipe_allocations']):
        keys={'name','receipt','attempted','returned','api_success','error','raw_outputs','unknown','adopted','readback','return_qpc'}
        require(type(r) is dict and set(r)==keys and r['name']==('response','request')[i] and all(type(r[k]) is bool for k in ('attempted','returned','unknown','adopted','readback')),'ipc_pipe_state')
        if r['attempted'] and not r['api_success']:require(r['unknown'] and j['pipe_allocation_unknown'] and not r['adopted'],'ipc_failed_pipe_indeterminate')
        if r['adopted']:
            require(r['api_success'] is True and r['returned'] and type(r['raw_outputs']) is list and len(r['raw_outputs'])==2 and all(base.ac.integer(h,1,(1<<64)-1) for h in r['raw_outputs'])
                and len(set((*allocated,*r['raw_outputs'])))==len(allocated)+2,'ipc_adopted_pipe_pair');allocated+=r['raw_outputs']
            require(r['receipt'] is not None and base.ac.integer(r['return_qpc'],pair['start'],c['root_deadline_qpc']),'ipc_pipe_owned_return_receipt')
        if r['readback']:require(r['adopted'] and base.ac.integer(r['return_qpc'],pair['start'],pair['end']-1),'ipc_pipe_readback_clock')
        if r['receipt'] is not None:
            receipt=r['receipt'];needname='pipe-'+r['name']+'.json';require(receipt['name']==needname,'ipc_pipe_receipt_name')
            v=record_value({k:receipt[k] for k in ('text','sha256')},root=root,path='returns/'+needname)
            require(v==dict(schema_version=1,scope=SCOPE,config_sha256=sha(encode(c)),pipe=r['name'],observation={k:v for k,v in r.items() if k not in ('name','receipt')}),'ipc_pipe_return_binding')
    closes=j['parent_pipe_close_attempts'];require(type(closes) is list and len(closes)<=4 and all(type(r) is dict and set(r)=={'handle','attempted','confirmed'} and r['handle'] in allocated
        and r['attempted'] is True and type(r['confirmed']) is bool for r in closes) and len({r['handle'] for r in closes})==len(closes),'ipc_parent_closes')
    if any(r['resumed'] for r in j['tasks'] if r['role'] in ('lpac-pipe-front','ordinary-pipe-relay')):
        require(len(allocated)==4 and len(closes)==4 and all(r['confirmed'] for r in closes) and all(r['readback'] for r in j['pipe_allocations']) and not j['pipe_allocation_unknown']
            and j['proof'] is not None and j['proof']['qualified'] and j['observer_resources_cleanup_verified'],'ipc_pair_resume_proof_and_closes')
    if len(allocated)==4:
        for role,ends in (('lpac-pipe-front',[allocated[0],allocated[3]]),('ordinary-pipe-relay',[allocated[2],allocated[1]])):
            if role in rows:require(rows[role]['ends']==ends,'ipc_pipe_direction')
    if j['proof'] is not None:
        front=rows['lpac-pipe-front'];zero.validate_proof(j['proof'],expected_primary_identity=front['expected_primary'],expected_role='lpac',expected_pid=front['pid'],expected_creation=front['created'],frequency=c['frequency'],deadline=pair['end'])
        require(j['observer_attempted'] and j['observer_resources_cleanup_verified']==j['proof']['resource_cleanup_verified'],'ipc_proof_resources')
        observe=[a for a in actions if a['action']=='observe-lpac'];require(len(observe)==1,'ipc_single_observer_intent')
        if j['proof']['start_qpc'] is not None:require(front['admission_qpc']<=observe[0]['qpc']<=j['proof']['start_qpc'],'ipc_observer_causality')
        for role in ('lpac-pipe-front','ordinary-pipe-relay'):
            if rows.get(role,{}).get('resumed'):
                close=[a for a in actions if a['action']=='parent-pipe-close'];require(len(close)==1 and j['proof']['end_qpc']<=close[0]['qpc']<=rows[role]['resume_intent_qpc'],'ipc_proof_before_pair_resume')
    require(type(j['reports']) is dict and set(j['reports'])==set(REPORT_PATHS) and type(j['report_status']) is dict and set(j['report_status'])==set(REPORT_PATHS),'ipc_native_slots')
    for key,r in j['reports'].items():
        require(j['report_status'][key] in ('unavailable','valid','invalid') and (r is None)==(j['report_status'][key]=='unavailable'),'ipc_report_availability')
        if r is not None:
            raw=r['text'].encode('ascii');require(len(raw)<=MAX_NATIVE and sha(raw)==r['sha256'],'ipc_native_raw')
            if root is not None:require(local.bounded(launcher.checked_path(Path(root)/REPORT_PATHS[key],inside=root),MAX_NATIVE)==raw,'ipc_native_physical')
            if j['report_status'][key]=='valid':validate_native(key,decode(raw),j,c,parent)
    require(type(j['labels']) is list and len(j['labels'])<=1,'ipc_label_scope')
    for r in j['labels']:require(type(r) is dict and set(r)=={'name','before','attempted','lowered','restored'} and r['name']=='selected-report' and r['before'] is None
        and all(type(r[k]) is bool for k in ('attempted','lowered','restored')) and (not r['lowered'] or r['attempted']) and (not r['restored'] or r['attempted']),'ipc_label_state')
    require(not j['labels_restored'] or all(not r['attempted'] or r['restored'] for r in j['labels']),'ipc_label_restore')
    require(not j['pipe_allocation_known'] or not j['pipe_allocation_unknown'],'ipc_allocation_known')
    require(not j['profile_deleted'] or all(j[k] for k in ('workload_cleanup','workload_job_empty','parent_pipe_handles_closed','pipe_allocation_known','observer_resources_cleanup_verified','labels_restored','acl_removed','cleanup_tools'))
        and not j['creation_unknown'],'ipc_profile_delete_gate')
    if state['created'] and j['cleanup_tools'] and j['acl_removed']:
        require(len(j['cleanup_tasks'])==1 and j['cleanup_tasks'][0]['name']=='remove' and all(j['cleanup_tasks'][0][k] for k in ('attempted','process_returned','assigned','admitted','resumed','exited'))
            and j['cleanup_tasks'][0]['exit_code']==0,'ipc_cleanup_tool_ledger')
    validate_sinks(j,c,root=root)
    copy=dict(j);harvest(copy,c,parent)
    require(all(not copy[k] or j[k] for k in ('selected_ipc_observed','relay_connect_observed','origin_accepted_observed','origin_request_observed','origin_response_observed')),'ipc_sticky_facts')
    require(not j['mechanism_verified'] or positive(j,c,parent),'ipc_mechanism_recomputed')
    validate_extension(j,c,parent=parent,root=root,actions=actions)
    if j['failure'] is None:require(j['mechanism_verified'] and all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'],'a2_complete_result')
    return j


def controlled_stop_confirmed(j):
    r=j['core_stop']
    if r is None or r['observation'] is None:return False
    v=r['observation']
    return (r['receipt'] is not None and v['returned'] and type(v['raw_return']) is int and v['raw_return']!=0
        and v['error']==0 and v['exception'] is None and r['observed_exit_qpc'] is not None and r['exit_code']==1)

def project(j,c,*,parent,root=None):
    validate_result(j,c,parent=parent,root=root)
    cleanup=all(j[k] for k in CLEAN_KEYS) and not j['creation_unknown'];complete=j['failure'] is None and j['mechanism_verified'] and cleanup and not j['workload_stop']
    return dict(schema_version=1,stage='lpac-stream-mihomo-origin-observation',scope=SCOPE,profile=PROFILE,mechanism_verified=complete,
        selected_stream_observed=j['selected_ipc_observed'],semantic_lpac_verified=j['proof'] is not None and j['proof']['qualified'],network_tested=j['relay_connect_observed'] or j['origin_accepted_observed'],
        network_scope='ordinary-relay-to-held-mihomo-to-owned-origin-only',relay_connect_observed=j['relay_connect_observed'],origin_accepted_observed=j['origin_accepted_observed'],
        origin_request_observed=j['origin_request_observed'],origin_response_observed=j['origin_response_observed'],payloads_verified=payloads_passed(j,c,parent),native_report_status=dict(j['report_status']),
        finite_core_integration_observed=j['core_integration_observed'],core_config_check_completed=j['core_check_completed'],core_controlled_stop_confirmed=controlled_stop_confirmed(j),
        kernel_tcp_snapshot_observed=j['kernel_tcp_snapshot_observed'],cleanup_known=cleanup,failure=j['failure'],
        http_boundary='canonical-HTTP-Content-Length-message-with-real-proxy-EOF-not-transparent-TCP-FIN',**{k:j[k] for k in CLEAN_KEYS},**dict.fromkeys(FALSE_CLAIMS,False))

def execute(root,c,parent,api,budget):return Owner(root,c,parent,api,budget).execute()
