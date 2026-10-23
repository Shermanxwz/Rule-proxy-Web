"""Source-bound experimental curl loader owner; no transport adapter.

WORK prototype, ACTUAL_READY=False. Construction of the production backend is
reserved for the separately reviewed, explicitly opted-in guarded entry.
"""
from __future__ import annotations
import ctypes as C
import datetime
import importlib.util
import os
from pathlib import Path, PureWindowsPath
import re
import struct
import subprocess
import uuid

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
zero=load('curl_loader_zero','windows_identity_lpac_loopback.py')
cell=zero.identity_cell
base,access=cell.owner,cell.access
local,launcher,helpers,live=base.local,base.launcher,base.helpers,base.live
require,sha,encode,decode=base.require,base.sha,base.encode,base.decode
MODULE='.github/windows_identity_lpac_curl_mm_loader.py'
LOCAL_MODULE='.github/windows_identity_lpac_curl_mm_loader_local.py'
SCOPE='one-local-held-zero-cap-lpac-curl-memory-map-observation-v1'
PROFILE='zero-cap-curl-memory-map-observation-with-version-controls-v1'
ACTUAL_READY=True
NONCES=('run','before_case','selected_case','after_case')
WRAPPER='windows_identity_lpac_curl_mm_loader_wrapper.dll'
MARKER='windows_identity_lpac_curl_mm_loader_marker.dll'
MANIFEST='identity-lpac-curl-mm-loader-manifest.json'
CURL_BYTES=818512
CURL_SHA256='73d24149ff289afc49ec41f08918ef9faa727d39ad993e929757dc2ddafab805'
MAX_REPORT=1024*1024
MAX_OUTPUT=8192
# The final backend closure is a reviewed constant, never a manifest-selected list.
NATIVE_SOURCE_CLOSURE_FINAL=True
NATIVE_SOURCES=tuple('.github/native/windows_identity_lpac_curl_mm_loader_'+n for n in
    ('wrapper.hpp','core.hpp','ownership.hpp','operations.hpp','marker_core.hpp','backend.hpp','context.hpp','win32.hpp','wrapper.cpp','marker.cpp','marker.def'))
INPUT_MODULE='.github/windows_identity_lpac_curl_mm_inputs.py'
PROTOCOL_MODULE='.github/windows_identity_lpac_curl_mm_protocol.py'
READER_MODULE='.github/windows_identity_lpac_curl_mm_binary_reader.py'
protocol=load('cmm_owner_protocol','windows_identity_lpac_curl_mm_protocol.py')
# The independent byte reader is supplied as its own reviewed source input.
reader=load('cmm_owner_reader','windows_identity_lpac_curl_mm_binary_reader.py')
VENDOR_FILES=('src/Makefile','src/creatwth.cpp','src/detours.cpp','src/detours.h','src/detver.h','src/disasm.cpp','src/disolarm.cpp','src/disolarm64.cpp','src/disolia64.cpp','src/disolx64.cpp','src/disolx86.cpp','src/image.cpp','src/modules.cpp','src/uimports.cpp','CREDITS.md','LICENSE','LICENSE.md','Makefile','README.md','system.mak')
# Final freeze recomputes the complete physical union; unused old actor/native
# protocol sources are not rebound or impersonated by this new owner.
SOURCES=tuple(dict.fromkeys((*cell.SOURCES,zero.MODULE,MODULE,LOCAL_MODULE,INPUT_MODULE,PROTOCOL_MODULE,READER_MODULE,*NATIVE_SOURCES,*('.github/vendor/detours/'+n for n in VENDOR_FILES))))
ACKS=('fresh_profile_owned_acl_acknowledged','existing_curl_instrumentation_acknowledged','zero_capabilities_no_fallback_acknowledged',
      'partial_remote_memory_acknowledged','restore_unknown_acknowledged','mapping_race_acknowledged',
      'ordinary_version_controls_acknowledged','same_sid_unqualified_acknowledged','no_network_adapter_acknowledged')
FALSE_CLAIMS=('restoration_fully_verified','restore_payload_absence_verified','DllMain_return_proven_by_event','curl_entry_proven_by_event',
              'winsock_absence_verified','curl_network_adapter_qualified','hostile_same_sid_boundary_verified','dns_isolation_qualified',
              'PSEC_qualified','proxy_qualified','Linux_equivalence','product_acceptance','whole_mapped_image_integrity_verified','section_handle_mapping_proven')
CLEAN_KEYS=('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified','parent_event_stdio_closed',
            'marker_file_closed','target_file_closed','outer_query_closed','native_resources_closed','query_resources_closed','labels_restored','acl_removed','cleanup_tools','profile_deleted','sid_released')
ARTIFACT_KEYS=('curl','wrapper','marker','manifest')
OBS_BOOLS=('ordinary_before_positive','ordinary_after_positive','lpac_identity_verified','update_returned_true',
           'payload_installed','selected_resumed','entered_event_observed','body_event_observed','coherent_marker_observed',
           'memory_mapping_correlated','selected_natural_exit','selected_version_positive','loader_mechanism_observed',
           'version_behavior_observed','observation_complete','native_critical_complete','trace_complete',*CLEAN_KEYS)
OBS_KEYS={'failure','selected_exit_code',*OBS_BOOLS,*FALSE_CLAIMS}

def api_version():return 2
def stage_name(run):return 'local-lpac-curl-mm-loader-'+run
def work_cutoff(c):return c['root_deadline_qpc']-35*c['frequency']
def artifact_paths(root):
    return dict(wrapper=root/'owner-inputs'/WRAPPER,marker=root/'package'/MARKER,manifest=root/'owner-inputs'/MANIFEST)
def argv(c):return [c['curl_path'],'--disable','--version']

def curl_command_matches_system(command,system_path):
    # GetSystemDirectoryW may spell the same already pinned Windows path with
    # different casing. Compare Windows paths, not case-sensitive strings;
    # preserve the original requested argv bytes for CreateProcessW.
    if type(command) is not list or len(command)!=3 or any(type(v) is not str for v in command):return False
    if command[1:]!=['--disable','--version']:return False
    try:requested,expected=PureWindowsPath(command[0]),PureWindowsPath(system_path)
    except (TypeError,ValueError):return False
    dos_paths=all(p.is_absolute() and len(p.drive)==2 and p.drive[1]==':'
        and 'A'<=p.drive[0].upper()<='Z' and p.root=='\\' and '..' not in p.parts for p in (requested,expected))
    return dos_paths and requested==expected

def private_process_thread_sddl(value,parent_sid):
    # Process/thread generic-all can be serialized as the Vista+ mapped mask.
    # Accept only the same protected two-allow-ACE layout and exact trustees;
    # retain the original observed strings for subsequent held equality.
    if type(value) is not str or type(parent_sid) is not str or launcher.SID_PATTERN.fullmatch(parent_sid) is None:return False
    masks=('GA','0x1fffff')
    return any(value=='D:P(A;;'+system+';;;SY)(A;;'+parent+';;;'+parent_sid+')' for system in masks for parent in masks)

def validate_artifact_pins(value):
    require(type(value) is dict and set(value)==set(ARTIFACT_KEYS),'loader_artifact_set')
    for k,r in value.items():
        require(type(r) is dict and set(r)=={'bytes','sha256'} and live.integer(r['bytes'],1,8*1024*1024)
                and base.ac.digest(r['sha256']),'loader_artifact_pin')
    require(value['curl']==dict(bytes=CURL_BYTES,sha256=CURL_SHA256),'loader_curl_fixed')
    return value

def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','profile',*NONCES,'start_qpc','frequency','root_deadline_qpc','deadline_qpc','guard_job_name',
          'source_hashes','source_sha256','device_sha256','recovery_plan_sha256','artifacts','curl_path'}
    require(type(c) is dict and set(c)==keys and c['schema_version']==1 and type(c['schema_version']) is int
            and c['scope']==SCOPE and c['profile']==PROFILE,'loader_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and len({c[k] for k in NONCES})==4,'loader_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency']
            and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
            and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'loader_clock')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names)
            and all(base.ac.digest(v) for v in c['source_hashes'].values())
            and sha(encode(c['source_hashes']))==c['source_sha256'],'loader_sources')
    require(all(base.ac.digest(c[k]) for k in ('source_sha256','device_sha256','recovery_plan_sha256')),'loader_digest')
    require(type(c['curl_path']) is str and Path(c['curl_path']).is_absolute() and Path(c['curl_path']).name.casefold()=='curl.exe','loader_curl_path')
    validate_artifact_pins(c['artifacts']);return c

def validate_plan(p,*,device,source,artifacts,curl_path):
    keys={'schema_version','scope','profile',*NONCES,'device_sha256','source_sha256','artifacts','curl_path','recovery_reference',*ACKS}
    require(type(p) is dict and set(p)==keys and p['schema_version']==1 and type(p['schema_version']) is int
            and p['scope']==SCOPE and p['profile']==PROFILE,'loader_plan')
    require(all(base.ac.nonce(p[k]) for k in NONCES) and len({p[k] for k in NONCES})==4,'loader_plan_nonces')
    require(p['device_sha256']==device and p['source_sha256']==source and p['artifacts']==artifacts and p['curl_path']==curl_path,'loader_plan_binding')
    validate_artifact_pins(artifacts)
    require(all(p[k] is True for k in ACKS) and type(p['recovery_reference']) is str and 400<=len(p['recovery_reference'])<=2048,'loader_plan_ack')
    return p

def version_output(raw,stderr):
    require(type(raw) is bytes and type(stderr) is bytes and len(raw)<=MAX_OUTPUT and len(stderr)<=MAX_OUTPUT,'loader_output_bound')
    r=dict(stdout_bytes=len(raw),stdout_sha256=sha(raw),stderr_bytes=len(stderr),stderr_sha256=sha(stderr),recognized=False)
    if not raw or stderr:return r
    try:text=raw.decode('ascii')
    except UnicodeDecodeError:return r
    if any(ord(ch)<32 and ch not in '\r\n' or ord(ch)==127 for ch in text):return r
    if '\r' in text and text.replace('\r\n','').find('\r')!=-1:return r
    lines=text.replace('\r\n','\n').split('\n')
    if lines[-1]=='':lines.pop()
    if not 2<=len(lines)<=4 or any(not x or len(x)>2048 for x in lines):return r
    if not re.fullmatch(r'curl 8\.21\.0 \(Windows\) libcurl/8\.21\.0(?: [\x20-\x7e]+)?',lines[0]):return r
    if not re.fullmatch(r'Release-Date: \d{4}-\d{2}-\d{2}(?:, security patched: \d{4}-\d{2}-\d{2})?',lines[1]):return r
    try:
        for date in re.findall(r'\d{4}-\d{2}-\d{2}',lines[1]):datetime.date.fromisoformat(date)
    except ValueError:return r
    rest=lines[2:];previous=0
    for line in rest:
        label='Protocols:' if line.startswith('Protocols:') else 'Features:' if line.startswith('Features:') else None
        if label is None:return r
        order=1 if label=='Protocols:' else 2
        if order<=previous:return r
        previous=order;tokens=line[len(label):].split(' ')
        if len(tokens)<2 or tokens[0]!='' or not 1<=len(tokens[1:])<=128 or len(set(tokens[1:]))!=len(tokens[1:]):return r
        pattern=r'[a-z][a-z0-9+.-]{0,31}' if order==1 else r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,63}'
        if any(re.fullmatch(pattern,t) is None for t in tokens[1:]):return r
    r['recognized']=True;return r

FAILURES=('inputs','setup','ordinary_before','construct','admission','accesscheck','update','payload','resume','observe','ordinary_after','cleanup','report','deadline')
U8,U16,U32,U64,I32=C.c_uint8,C.c_uint16,C.c_uint32,C.c_uint64,C.c_int32
OPERATIONS={'begin':1,'update':2,'install':3,'observe':4,'forget':5}
def result_record(raw,operation,window):
    return reader.decode_result(raw,operation,window=window)

def binary_record(root,name,raw):
    require(type(raw) is bytes and re.fullmatch(r'[a-z0-9-]+\.(bin|u16|ascii)',name),'mm_binary_name')
    base.durable_private(Path(root)/name,raw)
    return dict(name=name,bytes=len(raw),sha256=sha(raw))

def read_binary(root,d,limit):
    require(type(d) is dict and set(d)=={'name','bytes','sha256'} and type(d['name']) is str
        and re.fullmatch(r'[a-z0-9-]+\.(bin|u16|ascii)',d['name']) and live.integer(d['bytes'],1,limit)
        and base.ac.digest(d['sha256']),'mm_binary_descriptor')
    raw=local.bounded(launcher.checked_path(Path(root)/d['name'],inside=root),limit)
    require(len(raw)==d['bytes'] and sha(raw)==d['sha256'],'mm_binary_physical');return raw

def pe_fact(raw,*,dll):
    p=pe_shape(raw,dll=dll);off=struct.unpack_from('<I',raw,60)[0]
    return dict(machine=0x8664,timestamp=p['timestamp'],entry_rva=p['entry_rva'],image_bytes=p['image_size'],
        header_bytes=struct.unpack_from('<I',raw,off+84)[0],subsystem=struct.unpack_from('<H',raw,off+92)[0],is_dll=dll)

def pe_shape(raw,*,dll):
    require(type(raw) is bytes and 512<=len(raw)<=8*1024*1024 and raw[:2]==b'MZ','loader_pe')
    off=struct.unpack_from('<I',raw,60)[0];require(64<=off<=len(raw)-264 and raw[off:off+4]==b'PE\0\0','loader_pe_offset')
    machine,sections,timestamp,_,_,optsize,flags=struct.unpack_from('<HHIIIHH',raw,off+4)
    require(machine==0x8664 and 1<=sections<=32 and optsize>=240 and bool(flags&0x2000)==dll
            and struct.unpack_from('<H',raw,off+24)[0]==0x20b,'loader_pe_kind')
    entry=struct.unpack_from('<I',raw,off+40)[0];size=struct.unpack_from('<I',raw,off+80)[0]
    require(0<entry<size<=64*1024*1024,'loader_pe_size');return dict(timestamp=timestamp,entry_rva=entry,image_size=size)

def verify_manifest(raw,artifacts,*,source_root):
    require(NATIVE_SOURCE_CLOSURE_FINAL,'mm_native_closure_pending')
    v=decode(raw.removeprefix(b'\xef\xbb\xbf'))
    keys={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','wrapperSha256','markerSha256','nativeSourceHashes','detoursCommit','detoursSourceHashes'}
    require(type(v) is dict and set(v)==keys and v['schemaVersion']==1 and type(v['schemaVersion']) is int
            and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['interfaceVersion']==2 and type(v['interfaceVersion']) is int,'loader_manifest')
    require(v['wrapperSha256']==artifacts['wrapper']['sha256'] and v['markerSha256']==artifacts['marker']['sha256']
            and v['detoursCommit']=='1dbd4ea281d73d478aa8d09a8b83fbd265f715f7','loader_manifest_artifacts')
    for key,names in (('nativeSourceHashes',NATIVE_SOURCES),('detoursSourceHashes',tuple('.github/vendor/detours/'+n for n in VENDOR_FILES))):
        require(type(v[key]) is dict and set(v[key])==set(names),'loader_manifest_source_set')
        for name in names:
            require(v[key][name]==sha(local.bounded(launcher.checked_path(Path(source_root)/name,inside=source_root),256*1024)),'loader_manifest_source')
    return v

def verify_input_artifacts(wrapper,marker,manifest,curl_path,artifacts,*,root=ROOT):
    validate_artifact_pins(artifacts)
    paths=dict(wrapper=Path(wrapper),marker=Path(marker),manifest=Path(manifest),curl=Path(curl_path))
    for key,path in paths.items():
        checked=launcher.checked_path(path);raw=local.bounded(checked,8*1024*1024)
        require(len(raw)==artifacts[key]['bytes'] and sha(raw)==artifacts[key]['sha256'],'loader_input_pin')
        if key!='manifest':pe_shape(raw,dll=key!='curl')
    verify_manifest(local.bounded(paths['manifest'],64*1024),artifacts,source_root=root)
    return artifacts

def verify_artifacts(c,root):
    p=artifact_paths(Path(root));return verify_input_artifacts(p['wrapper'],p['marker'],p['manifest'],c['curl_path'],c['artifacts'],root=root)

def verify_system_curl(api,path):
    # The ordinary outer adapter has the same .k query interface but does not
    # inherit this new backend. No backend or DLL is constructed by this query.
    expected=launcher.checked_path(api.system_curl() if hasattr(api,'system_curl') else NativeAPI.system_curl(api))
    require(launcher.checked_path(path)==expected and sha(local.bounded(expected,8*1024*1024))==CURL_SHA256,'loader_system_curl')
    return expected

class NativeAPI(zero.API):
    """Production backend, constructed only by an explicit ready worker.

    Defining/importing this class makes no Windows call. Test fakes never call
    this initializer or WinDLL. All borrowed context values remain same-owner.
    """
    def __init__(self):
        super().__init__();self.wrapper=None
    def system_curl(self):
        self.k.GetSystemDirectoryW.argtypes=[C.c_wchar_p,U32];self.k.GetSystemDirectoryW.restype=U32
        b=C.create_unicode_buffer(32768);n=self.k.GetSystemDirectoryW(b,32768)
        require(0<n<32768,'loader_system_directory');return Path(b.value)/'curl.exe'
    def _bind(self,name,args,result):
        f=getattr(self.k,name);f.argtypes=args;f.restype=result;return f
    def _adopt(self,h,ledger,other):
        if not (type(h) is int and 0<h<0xffffffffffffffff and h not in set(ledger.pending)|set(other)):
            self.controls_uncertain=True;raise ValueError('loader_resource_alias')
        ledger.add(h);return h
    def event(self,ledger,other,sid):
        try:sd=local.LocalNativeAPI.private_descriptor(self.native,sid,job=True)
        except BaseException:self.controls_uncertain=True;raise
        try:
            sa=launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes),sd,False)
            f=self._bind('CreateEventExW',[C.c_void_p,C.c_wchar_p,U32,U32],C.c_void_p)
            h=f(C.byref(sa),None,1,0x100002)
            if not h:self.native.check(False,'CreateEventExW(loader)')
            try:self._adopt(int(h),ledger,other)
            except BaseException:self.controls_uncertain=True;raise
            require(self.handle_flags(h)==0,'loader_parent_event_inherit');return int(h)
        except BaseException:
            self.controls_uncertain=True;raise
        finally:
            try:require(not self.k.LocalFree(sd),'loader_event_SD_free')
            except BaseException:self.controls_uncertain=True;raise
    def signal_duplicate(self,h,ledger,other):
        out=C.c_void_p();f=self._bind('DuplicateHandle',[C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p),U32,C.c_int,U32],C.c_int)
        try:ok=f(self.k.GetCurrentProcess(),h,self.k.GetCurrentProcess(),C.byref(out),2,True,0)
        except BaseException:self.controls_uncertain=True;raise
        error=0 if ok else C.get_last_error()
        if not ok:self.controls_uncertain=True;raise launcher.NativeFailure('DuplicateHandle(signal-only)',error)
        try:self._adopt(int(out.value or 0),ledger,other)
        except BaseException:self.controls_uncertain=True;raise
        require(self.handle_flags(out.value)==1,'loader_signal_inherit');return int(out.value)
    def handle_flags(self,h):
        flags=U32();self.native.check(self._bind('GetHandleInformation',[C.c_void_p,C.POINTER(U32)],C.c_int)(h,C.byref(flags)),'GetHandleInformation(loader)')
        return flags.value
    def kernel_sddl(self,h):
        sd,text=C.c_void_p(),C.c_wchar_p();owned=[]
        self.a.GetSecurityInfo.argtypes=[C.c_void_p,C.c_int,U32,C.c_void_p,C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)];self.a.GetSecurityInfo.restype=U32
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes=[C.c_void_p,U32,U32,C.POINTER(C.c_wchar_p),C.c_void_p];self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype=C.c_int
        try:
            code=self.a.GetSecurityInfo(h,6,4,None,None,None,None,C.byref(sd))
            require(code==0 and sd.value,'loader_kernel_SD');owned.append(sd.value)
            ok=self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,1,4,C.byref(text),None)
            require(ok and C.cast(text,C.c_void_p).value,'loader_kernel_SD_text');p=C.cast(text,C.c_void_p).value
            require(p not in owned,'loader_kernel_SD_alias');owned.append(p);return text.value
        except BaseException:
            self.controls_uncertain=True;raise
        finally:
            uncertain=False
            for p in reversed(owned):
                try:require(not self.k.LocalFree(p),'loader_kernel_SD_close')
                except BaseException:uncertain=True
            if uncertain:self.controls_uncertain=True;raise ValueError('loader_kernel_SD_close')
    def create_curl(self,info,command,cwd,environment,job,owners,state,*,handles,stdio,profile_pointer,parent_sid,budget,end,on_return,other_owned=()):
        selected=profile_pointer is not None;expected_handles=5 if selected else 3
        require(curl_command_matches_system(command,self.system_curl()) and len(handles)==expected_handles
                and len(set(handles))==expected_handles and list(handles[-3:])==list(stdio) and len(stdio)==3,'loader_constructor_inputs')
        require(all(self.handle_flags(h)==1 for h in handles),'loader_constructor_inheritance')
        if selected:
            require(environment.endswith('\0\0') and {x.split('=',1)[0] for x in environment.rstrip('\0').split('\0')}=={'SystemRoot','LOCALAPPDATA'},'loader_selected_env')
        count=4 if selected else 2;size=C.c_size_t();self.k.InitializeProcThreadAttributeList(None,count,0,C.byref(size));require(1<=size.value<=65536,'loader_attrs_size')
        attrs=C.create_string_buffer(size.value);self.native.check(self.k.InitializeProcThreadAttributeList(attrs,count,0,C.byref(size)),'InitializeProcThreadAttributeList(loader)')
        sd=None;state.update(creation_attempted=False,creation_unknown=False,create_status='not_entered',raw_return=None,raw_error=None,raw_pi=[0,0,0,0],returned_qpc=None)
        try:
            try:sd=local.LocalNativeAPI.private_descriptor(self.native,parent_sid,job=True)
            except BaseException:self.controls_uncertain=True;raise
            sa=launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes),sd,False)
            jobs=(C.c_void_p*1)(job);hl=(C.c_void_p*len(handles))(*handles);values=[(base.JOB_LIST,jobs),(0x20002,hl)]
            if selected:
                caps=self.proc._SecurityCapabilities(profile_pointer,None,0,0);policy=U32(1)
                values += [(base.SECURITY_CAPABILITIES,caps),(base.ALL_APPLICATION_PACKAGES_POLICY,policy)]
            for k,v in values:self.native.check(self.k.UpdateProcThreadAttribute(attrs,0,k,C.byref(v),C.sizeof(v),None,None),'UpdateProcThreadAttribute(loader)')
            startup=self.proc._StartupInfoEx();startup.StartupInfo.cb=C.sizeof(startup);startup.lpAttributeList=C.cast(attrs,C.c_void_p)
            startup.StartupInfo.dwFlags=0x100;startup.StartupInfo.hStdInput,startup.StartupInfo.hStdOutput,startup.StartupInfo.hStdError=stdio
            cmd=C.create_unicode_buffer(subprocess.list2cmdline(command));env=C.create_unicode_buffer(environment);out=self.process_info()
            budget.require_ms(end);state.update(creation_attempted=True,creation_unknown=True)
            physical_error=None
            try:
                ok=self.k.CreateProcessW(command[0],cmd,C.byref(sa),C.byref(sa),True,
                    self.proc._CREATE_SUSPENDED|self.proc._CREATE_UNICODE_ENVIRONMENT|self.proc._EXTENDED_STARTUPINFO_PRESENT|0x08000000,
                    env,str(cwd),C.byref(startup),C.byref(out));error=0 if ok else C.get_last_error()
                state.update(create_status='returned_true' if ok else 'returned_false',raw_return=int(ok),raw_error=None if ok else error)
            except BaseException as exc:physical_error=exc;state['create_status']='exception'
            v=[int(out.hProcess or 0),int(out.hThread or 0),int(out.dwProcessId),int(out.dwThreadId)];state['raw_pi']=v
            try:state['returned_qpc']=budget.read()
            except BaseException:pass
            known_true=(state['create_status']=='returned_true' and all(v) and all(0<h<0xffffffffffffffff for h in v[:2])
                and v[0]!=v[1] and not any(h in owners.pending or h in handles or h in other_owned for h in v[:2]))
            known_none=state['create_status']=='returned_false' and type(state['raw_error']) is int and state['raw_error']>0 and not any(v) and type(state['returned_qpc']) is int and state['returned_qpc']<end
            state['creation_unknown']=not(known_true or known_none)
            # TRUE outputs confer exact cleanup ownership even when durable
            # publication fails. Never adopt failed or ambiguous PI numbers.
            if known_true:
                info.hProcess,info.hThread,info.dwProcessId,info.dwThreadId=v;owners.add(v[0]);owners.add(v[1])
            on_return(state.copy())
            if physical_error is not None:raise physical_error
            require(known_true,'loader_create_no_owned_child');budget.require_ms(end)
        finally:
            uncertain=False
            try:self.k.DeleteProcThreadAttributeList(attrs)
            except BaseException:uncertain=True
            if sd:
                try:require(not self.k.LocalFree(sd),'loader_constructor_SD_close')
                except BaseException:uncertain=True
            if uncertain:self.controls_uncertain=True;raise ValueError('loader_constructor_resource_close')
    def load_wrapper(self,path):
        require(self.wrapper is None,'mm_wrapper_once')
        lib=C.WinDLL(str(path),use_last_error=True,winmode=0x900)
        protocol.bind_library(lib);self.wrapper=lib
    def wrapper_call(self,op,buffers):
        return buffers.call(self.wrapper,op)
    def resume_raw(self,thread):
        f=self._bind('ResumeThread',[C.c_void_p],U32)
        value=int(f(thread));error=int(C.get_last_error()) if value==0xffffffff else None
        return value,error
    def open_outer_query(self,name,process,ledger,other):
        f=self._bind('OpenJobObjectW',[U32,C.c_int,C.c_wchar_p],C.c_void_p)
        h=f(4,False,name)
        if not h:self.native.check(False,'OpenJobObjectW(MM retained query)')
        self._adopt(int(h),ledger,other)
        require(self.handle_flags(h)==0,'mm_outer_inherit');self.verify_job(h,process);return int(h)
    def file_fact(self,h,budget,end):
        budget.require_ms(end);tag=(U8*8)();fid=(U8*24)()
        f=self._bind('GetFileInformationByHandleEx',[C.c_void_p,C.c_int,C.c_void_p,U32],C.c_int)
        self.native.check(f(h,9,tag,8),'GetFileInformationByHandleEx(attribute)');require(not struct.unpack_from('<I',bytes(tag))[0]&0x410,'loader_marker_regular')
        self.native.check(f(h,18,fid,24),'GetFileInformationByHandleEx(FileIdInfo)')
        b=C.create_unicode_buffer(32768);n=self._bind('GetFinalPathNameByHandleW',[C.c_void_p,C.c_wchar_p,U32,U32],U32)(h,b,32768,2)
        require(0<n<32768 and b.value.startswith('\\Device\\HarddiskVolume') and len(b.value)==n,'loader_marker_NT_path')
        budget.require_ms(end);return dict(nt_path=b.value,volume_serial=struct.unpack_from('<Q',bytes(fid))[0],file_id=bytes(fid)[8:].hex())
    def held_file_hash(self,h,expected_bytes,budget,end):
        require(live.integer(expected_bytes,1,8*1024*1024),'loader_held_file_size');budget.require_ms(end)
        position=C.c_int64();self.native.check(self._bind('SetFilePointerEx',[C.c_void_p,C.c_int64,C.POINTER(C.c_int64),U32],C.c_int)(h,0,C.byref(position),0),'SetFilePointerEx(marker)')
        chunks=[];count=0;readfile=self._bind('ReadFile',[C.c_void_p,C.c_void_p,U32,C.POINTER(U32),C.c_void_p],C.c_int)
        while count<=expected_bytes:
            budget.require_ms(end);capacity=min(65536,expected_bytes+1-count);buf=(U8*capacity)();got=U32()
            self.native.check(readfile(h,buf,capacity,C.byref(got),None),'ReadFile(marker)');require(got.value<=capacity,'loader_marker_read_extent')
            if not got.value:break
            chunks.append(bytes(buf)[:got.value]);count+=got.value
        require(count==expected_bytes,'loader_marker_read_size');budget.require_ms(end);return sha(b''.join(chunks))
    def open_marker(self,path,owners,other,budget,end):
        budget.require_ms(end);h=self._bind('CreateFileW',[C.c_wchar_p,U32,U32,C.c_void_p,U32,U32,C.c_void_p],C.c_void_p)(str(path),0x80000000,1,None,3,0x200000,None)
        if not h or h==0xffffffffffffffff:self.native.check(False,'CreateFileW(marker lease)')
        try:self._adopt(int(h),owners,other)
        except BaseException:self.controls_uncertain=True;raise
        return int(h),self.file_fact(h,budget,end)
API=NativeAPI
GRANTS=(('root','', 'RX'),('package','package','(OI)(CI)(RX)'),('output','selected-output','(OI)(CI)(M)'))

def expected_acl(root,path):
    if path==root:return [(0,0x1200a9)]
    for name,mask in (('package',0x1200a9),('selected-output',0x1301bf)):
        d=root/name
        if path==d:return [(3,mask)]
        if d in path.parents:return [(19 if path.is_dir() else 16,mask)]
    return []
def task_projection(row):
    keys=('name','attempted','assigned','exited','exit_code','pid','created','process_returned','resumed','admitted','image_sha256',
          'admission_qpc','resume_qpc','resume_intent_qpc','exit_observed_qpc','natural_exit','identity','capabilities','lpac','lpac_expected',
          'expected_primary','held_checks','receipt','create_observation','constructor_return_qpc','inherited_handles','parent_copies_closed','kernel_security')
    return {k:row[k] for k in keys}

class Owner(cell.CellOwner):
    def __init__(self,root,c,parent,api,budget):
        self.root,self.c,self.parent,self.api,self.budget=Path(root),c,parent,api,budget
        self.owners=helpers.OneShotHandles(api.close);self.resources=helpers.OneShotHandles(api.close)
        self.signal_owners=helpers.OneShotHandles(api.close);self.stdio_ledgers=[]
        self.job=None;self.children=[];self.tasks={};self.catalog={};self.phase='setup'
        self.profile=dict(attempted=False,returned=False,created=False,pointer=None,sid=None);self.selected_environment=None
        self.buffers=None;self.context_bound=False;self.native_unknown=False
        self.target_handle=None;self.target_fact=None;self.outer_query=None
        self.events=[];self.signals=[];self.marker_handle=None;self.marker_fact=None
        self.j=dict(schema_version=1,stage='lpac-curl-mm-loader-result',scope=SCOPE,profile=PROFILE,config_sha256=sha(encode(c)),
            failure=None,failure_detail=None,profile_name='ruleproxy-curl-mm-loader-'+c['run'],profile_sid=None,
            profile_state=dict(attempted=False,returned=False,created=False,sid_pointer_returned=False),
            child_environment=launcher.default_child_environment(),intents=[],returns=[],operations=[],proofs=[],tasks=[],cleanup_tasks=[],
            labels=[],window=None,native_inputs=None,borrowed_resources=None,marker_lease=None,target_lease=None,outer_query=None,lease_checks=[],event_resources=[],resume_observation=None,controls=dict(before=None,after=None),selected_output=None,
            profile_created=False,acl_attempted=False,creation_unknown=False,context_bound=False,context_forgotten=False,
            selected_stop_attempted=False,selected_exit_confirmed=False,token_class46_queried=False,endpoint_created=False,
            dns_api_called=False,**dict.fromkeys(CLEAN_KEYS,False),**dict.fromkeys(FALSE_CLAIMS,False))
        self.j.update(observer_resources_cleanup_verified=True,parent_event_stdio_closed=True,marker_file_closed=True,
                      query_resources_closed=True,target_file_closed=True,outer_query_closed=True,native_resources_closed=True,labels_restored=True)
    def journal(self,label):
        require(re.fullmatch('[a-z0-9-]{1,64}',label) is not None and len(self.j['intents'])<64,'loader_intent')
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label))
        name='%02d-%s.json'%(len(self.j['intents']),label);base.durable_private(self.root/'journal'/name,raw)
        r=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw));self.j['intents'].append(r);return r
    def returned(self,label,intent,data):
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            intent_sha256=intent['sha256'],action=label,qpc=self.budget.read(),data=data))
        name='%02d-%s.json'%(len(self.j['returns']),label);base.durable_private(self.root/'returns'/name,raw)
        r=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw));self.j['returns'].append(r);return r
    def scope_acl(self,removed=False):
        for path in base.owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(3 if removed else 25))
            require(self.api.acl_read(path,self.profile['sid'])==([] if removed else expected_acl(self.root,path)),'loader_acl_scope')
    def task(self,name,command,work,*,lpac=False,stdio=False,owners=None,children=None,job=None,cleanup=False):
        # Fixed ordinary icacls seam, preserving held Job/token admission. It
        # deliberately does not reuse any old native actor/report validator.
        require(name in ('grant-root','grant-package','grant-output','remove') and not lpac and stdio and cleanup==(name=='remove'),'loader_tool_role')
        sid='*'+self.profile['sid'];tool=str(self.fixed_tool('icacls.exe'))
        spec={label:(part,right) for label,part,right in GRANTS}
        expected=([tool,str(self.root),'/remove:g',sid,'/T','/Q'] if cleanup else
            [tool,str(self.root/spec[name[6:]][0]),'/grant',sid+':'+spec[name[6:]][1],'/Q'])
        require(command==expected and work==self.root/'tools'/name and (work/'temp').is_dir(),'loader_tool_command')
        ledger=self.owners if owners is None else owners;rows=self.children if children is None else children;job=self.job if job is None else job
        end=self.budget.cutoff(3 if cleanup else 25);info=self.api.process_info();image=launcher.checked_path(command[0]);image_hash=sha(local.bounded(image,8*1024*1024))
        row=self.new_row(name,info,image_hash,False,end);rows.append(row)
        state=dict(creation_attempted=False);stdio_owners=helpers.OneShotHandles(self.api.close);self.journal('spawn-'+name)
        try:
            handles=[]
            for label in ('stdin','stdout','stderr'):
                h=self.api.open_stdio_file(work/label,read=label=='stdin');require(h not in ledger.pending and h not in self.resources.pending,'loader_tool_stdio_alias');stdio_owners.add(h);handles.append(h)
            env=self.api.native.environment(work);self.budget.require_ms(end)
            self.api.atomic_spawn(info,command,work,job,ledger,state,environment=env,stdio=handles,profile_pointer=None,catalog=None)
        finally:
            row.update(attempted=state['creation_attempted'],process_returned=bool(info.hProcess),pid=int(info.dwProcessId) or None)
            row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('create_winerror'),
                process_information=state.get('create_information','not_observed'),returned_qpc=self.budget.read(),work_cutoff=end,exception_detail=state.get('create_exception_detail'))
            for h in tuple(stdio_owners.pending):
                try:stdio_owners.close(h)
                except BaseException:self.api.controls_uncertain=True
            if not stdio_owners.confirmed_closed:self.api.controls_uncertain=True
        require(info.hProcess and info.hThread,'loader_tool_partial');row['created']=self.api.creation_time(info.hProcess)
        self.api.verify_job(job,info.hProcess);row['assigned']=True;self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,image)
        row['token']=self.api.token_for_process(info.hProcess);ledger.add(row['token'])
        row['identity'],row['capabilities'],row['lpac']=base.held_identity(self.api,row,self.parent,{},self.profile['sid'],False)
        row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row
    def tool(self,command,label,*,cleanup=False,owners=None,children=None,job=None):
        work=self.root/'tools'/label;work.mkdir(exist_ok=True);(work/'temp').mkdir(exist_ok=True)
        row=self.task(label,command,work,stdio=True,cleanup=cleanup,owners=owners,children=children,job=job)
        require(row['admitted'] and not row['resumed'],'loader_tool_resume');self.api.resume(row['info'].hThread)
        row['resumed']=True;row['resume_qpc']=self.budget.read();base.Owner.wait(self,row,self.budget.cutoff(3 if cleanup else 25));return row
    def new_row(self,name,info,image_hash,selected,end):
        return dict(info=info,token=None,name=name,attempted=False,assigned=False,exited=False,exit_code=None,pid=None,created=None,
            process_returned=False,resumed=False,admitted=False,image_sha256=image_hash,admission_qpc=None,resume_qpc=None,
            resume_intent_qpc=None,exit_observed_qpc=None,natural_exit=False,identity=None,capabilities=None,lpac=None,lpac_expected=selected,
            expected_primary=None,held_checks=[],receipt=None,constructor_return_qpc=None,inherited_handles=[],parent_copies_closed=False,
            kernel_security=None,go_qpc=[],create_observation=dict(status='not_entered',winerror=None,process_information='not_observed',returned_qpc=None,work_cutoff=end,exception_detail=None))
    def setup_profile(self):
        self.budget.require_ms(work_cutoff(self.c));folder=self.api.local_appdata(self.budget,self.j['child_environment'])
        self.selected_environment=self.api.front_environment(folder,self.j['child_environment'])
        require(launcher.child_environment_admitted(self.j['child_environment']),'loader_environment');self.journal('profile-create')
        try:self.api.create_profile(self.j['profile_name'],self.profile)
        finally:
            self.j['profile_state']={k:self.profile[k] for k in ('attempted','returned','created')};self.j['profile_state']['sid_pointer_returned']=bool(self.profile['pointer']);self.j['profile_sid']=self.profile['sid']
        require(self.profile['created'] and self.api.derive_profile_sid(self.j['profile_name'])==self.profile['sid'],'loader_fresh_profile');self.j['profile_created']=True
        for p in base.owned_tree(self.root):require(self.api.acl_read(p,self.profile['sid'])==[],'loader_fresh_ACE')
        self.j['acl_attempted']=True;self.journal('acl-grant')
        for name,part,right in GRANTS:self.tool([str(self.fixed_tool('icacls.exe')),str(self.root/part),'/grant','*'+self.profile['sid']+':'+right,'/Q'],'grant-'+name)
        self.scope_acl();out=self.root/'selected-output';require(self.api.label_read(out) is None,'loader_label_initial')
        self.j['labels'].append(dict(name='selected-output',attempted=True,lowered=False,restored=False));self.j['labels_restored']=False;self.journal('label-lower')
        self.api.label_set(out,zero.LOW_LABEL);require(self.api.label_read(out)==zero.LOW_LABEL,'loader_label_lower');self.j['labels'][0]['lowered']=True
    def held(self,row,end):
        self.budget.require_ms(end);h=row['info'].hProcess
        require(row['pid']==self.api.process_id(h) and row['created']==self.api.creation_time(h) and not self.api.wait(h,0),'loader_held_generation')
        self.api.verify_job(self.job,h);self.api.verify_outer(self.c['guard_job_name'],h);self.api.verify_image(h,Path(self.c['curl_path']))
        require(sha(local.bounded(Path(self.c['curl_path']),8*1024*1024))==CURL_SHA256,'loader_held_disk')
        current=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,row['lpac_expected'])
        require(current==row['expected_primary'],'loader_primary_changed')
        security=dict(process=self.api.kernel_sddl(h),thread=self.api.kernel_sddl(row['info'].hThread))
        require(all(private_process_thread_sddl(x,self.parent['sid']) for x in security.values()),'loader_process_thread_DACL')
        require(security==row['kernel_security'],'loader_kernel_SD_changed')
        row['held_checks'].append(dict(qpc=self.budget.read(),pid=row['pid'],created=row['created'],image_sha256=CURL_SHA256,
            primary=current,inner_job=True,outer_job=True,kernel_security=security));self.budget.require_ms(end)
    def spawn(self,name,end,selected=False):
        info=self.api.process_info();row=self.new_row(name,info,CURL_SHA256,selected,end);self.children.append(row);self.tasks[name]=row
        intent=self.journal('create-'+name);state=dict(creation_attempted=False,creation_unknown=False);stdio_owners=helpers.OneShotHandles(self.api.close)
        self.stdio_ledgers.append(stdio_owners);row_handles=[];directory=self.root/('selected-output' if selected else 'ordinary-'+name)
        try:
            for kind in ('stdin','stdout','stderr'):
                h=self.api.open_stdio_file(directory/kind,read=kind=='stdin')
                if not (type(h) is int and 0<h<0xffffffffffffffff and h not in self.owners.pending and h not in self.resources.pending and h not in self.signal_owners.pending and h not in stdio_owners.pending):
                    self.api.controls_uncertain=True;raise ValueError('loader_stdio_alias')
                stdio_owners.add(h);row_handles.append(h)
            all_handles=([*self.signals,*row_handles] if selected else row_handles);row['inherited_handles']=list(all_handles)
            self.j['parent_event_stdio_closed']=False
            def raw_return(s):
                row['receipt']=self.returned('create-'+name,intent,s)
            try:self.api.create_curl(info,argv(self.c),self.root/'package' if selected else directory,
                self.selected_environment if selected else self.api.native.environment(directory),self.job,self.owners,state,
                handles=all_handles,stdio=row_handles,profile_pointer=self.profile['pointer'] if selected else None,parent_sid=self.parent['sid'],
                budget=self.budget,end=end,on_return=raw_return,other_owned=set(self.resources.pending)|set(self.signal_owners.pending))
            finally:
                row.update(attempted=state.get('creation_attempted',False),process_returned=bool(info.hProcess),pid=int(info.dwProcessId) or None)
                row['constructor_return_qpc']=self.budget.read()
                v=state.get('raw_pi',[0,0,0,0]);row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('raw_error'),
                    process_information='nonzero' if any(v) else 'all_zero',returned_qpc=state.get('returned_qpc'),work_cutoff=end,exception_detail=None)
                if row['receipt'] is None:row['receipt']=self.returned('create-'+name,intent,state)
                if state.get('creation_unknown',False):self.j['creation_unknown']=True;self.api.controls_uncertain=True
        finally:
            for ledger in ([stdio_owners,self.signal_owners] if selected else [stdio_owners]):
                for h in tuple(ledger.pending):
                    try:ledger.close(h)
                    except BaseException:self.api.controls_uncertain=True
            row['parent_copies_closed']=stdio_owners.confirmed_closed and (not selected or self.signal_owners.confirmed_closed)
        require(row['parent_copies_closed'] and info.hProcess and info.hThread and row['pid'],'loader_owned_child')
        self.budget.require_ms(end);row['created']=self.api.creation_time(info.hProcess);self.api.verify_job(self.job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,Path(self.c['curl_path']))
        row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token']);row['identity']=self.api.identity(row['token'])
        row['capabilities']=[];row['expected_primary']=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,selected)
        row['kernel_security']=dict(process=self.api.kernel_sddl(info.hProcess),thread=self.api.kernel_sddl(info.hThread))
        require(all(private_process_thread_sddl(v,self.parent['sid']) for v in row['kernel_security'].values()),'loader_process_thread_SD')
        self.held(row,end);row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row
    def resume_curl(self,row,end):
        self.held(row,end);require(row['admitted'] and not row['resumed'] and row['parent_copies_closed'],'loader_resume_once')
        intent=self.journal('resume-'+row['name']);row['resume_intent_qpc']=decode(intent['text'].encode('ascii'))['qpc'];self.budget.require_ms(end)
        self.api.resume(row['info'].hThread);row['resumed']=True;row['resume_qpc']=self.budget.read();self.budget.require_ms(end)
    def wait_curl(self,row,end):
        row['exited']=self.api.wait(row['info'].hProcess,self.budget.require_ms(end)) is True
        if row['exited']:
            row['exit_code']=self.api.exit_code(row['info'].hProcess);row['exit_observed_qpc']=self.budget.read();row['natural_exit']=True
        self.budget.require_ms(end);require(row['exited'],'loader_natural_wait')
    def output(self,row):
        require(row['exited'] and row['parent_copies_closed'],'loader_output_closed')
        d=self.root/('selected-output' if row['lpac_expected'] else 'ordinary-'+row['name'])
        return version_output(local.bounded(d/'stdout',MAX_OUTPUT),local.bounded(d/'stderr',MAX_OUTPUT))
    def control(self,name):
        end=min(self.budget.read()+8*self.c['frequency'],work_cutoff(self.c));row=self.spawn(name,end)
        self.resume_curl(row,end);self.wait_curl(row,end);out=self.output(row)
        record=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),parent_sha256=sha(encode(self.parent)),
            role=name,case=self.c[name+'_case'],deadline_qpc=end,task=task_projection(row),output=out,
            positive=row['natural_exit'] and row['exit_code']==0 and out['recognized'])
        raw=encode(record);base.durable_private(self.root/('control-'+name+'.json'),raw)
        self.j['controls'][name]=dict(text=raw.decode('ascii'),sha256=sha(raw));require(record['positive'],'loader_ordinary_'+name);return True
    def semantic(self,row,label,end):
        self.held(row,end);intent=self.journal('observe-'+label);self.j['observer_resources_cleanup_verified']=False
        p=zero.observe_held(self.api.access_api(),row['info'].hProcess,row['expected_primary'],expected_pid=row['pid'],expected_creation=row['created'],
            expected_role='lpac',frequency=self.c['frequency'],deadline=end)
        self.j['proofs'].append(dict(label=label,intent_sha256=intent['sha256'],value=p));self.j['observer_resources_cleanup_verified']=all(x['value']['resource_cleanup_verified'] for x in self.j['proofs'])
        require(p['qualified'] and self.j['observer_resources_cleanup_verified'],'loader_lpac_semantics');self.held(row,end)
    def _operation_row(self,name,intent):
        row=dict(operation=name,intent_sha256=intent['sha256'],returned=False,return_code=None,raw=None,result_file=None,context=None,output=None,status='missing',receipt=None)
        self.j['operations'].append(row);return row
    def _save_operation(self,row,intent,answer):
        code,raw,output=answer
        row.update(returned=True,return_code=code,raw=raw.hex(),status='invalid')
        row['result_file']=binary_record(self.root,'native-'+row['operation']+'-result.bin',raw)
        if output is not None:row['output']=binary_record(self.root,'native-observe-output.bin',output)
        row['context']=binary_record(self.root,'native-'+row['operation']+'-context.bin',protocol.logical_bytes(self.buffers.ctx))
        row['receipt']=self.returned('wrapper-'+row['operation'],intent,{k:row[k] for k in ('return_code','raw','result_file','context','output')})
        parsed=result_record(raw,row['operation'],(self.j['window']['start'],self.j['window']['end']))
        require(code==parsed['result_class'],'mm_result_code')
        if row['operation']=='update' and parsed['result_class']==11:
            require(parsed['primary_call']['requested']==struct.unpack_from('<Q',self.buffers.expectation()['plan512'],64)[0],'mm_update_process_binding')
        if parsed['context_known']:self.context_bound=True;self.j['context_bound']=True
        if output is not None:
            decoded=reader.decode_output(output,self.buffers.expectation())
            require(decoded['result']==parsed,'mm_output_result_match')
            self.j['native_resources_closed']=bool(decoded['gates']['resources'])
            if not self.j['native_resources_closed']:self.native_unknown=True;self.api.controls_uncertain=True
        require(self.buffers.inputs_unchanged(),'mm_input_buffer_changed')
        row['status']='valid';return parsed
    def operation(self,name):
        intent=self.journal('wrapper-'+name);r=self._operation_row(name,intent)
        try:return self._save_operation(r,intent,self.api.wrapper_call(name,self.buffers))
        except BaseException:
            self.native_unknown=True;self.j['native_resources_closed']=False;self.api.controls_uncertain=True
            raise
    def lease_check(self,phase,end):
        intent=self.journal('lease-'+phase);facts={}
        for name,h,fact,path in (('target',self.target_handle,self.target_fact,Path(self.c['curl_path'])),
                                ('marker',self.marker_handle,self.marker_fact,artifact_paths(self.root)['marker'])):
            require(self.api.handle_flags(h)==0,'mm_lease_inherited')
            require(self.api.file_fact(h,self.budget,end)==fact,'mm_lease_FileID_changed')
            require(self.api.held_file_hash(h,self.c['artifacts'][name if name=='marker' else 'curl']['bytes'],self.budget,end)
                ==self.c['artifacts'][name if name=='marker' else 'curl']['sha256'],'mm_lease_bytes_changed')
            raw=local.bounded(path,8*1024*1024)
            facts[name]=dict(file_identity=fact,bytes=len(raw),sha256=sha(raw),pe=pe_fact(raw,dll=name=='marker'))
            require(facts[name]['sha256']==self.c['artifacts'][name if name=='marker' else 'curl']['sha256'],'mm_lease_disk_changed')
        self.j['lease_checks'].append(self.returned('lease-'+phase,intent,facts));return facts
    def prepare_native(self,row):
        paths=artifact_paths(self.root);facts=self.lease_check('before',work_cutoff(self.c))
        intent=self.journal('outer-query');self.outer_query=self.api.open_outer_query(self.c['guard_job_name'],row['info'].hProcess,
            self.resources,set(self.owners.pending)|set(self.signal_owners.pending));self.j['outer_query_closed']=False
        self.j['outer_query']=self.returned('outer-query',intent,dict(handle=self.outer_query,access=4,inherited=False))
        handles=dict(process=int(row['info'].hProcess),thread=int(row['info'].hThread),primary_token=row['token'],inner_job=self.job,
            outer_job=self.outer_query,entered_event=self.events[0],body_event=self.events[1],target_lease=self.target_handle,marker_lease=self.marker_handle)
        require(len(set(handles.values()))==9 and all(self.api.handle_flags(h)==0 for h in handles.values()),'mm_borrow_flags')
        intent=self.journal('native-borrows')
        self.j['borrowed_resources']=self.returned('native-borrows',intent,dict(handles=handles,flags=dict.fromkeys(handles,0)))
        self.api.load_wrapper(paths['wrapper'])
        start=self.budget.read();end=min(start+8*self.c['frequency'],work_cutoff(self.c));self.j['window']=dict(start=start,end=end)
        cfg=dict(frequency=self.c['frequency'],start_qpc=self.c['start_qpc'],root_deadline_qpc=self.c['root_deadline_qpc'],run=self.c['run'],
            config_sha256=sha(encode(self.c)),source_sha256=self.c['source_sha256'],target_sha256=CURL_SHA256,marker_sha256=self.c['artifacts']['marker']['sha256'])
        self.buffers=protocol.NativeBuffers(config=cfg,window=self.j['window'],generation=dict(pid=row['pid'],created=row['created']),handles=handles,
            paths=dict(target=self.c['curl_path'],marker_nt=self.marker_fact['nt_path'],marker_ascii=str(paths['marker'])),
            target=dict(fact=self.target_fact,bytes=facts['target']['bytes'],pe=facts['target']['pe']),
            marker_file=dict(fact=self.marker_fact,bytes=facts['marker']['bytes'],pe=facts['marker']['pe']),
            primary=row['expected_primary'],security=row['kernel_security'],signals=self.signals)
        self.j['native_inputs']={name:binary_record(self.root,name,raw) for name,raw in self.buffers.input_files().items()}
        r=self.operation('begin');require(r['result_class']==9,'mm_begin');self.context_bound=True;self.j['context_bound']=True
    def resume_observe(self,row):
        end=self.j['window']['end'];self.held(row,end)
        require(row['admitted'] and not row['resumed'] and row['parent_copies_closed'] and self.buffers.inputs_unchanged(),'mm_resume_once')
        resume_intent=self.journal('resume-selected');row['resume_intent_qpc']=decode(resume_intent['text'].encode('ascii'))['qpc']
        # Both physical intents and every native buffer exist before Resume.
        observe_intent=self.journal('wrapper-observe');operation=self._operation_row('observe',observe_intent)
        self.budget.require_ms(end)
        fact=dict(entered=True,returned=False,count=None,error=None,returned_qpc=None,clock_error=False,exception=False)
        answer=None;original=None;observe_invoked=False
        try:
            try:
                count,error=self.api.resume_raw(row['info'].hThread)
                fact.update(returned=True,count=count,error=error)
                try:fact['returned_qpc']=self.budget.read()
                except BaseException:
                    fact['clock_error']=True;self.api.controls_uncertain=True;raise
                row['resume_qpc']=fact['returned_qpc']
                if type(count) is int and count==1 and error is None:
                    row['resumed']=True
                    require(type(fact['returned_qpc']) is int and row['resume_intent_qpc']<=fact['returned_qpc']<end,'mm_resume_deadline')
                    self.phase='observe'
                    # No disk, held query, hash, journal or new ctypes output
                    # buffer between raw Resume and this single native call.
                    observe_invoked=True;answer=self.api.wrapper_call('observe',self.buffers)
                else:raise ValueError('mm_resume_count')
            except BaseException as exc:
                if not fact['returned']:fact['exception']=True;self.api.controls_uncertain=True
                original=exc
        finally:
            # Preserve physical Resume facts even if observe/clock/decode fails.
            persistence_errors=[]
            if not observe_invoked:self.j['operations'].remove(operation)
            if answer is not None:
                try:self._save_operation(operation,observe_intent,answer)
                except BaseException as exc:
                    self.native_unknown=True;self.j['native_resources_closed']=False;self.api.controls_uncertain=True
                    persistence_errors.append(exc)
            elif row['resumed']:
                self.native_unknown=True;self.j['native_resources_closed']=False;self.api.controls_uncertain=True
            try:self.j['resume_observation']=self.returned('resume-selected',resume_intent,fact)
            except BaseException as exc:
                self.api.controls_uncertain=True;persistence_errors.append(exc)
            if persistence_errors:raise persistence_errors[0]
        if original is not None:raise original
        require(fact['returned_qpc'] is not None and row['resume_intent_qpc']<=fact['returned_qpc']<end,'mm_resume_deadline')
        # The native gate proved the generation alive before it returned. A
        # following held wait supplies actual natural exit, including nonzero.
        self.phase='observe';parsed=result_record(answer[1],'observe',(self.j['window']['start'],end))
        require(parsed['target_alive']==1 and parsed['return_clock_known']==1,'mm_alive_before_natural_wait')
        self.wait_curl(row,end);self.j['selected_exit_confirmed']=True;self.j['selected_output']=self.output(row)
        self.lease_check('after',end)
    def stop_selected(self):
        row=self.tasks.get('selected')
        if row is None or not row['info'].hProcess:return
        if not row['exited']:
            self.journal('stop-selected');self.j['selected_stop_attempted']=True
            if not self.api.wait(row['info'].hProcess,0):self.api.terminate_process(row['info'].hProcess)
            row['exited']=self.api.wait(row['info'].hProcess,self.budget.require_ms(self.budget.cutoff(12))) is True
            if row['exited']:row['exit_code']=self.api.exit_code(row['info'].hProcess);row['exit_observed_qpc']=self.budget.read()
        self.j['selected_exit_confirmed']=row['exited']
        if self.context_bound and row['exited']:
            r=self.operation('forget');require(r['result_class']==10,'loader_forget');self.context_bound=False;self.j['context_forgotten']=True
    def run(self):
        try:
            verify_artifacts(self.c,self.root);verify_system_curl(self.api,self.c['curl_path']);base.owned_tree(self.root)
            self.job=self.api.owned_job(self.owners);self.phase='ordinary_before';self.control('before')
            self.phase='setup';self.setup_profile();end=work_cutoff(self.c)
            intent=self.journal('target-lease');self.target_handle,self.target_fact=self.api.open_marker(Path(self.c['curl_path']),self.resources,self.owners.pending,self.budget,end);self.j['target_file_closed']=False
            self.j['target_lease']=self.returned('target-lease',intent,dict(handle=self.target_handle,file_identity=self.target_fact))
            intent=self.journal('marker-lease');self.marker_handle,self.marker_fact=self.api.open_marker(artifact_paths(self.root)['marker'],self.resources,self.owners.pending,self.budget,end);self.j['marker_file_closed']=False
            require(self.api.held_file_hash(self.marker_handle,self.c['artifacts']['marker']['bytes'],self.budget,end)==self.c['artifacts']['marker']['sha256'],'loader_marker_lease_bytes')
            self.j['marker_lease']=self.returned('marker-lease',intent,dict(handle=self.marker_handle,file_identity=self.marker_fact))
            for _ in range(2):
                intent=self.journal('event-create');h=self.api.event(self.resources,self.owners.pending,self.parent['sid']);self.events.append(h)
                self.j['event_resources'].append(self.returned('event-create',intent,dict(handle=h,desired_access=0x100002,inherited=False)))
            for h in self.events:
                intent=self.journal('event-duplicate');value=self.api.signal_duplicate(h,self.signal_owners,set(self.resources.pending)|set(self.owners.pending));self.signals.append(value)
                self.j['event_resources'].append(self.returned('event-duplicate',intent,dict(source=h,handle=value,desired_access=2,inherited=True,options=0)))
            self.phase='construct';row=self.spawn('selected',end,True);self.phase='accesscheck';self.semantic(row,'before-update',end)
            self.phase='update';self.prepare_native(row);end=self.j['window']['end'];self.held(row,end)
            require(self.operation('update')['result_class']==11,'loader_update_failed')
            self.phase='payload';require(self.operation('install')['result_class']==5,'loader_payload_failed')
            self.phase='accesscheck';self.semantic(row,'before-resume',end)
            self.phase='resume';self.resume_observe(row)
        except BaseException as exc:
            self.j['failure']=self.phase if self.phase in FAILURES else 'report';self.j['failure_detail']=base.private_failure_detail(exc,self.phase)
        finally:
            try:self.stop_selected()
            except BaseException as exc:self.j['failure']=self.j['failure'] or 'cleanup';self.j['failure_detail']=self.j['failure_detail'] or base.private_failure_detail(exc,'stop-selected')
            # A control may follow a returned known failure only after the exact
            # selected generation has stopped, with the original clock intact.
            try:
                if self.j['controls']['before'] is not None and not self.j['creation_unknown'] and not self.context_bound and not self.api.controls_uncertain and self.budget.read()<work_cutoff(self.c):
                    self.phase='ordinary_after';self.control('after')
            except BaseException as exc:
                self.j['failure']=self.j['failure'] or 'ordinary_after';self.j['failure_detail']=self.j['failure_detail'] or base.private_failure_detail(exc,'ordinary-after')
            self.cleanup()
        self.j['tasks']=[task_projection(x) for x in self.children];return self.j
    def cleanup(self):
        try:
            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')
            rows=[r for r in self.children if not base.known_no_child(r,start=self.c['start_qpc'])]
            clean,empty,_=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(8)),self.job,rows,self.owners)
            self.j.update(workload_cleanup=clean,workload_job_empty=empty)
        except BaseException:pass
        closable=[*self.stdio_ledgers,self.signal_owners]+([self.resources] if self.j['workload_cleanup'] else [])
        for ledger in closable:
            for h in tuple(ledger.pending):
                try:ledger.close(h)
                except BaseException:self.api.controls_uncertain=True
        self.j['parent_event_stdio_closed']=all(x.confirmed_closed for x in [*self.stdio_ledgers,self.signal_owners]) and self.resources.confirmed_closed
        self.j['marker_file_closed']=self.resources.confirmed_closed
        self.j['target_file_closed']=self.resources.confirmed_closed
        self.j['outer_query_closed']=self.resources.confirmed_closed
        if self.native_unknown or not self.j['native_resources_closed']:self.api.controls_uncertain=True
        if not self.j['workload_cleanup'] and self.resources.pending:launcher._RETAINED_SCOPED_OWNERS.append((self.api,self.resources,'loader-live-target-file-events'))
        if not self.j['parent_event_stdio_closed'] or not self.j['marker_file_closed']:self.api.controls_uncertain=True
        observer_count=sum(decode(r['text'].encode('ascii'))['action'].startswith('observe-') for r in self.j['intents'])
        if len(self.j['proofs'])!=observer_count:self.j['observer_resources_cleanup_verified']=False
        if not self.j['observer_resources_cleanup_verified'] or self.context_bound:self.api.controls_uncertain=True
        if self.j['workload_cleanup'] and self.j['observer_resources_cleanup_verified'] and not self.api.controls_uncertain:
            try:
                if self.j['labels']:
                    self.journal('label-restore')
                    for p in sorted(base.owned_tree(self.root/'selected-output'),key=lambda p:len(p.parts),reverse=True):
                        self.budget.require_ms(self.budget.cutoff(5));self.api.label_set(p,None)
                    for p in base.owned_tree(self.root/'selected-output'):
                        self.budget.require_ms(self.budget.cutoff(5));require(self.api.label_read(p) is None,'loader_label_restore')
                    self.j['labels'][0]['restored']=True
                self.j['labels_restored']=True
                if self.profile['created']:
                    ledger=helpers.OneShotHandles(self.api.close);rows=[];job=None
                    try:
                        job=self.api.owned_job(ledger);self.journal('acl-remove');self.tool([str(self.fixed_tool('icacls.exe')),str(self.root),'/remove:g','*'+self.profile['sid'],'/T','/Q'],
                            'remove',cleanup=True,owners=ledger,children=rows,job=job);self.scope_acl(True);self.j['acl_removed']=True
                    finally:
                        if job is not None:self.j['cleanup_tools']=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,rows,ledger)[0]
                        self.j['cleanup_tasks']=[task_projection(x) for x in rows]
                    if self.j['acl_removed'] and self.j['cleanup_tools']:
                        self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True
                elif not self.profile['attempted']:self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)
            except BaseException:pass
        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True
        except BaseException:pass
        if not all(self.j[k] for k in CLEAN_KEYS):self.j['failure']=self.j['failure'] or 'cleanup'

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent),'loader_parent')
    require(budget.frequency==c['frequency'] and budget.deadline==c['deadline_qpc'],'loader_budget')
    return Owner(root,c,parent,api,budget).run()

INPUT_NAMES=('native-plan.bin','native-marker.bin','native-identity.bin','native-security.bin',
    'native-target-path.u16','native-marker-nt-path.u16','native-marker-ascii-path.ascii')

def read_expectation(j,c,root,selected):
    require(type(j['native_inputs']) is dict and set(j['native_inputs'])==set(INPUT_NAMES),'mm_native_input_set')
    raw={name:read_binary(root,d,4096) for name,d in j['native_inputs'].items()}
    require(all(j['native_inputs'][name]['name']==name for name in INPUT_NAMES),'mm_input_name')
    def path(name,encoding):
        r=raw[name];nul=b'\0\0' if encoding=='utf-16-le' else b'\0'
        require(r.endswith(nul),'mm_path_NUL');return r[:-len(nul)].decode(encoding)
    expected=dict(plan512=raw['native-plan.bin'],identity256=raw['native-identity.bin'],security1024=raw['native-security.bin'],
        initial_marker320=raw['native-marker.bin'],target_path=path('native-target-path.u16','utf-16-le'),
        marker_nt_path=path('native-marker-nt-path.u16','utf-16-le'),marker_ascii_path=path('native-marker-ascii-path.ascii','ascii'),
        commitments=dict(run=bytes.fromhex(c['run']),config_sha256=bytes.fromhex(sha(encode(c))),source_sha256=bytes.fromhex(c['source_sha256']),
            target_sha256=bytes.fromhex(CURL_SHA256),marker_sha256=bytes.fromhex(c['artifacts']['marker']['sha256'])))
    p=raw['native-plan.bin'];w=j['window'];require(len(p)==512,'mm_plan_size')
    require(struct.unpack_from('<5Q',p,8)==(c['frequency'],c['start_qpc'],c['root_deadline_qpc'],w['start'],w['end'])
        and struct.unpack_from('<I',p,48)[0]==selected['pid'] and struct.unpack_from('<Q',p,56)[0]==selected['created'],'mm_plan_epoch_generation')
    require(raw['native-identity.bin']==protocol.inputs.identity_bytes(selected['expected_primary'])
        and raw['native-security.bin']==protocol.inputs.security_bytes(selected['kernel_security'],selected['expected_primary']['sid']),'mm_expected_primary_SD')
    cfg=dict(frequency=c['frequency'],start_qpc=c['start_qpc'],root_deadline_qpc=c['root_deadline_qpc'],run=c['run'],
        config_sha256=sha(encode(c)),source_sha256=c['source_sha256'],marker_sha256=c['artifacts']['marker']['sha256'])
    require(raw['native-marker.bin']==protocol.inputs.marker_bytes(cfg,w,dict(pid=selected['pid'],created=selected['created']),selected['inherited_handles'][:2]),'mm_initial_marker_binding')
    require(expected['target_path']==c['curl_path'] and expected['marker_ascii_path']==str(artifact_paths(Path(root))['marker']),'mm_input_paths')
    reader.validate_inputs(expected)
    return expected

def validate_operations(j,c,root,intents,returns,selected):
    require(type(j['operations']) is list and len(j['operations'])<=5,'mm_operation_bound')
    operations=[];decoded=None;window=j['window'];rmap={}
    expected=read_expectation(j,c,root,selected) if j['native_inputs'] is not None else None
    for row in j['operations']:
        require(type(row) is dict and set(row)=={'operation','intent_sha256','returned','return_code','raw','result_file','context','output','status','receipt'}
            and row['operation'] in OPERATIONS and row['intent_sha256'] in intents
            and intents[row['intent_sha256']]['action']=='wrapper-'+row['operation'] and type(row['returned']) is bool
            and row['status'] in ('missing','invalid','valid'),'mm_operation_schema')
        op=row['operation'];require(op not in operations,'mm_operation_once');operations.append(op)
        if not row['returned']:
            require(row['status']=='missing' and all(row[k] is None for k in ('raw','return_code','result_file','context','output','receipt')),'mm_unreturned_native')
            require(not j['native_resources_closed'] and not j['profile_deleted'],'mm_native_unknown_blocks_cleanup');continue
        require(type(row['raw']) is str and re.fullmatch('[0-9a-f]{512}',row['raw']) and type(row['return_code']) is int
            and row['receipt'] is not None and row['receipt']['sha256'] in returns,'mm_raw_return_shape')
        rec=returns[row['receipt']['sha256']]
        require(rec['intent_sha256']==row['intent_sha256'] and rec['action']=='wrapper-'+op
            and rec['data']=={k:row[k] for k in ('return_code','raw','result_file','context','output')},'mm_native_physical_return')
        require(read_binary(root,row['result_file'],256)==bytes.fromhex(row['raw']),'mm_result_binary_physical')
        require(row['result_file']['name']=='native-'+op+'-result.bin' and row['context']['name']=='native-'+op+'-context.bin','mm_operation_file_names')
        ctx=read_binary(root,row['context'],8192);require(len(ctx)==8192,'mm_context_extent')
        if row['status']!='valid':
            require(not j['native_resources_closed'] and not j['profile_deleted'],'mm_invalid_native_blocks_cleanup');continue
        r=result_record(bytes.fromhex(row['raw']),op,(window['start'],window['end']));rmap[op]=r
        if op=='update' and r['result_class']==11:
            require(r['primary_call']['requested']==struct.unpack_from('<Q',expected['plan512'],64)[0],'mm_update_process_binding')
        if op=='forget' and r['result_class']==10:require(ctx==bytes(8192),'mm_forget_physical_context_zero')
        require(row['return_code']==r['result_class'],'mm_return_code')
        if r['return_clock_known']:require(r['returned_qpc']<=rec['qpc'],'mm_native_return_causal')
        if r['within_window']:require(r['entered_qpc']>=intents[row['intent_sha256']]['qpc'],'mm_native_intent_causal')
        if op=='observe':
            require(row['output'] is not None and row['output']['name']=='native-observe-output.bin','mm_observe_file_name')
            raw=read_binary(root,row['output'],24576);require(len(raw)==24576 and raw[:256]==bytes.fromhex(row['raw']),'mm_output_result')
            decoded=reader.decode_output(raw,expected)
            require(decoded['result']==r,'mm_decoded_result')
            if decoded['gates']['coherent_marker']:
                require(all(struct.unpack_from('<Q',v,232)[0]>=selected['resume_intent_qpc'] for v in decoded['markers'][2:]),'mm_marker_resume_causal')
        else:require(row['output'] is None,'mm_nonobserve_output')
    def good(op,k):return op in rmap and rmap[op]['result_class']==k
    require(not operations or operations[0]=='begin','mm_operation_start')
    for op,index in (('update',1),('install',2),('observe',3)):
        if op in operations:require(operations.index(op)==index,'mm_operation_order')
    if 'forget' in operations:require(operations[-1]=='forget','mm_forget_order')
    if 'update' in operations:require(good('begin',9) and len(j['proofs'])>=1 and j['proofs'][0]['value']['qualified'],'mm_update_gate')
    if 'install' in operations:require(good('update',11),'mm_install_gate')
    resume=j['resume_observation']
    if resume is not None:
        require(resume['sha256'] in returns,'mm_resume_physical');v=returns[resume['sha256']];f=v['data']
        require(v['action']=='resume-selected' and selected is not None and v['intent_sha256'] in intents
            and intents[v['intent_sha256']]['qpc']==selected['resume_intent_qpc'],'mm_resume_intent')
        require(type(f) is dict and set(f)=={'entered','returned','count','error','returned_qpc','clock_error','exception'}
            and f['entered'] is True and all(type(f[k]) is bool for k in ('returned','clock_error','exception')),'mm_resume_raw_schema')
        require(f['count'] is None or live.integer(f['count'],0,0xffffffff),'mm_resume_raw_count')
        require(f['error'] is None or live.integer(f['error'],0,0xffffffff),'mm_resume_error')
        if selected['resumed']:
            require(f['returned'] and f['count']==1 and f['error'] is None and not f['clock_error'] and not f['exception']
                and f['returned_qpc']==selected['resume_qpc'] and selected['resume_intent_qpc']<=f['returned_qpc']<=v['qpc'],'mm_resume_known_raw')
    else:require(selected is None or not selected['resumed'],'mm_resume_receipt_missing')
    if 'observe' in operations:require(good('install',5) and selected is not None and selected['resumed'] and resume is not None
        and selected['resume_qpc']<window['end'],'mm_observe_resume_gate')
    if selected is not None and selected['natural_exit']:
        require('observe' in rmap and rmap['observe']['target_alive']==1 and rmap['observe']['return_clock_known']==1
            and rmap['observe']['returned_qpc']<=selected['exit_observed_qpc']<window['end'],'mm_natural_exit_alive_causal')
        require(not j['selected_stop_attempted'] and all(v['action'] not in ('stop-selected','workload-stop')
            or v['qpc']>selected['exit_observed_qpc'] for v in intents.values()),'mm_natural_exit_not_controlled_stop')
    return good,decoded

def validate_leases(j,c,root,returns,selected):
    require(type(j['lease_checks']) is list and len(j['lease_checks'])<=2,'mm_lease_check_count')
    leases={}
    for field,action in (('target_lease','target-lease'),('marker_lease','marker-lease'),('outer_query','outer-query')):
        d=j[field]
        if d is None:continue
        require(d['sha256'] in returns,'mm_lease_return');v=returns[d['sha256']];require(v['action']==action,'mm_lease_action')
        data=v['data'];require(type(data) is dict and live.integer(data.get('handle'),1,0xfffffffffffffffe),'mm_lease_handle')
        if field=='outer_query':require(set(data)=={'handle','access','inherited'} and data['access']==4 and data['inherited'] is False,'mm_outer_query_scope')
        else:require(set(data)=={'handle','file_identity'} and type(data['file_identity']) is dict,'mm_lease_file')
        leases[field]=data
    for index,d in enumerate(j['lease_checks']):
        require(d['sha256'] in returns,'mm_lease_check_return');v=returns[d['sha256']]
        require(v['action']==('lease-before','lease-after')[index] and set(v['data'])=={'target','marker'},'mm_lease_check_phase')
        for role,field,key in (('target','target_lease','curl'),('marker','marker_lease','marker')):
            x=v['data'][role];require(type(x) is dict and set(x)=={'file_identity','bytes','sha256','pe'} and field in leases
                and x['file_identity']==leases[field]['file_identity'] and x['bytes']==c['artifacts'][key]['bytes'] and x['sha256']==c['artifacts'][key]['sha256'],'mm_lease_hash_ID')
            protocol.inputs.pe_bytes(x['pe'],dll=role=='marker')
        if index==1:require(selected is not None and selected['natural_exit'] and selected['exit_observed_qpc']<=v['qpc'],'mm_postexit_lease')
    if j['native_inputs'] is not None:
        require(len(j['lease_checks'])>=1 and len(leases)==3,'mm_prepared_leases')
        d=j['borrowed_resources'];require(d is not None and d['sha256'] in returns,'mm_borrow_receipt')
        v=returns[d['sha256']];data=v['data'];names=('process','thread','primary_token','inner_job','outer_job','entered_event','body_event','target_lease','marker_lease')
        require(v['action']=='native-borrows' and type(data) is dict and set(data)=={'handles','flags'}
            and type(data['handles']) is dict and set(data['handles'])==set(names) and type(data['flags']) is dict
            and set(data['flags'])==set(names) and all(type(f) is int and f==0 for f in data['flags'].values()),'mm_borrow_flags_record')
        p=read_binary(root,j['native_inputs']['native-plan.bin'],512)
        hs=struct.unpack_from('<9Q',p,64);pi=physical_record(selected['receipt'],Path(root)/'returns'/selected['receipt']['name'])['data']['raw_pi']
        require(hs==tuple(data['handles'][name] for name in names),'mm_plan_borrow_receipt')
        require(hs[:2]==tuple(pi[:2]) and hs[4]==leases['outer_query']['handle'] and hs[7:]==(leases['target_lease']['handle'],leases['marker_lease']['handle']),'mm_plan_owned_borrows')
        require(hs[5:7]==tuple(physical_record(d,Path(root)/'returns'/d['name'])['data']['handle'] for d in j['event_resources'][:2]),'mm_plan_events')
        before=returns[j['lease_checks'][0]['sha256']]['data']
        for off,name in ((360,'target'),(384,'marker')):
            require(p[off:off+24]==protocol.inputs.file_id_bytes(before[name]['file_identity']),'mm_plan_FileID')
        for off,name in ((408,'target'),(440,'marker')):
            require(p[off:off+32]==protocol.inputs.pe_bytes(before[name]['pe'],dll=name=='marker'),'mm_plan_PE')
        require(struct.unpack_from('<2Q',p,488)==(c['artifacts']['curl']['bytes'],c['artifacts']['marker']['bytes']),'mm_plan_file_sizes')

def validate_observation(v):
    require(type(v) is dict and set(v)==OBS_KEYS and all(type(v[k]) is bool for k in (*OBS_BOOLS,*FALSE_CLAIMS))
        and v['failure'] in (None,*FAILURES) and (v['selected_exit_code'] is None or live.integer(v['selected_exit_code'],0,0xffffffff)),'mm_observation')
    require(not any(v[k] for k in FALSE_CLAIMS),'mm_false_claims')
    require(not v['selected_version_positive'] or v['selected_natural_exit'] and v['selected_exit_code']==0,'mm_version_requires_zero')
    required=('lpac_identity_verified','update_returned_true','payload_installed','selected_resumed','entered_event_observed','body_event_observed',
        'coherent_marker_observed','memory_mapping_correlated','native_critical_complete','trace_complete','selected_natural_exit')
    require(not v['loader_mechanism_observed'] or all(v[k] for k in required),'mm_mechanism')
    require(not v['version_behavior_observed'] or all(v[k] for k in ('ordinary_before_positive','ordinary_after_positive','selected_version_positive')),'mm_version_controls')
    require(not v['observation_complete'] or v['failure'] is None and v['loader_mechanism_observed'] and v['ordinary_before_positive']
        and v['ordinary_after_positive'] and all(v[k] for k in CLEAN_KEYS),'mm_complete')
    return v

def project(j,c,*,parent,root):
    validate_result(j,c,parent=parent,root=root)
    v=dict(failure=j['failure'],selected_exit_code=None,**dict.fromkeys(OBS_BOOLS,False),**dict.fromkeys(FALSE_CLAIMS,False))
    v.update({k:j[k] for k in CLEAN_KEYS});controls=ordinary_controls(root,c,parent)
    v['ordinary_before_positive'],v['ordinary_after_positive']=controls['before'],controls['after']
    selected=next((t for t in j['tasks'] if t['name']=='selected'),None)
    v['lpac_identity_verified']=bool(len(j['proofs'])==2 and all(x['value']['qualified'] for x in j['proofs']))
    for op,key,code in (('update','update_returned_true',11),('install','payload_installed',5)):
        v[key]=any(r['operation']==op and r['status']=='valid' and r['return_code']==code for r in j['operations'])
    if selected:
        v.update(selected_resumed=selected['resumed'],selected_natural_exit=selected['natural_exit'],selected_exit_code=selected['exit_code'])
        v['selected_version_positive']=bool(selected['natural_exit'] and selected['exit_code']==0 and j['selected_output'] and j['selected_output']['recognized'])
    op=next((r for r in j['operations'] if r['operation']=='observe' and r['status']=='valid'),None)
    if op is not None:
        d=reader.decode_output(read_binary(root,op['output'],24576),read_expectation(j,c,root,selected));g=d['gates'];r=d['result']
        v.update(native_critical_complete=g['inner_complete'],trace_complete=g['trace_complete'],entered_event_observed=bool(r['entered_observed']),
            body_event_observed=bool(r['body_observed']),coherent_marker_observed=g['coherent_marker'],memory_mapping_correlated=g['memory_mapping'])
    v['loader_mechanism_observed']=all(v[k] for k in ('lpac_identity_verified','update_returned_true','payload_installed','selected_resumed',
        'entered_event_observed','body_event_observed','coherent_marker_observed','memory_mapping_correlated','native_critical_complete','trace_complete','selected_natural_exit')) and len(j['lease_checks'])==2
    v['version_behavior_observed']=all(v[k] for k in ('ordinary_before_positive','ordinary_after_positive','selected_version_positive'))
    v['observation_complete']=v['failure'] is None and v['loader_mechanism_observed'] and v['ordinary_before_positive'] and v['ordinary_after_positive'] and all(v[k] for k in CLEAN_KEYS)
    return validate_observation(v)

def physical_record(record,path):
    require(type(record) is dict and set(record)=={'name','text','sha256'} and record['name']==Path(path).name
            and type(record['text']) is str and len(record['text'])<=MAX_REPORT and base.ac.digest(record['sha256']),'loader_record')
    raw=record['text'].encode('ascii');require(sha(raw)==record['sha256'] and local.bounded(Path(path),MAX_REPORT)==raw,'loader_record_physical')
    return decode(raw)

TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','process_returned','resumed','admitted','image_sha256',
    'admission_qpc','resume_qpc','resume_intent_qpc','exit_observed_qpc','natural_exit','identity','capabilities','lpac','lpac_expected',
    'expected_primary','held_checks','receipt','create_observation','constructor_return_qpc','inherited_handles','parent_copies_closed','kernel_security'}
TASK_BOOLS={'attempted','assigned','exited','process_returned','resumed','admitted','natural_exit','lpac_expected','parent_copies_closed'}

def known_no_child(t,c):
    ob=t['create_observation']
    return (t['attempted'] and ob['status']=='returned_false' and live.integer(ob['winerror'],1,0xffffffff)
        and ob['process_information']=='all_zero' and live.integer(ob['returned_qpc'],c['start_qpc'],ob['work_cutoff']-1)
        and not any(t[k] for k in ('process_returned','assigned','admitted','resumed','exited'))
        and all(t[k] is None for k in ('pid','created','identity','capabilities','lpac','exit_code','admission_qpc','resume_qpc')))

def task_validate(t,c,parent,root,*,curl):
    require(type(t) is dict and set(t)==TASK_KEYS and all(type(t[k]) is bool for k in TASK_BOOLS),'loader_task_schema')
    selected=t['name']=='selected'
    require(t['name'] in ('before','selected','after','grant-root','grant-package','grant-output','remove')
            and t['lpac_expected']==selected and t['lpac'] is None and (t['capabilities'] is None or t['capabilities']==[]),'loader_task_role')
    for k in ('pid','created','admission_qpc','resume_qpc','resume_intent_qpc','exit_observed_qpc','constructor_return_qpc'):
        require(t[k] is None or live.integer(t[k],1,0xffffffffffffffff),'loader_task_integer')
    require(t['exit_code'] is None or live.integer(t['exit_code'],0,0xffffffff),'loader_task_exit')
    require(not t['exited'] or t['process_returned'] and t['exit_code'] is not None,'loader_task_exit_binding')
    require(not t['natural_exit'] or t['exited'],'mm_natural_requires_exit')
    require(type(t['held_checks']) is list and len(t['held_checks'])<=24 and type(t['inherited_handles']) is list,'loader_task_bounds')
    require(not t['admitted'] or t['assigned'] and t['attempted'] and t['process_returned'] and t['identity'] is not None
            and t['created'] is not None and t['pid'] is not None and t['capabilities']==[] and t['admission_qpc'] is not None,'loader_task_admitted')
    require(not t['resumed'] or t['admitted'] and t['resume_qpc'] is not None,'loader_task_resumed')
    if not curl:
        require(not selected and not t['natural_exit'],'loader_tool_claim')
        if t['admitted']:require(launcher.token_is_ordinary(t['identity']) and launcher.same_identity(t['identity'],parent),'loader_tool_ordinary')
        return t
    require(t['image_sha256']==CURL_SHA256,'loader_task_image')
    r=t['receipt']
    if r is not None:
        v=physical_record(r,Path(root)/'returns'/r['name']);data=v['data']
        require(v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['action']=='create-'+t['name'],'loader_PI_scope')
        require(type(data) is dict and set(data)<= {'creation_attempted','creation_unknown','create_status','raw_return','raw_error','raw_pi','returned_qpc'},'loader_PI_data')
        pi=data.get('raw_pi',[0,0,0,0]);require(type(pi) is list and len(pi)==4 and all(live.integer(x,0,0xffffffffffffffff) for x in pi),'loader_PI_extent')
        if t['process_returned']:require(data.get('create_status')=='returned_true' and data.get('raw_return') not in (None,0)
            and all(pi) and all(0<h<0xffffffffffffffff for h in pi[:2]) and pi[0]!=pi[1] and t['pid']==pi[2] and pi[2]<=0xffffffff and pi[3]<=0xffffffff,'loader_PI_owned')
    else:require(not t['admitted'],'loader_PI_missing')
    if t['admitted']:
        ob=t['create_observation'];require(type(ob) is dict and set(ob)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'}
            and ob['status']=='returned_true' and ob['winerror'] is None and ob['process_information']=='nonzero' and ob['exception_detail'] is None,'loader_create_observation')
        require(live.integer(ob['returned_qpc'],c['start_qpc'],ob['work_cutoff']-1) and ob['returned_qpc']<=t['constructor_return_qpc']<=t['admission_qpc']<ob['work_cutoff']<=work_cutoff(c),'loader_admission_clock')
        require(t['parent_copies_closed'] and len(t['inherited_handles'])==(5 if selected else 3)
            and len(set(t['inherited_handles']))==len(t['inherited_handles']) and all(live.integer(h,1,0xfffffffffffffffe) for h in t['inherited_handles']),'loader_handle_list')
        require(type(t['kernel_security']) is dict and set(t['kernel_security'])=={'process','thread'}
                and all(private_process_thread_sddl(v,parent['sid']) for v in t['kernel_security'].values()),'loader_private_process_thread')
        p=t['expected_primary'];access.identity_shape(p)
        if selected:zero.identity(p,primary=True)
        else:require(not p['appcontainer'] and p['appcontainer_sid'] is None and p['capabilities']==[] and p['token_type']==1 and not p['elevated'] and not p['ui_access'],'loader_control_token')
        require(p['sid']==parent['sid'] and p['session_id']==parent['session_id'] and type(p['token_id']) is int and type(p['authentication_id']) is int,'loader_primary_binding')
        require(t['identity']['capability_count']==0 and all(t['identity'][k]==p[k] for k in ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access')),'loader_identity_primary_match')
        require(t['held_checks'],'loader_held_missing')
        for h in t['held_checks']:
            require(type(h) is dict and set(h)=={'qpc','pid','created','image_sha256','primary','inner_job','outer_job','kernel_security'}
                and h['pid']==t['pid'] and h['created']==t['created'] and h['image_sha256']==CURL_SHA256 and h['primary']==p
                and h['inner_job'] is True and h['outer_job'] is True and h['kernel_security']==t['kernel_security']
                and live.integer(h['qpc'],c['start_qpc'],work_cutoff(c)-1),'loader_held_binding')
        if t['resumed']:
            require(live.integer(t['resume_intent_qpc'],t['admission_qpc'],work_cutoff(c)-1)
                and t['resume_intent_qpc']<=t['resume_qpc']<ob['work_cutoff'],'loader_resume_causal')
        if t['natural_exit']:require(t['resumed'] and live.integer(t['exit_observed_qpc'],t['resume_qpc'],ob['work_cutoff']-1),'loader_exit_causal')
    return t

def validate_ordinary_control(value,c,*,role,parent,root):
    require(role in ('before','after') and type(value) is dict and set(value)=={'schema_version','scope','run','config_sha256','parent_sha256','role','case','deadline_qpc','task','output','positive'},'loader_control_schema')
    require(value['schema_version']==1 and type(value['schema_version']) is int and value['scope']==SCOPE and value['run']==c['run'] and value['config_sha256']==sha(encode(c))
        and value['parent_sha256']==sha(encode(parent)) and value['role']==role and value['case']==c[role+'_case'],'loader_control_binding')
    t=task_validate(value['task'],c,parent,root,curl=True);require(t['name']==role and not t['lpac_expected'],'loader_control_role')
    directory=Path(root)/('ordinary-'+role);output=version_output(local.bounded(directory/'stdout',MAX_OUTPUT),local.bounded(directory/'stderr',MAX_OUTPUT))
    require(output==value['output'] and type(value['positive']) is bool and value['deadline_qpc']==t['create_observation']['work_cutoff'],'loader_control_output')
    positive=t['natural_exit'] and t['exit_code']==0 and output['recognized']
    require(value['positive']==positive,'loader_control_positive');return value

def ordinary_controls(root,c,parent):
    out=dict(before=False,after=False)
    for role in out:
        try:
            value=decode(local.bounded(Path(root)/('control-'+role+'.json'),MAX_REPORT))
            validate_ordinary_control(value,c,role=role,parent=parent,root=root);out[role]=value['positive']
        except BaseException:pass
    return out

def validate_result(j,c,*,parent,root):
    config_validate(c);require(launcher.token_is_ordinary(parent),'loader_result_parent');root=Path(root)
    keys={'schema_version','stage','scope','profile','config_sha256','failure','failure_detail','profile_name','profile_sid','profile_state','child_environment',
        'intents','returns','operations','proofs','tasks','cleanup_tasks','labels','window','native_inputs','borrowed_resources','marker_lease','target_lease','outer_query','lease_checks','event_resources','resume_observation','controls','selected_output',
        'profile_created','acl_attempted','creation_unknown','context_bound','context_forgotten','selected_stop_attempted','selected_exit_confirmed',
        'token_class46_queried','endpoint_created','dns_api_called',*CLEAN_KEYS,*FALSE_CLAIMS}
    require(type(j) is dict and set(j)==keys and j['schema_version']==1 and type(j['schema_version']) is int and j['stage']=='lpac-curl-mm-loader-result' and j['scope']==SCOPE
        and j['profile']==PROFILE and j['config_sha256']==sha(encode(c)) and j['failure'] in (None,*FAILURES),'loader_result_schema')
    base.validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'loader_failure_detail')
    booleans={'profile_created','acl_attempted','creation_unknown','context_bound','context_forgotten','selected_stop_attempted','selected_exit_confirmed',
              'token_class46_queried','endpoint_created','dns_api_called',*CLEAN_KEYS,*FALSE_CLAIMS}
    require(all(type(j[k]) is bool for k in booleans) and not any(j[k] for k in (*FALSE_CLAIMS,'token_class46_queried','endpoint_created','dns_api_called')),'loader_result_scope')
    require(j['profile_name']=='ruleproxy-curl-mm-loader-'+c['run'] and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'loader_profile_binding')
    require(type(j['profile_state']) is dict and set(j['profile_state'])=={'attempted','returned','created','sid_pointer_returned'} and all(type(x) is bool for x in j['profile_state'].values()),'loader_profile_state')
    require(not j['profile_created'] or j['profile_state']['created'] and j['profile_sid'] is not None and launcher.child_environment_admitted(j['child_environment']),'loader_profile_created')
    require(not j['acl_attempted'] or j['profile_created'],'loader_ACL_intent')
    require(type(j['intents']) is list and len(j['intents'])<=64 and type(j['returns']) is list and len(j['returns'])<=64,'loader_journal_bound')
    intents={};returns={};previous=c['start_qpc']
    for index,d in enumerate(j['intents']):
        v=physical_record(d,root/'journal'/d['name'])
        require(set(v)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action'} and v['schema_version']==1 and type(v['schema_version']) is int
            and v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['frequency']==c['frequency']
            and v['deadline_qpc']==c['deadline_qpc'] and live.integer(v['qpc'],previous,c['deadline_qpc']-1)
            and d['name']=='%02d-%s.json'%(index,v['action']) and re.fullmatch('[a-z0-9-]{1,64}',v['action']),'loader_intent_binding')
        intents[d['sha256']]=v;previous=v['qpc']
    for index,d in enumerate(j['returns']):
        v=physical_record(d,root/'returns'/d['name'])
        require(set(v)=={'schema_version','scope','run','config_sha256','intent_sha256','action','qpc','data'} and v['schema_version']==1 and type(v['schema_version']) is int
            and v['scope']==SCOPE and v['run']==c['run'] and v['config_sha256']==sha(encode(c)) and v['intent_sha256'] in intents
            and v['action']==intents[v['intent_sha256']]['action'] and live.integer(v['qpc'],intents[v['intent_sha256']]['qpc'],c['deadline_qpc']-1)
            and d['name']=='%02d-%s.json'%(index,v['action']),'loader_return_binding')
        returns[d['sha256']]=v
    require({p.name for p in (root/'journal').iterdir()}=={r['name'] for r in j['intents']}
        and {p.name for p in (root/'returns').iterdir()}=={r['name'] for r in j['returns']},'loader_closed_physical_journal')
    require(type(j['tasks']) is list and len(j['tasks'])<=6 and type(j['cleanup_tasks']) is list and len(j['cleanup_tasks'])<=1,'loader_task_count')
    tasks={}
    for t in j['tasks']:
        task_validate(t,c,parent,root,curl=t['name'] in ('before','selected','after'));require(t['name'] not in tasks,'loader_task_duplicate');tasks[t['name']]=t
        if t['receipt'] is not None:require(t['receipt']['sha256'] in returns,'loader_task_PI_return')
    for t in j['cleanup_tasks']:task_validate(t,c,parent,root,curl=False);require(t['name']=='remove','loader_cleanup_tool_role')
    controls=ordinary_controls(root,c,parent);require(type(j['controls']) is dict and set(j['controls'])=={'before','after'},'loader_controls')
    for role,d in j['controls'].items():
        if d is not None:
            require(type(d) is dict and set(d)=={'text','sha256'} and sha(d['text'].encode('ascii'))==d['sha256']
                and local.bounded(root/('control-'+role+'.json'),MAX_REPORT)==d['text'].encode('ascii'),'loader_control_physical')
            v=validate_ordinary_control(decode(d['text'].encode('ascii')),c,role=role,parent=parent,root=root);require(v['task']==tasks[role],'loader_control_task_match')
    selected=tasks.get('selected');window=j['window']
    if selected is not None and selected['admitted']:require(selected['expected_primary']['appcontainer_sid']==j['profile_sid'] and j['profile_created'] and j['acl_attempted'],'loader_selected_profile')
    if window is not None:
        require(type(window) is dict and set(window)=={'start','end'} and live.integer(window['start'],c['start_qpc'],work_cutoff(c)-1)
            and window['end']==min(window['start']+8*c['frequency'],work_cutoff(c)) and selected is not None,'loader_window')
        if j['native_inputs'] is None:
            require(not j['operations'] and not j['context_bound'] and not selected['resumed'] and j['failure'] is not None,'loader_partial_native_preparation')
        else:
            expected=read_expectation(j,c,root,selected)
            reader.validate_inputs(expected)
    else:require(j['native_inputs'] is None and not j['operations'],'loader_no_native_window')
    require(type(j['proofs']) is list and len(j['proofs'])<=2,'loader_proof_count')
    for index,row in enumerate(j['proofs']):
        require(set(row)=={'label','intent_sha256','value'} and row['label']==('before-update','before-resume')[index] and selected is not None
            and row['intent_sha256'] in intents and intents[row['intent_sha256']]['action']=='observe-'+row['label'],'loader_proof_intent')
        end=work_cutoff(c) if index==0 else window['end'];proof=row['value']
        zero.validate_proof(proof,expected_primary_identity=selected['expected_primary'],expected_role='lpac',expected_pid=selected['pid'],expected_creation=selected['created'],frequency=c['frequency'],deadline=end)
        require(proof['start_qpc'] is None or proof['start_qpc']>=intents[row['intent_sha256']]['qpc'],'loader_proof_causal')
    count=sum(x['action'].startswith('observe-') for x in intents.values())
    require(not j['observer_resources_cleanup_verified'] or count==len(j['proofs']) and all(x['value']['resource_cleanup_verified'] for x in j['proofs']),'loader_observer_cleanup')
    good,decoded=validate_operations(j,c,root,intents,returns,selected)
    if selected is not None and selected['resumed']:
        require(good('install',5) and len(j['proofs'])==2 and all(p['value']['qualified'] for p in j['proofs'])
            and j['proofs'][1]['value']['end_qpc']<=selected['resume_intent_qpc']<window['end'],'mm_selected_resume_gate')
    if j['context_forgotten']:require(good('forget',10) and j['selected_exit_confirmed'],'mm_context_forget')
    require(type(j['event_resources']) is list and len(j['event_resources'])<=4,'loader_event_resources')
    handles=[]
    for index,d in enumerate(j['event_resources']):
        require(d['sha256'] in returns,'loader_event_return');v=returns[d['sha256']];data=v['data'];handles.append(data['handle'])
        if index<2:require(v['action']=='event-create' and set(data)=={'handle','desired_access','inherited'} and data['desired_access']==0x100002 and data['inherited'] is False,'loader_event_parent_rights')
        else:require(v['action']=='event-duplicate' and set(data)=={'source','handle','desired_access','inherited','options'} and data['source']==handles[index-2]
            and data['desired_access']==2 and data['inherited'] is True and data['options']==0,'loader_event_signal_rights')
    require(all(live.integer(h,1,0xfffffffffffffffe) for h in handles) and len(handles)==len(set(handles)),'loader_event_alias')
    if selected is not None and selected['admitted']:require(len(handles)==4 and selected['inherited_handles'][:2]==handles[2:],'loader_selected_events')
    validate_leases(j,c,root,returns,selected)
    if decoded is not None:
        require(not j['native_resources_closed'] or decoded['gates']['resources'],'mm_resource_claim')
    elif any(x['operation']=='observe' for x in j['operations']):
        require(not j['native_resources_closed'],'mm_unreturned_observe_resources')
    if j['selected_output'] is not None:
        require(selected is not None and selected['exited'] and j['selected_output']==version_output(local.bounded(root/'selected-output'/'stdout',MAX_OUTPUT),local.bounded(root/'selected-output'/'stderr',MAX_OUTPUT)),'loader_selected_output')
    if j['workload_cleanup']:
        require(j['workload_job_empty'] and not j['creation_unknown'] and all(not t['attempted'] or t['exited'] or known_no_child(t,c) for t in j['tasks']),'loader_workload_cleanup')
    if j['profile_deleted'] and j['profile_state']['attempted']:
        require(j['acl_removed'] and j['cleanup_tools'] and j['labels_restored'] and all(j[k] for k in CLEAN_KEYS if k not in ('profile_deleted','sid_released'))
            and len(j['cleanup_tasks'])==1 and j['cleanup_tasks'][0]['admitted'] and j['cleanup_tasks'][0]['resumed'] and j['cleanup_tasks'][0]['exited'] and j['cleanup_tasks'][0]['exit_code']==0,'loader_profile_cleanup_gate')
    require(type(j['labels']) is list and len(j['labels'])<=1,'loader_label_rows')
    if j['labels']:
        label=j['labels'][0];require(type(label) is dict and set(label)=={'name','attempted','lowered','restored'} and label['name']=='selected-output'
            and label['attempted'] is True and all(type(label[k]) is bool for k in ('lowered','restored')),'loader_label_schema')
        require(not j['labels_restored'] or label['restored'],'loader_label_restored')
    if selected is not None and selected['admitted']:
        require(len(j['labels'])==1 and j['labels'][0]['lowered'] and any(v['action']=='label-lower' for v in intents.values())
            and all(name in tasks and tasks[name]['admitted'] and tasks[name]['resumed'] and tasks[name]['exited'] and tasks[name]['exit_code']==0 for name in ('grant-root','grant-package','grant-output')),'loader_selected_setup_gate')
    if j['labels'] and j['labels_restored']:require(any(v['action']=='label-restore' for v in intents.values()),'loader_label_restore_intent')
    if j['profile_deleted'] and j['profile_created']:require(any(v['action']=='acl-remove' for v in intents.values()) and any(v['action']=='profile-delete' for v in intents.values()),'loader_profile_delete_intents')
    if all(j[k] for k in CLEAN_KEYS) and j['context_bound']:require(j['context_forgotten'],'loader_context_cleanup_gate')
    return j

