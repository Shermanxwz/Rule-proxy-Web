"""Gated A4 fixed-curl startup diagnostic owner. Explicit local opt-in required.

No module-level native construction, DLL load, target, test or API call. Reused
CMM Python is a source-pinned utility dependency, not a CMM execution fallback.
Memory/GUID/trace/version/external cleanup are distinct facts; no adapter claim.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
from types import SimpleNamespace

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    path=Path(__file__).with_name(file)
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    # The memory dependency has one ordinary absolute builder import. Bind the
    # fixed pure source first, not a search/PATH-dependent alternate builder.
    sys.modules[name]=module
    spec.loader.exec_module(module)
    return module

mm=load('a4_cmm_shared_utilities','windows_identity_lpac_curl_mm_loader.py')
builder=load('windows_identity_lpac_curl_import_builder','windows_identity_lpac_curl_import_builder.py')
memory=load('a4_fixed_memory_sequence','windows_identity_lpac_curl_a4_memory.py')
trace_reader=load('a4_independent_trace_reader','windows_identity_lpac_curl_a4_binary_reader.py')
zero,cell,base,access=mm.zero,mm.cell,mm.base,mm.access
local,launcher,helpers,live=mm.local,mm.launcher,mm.helpers,mm.live
require,sha,encode,decode=mm.require,mm.sha,mm.encode,mm.decode

ACTUAL_READY=True
MODULE='.github/windows_identity_lpac_curl_a4_loader.py'
LOCAL_MODULE='.github/windows_identity_lpac_curl_a4_loader_local.py'
MEMORY_MODULE='.github/windows_identity_lpac_curl_a4_memory.py'
BUILDER_MODULE='.github/windows_identity_lpac_curl_import_builder.py'
READER_MODULE='.github/windows_identity_lpac_curl_a4_binary_reader.py'
PHYSICAL_MODULE='.github/windows_identity_lpac_curl_a4_physical.py'
MEMORY_PHYSICAL_MODULE='.github/windows_identity_lpac_curl_a4_memory_physical.py'
TRACE_ABI_MODULE='.github/windows_identity_lpac_curl_a4_trace_abi.json'
CARRIER_ABI_MODULE='.github/windows_identity_lpac_curl_a4_carrier_abi.json'
SIGNATURE_MODULE='.github/windows_identity_lpac_curl_a4_signatures.json'
SCOPE='one-local-zero-cap-lpac-fixed-curl-startup-diagnostic-v1'
PROFILE='zero-cap-fixed-curl-private-startup-with-ordinary-version-controls-v1'
NONCES=('run','before_case','selected_case','after_case','trace_case')
SHIM='windows_identity_lpac_curl_ws2_shim.dll'
CARRIER='windows_identity_lpac_curl_a4_payload_wrapper.dll'
MANIFEST='lpac-curl-A4-native-artifact-manifest-01.json'
NATIVE_SOURCES=tuple('.github/native/windows_identity_lpac_curl_ws2_startup_'+n for n in
    ('abi.hpp','core.hpp','find.hpp','refs.hpp','shim.cpp','shim.def','shim.hpp','win32.hpp'))
CARRIER_SOURCES=tuple('.github/native/windows_identity_lpac_curl_a4_payload_wrapper.'+n for n in ('cpp','hpp'))
VENDOR_SOURCES=tuple('.github/vendor/detours/'+n for n in mm.VENDOR_FILES)
SOURCES=tuple(dict.fromkeys((*mm.SOURCES,MODULE,LOCAL_MODULE,MEMORY_MODULE,BUILDER_MODULE,READER_MODULE,PHYSICAL_MODULE,MEMORY_PHYSICAL_MODULE,
    TRACE_ABI_MODULE,CARRIER_ABI_MODULE,SIGNATURE_MODULE,*NATIVE_SOURCES,*CARRIER_SOURCES)))
TRACE_ABI_SHA256='6c3eb52d716124c3638530e0a9a78df2130e50cbdc1e471f9cd9845653dc2b0d'
CARRIER_ABI_SHA256='4d1eacbafb2335516f728cdc1f909b95add4276f4d84919c1bb947cb92589d4f'
SIGNATURE_SHA256='02b5f4a24433f7725e1f2d1f423da75c431d5427ce51b1ce170f9d531de600d2'
GUID_BYTES=bytes.fromhex('1e3b748b5028824ca350fda8439e3ab1')
CURL_BYTES,CURL_SHA256=mm.CURL_BYTES,mm.CURL_SHA256
BASELINE_BYTES=366
BASELINE_SHA256='462db4e956d97703eae92a1863090a26987ab7b9bc55c43b4e11565918cc56a4'
TRACE_BYTES=557312
MAX_REPORT=4*1024*1024
MAX_OUTPUT=8192
ACKS=('fresh_profile_owned_acl_acknowledged','fixed_curl_import_rewrite_acknowledged',
      'zero_capabilities_no_fallback_acknowledged','target_vm_lifetime_cleanup_acknowledged',
      'fixed_payload_carrier_acknowledged','shared_trace_not_hostile_acknowledged',
      'ordinary_version_controls_acknowledged','same_sid_unqualified_acknowledged',
      'no_transport_adapter_acknowledged','amd64_private_PEB_probe_acknowledged')
FALSE_CLAIMS=('restoration_fully_verified','restore_payload_absence_verified','all_dynamic_calls_mediated',
    'network_qualified','dns_isolation_qualified','proxy_qualified','Linux_equivalence','application_compatibility',
    'product_acceptance','hostile_same_sid_boundary_verified','hostile_child_trace_authenticity',
    'whole_mapped_image_integrity_verified','PSEC_qualified','root_crash_safe')
ARTIFACT_KEYS=('curl','shim','carrier','manifest')
FROZEN_ARTIFACTS={
    'curl':dict(bytes=CURL_BYTES,sha256=CURL_SHA256),
    'shim':dict(bytes=146944,sha256='2e219f1c6244bbe26d7c08f09964a64cad24b2eecb5e96a0cbdd59ae7b029473'),
    'carrier':dict(bytes=123392,sha256='3c23f0d2c443138a7d4250005eea001a7093fa1593d9da9d2545a24cc9e9ee61'),
    'manifest':dict(bytes=4329,sha256='815fded39baa946bae40ecd09c64f4ea12ec81eab88ce8e8d58d3d89c650c4f9')}
FAILURES=('inputs','setup','ordinary_before','construct','admission','accesscheck','base_probe','mapping',
          'memory','payload','resume','trace','ordinary_after','cleanup','report','deadline')
CLEAN_KEYS=('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified',
    'parent_stdio_mapping_duplicate_closed','trace_view_unmapped','trace_mapping_closed','shim_file_closed',
    'target_file_closed','query_resources_closed','labels_restored','acl_removed','cleanup_tools','profile_deleted','sid_released')
OBS_BOOLS=('ordinary_before_positive','ordinary_after_positive','lpac_identity_verified',
    'private_memory_sequence_complete','payload_carrier_returned_nonnull','payload_readback_readonly_verified',
    'selected_resumed','trace_header_bound','trace_stable','trace_diagnostic_candidate_complete',
    'selected_natural_exit','selected_version_positive','startup_diagnostic_observed','observation_complete',*CLEAN_KEYS)
OBS_KEYS={'failure','selected_exit_code','trace_call_count',*OBS_BOOLS,*FALSE_CLAIMS}

def api_version():return 1
def stage_name(run):return 'local-lpac-curl-a4-loader-'+run
def work_cutoff(c):return c['root_deadline_qpc']-35*c['frequency']
def argv(c):return [c['curl_path'],'--disable','--version']
def artifact_paths(root):
    root=Path(root)
    return dict(shim=root/'package'/SHIM,carrier=root/'owner-inputs'/CARRIER,manifest=root/'owner-inputs'/MANIFEST)

def validate_artifact_pins(v):
    require(type(v) is dict and set(v)==set(ARTIFACT_KEYS),'a4_artifact_set')
    for key,pin in v.items():
        require(type(pin) is dict and set(pin)=={'bytes','sha256'} and live.integer(pin['bytes'],1,8*1024*1024)
                and base.ac.digest(pin['sha256']),'a4_artifact_pin')
    require(v==FROZEN_ARTIFACTS,'a4_exact_root_artifacts')
    return v

def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','profile',*NONCES,'start_qpc','frequency','root_deadline_qpc','deadline_qpc',
          'guard_job_name','source_hashes','source_sha256','device_sha256','recovery_plan_sha256','artifacts','curl_path'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1
        and c['scope']==SCOPE and c['profile']==PROFILE,'a4_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and len({c[k] for k in NONCES})==len(NONCES),'a4_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency']
        and c['deadline_qpc']==c['start_qpc']+115*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'a4_original_epoch')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names)
        and all(base.ac.digest(v) for v in c['source_hashes'].values())
        and sha(encode(c['source_hashes']))==c['source_sha256'],'a4_source_closure')
    require(all(base.ac.digest(c[k]) for k in ('source_sha256','device_sha256','recovery_plan_sha256')),'a4_config_digest')
    require(type(c['curl_path']) is str and Path(c['curl_path']).is_absolute()
        and Path(c['curl_path']).name.casefold()=='curl.exe','a4_curl_path')
    validate_artifact_pins(c['artifacts']);return c

def validate_plan(p,*,device,source,artifacts,curl_path):
    keys={'schema_version','scope','profile',*NONCES,'device_sha256','source_sha256','artifacts','curl_path','recovery_reference',*ACKS}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1
        and p['scope']==SCOPE and p['profile']==PROFILE,'a4_plan')
    require(all(base.ac.nonce(p[k]) for k in NONCES) and len({p[k] for k in NONCES})==len(NONCES),'a4_plan_nonces')
    require(p['device_sha256']==device and p['source_sha256']==source and p['artifacts']==artifacts
        and p['curl_path']==curl_path,'a4_plan_binding');validate_artifact_pins(artifacts)
    require(all(p[k] is True for k in ACKS) and type(p['recovery_reference']) is str
        and 400<=len(p['recovery_reference'])<=2048,'a4_plan_ack');return p

def verify_manifest(raw,artifacts,*,source_root):
    # Missing/incomplete actual root artifact manifest MUST stop. Caller hashes
    # alone never replace this closed source/artifact/ABI/signature agreement.
    v=decode(raw.removeprefix(b'\xef\xbb\xbf'))
    keys={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','shimSha256','carrierSha256',
          'shimSourceHashes','carrierSourceHashes','detoursCommit','detoursSourceHashes',
          'traceAbiSha256','carrierAbiSha256','signatureManifestSha256'}
    require(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1
        and v['compileOnly'] is True and v['runtimeAcceptance'] is False and type(v['interfaceVersion']) is int
        and v['interfaceVersion']==1,'a4_manifest_schema')
    require(v['shimSha256']==artifacts['shim']['sha256'] and v['carrierSha256']==artifacts['carrier']['sha256']
        and v['detoursCommit']=='1dbd4ea281d73d478aa8d09a8b83fbd265f715f7'
        and v['traceAbiSha256']==TRACE_ABI_SHA256 and v['carrierAbiSha256']==CARRIER_ABI_SHA256
        and v['signatureManifestSha256']==SIGNATURE_SHA256,'a4_manifest_binding')
    root=Path(source_root)
    for key,names in (('shimSourceHashes',NATIVE_SOURCES),('carrierSourceHashes',CARRIER_SOURCES),('detoursSourceHashes',VENDOR_SOURCES)):
        require(type(v[key]) is dict and set(v[key])==set(names),'a4_manifest_closed_sources')
        for name in names:
            require(v[key][name]==sha(local.bounded(launcher.checked_path(root/name,inside=root),256*1024)),'a4_manifest_source_pin')
    for name,expected in ((TRACE_ABI_MODULE,TRACE_ABI_SHA256),(CARRIER_ABI_MODULE,CARRIER_ABI_SHA256),(SIGNATURE_MODULE,SIGNATURE_SHA256)):
        require(sha(local.bounded(launcher.checked_path(root/name,inside=root),64*1024))==expected,'a4_metadata_pin')
    return v

def verify_input_artifacts(shim,carrier,manifest,curl_path,artifacts,*,root=ROOT):
    validate_artifact_pins(artifacts)
    paths=dict(shim=Path(shim),carrier=Path(carrier),manifest=Path(manifest),curl=Path(curl_path))
    for role,path in paths.items():
        raw=local.bounded(launcher.checked_path(path),8*1024*1024)
        require(len(raw)==artifacts[role]['bytes'] and sha(raw)==artifacts[role]['sha256'],'a4_artifact_bytes')
        if role!='manifest':mm.pe_shape(raw,dll=role!='curl')
    verify_manifest(local.bounded(paths['manifest'],128*1024),artifacts,source_root=root);return artifacts

def verify_artifacts(c,root):
    paths=artifact_paths(root)
    return verify_input_artifacts(paths['shim'],paths['carrier'],paths['manifest'],c['curl_path'],c['artifacts'],root=root)

def pack_config(c,row,window,trace_handle,shim_path,system_ws2):
    raw=bytearray(2048);struct.pack_into('<4sHH',raw,0,b'A4P1',1,2048)
    raw[8:24]=bytes.fromhex(c['run']);raw[24:56]=bytes.fromhex(c['source_sha256']);raw[56:88]=bytes.fromhex(sha(encode(c)))
    raw[88:120]=bytes.fromhex(CURL_SHA256);raw[120:152]=bytes.fromhex(c['artifacts']['shim']['sha256'])
    struct.pack_into('<6QIIQQ',raw,152,c['frequency'],c['start_qpc'],c['root_deadline_qpc'],work_cutoff(c),window['start'],window['end'],row['pid'],0,row['created'],trace_handle)
    path=str(shim_path).encode('ascii');system=str(system_ws2).encode('utf-16-le')
    require(0<len(path)<1024 and b'\0' not in path and len(system)%2==0 and 0<len(system)//2<260,'a4_config_paths')
    struct.pack_into('<4I',raw,224,TRACE_BYTES,256,len(path),len(system)//2)
    raw[240:256]=bytes.fromhex(c['trace_case']);raw[256:256+len(path)]=path;raw[1280:1280+len(system)]=system
    value=bytes(raw)
    # ABI03 JSON is separately source/manifest pinned; reader's closed schema
    # metadata additionally binds source08/primitive tables. They are not the
    # same JSON shape and must never be substituted for each other.
    trace_reader.validate_config(value,schema_metadata=trace_reader.SCHEMA_METADATA)
    return value

U32=C.c_uint32
verify_system_curl=mm.verify_system_curl
private_process_thread_sddl=mm.private_process_thread_sddl
curl_command_matches_system=mm.curl_command_matches_system
task_projection=mm.task_projection
GRANTS=mm.GRANTS
expected_acl=mm.expected_acl

class NativeAPI(mm.NativeAPI):
    """New A4 parent bindings, constructed only by the explicit ready worker.

    No CMM library is loaded/called. Raw new API returns and bounded outputs
    enter a local JSON-safe record before post-clock. Known ownership adoption
    also precedes post-clock; a failed receipt cannot erase cleanup authority.
    """
    def __init__(self):
        super().__init__();self.carrier=None;self.a4_calls=[]
        self._bind('VirtualAllocEx',[C.c_void_p,C.c_void_p,C.c_size_t,U32,U32],C.c_void_p)
        self._bind('VirtualQueryEx',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t],C.c_size_t)
        self._bind('ReadProcessMemory',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],C.c_int)
        self._bind('WriteProcessMemory',[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)],C.c_int)
        self._bind('VirtualProtectEx',[C.c_void_p,C.c_void_p,C.c_size_t,U32,C.POINTER(U32)],C.c_int)
        self.memory=memory.KernelMemory(self.k,C.get_last_error)
        self.nt=C.WinDLL('ntdll.dll',use_last_error=True,winmode=0x800)
        self.nt.NtQueryInformationProcess.argtypes=[C.c_void_p,U32,C.c_void_p,U32,C.POINTER(U32)]
        self.nt.NtQueryInformationProcess.restype=C.c_int32

    def _record(self,operation,arguments,invoke,outputs,*,budget,end,emit,adopt=None,known_close=False):
        # Normal admission leaves32 raw rows for <=5 simultaneously known
        # new-scope closers (section+dup+view+freshToken+mappingSD). Cleanup
        # consumes existing ownership; its reservation is never a normal gate.
        require(len(self.a4_calls)<(128 if known_close else 96),'a4_parent_call_capacity')
        before=None;admission_known=True
        try:before=budget.read();require(before<end,'a4_parent_call_cutoff')
        except BaseException:
            if not known_close:raise
            admission_known=False;self.controls_uncertain=True
        intent=None
        try:intent=emit.intent(operation,arguments,before)
        except BaseException:
            if not known_close:raise
            admission_known=False;self.controls_uncertain=True
        try:
            entered_tick=budget.read();require(entered_tick<end,'a4_parent_after_intent_cutoff');before=entered_tick
        except BaseException:
            if not known_close:raise
            admission_known=False;self.controls_uncertain=True
        row=dict(operation=operation,arguments=arguments,deadline_qpc=end,admission_known=admission_known,entered_qpc=before,entered=True,returned=False,
            raw_return=None,error=None,error_captured=False,native_exception=None,error_exception=None,
            outputs={},output_error=None,post_call_qpc=None,clock_known=False,timely=False,clock_error=None,
            intent_sha256=intent)
        try:
            value=invoke();row['returned']=True
            row['raw_return']=0 if value is None else value
            try:
                error=C.get_last_error();row['error_captured']=type(error) is int and 0<=error<=0xffffffff
                row['error']=error if row['error_captured'] else None
            except BaseException as exc:row['error_exception']=type(exc).__name__
        except BaseException as exc:row['native_exception']=type(exc).__name__
        raw=b''
        try:row['outputs'],raw=outputs()
        except BaseException as exc:row['output_error']=type(exc).__name__
        if not row['returned'] or row['output_error'] is not None or not row['error_captured']:
            # Entered resource/view allocation or close may have effects even
            # without a returned value. A later successful SD free is unrelated.
            self.controls_uncertain=True
        require(type(raw) is bytes,'a4_parent_output_type')
        row['output_bytes']=len(raw);row['output_sha256']=sha(raw)
        # No QPC or user persistence callback before these owned physical facts.
        sealed=decode(encode(row));self.a4_calls.append(sealed)
        if adopt is not None:
            try:adopt(sealed)
            except BaseException:
                self.controls_uncertain=True
                # Adoption failure never authorizes closing an ambiguous value.
                sealed['adoption_failed']=True
        try:
            tick=budget.read();sealed['post_call_qpc']=tick;sealed['clock_known']=True
            sealed['timely']=admission_known and before is not None and before<=tick<end
        except BaseException as exc:
            sealed['clock_error']=type(exc).__name__;self.controls_uncertain=True
        try:emit(sealed,raw)
        except BaseException:self.controls_uncertain=True;raise
        if (not sealed['returned'] or not sealed['error_captured'] or sealed['native_exception'] is not None
                or sealed['output_error'] is not None or sealed.get('adoption_failed')
                or not sealed['clock_known'] or not sealed['timely']):
            raise ValueError('a4_parent_raw_or_clock')
        return sealed

    def a4_close(self,h,*,budget,end,emit):
        # Caller ledger consumes the known handle before reaching this method.
        row=self._record('CloseHandle',dict(handle=h),lambda:self.k.CloseHandle(C.c_void_p(h)),lambda:({},b''),
            budget=budget,end=end,emit=emit,known_close=True)
        require(type(row['raw_return']) is int and row['raw_return']!=0,'a4_known_handle_close')

    def a4_flags(self,h,*,budget,end,emit):
        value=U32();f=self._bind('GetHandleInformation',[C.c_void_p,C.POINTER(U32)],C.c_int)
        row=self._record('GetHandleInformation',dict(handle=h),lambda:f(h,C.byref(value)),
            lambda:(dict(flags=value.value),b''),budget=budget,end=end,emit=emit)
        require(row['raw_return']!=0,'a4_handle_flags_return');return value.value

    def mapping(self,ledger,other,*,budget,end,emit):
        # Fresh anonymous pagefile section; private parent/SY descriptor, no name
        # or global object. Child rights2 create an actually read/write view.
        try:sd=local.LocalNativeAPI.private_descriptor(self.native,other['parent_sid'],job=True)
        except BaseException:self.controls_uncertain=True;raise
        try:
            sa=launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes),sd,False)
            f=self._bind('CreateFileMappingW',[C.c_void_p,C.c_void_p,U32,U32,U32,C.c_wchar_p],C.c_void_p)
            def adopt(row):
                if row['returned'] and type(row['raw_return']) is int and row['raw_return']:
                    self._adopt(row['raw_return'],ledger,other['handles'])
            row=self._record('CreateFileMappingW',dict(bytes=TRACE_BYTES,protection=4,named=False),
                lambda:f(C.c_void_p(-1),C.byref(sa),4,0,TRACE_BYTES,None),lambda:({},b''),
                budget=budget,end=end,emit=emit,adopt=adopt)
            h=row['raw_return'];require(type(h) is int and h>0 and h!=0xffffffffffffffff,'a4_mapping_return')
            require(self.a4_flags(h,budget=budget,end=end,emit=emit)==0,'a4_mapping_noninherit');return h
        finally:
            row=self._record('LocalFree(mapping_SD)',dict(pointer=int(sd)),lambda:self.k.LocalFree(sd),lambda:({},b''),
                budget=budget,end=end,emit=emit,known_close=True)
            if row['raw_return']!=0:self.controls_uncertain=True;raise ValueError('a4_mapping_SD_close')

    def mapping_duplicate(self,h,ledger,other,*,budget,end,emit):
        value=C.c_void_p();f=self._bind('DuplicateHandle',[C.c_void_p,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p),U32,C.c_int,U32],C.c_int)
        def adopt(row):
            if row['returned'] and type(row['raw_return']) is int and row['raw_return']!=0:
                self._adopt(int(value.value or 0),ledger,other)
            elif value.value:self.controls_uncertain=True
        row=self._record('DuplicateHandle(trace_write)',dict(source=h,desired_access=2,inherited=True,options=0),
            lambda:f(self.k.GetCurrentProcess(),h,self.k.GetCurrentProcess(),C.byref(value),2,True,0),
            lambda:(dict(handle=int(value.value or 0)),b''),budget=budget,end=end,emit=emit,adopt=adopt)
        require(row['raw_return']!=0 and value.value and self.a4_flags(value.value,budget=budget,end=end,emit=emit)==1,'a4_mapping_duplicate')
        return int(value.value)

    def map_read(self,h,*,budget,end,emit,adopt):
        f=self._bind('MapViewOfFile',[C.c_void_p,U32,U32,U32,C.c_size_t],C.c_void_p)
        row=self._record('MapViewOfFile(parent_read)',dict(handle=h,access=4,bytes=TRACE_BYTES),
            lambda:f(h,4,0,0,TRACE_BYTES),lambda:({},b''),budget=budget,end=end,emit=emit,
            adopt=lambda r:adopt(r['raw_return']) if r['returned'] and type(r['raw_return']) is int and r['raw_return'] else None)
        require(type(row['raw_return']) is int and 0x10000<=row['raw_return']<(1<<47)-TRACE_BYTES,'a4_mapping_view')
        return row['raw_return']

    def unmap(self,p,*,budget,end,emit):
        f=self._bind('UnmapViewOfFile',[C.c_void_p],C.c_int)
        row=self._record('UnmapViewOfFile(parent)',dict(view=p),lambda:f(C.c_void_p(p)),lambda:({},b''),
            budget=budget,end=end,emit=emit,known_close=True)
        require(row['raw_return']!=0,'a4_unmap_return')

    def current_primary(self,process,ledger,other,*,budget,end,emit):
        token=C.c_void_p();f=self.a.OpenProcessToken;f.argtypes=[C.c_void_p,U32,C.POINTER(C.c_void_p)];f.restype=C.c_int
        def adopt(row):
            if row['returned'] and type(row['raw_return']) is int and row['raw_return']!=0:self._adopt(int(token.value or 0),ledger,other)
            elif token.value:self.controls_uncertain=True
        row=self._record('OpenProcessToken(current-primary)',dict(process=process,access=8),
            lambda:f(process,8,C.byref(token)),lambda:(dict(handle=int(token.value or 0)),b''),
            budget=budget,end=end,emit=emit,adopt=adopt)
        require(row['raw_return']!=0 and token.value,'a4_current_token');return int(token.value)

    def pbi(self,process,pid,*,budget,end,emit):
        raw=(C.c_ubyte*48)();length=U32()
        row=self._record('NtQueryInformationProcess(PBI48)',dict(process=process,information_class=0,bytes=48),
            lambda:self.nt.NtQueryInformationProcess(process,0,raw,48,C.byref(length)),
            lambda:(dict(returned_length=length.value),bytes(raw)),budget=budget,end=end,emit=emit)
        value=bytes(raw);require(row['raw_return']==0 and length.value==48 and struct.unpack_from('<Q',value,32)[0]==pid,'a4_PBI48')
        pointer=struct.unpack_from('<Q',value,8)[0]
        require(0x10000<=pointer<(1<<47)-32,'a4_PEB_address');return pointer

    def load_carrier(self,path):
        require(self.carrier is None,'a4_carrier_once')
        lib=C.WinDLL(str(path),use_last_error=True,winmode=0x900)
        lib.a4_payload_abi_v1.argtypes=[];lib.a4_payload_abi_v1.restype=U32
        lib.a4_copy_config_v1.argtypes=[C.c_void_p,C.c_void_p,U32,C.c_void_p];lib.a4_copy_config_v1.restype=U32
        require(lib.a4_payload_abi_v1()==1,'a4_carrier_ABI');self.carrier=lib

    def copy_config(self,process,raw,*,budget,end,emit):
        require(self.carrier is not None and type(raw) is bytes and len(raw)==2048,'a4_carrier_input')
        source=C.create_string_buffer(raw);storage=(C.c_uint64*4)()
        row=self._record('a4_copy_config_v1',dict(process=process,config_sha256=sha(raw),bytes=2048),
            lambda:self.carrier.a4_copy_config_v1(process,source,2048,storage),
            lambda:({},bytes(storage)),budget=budget,end=end,emit=emit)
        result=bytes(storage);size,version,flags,error,pointer,seh,reserved=struct.unpack('<4IQ2I',result)
        require(row['raw_return']==0 and size==32 and version==1 and flags==3 and error==0 and seh==0 and reserved==0
            and 0x10000+456<=pointer<(1<<47)-2048,'a4_carrier_return')
        return pointer

    def create_curl(self,info,command,cwd,environment,job,owners,state,*,handles,stdio,profile_pointer,parent_sid,budget,end,on_return,other_owned=()):
        selected=profile_pointer is not None;expected_handles=4 if selected else 3
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

API=NativeAPI

def binary_record(root,name,raw):
    require(type(raw) is bytes and re.fullmatch('[a-z0-9-]+\\.bin',name),'a4_binary_name')
    base.durable_private(Path(root)/name,raw);return dict(name=name,bytes=len(raw),sha256=sha(raw))

def read_binary(root,d,limit):
    require(type(d) is dict and set(d)=={'name','bytes','sha256'} and type(d['name']) is str
        and re.fullmatch('[a-z0-9-]+\\.bin',d['name']) and live.integer(d['bytes'],0,limit)
        and base.ac.digest(d['sha256']),'a4_binary_descriptor')
    raw=local.bounded(launcher.checked_path(Path(root)/d['name'],inside=root),limit)
    require(len(raw)==d['bytes'] and sha(raw)==d['sha256'],'a4_binary_physical');return raw

class Owner(cell.CellOwner):
    # Reuse only scope-free utility methods. CMM run/operation/prepare_native/
    # resume_observe/result predicates and marker/event APIs are never invoked.
    scope_acl=mm.Owner.scope_acl
    task=mm.Owner.task
    tool=mm.Owner.tool
    new_row=mm.Owner.new_row
    setup_profile=mm.Owner.setup_profile
    wait_curl=mm.Owner.wait_curl
    semantic=mm.Owner.semantic

    def __init__(self,root,c,parent,api,budget):
        self.root,self.c,self.parent,self.api,self.budget=Path(root),c,parent,api,budget
        self.owners=helpers.OneShotHandles(api.close);self.resources=helpers.OneShotHandles(api.close)
        self.job=None;self.children=[];self.tasks={};self.catalog={};self.phase='setup';self.stdio_ledgers=[]
        self.profile=dict(attempted=False,returned=False,created=False,pointer=None,sid=None);self.selected_environment=None
        self.mapping_handle=None;self.child_mapping=None;self.child_mapping_number=None;self.view=None;self.view_consumed=False
        self.target_handle=self.shim_handle=None;self.target_fact=self.shim_fact=None
        self.window=None;self.config_bytes=None;self.remote_memory_unknown=False;self.query_ledgers=[];self.image_bytes=None;self.system_ws2=None
        self.mapping_owners=helpers.OneShotHandles(lambda h:api.a4_close(h,budget=budget,end=budget.cutoff(3),emit=self))
        self.mapping_duplicates=helpers.OneShotHandles(lambda h:api.a4_close(h,budget=budget,end=budget.cutoff(3),emit=self))
        for name in ('api-calls','memory','payload'):(self.root/name).mkdir()
        self.j=dict(schema_version=1,stage='lpac-curl-a4-loader-result',scope=SCOPE,profile=PROFILE,config_sha256=sha(encode(c)),
            failure=None,failure_detail=None,profile_name='ruleproxy-curl-a4-loader-'+c['run'],profile_sid=None,
            profile_state=dict(attempted=False,returned=False,created=False,sid_pointer_returned=False),
            child_environment=launcher.default_child_environment(),intents=[],returns=[],proofs=[],tasks=[],cleanup_tasks=[],
            labels=[],window=None,api_intents=[],api_calls=[],api_raw_calls=self.api.a4_calls,memory_records=[],memory_summary=None,
            base_provenance=None,payload=None,config_binary=None,trace_binary=None,trace_review=None,
            mapping=None,target_lease=None,shim_lease=None,lease_checks=[],controls=dict(before=None,after=None),
            selected_output=None,resume_observation=None,profile_created=False,acl_attempted=False,creation_unknown=False,controls_uncertain=False,completed_qpc=None,
            selected_stop_attempted=False,selected_exit_confirmed=False,remote_memory_unknown=False,
            token_class46_queried=False,endpoint_created=False,dns_api_called=False,
            **dict.fromkeys(CLEAN_KEYS,False),**dict.fromkeys(FALSE_CLAIMS,False))
        self.j.update(observer_resources_cleanup_verified=True,parent_stdio_mapping_duplicate_closed=True,
            trace_view_unmapped=True,trace_mapping_closed=True,shim_file_closed=True,target_file_closed=True,
            query_resources_closed=True,labels_restored=True)

    def journal(self,label):
        require(re.fullmatch('[a-z0-9-]{1,64}',label) and len(self.j['intents'])<256,'a4_intent')
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read(),action=label))
        name='%03d-%s.json'%(len(self.j['intents']),label);base.durable_private(self.root/'journal'/name,raw)
        row=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw));self.j['intents'].append(row);return row

    def returned(self,label,intent,data):
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            intent_sha256=intent['sha256'],action=label,qpc=self.budget.read(),data=data))
        name='%03d-%s.json'%(len(self.j['returns']),label);base.durable_private(self.root/'returns'/name,raw)
        row=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw));self.j['returns'].append(row);return row

    def intent(self,operation,arguments,qpc):
        require(len(self.j['api_intents'])<128,'a4_API_intent_capacity')
        row=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            index=len(self.j['api_intents']),operation=operation,arguments=arguments,qpc=qpc)
        raw=encode(row);name='%03d-intent.json'%row['index'];base.durable_private(self.root/'api-calls'/name,raw)
        self.j['api_intents'].append(dict(name=name,text=raw.decode('ascii'),sha256=sha(raw)));return sha(raw)

    def __call__(self,row,raw):
        require(len(self.j['api_calls'])<128,'a4_API_return_capacity')
        index=len(self.j['api_calls']);name='%03d-return.json'%index;data_name='api-%03d.bin'%index
        descriptor=binary_record(self.root,data_name,raw)
        record=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            index=index,call=decode(encode(row)),output=descriptor)
        text=encode(record);base.durable_private(self.root/'api-calls'/name,text)
        self.j['api_calls'].append(dict(name=name,text=text.decode('ascii'),sha256=sha(text)))

    def memory_journal(self,record,raw):
        index=len(self.j['memory_records']);require(index<128,'a4_memory_records')
        descriptor=binary_record(self.root,'memory-%03d.bin'%index,raw)
        value=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),
            index=index,record=record,output=descriptor)
        text=encode(value);name='%03d.json'%index;base.durable_private(self.root/'memory'/name,text)
        self.j['memory_records'].append(dict(name=name,text=text.decode('ascii'),sha256=sha(text)));return sha(text)

    def held(self,row,end):
        self.budget.require_ms(end);h=row['info'].hProcess
        require(row['pid']==self.api.process_id(h) and row['created']==self.api.creation_time(h) and not self.api.wait(h,0),'a4_held_generation')
        self.api.verify_job(self.job,h);self.api.verify_outer(self.c['guard_job_name'],h);self.api.verify_image(h,Path(self.c['curl_path']))
        # Query current primary from the retained process afresh. Old borrowed
        # row.token is only the admitted expected object, never current proof.
        temporary=helpers.OneShotHandles(lambda value:self.api.a4_close(value,budget=self.budget,end=end,emit=self))
        self.query_ledgers.append(temporary)
        self.j['query_resources_closed']=False
        try:
            token=self.api.current_primary(h,temporary,set(self.owners.pending)|set(self.resources.pending)|set(self.mapping_owners.pending)|set(self.mapping_duplicates.pending),budget=self.budget,end=end,emit=self)
            current=zero.capture_primary(self.api,token,self.parent,self.profile['sid'],self.budget,end,row['lpac_expected'])
            require(current==row['expected_primary'],'a4_current_primary_changed')
        finally:
            for value in tuple(temporary.pending):
                try:temporary.close(value)
                except BaseException:self.api.controls_uncertain=True
            self.j['query_resources_closed']=all(x.confirmed_closed for x in self.query_ledgers)
        require(self.j['query_resources_closed'],'a4_current_primary_close')
        security=dict(process=self.api.kernel_sddl(h),thread=self.api.kernel_sddl(row['info'].hThread))
        require(all(private_process_thread_sddl(v,self.parent['sid']) for v in security.values()) and security==row['kernel_security'],'a4_kernel_SD_changed')
        if row['lpac_expected']:
            for handle,fact in ((self.target_handle,self.target_fact),(self.shim_handle,self.shim_fact)):
                require(handle and self.api.handle_flags(handle)==0 and self.api.file_fact(handle,self.budget,end)==fact,'a4_hot_lease_changed')
        row['held_checks'].append(dict(qpc=self.budget.read(),pid=row['pid'],created=row['created'],image_sha256=CURL_SHA256,
            primary=current,inner_job=True,outer_job=True,kernel_security=security));self.budget.require_ms(end)

    def output(self,row):
        require(row['exited'] and row['parent_copies_closed'],'a4_output_closed')
        directory=self.root/('selected-output' if row['lpac_expected'] else 'ordinary-'+row['name'])
        stdout=local.bounded(directory/'stdout',MAX_OUTPUT);stderr=local.bounded(directory/'stderr',MAX_OUTPUT)
        return dict(stdout_bytes=len(stdout),stdout_sha256=sha(stdout),stderr_bytes=len(stderr),stderr_sha256=sha(stderr),
            exact_baseline=len(stdout)==BASELINE_BYTES and sha(stdout)==BASELINE_SHA256 and not stderr)

    def control(self,name):
        end=min(self.budget.read()+8*self.c['frequency'],work_cutoff(self.c));row=self.spawn(name,end)
        self.resume_curl(row,end);self.wait_curl(row,end);output=self.output(row)
        value=dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),parent_sha256=sha(encode(self.parent)),
            role=name,case=self.c[name+'_case'],deadline_qpc=end,task=task_projection(row),output=output,
            positive=row['natural_exit'] and row['exit_code']==0 and output['exact_baseline'])
        raw=encode(value);base.durable_private(self.root/('control-'+name+'.json'),raw)
        self.j['controls'][name]=dict(text=raw.decode('ascii'),sha256=sha(raw));require(value['positive'],'a4_ordinary_'+name);return True

    resume_curl=mm.Owner.resume_curl

    def spawn(self,name,end,selected=False):
        require(name in ('before','selected','after') and selected==(name=='selected') and name not in self.tasks,'a4_spawn_role_once')
        info=self.api.process_info();row=self.new_row(name,info,CURL_SHA256,selected,end);self.children.append(row);self.tasks[name]=row
        intent=self.journal('create-'+name);state=dict(creation_attempted=False,creation_unknown=False)
        stdio=helpers.OneShotHandles(self.api.close);self.stdio_ledgers.append(stdio);handles=[]
        directory=self.root/('selected-output' if selected else 'ordinary-'+name)
        try:
            for kind in ('stdin','stdout','stderr'):
                h=self.api.open_stdio_file(directory/kind,read=kind=='stdin')
                other=set(self.owners.pending)|set(self.resources.pending)|set(self.mapping_owners.pending)|set(self.mapping_duplicates.pending)|set(stdio.pending)
                if not(type(h) is int and 0<h<0xffffffffffffffff and h not in other):
                    self.api.controls_uncertain=True;raise ValueError('a4_stdio_alias')
                stdio.add(h);handles.append(h)
            inherited=([self.child_mapping_number,*handles] if selected else handles)
            row['inherited_handles']=list(inherited);self.j['parent_stdio_mapping_duplicate_closed']=False
            def raw_return(s):row['receipt']=self.returned('create-'+name,intent,s)
            try:
                self.api.create_curl(info,argv(self.c),self.root/'package' if selected else directory,
                    self.selected_environment if selected else self.api.native.environment(directory),self.job,self.owners,state,
                    handles=inherited,stdio=handles,profile_pointer=self.profile['pointer'] if selected else None,
                    parent_sid=self.parent['sid'],budget=self.budget,end=end,on_return=raw_return,
                    other_owned=set(self.resources.pending)|set(self.mapping_owners.pending)|set(self.mapping_duplicates.pending))
            finally:
                row.update(attempted=state.get('creation_attempted',False),process_returned=bool(info.hProcess),pid=int(info.dwProcessId) or None)
                row['constructor_return_qpc']=self.budget.read();v=state.get('raw_pi',[0,0,0,0])
                row['create_observation']=dict(status=state.get('create_status','not_entered'),winerror=state.get('raw_error'),
                    process_information='nonzero' if any(v) else 'all_zero',returned_qpc=state.get('returned_qpc'),work_cutoff=end,exception_detail=None)
                if row['receipt'] is None:row['receipt']=self.returned('create-'+name,intent,state)
                if state.get('creation_unknown',False):self.j['creation_unknown']=True;self.api.controls_uncertain=True
        finally:
            ledgers=[stdio,self.mapping_duplicates] if selected else [stdio]
            for ledger in ledgers:
                for h in tuple(ledger.pending):
                    try:ledger.close(h)
                    except BaseException:self.api.controls_uncertain=True
            row['parent_copies_closed']=all(x.confirmed_closed for x in ledgers)
            self.j['parent_stdio_mapping_duplicate_closed']=all(x.confirmed_closed for x in [*self.stdio_ledgers,self.mapping_duplicates])
        require(row['parent_copies_closed'] and info.hProcess and info.hThread and row['pid'],'a4_owned_child')
        self.budget.require_ms(end);row['created']=self.api.creation_time(info.hProcess)
        self.api.verify_job(self.job,info.hProcess);row['assigned']=True
        self.api.verify_outer(self.c['guard_job_name'],info.hProcess);self.api.verify_image(info.hProcess,Path(self.c['curl_path']))
        row['token']=self.api.token_for_process(info.hProcess);self.owners.add(row['token']);row['identity']=self.api.identity(row['token'])
        row['capabilities']=[];row['expected_primary']=zero.capture_primary(self.api,row['token'],self.parent,self.profile['sid'],self.budget,end,selected)
        row['kernel_security']=dict(process=self.api.kernel_sddl(info.hProcess),thread=self.api.kernel_sddl(info.hThread))
        require(all(private_process_thread_sddl(v,self.parent['sid']) for v in row['kernel_security'].values()),'a4_process_thread_SD')
        self.held(row,end);row['admission_qpc']=self.budget.read();self.budget.require_ms(end);row['admitted']=True;return row

    def lease_check(self,phase,end):
        require(phase in ('before','after'),'a4_lease_phase');intent=self.journal('lease-'+phase);facts={}
        for name,h,fact,path in (('target',self.target_handle,self.target_fact,Path(self.c['curl_path'])),
                                ('shim',self.shim_handle,self.shim_fact,artifact_paths(self.root)['shim'])):
            pin=self.c['artifacts']['curl' if name=='target' else 'shim']
            require(self.api.handle_flags(h)==0 and self.api.file_fact(h,self.budget,end)==fact,'a4_lease_identity')
            require(self.api.held_file_hash(h,pin['bytes'],self.budget,end)==pin['sha256'],'a4_lease_held_hash')
            raw=local.bounded(path,8*1024*1024)
            require(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'a4_lease_disk_hash')
            facts[name]=dict(file_identity=fact,bytes=len(raw),sha256=sha(raw))
        receipt=self.returned('lease-'+phase,intent,facts);self.j['lease_checks'].append(receipt);return receipt

    def remote_call(self,row,operation,address,size,argument=0):
        # This is a new parent probe/carrier check, not a second import-rewrite
        # coordinator. Raw is immutable before any clock or persistence call.
        end=self.window['end'];before=self.budget.read();require(before<end,'a4_remote_cutoff')
        arguments=dict(process=int(row['info'].hProcess),address=address,bytes=size)
        if type(argument) is bytes:arguments['input_sha256']=sha(argument)
        else:arguments['argument']=argument
        intent=self.memory_journal(dict(kind='a4-probe-intent',operation=operation,arguments=arguments,qpc=before),b'')
        entered=self.budget.read();require(before<=entered<end,'a4_remote_after_intent')
        raw=self.api.memory.invoke(operation,int(row['info'].hProcess),address,size,argument)
        require(type(raw) is memory.Raw,'a4_remote_adapter')
        # Preserve the complete physical Raw before sampling the post-clock.
        value=dict(kind='a4-probe-return',operation=operation,arguments=arguments,intent_sha256=intent,
            entered_qpc=entered,raw=raw.record(),returned_qpc=None,return_clock_known=False,timely=False,clock_error=None)
        try:
            tick=self.budget.read();value.update(returned_qpc=tick,return_clock_known=True,timely=entered<=tick<end)
        except BaseException as exc:value['clock_error']=type(exc).__name__
        reference=self.memory_journal(value,raw.data)
        require(raw.returned and raw.exception is None and raw.error_captured and value['return_clock_known'] and value['timely'],'a4_remote_unknown_or_clock')
        if operation=='query':require(raw.value==48 and len(raw.data)==48,'a4_remote_query_size')
        elif operation in ('read','write'):require(raw.value!=0 and raw.field('transferred')==size,'a4_remote_transfer')
        elif operation=='protect':require(raw.value!=0,'a4_remote_protection')
        return raw,reference

    def base_probe(self,row):
        intent=self.journal('base-probe');self.held(row,self.window['end'])
        peb=self.api.pbi(row['info'].hProcess,row['pid'],budget=self.budget,end=self.window['end'],emit=self)
        raw,peb_ref=self.remote_call(row,'read',peb,32);actual=struct.unpack_from('<Q',raw.data,16)[0]
        require(actual>=0x10000 and actual%65536==0 and actual<(1<<47)-builder.SIZE_IMAGE,'a4_image_base')
        raw,query_ref=self.remote_call(row,'query',actual,48);region=dict(raw.fields)
        require(memory.Coordinator._covers(region,actual,4096) and region['allocation_base']==actual
            and region['state']==0x1000 and region['type']==0x1000000 and region['protect']==2,'a4_base_image_region')
        raw,header_ref=self.remote_call(row,'read',actual,builder.SIZE_HEADERS)
        image=self.image_bytes;require(type(image) is bytes,'a4_retained_source_bytes');pe=builder.verify_fixed_pe(image)
        require(raw.data==pe.header,'a4_base_header');self.held(row,self.window['end'])
        receipt=self.returned('base-probe',intent,dict(information_class=0,pbi_bytes=48,peb_probe_bytes=32,
            peb_layout='local-amd64-internal-offset16-not-public-stable',peb=peb,actual_base=actual,
            peb_return_sha256=peb_ref,query_return_sha256=query_ref,header_return_sha256=header_ref,
            pid=row['pid'],created=row['created'],header_sha256=sha(pe.header)))
        self.j['base_provenance']=receipt;return actual,image

    def memory_sequence(self,row,actual,image):
        intent=self.journal('memory-sequence')
        epoch=memory.Epoch(self.c['frequency'],self.c['start_qpc'],self.c['root_deadline_qpc'],work_cutoff(self.c),self.window['start'],self.window['end'])
        bindings=memory.Bindings(self.c['run'],self.c['source_sha256'],sha(encode(self.c)),self.c['recovery_plan_sha256'],
            row['receipt']['sha256'],self.j['base_provenance']['sha256'])
        def gate(label,epoch_value,binding_value):
            require(epoch_value==epoch and binding_value==bindings,'a4_memory_gate_inputs')
            held_intent=self.journal('memory-held-'+label);self.held(row,self.window['end'])
            return self.returned('memory-held-'+label,held_intent,row['held_checks'][-1])['sha256']
        outcome=memory.Coordinator(self.api.memory,int(row['info'].hProcess),image,actual,str(artifact_paths(self.root)['shim']),
            epoch,bindings,clock=self.budget.read,gate=gate,journal=self.memory_journal).run()
        data={k:getattr(outcome,k) for k in ('status','failure','mutation_intent_sha256','mutation_attempted','allocation_state',
            'memory_bytes_match','memory_sequence_complete','controls_unknown','actual_base','arena_address','remote_lifetime',
            'actual_ready','resume_authorized','config_GUID_injection_complete','external_identity_gates_verified_by_this_module','actual_loader_or_transport_qualified')}
        data.update(call_count=len(outcome.calls),gates=[list(x) for x in outcome.gates],epoch=dict(epoch.__dict__),bindings=dict(bindings.__dict__))
        self.remote_memory_unknown=outcome.controls_unknown;self.j['remote_memory_unknown']=outcome.controls_unknown
        self.j['memory_summary']=self.returned('memory-sequence',intent,data)
        require(outcome.memory_sequence_complete and outcome.memory_bytes_match and not outcome.controls_unknown,'a4_memory_stopped')

    def payload(self,row):
        intent=self.journal('config-carrier');end=self.window['end'];self.held(row,end)
        self.api.load_carrier(artifact_paths(self.root)['carrier'])
        config=pack_config(self.c,row,self.window,self.child_mapping_number,artifact_paths(self.root)['shim'],self.system_ws2)
        self.config_bytes=config;self.j['config_binary']=binary_record(self.root,'a4-config.bin',config)
        # Entered carrier can leave remote state even when NULL/SEH/partial.
        # No rollback/free or retry is attempted; exact target exit bounds it.
        pointer=self.api.copy_config(row['info'].hProcess,config,budget=self.budget,end=end,emit=self)
        base_address=pointer-456;require(base_address%4096==0,'a4_payload_allocation_alignment')
        expected=payload_framing(config);raw,first_ref=self.remote_call(row,'read',base_address,len(expected))
        require(raw.data==expected,'a4_payload_exact_framing')
        raw,query_ref=self.remote_call(row,'query',base_address,48);region=dict(raw.fields)
        require(region['base']==base_address and region['allocation_base']==base_address
            and memory.Coordinator._covers(region,base_address,4096) and region['state']==0x1000 and region['type']==0x20000
            and region['allocation_protect']==4 and region['protect']==4,'a4_payload_RW_allocation')
        raw,protect_ref=self.remote_call(row,'protect',base_address,4096,2);require(raw.field('old_protect')==4,'a4_payload_old_protect')
        raw,ro_ref=self.remote_call(row,'query',base_address,48);region=dict(raw.fields)
        require(region['base']==base_address and region['allocation_base']==base_address and memory.Coordinator._covers(region,base_address,4096)
            and region['state']==0x1000 and region['type']==0x20000 and region['protect']==2,'a4_payload_RO_query')
        raw,last_ref=self.remote_call(row,'read',base_address,len(expected));require(raw.data==expected,'a4_payload_RO_readback')
        self.held(row,end)
        self.j['payload']=self.returned('config-carrier',intent,dict(pointer=pointer,allocation_base=base_address,framing_bytes=len(expected),
            config_sha256=sha(config),framing_sha256=sha(expected),first_read_sha256=first_ref,query_sha256=query_ref,
            protect_sha256=protect_ref,readonly_query_sha256=ro_ref,readonly_read_sha256=last_ref,readonly_verified=True))

    def trace_after_exit(self,row):
        require(row['exited'] and row['natural_exit'] and self.view is not None and not self.view_consumed,'a4_trace_exact_exit')
        intent=self.journal('trace-after-exit');end=self.window['end'];before=self.budget.read();require(before<end,'a4_trace_cutoff')
        first=C.string_at(self.view,TRACE_BYTES);second=C.string_at(self.view,TRACE_BYTES);after=self.budget.read()
        require(len(first)==TRACE_BYTES and first==second and before<=after<end,'a4_trace_stability')
        self.j['trace_binary']=binary_record(self.root,'a4-trace.bin',first)
        # The physical parent epoch and Config are separately bound. Decoder's
        # fixed inner false claims are never overwritten by these owner facts.
        review=trace_reader.review(first,expected_config2048=self.config_bytes,schema_metadata=trace_reader.SCHEMA_METADATA)
        self.j['trace_review']=self.returned('trace-after-exit',intent,dict(before_qpc=before,after_qpc=after,
            trace_sha256=sha(first),config_sha256=sha(self.config_bytes),stable=True,review=review))
        return review

    def selected_run(self,row):
        end=self.window['end'];self.phase='base_probe';actual,image=self.base_probe(row)
        self.phase='memory';self.memory_sequence(row,actual,image)
        self.phase='payload';self.payload(row)
        self.phase='accesscheck';self.semantic(row,'before-resume',end)
        self.phase='resume';intent=self.journal('resume-selected');row['resume_intent_qpc']=decode(intent['text'].encode('ascii'))['qpc']
        self.held(row,end);self.budget.require_ms(end)
        fact=dict(entered=True,returned=False,count=None,error=None,returned_qpc=None,clock_error=False,exception=False)
        try:
            count,error=self.api.resume_raw(row['info'].hThread);fact.update(returned=True,count=count,error=error)
            if count==1 and error is None:row['resumed']=True
            try:fact['returned_qpc']=self.budget.read();row['resume_qpc']=fact['returned_qpc']
            except BaseException:fact['clock_error']=True;self.api.controls_uncertain=True;raise
            require(type(count) is int and count==1 and error is None and row['resume_intent_qpc']<=fact['returned_qpc']<end,'a4_resume_once')
        except BaseException:
            if not fact['returned']:fact['exception']=True;self.api.controls_uncertain=True
            raise
        finally:self.j['resume_observation']=self.returned('resume-selected',intent,fact)
        self.phase='trace';self.wait_curl(row,end);self.j['selected_exit_confirmed']=True
        self.j['selected_output']=self.output(row);review=self.trace_after_exit(row);self.lease_check('after',end)
        require(review['diagnostic_candidate_complete'] and row['exit_code']==0 and self.j['selected_output']['exact_baseline'],'a4_trace_or_version_inconclusive')

    def stop_selected(self):
        row=self.tasks.get('selected')
        if row is None or not row['info'].hProcess:return
        if not row['exited']:
            self.journal('stop-selected');self.j['selected_stop_attempted']=True
            if not self.api.wait(row['info'].hProcess,0):self.api.terminate_process(row['info'].hProcess)
            row['exited']=self.api.wait(row['info'].hProcess,self.budget.require_ms(self.budget.cutoff(12))) is True
            if row['exited']:row['exit_code']=self.api.exit_code(row['info'].hProcess);row['exit_observed_qpc']=self.budget.read()
        self.j['selected_exit_confirmed']=row['exited']

    def run(self):
        try:
            verify_artifacts(self.c,self.root);verify_system_curl(self.api,self.c['curl_path']);base.owned_tree(self.root)
            self.job=self.api.owned_job(self.owners);self.phase='ordinary_before';self.control('before')
            self.phase='setup';self.setup_profile();end=work_cutoff(self.c)
            for role,path in (('target',Path(self.c['curl_path'])),('shim',artifact_paths(self.root)['shim'])):
                intent=self.journal(role+'-lease');h,fact=self.api.open_marker(path,self.resources,
                    set(self.owners.pending)|set(self.mapping_owners.pending),self.budget,end)
                setattr(self,role+'_handle',h);setattr(self,role+'_fact',fact);self.j[role+'_file_closed']=False
                self.j[role+'_lease']=self.returned(role+'-lease',intent,dict(handle=h,file_identity=fact))
            self.lease_check('before',end)
            # Freeze source bytes/SystemDirectory-derived canonical name before
            # the short mutation window. Hot held gates use retained leases;
            # they never reopen or hash a pathname between the two lease checks.
            self.image_bytes=local.bounded(Path(self.c['curl_path']),8*1024*1024);builder.verify_fixed_pe(self.image_bytes)
            canonical_ws2=self.api.system_curl().parent/'WS2_32.dll'
            self.system_ws2=Path(self.c['curl_path']).parent/'WS2_32.dll'
            require(str(canonical_ws2).casefold()==str(self.system_ws2).casefold(),'a4_system_directory_spelling')
            self.phase='mapping'
            self.mapping_handle=self.api.mapping(self.mapping_owners,dict(parent_sid=self.parent['sid'],handles=set(self.owners.pending)|set(self.resources.pending)),
                budget=self.budget,end=end,emit=self);self.j['trace_mapping_closed']=False
            self.child_mapping_number=self.api.mapping_duplicate(self.mapping_handle,self.mapping_duplicates,
                set(self.owners.pending)|set(self.resources.pending)|set(self.mapping_owners.pending),budget=self.budget,end=end,emit=self)
            self.j['parent_stdio_mapping_duplicate_closed']=False
            def adopt_view(value):
                require(self.view is None and type(value) is int and 0x10000<=value<(1<<47)-TRACE_BYTES,'a4_view_once');self.view=value;self.j['trace_view_unmapped']=False
            self.api.map_read(self.mapping_handle,budget=self.budget,end=end,emit=self,adopt=adopt_view)
            initial=C.string_at(self.view,TRACE_BYTES);require(initial==bytes(TRACE_BYTES),'a4_trace_initial_zero')
            self.j['mapping']=dict(parent_handle=self.mapping_handle,child_handle=self.child_mapping_number,parent_view=self.view,
                trace_bytes=TRACE_BYTES,child_access=2,parent_access=4,initial_sha256=sha(initial))
            self.phase='construct';row=self.spawn('selected',end,True)
            self.phase='accesscheck';self.semantic(row,'before-memory',end)
            start=self.budget.read();self.window=dict(start=start,end=min(start+8*self.c['frequency'],work_cutoff(self.c)));self.j['window']=dict(self.window)
            self.selected_run(row)
        except BaseException as exc:
            self.j['failure']=self.phase if self.phase in FAILURES else 'report';self.j['failure_detail']=base.private_failure_detail(exc,self.phase)
        finally:
            try:self.stop_selected()
            except BaseException as exc:self.j['failure']=self.j['failure'] or 'cleanup';self.j['failure_detail']=self.j['failure_detail'] or base.private_failure_detail(exc,'stop-selected')
            try:
                selected=self.tasks.get('selected')
                if self.j['controls']['before'] is not None and not self.j['creation_unknown'] and (selected is None or selected['exited']) and not self.api.controls_uncertain and self.budget.read()<work_cutoff(self.c):
                    self.phase='ordinary_after';self.control('after')
            except BaseException as exc:
                self.j['failure']=self.j['failure'] or 'ordinary_after';self.j['failure_detail']=self.j['failure_detail'] or base.private_failure_detail(exc,'ordinary-after')
            self.cleanup()
        self.j['tasks']=[task_projection(x) for x in self.children];self.j['controls_uncertain']=bool(self.api.controls_uncertain)
        if any(x['operation']=='a4_copy_config_v1' for x in self.api.a4_calls) and self.j['payload'] is None:
            # NULL/exception/late or incomplete readback does not prove that a
            # remote carrier allocation was absent. Its scope is target life.
            self.j['remote_memory_unknown']=True
        try:self.j['completed_qpc']=self.budget.read()
        except BaseException:
            self.j['failure']=self.j['failure'] or 'deadline'
        return self.j

    def cleanup(self):
        try:
            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')
            rows=[r for r in self.children if not base.known_no_child(r,start=self.c['start_qpc'])]
            clean,empty,_=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(8)),self.job,rows,self.owners)
            self.j.update(workload_cleanup=clean,workload_job_empty=empty)
        except BaseException:pass
        for ledger in [*self.stdio_ledgers,self.mapping_duplicates]:
            for h in tuple(ledger.pending):
                try:ledger.close(h)
                except BaseException:self.api.controls_uncertain=True
        self.j['parent_stdio_mapping_duplicate_closed']=all(x.confirmed_closed for x in [*self.stdio_ledgers,self.mapping_duplicates]) and not parent_allocation_unknown(self.api.a4_calls,'DuplicateHandle(trace_write)')
        # A view is a pointer namespace, never a HANDLE. Keep the section/view
        # while target exit is unknown; closing another integer is not cleanup.
        if self.j['workload_cleanup']:
            if self.view is not None and not self.view_consumed:
                self.view_consumed=True
                try:self.api.unmap(self.view,budget=self.budget,end=self.budget.cutoff(3),emit=self);self.j['trace_view_unmapped']=True
                except BaseException:self.api.controls_uncertain=True
            for ledger in (self.mapping_owners,self.resources):
                for h in tuple(ledger.pending):
                    try:ledger.close(h)
                    except BaseException:self.api.controls_uncertain=True
        elif self.resources.pending or self.mapping_owners.pending or self.view is not None:
            launcher._RETAINED_SCOPED_OWNERS.append((self.api,self.resources,self.mapping_owners,self.view,'a4-live-exact-target'))
        self.j['trace_mapping_closed']=self.mapping_owners.confirmed_closed and not parent_allocation_unknown(self.api.a4_calls,'CreateFileMappingW')
        if self.view is None and parent_allocation_unknown(self.api.a4_calls,'MapViewOfFile(parent_read)'):self.j['trace_view_unmapped']=False
        self.j['target_file_closed']=self.resources.confirmed_closed;self.j['shim_file_closed']=self.resources.confirmed_closed
        self.j['query_resources_closed']=all(x.confirmed_closed for x in self.query_ledgers) and not parent_allocation_unknown(self.api.a4_calls,'OpenProcessToken(current-primary)')
        observer_count=sum(decode(r['text'].encode('ascii'))['action'].startswith('observe-') for r in self.j['intents'])
        if len(self.j['proofs'])!=observer_count:self.j['observer_resources_cleanup_verified']=False
        if not all(self.j[k] for k in ('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified',
            'parent_stdio_mapping_duplicate_closed','trace_view_unmapped','trace_mapping_closed','target_file_closed','shim_file_closed','query_resources_closed')):
            self.api.controls_uncertain=True
        if not self.api.controls_uncertain:
            try:
                if self.j['labels']:
                    self.journal('label-restore')
                    for p in sorted(base.owned_tree(self.root/'selected-output'),key=lambda p:len(p.parts),reverse=True):
                        self.budget.require_ms(self.budget.cutoff(5));self.api.label_set(p,None)
                    for p in base.owned_tree(self.root/'selected-output'):
                        self.budget.require_ms(self.budget.cutoff(5));require(self.api.label_read(p) is None,'a4_batch_label_readback')
                    self.j['labels'][0]['restored']=True
                self.j['labels_restored']=True
                if self.profile['created']:
                    ledger=helpers.OneShotHandles(self.api.close);rows=[];job=None
                    try:
                        job=self.api.owned_job(ledger);self.journal('acl-remove')
                        self.tool([str(self.fixed_tool('icacls.exe')),str(self.root),'/remove:g','*'+self.profile['sid'],'/T','/Q'],
                            'remove',cleanup=True,owners=ledger,children=rows,job=job)
                        self.scope_acl(True);self.j['acl_removed']=True
                    finally:
                        if job is not None:self.j['cleanup_tools']=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,rows,ledger)[0]
                        self.j['cleanup_tasks']=[task_projection(x) for x in rows]
                    require(not self.api.controls_uncertain and self.j['acl_removed'] and self.j['cleanup_tools'],'a4_profile_delete_known_resources')
                    self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True
                elif not self.profile['attempted']:self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)
            except BaseException:pass
        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True
        except BaseException:pass
        if not all(self.j[k] for k in CLEAN_KEYS):self.j['failure']=self.j['failure'] or 'cleanup'

def payload_framing(config):
    require(type(config) is bytes and len(config)==2048,'a4_payload_config_size')
    value=bytearray(456+len(config));struct.pack_into('<H',value,0,0x5a4d);struct.pack_into('<I',value,60,64)
    struct.pack_into('<I',value,64,0x4550);struct.pack_into('<H',value,70,1);struct.pack_into('<HHH',value,84,240,0x2000,0x20b)
    value[328:336]=b'.detour\0';struct.pack_into('<II',value,340,368,2136)
    struct.pack_into('<4I',value,368,64,0x00727444,64,2136);struct.pack_into('<II',value,432,2072,0)
    value[440:456]=GUID_BYTES;value[456:]=config;return bytes(value)

def parent_allocation_unknown(calls,operation):
    for row in calls:
        if row['operation']!=operation:continue
        if not row['returned'] or row['native_exception'] is not None or row['output_error'] is not None or row.get('adoption_failed',False):return True
        if operation in ('DuplicateHandle(trace_write)','OpenProcessToken(current-primary)'):
            value=row['outputs'].get('handle')
            if not row['raw_return'] and value:return True
            if row['raw_return'] and not(live.integer(value,1,0xfffffffffffffffe)):return True
    return False

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent),'a4_parent')
    require(budget.frequency==c['frequency'] and budget.deadline==c['deadline_qpc'],'a4_budget')
    return Owner(root,c,parent,api,budget).run()

# These modules are pure and take a closed source namespace explicitly. The
# guard's importlib loader need not register this module in sys.modules.
physical=load('a4_independent_physical','windows_identity_lpac_curl_a4_physical.py')
memory_physical=load('a4_independent_memory_physical','windows_identity_lpac_curl_a4_memory_physical.py')
def _context():return SimpleNamespace(**globals())
def task_validate(t,c,parent,root,*,curl):return physical.task_validate(_context(),t,c,parent,root,curl=curl)
def ordinary_controls(root,c,parent):return physical.ordinary_controls(_context(),root,c,parent)
def validate_observation(v):return physical.validate_observation(_context(),v)
def physical_record(d,path,root):return physical.physical_record(_context(),d,path,root)

API_OPERATIONS={
    'CloseHandle':{'handle'},'GetHandleInformation':{'handle'},
    'CreateFileMappingW':{'bytes','protection','named'},'LocalFree(mapping_SD)':{'pointer'},
    'DuplicateHandle(trace_write)':{'source','desired_access','inherited','options'},
    'MapViewOfFile(parent_read)':{'handle','access','bytes'},'UnmapViewOfFile(parent)':{'view'},
    'OpenProcessToken(current-primary)':{'process','access'},
    'NtQueryInformationProcess(PBI48)':{'process','information_class','bytes'},
    'a4_copy_config_v1':{'process','config_sha256','bytes'}}
API_RAW_KEYS={'operation','arguments','deadline_qpc','admission_known','entered_qpc','entered','returned','raw_return','error','error_captured',
    'native_exception','error_exception','outputs','output_error','post_call_qpc','clock_known','timely','clock_error',
    'intent_sha256','output_bytes','output_sha256'}

def _raw_api_shape(row,c):
    require(type(row) is dict and set(row) in (API_RAW_KEYS,API_RAW_KEYS|{'adoption_failed'})
        and row['operation'] in API_OPERATIONS and type(row['arguments']) is dict
        and set(row['arguments'])==API_OPERATIONS[row['operation']],'a4_API_raw_schema')
    require(all(type(row[k]) is bool for k in ('admission_known','entered','returned','error_captured','clock_known','timely'))
        and row['entered'] is True and ('adoption_failed' not in row or row['adoption_failed'] is True),'a4_API_raw_flags')
    require(row['raw_return'] is None or type(row['raw_return']) is int and -(1<<31)<=row['raw_return']<1<<64,'a4_API_raw_value')
    require((row['error'] is None or live.integer(row['error'],0,0xffffffff))
        and row['error_captured']==(row['error'] is not None),'a4_API_raw_error')
    require(row['returned'] or row['raw_return'] is None,'a4_API_unreturned_raw')
    for key in ('native_exception','error_exception','output_error','clock_error'):
        require(row[key] is None or type(row[key]) is str and re.fullmatch('[A-Za-z0-9_]{1,80}',row[key]),'a4_API_error_kind')
    require(type(row['outputs']) is dict and live.integer(row['output_bytes'],0,4096)
        and base.ac.digest(row['output_sha256']) and (row['intent_sha256'] is None or base.ac.digest(row['intent_sha256'])),'a4_API_outputs')
    require(live.integer(row['deadline_qpc'],c['start_qpc']+1,c['deadline_qpc'])
        and (row['entered_qpc'] is None or live.integer(row['entered_qpc'],c['start_qpc'],c['deadline_qpc']-1)),'a4_API_cutoff')
    require(not row['clock_known'] or live.integer(row['post_call_qpc'],c['start_qpc'],c['deadline_qpc'])
        and row['clock_error'] is None,'a4_API_known_clock')
    require(row['clock_known'] or row['post_call_qpc'] is None,'a4_API_unknown_clock')
    require(row['timely']==bool(row['admission_known'] and row['clock_known'] and row['entered_qpc'] is not None
        and row['entered_qpc']<=row['post_call_qpc']<row['deadline_qpc']),'a4_API_timely')
    return row

def validate_api_records(j,c,root,selected):
    root=Path(root);intents={};calls=[];physical_calls=[]
    require(type(j['api_intents']) is list and len(j['api_intents'])<=128
        and type(j['api_calls']) is list and len(j['api_calls'])<=128
        and type(j['api_raw_calls']) is list and len(j['api_raw_calls'])<=128,'a4_API_bounds')
    for index,d in enumerate(j['api_intents']):
        # API file basenames are intentionally a distinct closed form.
        require(type(d) is dict and set(d)=={'name','text','sha256'} and d['name']=='%03d-intent.json'%index
            and type(d['text']) is str and base.ac.digest(d['sha256']),'a4_API_intent_descriptor')
        raw=d['text'].encode('ascii');require(sha(raw)==d['sha256'] and local.bounded(launcher.checked_path(root/'api-calls'/d['name'],inside=root),MAX_REPORT)==raw,'a4_API_intent_physical')
        v=decode(raw);require(type(v) is dict and set(v)=={'schema_version','scope','run','config_sha256','index','operation','arguments','qpc'}
            and type(v['schema_version']) is int and v['schema_version']==1 and v['scope']==SCOPE and v['run']==c['run']
            and v['config_sha256']==sha(encode(c)) and v['index']==index and type(v['index']) is int
            and v['operation'] in API_OPERATIONS and type(v['arguments']) is dict and set(v['arguments'])==API_OPERATIONS[v['operation']]
            and (v['qpc'] is None or live.integer(v['qpc'],c['start_qpc'],c['deadline_qpc'])),'a4_API_intent_binding')
        require(d['sha256'] not in intents,'a4_API_duplicate_intent');intents[d['sha256']]=v
    for index,d in enumerate(j['api_calls']):
        require(type(d) is dict and set(d)=={'name','text','sha256'} and d['name']=='%03d-return.json'%index
            and type(d['text']) is str and base.ac.digest(d['sha256']),'a4_API_return_descriptor')
        raw=d['text'].encode('ascii');require(sha(raw)==d['sha256'] and local.bounded(launcher.checked_path(root/'api-calls'/d['name'],inside=root),MAX_REPORT)==raw,'a4_API_return_physical')
        v=decode(raw);require(type(v) is dict and set(v)=={'schema_version','scope','run','config_sha256','index','call','output'}
            and type(v['schema_version']) is int and v['schema_version']==1 and v['scope']==SCOPE and v['run']==c['run']
            and v['config_sha256']==sha(encode(c)) and type(v['index']) is int and v['index']==index,'a4_API_return_binding')
        call=_raw_api_shape(v['call'],c);out=read_binary(root,v['output'],4096)
        require(v['output']['name']=='api-%03d.bin'%index and len(out)==call['output_bytes'] and sha(out)==call['output_sha256'],'a4_API_binary_binding')
        if call['intent_sha256'] is not None:
            require(call['intent_sha256'] in intents,'a4_API_intent_missing');prior=intents[call['intent_sha256']]
            require(prior['operation']==call['operation'] and prior['arguments']==call['arguments']
                and (prior['qpc'] is None or call['entered_qpc'] is not None and prior['qpc']<=call['entered_qpc']),'a4_API_causal')
        else:require(j['controls_uncertain'] and call['operation'] in ('CloseHandle','UnmapViewOfFile(parent)','LocalFree(mapping_SD)'),'a4_API_missing_intent_unknown')
        physical_calls.append(call);calls.append((call,out,d['sha256']))
    require(j['api_raw_calls'][:len(physical_calls)]==physical_calls,'a4_API_local_physical_prefix')
    for row in j['api_raw_calls']:_raw_api_shape(row,c)
    if len(j['api_raw_calls'])!=len(physical_calls):
        require(j['controls_uncertain'] and j['failure'] is not None,'a4_API_uncommitted_partial')
    require({p.name for p in (root/'api-calls').iterdir()}=={d['name'] for d in [*j['api_intents'],*j['api_calls']]},'a4_API_closed_directory')
    active={};views=set();seen_mapping=[];seen_duplicate=[];seen_view=[];carrier=[];qualified=True
    for call,out,reference in calls:
        op,args,value=call['operation'],call['arguments'],call['raw_return'];outputs=call['outputs']
        require(set(outputs)==({'flags'} if op=='GetHandleInformation' else {'handle'} if op in ('DuplicateHandle(trace_write)','OpenProcessToken(current-primary)')
            else {'returned_length'} if op=='NtQueryInformationProcess(PBI48)' else set()) or call['output_error'] is not None,'a4_API_typed_outputs')
        returned=call['returned'] and call['native_exception'] is None
        clean=returned and call['error_captured'] and call['output_error'] is None
        qualified=qualified and clean and call['clock_known'] and call['timely'] and not call.get('adoption_failed',False)
        handle=None
        if op=='CreateFileMappingW':
            require(args==dict(bytes=TRACE_BYTES,protection=4,named=False),'a4_section_parameters')
            if returned and value:handle=value;seen_mapping.append(value)
        elif op=='DuplicateHandle(trace_write)':
            require(args['desired_access']==2 and args['inherited'] is True and args['options']==0
                and args['source'] in seen_mapping,'a4_section_dup_parameters')
            if returned and value:handle=outputs.get('handle');seen_duplicate.append(handle)
            elif outputs.get('handle'):require(j['controls_uncertain'],'a4_failed_duplicate_unknown')
        elif op=='OpenProcessToken(current-primary)':
            require(args['access']==8 and live.integer(args['process'],1,0xfffffffffffffffe),'a4_current_primary_rights')
            if returned and value:handle=outputs.get('handle')
            elif outputs.get('handle'):require(j['controls_uncertain'],'a4_failed_token_unknown')
        elif op=='MapViewOfFile(parent_read)':
            require(args['access']==4 and args['bytes']==TRACE_BYTES and args['handle'] in seen_mapping,'a4_parent_view_parameters')
            if returned and value:
                require(live.integer(value,0x10000,(1<<47)-TRACE_BYTES) and value not in views,'a4_parent_view_alias');views.add(value);seen_view.append(value)
        elif op=='CloseHandle':
            require(live.integer(args['handle'],1,0xfffffffffffffffe) and args['handle'] in active,'a4_close_known_owner')
            del active[args['handle']]
            if not clean or value==0:require(j['controls_uncertain'],'a4_close_failure_sticky')
        elif op=='UnmapViewOfFile(parent)':
            require(args['view'] in views,'a4_unmap_known_owner');views.remove(args['view'])
            if not clean or value==0:require(j['controls_uncertain'],'a4_unmap_failure_sticky')
        elif op=='LocalFree(mapping_SD)':
            require(live.integer(args['pointer'],0x10000,(1<<47)-1),'a4_mapping_SD_pointer')
            if not clean or value!=0:require(j['controls_uncertain'],'a4_SD_close_failure_sticky')
        elif op=='GetHandleInformation':
            require(live.integer(args['handle'],1,0xfffffffffffffffe) and (call['output_error'] is not None or live.integer(outputs['flags'],0,3)),'a4_flags_parameters')
            if clean:
                expected=1 if active.get(args['handle'])=='DuplicateHandle(trace_write)' else 0
                qualified=qualified and args['handle'] in active and outputs['flags']==expected
        elif op=='NtQueryInformationProcess(PBI48)':
            require(args['information_class']==0 and args['bytes']==48 and live.integer(args['process'],1,0xfffffffffffffffe)
                and len(out)==48 and live.integer(outputs['returned_length'],0,0xffffffff),'a4_PBI_raw')
        elif op=='a4_copy_config_v1':
            require(args['bytes']==2048 and base.ac.digest(args['config_sha256']) and len(out)==32
                and selected is not None,'a4_carrier_parameters');carrier.append((call,out,reference))
        if clean:
            if op=='LocalFree(mapping_SD)':qualified=qualified and value==0
            elif op=='NtQueryInformationProcess(PBI48)':qualified=qualified and value==0 and outputs['returned_length']==48
            elif op=='a4_copy_config_v1':
                size,version,flags,error,pointer,seh,reserved=struct.unpack('<4IQ2I',out)
                qualified=qualified and value==0 and (size,version,flags,error,seh,reserved)==(32,1,3,0,0,0) and pointer>=0x10000+456
            else:qualified=qualified and value is not None and value!=0
        if handle is not None:
            if call.get('adoption_failed'):
                require(j['controls_uncertain'],'a4_failed_adoption_sticky')
            else:
                require(live.integer(handle,1,0xfffffffffffffffe) and handle not in active,'a4_parent_handle_alias');active[handle]=op
        if not clean or not call['clock_known']:
            require(j['controls_uncertain'],'a4_API_unknown_sticky')
    require(len(seen_mapping)<=1 and len(seen_duplicate)<=1 and len(seen_view)<=1 and len(carrier)<=1,'a4_parent_once')
    if j['trace_mapping_closed']:require(not any(v=='CreateFileMappingW' for v in active.values()),'a4_section_close_claim')
    if j['parent_stdio_mapping_duplicate_closed']:require(not any(v=='DuplicateHandle(trace_write)' for v in active.values()),'a4_duplicate_close_claim')
    if j['query_resources_closed']:require(not any(v=='OpenProcessToken(current-primary)' for v in active.values()),'a4_query_close_claim')
    if j['trace_view_unmapped']:require(not views,'a4_view_close_claim')
    for operation,key in (('CreateFileMappingW','trace_mapping_closed'),('DuplicateHandle(trace_write)','parent_stdio_mapping_duplicate_closed'),
        ('MapViewOfFile(parent_read)','trace_view_unmapped'),('OpenProcessToken(current-primary)','query_resources_closed')):
        require(not j[key] or not parent_allocation_unknown(j['api_raw_calls'],operation),'a4_unknown_allocation_cleanup_claim')
    if j['mapping'] is not None:
        v=j['mapping'];require(type(v) is dict and set(v)=={'parent_handle','child_handle','parent_view','trace_bytes','child_access','parent_access','initial_sha256'}
            and seen_mapping==[v['parent_handle']] and seen_duplicate==[v['child_handle']] and seen_view==[v['parent_view']]
            and v['trace_bytes']==TRACE_BYTES and v['child_access']==2 and v['parent_access']==4
            and v['initial_sha256']==sha(bytes(TRACE_BYTES)),'a4_mapping_commitment')
        if selected is not None and selected['admitted']:require(selected['inherited_handles'][0]==v['child_handle'],'a4_child_mapping_inherited')
    elif selected is not None:require(not selected['admitted'],'a4_selected_requires_mapping')
    return dict(calls=calls,carrier=carrier,qualified=bool(qualified))

RESULT_KEYS={'schema_version','stage','scope','profile','config_sha256','failure','failure_detail','profile_name','profile_sid','profile_state',
    'child_environment','intents','returns','proofs','tasks','cleanup_tasks','labels','window','api_intents','api_calls','api_raw_calls',
    'memory_records','memory_summary','base_provenance','payload','config_binary','trace_binary','trace_review','mapping','target_lease',
    'shim_lease','lease_checks','controls','selected_output','resume_observation','profile_created','acl_attempted','creation_unknown',
    'controls_uncertain','completed_qpc','selected_stop_attempted','selected_exit_confirmed','remote_memory_unknown',
    'token_class46_queried','endpoint_created','dns_api_called',*CLEAN_KEYS,*FALSE_CLAIMS}
RESULT_BOOLS={'profile_created','acl_attempted','creation_unknown','controls_uncertain','selected_stop_attempted','selected_exit_confirmed',
    'remote_memory_unknown','token_class46_queried','endpoint_created','dns_api_called',*CLEAN_KEYS,*FALSE_CLAIMS}

def _journal_graph(j,c,root):
    intents={};returns={};previous=c['start_qpc'];root=Path(root)
    require(type(j['intents']) is list and len(j['intents'])<=256 and type(j['returns']) is list and len(j['returns'])<=256,'a4_journal_bounds')
    for index,d in enumerate(j['intents']):
        v=physical_record(d,root/'journal'/d['name'],root)
        require(type(v) is dict and set(v)=={'schema_version','scope','run','config_sha256','frequency','deadline_qpc','qpc','action'}
            and type(v['schema_version']) is int and v['schema_version']==1 and v['scope']==SCOPE and v['run']==c['run']
            and v['config_sha256']==sha(encode(c)) and v['frequency']==c['frequency'] and v['deadline_qpc']==c['deadline_qpc']
            and live.integer(v['qpc'],previous,c['deadline_qpc']-1) and re.fullmatch('[a-z0-9-]{1,64}',v['action'])
            and d['name']=='%03d-%s.json'%(index,v['action']) and d['sha256'] not in intents,'a4_intent_binding')
        intents[d['sha256']]=v;previous=v['qpc']
    used=set()
    for index,d in enumerate(j['returns']):
        v=physical_record(d,root/'returns'/d['name'],root)
        require(type(v) is dict and set(v)=={'schema_version','scope','run','config_sha256','intent_sha256','action','qpc','data'}
            and type(v['schema_version']) is int and v['schema_version']==1 and v['scope']==SCOPE and v['run']==c['run']
            and v['config_sha256']==sha(encode(c)) and v['intent_sha256'] in intents and v['intent_sha256'] not in used
            and v['action']==intents[v['intent_sha256']]['action'] and live.integer(v['qpc'],intents[v['intent_sha256']]['qpc'],c['deadline_qpc']-1)
            and d['name']=='%03d-%s.json'%(index,v['action']) and d['sha256'] not in returns,'a4_return_binding')
        returns[d['sha256']]=v;used.add(v['intent_sha256'])
    require({p.name for p in (root/'journal').iterdir()}=={d['name'] for d in j['intents']}
        and {p.name for p in (root/'returns').iterdir()}=={d['name'] for d in j['returns']},'a4_closed_journal')
    return intents,returns

def _validate_leases(j,c,returns,selected):
    leases={}
    for field,action in (('target_lease','target-lease'),('shim_lease','shim-lease')):
        d=j[field]
        if d is not None:
            require(d['sha256'] in returns and returns[d['sha256']]['action']==action,'a4_lease_return')
            v=returns[d['sha256']]['data'];require(type(v) is dict and set(v)=={'handle','file_identity'}
                and live.integer(v['handle'],1,0xfffffffffffffffe),'a4_lease_shape')
            mm.protocol.inputs.file_id_bytes(v['file_identity']);leases[field]=v
    require(type(j['lease_checks']) is list and len(j['lease_checks'])<=2,'a4_lease_check_count')
    for index,d in enumerate(j['lease_checks']):
        require(d['sha256'] in returns,'a4_lease_check_return');v=returns[d['sha256']]
        require(v['action']==('lease-before','lease-after')[index] and type(v['data']) is dict and set(v['data'])=={'target','shim'},'a4_lease_phase')
        for role,key in (('target','curl'),('shim','shim')):
            fact=v['data'][role];require(type(fact) is dict and set(fact)=={'file_identity','bytes','sha256'}
                and role+'_lease' in leases and fact['file_identity']==leases[role+'_lease']['file_identity']
                and fact['bytes']==c['artifacts'][key]['bytes'] and fact['sha256']==c['artifacts'][key]['sha256'],'a4_lease_bytes_ID')
        if index==0:
            require(j['window'] is None or v['qpc']<=j['window']['start'],'a4_lease_before_window')
        else:
            require(selected is not None and selected['natural_exit'] and selected['exit_observed_qpc']<=v['qpc']<j['window']['end'],'a4_lease_after_exact_exit')
    if selected is not None and selected['admitted']:
        require(len(leases)==2 and len(j['lease_checks'])>=1,'a4_selected_retained_leases')
    return leases

def _validate_trace(j,c,root,selected,config,returns):
    if j['trace_binary'] is None:
        require(j['trace_review'] is None,'a4_trace_review_without_binary');return None
    require(config is not None and selected is not None and selected['natural_exit'] and selected['resumed']
        and selected['exit_observed_qpc'] is not None,'a4_trace_requires_natural_exit')
    raw=read_binary(root,j['trace_binary'],TRACE_BYTES);require(j['trace_binary']['name']=='a4-trace.bin' and len(raw)==TRACE_BYTES,'a4_trace_file')
    d=j['trace_review'];require(d is not None and d['sha256'] in returns,'a4_trace_return')
    v=returns[d['sha256']];data=v['data'];window=j['window']
    require(v['action']=='trace-after-exit' and type(data) is dict
        and set(data)=={'before_qpc','after_qpc','trace_sha256','config_sha256','stable','review'} and data['stable'] is True
        and selected['exit_observed_qpc']<=data['before_qpc']<=data['after_qpc']<=v['qpc']<window['end']
        and data['trace_sha256']==sha(raw) and data['config_sha256']==sha(config),'a4_trace_causal')
    review=trace_reader.review(raw,expected_config2048=config,schema_metadata=trace_reader.SCHEMA_METADATA)
    require(data['review']==review,'a4_trace_independent_projection');return review

def validate_result(j,c,*,parent,root):
    config_validate(c);require(launcher.token_is_ordinary(parent),'a4_result_parent');root=Path(root)
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='lpac-curl-a4-loader-result' and j['scope']==SCOPE and j['profile']==PROFILE
        and j['config_sha256']==sha(encode(c)) and j['failure'] in (None,*FAILURES),'a4_result_schema')
    require(all(type(j[k]) is bool for k in RESULT_BOOLS) and not any(j[k] for k in (*FALSE_CLAIMS,'token_class46_queried','endpoint_created','dns_api_called')),'a4_result_boolean_scope')
    base.validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'a4_failure_detail')
    require(j['completed_qpc'] is None or live.integer(j['completed_qpc'],c['start_qpc'],(1<<63)-1),'a4_result_clock')
    require(j['completed_qpc'] is not None or j['failure'] is not None,'a4_missing_completed_clock')
    require(j['profile_name']=='ruleproxy-curl-a4-loader-'+c['run'] and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'a4_profile_name')
    require(type(j['profile_state']) is dict and set(j['profile_state'])=={'attempted','returned','created','sid_pointer_returned'}
        and all(type(x) is bool for x in j['profile_state'].values()),'a4_profile_state')
    require(not j['profile_created'] or j['profile_state']['created'] and j['profile_sid'] is not None
        and launcher.child_environment_admitted(j['child_environment']),'a4_profile_created')
    require(not j['acl_attempted'] or j['profile_created'],'a4_ACL_scope')
    intents,returns=_journal_graph(j,c,root)
    require(type(j['tasks']) is list and len(j['tasks'])<=6 and type(j['cleanup_tasks']) is list and len(j['cleanup_tasks'])<=1,'a4_task_bounds')
    tasks={}
    for t in j['tasks']:
        task_validate(t,c,parent,root,curl=t['name'] in ('before','selected','after'))
        require(t['name'] not in tasks,'a4_task_duplicate');tasks[t['name']]=t
        if t['receipt'] is not None:require(t['receipt']['sha256'] in returns,'a4_task_return_graph')
        for key in ('constructor_return_qpc','admission_qpc','resume_qpc','exit_observed_qpc'):
            require(t[key] is None or j['completed_qpc'] is None or t[key]<=j['completed_qpc'],'a4_task_before_completion')
    for t in j['cleanup_tasks']:
        task_validate(t,c,parent,root,curl=False);require(t['name']=='remove','a4_cleanup_tool')
    selected=tasks.get('selected');window=j['window']
    if window is not None:
        require(type(window) is dict and set(window)=={'start','end'} and live.integer(window['start'],c['start_qpc'],work_cutoff(c)-1)
            and window['end']==min(window['start']+8*c['frequency'],work_cutoff(c)) and selected is not None
            and selected['admitted'] and selected['admission_qpc']<=window['start'],'a4_window')
    else:
        require(all(j[k] is None for k in ('base_provenance','memory_summary','payload','config_binary','trace_binary','trace_review')),'a4_no_window_partial')
    require(type(j['controls']) is dict and set(j['controls'])=={'before','after'},'a4_control_set')
    for role,d in j['controls'].items():
        if d is not None:
            require(type(d) is dict and set(d)=={'text','sha256'} and type(d['text']) is str and sha(d['text'].encode('ascii'))==d['sha256']
                and local.bounded(launcher.checked_path(root/('control-'+role+'.json'),inside=root),MAX_REPORT)==d['text'].encode('ascii'),'a4_control_physical')
            v=physical.validate_ordinary_control(_context(),decode(d['text'].encode('ascii')),c,role=role,parent=parent,root=root)
            require(role in tasks and v['task']==tasks[role],'a4_control_task_match')
    require(type(j['proofs']) is list and len(j['proofs'])<=2,'a4_proofs')
    for index,p in enumerate(j['proofs']):
        require(type(p) is dict and set(p)=={'label','intent_sha256','value'} and p['label']==('before-memory','before-resume')[index]
            and p['intent_sha256'] in intents and intents[p['intent_sha256']]['action']=='observe-'+p['label'] and selected is not None,'a4_proof_intent')
        deadline=work_cutoff(c) if index==0 else window['end']
        zero.validate_proof(p['value'],expected_primary_identity=selected['expected_primary'],expected_role='lpac',expected_pid=selected['pid'],
            expected_creation=selected['created'],frequency=c['frequency'],deadline=deadline)
        require(p['value']['start_qpc'] is None or p['value']['start_qpc']>=intents[p['intent_sha256']]['qpc'],'a4_proof_causal')
    count=sum(v['action'].startswith('observe-') for v in intents.values())
    require(not j['observer_resources_cleanup_verified'] or count==len(j['proofs']) and all(p['value']['resource_cleanup_verified'] for p in j['proofs']),'a4_observer_sticky_cleanup')
    if selected is not None and selected['admitted']:
        require(j['profile_created'] and j['acl_attempted'] and selected['expected_primary']['appcontainer_sid']==j['profile_sid'],'a4_selected_profile')
    api=validate_api_records(j,c,root,selected)
    if any(x['operation']=='a4_copy_config_v1' for x in j['api_raw_calls']) and j['payload'] is None:
        require(j['remote_memory_unknown'],'a4_partial_carrier_unknown_retained')
    mem=memory_physical.validate_memory_records(_context(),j,c,root,selected)
    require(type(mem) is dict and set(mem)=={'base','memory_complete','payload_pointer','payload_readonly','config'}
        and all(type(mem[k]) is bool for k in ('memory_complete','payload_pointer','payload_readonly')),'a4_memory_projection_schema')
    _validate_leases(j,c,returns,selected);trace=_validate_trace(j,c,root,selected,mem['config'],returns)
    if selected is not None and selected['resumed']:
        require(mem['memory_complete'] and mem['payload_readonly'] and len(j['proofs'])==2
            and all(p['value']['qualified'] and p['value']['resource_cleanup_verified'] for p in j['proofs'])
            and j['proofs'][1]['value']['end_qpc']<=selected['resume_intent_qpc']<window['end'],'a4_resume_authorization')
        d=j['resume_observation'];require(d is not None and d['sha256'] in returns,'a4_resume_return')
        v=returns[d['sha256']];data=v['data'];require(v['action']=='resume-selected' and type(data) is dict
            and set(data)=={'entered','returned','count','error','returned_qpc','clock_error','exception'} and data['entered'] is True
            and data['returned'] is True and type(data['count']) is int and data['count']==1 and data['error'] is None
            and data['returned_qpc']==selected['resume_qpc'] and data['clock_error'] is False and data['exception'] is False
            and data['returned_qpc']<=v['qpc'],'a4_resume_physical')
        if j['payload'] is not None:require(returns[j['payload']['sha256']]['qpc']<=selected['resume_intent_qpc'],'a4_payload_before_resume')
    elif j['resume_observation'] is not None:
        require(j['resume_observation']['sha256'] in returns and returns[j['resume_observation']['sha256']]['action']=='resume-selected'
            and j['failure'] is not None,'a4_failed_resume_partial')
    if j['selected_output'] is not None:
        require(selected is not None and selected['exited'],'a4_selected_output_exit')
        stdout=local.bounded(launcher.checked_path(root/'selected-output'/'stdout',inside=root),MAX_OUTPUT)
        stderr=local.bounded(launcher.checked_path(root/'selected-output'/'stderr',inside=root),MAX_OUTPUT)
        out=dict(stdout_bytes=len(stdout),stdout_sha256=sha(stdout),stderr_bytes=len(stderr),stderr_sha256=sha(stderr),
            exact_baseline=len(stdout)==BASELINE_BYTES and sha(stdout)==BASELINE_SHA256 and not stderr)
        require(j['selected_output']==out,'a4_selected_output_physical')
        if out['exact_baseline']:
            for role in ('before','after'):
                if j['controls'][role] is not None:
                    require(stdout==local.bounded(launcher.checked_path(root/('ordinary-'+role)/'stdout',inside=root),MAX_OUTPUT),'a4_exact_three_stdout')
    if j['workload_cleanup']:
        require(j['workload_job_empty'] and not j['creation_unknown'] and all(not t['attempted'] or t['exited'] or mm.known_no_child(t,c) for t in tasks.values()),'a4_workload_cleanup')
    require(not j['selected_exit_confirmed'] or selected is not None and selected['exited'],'a4_selected_exit_claim')
    require(type(j['labels']) is list and len(j['labels'])<=1,'a4_label_set')
    if j['labels']:
        label=j['labels'][0];require(type(label) is dict and set(label)=={'name','attempted','lowered','restored'} and label['name']=='selected-output'
            and label['attempted'] is True and all(type(label[k]) is bool for k in ('lowered','restored')),'a4_label_schema')
        require(not j['labels_restored'] or label['restored'] and any(v['action']=='label-restore' for v in intents.values()),'a4_label_restored')
    if selected is not None and selected['admitted']:
        require(len(j['labels'])==1 and j['labels'][0]['lowered'] and any(v['action']=='label-lower' for v in intents.values())
            and all(name in tasks and tasks[name]['admitted'] and tasks[name]['resumed'] and tasks[name]['exited'] and tasks[name]['exit_code']==0
                for name in ('grant-root','grant-package','grant-output')),'a4_selected_setup')
    if j['profile_deleted'] and j['profile_state']['attempted']:
        require(j['profile_created'] and not j['controls_uncertain'] and j['acl_removed'] and j['cleanup_tools'] and j['labels_restored']
            and all(j[k] for k in CLEAN_KEYS if k not in ('profile_deleted','sid_released')) and len(j['cleanup_tasks'])==1
            and all(j['cleanup_tasks'][0][k] for k in ('admitted','resumed','exited')) and j['cleanup_tasks'][0]['exit_code']==0
            and any(v['action']=='acl-remove' for v in intents.values()) and any(v['action']=='profile-delete' for v in intents.values()),'a4_profile_delete_gate')
    if j['failure'] is None:
        require(not j['controls_uncertain'] and api['qualified'] and j['completed_qpc']<c['deadline_qpc'] and all(j[k] for k in CLEAN_KEYS) and selected is not None and selected['natural_exit']
            and selected['exit_code']==0 and j['selected_output'] is not None and j['selected_output']['exact_baseline']
            and all(ordinary_controls(root,c,parent).values()) and trace is not None and trace['diagnostic_candidate_complete']
            and len(j['lease_checks'])==2 and len(j['proofs'])==2 and all(p['value']['qualified'] for p in j['proofs']),'a4_failure_free_complete')
    return j

def project(j,c,*,parent,root):
    validate_result(j,c,parent=parent,root=root)
    v=dict(failure=j['failure'],selected_exit_code=None,trace_call_count=None,**dict.fromkeys(OBS_BOOLS,False),**dict.fromkeys(FALSE_CLAIMS,False))
    v.update({k:j[k] for k in CLEAN_KEYS});controls=ordinary_controls(root,c,parent)
    v.update(ordinary_before_positive=controls['before'],ordinary_after_positive=controls['after'])
    selected=next((t for t in j['tasks'] if t['name']=='selected'),None)
    v['lpac_identity_verified']=len(j['proofs'])==2 and all(p['value']['qualified'] and p['value']['resource_cleanup_verified'] for p in j['proofs'])
    mem=memory_physical.validate_memory_records(_context(),j,c,root,selected)
    v.update(private_memory_sequence_complete=mem['memory_complete'],payload_carrier_returned_nonnull=mem['payload_pointer'],payload_readback_readonly_verified=mem['payload_readonly'])
    if selected is not None:
        v.update(selected_exit_code=selected['exit_code'],selected_resumed=selected['resumed'],selected_natural_exit=selected['natural_exit'])
        v['selected_version_positive']=bool(selected['natural_exit'] and selected['exit_code']==0 and j['selected_output'] is not None and j['selected_output']['exact_baseline'])
    if j['trace_review'] is not None:
        review=decode(j['trace_review']['text'].encode('ascii'))['data']['review']
        v.update(trace_header_bound=review['header_bound'],trace_stable=review['stable'],trace_call_count=review['row_count'],
            trace_diagnostic_candidate_complete=review['diagnostic_candidate_complete'])
    required=('ordinary_before_positive','ordinary_after_positive','lpac_identity_verified','private_memory_sequence_complete',
        'payload_carrier_returned_nonnull','payload_readback_readonly_verified','selected_resumed','trace_header_bound','trace_stable',
        'trace_diagnostic_candidate_complete','selected_natural_exit','selected_version_positive')
    v['startup_diagnostic_observed']=all(v[k] for k in required) and len(j['lease_checks'])==2
    v['observation_complete']=j['failure'] is None and v['startup_diagnostic_observed'] and all(v[k] for k in CLEAN_KEYS)
    return validate_observation(v)
