"""Supervised CPSE deny-all matched identity cell. Import is API-free.

The C ABI owns one opaque environment in caller-owned aligned storage; Python
owns every returned kernel handle. Neither arm is ever resumed. A normal VOID
close return closes the caller's API obligation, not proof of broker absence.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
import os
from pathlib import Path
import struct

ROOT=Path(__file__).resolve().parents[1]
def load(name,file):
    s=importlib.util.spec_from_file_location(name,Path(__file__).with_name(file))
    m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
identity=load('cpse_identity','windows_identity_lpac_identity_cell.py')
spec=load('cpse_spec','windows_identity_psec_spec.py')
base,access=identity.owner,identity.access
launcher,local,live,helpers=base.launcher,base.local,base.live,base.helpers
require,encode,decode,sha=base.require,base.encode,base.decode,base.sha
MODULE='.github/windows_identity_psec_lpac_bridge.py'
LOCAL_MODULE='.github/windows_identity_psec_lpac_bridge_local.py'
SOURCES=tuple(dict.fromkeys((*identity.SOURCES,'.github/windows_identity_psec_spec.py',MODULE,LOCAL_MODULE)))
SCOPE='one-local-cpse-deny-all-matched-aap-identity-v1'
VARIANT=spec.VARIANT
DLL='windows_psec_lpac_bridge.dll'
DLL_MANIFEST='psec-lpac-bridge-manifest.json'
NONCES=('run','ac_nonce','lpac_nonce')
MAX_REPORT=512*1024
# A runnable backend is present. This never bypasses the explicit local flag,
# source/device/spec/artifact plan, held guard/worker or original QPC gates.
# Promotion and every real run remain the root operator's separate actions.
ACTUAL_READY=True

def api_version():return 1
def stage_name(run):return 'local-psec-lpac-identity-'+run
def work_cutoff(c):return c['root_deadline_qpc']-35*c['frequency']

class Plan(C.Structure):
    _fields_=[('size',C.c_uint32),('version',C.c_uint32),*[(k,C.c_uint64) for k in
        ('frequency','start_qpc','root_deadline_qpc','worker_deadline_qpc','work_cutoff_qpc')]]
class Child(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ('size','version','policy','reserved')]+[('job',C.c_uint64)]+sum(
        ([(key,C.POINTER(C.c_uint16)),(key+'_units',C.c_uint32)] for key in ('image','inputs_directory','system_root','local_appdata')),[])
class PI(C.Structure):
    _fields_=[('process',C.c_uint64),('thread',C.c_uint64),('process_id',C.c_uint32),('thread_id',C.c_uint32)]
class Result(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ('size','version','operation','wrapper_status','api_entered','api_returned','hresult_valid')]+[
        ('hresult',C.c_int32),('win32_error',C.c_uint32),('within_deadline',C.c_uint32),('before_qpc',C.c_uint64),('after_qpc',C.c_uint64)]+[
        (k,C.c_uint32) for k in ('environment_state','opaque_outcome_unknown','close_invoked_once','close_returned_normally',
        'module_close_attempted','module_close_confirmed')]+[('support_flags',C.c_uint64),('schema_major_available',C.c_uint32),('schema_minor',C.c_uint32)]

RESULT_FIELDS=tuple(name for name,_ in Result._fields_)
NATIVE_RESULT_BOOLS=('api_entered','api_returned','hresult_valid','within_deadline','opaque_outcome_unknown',
    'close_invoked_once','close_returned_normally','module_close_attempted','module_close_confirmed','schema_major_available')
OPS={'bind':1,'create':2,'ac':3,'lpac':3,'close':4,'unbind':5}
def abi_layout():
    require(C.sizeof(C.c_void_p)==8 and C.sizeof(Plan)==48 and C.sizeof(Child)==88 and C.sizeof(PI)==24 and C.sizeof(Result)==96,'bridge_layout')
    require(Child.job.offset==16 and Child.image.offset==24 and Child.local_appdata_units.offset==80
        and Result.before_qpc.offset==40 and Result.support_flags.offset==80,'bridge_offsets')
    return True

def validate_native(v,label,c):
    require(type(v) is dict and set(v)==set(RESULT_FIELDS),'bridge_result_schema')
    require(all(type(x) is int for x in v.values()) and v['size']==96 and v['version']==1
        and v['operation']==OPS[label] and 0<=v['wrapper_status']<=9,'bridge_result_header')
    require(all(v[k] in (0,1) for k in NATIVE_RESULT_BOOLS) and 0<=v['environment_state']<=3
        and -(1<<31)<=v['hresult']<(1<<31) and 0<=v['win32_error']<1<<32
        and all(0<=v[k]<1<<64 for k in ('before_qpc','after_qpc','support_flags'))
        and 0<=v['schema_minor']<1<<32,'bridge_result_values')
    require(not v['api_returned'] or v['api_entered'],'bridge_return_without_call')
    require(not v['hresult_valid'] or label in ('bind','create') and v['api_returned'],'bridge_hresult_kind')
    require(not v['within_deadline'] or c['start_qpc']<=v['before_qpc']<=v['after_qpc']<
        (c['deadline_qpc'] if label in ('close','unbind') else work_cutoff(c)),'bridge_result_clock')
    require(not v['close_returned_normally'] or v['close_invoked_once'] and v['environment_state']==3,'bridge_close_receipt')
    require(not v['module_close_confirmed'] or v['module_close_attempted'],'bridge_module_receipt')
    return v

def pe_x64(raw,*,dll=False):
    require(type(raw) is bytes and 256<=len(raw)<=8*1024*1024 and raw[:2]==b'MZ','bridge_pe')
    at=struct.unpack_from('<I',raw,60)[0];require(at+26<len(raw) and raw[at:at+4]==b'PE\0\0','bridge_pe_header')
    machine=struct.unpack_from('<H',raw,at+4)[0];flags=struct.unpack_from('<H',raw,at+22)[0]
    require(machine==0x8664 and struct.unpack_from('<H',raw,at+24)[0]==0x20b
        and bool(flags&0x2000)==dll,'bridge_pe_kind');return True

def pe_linkage(raw):
    """Read only PE32+ file tables, never map or load the DLL."""
    pe_x64(raw,dll=True);pe=struct.unpack_from('<I',raw,60)[0];count=struct.unpack_from('<H',raw,pe+6)[0]
    optional_size=struct.unpack_from('<H',raw,pe+20)[0];optional=pe+24
    require(1<=count<=96 and optional_size>=240 and optional+optional_size+count*40<=len(raw),'bridge_pe_sections')
    require(struct.unpack_from('<I',raw,optional+108)[0]>=2,'bridge_pe_directories')
    sections=[]
    for index in range(count):
        at=optional+optional_size+index*40;virtual_size,rva,size,offset=struct.unpack_from('<IIII',raw,at+8)
        require(offset+size<=len(raw),'bridge_pe_section_bounds');sections.append((rva,max(virtual_size,size),offset,size))
    def file_at(rva,size):
        matches=[offset+rva-start for start,extent,offset,file_size in sections
            if start<=rva and rva+size<=start+file_size and size<=extent]
        require(len(matches)==1 and matches[0]+size<=len(raw),'bridge_pe_rva');return matches[0]
    def text(rva):
        at=file_at(rva,1);end=raw.find(b'\0',at,min(at+257,len(raw)))
        require(end>at,'bridge_pe_string');value=raw[at:end].decode('ascii','strict')
        require(all(32<=ord(ch)<127 for ch in value),'bridge_pe_ascii');return value
    export_rva,export_size=struct.unpack_from('<II',raw,optional+112)
    require(export_rva and export_size>=40,'bridge_pe_export_directory');at=file_at(export_rva,40)
    functions,names,functions_rva,names_rva,ordinals_rva=struct.unpack_from('<IIIII',raw,at+20)
    require(1<=names==functions<=128,'bridge_pe_export_count');exports=[]
    for index in range(names):
        name=text(struct.unpack_from('<I',raw,file_at(names_rva+index*4,4))[0]);ordinal=struct.unpack_from('<H',raw,file_at(ordinals_rva+index*2,2))[0]
        require(ordinal<functions,'bridge_pe_ordinal');function=struct.unpack_from('<I',raw,file_at(functions_rva+ordinal*4,4))[0]
        require(function and not export_rva<=function<export_rva+export_size,'bridge_no_forwarded_export');file_at(function,1);exports.append(name)
    import_rva,import_size=struct.unpack_from('<II',raw,optional+120);require(import_rva and 20<=import_size<=65536,'bridge_pe_import_directory')
    imports=[]
    for index in range(33):
        row=struct.unpack_from('<IIIII',raw,file_at(import_rva+index*20,20))
        if not any(row):break
        require(index<32 and row[3],'bridge_pe_import_bound');imports.append(text(row[3]))
    else:raise ValueError('bridge_pe_import_termination')
    require(len(imports)==len(set(x.casefold() for x in imports)) and len(exports)==len(set(exports)),'bridge_pe_duplicate_names')
    return sorted(imports,key=str.casefold),sorted(exports)

DEPENDENCY_NAMES={f'vendor/flatbuffers/include/flatbuffers/{name}.h' for name in (
    'allocator','array','base','buffer','buffer_ref','code_generator','code_generators','default_allocator','detached_buffer',
    'file_manager','flatbuffer_builder','flatbuffers','flatc','flex_flat_util','flexbuffers','grpc','hash','idl','minireflect',
    'reflection','reflection_generated','registry','stl_emulation','string','struct','table','util','vector','vector_downward','verifier')}
DEPENDENCY_NAMES.add('vendor/flatbuffers/LICENSE')

def verify_manifest(dll_path,manifest_path,dll_sha,manifest_sha,*,root):
    # Native source/dependency closure and exact import/export contract are
    # checked against the frozen build manifest before WinDLL is permitted.
    raw=local.bounded(launcher.checked_path(dll_path,inside=root),8*1024*1024)
    mr=local.bounded(launcher.checked_path(manifest_path,inside=root),256*1024)
    require(sha(raw)==dll_sha and sha(mr)==manifest_sha,'bridge_artifact_digest');pe_x64(raw,dll=True)
    m=decode(mr)
    require(type(m) is dict and set(m)=={'schema_version','stage','compile_only','runtime_acceptance','abi_version','spec_variant',
        'dll_sha256','dll_bytes','architecture','sources','dependencies','toolchain','imports','exports'}
        and type(m['schema_version']) is int and m['schema_version']==1 and m['stage']=='psec-lpac-identity-bridge-compile-only'
        and m['compile_only'] is True and m['runtime_acceptance'] is False and m['abi_version']==1 and type(m['abi_version']) is int
        and m['spec_variant']==VARIANT and m['dll_sha256']==dll_sha and m['dll_bytes']==len(raw) and type(m['dll_bytes']) is int
        and m['architecture']=='amd64','bridge_manifest')
    names={'.github/native/windows_psec_lpac_bridge'+suffix for suffix in ('.hpp','_core.hpp','_spec.hpp','.cpp')}
    names|={'vendor/windows-sdk/ProcessSecurityEnvironment.fbs','generated/ProcessSecurityEnvironment_generated.h'}
    require(type(m['sources']) is dict and set(m['sources'])==names and type(m['dependencies']) is dict
        and set(m['dependencies'])==DEPENDENCY_NAMES,'bridge_exact_pins')
    pins={**m['sources'],**m['dependencies']};require(len(pins)==37,'bridge_pin_alias')
    for name,digest in pins.items():
        require(type(name) is str and not name.startswith(('/','\\')) and '..' not in Path(name).parts and base.ac.digest(digest),'bridge_source_pin')
        require(sha(local.bounded(launcher.checked_path(root/name,inside=root),512*1024))==digest,'bridge_source_bytes')
    require(m.get('exports')==['pb_abi_version','pb_bind','pb_build_spec','pb_close_environment','pb_create_arm',
        'pb_create_environment','pb_unbind','pb_verify_spec'],'bridge_export_manifest')
    imports=m.get('imports');require(imports==['KERNEL32.dll'],'bridge_import_manifest')
    actual_imports,actual_exports=pe_linkage(raw);require(imports==actual_imports and m['exports']==actual_exports,'bridge_pe_linkage_binding')
    tool=m['toolchain'];require(type(tool) is dict and set(tool)=={'compiler','compiler_version','vc_tools_version','windows_sdk_version','runtime','architecture','flags'}
        and tool['compiler']=='MSVC' and tool['runtime']=='MT' and tool['architecture']=='amd64'
        and all(type(tool[k]) is str and 1<=len(tool[k])<=128 for k in tool if k!='flags')
        and type(tool['flags']) is list and 1<=len(tool['flags'])<=32 and '/MT' in tool['flags']
        and all(type(v) is str and 1<=len(v)<=128 for v in tool['flags']),'bridge_toolchain')
    return m

def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','variant',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name',
        'source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','dll_sha256','dll_manifest_sha256',
        'processmodel_sha256','spec_sha256','recovery_plan_sha256','capability_catalog'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1
        and c['scope']==SCOPE and c['variant']==VARIANT,'bridge_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and len({c[k] for k in NONCES})==3,'bridge_config_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'bridge_config_clock')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names)
        and all(base.ac.digest(v) for v in c['source_hashes'].values()) and sha(encode(c['source_hashes']))==c['source_sha256'],'bridge_config_sources')
    require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')),'bridge_config_digests')
    base.capability_catalog(c['capability_catalog']);return c

def validate_plan(p,*,device,source,actor,manifest,dll,dll_manifest,processmodel,inputs):
    keys={'schema_version','scope','variant',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','dll_sha256',
        'dll_manifest_sha256','processmodel_sha256','spec_sha256','never_resume_acknowledged','deny_all_not_proxy_acknowledged',
        'opaque_unknown_recovery_acknowledged','recovery_reference'}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1
        and p['scope']==SCOPE and p['variant']==VARIANT,'bridge_plan')
    require(all(base.ac.nonce(p[k]) for k in NONCES) and len({p[k] for k in NONCES})==3,'bridge_plan_nonces')
    for key,value in (('device',device),('source',source),('actor',actor),('manifest',manifest),('dll',dll),('dll_manifest',dll_manifest),('processmodel',processmodel)):
        require(base.ac.digest(value) and p[key+'_sha256']==value,'bridge_plan_commitment')
    require(p['spec_sha256']==sha(spec.build(str(inputs))) and all(p[k] is True for k in
        ('never_resume_acknowledged','deny_all_not_proxy_acknowledged','opaque_unknown_recovery_acknowledged'))
        and type(p['recovery_reference']) is str and 1<=len(p['recovery_reference'])<=512,'bridge_plan_acknowledgement')
    return p

class Bridge:
    """Real DLL adapter, constructed only by the already guarded worker."""
    def __init__(self,dll_path):
        abi_layout();self.memory=C.create_string_buffer(512+15)
        self.context=C.c_void_p((C.addressof(self.memory)+15)&~15)
        self.dll=C.WinDLL(str(dll_path),use_last_error=True,winmode=0x100|0x800)
        signatures={'pb_abi_version':[], 'pb_build_spec':[C.POINTER(C.c_uint16),C.c_uint32,C.POINTER(C.c_ubyte),C.c_uint32,C.POINTER(C.c_uint32)],
            'pb_verify_spec':[C.POINTER(C.c_ubyte),C.c_uint32,C.POINTER(C.c_uint16),C.c_uint32],
            'pb_bind':[C.c_void_p,C.POINTER(Plan),C.POINTER(Result)],
            'pb_create_environment':[C.c_void_p,C.POINTER(C.c_ubyte),C.c_uint32,C.POINTER(C.c_uint16),C.c_uint32,C.POINTER(Result)],
            'pb_create_arm':[C.c_void_p,C.POINTER(Child),C.POINTER(PI),C.POINTER(Result)],
            'pb_close_environment':[C.c_void_p,C.POINTER(Result)],'pb_unbind':[C.c_void_p,C.POINTER(Result)]}
        for name,args in signatures.items():
            function=getattr(self.dll,name);function.argtypes=args;function.restype=C.c_uint32
        require(self.dll.pb_abi_version()==1,'bridge_abi_version')
    @staticmethod
    def utf16(value):
        spec.path(value);raw=value.encode('utf-16-le');return (C.c_uint16*(len(raw)//2+1)).from_buffer_copy(raw+b'\0\0'),len(raw)//2
    def invoke(self,label,c,*,raw=None,inputs=None,child=None,pi=None):
        result=Result();result.size=96;result.version=1
        if label=='bind':
            plan=Plan(48,1,c['frequency'],c['start_qpc'],c['root_deadline_qpc'],c['deadline_qpc'],work_cutoff(c))
            status=self.dll.pb_bind(self.context,C.byref(plan),C.byref(result))
        elif label=='create':
            buffer=(C.c_ubyte*len(raw)).from_buffer_copy(raw);path,units=self.utf16(inputs)
            require(self.dll.pb_verify_spec(buffer,len(raw),path,units)==0,'native_spec_verify')
            status=self.dll.pb_create_environment(self.context,buffer,len(raw),path,units,C.byref(result))
        elif label in ('ac','lpac'):
            records={key:self.utf16(value) for key,value in child.items() if key!='job'}
            record=Child();record.size=88;record.version=1;record.policy=0 if label=='ac' else 1;record.job=child['job']
            for key,(value,units) in records.items():setattr(record,key,value);setattr(record,key+'_units',units)
            status=self.dll.pb_create_arm(self.context,C.byref(record),C.byref(pi),C.byref(result))
        else:status=getattr(self.dll,'pb_'+('close_environment' if label=='close' else 'unbind'))(self.context,C.byref(result))
        # Return the untouched ABI result and function status together. The
        # owner durably records both (and PI) before any semantic validation.
        return int(status),{name:int(getattr(result,name)) for name in RESULT_FIELDS}

class NativeAPI(base.LPACAPI):
    def bridge(self,path):return Bridge(path)
    def access_api(self):return access.NativeAPI()
    def processmodel_path(self):
        self.k.GetSystemDirectoryW.argtypes=[C.c_wchar_p,C.c_uint32];self.k.GetSystemDirectoryW.restype=C.c_uint32
        buffer=C.create_unicode_buffer(32768);n=self.k.GetSystemDirectoryW(buffer,len(buffer));require(0<n<len(buffer),'processmodel_system_directory')
        return launcher.checked_path(Path(buffer.value)/'processmodel.dll')

def native_ok(v):
    if not (v['wrapper_status']==0 and v['within_deadline']==1 and v['opaque_outcome_unknown']==0
            and v['api_entered']==v['api_returned']==1 and v['win32_error']==0):return False
    operation=v['operation']
    if operation==1:return v['hresult_valid']==1 and v['hresult']==0 and v['environment_state']==0 and bool(v['support_flags']&8) and v['schema_major_available']==1 and v['schema_minor']>=1
    if operation==2:return v['hresult_valid']==1 and v['hresult']==0 and v['environment_state']==2
    if operation==3:return v['hresult_valid']==0 and v['hresult']==0 and v['environment_state']==2
    if operation==4:return v['hresult_valid']==0 and v['environment_state']==3 and v['close_invoked_once']==v['close_returned_normally']==1
    if operation==5:return v['hresult_valid']==0 and v['module_close_attempted']==v['module_close_confirmed']==1
    return False

def opaque_return_known(label,status,value,c):
    """Only ownership knowledge; lateness cannot turn this into qualification."""
    try:
        v=validate_native(value,label,c)
        if type(status) is not int or status!=v['wrapper_status'] or v['opaque_outcome_unknown']:return False
        if label=='create':
            return bool(v['api_returned']==v['hresult_valid']==1 and (v['hresult']==0 and v['environment_state']==2
                or v['hresult']<0 and v['environment_state']==1)
                or v['api_entered']==v['api_returned']==v['hresult_valid']==0 and v['environment_state']==0)
        if label=='close':
            return bool(v['api_entered']==v['api_returned']==1 and v['hresult_valid']==0 and v['environment_state']==3
                and v['close_invoked_once']==v['close_returned_normally']==1
                or v['api_entered']==v['api_returned']==0 and v['environment_state']==2
                    and v['close_invoked_once']==v['close_returned_normally']==0)
    except BaseException:pass
    return False
def known_no_child(row,c):
    v=row.get('native');return bool(v is not None and v['api_entered']==v['api_returned']==1 and v['wrapper_status']==6
        and row.get('return_status')==v['wrapper_status']
        and v['win32_error']>0 and v['within_deadline']==1 and row['pi']==dict.fromkeys(('process','thread','process_id','thread_id'),0)
        and not any(row[k] for k in ('assigned','exited','admitted','resumed')) and row['pid'] is None and row['created'] is None)

class Cell:
    def __init__(self,root,c,parent,api,budget):
        self.root,self.c,self.parent,self.api,self.budget=root,c,parent,api,budget
        self.owners=helpers.OneShotHandles(api.close);self.jobowners=helpers.OneShotHandles(api.close)
        self.job=None;self.rows=[];self.bridge=None;self.phase='setup';self.operations=[]
        self.j=dict(schema_version=1,stage='cpse-matched-identity-result',scope=SCOPE,config_sha256=sha(encode(c)),failure=None,failure_detail=None,
            child_environment=launcher.default_child_environment(),common=None,intents=[],operations=self.operations,tasks=[],proofs=[],
            first_appcontainer_sid=None,common_inputs_verified=False,observer_resources_cleanup_verified=True,child_resources_cleanup=False,workload_cleanup=False,
            workload_job_empty=False,opaque_outcome_unknown=False,api_obligations_closed=False,module_unbound=False,
            actor_resumed=False,token_class46_queried=False,external_environment_absence_verified=False,broker_cancellation_proven=False,
            network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False)
    def intent(self,label):
        require(label in (*OPS,'observe-ac','observe-lpac','stop') and label not in [x['action'] for x in self.j['intents']],'bridge_intent_once')
        directory=self.root/'journal';directory.mkdir(exist_ok=True)
        raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),action=label,
            frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],qpc=self.budget.read()))
        name='%02d-%s.json'%(len(self.j['intents']),label);base.durable_private(directory/name,raw)
        self.j['intents'].append(dict(action=label,name=name,text=raw.decode('ascii'),sha256=sha(raw)))
    def call(self,label,**kwargs):
        self.intent(label);record=dict(label=label,return_status=None,native=None,receipt=None,exception=None);self.operations.append(record)
        try:
            status,value=self.bridge.invoke(label,self.c,**kwargs);record.update(return_status=status,native=value)
            # This is explicitly a returned raw observation, not qualification.
            # Keep the original status, every native scalar and every PI field
            # even when the following validator rejects their interpretation.
            intent=self.j['intents'][-1];pi=kwargs.get('pi')
            raw=encode(dict(schema_version=1,scope=SCOPE,run=self.c['run'],config_sha256=sha(encode(self.c)),action=label,
                intent_sha256=intent['sha256'],frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],
                return_status=status,native=value,pi=None if pi is None else {name:int(getattr(pi,name)) for name in ('process','thread','process_id','thread_id')}))
            directory=self.root/'receipts';directory.mkdir(exist_ok=True);name=intent['name'][:-5]+'-returned.json'
            base.durable_private(directory/name,raw);record['receipt']=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw))
            validate_native(value,label,self.c);require(type(status) is int and status==value['wrapper_status'],'bridge_status_binding')
            if value['opaque_outcome_unknown'] or label in ('create','close') and not opaque_return_known(label,status,value,self.c):
                self.j['opaque_outcome_unknown']=True
            return value
        except BaseException as error:
            record['exception']=base.private_failure_detail(error,label)
            if label in ('create','close'):
                if not opaque_return_known(label,record['return_status'],record['native'],self.c):self.j['opaque_outcome_unknown']=True
            raise
    def held(self,row):
        self.budget.require_ms(work_cutoff(self.c));process=row['info'].hProcess
        require(not self.api.wait(process,0) and self.api.process_id(process)==row['pid']
            and self.api.creation_time(process)==row['created'],'cpse_held_generation')
        self.api.verify_job(self.job,process);self.api.verify_outer(self.c['guard_job_name'],process)
        self.api.verify_image(process,self.root/'inputs'/live.ACTOR)
        require(sha(local.bounded(self.root/'inputs'/live.ACTOR,8*1024*1024))==self.c['actor_sha256'],'cpse_held_image')
        primary=identity.capture_primary(self.api,row['token'],self.parent,self.c['capability_catalog'],self.j['first_appcontainer_sid'],self.budget,work_cutoff(self.c))
        require(primary==row['expected_primary'],'cpse_primary_changed');row['held_checks'].append(self.budget.read());return primary
    def arm(self,role):
        self.phase='construct';self.budget.require_ms(work_cutoff(self.c));pi=PI();info=self.api.process_info()
        for prior in self.rows:self.held(prior)
        row=dict(name=role,info=info,token=None,attempted=True,assigned=False,exited=False,exit_code=None,pid=None,created=None,
            admitted=False,resumed=False,expected_primary=None,held_checks=[],pi=dict.fromkeys(('process','thread','process_id','thread_id'),0),return_status=None,native=None)
        self.rows.append(row)
        try:row['native']=self.call(role,child=self.child,pi=pi)
        finally:
            row['native']=next((op['native'] for op in reversed(self.operations) if op['label']==role),None)
            row['return_status']=next((op['return_status'] for op in reversed(self.operations) if op['label']==role),None)
            row['pi']={name:int(getattr(pi,name)) for name in ('process','thread','process_id','thread_id')}
            info.hProcess=pi.process;info.hThread=pi.thread;info.dwProcessId=pi.process_id;info.dwThreadId=pi.thread_id
            # Consume every known returned kernel handle before any validation.
            for handle in (pi.process,pi.thread):
                if handle:self.owners.add(handle)
            if pi.process_id:row['pid']=int(pi.process_id)
        require(native_ok(row['native']) and all(row['pi'].values()) and pi.process!=pi.thread,'cpse_arm_return')
        self.phase='admission';process=info.hProcess;row['created']=self.api.creation_time(process)
        self.api.verify_job(self.job,process);self.api.verify_outer(self.c['guard_job_name'],process);row['assigned']=True
        self.api.verify_image(process,self.root/'inputs'/live.ACTOR)
        row['token']=self.api.token_for_process(process);self.owners.add(row['token'])
        observed=self.api.identity(row['token'])
        if self.j['first_appcontainer_sid'] is None:
            require(role=='ac' and base.ac.ac_profile_sid(observed['appcontainer_sid']),'cpse_first_sid')
            self.j['first_appcontainer_sid']=observed['appcontainer_sid']
        row['expected_primary']=identity.capture_primary(self.api,row['token'],self.parent,self.c['capability_catalog'],self.j['first_appcontainer_sid'],self.budget,work_cutoff(self.c))
        self.held(row);row['admitted']=True;return row
    def execute(self):
        try:
            self.budget.require_ms(work_cutoff(self.c));require(base.fixed_catalog()==self.c['capability_catalog'],'cpse_worker_catalog')
            self.job=self.api.owned_job(self.jobowners)
            model=self.api.processmodel_path();require(sha(local.bounded(model,8*1024*1024))==self.c['processmodel_sha256'],'cpse_system_module')
            raw=local.bounded(self.root/'spec.bin',spec.MAX_BYTES);spec.verify(raw,str(self.root/'inputs'));require(sha(raw)==self.c['spec_sha256'],'cpse_spec_hash')
            local_path=self.api.local_appdata(self.budget,self.j['child_environment'])
            env=self.api.front_environment(local_path,self.j['child_environment']);require(launcher.child_environment_admitted(self.j['child_environment']),'cpse_environment')
            values=dict(value.split('=',1) for value in env.rstrip('\0').split('\0'));require(set(values)=={'SystemRoot','LOCALAPPDATA'},'cpse_environment_keys')
            self.child=dict(job=self.job,image=str(self.root/'inputs'/live.ACTOR),inputs_directory=str(self.root/'inputs'),system_root=values['SystemRoot'],local_appdata=values['LOCALAPPDATA'])
            self.j['common']=dict(actor_sha256=self.c['actor_sha256'],spec_sha256=self.c['spec_sha256'],environment_sha256=sha(env.encode('utf-16-le')),
                child=self.child,parent=self.parent,catalog=self.c['capability_catalog'],outer_job=self.c['guard_job_name'])
            self.bridge=self.api.bridge(self.root/'inputs'/DLL)
            self.phase='bind';v=self.call('bind');require(native_ok(v),'cpse_bind')
            self.phase='environment';v=self.call('create',raw=raw,inputs=str(self.root/'inputs'))
            self.j['opaque_outcome_unknown']=self.j['opaque_outcome_unknown'] or bool(v['opaque_outcome_unknown'])
            require(native_ok(v) and v['api_returned']==v['hresult_valid']==1 and v['hresult']==0 and v['environment_state']==2,'cpse_create')
            arms=[self.arm(role) for role in ('ac','lpac')]
            require(arms[0]['expected_primary']['authentication_id']==arms[1]['expected_primary']['authentication_id']
                and arms[0]['expected_primary']['token_id']!=arms[1]['expected_primary']['token_id'],'cpse_matched_authentication')
            self.j['common_inputs_verified']=True;self.phase='accesscheck';probe=self.api.access_api()
            for row in arms:
                for arm in arms:self.held(arm)
                self.intent('observe-'+row['name']);self.j['observer_resources_cleanup_verified']=False
                proof=access.observe_held(probe,row['info'].hProcess,row['expected_primary'],expected_pid=row['pid'],
                    expected_creation=row['created'],expected_role=row['name'],frequency=self.c['frequency'],deadline=work_cutoff(self.c))
                self.j['proofs'].append(proof);self.j['observer_resources_cleanup_verified']=all(p['resource_cleanup_verified'] for p in self.j['proofs'])
                for arm in arms:self.held(arm)
                require(proof['qualified'],'cpse_accesscheck_matrix')
        except BaseException as error:
            self.j['failure']=self.phase;self.j['failure_detail']=base.private_failure_detail(error)
        finally:self.cleanup()
        self.j['tasks']=[{k:v for k,v in row.items() if k not in ('info','token')} for row in self.rows]
        return self.j
    def cleanup(self):
        try:
            if any(row['info'].hProcess and not row['exited'] for row in self.rows):self.intent('stop')
            rows=[row for row in self.rows if not known_no_child(row,self.c)]
            clean,empty,_=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(12)),self.job,rows,self.owners)
            self.j.update(child_resources_cleanup=clean,workload_job_empty=empty)
        except BaseException:pass
        if self.bridge is not None:
            last=next((r['native'] for r in reversed(self.operations) if r['native'] is not None),None)
            if last is not None and last['opaque_outcome_unknown']:self.j['opaque_outcome_unknown']=True
            clean=self.j['child_resources_cleanup'] and self.j['workload_job_empty'] and self.j['observer_resources_cleanup_verified'] and not self.api.controls_uncertain
            if clean and not self.j['opaque_outcome_unknown']:
                try:
                    if last is not None and last['environment_state']==2:
                        # The opaque close authority is consumed in both the
                        # durable owner journal and native context before VOID.
                        v=self.call('close');require(v['close_invoked_once']==v['close_returned_normally']==1 and not v['opaque_outcome_unknown'],'cpse_close')
                        self.j['api_obligations_closed']=True
                        if not native_ok(v):self.j['failure']=self.j['failure'] or 'cleanup'
                    elif last is not None and last['environment_state'] in (0,1):
                        self.j['api_obligations_closed']=bool(last['environment_state']==0 or last['api_returned'] and last['hresult_valid'] and last['hresult']<0)
                    if self.j['api_obligations_closed']:
                        v=self.call('unbind');self.j['module_unbound']=bool(v['module_close_attempted'] and v['module_close_confirmed'] and not v['opaque_outcome_unknown'])
                        if not native_ok(v):self.j['failure']=self.j['failure'] or 'cleanup'
                except BaseException:pass
        elif not self.operations:
            self.j.update(api_obligations_closed=True,module_unbound=True)
        # The same Job remains held through native's independent empty check.
        # It is consumed exactly once after the opaque close/unbind attempt.
        jobclosed=True
        for handle in tuple(self.jobowners.pending):
            try:self.jobowners.close(handle)
            except BaseException:jobclosed=False
        self.j['workload_cleanup']=bool(self.j['child_resources_cleanup'] and jobclosed and self.jobowners.confirmed_closed)
        if not all(self.j[k] for k in ('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified','api_obligations_closed','module_unbound')):
            self.j['failure']=self.j['failure'] or 'cleanup'

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent) and budget.deadline==c['deadline_qpc'] and budget.frequency==c['frequency'],'cpse_parent_budget')
    return Cell(root,c,parent,api,budget).execute()

RESULT_BOOLS=('common_inputs_verified','observer_resources_cleanup_verified','child_resources_cleanup','workload_cleanup','workload_job_empty','opaque_outcome_unknown',
    'api_obligations_closed','module_unbound','actor_resumed','token_class46_queried','external_environment_absence_verified',
    'broker_cancellation_proven','network_tested','dns_tested','proxy_tested','product_acceptance')
RESULT_KEYS={'schema_version','stage','scope','config_sha256','failure','failure_detail','child_environment','common','intents','operations','tasks','proofs',
    'first_appcontainer_sid',*RESULT_BOOLS}
TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','admitted','resumed','expected_primary','held_checks','pi','return_status','native'}

def validate_result(j,c,*,parent):
    config_validate(c);require(launcher.token_is_ordinary(parent),'cpse_result_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='cpse-matched-identity-result' and j['scope']==SCOPE and j['config_sha256']==sha(encode(c))
        and j['failure'] in (None,'setup','bind','environment','construct','admission','accesscheck','cleanup'),'cpse_result')
    require(all(type(j[k]) is bool for k in RESULT_BOOLS),'cpse_result_booleans');base.validate_failure_detail(j['failure_detail'])
    require(j['failure'] is not None or j['failure_detail'] is None,'cpse_result_detail')
    require(not any(j[k] for k in ('actor_resumed','token_class46_queried','external_environment_absence_verified','broker_cancellation_proven',
        'network_tested','dns_tested','proxy_tested','product_acceptance')),'cpse_scope')
    launcher.validate_child_environment(j['child_environment'])
    require(j['first_appcontainer_sid'] is None or base.ac.ac_profile_sid(j['first_appcontainer_sid']),'cpse_result_sid')
    intents=j['intents'];require(type(intents) is list and len(intents)<=9,'cpse_intent_bound');actions=[];ticks={}
    last=c['start_qpc']
    for index,row in enumerate(intents):
        require(type(row) is dict and set(row)=={'action','name','text','sha256'} and row['action'] in (*OPS,'observe-ac','observe-lpac','stop')
            and row['action'] not in actions and row['name']=='%02d-%s.json'%(index,row['action'])
            and type(row['text']) is str and len(row['text'])<=4096 and sha(row['text'].encode('ascii'))==row['sha256'],'cpse_intent')
        value=decode(row['text'].encode('ascii'))
        require(type(value) is dict and set(value)=={'schema_version','scope','run','config_sha256','action','frequency','deadline_qpc','qpc'}
            and value==dict(schema_version=1,scope=SCOPE,run=c['run'],config_sha256=sha(encode(c)),action=row['action'],frequency=c['frequency'],
                deadline_qpc=c['deadline_qpc'],qpc=value['qpc']) and live.integer(value['qpc'],last,live.MAX_SIGNED),'cpse_intent_binding')
        last=value['qpc'];actions.append(row['action']);ticks[row['action']]=last
    operations=j['operations'];require(type(operations) is list and len(operations)<=6,'cpse_operations')
    labels=[];native={};statuses={}
    for row in operations:
        require(type(row) is dict and set(row)=={'label','return_status','native','receipt','exception'} and row['label'] in OPS
            and row['label'] in actions and row['label'] not in labels,'cpse_operation')
        labels.append(row['label']);base.validate_failure_detail(row['exception'])
        if row['native'] is not None:
            value=validate_native(row['native'],row['label'],c);native[row['label']]=value
            require(type(row['return_status']) is int and 0<=row['return_status']<=9,'cpse_function_status')
            statuses[row['label']]=row['return_status']
            require(row['exception'] is not None or row['return_status']==value['wrapper_status'],'cpse_function_status_binding')
            require(not value['within_deadline'] or value['before_qpc']>=ticks[row['label']],'cpse_call_after_intent')
        else:require(row['exception'] is not None and row['return_status'] is None,'cpse_missing_call_receipt')
        receipt=row['receipt']
        if receipt is not None:
            require(type(receipt) is dict and set(receipt)=={'name','text','sha256'} and type(receipt['text']) is str
                and len(receipt['text'])<=32768 and sha(receipt['text'].encode('ascii'))==receipt['sha256'],'cpse_returned_receipt')
            intent=next(intent for intent in intents if intent['action']==row['label']);raw=decode(receipt['text'].encode('ascii'))
            require(receipt['name']==intent['name'][:-5]+'-returned.json' and type(raw) is dict and set(raw)=={'schema_version','scope','run','config_sha256',
                'action','intent_sha256','frequency','deadline_qpc','return_status','native','pi'} and type(raw['schema_version']) is int and raw['schema_version']==1
                and raw['scope']==SCOPE and raw['run']==c['run'] and raw['config_sha256']==sha(encode(c)) and raw['action']==row['label']
                and raw['intent_sha256']==intent['sha256'] and raw['frequency']==c['frequency'] and raw['deadline_qpc']==c['deadline_qpc']
                and raw['return_status']==row['return_status'] and raw['native']==row['native'],'cpse_returned_receipt_binding')
            require(raw['pi'] is None if row['label'] not in ('ac','lpac') else type(raw['pi']) is dict,'cpse_returned_pi_kind')
        else:require(row['exception'] is not None,'cpse_missing_durable_return')
    # A validation/write exception after a structurally valid returned tuple
    # does not erase known S_OK-owned or normal VOID-return observations.
    opaque_sticky=any(row['native'] is not None and row['native']['opaque_outcome_unknown']
        or row['label'] in ('create','close') and not opaque_return_known(row['label'],row['return_status'],row['native'],c)
        for row in operations)
    require(not opaque_sticky or j['opaque_outcome_unknown'],'cpse_opaque_unknown_sticky')
    require(labels==[label for label in ('bind','create','ac','lpac','close','unbind') if label in labels],'cpse_operation_order')
    require('create' not in labels or 'bind' in native and native_ok(native['bind']),'cpse_create_bound')
    for role in ('ac','lpac'):
        require(role not in labels or 'create' in native and native_ok(native['create']) and native['create']['hresult_valid']==1
            and native['create']['hresult']==0 and native['create']['environment_state']==2,'cpse_arm_environment')
    require('lpac' not in labels or 'ac' in native and native_ok(native['ac']),'cpse_second_arm')
    tasks=j['tasks'];require(type(tasks) is list and len(tasks)<=2 and [r.get('name') for r in tasks]==['ac','lpac'][:len(tasks)],'cpse_task_order')
    for row in tasks:
        require(type(row) is dict and set(row)==TASK_KEYS and all(type(row[k]) is bool for k in ('attempted','assigned','exited','admitted','resumed'))
            and row['attempted'] and row['resumed'] is False and row['name'] in labels,'cpse_task_schema')
        role=row['name'];require(row['native']==native.get(role) and row['return_status']==statuses.get(role),'cpse_task_receipt')
        require(type(row['pi']) is dict and set(row['pi'])=={'process','thread','process_id','thread_id'}
            and all(live.integer(row['pi'][key],0,0xffffffffffffffff if key in ('process','thread') else 0xffffffff) for key in row['pi']),'cpse_task_pi')
        for key in ('pid','created','exit_code'):
            require(row[key] is None or live.integer(row[key],0 if key=='exit_code' else 1,0xffffffffffffffff if key=='created' else 0xffffffff),'cpse_task_number')
        op=next(op for op in operations if op['label']==role)
        if op['receipt'] is not None:require(decode(op['receipt']['text'].encode('ascii'))['pi']==row['pi'],'cpse_task_raw_pi_binding')
        require(row['pid']==(row['pi']['process_id'] or None),'cpse_task_pid')
        require(not row['exited'] or row['pi']['process'] and row['exit_code'] is not None,'cpse_exit_receipt')
        require(type(row['held_checks']) is list and len(row['held_checks'])<=16 and row['held_checks']==sorted(row['held_checks'])
            and all(live.integer(t,c['start_qpc'],work_cutoff(c)-1) for t in row['held_checks']),'cpse_held_checks')
        prior=row['expected_primary']
        if prior is not None:
            access.identity(prior,primary=True);live.capability_set(prior['capabilities'],'agentic-pncs',c['capability_catalog'])
            require(prior['sid']==parent['sid'] and prior['session_id']==parent['session_id'] and prior['appcontainer_sid']==j['first_appcontainer_sid']
                and prior['appcontainer'] and prior['integrity_rid']==4096 and not prior['elevated'] and not prior['ui_access'],'cpse_primary_binding')
        if row['admitted']:
            require(prior is not None and row['created'] is not None and row['assigned'] and row['held_checks'] and row['native'] is not None
                and native_ok(row['native']) and all(row['pi'].values()) and row['pi']['process']!=row['pi']['thread'],'cpse_task_admitted')
        if j['workload_cleanup']:require(known_no_child(row,c) or row['exited'],'cpse_clean_child')
    common=j['common']
    if common is not None:
        require(type(common) is dict and set(common)=={'actor_sha256','spec_sha256','environment_sha256','child','parent','catalog','outer_job'}
            and common['actor_sha256']==c['actor_sha256'] and common['spec_sha256']==c['spec_sha256']
            and base.ac.digest(common['environment_sha256']) and common['parent']==parent and common['catalog']==c['capability_catalog']
            and common['outer_job']==c['guard_job_name'] and launcher.child_environment_admitted(j['child_environment']),'cpse_common')
        child=common['child'];require(type(child) is dict and set(child)=={'job','image','inputs_directory','system_root','local_appdata'}
            and live.integer(child['job'],1,0xffffffffffffffff) and all(type(child[k]) is str for k in ('image','inputs_directory','system_root','local_appdata'))
            and Path(child['image']).name==live.ACTOR and Path(child['image']).parent==Path(child['inputs_directory']),'cpse_common_child')
    if j['common_inputs_verified']:
        require(common is not None and len(tasks)==2 and all(r['admitted'] for r in tasks) and tasks[0]['pid']!=tasks[1]['pid']
            and tasks[0]['expected_primary']['token_id']!=tasks[1]['expected_primary']['token_id']
            and tasks[0]['expected_primary']['authentication_id']==tasks[1]['expected_primary']['authentication_id'],'cpse_common_admission')
    proofs=j['proofs'];require(type(proofs) is list and len(proofs)<=2,'cpse_proofs')
    for proof,row in zip(proofs,tasks):
        require(j['common_inputs_verified'] and 'observe-'+row['name'] in actions,'cpse_observer_admission')
        access.validate_proof(proof,expected_primary_identity=row['expected_primary'],expected_role=row['name'],expected_pid=row['pid'],
            expected_creation=row['created'],frequency=c['frequency'],deadline=work_cutoff(c))
        require(proof['start_qpc']>=ticks['observe-'+row['name']],'cpse_observer_intent')
        if proof['qualified']:require(any(t<=proof['start_qpc'] for t in row['held_checks'])
            and any(t>=proof['end_qpc'] for t in row['held_checks']) and len(row['held_checks'])>=3,'cpse_observer_bracket')
    require(not j['observer_resources_cleanup_verified'] or len(proofs)==sum(a.startswith('observe-') for a in actions)
        and all(p['resource_cleanup_verified'] for p in proofs),'cpse_observer_cleanup')
    require(not j['workload_cleanup'] or j['child_resources_cleanup'] and j['workload_job_empty'],'cpse_cleanup_empty')
    if 'close' in labels:
        require(j['child_resources_cleanup'] and j['workload_job_empty'] and j['observer_resources_cleanup_verified'] and 'create' in native
            and native['create']['environment_state']==2,'cpse_close_order')
        require(not any(row['pi']['process'] and not row['exited'] for row in tasks),'cpse_close_live_child')
    if j['api_obligations_closed']:
        require(not j['opaque_outcome_unknown'] and ('close' in native and opaque_return_known('close',statuses['close'],native['close'],c)
            and native['close']['close_invoked_once']==native['close']['close_returned_normally']==1
            or 'close' not in labels and ('create' not in labels or 'create' in native and native['create']['api_returned']==native['create']['hresult_valid']==1
                and native['create']['hresult']<0 and native['create']['environment_state']==1 and not native['create']['opaque_outcome_unknown'])),'cpse_obligation_receipt')
    require(not j['module_unbound'] or j['api_obligations_closed'] and ('bind' not in labels or 'unbind' in native
        and native['unbind']['module_close_attempted']==native['unbind']['module_close_confirmed']==1),'cpse_unbind_receipt')
    if j['failure'] is None:
        require(j['common_inputs_verified'] and len(proofs)==2 and all(p['qualified'] for p in proofs)
            and all(j[k] for k in ('observer_resources_cleanup_verified','workload_cleanup','workload_job_empty','api_obligations_closed','module_unbound'))
            and not j['opaque_outcome_unknown'] and all(native_ok(v) for v in native.values()) and len(labels)==6,'cpse_complete')
        require(all(row['exception'] is None and row['receipt'] is not None for row in operations),'cpse_complete_returned_receipts')
    require(len(encode(j))<=MAX_REPORT,'cpse_result_bound');return j

def project(j,c,*,parent):
    validate_result(j,c,parent=parent)
    value={k:j[k] for k in ('failure','common_inputs_verified','observer_resources_cleanup_verified','workload_cleanup','workload_job_empty',
        'opaque_outcome_unknown','api_obligations_closed','module_unbound')}
    proofs={p['expected_role']:p for p in j['proofs']};tasks={r['name']:r for r in j['tasks']}
    for role in ('ac','lpac'):
        row=tasks.get(role);p=proofs.get(role)
        value[role+'_held_verified']=bool(row and row['admitted'])
        value[role+'_accesscheck_verified']=bool(p and p['qualified'])
        value[role+'_granted_access']=None if p is None or len(p['calls'])!=4 or not all(x['api_success'] for x in p['calls']) else [x['granted_access'] for x in p['calls']]
    value['inner_complete']=j['failure'] is None
    return value
