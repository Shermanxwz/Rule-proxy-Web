"""Three held CPSE actors with externally matched SC bytes. Import is API-free.

The C ABI owns one opaque environment in caller-owned aligned storage; Python
owns every returned kernel handle. Bootstrap and both arms never resume. A normal VOID
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
MODULE='.github/windows_identity_psec_lpac_matchedcaps_bridge.py'
LOCAL_MODULE='.github/windows_identity_psec_lpac_matchedcaps_bridge_local.py'
SOURCES=tuple(dict.fromkeys((*identity.SOURCES,'.github/windows_identity_psec_spec.py',MODULE,LOCAL_MODULE)))
SCOPE='one-local-cpse-deny-all-outer-guarded-matched-secaps-identity-v1'
CONSTRUCTOR_POLICY='bootstrap-held-primary-matched-security-capabilities-aap-only-v1'
VARIANT=spec.VARIANT
DLL='windows_psec_lpac_matchedcaps_bridge.dll'
DLL_MANIFEST='psec-lpac-matchedcaps-bridge-manifest.json'
NONCES=('run','bootstrap_nonce','ac_nonce','lpac_nonce')
MAX_REPORT=768*1024
# A candidate backend is present but is not promoted. This cannot bypass the explicit local flag,
# source/device/spec/artifact plan, held guard/worker or original QPC gates.
# Promotion and every real run remain the root operator's separate actions.
ACTUAL_READY=True

def api_version():return 3
def stage_name(run):return 'local-psec-lpac-matchedcaps-identity-'+run
def work_cutoff(c):return c['root_deadline_qpc']-35*c['frequency']

class Plan(C.Structure):
    _fields_=[('size',C.c_uint32),('version',C.c_uint32),*[(k,C.c_uint64) for k in
        ('frequency','start_qpc','root_deadline_qpc','worker_deadline_qpc','work_cutoff_qpc')]]
class Child(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ('size','version','policy','reserved')]+[('job',C.c_uint64)]+sum(
        ([(key,C.POINTER(C.c_uint16)),(key+'_units',C.c_uint32)] for key in ('image','inputs_directory','system_root','local_appdata')),[])
class PI(C.Structure):
    _fields_=[('process',C.c_uint64),('thread',C.c_uint64),('process_id',C.c_uint32),('thread_id',C.c_uint32)]
class SecurityCapabilities(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ('size','version','capability_count','reserved')]+[
        ('package_sid',C.POINTER(C.c_ubyte)),('package_bytes',C.c_uint32),('reserved2',C.c_uint32),
        ('agentic_sid',C.POINTER(C.c_ubyte)),('agentic_bytes',C.c_uint32),('agentic_attributes',C.c_uint32),
        ('pncs_sid',C.POINTER(C.c_ubyte)),('pncs_bytes',C.c_uint32),('pncs_attributes',C.c_uint32)]
class Result(C.Structure):
    _fields_=[(k,C.c_uint32) for k in ('size','version','operation','wrapper_status','api_entered','api_returned','hresult_valid')]+[
        ('hresult',C.c_int32),('win32_error',C.c_uint32),('within_deadline',C.c_uint32),('before_qpc',C.c_uint64),('after_qpc',C.c_uint64)]+[
        (k,C.c_uint32) for k in ('environment_state','opaque_outcome_unknown','close_invoked_once','close_returned_normally',
        'module_close_attempted','module_close_confirmed')]+[('support_flags',C.c_uint64),('schema_major_available',C.c_uint32),('schema_minor',C.c_uint32)]

RESULT_FIELDS=tuple(name for name,_ in Result._fields_)
NATIVE_RESULT_BOOLS=('api_entered','api_returned','hresult_valid','within_deadline','opaque_outcome_unknown',
    'close_invoked_once','close_returned_normally','module_close_attempted','module_close_confirmed','schema_major_available')
OPS={'bind':1,'create':2,'bootstrap':3,'ac':3,'lpac':3,'close':4,'unbind':5}
def abi_layout():
    require(C.sizeof(C.c_void_p)==8 and C.sizeof(Plan)==48 and C.sizeof(Child)==88 and C.sizeof(PI)==24 and C.sizeof(Result)==96
        and C.sizeof(SecurityCapabilities)==64,'bridge_layout')
    require(Child.job.offset==16 and Child.image.offset==24 and Child.local_appdata_units.offset==80
        and Result.before_qpc.offset==40 and Result.support_flags.offset==80 and SecurityCapabilities.package_sid.offset==16
        and SecurityCapabilities.agentic_sid.offset==32 and SecurityCapabilities.pncs_sid.offset==48,'bridge_offsets')
    return True

def validate_native(v,label,c):
    require(type(v) is dict and set(v)==set(RESULT_FIELDS),'bridge_result_schema')
    require(all(type(x) is int for x in v.values()) and v['size']==96 and v['version']==1
        and v['operation']==OPS[label] and 0<=v['wrapper_status']<=10,'bridge_result_header')
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
    require(v['wrapper_status']!=10 or label in ('bootstrap','ac','lpac') and v['api_entered']==v['api_returned']==v['hresult_valid']==0
        and v['environment_state']==2 and v['opaque_outcome_unknown']==0,'bridge_precreate_status_kind')
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
        'dll_sha256','dll_bytes','architecture','sources','dependencies','toolchain','imports','exports','constructor_policy'}
        and type(m['schema_version']) is int and m['schema_version']==1 and m['stage']=='psec-lpac-matchedcaps-bridge-compile-only'
        and m['compile_only'] is True and m['runtime_acceptance'] is False and m['abi_version']==3 and type(m['abi_version']) is int
        and m['constructor_policy']==CONSTRUCTOR_POLICY and m['spec_variant']==VARIANT and m['dll_sha256']==dll_sha and m['dll_bytes']==len(raw) and type(m['dll_bytes']) is int
        and m['architecture']=='amd64','bridge_manifest')
    names={'.github/native/windows_psec_lpac_matchedcaps_bridge'+suffix for suffix in ('.hpp','_core.hpp','.cpp')}
    names.add('.github/native/windows_psec_lpac_bridge_spec.hpp')
    names|={'vendor/windows-sdk/ProcessSecurityEnvironment.fbs','generated/ProcessSecurityEnvironment_generated.h'}
    require(type(m['sources']) is dict and set(m['sources'])==names and type(m['dependencies']) is dict
        and set(m['dependencies'])==DEPENDENCY_NAMES,'bridge_exact_pins')
    pins={**m['sources'],**m['dependencies']};require(len(pins)==37,'bridge_pin_alias')
    for name,digest in pins.items():
        require(type(name) is str and not name.startswith(('/','\\')) and '..' not in Path(name).parts and base.ac.digest(digest),'bridge_source_pin')
        require(sha(local.bounded(launcher.checked_path(root/name,inside=root),512*1024))==digest,'bridge_source_bytes')
    require(m.get('exports')==['pb_abi_version','pb_bind','pb_build_spec','pb_close_environment','pb_create_environment',
        'pb_create_matched_child','pb_unbind','pb_verify_spec'],'bridge_export_manifest')
    imports=m.get('imports');require(imports==['KERNEL32.dll'],'bridge_import_manifest')
    actual_imports,actual_exports=pe_linkage(raw);require(imports==actual_imports and m['exports']==actual_exports,'bridge_pe_linkage_binding')
    tool=m['toolchain'];require(type(tool) is dict and set(tool)=={'compiler','compiler_version','vc_tools_version','windows_sdk_version','runtime','architecture','flags'}
        and tool['compiler']=='MSVC' and tool['runtime']=='MT' and tool['architecture']=='amd64'
        and all(type(tool[k]) is str and 1<=len(tool[k])<=128 for k in tool if k!='flags')
        and type(tool['flags']) is list and 1<=len(tool['flags'])<=32 and '/MT' in tool['flags']
        and all(type(v) is str and 1<=len(v)<=128 for v in tool['flags']),'bridge_toolchain')
    return m

def config_validate(c,*,source_names=SOURCES):
    keys={'schema_version','scope','variant','constructor_policy',*NONCES,'frequency','start_qpc','root_deadline_qpc','deadline_qpc','guard_job_name',
        'source_hashes','source_sha256','device_sha256','actor_sha256','manifest_sha256','dll_sha256','dll_manifest_sha256',
        'processmodel_sha256','spec_sha256','recovery_plan_sha256','capability_catalog'}
    require(type(c) is dict and set(c)==keys and type(c['schema_version']) is int and c['schema_version']==1
        and c['scope']==SCOPE and c['variant']==VARIANT and c['constructor_policy']==CONSTRUCTOR_POLICY,'bridge_config')
    require(all(base.ac.nonce(c[k]) for k in NONCES) and len({c[k] for k in NONCES})==4,'bridge_config_nonces')
    live.clock_record(c['start_qpc'],c['frequency'],c['root_deadline_qpc'])
    require(c['root_deadline_qpc']==c['start_qpc']+120*c['frequency'] and c['deadline_qpc']==c['root_deadline_qpc']-5*c['frequency']
        and c['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+c['run'],'bridge_config_clock')
    require(type(c['source_hashes']) is dict and set(c['source_hashes'])==set(source_names)
        and all(base.ac.digest(v) for v in c['source_hashes'].values()) and sha(encode(c['source_hashes']))==c['source_sha256'],'bridge_config_sources')
    require(all(base.ac.digest(c[k]) for k in keys if k.endswith('_sha256')),'bridge_config_digests')
    base.capability_catalog(c['capability_catalog']);return c

def validate_plan(p,*,device,source,actor,manifest,dll,dll_manifest,processmodel,inputs):
    keys={'schema_version','scope','variant','constructor_policy',*NONCES,'device_sha256','source_sha256','actor_sha256','manifest_sha256','dll_sha256',
        'dll_manifest_sha256','processmodel_sha256','spec_sha256','never_resume_acknowledged','deny_all_not_proxy_acknowledged',
        'opaque_unknown_recovery_acknowledged','held_postassign_acknowledged','outer_guard_required_acknowledged','bootstrap_security_capabilities_acknowledged','same_security_capabilities_acknowledged','recovery_reference'}
    require(type(p) is dict and set(p)==keys and type(p['schema_version']) is int and p['schema_version']==1
        and p['scope']==SCOPE and p['variant']==VARIANT and p['constructor_policy']==CONSTRUCTOR_POLICY,'bridge_plan')
    require(all(base.ac.nonce(p[k]) for k in NONCES) and len({p[k] for k in NONCES})==4,'bridge_plan_nonces')
    for key,value in (('device',device),('source',source),('actor',actor),('manifest',manifest),('dll',dll),('dll_manifest',dll_manifest),('processmodel',processmodel)):
        require(base.ac.digest(value) and p[key+'_sha256']==value,'bridge_plan_commitment')
    require(p['spec_sha256']==sha(spec.build(str(inputs))) and all(p[k] is True for k in
        ('never_resume_acknowledged','deny_all_not_proxy_acknowledged','opaque_unknown_recovery_acknowledged','held_postassign_acknowledged','outer_guard_required_acknowledged','bootstrap_security_capabilities_acknowledged','same_security_capabilities_acknowledged'))
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
            'pb_create_matched_child':[C.c_void_p,C.POINTER(Child),C.c_uint32,C.POINTER(SecurityCapabilities),C.POINTER(PI),C.POINTER(Result)],
            'pb_close_environment':[C.c_void_p,C.POINTER(Result)],'pb_unbind':[C.c_void_p,C.POINTER(Result)]}
        for name,args in signatures.items():
            function=getattr(self.dll,name);function.argtypes=args;function.restype=C.c_uint32
        require(self.dll.pb_abi_version()==3,'bridge_abi_version')
    @staticmethod
    def utf16(value):
        spec.path(value);raw=value.encode('utf-16-le');return (C.c_uint16*(len(raw)//2+1)).from_buffer_copy(raw+b'\0\0'),len(raw)//2
    def invoke(self,label,c,*,raw=None,inputs=None,child=None,pi=None,security_capabilities=None):
        result=Result();result.size=96;result.version=1
        if label=='bind':
            plan=Plan(48,1,c['frequency'],c['start_qpc'],c['root_deadline_qpc'],c['deadline_qpc'],work_cutoff(c))
            status=self.dll.pb_bind(self.context,C.byref(plan),C.byref(result))
        elif label=='create':
            buffer=(C.c_ubyte*len(raw)).from_buffer_copy(raw);path,units=self.utf16(inputs)
            require(self.dll.pb_verify_spec(buffer,len(raw),path,units)==0,'native_spec_verify')
            status=self.dll.pb_create_environment(self.context,buffer,len(raw),path,units,C.byref(result))
        elif label in ('bootstrap','ac','lpac'):
            records={key:self.utf16(value) for key,value in child.items() if key!='job'}
            record=Child();record.size=88;record.version=1;record.policy=1 if label=='lpac' else 0;record.job=child['job']
            for key,(value,units) in records.items():setattr(record,key,value);setattr(record,key+'_units',units)
            # Buffer lifetimes cover the complete potentially blocking create.
            # A bootstrap must never receive this second identity input.
            sc=None;buffers=None
            if label=='bootstrap':require(security_capabilities is None,'bridge_bootstrap_no_security_capabilities')
            else:
                sc,buffers=security_capabilities_record(security_capabilities,c['capability_catalog'])
            status=self.dll.pb_create_matched_child(self.context,C.byref(record),{'bootstrap':0,'ac':1,'lpac':2}[label],
                None if sc is None else C.byref(sc),C.byref(pi),C.byref(result))
        else:status=getattr(self.dll,'pb_'+('close_environment' if label=='close' else 'unbind'))(self.context,C.byref(result))
        # Return the untouched ABI result and function status together. The
        # owner durably records both (and PI) before any semantic validation.
        return int(status),{name:int(getattr(result,name)) for name in RESULT_FIELDS}

def sid_bytes(value):
    """Canonical SID encoding, with no ConvertStringSid or native allocation."""
    require(type(value) is str and value.startswith('S-1-'),'secaps_sid_text')
    parts=value.split('-');require(4<=len(parts)<=18 and parts[:2]==['S','1'],'secaps_sid_parts')
    require(all(part.isascii() and part.isdecimal() and str(int(part))==part for part in parts[2:]),'secaps_sid_canonical')
    numbers=[int(part) for part in parts[2:]];authority,*sub=numbers
    require(0<=authority<(1<<48) and 1<=len(sub)<=15 and all(0<=x<1<<32 for x in sub),'secaps_sid_range')
    return bytes((1,len(sub)))+authority.to_bytes(6,'big')+struct.pack('<'+'I'*len(sub),*sub)

def security_capabilities_value(primary,catalog):
    access.identity(primary,primary=True);base.capability_catalog(catalog)
    live.capability_set(primary['capabilities'],'agentic-pncs',catalog)
    require(base.ac.ac_profile_sid(primary['appcontainer_sid']),'secaps_package_sid')
    return dict(schema_version=3,package_sid=sid_bytes(primary['appcontainer_sid']).hex(),
        agentic_sid=sid_bytes(catalog['AgenticAppContainer']).hex(),pncs_sid=sid_bytes(catalog['privateNetworkClientServer']).hex(),
        agentic_attributes=4,pncs_attributes=4)

def validate_security_capabilities(value,catalog):
    require(type(value) is dict and set(value)=={'schema_version','package_sid','agentic_sid','pncs_sid','agentic_attributes','pncs_attributes'}
        and type(value['schema_version']) is int and value['schema_version']==3
        and type(value['agentic_attributes']) is type(value['pncs_attributes']) is int
        and value['agentic_attributes']==value['pncs_attributes']==4,'secaps_schema')
    base.capability_catalog(catalog)
    for key in ('package_sid','agentic_sid','pncs_sid'):
        text=value[key];require(type(text) is str and 24<=len(text)<=136 and len(text)%2==0
            and all(ch in '0123456789abcdef' for ch in text),'secaps_sid_hex')
        raw=bytes.fromhex(text);require(raw[0]==1 and 1<=raw[1]<=15 and len(raw)==8+4*raw[1],'secaps_sid_binary')
        authority=int.from_bytes(raw[2:8],'big');sub=struct.unpack('<'+'I'*raw[1],raw[8:])
        canonical='S-1-'+str(authority)+''.join('-'+str(x) for x in sub)
        require(sid_bytes(canonical)==raw,'secaps_sid_roundtrip')
        require(base.ac.ac_profile_sid(canonical) if key=='package_sid' else raw==sid_bytes(catalog[
            'AgenticAppContainer' if key=='agentic_sid' else 'privateNetworkClientServer']),'secaps_fixed_sid')
    return value

def security_capabilities_bytes(value,catalog):
    validate_security_capabilities(value,catalog)
    package,agentic,pncs=(bytes.fromhex(value[k]) for k in ('package_sid','agentic_sid','pncs_sid'))
    # Pointer-free commitment to every SID byte and both exact attributes.
    return b'SCI3'+struct.pack('<IIIII',len(package),len(agentic),4,len(pncs),4)+package+agentic+pncs

def security_capabilities_record(value,catalog):
    validate_security_capabilities(value,catalog)
    buffers={k:(C.c_ubyte*(len(value[k])//2)).from_buffer_copy(bytes.fromhex(value[k]))
        for k in ('package_sid','agentic_sid','pncs_sid')}
    record=SecurityCapabilities();record.size=64;record.version=3;record.capability_count=2
    for key,buffer in buffers.items():setattr(record,key,buffer);setattr(record,key.replace('_sid','_bytes'),len(buffer))
    record.agentic_attributes=record.pncs_attributes=4
    return record,buffers

def security_capabilities_blank():
    return dict(value=None,raw_sha256=None,receipt=None,decision_qpc=None,exception=None)

def security_capabilities_binding(state,j,c):
    bootstrap=j['tasks'][0];operation=next(op for op in j['operations'] if op['label']=='bootstrap')
    require(bootstrap['admitted'] and operation['receipt'] is not None,'secaps_bootstrap_admitted')
    value=state['value'];raw=security_capabilities_bytes(value,c['capability_catalog'])
    return dict(schema_version=1,stage='cpse-matched-security-capabilities-from-held-bootstrap',scope=SCOPE,
        constructor_policy=CONSTRUCTOR_POLICY,run=c['run'],config_sha256=sha(encode(c)),source_sha256=c['source_sha256'],
        actor_sha256=c['actor_sha256'],bootstrap_pid=bootstrap['pid'],bootstrap_created=bootstrap['created'],
        bootstrap_pi_receipt_sha256=operation['receipt']['sha256'],bootstrap_primary=bootstrap['expected_primary'],
        frequency=c['frequency'],root_deadline_qpc=c['root_deadline_qpc'],deadline_qpc=c['deadline_qpc'],
        work_cutoff_qpc=work_cutoff(c),value=value,raw_hex=raw.hex(),raw_sha256=sha(raw))

def validate_security_capabilities_state(state,j,c):
    require(type(state) is dict and set(state)==set(security_capabilities_blank()),'secaps_state_schema')
    base.validate_failure_detail(state['exception'])
    require(state['decision_qpc'] is None or live.integer(state['decision_qpc'],c['start_qpc'],live.MAX_SIGNED),'secaps_state_clock')
    if state['value'] is not None:
        validate_security_capabilities(state['value'],c['capability_catalog'])
        require(j['tasks'] and j['tasks'][0]['admitted'] and state['value']==security_capabilities_value(
            j['tasks'][0]['expected_primary'],c['capability_catalog']),'secaps_external_primary_binding')
        require(state['raw_sha256']==sha(security_capabilities_bytes(state['value'],c['capability_catalog'])),'secaps_raw_digest')
    else:require(state['raw_sha256'] is None and state['receipt'] is None and state['decision_qpc'] is None,'secaps_absent')
    if state['receipt'] is not None:
        value=receipt_value(state['receipt'],'held-bootstrap.json',16384)
        require(type(value) is dict and set(value)==set(security_capabilities_binding(state,j,c))|
            {'bootstrap_held_check_qpc','bootstrap_job_receipt_sha256'},'secaps_receipt_schema')
        expected=security_capabilities_binding(state,j,c)
        require(all(value[k]==v for k,v in expected.items()),'secaps_receipt_binding')
        bootstrap=j['tasks'][0]
        require(value['bootstrap_held_check_qpc'] in bootstrap['held_checks']
            and any(entry['receipt'] is not None and entry['receipt']['sha256']==value['bootstrap_job_receipt_sha256']
                and job_admission_passed(entry,bootstrap,c) and entry['purpose']=='held'
                and entry['decision_qpc']<=value['bootstrap_held_check_qpc'] for entry in bootstrap['job_admissions']),
            'secaps_held_bootstrap_receipt')
        require(state['decision_qpc'] is None or state['decision_qpc']>=value['bootstrap_held_check_qpc'],'secaps_decision_order')
    elif state['value'] is not None:require(state['exception'] is not None,'secaps_missing_receipt')
    if state['decision_qpc'] is not None:require(state['receipt'] is not None,'secaps_decision_receipt')
    return state

def security_capabilities_passed(state,j,c):
    return bool(state['exception'] is None and state['value'] is not None and state['receipt'] is not None
        and type(state['decision_qpc']) is int and c['start_qpc']<=state['decision_qpc']<work_cutoff(c))

class NativeAPI(base.LPACAPI):
    def bridge(self,path):return Bridge(path)
    def access_api(self):return access.NativeAPI()
    def assign_inner_once(self,process,inner_job,budget,cutoff):
        """One explicit assignment of the original returned process handle.

        The caller must have durably admitted the outer-only pretransfer
        observation. No process reopening, retry or privilege fallback exists.
        Preserve the raw return even when the subsequent clock read fails.
        """
        value=assign_blank()
        self.k.AssignProcessToJobObject.argtypes=[C.c_void_p,C.c_void_p]
        self.k.AssignProcessToJobObject.restype=C.c_int
        try:
            value['before_qpc']=budget.read();budget.require_ms(cutoff)
            value['attempted']=True;C.set_last_error(0)
            returned=self.k.AssignProcessToJobObject(inner_job,process)
            error=C.get_last_error()
            value.update(returned=True,return_value=int(returned),api_success=bool(returned),win32_error=0 if returned else int(error))
            value['after_qpc']=budget.read()
            value['within_deadline']=value['before_qpc']<=value['after_qpc']<cutoff
        except BaseException as error:
            value['exception']=base.private_failure_detail(error,'AssignProcessToJobObject(exact-inner)')
        return value
    def query_exact_jobs(self,process,inner_job,outer_name,budget,cutoff,*,protected_handles):
        """Two read-only queries, even when one API returns known false.

        A fresh scoped handle ledger permits legal numeric HANDLE reuse across
        later queries. No assignment, token lookup, resume or fallback occurs.
        """
        protected=sorted(set(int(value) for value in protected_handles))
        require(len(protected)<=32 and all(0<value<(1<<64)-1 for value in protected)
            and int(process) in protected and int(inner_job) in protected,'cpse_job_protected_handles')
        result=job_query_blank(process,inner_job,outer_name,budget.frequency,budget.deadline,cutoff,protected)
        resource=result['outer_resource'];owners=None
        self.k.IsProcessInJob.argtypes=[C.c_void_p,C.c_void_p,C.POINTER(C.c_int)];self.k.IsProcessInJob.restype=C.c_int
        self.k.CloseHandle.argtypes=[C.c_void_p];self.k.CloseHandle.restype=C.c_int
        def stamp(row,key):
            value=budget.read();row[key]=value
            require(value<cutoff,'cpse_job_query_deadline');return value
        def query(job,row):
            try:
                stamp(row,'before_qpc');value=C.c_int(-1)
                row['attempted']=True;C.set_last_error(0)
                returned=self.k.IsProcessInJob(process,job,C.byref(value))
                error=C.get_last_error()  # Immediate: before output reads or QPC.
                row.update(returned=True,api_success=bool(returned),win32_error=0 if returned else int(error))
                if returned:
                    require(value.value in (0,1),'cpse_job_membership_output')
                    row['membership']=bool(value.value)
                stamp(row,'after_qpc');row['within_deadline']=True
            except BaseException as error:row['exception']=base.private_failure_detail(error,'IsProcessInJob(exact)')
        # The borrowed owned inner handle is never closed by this observation.
        query(inner_job,result['inner'])
        try:
            stamp(resource,'open_before_qpc')
            self.k.OpenJobObjectW.argtypes=[C.c_uint32,C.c_int,C.c_wchar_p];self.k.OpenJobObjectW.restype=C.c_void_p
            resource['open_attempted']=True;C.set_last_error(0)
            value=self.k.OpenJobObjectW(0x0004,False,outer_name)
            error=C.get_last_error()  # Immediate: query-only open has separate failure facts.
            resource.update(open_returned=True,handle_value=int(value) if value else None,open_win32_error=0 if value else int(error))
            if value:
                require(type(value) is int and 0<value<(1<<64)-1,'cpse_outer_query_handle')
                if value in protected:
                    resource['alias']=resource['close_uncertain']=True
                    raise ValueError('cpse_outer_query_alias')
                def close_query(handle):
                    resource['close_attempted']=True
                    try:resource['close_before_qpc']=budget.read()
                    except BaseException:pass  # Known handle must still be consumed once.
                    C.set_last_error(0);returned=self.k.CloseHandle(handle)
                    close_error=C.get_last_error()  # Immediate, independent of the membership result.
                    resource.update(close_returned=True,close_api_success=bool(returned),close_win32_error=0 if returned else int(close_error))
                    require(bool(returned),'cpse_outer_query_close_failed')
                owners=helpers.OneShotHandles(close_query);owners.add(value)
            stamp(resource,'open_after_qpc');resource['open_within_deadline']=True
            if value:query(value,result['outer'])
        except BaseException as error:resource['exception']=base.private_failure_detail(error,'OpenJobObjectW(exact-query)')
        finally:
            if resource['open_attempted'] and not resource['open_returned']:resource['close_uncertain']=True
            if resource['handle_value'] is not None and owners is None:resource['close_uncertain']=True
            if owners is not None:
                for handle in tuple(owners.pending):
                    try:owners.close(handle)
                    except BaseException as error:
                        resource['close_uncertain']=True
                        resource['exception']=base.private_failure_detail(error,'CloseHandle(exact-query)')
                    finally:
                        try:
                            resource['close_after_qpc']=budget.read()
                            resource['close_within_deadline']=bool(resource['close_before_qpc'] is not None and
                                budget.deadline-115*budget.frequency<=resource['close_before_qpc']<=resource['close_after_qpc']<cutoff)
                        except BaseException:pass
                if not owners.confirmed_closed:resource['close_uncertain']=True
            if resource['close_uncertain'] or resource['alias']:
                self.controls_uncertain=True
                launcher._RETAINED_SCOPED_OWNERS.append((self,owners,'exact_outer_query_unknown'))
        result['resource_cleanup_verified']=job_resource_clean(resource)
        return result
    def processmodel_path(self):
        self.k.GetSystemDirectoryW.argtypes=[C.c_wchar_p,C.c_uint32];self.k.GetSystemDirectoryW.restype=C.c_uint32
        buffer=C.create_unicode_buffer(32768);n=self.k.GetSystemDirectoryW(buffer,len(buffer));require(0<n<len(buffer),'processmodel_system_directory')
        return launcher.checked_path(Path(buffer.value)/'processmodel.dll')


JOB_QUERY_KEYS=('attempted','returned','api_success','membership','win32_error','before_qpc','after_qpc','within_deadline','exception')
JOB_RESOURCE_KEYS=('open_attempted','open_returned','handle_value','open_win32_error','open_before_qpc','open_after_qpc','open_within_deadline',
    'close_attempted','close_returned','close_api_success','close_win32_error','close_before_qpc','close_after_qpc','close_within_deadline','close_uncertain','alias','exception')
def job_query_blank(process,inner,outer,frequency,deadline,cutoff,protected=()):
    def row():return dict(attempted=False,returned=False,api_success=None,membership=None,win32_error=None,
        before_qpc=None,after_qpc=None,within_deadline=False,exception=None)
    return dict(schema_version=1,process=int(process),inner_job=int(inner),outer_job=outer,frequency=frequency,deadline_qpc=deadline,
        work_cutoff_qpc=cutoff,protected_handles=list(protected),inner=row(),outer=row(),outer_resource=dict(open_attempted=False,open_returned=False,handle_value=None,
            open_win32_error=None,open_before_qpc=None,open_after_qpc=None,open_within_deadline=False,close_attempted=False,
            close_returned=False,close_api_success=None,close_win32_error=None,close_before_qpc=None,close_after_qpc=None,
            close_within_deadline=False,close_uncertain=False,alias=False,exception=None),resource_cleanup_verified=True)

def job_resource_clean(v):
    return bool(not v['close_uncertain'] and not v['alias'] and (not v['open_attempted'] or v['open_returned'])
        and (v['handle_value'] is None or v['close_attempted'] and v['close_returned'] and v['close_api_success'] is True))

def job_query_passed(v):
    return bool(v is not None and v['resource_cleanup_verified'] and all(v[key]['attempted'] and v[key]['returned']
        and v[key]['api_success'] is True and v[key]['membership'] is True and v[key]['win32_error']==0
        and v[key]['within_deadline'] and v[key]['exception'] is None for key in ('inner','outer'))
        and v['outer_resource']['open_within_deadline'] and v['outer_resource']['close_within_deadline']
        and v['outer_resource']['exception'] is None)

def outer_only_query_passed(v):
    if v is None or not v['resource_cleanup_verified']:return False
    return bool(all(v[key]['attempted'] and v[key]['returned'] and v[key]['api_success'] is True
        and v[key]['membership'] is expected and v[key]['win32_error']==0 and v[key]['within_deadline']
        and v[key]['exception'] is None for key,expected in (('inner',False),('outer',True)))
        and v['outer_resource']['open_within_deadline'] and v['outer_resource']['close_within_deadline']
        and v['outer_resource']['exception'] is None)

def assign_blank():
    return dict(attempted=False,returned=False,return_value=None,api_success=None,win32_error=None,before_qpc=None,after_qpc=None,
        within_deadline=False,exception=None)

def validate_assign(value,c):
    require(type(value) is dict and set(value)==set(assign_blank()),'postassign_raw_schema')
    require(all(type(value[k]) is bool for k in ('attempted','returned','within_deadline'))
        and (value['api_success'] is None or type(value['api_success']) is bool),'postassign_raw_types')
    require(value['win32_error'] is None or live.integer(value['win32_error']),'postassign_raw_error')
    require(not value['returned'] or value['attempted'] and type(value['return_value']) is int
        and -(1<<31)<=value['return_value']<(1<<31) and value['api_success'] is bool(value['return_value'])
        and type(value['win32_error']) is int and (not value['api_success'] or value['win32_error']==0),'postassign_raw_return')
    require(value['returned'] or value['return_value'] is value['api_success'] is value['win32_error'] is None,'postassign_unreturned_output')
    for key in ('before_qpc','after_qpc'):
        require(value[key] is None or live.integer(value[key],c['start_qpc'],live.MAX_SIGNED),'postassign_raw_tick')
    require(not value['within_deadline'] or value['before_qpc'] is not None and value['after_qpc'] is not None
        and value['before_qpc']<=value['after_qpc']<work_cutoff(c),'postassign_raw_clock')
    base.validate_failure_detail(value['exception']);return value

def transfer_blank():
    return dict(guard=None,intent=None,raw=None,receipt=None,decision_qpc=None,exception=None)

def guard_passed(entry,row,c):
    return bool(entry is not None and entry['receipt'] is not None and entry['exception'] is None
        and generation_passed(entry['before'],row,c) and generation_passed(entry['after'],row,c)
        and outer_only_query_passed(entry['query']) and type(entry['decision_qpc']) is int
        and entry['after']['after_qpc']<=entry['decision_qpc']<work_cutoff(c))

def transfer_passed(value,row,c):
    raw=value['raw']
    return bool(value['exception'] is None and guard_passed(value['guard'],row,c) and value['intent'] is not None
        and value['receipt'] is not None and raw is not None and raw['attempted'] and raw['returned']
        and raw['api_success'] is True and raw['win32_error']==0 and raw['within_deadline'] and raw['exception'] is None
        and type(value['decision_qpc']) is int and raw['after_qpc']<=value['decision_qpc']<work_cutoff(c))

def validate_job_query(v,c,*,process,inner):
    template=job_query_blank(process,inner,c['guard_job_name'],c['frequency'],c['deadline_qpc'],work_cutoff(c))
    require(type(v) is dict and set(v)==set(template),'cpse_job_query_schema')
    for key in ('schema_version','process','inner_job','outer_job','frequency','deadline_qpc','work_cutoff_qpc'):
        require(type(v[key]) is type(template[key]) and v[key]==template[key],'cpse_job_query_binding')
    require(type(v['protected_handles']) is list and len(v['protected_handles'])<=32
        and all(live.integer(h,1,(1<<64)-2) for h in v['protected_handles'])
        and v['protected_handles']==sorted(set(v['protected_handles']))
        and process in v['protected_handles'] and inner in v['protected_handles'],'cpse_job_query_protected_handles')
    def clock(row,prefix='',flag='within_deadline'):
        before,after=row[prefix+'before_qpc'],row[prefix+'after_qpc']
        for tick in (before,after):require(tick is None or live.integer(tick,1,live.MAX_SIGNED),'cpse_job_query_tick')
        require(type(row[flag]) is bool and (not row[flag] or before is not None and after is not None
            and c['start_qpc']<=before<=after<work_cutoff(c)),'cpse_job_query_clock')
    for key in ('inner','outer'):
        row=v[key];require(type(row) is dict and set(row)==set(JOB_QUERY_KEYS),'cpse_job_query_call_schema')
        require(all(type(row[k]) is bool for k in ('attempted','returned','within_deadline'))
            and all(row[k] is None or type(row[k]) is bool for k in ('api_success','membership')),'cpse_job_query_call_types')
        require(row['win32_error'] is None or live.integer(row['win32_error']),'cpse_job_query_error')
        require(not row['returned'] or row['attempted'] and type(row['api_success']) is bool
            and ((type(row['membership']) is bool or row['membership'] is None and row['exception'] is not None)
                and row['win32_error']==0 if row['api_success'] else row['membership'] is None and type(row['win32_error']) is int),'cpse_job_query_api_vs_membership')
        require(row['returned'] or row['api_success'] is row['membership'] is row['win32_error'] is None,'cpse_job_query_unreturned_output')
        base.validate_failure_detail(row['exception']);clock(row)
    r=v['outer_resource'];require(type(r) is dict and set(r)==set(JOB_RESOURCE_KEYS),'cpse_job_resource_schema')
    require(all(type(r[k]) is bool for k in ('open_attempted','open_returned','open_within_deadline','close_attempted','close_returned',
        'close_within_deadline','close_uncertain','alias')) and (r['close_api_success'] is None or type(r['close_api_success']) is bool),'cpse_job_resource_types')
    require(r['handle_value'] is None or live.integer(r['handle_value'],1,(1<<64)-1),'cpse_job_resource_handle')
    require(r['alias']==(r['handle_value'] is not None and r['handle_value'] in v['protected_handles']),'cpse_job_resource_alias')
    require(all(r[k] is None or live.integer(r[k]) for k in ('open_win32_error','close_win32_error')),'cpse_job_resource_error')
    require(not r['open_returned'] or r['open_attempted'] and type(r['open_win32_error']) is int,'cpse_job_open_return')
    require(r['open_returned'] or r['handle_value'] is r['open_win32_error'] is None,'cpse_job_open_unknown')
    require(not r['close_attempted'] or r['handle_value'] is not None and not r['alias'],'cpse_job_close_authority')
    require(not r['close_returned'] or r['close_attempted'] and type(r['close_api_success']) is bool
        and type(r['close_win32_error']) is int and (not r['close_api_success'] or r['close_win32_error']==0),'cpse_job_close_return')
    require(r['close_returned'] or r['close_api_success'] is r['close_win32_error'] is None,'cpse_job_close_unknown')
    require(not (r['open_attempted'] and not r['open_returned'] or r['alias'] or r['close_attempted'] and not r['close_api_success'])
        or r['close_uncertain'],'cpse_job_resource_unknown_sticky')
    require(not v['outer']['attempted'] or r['handle_value'] is not None and r['open_returned'] and not r['alias'],'cpse_job_outer_handle_bound')
    base.validate_failure_detail(r['exception']);clock(r,'open_','open_within_deadline');clock(r,'close_','close_within_deadline')
    require(type(v['resource_cleanup_verified']) is bool and v['resource_cleanup_verified']==job_resource_clean(r),'cpse_job_resource_cleanup')
    return v


GENERATION_KEYS={'before_qpc','after_qpc','within_deadline','alive','pid','created','image_verified','exception'}
def validate_generation(v,c):
    require(type(v) is dict and set(v)==GENERATION_KEYS and type(v['within_deadline']) is bool
        and type(v['image_verified']) is bool and (v['alive'] is None or type(v['alive']) is bool),'cpse_job_generation_schema')
    require(v['pid'] is None or live.integer(v['pid'],1),'cpse_job_generation_pid')
    require(v['created'] is None or live.integer(v['created'],1,(1<<64)-1),'cpse_job_generation_created')
    for key in ('before_qpc','after_qpc'):require(v[key] is None or live.integer(v[key],1,live.MAX_SIGNED),'cpse_job_generation_tick')
    require(not v['within_deadline'] or v['before_qpc'] is not None and v['after_qpc'] is not None
        and c['start_qpc']<=v['before_qpc']<=v['after_qpc']<work_cutoff(c),'cpse_job_generation_clock')
    base.validate_failure_detail(v['exception']);return v

def generation_passed(v,row,c):
    return bool(v is not None and v['within_deadline'] and v['alive'] is True and v['pid']==row['pid']
        and v['created']==row['created'] and v['image_verified'] and v['exception'] is None)

def job_admission_value(entry,row,c,inner,pi_receipt_sha256):
    return dict(schema_version=1,stage='cpse-exact-job-admission-observation',scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,run=c['run'],config_sha256=sha(encode(c)),
        source_sha256=c['source_sha256'],role=row['name'],sequence=entry['sequence'],purpose=entry['purpose'],
        process=row['pi']['process'],pid=row['pid'],created=row['created'],pi_receipt_sha256=pi_receipt_sha256,actor_sha256=c['actor_sha256'],
        frequency=c['frequency'],root_deadline_qpc=c['root_deadline_qpc'],deadline_qpc=c['deadline_qpc'],work_cutoff_qpc=work_cutoff(c),
        inner_job=inner,outer_job=c['guard_job_name'],before=entry['before'],after=entry['after'],query=entry['query'],
        admission_decision_recorded=False)

def job_admission_passed(entry,row,c):
    return bool(entry['receipt'] is not None and entry['exception'] is None and generation_passed(entry['before'],row,c)
        and generation_passed(entry['after'],row,c) and job_query_passed(entry['query'])
        and type(entry['decision_qpc']) is int and entry['after']['after_qpc']<=entry['decision_qpc']<work_cutoff(c))

def validate_job_admissions(row,j,c,operation):
    entries=row['job_admissions'];require(type(entries) is list and len(entries)<=16,'cpse_job_admission_bound')
    common=j['common'];require(not entries or type(common) is dict and type(common.get('child')) is dict
        and live.integer(common['child'].get('job'),1,(1<<64)-1),'cpse_job_admission_owned_inner')
    for index,entry in enumerate(entries,1):
        require(type(entry) is dict and set(entry)=={'sequence','purpose','before','after','query','receipt','decision_qpc','exception'}
            and type(entry['sequence']) is int and entry['sequence']==index
            and entry['purpose']==('initial' if index==1 else 'held'),'cpse_job_admission_schema')
        base.validate_failure_detail(entry['exception'])
        require(entry['decision_qpc'] is None or live.integer(entry['decision_qpc'],c['start_qpc'],live.MAX_SIGNED),'cpse_job_decision_tick')
        for label in ('before','after'):
            if entry[label] is not None:validate_generation(entry[label],c)
        if entry['query'] is not None:
            validate_job_query(entry['query'],c,process=row['pi']['process'],inner=common['child']['job'])
            query=entry['query']
            if entry['before'] is not None and entry['before']['after_qpc'] is not None:
                for tick in (query['inner']['before_qpc'],query['outer_resource']['open_before_qpc']):
                    require(tick is None or tick>=entry['before']['after_qpc'],'cpse_job_query_after_generation')
            if entry['after'] is not None and entry['after']['before_qpc'] is not None:
                for tick in (query['inner']['after_qpc'],query['outer']['after_qpc'],query['outer_resource']['close_after_qpc']):
                    require(tick is None or tick<=entry['after']['before_qpc'],'cpse_job_query_before_generation')
        receipt=entry['receipt']
        if receipt is not None:
            require(type(receipt) is dict and set(receipt)=={'name','text','sha256'}
                and receipt['name']=='%s-%02d.json'%(row['name'],index) and type(receipt['text']) is str
                and len(receipt['text'])<=16384 and sha(receipt['text'].encode('ascii'))==receipt['sha256'],'cpse_job_admission_receipt')
            require(operation['receipt'] is not None and entry['query'] is not None and entry['before'] is not None
                and entry['after'] is not None and decode(receipt['text'].encode('ascii'))==
                    job_admission_value(entry,row,c,common['child']['job'],operation['receipt']['sha256']),'cpse_job_admission_receipt_binding')
        else:require(entry['exception'] is not None,'cpse_job_admission_missing_receipt')
    require(not row['assigned'] or entries and job_admission_passed(entries[0],row,c),'cpse_job_assignment_proof')
    if entries and not job_admission_passed(entries[0],row,c):
        require(not row['assigned'] and not row['admitted'] and row['expected_primary'] is None and row['held_checks']==[],
            'cpse_job_failure_before_token')
    return entries

def transfer_binding(row,c,inner,pi_receipt_sha256):
    return dict(schema_version=1,scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,run=c['run'],role=row['name'],
        config_sha256=sha(encode(c)),source_sha256=c['source_sha256'],pi_receipt_sha256=pi_receipt_sha256,
        process=row['pi']['process'],pid=row['pid'],created=row['created'],actor_sha256=c['actor_sha256'],
        inner_job=inner,outer_job=c['guard_job_name'],frequency=c['frequency'],root_deadline_qpc=c['root_deadline_qpc'],
        deadline_qpc=c['deadline_qpc'],work_cutoff_qpc=work_cutoff(c))

def transfer_intent_value(value,row,c,inner,pi_receipt_sha256,qpc):
    return dict(**transfer_binding(row,c,inner,pi_receipt_sha256),stage='cpse-explicit-inner-assignment-intent',
        guard_receipt_sha256=value['guard']['receipt']['sha256'],qpc=qpc)

def transfer_return_value(value,row,c,inner,pi_receipt_sha256):
    return dict(**transfer_binding(row,c,inner,pi_receipt_sha256),stage='cpse-explicit-inner-assignment-returned',
        guard_receipt_sha256=value['guard']['receipt']['sha256'],intent_sha256=value['intent']['sha256'],
        raw=value['raw'],admission_decision_recorded=False)

def receipt_value(value,name,limit):
    require(type(value) is dict and set(value)=={'name','text','sha256'} and value['name']==name
        and type(value['text']) is str and len(value['text'])<=limit
        and sha(value['text'].encode('ascii'))==value['sha256'],'postassign_receipt')
    return decode(value['text'].encode('ascii'))

def validate_transfer(value,row,j,c,operation):
    require(type(value) is dict and set(value)==set(transfer_blank()),'postassign_transfer_schema')
    base.validate_failure_detail(value['exception'])
    require(value['decision_qpc'] is None or live.integer(value['decision_qpc'],c['start_qpc'],live.MAX_SIGNED),'postassign_decision_tick')
    guard=value['guard'];common=j['common'];inner=None
    if guard is not None:
        require(type(common) is dict and type(common.get('child')) is dict
            and live.integer(common['child'].get('job'),1,(1<<64)-1),'postassign_inner_binding')
        inner=common['child']['job']
        require(type(guard) is dict and set(guard)=={'sequence','purpose','before','after','query','receipt','decision_qpc','exception'}
            and type(guard['sequence']) is int and guard['sequence']==1 and guard['purpose']=='pretransfer','postassign_guard_schema')
        base.validate_failure_detail(guard['exception'])
        require(guard['decision_qpc'] is None or live.integer(guard['decision_qpc'],c['start_qpc'],live.MAX_SIGNED),'postassign_guard_decision')
        for key in ('before','after'):
            if guard[key] is not None:validate_generation(guard[key],c)
        if guard['query'] is not None:
            query=validate_job_query(guard['query'],c,process=row['pi']['process'],inner=inner)
            if guard['before'] is not None and guard['before']['after_qpc'] is not None:
                for tick in (query['inner']['before_qpc'],query['outer_resource']['open_before_qpc']):
                    require(tick is None or tick>=guard['before']['after_qpc'],'postassign_guard_query_start')
            if guard['after'] is not None and guard['after']['before_qpc'] is not None:
                for tick in (query['inner']['after_qpc'],query['outer']['after_qpc'],query['outer_resource']['close_after_qpc']):
                    require(tick is None or tick<=guard['after']['before_qpc'],'postassign_guard_query_end')
        if guard['receipt'] is not None:
            require(operation['receipt'] is not None and all(guard[k] is not None for k in ('before','after','query')),'postassign_guard_material')
            require(receipt_value(guard['receipt'],row['name']+'-guard.json',16384)==
                job_admission_value(guard,row,c,inner,operation['receipt']['sha256']),'postassign_guard_receipt_binding')
        else:require(guard['exception'] is not None,'postassign_guard_missing_receipt')
    require(value['raw'] is None or value['intent'] is not None,'postassign_no_call_without_intent')
    if value['intent'] is not None:
        require(guard_passed(guard,row,c) and operation['receipt'] is not None,'postassign_guard_before_intent')
        raw=receipt_value(value['intent'],row['name']+'-assign-intent.json',4096)
        require(type(raw) is dict and live.integer(raw.get('qpc'),guard['decision_qpc'],work_cutoff(c)-1)
            and raw==transfer_intent_value(value,row,c,inner,operation['receipt']['sha256'],raw['qpc']),'postassign_intent_binding')
    if value['raw'] is not None:
        raw=validate_assign(value['raw'],c)
        require(raw['before_qpc'] is None or raw['before_qpc']>=decode(value['intent']['text'].encode('ascii'))['qpc'],'postassign_call_after_intent')
        require(not raw['returned'] or raw['attempted'],'postassign_call_return')
    if value['receipt'] is not None:
        require(value['raw'] is not None and value['intent'] is not None and operation['receipt'] is not None,'postassign_return_material')
        require(receipt_value(value['receipt'],row['name']+'-assign-returned.json',8192)==
            transfer_return_value(value,row,c,inner,operation['receipt']['sha256']),'postassign_return_binding')
    if value['decision_qpc'] is not None:
        require(value['receipt'] is not None and value['raw'] is not None
            and (value['raw']['after_qpc'] is None or value['decision_qpc']>=value['raw']['after_qpc']),'postassign_decision_after_return')
    if row['created'] is not None and row['native'] is not None and native_ok(row['native']):
        require(guard is not None,'postassign_created_guard_required')
    if row['job_admissions']:
        require(transfer_passed(value,row,c),'postassign_transfer_before_both_jobs')
        first=row['job_admissions'][0]['before']
        require(first is not None and first['before_qpc']>=value['decision_qpc'],'postassign_both_jobs_after_transfer')
    if row['assigned'] or row['admitted'] or row['expected_primary'] is not None:
        require(transfer_passed(value,row,c),'postassign_transfer_before_token')
    return value

def validate_physical_receipts(j,root):
    """Both guarded worker and outer owner bind the reported bytes to files."""
    root=launcher.checked_path(root,is_file=False)
    values=[]
    if j['security_capabilities']['receipt'] is not None:
        values.append(('security-capabilities',j['security_capabilities']['receipt'],16384))
    for operation in j['operations']:
        if operation['receipt'] is not None:values.append(('receipts',operation['receipt'],32768))
    for row in j['tasks']:
        transfer=row['transfer']
        if transfer['guard'] is not None and transfer['guard']['receipt'] is not None:
            values.append(('pretransfer',transfer['guard']['receipt'],16384))
        for key in ('intent','receipt'):
            if transfer[key] is not None:values.append(('transfers',transfer[key],8192))
        for entry in row['job_admissions']:
            if entry['receipt'] is not None:values.append(('job-admissions',entry['receipt'],16384))
    names=set()
    for directory,entry,limit in values:
        key=(directory,entry['name']);require(key not in names,'postassign_physical_receipt_unique');names.add(key)
        raw=local.bounded(launcher.checked_path(root/directory/entry['name'],inside=root),limit)
        require(raw==entry['text'].encode('ascii') and sha(raw)==entry['sha256'],'postassign_physical_receipt_bytes')
    return True

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
    v=row.get('native')
    try:
        validate_native(v,row['name'],c)
        known_create_false=v['api_entered']==v['api_returned']==1 and v['wrapper_status']==6 and v['win32_error']>0
        # ABI3 status10 is ONLY a returned attributes setup/update failure,
        # before CreateProcessW. It does not claim a failed Create API call.
        known_precreate=v['api_entered']==v['api_returned']==0 and v['wrapper_status']==10 and v['hresult_valid']==0
        return bool((known_create_false or known_precreate) and row.get('return_status')==v['wrapper_status']
            and v['environment_state']==2 and not v['opaque_outcome_unknown'] and v['within_deadline']==1
            and row['pi']==dict.fromkeys(('process','thread','process_id','thread_id'),0)
            and not any(row[k] for k in ('assigned','exited','admitted','resumed')) and row['pid'] is None and row['created'] is None)
    except BaseException:return False

class Cell:
    def __init__(self,root,c,parent,api,budget):
        self.root,self.c,self.parent,self.api,self.budget=root,c,parent,api,budget
        self.owners=helpers.OneShotHandles(api.close);self.jobowners=helpers.OneShotHandles(api.close)
        self.job=None;self.rows=[];self.bridge=None;self.phase='setup';self.operations=[]
        self.j=dict(schema_version=1,stage='cpse-matchedcaps-three-held-identity-result',scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,config_sha256=sha(encode(c)),failure=None,failure_detail=None,
            child_environment=launcher.default_child_environment(),common=None,intents=[],operations=self.operations,tasks=[],proofs=[],
            security_capabilities=security_capabilities_blank(),security_capabilities_verified=False,psec_network_preservation_proven=False,
            first_appcontainer_sid=None,common_inputs_verified=False,observer_resources_cleanup_verified=True,job_query_resources_cleanup_verified=True,child_resources_cleanup=False,workload_cleanup=False,
            workload_job_empty=False,opaque_outcome_unknown=False,api_obligations_closed=False,module_unbound=False,
            actor_resumed=False,token_class46_queried=False,external_environment_absence_verified=False,broker_cancellation_proven=False,
            network_tested=False,dns_tested=False,proxy_tested=False,product_acceptance=False)
    def intent(self,label):
        require(label in (*OPS,'observe-ac','observe-lpac','stop') and label not in [x['action'] for x in self.j['intents']],'bridge_intent_once')
        directory=self.root/'journal';directory.mkdir(exist_ok=True)
        raw=encode(dict(schema_version=1,scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,run=self.c['run'],config_sha256=sha(encode(self.c)),action=label,
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
            sc=kwargs.get('security_capabilities')
            raw=encode(dict(schema_version=1,scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,run=self.c['run'],config_sha256=sha(encode(self.c)),action=label,
                intent_sha256=intent['sha256'],frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc'],
                security_capabilities_sha256=None if sc is None else sha(security_capabilities_bytes(sc,self.c['capability_catalog'])),
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
    def generation(self,row):
        value=dict(before_qpc=None,after_qpc=None,within_deadline=False,alive=None,pid=None,created=None,image_verified=False,exception=None)
        try:
            value['before_qpc']=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
            process=row['info'].hProcess;value['alive']=not self.api.wait(process,0)
            value['pid']=self.api.process_id(process);value['created']=self.api.creation_time(process)
            self.api.verify_image(process,self.root/'inputs'/live.ACTOR)
            require(sha(local.bounded(self.root/'inputs'/live.ACTOR,8*1024*1024))==self.c['actor_sha256'],'cpse_held_image')
            value['image_verified']=True;value['after_qpc']=self.budget.read()
            value['within_deadline']=self.c['start_qpc']<=value['before_qpc']<=value['after_qpc']<work_cutoff(self.c)
        except BaseException as error:value['exception']=base.private_failure_detail(error,'cpse-held-generation')
        return value
    def job_admission(self,row,purpose):
        entry=dict(sequence=len(row['job_admissions'])+1,purpose=purpose,before=None,after=None,query=None,receipt=None,decision_qpc=None,exception=None)
        row['job_admissions'].append(entry)
        try:
            entry['before']=self.generation(row)
            entry['query']=self.api.query_exact_jobs(row['info'].hProcess,self.job,self.c['guard_job_name'],self.budget,work_cutoff(self.c),
                protected_handles=tuple(self.owners.pending|self.jobowners.pending))
            entry['after']=self.generation(row)
            self.j['job_query_resources_cleanup_verified']&=entry['query']['resource_cleanup_verified']
            operation=next(op for op in self.operations if op['label']==row['name'])
            require(operation['receipt'] is not None,'cpse_job_pi_receipt_required')
            value=job_admission_value(entry,row,self.c,self.job,operation['receipt']['sha256'])
            raw=encode(value);directory=self.root/'job-admissions';directory.mkdir(exist_ok=True)
            name='%s-%02d.json'%(row['name'],entry['sequence']);base.durable_private(directory/name,raw)
            entry['receipt']=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw))
            validate_job_query(entry['query'],self.c,process=row['pi']['process'],inner=self.job)
            entry['decision_qpc']=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
        except BaseException as error:
            entry['exception']=base.private_failure_detail(error,'cpse-exact-job-admission')
            if entry['query'] is None:
                self.j['job_query_resources_cleanup_verified']=False;self.api.controls_uncertain=True
            raise
        require(job_admission_passed(entry,row,self.c),'cpse_exact_jobs_not_admitted')
    def pretransfer_guard(self,row):
        entry=dict(sequence=1,purpose='pretransfer',before=None,after=None,query=None,receipt=None,decision_qpc=None,exception=None)
        row['transfer']['guard']=entry
        try:
            entry['before']=self.generation(row)
            entry['query']=self.api.query_exact_jobs(row['info'].hProcess,self.job,self.c['guard_job_name'],self.budget,work_cutoff(self.c),
                protected_handles=tuple(self.owners.pending|self.jobowners.pending))
            entry['after']=self.generation(row)
            self.j['job_query_resources_cleanup_verified']&=entry['query']['resource_cleanup_verified']
            operation=next(op for op in self.operations if op['label']==row['name'])
            require(operation['receipt'] is not None,'postassign_pretransfer_pi_receipt')
            value=job_admission_value(entry,row,self.c,self.job,operation['receipt']['sha256'])
            raw=encode(value);directory=self.root/'pretransfer';directory.mkdir(exist_ok=True)
            name=row['name']+'-guard.json';base.durable_private(directory/name,raw)
            entry['receipt']=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw))
            validate_job_query(entry['query'],self.c,process=row['pi']['process'],inner=self.job)
            entry['decision_qpc']=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
        except BaseException as error:
            entry['exception']=base.private_failure_detail(error,'postassign-outer-guard')
            if entry['query'] is None:
                self.j['job_query_resources_cleanup_verified']=False;self.api.controls_uncertain=True
            raise
        require(guard_passed(entry,row,self.c),'postassign_outer_guard_not_admitted')
    def explicit_transfer(self,row):
        value=row['transfer']
        require(value==transfer_blank(),'postassign_transfer_once')
        try:
            self.pretransfer_guard(row)
            operation=next(op for op in self.operations if op['label']==row['name'])
            directory=self.root/'transfers';directory.mkdir(exist_ok=True)
            self.budget.require_ms(work_cutoff(self.c));tick=self.budget.read()
            require(tick<work_cutoff(self.c),'postassign_intent_deadline')
            raw=encode(transfer_intent_value(value,row,self.c,self.job,operation['receipt']['sha256'],tick))
            name=row['name']+'-assign-intent.json';base.durable_private(directory/name,raw)
            value['intent']=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw))
            # Pretransfer query handles have already been consumed once. Only
            # the owned inner Job and original PI process HANDLE enter this API.
            self.budget.require_ms(work_cutoff(self.c))
            value['raw']=self.api.assign_inner_once(row['info'].hProcess,self.job,self.budget,work_cutoff(self.c))
            raw=encode(transfer_return_value(value,row,self.c,self.job,operation['receipt']['sha256']))
            name=row['name']+'-assign-returned.json';base.durable_private(directory/name,raw)
            value['receipt']=dict(name=name,text=raw.decode('ascii'),sha256=sha(raw))
            validate_assign(value['raw'],self.c)
            value['decision_qpc']=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
            require(transfer_passed(value,row,self.c),'postassign_assignment_not_admitted')
        except BaseException as error:
            value['exception']=base.private_failure_detail(error,'postassign-explicit-inner-transfer')
            # Assignment uncertainty is not a CPSE create/VOID-close return.
            # Keep the raw assignment and exact-process cleanup authority.
            raise
    def held(self,row):
        self.budget.require_ms(work_cutoff(self.c));phase=self.phase;self.phase='admission'
        self.job_admission(row,'held');self.phase=phase
        primary=identity.capture_primary(self.api,row['token'],self.parent,self.c['capability_catalog'],self.j['first_appcontainer_sid'],self.budget,work_cutoff(self.c))
        require(primary==row['expected_primary'],'cpse_primary_changed');row['held_checks'].append(self.budget.read());return primary
    def freeze_security_capabilities(self,bootstrap):
        state=self.j['security_capabilities'];require(state==security_capabilities_blank(),'secaps_commit_once')
        self.phase='admission'
        try:
            self.held(bootstrap)
            state['value']=security_capabilities_value(bootstrap['expected_primary'],self.c['capability_catalog'])
            state['raw_sha256']=sha(security_capabilities_bytes(state['value'],self.c['capability_catalog']))
            view=dict(self.j,tasks=[{k:v for k,v in row.items() if k not in ('info','token')} for row in self.rows])
            value=security_capabilities_binding(state,view,self.c)
            value.update(bootstrap_held_check_qpc=bootstrap['held_checks'][-1],
                bootstrap_job_receipt_sha256=bootstrap['job_admissions'][-1]['receipt']['sha256'])
            raw=encode(value);directory=self.root/'security-capabilities';directory.mkdir(exist_ok=True)
            base.durable_private(directory/'held-bootstrap.json',raw)
            state['receipt']=dict(name='held-bootstrap.json',text=raw.decode('ascii'),sha256=sha(raw))
            state['decision_qpc']=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
            validate_security_capabilities_state(state,view,self.c)
            require(security_capabilities_passed(state,view,self.c),'secaps_commit_not_admitted')
            self.j['security_capabilities_verified']=True
        except BaseException as error:
            state['exception']=base.private_failure_detail(error,'held-bootstrap-security-capabilities')
            raise
    def arm(self,role):
        self.phase='construct';self.budget.require_ms(work_cutoff(self.c));pi=PI();info=self.api.process_info()
        for prior in self.rows:self.held(prior)
        sc=None
        if role!='bootstrap':
            require(self.j['security_capabilities_verified'] and security_capabilities_passed(self.j['security_capabilities'],self.j,self.c),
                'secaps_before_measured_constructor')
            sc=self.j['security_capabilities']['value']
        row=dict(name=role,info=info,token=None,attempted=True,assigned=False,exited=False,exit_code=None,pid=None,created=None,
            admitted=False,resumed=False,expected_primary=None,primary_observation_qpc=None,held_checks=[],job_admissions=[],transfer=transfer_blank(),
            bootstrap_before_create_check_qpc=None if role=='bootstrap' else self.rows[0]['held_checks'][-1],bootstrap_before_token_check_qpc=None,
            security_capabilities_sha256=None if sc is None else sha(security_capabilities_bytes(sc,self.c['capability_catalog'])),
            pi=dict.fromkeys(('process','thread','process_id','thread_id'),0),return_status=None,native=None)
        self.rows.append(row)
        try:row['native']=self.call(role,child=self.child,pi=pi,security_capabilities=sc)
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
        self.explicit_transfer(row)
        self.job_admission(row,'initial');row['assigned']=True
        if role!='bootstrap':
            self.held(self.rows[0]);row['bootstrap_before_token_check_qpc']=self.rows[0]['held_checks'][-1]
        row['token']=self.api.token_for_process(process);self.owners.add(row['token'])
        observed=self.api.identity(row['token'])
        if self.j['first_appcontainer_sid'] is None:
            require(role=='bootstrap' and base.ac.ac_profile_sid(observed['appcontainer_sid']),'cpse_first_sid')
            self.j['first_appcontainer_sid']=observed['appcontainer_sid']
        primary=identity.capture_primary(self.api,row['token'],self.parent,self.c['capability_catalog'],self.j['first_appcontainer_sid'],self.budget,work_cutoff(self.c))
        tick=self.budget.read();self.budget.require_ms(work_cutoff(self.c))
        row['expected_primary']=primary;row['primary_observation_qpc']=tick
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
            bootstrap=self.arm('bootstrap');self.freeze_security_capabilities(bootstrap)
            arms=[self.arm(role) for role in ('ac','lpac')]
            require(len({row['expected_primary']['authentication_id'] for row in self.rows})==1
                and len({row['expected_primary']['token_id'] for row in self.rows})==3
                and len({row['pid'] for row in self.rows})==3,'cpse_matched_authentication')
            self.j['common_inputs_verified']=True;self.phase='accesscheck';probe=self.api.access_api()
            for row in arms:
                for arm in self.rows:self.held(arm)
                self.intent('observe-'+row['name']);self.j['observer_resources_cleanup_verified']=False
                proof=access.observe_held(probe,row['info'].hProcess,row['expected_primary'],expected_pid=row['pid'],
                    expected_creation=row['created'],expected_role=row['name'],frequency=self.c['frequency'],deadline=work_cutoff(self.c))
                self.j['proofs'].append(proof);self.j['observer_resources_cleanup_verified']=all(p['resource_cleanup_verified'] for p in self.j['proofs'])
                for arm in self.rows:self.held(arm)
                require(proof['qualified'],'cpse_accesscheck_matrix')
        except BaseException as error:
            self.j['failure']=self.phase;self.j['failure_detail']=base.private_failure_detail(error)
        finally:self.cleanup()
        self.j['tasks']=[{k:v for k,v in row.items() if k not in ('info','token')} for row in self.rows]
        return self.j
    def cleanup(self):
        try:
            if any(row['info'].hProcess and not row['exited'] for row in self.rows):self.intent('stop')
            originals=[row for row in self.rows if not known_no_child(row,self.c)]
            # A later failed membership observation must not cause cleanup to
            # rely solely on an earlier successful Job admission. Preserve the
            # historical row and use only this derived view for exact stop.
            rows=[dict(row,assigned=False) if row['assigned'] and row['job_admissions']
                and not job_admission_passed(row['job_admissions'][-1],row,self.c) else row for row in originals]
            clean,empty,_=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(12)),self.job,rows,self.owners)
            for original,view in zip(originals,rows):original.update(exited=view['exited'],exit_code=view['exit_code'])
            self.j.update(child_resources_cleanup=clean,workload_job_empty=empty)
        except BaseException:pass
        if self.bridge is not None:
            last=next((r['native'] for r in reversed(self.operations) if r['native'] is not None),None)
            if last is not None and last['opaque_outcome_unknown']:self.j['opaque_outcome_unknown']=True
            clean=self.j['child_resources_cleanup'] and self.j['workload_job_empty'] and self.j['observer_resources_cleanup_verified'] and self.j['job_query_resources_cleanup_verified'] and not self.api.controls_uncertain
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
        if not all(self.j[k] for k in ('workload_cleanup','workload_job_empty','observer_resources_cleanup_verified','job_query_resources_cleanup_verified','api_obligations_closed','module_unbound')):
            self.j['failure']=self.j['failure'] or 'cleanup'

def execute(root,c,parent,api,budget):
    config_validate(c);require(launcher.token_is_ordinary(parent) and budget.deadline==c['deadline_qpc'] and budget.frequency==c['frequency'],'cpse_parent_budget')
    return Cell(root,c,parent,api,budget).execute()

RESULT_BOOLS=('common_inputs_verified','observer_resources_cleanup_verified','job_query_resources_cleanup_verified','child_resources_cleanup','workload_cleanup','workload_job_empty','opaque_outcome_unknown',
    'api_obligations_closed','module_unbound','actor_resumed','token_class46_queried','external_environment_absence_verified',
    'broker_cancellation_proven','network_tested','dns_tested','proxy_tested','product_acceptance','security_capabilities_verified','psec_network_preservation_proven')
RESULT_KEYS={'schema_version','stage','scope','constructor_policy','config_sha256','failure','failure_detail','child_environment','common','intents','operations','tasks','proofs',
    'first_appcontainer_sid','security_capabilities',*RESULT_BOOLS}
TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','admitted','resumed','expected_primary','held_checks','job_admissions','transfer',
    'primary_observation_qpc','security_capabilities_sha256','bootstrap_before_create_check_qpc','bootstrap_before_token_check_qpc','pi','return_status','native'}

def validate_result(j,c,*,parent,root=None):
    config_validate(c);require(launcher.token_is_ordinary(parent),'cpse_result_parent')
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1
        and j['constructor_policy']==CONSTRUCTOR_POLICY and j['stage']=='cpse-matchedcaps-three-held-identity-result' and j['scope']==SCOPE and j['config_sha256']==sha(encode(c))
        and j['failure'] in (None,'setup','bind','environment','construct','admission','accesscheck','cleanup'),'cpse_result')
    require(all(type(j[k]) is bool for k in RESULT_BOOLS),'cpse_result_booleans');base.validate_failure_detail(j['failure_detail'])
    require(j['failure'] is not None or j['failure_detail'] is None,'cpse_result_detail')
    require(not any(j[k] for k in ('actor_resumed','token_class46_queried','external_environment_absence_verified','broker_cancellation_proven',
        'network_tested','dns_tested','proxy_tested','product_acceptance','psec_network_preservation_proven')),'cpse_scope')
    launcher.validate_child_environment(j['child_environment'])
    require(j['first_appcontainer_sid'] is None or base.ac.ac_profile_sid(j['first_appcontainer_sid']),'cpse_result_sid')
    intents=j['intents'];require(type(intents) is list and len(intents)<=10,'cpse_intent_bound');actions=[];ticks={}
    last=c['start_qpc']
    for index,row in enumerate(intents):
        require(type(row) is dict and set(row)=={'action','name','text','sha256'} and row['action'] in (*OPS,'observe-ac','observe-lpac','stop')
            and row['action'] not in actions and row['name']=='%02d-%s.json'%(index,row['action'])
            and type(row['text']) is str and len(row['text'])<=4096 and sha(row['text'].encode('ascii'))==row['sha256'],'cpse_intent')
        value=decode(row['text'].encode('ascii'))
        require(type(value) is dict and set(value)=={'schema_version','scope','constructor_policy','run','config_sha256','action','frequency','deadline_qpc','qpc'}
            and value==dict(schema_version=1,scope=SCOPE,constructor_policy=CONSTRUCTOR_POLICY,run=c['run'],config_sha256=sha(encode(c)),action=row['action'],frequency=c['frequency'],
                deadline_qpc=c['deadline_qpc'],qpc=value['qpc']) and live.integer(value['qpc'],last,live.MAX_SIGNED),'cpse_intent_binding')
        last=value['qpc'];actions.append(row['action']);ticks[row['action']]=last
    operations=j['operations'];require(type(operations) is list and len(operations)<=7,'cpse_operations')
    labels=[];native={};statuses={}
    for row in operations:
        require(type(row) is dict and set(row)=={'label','return_status','native','receipt','exception'} and row['label'] in OPS
            and row['label'] in actions and row['label'] not in labels,'cpse_operation')
        labels.append(row['label']);base.validate_failure_detail(row['exception'])
        if row['native'] is not None:
            value=validate_native(row['native'],row['label'],c);native[row['label']]=value
            require(type(row['return_status']) is int and 0<=row['return_status']<=10,'cpse_function_status')
            statuses[row['label']]=row['return_status']
            require(row['exception'] is not None or row['return_status']==value['wrapper_status'],'cpse_function_status_binding')
            require(not value['within_deadline'] or value['before_qpc']>=ticks[row['label']],'cpse_call_after_intent')
        else:require(row['exception'] is not None and row['return_status'] is None,'cpse_missing_call_receipt')
        receipt=row['receipt']
        if receipt is not None:
            require(type(receipt) is dict and set(receipt)=={'name','text','sha256'} and type(receipt['text']) is str
                and len(receipt['text'])<=32768 and sha(receipt['text'].encode('ascii'))==receipt['sha256'],'cpse_returned_receipt')
            intent=next(intent for intent in intents if intent['action']==row['label']);raw=decode(receipt['text'].encode('ascii'))
            require(receipt['name']==intent['name'][:-5]+'-returned.json' and type(raw) is dict and set(raw)=={'schema_version','scope','constructor_policy','run','config_sha256',
                'action','intent_sha256','frequency','deadline_qpc','return_status','native','pi','security_capabilities_sha256'} and type(raw['schema_version']) is int and raw['schema_version']==1
                and raw['scope']==SCOPE and raw['constructor_policy']==CONSTRUCTOR_POLICY and raw['run']==c['run'] and raw['config_sha256']==sha(encode(c)) and raw['action']==row['label']
                and raw['intent_sha256']==intent['sha256'] and raw['frequency']==c['frequency'] and raw['deadline_qpc']==c['deadline_qpc']
                and raw['return_status']==row['return_status'] and raw['native']==row['native'],'cpse_returned_receipt_binding')
            require(raw['pi'] is None if row['label'] not in ('bootstrap','ac','lpac') else type(raw['pi']) is dict,'cpse_returned_pi_kind')
            expected_sc=j['security_capabilities']['raw_sha256'] if row['label'] in ('ac','lpac') else None
            require(raw['security_capabilities_sha256']==expected_sc,'secaps_returned_input_binding')
        else:require(row['exception'] is not None,'cpse_missing_durable_return')
    # A validation/write exception after a structurally valid returned tuple
    # does not erase known S_OK-owned or normal VOID-return observations.
    opaque_sticky=any(row['native'] is not None and row['native']['opaque_outcome_unknown']
        or row['label'] in ('create','close') and not opaque_return_known(row['label'],row['return_status'],row['native'],c)
        for row in operations)
    require(not opaque_sticky or j['opaque_outcome_unknown'],'cpse_opaque_unknown_sticky')
    require(labels==[label for label in ('bind','create','bootstrap','ac','lpac','close','unbind') if label in labels],'cpse_operation_order')
    require('create' not in labels or 'bind' in native and native_ok(native['bind']),'cpse_create_bound')
    for role in ('bootstrap','ac','lpac'):
        require(role not in labels or 'create' in native and native_ok(native['create']) and native['create']['hresult_valid']==1
            and native['create']['hresult']==0 and native['create']['environment_state']==2,'cpse_arm_environment')
    require('ac' not in labels or 'bootstrap' in native and native_ok(native['bootstrap'])
        and j['security_capabilities_verified'],'secaps_bootstrap_before_measured')
    require('lpac' not in labels or 'ac' in native and native_ok(native['ac']),'cpse_second_arm')
    tasks=j['tasks'];require(type(tasks) is list and len(tasks)<=3 and [r.get('name') for r in tasks]==['bootstrap','ac','lpac'][:len(tasks)],'cpse_task_order')
    require([row['name'] for row in tasks]==[role for role in ('bootstrap','ac','lpac') if role in labels],'secaps_all_constructor_rows_retained')
    for index,row in enumerate(tasks):
        require(not index or all(prior['admitted'] for prior in tasks[:index]),'secaps_prior_held_admission')
    for row in tasks:
        require(type(row) is dict and set(row)==TASK_KEYS and all(type(row[k]) is bool for k in ('attempted','assigned','exited','admitted','resumed'))
            and row['attempted'] and row['resumed'] is False and row['name'] in labels,'cpse_task_schema')
        role=row['name'];require(row['native']==native.get(role) and row['return_status']==statuses.get(role),'cpse_task_receipt')
        require(row['security_capabilities_sha256']==(j['security_capabilities']['raw_sha256'] if role in ('ac','lpac') else None),
            'secaps_task_input_binding')
        for key in ('bootstrap_before_create_check_qpc','bootstrap_before_token_check_qpc'):
            require(row[key] is None or live.integer(row[key],c['start_qpc'],work_cutoff(c)-1),'secaps_recheck_tick')
            require(role!='bootstrap' or row[key] is None,'secaps_bootstrap_is_not_a_measured_arm')
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
        validate_transfer(row['transfer'],row,j,c,op)
        entries=validate_job_admissions(row,j,c,op)
        held=[entry for entry in entries if entry['purpose']=='held' and job_admission_passed(entry,row,c)]
        require(len(row['held_checks'])<=len(held) and all(any(entry['after']['after_qpc']<=tick
            for entry in held) for tick in row['held_checks']),'cpse_held_job_checks')
        prior=row['expected_primary']
        require(row['primary_observation_qpc'] is None or live.integer(row['primary_observation_qpc'],c['start_qpc'],work_cutoff(c)-1),'secaps_primary_observation_tick')
        require((prior is None)==(row['primary_observation_qpc'] is None),'secaps_primary_observation_binding')
        if prior is not None:
            access.identity(prior,primary=True);live.capability_set(prior['capabilities'],'agentic-pncs',c['capability_catalog'])
            require(prior['sid']==parent['sid'] and prior['session_id']==parent['session_id'] and prior['appcontainer_sid']==j['first_appcontainer_sid']
                and prior['appcontainer'] and prior['integrity_rid']==4096 and not prior['elevated'] and not prior['ui_access'],'cpse_primary_binding')
        if row['admitted']:
            require(prior is not None and row['created'] is not None and row['assigned'] and row['held_checks'] and row['native'] is not None
                and native_ok(row['native']) and all(row['pi'].values()) and row['pi']['process']!=row['pi']['thread']
                and len(entries)>=2 and job_admission_passed(entries[1],row,c),'cpse_task_admitted')
        if j['workload_cleanup']:require(known_no_child(row,c) or row['exited'],'cpse_clean_child')
    job_clean=all(entry['query'] is not None and entry['query']['resource_cleanup_verified']
        for row in tasks for entry in [*row['job_admissions'],*([row['transfer']['guard']] if row['transfer']['guard'] is not None else [])])
    require(j['job_query_resources_cleanup_verified']==job_clean,'cpse_job_resources_cleanup_binding')
    for index,row in enumerate(tasks):
        if not transfer_passed(row['transfer'],row,c) or row['job_admissions'] and not job_admission_passed(row['job_admissions'][0],row,c):
            require(index==len(tasks)-1 and not j['proofs'],'cpse_job_failure_stops_next_arm')
    validate_security_capabilities_state(j['security_capabilities'],j,c)
    require(j['security_capabilities_verified']==security_capabilities_passed(j['security_capabilities'],j,c),'secaps_verified_binding')
    for row in tasks[1:]:
        require(j['security_capabilities_verified'] and row['security_capabilities_sha256'] is not None,
            'secaps_measured_requires_committed_input')
        bootstrap=tasks[0];created=native.get(row['name']);source_tick=j['security_capabilities']['decision_qpc']
        if created is not None and created['before_qpc']:
            tick=row['bootstrap_before_create_check_qpc']
            require(tick in bootstrap['held_checks'] and source_tick<=tick<=created['before_qpc'],
                'secaps_live_bootstrap_before_measured_create')
        if row['expected_primary'] is not None:
            initial=row['job_admissions'][0]
            tick=row['bootstrap_before_token_check_qpc']
            require(tick in bootstrap['held_checks'] and initial['decision_qpc']<=tick<=row['primary_observation_qpc'],
                'secaps_live_bootstrap_before_measured_token')
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
        require(j['security_capabilities_verified'] and common is not None and len(tasks)==3 and all(r['admitted'] for r in tasks) and len({r['pid'] for r in tasks})==3
            and len({r['expected_primary']['token_id'] for r in tasks})==3
            and len({r['expected_primary']['authentication_id'] for r in tasks})==1,'cpse_common_admission')
    proofs=j['proofs'];require(type(proofs) is list and len(proofs)<=2 and len(proofs)<=max(0,len(tasks)-1)
        and (not proofs or j['common_inputs_verified']),'cpse_proofs')
    for proof,row in zip(proofs,tasks[1:]):
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
        require(j['child_resources_cleanup'] and j['workload_job_empty'] and j['observer_resources_cleanup_verified']
            and j['job_query_resources_cleanup_verified'] and 'create' in native
            and native['create']['environment_state']==2,'cpse_close_order')
        require(not any(row['pi']['process'] and not row['exited'] for row in tasks),'cpse_close_live_child')
    if j['api_obligations_closed']:
        require(j['job_query_resources_cleanup_verified'] and not j['opaque_outcome_unknown'] and ('close' in native and opaque_return_known('close',statuses['close'],native['close'],c)
            and native['close']['close_invoked_once']==native['close']['close_returned_normally']==1
            or 'close' not in labels and ('create' not in labels or 'create' in native and native['create']['api_returned']==native['create']['hresult_valid']==1
                and native['create']['hresult']<0 and native['create']['environment_state']==1 and not native['create']['opaque_outcome_unknown'])),'cpse_obligation_receipt')
    require(not j['module_unbound'] or j['api_obligations_closed'] and ('bind' not in labels or 'unbind' in native
        and native['unbind']['module_close_attempted']==native['unbind']['module_close_confirmed']==1),'cpse_unbind_receipt')
    if j['failure'] is None:
        require(j['common_inputs_verified'] and j['security_capabilities_verified'] and len(proofs)==2 and all(p['qualified'] for p in proofs)
            and all(j[k] for k in ('observer_resources_cleanup_verified','job_query_resources_cleanup_verified','workload_cleanup','workload_job_empty','api_obligations_closed','module_unbound'))
            and not j['opaque_outcome_unknown'] and all(native_ok(v) for v in native.values()) and len(labels)==7,'cpse_complete')
        require(all(row['exception'] is None and row['receipt'] is not None for row in operations),'cpse_complete_returned_receipts')
        require(all(job_admission_passed(entry,row,c) for row in tasks for entry in row['job_admissions']),'cpse_complete_job_receipts')
        require(all(transfer_passed(row['transfer'],row,c) for row in tasks),'postassign_complete_transfer_receipts')
    require(len(encode(j))<=MAX_REPORT,'cpse_result_bound')
    if root is not None:validate_physical_receipts(j,root)
    return j

def project(j,c,*,parent,root=None):
    validate_result(j,c,parent=parent,root=root)
    value={k:j[k] for k in ('failure','common_inputs_verified','observer_resources_cleanup_verified','workload_cleanup','workload_job_empty',
        'opaque_outcome_unknown','api_obligations_closed','module_unbound','security_capabilities_verified','psec_network_preservation_proven')}
    proofs={p['expected_role']:p for p in j['proofs']};tasks={r['name']:r for r in j['tasks']}
    row=tasks.get('bootstrap')
    value['bootstrap_inner_assignment_verified']=bool(row and transfer_passed(row['transfer'],row,c)
        and row['job_admissions'] and job_admission_passed(row['job_admissions'][0],row,c))
    value['bootstrap_held_verified']=bool(row and row['admitted'])
    for role in ('ac','lpac'):
        row=tasks.get(role);p=proofs.get(role)
        value[role+'_inner_assignment_verified']=bool(row and transfer_passed(row['transfer'],row,c)
            and row['job_admissions'] and job_admission_passed(row['job_admissions'][0],row,c))
        value[role+'_held_verified']=bool(row and row['admitted'])
        value[role+'_accesscheck_verified']=bool(p and p['qualified'])
        value[role+'_granted_access']=None if p is None or len(p['calls'])!=4 or not all(x['api_success'] for x in p['calls']) else [x['granted_access'] for x in p['calls']]
    value['inner_complete']=j['failure'] is None
    return value
