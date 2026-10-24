"""Static PE and compile-input audit; does not load any DLL."""
import hashlib
import json
from pathlib import Path
import struct

BASE=Path(__file__).resolve().parent
BUILD=BASE/'psec-lpac-postassign-bridge-compile-01'
def need(ok,label):
    if not ok:raise ValueError(label)
def sha(b):return hashlib.sha256(b).hexdigest()
def encode(v):return (json.dumps(v,sort_keys=True,ensure_ascii=True,indent=2)+'\n').encode('ascii')
def write_once(path,raw):
    if path.exists():need(path.read_bytes()==raw,'immutable_output')
    else:
        with path.open('xb') as f:need(f.write(raw)==len(raw),'write')

def main():
    snapshot=json.loads((BUILD/'input-snapshot.json').read_text(encoding='utf-8-sig'))
    need(snapshot['SnapshotBeforeCompile'] is True and len(snapshot['SourcesAndDependencies'])==37,'snapshot')
    need(snapshot['ConstructorPolicy']=='outer-guarded-held-explicit-inner-assignment-v1' and snapshot['LibraryAbiVersion']==2 and snapshot['PayloadVersion']==1,'explicit_new_constructor_snapshot')
    groups={'source':{},'dependency':{}}
    for row in snapshot['SourcesAndDependencies']:
        need(row['Kind'] in groups and row['Path'] not in groups[row['Kind']],'input_schema')
        need(sha((BUILD/'src'/row['Path']).read_bytes())==row['Sha256'],'snapshot_hash')
        groups[row['Kind']][row['Path']]=row['Sha256']
    need(len(groups['source'])==6 and len(groups['dependency'])==31,'closure')
    need(groups['source'].get('.github/native/windows_psec_lpac_postassign_bridge.cpp')=='806ead04ee3f583bac1f0d7dc72f51fa10de4634bb7cd2b597f0a3a3c8b29f36' and '.github/native/windows_psec_lpac_bridge.cpp' not in groups['source'],'new_frozen_cpp_only')
    raw=(BUILD/'windows_psec_lpac_postassign_bridge.dll').read_bytes()
    def get(fmt,at):
        size=struct.calcsize(fmt);need(0<=at<=len(raw)-size,'pe_bounds');return struct.unpack_from(fmt,raw,at)
    need(raw[:2]==b'MZ','dos');pe=get('<I',60)[0];need(raw[pe:pe+4]==b'PE\0\0','pe')
    machine,count,_,_,_,opt_size,flags=get('<HHIIIHH',pe+4);opt=pe+24
    need(machine==0x8664 and 1<=count<=32 and flags&0x2000 and get('<H',opt)[0]==0x20b and opt_size>=240,'amd64_dll')
    need(get('<I',opt+108)[0]>=16,'directories');dirs=opt+112
    sections=[]
    for index in range(count):
        size,rva,file_size,file_at=get('<IIII',opt+opt_size+40*index+8)
        need(file_at+file_size<=len(raw),'section_bounds');sections.append((rva,size,file_at,file_size))
    def offset(rva,n=1):
        for start,size,file_at,file_size in sections:
            if start<=rva and rva+n<=start+max(size,file_size):
                need(rva+n<=start+file_size,'initialized_rva');return file_at+rva-start
        raise ValueError('unmapped_rva')
    def string(rva):
        at=offset(rva);end=raw.find(b'\0',at,min(at+512,len(raw)));need(end>=at,'string_termination')
        offset(rva,end-at+1);return raw[at:end].decode('ascii','strict')
    export_rva,export_size=get('<II',dirs)
    _,_,_,_,_,ordinal_base,nfunc,nnames,functions,names,ordinals=get('<IIHHIIIIIII',offset(export_rva,40))
    need(nfunc==nnames==8,'exact_export_count');exports=[];export_details=[]
    for index in range(nnames):
        name=string(get('<I',offset(names+4*index,4))[0]);ordinal=get('<H',offset(ordinals+2*index,2))[0]
        need(ordinal<nfunc,'export_ordinal');address=get('<I',offset(functions+4*ordinal,4))[0]
        need(address and not export_rva<=address<export_rva+export_size,'no_export_forwarder');offset(address)
        exports.append(name);export_details.append(dict(name=name,ordinal=ordinal_base+ordinal,rva=address))
    expected=['pb_abi_version','pb_bind','pb_build_spec','pb_close_environment','pb_create_arm','pb_create_environment','pb_unbind','pb_verify_spec']
    need(exports==expected,'exact_eight_exports')
    abi_rva=next(item['rva'] for item in export_details if item['name']=='pb_abi_version')
    abi_bytes=raw[offset(abi_rva,6):offset(abi_rva,6)+6]
    need(abi_bytes==bytes.fromhex('b802000000c3'),'static_abi_export_returns2')
    imports=[];import_rva,import_size=get('<II',dirs+8);need(import_rva and 20<=import_size<=4096,'import_directory')
    terminated=False
    for index in range(import_size//20):
        fields=get('<IIIII',offset(import_rva+index*20,20))
        if not any(fields):terminated=True;break
        need(fields[3]!=0,'import_name');imports.append(string(fields[3]))
    need(terminated and len(imports)==len(set(x.casefold() for x in imports)),'terminated_unique_imports')
    need([x.casefold() for x in imports]==['kernel32.dll'],'static_mt_kernel_only')
    delay_rva,delay_size=get('<II',dirs+13*8);need(delay_rva==delay_size==0,'no_delay_imports')
    tool=json.loads((BUILD/'toolchain.json').read_text(encoding='utf-8-sig'))
    need(tool['CompileOnly'] is True and tool['Runtime']=='MT' and tool['Architecture']=='amd64','toolchain')
    toolchain=dict(compiler='MSVC',compiler_version=tool['CompilerFileVersion'],vc_tools_version=tool['VCToolsVersion'],
        windows_sdk_version=tool['WindowsSDKVersion'].rstrip('\\'),runtime='MT',architecture='amd64',
        flags=['/std:c++17','/EHsc','/W4','/WX','/LD','/MT','/O2','/guard:cf','/INCREMENTAL:NO','/DYNAMICBASE','/NXCOMPAT'])
    manifest=dict(schema_version=1,stage='psec-lpac-postassign-bridge-compile-only',compile_only=True,runtime_acceptance=False,
        abi_version=2,constructor_policy='outer-guarded-held-explicit-inner-assignment-v1',spec_variant='identity-only-deny-all-v1',dll_sha256=sha(raw),dll_bytes=len(raw),architecture='amd64',
        sources=groups['source'],dependencies=groups['dependency'],toolchain=toolchain,imports=imports,exports=exports)
    mr=encode(manifest);write_once(BUILD/'psec-lpac-postassign-bridge-manifest.json',mr)
    audit=dict(schema_version=1,stage='psec-lpac-postassign-bridge-compile01-static-audit',compile_only=True,dll_loaded=False,
        processmodel_loaded=False,cpse_called=False,actor_executed=False,native_source_input_count=6,dependency_input_count=31,
        immutable_snapshot_verified=True,input_snapshot_sha256=sha((BUILD/'input-snapshot.json').read_bytes()),
        compile_log_sha256=sha((BUILD/'compile.log').read_bytes()),toolchain_record_sha256=sha((BUILD/'toolchain.json').read_bytes()),
        compiler_script_sha256=sha((BASE/'compile_psec_lpac_postassign_bridge_01.ps1').read_bytes()),reader_sha256=sha(Path(__file__).read_bytes()),
        manifest_sha256=sha(mr),dll_sha256=sha(raw),dll_bytes=len(raw),imports=imports,export_details=export_details,
        abi_version=2,payload_version=1,constructor_policy='outer-guarded-held-explicit-inner-assignment-v1',
        abi_export_machine_code_hex=abi_bytes.hex(),runtime_acceptance=False,limits='Static PE/compile evidence only. No environment, process, token, Job or network acceptance.')
    ar=encode(audit);write_once(BUILD/'static-pe-review.json',ar)
    print(json.dumps(dict(dll_bytes=len(raw),dll_sha256=sha(raw),manifest_sha256=sha(mr),audit_sha256=sha(ar),imports=imports,exports=exports,dll_loaded=False)))
if __name__=='__main__':main()
