"""Independent file-only compile audit; never execute compiler/original reader/DLL."""
import ast
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

BASE=Path(__file__).resolve().parent
ROOT=BASE/'Rule-proxy-Web'
CANDIDATE=BASE/'psec-lpac-matchedcaps-candidate'
BUILD=BASE/'psec-lpac-matchedcaps-bridge-compile-01'
POLICY='bootstrap-held-primary-matched-security-capabilities-aap-only-v1'
EXPECTED={
    'psec-lpac-matchedcaps-native-freeze-01.json':'7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f',
    'psec-lpac-matchedcaps-python-candidate-freeze-03.json':'dfdfcf9a9afd67fc9f15e0a252fdfcd672f3bcfd07417ba3a23e259a4537e762',
    'compile_psec_lpac_matchedcaps_bridge_01.ps1':'196ab8c0d7ac2eecce845cf533146d6978dc43387ddb83439da46547b147f0a5',
    'inspect_psec_lpac_matchedcaps_bridge_compile_01.py':'c6b0de07555906d5d4c802c0dace04257ae8c9f2d99f0097135f9403adb3d043',
}
PRODUCTS={
    'windows_psec_lpac_matchedcaps_bridge.dll':'91e9fdc092943ac3a3b47c9f5ad394f4aacb522d105aa802c47b74d5c4f702b1',
    'psec-lpac-matchedcaps-bridge-manifest.json':'fbbb268bde396dbe7bbdf7247f062bd2e1892f537f5e553a5ee105d1b52566d7',
    'static-pe-review.json':'2b8c3d42d89fa6305357b3af638abe47349c76b6445f6321ad7368a3c7ad76e5',
}


def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(path,expected=None):
    raw=path.read_bytes()
    if expected is not None:need(sha(raw)==expected,'input_digest:'+path.name)
    return dict(bytes=len(raw),sha256=sha(raw))
def decode(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def git_bytes(commit,path):
    result=subprocess.run(['git','show',commit+':'+path],cwd=ROOT,capture_output=True,check=True)
    return result.stdout


def pe(raw):
    def get(fmt,at):
        size=struct.calcsize(fmt);need(0<=at<=len(raw)-size,'PE_bounds')
        return struct.unpack_from(fmt,raw,at)
    need(raw[:2]==b'MZ','MZ');start=get('<I',60)[0];need(raw[start:start+4]==b'PE\0\0','PE')
    machine,n,_,_,_,opt_size,flags=get('<HHIIIHH',start+4);opt=start+24
    need(machine==0x8664 and flags&0x2000 and 1<=n<=32 and get('<H',opt)[0]==0x20b and opt_size>=240,'x64_DLL')
    need(get('<I',opt+108)[0]>=16,'directories')
    sections=[]
    for i in range(n):
        virtual_size,rva,size,at=get('<IIII',opt+opt_size+40*i+8)
        need(at+size<=len(raw),'section_file_range');sections.append((rva,virtual_size,at,size))
    def offset(rva,nbytes=1):
        for first,vsize,at,size in sections:
            if first<=rva and rva+nbytes<=first+max(size,vsize):
                need(rva+nbytes<=first+size,'initialized_bytes');return at+rva-first
        raise ValueError('unmapped_RVA')
    def string(rva):
        at=offset(rva);end=raw.find(b'\0',at,min(len(raw),at+512));need(end>=at,'string')
        offset(rva,end-at+1);return raw[at:end].decode('ascii')
    er,es=get('<II',opt+112)
    _,_,_,_,_,base,nfunc,nnames,functions,names,ordinals=get('<IIHHIIIIIII',offset(er,40))
    need(nfunc==nnames==8,'eight_exports');exports=[]
    for i in range(nnames):
        name=string(get('<I',offset(names+4*i,4))[0]);ordinal=get('<H',offset(ordinals+2*i,2))[0]
        need(ordinal<nfunc,'ordinal');rva=get('<I',offset(functions+4*ordinal,4))[0]
        need(rva and not er<=rva<er+es,'not_forwarded');offset(rva)
        exports.append(dict(name=name,ordinal=base+ordinal,rva=rva))
    ar=next(x['rva'] for x in exports if x['name']=='pb_abi_version')
    code=raw[offset(ar,6):offset(ar,6)+6];need(code==bytes.fromhex('b803000000c3'),'ABI3_code_not_called')
    ir,isize=get('<II',opt+120);need(ir and 20<=isize<=4096,'import_bounds');imports=[];end=False
    for i in range(isize//20):
        row=get('<IIIII',offset(ir+20*i,20))
        if not any(row):end=True;break
        need(row[3],'import_name');imports.append(string(row[3]))
    need(end and [s.lower() for s in imports]==['kernel32.dll'],'KERNEL32_only')
    need(get('<II',opt+112+13*8)==(0,0),'no_delay_imports')
    return dict(exports=exports,imports=imports,ABI_machine_code=code.hex())


def main():
    pins={name:pin(BASE/name,value) for name,value in EXPECTED.items()}
    products={name:pin(BUILD/name,value) for name,value in PRODUCTS.items()}
    native=decode(BASE/'psec-lpac-matchedcaps-native-freeze-01.json')
    python=decode(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-03.json')
    manifest=decode(BUILD/'psec-lpac-matchedcaps-bridge-manifest.json')
    audit=decode(BUILD/'static-pe-review.json');snapshot=decode(BUILD/'input-snapshot.json')
    expected_inputs={**native['native_sources'],**native['dependencies']}
    need(len(native['native_sources'])==6 and len(native['dependencies'])==31 and len(expected_inputs)==37,'six_plus31')
    need(manifest['sources']==native['native_sources'] and manifest['dependencies']==native['dependencies'],'manifest_frozen37')
    need(set(manifest)=={'schema_version','stage','compile_only','runtime_acceptance','abi_version','constructor_policy','spec_variant','dll_sha256','dll_bytes',
        'architecture','sources','dependencies','toolchain','imports','exports'} and manifest['schema_version']==1
        and manifest['stage']=='psec-lpac-matchedcaps-bridge-compile-only' and manifest['compile_only'] is True
        and manifest['runtime_acceptance'] is False and manifest['abi_version']==3 and manifest['constructor_policy']==POLICY
        and manifest['spec_variant']=='identity-only-deny-all-v1' and manifest['architecture']=='amd64','closed_manifest')
    need(snapshot['SnapshotBeforeCompile'] is True and snapshot['NativeFreezeSha256']==EXPECTED['psec-lpac-matchedcaps-native-freeze-01.json']
        and snapshot['LibraryAbiVersion']==3 and snapshot['PayloadVersion']==1 and snapshot['ConstructorPolicy']==POLICY
        and snapshot['DllLoaded'] is snapshot['CpseCalled'] is snapshot['ActorExecuted'] is False,'snapshot_contract')
    rows=snapshot['SourcesAndDependencies'];need(len(rows)==37,'37_rows');seen={}
    for row in rows:
        path=row['Path'];need(set(row)=={'Path','Sha256','Kind'} and path in expected_inputs and path not in seen
            and row['Sha256']==expected_inputs[path] and row['Kind']==('source' if path in native['native_sources'] else 'dependency'),'exact_row')
        raw=(BUILD/'src'/path).read_bytes();need(sha(raw)==expected_inputs[path],'snapshot_bytes')
        need((ROOT/path).read_bytes()==raw and (CANDIDATE/path).read_bytes()==raw,'origin_main_snapshot_equal')
        seen[path]=row['Sha256']
    need(seen==expected_inputs,'complete_snapshot')
    combined_new={**native['files'],**python['files']};need(len(combined_new)==8,'eight_new')
    for path,value in combined_new.items():
        raw=(ROOT/path).read_bytes();need(len(raw)==value['bytes'] and sha(raw)==value['sha256']
            and (CANDIDATE/path).read_bytes()==raw and b'\r' not in raw,'new_eight_exact_LF')
    baseline=python['baseline_commit'];old_checks={**native['old_37_inputs_unchanged'],**python['old_scope_files']}
    old_git={}
    for path,value in old_checks.items():
        expected=value['sha256'] if isinstance(value,dict) else value
        raw=(ROOT/path).read_bytes();need(sha(raw)==expected and git_bytes(baseline,path)==raw,'old_source_Git_equal')
        old_git[path]=expected
    shared={path:expected for path,expected in python['source_hashes'].items() if path not in python['files']}
    need(len(shared)==34 and python['runtime_source_count']==36 and len(python['source_hashes'])==36,'runtime_36_shared34')
    for path,expected in shared.items():
        raw=(ROOT/path).read_bytes();need(sha(raw)==expected and git_bytes(baseline,path)==raw,'shared_runtime_Git_equal')
    runtime={path:sha((ROOT/path).read_bytes()) for path in python['source_hashes']}
    need(runtime==python['source_hashes'] and sha((json.dumps(runtime,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii'))==python['source_sha256'],'runtime_closure')
    false=decode(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-02.json')
    changed=[]
    for path,value in python['files'].items():
        if value!=false['files'][path]:
            raw=(ROOT/path).read_bytes();need(raw.count(b'ACTUAL_READY=True')==1
                and sha(raw.replace(b'ACTUAL_READY=True',b'ACTUAL_READY=False'))==false['files'][path]['sha256'],'promotion_one_literal')
            changed.append(path)
    need(len(changed)==1 and python['actual_ready'] is True,'operator_promotion_only')
    reader=(BASE/'inspect_psec_lpac_matchedcaps_bridge_compile_01.py').read_bytes();ast.parse(reader)
    need(not any(x in reader for x in (b'LoadLibrary(',b'WinDLL(',b'ctypes',b'subprocess')),'reader_is_file_only')
    compiler=(BASE/'compile_psec_lpac_matchedcaps_bridge_01.ps1').read_text()
    need(compiler.index('input-snapshot.json')<compiler.index('& cl.exe') and '/MT' in compiler and '/W4 /WX' in compiler
        and 'Fresh compile directory required' in compiler and 'LoadLibrary' not in compiler,'compiler_snapshot_before_cl')
    log=(BUILD/'compile.log').read_bytes();need(log and not re.search(rb'(?:fatal error|error [A-Z]+\d+:|warning [A-Z]+\d+:)',log,re.I),'compiler_no_diagnostics')
    tool=decode(BUILD/'toolchain.json');need(tool['CompileOnly'] is True and tool['Runtime']=='MT' and tool['Architecture']=='amd64','toolchain_record')
    need(manifest['toolchain']['compiler_version']==tool['CompilerFileVersion'] and manifest['toolchain']['vc_tools_version']==tool['VCToolsVersion']
        and manifest['toolchain']['windows_sdk_version']==tool['WindowsSDKVersion'].rstrip('\\'),'normalized_toolchain')
    for artifact,key in (('compile.log','compile_log_sha256'),('toolchain.json','toolchain_record_sha256'),('input-snapshot.json','input_snapshot_sha256')):
        need(sha((BUILD/artifact).read_bytes())==audit[key],'audit_record_binding')
    need(audit['compiler_script_sha256']==pins['compile_psec_lpac_matchedcaps_bridge_01.ps1']['sha256']
        and audit['reader_sha256']==pins['inspect_psec_lpac_matchedcaps_bridge_compile_01.py']['sha256'],'audit_helper_binding')
    observed=pe((BUILD/'windows_psec_lpac_matchedcaps_bridge.dll').read_bytes())
    need(observed['exports']==audit['export_details'] and [x['name'] for x in observed['exports']]==manifest['exports']
        and observed['imports']==manifest['imports']==audit['imports'] and observed['ABI_machine_code']==audit['abi_export_machine_code_hex'],'independent_PE_equal')
    need(manifest['dll_sha256']==products['windows_psec_lpac_matchedcaps_bridge.dll']['sha256']
        and manifest['dll_bytes']==217088 and audit['manifest_sha256']==products['psec-lpac-matchedcaps-bridge-manifest.json']['sha256'],'DLL_manifest')
    cpp=(BUILD/'src/.github/native/windows_psec_lpac_matchedcaps_bridge.cpp').read_text()
    need('static_assert(sizeof(Internal)<=sizeof(PB_CONTEXT_V1));' in cpp
        and 'static_assert(alignof(Internal)<=alignof(PB_CONTEXT_V1));' in cpp,'compiled_Internal_assert_present')
    pure_raw=(BASE/'psec-lpac-matchedcaps-main-pure-01.log').read_bytes()
    need(b'Ran 955 tests in 83.640s' in pure_raw and b'OK (skipped=2)' in pure_raw
        and b'MATCHEDCAPS_SC_FAKE_CHECKS 100' in pure_raw and b'MATCHEDCAPS_ROLE_FAKE_CHECKS 154' in pure_raw,'root_pure_log')
    value=dict(schema_version=1,stage='matchedcaps-compile01-independent-file-review',verdict='GO for compiled artifact/source binding; no runtime or identity acceptance',
        reviewed_metadata=pins,products=products,native_inputs=expected_inputs,main_new_eight=combined_new,
        snapshot_count=37,source_count=6,dependency_count=31,old_Git_pins_verified=old_git,
        shared_runtime_Git_count=34,shared_runtime_Git_pins=shared,baseline_commit=baseline,
        runtime_source_count=36,runtime_source_sha256=python['source_sha256'],promotion_changed_paths=changed,
        observations=dict(independent_PE=observed,Internal_static_assert_source_in_successful_compile=True,
            Context512_compile_gate_passed=True,toolchain=manifest['toolchain'],snapshot_before_compile=True,
            root_full_pure=dict(tests=955,failures=0,errors=0,old_permission_skips=2,seconds=83.640,
                log=pin(BASE/'psec-lpac-matchedcaps-main-pure-01.log'),new_portable_SC_assertions=100,new_portable_role_assertions=154,new_portable_assertions=254,
                note='The root full run already executed all three new native tests; this reviewer did not repeat them.')),
        execution=dict(compiler_repeated=False,original_static_reader_repeated=False,DLL_loaded=False,CPSE_called=False,
            native_API_called=False,actor_executed=False,network_executed=False,main_modified=False),
        limits='Compile/PE/file-only evidence only. No three-arm semantic success, environment absence, CPSE policy preservation, DNS/proxy qualification or product acceptance follows.')
    out=BASE/'psec-lpac-matchedcaps-compile-independent-review-01.json'
    data=(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+'\n').encode()
    with out.open('xb') as stream:stream.write(data)
    print(json.dumps(dict(verdict='GO',bytes=len(data),sha256=sha(data),snapshot_count=37,new_main_paths=8,DLL_loaded=False)))


if __name__=='__main__':main()
