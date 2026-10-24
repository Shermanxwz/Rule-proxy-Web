"""File-only independent review receipt; never imports or loads the native DLL."""
import hashlib
import json
from pathlib import Path
import struct

W=Path(__file__).resolve().parent
C=W/'psec-lpac-identity-bridge-candidate'
B=W/'psec-lpac-bridge-compile-02'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
freeze_path=W/'psec-lpac-native-candidate-freeze-01.json'
freeze=json.loads(freeze_path.read_bytes())
manifest_path=B/'psec-lpac-bridge-manifest.json'
manifest=json.loads(manifest_path.read_bytes())
files=[]
for path,digest in freeze['files'].items():
    row=record(C/path);assert row['sha256']==digest
    files.append(dict(path=path,**row))
abi=W/'psec-lpac-identity-bridge-abi-01.json'
assert record(abi)['sha256']==freeze['abi_sha256']
log=W/'psec-lpac-bridge-native-pure-01.log'
assert record(log)['sha256']==freeze['pure_tests']['log_sha256']
pins={**manifest['sources'],**manifest['dependencies']};assert len(pins)==37
for path,digest in pins.items():
    assert record(B/'src'/path)['sha256']==digest
    assert record(C/path)['sha256']==digest
for row in files:
    if row['path'] in manifest['sources']:assert manifest['sources'][row['path']]==row['sha256']
raw=(B/'windows_psec_lpac_bridge.dll').read_bytes()
assert len(raw)==manifest['dll_bytes'] and sha(raw)==manifest['dll_sha256']
assert raw[:2]==b'MZ'
pe=struct.unpack_from('<I',raw,60)[0]
assert raw[pe:pe+4]==b'PE\0\0'
machine,count,_,_,_,optional_size,flags=struct.unpack_from('<HHIIIHH',raw,pe+4)
optional=pe+24
assert machine==0x8664 and flags&0x2000 and struct.unpack_from('<H',raw,optional)[0]==0x20b
sections=[]
for i in range(count):
    at=optional+optional_size+40*i
    vs,va,rs,rp=struct.unpack_from('<IIII',raw,at+8);sections.append((va,vs,rs,rp))
def offset(rva,size=1):
    for va,vs,rs,rp in sections:
        if va<=rva and rva+size<=va+rs:
            out=rp+rva-va;assert out+size<=len(raw);return out
    raise AssertionError('RVA outside raw section')
def string(rva):
    at=offset(rva);end=raw.index(b'\0',at,min(len(raw),at+1024));return raw[at:end].decode('ascii')
def directory(index):return struct.unpack_from('<II',raw,optional+112+index*8)
import_rva,import_size=directory(1);imports=[]
if import_rva:
    at=offset(import_rva,20)
    for _ in range(32):
        row=struct.unpack_from('<IIIII',raw,at)
        if not any(row):break
        imports.append(string(row[3]));at+=20
    else:raise AssertionError('Import bound')
export_rva,export_size=directory(0);at=offset(export_rva,40)
functions_count,names_count,functions,names,ordinals=struct.unpack_from('<IIIII',raw,at+20)
exports=[]
assert names_count==functions_count==8
for i in range(names_count):
    name=string(struct.unpack_from('<I',raw,offset(names+4*i,4))[0])
    ordinal=struct.unpack_from('<H',raw,offset(ordinals+2*i,2))[0]
    assert ordinal<functions_count
    function=struct.unpack_from('<I',raw,offset(functions+4*ordinal,4))[0]
    assert function and not export_rva<=function<export_rva+export_size
    offset(function);exports.append(name)
assert imports==manifest['imports']==['KERNEL32.dll']
assert exports==manifest['exports']==['pb_abi_version','pb_bind','pb_build_spec','pb_close_environment','pb_create_arm','pb_create_environment','pb_unbind','pb_verify_spec']
assert directory(13)==(0,0) and directory(14)==(0,0)
receipt=dict(schema_version=1,stage='cpse-lpac-native-independent-file-only-review',scope=manifest['spec_variant'],
    review_conclusion='No remaining native-source blocker found in this bounded review. This is not runtime approval; Python owner/guard final review is pending.',
    actual_ready=False,native_sources=files,freeze=record(freeze_path),abi=record(abi),
    dependency_review=record(W/'psec-lpac-dependency-independent-review-01.json'),
    compile_artifact=dict(dll=record(B/'windows_psec_lpac_bridge.dll'),manifest=record(manifest_path),
        immutable_source_dependency_count=37,static_imports=imports,static_exports=exports,delay_import_directory_absent=True,clr_directory_absent=True),
    author_pure_test_evidence=dict(log=record(log),reported_tests=2,reported_skips=0,reported_portable_assertions=327,rerun_by_reviewer=False),
    checks=dict(all_frozen_source_bytes_equal=True,compile_snapshot_37_equal=True,abi_layout96_equal=True,
        header_schema_version_pins_equal=True,generated_cpp_header_matches_frozen_hash=True,
        exact_spec_bytes_forwarded_to_cpse_without_rebuild=True,semantic_verifier_rejects_proxy_peer_extra_policy=True,
        windows_except_macro_scoped_undef_restore=True,no_object_api_schema_mutation=True,
        bind_verified_requires_support_version_original_clock=True,cpse_flags_zero=True,
        only_security_environment_job_list_aap_attributes=True,no_second_identity_source=True,
        suspended_no_handle_inheritance_no_resume=True,partial_pi_transferred_before_postcall_checks=True,
        failure_nonnull_and_success_null_unknown=True,opaque_value_not_kernel_closed=True,
        close_consumed_before_void_call_and_no_retry=True,exact_borrowed_job_empty_check_before_close=True,
        no_external_absence_or_broker_cancellation_claim=True),
    interpretation=[
        'The fixed policy is independent identity-only deny-all; this is not the prior Model2 proxy/peer policy.',
        'Native semantic validation accepts equivalent valid FlatBuffer layout, but Create receives the exact caller plan-bound byte buffer and byte count. Python must keep the plan SHA and independent canonical decoder gate.',
        'A returned exact S_OK with non-null output establishes known close authority. A later deadline failure must remain disqualified, while still allowing one cleanup close of that known resource.',
        'Failed HRESULT with non-null output, unexpected nonnegative HRESULT, unreturned create, malformed opaque result, or unreturned VOID close cannot be washed into absence or cancellation.',
        'The borrowed inner Job handle must stay live through native close; kernel child/token/proof resources must be closed by the owner before opaque close. Job empty or worker death alone does not prove broker cancellation.',
        'The scoped Windows except macro workaround surrounds the generated schema/spec include and restores the macro. The pinned schema is unchanged; regenerated C++ lacks object API.',
        'Portable core/spec tests do not exercise Windows.h adapter API calls. Actual DLL loading, support/version, CPSE composition, and token observations remain untested here.'
    ],
    remaining_review=['Python owner/guard final lifecycle and closed report validation is pending author freeze.'],
    primary_sources=[
        'https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-createprocesssecurityenvironment',
        'https://learn.microsoft.com/en-us/windows/win32/api/processmodel/nf-processmodel-closeprocesssecurityenvironment',
        'https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/secenv.rs',
        'https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/external/windows-sdk/ProcessSecurityEnvironment.fbs'],
    actions=dict(file_hashes_and_static_pe_read=True,native_dll_loaded=False,processmodel_called=False,native_actor_executed=False,
        native_compiler_or_flatc_executed_by_reviewer=False,tests_rerun=False,main_source_modified=False,security_or_network_changed=False))
out=W/'psec-lpac-native-independent-review-01.json'
assert not out.exists()
data=(json.dumps(receipt,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode();out.write_bytes(data)
print(json.dumps(dict(review='native-file-only-no-blocker',bytes=len(data),sha256=sha(data),dll_sha256=sha(raw),actual_ready=False)))
