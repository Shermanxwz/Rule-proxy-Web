"""Independent file/hash and source review; does not execute the PE reader."""
from pathlib import Path
import hashlib
import json
import subprocess

W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web';B=W/'psec-lpac-postassign-bridge-compile-01'
C=W/'psec-lpac-postassign-native-candidate'
BASELINE='4c5878ba0ffa6f4b938e26bf5c8c016b7042b333'
OLD='.github/native/windows_psec_lpac_bridge.cpp';NEW='.github/native/windows_psec_lpac_postassign_bridge.cpp'
def sha(raw):return hashlib.sha256(raw).hexdigest()
def record(path):
    raw=path.read_bytes();return dict(bytes=len(raw),sha256=sha(raw))
def read(path):return json.loads(path.read_bytes().decode('utf-8-sig'))
def git(name):return subprocess.check_output(['git','show',BASELINE+':'+name],cwd=R)

freeze_path=W/'psec-lpac-postassign-native-freeze-01.json';freeze=read(freeze_path)
assert record(freeze_path)['sha256']=='f7d62220f30d11ad245ab7de859bd4c93ca4bee13294c1c8b64e5db5aad4b981'
manifest_path=B/'psec-lpac-postassign-bridge-manifest.json';manifest=read(manifest_path)
assert record(manifest_path)['sha256']=='1a29ce2ce18f75e13dc1546fc201558121e30563e475d2075d94951546aaef56'
audit_path=B/'static-pe-review.json';audit=read(audit_path)
assert record(audit_path)['sha256']=='8927e621edc51235f70670fb90ee294d525760bf684166afc3372a2162431a6d'
old_manifest_path=W/'psec-lpac-bridge-compile-02/psec-lpac-bridge-manifest.json';old_manifest=read(old_manifest_path)
assert record(old_manifest_path)['sha256']=='9b9ab93826c99bbde32c18cca3a32389d75086c3b1f7abbc453a2dda98d09209'
assert set(manifest)=={'schema_version','stage','compile_only','runtime_acceptance','abi_version','constructor_policy','spec_variant',
    'dll_sha256','dll_bytes','architecture','sources','dependencies','toolchain','imports','exports'}
assert type(manifest['schema_version']) is int and manifest['schema_version']==1
assert manifest['stage']=='psec-lpac-postassign-bridge-compile-only' and manifest['abi_version']==2
assert manifest['constructor_policy']=='outer-guarded-held-explicit-inner-assignment-v1'
assert manifest['spec_variant']=='identity-only-deny-all-v1' and manifest['compile_only'] is True and manifest['runtime_acceptance'] is False
assert manifest['architecture']=='amd64' and manifest['dll_bytes']==214528
assert manifest['dll_sha256']=='5db0d4db168074a64b3c042b1be86954edaf7138e643c01fdd3625264a8b8f64'
old_pins={**old_manifest['sources'],**old_manifest['dependencies']}
assert old_pins==freeze['old_native_pins_unchanged'] and len(old_pins)==37
for name,digest in old_pins.items():assert sha((R/name).read_bytes())==digest and (R/name).read_bytes()==git(name)
expected_sources=dict(old_manifest['sources']);expected_sources.pop(OLD)
expected_sources[NEW]=freeze['files'][NEW]['sha256']
assert manifest['sources']==expected_sources and len(expected_sources)==6 and OLD not in expected_sources
assert manifest['dependencies']==old_manifest['dependencies'] and len(manifest['dependencies'])==31
snapshot_path=B/'input-snapshot.json';snapshot=read(snapshot_path)
assert snapshot['SchemaVersion']==1 and snapshot['SnapshotBeforeCompile'] is True
assert snapshot['LibraryAbiVersion']==2 and snapshot['PayloadVersion']==1
assert snapshot['ConstructorPolicy']==manifest['constructor_policy']
assert snapshot['DllLoaded'] is snapshot['CpseCalled'] is snapshot['ActorExecuted'] is False
rows=snapshot['SourcesAndDependencies'];assert len(rows)==37
observed={};inputs=[]
for row in rows:
    assert set(row)=={'Path','Sha256','Kind'} and row['Kind'] in ('source','dependency') and row['Path'] not in observed
    name=row['Path'];expected=manifest['sources'] if row['Kind']=='source' else manifest['dependencies']
    assert row['Sha256']==expected[name];observed[name]=row['Sha256']
    raw=(B/'src'/name).read_bytes();original=(C/name if name==NEW else R/name).read_bytes()
    assert raw==original and sha(raw)==row['Sha256']
    if name!=NEW:assert raw==git(name)
    inputs.append(dict(path=name,kind=row['Kind'],bytes=len(raw),sha256=sha(raw),snapshot_input_equal=True))
assert observed=={**manifest['sources'],**manifest['dependencies']}
assert sum(row['Kind']=='source' for row in rows)==6
assert sum(row['Kind']=='dependency' for row in rows)==31
new=(C/NEW).read_bytes();old=(R/OLD).read_bytes();assert sha(new)=='806ead04ee3f583bac1f0d7dc72f51fa10de4634bb7cd2b597f0a3a3c8b29f36'
assert sha(old)=='06969090ece3d5a74b7400f9808ebd60ee9234a7eed7a852c09abaf9942cf8ab'
assert new==(B/'src'/NEW).read_bytes() and b'\r' not in new
text=new.decode('ascii');assert text.count('UpdateProcThreadAttribute(')==2
assert 'job_list' not in text and '0x2000d' not in text and 'AssignProcessToJobObject' not in text
assert 'ResumeThread' not in text and 'SECURITY_CAPABILITIES' not in text
assert 'InitializeProcThreadAttributeList(nullptr,2,0,&size)' in text and 'InitializeProcThreadAttributeList(candidate,2,0,&size)' in text
assert 'job_valid(j,false)' in text and 'j==c->job' in text and 'c->state.begin_close(!c->job || job_valid(c->job,true))' in text
assert 'pb_abi_version() noexcept { return 2; }' in text
diff_path=W/'psec-lpac-postassign-native-diff-01.txt'
assert record(diff_path)['sha256']==freeze['diff']['sha256']
assert record(W/'psec-lpac-postassign-native-01.patch')['sha256']==freeze['patch']['sha256']

compiler_path=W/'compile_psec_lpac_postassign_bridge_01.ps1';compiler=compiler_path.read_bytes()
reader_path=W/'inspect_psec_lpac_postassign_bridge_compile_01.py';reader=reader_path.read_bytes()
assert sha(compiler)==audit['compiler_script_sha256']=='7f94684dc612b20c3cb034700cd6b9d157c27d2edb22a7496814ba957b15c58d'
assert sha(reader)==audit['reader_sha256']=='64ac422501a5f2984f07ea641d887064c340f7b7e67782a6b040ac1e769137e5'
assert audit['input_snapshot_sha256']==record(snapshot_path)['sha256']
assert audit['toolchain_record_sha256']==record(B/'toolchain.json')['sha256']
assert audit['compile_log_sha256']==record(B/'compile.log')['sha256']
assert audit['manifest_sha256']==record(manifest_path)['sha256']
assert record(B/'windows_psec_lpac_postassign_bridge.dll')==dict(bytes=214528,sha256=manifest['dll_sha256'])
assert audit['dll_sha256']==manifest['dll_sha256'] and audit['dll_bytes']==manifest['dll_bytes']
expected_exports=['pb_abi_version','pb_bind','pb_build_spec','pb_close_environment','pb_create_arm','pb_create_environment','pb_unbind','pb_verify_spec']
assert manifest['exports']==expected_exports==[row['name'] for row in audit['export_details']]
assert manifest['imports']==audit['imports']==['KERNEL32.dll']
assert audit['abi_version']==2 and audit['payload_version']==1 and audit['abi_export_machine_code_hex']=='b802000000c3'
assert audit['constructor_policy']==manifest['constructor_policy'] and audit['immutable_snapshot_verified'] is True
assert audit['native_source_input_count']==6 and audit['dependency_input_count']==31
assert audit['compile_only'] is True and audit['runtime_acceptance'] is False
assert all(audit[k] is False for k in ('dll_loaded','processmodel_loaded','cpse_called','actor_executed'))
tool=read(B/'toolchain.json');normalized=manifest['toolchain']
assert tool['CompilerFileVersion']==normalized['compiler_version']=='19.44.35229.0'
assert tool['VCToolsVersion']==normalized['vc_tools_version']=='14.44.35207'
assert tool['WindowsSDKVersion'].rstrip('\\')==normalized['windows_sdk_version']=='10.0.26100.0'
assert tool['Runtime']==normalized['runtime']=='MT' and tool['Architecture']==normalized['architecture']=='amd64'
assert tool['CompileOnly'] is True and all(flag in normalized['flags'] for flag in ('/MT','/W4','/WX','/guard:cf'))

# This is source review, not a second execution of the original PE parser.
reader_text=reader.decode('ascii')
assert 'raw=(BUILD/\'windows_psec_lpac_postassign_bridge.dll\').read_bytes()' in reader_text
assert "abi_bytes==bytes.fromhex('b802000000c3')" in reader_text
assert 'no_export_forwarder' in reader_text and 'no_delay_imports' in reader_text
assert 'ctypes' not in reader_text and 'WinDLL' not in reader_text and 'LoadLibrary(' not in reader_text
out=dict(schema_version=1,stage='psec-lpac-postassign-compile01-independent-review',review='GO-no-compile-evidence-blocker',
    compile_only=True,runtime_acceptance=False,actual_ready=False,
    commitments=dict(native_freeze=record(freeze_path),native_new_cpp=record(C/NEW),native_diff=record(diff_path),
        compiler_script=record(compiler_path),pe_reader=record(reader_path),input_snapshot=record(snapshot_path),
        toolchain=record(B/'toolchain.json'),compile_log_raw_private=record(B/'compile.log'),
        manifest=record(manifest_path),static_pe_audit=record(audit_path),dll_raw_private=record(B/'windows_psec_lpac_postassign_bridge.dll')),
    input_verification=dict(count=37,native_sources=6,dependencies=31,snapshot_before_compile_recorded=True,
        frozen_candidate_snapshot_bytes_equal=True,shared_main_git_snapshot_bytes_equal=True,
        original_native37_unchanged=True,old_cpp_excluded_from_new_dll=True,new_cpp_only=True,files=inputs),
    abi=dict(library_version=2,payload_version=1,plan_bytes=48,child_bytes=88,result_bytes=96,pi_bytes=24,
        exports=expected_exports,imports=['KERNEL32.dll'],abi_export_machine_code_hex='b802000000c3',
        pe_facts_from_hash_bound_existing_static_audit=True,existing_pe_reader_source_reviewed=True,pe_reader_reexecuted=False),
    native_diff_verified=dict(attributes_exact=['SE_ENV','AAP_POLICY'],count=2,job_list_requested=False,
        assign_called=False,resume_called=False,security_capabilities_added=False,
        inner_job_valid_same_handle_and_empty_close_gate_preserved=True,old_opaque_qpc_void_close_logic_unchanged=True),
    toolchain=dict(compiler='MSVC',compiler_version='19.44.35229.0',vc_tools_version='14.44.35207',sdk='10.0.26100.0',
        runtime='MT',architecture='amd64',flags=normalized['flags']),
    limits=[
        'The compiled DLL was hashed as a file and its previously recorded PE parser/source were reviewed; neither DLL nor processmodel was loaded by this audit.',
        'ABI2 labels a new explicit constructor policy while all caller-owned PB_*_V1 payload layouts remain unchanged. Matching a machine-code return constant is static metadata, not runtime acceptance.',
        'This native constructor does not verify inherited outer membership or perform inner assignment. Independent owner pre-transfer outer membership, once-assignment receipts, post-transfer both-Job verification and cleanup remain required.',
        'No normal VOID-close inference proves external environment absence or broker cancellation. No token, AccessCheck, process, Job, network, DNS, proxy or product mechanism has been accepted by compilation.',
        'Original327 portable assertions were neither rerun nor recounted as new tests. New compiled/runtime tests in this audit:0.',
        'The raw DLL and raw compiler log remain private file commitments; neither is copied or published by this review.'
    ],
    actions=dict(file_hashes_and_readonly_git=True,compiler_reexecuted=False,original_pe_reader_reexecuted=False,
        native_api_called=False,dll_loaded=False,processmodel_loaded=False,actor_or_network_executed=False,
        candidate_or_main_modified=False,original_compile_outputs_modified=False))
path=W/'psec-lpac-postassign-compile-independent-review-01.json';assert not path.exists()
raw=(json.dumps(out,ensure_ascii=True,sort_keys=True,indent=2)+'\n').encode('ascii')
with path.open('xb') as stream:stream.write(raw)
print(json.dumps(dict(review='compile-only-GO',bytes=len(raw),sha256=sha(raw),inputs=37,native_executed=False)))
