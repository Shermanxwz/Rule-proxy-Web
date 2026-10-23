"""Verify/stage the five new postassign source files after the root's full run.

The root-selected final promotion02 freeze and SHA are fixed here. This tool
never executes tests, DLLs, actors, APIs, cleanup or network. --check-only does
not stage or write the integrated receipt. All historical tracked tests and
verification/validation evidence are checked against the pre-stage Git tree.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
PRE_STAGE_HEAD='6374895503ecd18dce664d809008a5050334761c'
OLD_FREEZE_NAME='psec-lpac-python-diagnostic-freeze-03.json'
OLD_FREEZE_SHA256='0fafbd55ebe54ea9ed13ac7705dec0b7baa8e0cc26f7971290219f8f6683c00d'
BASELINE_RECEIPT_NAME='psec-lpac-integrated-pure-03.json'
BASELINE_RECEIPT_SHA256='719fee52ac2cec526a7078207b43552b02f106c60fa1fa01088f35c727859793'
NATIVE_FREEZE_NAME='psec-lpac-postassign-native-freeze-01.json'
NATIVE_FREEZE_SHA256='f7d62220f30d11ad245ab7de859bd4c93ca4bee13294c1c8b64e5db5aad4b981'
FINAL_FREEZE_NAME='psec-lpac-postassign-python-candidate-freeze-02.json'
FINAL_FREEZE_SHA256='5a7b92ab97c472333ed28f9888ffec99dd4f4ec1018a721bfd1858a0d896ab06'
FINAL_SOURCE_SHA256='d625a45670dc4b544c73e7dfb0acb55f483064dca23495e5e12f9dcbf8705f9f'
CORE='.github/windows_identity_psec_lpac_postassign_bridge.py'
LOCAL='.github/windows_identity_psec_lpac_postassign_bridge_local.py'
NEW_CPP='.github/native/windows_psec_lpac_postassign_bridge.cpp'
OLD_CPP='.github/native/windows_psec_lpac_bridge.cpp'
OLD_MODULES={'.github/windows_identity_psec_lpac_bridge.py','.github/windows_identity_psec_lpac_bridge_local.py'}
TESTS={'tests/test_windows_identity_psec_lpac_postassign_bridge.py','tests/test_windows_identity_psec_lpac_postassign_bridge_local.py'}
PY_PATHS={CORE,LOCAL,*TESTS}
CHANGES={NEW_CPP,*PY_PATHS}
LOG='psec-lpac-postassign-main-pure-01.log'
RECEIPT='psec-lpac-postassign-integrated-pure-01.json'
SCOPE='one-local-cpse-deny-all-outer-guarded-postassign-identity-v1'

OLD_SOURCES=('.github/native/windows_identity_actor.cpp', '.github/native/windows_identity_dns_raw_udp.hpp', '.github/native/windows_identity_dns_standard_probe.hpp', '.github/native/windows_identity_proxy_bridge_core.hpp', '.github/native/windows_identity_proxy_c_actor.cpp', '.github/native/windows_identity_proxy_c_contract.hpp', '.github/native/windows_identity_proxy_origin_actor.cpp', '.github/native/windows_identity_proxy_origin_transport.hpp', '.github/native/windows_identity_proxy_pipe_actor.cpp', '.github/windows_dns_fixture.py', '.github/windows_identity_dns_cases_fixture.py', '.github/windows_identity_dns_standard_inventory.ps1', '.github/windows_identity_lpac_dns_local.py', '.github/windows_identity_model2_controller.py', '.github/windows_identity_model2_dns.py', '.github/windows_identity_model2_dns_raw.py', '.github/windows_identity_model2_firewall.ps1', '.github/windows_identity_model2_live.py', '.github/windows_identity_model2_local.py', '.github/windows_identity_model2_local_probe.py', '.github/windows_identity_model2_maintenance.py', '.github/windows_identity_ordinary_launcher.py', '.github/windows_identity_pipe_probe.py', '.github/windows_identity_proof.py', '.github/windows_identity_proxy_origin_probe.py', '.github/windows_identity_proxy_pipe_ac_guest.py', '.github/windows_identity_proxy_pipe_ac_local.py', '.github/windows_identity_proxy_pipe_probe.py', '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_app_process.py', 'ruleproxy/windows_runtime_pins.py', '.github/windows_identity_lpac_accesscheck.py', '.github/windows_identity_lpac_identity_cell.py', '.github/windows_identity_psec_spec.py', '.github/windows_identity_psec_lpac_bridge.py', '.github/windows_identity_psec_lpac_bridge_local.py')

def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
def read(path,limit=2*1024*1024):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        info=part.lstat();need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'no_reparse_input')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit,'input_file_bound')
    raw=path.read_bytes();need(len(raw)==info.st_size,'stable_input_read');return raw
def decode(raw):
    def pairs(rows):
        result={}
        for key,value in rows:need(key not in result,'duplicate_json_key');result[key]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
def relative(name):
    need(type(name) is str and name and '\\' not in name,'repo_path_string');part=PurePosixPath(name)
    need(not part.is_absolute() and '..' not in part.parts,'repo_relative_path');return name
def git(*args):return subprocess.check_output(['git',*args],cwd=REPO)
def blob_sha(raw):return hashlib.sha1(b'blob '+str(len(raw)).encode('ascii')+b'\0'+raw).hexdigest()
def tree_ids():
    raw=git('ls-tree','-r','-z',PRE_STAGE_HEAD);need(len(raw)<=8*1024*1024,'tracked_tree_inventory_bound');result={}
    for item in raw.split(b'\0'):
        if not item:continue
        info,name=item.split(b'\t',1);mode,kind,digest=info.split(b' ');name=relative(name.decode('utf8'))
        need(kind==b'blob' and name not in result,'tracked_blob_tree');result[name]=(mode.decode('ascii'),digest.decode('ascii'))
    return result
def test_cases(raw):
    value=ast.parse(raw);rows=[]
    for cls in value.body:
        if isinstance(cls,ast.ClassDef):
            rows.extend((cls.name,method.name) for method in cls.body if isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) and method.name.startswith('test_'))
    need(rows and len(rows)==len(set(rows)),'unique_new_test_methods');return rows
def literal(raw,name):
    tree=ast.parse(raw);rows=[node for node in tree.body if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id==name for target in node.targets)]
    need(len(rows)==1,'single_static_'+name);return ast.literal_eval(rows[0].value)
def parse_log(raw,expected,old_skips):
    need(type(raw) is bytes and 1<=len(raw)<=4*1024*1024,'full_log_bound')
    rows=re.findall(rb'(?m)^Ran ([0-9]+) tests in ([0-9]+(?:\.[0-9]+)?)s\r?$',raw)
    need(len(rows)==1,'one_full_test_summary');count=int(rows[0][0]);seconds=float(rows[0][1])
    ok=re.findall(rb'(?m)^OK(?: \(skipped=([0-9]+)\))?\r?$',raw)
    need(count==expected and 0<seconds<=86400 and len(ok)==1 and b'FAILED (' not in raw
        and not re.search(rb'(?m)^(?:FAIL|ERROR): ',raw),'full_suite_count_and_success')
    skips={line.strip() for line in raw.splitlines() if b' ... skipped ' in line};skip_count=int(ok[0] or b'0')
    need(skips==old_skips and skip_count==len(skips),'only_original_symlink_skips')
    return dict(tests=count,duration_seconds=seconds,failures=0,errors=0,skipped=skip_count,
        log_bytes=len(raw),log_sha256=sha(raw),linux_executed=False)

def check(freeze_path,expected_sha):
    need(expected_sha==FINAL_FREEZE_SHA256,'explicit_final_freeze_sha256')
    freeze_path=Path(freeze_path).resolve(strict=True);need(freeze_path.parent==BASE and freeze_path.name==FINAL_FREEZE_NAME,'reviewed_freeze_in_work')
    raw_freeze=read(freeze_path);need(sha(raw_freeze)==expected_sha,'reviewed_final_promotion_freeze_pin');freeze=decode(raw_freeze)
    need(freeze['actual_ready'] is True and freeze['scope']==SCOPE and freeze['source_sha256']==FINAL_SOURCE_SHA256
        and set(freeze['files'])==PY_PATHS and freeze['source_count']==36
        and type(freeze['native_pins']) is dict and len(freeze['native_pins'])==37,'final_promotion_true_four_python_paths')
    need(git('rev-parse','HEAD').decode('ascii').strip()==PRE_STAGE_HEAD,'reviewed_baseline_head')
    ids=tree_ids();need(all(name not in ids for name in CHANGES),'five_paths_are_new_at_reviewed_head')
    old_raw=read(BASE/OLD_FREEZE_NAME);need(sha(old_raw)==OLD_FREEZE_SHA256,'old_source03_freeze_pin');old=decode(old_raw)
    native_raw=read(BASE/NATIVE_FREEZE_NAME);need(sha(native_raw)==NATIVE_FREEZE_SHA256,'new_native_source01_freeze_pin');native=decode(native_raw)
    need(set(native['files'])=={NEW_CPP} and native['old_native_pins_unchanged']==old['native_pins'],'new_native_old37_binding')
    pins={}
    for name,row in {**freeze['files'],**native['files']}.items():
        raw=read(REPO/relative(name));need(b'\r' not in raw and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'five_new_frozen_lf_bytes')
        pins[name]=row['sha256']
    need(set(pins)==CHANGES,'exact_five_new_paths')
    core_raw=read(REPO/CORE);need(literal(core_raw,'ACTUAL_READY') is True and literal(core_raw,'SCOPE')==SCOPE,'new_core_promoted_explicit_scope')
    old_sources=old['source_hashes'];need(set(old_sources)==set(OLD_SOURCES) and len(old_sources)==36,'old36_runtime_names')
    shared=set(OLD_SOURCES)-OLD_MODULES;expected_sources={*shared,CORE,LOCAL}
    hashes=freeze['source_hashes'];need(set(hashes)==expected_sources and len(shared)==34 and len(hashes)==36
        and sha(canonical(hashes))==freeze['source_sha256'],'new36_runtime_shared34_closure')
    for name,digest in old_sources.items():
        raw=read(REPO/relative(name));need(sha(raw)==digest and blob_sha(raw)==ids[name][1],'old36_runtime_exact_baseline_blob')
        if name in shared:need(hashes[name]==digest,'shared34_runtime_pin_unchanged')
    for name in (CORE,LOCAL):need(hashes[name]==pins[name],'new_runtime_module_pins')
    old_native=old['native_pins'];need(len(old_native)==37 and OLD_CPP in old_native,'old37_native_names')
    expected_native={name:digest for name,digest in old_native.items() if name!=OLD_CPP};expected_native[NEW_CPP]=pins[NEW_CPP]
    need(freeze['native_pins']==expected_native and len(set(old_native)&set(expected_native))==36,'new37_native_shared36_plus_newcpp')
    for name,digest in old_native.items():
        raw=read(REPO/relative(name));need(sha(raw)==digest and blob_sha(raw)==ids[name][1],'all_old37_native_including_original_cpp_unchanged')
    # All tracked tests and validation archives/documents remain exact Git blobs.
    protected={name:value for name,value in ids.items() if name.startswith(('tests/','verification/','docs/validation/'))}
    need(protected and len(protected)<=12000,'protected_history_inventory_bound')
    total=0
    for name,(mode,digest) in protected.items():
        need(mode in ('100644','100755'),'protected_history_regular_blob')
        raw=read(REPO/name,32*1024*1024);total+=len(raw);need(total<=1024*1024*1024,'protected_history_total_bytes_bound')
        need(blob_sha(raw)==digest,'all_existing_tests_archives_validation_exact_git_blob')
    test_rows={name:test_cases(read(REPO/name)) for name in sorted(TESTS)};method_counts={name:len(rows) for name,rows in test_rows.items()}
    counts=freeze;method_total=sum(method_counts.values())
    need(counts['baseline_full_count']==872 and counts['new_test_method_counts']==method_counts
        and counts['new_test_method_count']==method_total and counts['expected_full_count']==872+method_total
        and counts['expected_full_count_is_prediction'] is True,'final_freeze_actual_new_method_count_prediction')
    need(freeze['pure']['test_method_counts']==method_counts and freeze['pure']['tests']==method_total,'author_pure_matches_only_two_new_test_modules')
    baseline_raw=read(BASE/BASELINE_RECEIPT_NAME);need(sha(baseline_raw)==BASELINE_RECEIPT_SHA256,'baseline872_receipt_pin');baseline=decode(baseline_raw)
    old_log=read(BASE/'psec-lpac-main-pure-03.log',4*1024*1024)
    need(baseline['tests']['tests']==872 and len(old_log)==baseline['tests']['log_bytes'] and sha(old_log)==baseline['tests']['log_sha256'],'baseline872_log_pin')
    old_skips={line.strip() for line in old_log.splitlines() if b' ... skipped ' in line}
    need(len(old_skips)==baseline['tests']['skipped']==2 and all(b'symlink' in line for line in old_skips),'baseline_two_original_skips')
    raw_log=read(BASE/LOG,4*1024*1024);tests=parse_log(raw_log,counts['expected_full_count'],old_skips)
    for name,rows in test_rows.items():
        module=Path(name).stem
        for cls,method in rows:need((method+' ('+module+'.'+cls+'.'+method+')').encode('ascii') in raw_log,'every_new_method_present_in_actual_full_log')
    need(not git('diff','--cached','--name-only'),'no_preexisting_staged_files')
    need(not git('diff','--name-only'),'no_existing_tracked_files_changed')
    untracked=set(git('ls-files','--others','--exclude-standard').decode('utf8').splitlines());need(untracked==CHANGES,'only_five_expected_untracked_paths')
    need(not (BASE/RECEIPT).exists(),'fresh_postassign_integrated_receipt')
    return pins,dict(schema_version=1,stage='psec-lpac-postassign-source01-integrated-pure-receipt',scope=SCOPE,
        pre_stage_head=PRE_STAGE_HEAD,final_promotion_freeze=dict(name=freeze_path.name,bytes=len(raw_freeze),sha256=sha(raw_freeze)),
        native_source_freeze=dict(name=NATIVE_FREEZE_NAME,bytes=len(native_raw),sha256=sha(native_raw)),
        runtime_source_count=36,runtime_source_sha256=freeze['source_sha256'],runtime_shared_count=34,new_runtime_module_count=2,
        old_runtime36_unchanged=True,old_native37_unchanged=True,new_native_pin_count=37,shared_native_pin_count=36,new_native_cpp_count=1,
        protected_tracked_file_count=len(protected),protected_tracked_bytes=total,
        protected_tests_count=sum(name.startswith('tests/') for name in protected),
        protected_verification_count=sum(name.startswith('verification/') for name in protected),
        protected_validation_docs_count=sum(name.startswith('docs/validation/') for name in protected),
        protected_git_tree_sha256=sha(canonical({name:value[1] for name,value in protected.items()})),
        baseline_test_count=872,new_test_method_counts=method_counts,new_test_method_count=method_total,
        existing_327_native_assertions_not_added_to_test_count=True,tests=tests,staged_files=pins,no_archive_paths_staged=True,
        old_actual01_unknown_preserved=True,old_actual02_03_and_dns_not_rewritten=True,
        test_or_native_or_actor_or_api_or_network_or_cleanup_run_by_this_script=False,postassign_experiment_executed=False)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--freeze',type=Path,default=BASE/FINAL_FREEZE_NAME)
    parser.add_argument('--freeze-sha256',default=FINAL_FREEZE_SHA256)
    parser.add_argument('--check-only',action='store_true');args=parser.parse_args(argv)
    pins,receipt=check(args.freeze,args.freeze_sha256)
    if not args.check_only:
        subprocess.run(['git','add','--',*sorted(pins)],cwd=REPO,check=True)
        names=set(git('diff','--cached','--name-only').decode('utf8').splitlines());need(names==CHANGES,'exact_five_staged_new_paths')
        for name,digest in pins.items():need(sha(git('show',':'+name))==digest,'every_staged_lf_blob_exact_frozen_byte_pin')
        raw=(json.dumps(receipt,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
        with (BASE/RECEIPT).open('xb') as stream:need(stream.write(raw)==len(raw),'fresh_integrated_receipt_write')
        need(read(BASE/RECEIPT)==raw,'integrated_receipt_readback')
    print(json.dumps(dict(check_only=args.check_only,source_paths=len(pins),runtime_source_count=36,runtime_shared_count=34,
        runtime_source_sha256=receipt['runtime_source_sha256'],new_test_methods=receipt['new_test_method_count'],tests=receipt['tests']['tests'],
        staged=not args.check_only,archive_paths_staged=False,experiment_run=False),sort_keys=True))
if __name__=='__main__':main()
