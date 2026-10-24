"""Verify/stage only frozen source03 core+test after the root's fresh full run.

Only stdlib and read-only Git are used until the final explicit git add of two
paths. No archive, actor, DLL, API, network, recovery or test is run here.
--check-only performs the same checks without staging or writing the receipt.
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
FREEZE_NAME='psec-lpac-python-diagnostic-freeze-03.json'
FREEZE_SHA256='0fafbd55ebe54ea9ed13ac7705dec0b7baa8e0cc26f7971290219f8f6683c00d'
BASELINE_COMMIT='b269c78eef15b6f71bdae5a5ee631a4e8a34ce9e'
BASELINE_RECEIPT_SHA256='c344aee51ab13d93700d08f6b615e15012ffd2933e5f2d653fbfc145523d42e8'
PRE_STAGE_HEAD='eabd009822426b469c4662e4c23ccec9de9b16b0'
CHANGES={'.github/windows_identity_psec_lpac_bridge.py','tests/test_windows_identity_psec_lpac_bridge.py'}
RUNTIME_CHANGED='.github/windows_identity_psec_lpac_bridge.py'
SOURCE_NAMES=('.github/native/windows_identity_actor.cpp', '.github/native/windows_identity_dns_raw_udp.hpp', '.github/native/windows_identity_dns_standard_probe.hpp', '.github/native/windows_identity_proxy_bridge_core.hpp', '.github/native/windows_identity_proxy_c_actor.cpp', '.github/native/windows_identity_proxy_c_contract.hpp', '.github/native/windows_identity_proxy_origin_actor.cpp', '.github/native/windows_identity_proxy_origin_transport.hpp', '.github/native/windows_identity_proxy_pipe_actor.cpp', '.github/windows_dns_fixture.py', '.github/windows_identity_dns_cases_fixture.py', '.github/windows_identity_dns_standard_inventory.ps1', '.github/windows_identity_lpac_dns_local.py', '.github/windows_identity_model2_controller.py', '.github/windows_identity_model2_dns.py', '.github/windows_identity_model2_dns_raw.py', '.github/windows_identity_model2_firewall.ps1', '.github/windows_identity_model2_live.py', '.github/windows_identity_model2_local.py', '.github/windows_identity_model2_local_probe.py', '.github/windows_identity_model2_maintenance.py', '.github/windows_identity_ordinary_launcher.py', '.github/windows_identity_pipe_probe.py', '.github/windows_identity_proof.py', '.github/windows_identity_proxy_origin_probe.py', '.github/windows_identity_proxy_pipe_ac_guest.py', '.github/windows_identity_proxy_pipe_ac_local.py', '.github/windows_identity_proxy_pipe_probe.py', '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_app_process.py', 'ruleproxy/windows_runtime_pins.py', '.github/windows_identity_lpac_accesscheck.py', '.github/windows_identity_lpac_identity_cell.py', '.github/windows_identity_psec_spec.py', '.github/windows_identity_psec_lpac_bridge.py', '.github/windows_identity_psec_lpac_bridge_local.py')

def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
def read(path,limit=2*1024*1024):
    path=Path(path).absolute()
    for part in (path,*path.parents):
        info=part.lstat();need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'no_reparse_input')
    info=path.stat();need(stat.S_ISREG(info.st_mode) and 0<=info.st_size<=limit,'file_bound')
    raw=path.read_bytes();need(len(raw)==info.st_size,'stable_read');return raw
def decode(raw):
    def pairs(rows):
        result={}
        for name,value in rows:need(name not in result,'duplicate_key');result[name]=value
        return result
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite_json')))
def relative(name):
    need(type(name) is str,'repo_relative_path_type');part=PurePosixPath(name);need(not part.is_absolute() and '..' not in part.parts and '\\' not in name,'repo_relative_path');return name
def git(*args):return subprocess.check_output(['git',*args],cwd=REPO)
def blob(commit,name):return git('show',commit+':'+relative(name))
def test_cases(raw):
    tree=ast.parse(raw);cases=[]
    for node in tree.body:
        if isinstance(node,ast.ClassDef):
            cases.extend((node.name,method.name) for method in node.body if isinstance(method,(ast.FunctionDef,ast.AsyncFunctionDef)) and method.name.startswith('test_'))
    need(cases and len(cases)==len(set(cases)),'unique_targeted_ast_methods');return cases
def parse_log(raw,expected,expected_skip_lines):
    need(type(raw) is bytes and 1<=len(raw)<=4*1024*1024,'full_log_bound')
    summaries=re.findall(rb'(?m)^Ran ([0-9]+) tests in ([0-9]+(?:\.[0-9]+)?)s\r?$',raw)
    need(len(summaries)==1,'single_main_unittest_summary')
    count=int(summaries[0][0]);duration=float(summaries[0][1]);need(count==expected and 0<duration<=86400,'actual_full_count_duration')
    success=re.findall(rb'(?m)^OK(?: \(skipped=([0-9]+)\))?\r?$',raw)
    need(len(success)==1 and b'FAILED (' not in raw and not re.search(rb'(?m)^(?:FAIL|ERROR): ',raw),'successful_full_suite')
    skip_lines={line.strip() for line in raw.splitlines() if b' ... skipped ' in line}
    skips=int(success[0] or b'0');need(skip_lines==set(expected_skip_lines) and skips==len(skip_lines),'only_original_symlink_skips')
    return dict(tests=count,duration_seconds=duration,failures=0,errors=0,skipped=skips,log_bytes=len(raw),log_sha256=sha(raw),linux_executed=False)

def check():
    raw_freeze=read(BASE/FREEZE_NAME);need(sha(raw_freeze)==FREEZE_SHA256,'final_author_freeze_pin');freeze=decode(raw_freeze)
    need(freeze['baseline_commit']==BASELINE_COMMIT and freeze['source_count']==36 and set(freeze['files'])==CHANGES
        and freeze['native_unchanged'] is True and freeze['native_pin_count']==37 and freeze['unchanged_runtime_count']==35,'frozen_scope')
    need(git('rev-parse','HEAD').decode('ascii').strip()==PRE_STAGE_HEAD,'reviewed_pre_stage_head')
    pins={}
    for name,row in freeze['files'].items():
        raw=read(REPO/relative(name));need(b'\r' not in raw and len(raw)==row['bytes'] and sha(raw)==row['sha256'],'changed_file_frozen_lf_bytes');pins[name]=row['sha256']
    sources=freeze['source_hashes'];need(type(sources) is dict and set(sources)==set(SOURCE_NAMES) and len(sources)==36,'closed_runtime36_names')
    need(sha(canonical(sources))==freeze['source_sha256'],'source36_closure')
    unchanged=freeze['unchanged_runtime'];need(set(unchanged)==set(SOURCE_NAMES)-{RUNTIME_CHANGED} and len(unchanged)==35,'exact35_unchanged_runtime')
    for name,digest in sources.items():
        raw=read(REPO/relative(name));need(b'\r' not in raw and sha(raw)==digest,'all_runtime36_pre_import_bytes')
        before=blob(BASELINE_COMMIT,name);need(before==blob(PRE_STAGE_HEAD,name),'publication_commit_did_not_change_runtime')
        if name!=RUNTIME_CHANGED:need(raw==before and digest==unchanged[name],'unchanged_runtime35_exact_blob')
    need(sources[RUNTIME_CHANGED]==pins[RUNTIME_CHANGED],'changed_core_source_pin')
    native=freeze['native_pins'];need(type(native) is dict and len(native)==37,'native37_pins')
    for name,digest in native.items():
        raw=read(REPO/relative(name));need(sha(raw)==digest and raw==blob(BASELINE_COMMIT,name)==blob(PRE_STAGE_HEAD,name),'native37_unchanged')
    test_name='tests/test_windows_identity_psec_lpac_bridge.py';current_cases=test_cases(read(REPO/test_name));before_test=blob(BASELINE_COMMIT,test_name)
    need(before_test==blob(PRE_STAGE_HEAD,test_name),'publication_commit_did_not_change_old_tests');baseline_cases=test_cases(before_test)
    counts=freeze['tests'];raw_baseline=read(BASE/'psec-lpac-integrated-pure-02.json');need(sha(raw_baseline)==BASELINE_RECEIPT_SHA256,'baseline_full_receipt_pin');baseline=decode(raw_baseline)
    need(baseline['runtime_source_count']==36 and baseline['runtime_source_sha256']=='7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba'
        and baseline['tests']['tests']==863 and counts['baseline_full_count']==baseline['tests']['tests'],'baseline_full_receipt')
    need(counts['baseline_targeted_count']==len(baseline_cases)==16 and counts['targeted_count']==len(current_cases)
        and counts['added_targeted_count']==len(current_cases)-len(baseline_cases)>0
        and counts['expected_full_count']==counts['baseline_full_count']+counts['added_targeted_count']
        and counts['expected_full_count_is_prediction'] is True,'expected_count_derived_from_final_freeze_and_ast')
    old_log=read(BASE/'psec-lpac-main-pure-02.log',4*1024*1024)
    need(sha(old_log)==baseline['tests']['log_sha256'] and len(old_log)==baseline['tests']['log_bytes'],'baseline_log_pin')
    old_skip_lines={line.strip() for line in old_log.splitlines() if b' ... skipped ' in line}
    need(len(old_skip_lines)==baseline['tests']['skipped']==2 and all(b'symlink' in line for line in old_skip_lines),'baseline_only_old_symlink_skips')
    raw_log=read(BASE/'psec-lpac-main-pure-03.log',4*1024*1024);tests=parse_log(raw_log,counts['expected_full_count'],old_skip_lines)
    for classname,method in current_cases:
        identifier=(method+' (test_windows_identity_psec_lpac_bridge.'+classname+'.'+method+')').encode('ascii')
        need(identifier in raw_log,'every_frozen_targeted_test_appears_in_actual_full_log')
    # Read/freeze archive evidence only. Nothing below adds archive files.
    archive_records=[]
    for attempt,public_sha in (('01','cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c'),
            ('02','100dc78f9af83445829a9f8ddf03ebe1f6bb5fc3af8f1a694e43bb78229daba2')):
        prefix='verification/windows-2026-10-22/psec-lpac-identity-local-'+attempt
        index_name=prefix+'-evidence-index.json';raw_index=read(REPO/index_name);need(raw_index==blob(PRE_STAGE_HEAD,index_name),'immutable_actual_index')
        index=decode(raw_index);need(len(index['files'])==12,'actual_archive12_plus_index')
        seen=set()
        for row in index['files']:
            name=relative(row['path']);need(name.startswith(prefix+'-') and name not in seen,'closed_actual_archive_path');seen.add(name)
            raw=read(REPO/name,4*1024*1024);need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and raw==blob(PRE_STAGE_HEAD,name),'immutable_actual_archive_bytes')
        public=decode(read(REPO/(prefix+'-public.json')));need(sha(read(REPO/(prefix+'-public.json')))==public_sha,'original_actual_public')
        need(public['status']=='inconclusive' and public['observation_complete'] is False,'historical_no_acceptance')
        if attempt=='01':need(public['recovery_required'] is public['broker_outcome_unknown'] is True and public['failure']=='report','original01_unknown_preserved')
        else:need(public['recovery_required'] is public['broker_outcome_unknown'] is False and public['failure']=='admission','original02_result_preserved')
        archive_records.append(dict(attempt=int(attempt),files=13,index_sha256=sha(raw_index),original_public_sha256=public_sha,
            original_recovery_required=public['recovery_required'],original_broker_outcome_unknown=public['broker_outcome_unknown']))
    for name in ('docs/validation/2026-10-23-psec-lpac-identity-01.md','docs/validation/2026-10-23-psec-lpac-identity-02.md',
            'docs/validation/2026-10-23-lpac-semantic-dns-02.md',
            'verification/windows-2026-10-22/psec-lpac-identity-local-01-checkpoint.json',
            'verification/windows-2026-10-22/psec-lpac-identity-local-02-checkpoint.json',
            'verification/windows-2026-10-22/lpac-semantic-dns-local-02-checkpoint.json',
            'verification/windows-2026-10-22/lpac-semantic-dns-local-02-public.json'):
        need(read(REPO/name)==blob(PRE_STAGE_HEAD,name),'immutable_history_and_dns_checkpoint')
    need(not git('diff','--cached','--name-only'),'no_existing_staged_files')
    changed=set(git('diff','--name-only').decode('utf8').splitlines());need(changed==CHANGES,'exact_two_tracked_worktree_changes')
    need(not (BASE/'psec-lpac-integrated-pure-03.json').exists(),'fresh_integrated03_receipt_required')
    return pins,dict(schema_version=1,stage='psec-lpac-source03-integrated-pure-receipt',baseline_source_commit=BASELINE_COMMIT,
        pre_stage_head=PRE_STAGE_HEAD,runtime_source_count=36,runtime_source_sha256=freeze['source_sha256'],
        runtime_changed_files=[RUNTIME_CHANGED],runtime_unchanged_count=35,native_unchanged_pin_count=37,
        final_author_freeze=dict(bytes=len(raw_freeze),sha256=sha(raw_freeze)),tests=tests,
        frozen_targeted_test_count=len(current_cases),added_targeted_test_count=len(current_cases)-len(baseline_cases),
        actual_full_count_equals_final_prediction=True,preserved_actual_archives=archive_records,
        original01_recovery_required=True,original01_broker_outcome_unknown=True,
        no_archive_paths_staged=True,staged_files=pins,source03_experiment_executed=False,dll_rebuilt_by_this_script=False,
        test_or_actor_or_api_or_network_or_cleanup_run_by_this_script=False)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--check-only',action='store_true');args=parser.parse_args(argv)
    pins,receipt=check()
    if not args.check_only:
        subprocess.run(['git','add','--',*sorted(pins)],cwd=REPO,check=True)
        names=set(git('diff','--cached','--name-only').decode('utf8').splitlines());need(names==CHANGES,'exact_two_staged_source_paths')
        for name,digest in pins.items():need(sha(git('show',':'+name))==digest,'exact_staged_blob_byte_pin')
        raw=(json.dumps(receipt,sort_keys=True,indent=2,ensure_ascii=True,allow_nan=False)+'\n').encode('ascii')
        with (BASE/'psec-lpac-integrated-pure-03.json').open('xb') as stream:need(stream.write(raw)==len(raw),'fresh_receipt_write')
        need(read(BASE/'psec-lpac-integrated-pure-03.json')==raw,'receipt_readback')
    print(json.dumps(dict(check_only=args.check_only,source_paths=len(pins),runtime_source_count=36,runtime_unchanged_count=35,
        runtime_source_sha256=receipt['runtime_source_sha256'],tests=receipt['tests']['tests'],
        staged=not args.check_only,archive_paths_staged=False,experiment_run=False),sort_keys=True))
if __name__=='__main__':main()
