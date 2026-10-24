"""Stage only the reviewed eight new files after the full 955-test gate."""
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
BASE=Path(__file__).resolve().parent;REPO=BASE/'Rule-proxy-Web';CAND=BASE/'psec-lpac-matchedcaps-candidate'
sha=lambda b:hashlib.sha256(b).hexdigest()
def need(x,s):
    if not x:raise ValueError(s)
def git(*args):
    r=subprocess.run(['git','--literal-pathspecs','-C',str(REPO),*args],capture_output=True);need(r.returncode==0,'git');return r.stdout
def main():
    head=git('rev-parse','HEAD').decode().strip();need(head=='3c3a6b56f11d8f5bbdb4625a151982d905c6c51b','base')
    need(not git('diff','--name-only') and not git('diff','--cached','--name-only'),'no previous file or staged changes')
    fr=(BASE/'psec-lpac-matchedcaps-python-candidate-freeze-03.json').read_bytes();need(sha(fr)=='dfdfcf9a9afd67fc9f15e0a252fdfcd672f3bcfd07417ba3a23e259a4537e762','promotion freeze')
    nf=(BASE/'psec-lpac-matchedcaps-native-freeze-01.json').read_bytes();need(sha(nf)=='7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f','native freeze')
    f,n=json.loads(fr),json.loads(nf);files={**f['files'],**n['files']};need(len(files)==8,'exact eight')
    need(set(git('ls-files','--others','--exclude-standard').decode().splitlines())==set(files),'only reviewed new paths')
    for name,row in files.items():
        raw=(REPO/name).read_bytes();need(raw==(CAND/name).read_bytes() and len(raw)==row['bytes'] and sha(raw)==row['sha256'] and b'\r' not in raw,'frozen new LF bytes')
    canonical=(json.dumps(f['source_hashes'],sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
    need(f['actual_ready'] is True and len(f['source_hashes'])==36 and sha(canonical)==f['source_sha256']=='f77fdff1de75ba53d6dca04d65659deb43fd6bdc91c2feaf1c6a03ade7c008db','promoted runtime36')
    for name,digest in {**f['source_hashes'],**f['native_pins']}.items():
        raw=(REPO/name).read_bytes();need(sha(raw)==digest,'new closure')
        if name not in files:need(git('show','HEAD:'+name)==raw,'shared Git bytes')
    for name,row in f['old_scope_files'].items():need(sha((REPO/name).read_bytes())==row['sha256'],'old scope bytes')
    for name,digest in n['old_37_inputs_unchanged'].items():need(sha((REPO/name).read_bytes())==digest,'old native37')
    methods={name:sum(isinstance(x,ast.FunctionDef) and x.name.startswith('test_') for x in ast.walk(ast.parse((REPO/name).read_bytes()))) for name in files if name.startswith('tests/')}
    need(sum(methods.values())==33,'33 new test methods')
    log=(BASE/'psec-lpac-matchedcaps-main-pure-01.log').read_bytes()
    need(re.findall(rb'Ran ([0-9]+) tests in ([0-9.]+)s',log)==[(b'955',b'83.640')] and b'OK (skipped=2)' in log and b'FAILED' not in log,'full955 original log')
    need(b'MATCHEDCAPS_SC_FAKE_CHECKS 100' in log and b'MATCHEDCAPS_ROLE_FAKE_CHECKS 154' in log,'portable production assertions executed')
    git('add','--',*sorted(files));need(set(git('diff','--cached','--name-only').decode().splitlines())==set(files),'only eight staged')
    for name in files:need(git('show',':'+name)==(REPO/name).read_bytes(),'staged original LF')
    git('diff','--cached','--check')
    receipt=dict(schema_version=1,stage='matchedcaps-source03-integrated-pure',pre_stage_head=head,source_scope=f['scope'],constructor_policy=f['constructor_policy'],
        source_sha256=f['source_sha256'],runtime_source_count=36,runtime_shared_count=34,native_source_count=6,native_dependency_count=31,new_source_and_test_files=files,
        all_new_test_method_counts=methods,baseline_tests=922,new_python_tests=30,new_native_tests=3,full_expected=955,
        tests=dict(tests=955,seconds=83.640,failures=0,errors=0,skips=2,existing_symlink_skips=True,log_bytes=len(log),log_sha256=sha(log),linux_executed=False),
        native_compiled_assertions=254,native_compiled_assertions_are_in_three_tests=True,old_327_assertions_not_added_as_new_tests=True,
        promotion_freeze_sha256=sha(fr),native_freeze_sha256=sha(nf),old_scopes_and_shared_sources_unchanged=True,
        actual_experiment_executed=False,dll_loaded=False,network_executed=False)
    path=BASE/'psec-lpac-matchedcaps-integrated-pure-01.json';need(not path.exists(),'fresh receipt')
    raw=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode('ascii')
    with path.open('xb') as stream:need(stream.write(raw)==len(raw),'receipt write')
    print(json.dumps(dict(staged_files=8,tests=955,seconds=83.640,failures=0,skips=2,native_assertions=254,receipt_sha256=sha(raw))))
if __name__=='__main__':main()
