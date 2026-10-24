"""Root authorized ready-only promotion and add-only source installation."""
import ast
import copy
import difflib
import hashlib
import json
from pathlib import Path
import subprocess

BASE=Path(__file__).resolve().parent;REPO=BASE/'Rule-proxy-Web';CAND=BASE/'psec-lpac-matchedcaps-candidate'
sha=lambda raw:hashlib.sha256(raw).hexdigest()
def need(ok,label):
    if not ok:raise ValueError(label)
def read_pin(name,digest):
    raw=(BASE/name).read_bytes();need(sha(raw)==digest,'frozen input '+name);return raw,json.loads(raw)
def encode(v):return (json.dumps(v,sort_keys=True,ensure_ascii=True,indent=2)+'\n').encode('ascii')
def canonical(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')
def put(path,raw):
    need(not path.exists(),'fresh output '+path.name);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('xb') as f:need(f.write(raw)==len(raw),'write')
def git(*args):
    r=subprocess.run(['git','-C',str(REPO),*args],capture_output=True);need(r.returncode==0,'git');return r.stdout
def main():
    need(not git('status','--porcelain'),'main clean before add-only source installation')
    before_head=git('rev-parse','HEAD').decode().strip()
    need(before_head=='3c3a6b56f11d8f5bbdb4625a151982d905c6c51b','reviewed publication baseline')
    false_raw,p=read_pin('psec-lpac-matchedcaps-python-candidate-freeze-02.json','3d5ac7715ee8effdc7a9e816defba096892ce33a3e5027aea8ed6654580268b8')
    nr,n=read_pin('psec-lpac-matchedcaps-native-freeze-01.json','7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f')
    ir,i=read_pin('psec-lpac-matchedcaps-python-independent-review-02.json','edd3c3a63b406e7bdbd45ef906b5e97d0bf776a057e4f6e562546c47807d8d79')
    cr,c=read_pin('psec-lpac-matchedcaps-source-closure-independent-review-02.json','2a428287c002adf43f2f45331e09ab1fa0f6f421f752d7bd19d6071e6088292a')
    need(not p['actual_ready'] and i['decision']=='GO-for-root-review-and-separate-promotion-only','False candidate reviewed')
    files={**p['files'],**n['files']};need(len(files)==8,'two modules three native three test files')
    for name,row in files.items():
        raw=(CAND/name).read_bytes();need(len(raw)==row['bytes'] and sha(raw)==row['sha256'] and b'\r' not in raw,'eight candidate frozen LF bytes')
        need(not (REPO/name).exists(),'no existing source overwritten')
    for name,row in p['old_scope_files'].items():need(sha((REPO/name).read_bytes())==row['sha256'],'old scopes unchanged')
    for name,digest in n['old_37_inputs_unchanged'].items():need(sha((REPO/name).read_bytes())==digest,'old native37 unchanged')
    for name,digest in p['source_hashes'].items():
        if name not in p['files']:need(sha((REPO/name).read_bytes())==digest and (REPO/name).read_bytes()==git('show','HEAD:'+name),'shared34 exact Git')
    core='.github/windows_identity_psec_lpac_matchedcaps_bridge.py';raw=(CAND/core).read_bytes()
    need(raw.count(b'ACTUAL_READY=False')==1 and b'ACTUAL_READY=True' not in raw,'single ready literal')
    put(BASE/'psec-lpac-matchedcaps-python-core-false02.py',raw)
    promoted=raw.replace(b'ACTUAL_READY=False',b'ACTUAL_READY=True',1);(CAND/core).write_bytes(promoted)
    q=copy.deepcopy(p);q.update(stage='root-reviewed-ready-only-three-held-promotion03',actual_ready=True,actual_executed=False,independent_review_pending=False,
        pre_install_head=before_head,prior_false_freeze=dict(bytes=len(false_raw),sha256=sha(false_raw)),
        independent_false_source_review=dict(bytes=len(ir),sha256=sha(ir)),source_closure_review=dict(bytes=len(cr),sha256=sha(cr)),
        native_freeze=dict(bytes=len(nr),sha256=sha(nr)),promotion_only_ready_literal=True,
        promoted_pure_not_yet_run=True,baseline_full_test_count=922,new_native_test_method_count=3,expected_full_test_count=955)
    q['files'][core]=dict(bytes=len(promoted),sha256=sha(promoted));q['source_hashes'][core]=sha(promoted)
    q['source_sha256']=sha(canonical(q['source_hashes']));q['native_pins']={**n['native_sources'],**n['dependencies']}
    q['pre_promotion_author_pure']=q.pop('pure');q.pop('patch');q.pop('abi')
    methods={}
    for name,row in files.items():
        if name.startswith('tests/'):
            tree=ast.parse((CAND/name).read_bytes());methods[name]=sum(isinstance(x,(ast.FunctionDef,ast.AsyncFunctionDef)) and x.name.startswith('test_') for x in ast.walk(tree))
    need(sum(methods.values())==33,'thirty Python plus three portable native tests')
    q['all_new_test_method_counts']=methods
    patch=[]
    for name in sorted(p['files']):patch.extend(difflib.unified_diff([], (CAND/name).read_text().splitlines(True),fromfile='/dev/null',tofile='b/'+name))
    patch_raw=''.join(patch).encode('utf8');patch_path=BASE/'psec-lpac-matchedcaps-python-candidate-03.patch';put(patch_path,patch_raw)
    q['patch']=dict(name=patch_path.name,bytes=len(patch_raw),sha256=sha(patch_raw))
    freeze_path=BASE/'psec-lpac-matchedcaps-python-candidate-freeze-03.json';freeze_raw=encode(q);put(freeze_path,freeze_raw)
    for name in sorted(files):put(REPO/name,(CAND/name).read_bytes())
    need(set(git('ls-files','--others','--exclude-standard').decode().splitlines())==set(files),'only eight new files')
    need(not git('diff','--name-only') and not git('diff','--cached','--name-only'),'existing files/index unchanged')
    listing=BASE/'stage_psec_lpac_matchedcaps_source_03_paths.txt';put(listing,''.join(n+'\n' for n in sorted(files)).encode('ascii'))
    print(json.dumps(dict(promoted=True,source_installed=True,git_staged=False,new_files=8,new_test_methods=33,full_expected=955,
        freeze_sha256=sha(freeze_raw),runtime36_sha256=q['source_sha256'],old_sources_unchanged=True,native_or_network_executed=False)))
if __name__=='__main__':main()
