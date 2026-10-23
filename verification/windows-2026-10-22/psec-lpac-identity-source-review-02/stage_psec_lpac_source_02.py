"""Verify new diagnostics and stage source plus the immutable failed attempt."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
BASE=Path(__file__).resolve().parent;REPO=BASE/'Rule-proxy-Web'
def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def main():
    freeze=json.loads((BASE/'psec-lpac-python-candidate-freeze-02.json').read_bytes())
    pins={name:value['sha256'] for name,value in freeze['files'].items()};need(len(pins)==4,'four_changes')
    for name,digest in pins.items():need(sha((REPO/name).read_bytes())==digest,'freeze_pin')
    loader=importlib.util.spec_from_file_location('cpse_stage_source02',REPO/'.github/windows_identity_psec_lpac_bridge_local.py')
    m=importlib.util.module_from_spec(loader);loader.loader.exec_module(m);_,_,closure=m.snapshot(REPO)
    need(closure==freeze['source_sha256']=='7de9968d0984cc7304951ba220d806fea74e998c0a623beddd870a0eb1e0f0ba','runtime36')
    log=(BASE/'psec-lpac-main-pure-02.log').read_bytes()
    need(b'Ran 863 tests in 49.893s' in log and b'OK (skipped=2)' in log and b'FAILED (' not in log,'pure863')
    archive_names=(BASE/'stage_psec_lpac_identity_local_01_paths.txt').read_text(encoding='ascii').splitlines()
    need(len(archive_names)==13 and len(set(archive_names))==13,'archive13')
    public=REPO/'verification/windows-2026-10-22/psec-lpac-identity-local-01-public.json'
    need(sha(public.read_bytes())=='cc562d1b045fea336c4257051faa52e63aa415d91556a4ea84f18aa363652f9c','old_public_immutable')
    index=json.loads((public.with_name('psec-lpac-identity-local-01-evidence-index.json')).read_bytes())
    for row in index['files']:
        raw=(REPO/row['path']).read_bytes();need(len(raw)==row['bytes'] and sha(raw)==row['sha256'],'old_archive_pin')
    for name in archive_names:
        need(name.startswith('verification/windows-2026-10-22/psec-lpac-identity-local-01-'),'archive_path')
        pins[name]=sha((REPO/name).read_bytes())
    need(len(pins)==17,'stage17')
    need(not subprocess.check_output(['git','diff','--cached','--name-only'],cwd=REPO),'no_existing_staged_files')
    subprocess.run(['git','add','--',*sorted(pins)],cwd=REPO,check=True)
    names=set(subprocess.check_output(['git','diff','--cached','--name-only'],cwd=REPO,text=True).splitlines());need(names==set(pins),'exact_staged_set')
    for name,digest in pins.items():need(sha(subprocess.check_output(['git','show',':'+name],cwd=REPO))==digest,'staged_bytes')
    receipt=dict(schema_version=1,stage='psec-lpac-source02-integrated-pure-receipt',runtime_source_count=36,runtime_source_sha256=closure,
        tests=dict(tests=863,failures=0,errors=0,skipped=2,duration_seconds=49.893,log_bytes=len(log),log_sha256=sha(log),linux_executed=False),
        original01_public_sha256=sha(public.read_bytes()),original01_recovery_required=True,original01_broker_outcome_unknown=True,
        staged_files=pins,source02_experiment_executed=False,dll_rebuilt=False)
    raw=(json.dumps(receipt,sort_keys=True,indent=2)+'\n').encode('ascii')
    with (BASE/'psec-lpac-integrated-pure-02.json').open('xb') as stream:need(stream.write(raw)==len(raw),'receipt')
    print(json.dumps(dict(staged_files=len(pins),runtime_source_sha256=closure,receipt_sha256=sha(raw),tests=863)))
if __name__=='__main__':main()
