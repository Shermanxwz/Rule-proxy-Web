"""One reviewed zero-cap same-SID loopback mechanism run; no retry/fallback."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
# Root fills this only after independent review and ready-only source promotion.
EXPECTED_SOURCE='b726d48d6dddfed2533168ac0921add834488f333931f08b75dc6195cd9fc4ac'
EXPECTED_READY_FREEZE='086940edb854de4a54cc6ced7068972b7cc02e77e7eaebeb522f0eac93da242f'
ACTOR_SHA='5015367a6edeaefd1830f5a6584024894070926ea5012c343534e43054b0461d'
MANIFEST_SHA='0c371e646873d3970bb3aea2e05ba05a10bb1b3e0b4c02c84963f7f265537a52'

def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def put(path,raw):
    with path.open('xb') as stream:need(stream.write(raw)==len(raw),'exact fresh write')
def git_blob(head,name):return subprocess.check_output(['git','show',head+':'+name],cwd=REPO)

def main():
    need(len(EXPECTED_SOURCE)==64 and len(EXPECTED_READY_FREEZE)==64,'root review pending')
    need(len(sys.argv)==2 and len(sys.argv[1])==40,'explicit frozen source commit')
    head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()
    need(head==sys.argv[1],'exact source HEAD')
    freeze=BASE/'zero-cap-loopback02-python-candidate-freeze-02.json'
    need(sha(freeze.read_bytes())==EXPECTED_READY_FREEZE,'promoted freeze pin')
    frozen=json.loads(freeze.read_bytes())
    need(frozen['actual_ready'] is True and frozen['source_sha256']==EXPECTED_SOURCE
        and type(frozen['source_hashes']) is dict and len(frozen['source_hashes'])==37,'reviewed frozen source map')
    for name,digest in frozen['source_hashes'].items():
        raw=(REPO/name).read_bytes()
        need(sha(raw)==digest and raw==git_blob(head,name) and b'\r' not in raw,'source Git bytes before import')
    entry='.github/windows_identity_lpac_loopback_local.py'
    need((REPO/entry).read_bytes()==git_blob(head,entry),'entry Git bytes')
    loader=importlib.util.spec_from_file_location('zero_cap_loopback_actual02',REPO/entry)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    need(module.core.ACTUAL_READY is True and module.core.api_version()==1 and len(module.SOURCES)==37,'reviewed source interface')
    need(set(module.SOURCES)==set(frozen['source_hashes']),'exact prechecked import closure')
    for name in module.SOURCES:need((REPO/name).read_bytes()==git_blob(head,name),'runtime source Git bytes')
    _,hashes,closure=module.snapshot(REPO)
    need(closure==EXPECTED_SOURCE and closure==frozen['source_sha256'] and hashes==frozen['source_hashes'],'runtime37 frozen closure')
    build=BASE/'zero-cap-loopback-compile-01'
    actor=build/module.core.ACTOR;manifest=build/module.core.MANIFEST
    need(sha(actor.read_bytes())==ACTOR_SHA and sha(manifest.read_bytes())==MANIFEST_SHA,'compiled actor and manifest pins')
    for name in module.core.NATIVE_SOURCES:
        raw=(REPO/name).read_bytes()
        need(raw==git_blob(head,name) and raw==(build/'src'/name).read_bytes(),'exact immutable compile source')
    parent=REPO/'private'
    artifact=parent/'zero-cap-loopback-compile01-actual02';artifact.mkdir()
    for path in (actor,manifest):put(artifact/path.name,path.read_bytes())
    actor,manifest=artifact/actor.name,artifact/manifest.name
    module.core.verify_actor(actor,manifest,ACTOR_SHA,MANIFEST_SHA,root=REPO)
    api=module.local.LocalNativeAPI();module.local.ordinary(api)
    nonces={name:secrets.token_hex(16) for name in module.core.NONCES}
    need(len(set(nonces.values()))==8,'eight fresh independent nonces')
    ports=secrets.SystemRandom().sample(range(49153,65536),2)
    reference=('One fixed trusted-actor reachability assay, not isolation acceptance. '
        'Fresh owned profile; AC and LPAC use same SID and zero capabilities. '
        'Only two fresh report subtrees get package Modify and Low mandatory labels; '
        'controls are read-only. Exact identity, both Jobs, actual held matrices, '
        'original120/115s budget and once cleanup required. Stop actors before label/ACL restoration '
        'and profile deletion; unknown retains tree for review. No retry, capability fallback or global network changes.')
    need(1<=len(reference)<=512,'recovery reference bound')
    plan=dict(schema_version=1,scope=module.SCOPE,profile=module.core.PROFILE,**nonces,
        ports=dict(frontend=ports[0],ordinary=ports[1]),device_sha256=api.device_sha256(),
        source_sha256=closure,actor_sha256=ACTOR_SHA,manifest_sha256=MANIFEST_SHA,
        **dict.fromkeys(module.core.ACKS,True),recovery_reference=reference)
    plan_path=parent/'zero-cap-loopback-recovery-plan-02.json';put(plan_path,module.encode(plan))
    evidence=REPO/'verification/windows-2026-10-22'
    args=(actor,manifest,ACTOR_SHA,MANIFEST_SHA,parent,plan_path)
    pre=module.preflight(*args)
    put(evidence/'zero-cap-loopback-local-02-preflight.json',module.encode(pre))
    need(pre['status']=='ready','preflight '+str(pre['failure']))
    value=module.run_local(*args,approved=True)
    raw=module.encode(value);put(evidence/'zero-cap-loopback-local-02-public.json',raw)
    print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),public_sha256=sha(raw),result=value),sort_keys=True))
    return 0 if value['status']=='observed' else 1

if __name__=='__main__':raise SystemExit(main())
