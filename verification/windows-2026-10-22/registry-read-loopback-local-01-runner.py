"""One reviewed registryRead LPAC same-SID loopback mechanism run; no retry/fallback."""
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
EXPECTED_SOURCE='069d9f2702e235f03603d11b5962f320fe0f077cd81ccfabafefd48cbd11dfb6'
EXPECTED_READY_FREEZE='48f4f10b020b78754511e1ba6c0db8dca59f5257aab6ce5e78288f391be46bac'
ACTOR_SHA='ff5ce2453d91902b516eed4d9266735579c3ee7fd936b4fbdf915ce086b531f0'
MANIFEST_SHA='72679ffee1c1e110730207b9cae747385afb8a0f4a6a65f5fe78e6b2b76758a1'

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
    freeze=BASE/'registry-read-loopback-python-candidate-freeze-02.json'
    need(sha(freeze.read_bytes())==EXPECTED_READY_FREEZE,'promoted freeze pin')
    frozen=json.loads(freeze.read_bytes())
    need(frozen['actual_ready'] is True and frozen['source_sha256']==EXPECTED_SOURCE
        and type(frozen['source_hashes']) is dict and len(frozen['source_hashes'])==37,'reviewed frozen source map')
    for name,digest in frozen['source_hashes'].items():
        raw=(REPO/name).read_bytes()
        need(sha(raw)==digest and raw==git_blob(head,name) and b'\r' not in raw,'source Git bytes before import')
    entry='.github/windows_identity_lpac_registry_loopback_local.py'
    need((REPO/entry).read_bytes()==git_blob(head,entry),'entry Git bytes')
    loader=importlib.util.spec_from_file_location('registry_read_loopback_actual01',REPO/entry)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    need(module.core.ACTUAL_READY is True and module.core.api_version()==1 and len(module.SOURCES)==37,'reviewed source interface')
    need(set(module.SOURCES)==set(frozen['source_hashes']),'exact prechecked import closure')
    need(module.SCOPE=='one-local-registry-read-same-sid-loopback-v1'
        and module.core.PROFILE=='same-sid-registry-read-lpac-loopback-mechanism-v1','independent registryRead profile')
    need(module.core.role_capabilities('selected-client')==[dict(sid='S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681',attributes=4)]
        and all(module.core.role_capabilities(role)==[] for role in ('front-listener','ordinary-listener','ordinary-client')),'exact role capability profile')
    for name in module.SOURCES:need((REPO/name).read_bytes()==git_blob(head,name),'runtime source Git bytes')
    _,hashes,closure=module.snapshot(REPO)
    need(closure==EXPECTED_SOURCE and closure==frozen['source_sha256'] and hashes==frozen['source_hashes'],'runtime37 frozen closure')
    build=BASE/'registry-read-loopback-compile-01'
    actor=build/module.core.ACTOR;manifest=build/module.core.MANIFEST
    need(sha(actor.read_bytes())==ACTOR_SHA and sha(manifest.read_bytes())==MANIFEST_SHA,'compiled actor and manifest pins')
    for name in module.core.NATIVE_SOURCES:
        raw=(REPO/name).read_bytes()
        need(raw==git_blob(head,name) and raw==(build/'src'/name).read_bytes(),'exact immutable compile source')
    parent=REPO/'private'
    artifact=parent/'registry-read-loopback-compile01-actual01';artifact.mkdir()
    for path in (actor,manifest):put(artifact/path.name,path.read_bytes())
    actor,manifest=artifact/actor.name,artifact/manifest.name
    module.core.verify_actor(actor,manifest,ACTOR_SHA,MANIFEST_SHA,root=REPO)
    api=module.local.LocalNativeAPI();module.local.ordinary(api)
    nonces={name:secrets.token_hex(16) for name in module.core.NONCES}
    need(len(set(nonces.values()))==8,'eight fresh independent nonces')
    ports=secrets.SystemRandom().sample(range(49153,65536),2)
    reference='One trusted-actor registryRead LPAC loopback assay, not isolation acceptance. Selected only registryRead attrs4; frontend/ordinary caps0. registryRead may read any existing registry key with its ACE, not just Winsock catalogs. Same fresh SID, exact held identity, both Jobs and real matrices; original120/115s budget. Only two fresh report subtrees get Modify/Low labels; controls read-only. Stop actors before label/ACL/profile cleanup; unknown retains tree. No retry/fallback or global policy changes.'
    need(1<=len(reference)<=512,'recovery reference bound')
    plan=dict(schema_version=1,scope=module.SCOPE,profile=module.core.PROFILE,**nonces,
        ports=dict(frontend=ports[0],ordinary=ports[1]),device_sha256=api.device_sha256(),
        source_sha256=closure,actor_sha256=ACTOR_SHA,manifest_sha256=MANIFEST_SHA,
        **dict.fromkeys(module.core.ACKS,True),recovery_reference=reference)
    plan_path=parent/'registry-read-loopback-recovery-plan-01.json';put(plan_path,module.encode(plan))
    evidence=REPO/'verification/windows-2026-10-22'
    args=(actor,manifest,ACTOR_SHA,MANIFEST_SHA,parent,plan_path)
    pre=module.preflight(*args)
    put(evidence/'registry-read-loopback-local-01-preflight.json',module.encode(pre))
    need(pre['status']=='ready','preflight '+str(pre['failure']))
    value=module.run_local(*args,approved=True)
    raw=module.encode(value);put(evidence/'registry-read-loopback-local-01-public.json',raw)
    print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),public_sha256=sha(raw),result=value),sort_keys=True))
    return 0 if value['status']=='observed' else 1

if __name__=='__main__':raise SystemExit(main())
