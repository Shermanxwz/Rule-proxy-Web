"""Root-reviewed one-shot driver CANDIDATE. Default: file-only preview.

Final Python Ready/source pins are intentionally absent until independent
review. No actor/API, output directory, artifact copy, nonce or plan is created
without --execute-root-reviewed and all final source/artifact gates.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import secrets
import subprocess

BASE=Path(__file__).resolve().parent
REPO=BASE/'Rule-proxy-Web'
ENTRY='.github/windows_identity_lpac_pipe_origin_local.py'
SCOPE='one-local-semantic-lpac-held-ipc-relay-origin-v1'
PROFILE='zero-cap-lpac-fixed-pipe-origin-mechanism-v1'
# Root must fill these ONLY from the final independently reviewed promotion.
EXPECTED_SOURCE='d136e22b2dfbdb991cfbef06d5dd7a54d687135bedbff653ada5e4d01ab88a61'
EXPECTED_SOURCE_COUNT=40
EXPECTED_READY_FREEZE_NAME='lpac-pipe-origin-ready-source-freeze-02.json'
EXPECTED_READY_FREEZE='99719b7d6a22a03b59f639fd4cb06a9588701e744d47a1f98c1e9df0b5fd329d'
SELECTED_BUILD=BASE/'lpac-pipe-front-compile-01'
SELECTED_ACTOR='windows_identity_lpac_pipe_front_actor.exe'
SELECTED_MANIFEST='identity-lpac-pipe-front-manifest.json'
SELECTED_SHA='8d4f0628b9f254ba868753342e0b4d06a472de38912c12fe3b44d873823488e6'
SELECTED_MANIFEST_SHA='9a1a77084d987e663a72cb076035de802f55f04ff536087ebb387662045cdbeb'
SELECTED_NATIVE={
    'actorSourceSha256':'.github/native/windows_identity_lpac_pipe_front_actor.cpp',
    'pipeActorSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
    'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
    'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp'}
SELECTED_PE_REVIEW_SHA='6859172be6bf1b40e2dcb6b1fa38738390e64430cb600dc67182e330dcd48dd9'
ORIGIN_BUILD=BASE/'proxy-origin-compile-03'
ORIGIN_ACTOR='windows_identity_proxy_origin_actor.exe'
ORIGIN_MANIFEST='identity-proxy-origin-manifest.json'
ORIGIN_SHA='042562a096a9f488b7a52ee8eb894af0b26dc679a05dc8948a9ae159b71cf161'
ORIGIN_MANIFEST_SHA='5b3660539e70bc53d004b2ee3b7b13bfa7fe6418042e57bbd0263b03cef4a456'
ORIGIN_NATIVE={
    'actorSourceSha256':'.github/native/windows_identity_proxy_origin_actor.cpp',
    'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
    'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp',
    'pipeHelperSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
    'originTransportSha256':'.github/native/windows_identity_proxy_origin_transport.hpp'}
EXPECTED_ACKS=('fresh_profile_owned_acl_acknowledged','zero_capabilities_no_fallback_acknowledged',
    'trusted_actor_mechanism_only_acknowledged','cooperative_fixed_frame_mapping_acknowledged',
    'inherited_pipe_authority_acknowledged','residue_review_acknowledged')
PRIVATE=REPO/'private'
ARTIFACT=PRIVATE/'lpac-pipe-origin-compile01-origin03-actual01'
PLAN=PRIVATE/'lpac-pipe-origin-recovery-plan-01.json'
EVIDENCE=REPO/'verification/windows-2026-10-22'
PREFLIGHT=EVIDENCE/'lpac-pipe-origin-local-01-preflight.json'
PUBLIC=EVIDENCE/'lpac-pipe-origin-local-01-public.json'
BEFORE=PRIVATE/'lpac-pipe-origin-before-ipc01-global-snapshot.json'
BASELINE_SHA='f05d91ee76ee8a97ae5ab3bfa092167a8ee560c083255f142e6c453f2edf7ab3'

def need(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(v):return type(v) is str and re.fullmatch('[0-9a-f]{64}',v) is not None
def unique(pairs):
    out={}
    for key,value in pairs:
        need(key not in out,'duplicate JSON key');out[key]=value
    return out
def decode(raw):
    return json.loads(raw.decode('utf-8-sig','strict'),object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def bounded(path,limit):
    path=Path(path);need(path.is_file() and not path.is_symlink(),'regular pinned file')
    need(0<path.stat().st_size<=limit,'bounded pinned file')
    raw=path.read_bytes();need(0<len(raw)<=limit,'bounded exact file');return raw
def put(path,raw):
    with Path(path).open('xb') as stream:
        need(stream.write(raw)==len(raw),'exact fresh write');stream.flush()
def git_blob(head,name):return subprocess.check_output(['git','show',head+':'+name],cwd=REPO)
def inspect_artifact(build,actor,manifest,actor_sha,manifest_sha,pins,interface):
    actorraw=bounded(build/actor,8*1024*1024);raw=bounded(build/manifest,8192);v=decode(raw)
    keys={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*pins}
    if interface:keys.add('interfaceVersion')
    need(type(v) is dict and set(v)==keys and type(v['schemaVersion']) is int and v['schemaVersion']==1
        and v['compileOnly'] is True and v['runtimeAcceptance'] is False,'exact compiled manifest')
    if interface:need(type(v['interfaceVersion']) is int and v['interfaceVersion']==1,'selected interface1')
    need(sha(actorraw)==actor_sha and sha(raw)==manifest_sha and v['executableSha256']==actor_sha,'artifact byte pins')
    need(all(digest(v[key]) for key in pins),'native source digests')
    return actorraw,raw,v
def inspect_inputs():
    selected=inspect_artifact(SELECTED_BUILD,SELECTED_ACTOR,SELECTED_MANIFEST,SELECTED_SHA,SELECTED_MANIFEST_SHA,SELECTED_NATIVE,True)
    origin=inspect_artifact(ORIGIN_BUILD,ORIGIN_ACTOR,ORIGIN_MANIFEST,ORIGIN_SHA,ORIGIN_MANIFEST_SHA,ORIGIN_NATIVE,False)
    review=bounded(BASE/'lpac-pipe-front-compile-independent-review-01.json',64*1024)
    need(sha(review)==SELECTED_PE_REVIEW_SHA,'independent selected PE review pin')
    return selected,origin
def frozen_source(head):
    need(digest(EXPECTED_SOURCE) and digest(EXPECTED_READY_FREEZE) and type(EXPECTED_SOURCE_COUNT) is int
        and EXPECTED_SOURCE_COUNT>0 and EXPECTED_READY_FREEZE_NAME!='PENDING_ROOT_REVIEW','final root-reviewed Ready pins pending')
    need(Path(EXPECTED_READY_FREEZE_NAME).name==EXPECTED_READY_FREEZE_NAME,'fixed freeze basename')
    raw=bounded(BASE/EXPECTED_READY_FREEZE_NAME,256*1024);need(sha(raw)==EXPECTED_READY_FREEZE,'final Ready freeze pin')
    frozen=decode(raw)
    need(frozen['actual_ready'] is True and frozen['source_sha256']==EXPECTED_SOURCE and type(frozen['source_hashes']) is dict
        and len(frozen['source_hashes'])==EXPECTED_SOURCE_COUNT,'promoted exact source map')
    hashes=frozen['source_hashes'];need(ENTRY in hashes and all(digest(v) for v in hashes.values()),'preimport closure')
    for name,digest_value in hashes.items():
        need(type(name) is str and name.startswith(('.github/','ruleproxy/')) and '..' not in Path(name).parts,'source relative name')
        data=bounded(REPO/name,256*1024)
        need(b'\r' not in data and sha(data)==digest_value and data==git_blob(head,name),'exact source Git LF bytes before import')
    return hashes
def actual(head,selected,origin):
    need(type(head) is str and re.fullmatch('[0-9a-f]{40}',head) is not None,'explicit source commit')
    need(subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip()==head,'exact current source HEAD')
    hashes=frozen_source(head)
    # Final source and immutable compiler inputs qualify before any repo import.
    for field,name in SELECTED_NATIVE.items():
        raw=bounded(REPO/name,256*1024)
        need(raw==bounded(SELECTED_BUILD/'src'/name,256*1024) and sha(raw)==selected[2][field] and raw==git_blob(head,name),'selected immutable compile source')
    for field,name in ORIGIN_NATIVE.items():
        raw=bounded(REPO/name,256*1024);need(sha(raw)==origin[2][field] and raw==git_blob(head,name),'reused B source bytes')
    need(sha(bounded(BEFORE,256*1024))==BASELINE_SHA,'fresh before capture equals preserved global baseline')
    need(PRIVATE.is_dir() and EVIDENCE.is_dir() and all(not p.exists() and not p.is_symlink() for p in (ARTIFACT,PLAN,PREFLIGHT,PUBLIC)),'fresh actual01 destinations')
    loader=importlib.util.spec_from_file_location('lpac_pipe_origin_actual01',REPO/ENTRY)
    module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    need(module.SCOPE==SCOPE and module.core.PROFILE==PROFILE and module.core.ACTUAL_READY is True and module.core.api_version()==1,'new reviewed scope/interface')
    need(set(module.SOURCES)==set(hashes) and tuple(module.core.NONCES)==('run','case') and tuple(module.core.ACKS)==EXPECTED_ACKS,'exact source/nonces/approval interface')
    need(module.core.ACTOR==SELECTED_ACTOR and module.core.MANIFEST==SELECTED_MANIFEST and module.core.NATIVE_SOURCES==SELECTED_NATIVE
        and module.core.origin.ACTOR==ORIGIN_ACTOR and module.core.origin.MANIFEST==ORIGIN_MANIFEST,'two separate artifacts')
    _,observed_hashes,closure=module.snapshot(REPO)
    need(closure==EXPECTED_SOURCE and observed_hashes==hashes,'postimport exact closure')
    for name in module.SOURCES:need(bounded(REPO/name,256*1024)==git_blob(head,name),'source stable after import')
    # Explicit LocalNativeAPI construction starts below. Imported modules may
    # initialize libraries including Winsock; this is no whole-parent no-WSA
    # claim. The owner creates rootD=T0+120F/workerD=rootD-5F, pairE=pairS+10F.
    module.core.verify_actor(SELECTED_BUILD/SELECTED_ACTOR,SELECTED_BUILD/SELECTED_MANIFEST,SELECTED_SHA,SELECTED_MANIFEST_SHA,root=REPO)
    module.core.origin.verify_artifact(ORIGIN_BUILD/ORIGIN_ACTOR,ORIGIN_BUILD/ORIGIN_MANIFEST,ORIGIN_MANIFEST_SHA,ORIGIN_SHA,source_root=REPO)
    api=module.local.LocalNativeAPI();module.local.ordinary(api)
    nonces={name:secrets.token_hex(16) for name in ('run','case')};need(len(set(nonces.values()))==2,'fresh independent run/case')
    stage=PRIVATE/module.core.stage_name(nonces['run']);need(not stage.exists() and not stage.is_symlink(),'fresh private stage')
    reference=('One zero-cap LPAC request/sink over inherited pipes; ordinary B relay alone opens owned loopback origin. '
        'Original120/115s epoch; pair10s includes create/admit/AccessCheck/pipe-close/resume/exit. Exact held identity, both Jobs and real matrix before resume. '
        'Fresh profile and only owned selected report ACL/Low label; stop workloads, restore label/ACE, delete exact profile. '
        'Unknown retains tree. No selected socket/DNS, app transparency, proxy or isolation acceptance; no retry/fallback/global changes.')
    need(1<=len(reference)<=512,'bounded recovery reference')
    plan=dict(schema_version=1,scope=SCOPE,profile=PROFILE,**nonces,device_sha256=api.device_sha256(),source_sha256=closure,
        actor_sha256=SELECTED_SHA,manifest_sha256=SELECTED_MANIFEST_SHA,origin_actor_sha256=ORIGIN_SHA,origin_manifest_sha256=ORIGIN_MANIFEST_SHA,
        **dict.fromkeys(EXPECTED_ACKS,True),recovery_reference=reference)
    module.core.validate_plan(plan,device=plan['device_sha256'],source=closure,actor=SELECTED_SHA,manifest=SELECTED_MANIFEST_SHA,origin_actor=ORIGIN_SHA,origin_manifest=ORIGIN_MANIFEST_SHA)
    ARTIFACT.mkdir()
    for name,raw in ((SELECTED_ACTOR,selected[0]),(SELECTED_MANIFEST,selected[1]),(ORIGIN_ACTOR,origin[0]),(ORIGIN_MANIFEST,origin[1])):put(ARTIFACT/name,raw)
    put(PLAN,module.encode(plan))
    args=(ARTIFACT/SELECTED_ACTOR,ARTIFACT/SELECTED_MANIFEST,SELECTED_SHA,SELECTED_MANIFEST_SHA,
        ARTIFACT/ORIGIN_ACTOR,ARTIFACT/ORIGIN_MANIFEST,ORIGIN_SHA,ORIGIN_MANIFEST_SHA,PRIVATE,PLAN)
    pre=module.preflight(*args);put(PREFLIGHT,module.encode(pre));need(pre['status']=='ready','preflight did not qualify')
    value=module.run_local(*args,approved=True);raw=module.encode(value);put(PUBLIC,raw)
    print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),public_sha256=sha(raw),result=value),sort_keys=True))
    return 0 if value['status']=='observed' else 1
def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute-root-reviewed',action='store_true')
    parser.add_argument('--source-commit')
    args=parser.parse_args(argv)
    selected,origin=inspect_inputs()
    if not args.execute_root_reviewed:
        print(json.dumps(dict(mode='file-only-preview',repo_imported=False,native_api_called=False,files_written=False,
            final_ready_pins_present=bool(digest(EXPECTED_SOURCE) and digest(EXPECTED_READY_FREEZE)),source_commit_parameter=args.source_commit,
            selected_actor_sha256=SELECTED_SHA,selected_manifest_sha256=SELECTED_MANIFEST_SHA,
            ordinary_B_actor_sha256=ORIGIN_SHA,ordinary_B_manifest_sha256=ORIGIN_MANIFEST_SHA,
            scope=SCOPE,profile=PROFILE,actual_ready=False,single_attempt_only=True),sort_keys=True));return 0
    return actual(args.source_commit,selected,origin)
if __name__=='__main__':raise SystemExit(main())
