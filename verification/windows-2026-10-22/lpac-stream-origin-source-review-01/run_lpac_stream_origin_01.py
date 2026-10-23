"""Root-only one-shot A-min driver. Default prints an inert stdlib preview."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import re,stat,subprocess
W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web';BUILD=W/'lpac-stream-native-compile-01'
ENTRY='.github/windows_identity_lpac_stream_origin_local.py'
SCOPE='one-local-semantic-lpac-inherited-stream-origin-v1';PROFILE='zero-cap-lpac-bounded-byte-stream-mechanism-v1'
SOURCE='ccc4008de826faf35eb5c7ea8df47ecdfe54fe0fbf3c31c854d764bbd51899be';COUNT=45
READY=W/'lpac-stream-origin-ready-source-freeze-04.json'
ACTOR='windows_identity_lpac_stream_front_actor.exe';MANIFEST='identity-lpac-stream-front-manifest.json'
NETWORK_ACTOR='windows_identity_lpac_stream_network_actor.exe';NETWORK_MANIFEST='identity-lpac-stream-network-manifest.json'
AH='b7327db1d30f4d81f7806b449d191cf7d49e22563c1da0c734f85cd478c9ae2a';MH='9a9df1de567bc4c6a9d0de334adeed4665fba2ade5ae5b62d26279d37134c4ba'
NH='074440e530ec26e149c90e1575261f930fadfdeaf156c4ceaf6b6f8f5fb9d1db';NMH='e7b090b9b2b24189ba5c202919a1b9fc27b1d6ecdf32b36087379f55b9d505a2'
NATIVE={'actorSourceSha256':'.github/native/windows_identity_lpac_stream_front_actor.cpp','streamContractSha256':'.github/native/windows_identity_lpac_stream_contract.hpp','identitySourceSha256':'.github/native/windows_identity_actor.cpp'}
NETWORK_NATIVE=NATIVE|{'actorSourceSha256':'.github/native/windows_identity_lpac_stream_network_actor.cpp'}
COMPILE_REVIEW=W/'lpac-stream-native-compile-static-review-01.json';CPIN='8388a661c10036a7676fc79b3b595a141905e2a87b734a777809878456cf5d35'
ACKS=('fresh_profile_owned_acl_acknowledged','zero_capabilities_no_fallback_acknowledged','trusted_actor_mechanism_only_acknowledged','cooperative_bounded_stream_acknowledged','independent_unpredictable_binary_challenges_acknowledged','inherited_pipe_authority_acknowledged','residue_review_acknowledged')
PRIVATE=R/'private';EVIDENCE=R/'verification/windows-2026-10-22';ARTIFACT=PRIVATE/'lpac-stream-native-compile01-actual01'
PLAN=PRIVATE/'lpac-stream-origin-recovery-plan-01.json';PUBLIC=EVIDENCE/'lpac-stream-origin-local-01-public.json';PREFLIGHT=EVIDENCE/'lpac-stream-origin-local-01-preflight.json'
BEFORE=PRIVATE/'lpac-stream-origin-before-stream01-global-snapshot.json'
def require(ok,label):
    if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(s):return type(s) is str and re.fullmatch('[0-9a-f]{64}',s) is not None
def unique(rows):
    value={}
    for k,v in rows:require(k not in value,'duplicate JSON key');value[k]=v
    return value
def decode(raw):return json.loads(raw.decode('utf-8-sig','strict'),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def bounded(path,limit):
    path=Path(path).absolute();require(path.is_relative_to(W),'owned WORK input path');current=W
    for part in (None,*path.relative_to(W).parts):
        if part is not None:current=current/part
        st=current.lstat();require(not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400,'no reparse input')
    require(stat.S_ISREG(st.st_mode) and 0<st.st_size<=limit,'bounded regular input');raw=path.read_bytes();require(len(raw)==st.st_size,'stable read');return raw
def put(path,raw):
    with path.open('xb') as stream:require(stream.write(raw)==len(raw),'fresh exact write');stream.flush()
def git(*args):return subprocess.check_output(['git','-C',str(R),*args])
def artifact(actor,manifest,ah,mh,pins,head):
    body=bounded(BUILD/actor,8*1024*1024);raw=bounded(BUILD/manifest,8192);v=decode(raw)
    require(sha(body)==ah and sha(raw)==mh,'compiled artifact pins');require(type(v) is dict and set(v)=={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion','executableSha256',*pins},'exact manifest8')
    require(type(v['schemaVersion']) is type(v['interfaceVersion']) is int and v['schemaVersion']==v['interfaceVersion']==1 and v['compileOnly'] is True and v['runtimeAcceptance'] is False and v['executableSha256']==ah,'compile-only interface1')
    for k,name in pins.items():
        source=bounded(R/name,256*1024);require(sha(source)==v[k] and source==git('show',head+':'+name)==bounded(BUILD/'src'/Path(name).name,256*1024),'manifest/source/Git/original snapshot')
    return body,raw

def actual(args):
    require(type(args.source_commit) is str and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None and git('rev-parse','HEAD').decode().strip()==args.source_commit,'explicit current source commit')
    require(digest(args.ready_freeze_sha256) and digest(args.before_sha256),'explicit Ready and before pins')
    readyraw=bounded(READY,256*1024);require(sha(readyraw)==args.ready_freeze_sha256,'Ready04 byte pin');ready=decode(readyraw)
    require(ready['actual_ready'] is True and ready['source_count']==COUNT and ready['source_sha256']==SOURCE and type(ready['source_hashes']) is dict and len(ready['source_hashes'])==COUNT,'reviewed promoted source45')
    hashes=ready['source_hashes'];require(ENTRY in hashes and all(digest(x) for x in hashes.values()),'source map')
    for name,pin in hashes.items():
        require(type(name) is str and name.startswith(('.github/','ruleproxy/')) and '..' not in Path(name).parts,'relative source')
        raw=bounded(R/name,256*1024);require(b'\r' not in raw and sha(raw)==pin and raw==git('show',args.source_commit+':'+name),'all45 Git bytes before import')
    front=artifact(ACTOR,MANIFEST,AH,MH,NATIVE,args.source_commit);network=artifact(NETWORK_ACTOR,NETWORK_MANIFEST,NH,NMH,NETWORK_NATIVE,args.source_commit)
    reviewraw=bounded(COMPILE_REVIEW,64*1024);require(sha(reviewraw)==CPIN and decode(reviewraw)['passed'] is True,'root compile/PE review')
    require(sha(bounded(BEFORE,256*1024))==args.before_sha256,'fresh independent before capture byte pin')
    # The before snapshot is an independent observation, never required to equal
    # the old baseline. Root captures after separately and preserves any delta.
    require(PRIVATE.is_dir() and EVIDENCE.is_dir() and all(not p.exists() and not p.is_symlink() for p in (ARTIFACT,PLAN,PREFLIGHT,PUBLIC)),'fresh actual01 destinations')
    import importlib.util
    loader=importlib.util.spec_from_file_location('root_stream_actual01',R/ENTRY);module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
    require(module.SCOPE==SCOPE and module.core.PROFILE==PROFILE and module.core.ACTUAL_READY is True and module.core.api_version()==1,'scope/Ready/interface')
    require(set(module.SOURCES)==set(hashes) and tuple(module.core.NONCES)==('run','case') and tuple(module.core.ACKS)==ACKS,'exact closure and plan ABI')
    require(module.core.NATIVE_SOURCES==NATIVE and module.core.NETWORK_SOURCES==NETWORK_NATIVE and (module.core.ACTOR,module.core.MANIFEST,module.core.NETWORK_ACTOR,module.core.NETWORK_MANIFEST)==(ACTOR,MANIFEST,NETWORK_ACTOR,NETWORK_MANIFEST),'separate artifacts')
    _,observed,source=module.snapshot(R);require(observed==hashes and source==SOURCE,'post-import closure')
    module.core.verify_actor(BUILD/ACTOR,BUILD/MANIFEST,AH,MH,root=R);module.core.verify_actor(BUILD/NETWORK_ACTOR,BUILD/NETWORK_MANIFEST,NH,NMH,root=R,network=True)
    # No project import, nonce, file output or explicit LocalNativeAPI exists
    # on the default preview path. Imports here may initialize libraries; no
    # claim that the whole ordinary Python parent never initialized Winsock.
    api=module.local.LocalNativeAPI();parent=module.local.ordinary(api)
    import os,secrets
    nonce={name:secrets.token_hex(16) for name in ('run','case')};require(len(set(nonce.values()))==2,'independent fresh nonce')
    require(not (PRIVATE/module.core.stage_name(nonce['run'])).exists(),'fresh stage')
    request=bytes(range(256))+b'RPS1'+os.urandom(8193-260)
    response=bytes(reversed(range(256)))+b'RPS1'+os.urandom(12289-260)
    challenges={k:dict(bytes=len(v),sha256=sha(v)) for k,v in (('request',request),('response',response))};module.core.challenge_meta(challenges)
    reference=('One genuine zero-cap LPAC binary stream over exact inherited pipes; ordinary relay to one held owned loopback origin. '
        'Root120/worker115/work85/pair10 original epoch; held token/Jobs/matrix before resume. '
        'Request read-only; ordinary response inaccessible; post-exit physical inputs and five sinks. '
        'Stop all, restore mandatory-label ACE absence, remove exact SID ACE, delete profile. '
        'Unknown retained. No concurrent stream, app/core/proxy/DNS/Linux/product acceptance; preserve all global deltas.')
    require(len(reference)<=512,'bounded recovery reference')
    plan=dict(schema_version=1,scope=SCOPE,profile=PROFILE,**nonce,device_sha256=api.device_sha256(),source_sha256=source,actor_sha256=AH,manifest_sha256=MH,network_actor_sha256=NH,network_manifest_sha256=NMH,challenges=challenges,**dict.fromkeys(ACKS,True),recovery_reference=reference)
    module.core.validate_plan(plan,device=plan['device_sha256'],source=source,actor=AH,manifest=MH,network_actor=NH,network_manifest=NMH,challenges=challenges)
    api.private_directory(ARTIFACT,parent['sid'])
    for name,raw in ((ACTOR,front[0]),(MANIFEST,front[1]),(NETWORK_ACTOR,network[0]),(NETWORK_MANIFEST,network[1]),('request.bin',request),('response.bin',response)):put(ARTIFACT/name,raw)
    module.core.challenge_inputs(ARTIFACT/'request.bin',ARTIFACT/'response.bin',challenges);put(PLAN,module.encode(plan))
    call=(ARTIFACT/ACTOR,ARTIFACT/MANIFEST,AH,MH,ARTIFACT/NETWORK_ACTOR,ARTIFACT/NETWORK_MANIFEST,NH,NMH,ARTIFACT/'request.bin',ARTIFACT/'response.bin',PRIVATE,PLAN)
    pre=module.preflight(*call);put(PREFLIGHT,module.encode(pre));require(pre['status']=='ready','preflight qualification')
    result=module.run_local(*call,approved=True);raw=module.encode(result);put(PUBLIC,raw)
    print(json.dumps(dict(source_commit=args.source_commit,source_sha256=source,public_bytes=len(raw),public_sha256=sha(raw),result=result),sort_keys=True));return 0 if result['status']=='observed' else 1

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-root-reviewed',action='store_true');p.add_argument('--source-commit');p.add_argument('--ready-freeze-sha256');p.add_argument('--before-sha256');a=p.parse_args(argv)
    if not a.execute_root_reviewed:
        print(json.dumps(dict(mode='inert-stdlib-preview',scope=SCOPE,profile=PROFILE,promoted_source_sha256=SOURCE,source_count=COUNT,source_commit=a.source_commit,Ready_pin_required_later=True,independent_before_pin_required_later=True,project_imported=False,nonce_or_plan_created=False,files_written=False,native_API_or_actor_called=False,actual_ready=False,one_attempt_only=True),sort_keys=True));return 0
    return actual(a)
if __name__=='__main__':raise SystemExit(main())
