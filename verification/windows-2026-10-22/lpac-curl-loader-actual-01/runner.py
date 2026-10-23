"""Root-only, one-shot curl-loader candidate. Default is a stdlib preview.

No final Ready or source commit is guessed. Explicit execution is a separate
future root action after full review. The selected command has no URL; this is
an event/mapping/version experiment, not a curl network adapter or isolation
qualification. Failed or unknown effects are retained; this driver never retries
the loader, clears old unknown state, or deletes an earlier assay.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

W=Path(__file__).resolve().parent
R=W/'Rule-proxy-Web'
CORE='.github/windows_identity_lpac_curl_loader.py'
ENTRY='.github/windows_identity_lpac_curl_loader_local.py'
SCOPE='one-local-held-zero-cap-lpac-system-curl-loader-events-v1'
PROFILE='zero-cap-system-curl-loader-events-with-version-controls-v1'
BUILD=W/'lpac-curl-loader-native-build-01'
WRAPPER='windows_identity_lpac_curl_loader_wrapper.dll'
MARKER='windows_identity_lpac_curl_loader_marker.dll'
MANIFEST='identity-lpac-curl-loader-manifest.json'
PINS_FILE=W/'lpac-curl-loader-artifact-pins-01.json'
PINS_META=dict(bytes=486,sha256='d65f99d3ae6b0a5729dcbe8c2561fa8c059cd401f418c7be2ab13890ad8ad47a')
COMPILE_REVIEW=W/'lpac-curl-loader-native-compile-independent-review-01.json'
COMPILE_REVIEW_META=dict(bytes=20693,sha256='b5b5492bdf80bf519eb90b0baa496d739ce27f1eacbfb267a19bbf53c13628aa')
VENDOR_REVIEW=W/'detours-fixed-source-01/verification.json'
VENDOR_REVIEW_META=dict(bytes=4786,sha256='fc1ddbc3ef86b81443e9d3ef18864b33a188b38258136806324944effe31f4d1')
DETOURS_COMMIT='1dbd4ea281d73d478aa8d09a8b83fbd265f715f7'
NATIVE=tuple('.github/native/windows_identity_lpac_curl_loader_'+n for n in
    ('wrapper.hpp','core.hpp','wrapper.cpp','marker_core.hpp','marker.cpp','marker.def'))
ACKS=('fresh_profile_owned_acl_acknowledged','existing_curl_instrumentation_acknowledged',
    'zero_capabilities_no_fallback_acknowledged','partial_remote_memory_acknowledged',
    'restore_unknown_acknowledged','mapping_race_acknowledged','ordinary_version_controls_acknowledged',
    'same_sid_unqualified_acknowledged','no_network_adapter_acknowledged')
NONCES=('run','before_case','selected_case','after_case')
PRIVATE=R/'private'
EVIDENCE=R/'verification/windows-2026-10-22'
ARTIFACT=PRIVATE/'lpac-curl-loader-a01'
PLAN=PRIVATE/'lpac-curl-loader-recovery-plan-01.json'
PUBLIC=EVIDENCE/'lpac-curl-loader-local-01-public.json'
PREFLIGHT=EVIDENCE/'lpac-curl-loader-local-01-preflight.json'
BEFORE=PRIVATE/'lpac-curl-loader-before-curl01-global-snapshot.json'
ORIGINAL_BASELINE=PRIVATE/'model2-first-01-global-baseline.json'
GLOBAL_KEYS=('firewall_profiles','dns','routes','user_proxy')


def require(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def meta(raw):return dict(bytes=len(raw),sha256=sha(raw))
def digest(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
def unique(rows):
    value={}
    for key,item in rows:
        require(key not in value,'duplicate JSON key');value[key]=item
    return value
def decode(raw):
    # One optional transport BOM, then the duplicate/nonfinite strict decoder.
    return json.loads(raw.removeprefix(b'\xef\xbb\xbf').decode('utf-8','strict'),object_pairs_hook=unique,
        parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def bounded(path,limit,*,inside=W):
    path=Path(path).absolute();anchor=Path(inside).absolute() if inside is not None else Path(path.anchor)
    require(path.is_relative_to(anchor),'bounded input root')
    current=anchor
    for part in (None,*path.relative_to(anchor).parts):
        if part is not None:current=current/part
        info=current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'no reparse input')
    require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=limit,'bounded regular file')
    raw=path.read_bytes();require(len(raw)==info.st_size,'stable bounded read');return raw
def put(path,raw):
    import os
    with path.open('xb') as out:
        require(out.write(raw)==len(raw),'fresh complete output');out.flush();os.fsync(out.fileno())
def git(*args):return subprocess.check_output(['git','-C',str(R),*args])
def work_name(name):
    require(type(name) is str and re.fullmatch('[A-Za-z0-9_.-]{1,128}',name) is not None and Path(name).name==name,'Ready WORK basename')
    return W/name


def global_snapshot(path,pin):
    raw=bounded(path,256*1024,inside=PRIVATE);require(sha(raw)==pin,'explicit global snapshot pin')
    value=decode(raw)
    require(type(value) is dict and set(value)=={'schema_version','stage',*GLOBAL_KEYS}
        and type(value['schema_version']) is int and value['schema_version']==1
        and value['stage']=='model2-first-global-readonly-baseline','four-object snapshot schema')
    require(type(value['firewall_profiles']) is list and len(value['firewall_profiles'])==3
        and type(value['dns']) is list and len(value['dns'])<=256
        and type(value['routes']) is list and len(value['routes'])<=1024
        and type(value['user_proxy']) is dict,'four-object snapshot bounds')
    return raw,value


def artifact_inputs(hashes,head,curl_path):
    pins_raw=bounded(PINS_FILE,8192);require(meta(pins_raw)==PINS_META,'fixed artifact descriptor file')
    pins=decode(pins_raw);require(type(pins) is dict and set(pins)=={'curl','wrapper','marker','manifest'},'closed four artifacts')
    payloads={}
    for key,name in (('wrapper',WRAPPER),('marker',MARKER),('manifest',MANIFEST)):
        payloads[key]=bounded(BUILD/name,8*1024*1024)
        require(meta(payloads[key])==pins[key],'compiled raw artifact '+key)
    curl_raw=bounded(curl_path,8*1024*1024,inside=None)
    require(meta(curl_raw)==pins['curl']==dict(bytes=818512,sha256='73d24149ff289afc49ec41f08918ef9faa727d39ad993e929757dc2ddafab805'),'fixed curl bytes')
    del curl_raw
    v=decode(payloads['manifest'])
    require(type(v) is dict and set(v)=={'schemaVersion','compileOnly','runtimeAcceptance','interfaceVersion',
        'wrapperSha256','markerSha256','nativeSourceHashes','detoursCommit','detoursSourceHashes'},'runtime nine-key manifest')
    require(type(v['schemaVersion']) is type(v['interfaceVersion']) is int and v['schemaVersion']==v['interfaceVersion']==1
        and v['compileOnly'] is True and v['runtimeAcceptance'] is False
        and v['wrapperSha256']==pins['wrapper']['sha256'] and v['markerSha256']==pins['marker']['sha256']
        and v['detoursCommit']==DETOURS_COMMIT,'typed compile manifest')
    vendor_raw=bounded(VENDOR_REVIEW,8192);require(meta(vendor_raw)==VENDOR_REVIEW_META,'fixed upstream verification')
    upstream=decode(vendor_raw)
    require(upstream['commit']==DETOURS_COMMIT and upstream['all_regular_git_blobs_exact'] is True,'official fixed upstream commit')
    vendor={'.github/vendor/detours/'+r['path']:r['sha256'] for r in upstream['files']}
    require(len(vendor)==20 and type(v['nativeSourceHashes']) is dict and set(v['nativeSourceHashes'])==set(NATIVE)
        and v['detoursSourceHashes']==vendor,'exact six native and twenty upstream inputs')
    native_hashes={**v['nativeSourceHashes'],**vendor}
    for name,pin in native_hashes.items():
        require(hashes.get(name)==pin,'native input in promoted source closure')
        raw=bounded(R/name,256*1024)
        require(raw==git('show',head+':'+name)==bounded(BUILD/'source'/name,256*1024) and sha(raw)==pin,'original precompile snapshot/Git')
    review_raw=bounded(COMPILE_REVIEW,65536);require(meta(review_raw)==COMPILE_REVIEW_META,'independent compiled PE review')
    review=decode(review_raw)
    require(review['verdict']=='GO-compile-and-static-only' and review['blockers']==[],'compiled static-only GO')
    for key in ('wrapper','marker'):
        require({k:review['artifacts'][key][k] for k in ('bytes','sha256')}==pins[key],'reviewed artifact physical pin')
    # No retrospective snapshot: only the original build/source tree above is used.
    return pins,pins_raw,payloads


def actual(args):
    require(args.acknowledge_existing_curl_loader_impact,'explicit existing-curl instrumentation acknowledgment')
    require(type(args.source_commit) is str and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None
        and git('rev-parse','HEAD').decode('ascii').strip()==args.source_commit,'exact current source commit')
    require(all(digest(v) for v in (args.source_sha256,args.ready_freeze_sha256,args.device_sha256,args.before_sha256,args.baseline_sha256)),
        'explicit source Ready device before baseline pins')
    require(args.curl_path is not None and args.baseline_file is not None,'explicit curl and baseline paths')
    require(args.baseline_file.absolute()==ORIGINAL_BASELINE.absolute(),'original baseline retained')
    ready_raw=bounded(work_name(args.ready_freeze_name),256*1024);require(sha(ready_raw)==args.ready_freeze_sha256,'late Ready raw pin')
    ready=decode(ready_raw)
    require(type(ready) is dict and ready['actual_ready'] is True and type(ready['source_count']) is int
        and 2<=ready['source_count']<=256 and ready['source_sha256']==args.source_sha256,'explicit promoted Ready source')
    hashes=ready['source_hashes']
    require(type(hashes) is dict and len(hashes)==ready['source_count'] and CORE in hashes and ENTRY in hashes
        and all(digest(v) for v in hashes.values()) and sha(encode(hashes))==args.source_sha256,'actual canonical source union')
    for name,pin in hashes.items():
        require(type(name) is str and name.startswith(('.github/','ruleproxy/')) and '\\' not in name and '..' not in Path(name).parts,'relative source input')
        raw=bounded(R/name,256*1024)
        require(sha(raw)==pin and raw==git('show',args.source_commit+':'+name),'exact committed source before import')
        require(name.startswith('.github/vendor/detours/') or b'\r' not in raw,'repo LF with unmodified raw upstream exceptions')
    pins,pins_raw,payloads=artifact_inputs(hashes,args.source_commit,args.curl_path)
    require(ready['artifacts']==pins,'Ready exact four artifact descriptors')
    before_raw,before=global_snapshot(BEFORE,args.before_sha256)
    baseline_raw,baseline=global_snapshot(args.baseline_file,args.baseline_sha256)
    comparisons={key:before[key]==baseline[key] for key in GLOBAL_KEYS}
    # An old route difference is preserved. Equality is an observation, not a
    # prerequisite or a promise about the independently captured future after.
    require(PRIVATE.is_dir() and EVIDENCE.is_dir() and all(not p.exists() and not p.is_symlink() for p in (ARTIFACT,PLAN,PREFLIGHT,PUBLIC)),
        'fresh artifact plan and evidence destinations')
    import importlib.util
    spec=importlib.util.spec_from_file_location('root_curl_loader_actual01',R/ENTRY)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    require(module.SCOPE==SCOPE and module.core.PROFILE==PROFILE and module.core.api_version()==1 and module.core.ACTUAL_READY is True,
        'new exclusive scope interface and promoted Ready')
    require(set(module.SOURCES)==set(hashes) and len(module.SOURCES)==ready['source_count']
        and tuple(module.core.NONCES)==NONCES and tuple(module.core.ACKS)==ACKS,'source and nine-ack nonce ABI')
    require(tuple(module.core.NATIVE_SOURCES)==NATIVE and (module.core.WRAPPER,module.core.MARKER,module.core.MANIFEST)==(WRAPPER,MARKER,MANIFEST),
        'separate loader artifact names')
    _,observed,source=module.snapshot(R)
    require(observed==hashes and source==args.source_sha256,'post-import closure unchanged')
    module.core.verify_input_artifacts(BUILD/WRAPPER,BUILD/MARKER,BUILD/MANIFEST,args.curl_path,pins,root=R)
    # First explicitly constructed native backend. It is the ordinary outer
    # guard metadata API, not the wrapper API. Wrapper loads only in its worker.
    api=module.local.LocalNativeAPI();parent=module.local.ordinary(api)
    require(api.device_sha256()==args.device_sha256,'explicit current device pin')
    module.core.verify_system_curl(api,args.curl_path)
    import secrets
    nonce={name:secrets.token_hex(16) for name in NONCES}
    require(len(set(nonce.values()))==4,'four distinct fresh nonces without retry')
    require(not (ARTIFACT/module.core.stage_name(nonce['run'])).exists()
        and not (ARTIFACT/module.core.stage_name(nonce['run'])).is_symlink(),'fresh independently named worker stage')
    reference=('One finite no-URL System32 curl --disable --version experiment with ordinary before and after controls, '
        'a fresh zero-cap semantic LPAC and exact held image/token/generation/two Jobs. Existing held target import update and marker payload '
        'are deliberate; no helper process, remote thread, hook, retry, alternate API, capability fallback or implicit Resume. '
        'Original root120/worker115/work85 and one original max8-second loader window are not renewed. '
        'Remote allocation/protection restoration is not proved by helper TRUE or event signals; unknown ownership or close blocks profile deletion '
        'and requires exact recovery. Events, coherent marker data, mapped-file correlation and curl output are separate facts. '
        'No URL is not proof of Winsock absence. No network adapter, hostile same-SID boundary, DNS/PSEC/Linux or product qualification; '
        'old atomic unknowns and global route drift remain separate retained history.')
    require(400<=len(reference)<=2048,'bounded explicit recovery risks')
    plan=dict(schema_version=1,scope=SCOPE,profile=PROFILE,**nonce,device_sha256=args.device_sha256,source_sha256=source,
        artifacts=pins,curl_path=str(args.curl_path),recovery_reference=reference,**dict.fromkeys(ACKS,True))
    module.core.validate_plan(plan,device=args.device_sha256,source=source,artifacts=pins,curl_path=str(args.curl_path))
    api.private_directory(ARTIFACT,parent['sid'])
    for name,raw in ((WRAPPER,payloads['wrapper']),(MARKER,payloads['marker']),(MANIFEST,payloads['manifest']),('artifact-pins.json',pins_raw)):
        put(ARTIFACT/name,raw)
    put(PLAN,module.encode(plan))
    call=(ARTIFACT/WRAPPER,ARTIFACT/MARKER,ARTIFACT/MANIFEST,args.curl_path,pins,ARTIFACT,PLAN)
    pre=module.preflight(*call,api=api,root=R);put(PREFLIGHT,module.encode(pre));require(pre['status']=='ready','new-scope preflight')
    # Use the guard's unique explicit entry. No Popen, alternate old entry,
    # direct core.execute call, or second assay is introduced by the driver.
    cli=['--run-local-lpac-curl-loader','--wrapper',str(ARTIFACT/WRAPPER),'--marker',str(ARTIFACT/MARKER),
        '--manifest',str(ARTIFACT/MANIFEST),'--curl',str(args.curl_path),'--artifact-pins',str(ARTIFACT/'artifact-pins.json'),
        '--work-parent',str(ARTIFACT),'--recovery-plan',str(PLAN),'--output',str(PUBLIC)]
    code=module.main(cli)
    raw=bounded(PUBLIC,module.MAX_REPORT);result=module.validate_public(module.decode(raw))
    require(type(code) is int and code==(0 if result['status']=='observed' else 1),'guard return and raw public consistency')
    require(all(result[k] is False for k in module.core.FALSE_CLAIMS),'unsupported claims fixed false')
    print(json.dumps(dict(source_commit=args.source_commit,source_sha256=source,public_bytes=len(raw),public_sha256=sha(raw),
        before=meta(before_raw),original_baseline=meta(baseline_raw),before_equal_original=comparisons,
        after_capture_performed=False,result=result),sort_keys=True))
    return code


def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute-root-reviewed',action='store_true')
    p.add_argument('--acknowledge-existing-curl-loader-impact',action='store_true')
    for name in ('source-commit','source-sha256','ready-freeze-name','ready-freeze-sha256','device-sha256','before-sha256','baseline-sha256'):
        p.add_argument('--'+name)
    p.add_argument('--curl-path',type=Path);p.add_argument('--baseline-file',type=Path)
    a=p.parse_args(argv)
    if not a.execute_root_reviewed:
        print(json.dumps(dict(mode='inert-stdlib-preview',scope=SCOPE,profile=PROFILE,
            final_source_commit_Ready_device_before_baseline_required=True,source_count='derive actual Ready map and imported SOURCES; not guessed',
            unique_entry='--run-local-lpac-curl-loader',nine_explicit_plan_acknowledgments=True,
            impact='existing held curl import/payload instrumentation with ordinary version controls and owned profile/ACL/label resources',
            project_imported=False,randomness_generated=False,files_written=False,native_backend_constructed=False,
            wrapper_loaded=False,curl_or_target_or_compiler_called=False,actual_executed=False,one_attempt_only=True),sort_keys=True))
        return 0
    return actual(a)
if __name__=='__main__':raise SystemExit(main())
