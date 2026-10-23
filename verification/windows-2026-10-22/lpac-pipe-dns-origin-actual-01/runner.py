"""Root-only first pipe-plus-DNS assay. Default is an inert stdlib preview."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess

W=Path(__file__).resolve().parent;R=W/'Rule-proxy-Web'
ENTRY='.github/windows_identity_lpac_pipe_dns_origin_local.py'
CORE='.github/windows_identity_lpac_pipe_dns_origin.py'
SCOPE='one-local-same-zero-cap-lpac-pipe-origin-explicit-dns-v1'
PROFILE='same-process-zero-cap-lpac-ipc-standard53-dns-diagnostic-v1'
COUNT=45
SOURCE='b42726c094e7619ee579a29d414bfc632dde09b1d6d13d29bc97b9add851f706'
AH='e29371fadc445f44408ee0b719914f484ff5995e0215f32046d2169144488ca6'
MH='177439d092b3e6f113802aa277995bde00eb26c551efdbda5fbe876601744531'
READY=W/'lpac-pipe-dns-ready-source-freeze-06.json'
SELECTED_BUILD=W/'lpac-pipe-dns-front-compile-02'
ACTOR='windows_identity_lpac_pipe_dns_front_actor.exe'
MANIFEST='identity-lpac-pipe-dns-front-manifest.json'
NATIVE={
 'actorSourceSha256':'.github/native/windows_identity_lpac_pipe_dns_front_actor.cpp',
 'controlHeaderSha256':'.github/native/windows_identity_lpac_pipe_dns_contract.hpp',
 'pipeActorSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
 'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
 'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp',
 'dnsProbeSha256':'.github/native/windows_identity_dns_standard_probe.hpp'}
ORIGIN_BUILD=W/'proxy-origin-compile-03'
ORIGIN_ACTOR='windows_identity_proxy_origin_actor.exe'
ORIGIN_MANIFEST='identity-proxy-origin-manifest.json'
OH='042562a096a9f488b7a52ee8eb894af0b26dc679a05dc8948a9ae159b71cf161'
OMH='5b3660539e70bc53d004b2ee3b7b13bfa7fe6418042e57bbd0263b03cef4a456'
ORIGIN_NATIVE={
 'actorSourceSha256':'.github/native/windows_identity_proxy_origin_actor.cpp',
 'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
 'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp',
 'pipeHelperSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
 'originTransportSha256':'.github/native/windows_identity_proxy_origin_transport.hpp'}
CONTROL_BUILD=W/'dns-standard-compile-02'
CONTROL_ACTOR='windows_identity_dns_standard_actor.exe'
CONTROL_MANIFEST='identity-dns-standard-manifest.json'
CH='5e7cbcaaa0a7bfdfa9026898493cbf74dafaa7b875bb4749680cc5be98261299'
CMH='49f4b44a06cd6bdbc6cfb0b4b2dd2c7a5c3443e0f2b79d61040e97479a2aa648'
CONTROL_NATIVE={
 'actorSourceSha256':'.github/native/windows_identity_dns_standard_actor.cpp',
 'identitySourceSha256':'.github/native/windows_identity_actor.cpp',
 'dnsProbeSha256':'.github/native/windows_identity_dns_standard_probe.hpp'}
NONCES=('run','case','dns_before_case','dns_selected_case','dns_after_case','inventory_run')
ACKS=('fresh_profile_owned_acl_acknowledged','zero_capabilities_no_fallback_acknowledged',
 'trusted_actor_mechanism_only_acknowledged','cooperative_fixed_frame_mapping_acknowledged',
 'inherited_pipe_authority_acknowledged','residue_review_acknowledged',
 'standard53_impact_acknowledged','same_process_dns_acknowledged')
PRIVATE=R/'private';EVIDENCE=R/'verification/windows-2026-10-22'
ARTIFACT=PRIVATE/'lpac-pipe-dns-front-compile02-origin03-control02-actual01'
PLAN=PRIVATE/'lpac-pipe-dns-origin-recovery-plan-01.json'
PUBLIC=EVIDENCE/'lpac-pipe-dns-origin-local-01-public.json'
PREFLIGHT=EVIDENCE/'lpac-pipe-dns-origin-local-01-preflight.json'
BEFORE=PRIVATE/'lpac-pipe-dns-origin-before-pipe-dns01-global-snapshot.json'

def require(ok,label):
 if not ok:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None
def unique(rows):
 out={}
 for key,value in rows:require(key not in out,'duplicate JSON key');out[key]=value
 return out
def decode(raw):return json.loads(raw.decode('utf-8-sig','strict'),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
def bounded(path,limit):
 path=Path(path).absolute();require(path.is_relative_to(W),'owned WORK input');current=W
 for part in (None,*path.relative_to(W).parts):
  if part is not None:current=current/part
  st=current.lstat();require(not stat.S_ISLNK(st.st_mode) and not getattr(st,'st_file_attributes',0)&0x400,'no reparse input')
 require(stat.S_ISREG(st.st_mode) and 0<st.st_size<=limit,'bounded regular input');raw=path.read_bytes();require(len(raw)==st.st_size,'stable input');return raw
def put(path,raw):
 with path.open('xb') as out:require(out.write(raw)==len(raw),'fresh exact output');out.flush()
def git(*args):return subprocess.check_output(['git','-C',str(R),*args])

def artifact(build,actor,manifest,ah,mh,pins,head,interface=False,snapshot=False):
 body=bounded(build/actor,8*1024*1024);raw=bounded(build/manifest,8192);value=decode(raw)
 keys={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*pins}
 if interface:keys.add('interfaceVersion')
 require(set(value)==keys and type(value['schemaVersion']) is int and value['schemaVersion']==1 and value['compileOnly'] is True and value['runtimeAcceptance'] is False,'closed compile-only manifest')
 if interface:require(type(value['interfaceVersion']) is int and value['interfaceVersion']==1,'selected interface1')
 require(sha(body)==ah and sha(raw)==mh and value['executableSha256']==ah,'original artifact byte pins')
 for key,name in pins.items():
  source=bounded(R/name,256*1024);require(sha(source)==value[key] and source==git('show',head+':'+name),'manifest/Git source')
  if snapshot:require(source==bounded(build/'src'/name,256*1024),'original selected precompile snapshot')
 return body,raw

def actual(args):
 require(type(args.source_commit) is str and re.fullmatch('[0-9a-f]{40}',args.source_commit) is not None and git('rev-parse','HEAD').decode().strip()==args.source_commit,'exact current source commit')
 require(all(digest(v) for v in (args.source_sha256,args.ready_freeze_sha256,args.selected_actor_sha256,args.selected_manifest_sha256,args.before_sha256)),'explicit late source/Ready/artifact/before pins')
 require(args.source_sha256==SOURCE and args.selected_actor_sha256==AH and args.selected_manifest_sha256==MH,'fixed reviewed promoted source and selected artifacts')
 readyraw=bounded(READY,256*1024);require(sha(readyraw)==args.ready_freeze_sha256,'Ready04 byte pin');ready=decode(readyraw)
 require(ready['actual_ready'] is True and ready['source_count']==COUNT and ready['source_sha256']==args.source_sha256 and len(ready['source_hashes'])==COUNT,'exact promoted source45')
 hashes=ready['source_hashes'];require(ENTRY in hashes and CORE in hashes and all(digest(v) for v in hashes.values()),'closed source map')
 for name,pin in hashes.items():
  require(type(name) is str and name.startswith(('.github/','ruleproxy/')) and '..' not in Path(name).parts,'relative source path')
  raw=bounded(R/name,256*1024);require(b'\r' not in raw and sha(raw)==pin and raw==git('show',args.source_commit+':'+name),'all45 exact Git bytes before import')
 selected=artifact(SELECTED_BUILD,ACTOR,MANIFEST,args.selected_actor_sha256,args.selected_manifest_sha256,NATIVE,args.source_commit,interface=True,snapshot=True)
 origin=artifact(ORIGIN_BUILD,ORIGIN_ACTOR,ORIGIN_MANIFEST,OH,OMH,ORIGIN_NATIVE,args.source_commit)
 control=artifact(CONTROL_BUILD,CONTROL_ACTOR,CONTROL_MANIFEST,CH,CMH,CONTROL_NATIVE,args.source_commit)
 for label,payloads in (('selected',selected),('origin',origin),('control',control)):
  require(ready['artifacts'][label]==dict(executable=dict(bytes=len(payloads[0]),sha256=sha(payloads[0])),manifest=dict(bytes=len(payloads[1]),sha256=sha(payloads[1]))),'Ready exact compiled artifact '+label)
 require(sha(bounded(BEFORE,256*1024))==args.before_sha256,'independent before capture pin')
 require(PRIVATE.is_dir() and EVIDENCE.is_dir() and all(not p.exists() and not p.is_symlink() for p in (ARTIFACT,PLAN,PREFLIGHT,PUBLIC)),'fresh assay destinations')
 import importlib.util
 loader=importlib.util.spec_from_file_location('root_pipe_dns_actual01',R/ENTRY);module=importlib.util.module_from_spec(loader);loader.loader.exec_module(module)
 require(module.SCOPE==SCOPE and module.core.PROFILE==PROFILE and module.core.ACTUAL_READY is True and module.core.api_version()==1,'scope/Ready/interface')
 require(set(module.SOURCES)==set(hashes) and tuple(module.core.NONCES)==NONCES and tuple(module.core.ACKS)==ACKS,'exact dependency/nonce/ack contract')
 require(module.core.NATIVE_SOURCES==NATIVE and module.core.CONTROL_SOURCES==CONTROL_NATIVE and module.core.ACTOR==ACTOR and module.core.MANIFEST==MANIFEST and module.core.CONTROL_ACTOR==CONTROL_ACTOR and module.core.CONTROL_MANIFEST==CONTROL_MANIFEST,'separate selected/control artifacts')
 _,observed,source=module.snapshot(R);require(observed==hashes and source==args.source_sha256,'post-import exact source45')
 module.core.verify_actor(SELECTED_BUILD/ACTOR,SELECTED_BUILD/MANIFEST,args.selected_actor_sha256,args.selected_manifest_sha256,root=R)
 module.core.origin.verify_artifact(ORIGIN_BUILD/ORIGIN_ACTOR,ORIGIN_BUILD/ORIGIN_MANIFEST,OMH,OH,source_root=R)
 module.core.verify_actor(CONTROL_BUILD/CONTROL_ACTOR,CONTROL_BUILD/CONTROL_MANIFEST,CH,CMH,root=R,control=True)
 # These are the first explicit backend and nonce/plan operations. Default
 # execution never imports project modules or constructs Windows API objects.
 api=module.local.LocalNativeAPI();parent=module.local.ordinary(api)
 import secrets
 nonces={name:secrets.token_hex(16) for name in NONCES};require(len(set(nonces.values()))==6,'fresh distinct six nonces')
 require(not (PRIVATE/module.core.stage_name(nonces['run'])).exists(),'fresh private stage')
 reference=('Same held zero-cap LPAC completes fixed inherited-pipe IPC, then finite explicit DnsQueryEx to owned127UDP53. '
  'Root120/worker115/pair10 original epoch; four inventory gates5F, two closed proofs and unchanged primary statistics. '
  'Stop exact held workloads, restore owned mandatory label absence and exactSID ACE, delete profile only when all resources known. '
  'Pending/unknown retained; receiver hit sticky. No broker cancellation, default resolver, general isolation, proxy/product/Linux qualification.')
 require(len(reference)<=512,'bounded recovery reference')
 plan=dict(schema_version=1,scope=SCOPE,profile=PROFILE,**nonces,device_sha256=api.device_sha256(),source_sha256=source,actor_sha256=args.selected_actor_sha256,manifest_sha256=args.selected_manifest_sha256,origin_actor_sha256=OH,origin_manifest_sha256=OMH,control_actor_sha256=CH,control_manifest_sha256=CMH,**dict.fromkeys(ACKS,True),recovery_reference=reference)
 module.core.validate_plan(plan,device=plan['device_sha256'],source=source,actor=args.selected_actor_sha256,manifest=args.selected_manifest_sha256,origin_actor=OH,origin_manifest=OMH,control_actor=CH,control_manifest=CMH)
 api.private_directory(ARTIFACT,parent['sid'])
 for name,raw in ((ACTOR,selected[0]),(MANIFEST,selected[1]),(ORIGIN_ACTOR,origin[0]),(ORIGIN_MANIFEST,origin[1]),(CONTROL_ACTOR,control[0]),(CONTROL_MANIFEST,control[1])):put(ARTIFACT/name,raw)
 put(PLAN,module.encode(plan))
 call=(ARTIFACT/ACTOR,ARTIFACT/MANIFEST,args.selected_actor_sha256,args.selected_manifest_sha256,ARTIFACT/ORIGIN_ACTOR,ARTIFACT/ORIGIN_MANIFEST,OH,OMH,ARTIFACT/CONTROL_ACTOR,ARTIFACT/CONTROL_MANIFEST,CH,CMH,PRIVATE,PLAN)
 pre=module.preflight(*call);put(PREFLIGHT,module.encode(pre));require(pre['status']=='ready','preflight qualification')
 result=module.run_local(*call,approved=True);raw=module.encode(result);put(PUBLIC,raw)
 print(json.dumps(dict(source_commit=args.source_commit,source_sha256=source,public_bytes=len(raw),public_sha256=sha(raw),result=result),sort_keys=True));return 0 if result['status']=='observed' else 1

def main(argv=None):
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--execute-root-reviewed',action='store_true')
 for name in ('source-commit','source-sha256','ready-freeze-sha256','selected-actor-sha256','selected-manifest-sha256','before-sha256'):p.add_argument('--'+name)
 args=p.parse_args(argv)
 if not args.execute_root_reviewed:
  print(json.dumps(dict(mode='inert-stdlib-preview',scope=SCOPE,profile=PROFILE,source_count=COUNT,source_commit=args.source_commit,all_actual_pins_explicit_later=True,project_imported=False,nonce_or_plan_created=False,files_written=False,native_API_or_actor_called=False,actual_ready=False,one_attempt_only=True),sort_keys=True));return 0
 return actual(args)
if __name__=='__main__':raise SystemExit(main())
