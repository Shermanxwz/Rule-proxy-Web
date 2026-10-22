"""One explicit source-frozen held identity pair; never resumes either actor."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

base=Path(__file__).resolve().parent
repo=base/'Rule-proxy-Web'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert len(sys.argv)==2 and head==sys.argv[1], 'explicit frozen commit required'
new_names=('windows_identity_lpac_accesscheck.py','windows_identity_lpac_identity_cell.py','windows_identity_lpac_identity_local.py')
for name in new_names:
    rel='.github/'+name
    assert (repo/rel).read_bytes()==subprocess.check_output(['git','show',head+':'+rel],cwd=repo),rel
spec=importlib.util.spec_from_file_location('lpac_identity_actual01',repo/'.github/windows_identity_lpac_identity_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert len(m.SOURCES)==34
for name in m.SOURCES:
    assert (repo/name).read_bytes()==subprocess.check_output(['git','show',head+':'+name],cwd=repo),name
_,_,closure=m.snapshot(repo)
actor=base/'proxy-c-compile-07'/m.live.ACTOR
manifest=actor.with_name(m.live.MANIFEST)
ah,mh=(hashlib.sha256(p.read_bytes()).hexdigest() for p in (actor,manifest))
assert ah=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
assert mh=='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
reference=('Owner-authorized identity-only matched AC/LPAC cell. Fresh profile, exact owned SID RX on stage root/inputs; '
    'same Agentic+PNCS, actor, command, environment, cwd and atomic Jobs; only AAP policy differs. '
    'Both actors remain suspended, independently held token/image/generation/two Jobs and four AccessChecks. '
    'Original120/115s, stop exact owned Jobs, close once, remove/readback SID ACEs, delete fresh profile. '
    'No actor resume, sockets, DNS, PSEC, proxy, firewall or global network edit; no automatic retry.')
assert len(reference)<=512
plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,fresh_profile_owned_acl_acknowledged=True,never_resume_acknowledged=True,
    semantics_only_acknowledged=True,recovery_reference=reference)
plan_path=repo/'private/lpac-identity-recovery-plan-01.json'
with plan_path.open('xb') as stream:stream.write(m.encode(plan))
inputs=(actor,manifest,ah,mh,repo/'private',plan_path)
evidence=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs)
with (evidence/'lpac-identity-local-01-preflight.json').open('xb') as stream:stream.write(m.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True)
raw=m.encode(value)
with (evidence/'lpac-identity-local-01-public.json').open('xb') as stream:stream.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),
    public_sha256=hashlib.sha256(raw).hexdigest(),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='observed' else 1)
