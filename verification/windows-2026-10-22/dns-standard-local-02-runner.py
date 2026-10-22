"""One supervised ordinary DNS mechanism; no selected isolation claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

base=Path(__file__).resolve().parent;repo=base/'Rule-proxy-Web'
spec=importlib.util.spec_from_file_location('dns_standard_actual_02',repo/'.github/windows_identity_dns_standard_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert len(sys.argv)==2 and head==sys.argv[1], 'explicit frozen source commit required'
_,_,closure=m.snapshot()
assert closure=='5206fd171b4fc7c44717d71a5dc654ca47a80c59d93df9e314c915b253532d9f'
for path in m.SOURCES:
    assert (repo/path).read_bytes()==subprocess.check_output(['git','show',head+':'+path],cwd=repo),path
build=base/'dns-standard-compile-02';actor=build/m.ACTOR;manifest=build/m.MANIFEST
ah=hashlib.sha256(actor.read_bytes()).hexdigest();mh=hashlib.sha256(manifest.read_bytes()).hexdigest()
assert ah=='5e7cbcaaa0a7bfdfa9026898493cbf74dafaa7b875bb4749680cc5be98261299'
m.artifact(actor,manifest,ah,mh)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=api.device_sha256(),actor_sha256=ah,manifest_sha256=mh,
    source_sha256=closure,residue_review_acknowledged=True,standard53_impact_acknowledged=True,
    recovery_reference='Owner-authorized ordinary standard53 mechanism only: read-only effective DNS/NRPT/UDP53/TCP53 inventory before exclusive 127.0.0.1 UDP53 bind and fresh before native resume. Abort on any loopback DNS, effective NRPT, occupied53, unknown or stale inventory. Reply only to the fresh owned invalid-name query; close owned socket and held non-breakaway Jobs. No resolver, firewall, proxy, DNS or route mutation. No selected DNS qualification.')
plan_path=repo/'private/dns-standard-recovery-plan-02.json'
with plan_path.open('xb') as f:f.write(m.encode(plan))
inputs=(actor,manifest,ah,mh,repo/'private',plan_path)
out=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs)
with (out/'dns-standard-local-02-preflight.json').open('xb') as f:f.write(m.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True);raw=m.encode(value)
with (out/'dns-standard-local-02-public.json').open('xb') as f:f.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_sha256=hashlib.sha256(raw).hexdigest(),public_bytes=len(raw),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='passed' else 1)
