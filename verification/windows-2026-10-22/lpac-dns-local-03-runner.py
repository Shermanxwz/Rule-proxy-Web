"""One frozen standalone LPAC DNS mechanism; no G/PSEC or proxy acceptance."""
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
spec=importlib.util.spec_from_file_location('lpac_dns_actual_01',repo/'.github/windows_identity_lpac_dns_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
for name in m.SOURCES:
    assert (repo/name).read_bytes()==subprocess.check_output(['git','show',head+':'+name],cwd=repo),name
_,_,closure=m.snapshot(repo)
build=base/'proxy-c-compile-07'
actor,manifest=build/m.live.ACTOR,build/m.live.MANIFEST
ah,mh=(hashlib.sha256(p.read_bytes()).hexdigest() for p in (actor,manifest))
assert ah=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
assert mh=='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
reference=('Owner-authorized standalone LPAC DNS mechanism. Fresh profile and exact owned SID directory ACEs; '
    'Agentic+PNCS with OPT_OUT. Hold token46=1, generation, image and both Jobs before resume/GO. '
    'One readonly DNS/NRPT/53 inventory, exclusively owned127 UDP53, ordinary sameAPI before/after. '
    'Original deadline and exact cleanup; no G/PSEC, proxy, Linux-equivalence or causal LPAC repair claim. '
    'No firewall rule, global network edit, new capability, retry or fallback.')
assert len(reference)<=512
plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,standard53_impact_acknowledged=True,
    fresh_lpac_acl_profile_acknowledged=True,residue_review_acknowledged=True,recovery_reference=reference)
plan_path=repo/'private/lpac-dns-recovery-plan-03.json'
with plan_path.open('xb') as stream:stream.write(m.encode(plan))
inputs=(actor,manifest,ah,mh,repo/'private',plan_path)
evidence=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs)
with (evidence/'lpac-dns-local-03-preflight.json').open('xb') as stream:stream.write(m.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True)
raw=m.encode(value)
with (evidence/'lpac-dns-local-03-public.json').open('xb') as stream:stream.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),
    public_sha256=hashlib.sha256(raw).hexdigest(),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='observed' else 1)
