"""One source-frozen semantic-LPAC DNS mechanism, separate from G/PSEC."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

base=Path(__file__).resolve().parent;repo=base/'Rule-proxy-Web'
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert len(sys.argv)==2 and head==sys.argv[1], 'explicit frozen commit required'
for name in ('windows_identity_lpac_semantic_dns.py','windows_identity_lpac_semantic_dns_local.py'):
    rel='.github/'+name
    assert (repo/rel).read_bytes()==subprocess.check_output(['git','show',head+':'+rel],cwd=repo),rel
spec=importlib.util.spec_from_file_location('lpac_semantic_dns_actual01',repo/'.github/windows_identity_lpac_semantic_dns_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert len(m.SOURCES)==35
for name in m.SOURCES:
    assert (repo/name).read_bytes()==subprocess.check_output(['git','show',head+':'+name],cwd=repo),name
_,_,closure=m.snapshot(repo)
actor=base/'proxy-c-compile-07'/m.live.ACTOR;manifest=actor.with_name(m.live.MANIFEST)
ah,mh=(hashlib.sha256(p.read_bytes()).hexdigest() for p in (actor,manifest))
assert ah=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
assert mh=='657c88ef59f8ba9d4c24f5e407696b27615f50c63d58adc5d8dd64f942104e92'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
reference=('Owner-authorized standalone semantic-LPAC standard53 DNS mechanism. Fresh profile and exact owned SID ACLs, '
    'same Agentic+PNCS and native07. Independent held primary snapshot, image/generation/two Jobs and four AccessChecks '
    'before resume/each GO. Readonly DNS/NRPT/53 inventory, exclusive127 UDP53, ordinary sameAPI before/after. '
    'Original120/115s, sticky wire event and exact cleanup. No class46 invention, firewall/global network edit, '
    'G/PSEC or proxy repair claim, retry or fallback.')
assert len(reference)<=512
plan=dict(schema_version=1,scope=m.SCOPE,identity_basis=m.IDENTITY_BASIS,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,semantic_identity_acknowledged=True,standard53_impact_acknowledged=True,
    fresh_lpac_acl_profile_acknowledged=True,residue_review_acknowledged=True,recovery_reference=reference)
plan_path=repo/'private/lpac-semantic-dns-recovery-plan-01.json'
with plan_path.open('xb') as stream:stream.write(m.encode(plan))
inputs=(actor,manifest,ah,mh,repo/'private',plan_path)
evidence=repo/'verification/windows-2026-10-22';pre=m.preflight(*inputs)
with (evidence/'lpac-semantic-dns-local-01-preflight.json').open('xb') as stream:stream.write(m.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True);raw=m.encode(value)
with (evidence/'lpac-semantic-dns-local-01-public.json').open('xb') as stream:stream.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_bytes=len(raw),
    public_sha256=hashlib.sha256(raw).hexdigest(),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='observed' else 1)
