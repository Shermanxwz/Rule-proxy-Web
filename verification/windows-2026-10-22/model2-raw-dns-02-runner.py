"""One original-deadline connected raw UDP53 diagnostic, separate from API6."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys

base=Path(__file__).resolve().parent
repo=base/'Rule-proxy-Web'
spec=importlib.util.spec_from_file_location('c_raw_dns_actual_02',repo/'.github/windows_identity_model2_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert len(sys.argv)==2 and head==sys.argv[1], 'explicit frozen source commit required'
_,_,closure=m.live.source_snapshot()
for name in m.live.SOURCES:
    assert (repo/name).read_bytes()==subprocess.check_output(['git','show',head+':'+name],cwd=repo),name
build=base/'proxy-c-compile-07';actor=build/m.live.ACTOR;manifest=build/m.live.MANIFEST
ah,mh=(hashlib.sha256(p.read_bytes()).hexdigest() for p in (actor,manifest))
assert ah=='0a9e867cce846b366693e8662034db8c0c4646bd312a6143c367da2c36fb557a'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
mode='profiles-off-diagnostic';profile='same-selected-raw-standard53-dns-v1'
extension=dict(profile=profile,before_case=secrets.token_hex(16),selected_case=secrets.token_hex(16),
    after_case=secrets.token_hex(16),inventory_run=secrets.token_hex(16))
reference=('Owner-authorized connected raw UDP53 diagnostic. Original held selected/PSEC, P/Q/O, root deadline and cleanup. '
    'One fresh supervised readonly DNS/NRPT/53 inventory; exclusive owned127 UDP53; ordinary raw controls before/after selected. '
    'One connect/send/recvfrom sequence per case; preserve stage errors and receiver positives through failure. '
    'No unconnected-sendto/all-UDP/broker claim or strict qualification; no new cap, rule scope, global network edit, retry or fallback.')
assert len(reference)<=512
plan=dict(schema_version=1,scope=m.RAW_DNS_SCOPE,execution_mode=mode,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,residue_review_acknowledged=True,standard53_impact_acknowledged=True,
    selected_admission=m.live.system_conhost_record(api),dns_extension=extension,recovery_reference=reference)
plan_path=repo/'private/model2-raw-dns-recovery-plan-02.json'
with plan_path.open('xb') as stream:stream.write(m.live.encode(plan))
inputs=(actor,manifest,ah,mh,base/'mxc-g-runtime-bundle.zip',base/'mxc-g-runtime',repo/'private',plan_path)
options=dict(execution_mode=mode,allow_held_system_conhost=True,test_dns=True,dns_profile=profile)
evidence=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs,**options)
with (evidence/'model2-raw-dns-02-preflight.json').open('xb') as stream:stream.write(m.live.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True,**options);raw=m.live.encode(value)
with (evidence/'model2-raw-dns-02-public.json').open('xb') as stream:stream.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_sha256=hashlib.sha256(raw).hexdigest(),
    public_bytes=len(raw),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='diagnostic-observed' else 1)
