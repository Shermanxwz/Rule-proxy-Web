"""One explicitly opted-in profiles-off diagnostic; never strict C acceptance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

base=Path(__file__).resolve().parent
repo=base/'Rule-proxy-Web'
spec=importlib.util.spec_from_file_location('c_diagnostic_actual_01',repo/'.github/windows_identity_model2_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert len(sys.argv)==2 and head==sys.argv[1], 'explicit frozen source commit required'
_,_,closure=m.live.source_snapshot()
for path in m.live.SOURCES:
    assert (repo/path).read_bytes()==subprocess.check_output(['git','show',head+':'+path],cwd=repo),path
build=base/'proxy-c-compile-03';actor=build/m.live.ACTOR;manifest=build/m.live.MANIFEST
ah=hashlib.sha256(actor.read_bytes()).hexdigest();mh=hashlib.sha256(manifest.read_bytes()).hexdigest()
assert ah=='b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
mode='profiles-off-diagnostic'
plan=dict(schema_version=1,scope=m.DIAGNOSTIC_SCOPE,execution_mode=mode,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,residue_review_acknowledged=True,
    recovery_reference='Explicit owner-authorized profiles-off diagnostic. Three effective firewall profiles must freshly be False before exact scope rule creation and each selected GO. Retain identity, held process/Job, original deadline, exact rule/ACL/profile cleanup. Observe real selected proxy and direct behavior; all strict C and product qualification remain false. No global firewall/proxy/DNS/route edits. All prior four attempts recovered or clean; private evidence retained.')
plan_path=repo/'private/model2-diagnostic-recovery-plan-01.json'
with plan_path.open('xb') as f:f.write(m.live.encode(plan))
inputs=(actor,manifest,ah,mh,base/'mxc-g-runtime-bundle.zip',base/'mxc-g-runtime',repo/'private',plan_path)
evidence=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs,execution_mode=mode)
with (evidence/'model2-diagnostic-01-preflight.json').open('xb') as f:f.write(m.live.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True,execution_mode=mode)
raw=m.live.encode(value)
with (evidence/'model2-diagnostic-01-public.json').open('xb') as f:f.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_sha256=hashlib.sha256(raw).hexdigest(),
    public_bytes=len(raw),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='diagnostic-observed' else 1)
