import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
base=Path(__file__).resolve().parent
repo=base/'Rule-proxy-Web'
spec=importlib.util.spec_from_file_location('c_first_actual_01',repo/'.github/windows_identity_model2_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
head=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip()
assert head.startswith('3e8e015')
_,_,closure=m.live.source_snapshot()
for path in m.live.SOURCES:
    local_raw=(repo/path).read_bytes()
    committed=subprocess.check_output(['git','show',head+':'+path],cwd=repo)
    assert local_raw==committed,path
build=base/'proxy-c-compile-03';actor=build/m.live.ACTOR;manifest=build/m.live.MANIFEST
ah=hashlib.sha256(actor.read_bytes()).hexdigest();mh=hashlib.sha256(manifest.read_bytes()).hexdigest()
assert ah=='b5fda518d9b621ecf86899eff5aa2a1f33f1c313305542fcde26832ac0065be7'
m.live.verify_actor(actor,manifest,ah,mh,root=repo)
api=m.local.LocalNativeAPI();m.local.ordinary(api)
plan=dict(schema_version=1,scope=m.SCOPE,device_sha256=api.device_sha256(),source_sha256=closure,
    actor_sha256=ah,manifest_sha256=mh,residue_review_acknowledged=True,
    recovery_reference='Full device-owner authorization; one fresh PNCS profile and exact journal-bound program/package/127.0.0.1 TCP high-port inbound rule. Held workload exit and Job empty before exact rule deletion, maintenance exit, ACL tools empty, profile deletion. Retain all private journals on any uncertainty. No global policy/proxy/DNS/route edits.')
plan_path=repo/'private/model2-first-recovery-plan-01.json'
with plan_path.open('xb') as f:f.write(m.live.encode(plan))
inputs=(actor,manifest,ah,mh,base/'mxc-g-runtime-bundle.zip',base/'mxc-g-runtime',repo/'private',plan_path)
evidence=repo/'verification/windows-2026-10-22'
pre=m.preflight(*inputs)
with (evidence/'model2-first-01-preflight.json').open('xb') as f:f.write(m.live.encode(pre))
assert pre['status']=='ready',pre['failure']
value=m.run_local(*inputs,approved=True)
raw=m.live.encode(value)
with (evidence/'model2-first-01-public.json').open('xb') as f:f.write(raw)
print(json.dumps(dict(source_commit=head,source_sha256=closure,public_sha256=hashlib.sha256(raw).hexdigest(),
    public_bytes=len(raw),result=value),sort_keys=True))
raise SystemExit(0 if value['status']=='observed' else 1)
