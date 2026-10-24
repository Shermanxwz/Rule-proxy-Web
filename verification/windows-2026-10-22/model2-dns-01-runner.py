"""One original-deadline, same-selected explicit-server DNS diagnostic."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import subprocess
import sys

base = Path(__file__).resolve().parent
repo = base / 'Rule-proxy-Web'
spec = importlib.util.spec_from_file_location('c_dns_actual_01', repo / '.github/windows_identity_model2_local.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=repo, text=True).strip()
assert len(sys.argv) == 2 and head == sys.argv[1], 'explicit frozen source commit required'
_, _, closure = m.live.source_snapshot()
for name in m.live.SOURCES:
    assert (repo / name).read_bytes() == subprocess.check_output(['git', 'show', head + ':' + name], cwd=repo), name
build = base / 'proxy-c-compile-06'
actor, manifest = build / m.live.ACTOR, build / m.live.MANIFEST
ah, mh = (hashlib.sha256(p.read_bytes()).hexdigest() for p in (actor, manifest))
assert ah == '2550491031b5041361d2c6448688e7e04a98fbd54ca8cdb2c1d2301db06fce10'
m.live.verify_actor(actor, manifest, ah, mh, root=repo)
api = m.local.LocalNativeAPI()
m.local.ordinary(api)
mode = 'profiles-off-diagnostic'
dns_extension = dict(profile='same-selected-standard53-dns-v1',
    before_case=secrets.token_hex(16), selected_case=secrets.token_hex(16),
    after_case=secrets.token_hex(16), inventory_run=secrets.token_hex(16))
reference = ('Owner-authorized standard53 diagnostic. Keep original held selected/PSEC, exact P/Q/O and root deadline. '
    'Supervise read-only inventory; bind exclusive owned loopback UDP53 only if freshly unoccupied, no loopback DNS or NRPT. '
    'Ordinary same-API controls before/after selected; retain every selected query even on failure. '
    'No resolver/broker/strict/product qualification, timeout-as-denial, cancel, retry, global network edits or external DNS target. '
    'Exact rule/ACL/profile/Job cleanup; preserve private evidence.')
assert len(reference) <= 512
plan = dict(schema_version=1, scope=m.DNS_SCOPE, execution_mode=mode,
    device_sha256=api.device_sha256(), source_sha256=closure, actor_sha256=ah, manifest_sha256=mh,
    residue_review_acknowledged=True, standard53_impact_acknowledged=True,
    selected_admission=m.live.system_conhost_record(api), dns_extension=dns_extension,
    recovery_reference=reference)
plan_path = repo / 'private/model2-dns-recovery-plan-01.json'
with plan_path.open('xb') as stream:
    stream.write(m.live.encode(plan))
inputs = (actor, manifest, ah, mh, base / 'mxc-g-runtime-bundle.zip',
          base / 'mxc-g-runtime', repo / 'private', plan_path)
options = dict(execution_mode=mode, allow_held_system_conhost=True, test_dns=True)
evidence = repo / 'verification/windows-2026-10-22'
pre = m.preflight(*inputs, **options)
with (evidence / 'model2-dns-01-preflight.json').open('xb') as stream:
    stream.write(m.live.encode(pre))
assert pre['status'] == 'ready', pre['failure']
value = m.run_local(*inputs, approved=True, **options)
raw = m.live.encode(value)
with (evidence / 'model2-dns-01-public.json').open('xb') as stream:
    stream.write(raw)
print(json.dumps(dict(source_commit=head, source_sha256=closure,
    public_sha256=hashlib.sha256(raw).hexdigest(), public_bytes=len(raw), result=value), sort_keys=True))
raise SystemExit(0 if value['status'] == 'diagnostic-observed' else 1)
