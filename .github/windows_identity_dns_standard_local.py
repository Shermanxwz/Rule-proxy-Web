"""Opt-in ordinary standard53 mechanism; default preflight starts no child.

The owned receiver is only exclusive UDP 127.0.0.1:53, never a resolver service.
Read-only DNS/Effective-NRPT/UDP53/TCP53 inventory must be known and safe before
bind and fresh before native resume. Nonempty effective NRPT is conservatively
refused, without claiming every rule affects this namespace. No auto retry,
DNS/proxy/route/firewall changes, default resolver or selected DNS qualification.
"""
from __future__ import annotations
import argparse
import importlib.util
import ipaddress
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('standard_dns_v1_helpers', Path(__file__).with_name('windows_identity_dns_v1_local.py'))
v1 = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(v1)
local, launcher, a = v1.local, v1.launcher, v1.a
sha, encode, require = v1.sha, v1.encode, v1.require
INVENTORY = '.github/windows_identity_dns_standard_inventory.ps1'
NATIVE = {'actorSourceSha256': '.github/native/windows_identity_dns_standard_actor.cpp',
    'identitySourceSha256': '.github/native/windows_identity_actor.cpp',
    'dnsProbeSha256': '.github/native/windows_identity_dns_standard_probe.hpp'}
SOURCES = (*v1.SOURCES, '.github/windows_identity_dns_standard_local.py', INVENTORY, *NATIVE.values())
ACTOR = 'windows_identity_dns_standard_actor.exe'
MANIFEST = 'identity-dns-standard-manifest.json'
SCOPE = 'one-ordinary-standard53-dns-owned-loopback-v1'
CONSTRUCTOR = 'official-v1-zero-port'
PRECHECKS = ('ordinary', 'device_plan', 'source_bound', 'artifact_bound')
CHECKS = (*v1.CHECKS, 'inventory_atomic', 'inventory_held', 'inventory_exit', 'inventory_cleanup',
    'inventory_report_bound', 'inventory_before_bind', 'inventory_before_query')
MAX_INVENTORY = 32768
INVENTORY_KEYS = {'schema_version', 'stage', 'run', 'pid', 'qpc_frequency', 'start_qpc', 'deadline_qpc',
    'begin_qpc', 'end_qpc', 'read_only', 'dns_servers', 'effective_nrpt_count', 'udp53_count', 'tcp53_count'}
INVENTORY_PUBLIC_KEYS = {'known', 'dns_server_count', 'loopback_dns_present', 'effective_nrpt_count',
    'udp53_count', 'tcp53_count', 'reason', 'raw_sha256'}
REASONS = ('none', 'unknown', 'dns_loopback', 'effective_nrpt_present', 'udp53_occupied', 'tcp53_occupied', 'stale')

def snapshot(root=ROOT):
    files = {name: local.bounded(launcher.checked_path(root/name, inside=root), 256*1024) for name in SOURCES}
    hashes = {name: sha(raw) for name, raw in files.items()}
    return files, hashes, sha(encode(hashes))

def artifact(actor, manifest, ah, mh, root=ROOT):
    actor = launcher.checked_path(actor); manifest = launcher.checked_path(manifest)
    require(actor.name == ACTOR and manifest.name == MANIFEST and actor.parent == manifest.parent)
    value, raw = a.bounded_json(manifest, 8192, inside=actor.parent)
    require(type(value) is dict and set(value) == {'schemaVersion', 'compileOnly', 'runtimeAcceptance', 'executableSha256', *NATIVE})
    require(type(value['schemaVersion']) is int and value['schemaVersion'] == 1
        and value['compileOnly'] is True and value['runtimeAcceptance'] is False)
    require(a.digest(ah) and a.digest(mh) and sha(raw) == mh and value['executableSha256'] == ah)
    a.pipe_helpers.verify_copied_actor(actor, ah)
    for key, name in NATIVE.items(): require(value[key] == sha(local.bounded(root/name, 256*1024)))
    return actor, manifest

def blank(mode):
    return dict(schema_version=1, stage='ordinary-dns-standard-local', mode=mode, status='inconclusive', failure=None,
        source_sha256=None, actor_sha256=None, manifest_sha256=None, recovery_plan_sha256=None,
        server_constructor=CONSTRUCTOR, checks=dict.fromkeys(CHECKS, False), inventory=None, api=None, fixture=None,
        network_tested=False, owned_query_observed=False, mechanism_passed=False, tree_retained=False,
        recovery_required=False, default_resolver_tested=False, selected_application_tested=False,
        broker_cancellation_proven=False, dns_isolation_qualified=False, product_acceptance=False)

def inventory_projection(value, *, run, pid, frequency, start, deadline, now, raw_sha256):
    require(type(value) is dict and set(value) == INVENTORY_KEYS)
    require(type(value['schema_version']) is int and value['schema_version'] == 1
        and value['stage'] == 'dns-standard-readonly-inventory' and value['run'] == run
        and type(value['pid']) is int and value['pid'] == pid and value['read_only'] is True)
    require(all(type(value[key]) is int and value[key] == expected for key, expected in
        (('qpc_frequency', frequency), ('start_qpc', start), ('deadline_qpc', deadline))))
    require(a.integer(start, 1) and a.integer(frequency, 1) and start < deadline <= start + 120*frequency
        and a.integer(value['begin_qpc'], start, deadline-1)
        and a.integer(value['end_qpc'], value['begin_qpc'], deadline-1) and a.integer(now, value['end_qpc']))
    servers = value['dns_servers']; require(type(servers) is list and len(servers) <= 256)
    addresses = []
    for server in servers:
        require(type(server) is str and 1 <= len(server) <= 96 and server == server.strip())
        address = ipaddress.ip_address(server)
        require(not address.is_unspecified and not address.is_multicast)
        addresses.append(address)
    require(all(a.integer(value[key], 0, 32768) for key in ('effective_nrpt_count', 'udp53_count', 'tcp53_count')))
    require(value['effective_nrpt_count'] <= 256 and a.digest(raw_sha256))
    loopback = any(address.is_loopback or isinstance(address, ipaddress.IPv6Address)
        and address.ipv4_mapped is not None and address.ipv4_mapped.is_loopback for address in addresses)
    reason = ('dns_loopback' if loopback else 'effective_nrpt_present' if value['effective_nrpt_count']
        else 'udp53_occupied' if value['udp53_count'] else 'tcp53_occupied' if value['tcp53_count']
        else 'stale' if now >= deadline or now-value['end_qpc'] > 5*frequency else 'none')
    return dict(known=True, dns_server_count=len(servers), loopback_dns_present=loopback,
        effective_nrpt_count=value['effective_nrpt_count'], udp53_count=value['udp53_count'], tcp53_count=value['tcp53_count'],
        reason=reason, raw_sha256=raw_sha256)

def unknown_inventory():
    return dict(known=False, dns_server_count=None, loopback_dns_present=None, effective_nrpt_count=None,
        udp53_count=None, tcp53_count=None, reason='unknown', raw_sha256=None)

def inventory_safe(value):
    return value is not None and value['known'] is True and value['reason'] == 'none'

def validate(value):
    template = blank(value.get('mode') if type(value) is dict else None)
    require(type(value) is dict and set(value) == set(template) and value['mode'] in ('preflight', 'runtime'))
    for key in ('schema_version', 'stage', 'server_constructor', 'default_resolver_tested', 'selected_application_tested',
            'broker_cancellation_proven', 'dns_isolation_qualified', 'product_acceptance'):
        require(type(value[key]) is type(template[key]) and value[key] == template[key])
    require(value['status'] in ('ready', 'inconclusive', 'passed') and value['failure'] in
        (None, 'inputs', 'identity', 'plan', 'deadline', 'staging', 'worker', 'report', 'cleanup', 'inventory', 'mechanism'))
    checks = value['checks']; require(type(checks) is dict and set(checks) == set(CHECKS) and all(type(x) is bool for x in checks.values()))
    for key in ('network_tested', 'owned_query_observed', 'mechanism_passed', 'tree_retained', 'recovery_required'): require(type(value[key]) is bool)
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256', 'recovery_plan_sha256'): require(value[key] is None or a.digest(value[key]))
    for flag, digest in (('source_bound', 'source_sha256'), ('artifact_bound', 'actor_sha256'), ('artifact_bound', 'manifest_sha256'), ('device_plan', 'recovery_plan_sha256')):
        require(not checks[flag] or a.digest(value[digest]))
    inventory = value['inventory']
    if inventory is not None:
        require(type(inventory) is dict and set(inventory) == INVENTORY_PUBLIC_KEYS and type(inventory['known']) is bool and inventory['reason'] in REASONS)
        if inventory['known']:
            require(a.integer(inventory['dns_server_count'], 0, 256) and type(inventory['loopback_dns_present']) is bool
                and a.integer(inventory['effective_nrpt_count'], 0, 256)
                and all(a.integer(inventory[k], 0, 32768) for k in ('udp53_count', 'tcp53_count')) and a.digest(inventory['raw_sha256']))
            expected = ('dns_loopback' if inventory['loopback_dns_present'] else 'effective_nrpt_present' if inventory['effective_nrpt_count']
                else 'udp53_occupied' if inventory['udp53_count'] else 'tcp53_occupied' if inventory['tcp53_count']
                else 'stale' if inventory['reason'] == 'stale' else 'none')
            require(inventory['reason'] == expected and expected in REASONS and expected != 'unknown')
            require(expected != 'none' or not any(inventory[k] for k in ('loopback_dns_present', 'effective_nrpt_count', 'udp53_count', 'tcp53_count')))
        else: require(inventory == unknown_inventory())
    require(not checks['inventory_before_bind'] or inventory_safe(inventory))
    require(not checks['inventory_before_query'] or checks['inventory_before_bind'])
    api = value['api']
    if api is not None:
        require(type(api) is dict and set(api) == {*v1.BOOLS, 'api_status', 'query_status', 'record_count', 'query_status_valid'})
        v1.validate_api({key: val for key, val in api.items() if key != 'query_status_valid'})
        require(type(api['query_status_valid']) is bool and api['query_status_valid'] == api['completed'])
    f = value['fixture']
    if f is not None:
        require(type(f) is dict and set(f) == {'matched_queries', 'answers_sent', 'rejected', 'send_failed', 'query_observed', 'snapshot_complete', 'error'})
        require(type(f['query_observed']) is bool and type(f['snapshot_complete']) is bool)
        require(all(a.integer(f[key], 0, 32) if f['snapshot_complete'] else f[key] is None
            for key in ('matched_queries', 'answers_sent', 'rejected', 'send_failed')) and f['error'] in ('none', 'bound', 'deadline', 'receive', 'operation', 'send'))
        require(not f['snapshot_complete'] or f['query_observed'] == (f['matched_queries'] > 0))
    require(value['network_tested'] == value['owned_query_observed'] == bool(f and f['query_observed']))
    if value['mode'] == 'preflight':
        require(api is None and f is None and inventory is None and not value['tree_retained'] and not value['recovery_required']
            and not any(checks[key] for key in CHECKS if key not in PRECHECKS))
        require(value['status'] != 'ready' or value['failure'] is None and all(checks[key] for key in PRECHECKS))
    success = (value['mode'] == 'runtime' and value['failure'] is None and all(checks.values()) and inventory_safe(inventory)
        and api is not None and all(api[key] for key in ('configured', 'called', 'completed', 'answer_match', 'records_released', 'within_deadline', 'query_status_valid'))
        and not api['pending'] and not api['context_retained'] and value['owned_query_observed'] and f['snapshot_complete']
        and f['answers_sent'] > 0 and f['rejected'] == f['send_failed'] == 0 and f['error'] == 'none'
        and not value['recovery_required'] and value['tree_retained'])
    require(value['mechanism_passed'] == success and (value['status'] == 'passed') == success)
    require(len(encode(value)) <= 8192); return value

def preflight(actor, manifest, ah, mh, work_parent, plan_path, *, api=None):
    v = blank('preflight'); phase = 'inputs'
    try:
        require(os.name == 'nt'); api = api or local.LocalNativeAPI(); require(api.windows_x64())
        phase = 'identity'; local.ordinary(api); v['checks']['ordinary'] = True
        phase = 'inputs'; _, _, closure = snapshot(); v['source_sha256'] = closure; v['checks']['source_bound'] = True
        artifact(actor, manifest, ah, mh); v.update(actor_sha256=ah, manifest_sha256=mh); v['checks']['artifact_bound'] = True
        parent = launcher.checked_path(work_parent, inside=ROOT/'private', is_file=False); require(parent.is_dir())
        phase = 'plan'; raw = local.bounded(plan_path, 8192); plan = local.guest.decode(raw)
        require(type(plan) is dict and set(plan) == {'schema_version', 'scope', 'device_sha256', 'actor_sha256', 'manifest_sha256',
            'source_sha256', 'residue_review_acknowledged', 'recovery_reference', 'standard53_impact_acknowledged'})
        require(type(plan['schema_version']) is int and plan['schema_version'] == 1 and plan['scope'] == SCOPE
            and plan['residue_review_acknowledged'] is True and plan['standard53_impact_acknowledged'] is True)
        for key, expected in (('device_sha256', api.device_sha256()), ('actor_sha256', ah), ('manifest_sha256', mh), ('source_sha256', closure)): require(plan[key] == expected)
        require(type(plan['recovery_reference']) is str and 1 <= len(plan['recovery_reference']) <= 512)
        v['recovery_plan_sha256'] = sha(raw); v['checks']['device_plan'] = True; v['status'] = 'ready'
    except BaseException: v['failure'] = phase
    return validate(v)

def native_projection(value, run, frequency, deadline, pid, sid, start):
    require(type(value) is dict and set(value) == {'schema_version', 'stage', 'identity', 'server_constructor', 'qpc_frequency', 'deadline_qpc', 'result'})
    require(type(value['schema_version']) is int and value['schema_version'] == 1 and value['stage'] == 'dns-standard-native'
        and value['server_constructor'] == CONSTRUCTOR and type(value['qpc_frequency']) is int and value['qpc_frequency'] == frequency
        and type(value['deadline_qpc']) is int and value['deadline_qpc'] == deadline)
    identity = value['identity']
    require(type(identity) is dict and set(identity) == {'schemaVersion', 'mode', 'nonce', 'pid', 'tokenUserSid',
        'tokenIsAppContainer', 'tokenAppContainerSid', 'tokenElevated', 'isProcessInJob', 'tokenCapabilities', 'queriesSucceeded', 'errors'})
    require(type(identity['schemaVersion']) is int and identity['schemaVersion'] == 1 and type(identity['pid']) is int and identity['pid'] == pid
        and identity['tokenUserSid'] == sid and identity['tokenAppContainerSid'] is None and identity['nonce'] == run and identity['mode'] == 'actor'
        and identity['queriesSucceeded'] is True and identity['errors'] == [] and identity['tokenElevated'] is False
        and identity['tokenIsAppContainer'] is False and identity['tokenCapabilities'] == [] and identity['isProcessInJob'] is True)
    r = value['result']; require(type(r) is dict and set(r) == {*v1.BOOLS, 'api_status', 'query_status', 'record_count', 'start_qpc', 'end_qpc'})
    require(a.integer(r['start_qpc'], start, 0x7fffffffffffffff) and a.integer(r['end_qpc'], r['start_qpc'], 0x7fffffffffffffff))
    require(not r['within_deadline'] or r['start_qpc'] <= r['end_qpc'] < deadline)
    result = v1.validate_api({key: val for key, val in r.items() if key not in ('start_qpc', 'end_qpc')})
    return dict(result, query_status_valid=result['completed'])

def config_valid(c):
    require(type(c) is dict and set(c) == {'schema_version', 'run', 'actor_run', 'inventory_run', 'frequency', 'start', 'root_deadline', 'deadline',
        'source_sha256', 'source_hashes', 'actor_sha256', 'manifest_sha256', 'device_sha256', 'guard_job_name', 'recovery_plan_sha256'})
    require(type(c['schema_version']) is int and c['schema_version'] == 1 and all(a.nonce(c[key]) for key in ('run', 'actor_run', 'inventory_run'))
        and len({c[key] for key in ('run', 'actor_run', 'inventory_run')}) == 3)
    require(all(a.integer(c[key], 1) for key in ('frequency', 'start', 'deadline', 'root_deadline'))
        and c['root_deadline'] == c['start']+120*c['frequency'] and c['deadline'] == c['root_deadline']-5*c['frequency'])
    require(c['guard_job_name'] == 'Local\\RuleProxy.LocalGuard.'+c['run'])
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256', 'device_sha256', 'recovery_plan_sha256'): require(a.digest(c[key]))
    require(type(c['source_hashes']) is dict and set(c['source_hashes']) == set(SOURCES)
        and all(a.digest(v) for v in c['source_hashes'].values()) and sha(encode(c['source_hashes'])) == c['source_sha256'])
    return c

def system_powershell(api, work):
    environment = dict(entry.split('=', 1) for entry in api.environment(work).rstrip('\0').split('\0'))
    require(set(environment) == {'SystemRoot', 'WINDIR', 'TEMP', 'TMP'} and environment['SystemRoot'] == environment['WINDIR'])
    return launcher.checked_path(Path(environment['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')

class GatedActorAPI(local.LocalNativeAPI):
    def __init__(self, gate):
        super().__init__(); self.inventory_gate = gate; self.inventory_gate_checked = False; self.inventory_gate_qpc = None
    def resume(self, thread):
        self.inventory_gate_qpc = self.inventory_gate(); self.inventory_gate_checked = True
        return super().resume(thread)

def collect_inventory(stage, c, parent, budget, *, api_factory=None):
    result = dict(launch=None, attempted=False, atomic=False, raw=None, raw_text=None, raw_sha256=None,
        observed_qpc=None, projection=unknown_inventory())
    api = None
    try:
        api = (api_factory or local.LocalNativeAPI)()
        require(api.qpc_frequency() == c['frequency'] and local.ordinary(api) == parent)
        api.worker_job_name = 'Local\\RuleProxy.LocalGuard.'+c['inventory_run']; api.worker_sid = parent['sid']
        work = stage/'inventory'; work.mkdir(); (work/'temp').mkdir()
        script = stage/INVENTORY; require(sha(local.bounded(script, 256*1024)) == c['source_hashes'][INVENTORY])
        exe = system_powershell(api, work)
        command = [str(exe), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(script),
            '-Run', c['inventory_run'], '-Frequency', str(c['frequency']), '-StartQpc', str(c['start']), '-DeadlineQpc', str(c['deadline'])]
        result['attempted'] = True
        result['launch'] = launcher.launch_owned(api, command, work, parent, parent, qpc_budget=budget,
            work_cutoff=min(budget.read()+10*c['frequency'], budget.cutoff(60)), cleanup_cutoff=budget.cutoff(50))
        raw = local.bounded(work/'controller.stdout', MAX_INVENTORY)
        require(not local.bounded(work/'controller.stderr', MAX_INVENTORY) and sha(local.bounded(script, 256*1024)) == c['source_hashes'][INVENTORY])
        value = local.guest.decode(raw); observed = budget.read()
        projection = inventory_projection(value, run=c['inventory_run'], pid=result['launch'].get('child_pid'), frequency=c['frequency'], start=c['start'],
            deadline=c['deadline'], now=observed, raw_sha256=sha(raw))
        result.update(raw=value, raw_text=raw.decode('utf-8', 'strict'), raw_sha256=sha(raw), observed_qpc=observed, projection=projection)
    except BaseException:
        pass
    result['atomic'] = api is not None and api.atomic_job_requested is True
    return result

def perform_mechanism(stage, c, parent, budget, *, inventory_fn=None, fixture_factory=None, actor_api_factory=None):
    """Injection seam is only for pure tests; production calls fixed dependencies."""
    fixture = fixture_result = launch = raw_native = None
    inventory = None; failure = None; actor_api = None; before_bind = False; before_bind_qpc = None; actor_attempted = False
    try:
        inventory = (inventory_fn or collect_inventory)(stage, c, parent, budget)
        require(inventory['atomic'] and inventory['attempted'] and v1.launch_ok(inventory['launch']))
        require(inventory_safe(inventory['projection']))
        def gate():
            now = budget.read()
            fresh = inventory_projection(inventory['raw'], run=c['inventory_run'], pid=inventory['launch']['child_pid'],
                frequency=c['frequency'], start=c['start'], deadline=c['deadline'], now=now, raw_sha256=inventory['raw_sha256'])
            require(inventory_safe(fresh))
            return now
        before_bind_qpc = gate(); before_bind = True
        deadline = time.monotonic()+budget.remaining_ms(budget.cutoff(10))/1000
        fixture = (fixture_factory or v1.fixture_module.DnsFixture.for_port53)(c['actor_run'], deadline=deadline)
        require(fixture.bind_port == 53 and fixture.bind_address == '127.0.0.1' and fixture.allowed_peers == ('127.0.0.1',))
        require(fixture.start() == 53)
        gate()
        work = stage/'actor'; work.mkdir(); (work/'temp').mkdir()
        actor_api = (actor_api_factory or GatedActorAPI)(gate)
        require(actor_api.qpc_frequency() == c['frequency'] and local.ordinary(actor_api) == parent)
        actor_api.worker_job_name = 'Local\\RuleProxy.LocalGuard.'+c['actor_run']; actor_api.worker_sid = parent['sid']
        actor_attempted = True
        launch = launcher.launch_owned(actor_api, [str(stage/'native'/ACTOR), c['actor_run'], str(c['frequency']), str(budget.cutoff(15))],
            work, parent, parent, qpc_budget=budget, work_cutoff=budget.cutoff(10), cleanup_cutoff=budget.cutoff(5))
        raw_native = local.bounded(work/'controller.stdout', 8192)
        require(not local.bounded(work/'controller.stderr', 8192))
    except BaseException: failure = 'inventory' if not before_bind else 'worker'
    finally:
        if fixture is not None:
            try: fixture_result = fixture.finish(deadline=time.monotonic()+budget.remaining_ms(budget.cutoff(2))/1000)
            except BaseException: failure = 'cleanup'
    text, status, digest = v1.native_text(raw_native)
    if status == 'non-ascii': failure = 'worker'
    return dict(inventory=inventory, inventory_before_bind=before_bind,
        inventory_before_bind_qpc=before_bind_qpc,
        inventory_before_query=actor_api is not None and actor_api.inventory_gate_checked is True,
        inventory_before_query_qpc=None if actor_api is None else actor_api.inventory_gate_qpc,
        launch=launch, actor_attempted=actor_attempted, actor_atomic=actor_api is not None and actor_api.atomic_job_requested is True,
        fixture=fixture_result, fixture_attempted=fixture is not None, native=text, native_status=status, native_sha256=digest, failure=failure)

def worker(config_path):
    stage = Path(__file__).resolve().parents[1]; config_path = launcher.checked_path(config_path, inside=stage)
    require(config_path == stage/'dns-standard-config.json')
    c = config_valid(local.guest.decode(local.bounded(config_path, 16384)))
    api = local.LocalNativeAPI(); parent = local.ordinary(api); local.verify_guard_job(api, c['guard_job_name'])
    require(c['device_sha256'] == api.device_sha256() and c['frequency'] == api.qpc_frequency())
    _, hashes, closure = snapshot(stage); require(closure == c['source_sha256'] and hashes == c['source_hashes'])
    require(sha(local.bounded(stage/'recovery-plan.json', 8192)) == c['recovery_plan_sha256'])
    artifact(stage/'native'/ACTOR, stage/'native'/MANIFEST, c['actor_sha256'], c['manifest_sha256'], stage)
    budget = launcher.QpcBudget(api, c['deadline'], c['frequency']); budget.require_ms(budget.cutoff(70))
    result = perform_mechanism(stage, c, parent, budget)
    report = dict(schema_version=1, stage='dns-standard-owned-worker', run=c['run'], worker_pid=os.getpid(), worker_sid=parent['sid'],
        source_sha256=closure, actor_sha256=c['actor_sha256'], manifest_sha256=c['manifest_sha256'],
        frequency=c['frequency'], start=c['start'], deadline=c['deadline'], root_deadline=c['root_deadline'], **result)
    launcher.write_private_bytes(stage/'dns-standard-worker-report.json', encode(report)); return 0

def bind_report(report, c, launch, sid):
    keys = {'schema_version', 'stage', 'run', 'worker_pid', 'worker_sid', 'source_sha256', 'actor_sha256', 'manifest_sha256',
        'frequency', 'start', 'deadline', 'root_deadline', 'inventory', 'inventory_before_bind', 'inventory_before_query',
        'inventory_before_bind_qpc', 'inventory_before_query_qpc',
        'launch', 'actor_attempted', 'actor_atomic', 'fixture', 'fixture_attempted', 'native', 'native_status', 'native_sha256', 'failure'}
    require(type(report) is dict and set(report) == keys and type(report['schema_version']) is int and report['schema_version'] == 1
        and report['stage'] == 'dns-standard-owned-worker' and type(report['worker_pid']) is int
        and report['worker_pid'] == launch.get('child_pid') and report['worker_sid'] == sid)
    for key in ('run', 'source_sha256', 'actor_sha256', 'manifest_sha256', 'frequency', 'start', 'deadline', 'root_deadline'):
        require(type(report[key]) is type(c[key]) and report[key] == c[key])
    require(all(type(report[key]) is bool for key in ('inventory_before_bind', 'inventory_before_query', 'actor_attempted', 'actor_atomic', 'fixture_attempted')))
    require(report['failure'] in (None, 'inventory', 'worker', 'cleanup'))
    require(report['native_status'] in ('missing', 'ascii', 'non-ascii'))
    if report['native'] is None:
        require(report['native_status'] in ('missing', 'non-ascii')
            and (report['native_sha256'] is None if report['native_status'] == 'missing' else a.digest(report['native_sha256'])))
    else:
        require(type(report['native']) is str and report['native_status'] == 'ascii'
            and len(report['native']) <= 8192 and sha(report['native'].encode('ascii', 'strict')) == report['native_sha256'])
    require(report['launch'] is None or report['actor_attempted'])
    require(report['fixture'] is None or report['fixture_attempted'])
    for key in ('inventory_before_bind', 'inventory_before_query'):
        timestamp = report[key+'_qpc']
        require(a.integer(timestamp, c['start'], c['deadline']-1) if report[key] else timestamp is None)
    require(not report['inventory_before_query'] or report['inventory_before_bind']
        and report['inventory_before_query_qpc'] >= report['inventory_before_bind_qpc'])
    return report

def apply_report(v, report, c, outer, sid, now):
    bind_report(report, c, outer, sid); checks = v['checks']; checks['worker_report_bound'] = True
    require(a.integer(now, c['start'], c['root_deadline']-1))
    inventory = report['inventory']
    if inventory is None:
        v['inventory'] = unknown_inventory()
    else:
        require(type(inventory) is dict and set(inventory) == {'launch', 'attempted', 'atomic', 'raw', 'raw_text', 'raw_sha256', 'observed_qpc', 'projection'})
        require(type(inventory['atomic']) is bool and type(inventory['attempted']) is bool)
        il = inventory['launch']; checks['inventory_atomic'] = inventory['atomic']
        checks['inventory_cleanup'] = not inventory['attempted']
        if il is not None:
            checks.update(inventory_held=il.get('native_identity_verified_before_resume') is True,
                inventory_exit=il.get('cleanup', {}).get('process_exit_confirmed') is True, inventory_cleanup=local.guest.cleanup_verified(il))
        if inventory['raw'] is None:
            require(inventory['raw_text'] is None and inventory['raw_sha256'] is None and inventory['observed_qpc'] is None
                and inventory['projection'] == unknown_inventory() and not report['inventory_before_bind'] and not report['inventory_before_query'])
            v['inventory'] = unknown_inventory()
        else:
            require(il is not None and type(inventory['raw_text']) is str)
            raw = inventory['raw_text'].encode('utf-8', 'strict')
            require(len(raw) <= MAX_INVENTORY and sha(raw) == inventory['raw_sha256'] and local.guest.decode(raw) == inventory['raw'])
            require(a.integer(inventory['observed_qpc'], c['start'], now))
            observed = inventory_projection(inventory['raw'], run=c['inventory_run'], pid=il.get('child_pid'),
                frequency=c['frequency'], start=c['start'], deadline=c['deadline'], now=inventory['observed_qpc'], raw_sha256=sha(raw))
            require(observed == inventory['projection']); v['inventory'] = observed; checks['inventory_report_bound'] = True
            for key in ('inventory_before_bind', 'inventory_before_query'):
                if report[key]:
                    fresh = inventory_projection(inventory['raw'], run=c['inventory_run'], pid=il.get('child_pid'), frequency=c['frequency'],
                        start=c['start'], deadline=c['deadline'], now=report[key+'_qpc'], raw_sha256=sha(raw))
                    require(inventory_safe(fresh) and inventory['observed_qpc'] <= report[key+'_qpc'] <= now); checks[key] = True
    # Independent receiver observations precede native decoding and stay sticky.
    fixture = report['fixture']
    checks['fixture_cleanup'] = not report['fixture_attempted']
    if fixture is not None:
        v['fixture'] = v1.receiver_projection(fixture); checks['fixture_cleanup'] = fixture['cleanup_confirmed'] is True
        v['network_tested'] = v['owned_query_observed'] = v['fixture']['query_observed']
    actor = report['launch']; checks['actor_cleanup'] = not report['actor_attempted']
    checks['actor_atomic'] = report['actor_atomic']
    if actor is not None:
        checks.update(actor_held=actor.get('native_identity_verified_before_resume') is True,
            actor_exit=actor.get('cleanup', {}).get('process_exit_confirmed') is True, actor_cleanup=local.guest.cleanup_verified(actor))
    v['recovery_required'] = not (checks['outer_cleanup'] and checks['inventory_cleanup'] and checks['actor_cleanup'] and checks['fixture_cleanup'])
    if report['native'] is not None:
        require(report['native_status'] == 'ascii' and report['native_sha256'] == sha(report['native'].encode('ascii')))
        v['api'] = native_projection(local.guest.decode(report['native'].encode('ascii')), c['actor_run'], c['frequency'],
            c['deadline']-15*c['frequency'], None if actor is None else actor.get('child_pid'), sid,
            report['inventory_before_query_qpc'] if report['inventory_before_query'] else c['start'])
    require(now < c['root_deadline'])
    return inventory, actor

def run_local(actor, manifest, ah, mh, work_parent, plan_path, *, approved=False):
    v = blank('runtime'); phase = 'inputs'; launched = False
    try:
        require(approved); api = local.LocalNativeAPI(); f = api.qpc_frequency(); start = api.qpc()
        budget = launcher.QpcBudget(api, start+120*f, f)
        pre = preflight(actor, manifest, ah, mh, work_parent, plan_path, api=api)
        for key in ('checks', 'source_sha256', 'actor_sha256', 'manifest_sha256', 'recovery_plan_sha256'): v[key] = pre[key]
        if pre['status'] != 'ready': phase = pre['failure']; raise ValueError('preflight')
        files, hashes, closure = snapshot(); require(closure == v['source_sha256'])
        parent = local.ordinary(api); run, actor_run, inventory_run = (secrets.token_hex(16) for _ in range(3))
        require(len({run, actor_run, inventory_run}) == 3)
        phase = 'deadline'; budget.require_ms(budget.cutoff(80)); phase = 'staging'; stage = Path(work_parent)/('local-dns-standard-'+run)
        v['tree_retained'] = True; api.private_directory(stage, parent['sid'])
        for name, raw in files.items():
            path = stage/name; path.parent.mkdir(parents=True, exist_ok=True); launcher.write_private_bytes(path, raw)
        native = stage/'native'; native.mkdir()
        launcher.write_private_bytes(native/ACTOR, local.bounded(actor, 8*1024*1024))
        launcher.write_private_bytes(native/MANIFEST, local.bounded(manifest, 8192)); artifact(native/ACTOR, native/MANIFEST, ah, mh, stage)
        api.worker_job_name = 'Local\\RuleProxy.LocalGuard.'+run; api.worker_sid = parent['sid']
        c = config_valid(dict(schema_version=1, run=run, actor_run=actor_run, inventory_run=inventory_run, frequency=f, start=start,
            root_deadline=budget.deadline, deadline=budget.cutoff(5), source_sha256=closure, source_hashes=hashes,
            actor_sha256=ah, manifest_sha256=mh, device_sha256=api.device_sha256(), guard_job_name=api.worker_job_name,
            recovery_plan_sha256=v['recovery_plan_sha256']))
        launcher.write_private_bytes(stage/'dns-standard-config.json', encode(c))
        plan_raw = local.bounded(plan_path, 8192); require(sha(plan_raw) == v['recovery_plan_sha256'])
        launcher.write_private_bytes(stage/'recovery-plan.json', plan_raw)
        guard = stage/'guard'; guard.mkdir(); (guard/'temp').mkdir(); phase = 'deadline'; budget.require_ms(budget.cutoff(75))
        require(snapshot()[2] == closure); phase = 'worker'; launched = True; v['recovery_required'] = True
        outer = launcher.launch_owned(api, [sys.executable, '-I', '-S', '-B', str(stage/'.github/windows_identity_dns_standard_local.py'),
            '--owned-worker', '--config', str(stage/'dns-standard-config.json')], guard, parent, parent,
            qpc_budget=budget, work_cutoff=budget.cutoff(3), cleanup_cutoff=budget.deadline)
        checks = v['checks']; checks.update(guard_atomic=api.atomic_job_requested is True,
            worker_held=outer.get('native_identity_verified_before_resume') is True,
            worker_exit=outer.get('cleanup', {}).get('process_exit_confirmed') is True, outer_cleanup=local.guest.cleanup_verified(outer))
        require(checks['worker_exit']); phase = 'report'
        report = local.guest.decode(local.bounded(stage/'dns-standard-worker-report.json', 128*1024))
        inventory, al = apply_report(v, report, c, outer, parent['sid'], budget.read())
        phase = 'inventory'; require(inventory is not None and inventory_safe(v['inventory']) and v1.launch_ok(inventory['launch']))
        phase = 'cleanup'; require(not v['recovery_required'] and all(checks.values()) and v1.launch_ok(outer) and v1.launch_ok(al) and report['failure'] is None)
        phase = 'mechanism'; r = v['api']; require(r is not None and r['answer_match'] and r['within_deadline'] and r['records_released']
            and not r['pending'] and v['owned_query_observed'] and v['fixture']['answers_sent'] > 0 and v['fixture']['error'] == 'none')
        budget.require_ms(budget.deadline); v.update(status='passed', mechanism_passed=True)
    except BaseException:
        v.update(failure=phase, status='inconclusive', mechanism_passed=False)
        if launched and not v['checks']['worker_report_bound']: v['recovery_required'] = True
    return validate(v)

def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-local-standard-mechanism', action='store_true'); p.add_argument('--approved-local-security-test', action='store_true')
    p.add_argument('--owned-worker', action='store_true', help=argparse.SUPPRESS); p.add_argument('--config', help=argparse.SUPPRESS)
    for name in ('actor', 'manifest', 'actor-sha256', 'manifest-sha256', 'work-parent', 'recovery-plan'): p.add_argument('--'+name)
    args = p.parse_args(argv)
    if args.owned_worker:
        try: return worker(args.config)
        except BaseException: return 1
    values = (args.actor, args.manifest, args.actor_sha256, args.manifest_sha256, args.work_parent, args.recovery_plan)
    result = run_local(*values, approved=args.approved_local_security_test) if args.run_local_standard_mechanism else preflight(*values)
    sys.stdout.write(encode(result).decode('ascii')); return 0 if result['status'] in ('ready', 'passed') else 1

if __name__ == '__main__': raise SystemExit(main())
