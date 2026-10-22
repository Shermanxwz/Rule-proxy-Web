"""Internal first C cell: real native HTTP chain and same-container direct deny.

Only the staged atomic outer guard may call this worker. No standalone runtime
CLI is supplied. Every observation is retained privately; public output is a
closed projection with original Stage 0 and product acceptance fixed false.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
import os
from pathlib import Path
import stat
from types import SimpleNamespace

_spec = importlib.util.spec_from_file_location('first_c_live', Path(__file__).with_name('windows_identity_model2_live.py'))
live = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live)
_mspec = importlib.util.spec_from_file_location('first_c_maintenance', Path(__file__).with_name('windows_identity_model2_maintenance.py'))
maintenance = importlib.util.module_from_spec(_mspec)
_mspec.loader.exec_module(maintenance)
launcher, ac, helpers = live.launcher, live.ac, live.helpers
ROOT = Path(__file__).resolve().parents[1]
FAILURES = (None, 'identity', 'capability', 'qpc', 'report', 'command', 'close', 'configuration', 'deadline')
IDENTITY_KEYS = {'schemaVersion', 'mode', 'nonce', 'pid', 'tokenUserSid', 'tokenIsAppContainer',
    'tokenAppContainerSid', 'tokenElevated', 'isProcessInJob', 'tokenCapabilities', 'queriesSucceeded', 'errors'}


def owned_tree(work, *, max_nodes=512, max_depth=16, max_bytes=live.local.MAX_STAGE):
    """C's larger staged closure, bounded before ACL mutation; no alias follow.

    The root counts as one node at depth zero. Pending children count against
    capacity before they are visited, and regular-file sizes share one bound.
    A/B retain their original small-tree helper and acceptance unchanged.
    """
    live.require(live.integer(max_nodes, 1, 512) and live.integer(max_depth, 0, 16)
        and live.integer(max_bytes, 0, live.local.MAX_STAGE), 'owned_tree_limits')
    work = launcher.checked_path(work, is_file=False)
    pending = [(work, 0)]
    result = []
    total = 0
    while pending:
        path, depth = pending.pop()
        info = path.lstat()
        live.require(depth <= max_depth and not stat.S_ISLNK(info.st_mode)
            and not getattr(info, 'st_file_attributes', 0) & 0x400, 'owned_tree_reparse_or_depth')
        live.require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'owned_tree_type')
        result.append(path)
        live.require(len(result) <= max_nodes, 'owned_tree_nodes')
        if stat.S_ISREG(info.st_mode):
            live.require(type(info.st_size) is int and info.st_size >= 0, 'owned_tree_size')
            total += info.st_size
            live.require(total <= max_bytes, 'owned_tree_bytes')
        else:
            with os.scandir(path) as entries:
                for entry in entries:
                    live.require(depth < max_depth, 'owned_tree_depth')
                    pending.append((Path(entry.path), depth + 1))
                    live.require(len(result) + len(pending) <= max_nodes, 'owned_tree_nodes')
    return result


def validate_config(value):
    keys = {'schema_version', 'stage', 'run', 'boot_case', 'positive_case', 'direct_case', 'health_cases',
        'admission_nonce', 'maintenance_nonce', 'capability_profile', 'start_qpc', 'frequency', 'deadline_qpc',
        'root_deadline_qpc', 'source_hashes', 'source_sha256', 'actor_sha256', 'manifest_sha256',
        'guard_job_name', 'device_sha256', 'recovery_plan_sha256'}
    mode = live.execution_mode(value)
    if mode != 'strict': keys.add('execution_mode')
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'model2-first-owned-input', 'config')
    live.clock_record(value['start_qpc'], value['frequency'], value['root_deadline_qpc'])
    live.require(value['deadline_qpc'] == value['root_deadline_qpc'] - 5 * value['frequency']
        and value['deadline_qpc'] > value['start_qpc'], 'config_clock')
    names = ('run', 'boot_case', 'positive_case', 'direct_case', 'admission_nonce', 'maintenance_nonce')
    live.require(all(ac.nonce(value[k]) for k in names) and type(value['health_cases']) is list
        and len(value['health_cases']) == 3 and all(ac.nonce(x) for x in value['health_cases']), 'config_nonce')
    nonces = [value[k] for k in names] + value['health_cases']
    live.require(len(nonces) == len(set(nonces)) and value['capability_profile'] == 'agentic-pncs', 'config_profile')
    live.require(value['guard_job_name'] == 'Local\\RuleProxy.LocalGuard.' + value['run'], 'config_job')
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256', 'device_sha256', 'recovery_plan_sha256'):
        live.require(ac.digest(value[key]), 'config_digest')
    live.require(type(value['source_hashes']) is dict and set(value['source_hashes']) == set(live.SOURCES)
        and all(ac.digest(x) for x in value['source_hashes'].values())
        and live.sha(live.encode(value['source_hashes'])) == value['source_sha256'], 'config_sources')
    return value


def qpc(value, frequency, start, deadline, *, lower=None):
    live.require(type(value) is list and len(value) == 4 and all(live.integer(x, 0, live.MAX_SIGNED) for x in value)
        and value[:3] == [frequency, start, deadline] and max(start, lower or 0) <= value[3] < deadline, 'native_clock')


def native_identity(value, task, run):
    live.require(type(value) is dict and set(value) == IDENTITY_KEYS and live.integer(value['schemaVersion'], 1, 1)
        and value['mode'] == 'actor' and value['nonce'] == run and type(value['pid']) is int and value['pid'] == task['pid']
        and value['tokenUserSid'] == task['identity']['sid'] and value['tokenElevated'] is False
        and value['tokenIsAppContainer'] is task['identity']['appcontainer']
        and value['tokenAppContainerSid'] == task['identity']['appcontainer_sid']
        and value['isProcessInJob'] is True and value['queriesSucceeded'] is True and value['errors'] == [], 'native_identity')
    entries, invalid, duplicates = live.proof.capability_entries(value['tokenCapabilities'])
    expected, e_invalid, e_duplicates = live.proof.capability_entries(task['capabilities'])
    live.require(entries is not None and expected is not None and not invalid and not duplicates
        and not e_invalid and not e_duplicates and sorted(entries) == sorted(expected), 'native_capabilities')


def ready_client(value, task, config, *, role, boot, admission, profile):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'qpc', 'admission_nonce', 'ready',
        'network_initialized', 'failure'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-client-ready' and value['role'] == role and value['run_id'] == config['run']
        and value['boot_case_id'] == boot and value['pid'] == task['pid'] and type(value['pid']) is int
        and value['capability_profile'] == profile and value['capability_profile_verified'] is True
        and value['catalog_cleanup_verified'] is True and value['admission_nonce'] == admission
        and value['ready'] is True and value['network_initialized'] is False and value['failure'] is None, 'client_ready')
    native_identity(value['identity'], task, config['run'])
    qpc(value['qpc'], config['frequency'], config['start_qpc'], config['deadline_qpc'])
    return value


def ready_listener(value, task, config, *, role, boot, profile, start=None, deadline=None):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'qpc', 'port', 'ready', 'network_initialized', 'failure'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-listener-ready' and value['role'] == role and value['run_id'] == config['run']
        and value['boot_case_id'] == boot and value['pid'] == task['pid'] and type(value['pid']) is int
        and value['capability_profile'] == profile and value['capability_profile_verified'] is True
        and value['catalog_cleanup_verified'] is True and value['ready'] is True
        and value['network_initialized'] is True and value['failure'] is None
        and live.integer(value['port'], 49153, 65535), 'listener_ready')
    native_identity(value['identity'], task, config['run'])
    qpc(value['qpc'], config['frequency'], config['start_qpc'] if start is None else start,
        config['deadline_qpc'] if deadline is None else deadline)
    return value


def client_phase(value, task, config, *, role, boot, admission, sequence, case, operation, target_port, phase_deadline):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'case_id', 'pid', 'sequence', 'operation',
        'target_port', 'admission_nonce', 'identity', 'root_qpc', 'phase_qpc', 'command_close_verified',
        'network', 'failure', 'proxy_tested', 'product_acceptance'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-client-phase' and value['role'] == role and value['run_id'] == config['run']
        and value['boot_case_id'] == boot and value['case_id'] == case and value['pid'] == task['pid']
        and type(value['pid']) is int and value['sequence'] == sequence and type(value['sequence']) is int
        and value['operation'] == operation and value['target_port'] == target_port and type(value['target_port']) is int
        and value['admission_nonce'] == admission and value['command_close_verified'] is True
        and value['failure'] in FAILURES and value['proxy_tested'] is False and value['product_acceptance'] is False, 'client_phase')
    native_identity(value['identity'], task, config['run'])
    live.require(type(value['root_qpc']) is list and value['root_qpc'] == [config['frequency'], config['start_qpc'], config['deadline_qpc']]
        and all(type(x) is int for x in value['root_qpc']), 'phase_root_clock')
    p = value['phase_qpc']
    live.require(type(p) is list and len(p) == 3 and all(live.integer(x, 0, live.MAX_SIGNED) for x in p)
        and config['start_qpc'] <= p[0] <= p[2] and p[1] == phase_deadline <= config['deadline_qpc'], 'phase_clock')
    validate_transport(value['network'], target_port, case, operation)
    return value


def transport_payload(case, port, operation):
    if operation == 'direct-tcp':
        return live.origin.payloads(case, port)
    return (('GET http://ruleproxy-identity-proof.invalid/' + case
        + ' HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n').encode('ascii'),
        live.origin.payloads(case, port)[1])


def validate_transport(value, port, case, operation):
    keys = {*live.origin.RELAY_BOOLS, 'port', 'local_port', 'peer_port', 'request_bytes', 'response_bytes',
        'socket_close', 'failure', 'wsa_error'}
    live.require(type(value) is dict and set(value) == keys and type(value['port']) is int and value['port'] == port
        and all(type(value[k]) is bool for k in live.origin.RELAY_BOOLS), 'transport_schema')
    request, response = transport_payload(case, port, operation)
    live.require(all(value[k] is None or live.integer(value[k], 1, 65535) for k in ('local_port', 'peer_port'))
        and live.integer(value['request_bytes'], 0, len(request)) and live.integer(value['response_bytes'], 0, 257)
        and value['socket_close'] in ('not_attempted', 'confirmed', 'uncertain')
        and value['failure'] in (None, 'setup', 'connect', 'io', 'response', 'deadline', 'close')
        and (value['wsa_error'] is None or live.integer(value['wsa_error'])), 'transport_values')
    live.require(not value['connect_completed'] or value['connect_attempted'] and value['socket_created'], 'transport_connect')
    live.require(not value['peer_loopback'] or value['connect_completed'] and value['peer_port'] == port, 'transport_peer')
    live.require(not value['request_complete'] or value['connect_completed'] and value['request_bytes'] == len(request), 'transport_request')
    live.require(not value['response_exact'] or value['response_bytes'] == len(response), 'transport_response')


def transport_passed(value, case, operation):
    request, response = transport_payload(case, value['port'], operation)
    return (all(value[k] for k in live.origin.RELAY_BOOLS) and value['socket_close'] == 'confirmed'
        and value['failure'] is None and value['wsa_error'] is None
        and value['request_bytes'] == len(request) and value['response_bytes'] == len(response)
        and value['peer_port'] == value['port'] and live.integer(value['local_port'], 1, 65535))


def phase_passed(value, case):
    return (value['failure'] is None and value['phase_qpc'][2] < value['phase_qpc'][1]
        and transport_passed(value['network'], case, value['operation']))


def client_final(value, task, config, *, role, boot, profile, count):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'qpc', 'phase_count', 'finished',
        'network_initialized_before_go', 'network_initialized', 'command_close_verified', 'failure', 'proxy_tested', 'product_acceptance'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-client-final' and value['role'] == role and value['run_id'] == config['run']
        and value['boot_case_id'] == boot and value['pid'] == task['pid'] and type(value['pid']) is int
        and value['capability_profile'] == profile and value['capability_profile_verified'] is True
        and value['catalog_cleanup_verified'] is True and value['phase_count'] == count and type(value['phase_count']) is int
        and value['finished'] is True and value['network_initialized_before_go'] is False
        and value['network_initialized'] is True and value['command_close_verified'] is True
        and value['failure'] is None and value['proxy_tested'] is False and value['product_acceptance'] is False, 'client_final')
    native_identity(value['identity'], task, config['run'])
    qpc(value['qpc'], config['frequency'], config['start_qpc'], config['deadline_qpc'])
    return value


def receipt(value, task, config, *, boot, port, index):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'case_id', 'pid', 'index', 'port', 'peer_port',
        'qpc', 'request_bytes', 'request_exact', 'request_eof', 'response_bytes', 'response_complete', 'send_shutdown',
        'connection_close', 'failure', 'wsa_error'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-listener-receipt' and value['role'] == 'health-origin'
        and value['run_id'] == config['run'] and value['boot_case_id'] == boot
        and value['pid'] == task['pid'] and type(value['pid']) is int and value['index'] == index
        and type(value['index']) is int and value['port'] == port and type(value['port']) is int
        and live.integer(value['peer_port'], 1, 65535) and (value['case_id'] is None or ac.nonce(value['case_id']))
        and all(type(value[k]) is bool for k in ('request_exact', 'request_eof', 'response_complete', 'send_shutdown'))
        and live.integer(value['request_bytes'], 0, 8449) and live.integer(value['response_bytes'], 0, 8192)
        and value['connection_close'] in ('not_attempted', 'confirmed', 'uncertain')
        and (value['failure'] is None or type(value['failure']) is str and value['failure'] in
            ('socket', 'bind', 'listen', 'accept', 'request', 'send', 'shutdown', 'close', 'report', 'deadline', 'identity', 'capability', 'qpc', 'command', 'configuration'))
        and (value['wsa_error'] is None or live.integer(value['wsa_error'])), 'receipt')
    q = value['qpc']
    live.require(type(q) is list and len(q) == 4 and all(live.integer(x, 0, live.MAX_SIGNED) for x in q)
        and q[0] == config['frequency'] and config['start_qpc'] <= q[1] <= q[3]
        and q[2] == config['deadline_qpc'], 'receipt_clock')
    return value


def receipt_passed(row):
    if row['case_id'] is None:
        return False
    request, response = live.origin.payloads(row['case_id'], row['port'])
    return (all(row[k] for k in ('request_exact', 'request_eof', 'response_complete', 'send_shutdown'))
        and row['request_bytes'] == len(request) and row['response_bytes'] == len(response)
        and row['connection_close'] == 'confirmed' and row['failure'] is None and row['wsa_error'] is None
        and row['qpc'][3] < row['qpc'][2])


def validate_relay(value, task, config, port, start, end):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'case_id', 'pid', 'ipc_mechanics', 'origin',
        'http_boundary', 'network_tested', 'proxy_tested', 'product_acceptance'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'bridge-origin-pipe-test' and value['role'] == 'pipe-relay'
        and value['run_id'] == config['run'] and value['case_id'] == config['positive_case']
        and type(value['pid']) is int and value['pid'] == task['pid']
        and value['http_boundary'] == live.origin.BOUNDARY and value['network_tested'] is True
        and value['proxy_tested'] is False and value['product_acceptance'] is False, 'relay_report')
    ac.validate_ac_native(value['ipc_mechanics'], role='pipe-relay', run_id=config['run'], case_id=config['positive_case'],
        pid=task['pid'], identity=task['identity'], frequency=config['frequency'], start=start, end=end, expected_ac_sid=None)
    live.require(ac.successful_native(value['ipc_mechanics']), 'relay_ipc')
    live.origin.validate_relay(value['origin'], port, config['positive_case'])
    live.require(live.origin.relay_passed(value['origin'], config['positive_case']), 'relay_transport')


def validate_front(value, task, config, proxy_port, origin_port, start, end):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'ipc_mechanics', 'listener', 'client',
        'wsa_startup', 'wsa_cleanup', 'failure', 'wsa_error', 'http_boundary', 'network_tested', 'proxy_tested', 'product_acceptance'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-live-front' and value['role'] == 'pipe-live-front'
        and value['run_id'] == config['run'] and value['case_id'] == config['positive_case']
        and type(value['pid']) is int and value['pid'] == task['pid'] and value['capability_profile'] == 'pncs'
        and value['capability_profile_verified'] is True and value['catalog_cleanup_verified'] is True
        and value['wsa_startup'] is True and value['wsa_cleanup'] is True and value['failure'] is None
        and value['wsa_error'] is None and value['http_boundary'] == 'real-client-request-and-response-socket'
        and value['network_tested'] is True and value['proxy_tested'] is False and value['product_acceptance'] is False, 'front_report')
    native_identity(value['identity'], task, config['run'])
    listener = value['listener']
    listener_keys = {'port', 'listener_created', 'inheritance_cleared', 'exclusive', 'bind_loopback', 'accepted',
        'peer_loopback', 'peer_port', 'listener_close'}
    live.require(type(listener) is dict and set(listener) == listener_keys and type(listener['port']) is int
        and listener['port'] == proxy_port and live.integer(listener['peer_port'], 1, 65535)
        and all(listener[k] is True for k in listener_keys - {'port', 'peer_port', 'listener_close'})
        and listener['listener_close'] == 'confirmed', 'front_listener')
    client = value['client']
    client_keys = {'request_bytes', 'request_exact', 'request_eof', 'response_bytes', 'response_complete', 'send_shutdown', 'connection_close'}
    request, response = transport_payload(config['positive_case'], proxy_port, 'proxy-get')
    live.require(type(client) is dict and set(client) == client_keys
        and type(client['request_bytes']) is int and client['request_bytes'] == len(request)
        and type(client['response_bytes']) is int and client['response_bytes'] == len(response)
        and all(client[k] is True for k in ('request_exact', 'request_eof', 'response_complete', 'send_shutdown'))
        and client['connection_close'] == 'confirmed', 'front_client')
    # C validates the shared mechanical shape with the actual PNCS identity.
    # It does not alter/project the old zero-capability A acceptance record.
    m = value['ipc_mechanics']
    mk = {'schema_version', 'stage', 'role', 'run_id', 'case_id', 'pid', 'identity', 'qpc', 'pipe', 'core',
        'synthetic_http', 'failure', 'win32_error', 'network_tested', 'proxy_tested', 'product_acceptance'}
    live.require(type(m) is dict and set(m) == mk and live.integer(m['schema_version'], 1, 1)
        and m['stage'] == 'bridge-pipe-test' and m['role'] == 'pipe-front' and m['run_id'] == config['run']
        and m['case_id'] == config['positive_case'] and type(m['pid']) is int and m['pid'] == task['pid']
        and m['failure'] is None and m['win32_error'] is None
        and all(m[k] is False for k in ('network_tested', 'proxy_tested', 'product_acceptance')), 'front_ipc')
    native_identity(m['identity'], task, config['run'])
    qpc(m['qpc'], config['frequency'], start, end)
    p = m['pipe']
    pk = {'read_bytes', 'write_bytes', 'read_frames', 'write_frames', 'inheritance_cleared', 'eof_observed',
        'reader_close', 'writer_close', 'requires_controller_timeout'}
    live.require(type(p) is dict and set(p) == pk and p['read_bytes'] == 96 and type(p['read_bytes']) is int
        and p['write_bytes'] == 144 and type(p['write_bytes']) is int
        and p['read_frames'] == 2 and type(p['read_frames']) is int
        and p['write_frames'] == 3 and type(p['write_frames']) is int
        and p['inheritance_cleared'] is True and p['eof_observed'] is True
        and p['reader_close'] == 'confirmed' and p['writer_close'] == 'confirmed'
        and p['requires_controller_timeout'] is True, 'front_ipc_pipe')
    core = m['core']
    live.require(type(core) is dict and set(core) == {'failure', 'observations', 'requested', 'confirmed', 'uncertain'}
        and all(type(x) is int for x in core.values()) and core == dict(failure=0, observations=177, requested=7, confirmed=7, uncertain=0), 'front_core')
    live.require(type(m['synthetic_http']) is dict and set(m['synthetic_http']) == {'request_checked', 'response_checked', 'client_sink_checked'}
        and all(x is True for x in m['synthetic_http'].values()), 'front_ipc_http')


def listener_final(value, task, config, *, boot, port, receipt_count):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'qpc', 'port', 'accepted_count', 'receipt_count',
        'finished', 'listener_close', 'wsa_startup', 'wsa_cleanup', 'command_close_verified', 'failure', 'wsa_error'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-listener-final' and value['role'] == 'health-origin'
        and value['run_id'] == config['run'] and value['boot_case_id'] == boot and value['pid'] == task['pid']
        and type(value['pid']) is int and value['capability_profile'] == 'ordinary'
        and value['capability_profile_verified'] is True and value['catalog_cleanup_verified'] is True
        and value['port'] == port and type(value['port']) is int
        and value['accepted_count'] == receipt_count and type(value['accepted_count']) is int
        and value['receipt_count'] == receipt_count and type(value['receipt_count']) is int
        and value['finished'] is True and value['listener_close'] == 'confirmed' and value['wsa_startup'] is True
        and value['wsa_cleanup'] is True and value['command_close_verified'] is True
        and value['failure'] is None and value['wsa_error'] is None, 'listener_final')
    native_identity(value['identity'], task, config['run'])
    qpc(value['qpc'], config['frequency'], config['start_qpc'], config['deadline_qpc'])


def read_when_closed(api, budget, path, process, cutoff):
    while True:
        budget.require_ms(cutoff)
        if path.exists():
            try:
                raw = live.local.bounded(path, live.MAX_NATIVE)
                return live.decode(raw), raw
            except OSError as exc:
                if getattr(exc, 'winerror', None) != 32:
                    raise
        if process is not None and api.wait(process, 0):
            # Normal publish-before-exit can race the first existence check.
            live.require(path.exists(), 'native_exited_without_report')
            raw = live.local.bounded(path, live.MAX_NATIVE)
            return live.decode(raw), raw
        api.sleep_ms(budget.require_ms(cutoff, 10))


class MaintenanceRules:
    """Consume one combined create/remove readback, never retain a stale cache."""
    def __init__(self, owner):
        self.owner = owner
        self.readback = {}

    def rule_read(self, name, store):
        key = name, store
        if key in self.readback:
            return self.readback.pop(key)
        return self.owner.operation('read-persistent' if store == 'PersistentStore' else 'read-active', name)

    def rule_create(self, rule):
        result = self.owner.operation('create', rule['name'])
        live.validate_rule(result, rule)
        self.readback.update({(rule['name'], store): result for store in ('PersistentStore', 'ActiveStore')})

    def rule_remove(self, rule):
        live.require(self.owner.operation('remove', rule['name']) is None, 'remove_readback')
        self.readback.update({(rule['name'], store): None for store in ('PersistentStore', 'ActiveStore')})


class FirstController:
    def __init__(self, config, root, api):
        self.config, self.root, self.api = validate_config(config), root, api
        self.budget = launcher.QpcBudget(api, config['deadline_qpc'], config['frequency'])
        self.owners = helpers.OneShotHandles(api.close)
        self.scoped_owners = []
        self.maintenance_owners = helpers.OneShotHandles(api.close)
        self.children = []
        self.tasks = {}
        self.job = None
        self.maintenance_job = None
        self.maintenance = None
        self.rule_owner = None
        self.rules = None
        self.profile = dict(attempted=False, returned=False, created=False, pointer=None, sid=None)
        self.acl_attempted = False
        self.acl_removed = False
        self.cleanup_ok = False
        self.mode = live.execution_mode(config)
        self.value = live.blank(self.mode)
        self.parent = None
        self.catalog = None
        self.phase = 'inputs'
        self.fixed_ports = None
        self.origin_boot = None
        self.direct_deadline = None
        self.go_records = []
        self.selected_discovery = None
        self.profile_deleted = False
        self.cleanup_ledger = {key: False for key in ('workload_cleanup_confirmed', 'workload_job_empty',
            'all_workloads_exited', 'maintenance_cleanup_confirmed', 'maintenance_handles_closed',
            'acl_removed', 'profile_deleted', 'sid_released', 'cleanup')}

    def directory(self, name, *, protected=False):
        path = self.root / name
        live.require(not path.exists(), 'fresh_directory')
        if protected:
            self.api.private_directory(path, self.parent['sid'])
        else:
            path.mkdir()
        return path

    def task(self, name, argv, work, *, profile=None, handles=None, environment=None, image_hash=None, cleanup=False):
        reserve = 3 if cleanup else 25
        self.budget.require_ms(self.budget.cutoff(reserve))
        api = self.api
        info = api.process_info()
        row = dict(info=info, attempted=False, assigned=False, exited=False, exit_code=None, pid=None,
            created=None, identity=None, capabilities=None, image_verified=False, resumed=False, work=work,
            command=list(argv), image_path=str(argv[0]), image_sha256=image_hash,
            admission_qpc=None, resume_qpc=None, cleanup_role=cleanup,
            externally_held_before_first_resume=True, externally_held_before_network_go=True)
        self.children.append(row)
        self.tasks[name] = row
        if image_hash is None:
            image_hash = self.config['actor_sha256']
        row['image_sha256'] = image_hash
        image = launcher.checked_path(argv[0])
        live.require(live.sha(live.local.bounded(image, 8 * 1024 * 1024)) == image_hash, 'task_image')
        stdio = []
        stdio_owners = helpers.OneShotHandles(api.close)
        self.scoped_owners.append(stdio_owners)
        state = dict(creation_attempted=False)
        try:
            if profile is not None:
                self.api.pncs_create(info, argv, work, [] if handles is None else handles, self.owners,
                    state, self.profile['pointer'], environment)
            elif handles is not None:
                self.api.owned_create(info, argv, work, handles, self.owners, state)
            else:
                if not (work / 'temp').exists():
                    (work / 'temp').mkdir()
                for label in ('stdin', 'stdout', 'stderr'):
                    h = api.open_stdio_file(work / label, read=label == 'stdin')
                    stdio_owners.add(h)
                    stdio.append(h)
                row['attempted'] = True
                try:
                    api.create_with_environment(info, argv, work, stdio,
                        api.native.environment(work) if environment is None else environment)
                finally:
                    if info.hProcess:
                        self.owners.add(info.hProcess)
                    if info.hThread:
                        self.owners.add(info.hThread)
        finally:
            row['attempted'] = row['attempted'] or state['creation_attempted']
            for h in stdio:
                stdio_owners.close(h)
        live.require(bool(info.hProcess) and bool(info.hThread), 'task_partial_create')
        row['pid'], row['created'] = int(info.dwProcessId), api.creation_time(info.hProcess)
        api.assign_job(self.job, info.hProcess)
        row['assigned'] = True
        api.verify_job(self.job, info.hProcess)
        api.verify_image(info.hProcess, image)
        live.require(live.sha(live.local.bounded(image, 8 * 1024 * 1024)) == image_hash, 'task_image')
        row['image_verified'] = True
        token = api.token_for_process(info.hProcess)
        self.owners.add(token)
        row['identity'] = api.identity(token)
        row['capabilities'] = [{'sid': sid, 'attributes': attr} for sid, attr in api.groups(token, 30, 'TokenCapabilities')]
        if profile is not None:
            live.frontend_identity(row['identity'], row['capabilities'], self.parent, profile, self.catalog)
        else:
            live.require(launcher.token_is_ordinary(row['identity']) and launcher.same_identity(row['identity'], self.parent)
                and row['capabilities'] == [], 'ordinary_task')
        row['admission_qpc'] = self.budget.read()
        return row

    def resume(self, row):
        self.budget.require_ms(self.budget.cutoff(25))
        live.require(not row['resumed'] and row['assigned'] and row['image_verified'], 'task_resume')
        self.api.resume(row['info'].hThread)
        row['resumed'] = True
        row['resume_qpc'] = self.budget.read()

    def wait(self, row, end, *, code=0):
        row['exited'] = self.api.wait(row['info'].hProcess, self.budget.require_ms(end)) is True
        if row['exited']:
            row['exit_code'] = self.api.exit_code(row['info'].hProcess)
        self.budget.require_ms(end)
        live.require(row['exited'] and (code is None or row['exit_code'] == code), 'task_exit')

    def alive(self, row):
        self.budget.require_ms(self.budget.cutoff(20))
        live.require(not self.api.wait(row['info'].hProcess, 0)
            and self.api.creation_time(row['info'].hProcess) == row['created'], 'held_generation')
        self.api.verify_job(self.job, row['info'].hProcess)

    def tool(self, argv, label, *, cleanup=False):
        work = self.directory('tools/' + label)
        row = self.task(label, argv, work, image_hash=live.sha(live.local.bounded(launcher.checked_path(argv[0]), 8 * 1024 * 1024)), cleanup=cleanup)
        # Same constructor and held token for tool processes; no Popen/system shell.
        if cleanup:
            self.budget.require_ms(self.budget.cutoff(5))
            self.api.resume(row['info'].hThread)
            row['resumed'] = True
            row['resume_qpc'] = self.budget.read()
            self.wait(row, self.budget.cutoff(3))
        else:
            self.resume(row)
            self.wait(row, self.budget.cutoff(25))

    def fixed_icacls(self):
        block = self.api.native.environment(self.root)
        env = dict(x.split('=', 1) for x in block.rstrip('\0').split('\0'))
        return launcher.checked_path(Path(env['SystemRoot']) / 'System32/icacls.exe')

    def grant(self, sid):
        owned_tree(self.root)
        self.acl_attempted = True
        image = str(self.fixed_icacls())
        for name, path, access in (('root', self.root, 'RX'), ('inputs', self.root / 'inputs', '(OI)(CI)(RX)'),
                                  ('front', self.root / 'front', '(OI)(CI)(M)')):
            owned_tree(self.root)
            self.tool([image, str(path), '/grant', '*' + sid + ':' + access, '/Q'], 'acl-' + name)
        for path in owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(30))
            expected = ([(0, 0x1200a9)] if path == self.root else [(3, 0x1200a9)] if path == self.root / 'inputs'
                else [(3, 0x1301bf)] if path == self.root / 'front'
                else [(16, 0x1200a9)] if path.parent == self.root / 'inputs'
                else [(16, 0x1301bf)] if self.root / 'front' in path.parents else [])
            live.require(self.api.acl_read(path, sid) == expected, 'acl_scope')

    def g_task(self, name, request, *, actual=False):
        work = self.directory(name, protected=True)
        self.api.private_directory(work / 'temp', self.parent['sid'])
        self.api.private_directory(work / 'dacl-state', self.parent['sid'])
        base = dict(x.split('=', 1) for x in self.api.native.environment(work).rstrip('\0').split('\0'))
        env = live.probe.child_environment(base, work, work / 'dacl-state')
        self.api.verify_private_directory(work / 'dacl-state',
            'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + self.parent['sid'] + ')')
        live.require(not list((work / 'dacl-state').iterdir()), 'fresh_reaper')
        exe = self.root / 'runtime/wxc-exec.exe'
        live.probe.verify_artifacts(self.root / 'bundle.zip', self.root / 'runtime')
        argv = [str(exe), '--config', str(request)] if actual else [str(exe), '--probe', '--config', str(request)]
        row = self.task(name, argv, work, environment=self.api.proc._environment_block(env), image_hash=live.probe.pins.MXC_G_EXECUTOR_SHA256)
        live.require(not list((work / 'dacl-state').iterdir()), 'reaper_changed_before_resume')
        self.resume(row)
        return row

    def native_phase(self, task, *, role, boot, admission, sequence, case, opcode, control, reports, fixed_ports, end):
        self.alive(task)
        if self.mode != 'strict' and role == 'selected-client':
            maintenance.validate_profiles_observation(self.maintenance.last_observation, 'profiles-status', self.mode,
                self.config['start_qpc'], self.config['frequency'], self.config['deadline_qpc'], self.budget.read())
        digest = live.publish_go(control, budget=self.budget, run=self.config['run'], case=case, sequence=sequence,
            opcode=opcode, frequency=self.config['frequency'], deadline=self.config['deadline_qpc'],
            fixed_ports=fixed_ports, admission=admission, phase_deadline=end)
        self.go_records.append(dict(role=role, sequence=sequence, opcode=opcode, case=case,
            phase_deadline=end, path=(control / ('phase-%04d.bin' % sequence)).relative_to(self.root).as_posix(), sha256=digest))
        # Collect a bounded late failure record without extending network work.
        collect_end = min(end + self.config['frequency'], self.budget.cutoff(20))
        value, _ = read_when_closed(self.api, self.budget, reports / ('phase-%04d.json' % sequence), task['info'].hProcess, collect_end)
        target = fixed_ports['origin' if opcode == 2 else 'wrong_port' if opcode == 3 else 'proxy']
        return client_phase(value, task, self.config, role=role, boot=boot, admission=admission,
            sequence=sequence, case=case, operation=live.OPS[opcode], target_port=target, phase_deadline=end)

    def finish_client(self, task, *, role, boot, admission, sequence, profile, control, reports, fixed_ports, count):
        self.alive(task)
        end = self.budget.cutoff(30)
        digest = live.publish_go(control, budget=self.budget, run=self.config['run'], case=boot, sequence=sequence, opcode=255,
            frequency=self.config['frequency'], deadline=self.config['deadline_qpc'], fixed_ports=fixed_ports,
            admission=admission, phase_deadline=end)
        self.go_records.append(dict(role=role, sequence=sequence, opcode=255, case=boot,
            phase_deadline=end, path=(control / ('phase-%04d.bin' % sequence)).relative_to(self.root).as_posix(), sha256=digest))
        self.wait(task, end)
        observed = live.decode(live.local.bounded(reports / 'final.json', live.MAX_NATIVE))
        client_final(observed, task, self.config, role=role, boot=boot, profile=profile, count=count)

    def run(self):
        c, root, api, budget, v = self.config, self.root, self.api, self.budget, self.value
        self.parent = api.identity_owned(self.owners)
        live.require(launcher.token_is_ordinary(self.parent) and api.compartment() == 1, 'ordinary_controller')
        self.catalog = api.catalog()
        v['checks']['ordinary'] = True
        _, hashes, source_hash = live.source_snapshot(root)
        live.require(hashes == c['source_hashes'] and source_hash == c['source_sha256'], 'controller_sources')
        v.update(source_sha256=source_hash, actor_sha256=c['actor_sha256'], manifest_sha256=c['manifest_sha256'], run_sha256=live.sha(c['run'].encode()))
        v['checks']['sources'] = True
        exe = live.verify_actor(root / 'inputs' / live.ACTOR, root / 'inputs' / live.MANIFEST,
            c['actor_sha256'], c['manifest_sha256'], root=root)
        live.probe.verify_artifacts(root / 'bundle.zip', root / 'runtime')
        v['checks']['artifacts'] = True
        self.job = api.owned_job(self.owners)
        for name in ('tools', 'front', 'origin', 'origin-control', 'health', 'health-control', 'selected', 'selected-control', 'maintenance'):
            self.directory(name)
        profile_name = 'RuleProxy.Model2.A.' + c['run']
        self.phase = 'identity'
        sid = api.create_profile(profile_name, self.profile)
        live.require(self.profile['created'] and sid == api.derive_profile_sid(profile_name), 'profile_binding')
        metadata = launcher.default_child_environment()
        folder = api.local_appdata(budget, metadata)
        front_environment = api.front_environment(folder, metadata)
        live.require(launcher.child_environment_admitted(metadata), 'front_environment')

        # The ordinary origin stays alive through all selected phases and controls.
        self.phase = 'health'
        origin_boot = c['health_cases'][0]
        self.origin_boot = origin_boot
        origin_argv = [str(exe), 'health-origin', c['run'], origin_boot, str(root / 'origin/final.json'),
            str(root / 'origin/ready.json'), str(root / 'origin-control'), str(c['frequency']), str(c['start_qpc']),
            str(c['deadline_qpc']), '0', self.parent['sid'], 'none', '8']
        origin_task = self.task('origin', origin_argv, root / 'origin')
        self.resume(origin_task)
        observed, _ = read_when_closed(api, budget, root / 'origin/ready.json', origin_task['info'].hProcess, budget.cutoff(40))
        ready_listener(observed, origin_task, c, role='health-origin', boot=origin_boot, profile='ordinary')
        origin_port = observed['port']
        p = 49153 + int(c['run'][:8], 16) % 16383
        if p == origin_port:
            p = 49153 if p == 65535 else p + 1
        q = 49153 if p == 65535 else p + 1
        if q == origin_port:
            q = 49153 if q == 65535 else q + 1
        fixed = live.ports(dict(proxy=p, wrong_port=q, origin=origin_port))
        self.fixed_ports = fixed
        health_boot = c['admission_nonce']
        health_admission = c['maintenance_nonce']
        health_argv = live.selected_command(exe, 'health-client', c['run'], health_boot, root / 'health/ready.json',
            root / 'health', root / 'health-control', c['start_qpc'], c['frequency'], c['deadline_qpc'],
            fixed, self.parent['sid'], 'ordinary', health_admission)
        health_task = self.task('health', health_argv, root / 'health')
        self.resume(health_task)
        observed, _ = read_when_closed(api, budget, root / 'health/ready.json', health_task['info'].hProcess, budget.cutoff(40))
        ready_client(observed, health_task, c, role='health-client', boot=health_boot, admission=health_admission, profile='ordinary')
        phase = self.native_phase(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=1, case=c['health_cases'][0], opcode=2, control=root / 'health-control', reports=root / 'health',
            fixed_ports=fixed, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(40)))
        live.require(phase_passed(phase, c['health_cases'][0]), 'origin_before_health')

        self.phase = 'firewall'
        maintain_api = live.local.LocalNativeAPI()
        maintain_api.worker_job_name = 'Local\\RuleProxy.LocalGuard.' + c['maintenance_nonce']
        maintain_api.worker_sid = self.parent['sid']
        self.maintenance_job = maintain_api.create_job()
        self.maintenance_owners.add(self.maintenance_job)
        rule = live.firewall_rule(c['run'], 'A-P', sid, exe, p)
        plan = dict(schema_version=1, stage='model2-maintenance-plan', run=c['run'], maintenance_nonce=c['maintenance_nonce'],
            source_hashes=c['source_hashes'], source_sha256=c['source_sha256'], parent_sid=self.parent['sid'],
            parent_session=self.parent['session_id'], start_qpc=c['start_qpc'], frequency=c['frequency'],
            deadline_qpc=c['deadline_qpc'], rules=[rule], actor_sha256=c['actor_sha256'])
        if self.mode != 'strict': plan['execution_mode'] = self.mode
        launcher.write_private_bytes(root / 'maintenance-plan.json', live.encode(plan))
        self.maintenance = maintenance.MaintenanceOwner(api, budget, root, plan, self.maintenance_job, self.maintenance_owners)
        self.maintenance.start()
        # Bootstrap verifies the original protected root DACL before any AC ACE
        # is added. The later exact root RX ACE is non-inheritable; maintenance
        # sources and command directories remain inaccessible to the frontend.
        self.grant(sid)
        self.rules = MaintenanceRules(self.maintenance)
        self.rule_owner = live.RuleOwnership(rule)
        def journal(row):
            launcher.write_private_bytes(root / ('rule-' + row['state'] + '.json'), live.encode(row))
        self.rule_owner.create(self.rules, budget, journal)
        if self.mode == 'strict':
            v['checks']['firewall_exact'] = True
        else:
            observed = self.maintenance.last_observation
            v['diagnostic'].update(profiles_off_verified=observed['profiles_off_verified'],
                exact_rule_scope_verified=True, effective_full_verified=observed['effective_full_verified'])

        # A single fixed pair window bounds native front/relay handshake and flow.
        self.phase = 'positive'
        pair_start = budget.read()
        pair_end = pair_start + 10 * c['frequency']
        live.require(pair_end < budget.cutoff(35), 'pair_capacity')
        pipe_owners = helpers.OneShotHandles(api.close)
        self.scoped_owners.append(pipe_owners)
        front_read, relay_write = api.owned_pipe(pipe_owners)
        relay_read, front_write = api.owned_pipe(pipe_owners)
        front_argv = [str(exe), 'pipe-live-front', c['run'], c['positive_case'], str(root / 'front/final.json'),
            str(front_read), str(front_write), str(pair_start), str(c['frequency']), str(pair_end), self.parent['sid'], sid,
            '0', str(origin_port), str(p), str(root / 'front/ready.json'), str(root / 'selected-control')]
        relay_work = self.directory('relay')
        relay_argv = [str(exe), 'pipe-relay', c['run'], c['positive_case'], str(relay_work / 'final.json'),
            str(relay_read), str(relay_write), str(pair_start), str(c['frequency']), str(pair_end), self.parent['sid'], 'none', '0', str(origin_port)]
        front = self.task('front', front_argv, root / 'front', profile=sid, handles=[front_read, front_write], environment=front_environment)
        relay = self.task('relay', relay_argv, relay_work, handles=[relay_read, relay_write])
        for h in (front_read, relay_write, relay_read, front_write):
            pipe_owners.close(h)
        self.resume(front)
        self.resume(relay)
        observed, _ = read_when_closed(api, budget, root / 'front/ready.json', front['info'].hProcess, pair_end)
        ready_listener(observed, front, c, role='pipe-live-front', boot=c['positive_case'], profile='pncs', start=pair_start, deadline=pair_end)
        live.require(observed['port'] == p, 'front_listener_port')
        peer = dict(profile=profile_name, derived_sid=sid, held_sid=front['identity']['appcontainer_sid'], held=True, listener_port=p)
        argv = live.selected_command(exe, 'selected-client', c['run'], c['boot_case'], root / 'selected/ready.json',
            root / 'selected', root / 'selected-control', c['start_qpc'], c['frequency'], c['deadline_qpc'],
            fixed, self.parent['sid'], 'agentic-pncs', c['admission_nonce'])
        request = live.request_document(run=c['run'], command=argv, cwd=root / 'selected', inputs=root / 'inputs',
            control=root / 'selected-control', reports=root / 'selected', native_environment=
            ['SystemRoot=' + dict(x.split('=', 1) for x in api.native.environment(root).rstrip('\0').split('\0'))['SystemRoot'],
             'WINDIR=' + dict(x.split('=', 1) for x in api.native.environment(root).rstrip('\0').split('\0'))['WINDIR'],
             'LOCALAPPDATA=' + str(folder)],
            peer=peer, fixed_ports=fixed, timeout_ms=min(120000, (c['deadline_qpc'] - c['start_qpc']) * 1000 // c['frequency']))
        request_path = root / 'live-request.json'
        request_raw = live.encode(request)
        launcher.write_private_bytes(request_path, request_raw)
        self.phase = 'probe'
        gp = self.g_task('g-probe', request_path)
        self.wait(gp, pair_end)
        live.require(not live.local.bounded(gp['work'] / 'stderr', live.MAX_NATIVE), 'probe_stderr')
        diagnostic = live.probe.projection(live.local.bounded(gp['work'] / 'stdout', live.probe.MAX_OUTPUT))
        live.require(diagnostic == dict(tier='base-container', needs_dacl_augmentation=False, warning_count=0,
            detector_error_present=False, base_container_api_present=True, bfs_compiled_in=False), 'live_probe')
        live.require(not list((gp['work'] / 'dacl-state').iterdir()), 'probe_reaper_changed')
        v['checks']['live_probe'] = True
        self.alive(front)
        self.alive(relay)
        live.require(live.local.bounded(request_path, live.MAX_PRIVATE) == request_raw, 'request_changed')
        self.phase = 'selected'
        g = self.g_task('g-live', request_path, actual=True)
        observed, _ = read_when_closed(api, budget, root / 'selected/ready.json', g['info'].hProcess, pair_end)
        held = live.admit_selected(api, self.owners, budget, g_process=g['info'].hProcess, g_created=g['created'],
            job=self.job, image=exe, image_hash=c['actor_sha256'], parent=self.parent, capability_profile='agentic-pncs', catalog=self.catalog)
        live.verify_exact_guard_member(api, held['handle'], c['guard_job_name'])
        held['discovery'].update(workload_job_verified=True, outer_job_verified=True, outer_query_handle_closed=True)
        selected = dict(info=SimpleNamespace(hProcess=held['handle'], hThread=None), attempted=True, assigned=True,
            exited=False, exit_code=None, pid=held['pid'], created=held['created'], identity=held['identity'],
            capabilities=held['capabilities'], image_verified=True, resumed=True, work=root / 'selected',
            command=list(argv), image_path=str(exe), image_sha256=c['actor_sha256'], admission_qpc=budget.read(),
            resume_qpc=None, cleanup_role=False, externally_held_before_first_resume=False,
            externally_held_before_network_go=True)
        self.selected_discovery = held['discovery']
        self.children.append(selected)
        self.tasks['selected'] = selected
        ready_client(observed, selected, c, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], profile='agentic-pncs')
        v['checks'].update(selected_held=True, declared_caps=True)
        self.alive(origin_task)
        self.phase = 'positive'
        self.refresh_profiles()
        positive = self.native_phase(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'],
            sequence=1, case=c['positive_case'], opcode=1, control=root / 'selected-control', reports=root / 'selected',
            fixed_ports=fixed, end=pair_end)
        v['observations']['selected_network_attempted'] = positive['network']['connect_attempted']
        live.require(phase_passed(positive, c['positive_case']), 'positive_client')
        self.wait(front, pair_end)
        self.wait(relay, pair_end)
        # Both actual legs are read after held exits; native reports cannot supply ownership.
        front_report = live.decode(live.local.bounded(root / 'front/final.json', live.MAX_NATIVE))
        relay_report = live.decode(live.local.bounded(relay_work / 'final.json', live.MAX_NATIVE))
        validate_front(front_report, front, c, p, origin_port, pair_start, pair_end)
        validate_relay(relay_report, relay, c, origin_port, pair_start, pair_end)
        live.require(front_report['listener']['peer_port'] == positive['network']['local_port'], 'client_front_tuple')
        v['observations']['real_http_accepted'] = front_report['listener']['accepted']
        origin_positive, _ = read_when_closed(api, budget, root / 'origin/receipt-0002.json', origin_task['info'].hProcess, budget.cutoff(35))
        origin_positive = receipt(origin_positive, origin_task, c, boot=origin_boot, port=origin_port, index=2)
        live.require(origin_positive['case_id'] == c['positive_case'] and receipt_passed(origin_positive)
            and origin_positive['peer_port'] == relay_report['origin']['local_port'], 'relay_origin_tuple')
        v['observations']['origin_nonce_received'] = True
        v['checks']['positive'] = True
        if self.mode != 'strict': v['diagnostic']['positive_verified'] = True

        self.phase = 'health'
        self.alive(g)
        self.alive(selected)
        self.alive(origin_task)
        during = self.native_phase(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=2, case=c['health_cases'][1], opcode=2, control=root / 'health-control', reports=root / 'health',
            fixed_ports=fixed, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(35)))
        live.require(phase_passed(during, c['health_cases'][1]), 'origin_during_health')
        self.phase = 'selected'
        self.refresh_profiles()
        self.direct_deadline = min(budget.read() + 3 * c['frequency'], budget.cutoff(35))
        direct = self.native_phase(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'],
            sequence=2, case=c['direct_case'], opcode=2, control=root / 'selected-control', reports=root / 'selected',
            fixed_ports=fixed, end=self.direct_deadline)
        v['violations']['direct_connected'] = direct['network']['connect_completed']
        v['checks']['direct_deny'] = (direct['failure'] is None and direct['phase_qpc'][2] < direct['phase_qpc'][1]
            and all(direct['network'][key] for key in ('wsa_startup', 'inheritance_cleared', 'socket_created', 'connect_attempted'))
            and not direct['network']['connect_completed'] and direct['network']['failure'] == 'connect'
            and direct['network']['wsa_error'] == 10013 and direct['network']['socket_close'] == 'confirmed'
            and direct['network']['wsa_cleanup'] is True)
        if self.mode != 'strict':
            v['diagnostic'].update(direct_attempted=direct['network']['connect_attempted'],
                direct_connected=direct['network']['connect_completed'], direct_denied_by_access=v['checks']['direct_deny'])
            live.require(direct['failure'] is None and direct['phase_qpc'][2] < direct['phase_qpc'][1]
                and all(direct['network'][key] for key in ('wsa_startup','inheritance_cleared','socket_created','connect_attempted','wsa_cleanup'))
                and direct['network']['socket_close'] == 'confirmed', 'direct_observation')
        self.alive(g)
        self.alive(selected)
        v['checks']['same_selected'] = True
        self.finish_client(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'],
            sequence=3, profile='agentic-pncs', control=root / 'selected-control', reports=root / 'selected', fixed_ports=fixed, count=2)
        self.wait(g, budget.cutoff(30))
        live.require(not list((g['work'] / 'dacl-state').iterdir()), 'actual_reaper_changed')
        actual = live.local.bounded(g['work'] / 'stdout', live.MAX_PRIVATE) + b'\n' + live.local.bounded(g['work'] / 'stderr', live.MAX_PRIVATE)
        live.require(live.proof.actual_tiers(actual) == ['base-container'], 'actual_tier')

        self.phase = 'health'
        self.alive(origin_task)
        after = self.native_phase(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=3, case=c['health_cases'][2], opcode=2, control=root / 'health-control', reports=root / 'health',
            fixed_ports=fixed, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(30)))
        live.require(phase_passed(after, c['health_cases'][2]), 'origin_after_health')
        self.finish_client(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=4, profile='ordinary', control=root / 'health-control', reports=root / 'health', fixed_ports=fixed, count=3)
        digest = live.publish_fixture_finish(root / 'origin-control', budget=budget, run=c['run'], boot_case=origin_boot)
        self.go_records.append(dict(role='health-origin', sequence=1, opcode=255, case=origin_boot,
            phase_deadline=c['deadline_qpc'], path='origin-control/finish.bin', sha256=digest))
        self.wait(origin_task, budget.cutoff(25))
        observed_cases = []
        for index in range(1, 9):
            path = root / ('origin/receipt-%04d.json' % index)
            if not path.exists():
                break
            item = receipt(live.decode(live.local.bounded(path, live.MAX_NATIVE)), origin_task, c, boot=origin_boot, port=origin_port, index=index)
            if item['case_id'] == c['direct_case']:
                v['violations']['forbidden_receiver_accepted'] = True
            if self.mode == 'strict' or item['case_id'] != c['direct_case']:
                live.require(receipt_passed(item), 'origin_receipt')
            observed_cases.append(item['case_id'])
        expected_cases = [c['health_cases'][0], c['positive_case'], c['health_cases'][1], c['health_cases'][2]]
        if self.mode != 'strict' and c['direct_case'] in observed_cases:
            expected_cases.insert(3, c['direct_case'])
        live.require(observed_cases == expected_cases, 'origin_case_binding')
        listener_final(live.decode(live.local.bounded(root / 'origin/final.json', live.MAX_NATIVE)), origin_task, c,
            boot=origin_boot, port=origin_port, receipt_count=len(expected_cases))
        v['observations']['origin_nonce_received'] = c['positive_case'] in observed_cases
        v['checks']['origin_healthy'] = True
        if self.mode == 'strict':
            live.require(v['checks']['direct_deny'] and not any(v['violations'].values()), 'direct_deny')
        else:
            v['diagnostic'].update(forbidden_nonce_received=v['violations']['forbidden_receiver_accepted'],
                direct_denied_by_access=v['checks']['direct_deny'] and not v['violations']['forbidden_receiver_accepted'],
                observation_complete=True)

    def refresh_profiles(self):
        if self.mode == 'strict': return
        self.maintenance.operation('profiles-status', self.rule_owner.rule['name'])
        observed = self.maintenance.last_observation
        maintenance.validate_profiles_observation(observed, 'profiles-status', self.mode, self.config['start_qpc'],
            self.config['frequency'], self.config['deadline_qpc'], self.budget.read())
        live.require(observed['profiles_off_verified'], 'profiles_off_before_go')

    def harvest(self):
        """Independent receiver/client positives survive later parser/exit failures."""
        c, root, v = self.config, self.root, self.value
        origin_task = self.tasks.get('origin')
        if origin_task is not None and origin_task['exited'] and self.fixed_ports is not None:
            for index in range(1, 9):
                path = root / ('origin/receipt-%04d.json' % index)
                if not path.exists():
                    continue
                try:
                    row = receipt(live.decode(live.local.bounded(path, live.MAX_NATIVE)), origin_task, c,
                        boot=self.origin_boot, port=self.fixed_ports['origin'], index=index)
                    if row['case_id'] == c['direct_case']:
                        v['violations']['forbidden_receiver_accepted'] = True
                    if row['case_id'] == c['positive_case'] and row['request_exact']:
                        v['observations']['origin_nonce_received'] = True
                except BaseException:
                    pass  # Unparseable evidence never becomes a negative/pass.
        selected = self.tasks.get('selected')
        if selected is not None and selected['exited'] and self.direct_deadline is not None:
            path = root / 'selected/phase-0002.json'
            if path.exists():
                try:
                    row = client_phase(live.decode(live.local.bounded(path, live.MAX_NATIVE)), selected, c,
                        role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=2,
                        case=c['direct_case'], operation='direct-tcp', target_port=self.fixed_ports['origin'],
                        phase_deadline=self.direct_deadline)
                    v['violations']['direct_connected'] |= row['network']['connect_completed']
                except BaseException:
                    pass
        if self.mode != 'strict':
            v['diagnostic']['direct_connected'] = v['violations']['direct_connected']
            v['diagnostic']['forbidden_nonce_received'] = v['violations']['forbidden_receiver_accepted']
            if v['violations']['direct_connected'] or v['violations']['forbidden_receiver_accepted']:
                v['diagnostic']['direct_denied_by_access'] = False

    def cleanup(self):
        api, budget, root = self.api, self.budget, self.root
        self.phase = 'cleanup'
        clean = False
        empty = False
        try:
            clean, empty, _ = ac._cleanup(api, live.CleanupView(budget, budget.cutoff(20)), self.job, self.children,
                live.origin.CombinedLedgers(self.owners, *self.scoped_owners))
        except BaseException:
            clean = False
        all_exited = all(not row['attempted'] or row['info'].hProcess and row['exited'] for row in self.children)
        self.harvest()
        rule_absent = self.rule_owner is None
        if self.rule_owner is not None and clean and empty and all_exited and self.maintenance is not None and self.maintenance.admitted:
            try:
                def journal(row):
                    launcher.write_private_bytes(root / ('rule-' + row['state'] + '.json'), live.encode(row))
                rule_absent = self.rule_owner.remove(self.rules, budget, journal, all_held_exited=bool(all_exited), job_empty=empty)
            except BaseException:
                rule_absent = False
        # A killed RPC/WMI operation may commit later outside the child Job.
        # A later absence observation cannot cancel that outstanding authority.
        rule_quiescent = rule_absent and (self.rule_owner is None or not self.rule_owner.uncertain)
        maintenance_clean = self.maintenance is None
        if self.maintenance is not None:
            try:
                if self.maintenance.admitted:
                    self.maintenance.finish()
                elif self.maintenance.process is not None:
                    self.maintenance.exited = api.wait(self.maintenance.process, budget.remaining_ms(budget.deadline, 1000)) is True
                maintenance_clean = self.maintenance.exited and not self.maintenance.spawn_unknown
            except BaseException:
                maintenance_clean = False
        if self.maintenance_job is not None:
            try:
                if not maintenance_clean:
                    api.terminate_job(self.maintenance_job)
                if self.maintenance is not None and self.maintenance.process is not None:
                    observed_exit = api.wait(self.maintenance.process, budget.remaining_ms(budget.deadline, 1000)) is True
                    maintenance_clean = maintenance_clean and observed_exit
                maintenance_clean = maintenance_clean and api.job_empty(self.maintenance_job)
            except BaseException:
                maintenance_clean = False
        for handle in tuple(self.maintenance_owners.pending):
            try:
                self.maintenance_owners.close(handle)
            except BaseException:
                maintenance_clean = False
        # ACL tools need a new owned workload Job after the application Job has
        # been proven empty/closed. They run only after every scoped actor exited.
        controls_clean = not self.profile['attempted']
        cleanup_tasks = []
        cleanup_owners = None
        old_children, old_owners, old_job, old_scopes = self.children, self.owners, self.job, self.scoped_owners
        if clean and empty and all_exited and rule_quiescent and maintenance_clean and self.profile['created']:
            try:
                self.children = cleanup_tasks
                self.owners = cleanup_owners = helpers.OneShotHandles(api.close)
                self.scoped_owners = []
                self.job = api.owned_job(self.owners)
                if self.acl_attempted:
                    owned_tree(root)
                    self.tool([str(self.fixed_icacls()), str(root), '/remove:g', '*' + self.profile['sid'], '/T', '/Q'], 'acl-remove', cleanup=True)
                    for path in owned_tree(root):
                        budget.require_ms(budget.cutoff(3))
                        live.require(api.acl_read(path, self.profile['sid']) == [], 'acl_remove')
                self.acl_removed = True
                controls_clean = True
            except BaseException:
                controls_clean = False
            finally:
                if cleanup_owners is not None:
                    try:
                        tool_ledgers = live.origin.CombinedLedgers(cleanup_owners, *self.scoped_owners)
                        tools_clean, tools_empty, _ = ac._cleanup(api, live.CleanupView(budget, budget.cutoff(2)), self.job, cleanup_tasks, tool_ledgers)
                        controls_clean = controls_clean and tools_clean and tools_empty and tool_ledgers.confirmed_closed
                    except BaseException:
                        controls_clean = False
                self.children, self.owners, self.job, self.scoped_owners = old_children, old_owners, old_job, old_scopes
            if controls_clean:
                try:
                    budget.require_ms(budget.cutoff(1))
                    api.delete_profile('RuleProxy.Model2.A.' + self.config['run'])
                    self.profile_deleted = True
                except BaseException:
                    controls_clean = False
        sid_released = False
        try:
            api.release_profile_sid(self.profile)
            sid_released = True
        except BaseException:
            pass
        if self.profile['attempted'] and not self.profile['returned']:
            controls_clean = False
        self.cleanup_ok = bool(clean and empty and all_exited and rule_quiescent and controls_clean and sid_released
            and maintenance_clean and self.maintenance_owners.confirmed_closed and not getattr(api, 'controls_uncertain', False))
        self.value['checks']['cleanup'] = self.cleanup_ok
        self.cleanup_ledger.update(workload_cleanup_confirmed=clean, workload_job_empty=empty,
            all_workloads_exited=bool(all_exited), maintenance_cleanup_confirmed=maintenance_clean,
            maintenance_handles_closed=self.maintenance_owners.confirmed_closed, acl_removed=self.acl_removed,
            profile_deleted=self.profile_deleted, sid_released=sid_released, cleanup=self.cleanup_ok)

    def ownership_journal(self):
        c = self.config
        keys = ('attempted', 'assigned', 'exited', 'exit_code', 'pid', 'created', 'identity', 'capabilities',
            'image_verified', 'resumed', 'command', 'image_path', 'image_sha256', 'admission_qpc', 'resume_qpc',
            'cleanup_role', 'externally_held_before_first_resume', 'externally_held_before_network_go')
        tasks = [dict(role=name, **{k: row[k] for k in keys}) for name, row in self.tasks.items()]
        native_paths = ['front/ready.json', 'front/final.json', 'relay/final.json', 'origin/ready.json', 'origin/final.json',
            'health/ready.json', 'health/final.json', 'selected/ready.json', 'selected/final.json',
            'g-probe/stdout', 'g-probe/stderr', 'g-live/stdout', 'g-live/stderr']
        native_paths += ['origin/receipt-%04d.json' % i for i in range(1, 9)]
        native_paths += ['health/phase-%04d.json' % i for i in range(1, 4)]
        native_paths += ['selected/phase-%04d.json' % i for i in range(1, 3)]
        reports = []
        for name in native_paths:
            path = self.root / name
            if not path.exists():
                continue
            try:
                raw = live.local.bounded(path, live.MAX_PRIVATE)
                reports.append(dict(path=name, state='read', bytes=len(raw), sha256=live.sha(raw)))
            except BaseException:
                reports.append(dict(path=name, state='unreadable', bytes=None, sha256=None))
        m = self.maintenance
        maintenance_record = dict(attempted=m is not None and m.attempted, spawn_unknown=m is not None and m.spawn_unknown,
            pid=None if m is None else m.pid, created=None if m is None else m.created, identity=None if m is None else m.identity,
            admitted=m is not None and m.admitted, exited=m is not None and m.exited, exit_code=None if m is None else m.exit_code,
            plan_sha256=None if m is None else m.plan_hash)
        rule_record = None if self.rule_owner is None else dict(rule=self.rule_owner.rule, intent=self.rule_owner.intent,
            attempted=self.rule_owner.attempted, present_verified=self.rule_owner.present_verified,
            absent_verified=self.rule_owner.absent_verified, uncertain=self.rule_owner.uncertain)
        return dict(schema_version=1, stage='model2-first-ownership', run=c['run'], controller_pid=os.getpid(),
            frequency=c['frequency'], start_qpc=c['start_qpc'], deadline_qpc=c['deadline_qpc'],
            source_sha256=c['source_sha256'], actor_sha256=c['actor_sha256'], manifest_sha256=c['manifest_sha256'],
            public_sha256=live.sha(live.encode(self.value)), tasks=tasks, selected_discovery=self.selected_discovery,
            public=self.value, fixed_ports=self.fixed_ports, go=self.go_records, native_reports=reports,
            maintenance=maintenance_record, rules=rule_record, cleanup=self.cleanup_ledger)


def validate_ownership_journal(value, config, *, controller_pid):
    keys = {'schema_version', 'stage', 'run', 'controller_pid', 'frequency', 'start_qpc', 'deadline_qpc',
        'source_sha256', 'actor_sha256', 'manifest_sha256', 'public_sha256', 'public', 'fixed_ports',
        'tasks', 'selected_discovery', 'go', 'native_reports', 'maintenance', 'rules', 'cleanup'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'model2-first-ownership' and type(value['controller_pid']) is int
        and value['controller_pid'] == controller_pid, 'journal_schema')
    for key in ('run', 'frequency', 'start_qpc', 'deadline_qpc', 'source_sha256', 'actor_sha256', 'manifest_sha256'):
        live.require(type(value[key]) is type(config[key]) and value[key] == config[key], 'journal_binding')
    public = live.validate_public(value['public'])
    live.require(ac.digest(value['public_sha256']) and value['public_sha256'] == live.sha(live.encode(public)), 'journal_public')
    live.require(public['checks']['guard_held'] is False and public['local_c_qualified'] is False, 'journal_scope')
    if value['fixed_ports'] is not None:
        live.ports(value['fixed_ports'])
    task_keys = {'role', 'attempted', 'assigned', 'exited', 'exit_code', 'pid', 'created', 'identity', 'capabilities',
        'image_verified', 'resumed', 'command', 'image_path', 'image_sha256', 'admission_qpc', 'resume_qpc', 'cleanup_role',
        'externally_held_before_first_resume', 'externally_held_before_network_go'}
    roles = {'origin', 'health', 'front', 'relay', 'g-probe', 'g-live', 'selected',
        'acl-root', 'acl-inputs', 'acl-front', 'acl-remove'}
    live.require(type(value['tasks']) is list and len(value['tasks']) <= len(roles), 'journal_tasks')
    tasks = {}
    for row in value['tasks']:
        live.require(type(row) is dict and set(row) == task_keys and row['role'] in roles and row['role'] not in tasks, 'journal_task')
        tasks[row['role']] = row
        for key in ('attempted', 'assigned', 'exited', 'image_verified', 'resumed', 'cleanup_role',
                    'externally_held_before_first_resume', 'externally_held_before_network_go'):
            live.require(type(row[key]) is bool, 'journal_task_bool')
        for key, maximum in (('pid', 0xffffffff), ('created', 0xffffffffffffffff)):
            live.require(row[key] is None or live.integer(row[key], 1, maximum), 'journal_task_generation')
        live.require(row['exit_code'] is None or live.integer(row['exit_code']) and row['exited'], 'journal_exit')
        live.require(type(row['command']) is list and 1 <= len(row['command']) <= 32
            and all(type(x) is str and 0 < len(x) <= 32768 and '\0' not in x for x in row['command'])
            and row['image_path'] == row['command'][0] and ac.digest(row['image_sha256']), 'journal_command')
        for key in ('admission_qpc', 'resume_qpc'):
            live.require(row[key] is None or live.integer(row[key], config['start_qpc'], config['deadline_qpc']), 'journal_task_clock')
        if row['identity'] is not None:
            live.require(type(row['identity']) is dict and set(row['identity']) == ac.AC_IDENTITY_KEYS, 'journal_identity')
            entries, invalid, duplicates = live.proof.capability_entries(row['capabilities'])
            live.require(entries is not None and not invalid and not duplicates
                and type(row['identity']['capability_count']) is int and row['identity']['capability_count'] == len(entries), 'journal_capabilities')
        else:
            live.require(row['capabilities'] is None, 'journal_partial_identity')
        live.require(not row['assigned'] or row['attempted'] and row['pid'] is not None, 'journal_assignment')
        if row['resumed']:
            live.require(row['assigned'] and row['image_verified'] and row['created'] is not None
                and row['identity'] is not None and row['admission_qpc'] is not None
                and row['externally_held_before_network_go'] is True, 'journal_admission')
            if row['role'] == 'selected':
                live.require(row['externally_held_before_first_resume'] is False and row['resume_qpc'] is None, 'journal_selected_resume')
            else:
                live.require(row['externally_held_before_first_resume'] is True and row['resume_qpc'] is not None
                    and row['resume_qpc'] >= row['admission_qpc'], 'journal_resume_order')
        if row['role'] in ('origin', 'health', 'front', 'relay', 'selected'):
            live.require(row['image_sha256'] == config['actor_sha256'], 'journal_actor_hash')
        if row['role'] in ('g-probe', 'g-live'):
            live.require(row['image_sha256'] == live.probe.pins.MXC_G_EXECUTOR_SHA256, 'journal_g_hash')
    discovery = value['selected_discovery']
    if discovery is not None:
        dk = {'parent_pid', 'parent_created', 'first_children', 'second_children', 'query_created', 'held_created',
            'workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed'}
        live.require(type(discovery) is dict and set(discovery) == dk and 'selected' in tasks and 'g-live' in tasks, 'journal_discovery')
        selected, parent = tasks['selected'], tasks['g-live']
        live.require(discovery['parent_pid'] == parent['pid'] and type(discovery['parent_pid']) is int
            and discovery['parent_created'] == parent['created'] and type(discovery['parent_created']) is int
            and type(discovery['first_children']) is list and type(discovery['second_children']) is list
            and discovery['first_children'] == discovery['second_children'] == [selected['pid']]
            and all(type(x) is int for x in discovery['first_children'] + discovery['second_children'])
            and type(discovery['query_created']) is int and type(discovery['held_created']) is int
            and discovery['query_created'] == discovery['held_created'] == selected['created'] >= parent['created']
            and all(discovery[k] is True for k in ('workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed')), 'journal_generation')
    live.require(not public['checks']['selected_held'] or discovery is not None, 'journal_missing_selected')
    expected_go = [('health-client', 1, 2, config['health_cases'][0]), ('selected-client', 1, 1, config['positive_case']),
        ('health-client', 2, 2, config['health_cases'][1]), ('selected-client', 2, 2, config['direct_case']),
        ('selected-client', 3, 255, config['boot_case']), ('health-client', 3, 2, config['health_cases'][2]),
        ('health-client', 4, 255, config['admission_nonce']), ('health-origin', 1, 255, config['health_cases'][0])]
    live.require(type(value['go']) is list and len(value['go']) <= len(expected_go), 'journal_go')
    for row, (role, sequence, opcode, case) in zip(value['go'], expected_go):
        live.require(type(row) is dict and set(row) == {'role', 'sequence', 'opcode', 'case', 'phase_deadline', 'path', 'sha256'}
            and row['role'] == role and type(row['sequence']) is int and row['sequence'] == sequence
            and type(row['opcode']) is int and row['opcode'] == opcode and row['case'] == case
            and live.integer(row['phase_deadline'], 1, config['deadline_qpc']) and ac.digest(row['sha256']), 'journal_go_binding')
        if role == 'health-origin':
            expected = live.fixture_finish(run=config['run'], boot_case=config['health_cases'][0],
                frequency=config['frequency'], deadline=config['deadline_qpc'])
            expected_path = 'origin-control/finish.bin'
        else:
            live.require(value['fixed_ports'] is not None, 'journal_go_ports')
            admission = config['admission_nonce'] if role == 'selected-client' else config['maintenance_nonce']
            expected = live.go_record(run=config['run'], case=case, sequence=sequence, opcode=opcode,
                frequency=config['frequency'], deadline=config['deadline_qpc'], fixed_ports=value['fixed_ports'],
                admission=admission, phase_deadline=row['phase_deadline'])
            expected_path = ('selected-control' if role == 'selected-client' else 'health-control') + '/phase-%04d.bin' % sequence
        live.require(row['path'] == expected_path and row['sha256'] == live.sha(expected), 'journal_go_digest')
    paths = set()
    live.require(type(value['native_reports']) is list and len(value['native_reports']) <= 26, 'journal_reports')
    for row in value['native_reports']:
        live.require(type(row) is dict and set(row) == {'path', 'state', 'bytes', 'sha256'}
            and type(row['path']) is str and row['path'] not in paths
            and re_report_path(row['path']) and row['state'] in ('read', 'unreadable'), 'journal_report')
        paths.add(row['path'])
        live.require(row['state'] != 'read' or live.integer(row['bytes'], 0, live.MAX_PRIVATE) and ac.digest(row['sha256']), 'journal_report_digest')
        live.require(row['state'] != 'unreadable' or row['bytes'] is None and row['sha256'] is None, 'journal_report_unreadable')
    m = value['maintenance']
    live.require(type(m) is dict and set(m) == {'attempted', 'spawn_unknown', 'pid', 'created', 'identity', 'admitted', 'exited', 'exit_code', 'plan_sha256'}
        and all(type(m[k]) is bool for k in ('attempted', 'spawn_unknown', 'admitted', 'exited'))
        and (m['pid'] is None or live.integer(m['pid'], 1)) and (m['created'] is None or live.integer(m['created'], 1, 0xffffffffffffffff))
        and (m['exit_code'] is None or live.integer(m['exit_code']) and m['exited'])
        and (m['plan_sha256'] is None or ac.digest(m['plan_sha256'])), 'journal_maintenance')
    if m['admitted']:
        live.require(m['attempted'] and not m['spawn_unknown'] and m['pid'] is not None and m['created'] is not None
            and m['identity'] is not None and m['plan_sha256'] is not None, 'journal_maintenance_admission')
    rule = value['rules']
    if rule is not None:
        live.require(type(rule) is dict and set(rule) == {'rule', 'intent', 'attempted', 'present_verified', 'absent_verified', 'uncertain'}
            and all(type(rule[k]) is bool for k in ('intent', 'attempted', 'present_verified', 'absent_verified', 'uncertain')), 'journal_rule')
        row = rule['rule']
        live.validate_rule(row, live.firewall_rule(config['run'], 'A-P', row.get('package_sid'), row.get('program'), row.get('local_port')))
        live.require(not rule['attempted'] or rule['intent'], 'journal_rule_intent')
        live.require(not rule['present_verified'] or rule['attempted'], 'journal_rule_create')
    cleanup_keys = {'workload_cleanup_confirmed', 'workload_job_empty', 'all_workloads_exited',
        'maintenance_cleanup_confirmed', 'maintenance_handles_closed', 'acl_removed', 'profile_deleted', 'sid_released', 'cleanup'}
    live.require(type(value['cleanup']) is dict and set(value['cleanup']) == cleanup_keys
        and all(type(x) is bool for x in value['cleanup'].values())
        and value['cleanup']['cleanup'] == public['checks']['cleanup'], 'journal_cleanup')
    if value['cleanup']['profile_deleted']:
        live.require(all(value['cleanup'][k] for k in cleanup_keys - {'cleanup', 'sid_released'})
            and (rule is None or rule['absent_verified'] and not rule['uncertain'])
            and (not m['attempted'] or m['exited'] and not m['spawn_unknown']), 'journal_profile_delete')
    live.require(public['execution_mode'] == live.execution_mode(config), 'journal_execution_mode')
    if live.first_ready(public, require_guard=False) or live.diagnostic_ready(public, require_guard=False):
        live.require(set(tasks) == roles and len(value['go']) == len(expected_go)
            and all(row['resumed'] and row['exited'] and row['exit_code'] == 0 for row in tasks.values())
            and all(value['cleanup'].values()) and rule is not None and rule['present_verified'] and rule['absent_verified']
            and m['admitted'] and m['exited'] and m['exit_code'] == 0
            and all(row['state'] == 'read' for row in value['native_reports']), 'journal_first_cell')
    return value


def re_report_path(path):
    import re
    return bool(re.fullmatch(r'(?:front/(?:ready|final)\.json|relay/final\.json|origin/(?:ready|final|receipt-000[1-8])\.json|'
        r'health/(?:ready|final|phase-000[1-3])\.json|selected/(?:ready|final|phase-000[12])\.json|g-(?:probe|live)/(?:stdout|stderr))', path))


def run_controller(config, root=ROOT, *, api=None):
    config = validate_config(config)
    root = launcher.checked_path(root, is_file=False)
    live.require(root.name == 'local-model2-' + config['run'], 'controller_stage')
    api = live.LiveNativeAPI() if api is None else api
    controller = FirstController(config, root, api)
    value = controller.value
    try:
        controller.run()
    except BaseException as exc:
        phase = controller.phase
        value['failure'] = phase if phase in ('inputs', 'identity', 'deadline', 'staging', 'probe', 'selected', 'firewall',
            'health', 'positive', 'cleanup', 'report') else 'worker'
        value['status'] = 'failed' if any(value['violations'].values()) else 'inconclusive'
        # Private only: retain native Win32/HRESULT and closed invariant details
        # for one evidence-driven repair, without exposing paths or raw stderr.
        error = dict(schema_version=1, stage='model2-controller-error', phase=phase,
            diagnostic=launcher.failure(exc), native_operation=None, native_code=None, invariant=None)
        operation, code = getattr(exc, 'operation', None), getattr(exc, 'winerror', None)
        if type(operation) is str and 1 <= len(operation) <= 128 and live.integer(code):
            error.update(native_operation=operation, native_code=code)
        if getattr(exc, 'domain', None) in ('win32', 'hresult') and live.integer(getattr(exc, 'code', None)):
            error.update(native_operation=exc.domain, native_code=exc.code)
        if type(exc) is ValueError:
            import re
            if re.fullmatch(r'[a-z0-9_:-]{1,128}', str(exc)):
                error['invariant'] = str(exc)
            if str(exc) == 'selected_child_set_changed' and type(getattr(exc, 'discovery', None)) is dict:
                error['discovery'] = exc.discovery
        raw_error = live.encode(error)
        if len(raw_error) <= 4096:
            launcher.write_private_bytes(root / 'controller-error-private.json', raw_error)
    finally:
        controller.cleanup()
        if not controller.cleanup_ok:
            value['failure'] = value['failure'] or 'cleanup'
    live.finalize_public(value)
    journal = controller.ownership_journal()
    validate_ownership_journal(journal, config, controller_pid=os.getpid())
    journal_raw = live.encode(journal)
    live.require(len(journal_raw) <= live.MAX_PRIVATE, 'ownership_journal_bound')
    launcher.write_private_bytes(root / 'model2-ownership-private.json', journal_raw)
    return dict(schema_version=1, stage='model2-first-controller', run=config['run'], controller_pid=os.getpid(),
        frequency=config['frequency'], start_qpc=config['start_qpc'], deadline_qpc=config['deadline_qpc'],
        source_sha256=config['source_sha256'], actor_sha256=config['actor_sha256'], manifest_sha256=config['manifest_sha256'],
        ownership_journal_sha256=live.sha(journal_raw), ownership_journal_bytes=len(journal_raw), public=value)


def validate_private(value, config, *, controller_pid):
    keys = {'schema_version', 'stage', 'run', 'controller_pid', 'frequency', 'start_qpc', 'deadline_qpc',
        'source_sha256', 'actor_sha256', 'manifest_sha256', 'ownership_journal_sha256', 'ownership_journal_bytes', 'public'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'model2-first-controller' and type(value['controller_pid']) is int
        and value['controller_pid'] == controller_pid, 'private_controller')
    for key in ('run', 'frequency', 'start_qpc', 'deadline_qpc', 'source_sha256', 'actor_sha256', 'manifest_sha256'):
        live.require(type(value[key]) is type(config[key]) and value[key] == config[key], 'private_binding')
    result = live.validate_public(value['public'])
    live.require(result['execution_mode'] == live.execution_mode(config), 'private_execution_mode')
    live.require(ac.digest(value['ownership_journal_sha256']) and live.integer(value['ownership_journal_bytes'], 1, live.MAX_PRIVATE), 'private_journal')
    live.require(result['checks']['guard_held'] is False and result['local_c_qualified'] is False
        and result['first_chain_verified'] is False and not any(result['checks'][k] for k in ('wrong_port', 'wrong_peer', 'proxy_death')),
        'first_cell_scope')
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256'):
        live.require(result[key] in (None, config[key]), 'private_source_binding')
    return result
