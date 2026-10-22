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
import time
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
    if type(value) is dict and 'selected_admission' in value:
        live.require(mode == 'profiles-off-diagnostic', 'helper_diagnostic_only')
        live.validate_selected_admission(value['selected_admission'])
        keys.add('selected_admission')
    if type(value) is dict and 'wrong_port_extension' in value:
        live.require(mode == 'profiles-off-diagnostic' and 'selected_admission' in value, 'wrong_port_diagnostic_only')
        live.validate_wrong_port_extension(value['wrong_port_extension'])
        keys.add('wrong_port_extension')
    if type(value) is dict and 'wrong_peer_extension' in value:
        live.require(mode == 'profiles-off-diagnostic' and 'selected_admission' in value
            and 'wrong_port_extension' not in value, 'wrong_peer_diagnostic_only')
        live.validate_wrong_peer_extension(value['wrong_peer_extension']); keys.add('wrong_peer_extension')
    if type(value) is dict and 'death_extension' in value:
        live.require(mode == 'profiles-off-diagnostic' and 'selected_admission' in value
            and not any(k in value for k in ('wrong_port_extension', 'wrong_peer_extension')), 'death_diagnostic_only')
        live.validate_death_extension(value['death_extension']); keys.add('death_extension')
    if type(value) is dict and 'dns_extension' in value:
        live.require(mode=='profiles-off-diagnostic' and 'selected_admission' in value
            and not any(k in value for k in ('wrong_port_extension','wrong_peer_extension','death_extension')), 'dns_diagnostic_only')
        live.dns.extension(value['dns_extension']); keys.add('dns_extension')
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'model2-first-owned-input', 'config')
    live.clock_record(value['start_qpc'], value['frequency'], value['root_deadline_qpc'])
    live.require(value['deadline_qpc'] == value['root_deadline_qpc'] - 5 * value['frequency']
        and value['deadline_qpc'] > value['start_qpc'], 'config_clock')
    names = ('run', 'boot_case', 'positive_case', 'direct_case', 'admission_nonce', 'maintenance_nonce')
    live.require(all(ac.nonce(value[k]) for k in names) and type(value['health_cases']) is list
        and len(value['health_cases']) == 3 and all(ac.nonce(x) for x in value['health_cases']), 'config_nonce')
    nonces = [value[k] for k in names] + value['health_cases']
    if 'wrong_port_extension' in value:
        nonces += [v for k, v in value['wrong_port_extension'].items() if k != 'profile']
    if 'wrong_peer_extension' in value:
        nonces += [v for k, v in value['wrong_peer_extension'].items() if k != 'profile']
    if 'death_extension' in value:
        nonces += [v for k, v in value['death_extension'].items() if k != 'profile']
    if 'dns_extension' in value:
        nonces += [v for k,v in value['dns_extension'].items() if k!='profile']
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
    live.require(operation in ('proxy-get','direct-tcp','wrong-port','wrong-peer','proxy-after-death'),'http_operation')
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


def connect_denied(value):
    n = value['network']
    return (value['failure'] is None and value['phase_qpc'][2] < value['phase_qpc'][1]
        and all(n[key] for key in ('wsa_startup', 'inheritance_cleared', 'socket_created', 'connect_attempted'))
        and not n['connect_completed'] and n['failure'] == 'connect' and n['wsa_error'] == 10013
        and n['socket_close'] == 'confirmed' and n['wsa_cleanup'] is True)


def bounded_connect_timeout(value, frequency, root_deadline):
    """A typed late failure permits observation/finish only; it is not a deny."""
    n, p = value['network'], value['phase_qpc']
    return (value['failure'] is None and p[0] <= p[1] <= p[2] < min(root_deadline, p[1] + frequency)
        and all(n[key] is True for key in ('wsa_startup', 'inheritance_cleared', 'socket_created', 'connect_attempted', 'wsa_cleanup'))
        and all(n[key] is False for key in ('connect_completed', 'peer_loopback', 'request_complete', 'send_shutdown', 'response_exact', 'response_eof'))
        and n['local_port'] is None and n['peer_port'] is None and n['request_bytes'] == 0 and n['response_bytes'] == 0
        and n['failure'] == 'deadline' and n['wsa_error'] is None and n['socket_close'] == 'confirmed')


def finish_peer_observation(value):
    if 'wrong_peer_extension' not in value: return
    peer = value['wrong_peer_extension']
    if peer['observation_complete'] and (peer['timed_out'] or not peer['denied_by_access'] and not peer['connected'] and not peer['forbidden_nonce_received']):
        value['failure'] = 'wrong-peer'


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


def receipt(value, task, config, *, boot, port, index, role='health-origin'):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'case_id', 'pid', 'index', 'port', 'peer_port',
        'qpc', 'request_bytes', 'request_exact', 'request_eof', 'response_bytes', 'response_complete', 'send_shutdown',
        'connection_close', 'failure', 'wsa_error'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-listener-receipt' and value['role'] == role
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


def receipt_passed(row, operation='direct-tcp'):
    if row['case_id'] is None:
        return False
    request, response = transport_payload(row['case_id'], row['port'], operation)
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


def listener_final(value, task, config, *, boot, port, receipt_count, role='health-origin', profile='ordinary'):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'qpc', 'port', 'accepted_count', 'receipt_count',
        'finished', 'listener_close', 'wsa_startup', 'wsa_cleanup', 'command_close_verified', 'failure', 'wsa_error'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-listener-final' and value['role'] == role
        and value['run_id'] == config['run'] and value['boot_case_id'] == boot and value['pid'] == task['pid']
        and type(value['pid']) is int and value['capability_profile'] == profile
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


def blank_death_ledger(config):
    return dict(schema_version=1, stage='model2-live-relay-death-ownership', run=config['run'],
        death_case=config['death_extension']['death_case'], after_direct_case=config['death_extension']['after_direct_case'],
        pair_start=None, pair_deadline=None, ticket=None, held_ack=None, relay_binding=None, stop_intent=None,
        stop_persisted_qpc=None, terminate_requested=False, terminate_returned=False, exit_code=None, exit_qpc=None,
        front_report=None, client_report=None, release_go=None, release_ack=None, after_direct_report=None, origin_receipts=[])


def read_death_record(root, relative):
    raw = live.local.bounded(root/relative, live.MAX_NATIVE)
    return dict(path=relative, bytes=len(raw), sha256=live.sha(raw), text=raw.decode('ascii', 'strict'))


def write_death_stop_intent(path, raw):
    live.require(type(raw) is bytes and len(raw) <= live.MAX_NATIVE and not path.exists(), 'death_stop_fresh')
    stream = path.open('xb')
    try:
        live.require(stream.write(raw) == len(raw), 'death_stop_short_write')
        stream.flush(); os.fsync(stream.fileno())
    finally:
        launcher.close_private_once(stream)


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
        self.b_profile = dict(attempted=False, returned=False, created=False, pointer=None, sid=None)
        self.b_profile_ledger = dict(name='RuleProxy.Model2.B.' + config['run'], attempted=False, returned=False,
            created=False, sid=None, derive_verified=False, different_a_verified=False, acl_attempted=False,
            acl_removed=False, deleted=False, released=False, a_front_closed_verified=False)
        self.acl_attempted = False
        self.acl_removed = False
        self.cleanup_ok = False
        self.mode = live.execution_mode(config)
        self.value = live.blank(self.mode, wrong_port_extension='wrong_port_extension' in config,
            wrong_peer_extension='wrong_peer_extension' in config, death_extension='death_extension' in config,
            dns_extension='dns_extension' in config)
        self.parent = None
        self.catalog = None
        self.phase = 'inputs'
        self.fixed_ports = None
        self.origin_boot = None
        self.direct_deadline = None
        self.wrong_port_deadline = None
        self.wrong_port_denied = False
        self.wrong_peer_deadline = None
        self.death_after_deadline = None
        self.death_after_denied = False
        self.death_ledger = blank_death_ledger(config) if 'death_extension' in config else None
        self.dns_ledger = live.dns.blank_ledger(config) if 'dns_extension' in config else None
        self.dns_fixture = None
        self.dns_inventory = None
        self.go_records = []
        self.selected_discovery = None
        self.q_selected_discovery = None
        self.b_selected_discovery = None
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

    def task(self, name, argv, work, *, profile=None, handles=None, environment=None, image_hash=None, cleanup=False, profile_record=None):
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
                record = self.profile if profile_record is None else profile_record
                live.require((record is self.profile or record is self.b_profile and 'wrong_peer_extension' in self.config)
                    and record['created'] and record['returned'] and record['pointer'] is not None and record['sid'] == profile,
                    'owned_profile_pointer')
                self.api.pncs_create(info, argv, work, [] if handles is None else handles, self.owners,
                    state, record['pointer'], environment)
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

    def grant(self, sid, *, prefix='', report_directory='front'):
        owned_tree(self.root)
        if prefix: self.b_profile_ledger['acl_attempted'] = True
        else: self.acl_attempted = True
        image = str(self.fixed_icacls())
        for name, path, access in (('root', self.root, 'RX'), ('inputs', self.root / 'inputs', '(OI)(CI)(RX)'),
                                  ('front', self.root / report_directory, '(OI)(CI)(M)')):
            owned_tree(self.root)
            self.tool([image, str(path), '/grant', '*' + sid + ':' + access, '/Q'], prefix + 'acl-' + name)
        for path in owned_tree(self.root):
            self.budget.require_ms(self.budget.cutoff(30))
            expected = ([(0, 0x1200a9)] if path == self.root else [(3, 0x1200a9)] if path == self.root / 'inputs'
                else [(3, 0x1301bf)] if path == self.root / report_directory
                else [(16, 0x1200a9)] if path.parent == self.root / 'inputs'
                else [(16, 0x1301bf)] if self.root / report_directory in path.parents else [])
            live.require(self.api.acl_read(path, sid) == expected, 'acl_scope')

    def g_task(self, name, request, *, actual=False):
        if actual and 'selected_admission' in self.config:
            live.require(live.system_conhost_record(self.api) == self.config['selected_admission'], 'helper_hash_before_g')
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
        argv = live.g_command(exe, request, actual=actual)
        row = self.task(name, argv, work, environment=self.api.proc._environment_block(env), image_hash=live.probe.pins.MXC_G_EXECUTOR_SHA256)
        live.require(not list((work / 'dacl-state').iterdir()), 'reaper_changed_before_resume')
        self.resume(row)
        return row

    def register_auxiliary(self, held, *, role='system-conhost'):
        live.require(role in ('system-conhost', 'q-system-conhost', 'b-system-conhost') and role not in self.tasks
            and 'selected_admission' in self.config, 'helper_register')
        row = dict(info=SimpleNamespace(hProcess=held['handle'], hThread=None), attempted=True, assigned=False,
            exited=False, exit_code=None, pid=held['pid'], created=held['created'], identity=None, capabilities=None,
            image_verified=False, resumed=False, work=self.root / ('q-health' if role.startswith('q-') else 'b-health' if role.startswith('b-') else 'selected'), command=None,
            image_path=held['image_path'], image_sha256=held['image_sha256'], admission_qpc=None, resume_qpc=None,
            cleanup_role=False, externally_held_before_first_resume=False, externally_held_before_network_go=True,
            natural_exit_observed=False, stop_requested=False, finish_order_verified=False)
        self.tasks[role] = row
        self.children.append(row)

    def selected_family_alive(self, family='main'):
        if 'selected_admission' not in self.config: return
        live.require(family in ('main', 'q', 'b'), 'selected_family')
        for role in (('g-live', 'selected', 'system-conhost') if family == 'main' else (family + '-g-live', family + '-health', family + '-system-conhost')):
            row = self.tasks[role]
            self.alive(row)
            live.require(self.api.creation_time(row['info'].hProcess) == row['created']
                and self.api.process_id(row['info'].hProcess) == row['pid'], 'selected_family_generation')
            self.api.verify_job(self.job, row['info'].hProcess)
            scope = helpers.OneShotHandles(self.api.close)
            self.scoped_owners.append(scope)
            live.verify_exact_guard_member(self.api, row['info'].hProcess, self.config['guard_job_name'], owners=scope)
            live.require(scope.confirmed_closed, 'selected_family_outer_close')

    def finish_auxiliary(self, role):
        if role not in self.tasks: return
        auxiliary = self.tasks[role]
        auxiliary['finish_order_verified'] = True
        end = min(self.budget.read() + self.config['frequency'], self.budget.cutoff(30))
        auxiliary['exited'] = self.api.wait(auxiliary['info'].hProcess, self.budget.require_ms(end)) is True
        if auxiliary['exited']:
            auxiliary['exit_code'] = self.api.exit_code(auxiliary['info'].hProcess)
            auxiliary['natural_exit_observed'] = True

    def verify_actual_tier(self, task, prefix=''):
        live.require(task['exited'] and task['exit_code'] == 0 and not list((task['work'] / 'dacl-state').iterdir()),
            prefix + 'actual_reaper_changed')
        actual = live.local.bounded(task['work'] / 'stdout', live.MAX_PRIVATE) + b'\n' + live.local.bounded(task['work'] / 'stderr', live.MAX_PRIVATE)
        live.require(live.proof.actual_tiers(actual) == ['base-container'], prefix + 'actual_tier')

    def peer_psec_control(self, exe, fixed, *, prefix='q', profile_record=None):
        live.require(prefix in ('q', 'b') and (prefix != 'b' or profile_record is self.b_profile), 'peer_control_profile')
        c, root, budget = self.config, self.root, self.budget
        x = c['wrong_peer_extension' if prefix == 'b' else 'wrong_port_extension']
        record = self.profile if profile_record is None else profile_record
        report_dir = root / (prefix + '-health')
        control_dir = root / (prefix + '-health-control')
        listener = self.tasks[prefix + '-listener']
        q_ports = live.ports(dict(proxy=fixed['wrong_port'], wrong_port=fixed['proxy'], origin=fixed['origin'])) if prefix == 'q' else fixed
        argv = live.selected_command(exe, 'health-client', c['run'], x['control_boot'], report_dir / 'ready.json',
            report_dir, control_dir, c['start_qpc'], c['frequency'], c['deadline_qpc'], q_ports,
            self.parent['sid'], 'agentic-pncs', x['control_admission'])
        base = dict(entry.split('=', 1) for entry in self.api.native.environment(root).rstrip('\0').split('\0'))
        request = live.request_document(run=c['run'], command=argv, cwd=report_dir, inputs=root / 'inputs',
            control=control_dir, reports=report_dir, native_environment=
            ['SystemRoot=' + base['SystemRoot'], 'WINDIR=' + base['WINDIR'], 'LOCALAPPDATA=' + str(self.local_folder)],
            peer=dict(profile='RuleProxy.Model2.' + ('B.' if prefix == 'b' else 'A.') + c['run'], derived_sid=record['sid'],
                held_sid=listener['identity']['appcontainer_sid'], held=True, listener_port=q_ports['proxy']),
            fixed_ports=q_ports, timeout_ms=min(120000, (c['deadline_qpc'] - c['start_qpc']) * 1000 // c['frequency']))
        request['containerId'] = 'ruleproxy-model2-' + prefix + '-control-' + c['run']
        path = root / (prefix + '-live-request.json'); raw = live.encode(request)
        launcher.write_private_bytes(path, raw)
        probe = self.g_task(prefix + '-g-probe', path)
        self.wait(probe, budget.cutoff(35))
        live.require(not live.local.bounded(probe['work'] / 'stderr', live.MAX_NATIVE), 'q_probe_stderr')
        diagnostic = live.probe.projection(live.local.bounded(probe['work'] / 'stdout', live.probe.MAX_OUTPUT))
        live.require(diagnostic == dict(tier='base-container', needs_dacl_augmentation=False, warning_count=0,
            detector_error_present=False, base_container_api_present=True, bfs_compiled_in=False), 'q_live_probe')
        live.require(not list((probe['work'] / 'dacl-state').iterdir()) and live.local.bounded(path, live.MAX_PRIVATE) == raw,
            'q_probe_reaper_or_request')
        self.alive(listener)
        g = self.g_task(prefix + '-g-live', path, actual=True)
        observed, _ = read_when_closed(self.api, budget, report_dir / 'ready.json', g['info'].hProcess, budget.cutoff(35))
        def register_actor(row):
            live.require(prefix + '-health' not in self.tasks, 'q_actor_register')
            control = dict(info=SimpleNamespace(hProcess=row['handle'], hThread=None), attempted=True, assigned=False,
                exited=False, exit_code=None, pid=row['pid'], created=row['created'], identity=None, capabilities=None,
                image_verified=False, resumed=False, work=report_dir, command=list(argv), image_path=str(exe),
                image_sha256=c['actor_sha256'], admission_qpc=None, resume_qpc=None, cleanup_role=False,
                externally_held_before_first_resume=False, externally_held_before_network_go=True)
            self.children.append(control); self.tasks[prefix + '-health'] = control
        held = live.admit_selected(self.api, self.owners, budget, g_process=g['info'].hProcess, g_created=g['created'],
            job=self.job, image=exe, image_hash=c['actor_sha256'], parent=self.parent, capability_profile='agentic-pncs', catalog=self.catalog,
            diagnostic_guard_name=c['guard_job_name'], diagnostic_scoped_owners=self.scoped_owners,
            selected_admission=c['selected_admission'], auxiliary_register=lambda row:self.register_auxiliary(row, role=prefix + '-system-conhost'),
            actor_register=register_actor)
        auxiliary = held['auxiliary']
        self.tasks[prefix + '-system-conhost'].update(assigned=True, identity=auxiliary['identity'], capabilities=auxiliary['capabilities'],
            image_verified=True, resumed=True, admission_qpc=budget.read())
        scope = helpers.OneShotHandles(self.api.close); self.scoped_owners.append(scope)
        live.verify_exact_guard_member(self.api, held['handle'], c['guard_job_name'], owners=scope)
        live.require(scope.confirmed_closed, 'q_control_outer_close')
        held['discovery'].update(workload_job_verified=True, outer_job_verified=True, outer_query_handle_closed=True)
        setattr(self, prefix + '_selected_discovery', held['discovery'])
        control = self.tasks[prefix + '-health']
        control.update(assigned=True, identity=held['identity'], capabilities=held['capabilities'], image_verified=True,
            resumed=True, admission_qpc=budget.read())
        ready_client(observed, control, c, role='health-client', boot=x['control_boot'], admission=x['control_admission'], profile='agentic-pncs')

    def wrong_port_setup(self, exe, fixed, environment):
        if 'wrong_port_extension' not in self.config: return
        c, root, x = self.config, self.root, self.config['wrong_port_extension']
        self.directory('q-health'); self.directory('q-health-control')
        argv = [str(exe), 'health-listener', c['run'], x['listener_boot'], str(root / 'front/q-final.json'),
            str(root / 'front/q-ready.json'), str(root / 'front'), str(c['frequency']), str(c['start_qpc']),
            str(c['deadline_qpc']), str(fixed['wrong_port']), self.parent['sid'], self.profile['sid'], '8']
        listener = self.task('q-listener', argv, root / 'front', profile=self.profile['sid'], environment=environment)
        self.resume(listener)
        row, _ = read_when_closed(self.api, self.budget, root / 'front/q-ready.json', listener['info'].hProcess, self.budget.cutoff(35))
        ready_listener(row, listener, c, role='health-listener', boot=x['listener_boot'], profile='pncs')
        live.require(row['port'] == fixed['wrong_port'], 'wrong_port_listener')
        if x['profile'] == 'same-peer-wrong-port-psec-control-v1':
            self.peer_psec_control(exe, fixed)
            return
        command = live.selected_command(exe, 'health-client', c['run'], x['control_boot'], root / 'q-health/ready.json',
            root / 'q-health', root / 'q-health-control', c['start_qpc'], c['frequency'], c['deadline_qpc'], fixed,
            self.parent['sid'], 'ordinary', x['control_admission'])
        control = self.task('q-health', command, root / 'q-health')
        self.resume(control)
        row, _ = read_when_closed(self.api, self.budget, root / 'q-health/ready.json', control['info'].hProcess, self.budget.cutoff(35))
        ready_client(row, control, c, role='health-client', boot=x['control_boot'], admission=x['control_admission'], profile='ordinary')

    def wrong_peer_setup(self, exe, fixed, environment):
        if 'wrong_peer_extension' not in self.config: return
        c, root, x = self.config, self.root, self.config['wrong_peer_extension']
        live.require(self.value['checks']['positive'] and all(self.tasks[role]['exited'] and self.tasks[role]['exit_code'] == 0
            for role in ('front', 'relay')), 'a_front_closed_before_b')
        self.b_profile_ledger['a_front_closed_verified'] = True
        for directory in ('b-front', 'b-health', 'b-health-control'): self.directory(directory)
        ledger = self.b_profile_ledger
        ledger['attempted'] = True
        try:
            sid = self.api.create_profile(ledger['name'], self.b_profile)
        finally:
            for key in ('attempted', 'returned', 'created', 'sid'): ledger[key] = self.b_profile[key]
        live.require(self.b_profile['created'] and sid == self.api.derive_profile_sid(ledger['name']), 'b_profile_binding')
        ledger['derive_verified'] = True
        live.require(sid != self.profile['sid'], 'different_proxy_peer')
        ledger['different_a_verified'] = True
        self.grant(sid, prefix='b-', report_directory='b-front')
        argv = [str(exe), 'health-listener', c['run'], x['listener_boot'], str(root / 'b-front/final.json'),
            str(root / 'b-front/ready.json'), str(root / 'b-front'), str(c['frequency']), str(c['start_qpc']),
            str(c['deadline_qpc']), str(fixed['proxy']), self.parent['sid'], sid, '8']
        listener = self.task('b-listener', argv, root / 'b-front', profile=sid, profile_record=self.b_profile, environment=environment)
        self.resume(listener)
        row, _ = read_when_closed(self.api, self.budget, root / 'b-front/ready.json', listener['info'].hProcess, self.budget.cutoff(35))
        ready_listener(row, listener, c, role='health-listener', boot=x['listener_boot'], profile='pncs')
        live.require(row['port'] == fixed['proxy'], 'wrong_peer_listener')
        self.peer_psec_control(exe, fixed, prefix='b', profile_record=self.b_profile)

    def wrong_port_run(self, selected, fixed, *, peer=False):
        key = 'wrong_peer_extension' if peer else 'wrong_port_extension'
        if key not in self.config: return
        c, root, budget, x = self.config, self.root, self.budget, self.config[key]
        prefix = 'b' if peer else 'q'
        listener_dir = root / ('b-front' if peer else 'front')
        control_dir, report_dir = root / (prefix + '-health-control'), root / (prefix + '-health')
        target = fixed['proxy' if peer else 'wrong_port']
        violation = 'wrong_peer_connected' if peer else 'wrong_port_connected'
        listener, control = self.tasks[prefix + '-listener'], self.tasks[prefix + '-health']
        public = self.value[key]
        psec = peer or x['profile'] == 'same-peer-wrong-port-psec-control-v1'
        control_ports = live.ports(dict(proxy=fixed['wrong_port'], wrong_port=fixed['proxy'], origin=fixed['origin'])) if psec and not peer else fixed
        control_opcode = 1 if psec else 3
        self.phase = 'health'
        self.selected_family_alive(); self.alive(listener)
        before = self.native_phase(control, role='health-client', journal_role=prefix + '-health', boot=x['control_boot'], admission=x['control_admission'],
            sequence=1, case=x['before_case'], opcode=control_opcode, control=control_dir, reports=report_dir,
            fixed_ports=control_ports, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(30)))
        live.require(phase_passed(before, x['before_case']), 'wrong_port_before_health')
        row, _ = read_when_closed(self.api, budget, listener_dir / 'receipt-0001.json', listener['info'].hProcess, budget.cutoff(30))
        row = receipt(row, listener, c, boot=x['listener_boot'], port=target, index=1, role='health-listener')
        live.require(row['case_id'] == x['before_case'] and receipt_passed(row, 'wrong-port')
            and row['peer_port'] == before['network']['local_port'], 'wrong_port_before_receipt')
        public['healthy_before'] = True
        self.phase = 'wrong-peer' if peer else 'wrong-port'
        self.refresh_profiles(); self.alive(listener)
        self.wrong_port_deadline = min(budget.read() + 3 * c['frequency'], budget.cutoff(30))
        if peer: self.wrong_peer_deadline = self.wrong_port_deadline
        wrong = self.native_phase(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'],
            sequence=3, case=x['wrong_case'], opcode=4 if peer else 3, control=root / 'selected-control', reports=root / 'selected',
            fixed_ports=fixed, end=self.wrong_port_deadline)
        public.update(attempted=wrong['network']['connect_attempted'], connected=wrong['network']['connect_completed'])
        self.value['violations'][violation] |= wrong['network']['connect_completed']
        self.wrong_port_denied = connect_denied(wrong)
        peer_timeout = peer and bounded_connect_timeout(wrong, c['frequency'], c['deadline_qpc'])
        if peer: public['timed_out'] = bool(peer_timeout)
        live.require(peer_timeout or wrong['failure'] is None and wrong['phase_qpc'][2] < wrong['phase_qpc'][1]
            and all(wrong['network'][key] for key in ('wsa_startup','inheritance_cleared','socket_created','connect_attempted','wsa_cleanup'))
            and wrong['network']['socket_close'] == 'confirmed', 'wrong_port_observation')
        self.phase = 'health'
        self.selected_family_alive(); self.alive(listener)
        after = self.native_phase(control, role='health-client', journal_role=prefix + '-health', boot=x['control_boot'], admission=x['control_admission'],
            sequence=2, case=x['after_case'], opcode=control_opcode, control=control_dir, reports=report_dir,
            fixed_ports=control_ports, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(30)))
        live.require(phase_passed(after, x['after_case']), 'wrong_port_after_health')
        self.finish_client(control, role='health-client', journal_role=prefix + '-health', boot=x['control_boot'], admission=x['control_admission'], sequence=3,
            profile='agentic-pncs' if psec else 'ordinary', control=control_dir, reports=report_dir, fixed_ports=control_ports, count=2)
        if psec:
            g = self.tasks[prefix + '-g-live']; self.wait(g, budget.cutoff(30)); self.finish_auxiliary(prefix + '-system-conhost')
            self.verify_actual_tier(g, prefix + '_')
        digest = live.publish_fixture_finish(listener_dir, budget=budget, run=c['run'], boot_case=x['listener_boot'])
        self.go_records.append(dict(role=prefix + '-listener', sequence=1, opcode=255, case=x['listener_boot'],
            phase_deadline=c['deadline_qpc'], path=('b-front' if peer else 'front') + '/finish.bin', sha256=digest))
        self.wait(listener, budget.cutoff(30))
        seen = []
        for index in range(1, 9):
            path = listener_dir / ('receipt-%04d.json' % index)
            if not path.exists(): break
            row = receipt(live.decode(live.local.bounded(path, live.MAX_NATIVE)), listener, c, boot=x['listener_boot'],
                port=target, index=index, role='health-listener')
            if row['case_id'] == x['wrong_case']:
                public['forbidden_nonce_received'] = True
                self.value['violations'][violation] = True
            else:
                live.require(receipt_passed(row, 'wrong-port'), 'wrong_port_receipt')
            if row['case_id'] == x['after_case']:
                live.require(row['peer_port'] == after['network']['local_port'], 'wrong_port_after_tuple')
            seen.append(row['case_id'])
        expected = [x['before_case'], x['after_case']]
        if x['wrong_case'] in seen: expected.insert(1, x['wrong_case'])
        live.require(seen == expected, 'wrong_port_receipt_cases')
        listener_final(live.decode(live.local.bounded(listener_dir / ('final.json' if peer else 'q-final.json'), live.MAX_NATIVE)), listener, c,
            boot=x['listener_boot'], port=target, receipt_count=len(expected), role='health-listener', profile='pncs')
        public.update(healthy_after=True, connected=self.value['violations'][violation], observation_complete=True,
            denied_by_access=self.wrong_port_denied and not self.value['violations'][violation])

    def publish_phase(self, task, *, role, boot, admission, sequence, case, opcode, control, reports, fixed_ports, end, journal_role=None):
        self.alive(task)
        if role == 'selected-client': self.selected_family_alive()
        control_psec = (journal_role == 'q-health' and self.config['wrong_port_extension']['profile'] == 'same-peer-wrong-port-psec-control-v1'
            or journal_role == 'b-health' and 'wrong_peer_extension' in self.config)
        if control_psec:
            self.refresh_profiles(); self.selected_family_alive('b' if journal_role == 'b-health' else 'q')
        if self.mode != 'strict' and (role == 'selected-client' or control_psec):
            maintenance.validate_profiles_observation(self.maintenance.last_observation, 'profiles-status', self.mode,
                self.config['start_qpc'], self.config['frequency'], self.config['deadline_qpc'], self.budget.read())
        issued_qpc = self.budget.read()
        if opcode==6:
            x=self.config['dns_extension']
            label=next((key for key in ('before','selected','after') if case==x[key+'_case']),None)
            live.require(label is not None and ((label=='selected' and role=='selected-client' and task is self.tasks['selected'])
                or label!='selected' and role=='health-client' and task is self.tasks['health']),'dns_go_role')
            self.dns_gate(label,now=issued_qpc)
        digest = live.publish_go(control, budget=self.budget, run=self.config['run'], case=case, sequence=sequence,
            opcode=opcode, frequency=self.config['frequency'], deadline=self.config['deadline_qpc'],
            fixed_ports=fixed_ports, admission=admission, phase_deadline=end)
        record = dict(role=role if journal_role is None else journal_role, sequence=sequence, opcode=opcode, case=case,
            phase_deadline=end, path=(control / ('phase-%04d.bin' % sequence)).relative_to(self.root).as_posix(), sha256=digest)
        self.go_records.append(record)
        return dict(task=task, role=role, boot=boot, admission=admission, sequence=sequence, case=case, opcode=opcode,
            reports=reports, fixed_ports=dict(fixed_ports), end=end, record=record, issued_qpc=issued_qpc)

    def collect_phase(self, ticket):
        task, end, sequence = ticket['task'], ticket['end'], ticket['sequence']
        # Collect a bounded late failure record without extending network work.
        collect_end = min(end + self.config['frequency'], self.budget.cutoff(20))
        if ticket['opcode']==6:self.observe_dns_event()
        try:
            value, _ = read_when_closed(self.api, self.budget, ticket['reports'] / ('phase-%04d.json' % sequence), task['info'].hProcess, collect_end)
        finally:
            if ticket['opcode']==6:self.observe_dns_event()
        if ticket['opcode']==6:
            # The receiver event is sampled before parsing or trusting native output.
            self.observe_dns_fixture()
            return live.dns.phase(value,task,self.config,role=ticket['role'],boot=ticket['boot'],admission=ticket['admission'],
                sequence=sequence,case=ticket['case'],phase_deadline=end,identity_check=native_identity)
        target = ticket['fixed_ports']['origin' if ticket['opcode'] == 2 else 'wrong_port' if ticket['opcode'] == 3 else 'proxy']
        return client_phase(value, task, self.config, role=ticket['role'], boot=ticket['boot'], admission=ticket['admission'],
            sequence=sequence, case=ticket['case'], operation=live.OPS[ticket['opcode']], target_port=target, phase_deadline=end)

    def native_phase(self, task, **fields):
        return self.collect_phase(self.publish_phase(task, **fields))

    def observe_dns_event(self):
        if self.dns_fixture is None:return None
        public,ledger=self.value['dns_extension'],self.dns_ledger
        # This independent sticky event does not depend on snapshot/JSON success.
        hit=self.dns_fixture.query_observed.is_set()
        public['selected_wire_query_observed'] |= hit
        self.value['violations']['selected_dns_query_observed'] |= hit
        ledger['selected_wire_query_observed'] |= hit
        return hit

    def observe_dns_fixture(self):
        if self.dns_fixture is None:return None
        self.observe_dns_event()
        public,ledger=self.value['dns_extension'],self.dns_ledger
        snapshot=self.dns_fixture.snapshot(deadline=time.monotonic()+self.budget.remaining_ms(self.budget.cutoff(20),500)/1000)
        live.dns.receiver(snapshot)
        hit=snapshot['selected_query_observed']
        public['selected_wire_query_observed'] |= hit
        self.value['violations']['selected_dns_query_observed'] |= hit
        ledger['selected_wire_query_observed'] |= hit
        live.require(len(ledger['fixture_snapshots'])<8,'dns_snapshot_bound')
        ledger['fixture_snapshots'].append(dict(observed_qpc=self.budget.read(),value=snapshot))
        return snapshot

    def dns_gate(self,label,*,now=None):
        c=self.config;row=self.tasks['dns-inventory'];now=self.budget.read() if now is None else now
        live.dns.inventory(self.dns_inventory,run=c['dns_extension']['inventory_run'],pid=row['pid'],frequency=c['frequency'],
            start=c['start_qpc'],deadline=c['deadline_qpc'],now=now)
        live.require(len(self.dns_ledger['inventory_gates'])<4,'dns_inventory_gate_bound')
        self.dns_ledger['inventory_gates'].append(dict(label=label,qpc=now))
        return now

    def dns_run(self,selected,health,fixed):
        if 'dns_extension' not in self.config:return
        self.phase='dns';c,root,budget=self.config,self.root,self.budget;x=c['dns_extension'];public=self.value['dns_extension']
        live.require(self.value['checks']['positive'] and self.value['checks']['direct_deny']
            and self.value['checks']['same_selected'],'dns_positive_first')
        self.selected_family_alive();self.alive(health)
        work=self.directory('tools/dns-inventory')
        env=dict(v.split('=',1) for v in self.api.native.environment(work).rstrip('\0').split('\0'))
        powershell=launcher.checked_path(Path(env['SystemRoot'])/'System32/WindowsPowerShell/v1.0/powershell.exe')
        script=launcher.checked_path(root/live.dns.INVENTORY,inside=root)
        live.require(live.sha(live.local.bounded(script,256*1024))==c['source_hashes'][live.dns.INVENTORY],'dns_inventory_source')
        command=[str(powershell),'-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(script),'-Run',x['inventory_run'],
            '-Frequency',str(c['frequency']),'-StartQpc',str(c['start_qpc']),'-DeadlineQpc',str(c['deadline_qpc'])]
        row=self.task('dns-inventory',command,work,image_hash=live.sha(live.local.bounded(powershell,8*1024*1024)))
        self.resume(row);self.wait(row,min(budget.read()+10*c['frequency'],budget.cutoff(35)))
        record=read_dns_record(root,'tools/dns-inventory/stdout',32768)
        live.require(not live.local.bounded(work/'stderr',32768),'dns_inventory_stderr')
        self.dns_inventory=live.decode(record['text'].encode('ascii'));self.dns_ledger['inventory']=record
        self.dns_gate('bind');public['inventory_verified']=True;public['inventory_before_bind']=True
        cutoff=budget.cutoff(25);budget.require_ms(cutoff);self.dns_ledger.update(fixture_attempted=True,fixture_deadline_qpc=cutoff)
        self.dns_fixture=live.dns.fixture.DnsCasesFixture(dict(before=x['before_case'],selected=x['selected_case'],after=x['after_case']),
            deadline=time.monotonic()+budget.remaining_ms(cutoff)/1000)
        live.require(self.dns_fixture.bind_address=='127.0.0.1' and self.dns_fixture.bind_port==53
            and self.dns_fixture.allowed_peers==('127.0.0.1',),'dns_fixture_endpoint')
        live.require(self.dns_fixture.start()==53,'dns_fixture_ready');public['fixture_ready']=True;self.dns_ledger['fixture_ready']=True
        self.observe_dns_fixture()
        for label,task,role,sequence,case in (('before',health,'health-client',3,x['before_case']),
                ('selected',selected,'selected-client',3,x['selected_case']),('after',health,'health-client',4,x['after_case'])):
            self.refresh_profiles();self.selected_family_alive();self.alive(task)
            end=min(budget.read()+2*c['frequency'],cutoff);budget.require_ms(end)
            directory='selected' if role=='selected-client' else 'health'
            result=self.native_phase(task,role=role,boot=c['boot_case'] if directory=='selected' else c['admission_nonce'],
                admission=c['admission_nonce'] if directory=='selected' else c['maintenance_nonce'],sequence=sequence,case=case,opcode=6,
                control=root/(directory+'-control'),reports=root/directory,fixed_ports=fixed,end=end)
            self.dns_ledger['phases'].append(dict(label=label,record=read_dns_record(root,directory+'/phase-%04d.json'%sequence)))
            if label=='selected':
                api=result['dns']['result'];public.update(selected_attempted=api['called'],selected_completed=api['completed'],
                    selected_pending=api['pending'],selected_late=not api['within_deadline'] or result['phase_qpc'][2]>=end,
                    selected_access_denial_observed=live.dns.access_denial(result))
                live.require(live.dns.timely(result),'dns_selected_incomplete')
            snapshot=self.observe_dns_fixture()
            if label!='selected':
                live.require(live.dns.positive(result) and live.dns.case_positive(snapshot,label),'dns_ordinary_control')
                public['ordinary_'+label+'_verified']=True
        public.update(inventory_before_each_query=True,same_selected=True,observation_complete=True)

    def finish_dns_fixture(self):
        if self.dns_fixture is None:return self.dns_ledger is None or not self.dns_ledger['fixture_attempted']
        # Called only after workload cleanup; keep observing until held queries exit.
        try:
            self.observe_dns_fixture()
        except BaseException:pass
        try:
            result=self.dns_fixture.finish(deadline=time.monotonic()+self.budget.remaining_ms(self.budget.cutoff(15))/1000)
        finally:self.observe_dns_event()
        live.dns.receiver(result,final=True)
        launcher.write_private_bytes(self.root/'dns-fixture-final.json',live.encode(result))
        self.dns_ledger['fixture_final']=result
        public=self.value['dns_extension'];public['receiver_complete']=result['counts'] is not None and result['thread_stopped']
        public['fixture_cleanup']=result['cleanup_confirmed']
        return result['cleanup_confirmed']

    def death_run(self, selected, fixed, exe, environment):
        if 'death_extension' not in self.config: return
        c, root, api, budget = self.config, self.root, self.api, self.budget
        x, public, ledger = c['death_extension'], self.value['death_extension'], self.death_ledger
        self.phase = 'death'
        live.require(self.value['checks']['positive'] and self.value['checks']['direct_deny'] and self.value['checks']['same_selected']
            and all(self.tasks[k]['exited'] and self.tasks[k]['exit_code'] == 0 for k in ('front', 'relay')), 'death_positive_first')
        self.selected_family_alive(); self.alive(self.tasks['origin'])
        start = budget.read(); end = start + 10*c['frequency']
        live.require(end < budget.cutoff(35), 'death_pair_capacity')
        ledger.update(pair_start=start, pair_deadline=end)
        pipes = helpers.OneShotHandles(api.close); self.scoped_owners.append(pipes)
        front_read, relay_write = api.owned_pipe(pipes); relay_read, front_write = api.owned_pipe(pipes)
        front_dir = self.directory('front/death'); relay_dir = self.directory('death-relay')
        front_argv = [str(exe), 'pipe-live-front', c['run'], x['death_case'], str(front_dir/'final.json'),
            str(front_read), str(front_write), str(start), str(c['frequency']), str(end), self.parent['sid'], self.profile['sid'],
            '0', str(fixed['origin']), str(fixed['proxy']), str(front_dir/'ready.json'), str(root/'selected-control')]
        relay_argv = [str(exe), 'pipe-relay', c['run'], x['death_case'], str(relay_dir/'final.json'),
            str(relay_read), str(relay_write), str(start), str(c['frequency']), str(end), self.parent['sid'], 'none', '0', str(fixed['origin'])]
        front = self.task('death-front', front_argv, front_dir, profile=self.profile['sid'], handles=[front_read, front_write], environment=environment)
        budget.require_ms(end)
        relay = self.task('death-relay', relay_argv, relay_dir, handles=[relay_read, relay_write])
        budget.require_ms(end)
        for handle in (front_read, relay_write, relay_read, front_write): pipes.close(handle)
        budget.require_ms(end); self.resume(front); budget.require_ms(end); self.resume(relay); budget.require_ms(end)
        ready, _ = read_when_closed(api, budget, front_dir/'ready.json', front['info'].hProcess, end)
        ready_listener(ready, front, c, role='pipe-live-front', boot=x['death_case'], profile='pncs', start=start, deadline=end)
        live.require(ready['port'] == fixed['proxy'] and front['identity']['appcontainer_sid'] == self.tasks['front']['identity']['appcontainer_sid'], 'death_same_peer_port')
        public['pair_held'] = True
        self.refresh_profiles()
        ticket = self.publish_phase(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=3,
            case=x['death_case'], opcode=5, control=root/'selected-control', reports=root/'selected', fixed_ports=fixed, end=end)
        ledger['ticket'] = dict(record=ticket['record'], issued_qpc=ticket['issued_qpc']); public['request_published'] = True
        held, _ = read_when_closed(api, budget, root/'origin/death-held.json', self.tasks['origin']['info'].hProcess, end)
        origin_death_ack(held, self.tasks['origin'], c, lower=ticket['issued_qpc'], upper=budget.read())
        live.require(held['port'] == fixed['origin'], 'death_origin_port')
        ledger['held_ack'] = read_death_record(root, 'origin/death-held.json'); public['origin_held_ack'] = True
        origin = self.tasks['origin']; self.alive(origin); self.alive(relay)
        before = budget.read(); budget.require_ms(end)
        def held_binding():
            for row in (origin, relay):
                budget.require_ms(end); self.alive(row)
                live.require(api.process_id(row['info'].hProcess) == row['pid'], 'death_exact_pid')
                api.verify_job(self.job, row['info'].hProcess)
                # Each temporary open has its own generation ledger. Windows
                # may reuse the numeric handle after a confirmed close.
                scope = helpers.OneShotHandles(api.close); self.scoped_owners.append(scope)
                live.verify_exact_guard_member(api, row['info'].hProcess, c['guard_job_name'], owners=scope)
                live.require(scope.confirmed_closed, 'death_guard_query_close')
        held_binding()
        flow = api.owned_halfclosed_tcp_flow(relay['pid'], held['peer_port'], fixed['origin'], budget, end)
        held_binding(); budget.require_ms(end)
        ledger['relay_binding'] = dict(pid=relay['pid'], created=relay['created'], before_qpc=before, after_qpc=budget.read(), flow=flow,
            origin_alive=True, relay_alive=True, exact_workload_job=True, exact_outer_job=True, query_handles_closed=True)
        public['relay_alive_verified'] = True
        intent = dict(schema_version=1, stage='model2-death-stop-intent', run=c['run'], case=x['death_case'],
            pid=relay['pid'], created=relay['created'], actor_sha256=c['actor_sha256'], frequency=c['frequency'],
            deadline_qpc=c['deadline_qpc'], issued_qpc=budget.read(), held_ack_sha256=ledger['held_ack']['sha256'],
            go_sha256=ticket['record']['sha256'], relay_flow_sha256=live.sha(live.encode(flow)))
        write_death_stop_intent(root/'death-stop-intent.json', live.encode(intent))
        ledger['stop_intent'] = read_death_record(root, 'death-stop-intent.json'); ledger['stop_persisted_qpc'] = budget.read()
        live.require(live.decode(ledger['stop_intent']['text'].encode('ascii')) == intent, 'death_stop_readback')
        public['stop_intent_persisted'] = True
        self.alive(relay); self.alive(origin); budget.require_ms(end)
        ledger['terminate_requested'] = True
        api.terminate_process(relay['info'].hProcess)
        ledger['terminate_returned'] = True
        self.wait(relay, end, code=1); ledger.update(exit_code=relay['exit_code'], exit_qpc=budget.read())
        public['relay_stop_confirmed'] = True
        self.wait(front, end, code=5)
        front_value = live.decode(live.local.bounded(front_dir/'final.json', live.MAX_NATIVE))
        validate_death_front(front_value, front, c, fixed['proxy'], fixed['origin'], start, end)
        ledger['front_report'] = read_death_record(root, 'front/death/final.json'); public['front_failed_closed'] = True
        client = self.collect_phase(ticket)
        live.require(death_client_failed_closed(client) and front_value['listener']['peer_port'] == client['network']['local_port'], 'death_client_failure')
        ledger['client_report'] = read_death_record(root, 'selected/phase-0003.json'); public['client_failed_closed'] = True
        self.selected_family_alive(); self.alive(origin)
        release_qpc = budget.read(); digest = live.publish_fixture_release(root/'origin-control', budget=budget, run=c['run'], death_case=x['death_case'])
        release = dict(role='health-origin-release', sequence=1, opcode=254, case=x['death_case'], phase_deadline=c['deadline_qpc'],
            path='origin-control/release.bin', sha256=digest)
        self.go_records.append(release); ledger['release_go'] = dict(record=release, issued_qpc=release_qpc)
        released, _ = read_when_closed(api, budget, root/'origin/death-release.json', origin['info'].hProcess, budget.cutoff(30))
        origin_death_ack(released, origin, c, released=True, held=held, lower=release_qpc, upper=budget.read())
        ledger['release_ack'] = read_death_record(root, 'origin/death-release.json'); public['origin_release_ack'] = True
        self.alive(origin); self.selected_family_alive(); self.refresh_profiles()
        self.death_after_deadline = min(budget.read()+3*c['frequency'], budget.cutoff(30))
        after = self.native_phase(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=4,
            case=x['after_direct_case'], opcode=2, control=root/'selected-control', reports=root/'selected', fixed_ports=fixed, end=self.death_after_deadline)
        ledger['after_direct_report'] = read_death_record(root, 'selected/phase-0004.json')
        public['after_direct_attempted'] = after['network']['connect_attempted']; public['after_direct_connected'] |= after['network']['connect_completed']
        self.value['violations']['fallback_after_death'] |= after['network']['connect_completed']
        self.death_after_denied = connect_denied(after)
        live.require(after['failure'] is None and after['phase_qpc'][2] < after['phase_qpc'][1]
            and all(after['network'][k] for k in ('wsa_startup', 'wsa_cleanup', 'socket_created', 'inheritance_cleared', 'connect_attempted'))
            and after['network']['socket_close'] == 'confirmed', 'death_after_observation')
        self.selected_family_alive(); self.alive(origin); public['same_selected'] = True

    def finish_client(self, task, *, role, boot, admission, sequence, profile, control, reports, fixed_ports, count, journal_role=None):
        self.alive(task)
        end = self.budget.cutoff(30)
        digest = live.publish_go(control, budget=self.budget, run=self.config['run'], case=boot, sequence=sequence, opcode=255,
            frequency=self.config['frequency'], deadline=self.config['deadline_qpc'], fixed_ports=fixed_ports,
            admission=admission, phase_deadline=end)
        self.go_records.append(dict(role=role if journal_role is None else journal_role, sequence=sequence, opcode=255, case=boot,
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
        self.local_folder = folder
        front_environment = api.front_environment(folder, metadata)
        live.require(launcher.child_environment_admitted(metadata), 'front_environment')

        # The ordinary origin stays alive through all selected phases and controls.
        self.phase = 'health'
        origin_boot = c['health_cases'][0]
        self.origin_boot = origin_boot
        origin_argv = [str(exe), 'health-origin', c['run'], origin_boot, str(root / 'origin/final.json'),
            str(root / 'origin/ready.json'), str(root / 'origin-control'), str(c['frequency']), str(c['start_qpc']),
            str(c['deadline_qpc']), '0', self.parent['sid'], 'none', '8']
        if 'death_extension' in c:
            origin_argv[1] = 'health-origin-withhold'; origin_argv.append(c['death_extension']['death_case'])
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
        self.phase = 'health'
        self.wrong_port_setup(exe, fixed, front_environment)

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
            job=self.job, image=exe, image_hash=c['actor_sha256'], parent=self.parent, capability_profile='agentic-pncs', catalog=self.catalog,
            diagnostic_guard_name=c['guard_job_name'], diagnostic_scoped_owners=self.scoped_owners,
            selected_admission=c.get('selected_admission'), auxiliary_register=self.register_auxiliary)
        if 'auxiliary' in held:
            auxiliary = held['auxiliary']
            self.tasks['system-conhost'].update(assigned=True, identity=auxiliary['identity'], capabilities=auxiliary['capabilities'],
                image_verified=True, resumed=True, admission_qpc=budget.read())
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
        self.wrong_port_run(selected, fixed)
        self.phase = 'health'
        self.wrong_peer_setup(exe, fixed, front_environment)
        self.wrong_port_run(selected, fixed, peer=True)
        self.death_run(selected, fixed, exe, front_environment)
        self.dns_run(selected,health_task,fixed)
        self.finish_client(selected, role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'],
            sequence=5 if 'death_extension' in c else 4 if any(k in c for k in ('wrong_port_extension','wrong_peer_extension','dns_extension')) else 3,
            profile='agentic-pncs', control=root / 'selected-control', reports=root / 'selected', fixed_ports=fixed,
            count=4 if 'death_extension' in c else 3 if any(k in c for k in ('wrong_port_extension','wrong_peer_extension','dns_extension')) else 2)
        self.wait(g, budget.cutoff(30))
        self.finish_auxiliary('system-conhost')
        self.verify_actual_tier(g)

        self.phase = 'health'
        self.alive(origin_task)
        after = self.native_phase(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=5 if 'dns_extension' in c else 3, case=c['health_cases'][2], opcode=2, control=root / 'health-control', reports=root / 'health',
            fixed_ports=fixed, end=min(budget.read() + 3 * c['frequency'], budget.cutoff(30)))
        live.require(phase_passed(after, c['health_cases'][2]), 'origin_after_health')
        self.finish_client(health_task, role='health-client', boot=health_boot, admission=health_admission,
            sequence=6 if 'dns_extension' in c else 4, profile='ordinary', control=root / 'health-control', reports=root / 'health', fixed_ports=fixed,
            count=5 if 'dns_extension' in c else 3)
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
            death_case = c.get('death_extension', {}).get('death_case')
            after_case = c.get('death_extension', {}).get('after_direct_case')
            if after_case is not None and item['case_id'] == after_case:
                v['violations']['fallback_after_death'] = True; v['death_extension']['after_forbidden_nonce_received'] = True
            if death_case is not None and item['case_id'] == death_case:
                live.require(death_receipt_passed(item), 'death_origin_receipt')
            elif self.mode == 'strict' or item['case_id'] != c['direct_case'] and (after_case is None or item['case_id'] != after_case):
                live.require(receipt_passed(item), 'origin_receipt')
            observed_cases.append(item['case_id'])
            if self.death_ledger is not None:
                self.death_ledger['origin_receipts'].append(read_death_record(root, ('origin/receipt-%04d.json' % index)))
        expected_cases = [c['health_cases'][0], c['positive_case'], c['health_cases'][1]]
        if self.mode != 'strict' and c['direct_case'] in observed_cases:
            expected_cases.append(c['direct_case'])
        if 'death_extension' in c:
            expected_cases.append(c['death_extension']['death_case'])
            if c['death_extension']['after_direct_case'] in observed_cases: expected_cases.append(c['death_extension']['after_direct_case'])
        expected_cases.append(c['health_cases'][2])
        live.require(observed_cases == expected_cases, 'origin_case_binding')
        listener_final(live.decode(live.local.bounded(root / 'origin/final.json', live.MAX_NATIVE)), origin_task, c,
            boot=origin_boot, port=origin_port, receipt_count=len(expected_cases))
        v['observations']['origin_nonce_received'] = c['positive_case'] in observed_cases
        v['checks']['origin_healthy'] = True
        if 'death_extension' in c:
            d = v['death_extension']; d['origin_healthy_after_release'] = True
            d['after_direct_denied_by_access'] = self.death_after_denied and not d['after_direct_connected'] and not d['after_forbidden_nonce_received']
            d['observation_complete'] = True
        if self.mode == 'strict':
            live.require(v['checks']['direct_deny'] and not any(v['violations'].values()), 'direct_deny')
        else:
            v['diagnostic'].update(forbidden_nonce_received=v['violations']['forbidden_receiver_accepted'],
                direct_denied_by_access=v['checks']['direct_deny'] and not v['violations']['forbidden_receiver_accepted'],
                observation_complete=True)
        finish_peer_observation(v)
        if 'dns_extension' in c and not v['dns_extension']['selected_access_denial_observed']:
            v['failure']='dns'

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
        self.observe_dns_event()
        origin_task = self.tasks.get('origin')
        if origin_task is not None and origin_task['exited'] and self.fixed_ports is not None:
            if self.death_ledger is not None: self.death_ledger['origin_receipts'] = []
            for index in range(1, 9):
                path = root / ('origin/receipt-%04d.json' % index)
                if not path.exists():
                    continue
                try:
                    row = receipt(live.decode(live.local.bounded(path, live.MAX_NATIVE)), origin_task, c,
                        boot=self.origin_boot, port=self.fixed_ports['origin'], index=index)
                    if row['case_id'] == c['direct_case']:
                        v['violations']['forbidden_receiver_accepted'] = True
                    if 'death_extension' in c and row['case_id'] == c['death_extension']['after_direct_case']:
                        v['violations']['fallback_after_death'] = True; v['death_extension']['after_forbidden_nonce_received'] = True
                    if self.death_ledger is not None and index == len(self.death_ledger['origin_receipts'])+1:
                        self.death_ledger['origin_receipts'].append(read_death_record(root, 'origin/receipt-%04d.json' % index))
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
        if 'death_extension' in c and selected is not None and selected['exited'] and self.death_after_deadline is not None:
            path = root/'selected/phase-0004.json'
            if path.exists():
                try:
                    row = client_phase(live.decode(live.local.bounded(path, live.MAX_NATIVE)), selected, c,
                        role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=4,
                        case=c['death_extension']['after_direct_case'], operation='direct-tcp', target_port=self.fixed_ports['origin'],
                        phase_deadline=self.death_after_deadline)
                    v['death_extension']['after_direct_connected'] |= row['network']['connect_completed']
                    v['violations']['fallback_after_death'] |= row['network']['connect_completed']
                except BaseException: pass
            if v['violations']['fallback_after_death']: v['death_extension']['after_direct_denied_by_access'] = False
        for key, prefix, target_key, operation, violation, end in (
            ('wrong_port_extension', 'q', 'wrong_port', 'wrong-port', 'wrong_port_connected', self.wrong_port_deadline),
            ('wrong_peer_extension', 'b', 'proxy', 'wrong-peer', 'wrong_peer_connected', self.wrong_peer_deadline)):
            if key not in c: continue
            x, public = c[key], v[key]
            listener_dir = root / ('b-front' if prefix == 'b' else 'front')
            listener = self.tasks.get(prefix + '-listener')
            if listener is not None and listener['exited'] and self.fixed_ports is not None:
                for index in range(1, 9):
                    path = listener_dir / ('receipt-%04d.json' % index)
                    if not path.exists(): continue
                    try:
                        row = receipt(live.decode(live.local.bounded(path, live.MAX_NATIVE)), listener, c,
                            boot=x['listener_boot'], port=self.fixed_ports[target_key], index=index, role='health-listener')
                        if row['case_id'] == x['wrong_case']:
                            public['forbidden_nonce_received'] = True
                            v['violations'][violation] = True
                    except BaseException: pass
            if selected is not None and selected['exited'] and end is not None:
                path = root / 'selected/phase-0003.json'
                if path.exists():
                    try:
                        row = client_phase(live.decode(live.local.bounded(path, live.MAX_NATIVE)), selected, c,
                            role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=3,
                            case=x['wrong_case'], operation=operation, target_port=self.fixed_ports[target_key],
                            phase_deadline=end)
                        public['attempted'] |= row['network']['connect_attempted']
                        v['violations'][violation] |= row['network']['connect_completed']
                        if key == 'wrong_peer_extension':
                            public['timed_out'] |= bounded_connect_timeout(row, c['frequency'], c['deadline_qpc'])
                    except BaseException: pass
            public['connected'] = v['violations'][violation]
            if public['connected'] or public['forbidden_nonce_received'] or public.get('timed_out', False): public['denied_by_access'] = False

    def cleanup(self):
        api, budget, root = self.api, self.budget, self.root
        self.phase = 'cleanup'
        clean = False
        empty = False
        for role in ('system-conhost', 'q-system-conhost', 'b-system-conhost'):
            auxiliary = self.tasks.get(role)
            if auxiliary is None or auxiliary['exited']: continue
            try:
                auxiliary['exited'] = api.wait(auxiliary['info'].hProcess, 0) is True
                if auxiliary['exited']:
                    auxiliary['exit_code'] = api.exit_code(auxiliary['info'].hProcess)
                    auxiliary['natural_exit_observed'] = True
                else:
                    auxiliary['stop_requested'] = True
                    launcher.write_private_bytes(root / ('auxiliary-stop-intent.json' if role == 'system-conhost' else role[0] + '-auxiliary-stop-intent.json'), live.encode(dict(schema_version=1,
                        stage='system-conhost-stop-intent', run=self.config['run'], pid=auxiliary['pid'],
                        created=auxiliary['created'], deadline_qpc=self.config['deadline_qpc'])))
            except BaseException:
                pass
        try:
            clean, empty, _ = ac._cleanup(api, live.CleanupView(budget, budget.cutoff(20)), self.job, self.children,
                live.origin.CombinedLedgers(self.owners, *self.scoped_owners))
        except BaseException:
            clean = False
        all_exited = all(not row['attempted'] or row['info'].hProcess and row['exited'] for row in self.children)
        if self.dns_ledger is not None:
            try: clean = self.finish_dns_fixture() and clean
            except BaseException: clean = False
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
                if self.b_profile['created']:
                    if self.b_profile_ledger['acl_attempted']:
                        owned_tree(root)
                        live.require(ac.ac_profile_sid(self.b_profile['sid']), 'b_cleanup_sid')
                        self.tool([str(self.fixed_icacls()), str(root), '/remove:g', '*' + self.b_profile['sid'], '/T', '/Q'],
                            'b-acl-remove', cleanup=True)
                        for path in owned_tree(root):
                            budget.require_ms(budget.cutoff(3))
                            live.require(api.acl_read(path, self.b_profile['sid']) == [], 'b_acl_remove')
                    self.b_profile_ledger['acl_removed'] = True
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
                    if self.b_profile['created']:
                        live.require(self.b_profile_ledger['acl_removed'], 'b_cleanup_gate')
                        api.delete_profile(self.b_profile_ledger['name'])
                        self.b_profile_ledger['deleted'] = True
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
        b_sid_released = False
        try:
            api.release_profile_sid(self.b_profile)
            b_sid_released = True
            self.b_profile_ledger['released'] = True
        except BaseException: pass
        if self.b_profile['attempted'] and (not self.b_profile['returned'] or not self.b_profile['created'] or self.b_profile['created'] and
                not self.b_profile_ledger['deleted']):
            controls_clean = False
        if self.profile['attempted'] and not self.profile['returned']:
            controls_clean = False
        self.cleanup_ok = bool(clean and empty and all_exited and rule_quiescent and controls_clean and sid_released and b_sid_released
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
        tasks = [dict(role=name, **{k: row[k] for k in keys}, **({k: row[k] for k in
            ('natural_exit_observed', 'stop_requested', 'finish_order_verified')} if name in ('system-conhost', 'q-system-conhost', 'b-system-conhost') else {}))
            for name, row in self.tasks.items()]
        native_paths = ['front/ready.json', 'front/final.json', 'relay/final.json', 'origin/ready.json', 'origin/final.json',
            'health/ready.json', 'health/final.json', 'selected/ready.json', 'selected/final.json',
            'g-probe/stdout', 'g-probe/stderr', 'g-live/stdout', 'g-live/stderr']
        native_paths += ['origin/receipt-%04d.json' % i for i in range(1, 9)]
        native_paths += ['health/phase-%04d.json' % i for i in range(1, 4)]
        native_paths += ['selected/phase-%04d.json' % i for i in range(1, 3)]
        if 'wrong_port_extension' in c:
            native_paths += ['front/q-ready.json', 'front/q-final.json', 'q-health/ready.json', 'q-health/final.json',
                'q-health/phase-0001.json', 'q-health/phase-0002.json', 'selected/phase-0003.json']
            native_paths += ['front/receipt-%04d.json' % i for i in range(1, 9)]
            if c['wrong_port_extension']['profile'] == 'same-peer-wrong-port-psec-control-v1':
                native_paths += ['q-g-probe/stdout', 'q-g-probe/stderr', 'q-g-live/stdout', 'q-g-live/stderr', 'q-live-request.json']
        if 'wrong_peer_extension' in c:
            native_paths += ['b-front/ready.json', 'b-front/final.json', 'b-health/ready.json', 'b-health/final.json',
                'b-health/phase-0001.json', 'b-health/phase-0002.json', 'selected/phase-0003.json',
                'b-g-probe/stdout', 'b-g-probe/stderr', 'b-g-live/stdout', 'b-g-live/stderr', 'b-live-request.json']
            native_paths += ['b-front/receipt-%04d.json' % i for i in range(1, 9)]
        if 'death_extension' in c:
            native_paths += ['front/death/ready.json', 'front/death/final.json', 'origin/death-held.json', 'origin/death-release.json',
                'selected/phase-0003.json', 'selected/phase-0004.json', 'death-stop-intent.json']
        if 'dns_extension' in c:
            native_paths += ['tools/dns-inventory/stdout','tools/dns-inventory/stderr','dns-fixture-final.json',
                'health/phase-0004.json','health/phase-0005.json','selected/phase-0003.json']
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
        value = dict(schema_version=1, stage='model2-first-ownership', run=c['run'], controller_pid=os.getpid(),
            frequency=c['frequency'], start_qpc=c['start_qpc'], deadline_qpc=c['deadline_qpc'],
            source_sha256=c['source_sha256'], actor_sha256=c['actor_sha256'], manifest_sha256=c['manifest_sha256'],
            public_sha256=live.sha(live.encode(self.value)), tasks=tasks, selected_discovery=self.selected_discovery,
            public=self.value, fixed_ports=self.fixed_ports, go=self.go_records, native_reports=reports,
            maintenance=maintenance_record, rules=rule_record, cleanup=self.cleanup_ledger)
        if c.get('wrong_port_extension', {}).get('profile') == 'same-peer-wrong-port-psec-control-v1':
            value['q_selected_discovery'] = self.q_selected_discovery
        if 'wrong_peer_extension' in c:
            value['b_selected_discovery'] = self.b_selected_discovery
            value['b_profile'] = dict(self.b_profile_ledger)
        if 'death_extension' in c: value['death'] = self.death_ledger
        if 'dns_extension' in c: value['dns'] = self.dns_ledger
        return value


def read_dns_record(root,relative,limit=live.MAX_NATIVE):
    raw=live.local.bounded(launcher.checked_path(root/relative,inside=root),limit)
    return dict(path=relative,bytes=len(raw),sha256=live.sha(raw),text=raw.decode('ascii','strict'))


def validate_dns_ledger(value,c,tasks,go,reports,public):
    template=live.dns.blank_ledger(c)
    live.require(type(value) is dict and set(value)==set(template),'dns_journal_schema')
    for key in ('schema_version','stage','run','profile'):
        live.require(type(value[key]) is type(template[key]) and value[key]==template[key],'dns_journal_binding')
    descriptors={row['path']:row for row in reports}
    def record(row,path,limit=live.MAX_NATIVE):
        live.require(type(row) is dict and set(row)=={'path','bytes','sha256','text'} and row['path']==path
            and type(row['text']) is str,'dns_journal_record')
        raw=row['text'].encode('ascii','strict')
        live.require(live.integer(row['bytes'],1,limit) and len(raw)==row['bytes'] and live.sha(raw)==row['sha256']
            and descriptors.get(path)==dict(path=path,state='read',bytes=len(raw),sha256=live.sha(raw)),'dns_journal_digest')
        return live.decode(raw)
    p=public['dns_extension'];x=c['dns_extension'];inventory=None
    gates=value['inventory_gates'];live.require(type(gates) is list and len(gates)<=4,'dns_journal_gates')
    live.require(all(type(value[k]) is bool for k in ('fixture_attempted','fixture_ready','selected_wire_query_observed')),'dns_journal_bool')
    live.require(p['fixture_ready']==value['fixture_ready'],'dns_journal_ready')
    if value['inventory'] is not None:
        live.require('dns-inventory' in tasks,'dns_inventory_task')
        task=tasks['dns-inventory']
        live.require(task['resumed'] and task['image_verified'] and task['exited'] and task['exit_code']==0
            and launcher.token_is_ordinary(task['identity']) and task['capabilities']==[],'dns_inventory_held')
        command=task['command'];stage=Path(tasks['health']['command'][0]).parent.parent
        live.require(len(command)==15 and Path(command[0]).name.casefold()=='powershell.exe'
            and command[1:7]==['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',str(stage/live.dns.INVENTORY)]
            and command[7:]==['-Run',x['inventory_run'],'-Frequency',str(c['frequency']),'-StartQpc',str(c['start_qpc']),'-DeadlineQpc',str(c['deadline_qpc'])]
            and launcher.same_identity(task['identity'],tasks['health']['identity']),'dns_inventory_command')
        inventory=record(value['inventory'],'tools/dns-inventory/stdout',32768)
    else:live.require(not gates and not p['inventory_verified'] and not value['fixture_attempted'],'dns_inventory_missing')
    last=c['start_qpc']
    for row,label in zip(gates,('bind','before','selected','after')):
        live.require(type(row) is dict and set(row)=={'label','qpc'} and row['label']==label
            and live.integer(row['qpc'],last,c['deadline_qpc']-1),'dns_inventory_gate_clock')
        live.dns.inventory(inventory,run=x['inventory_run'],pid=tasks['dns-inventory']['pid'],frequency=c['frequency'],
            start=c['start_qpc'],deadline=c['deadline_qpc'],now=row['qpc']);last=row['qpc']
    live.require(not p['inventory_verified'] or inventory is not None and bool(gates),'dns_inventory_public')
    if gates:
        live.require(descriptors.get('tools/dns-inventory/stderr')==dict(path='tools/dns-inventory/stderr',state='read',bytes=0,sha256=live.sha(b'')),'dns_inventory_stderr_digest')
    live.require(not p['inventory_before_bind'] or inventory is not None and bool(gates),'dns_bind_public')
    if value['fixture_attempted']:
        live.require(inventory is not None and bool(gates) and value['fixture_deadline_qpc']==c['deadline_qpc']-25*c['frequency'],'dns_fixture_scope')
    else:live.require(value['fixture_deadline_qpc'] is None and not value['fixture_ready'],'dns_fixture_unattempted')
    snapshots=value['fixture_snapshots'];live.require(type(snapshots) is list and len(snapshots)<=8,'dns_snapshots')
    hit=False;previous=None
    for row in snapshots:
        live.require(type(row) is dict and set(row)=={'observed_qpc','value'} and live.integer(row['observed_qpc'],c['start_qpc'],c['deadline_qpc']),'dns_snapshot_clock')
        snapshot=live.dns.receiver(row['value']);hit |= snapshot['selected_query_observed']
        if previous is not None and previous['counts'] is not None and snapshot['counts'] is not None:
            live.require(all(snapshot['counts'][key]>=previous['counts'][key] for key in snapshot['counts']),'dns_snapshot_monotonic')
        previous=snapshot
    final=value['fixture_final']
    if final is not None:
        live.dns.receiver(final,final=True);hit |= final['selected_query_observed']
        raw=live.encode(final)
        live.require(descriptors.get('dns-fixture-final.json')==dict(path='dns-fixture-final.json',state='read',bytes=len(raw),sha256=live.sha(raw)),'dns_final_digest')
        live.require(value['fixture_attempted'] and p['receiver_complete']==(final['counts'] is not None and final['thread_stopped'])
            and p['fixture_cleanup']==final['cleanup_confirmed'],'dns_receiver_public')
        if previous is not None and previous['counts'] is not None and final['counts'] is not None:
            live.require(all(final['counts'][key]>=previous['counts'][key] for key in final['counts']),'dns_final_monotonic')
    else:live.require(not p['receiver_complete'] and not p['fixture_cleanup'],'dns_receiver_missing')
    live.require(p['selected_wire_query_observed']==value['selected_wire_query_observed']
        and (not hit or value['selected_wire_query_observed']),'dns_wire_sticky')
    phases=value['phases'];live.require(type(phases) is list and len(phases)<=3,'dns_phases')
    parsed={}
    for row,(label,role,sequence) in zip(phases,(('before','health-client',3),('selected','selected-client',3),('after','health-client',4))):
        live.require(type(row) is dict and set(row)=={'label','record'} and row['label']==label,'dns_phase_order')
        task=tasks['selected' if label=='selected' else 'health'];directory='selected' if label=='selected' else 'health'
        matches=[g for g in go if g['role']==role and g['sequence']==sequence]
        live.require(len(matches)==1 and matches[0]['opcode']==6 and matches[0]['case']==x[label+'_case'],'dns_phase_go')
        live.require(len(gates)>=('before','selected','after').index(label)+2,'dns_phase_gate')
        phase=live.dns.phase(record(row['record'],directory+'/phase-%04d.json'%sequence),task,c,role=role,
            boot=c['boot_case'] if label=='selected' else c['admission_nonce'],admission=c['admission_nonce'] if label=='selected' else c['maintenance_nonce'],
            sequence=sequence,case=x[label+'_case'],phase_deadline=matches[0]['phase_deadline'],identity_check=native_identity)
        parsed[label]=phase
        live.require(phase['phase_qpc'][0]>=gates[('before','selected','after').index(label)+1]['qpc'],'dns_phase_after_gate')
        # Late/unknown native observations remain raw evidence, never completion.
        if live.dns.timely(phase):
            live.require(phase['phase_qpc'][0]-inventory['end_qpc']<=5*c['frequency'],'dns_query_freshness')
    if 'selected' in parsed:
        phase=parsed['selected'];r=phase['dns']['result']
        live.require(p['selected_attempted']==r['called'] and p['selected_completed']==r['completed'] and p['selected_pending']==r['pending']
            and p['selected_late']==(not r['within_deadline'] or phase['phase_qpc'][2]>=phase['phase_qpc'][1])
            and p['selected_access_denial_observed']==live.dns.access_denial(phase),'dns_selected_public')
    else:live.require(not any(p[k] for k in ('selected_attempted','selected_completed','selected_pending','selected_late','selected_access_denial_observed')),'dns_selected_missing')
    for label in ('before','after'):
        if p['ordinary_'+label+'_verified']:
            live.require(label in parsed and live.dns.positive(parsed[label]) and any(live.dns.case_positive(row['value'],label) for row in snapshots),'dns_control_public')
    live.require(not p['inventory_before_each_query'] or len(gates)==4,'dns_all_gates')
    live.require(not p['same_selected'] or 'selected' in parsed and tasks['selected']['resumed'] and tasks['selected']['image_verified'],'dns_same_selected')
    live.require(not p['observation_complete'] or len(phases)==3 and len(gates)==4
        and p['ordinary_before_verified'] and p['ordinary_after_verified'] and p['same_selected'],'dns_observation_complete')
    if live.dns.ready(p):
        live.require(len(phases)==3 and final is not None and final['counts'] is not None and final['cleanup_confirmed']
            and final['error']=='none' and final['counts']['rejected']==final['counts']['send_failed']==0
            and final['cases']['selected']['matched_queries']==final['cases']['selected']['answers_sent']==0
            and all(live.dns.case_positive(final,k) for k in ('before','after')),'dns_complete_receiver')
    return value


def validate_family_discovery(discovery, tasks, helper_contract):
    if discovery is not None:
        dk = {'parent_pid', 'parent_created', 'first_children', 'second_children', 'query_created', 'held_created',
            'workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed'}
        if helper_contract is not None: dk.add('auxiliary')
        live.require(type(discovery) is dict and set(discovery) == dk and 'selected' in tasks and 'g-live' in tasks, 'journal_discovery')
        selected, parent = tasks['selected'], tasks['g-live']
        live.require(discovery['parent_pid'] == parent['pid'] and type(discovery['parent_pid']) is int
            and discovery['parent_created'] == parent['created'] and type(discovery['parent_created']) is int
            and type(discovery['first_children']) is list and type(discovery['second_children']) is list
            and discovery['first_children'] == discovery['second_children'] == sorted([selected['pid']] +
                ([tasks['system-conhost']['pid']] if helper_contract is not None and 'system-conhost' in tasks else []))
            and all(type(x) is int for x in discovery['first_children'] + discovery['second_children'])
            and type(discovery['query_created']) is int and type(discovery['held_created']) is int
            and discovery['query_created'] == discovery['held_created'] == selected['created'] >= parent['created']
            and all(discovery[k] is True for k in ('workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed')), 'journal_generation')
        if helper_contract is not None:
            auxiliary = discovery['auxiliary']
            live.require('system-conhost' in tasks and type(auxiliary) is dict and set(auxiliary) ==
                {'pid', 'created', 'query_created', 'held_created', 'workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed'},
                'journal_helper_discovery')
            helper = tasks['system-conhost']
            live.require(type(auxiliary['pid']) is int and auxiliary['pid'] == helper['pid'] and helper['pid'] != selected['pid']
                and auxiliary['created'] == auxiliary['query_created'] == auxiliary['held_created'] == helper['created'] >= parent['created']
                and all(type(auxiliary[k]) is int for k in ('created', 'query_created', 'held_created'))
                and all(auxiliary[k] is True for k in ('workload_job_verified', 'outer_job_verified', 'outer_query_handle_closed')),
                'journal_helper_generation')
            live.require(live.launcher.token_is_ordinary(helper['identity']) and helper['identity']['integrity_rid'] == 8192
                and helper['capabilities'] == [] and helper['identity']['capability_count'] == 0
                and helper['identity']['sid'] == selected['identity']['sid']
                and helper['identity']['session_id'] == selected['identity']['session_id'], 'journal_helper_identity')


def validate_death_ledger(value, c, tasks, go, reports, fixed, public):
    template = blank_death_ledger(c)
    live.require(type(value) is dict and set(value) == set(template), 'death_journal_schema')
    for key in ('schema_version', 'stage', 'run', 'death_case', 'after_direct_case'):
        live.require(type(value[key]) is type(template[key]) and value[key] == template[key], 'death_journal_binding')
    for key in ('terminate_requested', 'terminate_returned'): live.require(type(value[key]) is bool, 'death_journal_bool')
    live.require(not value['terminate_returned'] or value['terminate_requested'], 'death_terminate_order')
    descriptors = {row['path']: row for row in reports}
    def record(row, path):
        live.require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'text'} and row['path'] == path
            and type(row['text']) is str, 'death_record_schema')
        raw = row['text'].encode('ascii', 'strict')
        live.require(live.integer(row['bytes'], 1, live.MAX_NATIVE) and len(raw) == row['bytes'] and live.sha(raw) == row['sha256']
            and descriptors.get(path) == dict(path=path, state='read', bytes=row['bytes'], sha256=row['sha256']), 'death_record_digest')
        return live.decode(raw)
    def required_task(role):
        live.require(role in tasks and tasks[role]['resumed'] and tasks[role]['image_verified'], 'death_held_task')
        return tasks[role]
    def ticket(row, role, sequence, opcode, case, path):
        live.require(type(row) is dict and set(row) == {'record', 'issued_qpc'}
            and live.integer(row['issued_qpc'], c['start_qpc'], c['deadline_qpc']-1), 'death_ticket')
        matches = [item for item in go if item['role'] == role and item['sequence'] == sequence]
        live.require(len(matches) == 1 and row['record'] == matches[0] and matches[0]['opcode'] == opcode
            and matches[0]['case'] == case and matches[0]['path'] == path, 'death_ticket_go')
        return row['record']
    start, end = value['pair_start'], value['pair_deadline']
    if start is not None:
        live.require(live.integer(start, c['start_qpc'], c['deadline_qpc']-1) and type(end) is int
            and end == start+10*c['frequency'] and end < c['deadline_qpc']-35*c['frequency'], 'death_pair_clock')
    else: live.require(end is None, 'death_pair_clock')
    public_death = public['death_extension']; death_case = c['death_extension']['death_case']
    if ('death-front' in tasks and 'front' in tasks
            and tasks['death-front']['identity'] is not None and tasks['front']['identity'] is not None):
        live.require(tasks['death-front']['identity']['appcontainer_sid'] == tasks['front']['identity']['appcontainer_sid'], 'death_same_profile')
    if 'death-relay' in tasks and tasks['death-relay']['identity'] is not None:
        relay_task = tasks['death-relay']
        live.require(launcher.token_is_ordinary(relay_task['identity']) and relay_task['capabilities'] == []
            and ('origin' not in tasks or launcher.same_identity(relay_task['identity'], tasks['origin']['identity'])), 'death_ordinary_relay')
    if public_death['pair_held']:
        live.require(start is not None and all(role in tasks and tasks[role]['resumed'] and tasks[role]['image_verified']
            and live.integer(tasks[role]['admission_qpc'], start, end-1) and live.integer(tasks[role]['resume_qpc'], tasks[role]['admission_qpc'], end-1)
            for role in ('death-front', 'death-relay')), 'death_pair_held')
    if value['ticket'] is not None:
        row = ticket(value['ticket'], 'selected-client', 3, 5, death_case, 'selected-control/phase-0003.bin')
        live.require(start is not None and start <= value['ticket']['issued_qpc'] < end and row['phase_deadline'] == end, 'death_ticket_clock')
    held = None
    if value['held_ack'] is not None:
        live.require(value['ticket'] is not None and fixed is not None, 'death_ack_order')
        held = origin_death_ack(record(value['held_ack'], 'origin/death-held.json'), required_task('origin'), c,
            lower=value['ticket']['issued_qpc'], upper=end-1)
        live.require(held['port'] == fixed['origin'], 'death_ack_port')
    binding = value['relay_binding']
    if binding is not None:
        relay = required_task('death-relay')
        bk = {'pid', 'created', 'before_qpc', 'after_qpc', 'flow', 'origin_alive', 'relay_alive', 'exact_workload_job', 'exact_outer_job', 'query_handles_closed'}
        live.require(held is not None and type(binding) is dict and set(binding) == bk
            and type(binding['pid']) is int and binding['pid'] == relay['pid'] and type(binding['created']) is int and binding['created'] == relay['created']
            and live.integer(binding['before_qpc'], held['flow_qpc'][-1], end-1)
            and live.integer(binding['after_qpc'], binding['before_qpc'], end-1)
            and all(binding[k] is True for k in ('origin_alive', 'relay_alive', 'exact_workload_job', 'exact_outer_job', 'query_handles_closed')), 'death_relay_binding')
        flow = binding['flow']
        live.require(type(flow) is dict and set(flow) == {'pid', 'state', 'local_address', 'remote_address', 'local_port', 'remote_port'}
            and type(flow['pid']) is int and flow['pid'] == relay['pid'] and type(flow['state']) is int and flow['state'] in (6, 7)
            and flow['local_address'] == flow['remote_address'] == '127.0.0.1'
            and type(flow['local_port']) is int and flow['local_port'] == held['peer_port']
            and type(flow['remote_port']) is int and flow['remote_port'] == fixed['origin'], 'death_tcp_binding')
    intent = None
    if value['stop_intent'] is not None:
        live.require(binding is not None, 'death_intent_order')
        intent = record(value['stop_intent'], 'death-stop-intent.json')
        ik = {'schema_version', 'stage', 'run', 'case', 'pid', 'created', 'actor_sha256', 'frequency', 'deadline_qpc',
            'issued_qpc', 'held_ack_sha256', 'go_sha256', 'relay_flow_sha256'}
        live.require(type(intent) is dict and set(intent) == ik and live.integer(intent['schema_version'], 1, 1)
            and intent['stage'] == 'model2-death-stop-intent' and intent['run'] == c['run'] and intent['case'] == death_case
            and type(intent['pid']) is int and intent['pid'] == binding['pid'] and type(intent['created']) is int and intent['created'] == binding['created']
            and intent['actor_sha256'] == c['actor_sha256'] and type(intent['frequency']) is int and intent['frequency'] == c['frequency']
            and type(intent['deadline_qpc']) is int and intent['deadline_qpc'] == c['deadline_qpc']
            and live.integer(intent['issued_qpc'], binding['after_qpc'], end-1)
            and intent['held_ack_sha256'] == value['held_ack']['sha256'] and intent['go_sha256'] == value['ticket']['record']['sha256']
            and intent['relay_flow_sha256'] == live.sha(live.encode(binding['flow']))
            and live.integer(value['stop_persisted_qpc'], intent['issued_qpc'], end-1), 'death_intent_binding')
    else: live.require(value['stop_persisted_qpc'] is None, 'death_intent_time')
    live.require(not value['terminate_requested'] or intent is not None, 'death_stop_authority')
    if value['exit_code'] is not None:
        relay = required_task('death-relay')
        live.require(value['terminate_requested'] and value['terminate_returned'] and type(value['exit_code']) is int and value['exit_code'] == 1
            and relay['exited'] and relay['exit_code'] == 1 and live.integer(value['exit_qpc'], value['stop_persisted_qpc'], end-1), 'death_held_exit')
    else: live.require(value['exit_qpc'] is None, 'death_exit_time')
    front = None
    if value['front_report'] is not None:
        live.require(value['exit_code'] == 1, 'death_front_order'); task = required_task('death-front')
        live.require(task['exited'] and task['exit_code'] == 5, 'death_front_exit')
        front = validate_death_front(record(value['front_report'], 'front/death/final.json'), task, c, fixed['proxy'], fixed['origin'], start, end)
    if value['client_report'] is not None:
        live.require(front is not None, 'death_client_order')
        client = client_phase(record(value['client_report'], 'selected/phase-0003.json'), required_task('selected'), c,
            role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=3, case=death_case,
            operation='proxy-after-death', target_port=fixed['proxy'], phase_deadline=end)
        live.require(death_client_failed_closed(client) and client['network']['local_port'] == front['listener']['peer_port'], 'death_client_closed')
    released = None
    if value['release_go'] is not None:
        row = ticket(value['release_go'], 'health-origin-release', 1, 254, death_case, 'origin-control/release.bin')
        live.require(value['client_report'] is not None and value['exit_code'] == 1
            and value['release_go']['issued_qpc'] >= value['exit_qpc'] and row['phase_deadline'] == c['deadline_qpc'], 'death_release_order')
    if value['release_ack'] is not None:
        live.require(value['release_go'] is not None, 'death_release_ack_order')
        released = origin_death_ack(record(value['release_ack'], 'origin/death-release.json'), required_task('origin'), c,
            released=True, held=held, lower=value['release_go']['issued_qpc'], upper=c['deadline_qpc']-1)
    after = None
    if value['after_direct_report'] is not None:
        live.require(released is not None, 'death_after_order')
        entries = [row for row in go if row['role'] == 'selected-client' and row['sequence'] == 4]
        live.require(len(entries) == 1, 'death_after_go')
        after = client_phase(record(value['after_direct_report'], 'selected/phase-0004.json'), required_task('selected'), c,
            role='selected-client', boot=c['boot_case'], admission=c['admission_nonce'], sequence=4, case=c['death_extension']['after_direct_case'],
            operation='direct-tcp', target_port=fixed['origin'], phase_deadline=entries[0]['phase_deadline'])
        live.require(after['phase_qpc'][0] >= released['flow_qpc'][-1], 'death_after_clock')
        live.require(public_death['after_direct_attempted'] == after['network']['connect_attempted']
            and public_death['after_direct_connected'] == after['network']['connect_completed'], 'death_after_sticky')
    live.require(type(value['origin_receipts']) is list and len(value['origin_receipts']) <= 8, 'death_receipts')
    cases = []
    for index, row in enumerate(value['origin_receipts'], 1):
        item = receipt(record(row, 'origin/receipt-%04d.json' % index), required_task('origin'), c,
            boot=c['health_cases'][0], port=fixed['origin'], index=index)
        if public_death['origin_healthy_after_release']:
            if item['case_id'] == death_case:
                live.require(death_receipt_passed(item) and held is not None and released is not None
                    and item['peer_port'] == held['peer_port'] and item['qpc'][1] == held['flow_qpc'][0]
                    and item['qpc'][3] >= released['flow_qpc'][-1], 'death_receipt')
            elif item['case_id'] not in (c['direct_case'], c['death_extension']['after_direct_case']):
                live.require(receipt_passed(item), 'death_health_receipt')
            if item['case_id'] == c['health_cases'][2]:
                live.require(after is not None and item['qpc'][1] >= after['phase_qpc'][2], 'death_after_health_order')
        cases.append(item['case_id'])
    live.require(not public_death['after_forbidden_nonce_received'] or c['death_extension']['after_direct_case'] in cases, 'death_receiver_sticky')
    for key, item in (('request_published', value['ticket']), ('origin_held_ack', held), ('relay_alive_verified', binding),
        ('stop_intent_persisted', intent), ('relay_stop_confirmed', value['exit_code']), ('front_failed_closed', front),
        ('client_failed_closed', value['client_report']), ('origin_release_ack', released), ('after_direct_attempted', after)):
        live.require(not public_death[key] or item is not None, 'death_public_evidence')
    if public_death['after_direct_denied_by_access']:
        live.require(after is not None and connect_denied(after) and c['health_cases'][2] in cases
            and c['death_extension']['after_direct_case'] not in cases, 'death_deny_evidence')
    if live.diagnostic_ready(public, require_guard=False):
        live.require(after is not None and connect_denied(after) and not any(public['violations'].values())
            and cases == [c['health_cases'][0], c['positive_case'], c['health_cases'][1], death_case, c['health_cases'][2]], 'death_complete')
    return value


def validate_ownership_journal(value, config, *, controller_pid):
    keys = {'schema_version', 'stage', 'run', 'controller_pid', 'frequency', 'start_qpc', 'deadline_qpc',
        'source_sha256', 'actor_sha256', 'manifest_sha256', 'public_sha256', 'public', 'fixed_ports',
        'tasks', 'selected_discovery', 'go', 'native_reports', 'maintenance', 'rules', 'cleanup'}
    q_psec = config.get('wrong_port_extension', {}).get('profile') == 'same-peer-wrong-port-psec-control-v1'
    if q_psec: keys.add('q_selected_discovery')
    peer = 'wrong_peer_extension' in config
    if peer: keys.update(('b_selected_discovery', 'b_profile'))
    death = 'death_extension' in config
    if death: keys.add('death')
    dns_cell='dns_extension' in config
    if dns_cell:keys.add('dns')
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
    helper_contract = config.get('selected_admission')
    if helper_contract is not None:
        live.validate_selected_admission(helper_contract)
        roles.add('system-conhost')
    wrong_extension = config.get('wrong_peer_extension') if peer else config.get('wrong_port_extension')
    if wrong_extension is not None and not peer: roles.update(('q-listener', 'q-health'))
    if q_psec: roles.update(('q-g-probe', 'q-g-live', 'q-system-conhost'))
    if peer: roles.update(('b-listener', 'b-health', 'b-g-probe', 'b-g-live', 'b-system-conhost',
        'b-acl-root', 'b-acl-inputs', 'b-acl-front', 'b-acl-remove'))
    if death: roles.update(('death-front', 'death-relay'))
    if dns_cell:roles.add('dns-inventory')
    live.require(('wrong_port_extension' in public) == ('wrong_port_extension' in config)
        and ('wrong_peer_extension' in public) == peer and ('death_extension' in public) == death and ('dns_extension' in public)==dns_cell, 'journal_extension_binding')
    live.require(type(value['tasks']) is list and len(value['tasks']) <= len(roles), 'journal_tasks')
    tasks = {}
    for row in value['tasks']:
        auxiliary = type(row) is dict and row.get('role') in ('system-conhost', 'q-system-conhost', 'b-system-conhost')
        expected_keys = task_keys | ({'natural_exit_observed', 'stop_requested', 'finish_order_verified'} if auxiliary else set())
        live.require(type(row) is dict and set(row) == expected_keys and row['role'] in roles and row['role'] not in tasks, 'journal_task')
        tasks[row['role']] = row
        for key in ('attempted', 'assigned', 'exited', 'image_verified', 'resumed', 'cleanup_role',
                    'externally_held_before_first_resume', 'externally_held_before_network_go'):
            live.require(type(row[key]) is bool, 'journal_task_bool')
        for key, maximum in (('pid', 0xffffffff), ('created', 0xffffffffffffffff)):
            live.require(row[key] is None or live.integer(row[key], 1, maximum), 'journal_task_generation')
        live.require(row['exit_code'] is None or live.integer(row['exit_code']) and row['exited'], 'journal_exit')
        if auxiliary:
            live.require(row['command'] is None and type(row['image_path']) is str and 0 < len(row['image_path']) <= 4096
                and Path(row['image_path']).name.casefold() == 'conhost.exe' and helper_contract is not None
                and row['image_sha256'] == helper_contract['conhost_sha256']
                and all(type(row[k]) is bool for k in ('natural_exit_observed', 'stop_requested', 'finish_order_verified'))
                and not row['externally_held_before_first_resume'] and row['externally_held_before_network_go'], 'journal_helper_image')
        else:
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
            if row['role'] in ('selected', 'system-conhost', 'q-system-conhost', 'b-system-conhost') or q_psec and row['role'] == 'q-health' or peer and row['role'] == 'b-health':
                live.require(row['externally_held_before_first_resume'] is False and row['resume_qpc'] is None, 'journal_selected_resume')
            else:
                live.require(row['externally_held_before_first_resume'] is True and row['resume_qpc'] is not None
                    and row['resume_qpc'] >= row['admission_qpc'], 'journal_resume_order')
        if row['role'] in ('origin', 'health', 'front', 'relay', 'selected', 'q-listener', 'q-health', 'b-listener', 'b-health', 'death-front', 'death-relay'):
            live.require(row['image_sha256'] == config['actor_sha256'], 'journal_actor_hash')
        if row['role'] in ('g-probe', 'g-live', 'q-g-probe', 'q-g-live', 'b-g-probe', 'b-g-live'):
            live.require(row['image_sha256'] == live.probe.pins.MXC_G_EXECUTOR_SHA256, 'journal_g_hash')
    discovery = value['selected_discovery']
    validate_family_discovery(discovery, tasks, helper_contract)
    if q_psec:
        q_discovery = value['q_selected_discovery']
        validate_family_discovery(q_discovery, {name: tasks[role] for name, role in
            (('selected', 'q-health'), ('g-live', 'q-g-live'), ('system-conhost', 'q-system-conhost')) if role in tasks}, helper_contract)
        live.require(not public['wrong_port_extension']['healthy_before'] or q_discovery is not None, 'journal_missing_q_selected')
    if peer:
        b_discovery = value['b_selected_discovery']
        validate_family_discovery(b_discovery, {name: tasks[role] for name, role in
            (('selected', 'b-health'), ('g-live', 'b-g-live'), ('system-conhost', 'b-system-conhost')) if role in tasks}, helper_contract)
        live.require(not public['wrong_peer_extension']['healthy_before'] or b_discovery is not None, 'journal_missing_b_selected')
        b = value['b_profile']
        b_keys = {'name', 'attempted', 'returned', 'created', 'sid', 'derive_verified', 'different_a_verified',
            'acl_attempted', 'acl_removed', 'deleted', 'released', 'a_front_closed_verified'}
        live.require(type(b) is dict and set(b) == b_keys and b['name'] == 'RuleProxy.Model2.B.' + config['run']
            and all(type(b[k]) is bool for k in b_keys - {'name', 'sid'})
            and (b['sid'] is None or ac.ac_profile_sid(b['sid'])) and (not b['created'] or b['attempted'] and b['returned']), 'journal_b_profile')
        if b['acl_attempted'] or 'b-listener' in tasks:
            live.require(b['created'] and b['derive_verified'] and b['different_a_verified'] and b['a_front_closed_verified']
                and 'front' in tasks and tasks['front']['exited'] and tasks['front']['exit_code'] == 0
                and 'relay' in tasks and tasks['relay']['exited'] and tasks['relay']['exit_code'] == 0, 'journal_b_creation_gate')
        if 'b-listener' in tasks and tasks['b-listener']['resumed']:
            live.require(tasks['b-listener']['identity']['appcontainer_sid'] == b['sid']
                and b['sid'] != tasks['front']['identity']['appcontainer_sid'], 'journal_b_peer')
        live.require(not b['deleted'] or b['created'] and b['acl_removed'] and all(value['cleanup'][k] for k in
            ('workload_cleanup_confirmed', 'workload_job_empty', 'all_workloads_exited', 'maintenance_cleanup_confirmed', 'maintenance_handles_closed')),
            'journal_b_delete')
    live.require(not public['checks']['selected_held'] or discovery is not None, 'journal_missing_selected')
    expected_go = [('health-client', 1, 2, config['health_cases'][0]), ('selected-client', 1, 1, config['positive_case']),
        ('health-client', 2, 2, config['health_cases'][1]), ('selected-client', 2, 2, config['direct_case']),
        ('selected-client', 3, 255, config['boot_case']), ('health-client', 3, 2, config['health_cases'][2]),
        ('health-client', 4, 255, config['admission_nonce']), ('health-origin', 1, 255, config['health_cases'][0])]
    if wrong_extension is not None:
        x = wrong_extension
        prefix = 'b' if peer else 'q'
        expected_go[4] = ('selected-client', 4, 255, config['boot_case'])
        expected_go[4:4] = [(prefix + '-health', 1, 1 if q_psec or peer else 3, x['before_case']), ('selected-client', 3, 4 if peer else 3, x['wrong_case']),
            (prefix + '-health', 2, 1 if q_psec or peer else 3, x['after_case']), (prefix + '-health', 3, 255, x['control_boot']), (prefix + '-listener', 1, 255, x['listener_boot'])]
    if death:
        x = config['death_extension']; expected_go[4] = ('selected-client', 5, 255, config['boot_case'])
        expected_go[4:4] = [('selected-client', 3, 5, x['death_case']), ('health-origin-release', 1, 254, x['death_case']),
            ('selected-client', 4, 2, x['after_direct_case'])]
    if dns_cell:
        x=config['dns_extension']
        expected_go[4:]=[('health-client',3,6,x['before_case']),('selected-client',3,6,x['selected_case']),
            ('health-client',4,6,x['after_case']),('selected-client',4,255,config['boot_case']),
            ('health-client',5,2,config['health_cases'][2]),('health-client',6,255,config['admission_nonce']),
            ('health-origin',1,255,config['health_cases'][0])]
    live.require(type(value['go']) is list and len(value['go']) <= len(expected_go), 'journal_go')
    for row, (role, sequence, opcode, case) in zip(value['go'], expected_go):
        live.require(type(row) is dict and set(row) == {'role', 'sequence', 'opcode', 'case', 'phase_deadline', 'path', 'sha256'}
            and row['role'] == role and type(row['sequence']) is int and row['sequence'] == sequence
            and type(row['opcode']) is int and row['opcode'] == opcode and row['case'] == case
            and live.integer(row['phase_deadline'], 1, config['deadline_qpc']) and ac.digest(row['sha256']), 'journal_go_binding')
        if role == 'health-origin-release':
            live.require(death and row['phase_deadline'] == config['deadline_qpc'], 'journal_release_scope')
            expected = live.fixture_release(run=config['run'], death_case=config['death_extension']['death_case'],
                frequency=config['frequency'], deadline=config['deadline_qpc']); expected_path = 'origin-control/release.bin'
        elif role in ('health-origin', 'q-listener', 'b-listener'):
            expected = live.fixture_finish(run=config['run'], boot_case=config['health_cases'][0] if role == 'health-origin' else wrong_extension['listener_boot'],
                frequency=config['frequency'], deadline=config['deadline_qpc'])
            expected_path = 'origin-control/finish.bin' if role == 'health-origin' else 'b-front/finish.bin' if role == 'b-listener' else 'front/finish.bin'
        else:
            live.require(value['fixed_ports'] is not None, 'journal_go_ports')
            admission = config['admission_nonce'] if role == 'selected-client' else wrong_extension['control_admission'] if role in ('q-health', 'b-health') else config['maintenance_nonce']
            go_ports = value['fixed_ports']
            if q_psec and role == 'q-health':
                go_ports = dict(proxy=go_ports['wrong_port'], wrong_port=go_ports['proxy'], origin=go_ports['origin'])
            expected = live.go_record(run=config['run'], case=case, sequence=sequence, opcode=opcode,
                frequency=config['frequency'], deadline=config['deadline_qpc'], fixed_ports=go_ports,
                admission=admission, phase_deadline=row['phase_deadline'])
            expected_path = ('selected-control' if role == 'selected-client' else 'q-health-control' if role == 'q-health' else 'b-health-control' if role == 'b-health' else 'health-control') + '/phase-%04d.bin' % sequence
        live.require(row['path'] == expected_path and row['sha256'] == live.sha(expected), 'journal_go_digest')
    paths = set()
    live.require(type(value['native_reports']) is list and len(value['native_reports']) <= (32 if dns_cell else 34 if death else 46 if q_psec or peer else 41 if wrong_extension is not None else 26), 'journal_reports')
    for row in value['native_reports']:
        live.require(type(row) is dict and set(row) == {'path', 'state', 'bytes', 'sha256'}
            and type(row['path']) is str and row['path'] not in paths
            and re_report_path(row['path'], wrong_port='wrong_port_extension' in config, q_psec=q_psec, peer=peer, death=death, dns=dns_cell)
            and row['state'] in ('read', 'unreadable'), 'journal_report')
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
    if death:
        validate_death_ledger(value['death'], config, tasks, value['go'], value['native_reports'], value['fixed_ports'], public)
    if dns_cell:
        validate_dns_ledger(value['dns'],config,tasks,value['go'],value['native_reports'],public)
    if live.first_ready(public, require_guard=False) or live.diagnostic_ready(public, require_guard=False):
        live.require(set(tasks) == roles and len(value['go']) == len(expected_go)
            and all(row['resumed'] and row['exited'] and (live.integer(row['exit_code']) if role in ('system-conhost', 'q-system-conhost', 'b-system-conhost')
                else row['exit_code'] == 1 if death and role == 'death-relay' else row['exit_code'] == 5 if death and role == 'death-front' else row['exit_code'] == 0)
                for role, row in tasks.items())
            and all(value['cleanup'].values()) and rule is not None and rule['present_verified'] and rule['absent_verified']
            and m['admitted'] and m['exited'] and m['exit_code'] == 0
            and all(row['state'] == 'read' for row in value['native_reports']), 'journal_first_cell')
        if helper_contract is not None:
            for role in ('system-conhost', 'b-system-conhost') if peer else ('system-conhost', 'q-system-conhost') if q_psec else ('system-conhost',):
                helper = tasks[role]
                live.require(helper['finish_order_verified'] and (helper['natural_exit_observed'] or helper['stop_requested']),
                    'journal_helper_finish')
        if peer:
            live.require(all(value['b_profile'][k] for k in b_keys - {'name', 'sid'}), 'journal_b_complete')
    return value


def origin_death_ack(value, task, config, *, released=False, held=None, lower, upper):
    common = {'schema_version', 'stage', 'role', 'run_id', 'boot_case_id', 'pid', 'identity', 'case_id', 'root_qpc',
        'flow_qpc', 'port', 'peer_port', 'request_bytes', 'request_exact', 'request_eof', 'response_bytes',
        'response_withheld', 'socket_held', 'failure', 'proxy_tested', 'product_acceptance'}
    keys = common | ({'release_sequence', 'release_verified', 'release_command_close_verified', 'connection_close'}
        if released else {'command_close_verified'})
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == ('proxy-c-origin-released' if released else 'proxy-c-origin-withheld')
        and value['role'] == 'health-origin-withhold' and value['run_id'] == config['run']
        and value['boot_case_id'] == config['health_cases'][0] and value['pid'] == task['pid'] and type(value['pid']) is int
        and value['case_id'] == config['death_extension']['death_case'] and value['failure'] is None
        and value['proxy_tested'] is False and value['product_acceptance'] is False, 'death_origin_ack')
    native_identity(value['identity'], task, config['run'])
    live.require(value['root_qpc'] == [config['frequency'], config['start_qpc'], config['deadline_qpc']]
        and all(type(x) is int for x in value['root_qpc']), 'death_origin_clock')
    flow = value['flow_qpc']
    live.require(type(flow) is list and len(flow) == (4 if released else 2)
        and all(live.integer(x, config['start_qpc'], config['deadline_qpc']-1) for x in flow)
        and flow == sorted(flow) and flow[-1] <= upper < config['deadline_qpc'], 'death_flow_clock')
    live.require(live.integer(value['port'], 49153, 65535) and live.integer(value['peer_port'], 1, 65535)
        and type(value['request_bytes']) is int and value['request_bytes'] == len(live.origin.payloads(value['case_id'], value['port'])[0])
        and value['request_exact'] is True and value['request_eof'] is True and type(value['response_bytes']) is int
        and value['response_bytes'] == 0 and value['response_withheld'] is True and value['socket_held'] is (not released), 'death_origin_flow')
    if released:
        live.require(held is not None and flow[:2] == held['flow_qpc'] and flow[2] >= lower
            and value['port'] == held['port'] and value['peer_port'] == held['peer_port']
            and type(value['release_sequence']) is int and value['release_sequence'] == 1 and value['release_verified'] is True
            and value['release_command_close_verified'] is True and value['connection_close'] == 'confirmed', 'death_release_ack')
    else: live.require(flow[0] >= lower and value['command_close_verified'] is True, 'death_held_ack')
    return value


def death_receipt_passed(row):
    return (row['request_exact'] is True and row['request_eof'] is True and row['request_bytes'] == len(live.origin.payloads(row['case_id'], row['port'])[0])
        and row['response_bytes'] == 0 and row['response_complete'] is False and row['send_shutdown'] is False
        and row['connection_close'] == 'confirmed' and row['failure'] is None and row['wsa_error'] is None
        and row['qpc'][3] < row['qpc'][2])


def death_client_failed_closed(value):
    n = value['network']
    return (value['failure'] is None and value['phase_qpc'][2] < value['phase_qpc'][1]
        and all(n[k] is True for k in ('wsa_startup', 'wsa_cleanup', 'inheritance_cleared', 'socket_created', 'connect_attempted',
            'connect_completed', 'peer_loopback', 'request_complete', 'send_shutdown', 'response_eof'))
        and n['request_bytes'] == 129 and n['response_bytes'] == 0 and n['response_exact'] is False
        and n['socket_close'] == 'confirmed' and n['failure'] == 'response' and n['wsa_error'] is None)


def validate_death_front(value, task, config, proxy_port, origin_port, start, end):
    keys = {'schema_version', 'stage', 'role', 'run_id', 'case_id', 'pid', 'identity', 'capability_profile',
        'capability_profile_verified', 'catalog_cleanup_verified', 'ipc_mechanics', 'listener', 'client',
        'wsa_startup', 'wsa_cleanup', 'failure', 'wsa_error', 'http_boundary', 'network_tested', 'proxy_tested', 'product_acceptance'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'proxy-c-live-front' and value['role'] == 'pipe-live-front' and value['run_id'] == config['run']
        and value['case_id'] == config['death_extension']['death_case'] and type(value['pid']) is int and value['pid'] == task['pid']
        and value['capability_profile'] == 'pncs' and value['capability_profile_verified'] is True and value['catalog_cleanup_verified'] is True
        and value['wsa_startup'] is True and value['wsa_cleanup'] is True and value['failure'] == 'pipe_read' and value['wsa_error'] is None
        and value['http_boundary'] == 'real-client-request-and-response-socket' and value['network_tested'] is True
        and value['proxy_tested'] is False and value['product_acceptance'] is False, 'death_front')
    native_identity(value['identity'], task, config['run'])
    listener = value['listener']; lk = {'port', 'listener_created', 'inheritance_cleared', 'exclusive', 'bind_loopback',
        'accepted', 'peer_loopback', 'peer_port', 'listener_close'}
    live.require(type(listener) is dict and set(listener) == lk and type(listener['port']) is int and listener['port'] == proxy_port
        and live.integer(listener['peer_port'], 1, 65535) and listener['listener_close'] == 'confirmed'
        and all(listener[k] is True for k in lk - {'port', 'peer_port', 'listener_close'}), 'death_front_listener')
    live.require(value['client'] == dict(request_bytes=129, request_exact=True, request_eof=True, response_bytes=0,
        response_complete=False, send_shutdown=False, connection_close='confirmed')
        and all(type(value['client'][k]) is type(v) for k, v in dict(request_bytes=129, request_exact=True, request_eof=True,
            response_bytes=0, response_complete=False, send_shutdown=False, connection_close='confirmed').items()), 'death_front_client')
    m = value['ipc_mechanics']
    mk = {'schema_version', 'stage', 'role', 'run_id', 'case_id', 'pid', 'identity', 'qpc', 'pipe', 'core',
        'synthetic_http', 'failure', 'win32_error', 'network_tested', 'proxy_tested', 'product_acceptance'}
    live.require(type(m) is dict and set(m) == mk and live.integer(m['schema_version'], 1, 1)
        and m['stage'] == 'bridge-pipe-test' and m['role'] == 'pipe-front' and m['run_id'] == config['run']
        and m['case_id'] == config['death_extension']['death_case'] and type(m['pid']) is int and m['pid'] == task['pid']
        and m['failure'] == 'pipe_read' and type(m['win32_error']) is int and m['win32_error'] == 109
        and all(m[k] is False for k in ('network_tested', 'proxy_tested', 'product_acceptance')), 'death_front_ipc')
    native_identity(m['identity'], task, config['run']); qpc(m['qpc'], config['frequency'], start, end)
    expected_pipe = dict(read_bytes=48, write_bytes=96, read_frames=1, write_frames=2, inheritance_cleared=True,
        eof_observed=False, reader_close='confirmed', writer_close='confirmed', requires_controller_timeout=True)
    expected_core = dict(failure=0, observations=1, requested=0, confirmed=0, uncertain=0)
    live.require(type(m['pipe']) is dict and set(m['pipe']) == set(expected_pipe)
        and all(type(m['pipe'][k]) is type(v) and m['pipe'][k] == v for k, v in expected_pipe.items())
        and type(m['core']) is dict and set(m['core']) == set(expected_core)
        and all(type(m['core'][k]) is int and m['core'][k] == v for k, v in expected_core.items())
        and m['synthetic_http'] == dict(request_checked=True, response_checked=False, client_sink_checked=False)
        and all(type(v) is bool for v in m['synthetic_http'].values()), 'death_front_golden')
    return value


def re_report_path(path, wrong_port=False, q_psec=False, peer=False, death=False, dns=False):
    import re
    base = bool(re.fullmatch(r'(?:front/(?:ready|final)\.json|relay/final\.json|origin/(?:ready|final|receipt-000[1-8])\.json|'
        r'health/(?:ready|final|phase-000[1-3])\.json|selected/(?:ready|final|phase-000[12])\.json|g-(?:probe|live)/(?:stdout|stderr))', path))
    return (base or wrong_port and bool(re.fullmatch(r'(?:front/(?:q-ready|q-final|receipt-000[1-8])\.json|'
        r'q-health/(?:ready|final|phase-000[12])\.json|selected/phase-0003\.json)', path))
        or q_psec and bool(re.fullmatch(r'q-g-(?:probe|live)/(?:stdout|stderr)|q-live-request\.json', path))
        or peer and bool(re.fullmatch(r'b-(?:front/(?:ready|final|receipt-000[1-8])\.json|'
            r'health/(?:ready|final|phase-000[12])\.json|g-(?:probe|live)/(?:stdout|stderr)|live-request\.json)|selected/phase-0003\.json', path))
        or death and bool(re.fullmatch(r'front/death/(?:ready|final)\.json|origin/death-(?:held|release)\.json|'
            r'selected/phase-000[34]\.json|death-stop-intent\.json', path))
        or dns and bool(re.fullmatch(r'tools/dns-inventory/(?:stdout|stderr)|dns-fixture-final\.json|'
            r'health/phase-000[45]\.json|selected/phase-0003\.json',path)))


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
            'health', 'positive', 'wrong-port', 'wrong-peer', 'death', 'dns', 'cleanup', 'report') else 'worker'
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
                discovery_raw = live.encode(dict(schema_version=1, stage='selected-rejected-held-discovery',
                    run=config['run'], frequency=config['frequency'], start_qpc=config['start_qpc'],
                    deadline_qpc=config['deadline_qpc'], source_sha256=config['source_sha256'],
                    network_authorized=False, discovery=exc.discovery))
                if len(discovery_raw) <= live.MAX_PRIVATE:
                    launcher.write_private_bytes(root / 'selected-discovery-private.json', discovery_raw)
                    error['discovery_sha256'] = live.sha(discovery_raw)
                    error['discovery_bytes'] = len(discovery_raw)
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
