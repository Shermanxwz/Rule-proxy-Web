"""C: closed local Model 2 ownership and barrier primitives.

The default command is read-only. Nothing in this module is a product launcher.
Native C, G/PSEC, profiles, firewall and sockets require the separate owned worker
path. The historical empty-capability Stage 0 and A/B contracts are unchanged.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


probe = _load('c_candidate_probe', 'windows_identity_model2_local_probe.py')
origin = _load('c_origin_ownership', 'windows_identity_proxy_origin_probe.py')
local = probe.local
launcher = local.launcher
ac = origin.a
helpers = origin.helpers
proof = helpers.proof
MAX_PRIVATE = 256 * 1024
MAX_NATIVE = 16 * 1024
MAX_PUBLIC = 8192
MAX_SIGNED = 0x7fffffffffffffff
PNCS = 'S-1-15-3-3'
CAP_PROFILES = ('identity-only', 'agentic-only', 'agentic-pncs')
OPS = {1: 'proxy-get', 2: 'direct-tcp', 3: 'wrong-port', 4: 'wrong-peer', 5: 'proxy-after-death', 255: 'finish'}
ACTOR = 'windows_identity_proxy_c_actor.exe'
MANIFEST = 'identity-proxy-c-manifest.json'
SOURCES = tuple(dict.fromkeys((*origin.SOURCES, *probe.SOURCES,
    '.github/windows_identity_model2_live.py', '.github/windows_identity_model2_maintenance.py',
    '.github/windows_identity_model2_controller.py', '.github/windows_identity_model2_local.py',
    '.github/windows_identity_model2_firewall.ps1')))
NATIVE_SOURCES = {**origin.NATIVE_SOURCES,
    'actorSourceSha256': '.github/native/windows_identity_proxy_c_actor.cpp',
    'originActorSha256': '.github/native/windows_identity_proxy_origin_actor.cpp',
    'liveContractSha256': '.github/native/windows_identity_proxy_c_contract.hpp'}
SOURCES = tuple(dict.fromkeys((*SOURCES, *NATIVE_SOURCES.values())))


def require(value, reason='live_contract'):
    if not value:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return local.encode(value)


def decode(raw):
    return local.guest.decode(raw)


def integer(value, minimum=0, maximum=0xffffffff):
    return ac.integer(value, minimum, maximum)


def clock_record(start, frequency, deadline):
    require(integer(start, 0, MAX_SIGNED) and integer(frequency, 1, 1000000000)
        and integer(deadline, 1, MAX_SIGNED) and start < deadline
        and deadline - start <= 120 * frequency, 'clock')
    return start, frequency, deadline


def ports(value):
    require(type(value) is dict and set(value) == {'proxy', 'wrong_port', 'origin'}, 'ports')
    require(all(integer(v, 49153, 65535) for v in value.values()) and len(set(value.values())) == 3, 'ports')
    return dict(value)


def source_snapshot(root=ROOT):
    root = launcher.checked_path(root, is_file=False)
    files = {name: local.bounded(launcher.checked_path(root / name, inside=root), 256 * 1024) for name in SOURCES}
    hashes = {name: sha(raw) for name, raw in files.items()}
    return files, hashes, sha(encode(hashes))


def verify_actor(actor, manifest, actor_hash, manifest_hash, *, root=None):
    actor = launcher.checked_path(actor)
    manifest = launcher.checked_path(manifest)
    require(actor.name == ACTOR and manifest.name == MANIFEST and actor.parent == manifest.parent, 'artifact')
    require(ac.digest(actor_hash) and ac.digest(manifest_hash), 'artifact')
    value, raw = ac.bounded_json(manifest, 8192, inside=actor.parent)
    keys = {'schemaVersion', 'compileOnly', 'runtimeAcceptance', 'executableSha256', *NATIVE_SOURCES}
    require(set(value) == keys and integer(value['schemaVersion'], 1, 1)
        and value['compileOnly'] is True and value['runtimeAcceptance'] is False, 'artifact')
    require(all(ac.digest(value[k]) for k in (*NATIVE_SOURCES, 'executableSha256'))
        and sha(raw) == manifest_hash and value['executableSha256'] == actor_hash, 'artifact')
    helpers.verify_copied_actor(actor, actor_hash)
    if root is not None:
        root = launcher.checked_path(root, is_file=False)
        for key, name in NATIVE_SOURCES.items():
            require(sha(local.bounded(launcher.checked_path(root / name, inside=root), 256 * 1024)) == value[key], 'native_source')
    return actor


def capability_set(entries, profile, catalog):
    """Exact declared fixed-name set and attributes; never accept observed input."""
    require(profile in (*CAP_PROFILES, 'pncs') and type(catalog) is dict, 'capability_profile')
    names = {'identity-only': (), 'agentic-only': ('AgenticAppContainer',),
        'agentic-pncs': ('AgenticAppContainer', 'privateNetworkClientServer'),
        'pncs': ('privateNetworkClientServer',)}[profile]
    require(all(name in catalog and proof.canonical_capability_sid(catalog[name]) for name in names), 'capability_catalog')
    if 'privateNetworkClientServer' in catalog:
        require(catalog['privateNetworkClientServer'] == PNCS, 'capability_catalog')
    expected = {(catalog[name], 4) for name in names}
    require(len(expected) == len(names), 'capability_catalog')
    parsed, invalid, duplicates = proof.capability_entries(entries)
    require(parsed is not None and not invalid and not duplicates and len(parsed) == len(expected)
        and set(parsed) == expected, 'capabilities')
    return True


def selected_identity(identity, capabilities, parent, profile, catalog):
    require(type(identity) is dict and set(identity) == ac.AC_IDENTITY_KEYS, 'selected_identity')
    require(profile in ('agentic-only', 'agentic-pncs'), 'selected_profile')
    require(identity['sid'] == parent['sid'] and identity['session_id'] == parent['session_id']
        and integer(identity['token_type'], 1, 1) and identity['elevated'] is False
        and identity['appcontainer'] is True and ac.ac_profile_sid(identity['appcontainer_sid'])
        and identity['ui_access'] is False and integer(identity['integrity_rid'], 0, 8192), 'selected_identity')
    require(identity['capability_count'] == len(capabilities), 'selected_capability_count')
    capability_set(capabilities, profile, catalog)
    return True


def frontend_identity(identity, capabilities, parent, sid, catalog):
    require(type(identity) is dict and set(identity) == ac.AC_IDENTITY_KEYS, 'frontend_identity')
    require(ac.ac_profile_sid(sid) and identity['sid'] == parent['sid'] and identity['session_id'] == parent['session_id']
        and integer(identity['token_type'], 1, 1) and identity['appcontainer'] is True
        and identity['appcontainer_sid'] == sid and identity['elevated'] is False
        and identity['ui_access'] is False and integer(identity['integrity_rid'], 0, 8192)
        and integer(identity['capability_count'], 1, 1), 'frontend_identity')
    capability_set(capabilities, 'pncs', catalog)
    return True


def go_record(*, run, case, sequence, opcode, frequency, deadline, fixed_ports, admission, phase_deadline):
    p = ports(fixed_ports)
    require(all(ac.nonce(x) for x in (run, case, admission)) and integer(sequence, 1, 16)
        and type(opcode) is int and opcode in OPS, 'go')
    require(integer(frequency, 1, 1000000000) and integer(deadline, 1, MAX_SIGNED)
        and integer(phase_deadline, 1, deadline), 'go')
    raw = bytearray(128)
    raw[:6] = b'RPC1\x01' + bytes((opcode,))
    struct.pack_into('<I', raw, 8, sequence)
    raw[16:32] = bytes.fromhex(run)
    raw[32:48] = bytes.fromhex(case)
    struct.pack_into('<QQHHH', raw, 48, frequency, deadline, p['proxy'], p['wrong_port'], p['origin'])
    raw[72:88] = bytes.fromhex(admission)
    struct.pack_into('<Q', raw, 88, phase_deadline)
    return bytes(raw)


def validate_go(raw, **expected):
    require(type(raw) is bytes and len(raw) == 128 and raw == go_record(**expected), 'go_binding')
    return raw


def fixture_finish(*, run, boot_case, frequency, deadline):
    require(ac.nonce(run) and ac.nonce(boot_case) and integer(frequency, 1, 1000000000)
        and integer(deadline, 1, MAX_SIGNED), 'fixture_finish')
    raw = bytearray(128)
    raw[:6] = b'RPC1\x01\xff'
    struct.pack_into('<I', raw, 8, 1)
    raw[16:32] = bytes.fromhex(run)
    raw[32:48] = bytes.fromhex(boot_case)
    struct.pack_into('<QQ', raw, 48, frequency, deadline)
    raw[72:88] = bytes.fromhex(boot_case)
    struct.pack_into('<Q', raw, 88, deadline)
    return bytes(raw)


def publish_fixture_finish(directory, *, budget, run, boot_case):
    directory = launcher.checked_path(directory, is_file=False)
    budget.require_ms(budget.cutoff(20))
    path, temporary = directory / 'finish.bin', directory / '.finish.tmp'
    require(not path.exists() and not temporary.exists(), 'finish_exists')
    raw = fixture_finish(run=run, boot_case=boot_case, frequency=budget.frequency, deadline=budget.deadline)
    launcher.write_private_bytes(temporary, raw)
    temporary.rename(path)
    budget.require_ms(budget.cutoff(20))
    return sha(raw)


def publish_go(directory, *, budget, **fields):
    """Only the fixed binary record is authorized. No existing sequence overwrite."""
    directory = launcher.checked_path(directory, is_file=False)
    require(fields['frequency'] == budget.frequency and fields['deadline'] == budget.deadline, 'go_clock')
    budget.require_ms(min(fields['phase_deadline'], budget.cutoff(20)))
    raw = go_record(**fields)
    path = directory / ('phase-%04d.bin' % fields['sequence'])
    temporary = directory / ('.phase-%04d.tmp' % fields['sequence'])
    require(not path.exists() and not temporary.exists(), 'go_exists')
    launcher.write_private_bytes(temporary, raw)
    # rename, not replace: neither endpoint can overwrite an earlier admission.
    temporary.rename(path)
    budget.require_ms(fields['phase_deadline'])
    return sha(raw)


def selected_command(exe, role, run, boot_case, ready, reports, control, start, frequency, deadline,
                     fixed_ports, expected_user, capability_profile, admission):
    p = ports(fixed_ports)
    clock_record(start, frequency, deadline)
    require(role in ('selected-client', 'health-client') and all(ac.nonce(x) for x in (run, boot_case, admission))
        and type(expected_user) is str and launcher.SID_PATTERN.fullmatch(expected_user)
        and (capability_profile in ('agentic-only', 'agentic-pncs')
             or role == 'health-client' and capability_profile == 'ordinary'), 'selected_command')
    return [str(exe), role, run, boot_case, str(ready), str(reports), str(control), str(frequency),
        str(start), str(deadline), str(p['proxy']), str(p['wrong_port']), str(p['origin']), expected_user,
        capability_profile, admission]


def request_document(*, run, command, cwd, inputs, control, reports, native_environment, peer, fixed_ports, timeout_ms):
    """Final request is built from independently held live peer, then re-probed."""
    p = ports(fixed_ports)
    require(ac.nonce(run) and type(command) is list and len(command) == 16
        and all(type(x) is str and x and '\0' not in x for x in command), 'request_command')
    require(command[1] in ('selected-client', 'health-client') and command[2] == run
        and command[14] == 'agentic-pncs' and all(ac.nonce(command[k]) for k in (3, 15))
        and command[4] == str(Path(reports) / 'ready.json') and command[5] == str(reports)
        and command[6] == str(control) and [command[k] for k in (10, 11, 12)] ==
            [str(p[k]) for k in ('proxy', 'wrong_port', 'origin')], 'request_command_binding')
    require(all(re.fullmatch(r'0|[1-9][0-9]*', command[k]) for k in (7, 8, 9)), 'request_clock')
    clock_record(int(command[8]), int(command[7]), int(command[9]))
    require(type(peer) is dict and set(peer) == {'profile', 'derived_sid', 'held_sid', 'held', 'listener_port'}
        and peer['held'] is True and peer['held_sid'] == peer['derived_sid']
        and ac.ac_profile_sid(peer['derived_sid']) and peer['listener_port'] == p['proxy']
        and type(peer['profile']) is str and re.fullmatch(r'RuleProxy\.Model2\.[AB]\.[0-9a-f]{32}', peer['profile']), 'live_peer')
    require(type(native_environment) is list and len(native_environment) == 3
        and all(type(x) is str and '\0' not in x for x in native_environment), 'request_environment')
    env = dict(x.split('=', 1) for x in native_environment)
    require(set(env) == {'SystemRoot', 'WINDIR', 'LOCALAPPDATA'} and env['SystemRoot'] == env['WINDIR']
        and bool(env['SystemRoot']) and bool(env['LOCALAPPDATA']), 'request_environment')
    require(integer(timeout_ms, 1000, 120000), 'request_timeout')
    return {'$schema': 'https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json',
        'version': '1.0.0', 'containment': 'processcontainer', 'containerId': 'ruleproxy-model2-live-' + run,
        'fallback': {'allowDaclMutation': False},
        'process': {'commandLine': subprocess.list2cmdline(command), 'cwd': str(cwd), 'inheritDefaultEnv': False,
            'env': list(native_environment), 'timeout': timeout_ms},
        'filesystem': {'readonlyPaths': [str(inputs), str(control)], 'readwritePaths': [str(reports)]},
        'ui': {'disable': True, 'clipboard': 'none'},
        'network': {'egress': {'default': 'deny'}, 'ingress': {'default': 'allow', 'hostLoopback': 'deny'}},
        'processContainer': {'network': {'allowedProxyPeer': peer['profile']}},
        'runtimeConfig': {'networkProxy': 'http://127.0.0.1:' + str(p['proxy'])}}


def firewall_rule(run, suffix, package_sid, program, port):
    require(ac.nonce(run) and suffix in ('A-P', 'A-Q', 'B-P') and ac.ac_profile_sid(package_sid)
        and integer(port, 49153, 65535), 'firewall_scope')
    require(isinstance(program, (str, Path)) and str(program) and '\0' not in str(program), 'firewall_program')
    return dict(name='RuleProxy.Model2.' + run + '.' + suffix, package_sid=package_sid,
        program=str(program), direction='Inbound', action='Allow', protocol='TCP',
        local_address='127.0.0.1', remote_address='127.0.0.1', local_port=port,
        remote_port='Any', profile='Any', enabled=True, edge_traversal='Block',
        override_block_rules=False, policy_store='PersistentStore')


def validate_rule(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'firewall_schema')
    require(all(type(value[k]) is type(expected[k]) and value[k] == expected[k] for k in expected), 'firewall_scope')
    return value


class RuleOwnership:
    """Intent precedes mutation; uncertain create is retained until exact readback."""
    def __init__(self, rule):
        self.rule = dict(rule)
        self.intent = False
        self.attempted = False
        self.present_verified = False
        self.absent_verified = False
        self.uncertain = False

    def create(self, api, budget, journal):
        require(not self.intent and not self.attempted, 'rule_once')
        budget.require_ms(budget.cutoff(30))
        require(api.rule_read(self.rule['name'], 'PersistentStore') is None
            and api.rule_read(self.rule['name'], 'ActiveStore') is None, 'fresh_rule')
        journal({'schema_version': 1, 'rule': self.rule, 'state': 'intent'})
        self.intent = True
        self.attempted = True
        try:
            api.rule_create(self.rule)
            budget.require_ms(budget.cutoff(30))
            validate_rule(api.rule_read(self.rule['name'], 'PersistentStore'), self.rule)
            validate_rule(api.rule_read(self.rule['name'], 'ActiveStore'), self.rule)
            self.present_verified = True
            journal({'schema_version': 1, 'rule': self.rule, 'state': 'present-verified'})
        except BaseException:
            self.uncertain = True
            raise

    def remove(self, api, budget, journal, *, all_held_exited, job_empty):
        require(all_held_exited is True and job_empty is True, 'rule_live_processes')
        if not self.attempted:
            self.absent_verified = True
            return True
        budget.require_ms(budget.cutoff(5))
        # Only an exact owned object may be deleted. No wildcard/prefix fallback.
        stored = api.rule_read(self.rule['name'], 'PersistentStore')
        effective = api.rule_read(self.rule['name'], 'ActiveStore')
        if stored is not None:
            validate_rule(stored, self.rule)
        if effective is not None:
            validate_rule(effective, self.rule)
        if stored is None and effective is not None:
            self.uncertain = True
            raise ValueError('effective_rule_without_owned_store')
        if stored is not None:
            try:
                api.rule_remove(self.rule)
            except BaseException:
                self.uncertain = True
                raise
        budget.require_ms(budget.cutoff(5))
        require(api.rule_read(self.rule['name'], 'PersistentStore') is None
            and api.rule_read(self.rule['name'], 'ActiveStore') is None, 'rule_still_present')
        self.absent_verified = True
        # Historical uncertainty stays sticky, even after later cleanup succeeds.
        journal({'schema_version': 1, 'rule': self.rule, 'state': 'absent-verified'})
        return True


def candidate_observations(api, owners, budget, candidates, *, first, second, first_images,
                           second_images, g_pid, g_created, job, guard_name, scoped_owners):
    """Private read-only facts for a rejected set; never an admission policy."""
    rows = []
    for pid, created, handle in candidates[:16]:
        row = dict(pid=pid, created=created, first_parent=first.get(pid), second_parent=second.get(pid),
            first_image=first_images.get(pid), second_image=second_images.get(pid), query_sync_handle_held=True,
            creation_stable=False, alive=False, image_path=None, image_sha256=None,
            system_conhost_path=None, system_conhost_sha256=None, system_conhost_image_equal=False,
            identity=None, capabilities=None, workload_job_verified=False, outer_job_verified=False,
            outer_query_handle_closed=False, network_authorized=False, errors=[])
        rows.append(row)
        def read(step, action):
            try:
                budget.require_ms(budget.cutoff(25))
                return action()
            except BaseException as exc:
                code = getattr(exc, 'winerror', None)
                row['errors'].append(dict(step=step, category=type(exc).__name__[:64],
                    winerror=code if integer(code) else None))
                return None
        def generation():
            row['creation_stable'] = (api.creation_time(handle) == created and created >= g_created
                and api.process_id(handle) == pid and first.get(pid) == g_pid and second.get(pid) == g_pid)
            row['alive'] = not api.wait(handle, 0)
        read('generation', generation)
        def image_fact():
            observed = api.process_image(handle)
            require(type(observed) is str and 0 < len(observed) <= 4096, 'candidate_image')
            row['image_path'] = observed
            path = launcher.checked_path(observed)
            row['image_sha256'] = sha(local.bounded(path, 8 * 1024 * 1024))
            expected = api.system_conhost_path()
            require(type(expected) is str and 0 < len(expected) <= 4096, 'system_conhost_image')
            row['system_conhost_path'] = expected
            row['system_conhost_sha256'] = sha(local.bounded(launcher.checked_path(expected), 8 * 1024 * 1024))
            row['system_conhost_image_equal'] = (os.path.normcase(observed) == os.path.normcase(expected)
                and row['image_sha256'] == row['system_conhost_sha256'])
        read('image', image_fact)
        def token_fact():
            token = api.token_for_process(handle)
            owners.add(token)
            row['identity'] = api.identity(token)
            entries = api.groups(token, 30, 'TokenCapabilities')
            require(type(entries) is list and len(entries) <= 64, 'candidate_capability_bound')
            row['capabilities'] = [{'sid': sid, 'attributes': flags} for sid, flags in entries]
        read('token', token_fact)
        def workload_fact():
            api.verify_job(job, handle)
            row['workload_job_verified'] = True
        read('workload_job', workload_fact)
        scope = helpers.OneShotHandles(api.close)
        scoped_owners.append(scope)
        def outer_fact():
            verify_exact_guard_member(api, handle, guard_name, owners=scope)
            row['outer_job_verified'] = True
        read('outer_job', outer_fact)
        row['outer_query_handle_closed'] = scope.confirmed_closed
        read('generation_after_queries', generation)
    return rows


def validate_selected_admission(value):
    require(type(value) is dict and set(value) == {'profile', 'conhost_sha256'}
        and value['profile'] == 'actor-plus-system-conhost-v1' and ac.digest(value['conhost_sha256']), 'selected_admission')
    return value


def system_conhost_record(api):
    if hasattr(api, 'system_conhost_path'):
        path = launcher.checked_path(api.system_conhost_path())
    else:
        api.k.GetSystemDirectoryW.argtypes = [C.c_wchar_p, C.c_uint32]
        api.k.GetSystemDirectoryW.restype = C.c_uint32
        buffer = C.create_unicode_buffer(32768)
        length = api.k.GetSystemDirectoryW(buffer, len(buffer))
        require(0 < length < len(buffer), 'system_directory')
        path = launcher.checked_path(Path(buffer.value) / 'conhost.exe')
    require(path.name.casefold() == 'conhost.exe', 'system_conhost_image')
    return dict(profile='actor-plus-system-conhost-v1', conhost_sha256=sha(local.bounded(path, 8 * 1024 * 1024)))


def admit_selected(api, owners, budget, *, g_process, g_created, job, image, image_hash,
                   parent, capability_profile, catalog, diagnostic_guard_name=None, diagnostic_scoped_owners=None,
                   selected_admission=None, auxiliary_register=None):
    """Discovery does not authorize. Hold generation+image+Job+token before GO."""
    require(capability_profile in ('agentic-only', 'agentic-pncs'), 'selected_profile')
    require(integer(g_created, 1, 0xffffffffffffffff) and ac.digest(image_hash), 'selected_parent')
    if selected_admission is not None:
        validate_selected_admission(selected_admission)
        require(callable(auxiliary_register) and type(diagnostic_scoped_owners) is list
            and system_conhost_record(api) == selected_admission, 'selected_helper_contract')
    budget.require_ms(budget.cutoff(25))
    require(not api.wait(g_process, 0) and api.creation_time(g_process) == g_created, 'g_generation')
    g_pid = api.process_id(g_process)
    first = api.parent_snapshot()
    first_images = dict(getattr(api, 'last_snapshot_images', {}))
    candidates = []
    # Every query HANDLE is kept in the ledger, including rejected candidates.
    for pid, ppid in first.items():
        if ppid != g_pid or pid == g_pid:
            continue
        budget.require_ms(budget.cutoff(25))
        handle = api.open_query_process(pid)
        owners.add(handle)
        created = api.creation_time(handle)
        if created >= g_created:
            candidates.append((pid, created, handle))
    second = api.parent_snapshot()
    first_children = {pid for pid, ppid in first.items() if ppid == g_pid and pid != g_pid}
    second_children = {pid for pid, ppid in second.items() if ppid == g_pid and pid != g_pid}
    if not (first_children == second_children and len(first_children) == (2 if selected_admission is not None else 1)
            and {pid for pid, _, _ in candidates} == first_children):
        error = ValueError('selected_child_set_changed')
        error.discovery = dict(parent_pid=g_pid, parent_created=g_created,
            first_child_count=len(first_children), second_child_count=len(second_children),
            first_children=sorted(first_children)[:16], second_children=sorted(second_children)[:16],
            first_images={str(pid):first_images.get(pid) for pid in sorted(first_children)[:16]},
            second_images={str(pid):getattr(api,'last_snapshot_images',{}).get(pid) for pid in sorted(second_children)[:16]},
            candidates=[dict(pid=pid,created=created) for pid,created,_ in candidates[:16]])
        if diagnostic_guard_name is not None:
            require(type(diagnostic_scoped_owners) is list, 'diagnostic_scoped_owners')
            error.discovery['held_observations'] = candidate_observations(api, owners, budget, candidates,
                first=first, second=second, first_images=first_images,
                second_images=dict(getattr(api, 'last_snapshot_images', {})), g_pid=g_pid, g_created=g_created,
                job=job, guard_name=diagnostic_guard_name, scoped_owners=diagnostic_scoped_owners)
        raise error
    require(not api.wait(g_process, 0) and api.creation_time(g_process) == g_created, 'g_generation')
    valid = []
    auxiliary = []
    expected_helper = launcher.checked_path(api.system_conhost_path()) if selected_admission is not None else None
    for pid, created, old in candidates:
        budget.require_ms(budget.cutoff(25))
        require(second.get(pid) == g_pid and not api.wait(old, 0), 'selected_child_changed')
        helper = False
        if selected_admission is not None:
            observed_image = launcher.checked_path(api.process_image(old))
            helper = os.path.normcase(str(observed_image)) == os.path.normcase(str(expected_helper))
            require(helper or os.path.normcase(str(observed_image)) == os.path.normcase(str(image)), 'selected_unexpected_image')
        handle = api.open_owned_process(pid)
        owners.add(handle)
        require(api.creation_time(handle) == created and api.creation_time(old) == created
            and api.process_id(handle) == pid, 'selected_pid_reuse')
        if helper:
            auxiliary_register(dict(handle=handle, pid=pid, created=created, image_path=str(expected_helper),
                image_sha256=selected_admission['conhost_sha256']))
        api.verify_job(job, handle)
        expected_image = expected_helper if helper else image
        expected_hash = selected_admission['conhost_sha256'] if helper else image_hash
        api.verify_image(handle, expected_image)
        helpers.verify_copied_actor(expected_image, expected_hash)
        token = api.token_for_process(handle)
        owners.add(token)
        identity = api.identity(token)
        capabilities = [{'sid': sid, 'attributes': flags} for sid, flags in api.groups(token, 30, 'TokenCapabilities')]
        if helper:
            require(launcher.token_is_ordinary(identity) and launcher.same_identity(identity, parent)
                and identity['token_type'] == 1 and identity['integrity_rid'] == 8192
                and identity['appcontainer'] is False and identity['appcontainer_sid'] is None
                and identity['capability_count'] == 0 and capabilities == [] and identity['ui_access'] is False,
                'selected_helper_identity')
            scope = helpers.OneShotHandles(api.close)
            diagnostic_scoped_owners.append(scope)
            verify_exact_guard_member(api, handle, diagnostic_guard_name, owners=scope)
            require(scope.confirmed_closed, 'selected_helper_outer_close')
            require(system_conhost_record(api) == selected_admission, 'selected_helper_hash_changed')
        else:
            selected_identity(identity, capabilities, parent, capability_profile, catalog)
        require(not api.wait(handle, 0), 'selected_exited')
        record = dict(handle=handle, pid=pid, created=created, identity=identity, capabilities=capabilities,
            image_verified=True, exact_job_verified=True, externally_held_before_first_resume=False,
            externally_held_before_network_go=True, discovery=dict(parent_pid=g_pid, parent_created=g_created,
                first_children=sorted(first_children), second_children=sorted(second_children),
                query_created=api.creation_time(old), held_created=api.creation_time(handle)))
        (auxiliary if helper else valid).append(record)
    require(len(valid) == 1 and len(auxiliary) == (1 if selected_admission is not None else 0), 'selected_not_unique')
    if auxiliary:
        valid[0]['auxiliary'] = auxiliary[0]
        valid[0]['discovery']['auxiliary'] = dict(pid=auxiliary[0]['pid'], created=auxiliary[0]['created'],
            query_created=auxiliary[0]['discovery']['query_created'], held_created=auxiliary[0]['discovery']['held_created'],
            workload_job_verified=True, outer_job_verified=True, outer_query_handle_closed=True)
    budget.require_ms(budget.cutoff(25))
    return valid[0]


def verify_exact_guard_member(api, process, name, *, owners=None):
    require(type(name) is str and re.fullmatch(r'Local\\RuleProxy\.LocalGuard\.[0-9a-f]{32}', name), 'outer_job_name')
    api.k.OpenJobObjectW.argtypes = [C.c_uint32, C.c_int, C.c_wchar_p]
    api.k.OpenJobObjectW.restype = C.c_void_p
    job = api.k.OpenJobObjectW(4, False, name)
    api.native.check(job, 'OpenJobObjectW(selected_outer_query)')
    if owners is not None: owners.add(job)
    try:
        api.verify_job(job, process)
        limits = api.proc._JobExtendedLimitInfo()
        api.native.check(api.k.QueryInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits), None), 'QueryInformationJobObject(selected_outer)')
        require(limits.BasicLimitInformation.LimitFlags == launcher.KILL_ON_JOB_CLOSE, 'selected_outer_job_limits')
    finally:
        api.close(job) if owners is None else owners.close(job)


class LiveNativeAPI(origin.OriginAPI):
    """Only instantiated in the owned runtime. No network or policy at import."""
    def __init__(self):
        super().__init__()
        H, D = C.c_void_p, C.c_uint32
        self.k.GetProcessTimes.argtypes = [H, H, H, H, H]
        self.k.GetProcessTimes.restype = C.c_int
        self.k.GetProcessId.argtypes = [H]
        self.k.GetProcessId.restype = D
        self.k.OpenProcess.argtypes = [D, C.c_int, D]
        self.k.OpenProcess.restype = H
        self.k.CreateToolhelp32Snapshot.argtypes = [D, D]
        self.k.CreateToolhelp32Snapshot.restype = H

    private_descriptor = local.LocalNativeAPI.private_descriptor
    private_directory = local.LocalNativeAPI.private_directory
    verify_private_directory = local.LocalNativeAPI.verify_private_directory

    def creation_time(self, process):
        creation, exit_time, kernel, user = (C.c_uint64() for _ in range(4))
        self.native.check(self.k.GetProcessTimes(process, C.byref(creation), C.byref(exit_time),
            C.byref(kernel), C.byref(user)), 'GetProcessTimes')
        require(creation.value > 0, 'creation_time')
        return creation.value

    def process_id(self, process):
        value = int(self.k.GetProcessId(process))
        self.native.check(value, 'GetProcessId')
        return value

    def process_image(self, process):
        size = C.c_uint32(32768)
        buffer = C.create_unicode_buffer(size.value)
        self.native.check(self.k.QueryFullProcessImageNameW(process, 0, buffer, C.byref(size)), 'QueryFullProcessImageNameW(candidate)')
        require(0 < size.value < len(buffer), 'candidate_image')
        return buffer.value

    def system_conhost_path(self):
        self.k.GetSystemDirectoryW.argtypes = [C.c_wchar_p, C.c_uint32]
        self.k.GetSystemDirectoryW.restype = C.c_uint32
        buffer = C.create_unicode_buffer(32768)
        length = self.k.GetSystemDirectoryW(buffer, len(buffer))
        self.native.check(0 < length < len(buffer), 'GetSystemDirectoryW(candidate)')
        return str(launcher.checked_path(Path(buffer.value) / 'conhost.exe'))

    def open_query_process(self, pid):
        handle = self.k.OpenProcess(0x1000 | 0x100000, False, pid)
        self.native.check(handle, 'OpenProcess(query_sync)')
        return handle

    def open_owned_process(self, pid):
        handle = self.k.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
        self.native.check(handle, 'OpenProcess(held_selected)')
        return handle

    def parent_snapshot(self):
        class Entry(C.Structure):
            _fields_ = [('size', C.c_uint32), ('usage', C.c_uint32), ('pid', C.c_uint32),
                ('heap', C.c_size_t), ('module', C.c_uint32), ('threads', C.c_uint32),
                ('ppid', C.c_uint32), ('priority', C.c_int32), ('flags', C.c_uint32), ('image', C.c_wchar * 260)]
        for name in ('Process32FirstW', 'Process32NextW'):
            fn = getattr(self.k, name)
            fn.argtypes, fn.restype = [C.c_void_p, C.POINTER(Entry)], C.c_int
        snapshot = self.k.CreateToolhelp32Snapshot(2, 0)
        require(snapshot != C.c_void_p(-1).value and bool(snapshot), 'snapshot')
        try:
            entry = Entry()
            entry.size = C.sizeof(entry)
            ok = self.k.Process32FirstW(snapshot, C.byref(entry))
            result = {}
            images = {}
            while ok:
                require(entry.pid not in result and len(result) < 32768, 'snapshot_bound')
                result[int(entry.pid)] = int(entry.ppid)
                images[int(entry.pid)] = str(entry.image)
                ok = self.k.Process32NextW(snapshot, C.byref(entry))
            require(C.get_last_error() == 18, 'snapshot_end')
            self.last_snapshot_images = images
            return result
        finally:
            self.close(snapshot)

    def catalog(self):
        catalog = proof.WindowsCapabilityObserver().catalog()
        require(catalog['privateNetworkClientServer'] == PNCS, 'catalog')
        return catalog

    def derive_profile_sid(self, name):
        self.ue.DeriveAppContainerSidFromAppContainerName.argtypes = [C.c_wchar_p, C.POINTER(C.c_void_p)]
        self.ue.DeriveAppContainerSidFromAppContainerName.restype = C.c_long
        pointer = C.c_void_p()
        code = self.ue.DeriveAppContainerSidFromAppContainerName(name, C.byref(pointer)) & 0xffffffff
        try:
            require(code == 0 and bool(pointer.value), 'profile_derive')
            text = C.c_wchar_p()
            self.native.check(self.a.ConvertSidToStringSidW(pointer, C.byref(text)), 'ConvertSidToStringSidW(profile)')
            try:
                require(ac.ac_profile_sid(text.value), 'profile_sid')
                return text.value
            finally:
                if self.k.LocalFree(C.cast(text, C.c_void_p)):
                    raise ValueError('profile_derive_text_close')
        finally:
            if pointer.value and self.a.FreeSid(pointer):
                raise ValueError('profile_derive_sid_close')

    def create_with_environment(self, info, command, cwd, stdio, environment):
        require(type(stdio) is list and len(stdio) == 3 and len(set(stdio)) == 3, 'stdio')
        require(type(environment) is str and environment.endswith('\0\0'), 'environment')
        H = C.c_void_p
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
        require(1 <= size.value <= 65536, 'attributes')
        attrs = C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs, 1, 0, C.byref(size)), 'InitializeProcThreadAttributeList')
        try:
            handles = (H * 3)(*stdio)
            self.native.check(self.k.UpdateProcThreadAttribute(attrs, 0, 0x20002, handles, C.sizeof(handles), None, None), 'UpdateProcThreadAttribute(stdio)')
            startup = self.proc._StartupInfoEx()
            startup.StartupInfo.cb = C.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x100
            startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = stdio
            startup.lpAttributeList = C.cast(attrs, H)
            self.native.check(self.k.CreateProcessW(command[0], C.create_unicode_buffer(subprocess.list2cmdline(command)), None, None,
                True, self.proc._CREATE_SUSPENDED | self.proc._CREATE_UNICODE_ENVIRONMENT | self.proc._EXTENDED_STARTUPINFO_PRESENT | 0x08000000,
                C.create_unicode_buffer(environment), str(cwd), C.byref(startup), C.byref(info)), 'CreateProcessW(fixed_environment)')
        finally:
            self.k.DeleteProcThreadAttributeList(attrs)

    def shell_elevated(self, image, arguments, directory):
        # RunAs is synchronous and can outlive a UAC prompt. The caller journals
        # an unknown spawn BEFORE entering this API; a guard timeout is not a
        # cancellation receipt. The bootstrap checks the original QPC before
        # joining its Job, publishing READY, accepting GO, or running policy.
        class ShellInfo(C.Structure):
            _fields_ = [('size', C.c_uint32), ('mask', C.c_uint32), ('window', C.c_void_p),
                ('verb', C.c_wchar_p), ('file', C.c_wchar_p), ('parameters', C.c_wchar_p),
                ('directory', C.c_wchar_p), ('show', C.c_int), ('instance', C.c_void_p),
                ('id_list', C.c_void_p), ('class_name', C.c_wchar_p), ('class_key', C.c_void_p),
                ('hotkey', C.c_uint32), ('icon_or_monitor', C.c_void_p), ('process', C.c_void_p)]
        shell = C.WinDLL('shell32', use_last_error=True)
        shell.ShellExecuteExW.argtypes, shell.ShellExecuteExW.restype = [C.POINTER(ShellInfo)], C.c_int
        value = ShellInfo()
        value.size, value.mask = C.sizeof(value), 0x40 | 0x100 | 0x400
        value.verb, value.file, value.parameters = 'runas', str(image), arguments
        value.directory, value.show = str(directory), 0  # SW_HIDE, never a visible console.
        self.native.check(shell.ShellExecuteExW(C.byref(value)), 'ShellExecuteExW(maintenance)')
        require(bool(value.process), 'maintenance_process_handle')
        return value.process


    def pncs_create(self, info, command, cwd, inherited, owners, state, profile_pointer, environment):
        """A distinct C constructor: exact PNCS, no change to A's zero-cap gate."""
        require(type(inherited) in (tuple, list) and len(inherited) in (0, 2)
            and len(set(inherited)) == len(inherited), 'inheritance')
        H = C.c_void_p
        count = 1 + bool(inherited)
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, count, 0, C.byref(size))
        require(1 <= size.value <= 65536, 'attributes')
        attrs = C.create_string_buffer(size.value)
        self.native.check(self.k.InitializeProcThreadAttributeList(attrs, count, 0, C.byref(size)), 'InitializeProcThreadAttributeList')
        sid = C.create_string_buffer(68)
        sid_size = C.c_uint32(len(sid))
        self.a.CreateWellKnownSid.argtypes = [C.c_int, H, H, C.POINTER(C.c_uint32)]
        self.a.CreateWellKnownSid.restype = C.c_int
        try:
            self.native.check(self.a.CreateWellKnownSid(87, None, sid, C.byref(sid_size)), 'CreateWellKnownSid(PNCS)')
            require(8 <= sid_size.value <= len(sid), 'pncs_sid')
            entries = (launcher.SIDAndAttributes * 1)(launcher.SIDAndAttributes(C.cast(sid, H), 4))
            capability = self.proc._SecurityCapabilities(profile_pointer, C.cast(entries, H), 1, 0)
            self.native.check(self.k.UpdateProcThreadAttribute(attrs, 0, self.proc._PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                C.byref(capability), C.sizeof(capability), None, None), 'UpdateProcThreadAttribute(PNCS)')
            handles = None
            if inherited:
                handles = (H * 2)(*inherited)
                self.native.check(self.k.UpdateProcThreadAttribute(attrs, 0, 0x20002, handles, C.sizeof(handles), None, None), 'UpdateProcThreadAttribute(pipe_list)')
            startup = self.proc._StartupInfoEx()
            startup.StartupInfo.cb = C.sizeof(startup)
            startup.lpAttributeList = C.cast(attrs, H)
            def create():
                ok = self.k.CreateProcessW(command[0], C.create_unicode_buffer(subprocess.list2cmdline(command)), None, None,
                    bool(inherited), self.proc._CREATE_SUSPENDED | self.proc._CREATE_UNICODE_ENVIRONMENT
                    | self.proc._EXTENDED_STARTUPINFO_PRESENT | 0x08000000,
                    C.create_unicode_buffer(environment), str(cwd), C.byref(startup), C.byref(info))
                return ok, C.get_last_error() if not ok else 0
            def check(result):
                if not result[0]:
                    raise launcher.NativeFailure('CreateProcessW(PNCS)', result[1])
            helpers.create_suspended_owned(create, check, info, owners, state)
        finally:
            self.k.DeleteProcThreadAttributeList(attrs)


class CleanupView:
    """A cutoff in the original QPC domain, never a newly sampled duration."""
    def __init__(self, budget, deadline):
        require(integer(deadline, 1, budget.deadline), 'cleanup_cutoff')
        self.budget, self.deadline = budget, deadline

    def read(self):
        return self.budget.read()

    def remaining_ms(self, cutoff, cap_ms=None):
        return self.budget.remaining_ms(min(cutoff, self.deadline), cap_ms)


MODES = ('strict', 'profiles-off-diagnostic')


def execution_mode(value):
    mode = value.get('execution_mode', 'strict') if type(value) is dict else None
    require(mode in MODES and ('execution_mode' not in value or mode == 'profiles-off-diagnostic'), 'execution_mode')
    return mode


def diagnostic_ready(value, *, require_guard=True):
    required = ('sources', 'artifacts', 'ordinary', 'live_probe', 'selected_held', 'declared_caps',
        'positive', 'origin_healthy', 'same_selected', 'cleanup')
    d = value['diagnostic']
    return (value['execution_mode'] == 'profiles-off-diagnostic' and all(value['checks'][key] for key in required)
        and (not require_guard or value['checks']['guard_held']) and value['failure'] is None
        and all(d[key] for key in ('requested', 'profiles_off_verified', 'exact_rule_scope_verified',
            'positive_verified', 'direct_attempted', 'observation_complete')))


def first_ready(value, *, require_guard=True):
    required = ('sources', 'artifacts', 'ordinary', 'live_probe', 'selected_held', 'declared_caps',
        'firewall_exact', 'positive', 'origin_healthy', 'direct_deny', 'same_selected', 'cleanup')
    return (value['execution_mode'] == 'strict' and all(value['checks'][key] for key in required) and (not require_guard or value['checks']['guard_held'])
        and not any(value['violations'].values()) and value['failure'] is None)


def finalize_public(value):
    value['direct_deny_verified'] = (value['execution_mode'] == 'strict' and value['checks']['direct_deny'] and value['checks']['origin_healthy']
        and not value['violations']['direct_connected'] and not value['violations']['forbidden_receiver_accepted'])
    value['first_chain_verified'] = first_ready(value)
    value['local_c_qualified'] = value['execution_mode'] == 'strict' and all(value['checks'].values()) and not any(value['violations'].values()) and value['failure'] is None
    value['diagnostic_completed'] = diagnostic_ready(value)
    if value['diagnostic_completed']:
        value['status'] = 'diagnostic-observed'
    elif value['local_c_qualified']:
        value['status'] = 'passed'
    elif value['first_chain_verified']:
        value['status'] = 'observed'
    elif any(value['violations'].values()):
        value['status'] = 'failed'
    elif value['status'] in ('observed', 'passed', 'diagnostic-observed'):
        value['status'] = 'inconclusive'
    return validate_public(value)


def blank(execution_mode='strict'):
    require(execution_mode in MODES, 'execution_mode')
    return dict(schema_version=1, stage='local-model2-live', profile='pncs-peer-port-held-barrier-v1',
        execution_mode=execution_mode, diagnostic={key: key == 'requested' and execution_mode == 'profiles-off-diagnostic'
            for key in ('requested', 'profiles_off_verified', 'exact_rule_scope_verified', 'effective_full_verified',
                'positive_verified', 'direct_attempted', 'direct_connected', 'direct_denied_by_access',
                'forbidden_nonce_received', 'observation_complete')}, diagnostic_completed=False,
        status='inconclusive', failure=None, source_sha256=None, actor_sha256=None, manifest_sha256=None,
        run_sha256=None, checks={k: False for k in ('sources', 'artifacts', 'ordinary', 'guard_held',
            'live_probe', 'selected_held', 'declared_caps', 'firewall_exact', 'positive', 'origin_healthy', 'direct_deny', 'wrong_port',
            'wrong_peer', 'proxy_death', 'same_selected', 'cleanup')},
        violations={k: False for k in ('direct_connected', 'wrong_port_connected', 'wrong_peer_connected',
            'forbidden_receiver_accepted', 'fallback_after_death')},
        observations=dict(selected_network_attempted=False, real_http_accepted=False, origin_nonce_received=False),
        original_stage0=False, system_dns_tested=False, service_brokers_tested=False,
        winhttp_tested=False, application_adapter_tested=False, product_acceptance=False,
        first_chain_verified=False, direct_deny_verified=False, local_c_qualified=False)


def validate_public(value):
    template = blank()
    require(type(value) is dict and set(value) == set(template), 'public_schema')
    for key in ('schema_version', 'stage', 'profile', 'original_stage0', 'system_dns_tested',
                'service_brokers_tested', 'winhttp_tested', 'application_adapter_tested', 'product_acceptance'):
        require(type(value[key]) is type(template[key]) and value[key] == template[key], 'public_scope')
    require(value['execution_mode'] in MODES, 'public_mode')
    for key in ('checks', 'violations', 'observations', 'diagnostic'):
        require(type(value[key]) is dict and set(value[key]) == set(template[key])
            and all(type(x) is bool for x in value[key].values()), 'public_types')
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256', 'run_sha256'):
        require(value[key] is None or ac.digest(value[key]), 'public_digest')
    require(value['status'] in ('ready', 'inconclusive', 'failed', 'observed', 'passed', 'diagnostic-observed')
        and value['failure'] in (None, 'platform', 'identity', 'inputs', 'deadline', 'staging', 'worker',
            'probe', 'selected', 'firewall', 'health', 'positive', 'wrong-port', 'wrong-peer', 'death', 'cleanup', 'report'), 'public_state')
    require(type(value['local_c_qualified']) is bool, 'public_types')
    require(type(value['first_chain_verified']) is bool and value['first_chain_verified'] == first_ready(value), 'public_first_cell')
    require(type(value['direct_deny_verified']) is bool
        and value['direct_deny_verified'] == (value['execution_mode'] == 'strict' and value['checks']['direct_deny'] and value['checks']['origin_healthy']
            and not value['violations']['direct_connected'] and not value['violations']['forbidden_receiver_accepted']), 'public_direct')
    passed = value['execution_mode'] == 'strict' and all(value['checks'].values()) and not any(value['violations'].values()) and value['failure'] is None
    require(value['local_c_qualified'] == passed and (value['status'] == 'passed') == passed, 'public_qualification')
    require((value['status'] == 'observed') == (value['first_chain_verified'] and not passed), 'public_first_cell')
    require(type(value['diagnostic_completed']) is bool and value['diagnostic_completed'] == diagnostic_ready(value)
        and (value['status'] == 'diagnostic-observed') == value['diagnostic_completed'], 'public_diagnostic')
    if value['execution_mode'] == 'strict':
        require(not any(value['diagnostic'].values()), 'public_diagnostic_scope')
    else:
        require(value['diagnostic']['requested'] and not value['checks']['firewall_exact'], 'public_diagnostic_scope')
        d = value['diagnostic']
        require(not d['positive_verified'] or value['checks']['positive'], 'diagnostic_positive')
        require(d['direct_connected'] == value['violations']['direct_connected']
            and d['forbidden_nonce_received'] == value['violations']['forbidden_receiver_accepted'], 'diagnostic_binding')
        require(not d['direct_denied_by_access'] or value['checks']['direct_deny'] and not d['direct_connected']
            and not d['forbidden_nonce_received'], 'diagnostic_deny')
    if value['status'] == 'ready':
        require(value['checks']['sources'] and value['checks']['artifacts']
            and not any(v for k, v in value['checks'].items() if k not in ('sources', 'artifacts'))
            and not any(value['observations'].values()) and not any(value['violations'].values())
            and not any(v for k,v in value['diagnostic'].items() if k != 'requested')
            and value['run_sha256'] is None and value['failure'] is None, 'public_readiness')
    require(not value['checks']['positive'] or all(value['observations'].values()), 'public_positive')
    require(len(encode(value)) <= MAX_PUBLIC, 'public_bound')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actor', type=Path)
    parser.add_argument('--manifest', type=Path)
    parser.add_argument('--actor-sha256')
    parser.add_argument('--manifest-sha256')
    args = parser.parse_args(argv)
    result = blank()
    phase = 'inputs'
    try:
        _, _, result['source_sha256'] = source_snapshot()
        result['checks']['sources'] = True
        verify_actor(args.actor, args.manifest, args.actor_sha256, args.manifest_sha256, root=ROOT)
        result.update(actor_sha256=args.actor_sha256, manifest_sha256=args.manifest_sha256, status='ready')
        result['checks']['artifacts'] = True
    except BaseException:
        result['failure'] = phase
    sys.stdout.buffer.write(encode(validate_public(result)))
    return 0 if result['status'] == 'ready' else 1


if __name__ == '__main__':
    raise SystemExit(main())
