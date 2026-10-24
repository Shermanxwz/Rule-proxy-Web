"""Separate opt-in local request probe; never launch a contained workload.

The pinned CLI runs its DACL reaper before --probe. Isolate that reaper with
an exact five-key child environment and a fresh, protected, empty state root.
The peer is deliberately unobserved: this measures candidate request/tier
compatibility, not peer existence, networking, Stage0, or product acceptance.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MAX_OUTPUT = 16 * 1024
MEMBERS = ('build-manifest.json', 'wxc-exec.exe', 'MXC-LICENSE.md')
MEMBER_LIMITS = (16 * 1024, 32 * 1024 * 1024, 64 * 1024)
CHECKS = ('artifacts', 'sources', 'request', 'ordinary', 'windows_x64',
          'fresh_empty_state', 'five_key_environment', 'atomic_job',
          'held_identity', 'held_exit', 'outer_cleanup', 'empty_state_after', 'parsed_output')
PHASES = ('platform', 'deadline', 'inputs', 'identity', 'staging', 'launch', 'report', 'cleanup')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


local = load('model2_local_owner_helpers', ROOT / '.github/windows_identity_proxy_pipe_ac_local.py')
pins = load('model2_pinned_runtime_constants', ROOT / 'ruleproxy/windows_runtime_pins.py')
launcher = local.launcher
SOURCES = ('.github/windows_identity_model2_local_probe.py', *local.SOURCES,
           'ruleproxy/windows_runtime_pins.py')


def encode(value):
    return local.encode(value)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def source_snapshot(root=ROOT):
    hashes = {name: sha(local.bounded(root / name, 256 * 1024)) for name in SOURCES}
    return sha(encode(hashes))


def admit_work_parent(path=None, *, root=ROOT):
    root = launcher.checked_path(root, is_file=False)
    base = launcher.checked_path(root / 'private', inside=root, is_file=False)
    return launcher.checked_path(base if path is None else path, inside=base, is_file=False)


def request_document(nonce, port=49183):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}', nonce) is None:
        raise ValueError('request_nonce')
    if type(port) is not int or not 49152 <= port <= 65535:
        raise ValueError('request_port')
    return {
        '$schema': 'https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json',
        'version': '1.0.0', 'containment': 'processcontainer',
        'containerId': 'ruleproxy-model2-probe-' + nonce,
        'fallback': {'allowDaclMutation': False},
        # Metadata for the parser only. The fixed CLI can never omit --probe.
        'process': {'commandLine': 'cmd.exe /d /c exit 97', 'env': [],
                    'inheritDefaultEnv': False, 'timeout': 1000},
        'ui': {'disable': True, 'clipboard': 'none'},
        'network': {'egress': {'default': 'deny'},
                    'ingress': {'default': 'allow', 'hostLoopback': 'deny'}},
        'runtimeConfig': {'networkProxy': 'http://127.0.0.1:' + str(port)},
        'processContainer': {'network': {'allowedProxyPeer': 'RuleProxy.IdentityProof.' + nonce}},
    }


def validate_request(value):
    try:
        container = value['containerId']
        nonce = container.removeprefix('ruleproxy-model2-probe-')
        endpoint = value['runtimeConfig']['networkProxy']
        match = re.fullmatch(r'http://127\.0\.0\.1:([0-9]{5})', endpoint)
        if match is None or encode(value) != encode(request_document(nonce, int(match[1]))):
            raise ValueError('request')
    except (KeyError, TypeError, AttributeError):
        raise ValueError('request') from None
    return value


def verify_artifacts(bundle, runtime_directory):
    bundle = launcher.checked_path(bundle)
    directory = launcher.checked_path(runtime_directory, is_file=False)
    raw = local.bounded(bundle, 32 * 1024 * 1024)
    if sha(raw) != pins.MXC_G_BUNDLE_SHA256:
        raise ValueError('bundle_hash')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        infos = archive.infolist()
        if tuple(item.filename for item in infos) != MEMBERS:
            raise ValueError('bundle_members')
        for item, limit in zip(infos, MEMBER_LIMITS):
            if (item.orig_filename != item.filename or item.is_dir()
                    or item.compress_type != zipfile.ZIP_STORED
                    or item.file_size != item.compress_size or not 0 < item.file_size <= limit
                    or item.date_time != (1980, 1, 1, 0, 0, 0)
                    or item.flag_bits & 1 or not stat.S_ISREG(item.external_attr >> 16)):
                raise ValueError('bundle_layout')
        files = {item.filename: archive.read(item) for item in infos}
    if {item.name for item in directory.iterdir()} != set(MEMBERS):
        raise ValueError('runtime_closure')
    for name, limit in zip(MEMBERS, MEMBER_LIMITS):
        if local.bounded(directory / name, limit) != files[name]:
            raise ValueError('runtime_member')
    manifest = local.guest.decode(files[MEMBERS[0]])
    image = files[MEMBERS[1]]
    if (manifest != pins.MXC_G_BUILD_MANIFEST or sha(image) != pins.MXC_G_EXECUTOR_SHA256
            or sha(files[MEMBERS[2]]) != pins.MXC_G_LICENSE_SHA256
            or len(image) < 512 or image[:2] != b'MZ'):
        raise ValueError('runtime_pins')
    offset = int.from_bytes(image[0x3c:0x40], 'little')
    if (offset < 64 or offset + 6 > len(image) or image[offset:offset + 4] != b'PE\0\0'
            or int.from_bytes(image[offset + 4:offset + 6], 'little') != 0x8664):
        raise ValueError('runtime_architecture')
    return directory / MEMBERS[1]


def child_environment(base, work, state):
    if (type(base) is not dict or set(base) != {'SystemRoot', 'WINDIR', 'TEMP', 'TMP'}
            or any(type(item) is not str or not item or '\0' in item for item in base.values())
            or base['SystemRoot'] != base['WINDIR']
            or base['TEMP'] != str(work / 'temp') or base['TMP'] != str(work / 'temp')
            or state != work / 'dacl-state'):
        raise ValueError('child_environment')
    return {**base, 'MXC_DACL_STATE_DIR': str(state)}


class ProbeAPI(local.LocalNativeAPI):
    def create_suspended(self, info, command, work, stdio, token):
        state = launcher.checked_path(self.reaper_state, inside=work, is_file=False)
        expected = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + self.worker_sid + ')'
        self.verify_private_directory(state, expected)
        if state != work / 'dacl-state' or list(state.iterdir()):
            raise ValueError('state_changed_before_create')
        super().create_suspended(info, command, work, stdio, token)

    def environment(self, work):
        block = super().environment(work)
        entries = block.rstrip('\0').split('\0')
        base = dict(item.split('=', 1) for item in entries)
        if len(entries) != 4 or len(base) != 4:
            raise ValueError('base_environment')
        result = child_environment(base, work, self.reaper_state)
        self.five_key_environment = len(result) == 5
        return self.proc._environment_block(result)

    def verify_image(self, process, expected):
        super().verify_image(process, expected)
        expected = Path(expected)
        if expected.name != 'wxc-exec.exe' or sha(local.bounded(expected, MEMBER_LIMITS[1])) != pins.MXC_G_EXECUTOR_SHA256:
            raise ValueError('held_image_hash')


def fixed_command(executor, request):
    return [str(executor), '--probe', '--config', str(request)]


def projection(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_OUTPUT:
        raise ValueError('probe_output_bound')
    value = local.guest.decode(raw)
    if (type(value) is not dict or not {'warnings', 'probes'} <= set(value)
            or not set(value) <= {'tier', 'needsDaclAugmentation', 'warnings', 'probes', 'error'}
            or type(value['warnings']) is not list or len(value['warnings']) > 16
            or any(type(item) is not str or len(item) > 4096 for item in value['warnings'])):
        raise ValueError('probe_shape')
    facts = value['probes']
    proof = local.controller.pipe_helpers.proof
    expected = set(proof.PROBE_FACTS) | {'uiCapabilities'}
    if type(facts) is not dict or set(facts) != expected:
        raise ValueError('probe_facts')
    if any(type(facts[key]) is not bool for key in proof.PROBE_FACTS):
        raise ValueError('probe_boolean')
    ui = facts['uiCapabilities']
    if type(ui) is not dict or set(ui) != set(proof.UI_FACTS) or any(type(v) is not bool for v in ui.values()):
        raise ValueError('probe_ui')
    error = value.get('error')
    if error is not None and (type(error) is not str or not error or len(error) > 4096):
        raise ValueError('probe_error')
    tier, needs = value.get('tier'), value.get('needsDaclAugmentation')
    if error is not None:
        if tier is not None or needs is not None:
            raise ValueError('probe_contradiction')
    elif tier not in ('base-container', 'appcontainer-bfs', 'appcontainer-dacl') or type(needs) is not bool:
        raise ValueError('probe_tier')
    return dict(tier=tier, needs_dacl_augmentation=needs, warning_count=len(value['warnings']),
                detector_error_present=error is not None,
                base_container_api_present=facts['baseContainerApiPresent'],
                bfs_compiled_in=facts['bfsCompiledIn'])


def blank():
    return dict(schema_version=1, stage='local-model2-candidate-request-probe-v1',
        status='failed', failure=None, source_sha256=None, request_sha256=None,
        bundle_sha256=pins.MXC_G_BUNDLE_SHA256, executor_sha256=pins.MXC_G_EXECUTOR_SHA256,
        checks={key: False for key in CHECKS}, probe=None, probe_exit_code=None, private_tree_retained=False,
        peer_observed=False, listener_observed=False, network_tested=False,
        proxy_tested=False, model2_runtime_qualified=False, strict_stage0_passed=False,
        product_acceptance=False)


def validate_public(value):
    template = blank()
    if type(value) is not dict or set(value) != set(template):
        raise ValueError('public_shape')
    for key in ('schema_version', 'stage', 'bundle_sha256', 'executor_sha256',
                'peer_observed', 'listener_observed', 'network_tested', 'proxy_tested',
                'model2_runtime_qualified', 'strict_stage0_passed', 'product_acceptance'):
        if type(value[key]) is not type(template[key]) or value[key] != template[key]:
            raise ValueError('public_constant')
    if value['status'] not in ('failed', 'prepared', 'supported_candidate', 'unsupported_candidate'):
        raise ValueError('public_status')
    if value['failure'] not in (None, *PHASES):
        raise ValueError('public_failure')
    if type(value['checks']) is not dict or set(value['checks']) != set(CHECKS) or any(type(v) is not bool for v in value['checks'].values()):
        raise ValueError('public_checks')
    for key in ('source_sha256', 'request_sha256'):
        if value[key] is not None and not local.controller.digest(value[key]):
            raise ValueError('public_hash')
    for check, key in (('sources', 'source_sha256'), ('request', 'request_sha256')):
        if value['checks'][check] and value[key] is None:
            raise ValueError('public_hash_binding')
    if type(value['private_tree_retained']) is not bool:
        raise ValueError('public_tree')
    if value['probe_exit_code'] is not None and (type(value['probe_exit_code']) is not int
            or not 0 <= value['probe_exit_code'] <= 0xffffffff):
        raise ValueError('public_exit_code')
    if value['probe'] is not None:
        p = value['probe']
        if type(p) is not dict or set(p) != {'tier', 'needs_dacl_augmentation', 'warning_count', 'detector_error_present', 'base_container_api_present', 'bfs_compiled_in'}:
            raise ValueError('public_probe')
        if (p['tier'] not in (None, 'base-container', 'appcontainer-bfs', 'appcontainer-dacl')
                or p['needs_dacl_augmentation'] is not None and type(p['needs_dacl_augmentation']) is not bool
                or type(p['warning_count']) is not int or not 0 <= p['warning_count'] <= 16
                or any(type(p[key]) is not bool for key in ('detector_error_present', 'base_container_api_present', 'bfs_compiled_in'))):
            raise ValueError('public_probe_values')
    if value['status'] in ('supported_candidate', 'unsupported_candidate'):
        if (value['failure'] is not None or not all(value['checks'].values())
                or value['probe'] is None or not value['private_tree_retained']
                or value['probe_exit_code'] != 0):
            raise ValueError('public_runtime_evidence')
        p = value['probe']
        supported = (p['tier'] == 'base-container' and p['needs_dacl_augmentation'] is False
                     and p['base_container_api_present'] and not p['detector_error_present']
                     and not p['bfs_compiled_in'])
        if (value['status'] == 'supported_candidate') != supported:
            raise ValueError('public_support')
    if value['status'] == 'prepared' and (value['failure'] is not None or not all(value['checks'][k] for k in ('artifacts', 'sources', 'request'))
            or value['probe'] is not None or value['private_tree_retained']
            or value['probe_exit_code'] is not None
            or any(value['checks'][k] for k in CHECKS if k not in ('artifacts', 'sources', 'request'))):
        raise ValueError('public_preparation')
    if len(encode(value)) > 4096:
        raise ValueError('public_bound')
    return value


def prepare(bundle, runtime_directory, request_output, *, root=ROOT, nonce=None):
    value = blank()
    try:
        value['failure'] = 'inputs'
        verify_artifacts(bundle, runtime_directory)
        value['checks']['artifacts'] = True
        value['source_sha256'] = source_snapshot(root)
        value['checks']['sources'] = True
        request = validate_request(request_document(nonce or secrets.token_hex(16)))
        raw = encode(request)
        launcher.write_private_bytes(Path(request_output), raw)
        value['request_sha256'] = sha(raw)
        value['checks']['request'] = True
        value.update(status='prepared', failure=None)
    except BaseException:
        pass
    return validate_public(value)


def run_probe(bundle, runtime_directory, request_path, work_parent, expected_source_sha256,
              *, run=False, api=None, root=ROOT, ids=secrets.token_hex):
    value = blank(); phase = 'platform'
    try:
        if not run or os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise ValueError('explicit_local_probe_required')
        api = ProbeAPI() if api is None else api
        phase = 'deadline'
        frequency, start = api.qpc_frequency(), api.qpc()
        budget = launcher.QpcBudget(api, start + 120 * frequency, frequency)
        phase = 'inputs'
        executor = verify_artifacts(bundle, runtime_directory)
        value['checks']['artifacts'] = True
        value['source_sha256'] = source_snapshot(root)
        if not local.controller.digest(expected_source_sha256) or expected_source_sha256 != value['source_sha256']:
            raise ValueError('source_snapshot_changed')
        value['checks']['sources'] = True
        raw = local.bounded(request_path, MAX_OUTPUT)
        validate_request(local.guest.decode(raw))
        value['request_sha256'] = sha(raw); value['checks']['request'] = True
        parentpath = admit_work_parent(work_parent, root=root)
        phase = 'identity'
        parent = local.ordinary(api); value['checks']['ordinary'] = True
        if not api.windows_x64():
            raise ValueError('native_windows_x64_required')
        value['checks']['windows_x64'] = True
        phase = 'deadline'; budget.require_ms(budget.cutoff(45))
        nonce = ids(16)
        if not local.controller.nonce(nonce):
            raise ValueError('fresh_nonce')
        work = parentpath / ('local-model2-probe-' + nonce)
        if work.exists() or work.is_symlink():
            raise ValueError('fresh_work')
        phase = 'staging'
        # Creation may succeed before ACL readback or descriptor release fails.
        value['private_tree_retained'] = True
        api.private_directory(work, parent['sid'])
        launcher.checked_path(work, inside=parentpath, is_file=False)
        for name in ('temp', 'dacl-state'):
            api.private_directory(work / name, parent['sid'])
        state = launcher.checked_path(work / 'dacl-state', inside=work, is_file=False)
        if list(state.iterdir()):
            raise ValueError('state_not_empty')
        value['checks']['fresh_empty_state'] = True
        config = work / 'model2-request.json'
        launcher.write_private_bytes(config, raw)
        if local.bounded(config, MAX_OUTPUT) != raw:
            raise ValueError('request_copy')
        # Pin one private executable copy and rehash while its process is suspended.
        image = work / 'wxc-exec.exe'
        launcher.write_private_bytes(image, local.bounded(executor, MEMBER_LIMITS[1]))
        if sha(local.bounded(image, MEMBER_LIMITS[1])) != pins.MXC_G_EXECUTOR_SHA256:
            raise ValueError('staged_image')
        if source_snapshot(root) != expected_source_sha256:
            raise ValueError('sources_changed_during_setup')
        api.reaper_state = state; api.five_key_environment = False
        api.worker_job_name = 'Local\\RuleProxy.LocalGuard.' + nonce
        api.worker_sid = parent['sid']
        phase = 'deadline'; budget.require_ms(budget.cutoff(30))
        phase = 'launch'
        result = launcher.launch_owned(api, fixed_command(image, config), work, parent, parent,
            qpc_budget=budget, work_cutoff=budget.cutoff(15), cleanup_cutoff=budget.deadline)
        value['checks']['five_key_environment'] = api.five_key_environment is True
        value['checks']['atomic_job'] = api.atomic_job_requested is True
        value['checks']['held_identity'] = result.get('native_identity_verified_before_resume') is True
        value['checks']['held_exit'] = result.get('cleanup', {}).get('process_exit_confirmed') is True
        value['checks']['outer_cleanup'] = local.guest.cleanup_verified(result)
        code = result.get('exit_code')
        if type(code) is int and 0 <= code <= 0xffffffff:
            value['probe_exit_code'] = code
        phase = 'cleanup'
        if not value['checks']['held_exit']:
            raise ValueError('owned_probe_incomplete')
        state = launcher.checked_path(state, inside=work, is_file=False)
        if list(state.iterdir()):
            raise ValueError('reaper_state_changed')
        value['checks']['empty_state_after'] = True
        phase = 'report'
        value['probe'] = projection(local.bounded(work / 'controller.stdout', MAX_OUTPUT))
        value['checks']['parsed_output'] = True
        # Preserve a verified projection even when later CLI/cleanup gates fail.
        # The pinned CLI emits detector errors in JSON and returns zero; an
        # unexpected nonzero exit remains failed, never a supported candidate.
        if local.bounded(work / 'controller.stderr', MAX_OUTPUT):
            raise ValueError('unexpected_probe_stderr')
        phase = 'cleanup'
        if (not all(value['checks'][key] for key in ('five_key_environment', 'atomic_job', 'held_identity', 'held_exit', 'outer_cleanup'))
                or 'error' in result or result.get('timed_out') is not False or value['probe_exit_code'] != 0):
            raise ValueError('owned_probe_incomplete')
        phase = 'deadline'; budget.require_ms(budget.deadline)
        p = value['probe']
        supported = (p['tier'] == 'base-container' and p['needs_dacl_augmentation'] is False
                     and p['base_container_api_present'] and not p['detector_error_present']
                     and not p['bfs_compiled_in'])
        value.update(status='supported_candidate' if supported else 'unsupported_candidate', failure=None)
    except BaseException:
        value['failure'] = phase
    return validate_public(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--runtime-directory', type=Path)
    parser.add_argument('--prepare-request-output', type=Path)
    parser.add_argument('--run-local-probe', action='store_true')
    parser.add_argument('--request', type=Path)
    parser.add_argument('--work-parent', type=Path)
    parser.add_argument('--expected-source-sha256')
    args = parser.parse_args(argv)
    if args.run_local_probe and args.prepare_request_output is not None:
        parser.error('prepare and run are mutually exclusive')
    if args.run_local_probe:
        value = run_probe(args.bundle, args.runtime_directory, args.request, args.work_parent,
                          args.expected_source_sha256, run=True)
    elif args.prepare_request_output is not None:
        value = prepare(args.bundle, args.runtime_directory, args.prepare_request_output)
    else:
        value = blank(); value['failure'] = 'inputs'
    sys.stdout.buffer.write(encode(value))
    return 0 if value['status'] in ('prepared', 'supported_candidate') else 1


if __name__ == '__main__':
    raise SystemExit(main())
