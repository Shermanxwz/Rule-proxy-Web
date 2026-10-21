"""Opt-in disposable Windows 11 Stage0. No product/privacy qualification.

Direct official26300.9457 image, exploratory below documented26300.9550 floor.
No servicing or media replacement. Only closed projections leave the guest. Media, credentials, guest disk,
raw reports, serial output and screenshots are never publication artifacts.
The existing pinned media helpers are reused, not the old experiment matrix.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import zipfile
from http.server import HTTPServer, BaseHTTPRequestHandler

ROOT = Path(__file__).resolve().parents[1]
ISO_BYTES = 8225329152
ISO_SHA256 = 'bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38'
ISO_URL = 'https://software-static.download.prss.microsoft.com/dbazure/26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso'
# Copied without changes from ruleproxy/windows_proxy_pins.py ASSETS['python'].
# The dedicated proof needs stdlib only, not the product's installers or wheels.
PYTHON_ASSET = {
    'name': 'python-3.14.8-embed-amd64.zip', 'size': 12601679,
    'url': 'https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip',
    'sha256': 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310',
}
PYTHON_MEMBERS = 37
PYTHON_EXPANDED = 24405990
STDLIB_MEMBERS = 563
STDLIB_EXPANDED = 9772779
PYTHON_PTH = b'python314.zip\r\n.\r\n\r\n# Uncomment to run site.main() automatically\r\n#import site\r\n'
PYTHON_REQUIRED = frozenset({
    'python.exe', 'python314.dll', 'python3.dll', 'python314.zip', 'python314._pth',
    '_ctypes.pyd', '_socket.pyd', '_hashlib.pyd', 'select.pyd',
    'libffi-8.dll', 'libcrypto-3.dll', 'vcruntime140.dll', 'vcruntime140_1.dll',
    'LICENSE.txt',
})
STDLIB_REQUIRED = frozenset({
    'encodings/__init__.pyc', 'encodings/utf_8.pyc', 'ctypes/__init__.pyc',
    'ctypes/wintypes.pyc', 'importlib/__init__.pyc', 'importlib/util.pyc',
    'argparse.pyc', 'json/__init__.pyc', 'http/server.pyc', 'zipfile/__init__.pyc',
    'hashlib.pyc', 'subprocess.pyc', 'threading.pyc', 'pathlib/__init__.pyc',
})
GUEST_SOURCES = (
    '.github/windows_identity_direct_stage0.py', '.github/windows_identity_proof.py',
    '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_runtime_pins.py',
)
CHECKS = ('request_aware_base_container', 'actual_base_container', 'fresh_actor',
          'native_identity', 'normal_exit', 'no_harness_error')
BOOLS = ('ordinary_account', 'direct_build_verified', 'stage0_passed', 'harness_completed')
EXECUTION_ENABLED = True  # Frozen code review only; separate execution decision required.
GIB = 1024**3
PREMEDIA_FREE = 32 * GIB
LAUNCH_FREE = 24 * GIB
DISK_FILE_CAP = 22 * GIB
STOP_FREE = 4 * GIB
MAX_PAYLOAD = 256 * 1024**2
MAX_SEED = 16 * 1024**2
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
MAX_REPORT = 16384
MIN_VM_WORK_SECONDS = 1800
PREP_ALLOWANCE = 512 * 1024**2
PREP_PHASES = ('before_checkout', 'post_checkout', 'post_apt_indexes', 'post_apt',
               'post_actor', 'post_g_download', 'post_g_bundle', 'post_python', 'pre_vm')
VM_PACKAGES = ('qemu-system-x86', 'qemu-utils', 'ovmf', 'swtpm', 'xorriso', 'curl', '7zip')
APT_DOWNLOAD_CEILING = 26223118
APT_INSTALLED_GROWTH_CEILING = 115951616
APT_PACKAGE_CEILING = 26
# A planning ledger, NOT filesystem quotas or a proven transient peak. Only
# current APT plan ceilings and observed net capacity gates are enforced below.
# The other categories are explicit conservative assumptions, including one
# additional full positive installed-growth amount for possible dpkg scratch.
# Background provider writes and intermediate peaks can invalidate this model.
PREP_PLANNING_BYTES = {
    'apt_download_plan_ceiling': APT_DOWNLOAD_CEILING,
    'apt_positive_growth_plan_ceiling': APT_INSTALLED_GROWTH_CEILING,
    'dpkg_transient_assumption': APT_INSTALLED_GROWTH_CEILING,
    'apt_indexes_assumption': 128 * 1024**2,
    'shallow_git_worktree_objects_assumption': 48 * 1024**2,
    'g_wrapper_expansion_repack_assumption': 16 * 1024**2,
    'python_archive_assumption': 13 * 1024**2,
    'actor_input_assumption': 16 * 1024**2,
    'logs_metadata_assumption': 32 * 1024**2,
}


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preparation_record(path):
    if path.is_symlink() or path.stat().st_size > MAX_REPORT:
        raise ValueError('bounded preparation record required')
    value = json.loads(path.read_text(encoding='ascii'))
    if (not isinstance(value, dict) or value.get('schema_version') != 1
            or value.get('allowance_bytes') != PREP_ALLOWANCE
            or value.get('minimum_free_bytes') != PREMEDIA_FREE
            or type(value.get('baseline_free_bytes')) is not int
            or value['baseline_free_bytes'] < PREMEDIA_FREE + PREP_ALLOWANCE
            or value.get('status') != 'observed_within_allowance'):
        raise ValueError('preparation baseline differs')
    samples = value.get('samples')
    if not isinstance(samples, list) or not 1 <= len(samples) <= len(PREP_PHASES):
        raise ValueError('bounded preparation samples required')
    for index, sample in enumerate(samples):
        if (not isinstance(sample, dict) or set(sample) != {'phase', 'free_bytes', 'net_decline_bytes'}
                or sample['phase'] != PREP_PHASES[index]
                or type(sample['free_bytes']) is not int or sample['free_bytes'] < PREMEDIA_FREE
                or type(sample['net_decline_bytes']) is not int
                or sample['net_decline_bytes'] != max(0, value['baseline_free_bytes'] - sample['free_bytes'])
                or sample['net_decline_bytes'] > PREP_ALLOWANCE):
            raise ValueError('preparation sample differs')
    # Rebuild a closed record; do not copy unexpected fields from disk.
    result = {'schema_version': 1, 'allowance_bytes': PREP_ALLOWANCE,
              'minimum_free_bytes': PREMEDIA_FREE, 'baseline_free_bytes': value['baseline_free_bytes'],
              'status': 'observed_within_allowance', 'samples': samples,
              'peak_measured': False, 'provider_background_writes_excluded': False,
              'planning_ledger_bytes': dict(PREP_PLANNING_BYTES),
              'planning_ledger_is_hard_quota': False, 'installed_plan_verified': False}
    if 'apt_plan' in value:
        plan = value['apt_plan']
        if (not isinstance(plan, dict) or set(plan) != {'verified', 'package_count', 'download_bytes',
                'positive_installed_growth_bytes', 'plan_sha256'} or plan['verified'] is not True
                or not isinstance(plan['plan_sha256'], str) or not DIGEST.fullmatch(plan['plan_sha256'])
                or any(type(plan[key]) is not int or not 0 <= plan[key] <= ceiling for key, ceiling in (
                    ('package_count', APT_PACKAGE_CEILING), ('download_bytes', APT_DOWNLOAD_CEILING),
                    ('positive_installed_growth_bytes', APT_INSTALLED_GROWTH_CEILING)))):
            raise ValueError('verified preparation package plan required')
        result['apt_plan'] = plan
    return result


def preparation_checkpoint(path, phase):
    result = preparation_record(path)
    if len(result['samples']) == len(PREP_PHASES) or phase != PREP_PHASES[len(result['samples'])]:
        raise ValueError('preparation phases must be observed in order')
    same_filesystem = (ROOT.stat().st_dev == path.parent.stat().st_dev
                       == int(os.environ.get('STOCK_PREP_DEVICE_ID', '-1')))
    free = shutil.disk_usage(ROOT).free
    declined = max(0, result['baseline_free_bytes'] - free)
    okay = (same_filesystem and sys.version_info[:2] == (3, 12)
            and free >= PREMEDIA_FREE and declined <= PREP_ALLOWANCE
            and (PREP_PHASES.index(phase) < PREP_PHASES.index('post_apt') or 'apt_plan' in result))
    result['samples'].append({'phase': phase, 'free_bytes': free, 'net_decline_bytes': declined})
    result['same_filesystem'] = same_filesystem
    result['status'] = 'observed_within_allowance' if okay else 'blocked'
    path.write_text(json.dumps(result, sort_keys=True) + '\n', encoding='ascii')
    return 0 if okay else 1


def apt_simulated_packages(text):
    if len(text) > 512 * 1024 or re.search(r'^(?:Remv|Purg)\s', text, re.MULTILINE):
        raise ValueError('bounded no-removal APT plan required')
    summary = re.findall(r'^(\d+) upgraded, (\d+) newly installed, (\d+) to remove and \d+ not upgraded\.$',
                         text, re.MULTILINE)
    if len(summary) != 1 or int(summary[0][2]) != 0:
        raise ValueError('unambiguous no-removal APT summary required')
    result = []
    for line in text.splitlines():
        if line.startswith('Inst '):
            match = re.match(r'^Inst ([a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?)(?: \[([^\]]+)\])? \(([^ ]+) ', line)
            if not match or not re.fullmatch(r'[A-Za-z0-9.+:~_-]+', match[3]):
                raise ValueError('unambiguous versioned APT input required')
            result.append(match.groups())
    if (len(result) != int(summary[0][0]) + int(summary[0][1])
            or len(result) > APT_PACKAGE_CEILING or len({item[0] for item in result}) != len(result)):
        raise ValueError('APT package count differs')
    return result


def reviewed_apt_plan(*, runner=subprocess.run):
    """Read current metadata only; no installs, downloads, removals or cleanup."""
    environment = dict(os.environ, LC_ALL='C')
    def command(argv, *, missing=False):
        completed = runner(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                           env=environment, timeout=30)
        if (completed.returncode not in ((0, 1) if missing else (0,))
                or len(completed.stdout) > 512 * 1024 or len(completed.stderr) > 512 * 1024):
            raise ValueError('APT plan metadata unavailable')
        return completed
    plan = apt_simulated_packages(command(
        ['apt-get', '-s', '--no-install-recommends', '--no-remove', 'install', *VM_PACKAGES]).stdout)
    download = growth = 0
    canonical = []
    for name, old, version in plan:
        text = command(['apt-cache', 'show', name + '=' + version]).stdout
        records = []
        for paragraph in re.split(r'\n\s*\n', text.strip()):
            fields = {}
            for line in paragraph.splitlines():
                if line and not line[0].isspace() and ': ' in line:
                    key, value = line.split(': ', 1)
                    if key in fields: raise ValueError('duplicate APT metadata field')
                    fields[key] = value
            if (fields.get('Package') != name.split(':', 1)[0] or fields.get('Version') != version
                    or fields.get('Architecture') not in ('amd64', 'all')
                    or not fields.get('Size', '').isdecimal() or not fields.get('Installed-Size', '').isdecimal()):
                raise ValueError('exact APT package metadata required')
            records.append((int(fields['Size']), int(fields['Installed-Size']) * 1024))
        if not records or len(set(records)) != 1:
            raise ValueError('ambiguous APT package sizes')
        size, installed = records[0]
        current = command(['dpkg-query', '-W', '-f=${db:Status-Status}\\n${Installed-Size}\\n${Version}\\n', name], missing=True)
        fields = current.stdout.splitlines()
        previous = 0
        if current.returncode == 0 and len(fields) == 3 and fields[0] == 'installed':
            if not fields[1].isdecimal() or old != fields[2]:
                raise ValueError('installed APT package changed since simulation')
            previous = int(fields[1]) * 1024
        elif old is not None:
            raise ValueError('installed APT metadata unavailable')
        download += size
        growth += max(0, installed - previous)
        canonical.append((name, version, size, installed, previous))
    if download > APT_DOWNLOAD_CEILING or growth > APT_INSTALLED_GROWTH_CEILING:
        raise ValueError('APT plan exceeds reviewed preparation ceilings')
    return {'verified': True, 'package_count': len(plan), 'download_bytes': download,
            'positive_installed_growth_bytes': growth,
            'plan_sha256': hashlib.sha256(json.dumps(canonical, sort_keys=True).encode('ascii')).hexdigest()}


def check_apt_plan(path):
    result = preparation_record(path)
    if result['samples'][-1]['phase'] != 'post_apt_indexes' or 'apt_plan' in result:
        raise ValueError('one current APT plan after index refresh required')
    try:
        result['apt_plan'] = reviewed_apt_plan()
    except Exception:
        result['status'] = 'blocked'
        result['apt_plan_verified'] = False
    path.write_text(json.dumps(result, sort_keys=True) + '\n', encoding='ascii')
    return 0 if result['status'] != 'blocked' else 1


def checked_members(archive, *, count, expanded, flat=False):
    """Bound both ZIP layers and reject Windows path aliases before extraction."""
    members = archive.infolist()
    if len(members) != count or sum(item.file_size for item in members) != expanded:
        raise ValueError('fixed archive expansion differs')
    seen = set()
    for item in members:
        name = item.filename
        parts = name.split('/')
        kind = stat.S_IFMT(item.external_attr >> 16)
        if (name != item.orig_filename or not name or name.startswith('/')
                or '\\' in name or ':' in name or '\x00' in name
                or any(not part or part in ('.', '..') or part.rstrip(' .') != part
                       or re.fullmatch(r'(?i)(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part)
                       for part in parts)
                or (flat and len(parts) != 1) or item.is_dir()
                or kind not in (0, stat.S_IFREG) or item.external_attr & 0x10
                or item.flag_bits & 1 or item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                or name.casefold() in seen):
            raise ValueError('unsafe archive member')
        seen.add(name.casefold())
    return {item.filename: item for item in members}


def verify_python(path):
    """Inspect, never execute, the exact existing official embedded interpreter."""
    if path.is_symlink() or not path.is_file() or path.stat().st_size != PYTHON_ASSET['size']:
        raise ValueError('fixed Python archive size differs')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PYTHON_ASSET['sha256']:
        raise ValueError('fixed Python archive digest differs')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = checked_members(archive, count=PYTHON_MEMBERS, expanded=PYTHON_EXPANDED, flat=True)
        if not PYTHON_REQUIRED <= members.keys() or archive.testzip() is not None:
            raise ValueError('required Python runtime absent or corrupt')
        if archive.read('python314._pth') != PYTHON_PTH:
            raise ValueError('isolated Python import layout differs')
        for name in ('python.exe', 'python314.dll'):
            binary = archive.read(name)
            offset = int.from_bytes(binary[60:64], 'little')
            if (binary[:2] != b'MZ' or not 64 <= offset < len(binary) - 6
                    or binary[offset:offset + 6] != b'PE\0\0\x64\x86'):
                raise ValueError('required AMD64 Python runtime differs')
        with zipfile.ZipFile(io.BytesIO(archive.read('python314.zip'))) as stdlib:
            library = checked_members(stdlib, count=STDLIB_MEMBERS, expanded=STDLIB_EXPANDED)
            if not STDLIB_REQUIRED <= library.keys() or stdlib.testzip() is not None:
                raise ValueError('required isolated stdlib absent or corrupt')
    return data


def download_python(destination):
    # Reconfirm this is the existing product pin, without using its downloader
    # or calling any product packaging/install path.
    pins = load('stock_python_source_pin', ROOT / 'ruleproxy/windows_proxy_pins.py')
    if (pins.ASSETS['python'] != PYTHON_ASSET or pins.PYTHON_VERSION != '3.14.8'
            or pins.PYTHON_PTH != 'python314._pth' or pins.PYTHON_STDLIB != 'python314.zip'):
        raise ValueError('existing Python pin changed; separate review required')
    import urllib.request
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            raise ValueError('fixed official Python URL must not redirect')
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(PYTHON_ASSET['url'], headers={'User-Agent': 'RuleProxy-Stage0/1'})
    opener = urllib.request.build_opener(NoRedirect)
    with opener.open(request, timeout=90) as response:
        if response.geturl() != PYTHON_ASSET['url'] or int(response.headers.get('Content-Length', '-1')) != PYTHON_ASSET['size']:
            raise ValueError('fixed Python response differs')
        data = response.read(PYTHON_ASSET['size'] + 1)
    # Never overwrite a cache or follow a pre-existing output link.
    with destination.open('xb') as output:
        output.write(data)
    verify_python(destination)


def verify_guest_import_path():
    runtime = ROOT / 'python'
    expected = [str(runtime / 'python314.zip'), str(runtime)]
    if (os.name != 'nt' or not sys.flags.isolated or not sys.flags.no_site
            or not sys.dont_write_bytecode or 'site' in sys.modules
            or Path(sys.executable).resolve() != (runtime / 'python.exe').resolve()
            or [os.path.normcase(os.path.abspath(p)) for p in sys.path]
               != [os.path.normcase(os.path.abspath(p)) for p in expected]):
        raise ValueError('isolated embedded Python entrypoint required')


GUEST_PHASES = ('not_started', 'import_path', 'proof_import', 'configuration', 'controller', 'report_read', 'completed')
LAUNCHER_PHASES = ('not_observed', 'configuration', 'identity', 'beacon', 'direct_build', 'claim', 'endpoint',
    'payload_download', 'payload_hash', 'payload_extract', 'python_hash', 'python_extract',
    'python_start', 'python_wait', 'report_read', 'report_parse', 'completed', 'transport', 'installed_boot_gate', 'installed_setup_wait')
LAUNCHER_FAILURES = ('none', 'operation_failed', 'identity_gate', 'direct_build_gate', 'endpoint_timeout',
    'payload_bound', 'payload_overrun', 'payload_incomplete', 'payload_hash', 'python_hash', 'python_not_started',
    'process_handle_missing', 'python_deadline', 'report_absent', 'report_over_bound', 'report_nonobject', 'report_parse', 'installed_boot_gate', 'installed_setup_deadline')
HOST_OPERATIONS = ('preflight', 'iso_download', 'iso_verify', 'payload_build', 'result_server', 'seed_build',
    'disk_create', 'launch_capacity', 'tpm_start', 'vm_work_budget', 'qemu_start', 'qmp_connect', 'kvm_verify',
    'guest_wait', 'result_validation', 'cleanup')
BREADCRUMBS = ('iso_verified', 'media_ready', 'qemu_started', 'guest_beacon', 'result_received', 'cleanup_done')


def proof_helpers():
    return load('identity_stage0_diagnostics', ROOT / '.github/windows_identity_proof.py')


def closed_failure(exc):
    proof = proof_helpers()
    return {'type': proof._enum(type(exc).__name__, proof.FAILURE_TYPES + ('BrokenPipeError', 'ConnectionResetError', 'ConnectionAbortedError', 'EarlyGuestFailure', 'BootstrapTimeout')),
            'errno': proof._integer(getattr(exc, 'errno', None), -0x80000000),
            'winerror': proof._integer(getattr(exc, 'winerror', None), -0x80000000)}


def project_stage0(raw):
    """No recursive pass-through: a malicious path/nonce/error cannot escape."""
    proof = proof_helpers()
    raw = proof._dict(raw)
    checks = proof._dict(raw.get('checks'))
    result = {'schema_version': 1, 'stage': 'win11-direct26300.9457-exploratory-ordinary-deny-only-stage0',
              'network_tested': False, 'product_acceptance': False, 'privacy_qualified': False,
              'exploratory_stage0': True, 'documented_support_floor': '26300.9550',
              'psec_cleanup_independently_verified': False,
              'checks': {key: checks.get(key) is True for key in CHECKS},
              'request_supported': checks.get('request_aware_base_container') is True,
              'stage0_passed': raw.get('stage0_passed') is True and all(checks.get(k) is True for k in CHECKS),
              'diagnostics': proof.closed_diagnostics(raw)}
    guest = proof._dict(raw.get('guest_diagnostic')); failure = proof._dict(guest.get('failure'))
    result['guest_diagnostic'] = {'phase': proof._enum(guest.get('phase'), GUEST_PHASES, 'not_started'),
        'failure': {'type': proof._enum(failure.get('type'), proof.FAILURE_TYPES, 'absent'),
                    'errno': proof._integer(failure.get('errno'), -0x80000000),
                    'winerror': proof._integer(failure.get('winerror'), -0x80000000)}}
    launcher = proof._dict(raw.get('launcher_diagnostic'))
    result['launcher_diagnostic'] = {'phase': proof._enum(launcher.get('phase'), LAUNCHER_PHASES, 'not_observed'),
        'failure_category': proof._enum(launcher.get('failure_category'), LAUNCHER_FAILURES, 'none'),
        'failed': launcher.get('failed') is True, 'hresult': proof._integer(launcher.get('hresult'), -0x80000000),
        'python_exit_code': proof._integer(launcher.get('python_exit_code'), -0x80000000),
        'transport_attempt': proof._integer(launcher.get('transport_attempt'), 0, 3)}
    for key in ('actor_sha256',):
        value = raw.get(key)
        if isinstance(value, str) and DIGEST.fullmatch(value): result[key] = value
    if type(raw.get('executor_exit_code')) is int and -0x80000000 <= raw['executor_exit_code'] <= 0xffffffff:
        result['executor_exit_code'] = raw['executor_exit_code']
    return result


def validate_guest(value, actor_digest):
    if not isinstance(value, dict) or len(json.dumps(value)) > MAX_REPORT:
        raise ValueError('bounded result required')
    result = project_stage0(value)
    result.update({key: value.get(key) is True for key in BOOLS})
    result['stage0_passed'] = (value.get('stage0_passed') is True
                               and all(result['checks'].values())
                               and all(result[k] for k in ('ordinary_account', 'direct_build_verified', 'harness_completed')))
    result['os'] = {'build': 26300, 'ubr': 9457, 'product_type': 'WinNT', 'architecture': 'AMD64'}
    if value.get('os') != result['os'] or value.get('actor_sha256') != actor_digest:
        raise ValueError('guest provenance differs')
    return result


def guest(args):
    output = args.output
    result = project_stage0({})
    phase = 'import_path'; options = None
    try:
        verify_guest_import_path()
        phase = 'proof_import'
        proof = load('identity_stage0_guest', ROOT / '.github/windows_identity_proof.py')
        phase = 'configuration'
        config = json.loads((ROOT / 'stage0-input.json').read_text())
        work = ROOT / 'private-stage0'
        options = SimpleNamespace(disposable_ci=True, approved_security_test=True,
            executor=ROOT / 'g/wxc-exec.exe', manifest=ROOT / 'g/build-manifest.json',
            actor=ROOT / 'actor.exe', actor_sha256=config['actor_sha256'], work=work, report=work / 'report.json')
        phase = 'controller'
        code = proof.controller(options)
        phase = 'report_read'
        raw = proof.smoke.read(options.report)
        raw['controller_phase'] = options.diagnostic_phase
        result = project_stage0(raw)
        result['harness_completed'] = True
        # A successful controller validates its observed current ordinary token;
        # the PowerShell entrypoint separately verifies the real RuleProxyCI user.
        identity = raw.get('controller_identity', {})
        result['ordinary_account'] = (identity.get('elevated') is False and identity.get('appcontainer') is False
                                      and identity.get('cid') == 1)
        phase = 'completed'
    except Exception as exc:
        code = 1
        prior = getattr(options, 'diagnostic_report', None)
        if isinstance(prior, dict): result = project_stage0(prior)
        result['stage0_passed'] = False
        result['harness_completed'] = False
        result['guest_diagnostic']['failure'] = closed_failure(exc)
        if options is not None:
            result['diagnostics']['controller_phase'] = proof_helpers()._enum(
                getattr(options, 'diagnostic_phase', None), proof_helpers().CONTROLLER_PHASES)
    result['guest_diagnostic']['phase'] = phase
    output.write_text(json.dumps(result, sort_keys=True), encoding='ascii')
    return code


def record_breadcrumb(public, name, work, disk, deadline):
    """Fixed allowlisted samples, no paths; observation is not a quota or peak guarantee."""
    if name not in BREADCRUMBS: raise ValueError('unknown breadcrumb')
    rows = public.setdefault('phase_samples', [])
    if any(row['phase'] == name for row in rows): return
    row = {'phase': name, 'filesystem_free_bytes': None, 'qcow_size_bytes': None,
           'qcow_allocated_bytes': None, 'remaining_work_seconds': max(0, int(deadline-time.monotonic())),
           'filesystem_sample': 'unavailable', 'qcow_sample': 'absent'}
    try:
        # After owned work deletion, sample its still-existing filesystem parent.
        row['filesystem_free_bytes'] = shutil.disk_usage(work if work.exists() else work.parent).free
        row['filesystem_sample'] = 'observed'
    except OSError: pass
    if disk is not None:
        try:
            info = disk.lstat()
            if stat.S_ISREG(info.st_mode):
                row.update(qcow_size_bytes=info.st_size, qcow_allocated_bytes=info.st_blocks*512, qcow_sample='observed')
            else: row['qcow_sample'] = 'not_regular'
        except FileNotFoundError: pass
        except (OSError, AttributeError): row['qcow_sample'] = 'unavailable'
    rows.append(row)
    try: print(json.dumps({'stage0_phase_sample': row}, sort_keys=True), flush=True)
    except OSError: pass  # Diagnostic transport must not change runtime acceptance.


MAX_N0A_REPORT = 4096


def n0a_helpers():
    name = 'identity_n0a_control_host'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / '.github/windows_n0a_control.py')
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        try: spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None); raise
    return sys.modules[name]


def capture_helpers():
    name = 'identity_n0a_capture_adapter_host'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / '.github/windows_n0a_capture_adapter.py')
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module
        try: spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(name, None); raise
    return sys.modules[name]



def udp_helpers():
    return udp_capture_helpers().helper('control')


def udp_capture_helpers():
    name = 'identity_udp_capture_adapter'
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, ROOT / '.github/windows_n0a_udp_capture_adapter.py')
        module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module)
    return sys.modules[name]

def parent_udp_capture_helpers():
    name='identity_parent_udp_capture_adapter'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'.github/windows_n0a_udp_parent_capture_adapter.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


def udp6_capture_helpers():
    name='identity_udp6_capture_adapter'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,ROOT/'.github/windows_n0a_udp6_capture_adapter.py')
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]


class CaptureTransportFailure(RuntimeError):
    pass


def observe_capture(owner, public):
    if owner is None: return
    reason = None
    try:
        status = owner.poll_status()  # Zero-wait poll; primitive caps total frames.
        if owner.errors or owner.ipc_eof: reason = 'ipc_or_capture_error'
        elif owner.child is None or owner.child.poll() is not None: reason = 'child_exit'
        elif not isinstance(status, dict): reason = 'status_unavailable'
        elif status.get('overflow') is True: reason = 'overflow'
        elif status.get('qemu_dump_write_error') is True: reason = 'dump_write'
        elif status.get('errors'): reason = 'capture_error'
        elif status.get('phase') == 'final': reason = 'premature_final'
    except Exception: reason = 'observation_error'
    if reason is not None:
        public['capture_abort'] = reason
        owner.fail('child_exit' if reason == 'child_exit' else 'read')
        raise CaptureTransportFailure('capture transport unavailable')


def capture_request_deadline(server, body):
    deadline = n0a_wait_deadline(server, server.capture_work_deadline)
    return min(deadline, server.capture_received_at + 10) if body else min(deadline, time.monotonic() + 5)


def read_capture_request(handler, length, deadline):
    # read1 prevents buffered read(length) from silently renewing socket waits.
    chunks = []; remaining = length
    while remaining:
        budget = deadline - time.monotonic()
        if budget <= 0: raise ValueError('capture body deadline')
        handler.connection.settimeout(min(5, budget))
        chunk = handler.rfile.read1(min(remaining, 65536))
        if not chunk: raise ValueError('capture body incomplete')
        chunks.append(chunk); remaining -= len(chunk)
    if time.monotonic() >= deadline: raise ValueError('capture body late')
    return b''.join(chunks)


def reject_capture_constant(_):
    raise ValueError('capture JSON constant')


def fallback_capture_owner(owner, deadline):
    # Exceptional path only. Exact held Popen objects and the primitive's
    # close-once ledger; never detached numeric PIDs or a renewed deadline.
    exited = True
    for process in (owner.process, owner.child):
        if process is None: continue
        observed = False
        try: observed = type(process.poll()) is int
        except Exception: exited = False
        if not observed:
            # A failed observation cannot suppress the owned stop attempt.
            try: process.kill()
            except Exception: exited = False
            try: process.wait(timeout=cleanup_remaining(deadline, 5))
            except Exception: exited = False
            try: observed = type(process.poll()) is int
            except Exception: exited = False
        exited = exited and observed
    closed = True
    for name in ('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel'):
        try: owner._close(name)
        except Exception: closed = False
    try:
        closed = (closed and not owner.close_ledger.uncertain
                  and all(getattr(owner, name) is None for name in
                          ('root_fd','stderr_read','stderr_write','dummy_fd','child_channel','channel')))
    except Exception: closed = False
    return {'attempted': True, 'process_exit_confirmed': exited, 'descriptors_closed': closed}


def finish_capture_before_cleanup(owner, server, capture_config, n0a_config, public,
                                  outer_deadline, header_before_link):
    adapter = udp_capture_helpers() if getattr(server, 'udp_enabled', False) else capture_helpers(); tentative = adapter.unavailable(); snapshot = True
    if server is not None:
        server.capture_accepting = False
        acquired = server.capture_lock.acquire(timeout=max(0, min(1, outer_deadline-time.monotonic())))
        if acquired: server.capture_lock.release()
        else: snapshot = False
    if owner is None: return None, tentative
    facts = {'cleanup_confirmed': False}
    try: facts = owner.finish(cleanup_deadline=outer_deadline-30)
    except Exception:
        public['capture_owner_fallback'] = fallback_capture_owner(owner, outer_deadline-30)
        return facts, tentative
    try:
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        expected = {'binding': {
            'run_nonce': capture_config['run_nonce'], 'case_nonce': n0a_config['case_nonce'],
            'actor_sha256': n0a_config['actor_sha256'], 'executor_sha256': MXC_G_EXECUTOR_SHA256,
            'actor_source_sha256': n0a_config['actor_source_sha256'],
            'identity_source_sha256': n0a_config['identity_source_sha256'],
            'source_commit': capture_config['source_commit'], 'build': 26300, 'ubr': 9457},
            'endpoint': {'vm_mac': capture_config['vm_mac'], 'destination_ipv4': '10.0.2.2',
                         'destination_port': n0a_config['runner_port']},
            'flow_commitment': server.capture_commitment, 'controller_result': server.n0a_result}
        if getattr(server, 'udp_enabled', False): expected['cleanup_verified'] = facts.get('cleanup_confirmed') is True  # Tentative; final host cleanup must qualify absence.
        if snapshot and time.monotonic() < outer_deadline-20:
            tentative = adapter.parse_before_cleanup(owner.output_path, facts, server.capture_private_body, expected,
                header_before_link=header_before_link,
                terminal_before_shutdown=server.n0a_received.is_set() and server.capture_body_received.is_set(),
                capacity_abort=bool(public.get('capacity_abort') or public.get('capture_abort')))
            if tentative.get('capture_read_cleanup_confirmed') is False:
                facts['cleanup_confirmed'] = False
    except Exception: pass  # Missing evidence never becomes packet absence.
    return facts, tentative



def finish_parent_capture_before_cleanup(owner, server, capture_config, n0a_config, public,
                                  outer_deadline, header_before_link):
    adapter = parent_udp_capture_helpers(); tentative = adapter.unavailable(); snapshot = True
    if server is not None:
        server.capture_accepting = False
        acquired = server.capture_lock.acquire(timeout=max(0, min(1, outer_deadline-time.monotonic())))
        if acquired: server.capture_lock.release()
        else: snapshot = False
    if owner is None: return None, tentative
    facts = {'cleanup_confirmed': False}
    try: facts = owner.finish(cleanup_deadline=outer_deadline-30)
    except Exception:
        public['capture_owner_fallback'] = fallback_capture_owner(owner, outer_deadline-30)
        return facts, tentative
    try:
        expected = adapter.flow_context(capture_config,n0a_config,server,facts.get('cleanup_confirmed') is True)
        if snapshot and time.monotonic() < outer_deadline-20:
            tentative = adapter.parse_before_cleanup(owner.output_path, facts, server.capture_private_body, expected,
                header_before_link=header_before_link,
                terminal_before_shutdown=server.n0a_received.is_set() and server.capture_body_received.is_set(),
                capacity_abort=bool(public.get('capacity_abort') or public.get('capture_abort')))
            if tentative.get('capture_read_cleanup_confirmed') is False:
                facts['cleanup_confirmed'] = False
    except Exception: pass  # Missing evidence never becomes packet absence.
    return facts, tentative


def finish_udp6_capture_before_cleanup(owner, server, capture_config, n0a_config, public,
                                  outer_deadline, header_before_link):
    adapter = udp6_capture_helpers(); tentative = adapter.unavailable(); snapshot = True
    if server is not None:
        server.capture_accepting = False
        acquired = server.capture_lock.acquire(timeout=max(0, min(1, outer_deadline-time.monotonic())))
        if acquired: server.capture_lock.release()
        else: snapshot = False
    if owner is None: return None, tentative
    facts = {'cleanup_confirmed': False}
    try: facts = owner.finish(cleanup_deadline=outer_deadline-30)
    except Exception:
        public['capture_owner_fallback'] = fallback_capture_owner(owner, outer_deadline-30)
        return facts, tentative
    try:
        expected = adapter.flow_context(capture_config,n0a_config,server,facts.get('cleanup_confirmed') is True)
        if snapshot and time.monotonic() < outer_deadline-20:
            tentative = adapter.parse_before_cleanup(owner.output_path, facts, server.capture_private_body, expected,
                header_before_link=header_before_link,
                terminal_before_shutdown=server.n0a_received.is_set() and server.capture_body_received.is_set(),
                capacity_abort=bool(public.get('capacity_abort') or public.get('capture_abort')))
            if tentative.get('capture_read_cleanup_confirmed') is False:
                facts['cleanup_confirmed'] = False
    except Exception: pass  # Missing evidence never becomes packet absence.
    return facts, tentative


def cleanup_remaining(deadline, maximum):
    return max(0, min(maximum, deadline-time.monotonic()))


def finish_capture_server(server, thread, deadline, facts):
    okay = True
    if server is not None:
        # Registered before start; never retry creation or imply thread killing.
        shutdown = getattr(server, 'capture_shutdown_thread', None)
        if shutdown is None and thread is not None and thread.ident is not None and cleanup_remaining(deadline, 1)>0:
            server.capture_shutdown_ok = False
            def shutdown_once():
                try: server.shutdown(); server.capture_shutdown_ok = True
                except Exception: pass
            shutdown = threading.Thread(target=shutdown_once, daemon=True)
            server.capture_shutdown_thread = shutdown
            try: shutdown.start()
            except Exception: okay = False
        if shutdown is not None:
            try: shutdown.join(timeout=cleanup_remaining(deadline, 5))
            except Exception: okay = False
            try: okay = okay and not shutdown.is_alive() and server.capture_shutdown_ok is True
            except Exception: okay = False
        elif thread is not None and thread.ident is not None: okay = False
        facts['server_shutdown_succeeded'] = okay
        try: server.server_close(); facts['server_close_succeeded'] = server.socket.fileno()<0
        except Exception: facts['server_close_succeeded'] = False
        okay = okay and facts['server_close_succeeded']
    if thread is not None:
        try: thread.join(timeout=cleanup_remaining(deadline, 5))
        except Exception: okay = False
        try: facts['server_thread_stopped'] = not thread.is_alive()
        except Exception: facts['server_thread_stopped'] = False
        okay = okay and facts['server_thread_stopped']
    return okay


def finalize_capture_owned(public, media, work, qemu, tpm, qmp, server, thread, watch,
                           n0a_endpoint, capture_facts, deadline):
    facts = new_teardown_facts(); public['teardown_diagnostic'] = facts
    facts['qemu_present'] = qemu is not None; facts['tpm_present'] = tpm is not None
    facts['qmp_present'] = qmp is not None; facts['server_present'] = server is not None
    okay = capture_facts.get('cleanup_confirmed') is True
    registered = tuple(watch.processes) if watch is not None else ()
    owned = []
    for process in (qemu, tpm, *registered):
        if process is not None and all(process is not prior for prior in owned): owned.append(process)
    helpers = [p for p in owned if p is not qemu and p is not tpm]; facts['helper_count'] = len(helpers)
    for process in owned:
        label = 'qemu' if process is qemu else 'tpm' if process is tpm else 'helper'
        exit_observation(process, facts, label, 'before')
        if process is qemu and facts.get('qemu_exit_before_cleanup') == -signal.SIGXFSZ:
            public['capacity_abort'] = 'file_size_limit_signal'
        # CaptureOwner is the sole cleanup signal owner for QEMU.
        if process is not qemu:
            observed = False
            try: observed = type(process.poll()) is int
            except Exception as exc: okay = False; teardown_error(facts, 'process_observation', exc)
            if not observed:
                try: process.kill()
                except Exception as exc: okay = False; teardown_error(facts, 'process_stop', exc)
                try: process.wait(timeout=cleanup_remaining(deadline, 5))
                except Exception as exc: okay = False; teardown_error(facts, 'process_stop', exc)
        confirmed = exit_observation(process, facts, label, 'after'); okay = okay and confirmed
        if label == 'helper' and confirmed: facts['helper_exit_confirmed_count'] += 1
    if n0a_endpoint is not None:
        try: endpoint = n0a_endpoint.finish(deadline=deadline)
        except Exception: endpoint = {'socket_cleanup_confirmed': False, 'endpoint_error': True, 'receiver_counts': None}
        public['n0a_receiver_cleanup'] = endpoint
        okay = okay and endpoint.get('socket_cleanup_confirmed') is True
    if watch is not None:
        facts['watcher_present'] = True
        try: watch.stop.set(); watch.thread.join(timeout=cleanup_remaining(deadline, 2))
        except Exception as exc: okay = False; teardown_error(facts, 'watcher_stop', exc)
        try: facts['watcher_stopped'] = not watch.thread.is_alive()
        except Exception: facts['watcher_stopped'] = False
        okay = okay and facts['watcher_stopped']; public['minimum_free_bytes'] = watch.minimum_free
    if qmp is not None:
        try:
            qmp.socket.settimeout(cleanup_remaining(deadline, 5))
            qmp.close(); facts['qmp_close_succeeded'] = True
        except Exception as exc:
            okay = False; facts['qmp_close_succeeded'] = False; teardown_error(facts, 'qmp_close', exc)
            try: qmp.socket.close()
            except Exception: pass
        observe_qmp_closed(qmp, facts)
        okay = okay and facts['qmp_file_closed'] is True and facts['qmp_socket_closed'] is True
    server_okay = finish_capture_server(server, thread, deadline, facts); okay = okay and server_okay
    if okay:
        facts['work_remove_attempted'] = True
        try: shutil.rmtree(work)
        except OSError as exc: okay = False; teardown_error(facts, 'work_remove', exc)
    else: facts['work_retained'] = True
    try: work.lstat(); facts['work_removed'] = False
    except FileNotFoundError: facts['work_removed'] = True
    except OSError: facts['work_removed'] = None
    public['vm_destroyed'] = okay and facts['work_removed'] is True
    reconcile_capacity(public, watch.reason if watch else None)
    if not public['vm_destroyed']:
        public['status'] = 'cleanup_unconfirmed'; public['stage0_passed'] = False
    return public


def verify_n0a_inputs(actor, manifest):
    def bounded(path, maximum):
        path = Path(path)
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
            raise ValueError('bounded regular N0a input required')
        data = path.read_bytes()
        if len(data) != info.st_size: raise ValueError('N0a input changed')
        return data
    actor_data = bounded(actor, 8 * 1024**2)
    if len(actor_data) < 512 or Path(actor).suffix.lower() != '.exe': raise ValueError('bounded native N0a executable required')
    manifest_data = bounded(manifest, 8192)
    value = json.loads(manifest_data, object_pairs_hook=n0a_helpers().unique_object)
    fields = {'schemaVersion','sourceSha256','identitySourceSha256','executableSha256',
              'targetArchitecture','staticCrt','httpCompiled','rawTcpCompiled','compileOnly',
              'testOnly','actorRole','builtAtUtc'}
    if type(value) is not dict or set(value) != fields: raise ValueError('N0a production manifest shape')
    source_digest = hashlib.sha256(bounded(ROOT / '.github/native/windows_n0a_actor.cpp', 128*1024)).hexdigest()
    identity_digest = hashlib.sha256(bounded(ROOT / '.github/native/windows_identity_actor.cpp', 128*1024)).hexdigest()
    digest = hashlib.sha256(actor_data).hexdigest()
    if (type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['sourceSha256'] != source_digest or value['identitySourceSha256'] != identity_digest
            or value['executableSha256'] != digest or value['targetArchitecture'] != 'x64'
            or value['staticCrt'] is not True or value['httpCompiled'] is not False
            or value['rawTcpCompiled'] is not True or value['compileOnly'] is not True
            or value['testOnly'] is not False or value['actorRole'] != 'n0a-tcp'
            or type(value['builtAtUtc']) is not str or not 1 <= len(value['builtAtUtc']) <= 64):
        raise ValueError('N0a production provenance differs')
    return {'actor': Path(actor), 'manifest': Path(manifest),
            'config': {'enabled': True, 'case_nonce': secrets.token_hex(16), 'runner_port': None,
                       'actor_sha256': digest, 'manifest_sha256': hashlib.sha256(manifest_data).hexdigest(),
                       'actor_source_sha256': source_digest, 'identity_source_sha256': identity_digest}}


def n0a_wait_deadline(server, outer_deadline):
    observed = getattr(server, 'original_received_at', None)
    return min(outer_deadline, observed + 120) if type(observed) in (int, float) else outer_deadline


def wait_for_n0a(server, deadline, watch, disk, qemu, public, capture_owner=None):
    # Only called after the independent original receipt was merged. The
    # optional deadline can shorten, never replace/extend the native deadline.
    observe_capture(capture_owner, public)
    while not server.n0a_received.wait(.2):
        observe_capture(capture_owner, public)
        if watch.reason: raise RuntimeError(watch.reason)
        if disk.stat().st_size >= DISK_FILE_CAP - 64 * 1024**2:
            public['capacity_abort'] = 'backing_file_ceiling_reached'; qemu.kill(); raise RuntimeError('file cap')
        if qemu.poll() is not None: return 'qemu_exited'
        if time.monotonic() >= n0a_wait_deadline(server, deadline): return 'deadline'
    if getattr(server, 'capture_enabled', False) and server.capture_commitment is not None:
        body_deadline = min(n0a_wait_deadline(server, deadline), server.capture_received_at+10)
        while not server.capture_body_received.wait(.2):
            observe_capture(capture_owner, public)
            if watch.reason: raise RuntimeError(watch.reason)
            if disk.stat().st_size >= DISK_FILE_CAP-64*1024**2:
                public['capacity_abort'] = 'backing_file_ceiling_reached'; qemu.kill(); raise RuntimeError('file cap')
            if time.monotonic() >= body_deadline: return 'capture_body_deadline'
            if qemu.poll() is not None: return 'qemu_exited'
    observe_capture(capture_owner, public)
    return 'received'


def collect_n0a_result(server):
    if server is not None and getattr(server, 'n0a_result', None) is not None:
        return server.n0a_result
    return n0a_helpers().default_host_n0a('report_absent')


def compose_n0a_public(server, public, wait_state):
    # The optional receipt is independent, but a denial conclusion also needs
    # original guest provenance and confirmed owned endpoint/VM cleanup.
    # Never mutate the separately stored receipt or hide attributed success.
    result = json.loads(json.dumps(collect_n0a_result(server)))
    result['original_stage0_receipt_verified'] = public.get('guest_result_provenance_verified') is True
    result['host_receiver'] = public.get('n0a_receiver_cleanup')
    result['vm_destroyed'] = public.get('vm_destroyed') is True
    result['host_wait_state'] = wait_state
    receiver = result['host_receiver']
    complete = (result['original_stage0_receipt_verified'] and result['vm_destroyed']
                and isinstance(receiver, dict)
                and receiver.get('socket_cleanup_confirmed') is True
                and receiver.get('endpoint_error') is False
                and isinstance(receiver.get('receiver_counts'), dict)
                and set(receiver['receiver_counts']) == {'accepted', 'ordinary_verified_frames', 'contained_verified_frames', 'rejected', 'timed_out'}
                and all(type(value) is int and 0 <= value <= 128 for value in receiver['receiver_counts'].values())
                and receiver['receiver_counts']['ordinary_verified_frames'] >= 5
                and receiver['receiver_counts']['contained_verified_frames'] == 0)
    if not complete and result['result']['status'] != 'connect_succeeded':
        result['result']['status'] = 'inconclusive'
        for endpoint in result['result']['endpoints'].values():
            if endpoint['status'] == 'observed_connect_denial':
                endpoint['status'] = 'inconclusive'
    return result


def payload(python_archive, actor, actor_digest, bundle, destination, *, n0a=None, capture=False, udp=None, parent_udp=None, udp6=None):
    if udp6 is not None:
        if n0a is not None or capture or udp is not None or parent_udp is not None: raise ValueError('UDP replaces TCP payload')
        payload(python_archive, actor, actor_digest, bundle, destination)
        with zipfile.ZipFile(destination, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
            for key, member, pin in (('actor','udp6/actor.exe','actor_sha256'), ('manifest','udp6/build-manifest.json','manifest_sha256')):
                with udp6[key].open('rb') as source: content = source.read(8*1024**2+1)
                if len(content)>8*1024**2 or hashlib.sha256(content).hexdigest()!=udp6['config'][pin]: raise ValueError('UDP packaged pin')
                archive.writestr(member, content)
            for name in ('windows_n0a_control.py','windows_n0a_guest.py','windows_n0a_udp6.py','windows_n0a_udp6_guest.py','windows_n0a_udp6_flow.py'):
                archive.write(ROOT / '.github' / name, '.github/' + name)
        return hashlib.sha256(destination.read_bytes()).hexdigest()
    if parent_udp is not None:
        if n0a is not None or udp is not None or capture:raise ValueError('parent UDP replaces other experiments')
        config=parent_udp['config']
        child=dict(actor=parent_udp['child'],manifest=parent_udp['child_manifest'],config=dict(actor_sha256=config['child_sha256'],manifest_sha256=config['child_manifest_sha256']))
        payload(python_archive,actor,actor_digest,bundle,destination,udp=child)
        with zipfile.ZipFile(destination,'a',compression=zipfile.ZIP_DEFLATED) as archive:
            for key,member,pin in (('parent','parent/actor.exe','parent_sha256'),('parent_manifest','parent/build-manifest.json','parent_manifest_sha256')):
                with parent_udp[key].open('rb') as stream:content=stream.read(16*1024**2+1)
                if len(content)>16*1024**2 or hashlib.sha256(content).hexdigest()!=config[pin]:raise ValueError('parent payload pin')
                archive.writestr(member,content)
            for name in ('windows_n0a_udp_parent_control.py','windows_n0a_udp_parent_guest.py','windows_n0a_udp_parent_flow.py'):
                archive.write(ROOT/'.github'/name,'.github/'+name)
        return hashlib.sha256(destination.read_bytes()).hexdigest()
    if udp is not None:
        if n0a is not None or capture: raise ValueError('UDP replaces TCP payload')
        payload(python_archive, actor, actor_digest, bundle, destination)
        with zipfile.ZipFile(destination, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
            for key, member, pin in (('actor','udp/actor.exe','actor_sha256'), ('manifest','udp/build-manifest.json','manifest_sha256')):
                with udp[key].open('rb') as source: content = source.read(8*1024**2+1)
                if len(content)>8*1024**2 or hashlib.sha256(content).hexdigest()!=udp['config'][pin]: raise ValueError('UDP packaged pin')
                archive.writestr(member, content)
            for name in ('windows_n0a_control.py','windows_n0a_guest.py','windows_n0a_udp.py','windows_n0a_udp_guest.py','windows_n0a_udp_flow.py'):
                archive.write(ROOT / '.github' / name, '.github/' + name)
        return hashlib.sha256(destination.read_bytes()).hexdigest()
    python_data = verify_python(python_archive)
    if actor.stat().st_size > 16 * 1024**2 or bundle.stat().st_size > 64 * 1024**2:
        raise ValueError('bounded payload inputs required')
    if not DIGEST.fullmatch(actor_digest) or hashlib.sha256(actor.read_bytes()).hexdigest() != actor_digest:
        raise ValueError('actor pin mismatch')
    sys.path.insert(0, str(ROOT))
    import install_runtime
    data = install_runtime._g_bundle_bytes(bundle, allow_env_cache=False)
    with zipfile.ZipFile(bundle) as checked:
        if sum(item.file_size for item in checked.infolist()) > 64 * 1024**2:
            raise ValueError('bounded bundle expansion required')
    # Validate the pinned archive before copying only its known members.
    with tempfile.TemporaryDirectory(prefix='identity-bundle-') as temporary:
        install_runtime._extract_g_bundle(data, Path(temporary))
        # The existing extractor validates the manifest but writes only the two
        # native/license files. Copy the same validated manifest from the same
        # pinned bytes, never from a second input or a reserialized substitute.
        with zipfile.ZipFile(io.BytesIO(data)) as checked:
            manifest = checked.read('build-manifest.json')
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('python-embed.zip', python_data)
            archive.write(actor, 'actor.exe')
            archive.writestr('stage0-input.json', json.dumps({'actor_sha256': actor_digest}))
            archive.writestr('g/build-manifest.json', manifest)
            for name in ('wxc-exec.exe', 'MXC-LICENSE.md'):
                archive.write(Path(temporary) / name, 'g/' + name)
            for name in GUEST_SOURCES:
                archive.write(ROOT / name, name)
            if n0a is not None:
                # Recheck the byte pins immediately before packaging.
                for key, member, pin in (('actor','n0a/actor.exe','actor_sha256'),
                                          ('manifest','n0a/build-manifest.json','manifest_sha256')):
                    content = n0a[key].read_bytes()
                    if hashlib.sha256(content).hexdigest() != n0a['config'][pin]: raise ValueError('N0a packaged input changed')
                    archive.writestr(member, content)
                for name in ('.github/windows_n0a_control.py', '.github/windows_n0a_guest.py'):
                    archive.write(ROOT / name, name)
                if capture: archive.write(ROOT / '.github/windows_n0a_flow.py', '.github/windows_n0a_flow.py')
    return hashlib.sha256(destination.read_bytes()).hexdigest()


class ClosedServer(HTTPServer):
    # One synchronous handler, bounded request body, no disk writes.
    def __init__(self, payload, n0a_expected=None, capture=False, capture_work_deadline=None):
        self.capture_enabled = capture
        self.capture_work_deadline = capture_work_deadline
        self.capture_accepting = True; self.capture_lock = threading.Lock()
        self.capture_received_at = None; self.capture_commitment = None
        self.capture_commitment_error = False; self.capture_private_body = None
        self.capture_body_attempted = False; self.capture_body_received = threading.Event()
        self.capture_shutdown_thread = None
        self.n0a_expected = n0a_expected
        self.n0a_received = threading.Event()
        self.n0a_result = None
        self.original_received_at = None
        self.payload = payload
        self.capability = secrets.token_hex(32)
        self.received = threading.Event()
        self.result = None
        super().__init__(("127.0.0.1", 0), ClosedHandler)


class ClosedHandler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def setup(self):
        super().setup()
        self.connection.settimeout(5)
    def do_GET(self):
        if self.path != '/' + self.server.capability + '/payload.zip':
            self.send_error(404); return
        self.send_response(200)
        self.send_header('Content-Length', str(self.server.payload.stat().st_size))
        self.end_headers()
        with self.server.payload.open('rb') as source:
            shutil.copyfileobj(source, self.wfile, 65536)
    def do_POST(self):
        if getattr(self.server, 'capture_enabled', False):
            if self.path == '/' + self.server.capability + '/n0a-capture-result': return self.do_capture_POST(False)
            if self.path == '/' + self.server.capability + '/n0a-runner-flow': return self.do_capture_POST(True)
        if (not getattr(self.server, 'capture_enabled', False) and self.server.n0a_expected is not None
                and self.path == '/' + self.server.capability + '/n0a-result'):
            return self.do_n0a_POST()
        try:
            self.server.result_transport_state = 'endpoint_check'
            if self.path != '/' + self.server.capability + '/result': raise ValueError()
            self.server.result_transport_state = 'length_check'
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_REPORT: raise ValueError()
            self.server.result_transport_state = 'body_read'
            raw = self.rfile.read(length)
            if len(raw) != length: raise ValueError()
            self.server.result_transport_state = 'json_parse'
            value = json.loads(raw)
            self.server.result_transport_state = 'object_check'
            if not isinstance(value, dict): raise ValueError()
            self.server.result_transport_state = 'object_received'
            if self.server.n0a_expected is not None and self.server.received.is_set():
                self.send_error(409); return  # Original receipt is immutable in dual-POST mode.
            self.server.result = value
            if self.server.n0a_expected is not None: self.server.original_received_at = time.monotonic()
            self.server.received.set()
            self.send_response(200); self.end_headers()
        except (ValueError, OSError): self.send_error(400)

    def do_n0a_POST(self):
        try:
            if not self.server.received.is_set() or self.server.n0a_received.is_set():
                self.send_error(409); return
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_N0A_REPORT: raise ValueError('N0a result bound')
            raw = self.rfile.read(length)
            if len(raw) != length: raise ValueError('N0a result incomplete')
            value = json.loads(raw, object_pairs_hook=n0a_helpers().unique_object)
            self.server.n0a_result = n0a_helpers().validate_host_n0a_envelope(value, self.server.n0a_expected)
            self.server.n0a_received.set()
            self.send_response(200); self.end_headers()
        except (ValueError, TypeError, OSError): self.send_error(400)

    def do_capture_POST(self, body):
        try:
            if not self.server.capture_accepting or not self.server.received.is_set():
                self.send_error(409); return
            if body:
                if (not self.server.n0a_received.is_set() or self.server.capture_body_attempted
                        or self.server.capture_commitment is None):
                    self.send_error(409); return
                self.server.capture_body_attempted = True
                limit = capture_helpers().MAX_FLOW
            else:
                if self.server.n0a_received.is_set():
                    self.send_error(409); return
                limit = MAX_N0A_REPORT
            deadline = capture_request_deadline(self.server, body)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= limit: raise ValueError('capture bound')
            raw = read_capture_request(self, length, deadline)
            if body:
                if not capture_helpers().accept_private_body(raw, self.server.capture_commitment):
                    raise ValueError('capture commitment')
                result = None
            else:
                value = json.loads(raw, object_pairs_hook=n0a_helpers().unique_object,
                                   parse_constant=reject_capture_constant)
                result = capture_helpers().validate_capture_envelope(value, self.server.n0a_expected)
            acquired = self.server.capture_lock.acquire(timeout=cleanup_remaining(deadline, 1))
            if not acquired: raise ValueError('capture commit unavailable')
            try:
                if not self.server.capture_accepting or time.monotonic() >= deadline:
                    raise ValueError('capture closed')
                if body:
                    self.server.capture_private_body = raw; self.server.capture_body_received.set()
                else:
                    self.server.n0a_result = result['legacy']
                    self.server.capture_commitment = result['commitment']
                    self.server.capture_commitment_error = result['commitment_error']
                    self.server.capture_received_at = time.monotonic(); self.server.n0a_received.set()
            finally: self.server.capture_lock.release()
            self.send_response(200); self.end_headers()
        except (ValueError, TypeError, OSError, RecursionError): self.send_error(400)



class UDPClosedServer(ClosedServer):
    def __init__(self, payload, expected, deadline):
        super().__init__(payload, expected, True, deadline)
        self.udp_enabled = True
        self.RequestHandlerClass = UDPClosedHandler


class UDPClosedHandler(ClosedHandler):
    def do_POST(self):
        if self.path == '/' + self.server.capability + '/udp-capture-result': return self.do_udp_POST(False)
        if self.path == '/' + self.server.capability + '/udp-runner-flow': return self.do_udp_POST(True)
        if self.path != '/' + self.server.capability + '/result':
            self.send_error(404); return
        return super().do_POST()

    def do_udp_POST(self, body):
        try:
            if not self.server.capture_accepting or not self.server.received.is_set():
                self.send_error(409); return
            if body:
                if (not self.server.n0a_received.is_set() or self.server.capture_body_attempted
                        or self.server.capture_commitment is None):
                    self.send_error(409); return
                self.server.capture_body_attempted = True
                limit = udp_capture_helpers().MAX_FLOW
            else:
                if self.server.n0a_received.is_set():
                    self.send_error(409); return
                limit = MAX_N0A_REPORT
            deadline = capture_request_deadline(self.server, body)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= limit: raise ValueError('capture bound')
            raw = read_capture_request(self, length, deadline)
            if body:
                if not udp_capture_helpers().accept_private_body(raw, self.server.capture_commitment):
                    raise ValueError('capture commitment')
                result = None
            else:
                value = json.loads(raw, object_pairs_hook=n0a_helpers().unique_object,
                                   parse_constant=reject_capture_constant)
                result = udp_capture_helpers().validate_capture_envelope(value, self.server.n0a_expected)
            acquired = self.server.capture_lock.acquire(timeout=cleanup_remaining(deadline, 1))
            if not acquired: raise ValueError('capture commit unavailable')
            try:
                if not self.server.capture_accepting or time.monotonic() >= deadline:
                    raise ValueError('capture closed')
                if body:
                    self.server.capture_private_body = raw; self.server.capture_body_received.set()
                else:
                    self.server.n0a_result = result['legacy']
                    self.server.capture_commitment = result['commitment']
                    self.server.capture_commitment_error = result['commitment_error']
                    self.server.capture_received_at = time.monotonic(); self.server.n0a_received.set()
            finally: self.server.capture_lock.release()
            self.send_response(200); self.end_headers()
        except (ValueError, TypeError, OSError, RecursionError): self.send_error(400)



class ParentUDPClosedServer(ClosedServer):
    def __init__(self, payload, expected, deadline):
        super().__init__(payload, expected, True, deadline)
        self.udp_enabled = True
        self.parent_udp_enabled = True
        self.RequestHandlerClass = ParentUDPClosedHandler


class ParentUDPClosedHandler(ClosedHandler):
    def do_POST(self):
        if self.path == '/' + self.server.capability + '/udp-parent-capture-result': return self.do_udp_POST(False)
        if self.path == '/' + self.server.capability + '/udp-parent-runner-flow': return self.do_udp_POST(True)
        if self.path != '/' + self.server.capability + '/result':
            self.send_error(404); return
        return super().do_POST()

    def do_udp_POST(self, body):
        try:
            if not self.server.capture_accepting or not self.server.received.is_set():
                self.send_error(409); return
            if body:
                if (not self.server.n0a_received.is_set() or self.server.capture_body_attempted
                        or self.server.capture_commitment is None):
                    self.send_error(409); return
                self.server.capture_body_attempted = True
                limit = parent_udp_capture_helpers().MAX_FLOW
            else:
                if self.server.n0a_received.is_set():
                    self.send_error(409); return
                limit = MAX_N0A_REPORT
            deadline = capture_request_deadline(self.server, body)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= limit: raise ValueError('capture bound')
            raw = read_capture_request(self, length, deadline)
            if body:
                if not parent_udp_capture_helpers().accept_private_body(raw, self.server.capture_commitment):
                    raise ValueError('capture commitment')
                result = None
            else:
                value = json.loads(raw, object_pairs_hook=n0a_helpers().unique_object,
                                   parse_constant=reject_capture_constant)
                result = parent_udp_capture_helpers().validate_capture_envelope(value, self.server.n0a_expected)
            acquired = self.server.capture_lock.acquire(timeout=cleanup_remaining(deadline, 1))
            if not acquired: raise ValueError('capture commit unavailable')
            try:
                if not self.server.capture_accepting or time.monotonic() >= deadline:
                    raise ValueError('capture closed')
                if body:
                    self.server.capture_private_body = raw; self.server.capture_body_received.set()
                else:
                    self.server.n0a_result = result['legacy']
                    self.server.capture_commitment = result['commitment']
                    self.server.capture_commitment_error = result['commitment_error']
                    self.server.capture_received_at = time.monotonic(); self.server.n0a_received.set()
            finally: self.server.capture_lock.release()
            self.send_response(200); self.end_headers()
        except (ValueError, TypeError, OSError, RecursionError): self.send_error(400)


class UDP6ClosedServer(ClosedServer):
    def __init__(self, payload, expected, deadline):
        super().__init__(payload, expected, True, deadline)
        self.udp_enabled = True
        self.udp6_enabled = True
        self.RequestHandlerClass = UDP6ClosedHandler


class UDP6ClosedHandler(ClosedHandler):
    def do_POST(self):
        if self.path == '/' + self.server.capability + '/udp6-capture-result': return self.do_udp_POST(False)
        if self.path == '/' + self.server.capability + '/udp6-runner-flow': return self.do_udp_POST(True)
        if self.path != '/' + self.server.capability + '/result':
            self.send_error(404); return
        return super().do_POST()

    def do_udp_POST(self, body):
        try:
            if not self.server.capture_accepting or not self.server.received.is_set():
                self.send_error(409); return
            if body:
                if (not self.server.n0a_received.is_set() or self.server.capture_body_attempted
                        or self.server.capture_commitment is None):
                    self.send_error(409); return
                self.server.capture_body_attempted = True
                limit = udp6_capture_helpers().MAX_FLOW
            else:
                if self.server.n0a_received.is_set():
                    self.send_error(409); return
                limit = MAX_N0A_REPORT
            deadline = capture_request_deadline(self.server, body)
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= limit: raise ValueError('capture bound')
            raw = read_capture_request(self, length, deadline)
            if body:
                if not udp6_capture_helpers().accept_private_body(raw, self.server.capture_commitment):
                    raise ValueError('capture commitment')
                result = None
            else:
                value = json.loads(raw, object_pairs_hook=n0a_helpers().unique_object,
                                   parse_constant=reject_capture_constant)
                result = udp6_capture_helpers().validate_capture_envelope(value, self.server.n0a_expected)
            acquired = self.server.capture_lock.acquire(timeout=cleanup_remaining(deadline, 1))
            if not acquired: raise ValueError('capture commit unavailable')
            try:
                if not self.server.capture_accepting or time.monotonic() >= deadline:
                    raise ValueError('capture closed')
                if body:
                    self.server.capture_private_body = raw; self.server.capture_body_received.set()
                else:
                    self.server.n0a_result = result['legacy']
                    self.server.capture_commitment = result['commitment']
                    self.server.capture_commitment_error = result['commitment_error']
                    self.server.capture_received_at = time.monotonic(); self.server.n0a_received.set()
            finally: self.server.capture_lock.release()
            self.send_response(200); self.end_headers()
        except (ValueError, TypeError, OSError, RecursionError): self.send_error(400)


def limited_command(command, ceiling):
    # prlimit applies limits before exec; do not use preexec_fn after threads start.
    return ['prlimit', '--fsize=' + str(ceiling) + ':' + str(ceiling),
            '--core=0:0', '--'] + command


class CapacityWatch:
    def __init__(self, work):
        self.work = work
        self.minimum_free = shutil.disk_usage(work).free
        self.reason = None
        self.processes = []
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
    def register(self, process):
        with self.lock:
            self.processes.append(process)
            if self.reason:
                if process.poll() is None: process.kill()
                raise RuntimeError('capacity guard already stopped')
    def run(self):
        while not self.stop.wait(.2):
            try:
                self.minimum_free = min(self.minimum_free, shutil.disk_usage(self.work).free)
                if self.minimum_free < STOP_FREE: self.reason = 'free_reserve_reached'
            except OSError: self.reason = 'capacity_measurement_failed'
            if self.reason:
                with self.lock: processes = tuple(self.processes)
                for process in processes:
                    if process.poll() is None:
                        try: process.kill()
                        except OSError: pass
                return
    def close(self):
        self.stop.set(); self.thread.join(2)
        if self.thread.is_alive(): self.reason = 'capacity_watch_stop_unconfirmed'


def reconcile_capacity(public, reason):
    if reason or public.get('capacity_abort'):
        public['capacity_abort'] = reason or public['capacity_abort']
        public['stage0_passed'] = False
        public['status'] = 'resource_abort'
    return public


def interrupted(signum, frame):
    raise InterruptedError('owned lab cancelled')


def remaining_budget(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('work budget exhausted; reserve cleanup')
    return min(maximum, remaining)


class VMWorkBudgetInsufficient(TimeoutError):
    pass


def require_vm_work_budget(deadline, *, now=None):
    # This is the existing work deadline, with the 120s cleanup reserve already
    # excluded. Never extend it because preparation took longer than expected.
    remaining = deadline - (time.monotonic() if now is None else now)
    if remaining < MIN_VM_WORK_SECONDS:
        raise VMWorkBudgetInsufficient('time_budget_insufficient')
    return remaining


def run_bounded(command, deadline, maximum, **kwargs):
    return subprocess.run(command, timeout=remaining_budget(deadline, maximum), **kwargs)


TEARDOWN_STAGES = ('process_stop', 'process_observation', 'qmp_close', 'qmp_file_observation',
    'qmp_socket_observation', 'qmp_socket_close', 'qemu_stop', 'tpm_stop', 'server_shutdown',
    'server_close', 'server_join', 'server_observation', 'watcher_stop', 'watcher_observation',
    'work_remove', 'work_observation', 'cleanup_wrapper')
TEARDOWN_ERRORS = ('BrokenPipeError', 'ConnectionResetError', 'ConnectionAbortedError', 'OSError',
    'TimeoutExpired', 'TimeoutError', 'ValueError', 'RuntimeError', 'PermissionError',
    'FileNotFoundError', 'ProcessLookupError', 'unclassified')


def teardown_error(facts, stage, exc):
    # Never publish exception text, paths, argv, PID or object representations.
    if stage not in TEARDOWN_STAGES: stage = 'cleanup_wrapper'
    facts['error_count'] += 1
    if facts['first_failed_stage'] is None: facts['first_failed_stage'] = stage
    if len(facts['errors']) < 8:
        facts['errors'].append({'stage': stage, 'type': type(exc).__name__ if type(exc).__name__ in TEARDOWN_ERRORS else 'unclassified',
            'errno': getattr(exc, 'errno', None) if type(getattr(exc, 'errno', None)) is int and -0x80000000 <= exc.errno <= 0xffffffff else None,
            'winerror': getattr(exc, 'winerror', None) if type(getattr(exc, 'winerror', None)) is int and -0x80000000 <= exc.winerror <= 0xffffffff else None})


def new_teardown_facts():
    return {'schema_version': 1, 'qemu_present': False, 'tpm_present': False,
        'qemu_exit_before_cleanup': None, 'tpm_exit_before_cleanup': None,
        'qemu_exit_after_cleanup': None, 'tpm_exit_after_cleanup': None,
        'qemu_exit_confirmed': None, 'tpm_exit_confirmed': None,
        'helper_count': 0, 'helper_exit_confirmed_count': 0,
        'qmp_present': False, 'qmp_close_succeeded': None, 'qmp_file_closed': None, 'qmp_socket_closed': None,
        'server_present': False, 'server_shutdown_succeeded': None, 'server_close_succeeded': None,
        'server_thread_stopped': None, 'watcher_present': False, 'watcher_stopped': None,
        'work_remove_attempted': False, 'work_removed': None, 'work_retained': False,
        'first_failed_stage': None, 'error_count': 0, 'errors': []}


def exit_observation(process, facts, label, when):
    if process is None: return True
    try:
        code = process.poll()
        # Popen returns int or None. Unexpected protocol values are not proof.
        observed = type(code) is int and -0x80000000 <= code <= 0xffffffff
        if label in ('qemu', 'tpm'):
            facts[label+'_exit_'+when+'_cleanup'] = code if observed else None
            facts[label+'_exit_confirmed'] = observed
        return observed
    except Exception as exc:
        teardown_error(facts, 'process_observation', exc)
        if label in ('qemu', 'tpm'): facts[label+'_exit_confirmed'] = False
        return False


def observe_qmp_closed(qmp, facts):
    try:
        value = getattr(getattr(qmp, 'file', None), 'closed', None)
        facts['qmp_file_closed'] = value if type(value) is bool else None
    except Exception as exc: teardown_error(facts, 'qmp_file_observation', exc)
    try:
        sock = getattr(qmp, 'socket', None)
        fd = sock.fileno() if sock is not None else None
        facts['qmp_socket_closed'] = fd < 0 if type(fd) is int else None
    except Exception as exc: teardown_error(facts, 'qmp_socket_observation', exc)


def cleanup_owned(media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None, *, retain_work=False, diagnostics=None):
    facts = diagnostics if diagnostics is not None else new_teardown_facts()
    cleanup_ok = True
    facts['qemu_present'] = qemu is not None; facts['tpm_present'] = tpm is not None
    facts['qmp_present'] = qmp is not None
    facts['server_present'] = server is not None
    if qmp is not None:
        try: qmp.close(); facts['qmp_close_succeeded'] = True
        except Exception as exc:
            cleanup_ok = False; facts['qmp_close_succeeded'] = False
            teardown_error(facts, 'qmp_close', exc)
            # Existing helper's buffered file.close can raise before socket.close.
            # Still close the owned socket independently; original failure remains
            # a failed cleanup criterion even if both handles are now closed.
            try:
                sock = getattr(qmp, 'socket', None)
                if sock is not None: sock.close()
            except Exception as socket_exc: teardown_error(facts, 'qmp_socket_close', socket_exc)
        observe_qmp_closed(qmp, facts)
        if facts['qmp_file_closed'] is not True or facts['qmp_socket_closed'] is not True:
            cleanup_ok = False
    for name, process in (('qemu', qemu), ('tpm', tpm)):
        try: media.stop_owned(process)
        except Exception as exc:
            cleanup_ok = False; teardown_error(facts, name+'_stop', exc)
    for stage, action in (('server_shutdown', server.shutdown if server is not None else None),
                          ('server_close', server.server_close if server is not None else None)):
        if action is not None:
            try: action(); facts[stage+'_succeeded'] = True
            except Exception as exc:
                cleanup_ok = False; facts[stage+'_succeeded'] = False; teardown_error(facts, stage, exc)
    if thread is not None:
        try: thread.join(timeout=5)
        except Exception as exc: cleanup_ok = False; teardown_error(facts, 'server_join', exc)
    live = False
    for name, process in (('qemu', qemu), ('tpm', tpm)):
        live = not exit_observation(process, facts, name, 'after') or live
    if thread is not None:
        try:
            facts['server_thread_stopped'] = not thread.is_alive()
            live = live or not facts['server_thread_stopped']
        except Exception as exc:
            live = True; teardown_error(facts, 'server_observation', exc)
    if not live and not retain_work:
        facts['work_remove_attempted'] = True
        try: shutil.rmtree(work)
        except OSError as exc: cleanup_ok = False; teardown_error(facts, 'work_remove', exc)
    else: facts['work_retained'] = True
    try:
        work.lstat(); facts['work_removed'] = False
    except FileNotFoundError: facts['work_removed'] = True
    except OSError as exc:
        facts['work_removed'] = None; cleanup_ok = False; teardown_error(facts, 'work_observation', exc)
    return cleanup_ok and not live and facts['work_removed'] is True


def finalize_owned(public, media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None, watch=None, n0a_endpoint=None, capture_facts=None, cleanup_deadline=None):
    if capture_facts is not None:
        return finalize_capture_owned(public, media, work, qemu, tpm, qmp, server, thread, watch,
                                      n0a_endpoint, capture_facts, cleanup_deadline)
    facts = new_teardown_facts(); public['teardown_diagnostic'] = facts
    facts['qemu_present'] = qemu is not None; facts['tpm_present'] = tpm is not None
    for name, process in (('qemu', qemu), ('tpm', tpm)): exit_observation(process, facts, name, 'before')
    teardown_uncertain = False
    registered = tuple(watch.processes) if watch is not None else ()
    owned = []
    for process in (qemu, tpm, *registered):
        if process is not None and all(process is not prior for prior in owned): owned.append(process)
    helpers = [p for p in owned if p is not qemu and p is not tpm]
    facts['helper_count'] = len(helpers)
    for process in owned:
        try:
            code = process.poll()
            if process is qemu and code == -signal.SIGXFSZ: public['capacity_abort'] = 'file_size_limit_signal'
            if code is None:
                try: process.kill()
                except OSError: pass  # Exit between poll and kill is normal; still wait/check.
                process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            teardown_uncertain = True; teardown_error(facts, 'process_stop', exc)
    retain_work = teardown_uncertain
    if n0a_endpoint is not None:
        try: endpoint_facts = n0a_endpoint.finish()
        except Exception: endpoint_facts = {'socket_cleanup_confirmed': False, 'endpoint_error': True, 'receiver_counts': None}
        public['n0a_receiver_cleanup'] = endpoint_facts
        if endpoint_facts.get('socket_cleanup_confirmed') is not True:
            retain_work = True; teardown_uncertain = True
    for process in owned:
        confirmed = exit_observation(process, facts, 'qemu' if process is qemu else 'tpm' if process is tpm else 'helper', 'after')
        retain_work = retain_work or not confirmed
        if any(process is helper for helper in helpers) and confirmed: facts['helper_exit_confirmed_count'] += 1
    if watch:
        facts['watcher_present'] = True; watcher_uncertain = False
        try: watch.close()
        except Exception as exc:
            watcher_uncertain = True; teardown_error(facts, 'watcher_stop', exc)
        try: facts['watcher_stopped'] = not watch.thread.is_alive()
        except Exception as exc:
            facts['watcher_stopped'] = False; teardown_error(facts, 'watcher_observation', exc)
        watcher_uncertain = watcher_uncertain or not facts['watcher_stopped']
        retain_work = retain_work or watcher_uncertain
        if watcher_uncertain: watch.reason = 'capacity_watch_stop_unconfirmed'
        public['minimum_free_bytes'] = watch.minimum_free
    try:
        cleaned = cleanup_owned(media, work, qemu, tpm, qmp, server, thread,
                                retain_work=retain_work, diagnostics=facts)
    except Exception as exc:
        cleaned = False; teardown_error(facts, 'cleanup_wrapper', exc)
    public['vm_destroyed'] = cleaned and not teardown_uncertain and not retain_work
    reconcile_capacity(public, watch.reason if watch else None)
    if not public['vm_destroyed']:
        public['status'] = 'cleanup_unconfirmed'; public['stage0_passed'] = False
    return public


QMP_COMMANDS = ('qmp_capabilities', 'query-block', 'query-named-block-nodes', 'query-status',
    'query-kvm', 'set_link', 'send-key', 'ringbuf-read')
QMP_ERROR_CLASSES = ('GenericError', 'CommandNotFound', 'DeviceNotActive', 'DeviceNotFound', 'KVMMissingCap')


def scoped_qmp_class(base, public):
    """Capture only QMP command/error enums, never the server's description."""
    class ScopedQmp(base):
        def _execute(self, command, arguments=None):
            public['qmp_diagnostic'] = {'command': command if command in QMP_COMMANDS else 'unclassified',
                'error_class': 'none', 'completed': False}
            request = {'execute': command}
            if arguments: request['arguments'] = arguments
            self.file.write(json.dumps(request).encode('ascii') + b'\n')
            self.file.flush()
            while True:
                raw = self.file.readline()
                if not raw: raise RuntimeError('QMP connection closed')
                response = json.loads(raw)
                if 'error' in response:
                    error = response['error']
                    kind = error.get('class') if isinstance(error, dict) else None
                    public['qmp_diagnostic']['error_class'] = kind if kind in QMP_ERROR_CLASSES else 'unclassified'
                    raise RuntimeError('QMP command rejected')
                if 'return' in response:
                    public['qmp_diagnostic']['completed'] = True
                    return response['return']
    return ScopedQmp


def merge_direct_result(public, value, actor_digest, installed_ready):
    public['stage0_passed'] = False
    public['guest_result_provenance_verified'] = False
    observed = project_stage0(value)
    for key in ('diagnostics', 'guest_diagnostic', 'launcher_diagnostic'):
        public[key] = observed[key]
    if public.get('early_guest_diagnostic') is not None:
        raise EarlyGuestFailure('closed guest failure contradicts result acceptance')
    validated = validate_guest(value, actor_digest)
    if not installed_ready: raise ValueError('installed guest handoff absent')
    public.update(validated)
    public['guest_result_provenance_verified'] = True


EARLY_OPERATIONS = ('configuration_read', 'identity', 'cim_os', 'cim_drive', 'version', 'product',
                    'setup', 'image', 'gate', 'beacon', 'waiting_setup', 'other')
EARLY_GATES = ('product_winnt', 'arch_amd64', 'setup_not_busy', 'oobe_not_busy', 'image_complete',
    'env_drive_c', 'os_drive_c', 'windows_directory', 'fixed_drive', 'build_26300', 'ubr_direct')
EARLY_KEYS = frozenset(('schema', 'phase', 'operation', 'failure_category', 'hresult', 'gates'))
EARLY_MAX_JSON = 2048
EARLY_PREFIX = 'RPDIAG1 '


class EarlyGuestFailure(RuntimeError):
    pass


def parse_early_guest(line):
    if not isinstance(line, str) or not line.startswith(EARLY_PREFIX): return None
    payload = line[len(EARLY_PREFIX):]
    if not 0 < len(payload) <= EARLY_MAX_JSON or not payload.isascii(): return None
    try:
        # Duplicate keys are rejected, not last-wins parsed.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError('duplicate diagnostic key')
                result[key] = value
            return result
        value = json.loads(payload, object_pairs_hook=unique)
    except (ValueError, TypeError, RecursionError): return None
    if not isinstance(value, dict) or frozenset(value) != EARLY_KEYS: return None
    if type(value['schema']) is not int or value['schema'] != 1: return None
    if type(value['phase']) is not str or value['phase'] not in LAUNCHER_PHASES: return None
    if type(value['operation']) is not str or value['operation'] not in EARLY_OPERATIONS: return None
    if type(value['failure_category']) is not str or value['failure_category'] not in LAUNCHER_FAILURES: return None
    if value['hresult'] is not None and (type(value['hresult']) is not int or not -0x80000000 <= value['hresult'] <= 0x7fffffff): return None
    gates = value['gates']
    if not isinstance(gates, dict) or frozenset(gates) != frozenset(EARLY_GATES): return None
    if any(v is not None and type(v) is not bool for v in gates.values()): return None
    # Rebuild in fixed order; never retain an input object or unknown data.
    return {'schema': 1, 'phase': value['phase'], 'operation': value['operation'],
        'failure_category': value['failure_category'], 'hresult': value['hresult'],
        'gates': {key: gates[key] for key in EARLY_GATES}}


class EarlyGuestSerial:
    """Bounded fragmented line observer. It cannot grant readiness or acceptance."""
    def __init__(self):
        self.pending = ''; self.dropping = False
    def feed(self, chunk):
        if not isinstance(chunk, str) or len(chunk) > 65536:
            self.pending = ''; self.dropping = True; return None
        for char in chunk:
            if char == '\n':
                line = self.pending.removesuffix('\r')
                dropping = self.dropping; self.pending = ''; self.dropping = False
                if not dropping:
                    value = parse_early_guest(line)
                    if value is not None: return value
                continue
            if self.dropping: continue
            self.pending += char
            if len(self.pending) > len(EARLY_PREFIX)+EARLY_MAX_JSON+1:
                self.pending = ''; self.dropping = True
        return None


def observe_guest_serial(public, observer, chunk, *, fail_fast=True):
    diagnostic = observer.feed(chunk)
    if diagnostic is not None:
        public['early_guest_diagnostic'] = diagnostic
        public['host_wait_failure'] = 'guest_launcher_failure'
        public['stage0_passed'] = False
        # Serial is negative evidence only. After NIC activation retain the
        # cause but allow the already bounded HTTP path to deliver full facts.
        if fail_fast:
            raise EarlyGuestFailure('closed early guest failure')


BOOTSTRAP_SECONDS = 2100


class BootstrapTimeout(TimeoutError):
    pass


def observe_bootstrap(public, observer, chunk, tail, *, started, handed_off, plugged, now):
    # Parse bounded negative evidence before testing the bootstrap clock. A
    # beacon first observed at the deadline cannot retroactively meet it.
    observe_guest_serial(public, observer, chunk, fail_fast=not plugged)
    tail = (tail + chunk)[-256:]
    if not handed_off and now >= started + BOOTSTRAP_SECONDS:
        public['stage0_passed'] = False
        public['host_wait_failure'] = 'bootstrap_timeout'
        raise BootstrapTimeout('installed guest beacon deadline')
    return tail, not handed_off and 'RPBEACON identity-ordinary-ready' in tail


def download_direct_iso(iso, deadline):
    # Larger official image gets a bounded 30-minute step, never extra job time.
    return run_bounded(limited_command(['curl', '--fail', '--location', '--retry', '3', '--proto', '=https',
        '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '1780',
        '--output', str(iso), ISO_URL], ISO_BYTES), deadline, 1800, check=True)


def host(args):
    if not EXECUTION_ENABLED:
        raise PermissionError('direct exploratory execution is disabled pending frozen review')
    udp6_mode = getattr(args, 'n0a_udp6_runner', False)
    if udp6_mode and any(getattr(args,key,False) for key in ('n0a_udp_parent_runner','n0a_udp_runner','n0a','n0a_capture_runner')):
        raise ValueError('UDP6 replaces other experiments')
    parent_udp_mode = getattr(args,'n0a_udp_parent_runner',False)
    if parent_udp_mode and getattr(args,'n0a_udp_runner',False):raise ValueError('parent UDP replaces root UDP')
    optional_udp = udp6_capture_helpers() if udp6_mode else parent_udp_capture_helpers() if parent_udp_mode else None
    udp_mode = getattr(args, 'n0a_udp_runner', False) or parent_udp_mode or udp6_mode
    if udp_mode and (getattr(args, 'n0a', False) or getattr(args, 'n0a_capture_runner', False)):
        raise ValueError('UDP replaces TCP experiment')
    if udp_mode and (optional_udp.helper('control') if parent_udp_mode or udp6_mode else udp_helpers()).EXECUTION_ENABLED is not True:
        raise PermissionError('UDP disabled pending separate activation')
    if getattr(args, 'n0a', False) and n0a_helpers().EXECUTION_ENABLED is not True:
        raise PermissionError('N0a execution disabled pending separate review')
    if getattr(args, 'n0a_capture_runner', False):
        if not getattr(args, 'n0a', False) or capture_helpers().CAPTURE_EXECUTION_ENABLED is not True:
            raise PermissionError('capture execution disabled pending separate review')
    if sys.platform != 'linux' or not args.approved_disposable_vm:
        raise PermissionError('explicit disposable VM approval required')
    media = load('identity_win11_media', ROOT / '.github/windows_vm_test.py')
    verify_python(args.python_archive)
    args.output.mkdir(parents=True, exist_ok=False)
    public = {'schema_version': 1, 'stage': 'win11-direct26300.9457-exploratory-ordinary-deny-only-stage0',
              'status': 'blocked', 'stage0_passed': False, 'product_acceptance': False,
              'exploratory_stage0': True, 'documented_support_floor': '26300.9550',
              'privacy_qualified': False, 'network_tested': False, 'vm_destroyed': False}
    available = min(args.timeout_seconds, args.job_deadline_epoch - time.time())
    if available < 300: raise TimeoutError('native job cleanup reserve unavailable')
    qemu = tpm = server = thread = qmp = watch = n0a_endpoint = None
    n0a = None; original_merged = False; n0a_wait_state = 'not_started'
    capture_owner = capture_config = capture_facts = capture_tentative = None; header_before_link = False
    mapped_observer = None; mapped_facts = None
    work = Path(tempfile.mkdtemp(prefix='identity-win11-private-')); work.chmod(0o700)
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    deadline = time.monotonic() + available - 120
    outer_deadline = deadline + 120
    # Also bound non-subprocess work (hashes/ZIPs/filesystem) and helper calls.
    signal.setitimer(signal.ITIMER_REAL, available - 120)
    source = os.environ.get('GITHUB_SHA', '')
    if re.fullmatch(r'[0-9a-f]{40}', source): public['source_commit'] = source
    public['iso_sha256'] = ISO_SHA256
    public['actor_sha256'] = args.actor_sha256
    phase = 'preflight'; operation = 'preflight'; disk = None
    try:
        if getattr(args, 'n0a', False):
            n0a = verify_n0a_inputs(args.n0a_actor, args.n0a_manifest)
        if udp6_mode:n0a=optional_udp.verify_inputs(args.udp6_actor,args.udp6_manifest)
        elif parent_udp_mode:n0a=optional_udp.verify_inputs(args.udp_parent_actor,args.udp_parent_manifest,args.udp_actor,args.udp_manifest)
        elif udp_mode: n0a = udp_capture_helpers().verify_inputs(args.udp_actor, args.udp_manifest)
        media.require_kvm()
        if shutil.disk_usage(work).free < PREMEDIA_FREE:
            raise RuntimeError('insufficient disposable storage; no host cleanup performed')
        if not (shutil.which('7zz') or shutil.which('7z')): raise RuntimeError('existing 7zip verifier required')
        for binary in ('qemu-system-x86_64', 'qemu-img', 'swtpm', 'xorriso', 'curl'):
            if not shutil.which(binary): raise RuntimeError('missing VM tool')
        if not shutil.which('prlimit'): raise RuntimeError('missing process resource limiter')
        public['premedia_free_bytes'] = shutil.disk_usage(work).free
        phase = 'verified_media_download'
        iso = work / 'official.iso'
        operation = 'iso_download'
        download_direct_iso(iso, deadline)
        operation = 'iso_verify'
        if iso.stat().st_size != ISO_BYTES or media.digest(iso) != ISO_SHA256:
            raise ValueError('ISO provenance failed')
        record_breadcrumb(public, 'iso_verified', work, disk, deadline)
        operation = 'payload_build'
        raw = work / 'private-reports'; raw.mkdir()
        package = work / 'payload.zip'
        if n0a is not None:
            n0a_endpoint = ((optional_udp if parent_udp_mode or udp6_mode else udp_capture_helpers()).receiver(n0a['config']['case_nonce'], outer_deadline) if udp_mode
                             else n0a_helpers().NonceEndpoint(n0a['config']['case_nonce'], 'runner', deadline))
            n0a['config']['runner_port'] = n0a_endpoint.start()
        package_digest = payload(args.python_archive, args.actor, args.actor_sha256, args.bundle, package, n0a=None if udp_mode else n0a, capture=getattr(args, 'n0a_capture_runner', False), udp=n0a if udp_mode and not parent_udp_mode and not udp6_mode else None, parent_udp=n0a if parent_udp_mode else None, udp6=n0a if udp6_mode else None)
        if package.stat().st_size > MAX_PAYLOAD: raise ValueError('payload size cap')
        operation = 'result_server'
        server = (UDP6ClosedServer(package,n0a['config'],deadline) if udp6_mode else ParentUDPClosedServer(package,n0a['config'],deadline) if parent_udp_mode else UDPClosedServer(package, n0a['config'], deadline) if udp_mode else
                  ClosedServer(package, n0a['config'] if n0a is not None else None, getattr(args, 'n0a_capture_runner', False), deadline))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        operation = 'seed_build'
        tree = work / 'seed-tree'; tree.mkdir()
        config = {'host_url': f'http://10.0.2.2:{server.server_address[1]}/{server.capability}',
                  'payload_sha256': package_digest, 'python_sha256': PYTHON_ASSET['sha256'],
                  'actor_sha256': args.actor_sha256}
        if n0a is not None: config['n0a_udp6' if udp6_mode else 'n0a_udp_parent' if parent_udp_mode else 'n0a_udp' if udp_mode else 'n0a'] = dict(n0a['config'])
        if udp_mode or getattr(args, 'n0a_capture_runner', False):
            capture_config = capture_helpers().make_configuration(n0a['config'], source, media.VM_NIC_MAC)
            config['capture'] = capture_config
        media.prepare_seed(tree, secrets.token_hex(16) + 'Ci!9', config)
        for role in ('setup', 'run'):
            shutil.copyfile(ROOT / f'.github/windows-identity-direct-stage0-{role}.ps1', tree / f'ruleproxy-vm-{role}.ps1')
        seed = work / 'seed.iso'
        run_bounded(limited_command(['xorriso', '-as', 'mkisofs', '-J', '-R', '-V', 'RULEPROXY_SEED',
                     '-o', str(seed), str(tree)], MAX_SEED), deadline, 60, check=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if seed.stat().st_size > MAX_SEED: raise ValueError('seed cap')
        shutil.rmtree(tree)
        operation = 'disk_create'
        disk = work / 'windows.qcow2'; nvram = work / 'OVMF_VARS.fd'
        firmware = Path('/usr/share/OVMF'); code = firmware / 'OVMF_CODE_4M.ms.fd'
        shutil.copyfile(firmware / 'OVMF_VARS_4M.ms.fd', nvram)
        run_bounded(limited_command(['qemu-img', 'create', '-f', 'qcow2', '-o', 'preallocation=off', str(disk), '80G'], DISK_FILE_CAP), deadline, 30, check=True, stdout=subprocess.DEVNULL)
        record_breadcrumb(public, 'media_ready', work, disk, deadline)
        state = work / 'tpm-state'; state.mkdir()
        tpm_socket, qmp_socket, serial = work / 'tpm.sock', work / 'qmp.sock', work / 'serial.log'
        phase = 'stock_guest_installation'
        operation = 'launch_capacity'
        public['launch_free_bytes'] = shutil.disk_usage(work).free
        public['disk_file_ceiling_bytes'] = DISK_FILE_CAP
        public['reserve_guard_hard_guarantee'] = False
        if public['launch_free_bytes'] < LAUNCH_FREE: raise RuntimeError('launch capacity gate')
        if capture_config is not None:
            public['capture_admission'] = capture_helpers().admit(package.stat().st_size, public['launch_free_bytes'], LAUNCH_FREE)
            capture_root = work / 'capture'; capture_root.mkdir(mode=0o700)
            capture_owner = capture_helpers().new_owner(capture_root, outer_deadline)
            capture_owner.start()
        watch = CapacityWatch(work); watch.thread.start()
        operation = 'tpm_start'
        tpm = subprocess.Popen(limited_command(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state}', '--ctrl', f'type=unixio,path={tpm_socket}'], 8 * 1024**2), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        watch.register(tpm)
        ready = time.monotonic() + 20
        while not tpm_socket.exists():
            observe_capture(capture_owner, public)
            stopped = tpm.poll() is not None
            if stopped or time.monotonic() > ready:
                public['host_wait_failure'] = 'tpm_exited' if stopped else 'tpm_ready_timeout'
                raise RuntimeError('TPM failed')
            time.sleep(.1)
        operation = 'vm_work_budget'
        public['vm_work_seconds_available'] = int(require_vm_work_budget(deadline))
        operation = 'qemu_start'
        bootstrap_started = time.monotonic()
        qemu_command = ['qemu-system-x86_64', '-machine', 'q35,accel=kvm,smm=on', '-cpu',
            'host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on', '-m', '6144', '-smp', '4',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}', '-drive', f'if=pflash,format=raw,file={nvram}',
            '-drive', f'if=none,id=system,file={disk},format=qcow2,discard=unmap', '-device', 'ide-hd,drive=system,bus=ide.0,bootindex=1',
            '-drive', f'if=none,id=install,file={iso},media=cdrom,readonly=on', '-device', 'ide-cd,id=install-cd,drive=install,bus=ide.1,bootindex=2',
            '-drive', f'if=none,id=seed,file={seed},media=cdrom,readonly=on', '-device', 'ide-cd,drive=seed,bus=ide.2',
            '-netdev', 'user,id=vmnet', '-device', f'e1000,netdev=vmnet,mac={media.VM_NIC_MAC}',
            '-chardev', f'socket,id=tpm,path={tpm_socket}', '-tpmdev', 'emulator,id=tpmdev,chardev=tpm', '-device', 'tpm-tis,tpmdev=tpmdev',
            '-device', 'qemu-xhci', '-device', 'usb-tablet', '-vga', 'std', '-display', 'none', '-monitor', 'none',
            '-chardev', 'ringbuf,id=serialbuf,size=65536', '-serial', 'chardev:serialbuf', '-qmp', f'unix:{qmp_socket},server=on,wait=off']
        if capture_owner is not None:
            qemu_command += ['-object', f'filter-dump,id=n0a-capture,netdev=vmnet,file={capture_owner.fifo_path},queue=all,status=on,maxlen=262144']
            qemu = capture_owner.spawn(limited_command(qemu_command, DISK_FILE_CAP))
        else:
            qemu = subprocess.Popen(limited_command(qemu_command, DISK_FILE_CAP),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        record_breadcrumb(public, 'qemu_started', work, disk, deadline)
        operation = 'qmp_connect'
        watch.register(qemu)
        ready = time.monotonic() + 20
        while qmp is None:
            observe_capture(capture_owner, public)
            stopped = qemu.poll() is not None
            if stopped or time.monotonic() > ready:
                public['host_wait_failure'] = 'qemu_exited_before_qmp' if stopped else 'qmp_ready_timeout'
                raise RuntimeError('QEMU failed')
            try: qmp = scoped_qmp_class(media.Qmp, public)(qmp_socket)
            except OSError: time.sleep(.1)
        operation = 'kvm_verify'
        if qmp.execute('query-kvm').get('enabled') is not True: raise RuntimeError('KVM required')
        qmp.execute('set_link', {'name': 'vmnet', 'up': False})
        if capture_owner is not None:
            if not capture_owner.wait_header(min(deadline, time.monotonic()+10)):
                raise RuntimeError('capture header unavailable')
            header_before_link = True
        if udp6_mode:
            operation = 'mapped_qemu_provenance'
            mapped_observer = optional_udp.new_provenance(qemu, Path(shutil.which('qemu-system-x86_64')).resolve(), deadline)
            mapped_observer.admit()
            mapped_facts = mapped_observer.snapshot()
            if mapped_facts.get('admitted') is not True:raise RuntimeError('mapped provenance unavailable')
        if True:  # Original ISO may require its standard press-key prompt.
            for _ in range(8):
                observe_capture(capture_owner, public)
                qmp.execute('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}], 'hold-time': 100}); time.sleep(2)
        operation = 'guest_wait'
        plugged = False; installed_handoff = False
        serial_tail = ""
        early_serial = EarlyGuestSerial()
        while not server.received.wait(.2):
            observe_capture(capture_owner, public)
            if watch.reason: raise RuntimeError(watch.reason)
            if disk.stat().st_size >= DISK_FILE_CAP - 64 * 1024**2:
                public['capacity_abort'] = 'backing_file_ceiling_reached'; qemu.kill(); raise RuntimeError('file cap')
            stopped = qemu.poll() is not None
            if stopped or time.monotonic() > deadline:
                public['host_wait_failure'] = 'qemu_exited' if stopped else 'guest_deadline'
                raise RuntimeError('guest deadline or exit')
            beacon = qmp.execute('ringbuf-read', {'device': 'serialbuf', 'size': 65536})
            serial_tail, installed_ready = observe_bootstrap(public, early_serial, beacon, serial_tail,
                started=bootstrap_started, handed_off=installed_handoff, plugged=plugged, now=time.monotonic())
            if 'RPBEACON identity-result-transport-failed' in serial_tail:
                public['guest_result_transport_failed'] = True
            if installed_ready:
                record_breadcrumb(public, 'guest_beacon', work, disk, deadline)
                installed_handoff = True
                qmp.execute('set_link', {'name': 'vmnet', 'up': True}); plugged = True
        observe_capture(capture_owner, public)
        record_breadcrumb(public, 'result_received', work, disk, deadline)
        operation = 'result_validation'
        # Preserve only closed diagnostics even if provenance validation fails.
        # These remain explicitly unverified, never acceptance evidence.
        merge_direct_result(public, server.result, args.actor_sha256, installed_handoff)
        public['status'] = 'passed' if public['stage0_passed'] else 'observed_failure'
        phase = 'stage0_completed'
        original_merged = True
        # Original receipt is already preserved/validated before optional wait.
        if n0a is not None:
            # Persist the original closed receipt before waiting on optional work.
            # vm_destroyed remains false until the existing final cleanup.
            (args.output / 'public-report.json').write_text(json.dumps(public, indent=2)+'\n', encoding='ascii')
            n0a_wait_state = wait_for_n0a(server, deadline, watch, disk, qemu, public, capture_owner)
    except VMWorkBudgetInsufficient as exc:
        public['stage0_passed'] = False
        public['host_failure'] = dict(closed_failure(exc), operation=operation)
        public['status'] = 'time_budget_insufficient'
    except (Exception, KeyboardInterrupt) as exc:
        public['stage0_passed'] = False
        public['host_failure'] = dict(closed_failure(exc), operation=operation)
        public['status'] = 'blocked'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        # A second cancellation must not interrupt owned-process cleanup.
        for sig in old_handlers: signal.signal(sig, signal.SIG_IGN)
        if server is not None:
            public['result_transport_state'] = getattr(server, 'result_transport_state', 'not_observed')
        if n0a is not None and not original_merged and server is not None and server.received.is_set():
            try:
                merge_direct_result(public, server.result, args.actor_sha256, installed_handoff)
                original_merged = True
            except Exception: public['stage0_passed'] = False
        if udp_mode or getattr(args, 'n0a_capture_runner', False):
            try:
                if udp6_mode:
                    if mapped_observer is not None:
                        try:mapped_observer.recheck_before_stop()
                        except Exception:pass
                    capture_facts, capture_tentative = finish_udp6_capture_before_cleanup(capture_owner,server,
                        capture_config,n0a['config'] if n0a is not None else None,public,outer_deadline,header_before_link)
                elif parent_udp_mode:
                    capture_facts, capture_tentative = finish_parent_capture_before_cleanup(capture_owner,server,
                        capture_config,n0a['config'] if n0a is not None else None,public,outer_deadline,header_before_link)
                else:
                    capture_facts, capture_tentative = finish_capture_before_cleanup(capture_owner, server,
                        capture_config, n0a['config'] if n0a is not None else None, public, outer_deadline, header_before_link)
            except Exception: capture_facts = {'cleanup_confirmed': False}
            if capture_facts is None: capture_facts = {'cleanup_confirmed': capture_owner is None}
        if udp6_mode and mapped_observer is not None:
            mapped_close_failed = False
            try:mapped_observer.close(cleanup_deadline=outer_deadline-25)
            except Exception:mapped_close_failed = True
            try:mapped_facts = mapped_observer.snapshot()
            except Exception:mapped_facts = None
            if mapped_close_failed and type(mapped_facts) is dict:
                mapped_facts=dict(mapped_facts,close_confirmed=False)
            if type(mapped_facts) is not dict or mapped_facts.get('close_confirmed') is not True:
                if capture_facts is None:capture_facts = {}
                capture_facts['cleanup_confirmed'] = False
        finalize_owned(public, media, work, qemu, tpm, qmp, server, thread, watch, n0a_endpoint,
                       capture_facts, outer_deadline if udp_mode or getattr(args, 'n0a_capture_runner', False) else None)
        if public['vm_destroyed']: record_breadcrumb(public, 'cleanup_done', work, disk, deadline)
        public['last_phase'] = phase
        (args.output / 'public-report.json').write_text(json.dumps(public, indent=2) + '\n', encoding='ascii')
        if udp6_mode:
            try:
                udp6_public=optional_udp.compose(server,public,n0a_wait_state)
                udp6_public['mapped_provenance']=mapped_facts
                udp6_public['packet']=optional_udp.qualify(capture_tentative,public,udp6_public)
                (args.output/'n0a-udp6-public.json').write_text(json.dumps(udp6_public,indent=2)+'\n',encoding='ascii')
            except Exception:
                try:print(json.dumps({'udp6_report_write_failed':True}),flush=True)
                except OSError:pass
        elif parent_udp_mode:
            try:
                parent_public=optional_udp.compose(server,public,n0a_wait_state)
                parent_public['packet']=optional_udp.qualify(capture_tentative,public,parent_public)
                (args.output/'n0a-udp-parent-public.json').write_text(json.dumps(parent_public,indent=2)+'\n',encoding='ascii')
            except Exception:
                try:print(json.dumps({'parent_udp_report_write_failed':True}),flush=True)
                except OSError:pass
        elif udp_mode:
            try:
                udp_public = udp_capture_helpers().compose(server, public, n0a_wait_state)
                udp_public['packet'] = udp_capture_helpers().qualify(capture_tentative, public, udp_public)
                (args.output / 'n0a-udp-public.json').write_text(json.dumps(udp_public, indent=2)+'\n', encoding='ascii')
            except Exception:
                try: print(json.dumps({'udp_report_write_failed': True}), flush=True)
                except OSError: pass
        elif n0a is not None:
            try:
                n0a_public = compose_n0a_public(server, public, n0a_wait_state)
                (args.output / 'n0a-connect-public.json').write_text(json.dumps(n0a_public, indent=2)+'\n', encoding='ascii')
                if getattr(args, 'n0a_capture_runner', False):
                    capture_public = capture_helpers().qualify(capture_tentative, public, n0a_public)
                    (args.output / 'n0a-capture-public.json').write_text(json.dumps(capture_public, indent=2)+'\n', encoding='ascii')
            except Exception:
                # Never let optional diagnostic/report failure erase Stage0.
                try: print(json.dumps({'n0a_report_write_failed': True}), flush=True)
                except OSError: pass
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
    return 0 if public['stage0_passed'] and public['vm_destroyed'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', action='store_true'); parser.add_argument('--approved-disposable-vm', action='store_true')
    parser.add_argument('--download-python', action='store_true')
    parser.add_argument('--check-preparation', action='store_true')
    parser.add_argument('--check-apt-plan', action='store_true')
    parser.add_argument('--preparation-phase', choices=PREP_PHASES[1:])
    parser.add_argument('--output', type=Path, required=True)
    for name in ('python-archive', 'actor', 'bundle'): parser.add_argument('--' + name, type=Path)
    parser.add_argument('--actor-sha256')
    parser.add_argument('--n0a-udp6-runner',action='store_true')
    parser.add_argument('--udp6-actor',type=Path);parser.add_argument('--udp6-manifest',type=Path)
    parser.add_argument('--n0a-udp-parent-runner',action='store_true')
    parser.add_argument('--udp-parent-actor',type=Path);parser.add_argument('--udp-parent-manifest',type=Path)
    parser.add_argument('--n0a-udp-runner', action='store_true')
    parser.add_argument('--udp-actor', type=Path); parser.add_argument('--udp-manifest', type=Path)
    parser.add_argument('--n0a', action='store_true')
    parser.add_argument('--n0a-capture-runner', action='store_true')
    parser.add_argument('--n0a-actor', type=Path); parser.add_argument('--n0a-manifest', type=Path)
    parser.add_argument('--timeout-seconds', type=int, default=6600)
    parser.add_argument('--job-deadline-epoch', type=int)
    args = parser.parse_args(argv)
    if args.n0a_udp6_runner and (args.n0a_udp_parent_runner or args.n0a_udp_runner or args.n0a or args.n0a_capture_runner or args.guest or args.download_python or args.check_preparation or args.check_apt_plan or not args.udp6_actor or not args.udp6_manifest):
        parser.error('UDP6 requires exclusive production inputs')
    if not args.n0a_udp6_runner and (args.udp6_actor or args.udp6_manifest):parser.error('UDP6 inputs require UDP6 opt-in')
    if args.n0a_udp_parent_runner and (args.n0a_udp_runner or args.n0a or args.n0a_capture_runner or args.guest or args.download_python or args.check_preparation or args.check_apt_plan or not all((args.udp_actor,args.udp_manifest,args.udp_parent_actor,args.udp_parent_manifest))):
        parser.error('parent UDP requires exclusive production inputs')
    if not args.n0a_udp_parent_runner and (args.udp_parent_actor or args.udp_parent_manifest):parser.error('parent inputs require parent opt-in')
    if args.n0a_udp_runner and (args.n0a or args.n0a_capture_runner or args.guest or args.download_python or args.check_preparation or args.check_apt_plan or not args.udp_actor or not args.udp_manifest):
        parser.error('UDP requires separate explicit host inputs')
    if not (args.n0a_udp_runner or args.n0a_udp_parent_runner) and (args.udp_actor or args.udp_manifest): parser.error('UDP inputs require explicit opt-in')
    if args.n0a and (args.guest or args.download_python or args.check_preparation or args.check_apt_plan
                      or not args.n0a_actor or not args.n0a_manifest):
        parser.error('N0a requires explicit host inputs only')
    if args.n0a_capture_runner and not args.n0a: parser.error('capture requires N0a opt-in')
    if not args.n0a and (args.n0a_actor or args.n0a_manifest): parser.error('N0a inputs require explicit opt-in')
    if args.check_preparation or args.check_apt_plan:
        if args.guest or args.approved_disposable_vm or args.download_python or (args.check_preparation and args.check_apt_plan):
            parser.error('preparation checks cannot execute a guest, VM or download')
        if args.check_apt_plan: return check_apt_plan(args.output)
        if args.preparation_phase is None: parser.error('closed preparation phase required')
        return preparation_checkpoint(args.output, args.preparation_phase)
    if args.download_python:
        if args.guest or args.approved_disposable_vm:
            parser.error('download mode must not execute a guest or VM')
        download_python(args.output)
        return 0
    if args.guest: return guest(args)
    if not all((args.python_archive, args.actor, args.bundle, args.actor_sha256)) or args.timeout_seconds != 6600 or args.job_deadline_epoch is None:
        parser.error('fixed host inputs, maximum6600-second budget and absolute job deadline required')
    return host(args)

if __name__ == '__main__': raise SystemExit(main())
