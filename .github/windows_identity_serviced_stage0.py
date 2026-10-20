"""Opt-in disposable Windows 11 Stage0. No product/privacy qualification.

Only closed projections leave the guest. Media, credentials, guest disk,
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
    '.github/windows_identity_serviced_stage0.py', '.github/windows_identity_proof.py',
    '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_runtime_pins.py',
)
CHECKS = ('request_aware_base_container', 'actual_base_container', 'fresh_actor',
          'native_identity', 'normal_exit', 'no_harness_error')
BOOLS = ('ordinary_account', 'servicing_verified', 'stage0_passed', 'harness_completed')
EXECUTION_ENABLED = True  # Frozen code review only; separate execution decision required.
GIB = 1024**3
PREMEDIA_FREE = 64 * GIB
LAUNCH_FREE = 54 * GIB
DISK_FILE_CAP = 48 * GIB
HOST_MAX_SECONDS = 9600
CLEANUP_RESERVE_SECONDS = 180
HOST_START_MIN_SECONDS = 9000
STOP_FREE = 4 * GIB
MAX_PAYLOAD = 256 * 1024**2
MAX_SEED = 16 * 1024**2
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
MAX_REPORT = 16384
MIN_VM_WORK_SECONDS = 7500
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
LAUNCHER_PHASES = ('not_observed', 'configuration', 'identity', 'beacon', 'stock_build', 'claim', 'endpoint',
    'payload_download', 'payload_hash', 'payload_extract', 'python_hash', 'python_extract',
    'python_start', 'python_wait', 'report_read', 'report_parse', 'completed', 'transport', 'installed_boot_gate', 'installed_setup_wait', 'servicing_wait', 'serviced_build')
LAUNCHER_FAILURES = ('none', 'operation_failed', 'identity_gate', 'stock_build_gate', 'endpoint_timeout',
    'payload_bound', 'payload_overrun', 'payload_incomplete', 'payload_hash', 'python_hash', 'python_not_started',
    'process_handle_missing', 'python_deadline', 'report_absent', 'report_over_bound', 'report_nonobject', 'report_parse', 'installed_boot_gate', 'installed_setup_deadline', 'servicing_receipt', 'servicing_failed', 'servicing_deadline', 'serviced_build_gate')
HOST_OPERATIONS = ('preflight', 'iso_download', 'iso_verify', 'payload_build', 'result_server', 'seed_build',
    'disk_create', 'launch_capacity', 'tpm_start', 'vm_work_budget', 'clock_contract', 'qemu_start', 'qmp_connect', 'kvm_verify',
    'guest_wait', 'serviced_media', 'result_validation', 'cleanup')
BREADCRUMBS = ('iso_verified', 'media_ready', 'qemu_started', 'guest_beacon', 'installer_reclaimed', 'updates_downloaded', 'update_iso_verified', 'update_sources_removed', 'servicing_admitted', 'result_received', 'cleanup_done')


SERVICED_QEMU_TZ = 'America/Los_Angeles'
SERVICED_WINDOWS_TZ = 'Pacific Standard Time'
SERVICED_RTC = 'base=localtime,clock=host'


def serviced_qemu_environment():
    # Child-only libc timezone contract; never mutate the controller's timezone.
    environment = os.environ.copy()
    environment['TZ'] = SERVICED_QEMU_TZ
    return environment


def require_serviced_clock_window(deadline_epoch, *, wall_now=None):
    from datetime import datetime, timezone
    from zoneinfo import ZoneInfo
    now = time.time() if wall_now is None else wall_now
    if not 0 < deadline_epoch - now <= HOST_MAX_SECONDS:
        raise ValueError('bounded clock window required')
    zone = ZoneInfo(SERVICED_QEMU_TZ)
    local = datetime.fromtimestamp(now, timezone.utc).astimezone(zone)
    if local.replace(fold=0).utcoffset() != local.replace(fold=1).utcoffset():
        raise ValueError('ambiguous initial local clock')
    offset = local.utcoffset()
    # Fixed Pacific zone transitions are larger than this sampling period;
    # include the exact endpoint and never extend the existing work deadline.
    sample = now
    while sample < deadline_epoch:
        sample = min(sample + 60, deadline_epoch)
        observed = datetime.fromtimestamp(sample, timezone.utc).astimezone(zone)
        if observed.replace(fold=0).utcoffset() != observed.replace(fold=1).utcoffset():
            raise ValueError('ambiguous local clock in work window')
        if observed.utcoffset() != offset:
            raise ValueError('clock transition in work window')


def render_serviced_timezone(unattend):
    original = '<TimeZone>UTC</TimeZone>'
    if not isinstance(unattend, str) or unattend.count(original) != 1:
        raise ValueError('exact original timezone required')
    if len(re.findall(r'<TimeZone(?:\s|>)', unattend)) != 1:
        raise ValueError('single timezone required')
    return unattend.replace(original, '<TimeZone>' + SERVICED_WINDOWS_TZ + '</TimeZone>', 1)


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
    result = {'schema_version': 1, 'stage': 'win11-serviced26200.9711-ordinary-deny-only-stage0',
              'network_tested': False, 'product_acceptance': False, 'privacy_qualified': False,
              'psec_cleanup_independently_verified': False,
              'checks': {key: checks.get(key) is True for key in CHECKS},
              'request_supported': checks.get('request_aware_base_container') is True,
              'stage0_passed': raw.get('stage0_passed') is True and all(checks.get(k) is True for k in CHECKS),
              'diagnostics': proof.closed_diagnostics(raw)}
    result['servicing_diagnostic'] = closed_servicing(raw.get('servicing_diagnostic'))
    result['servicing_read_diagnostic'] = closed_servicing_read(raw.get('servicing_read_diagnostic'))
    result['setup_read_diagnostic'] = closed_servicing_read(raw.get('setup_read_diagnostic'))
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
                               and all(result[k] for k in ('ordinary_account', 'servicing_verified', 'harness_completed')))
    result['servicing_diagnostic'] = closed_servicing(value.get('servicing_diagnostic'))
    result['stage0_passed'] = result['stage0_passed'] and all(result['servicing_diagnostic'][k] is True for k in ('completed', 'packages_verified', 'task_unregistered', 'reboot_observed'))
    receipt = result['servicing_diagnostic']
    result['stage0_passed'] = (result['stage0_passed'] and receipt['phase'] == 'completed'
        and receipt['failure'] == 'none' and receipt['dism_exit_code'] in (0,3010)
        and receipt['dism_wait_timed_out'] is False)
    result['os'] = {'build': 26200, 'ubr': 9711, 'product_type': 'WinNT', 'architecture': 'AMD64'}
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


def payload(python_archive, actor, actor_digest, bundle, destination):
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
    return hashlib.sha256(destination.read_bytes()).hexdigest()


class ClosedServer(HTTPServer):
    # One synchronous handler, bounded request body, no disk writes.
    def __init__(self, payload):
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
            self.server.result = value
            self.server.received.set()
            self.send_response(200); self.end_headers()
        except (ValueError, OSError): self.send_error(400)


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


def admit_host_budget(timeout, job_deadline, *, wall_now=None, monotonic_now=None):
    wall = time.time() if wall_now is None else wall_now
    mono = time.monotonic() if monotonic_now is None else monotonic_now
    available = min(timeout, job_deadline - wall)
    if available < HOST_START_MIN_SECONDS:
        raise VMWorkBudgetInsufficient('host start budget insufficient')
    work = available - CLEANUP_RESERVE_SECONDS
    return available, mono + work, int(wall + work)


def require_phase_budget(deadline, minimum, *, now=None):
    remaining = deadline - (time.monotonic() if now is None else now)
    if remaining < minimum:
        raise VMWorkBudgetInsufficient('phase time budget insufficient')
    return remaining


def require_vm_work_budget(deadline, *, now=None):
    # This is the existing work deadline, with the 180s cleanup reserve already
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


def finalize_owned(public, media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None, watch=None):
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


# New opt-in sizing, not a claim that servicing fits. The original stock path is
# unchanged. QEMU receives a 48 GiB hard limit from launch; no privilege increase.
UPDATE_VOLUME = 'RULEPROXY_UPDATE'
UPDATE_BYTES = 5308811935
UPDATE_ISO_OVERHEAD = 16 * 1024**2
UPDATE_ISO_CAP = UPDATE_BYTES + UPDATE_ISO_OVERHEAD
SERVICE_FLOOR = STOP_FREE + GIB
# Conservative full qcow cap plus the larger retained-installer or duplicate-update peak.
FULL_PEAK_BUDGET_BYTES = DISK_FILE_CAP + max(7092807680, UPDATE_BYTES + UPDATE_ISO_CAP) + SERVICE_FLOOR + GIB
MIN_MEDIA_WORK_SECONDS = 5400
MIN_SERVICE_SECONDS = 3000  # 40-minute DISM wait bound plus 10 minutes reboot/native checks.
UPDATE_PINS = (
    ('windows11.0-kb5043080-x64.msu', 533761740, '819632610a101af11c72907fb13ff05b5fb4222c0e263ee9a03bcc1d1d5f26a4'),
    ('windows11.0-kb5127648-x64.msu', 4775050195, '8a1067c763121953876e2e0dcbf5e2c5832545a44ef6baba362938287e05fcfb'),
)
SERVICE_PHASES = ('not_observed', 'unclassified', 'initializing', 'waiting_for_optical', 'verifying_optical', 'post_reboot_verify', 'installing_official_cu', 'reboot_pending', 'completed')
SERVICE_FAILURES = ('none','unclassified','service_deadline','system_required','prior_bound','prior_state','setup_deadline','optical_deadline','optical_device','optical_root','optical_members','optical_package','optical_changed','reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains','exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed','operation_failed')


SERVICE_READ_STEPS = ('not_started', 'clock_contract', 'directory_acl', 'budget_acl', 'budget_read', 'budget_json',
    'budget_schema', 'budget_epoch', 'receipt_acl', 'receipt_read', 'receipt_json', 'receipt_observed')
SERVICE_READ_REASONS = ('none', 'clock_contract', 'missing', 'acl', 'read', 'json', 'schema', 'type', 'expired', 'over_bound', 'operation_failed')


def closed_servicing_read(value):
    proof = proof_helpers(); value = proof._dict(value)
    return {'step': proof._enum(value.get('step'), SERVICE_READ_STEPS, 'not_started'),
            'reason': proof._enum(value.get('reason'), SERVICE_READ_REASONS, 'operation_failed'),
            'remaining_seconds': proof._integer(value.get('remaining_seconds'), -172800, 172800),
            'zone_pacific': value.get('zone_pacific') if type(value.get('zone_pacific')) is bool else None,
            'utc_offset_minutes': value.get('utc_offset_minutes') if type(value.get('utc_offset_minutes')) is int and value.get('utc_offset_minutes') in (-480, -420) else None}


def closed_servicing(value):
    proof = proof_helpers(); value = proof._dict(value)
    return {'phase': proof._enum(value.get('phase'), SERVICE_PHASES, 'not_observed'),
            **{k: value.get(k) is True for k in ('completed', 'packages_verified', 'task_unregistered', 'reboot_observed',
                'dism_wait_timed_out', 'dism_exit_observed', 'dism_exit_observation_available')},
            'dism_exit_code': proof._integer(value.get('dism_exit_code'), -0x80000000),
            'failure': proof._enum(value.get('failure'), SERVICE_FAILURES, 'unclassified')}


def update_packages(media):
    packages = media.UPDATE_PACKAGES
    if (media.UPDATE_BUILD, media.UPDATE_UBR) != (26200, 9711): raise ValueError('update target changed')
    if tuple((p.get('seed_filename'), p.get('bytes'), p.get('sha256')) for p in packages) != UPDATE_PINS:
        raise ValueError('update pins changed')
    for p in packages:
        if not p.get('url', '').startswith('https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/'):
            raise ValueError('update origin changed')
    return packages


def owned_regular(path, work):
    if path.parent != work or path.name not in ('official.iso', 'updates.iso', *(p[0] for p in UPDATE_PINS)):
        raise ValueError('unowned file target')
    root = work.lstat(); value = path.lstat()
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != os.getuid() or root.st_mode & 0o077 or
        not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1 or value.st_dev != root.st_dev):
        raise ValueError('owned regular file required')
    return value


def unlink_same(path, work, before):
    now = owned_regular(path, work)
    if (now.st_dev, now.st_ino, now.st_size) != (before.st_dev, before.st_ino, before.st_size):
        raise ValueError('owned file binding changed')
    path.unlink()


QMP_COMMANDS = ('qmp_capabilities', 'query-block', 'query-named-block-nodes', 'query-status',
    'stop', 'cont', 'blockdev-open-tray', 'blockdev-remove-medium', 'blockdev-change-medium',
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


def exact_frontend(qmp, backend, frontend):
    row = exact_block(qmp, backend)
    if row.get('qdev') != frontend:
        raise ValueError('owned frontend binding changed')
    return row


def block_inventory(qmp, command):
    rows = qmp.execute(command)
    if not isinstance(rows, list) or len(rows) > 64 or any(not isinstance(r, dict) for r in rows):
        raise ValueError('bounded block inventory required')
    if len(json.dumps(rows)) > 65536: raise ValueError('block inventory over bound')
    field = 'device' if command == 'query-block' else 'file'
    if any(not isinstance(r.get(field), str) for r in rows): raise ValueError('block inventory schema mismatch')
    return rows


def exact_block(qmp, device):
    rows = block_inventory(qmp, 'query-block')
    found = [r for r in rows if isinstance(r, dict) and r.get('device') == device]
    if len(found) != 1: raise ValueError('owned block device not unique')
    return found[0]


def references(value, path):
    if isinstance(value, dict): return any(references(v, path) for v in value.values())
    if isinstance(value, list): return any(references(v, path) for v in value)
    return isinstance(value, str) and str(path) in value


def pause_installed(qmp):
    if qmp.execute('query-status').get('running') is not True: raise ValueError('running guest required')
    qmp.execute('stop')
    state = qmp.execute('query-status')
    if state.get('running') is not False or state.get('status') != 'paused': raise ValueError('guest pause unconfirmed')


def reclaim_installer(qmp, iso, work, media, public=None):
    if public is None: public = {}
    before = owned_regular(iso, work)
    if before.st_size != media.ISO_BYTES: raise ValueError('original ISO size changed')
    inserted = exact_frontend(qmp, 'install', 'install-cd').get('inserted', {})
    if inserted.get('file') != str(iso) or inserted.get('ro') is not True: raise ValueError('original media binding changed')
    public['installer_frontend_verified'] = True
    qmp.execute('blockdev-open-tray', {'id': 'install-cd', 'force': True})
    public['installer_tray_opened'] = True
    qmp.execute('blockdev-remove-medium', {'id': 'install-cd'})
    public['installer_medium_removed'] = True
    if exact_frontend(qmp, 'install', 'install-cd').get('inserted'): raise ValueError('installer still inserted')
    for command in ('query-block', 'query-named-block-nodes'):
        if references(block_inventory(qmp, command), iso): raise ValueError('installer still referenced')
    public['installer_backend_released'] = True
    unlink_same(iso, work, before)


def attach_update_medium(qmp, update_iso, public):
    if exact_frontend(qmp, 'updates', 'update-cd').get('inserted'):
        raise ValueError('update device occupied')
    public['update_frontend_verified'] = True
    qmp.execute('blockdev-change-medium', {'id': 'update-cd', 'filename': str(update_iso),
        'format': 'raw', 'read-only-mode': 'read-only'})
    public['update_medium_changed'] = True
    inserted = exact_frontend(qmp, 'updates', 'update-cd').get('inserted', {})
    if inserted.get('file') != str(update_iso) or inserted.get('ro') is not True:
        raise ValueError('readonly update medium unconfirmed')
    public['update_media_attached_readonly'] = True


def service_capacity(work, disk, *, temporary=0, final_addition=0):
    value = disk.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_size >= DISK_FILE_CAP: raise ValueError('disk bound')
    free = shutil.disk_usage(work).free
    # Conservatively assume every logical byte through the hard file cap can
    # allocate a filesystem block. Never subtract sparse allocated bytes twice.
    growth = DISK_FILE_CAP - value.st_blocks * 512
    if growth < 0: raise ValueError('allocated disk exceeds bound')
    if free - temporary < SERVICE_FLOOR or free - final_addition - growth < SERVICE_FLOOR:
        raise RuntimeError('servicing capacity admission failed')
    return {'free_bytes': free, 'qcow_allocated_bytes': value.st_blocks*512,
            'temporary_bytes': temporary, 'final_addition_bytes': final_addition,
            'remaining_qcow_allocation_bound': growth,
            'projected_floor_bytes': min(free-temporary, free-final_addition-growth)}


def service_process(command, deadline, watch, *, ceiling, maximum=600, stream_digest=None):
    until = time.monotonic() + remaining_budget(deadline, maximum)
    process = subprocess.Popen(limited_command(command, ceiling), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if stream_digest else subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        watch.register(process)
        if stream_digest:
            import select
            expected_bytes, expected_digest = stream_digest
            count = 0; digest = hashlib.sha256()
            while True:
                if watch.reason or time.monotonic() >= until: raise TimeoutError('media verification deadline')
                ready, _, _ = select.select([process.stdout], [], [], min(.2, max(0, until-time.monotonic())))
                if not ready: continue
                data = os.read(process.stdout.fileno(), 65536)
                if not data: break
                count += len(data)
                if count > expected_bytes: raise ValueError('media member exceeds bound')
                digest.update(data)
            if count != expected_bytes or digest.hexdigest() != expected_digest:
                raise ValueError('update DVD member mismatch')
        code = process.wait(timeout=max(.01, until-time.monotonic()))
        if code or watch.reason: raise RuntimeError('bounded servicing helper failed')
    finally:
        if process.poll() is None: process.kill()
        process.wait(timeout=5)
        if process.stdout: process.stdout.close()


def prepare_servicing(media, qmp, work, iso, disk, deadline, watch, public):
    packages = update_packages(media)
    require_phase_budget(deadline, MIN_MEDIA_WORK_SECONDS)
    pause_installed(qmp)
    public['installed_guest_paused'] = True
    reclaim_installer(qmp, iso, work, media, public)
    public['installer_detach_verified'] = True
    record_breadcrumb(public, 'installer_reclaimed', work, disk, deadline)
    public['servicing_admission_before_download'] = service_capacity(work, disk,
        temporary=UPDATE_BYTES+UPDATE_ISO_CAP, final_addition=UPDATE_ISO_CAP)
    files = []
    for package in packages:
        path = work / package['seed_filename']
        if path.exists(): raise FileExistsError('owned package path occupied')
        service_process(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '3',
            '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '600',
            '--output', str(path), package['url']], deadline, watch, ceiling=package['bytes'], maximum=620)
        before = owned_regular(path, work)
        if before.st_size != package['bytes'] or media.digest(path) != package['sha256']: raise ValueError('update pin mismatch')
        files.append((path, before))
    record_breadcrumb(public, 'updates_downloaded', work, disk, deadline)
    service_capacity(work, disk, temporary=UPDATE_ISO_CAP, final_addition=UPDATE_ISO_CAP-UPDATE_BYTES)
    update_iso = work / 'updates.iso'
    if update_iso.exists(): raise FileExistsError('owned update image occupied')
    # ISO9660 level3 multi-extent, not UDF. Guest re-hashes both complete MSUs
    # before DISM, so unsupported Windows multi-extent reads fail explicitly.
    service_process(['xorriso', '-as', 'mkisofs', '-iso-level', '3', '-J', '-joliet-long', '-R',
        '-V', UPDATE_VOLUME, '-o', str(update_iso), '-graft-points',
        *[path.name+'='+str(path) for path, _ in files]], deadline, watch, ceiling=UPDATE_ISO_CAP, maximum=300)
    image = owned_regular(update_iso, work)
    if not UPDATE_BYTES <= image.st_size <= UPDATE_ISO_CAP: raise ValueError('update ISO bound')
    extractor = shutil.which('7zz') or shutil.which('7z')
    if not extractor: raise RuntimeError('7zip verifier missing')
    for package in packages:
        service_process([extractor, 'x', '-so', str(update_iso), package['seed_filename']], deadline, watch,
            ceiling=1024**2, maximum=300, stream_digest=(package['bytes'], package['sha256']))
    public['update_media_members_verified'] = True
    public['update_iso_sha256'] = media.digest(update_iso)
    public['update_iso_bytes'] = image.st_size
    record_breadcrumb(public, 'update_iso_verified', work, disk, deadline)
    for path, before in files: unlink_same(path, work, before)
    public['update_source_files_removed'] = True
    record_breadcrumb(public, 'update_sources_removed', work, disk, deadline)
    require_phase_budget(deadline, MIN_SERVICE_SECONDS)
    public['servicing_admission_before_attach'] = service_capacity(work, disk)
    rebound = owned_regular(update_iso, work)
    if (rebound.st_dev,rebound.st_ino,rebound.st_size) != (image.st_dev,image.st_ino,image.st_size): raise ValueError('update image binding changed')
    attach_update_medium(qmp, update_iso, public)
    record_breadcrumb(public, 'servicing_admitted', work, disk, deadline)
    require_phase_budget(deadline, MIN_SERVICE_SECONDS)
    qmp.execute('cont')
    if qmp.execute('query-status').get('running') is not True: raise ValueError('guest resume unconfirmed')
    public['installed_guest_resumed'] = True



def merge_serviced_result(public, value, actor_digest, service_started):
    public['stage0_passed'] = False
    public['guest_result_provenance_verified'] = False
    observed = project_stage0(value)
    for key in ('diagnostics', 'guest_diagnostic', 'launcher_diagnostic', 'servicing_diagnostic', 'servicing_read_diagnostic', 'setup_read_diagnostic'):
        public[key] = observed[key]
    if public.get('early_guest_diagnostic') is not None:
        raise EarlyGuestFailure('closed guest failure contradicts result acceptance')
    validated = validate_guest(value, actor_digest)
    if not service_started or any(public.get(k) is not True for k in ('installer_detach_verified', 'update_media_members_verified', 'update_source_files_removed', 'update_media_attached_readonly', 'installed_guest_resumed')):
        raise ValueError('host servicing stages incomplete')
    public.update(validated)
    public['guest_result_provenance_verified'] = True


EARLY_OPERATIONS = ('configuration_read', 'identity', 'cim_os', 'cim_drive', 'version', 'product',
                    'setup', 'image', 'gate', 'beacon', 'waiting_setup', 'other')
EARLY_GATES = ('product_winnt', 'arch_amd64', 'setup_not_busy', 'oobe_not_busy', 'image_complete',
    'env_drive_c', 'os_drive_c', 'windows_directory', 'fixed_drive', 'build_26200', 'ubr_stock_or_target')
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
    return tail, not handed_off and 'RPBEACON identity-stock-installed-ready' in tail


def host(args):
    if not EXECUTION_ENABLED:
        raise PermissionError('stock experiment execution is disabled pending frozen review')
    if sys.platform != 'linux' or not args.approved_disposable_vm:
        raise PermissionError('explicit disposable VM approval required')
    media = load('identity_win11_media', ROOT / '.github/windows_vm_test.py')
    verify_python(args.python_archive)
    if media.ISO_SHA256 != 'a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9' or media.ISO_BYTES != 7092807680:
        raise ValueError('stock ISO baseline changed')
    args.output.mkdir(parents=True, exist_ok=False)
    public = {'schema_version': 1, 'stage': 'win11-serviced26200.9711-ordinary-deny-only-stage0',
              'status': 'blocked', 'stage0_passed': False, 'product_acceptance': False,
              'privacy_qualified': False, 'network_tested': False, 'vm_destroyed': False}
    available, deadline, work_deadline_epoch = admit_host_budget(args.timeout_seconds, args.job_deadline_epoch)
    qemu = tpm = server = thread = qmp = watch = None
    work = Path(tempfile.mkdtemp(prefix='identity-win11-private-')); work.chmod(0o700)
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    # Also bound non-subprocess work (hashes/ZIPs/filesystem) and helper calls.
    signal.setitimer(signal.ITIMER_REAL, available - CLEANUP_RESERVE_SECONDS)
    source = os.environ.get('GITHUB_SHA', '')
    if re.fullmatch(r'[0-9a-f]{40}', source): public['source_commit'] = source
    public['iso_sha256'] = media.ISO_SHA256
    public['actor_sha256'] = args.actor_sha256
    phase = 'preflight'; operation = 'preflight'; disk = None
    try:
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
        run_bounded(limited_command(['curl', '--fail', '--location', '--retry', '3', '--proto', '=https',
            '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '1200',
            '--output', str(iso), media.ISO_URL], media.ISO_BYTES), deadline, 1220, check=True)
        operation = 'iso_verify'
        if iso.stat().st_size != media.ISO_BYTES or media.digest(iso) != media.ISO_SHA256:
            raise ValueError('ISO provenance failed')
        record_breadcrumb(public, 'iso_verified', work, disk, deadline)
        operation = 'payload_build'
        raw = work / 'private-reports'; raw.mkdir()
        package = work / 'payload.zip'
        package_digest = payload(args.python_archive, args.actor, args.actor_sha256, args.bundle, package)
        if package.stat().st_size > MAX_PAYLOAD: raise ValueError('payload size cap')
        operation = 'result_server'
        server = ClosedServer(package)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        operation = 'seed_build'
        tree = work / 'seed-tree'; tree.mkdir()
        config = {'host_url': f'http://10.0.2.2:{server.server_address[1]}/{server.capability}',
                  'payload_sha256': package_digest, 'python_sha256': PYTHON_ASSET['sha256'],
                  'actor_sha256': args.actor_sha256}
        media.prepare_seed(tree, secrets.token_hex(16) + 'Ci!9', config)
        unattend = tree / 'autounattend.xml'
        unattend.write_text(render_serviced_timezone(unattend.read_text(encoding='utf-8')), encoding='utf-8')
        # Readonly seed authority: SYSTEM copies this absolute deadline to protected storage.
        (tree / 'service-budget.json').write_text(json.dumps({'schema': 1,
            'deadline_unix_seconds': work_deadline_epoch}), encoding='ascii')
        for role in ('setup', 'run'):
            shutil.copyfile(ROOT / f'.github/windows-identity-serviced-stage0-{role}.ps1', tree / f'ruleproxy-vm-{role}.ps1')
        shutil.copyfile(ROOT / '.github/windows-identity-serviced-update.ps1', tree / 'windows-identity-serviced-update.ps1')
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
        watch = CapacityWatch(work); watch.thread.start()
        operation = 'tpm_start'
        tpm = subprocess.Popen(limited_command(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state}', '--ctrl', f'type=unixio,path={tpm_socket}'], 8 * 1024**2), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        watch.register(tpm)
        ready = time.monotonic() + 20
        while not tpm_socket.exists():
            stopped = tpm.poll() is not None
            if stopped or time.monotonic() > ready:
                public['host_wait_failure'] = 'tpm_exited' if stopped else 'tpm_ready_timeout'
                raise RuntimeError('TPM failed')
            time.sleep(.1)
        operation = 'vm_work_budget'
        public['vm_work_seconds_available'] = int(require_vm_work_budget(deadline))
        operation = 'clock_contract'
        require_serviced_clock_window(work_deadline_epoch)
        operation = 'qemu_start'
        bootstrap_started = time.monotonic()
        qemu = subprocess.Popen(limited_command(['qemu-system-x86_64', '-machine', 'q35,accel=kvm,smm=on', '-cpu',
            'host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on', '-rtc', SERVICED_RTC, '-m', '6144', '-smp', '4',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}', '-drive', f'if=pflash,format=raw,file={nvram}',
            '-drive', f'if=none,id=system,file={disk},format=qcow2,discard=unmap', '-device', 'ide-hd,drive=system,bus=ide.0,bootindex=1',
            '-drive', f'if=none,id=install,file={iso},media=cdrom,readonly=on', '-device', 'ide-cd,id=install-cd,drive=install,bus=ide.1,bootindex=2',
            '-drive', 'if=none,id=updates,media=cdrom,readonly=on', '-device', 'ide-cd,id=update-cd,drive=updates,bus=ide.3',
            '-drive', f'if=none,id=seed,file={seed},media=cdrom,readonly=on', '-device', 'ide-cd,drive=seed,bus=ide.2',
            '-netdev', 'user,id=vmnet', '-device', f'e1000,netdev=vmnet,mac={media.VM_NIC_MAC}',
            '-chardev', f'socket,id=tpm,path={tpm_socket}', '-tpmdev', 'emulator,id=tpmdev,chardev=tpm', '-device', 'tpm-tis,tpmdev=tpmdev',
            '-device', 'qemu-xhci', '-device', 'usb-tablet', '-vga', 'std', '-display', 'none', '-monitor', 'none',
            '-chardev', 'ringbuf,id=serialbuf,size=65536', '-serial', 'chardev:serialbuf', '-qmp', f'unix:{qmp_socket},server=on,wait=off'], DISK_FILE_CAP),
            env=serviced_qemu_environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        record_breadcrumb(public, 'qemu_started', work, disk, deadline)
        operation = 'qmp_connect'
        watch.register(qemu)
        ready = time.monotonic() + 20
        while qmp is None:
            stopped = qemu.poll() is not None
            if stopped or time.monotonic() > ready:
                public['host_wait_failure'] = 'qemu_exited_before_qmp' if stopped else 'qmp_ready_timeout'
                raise RuntimeError('QEMU failed')
            try: qmp = scoped_qmp_class(media.Qmp, public)(qmp_socket)
            except OSError: time.sleep(.1)
        operation = 'kvm_verify'
        if qmp.execute('query-kvm').get('enabled') is not True: raise RuntimeError('KVM required')
        qmp.execute('set_link', {'name': 'vmnet', 'up': False})
        if True:  # Original ISO may require its standard press-key prompt.
            for _ in range(8):
                qmp.execute('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}], 'hold-time': 100}); time.sleep(2)
        operation = 'guest_wait'
        plugged = False; service_started = False
        serial_tail = ""
        early_serial = EarlyGuestSerial()
        while not server.received.wait(.2):
            if watch.reason: raise RuntimeError(watch.reason)
            if disk.stat().st_size >= DISK_FILE_CAP - 64 * 1024**2:
                public['capacity_abort'] = 'backing_file_ceiling_reached'; qemu.kill(); raise RuntimeError('file cap')
            stopped = qemu.poll() is not None
            if stopped or time.monotonic() > deadline:
                public['host_wait_failure'] = 'qemu_exited' if stopped else 'guest_deadline'
                raise RuntimeError('guest deadline or exit')
            beacon = qmp.execute('ringbuf-read', {'device': 'serialbuf', 'size': 65536})
            serial_tail, installed_ready = observe_bootstrap(public, early_serial, beacon, serial_tail,
                started=bootstrap_started, handed_off=service_started, plugged=plugged, now=time.monotonic())
            if 'RPBEACON identity-result-transport-failed' in serial_tail:
                public['guest_result_transport_failed'] = True
            if installed_ready:
                record_breadcrumb(public, 'guest_beacon', work, disk, deadline)
                operation = 'serviced_media'
                prepare_servicing(media, qmp, work, iso, disk, deadline, watch, public)
                service_started = True; operation = 'guest_wait'
                qmp.execute('set_link', {'name': 'vmnet', 'up': True}); plugged = True
            if service_started and not plugged and 'RPBEACON identity-ordinary-ready' in serial_tail:
                qmp.execute('set_link', {'name': 'vmnet', 'up': True}); plugged = True
        record_breadcrumb(public, 'result_received', work, disk, deadline)
        operation = 'result_validation'
        # Preserve only closed diagnostics even if provenance validation fails.
        # These remain explicitly unverified, never acceptance evidence.
        merge_serviced_result(public, server.result, args.actor_sha256, service_started)
        public['status'] = 'passed' if public['stage0_passed'] else 'observed_failure'
        phase = 'stage0_completed'
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
        finalize_owned(public, media, work, qemu, tpm, qmp, server, thread, watch)
        if public['vm_destroyed']: record_breadcrumb(public, 'cleanup_done', work, disk, deadline)
        public['last_phase'] = phase
        (args.output / 'public-report.json').write_text(json.dumps(public, indent=2) + '\n', encoding='ascii')
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
    parser.add_argument('--timeout-seconds', type=int, default=HOST_MAX_SECONDS)
    parser.add_argument('--job-deadline-epoch', type=int)
    args = parser.parse_args(argv)
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
    if not all((args.python_archive, args.actor, args.bundle, args.actor_sha256)) or args.timeout_seconds != HOST_MAX_SECONDS or args.job_deadline_epoch is None:
        parser.error('fixed host inputs, maximum9600-second budget and absolute job deadline required')
    return host(args)

if __name__ == '__main__': raise SystemExit(main())
