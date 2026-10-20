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
    '.github/windows_identity_stock_stage0.py', '.github/windows_identity_proof.py',
    '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_runtime_pins.py',
)
CHECKS = ('request_aware_base_container', 'actual_base_container', 'fresh_actor',
          'native_identity', 'normal_exit', 'no_harness_error')
BOOLS = ('ordinary_account', 'stock_build_verified', 'stage0_passed', 'harness_completed')
EXECUTION_ENABLED = True  # Frozen code review only; separate execution decision required.
GIB = 1024**3
PREMEDIA_FREE = 32 * GIB
LAUNCH_FREE = 24 * GIB
DISK_FILE_CAP = 18 * GIB
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


def project_stage0(raw):
    """No recursive pass-through: a malicious path/nonce/error cannot escape."""
    checks = raw.get('checks', {})
    result = {'schema_version': 1, 'stage': 'win11-stock26200.6584-ordinary-deny-only-stage0',
              'network_tested': False, 'product_acceptance': False, 'privacy_qualified': False,
              'psec_cleanup_independently_verified': False,
              'checks': {key: checks.get(key) is True for key in CHECKS},
              'request_supported': checks.get('request_aware_base_container') is True,
              'stage0_passed': raw.get('stage0_passed') is True and all(checks.get(k) is True for k in CHECKS)}
    for key in ('actor_sha256',):
        value = raw.get(key)
        if isinstance(value, str) and DIGEST.fullmatch(value):
            result[key] = value
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
                               and all(result[k] for k in ('ordinary_account', 'stock_build_verified', 'harness_completed')))
    result['os'] = {'build': 26200, 'ubr': 6584, 'product_type': 'WinNT', 'architecture': 'AMD64'}
    if value.get('os') != result['os'] or value.get('actor_sha256') != actor_digest:
        raise ValueError('guest provenance differs')
    return result


def guest(args):
    output = args.output
    result = project_stage0({})
    try:
        verify_guest_import_path()
        proof = load('identity_stage0_guest', ROOT / '.github/windows_identity_proof.py')
        config = json.loads((ROOT / 'stage0-input.json').read_text())
        work = ROOT / 'private-stage0'
        options = SimpleNamespace(disposable_ci=True, approved_security_test=True,
            executor=ROOT / 'g/wxc-exec.exe', manifest=ROOT / 'g/build-manifest.json',
            actor=ROOT / 'actor.exe', actor_sha256=config['actor_sha256'], work=work, report=work / 'report.json')
        code = proof.controller(options)
        raw = proof.smoke.read(options.report)
        result = project_stage0(raw)
        result['harness_completed'] = True
        # A successful controller validates its observed current ordinary token;
        # the PowerShell entrypoint separately verifies the real RuleProxyCI user.
        identity = raw.get('controller_identity', {})
        result['ordinary_account'] = (identity.get('elevated') is False and identity.get('appcontainer') is False
                                      and identity.get('cid') == 1)
    except Exception:
        code = 1
        result['harness_completed'] = False
    output.write_text(json.dumps(result, sort_keys=True), encoding='ascii')
    return code


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
            if self.path != '/' + self.server.capability + '/result': raise ValueError()
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= MAX_REPORT: raise ValueError()
            raw = self.rfile.read(length)
            if len(raw) != length: raise ValueError()
            value = json.loads(raw)
            if not isinstance(value, dict): raise ValueError()
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


def require_vm_work_budget(deadline, *, now=None):
    # This is the existing work deadline, with the 120s cleanup reserve already
    # excluded. Never extend it because preparation took longer than expected.
    remaining = deadline - (time.monotonic() if now is None else now)
    if remaining < MIN_VM_WORK_SECONDS:
        raise VMWorkBudgetInsufficient('time_budget_insufficient')
    return remaining


def run_bounded(command, deadline, maximum, **kwargs):
    return subprocess.run(command, timeout=remaining_budget(deadline, maximum), **kwargs)


def cleanup_owned(media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None, *, retain_work=False):
    cleanup_ok = True
    for action in ((lambda: qmp.close()) if qmp else None,
                   lambda: media.stop_owned(qemu), lambda: media.stop_owned(tpm),
                   (lambda: server.shutdown()) if server else None,
                   (lambda: server.server_close()) if server else None):
        if action:
            try: action()
            except Exception: cleanup_ok = False
    if thread: thread.join(timeout=5)
    live = any(p is not None and p.poll() is None for p in (qemu, tpm))
    live = live or (thread is not None and thread.is_alive())
    if not live and not retain_work:
        try: shutil.rmtree(work)
        except OSError: cleanup_ok = False
    return cleanup_ok and not live and not work.exists()


def finalize_owned(public, media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None, watch=None):
    teardown_uncertain = False
    for process in (qemu, tpm):
        if process is None: continue
        try:
            code = process.poll()
            if process is qemu and code == -signal.SIGXFSZ:
                public['capacity_abort'] = 'file_size_limit_signal'
            if code is None:
                try: process.kill()
                except OSError: pass  # Exit between poll and kill is normal; still wait/check.
                process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired): teardown_uncertain = True
    retain_work = False
    if watch:
        try: watch.close()
        except Exception: retain_work = True
        retain_work = retain_work or watch.thread.is_alive()
        if retain_work: watch.reason = 'capacity_watch_stop_unconfirmed'
        public['minimum_free_bytes'] = watch.minimum_free
    try:
        cleaned = cleanup_owned(media, work, qemu, tpm, qmp, server, thread, retain_work=retain_work)
    except Exception:
        cleaned = False
    public['vm_destroyed'] = cleaned and not teardown_uncertain and not retain_work
    reconcile_capacity(public, watch.reason if watch else None)
    if not public['vm_destroyed']:
        public['status'] = 'cleanup_unconfirmed'
        public['stage0_passed'] = False
    return public


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
    public = {'schema_version': 1, 'stage': 'win11-stock26200.6584-ordinary-deny-only-stage0',
              'status': 'blocked', 'stage0_passed': False, 'product_acceptance': False,
              'privacy_qualified': False, 'network_tested': False, 'vm_destroyed': False}
    available = min(args.timeout_seconds, args.job_deadline_epoch - time.time())
    if available < 300: raise TimeoutError('native job cleanup reserve unavailable')
    qemu = tpm = server = thread = qmp = watch = None
    work = Path(tempfile.mkdtemp(prefix='identity-win11-private-')); work.chmod(0o700)
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    deadline = time.monotonic() + available - 120
    # Also bound non-subprocess work (hashes/ZIPs/filesystem) and helper calls.
    signal.setitimer(signal.ITIMER_REAL, available - 120)
    source = os.environ.get('GITHUB_SHA', '')
    if re.fullmatch(r'[0-9a-f]{40}', source): public['source_commit'] = source
    public['iso_sha256'] = media.ISO_SHA256
    public['actor_sha256'] = args.actor_sha256
    phase = 'preflight'
    try:
        media.require_kvm()
        if shutil.disk_usage(work).free < PREMEDIA_FREE:
            raise RuntimeError('insufficient disposable storage; no host cleanup performed')
        for binary in ('qemu-system-x86_64', 'qemu-img', 'swtpm', 'xorriso', 'curl'):
            if not shutil.which(binary): raise RuntimeError('missing VM tool')
        if not shutil.which('prlimit'): raise RuntimeError('missing process resource limiter')
        public['premedia_free_bytes'] = shutil.disk_usage(work).free
        phase = 'verified_media_download'
        iso = work / 'official.iso'
        run_bounded(limited_command(['curl', '--fail', '--location', '--retry', '3', '--proto', '=https',
            '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '1200',
            '--output', str(iso), media.ISO_URL], media.ISO_BYTES), deadline, 1220, check=True)
        if iso.stat().st_size != media.ISO_BYTES or media.digest(iso) != media.ISO_SHA256:
            raise ValueError('ISO provenance failed')
        raw = work / 'private-reports'; raw.mkdir()
        package = work / 'payload.zip'
        package_digest = payload(args.python_archive, args.actor, args.actor_sha256, args.bundle, package)
        if package.stat().st_size > MAX_PAYLOAD: raise ValueError('payload size cap')
        server = ClosedServer(package)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        tree = work / 'seed-tree'; tree.mkdir()
        config = {'host_url': f'http://10.0.2.2:{server.server_address[1]}/{server.capability}',
                  'payload_sha256': package_digest, 'python_sha256': PYTHON_ASSET['sha256'],
                  'actor_sha256': args.actor_sha256}
        media.prepare_seed(tree, secrets.token_hex(16) + 'Ci!9', config)
        for role in ('setup', 'run'):
            shutil.copyfile(ROOT / f'.github/windows-identity-stock-stage0-{role}.ps1', tree / f'ruleproxy-vm-{role}.ps1')
        seed = work / 'seed.iso'
        run_bounded(limited_command(['xorriso', '-as', 'mkisofs', '-J', '-R', '-V', 'RULEPROXY_SEED',
                     '-o', str(seed), str(tree)], MAX_SEED), deadline, 60, check=True,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if seed.stat().st_size > MAX_SEED: raise ValueError('seed cap')
        shutil.rmtree(tree)
        disk = work / 'windows.qcow2'; nvram = work / 'OVMF_VARS.fd'
        firmware = Path('/usr/share/OVMF'); code = firmware / 'OVMF_CODE_4M.ms.fd'
        shutil.copyfile(firmware / 'OVMF_VARS_4M.ms.fd', nvram)
        run_bounded(limited_command(['qemu-img', 'create', '-f', 'qcow2', '-o', 'preallocation=off', str(disk), '80G'], DISK_FILE_CAP), deadline, 30, check=True, stdout=subprocess.DEVNULL)
        state = work / 'tpm-state'; state.mkdir()
        tpm_socket, qmp_socket, serial = work / 'tpm.sock', work / 'qmp.sock', work / 'serial.log'
        phase = 'stock_guest_installation'
        public['launch_free_bytes'] = shutil.disk_usage(work).free
        public['disk_file_ceiling_bytes'] = DISK_FILE_CAP
        public['reserve_guard_hard_guarantee'] = False
        if public['launch_free_bytes'] < LAUNCH_FREE: raise RuntimeError('launch capacity gate')
        watch = CapacityWatch(work); watch.thread.start()
        tpm = subprocess.Popen(limited_command(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state}', '--ctrl', f'type=unixio,path={tpm_socket}'], 8 * 1024**2), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        watch.register(tpm)
        ready = time.monotonic() + 20
        while not tpm_socket.exists():
            if tpm.poll() is not None or time.monotonic() > ready: raise RuntimeError('TPM failed')
            time.sleep(.1)
        public['vm_work_seconds_available'] = int(require_vm_work_budget(deadline))
        qemu = subprocess.Popen(limited_command(['qemu-system-x86_64', '-machine', 'q35,accel=kvm,smm=on', '-cpu',
            'host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on', '-m', '6144', '-smp', '4',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}', '-drive', f'if=pflash,format=raw,file={nvram}',
            '-drive', f'if=none,id=system,file={disk},format=qcow2,discard=unmap', '-device', 'ide-hd,drive=system,bus=ide.0,bootindex=1',
            '-drive', f'if=none,id=install,file={iso},media=cdrom,readonly=on', '-device', 'ide-cd,drive=install,bus=ide.1,bootindex=2',
            '-drive', f'if=none,id=seed,file={seed},media=cdrom,readonly=on', '-device', 'ide-cd,drive=seed,bus=ide.2',
            '-netdev', 'user,id=vmnet', '-device', f'e1000,netdev=vmnet,mac={media.VM_NIC_MAC}',
            '-chardev', f'socket,id=tpm,path={tpm_socket}', '-tpmdev', 'emulator,id=tpmdev,chardev=tpm', '-device', 'tpm-tis,tpmdev=tpmdev',
            '-device', 'qemu-xhci', '-device', 'usb-tablet', '-vga', 'std', '-display', 'none', '-monitor', 'none',
            '-chardev', 'ringbuf,id=serialbuf,size=65536', '-serial', 'chardev:serialbuf', '-qmp', f'unix:{qmp_socket},server=on,wait=off'], DISK_FILE_CAP),
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        watch.register(qemu)
        ready = time.monotonic() + 20
        while qmp is None:
            if qemu.poll() is not None or time.monotonic() > ready: raise RuntimeError('QEMU failed')
            try: qmp = media.Qmp(qmp_socket)
            except OSError: time.sleep(.1)
        if qmp.execute('query-kvm').get('enabled') is not True: raise RuntimeError('KVM required')
        qmp.execute('set_link', {'name': 'vmnet', 'up': False})
        if True:  # Original ISO may require its standard press-key prompt.
            for _ in range(8):
                qmp.execute('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}], 'hold-time': 100}); time.sleep(2)
        plugged = False
        serial_tail = ""
        while not server.received.wait(.2):
            if watch.reason: raise RuntimeError(watch.reason)
            if disk.stat().st_size >= DISK_FILE_CAP - 64 * 1024**2:
                public['capacity_abort'] = 'backing_file_ceiling_reached'; qemu.kill(); raise RuntimeError('file cap')
            if qemu.poll() is not None or time.monotonic() > deadline: raise RuntimeError('guest deadline or exit')
            beacon = qmp.execute('ringbuf-read', {'device': 'serialbuf', 'size': 65536})
            serial_tail = (serial_tail + beacon)[-256:]
            if not plugged and 'RPBEACON identity-ordinary-ready' in serial_tail:
                qmp.execute('set_link', {'name': 'vmnet', 'up': True}); plugged = True
        public.update(validate_guest(server.result, args.actor_sha256))
        public['status'] = 'passed' if public['stage0_passed'] else 'observed_failure'
        phase = 'stage0_completed'
    except VMWorkBudgetInsufficient:
        public['status'] = 'time_budget_insufficient'
    except (Exception, KeyboardInterrupt):
        public['status'] = 'blocked'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        # A second cancellation must not interrupt owned-process cleanup.
        for sig in old_handlers: signal.signal(sig, signal.SIG_IGN)
        finalize_owned(public, media, work, qemu, tpm, qmp, server, thread, watch)
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
    parser.add_argument('--timeout-seconds', type=int, default=6600)
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
    if not all((args.python_archive, args.actor, args.bundle, args.actor_sha256)) or args.timeout_seconds != 6600 or args.job_deadline_epoch is None:
        parser.error('fixed host inputs, maximum6600-second budget and absolute job deadline required')
    return host(args)

if __name__ == '__main__': raise SystemExit(main())
