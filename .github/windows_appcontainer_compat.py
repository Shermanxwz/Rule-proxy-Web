"""One bounded stock-browser compatibility experiment on a disposable runner.

Normal controls and contained rows preserve each browser's own sandbox; two
no-sandbox rows are diagnostic only. A synthetic .invalid HTTP fixture proves
proxy receipt and DOM/PNG output, not real TLS/OAuth or product qualification.
Fixture/control/cleanup failures fail CI; unsupported contained apps are honest
negative results. No debugger binaries, raw logs or dumps are exported.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager
import hashlib
import secrets
import struct
import threading
import zlib

lab = None  # Loaded only by main on a disposable Windows Actions runner.

PROGRAMS = {
    'edge': Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'),
    'chrome': Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),
    'firefox': Path(r'C:\Program Files\Mozilla Firefox\firefox.exe'),
}
BASE = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--enable-logging=stderr', '--v=0']
VARIANTS = {
    'control': [],
    'contained': [],
    'diagnostic_no_sandbox': ['--no-sandbox'],
}
DUMPS = Path(r'C:\RuleProxyAppContainerCompat\dumps')
LOCALDUMPS = r'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
SYMBOLS = (r'srv*C:\sym*https://msdl.microsoft.com/download/symbols;'
           r'srv*C:\sym*https://chromium-browser-symsrv.commondatastorage.googleapis.com')


def digest(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def safe_environment(work):
    # Dumps/logs must never capture GitHub, OIDC or connector credentials.
    allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'COMSPEC', 'PATHEXT', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
               'PROGRAMW6432', 'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432',
               'OS', 'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_LEVEL', 'PROCESSOR_REVISION'}
    env = {key: value for key, value in os.environ.items() if key.upper() in allowed}
    env.update(TEMP=str(work / 'tmp'), TMP=str(work / 'tmp'), HOME=str(work / 'home'),
               USERPROFILE=str(work / 'home'), LOCALAPPDATA=str(work / 'local'), APPDATA=str(work / 'roaming'))
    return env


def read_tail(path, limit=65536):
    with Path(path).open('rb') as stream:
        stream.seek(0, 2)
        stream.seek(max(0, stream.tell() - limit))
        return stream.read(limit).decode('utf-8', errors='replace')


class Fixture:
    """Only a unique local proxy response, with no remote forwarding or DNS."""
    def __init__(self):
        self.nonce = secrets.token_hex(16)
        self.host = 'rp-' + self.nonce + '.invalid'
        self.received, self.lock = [], threading.Lock()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass
            def do_GET(self):
                prefix = 'http://' + owner.host + '/' + owner.nonce + '/'
                label = self.path[len(prefix):] if self.path.startswith(prefix) else ''
                expected = {family + '_' + variant for family in PROGRAMS for variant in VARIANTS
                            if family != 'firefox' or variant != 'diagnostic_no_sandbox'}
                if label not in expected:
                    self.send_error(403)
                    return
                with owner.lock:
                    owner.received.append(label)
                body = ('<!doctype html><html><title>RuleProxy fixture</title><body>'
                        + owner.marker(label) + '</body></html>').encode('ascii')
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(body)
            def do_CONNECT(self):
                self.send_error(403)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def marker(self, label):
        return 'RuleProxyFixture:' + self.nonce + ':' + label

    def url(self, label):
        return 'http://' + self.host + '/' + self.nonce + '/' + label

    def count(self, label):
        with self.lock:
            return self.received.count(label)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


def png_valid(path):
    if not path.is_file() or not 33 <= path.stat().st_size <= 8 * 1024 * 1024:
        return False
    data = path.read_bytes()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return False
    offset, image_data = 8, False
    while offset + 12 <= len(data):
        size = struct.unpack('!I', data[offset:offset + 4])[0]
        kind, end = data[offset + 4:offset + 8], offset + 12 + size
        if end > len(data) or zlib.crc32(data[offset + 4:end - 4]) != struct.unpack('!I', data[end - 4:end])[0]:
            return False
        if offset == 8 and (kind != b'IHDR' or size != 13
                           or not all(0 < n <= 16384 for n in struct.unpack('!II', data[offset + 8:offset + 16]))):
            return False
        image_data = image_data or kind == b'IDAT' and size > 0
        if kind == b'IEND':
            return image_data and size == 0 and end == len(data)
        offset = end
    return False


def row_success(outcome, received, rendered):
    return (outcome.get('started') is True and type(outcome.get('exit_code')) is int
            and outcome['exit_code'] == 0 and outcome.get('timed_out') is False
            and type(received) is int and received > 0 and rendered is True)


def summarize(report):
    compatibility = {}
    expected = {family + '_' + variant for family in PROGRAMS for variant in VARIANTS
                if family != 'firefox' or variant != 'diagnostic_no_sandbox'}
    for family in PROGRAMS:
        control = report['runs'].get(family + '_control', {})
        contained = report['runs'].get(family + '_contained', {})
        valid_control = (control.get('ok') is True and control.get('browser_sandbox_enabled') is True
                         and control.get('contained') is False and control.get('diagnostic_only') is False)
        compatibility[family] = {'control_valid': valid_control,
            'contained_sandbox_preserved_passed': valid_control and contained.get('ok') is True
            and contained.get('contained') is True and contained.get('browser_sandbox_enabled') is True
            and contained.get('diagnostic_only') is False}
    valid = (not report.get('error') and report.get('cleanup_ok') is True and set(report['runs']) == expected
             and all(value['control_valid'] for value in compatibility.values()))
    return {'compatibility': compatibility, 'valid_experiment': valid}


def cdb() -> Path | None:
    for root in (os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), os.environ.get('ProgramFiles', '')):
        candidate = Path(root) / 'Windows Kits' / '10' / 'Debuggers' / 'x64' / 'cdb.exe'
        if candidate.exists():
            return candidate
    return None


@contextmanager
def dump_policy(images):
    import winreg
    DUMPS.mkdir(parents=True, exist_ok=True)
    previous = {}
    created = set()
    try:
        for image in images:
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, LOCALDUMPS + '\\' + image):
                    pass
            except FileNotFoundError:
                created.add(image)
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, LOCALDUMPS + '\\' + image, 0,
                                    winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                old = previous.setdefault(image, {})
                for field, value, kind in (('DumpFolder', str(DUMPS), winreg.REG_EXPAND_SZ),
                                           ('DumpType', 1, winreg.REG_DWORD), ('DumpCount', 3, winreg.REG_DWORD)):
                    try:
                        old[field] = winreg.QueryValueEx(key, field)
                    except FileNotFoundError:
                        old[field] = None
                    winreg.SetValueEx(key, field, 0, kind, value)
        yield
    finally:
        for image, fields in previous.items():
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, LOCALDUMPS + '\\' + image, 0,
                                winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
                for field, old in fields.items():
                    if old is None:
                        try:
                            winreg.DeleteValue(key, field)
                        except FileNotFoundError:
                            pass
                    else:
                        winreg.SetValueEx(key, field, 0, old[1], old[0])
                subkeys, values, _stamp = winreg.QueryInfoKey(key)
            if image in created and subkeys == 0 and values == 0:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, LOCALDUMPS + '\\' + image)


def crash_events(since, program, pid):
    seconds = min(120, max(1, int(time.time() - since) + 3))
    script = r'''[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$out=@()
Get-WinEvent -FilterHashtable @{LogName='Application';Id=1000;StartTime=(Get-Date).AddSeconds(-__SECONDS__)} -MaxEvents 32 -ErrorAction SilentlyContinue | ForEach-Object {
 $data=@{};([xml]$_.ToXml()).Event.EventData.Data | ForEach-Object {$data[[string]$_.Name]=[string]$_.'#text'}
 if($data.AppPath -ieq $env:RP_COMPAT_IMAGE -and [Convert]::ToInt64($data.ProcessId,16) -eq [int]$env:RP_COMPAT_PID){
  $out += [ordered]@{image=$data.AppName;version=$data.AppVersion;module=$data.ModuleName;module_version=$data.ModuleVersion;exception=$data.ExceptionCode;offset=$data.FaultingOffset;pid=$data.ProcessId}}
};ConvertTo-Json -InputObject @($out | Select-Object -First 4) -Compress'''.replace('__SECONDS__', str(seconds))
    try:
        out = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-Command', script], capture_output=True,
                             timeout=15, env={**safe_environment(DUMPS.parent), 'RP_COMPAT_IMAGE': str(program),
                                              'RP_COMPAT_PID': str(pid or 0)})
        value = json.loads(out.stdout.decode('utf-8-sig')) if len(out.stdout) <= 8192 else []
        return value if isinstance(value, list) else []
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return []


def analyze(dump: Path, debugger: Path) -> str:
    env = {**safe_environment(DUMPS.parent), '_NT_SYMBOL_PATH': SYMBOLS}
    log = DUMPS.parent / 'cdb-analysis.log'
    with log.open('wb') as stream:
        try:
            subprocess.run([str(debugger), '-z', str(dump), '-c', '.ecxr;kc 20;q'], stdout=stream,
                           stderr=subprocess.STDOUT, timeout=45, env=env)
        except subprocess.TimeoutExpired:
            return 'cdb timeout'
    lines = read_tail(log, 32768).splitlines()
    start = next((i for i, line in enumerate(lines) if 'Call Site' in line), max(0, len(lines) - 40))
    return '\n'.join(lines[max(0, start - 8):start + 26])


def firefox_args(profile: Path, port: int, out: Path, url):
    (profile / 'user.js').write_text(
        ''.join(f'user_pref("{k}", {json.dumps(v)});\n' for k, v in {
            'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': port,
            'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': port, 'network.proxy.socks_remote_dns': True,
            'network.proxy.no_proxies_on': '',
            'network.trr.mode': 5, 'browser.shell.checkDefaultBrowser': False,
            'toolkit.startup.max_resumed_crashes': -1, 'datareporting.policy.dataSubmissionEnabled': False}.items()),
        encoding='utf-8')
    return ['--headless', '--no-remote', '--profile', str(profile), '--screenshot', str(out), url]


def launch_owned(sid, argv, contained, env, log):
    """Suspend, assign a kill-on-close Job, then resume the entire browser tree."""
    import ctypes as C
    import msvcrt
    from ruleproxy.windows_app_process import _get_api
    api = _get_api()
    job, process = api.create_job(), lab.PROCESS_INFORMATION()
    assigned = False
    try:
        api.configure_job(job, 0x2000)
        with log.open('wb') as stream:
            handle = msvcrt.get_osfhandle(stream.fileno())
            os.set_handle_inheritable(handle, True)
            info = lab.STARTUPINFOEXW()
            info.StartupInfo.cb = C.sizeof(info)
            info.StartupInfo.dwFlags = lab.STARTF_USESTDHANDLES
            info.StartupInfo.hStdOutput = info.StartupInfo.hStdError = handle
            size = C.c_size_t()
            lab.kernel.InitializeProcThreadAttributeList(None, 1, 0, C.byref(size))
            attributes = C.create_string_buffer(size.value)
            if not lab.kernel.InitializeProcThreadAttributeList(attributes, 1, 0, C.byref(size)):
                raise C.WinError(C.get_last_error())
            caps = lab.SECURITY_CAPABILITIES(sid.value, None, 0, 0)
            try:
                if contained and not lab.kernel.UpdateProcThreadAttribute(attributes, 0,
                        lab.PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, C.byref(caps), C.sizeof(caps), None, None):
                    raise C.WinError(C.get_last_error())
                info.lpAttributeList = C.cast(attributes, C.c_void_p) if contained else None
                flags = lab.EXTENDED_STARTUPINFO_PRESENT | lab.CREATE_NO_WINDOW | lab.CREATE_UNICODE_ENVIRONMENT | 4
                started = time.monotonic()
                if not lab.kernel.CreateProcessW(None, C.create_unicode_buffer(subprocess.list2cmdline(argv)), None, None,
                        True, flags, lab.environment_block(env), str(Path(argv[0]).parent), C.byref(info), C.byref(process)):
                    return {'started': False, 'error_code': C.get_last_error()}
                api.assign_job(job, process.hProcess)
                assigned = True
                api.resume_thread(process.hThread)
                timeout = lab.kernel.WaitForSingleObject(process.hProcess, 45000) != 0
                if timeout:
                    api.terminate_job(job)
                    lab.kernel.WaitForSingleObject(process.hProcess, 5000)
                code = lab.W.DWORD()
                if not lab.kernel.GetExitCodeProcess(process.hProcess, C.byref(code)):
                    raise C.WinError(C.get_last_error())
                return {'started': True, 'pid': process.dwProcessId, 'exit_code': code.value,
                        'timed_out': timeout, 'seconds': round(time.monotonic() - started, 3), 'owned_job': True}
            finally:
                lab.kernel.DeleteProcThreadAttributeList(attributes)
                os.set_handle_inheritable(handle, False)
    finally:
        if process.hProcess and not assigned:
            api.terminate_process(process.hProcess)
        api.close_handle(job)
        for handle in (process.hThread, process.hProcess):
            if handle:
                api.close_handle(handle)


def main() -> int:
    sys.stdout.reconfigure(encoding='utf-8', errors='backslashreplace')
    global lab
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true' or work != DUMPS.parent:
        raise RuntimeError('requires disposable Windows Actions runner and fixed work directory')
    if work.exists():
        raise RuntimeError('compat work directory already exists')
    for name in ('tmp', 'home', 'local', 'roaming'):
        (work / name).mkdir(parents=True)
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import windows_appcontainer_lab as lab
    report = {'schema_version': 2, 'windows': sys.getwindowsversion()[:4], 'runs': {}, 'notes': [],
              'source_commit': os.environ.get('GITHUB_SHA'), 'harness_sha256': digest(Path(__file__)),
              'product_qualified': False, 'interactive_qualified': False, 'real_tls_or_oauth_tested': False}
    debugger = cdb()
    report['debugger'] = {'available': debugger is not None, 'downloaded': False,
                          'sha256': digest(debugger) if debugger else None}
    sid = lab.container_sid()
    package = lab.sid_text(sid)
    proxy = Fixture()
    env = safe_environment(work)
    notices, stacks, analyzed = [], [], set()
    started_experiment = time.monotonic()

    def run(label, program, argv, contained, diagnostic=False, shot=None):
        if time.monotonic() - started_experiment > 540:
            raise TimeoutError('bounded compatibility experiment exhausted')
        log = work / f'{label}.log'
        started = time.time()
        before = set(DUMPS.glob('*.dmp'))
        outcome = launch_owned(sid, [str(program), *argv], contained, env, log)
        time.sleep(2)
        body = read_tail(log)
        received = proxy.count(label)
        rendered = png_valid(shot) if shot is not None else proxy.marker(label) in body
        entry = {'contained': contained, 'diagnostic_only': diagnostic, 'browser_sandbox_enabled': not diagnostic,
                 'ok': row_success(outcome, received, rendered), **outcome, 'fixture_requests': received,
                 'rendered': rendered, 'tail': body[-2500:], 'events': crash_events(started, program, outcome.get('pid'))}
        entry['render_evidence'] = 'valid_png_and_proxy_receipt' if shot is not None else 'dom_nonce_and_proxy_receipt'
        dumps = sorted(set(DUMPS.glob('*.dmp')) - before)
        entry['dumps'] = [{'name': d.name, 'bytes': d.stat().st_size, 'exported': False,
                           'sha256': digest(d) if d.stat().st_size <= 16 * 1024 * 1024 else None} for d in dumps[:3]]
        family = label.split('_')[0]
        if dumps and 0 < dumps[0].stat().st_size <= 16 * 1024 * 1024 and debugger and family not in analyzed:
            analyzed.add(family)
            entry['stack'] = analyze(dumps[0], debugger)
            stacks.append(f"{label}: " + ' / '.join(line.strip() for line in entry['stack'].splitlines()[:30]))
        report['runs'][label] = entry
        code = entry.get('exit_code')
        head = (f"{label}: ok={entry['ok']} exit=0x{code:08x}" if isinstance(code, int) else f"{label}: {outcome}")
        notices.append(head + (' | ' + json.dumps(entry['events'][0], ensure_ascii=True)[:300] if entry['events'] else ''))
        print(f"::group::{label}\n{json.dumps(entry, ensure_ascii=False, indent=1)[:12000]}\n::endgroup::", flush=True)

    try:
        # Chromium's normal network sandbox adjusts profile DACLs. Grant F only
        # on our disposable fixture tree, never the real browser/home tree.
        subprocess.run(['icacls', str(work), '/grant', f'*{package}:(OI)(CI)(F)', '/T', '/Q'],
                       check=True, capture_output=True, timeout=30)
        with dump_policy(['msedge.exe', 'chrome.exe', 'firefox.exe']):
            lab.exemption(sid, True)
            with lab.PackageFilters(sid, proxy.port):
                for name, program in PROGRAMS.items():
                    if not program.exists():
                        report['notes'].append(f'{name} missing')
                        continue
                    report.setdefault('browser_sha256', {})[name] = digest(program)
                    for variant, flags in VARIANTS.items():
                        if name == 'firefox' and flags:
                            continue
                        label = name + '_' + variant
                        profile = work / label
                        profile.mkdir()
                        if name == 'firefox':
                            shot = work / (label + '.png')
                            run(label, program, firefox_args(profile, proxy.port, shot, proxy.url(label)),
                                variant != 'control', shot=shot)
                        else:
                            argv = [*BASE, f'--user-data-dir={profile}', f'--proxy-server=http://127.0.0.1:{proxy.port}',
                                    '--proxy-bypass-list=<-loopback>', *flags, '--dump-dom', proxy.url(label)]
                            run(label, program, argv, variant != 'control', diagnostic=bool(flags))
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:400]
        notices.append('error: ' + report['error'])
    finally:
        proxy.close()
        try:
            lab.exemption(sid, False)
            code = lab.userenv.DeleteAppContainerProfile(lab.PROFILE)
            report['cleanup_ok'] = code == 0
        except OSError:
            report['cleanup_ok'] = False
    report.update(summarize(report))
    report['seconds'] = round(time.monotonic() - started_experiment, 3)
    (work / 'compat-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    for start in range(0, len(notices), 4):
        print('::notice title=AppContainer compat::' + ' ;; '.join(notices[start:start + 4]).replace('\n', ' '),
              flush=True)
    for stack in stacks[:8]:
        print('::warning title=AppContainer compat stack::' + stack[:4000], flush=True)
    return 0 if report['valid_experiment'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
