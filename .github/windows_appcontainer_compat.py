"""Which real desktop apps start inside the zero-capability AppContainer? Only for CI.

Runs stock Edge, Chrome and Firefox headless inside the lab container (loopback
exemption + package filters, proxy only) under several flag sets, and records
exit codes, the browser's own log tail, the Application Error event (faulting
module and offset) and, when cdb is installed, the faulting stack from a WER
LocalDumps minidump. Informational: it never fails the job.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import winreg
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import windows_appcontainer_lab as lab  # noqa: E402

PROGRAMS = {
    'edge': lab.EDGE,
    'chrome': Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),
    'firefox': Path(r'C:\Program Files\Mozilla Firefox\firefox.exe'),
}
BASE = ['--headless=new', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
        '--enable-logging=stderr', '--v=0']
VARIANTS = {
    'plain': [],
    'no_sandbox': ['--no-sandbox'],
    'no_sandbox_no_crashpad': ['--no-sandbox', '--disable-crash-reporter', '--disable-breakpad'],
    'no_sandbox_single': ['--no-sandbox', '--disable-crash-reporter', '--single-process'],
    'no_sandbox_features': ['--no-sandbox', '--disable-crash-reporter',
                            '--disable-features=NetworkServiceSandbox,RendererCodeIntegrity,'
                            'WinSboxNoFakeGdiInit,AudioServiceOutOfProcess',
                            '--in-process-gpu', '--disable-gpu-sandbox'],
}
DUMPS = Path(r'C:\RuleProxyCompatDumps')
LOCALDUMPS = r'SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
SYMBOLS = (r'srv*C:\sym*https://msdl.microsoft.com/download/symbols;'
           r'srv*C:\sym*https://chromium-browser-symsrv.commondatastorage.googleapis.com')


def cdb() -> Path | None:
    for root in (os.environ.get('ProgramFiles(x86)', r'C:\Program Files (x86)'), os.environ.get('ProgramFiles', '')):
        candidate = Path(root) / 'Windows Kits' / '10' / 'Debuggers' / 'x64' / 'cdb.exe'
        if candidate.exists():
            return candidate
    return None


def enable_dumps(images):
    DUMPS.mkdir(parents=True, exist_ok=True)
    for image in images:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, LOCALDUMPS + '\\' + image, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, 'DumpFolder', 0, winreg.REG_EXPAND_SZ, str(DUMPS))
            winreg.SetValueEx(key, 'DumpType', 0, winreg.REG_DWORD, 1)
            winreg.SetValueEx(key, 'DumpCount', 0, winreg.REG_DWORD, 3)


def crash_events(since: float) -> list[str]:
    seconds = int(time.time() - since) + 5
    script = ("Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1000; StartTime=(Get-Date).AddSeconds(-%d)} "
              "-ErrorAction SilentlyContinue | ForEach-Object { ($_.Properties | ForEach-Object { $_.Value }) -join '|' }"
              % seconds)
    out = subprocess.run(['powershell', '-NoProfile', '-Command', script], capture_output=True, text=True, timeout=60)
    return [line.strip() for line in out.stdout.splitlines() if line.strip()][:6]


def analyze(dump: Path, debugger: Path) -> str:
    env = dict(os.environ, _NT_SYMBOL_PATH=SYMBOLS)
    try:
        out = subprocess.run([str(debugger), '-z', str(dump), '-c', '.ecxr;kc 25;q'], capture_output=True,
                             text=True, timeout=300, env=env)
    except subprocess.TimeoutExpired:
        return 'cdb timeout'
    lines = out.stdout.splitlines()
    start = next((i for i, line in enumerate(lines) if 'Call Site' in line), max(0, len(lines) - 40))
    return '\n'.join(lines[max(0, start - 8):start + 26])


def firefox_args(profile: Path, port: int, out: Path):
    (profile / 'user.js').write_text(
        ''.join(f'user_pref("{k}", {json.dumps(v)});\n' for k, v in {
            'network.proxy.type': 1, 'network.proxy.http': '127.0.0.1', 'network.proxy.http_port': port,
            'network.proxy.ssl': '127.0.0.1', 'network.proxy.ssl_port': port, 'network.proxy.socks_remote_dns': True,
            'network.trr.mode': 5, 'browser.shell.checkDefaultBrowser': False,
            'toolkit.startup.max_resumed_crashes': -1, 'datareporting.policy.dataSubmissionEnabled': False}.items()),
        encoding='utf-8')
    return ['--headless', '--no-remote', '--profile', str(profile), '--screenshot', str(out), lab.PUBLIC_URL]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if work.exists():
        shutil.rmtree(work)
    (work / 'tmp').mkdir(parents=True)
    report = {'schema_version': 1, 'windows': sys.getwindowsversion()[:4], 'runs': {}, 'notes': []}
    debugger = cdb()
    report['cdb'] = str(debugger) if debugger else None
    enable_dumps(['msedge.exe', 'chrome.exe', 'firefox.exe'])
    sid = lab.container_sid()
    package = lab.sid_text(sid)
    proxy = lab.ConnectProxy()
    subprocess.run(['icacls', str(work), '/grant', f'*{package}:(OI)(CI)(M)', '/T', '/Q', '/C'],
                   capture_output=True, timeout=600)
    env = {k: v for k, v in os.environ.items() if k.upper() not in ('TEMP', 'TMP', 'HTTP_PROXY', 'HTTPS_PROXY',
                                                                      'ALL_PROXY', 'NO_PROXY')}
    env.update(TEMP=str(work / 'tmp'), TMP=str(work / 'tmp'),
               LOCALAPPDATA=str(work / 'tmp'), APPDATA=str(work / 'tmp'))
    notices, stacks, analyzed = [], [], set()

    def run(label, program, argv, contained, ok):
        log = work / f'{label}.log'
        started = time.time()
        before = set(DUMPS.glob('*.dmp'))
        outcome = lab.launch(sid, [str(program), *argv], contained=contained, cwd=program.parent, env=env,
                             log=log, timeout=75)
        time.sleep(3)
        body = log.read_text(encoding='utf-8', errors='replace')
        entry = {'contained': contained, 'ok': ok(body), **outcome, 'tunnels': proxy.tunnels,
                 'tail': body[-2500:], 'events': crash_events(started)}
        dumps = sorted(set(DUMPS.glob('*.dmp')) - before)
        entry['dumps'] = [d.name for d in dumps]
        family = label.split('_')[0]
        if dumps and debugger and family not in analyzed:
            analyzed.add(family)
            entry['stack'] = analyze(dumps[0], debugger)
            stacks.append(f"{label}: " + ' / '.join(line.strip() for line in entry['stack'].splitlines()[:30]))
        report['runs'][label] = entry
        code = entry.get('exit_code')
        head = (f"{label}: ok={entry['ok']} exit=0x{code:08x}" if isinstance(code, int) else f"{label}: {outcome}")
        notices.append(head + (' | ' + entry['events'][0][:300] if entry['events'] else ''))
        print(f"::group::{label}\n{json.dumps(entry, ensure_ascii=False, indent=1)[:12000]}\n::endgroup::", flush=True)

    lab.exemption(sid, True)
    try:
        with lab.PackageFilters(sid, proxy.port):
            for name, program in PROGRAMS.items():
                if not program.exists():
                    report['notes'].append(f'{name} missing')
                    continue
                if name == 'firefox':
                    for contained in (False, True):
                        profile = work / f'ff-{contained}'
                        profile.mkdir()
                        shot = work / f'ff-{contained}.png'
                        run(f'firefox_{"contained" if contained else "control"}', program,
                            firefox_args(profile, proxy.port, shot), contained, lambda _b, s=shot: s.exists())
                    continue
                for variant, flags in ({'control': ['--no-sandbox']} | VARIANTS).items():
                    profile = work / f'{name}-{variant}'
                    profile.mkdir()
                    argv = [*BASE, f'--user-data-dir={profile}', f'--proxy-server=http://127.0.0.1:{proxy.port}',
                            *flags, '--dump-dom', lab.PUBLIC_URL]
                    run(f'{name}_{variant}', program, argv, variant != 'control', lambda b: 'Example Domain' in b)
    except Exception as exc:
        report['error'] = f'{type(exc).__name__}: {exc}'[:400]
        notices.append('error: ' + report['error'])
    finally:
        try:
            lab.exemption(sid, False)
        except OSError as exc:
            report['notes'].append(f'exemption cleanup: {exc}')
        lab.userenv.DeleteAppContainerProfile(lab.PROFILE)
    (work / 'compat-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    for start in range(0, len(notices), 4):
        print('::notice title=AppContainer compat::' + ' ;; '.join(notices[start:start + 4]).replace('\n', ' '),
              flush=True)
    for stack in stacks[:8]:
        print('::warning title=AppContainer compat stack::' + stack[:4000], flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
