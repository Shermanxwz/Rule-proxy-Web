"""Exercise the real current-user WinINet proxy on a disposable CI runner.

The browser receives no explicit proxy argument or proxy environment. An
independent loopback HTTP fixture must receive its unique .invalid request.
This proves a headless Server case, not an interactive Windows 11 desktop.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def crash_recovery(work, port, before, environment):
    """Kill an owned panel actor; its independent monitor must restore WinINet."""
    from ruleproxy import system_proxy
    from ruleproxy.system_proxy_watchdog import STATUS
    actor = r'''
import json,sys,time
from pathlib import Path
sys.path.insert(0,sys.argv[1])
from ruleproxy import system_proxy
from ruleproxy.system_proxy_watchdog import start
directory,port,core=Path(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4])
watch=start(directory,core)
system_proxy.enable(directory,port,watchdog_session=watch.nonce)
watch.arm()
(directory/'panel-ready.json').write_text(json.dumps({'session':watch.nonce}),encoding='ascii')
time.sleep(90)
'''
    core = subprocess.Popen([sys.executable, '-I', '-S', '-c', 'import time; time.sleep(90)'],
                            env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
    panel = None
    try:
        with (work / 'panel-fixture.stderr').open('wb') as stderr:
            panel = subprocess.Popen([sys.executable, '-I', '-S', '-c', actor, str(ROOT),
                                      str(work), str(port), str(core.pid)], env=environment,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=stderr,
                                     creationflags=subprocess.CREATE_NO_WINDOW)
            deadline = time.monotonic() + 15
            while not (work / 'panel-ready.json').exists():
                if panel.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('Owned native panel fixture did not arm recovery')
                time.sleep(.05)
            session = json.loads((work / 'panel-ready.json').read_text(encoding='ascii'))['session']
            if not system_proxy._win_is_ours(port):
                raise RuntimeError('Panel fixture did not enable the expected native proxy')
            panel.kill()
            panel.wait(timeout=5)
            deadline = time.monotonic() + 15
            while True:
                status = work / STATUS
                if status.is_file():
                    value = json.loads(status.read_text(encoding='utf-8'))
                    if (value.get('session') == session and value.get('restored') is True
                            and system_proxy._win_read() == before
                            and not (work / system_proxy.BACKUP).exists()):
                        return True
                if time.monotonic() >= deadline:
                    raise RuntimeError('Independent native monitor did not restore after panel termination')
                time.sleep(.05)
    finally:
        for process in (panel, core):
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--work', type=Path, required=True)
    work = parser.parse_args().work.resolve()
    if os.name != 'nt' or os.environ.get('GITHUB_ACTIONS') != 'true':
        raise RuntimeError('This native settings check is restricted to disposable Windows CI')
    if work.exists():
        raise RuntimeError('Refusing to reuse a native proxy test directory')
    work.mkdir(parents=True)
    from ruleproxy import system_proxy

    candidates = [Path(os.environ.get(key, r'C:\Program Files')) /
                  'Microsoft/Edge/Application/msedge.exe'
                  for key in ('ProgramFiles(x86)', 'ProgramFiles')]
    browser = next((path for path in candidates if path.is_file()), None)
    if browser is None:
        raise RuntimeError('Native Edge positive control is required')
    before = system_proxy._win_read()
    nonce = secrets.token_hex(16)
    target = f'http://{nonce}.invalid/{nonce}'
    marker = 'ruleproxy-system-proxy-' + nonce
    received = []

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            if self.path != target:
                self.send_error(403)
                return
            received.append(self.path)
            body = ('<!doctype html><main>' + marker + '</main>').encode('ascii')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def do_CONNECT(self):
            self.send_error(403)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    report = {'scope': 'Windows Server headless Edge through actual current-user WinINet',
              'tun_used': False, 'explicit_browser_proxy_used': False,
              'proxy_environment_used': False, 'browser_sandbox_disabled': False,
              'interactive_desktop_qualified': False, 'passed': False}
    failure = None
    try:
        system_proxy.enable(work, server.server_port)
        command = [str(browser), '--headless=new', '--disable-gpu', '--no-first-run',
                   '--no-default-browser-check', '--disable-background-networking',
                   '--disable-sync', '--disable-component-update',
                   '--user-data-dir=' + str(work / 'browser-profile'), '--dump-dom', target]
        allowed = {'SYSTEMROOT', 'WINDIR', 'PATH', 'TEMP', 'TMP', 'USERPROFILE', 'HOMEDRIVE',
                   'HOMEPATH', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMFILES', 'PROGRAMFILES(X86)',
                   'PROGRAMW6432', 'SYSTEMDRIVE', 'COMSPEC'}
        environment = {key: value for key, value in os.environ.items() if key.upper() in allowed}
        with (work / 'edge.stdout').open('wb') as stdout, (work / 'edge.stderr').open('wb') as stderr:
            process = subprocess.Popen(command, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr,
                                       creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                code = process.wait(timeout=30)
            except BaseException:
                # Kill this browser's process tree only; never all Edge instances.
                subprocess.run(['taskkill.exe', '/PID', str(process.pid), '/T', '/F'],
                               capture_output=True, timeout=10, check=False)
                process.wait(timeout=10)
                raise
        dom_path = work / 'edge.stdout'
        if dom_path.stat().st_size > 1024 * 1024:
            raise RuntimeError('Unexpectedly large native browser output')
        dom = dom_path.read_bytes().decode('utf-8', errors='replace')
        report.update(browser_exit_code=code, independent_fixture_hits=len(received),
                      unique_dom_marker_verified=marker in dom,
                      exact_fixture_target_verified=bool(received) and set(received) == {target})
        if code != 0 or marker not in dom or not received or set(received) != {target}:
            raise RuntimeError('Headless Edge did not prove the actual system proxy path')
        system_proxy.restore(work)
        if system_proxy._win_read() != before:
            raise RuntimeError('Initial native system proxy restoration failed')
        report['panel_termination_independent_recovery_verified'] = crash_recovery(
            work, server.server_port, before, environment)
    except BaseException as exc:
        failure = exc
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:300]
    finally:
        try:
            system_proxy.restore(work)
            report['original_settings_restored'] = system_proxy._win_read() == before
            report['recovery_journal_removed'] = not (work / system_proxy.BACKUP).exists()
            if not report['original_settings_restored'] or not report['recovery_journal_removed']:
                raise RuntimeError('Native system proxy restoration could not be verified')
        except BaseException as exc:
            failure = failure or exc
            report['restore_error_type'] = type(exc).__name__
        server.shutdown()
        server.server_close()
        worker.join(3)
        report['passed'] = failure is None
        # Do not publish registry values, proxy credentials or the backup journal.
        (work / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print('::notice title=Native system proxy::' + json.dumps(report), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
