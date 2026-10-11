"""Real Edge rendering and cookie persistence through the production launcher."""
from __future__ import annotations
import argparse
import http.server
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import traceback

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ruleproxy import windows_runtime as runtime
from ruleproxy.launcher import prepare_app
from windows_native_validation import free_port, host_info, start_core


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    report = {'host': host_info(), 'mocked': False}
    nonce = secrets.token_hex(12)
    requests = []
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            requests.append({'path': self.path, 'cookie': self.headers.get('Cookie', '')})
            body = ('<!doctype html><html><body><p id="verified">' + nonce + '</p></body></html>').encode()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Set-Cookie', 'ruleproxy=' + nonce + '; Max-Age=3600; Path=/; SameSite=Lax')
            self.end_headers(); self.wfile.write(body)
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    code = 1
    try:
        executable = ROOT / 'bin/windows-amd64/wxc-exec.exe'
        probe = runtime.probe(str(executable)); report['probe'] = probe
        if not probe['supported']:
            report['verdict'] = 'unsupported-host-refused'; code = 0
            return code
        candidates = [Path(os.environ.get(key, 'C:/Program Files')) / 'Microsoft/Edge/Application/msedge.exe'
                      for key in ('ProgramFiles(x86)', 'ProgramFiles')]
        edge = next((p for p in candidates if p.is_file()), None)
        if edge is None: raise RuntimeError('Edge is required for the browser acceptance test')
        report['edge'] = str(edge)
        report['version'] = subprocess.run(['powershell', '-NoProfile', '-Command', f"(Get-Item -LiteralPath '{str(edge)}').VersionInfo.ProductVersion"], capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory(prefix='浏览器验收 ', ignore_cleanup_errors=True) as temporary:
            folder = Path(temporary)
            proxy = free_port(); core, log = start_core(folder, proxy)
            try:
                launches = []
                for number in (1, 2):
                    url = f'http://127.0.0.1:{server.server_port}/round-{number}'
                    app = {'id':'edge-acceptance', 'label':'Edge acceptance', 'path':str(edge), 'adapter':'chromium',
                           'args':['--headless=new', '--disable-gpu', '--dump-dom', url]}
                    command, env, _ = prepare_app(app, proxy, folder / 'profiles')
                    profile = folder / 'profiles' / app['id']
                    process = resource = None
                    try:
                        process, resource = runtime.launch(command, env, profile, proxy, str(executable), proxy_process=core)
                        exit_code = process.wait(45)
                        text = (profile / 'runtime.log').read_text(encoding='utf-8', errors='replace')
                        launches.append({'round':number, 'exit':exit_code, 'rendered':nonce in text,
                                         'log_tail':text[-4000:]})
                        if exit_code or nonce not in text:
                            raise RuntimeError('Edge failed to render through the controlled proxy')
                    finally:
                        if process is not None: runtime.stop(process)
                        if resource is not None: resource.close()
                report['launches'] = launches
                report['requests'] = requests
                second = [r for r in requests if r['path'] == '/round-2']
                report['cookie_persisted'] = bool(second and 'ruleproxy='+nonce in second[0]['cookie'])
                if not report['cookie_persisted']: raise RuntimeError('Browser cookie did not persist across restarts')
                report['profile_files'] = sum(1 for p in profile.rglob('*') if p.is_file())
                report['verdict'] = 'browser-render-and-cookie-pass'; code = 0
            finally:
                core.terminate(); core.wait(10); log.close()
    except Exception:
        report['error'] = traceback.format_exc()
    finally:
        server.shutdown(); server.server_close(); thread.join(2)
        (args.output / 'browser-report.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps(report, ensure_ascii=True, indent=2), flush=True)
    return code

if __name__ == '__main__':
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, 'reconfigure'): stream.reconfigure(encoding='utf-8', errors='replace')
    raise SystemExit(main())
