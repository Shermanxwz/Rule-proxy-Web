"""Real Windows admission, token inheritance and Job lifetime; no system install.

The Windows CI job requires an actual elevated token. A preinstalled Edge runs
headlessly with temporary data; these checks do not alter UAC, install services
or drivers, or qualify Windows 11 GUI behavior.
"""
import ctypes
from contextlib import contextmanager
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

from ruleproxy import windows_app_process
from ruleproxy.windows_core_process import CoreJob


ROOT = Path(__file__).resolve().parent.parent
TOKEN_READER = '''
def token_identity():
    import ctypes
    from ctypes import wintypes
    from ruleproxy.windows_proxy_client import current_user_sid
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    advapi = ctypes.WinDLL('advapi32', use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        elevated, returned = wintypes.DWORD(), wintypes.DWORD()
        if not advapi.GetTokenInformation(token, 20, ctypes.byref(elevated), ctypes.sizeof(elevated), ctypes.byref(returned)):
            raise ctypes.WinError(ctypes.get_last_error())
        if returned.value != ctypes.sizeof(elevated):
            raise OSError('Unexpected native TokenElevation size')
        return {'sid': current_user_sid(), 'elevated': bool(elevated.value)}
    finally:
        kernel.CloseHandle(token)
'''

EDGE_DRIVER = '''
import json, subprocess, sys, time, traceback
from pathlib import Path

started = time.monotonic()
result = {"outcome": "starting", "timeout_seconds": float(sys.argv[5])}
try:
    with open(sys.argv[1], "wb") as output, open(sys.argv[2], "wb") as errors:
        child = subprocess.run(sys.argv[6:], stdout=output, stderr=errors,
                               timeout=result["timeout_seconds"])
    result.update(outcome="exited", browser_returncode=child.returncode)
except Exception as error:
    result.update(outcome="timeout" if isinstance(error, subprocess.TimeoutExpired) else "exception",
                  exception_type=type(error).__name__)
    Path(sys.argv[4]).write_text(traceback.format_exc(), encoding="utf-8")
    raise
finally:
    result["elapsed_seconds"] = round(time.monotonic() - started, 3)
    Path(sys.argv[3]).write_text(json.dumps(result), encoding="utf-8")
raise SystemExit(child.returncode)
'''


def token_identity():
    namespace = {}
    exec(TOKEN_READER, namespace)
    return namespace['token_identity']()


def free_ports():
    reservations = []
    try:
        for _ in range(3):
            current = socket.socket()
            current.bind(('127.0.0.1', 0))
            reservations.append(current)
        return [current.getsockname()[1] for current in reservations]
    finally:
        for current in reservations:
            current.close()


@unittest.skipUnless(os.name == 'nt', 'Real Windows process tokens and Jobs')
class WindowsElevatedStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.actual = token_identity()
        if os.environ.get('RULEPROXY_REQUIRE_ELEVATED_STARTUP') == '1' and not cls.actual['elevated']:
            raise AssertionError('This Windows CI job requires a real elevated token; UAC settings were not changed.')

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='ruleproxy-native-token-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / '应用 数据'
        self.directory.mkdir()
        self.script = self.directory / 'token_child.py'
        child = ('import json,os,subprocess,sys,time\nfrom pathlib import Path\n'
                 'sys.path.insert(0, ' + repr(str(ROOT)) + ')\n' + TOKEN_READER + '\n'
                 'result=token_identity()\nresult.update(pid=os.getpid(), fixture=os.environ.get("RULEPROXY_TOKEN_FIXTURE"), '
                 'proxy_names=[name for name in os.environ if name.upper().endswith("_PROXY")])\n'
                 'if len(sys.argv)>2:\n'
                 '    result["grandchild_pid"]=subprocess.Popen([sys.executable,"-B",__file__,sys.argv[2]], '
                 'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).pid\n'
                 'Path(sys.argv[1]).write_text(json.dumps(result),encoding="utf-8")\ntime.sleep(60)\n')
        self.script.write_text(child, encoding='utf-8')
        windowless = Path(sys.executable).with_name('pythonw.exe')
        self.python = str(windowless if windowless.is_file() else Path(sys.executable))

    def read_report(self, report, process):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            try:
                return json.loads(report.read_text(encoding='utf-8'))
            except (OSError, ValueError):
                if process.poll() is not None:
                    self.fail('Native token fixture exited before its report')
                time.sleep(0.03)
        self.fail('Native token fixture did not report within eight seconds')

    @contextmanager
    def production_panel(self):
        ports = free_ports()
        log_path = self.directory / 'panel-output.log'
        state_path = self.directory / 'private-state'
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = 'http://127.0.0.1:' + str(ports[0])
        state = None
        with log_path.open('wb') as output:
            process = subprocess.Popen([self.python, '-B', str(ROOT / 'Run-RuleProxy.py'), '--no-browser',
                '--state-dir', str(state_path), '--port', str(ports[0]), '--proxy-port', str(ports[1]),
                '--controller-port', str(ports[2])], cwd=ROOT, stdin=subprocess.DEVNULL,
                stdout=output, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW)
            try:
                deadline = time.monotonic() + 12
                last_error = None
                while time.monotonic() < deadline:
                    try:
                        with opener.open(url + '/api/state', timeout=1) as response:
                            state = json.loads(response.read(4 * 1024**2))
                        break
                    except (OSError, ValueError) as error:
                        last_error = error
                        if process.poll() is not None:
                            break
                        time.sleep(0.05)
                if state is None:
                    diagnostics = []
                    for path in (log_path, state_path / 'panel.log'):
                        try:
                            tail = path.read_text(encoding='utf-8', errors='replace')[-2000:]
                        except OSError:
                            tail = '(log unavailable)'
                        diagnostics.append(path.name + ':\n' + tail)
                    self.fail('Production panel admission failed: ' + str(last_error)
                        + '\n' + '\n'.join(diagnostics))
                self.assertIs(state.get('process_elevated'), self.actual['elevated'])
                yield state, url
                request = urllib.request.Request(url + '/api/quit', data=b'{}', method='POST',
                    headers={'Content-Type': 'application/json', 'X-RuleProxy-Token': state['token']})
                with opener.open(request, timeout=3) as response:
                    self.assertTrue(json.loads(response.read())['quitting'])
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)

    def test_actual_elevated_or_standard_panel_serves_state_with_matching_permission(self):
        with self.production_panel() as (state, _url):
            self.assertFalse(state['imported'])
            self.assertFalse(state['running'])
            self.assertEqual(state['nodes'], [])

    def test_real_sandboxed_edge_executes_panel_state_fetch_under_current_token(self):
        candidates = [shutil.which('msedge')]
        for name in ('ProgramFiles(x86)', 'ProgramFiles', 'LOCALAPPDATA'):
            if os.environ.get(name):
                candidates.append(str(Path(os.environ[name]) / 'Microsoft/Edge/Application/msedge.exe'))
        edge = next((candidate for candidate in candidates if candidate and Path(candidate).is_file()), None)
        if edge is None:
            if os.environ.get('RULEPROXY_REQUIRE_ELEVATED_STARTUP') == '1':
                self.fail('Windows CI must provide its preinstalled Microsoft Edge; no browser was downloaded.')
            self.skipTest('Microsoft Edge is not installed on this development machine')

        # --dump-dom serializes the DOM after executing the production script:
        # https://developer.chrome.com/docs/automation-and-testing/headless-cli
        # A Python driver captures stdout while production launch owns its Job
        # and every Edge descendant, including on timeout or browser failure.
        driver = self.directory / 'edge_dom_driver.py'
        driver.write_text(EDGE_DRIVER, encoding='utf-8')
        dom_path, error_path = self.directory / 'edge-dom.html', self.directory / 'edge-stderr.log'
        result_path = self.directory / 'edge-result.json'
        exception_path = self.directory / 'edge-driver-exception.log'
        profile = self.directory / 'edge-private-profile'
        with self.production_panel() as (state, url):
            command = [sys.executable, '-B', str(driver), str(dom_path), str(error_path),
                str(result_path), str(exception_path), '30', str(edge),
                '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
                '--disable-background-networking', '--no-proxy-server',
                '--user-data-dir=' + str(profile), '--dump-dom', '--timeout=8000',
                '--virtual-time-budget=5000', url + '/']
            process = windows_app_process.launch(command, os.environ, str(self.directory))
            try:
                def tail(path, limit=2000):
                    try:
                        return path.read_text(encoding='utf-8', errors='replace')[-limit:]
                    except OSError:
                        return '(file unavailable)'

                try:
                    returncode = process.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    self.fail('Sandboxed Edge driver did not finish within thirty-five seconds.\n'
                        + tail(result_path) + '\nDriver exception:\n' + tail(exception_path)
                        + '\nEdge stderr:\n' + tail(error_path))
                diagnostic = ('Driver exit: ' + str(returncode) + '\nDriver result:\n' + tail(result_path)
                    + '\nDriver exception:\n' + tail(exception_path) + '\nEdge stderr:\n' + tail(error_path)
                    + '\nDOM tail:\n' + tail(dom_path, 500))
                try:
                    result = json.loads(result_path.read_text(encoding='utf-8'))
                except (OSError, ValueError):
                    self.fail('Sandboxed Edge driver did not produce a valid result.\n' + diagnostic)
                self.assertEqual(result.get('outcome'), 'exited', diagnostic)
                self.assertEqual(result.get('browser_returncode'), 0, diagnostic)
                self.assertEqual(returncode, 0, diagnostic)
                dom = dom_path.read_text(encoding='utf-8', errors='replace')

                class Fields(HTMLParser):
                    def __init__(self):
                        super().__init__()
                        self.values, self.active = {}, None

                    def handle_starttag(self, tag, attrs):
                        identity = dict(attrs).get('id')
                        if identity in ('version-label', 'status-title', 'platform-label', 'global-error'):
                            self.values[identity], self.active = '', identity

                    def handle_data(self, data):
                        if self.active:
                            self.values[self.active] += data

                    def handle_endtag(self, tag):
                        self.active = None

                fields = Fields()
                fields.feed(dom)
                message = 'Edge did not render the actual /api/state response.\n' + diagnostic
                self.assertEqual(fields.values.get('version-label'), '版本：' + state['version'], message)
                self.assertEqual(fields.values.get('status-title'), '等待导入配置', message)
                self.assertEqual(fields.values.get('platform-label'), state['platform'], message)
                self.assertNotIn('仅允许从本机', fields.values.get('global-error', ''), message)
                self.assertNotIn('无法读取', fields.values.get('global-error', ''), message)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=3)

    def test_production_app_launch_inherits_real_identity_and_job_stops_owned_family(self):
        root_report, child_report = self.directory / 'root.json', self.directory / 'descendant.json'
        environment = {**os.environ, 'RULEPROXY_TOKEN_FIXTURE': 'retained-native-fixture',
                       'HTTP_PROXY': 'http://127.0.0.1:9'}
        process = windows_app_process.launch([self.python, '-B', str(self.script), str(root_report), str(child_report)],
                                             environment, str(self.directory))
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        descendant = None
        try:
            root = self.read_report(root_report, process)
            child = self.read_report(child_report, process)
            for report in (root, child):
                self.assertEqual(report['sid'], self.actual['sid'])
                self.assertIs(report['elevated'], self.actual['elevated'])
                self.assertEqual(report['fixture'], 'retained-native-fixture')
                self.assertEqual(report['proxy_names'], [])
            self.assertEqual(root['pid'], process.pid)
            self.assertEqual(root['grandchild_pid'], child['pid'])
            descendant = kernel.OpenProcess(0x100000 | 0x1000, False, child['pid'])
            self.assertTrue(descendant, 'Could not retain the owned descendant handle')
            process.terminate()
            process.wait(timeout=3)
            self.assertEqual(kernel.WaitForSingleObject(descendant, 3000), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if descendant:
                kernel.CloseHandle(descendant)

    def test_real_core_job_accepts_current_token_and_kills_only_its_owned_process(self):
        report = self.directory / 'core.json'
        process = subprocess.Popen([self.python, '-B', str(self.script), str(report)],
            cwd=self.directory, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW)
        job = None
        unrelated = None
        try:
            job = CoreJob(process)
            unrelated = subprocess.Popen([self.python, '-c', 'import time;time.sleep(30)'],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW)
            actual = self.read_report(report, process)
            self.assertEqual(actual['sid'], self.actual['sid'])
            self.assertIs(actual['elevated'], self.actual['elevated'])
            job.close()
            process.wait(timeout=3)
            self.assertIsNone(unrelated.poll(), 'Closing CoreJob affected an unrelated process')
            job.close()
        finally:
            if job is not None:
                job.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if unrelated is not None and unrelated.poll() is None:
                unrelated.kill()
                unrelated.wait(timeout=3)


if __name__ == '__main__':
    unittest.main()
