"""Real Windows launcher proxy inheritance, without drivers or external requests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import uuid
from unittest.mock import patch

from ruleproxy.launcher import _infer_adapter, prepare_app


NATIVE_PROXY_ACTOR = '''
import json, os, subprocess, sys, traceback, urllib.request
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from ruleproxy import windows_app_process
from ruleproxy.windows_proxy_client import current_user_sid

role, directory, port, nonce = sys.argv[2], Path(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
report = {'pid': os.getpid(), 'ppid': os.getppid()}
try:
    report.update(sid=current_user_sid(), elevated=windows_app_process._get_api().is_elevated(),
                  launcher_file=str(Path(windows_app_process.__file__).resolve()))
    endpoint = 'http://127.0.0.1:' + str(port)
    expected = {'HTTP_PROXY': endpoint, 'HTTPS_PROXY': endpoint, 'ALL_PROXY': endpoint,
                'NO_PROXY': 'localhost,127.0.0.1,::1', 'NODE_USE_ENV_PROXY': '1'}
    actual = {key.upper(): value for key, value in os.environ.items() if key.upper().endswith('_PROXY')}
    report['proxy_environment'] = actual
    # Refuse a broken environment before urllib could consult registry proxies
    # or attempt any DNS/direct request. Both roles must then hit the fixture.
    if actual != expected:
        raise RuntimeError('Native launcher did not supply the controlled proxy environment')
    target = 'http://' + nonce + '.invalid/' + nonce + '/' + role
    report['target'] = target
    with urllib.request.urlopen(target, timeout=3) as response:
        report['response'] = response.read(128).decode('ascii')
    if report['response'] != 'proxy-fixture:' + nonce:
        raise RuntimeError('Unexpected local proxy response')
    if role == 'child':
        helper = subprocess.run([sys.executable, '-B', __file__, sys.argv[1], 'grandchild',
                                 str(directory), str(port), nonce],
                                capture_output=True, text=True, timeout=8)
        report['grandchild_exit_code'] = helper.returncode
        if helper.returncode != 0:
            raise RuntimeError('Grandchild failed: ' + helper.stderr[-2048:])
except BaseException:
    report['error'] = traceback.format_exc()[-4096:]
finally:
    (directory / (role + '.json')).write_text(json.dumps(report), encoding='utf-8')
if 'error' in report:
    raise SystemExit(1)
'''


def native_launcher_proxy_probe(directory):
    """Exercise the real current-token launcher; reusable by ordinary-user CI.

    The caller selects the already established Windows user context. This probe
    never creates users, changes tokens, installs components, or uses a shell.
    Its reports include native token identity and the loaded launcher location
    so installed-product acceptance can bind both to its existing owner.
    """
    from ruleproxy import windows_app_process
    from ruleproxy.windows_proxy_client import current_user_sid

    if os.name != 'nt':
        raise OSError('Native proxy inheritance probe requires Windows')
    launcher_file = str(Path(windows_app_process.__file__).resolve())
    project_root = str(Path(launcher_file).parent.parent)
    parent_token = {'sid': current_user_sid(), 'elevated': windows_app_process._get_api().is_elevated(),
                    'pid': os.getpid()}
    received = []
    nonce = uuid.uuid4().hex

    class Proxy(BaseHTTPRequestHandler):
        def log_message(self, *_): pass

        def do_GET(self):
            received.append(self.path)
            body = ('proxy-fixture:' + nonce).encode('ascii')
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        with tempfile.TemporaryDirectory(prefix='native-proxy-', dir=directory) as temporary:
            work = Path(temporary)
            actor = work / 'actor.py'
            actor.write_text(NATIVE_PROXY_ACTOR, encoding='utf-8')
            app = {'id': 'app', 'label': 'CLI', 'path': sys.executable, 'adapter': 'environment',
                   'args': ['-B', str(actor), project_root, 'child', str(work),
                            str(server.server_port), nonce]}
            command, environment, _ = prepare_app(app, server.server_port, work / 'profiles',
                                                 transparent=True, native_proxy=True)
            # The explicit native port must override all these untrusted input
            # values. A permissive pass-through would contact the wrong proxy.
            environment.update(HTTP_PROXY='http://untrusted.invalid:9', NO_PROXY='*',
                               CUSTOM_PROXY='http://untrusted.invalid:9', NODE_USE_ENV_PROXY='0')
            process = windows_app_process.launch(command, environment, str(work),
                                                native_proxy_port=server.server_port)
            try:
                exit_code = process.wait(15)
                child_path, helper_path = work / 'child.json', work / 'grandchild.json'
                child = json.loads(child_path.read_text(encoding='utf-8')) if child_path.is_file() else {}
                if exit_code != 0:
                    raise RuntimeError('Native proxy child failed: ' + str(child.get('error', exit_code)))
                grandchild = json.loads(helper_path.read_text(encoding='utf-8'))
                return {'parent_token': parent_token, 'child': child, 'grandchild': grandchild,
                        'expected_targets': [f'http://{nonce}.invalid/{nonce}/{role}'
                                             for role in ('child', 'grandchild')],
                        'received_targets': list(received), 'exit_code': exit_code,
                        'launcher_file': launcher_file, 'launched_pid': process.pid,
                        'proxy_port': server.server_port,
                        'probe_scope': 'windows-native-launcher-child-grandchild-loopback'}
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(5)
    finally:
        server.shutdown()
        server.server_close()
        worker.join(3)


class WindowsNativeProxyTests(unittest.TestCase):
    def test_package_cli_is_identified_by_pe_subsystem_without_application_name_exceptions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'arbitrary-helper.exe'
            binary = bytearray(128 + 94)
            binary[:2] = b'MZ'; binary[60:64] = (128).to_bytes(4, 'little')
            binary[128:132] = b'PE\0\0'
            binary[152:154] = (0x20b).to_bytes(2, 'little')
            binary[220:222] = (3).to_bytes(2, 'little')
            path.write_bytes(binary)
            self.assertEqual(_infer_adapter('ChatGPT Core command runner', path), 'environment')
            app = {'id': 'cli', 'label': 'Legacy CLI', 'path': str(path),
                   'adapter': 'chromium', 'args': [], 'use_original_data': True}
            with patch('os.access', return_value=True):
                command, environment, _ = prepare_app(app, 18809, Path(directory),
                                                     transparent=True, native_proxy=True)
            self.assertFalse(any(value.startswith('--') for value in command[1:]))
            self.assertEqual(environment['HTTPS_PROXY'], 'http://127.0.0.1:18809')

    @unittest.skipUnless(os.name == 'nt', 'Real Windows process tokens and native launcher')
    def test_windows_launcher_child_and_grandchild_use_only_owned_proxy(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = native_launcher_proxy_probe(directory)
        self.assertEqual(evidence['exit_code'], 0)
        self.assertEqual(evidence['received_targets'], evidence['expected_targets'])
        self.assertEqual(evidence['child']['pid'], evidence['launched_pid'])
        self.assertEqual(evidence['child']['ppid'], evidence['parent_token']['pid'])
        self.assertEqual(evidence['grandchild']['ppid'], evidence['child']['pid'])
        self.assertNotEqual(evidence['child']['pid'], evidence['grandchild']['pid'])
        self.assertEqual(evidence['child']['grandchild_exit_code'], 0)
        endpoint = f"http://127.0.0.1:{evidence['proxy_port']}"
        expected_environment = {'HTTP_PROXY': endpoint, 'HTTPS_PROXY': endpoint, 'ALL_PROXY': endpoint,
                                'NO_PROXY': 'localhost,127.0.0.1,::1', 'NODE_USE_ENV_PROXY': '1'}
        for index, role in enumerate(('child', 'grandchild')):
            with self.subTest(role=role, elevated=evidence['parent_token']['elevated']):
                actor = evidence[role]
                self.assertNotIn('error', actor)
                self.assertIs(type(actor['elevated']), bool)
                self.assertEqual(actor['elevated'], evidence['parent_token']['elevated'])
                self.assertEqual(actor['sid'], evidence['parent_token']['sid'])
                self.assertEqual(actor['launcher_file'], evidence['launcher_file'])
                self.assertEqual(actor['proxy_environment'], expected_environment)
                self.assertEqual(actor['target'], evidence['expected_targets'][index])

    def test_chromium_original_data_keeps_profile_and_has_explicit_proxy_and_udp_controls(self):
        with tempfile.TemporaryDirectory() as directory:
            app = {'id': 'app', 'label': 'Browser', 'path': sys.executable,
                   'adapter': 'chromium', 'args': [], 'use_original_data': True}
            with patch('ruleproxy.launcher.sys.platform', 'win32'), \
                    patch('ruleproxy.launcher._pe_console_program', return_value=False):
                command, environment, _ = prepare_app(app, 18809, Path(directory) / 'profiles',
                                                     transparent=True, native_proxy=True)
            self.assertIn('--proxy-server=http://127.0.0.1:18809', command)
            self.assertIn('--disable-quic', command)
            self.assertIn('--force-webrtc-ip-handling-policy=disable_non_proxied_udp', command)
            self.assertFalse(any(value.startswith('--user-data-dir') for value in command))
            self.assertFalse((Path(directory) / 'profiles').exists())
            self.assertEqual(environment['HTTP_PROXY'], 'http://127.0.0.1:18809')


if __name__ == '__main__':
    unittest.main()
