"""Real child-process proxy inheritance, without drivers or external requests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from ruleproxy.launcher import _infer_adapter, prepare_app


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

    def test_http_client_in_a_child_and_its_helper_uses_only_the_local_proxy(self):
        received = []
        class Proxy(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                received.append(self.path)
                body = b'proxy-fixture'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers(); self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as directory:
                app = {'id': 'app', 'label': 'CLI', 'path': sys.executable,
                       'adapter': 'environment', 'args': []}
                with patch.dict(os.environ, {'HTTPS_PROXY': 'http://unrelated.invalid:9',
                                              'no_proxy': '*'}):
                    _, environment, _ = prepare_app(app, server.server_port, Path(directory),
                                                     transparent=True, native_proxy=True)
                code = "import urllib.request; assert urllib.request.urlopen('http://token-exchange.invalid/synthetic', timeout=3).read() == b'proxy-fixture'"
                # A separate helper inherits the application's environment;
                # neither target can resolve on the real network.
                wrapper = 'import subprocess,sys; subprocess.run([sys.executable,"-c",' + repr(code) + '],check=True)'
                result = subprocess.run([sys.executable, '-c', wrapper], env=environment,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(received, ['http://token-exchange.invalid/synthetic'])
                self.assertEqual(environment['HTTPS_PROXY'], environment['https_proxy'])
                self.assertEqual(environment['NO_PROXY'], 'localhost,127.0.0.1,::1')
        finally:
            server.shutdown(); server.server_close(); worker.join(3)

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
