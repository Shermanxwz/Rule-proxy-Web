"""Protocol and evidence checks; Linux tests do not qualify a Windows product."""
import importlib.util
import json
import select
import socket
import ssl
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / '.github' / 'windows_compartment_product_probe.py'
SPEC = importlib.util.spec_from_file_location('windows_compartment_product_probe', SOURCE)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class EvidenceTests(unittest.TestCase):
    def test_service_restart_cannot_hide_original_process_crash(self):
        native = SimpleNamespace(wait=lambda handle, timeout: 0,
                                 exit_code=lambda handle: 0xC0000005)
        control = SimpleNamespace(status=lambda service: {'state': 4, 'pid': 999, 'win32_exit_code': 0})
        result = probe.service_state((native, control, 123, 42))
        self.assertFalse(result['alive'])
        self.assertEqual(result['pid'], 42)
        self.assertEqual(result['exit_code_hex'], '0xC0000005')
        self.assertEqual(result['scm']['pid'], 999)

    def test_cleanup_error_keeps_original_native_failure(self):
        try:
            try:
                raise PermissionError(5, 'native launch access denied')
            finally:
                raise TypeError("cannot create 'winreg.PyHKEY' instances")
        except TypeError as error:
            result = probe.failure(error)
        self.assertEqual(result['error_type'], 'TypeError')
        original = result['exception_chain'][0]
        self.assertEqual(original['relation'], 'context')
        self.assertEqual(original['error_type'], 'PermissionError')
        self.assertEqual(original['errno'], 5)
        self.assertTrue(original['frames'])

    def result(self):
        sid = 'S-1-5-21-1-2-3-1001'
        plain = {name: {'ok': True} for name in probe.LOCAL_PROXY + probe.LOCAL_DIRECT}
        inside = {name: {'ok': name in probe.LOCAL_PROXY} for name in plain}
        after = {name: {'ok': False} for name in plain}
        return {'outside': {'identity': {'sid': sid, 'elevated': False, 'compartment_id': 1}, 'before': plain},
                'inside': {'identity': {'sid': sid, 'elevated': False, 'compartment_id': 22}, 'before': inside,
                           'after': after, 'after_complete': True},
                'fault': {'injected': True}, 'actor_alive_before_fault': True, 'actor_exit_code': 0,
                'post_fault_tls_hits': [], 'post_fault_http_delta': 0,
                'outside_after': {'direct_tls': {'ok': True}}}

    def test_positive_requires_complete_same_api_controls(self):
        result = self.result()
        self.assertTrue(all(probe.fault_checks(result).values()))
        del result['outside']['before']['socks_tls']
        self.assertFalse(probe.fault_checks(result)['plain_same_api_positive'])

    def test_completed_leaking_actor_is_not_excused_by_exit_code(self):
        result = self.result()
        result['inside']['after']['connect_tls']['ok'] = True
        for exit_code in (0, 1, 125):
            result['actor_exit_code'] = exit_code
            self.assertFalse(probe.fault_checks(result)['post_fault_terminated_or_denied'])

    def test_terminated_actor_must_be_observed_alive_at_fault_barrier(self):
        result = self.result()
        result['inside'].pop('after_complete')
        result['actor_exit_code'] = 1
        self.assertTrue(probe.fault_checks(result)['post_fault_terminated_or_denied'])
        result['actor_alive_before_fault'] = False
        self.assertFalse(probe.fault_checks(result)['post_fault_terminated_or_denied'])

    def test_partial_actor_report_cannot_hide_origin_hits(self):
        result = self.result()
        result['inside'].pop('after_complete')
        result['actor_exit_code'] = 1
        result['post_fault_tls_hits'] = [{'tag': 'inside-after', 'time_ns': 10}]
        result['post_fault_http_delta'] = 1
        checks = probe.fault_checks(result)
        self.assertFalse(checks['no_post_fault_tls_hit'])
        self.assertFalse(checks['no_post_fault_http_hit'])

    def test_missing_data_and_system_identity_cannot_pass(self):
        self.assertFalse(any(probe.fault_checks({}).values()))
        result = self.result()
        for scope in ('inside', 'outside'):
            result[scope]['identity']['sid'] = 'S-1-5-18'
        self.assertFalse(probe.fault_checks(result)['ordinary_same_identity'])

    def test_source_identity_checks_exact_installed_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = probe.SOURCE_FILES + ('bin/windows-amd64/mihomo.exe', 'python/python.exe')
            for name in files:
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                if name in probe.SOURCE_FILES:
                    target.write_bytes((SOURCE.parents[1] / name).read_bytes())
                else:
                    target.write_text(name, encoding='ascii')
            metadata = {'files': {name: probe.digest(root / name) for name in files}}
            package = root / 'package-manifest.json'
            package.write_text(json.dumps({'files': dict(metadata['files'])}), encoding='ascii')
            metadata['files']['package-manifest.json'] = probe.digest(package)
            self.assertTrue(probe.source_identity(root, metadata)['deployment_inventory_matches'])
            self.assertTrue(probe.source_identity(root, metadata)['package_inventory_matches'])
            self.assertTrue(all(probe.source_identity(root, metadata)['source_matches_bundle'].values()))
            (root / probe.SOURCE_FILES[0]).write_text('different revision', encoding='ascii')
            changed = probe.source_identity(root, metadata)
            self.assertFalse(changed['deployment_inventory_matches'])
            self.assertFalse(changed['package_inventory_matches'])
            self.assertFalse(changed['source_matches_bundle']['ruleproxy/windows_compartment.py'])
            self.assertEqual(changed['mismatched_files'], [probe.SOURCE_FILES[0]])


class TLSProtocolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.fixture = probe.TLSFixture(Path('unused-mihomo'), Path(self.directory.name))
        # This unit test exercises TLS and SOCKS protocols directly. The native
        # script alone starts real Mihomo and the production compartment gate.
        with patch.object(probe.Fixture, 'start', lambda fixture: fixture):
            self.fixture.start()
        self.fixture.spec['origin_port'] = 1
        listener = self.fixture._listen()
        self.fixture.spec['proxy_port'] = listener.getsockname()[1]
        self.fixture._thread(self.fixture._accept, listener, self.fixture._socks)

    def tearDown(self):
        self.fixture.close()
        self.directory.cleanup()

    def test_direct_and_socks_tls_validate_ca_and_transfer_nonce_body(self):
        for route in ('direct', 'socks'):
            value = probe.tls_probe(self.fixture.spec, route, 'protocol-' + route)
            self.assertTrue(value['ok'], value)
            self.assertTrue(value['tls_verified'])
            self.assertEqual(len(value['certificate_sha256']), 64)
        counts = self.fixture.snapshot()
        self.assertEqual([item['tag'] for item in counts['tls_requests']], ['protocol-direct', 'protocol-socks'])
        self.assertEqual(counts['proxy_requests'], 1)

    def test_wrong_hostname_is_rejected_by_trusted_fixture_ca(self):
        context = ssl.create_default_context(cafile=self.fixture.spec['cafile'])
        with socket.create_connection(('127.0.0.1', self.fixture.spec['tls_port']), timeout=3) as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname='different.invalid')

    def test_connect_tls_transfers_real_tls_bytes_and_validates_certificate(self):
        def connect(connection):
            request = probe.header(connection)
            expected = f'CONNECT {probe.HOST}:{self.fixture.spec["tls_port"]} HTTP/1.1\r\n'.encode('ascii')
            self.assertTrue(request.startswith(expected))
            with socket.create_connection(('127.0.0.1', self.fixture.spec['tls_port']), timeout=3) as peer:
                connection.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                while not self.fixture.stop.is_set():
                    ready, _, _ = select.select((connection, peer), [], [], .2)
                    for source in ready:
                        payload = source.recv(16384)
                        if not payload:
                            return
                        (peer if source is connection else connection).sendall(payload)
        listener = self.fixture._listen()
        self.fixture._thread(self.fixture._accept, listener, connect)
        spec = {**self.fixture.spec, 'proxy_port': listener.getsockname()[1]}
        result = probe.tls_probe(spec, 'connect', 'connect-protocol')
        self.assertTrue(result['ok'], result)
        self.assertTrue(result['tls_verified'])
        self.assertEqual(self.fixture.snapshot()['tls_requests'][0]['tag'], 'connect-protocol')

    def test_default_system_trust_does_not_trust_test_ca(self):
        context = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', self.fixture.spec['tls_port']), timeout=3) as connection:
            with self.assertRaises(ssl.SSLCertVerificationError):
                context.wrap_socket(connection, server_hostname=probe.HOST)

    def test_upstream_rejects_unapproved_destination(self):
        with socket.create_connection(('127.0.0.1', self.fixture.spec['proxy_port']), timeout=3) as connection:
            with self.assertRaises(OSError):
                probe.socks_connect(connection, 'unrelated.example', 443)
        self.assertEqual(self.fixture.snapshot()['proxy_requests'], 0)


if __name__ == '__main__':
    unittest.main()
