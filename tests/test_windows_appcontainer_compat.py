"""Evidence boundaries for the bounded native browser experiment."""
from contextlib import contextmanager
import copy
import http.client
import importlib.util
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zlib

SCRIPT = Path(__file__).resolve().parents[1] / '.github/windows_appcontainer_compat.py'
SPEC = importlib.util.spec_from_file_location('browser_compat_tested', SCRIPT)
compat = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compat)


class BrowserEvidenceTests(unittest.TestCase):
    def test_fixture_only_accepts_unique_owned_absolute_http_target(self):
        fixture = compat.Fixture()
        self.addCleanup(fixture.close)
        connection = http.client.HTTPConnection('127.0.0.1', fixture.port, timeout=2)
        self.addCleanup(connection.close)
        connection.request('GET', fixture.url('edge_control'))
        response = connection.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn(fixture.marker('edge_control').encode(), response.read())
        self.assertEqual(fixture.count('edge_control'), 1)
        for target in ('http://example.com/', fixture.url('unknown'), fixture.url('edge_contained').replace(fixture.nonce, 'wrong', 1)):
            connection.request('GET', target)
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
        connection.request('CONNECT', 'example.com:443')
        response = connection.getresponse()
        self.assertEqual(response.status, 403)
        response.read()
        self.assertEqual(fixture.count('edge_contained'), 0)

    def test_proxy_receipt_render_and_successful_exit_are_all_required(self):
        outcome = {'started': True, 'exit_code': 0, 'timed_out': False}
        self.assertTrue(compat.row_success(outcome, 1, True))
        for field, value in (('started', 1), ('exit_code', False), ('exit_code', 1), ('timed_out', True), ('timed_out', None)):
            self.assertFalse(compat.row_success({**outcome, field: value}, 1, True))
        for received, rendered in ((0, True), (True, True), (1, False), (1, 1)):
            self.assertFalse(compat.row_success(outcome, received, rendered))

    def report(self):
        return {'cleanup_ok': True, 'runs': {family + '_' + variant: {
            'ok': variant == 'control', 'browser_sandbox_enabled': variant != 'diagnostic_no_sandbox',
            'contained': variant != 'control', 'diagnostic_only': variant == 'diagnostic_no_sandbox'}
            for family in compat.PROGRAMS for variant in compat.VARIANTS
            if family != 'firefox' or variant != 'diagnostic_no_sandbox'}}

    def test_diagnostic_success_cannot_promote_unsupported_contained_browser(self):
        report = self.report()
        report['runs']['edge_diagnostic_no_sandbox']['ok'] = True
        summary = compat.summarize(report)
        self.assertTrue(summary['valid_experiment'])
        self.assertFalse(summary['compatibility']['edge']['contained_sandbox_preserved_passed'])
        report['runs']['edge_contained']['ok'] = True
        self.assertTrue(compat.summarize(report)['compatibility']['edge']['contained_sandbox_preserved_passed'])
        report['runs']['edge_contained']['browser_sandbox_enabled'] = False
        self.assertFalse(compat.summarize(report)['compatibility']['edge']['contained_sandbox_preserved_passed'])

    def test_fixture_errors_missing_or_unsandboxed_controls_and_cleanup_fail_closed(self):
        base = self.report()
        mutations = [lambda r: r.update(error='internal fixture failed'), lambda r: r.update(cleanup_ok=False),
                     lambda r: r['runs'].pop('firefox_control'),
                     lambda r: r['runs']['edge_control'].update(ok=False),
                     lambda r: r['runs']['edge_control'].update(browser_sandbox_enabled=False)]
        for mutate in mutations:
            report = copy.deepcopy(base)
            mutate(report)
            self.assertFalse(compat.summarize(report)['valid_experiment'])

    def test_browser_and_debugger_environments_exclude_ci_credentials(self):
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'secret', 'ACTIONS_ID_TOKEN_REQUEST_TOKEN': 'secret',
                                         'HTTPS_PROXY': 'secret', 'CUSTOM_SECRET': 'secret', 'SystemRoot': 'C:\\Windows'}, clear=True):
            before = {key.upper(): value for key, value in os.environ.items()}
            env = compat.safe_environment(Path('owned'))
            self.assertEqual({key.upper(): value for key, value in os.environ.items()}, before)
        expected = {'SYSTEMROOT': 'C:\\Windows', **{key: str(Path('owned') / child) for key, child in (
            ('TEMP', 'tmp'), ('TMP', 'tmp'), ('HOME', 'home'), ('USERPROFILE', 'home'),
            ('LOCALAPPDATA', 'local'), ('APPDATA', 'roaming'))}}
        self.assertEqual({key.upper(): value for key, value in env.items()}, expected)
        self.assertFalse(any('secret' in value for value in env.values()))
        self.assertEqual(env['USERPROFILE'], str(Path('owned/home')))

    def test_partial_or_corrupted_png_is_not_rendering_evidence(self):
        def chunk(kind, data):
            return struct.pack('!I', len(data)) + kind + data + struct.pack('!I', zlib.crc32(kind + data))
        data = (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('!IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
                + chunk(b'IDAT', zlib.compress(b'\x00\xff\xff\xff')) + chunk(b'IEND', b''))
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'shot.png'
            for invalid in (data[:33], data[:-1], data[:-5] + b'bad!!', data + b'extra'):
                path.write_bytes(invalid)
                self.assertFalse(compat.png_valid(path))
            path.write_bytes(data)
            self.assertTrue(compat.png_valid(path))

    def test_dump_policy_restores_existing_values_and_deletes_new_empty_keys_on_error(self):
        values = {compat.LOCALDUMPS + '\\old.exe': {'DumpCount': (7, 1), 'Unrelated': ('keep', 2)}}
        before = copy.deepcopy(values)
        @contextmanager
        def open_key(_root, path, *_args):
            if path not in values:
                raise FileNotFoundError(path)
            yield path
        @contextmanager
        def create_key(_root, path, *_args):
            values.setdefault(path, {})
            yield path
        def query(key, field):
            if field not in values[key]:
                raise FileNotFoundError(field)
            return values[key][field]
        registry = SimpleNamespace(HKEY_LOCAL_MACHINE=1, KEY_QUERY_VALUE=1, KEY_SET_VALUE=2,
            REG_EXPAND_SZ=2, REG_DWORD=1, OpenKey=open_key, CreateKeyEx=create_key, QueryValueEx=query,
            SetValueEx=lambda key, field, _reserved, kind, value: values[key].__setitem__(field, (value, kind)),
            DeleteValue=lambda key, field: values[key].pop(field), QueryInfoKey=lambda key: (0, len(values[key]), 0),
            DeleteKey=lambda _root, path: values.pop(path))
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(sys.modules, {'winreg': registry}), \
                mock.patch.object(compat, 'DUMPS', Path(d) / 'dumps'):
            with self.assertRaisesRegex(RuntimeError, 'synthetic'):
                with compat.dump_policy(['old.exe', 'new.exe']):
                    self.assertEqual(values[compat.LOCALDUMPS + '\\old.exe']['DumpCount'][0], 3)
                    raise RuntimeError('synthetic fixture failure')
        self.assertEqual(values, before)


if __name__ == '__main__':
    unittest.main()
