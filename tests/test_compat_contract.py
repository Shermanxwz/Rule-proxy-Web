"""Offline contracts only: no application launch, network, registry or WFP writes."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy import launcher, windows_gemini as gemini
from ruleproxy import windows_app_guard as guard


class GeminiContractTests(unittest.TestCase):
    def test_rejected_switch_spellings_and_redaction(self):
        for name in gemini._UNSUPPORTED_SWITCHES:
            for prefix in ('--', '-', '/'):
                with self.subTest(name=name, prefix=prefix):
                    with self.assertRaises(ValueError) as result:
                        gemini.validate_launch_args([f' {prefix}{name.upper()}=secret-test-value '])
                    self.assertNotIn('secret-test-value', str(result.exception))

    def test_ordinary_args_unchanged(self):
        args = ['--open-settings', 'https://example.invalid/proxy-server']
        before = list(args)
        gemini.validate_launch_args(args)
        self.assertEqual(args, before)

    def _fixture(self, root):
        install = root / 'Google' / 'Gemini'
        for version in ('app-1.9.0', 'app-1.17.0'):
            directory = install / version
            directory.mkdir(parents=True)
            for name in ('Gemini.exe', 'GeminiAppLauncher.exe'):
                (directory / name).write_bytes(b'fixture: not executable')
                (directory / name).chmod(0o700)
        entry = install / 'Gemini.exe'
        entry.write_bytes(b'fixture: not executable')
        entry.chmod(0o700)
        return {'id': 'gemini-test', 'label': 'Gemini', 'path': str(entry),
                'adapter': 'chromium', 'args': [], 'use_original_data': True}

    def test_real_prepare_uses_version_and_no_chromium_flags(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self._fixture(root)
            with patch.dict(os.environ, LOCALAPPDATA=str(root)), patch.object(launcher.sys, 'platform', 'win32'):
                command, env, _ = launcher.prepare_app(app, 10809, root / 'profiles',
                                                      transparent=True, native_proxy=True)
            self.assertEqual(command, [str(root / 'Google/Gemini/app-1.17.0/Gemini.exe')])
            self.assertEqual(env['HTTPS_PROXY'], 'http://127.0.0.1:10809')
            self.assertEqual(env['NO_PROXY'], 'localhost,127.0.0.1,::1')
            self.assertEqual(app['adapter'], 'chromium')  # caller not mutated

    def test_prepare_rejects_saved_environment_proxy_switch(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            app = self._fixture(root)
            app.update(adapter='environment', use_original_data=False, args=['--proxy-server=http://secret.invalid'])
            with patch.dict(os.environ, LOCALAPPDATA=str(root)), patch.object(launcher.sys, 'platform', 'win32'):
                with self.assertRaises(ValueError) as result:
                    launcher.prepare_app(app, 10809, root / 'profiles', transparent=True, native_proxy=True)
                self.assertNotIn('secret.invalid', str(result.exception))

    def test_all_installed_gemini_images_covered(self):
        with tempfile.TemporaryDirectory() as temp:
            app = self._fixture(Path(temp))
            with patch.dict(os.environ, LOCALAPPDATA=temp):
                paths = gemini.routing_paths(app['path'])
                self.assertEqual(len(paths), 5)
                self.assertEqual(len(set(paths)), 5)


class GuardContractTests(unittest.TestCase):
    def setUp(self):
        self.rules = guard._plan([b'main-id', b'helper-id'], 10809)

    def test_both_families_and_app_identities_covered(self):
        self.assertEqual(len(self.rules), 8)
        self.assertEqual(guard.AppGuard._consistent(guard.AppGuard._expected(self.rules)), (2, 10809))

    def test_current_contract_excludes_other_local_ports(self):
        # This intentionally documents an UNRESOLVED IPC compatibility gap.
        # It is not a native filtering test or a claim that IPC has been repaired.
        for rule in self.rules:
            if rule.name.startswith('permit-'):
                self.assertIn(('flags', 6, 3, 1), rule.conditions)
                self.assertIn(('remote_port', 0, 2, 10809), rule.conditions)
                self.assertNotIn(('remote_port', 0, 2, 54321), rule.conditions)
            else:
                self.assertEqual(len(rule.conditions), 1)
                self.assertEqual(rule.conditions[0][0], 'app')

    def test_missing_family_rule_is_not_accepted(self):
        filters = guard.AppGuard._expected(self.rules)
        del filters[(6, 'block-1')]
        with self.assertRaises(guard.ProxyError):
            guard.AppGuard._consistent(filters)

    def test_invalid_port_is_rejected(self):
        for port in (True, 0, 1024, 65536, '10809'):
            with self.subTest(port=port), self.assertRaises(ValueError):
                guard._plan([b'app'], port)


if __name__ == '__main__':
    unittest.main()
