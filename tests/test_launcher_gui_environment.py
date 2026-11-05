"""Regression for maintenance-host Electron Node-mode contamination."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import launcher


class GuiEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.exe = self.root / 'test-gui.exe'
        self.exe.write_bytes(b'fixture')

    def prepare(self, source, *, adapter='chromium', gemini=False,
                console=False, platform='win32', transparent=True,
                native_proxy=True, original=True):
        app = {'id': 'gui-env-fixture', 'label': 'Fixture',
               'path': str(self.exe), 'adapter': adapter,
               'use_original_data': original if adapter == 'chromium' else False}
        with mock.patch.object(launcher.os, 'environ', source), \
             mock.patch.object(launcher.sys, 'platform', platform), \
             mock.patch.object(launcher, '_pe_console_program', return_value=console), \
             mock.patch('ruleproxy.windows_gemini.is_gemini', return_value=gemini), \
             mock.patch('ruleproxy.windows_gemini.launch_path', return_value=str(self.exe)):
            return launcher.prepare_app(app, 10809, self.root / 'profiles',
                                        transparent=transparent, native_proxy=native_proxy)

    def test_gui_strips_all_case_variants_without_mutating_parent(self):
        source = {'ELECTRON_RUN_AS_NODE': '1', 'electron_run_as_node': '0',
                  'Electron_Run_As_Node': '', 'PATH': 'retained',
                  'NODE_OPTIONS': '--trace-warnings'}
        original = dict(source)
        command, env, _ = self.prepare(source)
        self.assertFalse(any(k.upper() == 'ELECTRON_RUN_AS_NODE' for k in env))
        self.assertEqual(source, original)
        self.assertEqual(env['PATH'], 'retained')
        self.assertEqual(env['NODE_OPTIONS'], '--trace-warnings')
        self.assertIn('--proxy-server=http://127.0.0.1:10809', command)

    def test_gui_isolated_profile_also_strips_node_mode(self):
        command, env, _ = self.prepare({'ELECTRON_RUN_AS_NODE': '1'}, original=False)
        self.assertNotIn('ELECTRON_RUN_AS_NODE', env)
        self.assertTrue(any(v.startswith('--user-data-dir=') for v in command))

    def test_gemini_gui_strips_node_mode_without_chromium_flags(self):
        for adapter in ('chromium', 'environment'):
            with self.subTest(adapter=adapter):
                command, env, _ = self.prepare({'eLeCtRoN_rUn_As_NoDe': '1'},
                                               adapter=adapter, gemini=True)
                self.assertNotIn('eLeCtRoN_rUn_As_NoDe', env)
                self.assertFalse(any(v.startswith('--proxy-server') for v in command))
                self.assertFalse(any(v.startswith('--user-data-dir') for v in command))

    def test_generic_environment_adapter_retains_explicit_node_mode(self):
        _, env, _ = self.prepare({'ELECTRON_RUN_AS_NODE': '1'}, adapter='environment')
        self.assertEqual(env['ELECTRON_RUN_AS_NODE'], '1')

    def test_console_reclassification_retains_explicit_node_mode(self):
        command, env, _ = self.prepare({'ELECTRON_RUN_AS_NODE': '1'}, console=True)
        self.assertEqual(env['ELECTRON_RUN_AS_NODE'], '1')
        self.assertFalse(any(v.startswith('--proxy-server') for v in command))

    def test_unrelated_launch_modes_are_unchanged(self):
        for options in ({'platform': 'linux', 'original': False}, {'native_proxy': False},
                        {'transparent': False}):
            with self.subTest(options=options):
                _, env, _ = self.prepare({'ELECTRON_RUN_AS_NODE': '1'}, **options)
                self.assertEqual(env['ELECTRON_RUN_AS_NODE'], '1')

    def test_no_contamination_preserves_gui_proxy_configuration(self):
        command, env, _ = self.prepare({'PATH': 'retained'})
        self.assertEqual(env['PATH'], 'retained')
        self.assertEqual(env['HTTPS_PROXY'], 'http://127.0.0.1:10809')
        self.assertIn('--disable-quic', command)


if __name__ == '__main__':
    unittest.main()
