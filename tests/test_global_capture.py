"""Mode transitions and privileged-core ownership boundaries."""
import json
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from ruleproxy.config import compile_config
from ruleproxy.global_runtime import ManagedGlobalCore
from ruleproxy.manager import Manager

SOURCE = '''proxies:
  - name: Node
    type: socks5
    server: proxy.example.test
    port: 1080
rules: ['MATCH,DIRECT']
'''


class GlobalCompilerTests(unittest.TestCase):
    def test_global_enables_owned_dual_stack_tun_and_remote_dns_without_imported_controls(self):
        source = SOURCE + 'tun: {enable: false, exclude-uid: [1000]}\nlisteners: [{type: tun, name: injected}]\n'
        app = compile_config(source, secret='test', capture_mode='applications').config
        full = compile_config(source, secret='test', capture_mode='global').config
        self.assertEqual(app['tun'], {'enable': False})
        self.assertTrue(full['tun']['enable'])
        self.assertTrue(full['ipv6'])
        self.assertTrue(full['tun']['strict-route'])
        self.assertEqual(full['tun']['dns-hijack'], ['any:53', 'tcp://any:53'])
        self.assertNotIn('exclude-uid', full['tun'])
        self.assertEqual(full['dns']['proxy-server-nameserver'], ['https://1.1.1.1/dns-query#DIRECT'])
        self.assertEqual(full['rules'], ['MATCH,RuleProxySelected'])
        self.assertEqual(full['listeners'][0]['listen'], '127.0.0.1')

    def test_unknown_modes_are_not_silently_downgraded(self):
        for mode in (None, True, '', 'tun', 'GLOBAL', {}, []):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                compile_config(SOURCE, secret='test', capture_mode=mode)


class GlobalManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.temp.name), 18879)
        self.manager._probe_cache = {'supported': False}
        self.backend = Mock()
        self.backend.status.return_value = {'supported': True, 'running': False, 'state': 'idle'}
        self.backend.start.return_value = {'supported': True, 'running': True, 'pid': 64213, 'state': 'running'}
        self.backend.stop.return_value = {'running': False, 'state': 'idle'}
        self.manager._global_backend = self.backend

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def test_mode_and_node_survive_restore_and_do_not_launch_a_core(self):
        self.manager.import_yaml(SOURCE)
        with patch('subprocess.Popen') as popen:
            self.manager.set_capture_mode('global')
        popen.assert_not_called()
        saved = json.loads((Path(self.temp.name) / 'settings.json').read_text())
        self.assertEqual(saved['capture_mode'], 'global')
        self.assertEqual(saved['selected_node'], 'Node')
        self.assertTrue(self.manager.compiled.config['tun']['enable'])
        self.manager.set_capture_mode('applications')
        self.assertFalse(self.manager.compiled.config['tun']['enable'])

    def test_failed_mode_save_restores_old_compilation_and_mode(self):
        self.manager.import_yaml(SOURCE)
        before = self.manager.compiled
        with patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.manager.set_capture_mode('global')
        self.assertEqual(self.manager.capture_mode, 'applications')
        self.assertIs(self.manager.compiled, before)

    def test_switch_is_blocked_while_apps_or_fault_guard_are_owned(self):
        for attribute, value in (('active', {'a': (Mock(), None)}), ('_global_fault', True)):
            with self.subTest(attribute=attribute):
                previous = getattr(self.manager, attribute)
                setattr(self.manager, attribute, value)
                try:
                    with self.assertRaises(ValueError):
                        self.manager.set_capture_mode('global')
                finally:
                    setattr(self.manager, attribute, previous)

    def test_global_start_delegates_to_helper_and_never_launches_a_privileged_user_command(self):
        self.manager.import_yaml(SOURCE)
        self.manager.set_capture_mode('global')
        with patch('subprocess.Popen') as popen, patch.object(self.manager, 'core_path') as path:
            self.manager.start()
        popen.assert_not_called(); path.assert_not_called()
        self.assertIsInstance(self.manager.core, ManagedGlobalCore)
        self.assertEqual(self.manager.core.pid, 64213)
        self.backend.start.assert_called_once_with(SOURCE, self.manager.secret, 10809, 19097, 'Node',
                                                 **({'require_strict': True} if sys.platform == 'win32' else {}))

    def test_start_failure_retains_guard_until_explicit_stop(self):
        self.manager.import_yaml(SOURCE)
        self.manager.set_capture_mode('global')
        self.backend.start.side_effect = RuntimeError('core failed')
        self.backend.status.side_effect = [
            {'supported': True, 'running': False},
            {'supported': True, 'running': False, 'state': 'blocked', 'protection_active': True}]
        with self.assertRaises(RuntimeError):
            self.manager.start()
        self.backend.stop.assert_not_called()
        self.assertTrue(self.manager._global_fault)
        self.manager.stop()
        self.backend.stop.assert_called_once()
        self.assertFalse(self.manager._global_fault)

    def test_global_node_changes_use_closed_helper_operation_not_root_controller(self):
        self.manager.import_yaml(SOURCE)
        self.manager.set_capture_mode('global')
        self.manager.start()
        with patch.object(self.manager, '_controller') as controller:
            self.manager.select_node('Node')
        controller.assert_not_called()
        self.backend.select_node.assert_called_once_with('Node')

    def test_unknown_guard_state_is_explicitly_recovered_instead_of_reporting_a_successful_stop(self):
        self.manager.set_capture_mode('global')
        self.backend.status.return_value = {'supported': True, 'running': False, 'state': 'unknown'}
        self.backend.stop.side_effect = RuntimeError('recovery unavailable')
        with self.assertRaisesRegex(RuntimeError, 'recovery unavailable'):
            self.manager.stop()
        self.backend.stop.assert_called_once()
        self.backend.stop.side_effect = None

    def test_global_store_launch_refreshes_registered_entry_without_app_path_routing(self):
        self.manager.import_yaml(SOURCE)
        self.manager.set_capture_mode('global')
        self.manager.start()
        binding = {'package_family_name': 'Vendor.App_publisher', 'application_id': 'Main', 'scope': 'package'}
        app = {'id': 'app', 'label': 'Store application', 'path': r'C:\OldVersion\main.exe',
               'adapter': 'chromium', 'args': [], 'enabled': True, 'store_binding': binding}
        self.manager.settings['apps'] = [app]
        current = r'C:\CurrentVersion\main.exe'
        with patch('ruleproxy.manager.sys.platform', 'win32'), \
                patch('ruleproxy.windows_app_family.resolve_store_family', return_value=SimpleNamespace(entry_path=current)), \
                patch('ruleproxy.manager.prepare_app', return_value=([current], {}, '')) as prepare, \
                patch('ruleproxy.windows_app_process.launch', return_value=Mock(pid=5234, poll=Mock(return_value=None))), \
                patch.object(self.manager, 'windows_backend') as application_backend:
            self.manager.launch('app')
        application_backend.assert_not_called()
        self.assertEqual(app['path'], current)
        self.assertFalse(prepare.call_args.kwargs['native_proxy'])
        self.manager.active.clear()

    def test_managed_process_does_not_implicitly_release_the_guard_on_loss(self):
        core = ManagedGlobalCore(self.backend, self.backend.start.return_value)
        self.backend.status.return_value = {'running': False, 'state': 'blocked'}
        core._checked = 0
        self.assertEqual(core.poll(), 1)
        self.backend.stop.assert_not_called()
        self.assertFalse(hasattr(core, 'terminate'))


if __name__ == '__main__':
    unittest.main()
