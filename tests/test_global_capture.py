"""Global mode: the user's system proxy points at the local core; no TUN."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from ruleproxy import system_proxy
from ruleproxy.config import compile_config
from ruleproxy.manager import Manager

SOURCE = '''proxies:
  - name: Node
    type: socks5
    server: proxy.example.test
    port: 1080
rules: ['MATCH,DIRECT']
'''


class FakeDesktop:
    """In-memory system proxy settings standing in for WinINet/gsettings."""

    def __init__(self):
        self.values = {'mode': 'none'}
        self.writes = []

    def backend(self):
        return ('fake', lambda: dict(self.values), self.write,
                lambda port: {'mode': 'manual', 'port': port},
                lambda port: self.values == {'mode': 'manual', 'port': port})

    def write(self, values):
        self.writes.append(dict(values))
        self.values = dict(values)


class GlobalCompilerTests(unittest.TestCase):
    def test_global_never_enables_tun_or_imported_controls(self):
        source = SOURCE + 'tun: {enable: true, exclude-uid: [1000]}\nlisteners: [{type: tun, name: injected}]\n'
        for mode in ('applications', 'global'):
            with self.subTest(mode=mode):
                config = compile_config(source, secret='test', capture_mode=mode).config
                self.assertEqual(config['tun'], {'enable': False})
                self.assertEqual(config['dns']['proxy-server-nameserver'], ['system'])
                self.assertEqual([item['type'] for item in config['listeners']], ['mixed'])
                self.assertEqual(config['listeners'][0]['listen'], '127.0.0.1')
        self.assertEqual(compile_config(source, secret='test', capture_mode='global').config['rules'],
                         ['MATCH,RuleProxySelected'])

    def test_unknown_modes_are_not_silently_downgraded(self):
        for mode in (None, True, '', 'tun', 'GLOBAL', {}, []):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                compile_config(SOURCE, secret='test', capture_mode=mode)


class SystemProxyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.desktop = FakeDesktop()
        patcher = patch.object(system_proxy, '_backend', side_effect=self.desktop.backend)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_enable_saves_previous_settings_and_restore_puts_them_back(self):
        system_proxy.enable(self.directory, 10809)
        self.assertEqual(self.desktop.values, {'mode': 'manual', 'port': 10809})
        self.assertTrue((self.directory / system_proxy.BACKUP).exists())
        self.assertTrue(system_proxy.restore(self.directory))
        self.assertEqual(self.desktop.values, {'mode': 'none'})
        self.assertFalse((self.directory / system_proxy.BACKUP).exists())
        self.assertFalse(system_proxy.restore(self.directory))

    def test_second_enable_after_crash_keeps_the_original_backup(self):
        system_proxy.enable(self.directory, 10809)
        system_proxy.enable(self.directory, 10810)
        system_proxy.restore(self.directory)
        self.assertEqual(self.desktop.values, {'mode': 'none'})

    def test_settings_changed_by_the_user_are_not_overwritten(self):
        system_proxy.enable(self.directory, 10809)
        self.desktop.values = {'mode': 'manual', 'port': 3128}
        system_proxy.restore(self.directory)
        self.assertEqual(self.desktop.values, {'mode': 'manual', 'port': 3128})
        self.assertFalse((self.directory / system_proxy.BACKUP).exists())

    def test_failed_write_restores_immediately(self):
        original = self.desktop.write
        def broken(values):
            if values.get('mode') == 'manual':
                self.desktop.values = {'mode': 'manual', 'port': 10809}
                raise OSError('denied')
            original(values)
        self.desktop.write = broken
        with self.assertRaises(OSError):
            system_proxy.enable(self.directory, 10809)
        self.assertEqual(self.desktop.values, {'mode': 'none'})
        self.assertFalse((self.directory / system_proxy.BACKUP).exists())

    def test_corrupt_backup_is_dropped_without_touching_settings(self):
        (self.directory / system_proxy.BACKUP).write_text('{', encoding='utf-8')
        self.assertTrue(system_proxy.restore(self.directory))
        self.assertEqual(self.desktop.writes, [])


class GlobalManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.temp.name), 18879)
        self.manager._probe_cache = {'supported': False}
        self.legacy = Mock()
        self.legacy.status.return_value = {'supported': False, 'running': False, 'state': 'setup_required'}
        self.manager._global_backend = self.legacy

    def tearDown(self):
        with patch.object(system_proxy, 'restore'):
            self.manager.close()
        self.temp.cleanup()

    def test_mode_and_node_survive_restore_and_compile_without_tun(self):
        self.manager.import_yaml(SOURCE)
        with patch('subprocess.Popen') as popen:
            self.manager.set_capture_mode('global')
        popen.assert_not_called()
        saved = json.loads((Path(self.temp.name) / 'settings.json').read_text())
        self.assertEqual(saved['capture_mode'], 'global')
        self.assertEqual(saved['selected_node'], 'Node')
        self.assertEqual(self.manager.compiled.config['tun'], {'enable': False})

    def test_failed_mode_save_restores_old_compilation_and_mode(self):
        self.manager.import_yaml(SOURCE)
        before = self.manager.compiled
        with patch.object(self.manager, '_save', side_effect=OSError('disk full')):
            with self.assertRaises(OSError):
                self.manager.set_capture_mode('global')
        self.assertEqual(self.manager.capture_mode, 'applications')
        self.assertIs(self.manager.compiled, before)

    def test_switch_is_blocked_while_apps_are_owned(self):
        self.manager.active = {'a': (Mock(), None)}
        try:
            with self.assertRaises(ValueError):
                self.manager.set_capture_mode('global')
        finally:
            self.manager.active = {}

    def test_protection_reports_the_system_proxy_backend(self):
        self.manager.set_capture_mode('global')
        with patch.object(system_proxy, 'available', return_value=(True, 'ok')):
            status = self.manager.protection()
        self.assertEqual((status['supported'], status['backend']), (True, '系统代理'))
        self.legacy.status.assert_not_called()

    def test_stop_restores_system_proxy_and_releases_only_active_legacy_state(self):
        self.manager.set_capture_mode('global')
        with patch.object(system_proxy, 'restore') as restore:
            self.manager.stop()
        restore.assert_called_once_with(self.manager.directory)
        self.legacy.stop.assert_not_called()
        self.legacy.status.return_value = {'supported': True, 'running': False, 'state': 'blocked',
                                           'protection_active': True}
        with patch.object(system_proxy, 'restore'):
            self.manager.stop()
        self.legacy.stop.assert_called_once()

    def test_legacy_cleanup_failure_still_restores_the_proxy_and_reports(self):
        self.manager.set_capture_mode('global')
        self.legacy.status.return_value = {'running': False, 'state': 'unknown'}
        self.legacy.stop.side_effect = RuntimeError('service gone')
        with patch.object(system_proxy, 'restore') as restore:
            self.manager.stop()
        restore.assert_called_once()
        self.assertIn('service gone', self.manager.error)

    def test_panel_start_recovers_a_crashed_session(self):
        self.manager.set_capture_mode('global')
        with patch.object(system_proxy, 'restore') as restore:
            self.manager._recover_global()
        restore.assert_called_once_with(self.manager.directory)

    def test_global_launch_hands_the_proxy_to_apps(self):
        self.manager.import_yaml(SOURCE)
        self.manager.set_capture_mode('global')
        self.manager.core = Mock(pid=1, poll=Mock(return_value=None))
        self.manager.settings['apps'] = [{'id': 'app', 'label': 'App', 'path': '/bin/true',
                                          'adapter': 'firefox', 'args': [], 'enabled': True}]
        with patch('ruleproxy.manager.prepare_app', return_value=(['/bin/true'], {}, '')) as prepare, \
                patch.object(self.manager, 'protection', return_value={'supported': True}), \
                patch('subprocess.Popen', return_value=Mock(pid=7, poll=Mock(return_value=None))), \
                patch('ruleproxy.windows_app_process.launch', create=True,
                      return_value=Mock(pid=7, poll=Mock(return_value=None))):
            self.manager.launch('app')
        options = prepare.call_args.kwargs
        self.assertEqual((options['native_proxy'], options['system_proxy']), (True, True))
        self.manager.active.clear()
        self.manager.core = None


if __name__ == '__main__':
    unittest.main()
