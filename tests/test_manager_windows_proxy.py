"""Product policy updates and transparent launch ordering, without a driver."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from ruleproxy.manager import Manager


class WindowsManagerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = Manager(Path(self.directory.name), 18879)
        self.addCleanup(self.manager.close)
        self.backend = Mock()
        self.backend.probe.return_value = {"supported": True, "backend": "ProxiFyre"}
        self.backend.snapshot.return_value = {"state": "running"}
        self.manager._windows_backend = self.backend
        self.app = {"id": "app", "label": "App", "path": r"C:\Apps\app.exe",
                    "adapter": "environment", "args": [], "enabled": True,
                    "related_paths": [r"C:\Apps\helper.exe"]}
        self.manager.settings["apps"] = [dict(self.app)]
        self.platform = patch("ruleproxy.manager.sys.platform", "win32")
        self.platform.start()
        self.addCleanup(self.platform.stop)

    def use_core(self):
        self.manager.core = Mock(pid=1234, poll=Mock(return_value=None))

    def tearDown(self):
        self.manager.active.clear()
        self.manager.core = None
        # Injected backend failures belong to the test, not Manager.close in
        # addCleanup after the simulated platform restores to native Windows.
        self.backend.reset_mock(side_effect=True)

    def test_policy_covers_related_images_without_launching_them(self):
        self.use_core()
        self.manager._sync_windows_policy()
        self.backend.apply.assert_called_once_with(
            [self.app["path"], self.app["related_paths"][0]], self.manager.mixed_port, 1234)
        self.assertEqual(self.manager.active, {})

    def test_disabling_last_app_stops_routing_while_retaining_core(self):
        self.use_core()
        self.manager.change_app("app", enabled=False)
        self.backend.stop.assert_called_once()
        self.assertIsNotNone(self.manager.core)
        self.assertFalse(self.manager.app("app")["enabled"])

    def test_failed_rule_change_restores_previous_settings_and_policy(self):
        self.use_core()
        self.backend.stop.side_effect = OSError("engine did not stop")
        with self.assertRaisesRegex(OSError, "did not stop"):
            self.manager.change_app("app", enabled=False)
        self.assertTrue(self.manager.app("app")["enabled"])
        self.backend.apply.assert_called_once_with(
            [self.app["path"], self.app["related_paths"][0]], self.manager.mixed_port, 1234)

    def test_launch_applies_policy_before_an_ordinary_process_is_started(self):
        self.use_core()
        order = []
        process = Mock(pid=5678, poll=Mock(return_value=None))
        self.backend.apply.side_effect = lambda *args: order.append("policy")
        with patch("ruleproxy.manager.prepare_app", return_value=([self.app["path"]], {}, "")) as prepare, \
                patch("ruleproxy.windows_app_process.launch", side_effect=lambda *args: order.append("app") or process):
            result = self.manager.launch("app")
        self.assertEqual(order, ["policy", "app"])
        self.assertEqual(result["pid"], 5678)
        self.assertIn("transparent", prepare.call_args.kwargs)
        self.assertIsNone(self.manager.active["app"][1])

    def test_policy_failure_never_starts_app(self):
        self.use_core()
        self.backend.apply.side_effect = OSError("driver unavailable")
        with patch("ruleproxy.manager.prepare_app", return_value=([self.app["path"]], {}, "")), \
                patch("ruleproxy.windows_app_process.launch") as launch:
            with self.assertRaisesRegex(OSError, "driver unavailable"):
                self.manager.launch("app")
        launch.assert_not_called()

    def test_registered_package_refreshes_entry_and_routes_all_helpers_before_launch(self):
        self.use_core()
        binding = {'package_family_name': 'Vendor.Product_publisher', 'application_id': 'Main',
                   'scope': 'package'}
        app = self.manager.app('app')
        app.update(store_binding=binding, related_paths=[])
        family = SimpleNamespace(entry_path=r'C:\NewVersion\main.exe',
                                 paths=(r'C:\NewVersion\main.exe', r'C:\NewVersion\resources\token.exe'))
        process = Mock(pid=5678, poll=Mock(return_value=None))
        with patch('ruleproxy.windows_app_family.resolve_store_family', return_value=family) as resolve, \
                patch('ruleproxy.manager.prepare_app', return_value=([family.entry_path], {}, '')) as prepare, \
                patch('ruleproxy.windows_app_process.launch', return_value=process):
            self.manager.launch('app')
        resolve.assert_called_once_with(binding)
        self.assertEqual(app['path'], family.entry_path)
        self.assertEqual(self.backend.apply.call_args.args[0], list(family.paths))
        self.assertEqual(prepare.call_args.args[0]['path'], family.entry_path)
        self.assertTrue(prepare.call_args.kwargs['native_proxy'])

    def test_package_resolution_failure_never_launches_or_partially_updates_paths(self):
        self.use_core()
        binding = {'package_family_name': 'Vendor.Product_publisher', 'application_id': 'Main',
                   'scope': 'package'}
        first = self.manager.app('app')
        first['store_binding'] = binding
        self.manager.settings['apps'].append({**first, 'id': 'other', 'path': r'C:\Other\main.exe',
                                             'store_binding': {**binding, 'application_id': 'Other'}})
        family = SimpleNamespace(entry_path=r'C:\Updated\main.exe', paths=(r'C:\Updated\main.exe',))
        with patch('ruleproxy.windows_app_family.resolve_store_family',
                   side_effect=[family, ValueError('package registration is ambiguous')]), \
                patch('ruleproxy.windows_app_process.launch') as launch:
            with self.assertRaisesRegex(ValueError, 'ambiguous'):
                self.manager.launch('app')
        self.assertEqual(first['path'], self.app['path'])
        self.backend.apply.assert_not_called()
        launch.assert_not_called()

    def test_existing_old_package_paths_remain_selected_across_repeated_version_refreshes(self):
        with tempfile.TemporaryDirectory() as directory:
            old, helper, current = (Path(directory) / name for name in ('old.exe', 'helper.exe', 'new.exe'))
            for path in (old, helper, current):
                path.touch()
            app = self.manager.app('app')
            app.update(path=str(old), related_paths=[], store_binding={
                'package_family_name': 'Vendor.Product_publisher', 'application_id': 'Main', 'scope': 'package'})
            first = SimpleNamespace(entry_path=str(old), paths=(str(old), str(helper)))
            newer = SimpleNamespace(entry_path=str(current), paths=(str(current),))
            with patch('ruleproxy.windows_app_family.resolve_store_family', side_effect=[first, newer, newer]):
                self.manager._selected_windows_paths()
                second = self.manager._selected_windows_paths()
                third = self.manager._selected_windows_paths()
            self.assertEqual(set(second), {str(old), str(helper), str(current)})
            self.assertEqual(set(second), set(third))
            self.assertEqual(app['path'], str(current))

    def test_store_executable_is_the_policy_and_launch_target_before_resume(self):
        self.use_core()
        path = r'C:\Program Files\WindowsApps\OpenAI.ChatGPT_1.2.3_x64__publisher\app\ChatGPT.exe'
        self.manager.settings['apps'][0].update(path=path, related_paths=[])
        order = []
        process = Mock(pid=5678, poll=Mock(return_value=None))
        self.backend.apply.side_effect = lambda *args: order.append(('policy', args[0]))
        with patch('ruleproxy.manager.prepare_app', return_value=([path], {}, '')), \
                patch('ruleproxy.windows_app_process.launch',
                      side_effect=lambda command, env: order.append(('launch', command)) or process):
            self.manager.launch('app')
        self.assertEqual(order, [('policy', [path]), ('launch', [path])])

    def test_stop_order_is_owned_apps_then_routing_then_core(self):
        self.use_core()
        order = []
        process = Mock()
        process.terminate.side_effect = lambda: order.append("app")
        self.manager.active["app"] = (process, None)
        self.backend.stop.side_effect = lambda: order.append("routing")
        with patch("ruleproxy.manager.stop_process", side_effect=lambda core: order.append("core")):
            self.manager.stop()
        self.assertEqual(order, ["app", "routing", "core"])


if __name__ == "__main__":
    unittest.main()
