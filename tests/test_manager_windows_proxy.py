"""Product policy updates and transparent launch ordering, without a driver."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

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
