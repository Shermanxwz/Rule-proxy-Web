"""Persisted state failures must not prevent opening or silently lose recovery data."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy.launcher import prepare_app
from ruleproxy.manager import Manager, MAX_APPS


class SavedStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        discovery = patch("ruleproxy.manager.discover_apps", return_value=[])
        discovery.start()
        self.addCleanup(discovery.stop)

    def open_panel(self):
        manager = Manager(self.directory, 18879)
        self.addCleanup(manager.close)
        manager._probe_cache = {"supported": False, "detail": "test", "limitations": []}
        return manager

    def record(self, **overrides):
        return {"id": "saved-app", "label": "浏览器", "path": str(self.directory / "missing-app.exe"),
                "adapter": "chromium", "args": [], "enabled": True, **overrides}

    def save(self, value):
        text = json.dumps(value, ensure_ascii=True)
        (self.directory / "settings.json").write_text(text, encoding="utf-8")
        return text

    def test_corrupt_settings_open_with_defaults_and_original_is_backed_up_on_save(self):
        path = self.directory / "settings.json"
        original = b'{"apps": ['
        path.write_bytes(original)
        manager = self.open_panel()
        self.assertEqual(manager.settings["apps"], [])
        self.assertTrue(manager.state()["warnings"])
        self.assertEqual(path.read_bytes(), original)
        manager.save_settings({"core_path": ""})
        backups = list(self.directory.glob("settings.recovery-*.json"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), original)
        self.assertEqual(json.loads(path.read_text())["apps"], [])
        manager.save_settings({"core_path": ""})
        self.assertEqual(len(list(self.directory.glob("settings.recovery-*.json"))), 1)

    def test_a_failed_save_restores_the_original_corrupt_settings(self):
        path = self.directory / "settings.json"
        path.write_bytes(b"broken")
        manager = self.open_panel()
        with patch("ruleproxy.manager.write_private", side_effect=PermissionError("cannot write")):
            with self.assertRaises(PermissionError):
                manager.save_settings({"core_path": ""})
        self.assertEqual(path.read_bytes(), b"broken")
        self.assertEqual(list(self.directory.glob("settings.recovery-*.json")), [])

    def test_missing_executable_keeps_the_app_id_shortcuts_and_existing_profile(self):
        record = self.record(shortcuts=[str(self.directory / "浏览器 (RuleProxy).lnk")])
        self.save({"apps": [record]})
        profile = self.directory / "profiles" / record["id"]
        profile.mkdir(parents=True)
        (profile / "login-data").write_bytes(b"keep")
        manager = self.open_panel()
        self.assertEqual(manager.settings["apps"], [record])
        self.assertEqual((profile / "login-data").read_bytes(), b"keep")
        self.assertEqual(manager.state()["warnings"], [])
        with self.assertRaisesRegex(ValueError, "找不到这个程序"):
            prepare_app(record, 10809, self.directory / "profiles")

    def test_invalid_and_duplicate_records_cannot_break_the_state_api(self):
        first = self.record()
        bad = [None, {}, self.record(id="../escape"), self.record(enabled="yes"),
               self.record(label="\ud800"), self.record(args=["\ud800"]),
               self.record(id="second", path="relative.exe"), self.record(id="second", adapter="unknown"),
               self.record(id="second", path=first["path"]), first]
        self.save({"apps": [first, *bad], "core_path": [], "runtime_path": 1, "selected_node": {}})
        manager = self.open_panel()
        expected = {**first, "active": False, "cleanup_pending": False, "profile_preparing": False}
        if sys.platform == "win32":
            expected["routed"] = False
        self.assertEqual(manager.state()["apps"], [expected])
        self.assertEqual(manager.settings["core_path"], "")
        self.assertEqual(manager.settings["runtime_path"], "")
        self.assertIsNone(manager.settings["selected_node"])
        self.assertTrue(manager.state()["warnings"])

    def test_invalid_shortcut_metadata_is_dropped_without_discarding_the_app(self):
        self.save({"apps": [self.record(shortcuts="not a list")]})
        manager = self.open_panel()
        self.assertNotIn("shortcuts", manager.settings["apps"][0])
        self.assertTrue(manager.state()["warnings"])

    def test_oversized_or_invalid_utf8_settings_do_not_prevent_starting(self):
        path = self.directory / "settings.json"
        for data in (b" " * 101, b"\xff", b"[]"):
            with self.subTest(data=data[:10]):
                path.write_bytes(data)
                with patch("ruleproxy.manager.MAX_SETTINGS_BYTES", 100):
                    manager = self.open_panel()
                self.assertTrue(manager.state()["warnings"])
                manager.close()

    def test_oversized_or_invalid_utf8_yaml_leaves_the_panel_open_for_reimport(self):
        path = self.directory / "source.yaml"
        for data in (b" " * 101, b"\xff"):
            with self.subTest(data=data[:10]):
                path.write_bytes(data)
                with patch("ruleproxy.manager.MAX_SOURCE_BYTES", 100):
                    manager = self.open_panel()
                self.assertFalse(manager.state()["imported"])
                self.assertIn("请重新导入", manager.state()["error"])
                self.assertEqual(path.read_bytes(), data)
                manager.close()

    def test_app_count_is_bounded_on_restore_and_add(self):
        records = [self.record(id=f"app-{n}", path=str(self.directory / f"app-{n}.exe"))
                   for n in range(MAX_APPS + 1)]
        self.save({"apps": records})
        manager = self.open_panel()
        self.assertEqual(len(manager.state()["apps"]), MAX_APPS)
        self.assertTrue(manager.state()["warnings"])
        with self.assertRaisesRegex(ValueError, str(MAX_APPS)):
            manager.add_app(records[-1])
