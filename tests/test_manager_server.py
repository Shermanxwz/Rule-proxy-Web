import json
from pathlib import Path
import socket
import os
import sys
import time
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

from ruleproxy.manager import Manager
from ruleproxy.server import Handler


SOURCE = Path(__file__).resolve().parents[1] / "examples/ruleproxy.example.yaml"


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.temp.name), 18879)
        self.manager._probe_cache = {"supported": False, "backend": "test", "detail": "blocked", "limitations": []}

    def tearDown(self):
        self.manager.close()
        self.temp.cleanup()

    def test_import_saves_only_private_data_and_safe_compiled_settings(self):
        with patch("subprocess.Popen") as popen:
            self.manager.import_yaml(SOURCE.read_text())
        popen.assert_not_called()
        state = self.manager.state()
        self.assertTrue(state["imported"])
        self.assertFalse(state["running"])
        self.assertNotIn("secret", state)
        self.assertNotIn("yaml", state)
        self.assertFalse(self.manager.compiled.config["tun"]["enable"])

    def test_invalid_import_preserves_previous_source(self):
        self.manager.import_yaml(SOURCE.read_text())
        before = self.manager.source
        with self.assertRaises(ValueError):
            self.manager.import_yaml("proxies: []")
        self.assertEqual(self.manager.source, before)

    def test_start_requires_config_and_missing_core_fails_without_spawning(self):
        with patch("subprocess.Popen") as popen:
            with self.assertRaises(ValueError):
                self.manager.start()
            self.manager.import_yaml(SOURCE.read_text())
            self.manager.settings["core_path"] = str(Path(self.temp.name) / "missing")
            with self.assertRaises(ValueError):
                self.manager.start()
        popen.assert_not_called()

    def test_node_selection_rejects_direct(self):
        self.manager.import_yaml(SOURCE.read_text())
        with self.assertRaises(ValueError):
            self.manager.select_node("DIRECT")

    def test_stop_closes_only_owned_instances_before_core(self):
        app, core = Mock(), Mock()
        resource = Mock()
        self.manager.active["test"] = (app, resource)
        self.manager.core = core
        events = []

        def record(proc):
            events.append(proc)

        # Linux stops sandboxed apps through linux_runtime.stop; the core still uses stop_process.
        with patch("ruleproxy.manager.stop_process", side_effect=record), patch("ruleproxy.linux_runtime.stop", side_effect=record):
            self.manager.stop()
        self.assertEqual(events, [app, core])
        resource.close.assert_called_once()
        self.assertIsNone(self.manager.core)

    def test_windows_stop_failure_retains_guard_and_core(self):
        from ruleproxy.windows_runtime import SafeStopError
        app, core, resource = Mock(), Mock(), Mock()
        self.manager.active["test"] = (app, resource)
        self.manager.core = core
        try:
            with patch("ruleproxy.manager.sys.platform", "win32"), patch("ruleproxy.windows_runtime.stop", side_effect=SafeStopError("close the isolated window")), patch("ruleproxy.manager.stop_process") as stop_process:
                with self.assertRaises(SafeStopError):
                    self.manager.stop()
                stop_process.assert_not_called()
            self.assertIs(self.manager.core, core)
            self.assertIn("test", self.manager.active)
            resource.close.assert_not_called()
        finally:
            self.manager.active.clear()
            self.manager.core = None

    @unittest.skipUnless(sys.platform == "linux", "Linux desktop entries")
    def test_shortcuts_are_recorded_and_removed_with_the_app(self):
        executable = Path(self.temp.name) / "bin" / "chatgpt"
        executable.parent.mkdir()
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        home = Path(self.temp.name) / "home"
        home.mkdir()
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(Path(self.temp.name) / "data"), "HOME": str(home)}):
            self.manager.add_app({"label": "ChatGPT", "path": str(executable), "adapter": "chromium"})
            ident = self.manager.settings["apps"][0]["id"]
            created = self.manager.create_shortcuts(ident)
            self.assertEqual(len(created), 1)
            self.assertTrue(Path(created[0]).is_file())
            self.assertEqual(self.manager.app(ident)["shortcuts"], created)
            self.manager.change_app(ident, delete=True)
        self.assertFalse(Path(created[0]).exists())
        self.assertEqual(self.manager.settings["apps"], [])

    @unittest.skipUnless(sys.platform == "linux", "Linux launch-owner regression")
    def test_isolation_survives_short_lived_request_thread(self):
        from ruleproxy.linux_runtime import probe
        if not probe()["supported"]:
            self.skipTest("namespace isolation unavailable")
        executable = Path(self.temp.name) / "app-bin/probe"
        executable.parent.mkdir()
        executable.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(10)\n")
        executable.chmod(0o755)
        self.manager.add_app({"label": "probe", "path": str(executable), "adapter": "environment"})
        self.manager._probe_cache["supported"] = True
        self.manager.core = Mock()
        self.manager.core.poll.return_value = None
        ident = self.manager.settings["apps"][0]["id"]
        result = []
        def request_thread():
            with patch.dict(os.environ, {"DISPLAY": "", "WAYLAND_DISPLAY": ""}):
                result.append(self.manager.launch(ident))
        worker = threading.Thread(target=request_thread)
        worker.start()
        worker.join(timeout=10)
        self.assertFalse(worker.is_alive())
        self.assertTrue(result)
        time.sleep(0.15)
        self.assertIsNone(self.manager.active[ident][0].poll())
        self.manager.stop_app(ident)
        # The mocked core isn't an OS process.
        self.manager.core = None


class LocalServerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.manager = Manager(Path(self.temp.name), self.server.server_port)
        self.manager._probe_cache = {"supported": False, "backend": "test", "detail": "blocked", "limitations": []}
        self.server.manager = self.manager
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.manager.close()
        self.temp.cleanup()

    def request(self, path, payload=None, **headers):
        headers.setdefault("Content-Type", "application/json")
        request = urllib.request.Request(self.base + path, data=json.dumps(payload).encode() if payload is not None else None, headers=headers)
        return urllib.request.urlopen(request, timeout=5)

    def test_state_and_static_are_available_only_to_local_host(self):
        with self.request("/api/state") as response:
            self.assertIn("token", json.load(response))
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request("/api/state", **{"Host": "evil.example"})
        self.assertEqual(error.exception.code, 403)

    def test_mutation_rejects_missing_token_and_wrong_origin(self):
        for headers in ({}, {"X-RuleProxy-Token": self.manager.token, "Origin": "https://evil.example"}):
            with self.assertRaises(urllib.error.HTTPError) as error:
                self.request("/api/import", {"yaml": SOURCE.read_text()}, **headers)
            self.assertEqual(error.exception.code, 403)
        self.assertIsNone(self.manager.source)

    def test_authorized_import_and_invalid_payload(self):
        with self.request("/api/import", {"yaml": SOURCE.read_text()}, **{"X-RuleProxy-Token": self.manager.token}) as response:
            self.assertTrue(json.load(response)["imported"])
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request("/api/import", {"yaml": "bad"}, **{"X-RuleProxy-Token": self.manager.token})
        self.assertEqual(error.exception.code, 400)

    def app_with_executable(self):
        executable = Path(self.temp.name) / "bin" / f"chrome-{len(self.manager.settings['apps'])}"
        executable.parent.mkdir(exist_ok=True)
        executable.write_text("#!/bin/sh\n")
        executable.chmod(0o755)
        self.manager.add_app({"label": "Chrome", "path": str(executable), "adapter": "chromium"})
        return self.manager.settings["apps"][-1]["id"]

    def test_shortcut_endpoint_requires_the_token(self):
        ident = self.app_with_executable()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(f"/api/apps/{ident}/shortcut", {})
        self.assertEqual(error.exception.code, 403)

    def test_apps_cannot_be_pointed_at_another_browser_profile(self):
        ident = self.app_with_executable()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request(f"/api/apps/{ident}/data-dir", {"path": str(self.temp.name), "acknowledged": True}, **{"X-RuleProxy-Token": self.manager.token})
        self.assertEqual(error.exception.code, 404)

    @unittest.skipUnless(sys.platform == "linux", "Linux desktop entries")
    def test_shortcut_endpoint_writes_the_launcher_file(self):
        ident = self.app_with_executable()
        with patch.dict(os.environ, {"XDG_DATA_HOME": str(Path(self.temp.name) / "data"), "HOME": str(Path(self.temp.name) / "home")}):
            with self.request(f"/api/apps/{ident}/shortcut", {}, **{"X-RuleProxy-Token": self.manager.token}) as response:
                body = json.load(response)
        self.assertEqual(len(body["created"]), 1)
        launcher = Path(body["created"][0])
        self.assertTrue(launcher.is_file())
        self.assertIn("--launch-app " + ident, launcher.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
