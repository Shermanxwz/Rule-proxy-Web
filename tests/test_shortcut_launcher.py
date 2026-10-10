"""Headless shortcut runner: delegation to a running panel, and the standalone lifecycle."""
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from ruleproxy import shortcut_launcher


class FakePanel:
    """Answers the parts of the panel API that the runner uses, and records each request."""

    def __init__(self, *, running=False, launch_error=None):
        self.requests = []
        self.running = running
        self.launch_error = launch_error
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_json(self, status, body):
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                panel.requests.append(("GET", self.path, None, None))
                if self.path == "/api/state":
                    self.send_json(200, {"token": "secret-token", "version": "0.1.0", "running": panel.running})
                else:
                    self.send_json(404, {"error": "missing"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                panel.requests.append(("POST", self.path, self.headers.get("X-RuleProxy-Token"), self.headers.get("Content-Type")))
                if self.headers.get("X-RuleProxy-Token") != "secret-token":
                    return self.send_json(403, {"error": "token"})
                if self.path == "/api/start":
                    panel.running = True
                    return self.send_json(200, {"running": True})
                if self.path.endswith("/launch"):
                    if panel.launch_error:
                        return self.send_json(400, {"error": panel.launch_error})
                    return self.send_json(200, {"pid": 4242, "detail": "ok"})
                self.send_json(404, {"error": "missing"})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def posts(self):
        return [(path, token, ctype) for method, path, token, ctype in self.requests if method == "POST"]


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.panel = FakePanel()
        self.addCleanup(self.panel.close)
        self.state = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.state, ignore_errors=True))

    def run_runner(self, app_id="abc"):
        return shortcut_launcher.run(app_id, state_dir=self.state, panel_port=self.panel.port, mixed_port=10809, controller_port=19097)

    def test_a_stopped_core_is_started_and_the_app_launched_inside_the_panel(self):
        self.assertEqual(self.run_runner("abc"), 0)
        self.assertEqual([path for path, _, _ in self.panel.posts()], ["/api/start", "/api/apps/abc/launch"])
        self.assertTrue(all(token == "secret-token" and ctype == "application/json" for _, token, ctype in self.panel.posts()))

    def test_a_running_core_is_left_alone(self):
        self.panel.running = True
        self.assertEqual(self.run_runner("abc"), 0)
        self.assertEqual([path for path, _, _ in self.panel.posts()], ["/api/apps/abc/launch"])

    def test_the_panel_refusal_reason_is_reported(self):
        self.panel.launch_error = "请先将应用加入待保护列表。"
        err = io.StringIO()
        with patch.object(shortcut_launcher.shutil, "which", return_value=None), redirect_stderr(err):
            self.assertEqual(self.run_runner("abc"), 1)
        self.assertIn("请先将应用加入待保护列表", err.getvalue())

    def test_an_invalid_id_never_reaches_the_panel(self):
        err = io.StringIO()
        with patch.object(shortcut_launcher.shutil, "which", return_value=None), redirect_stderr(err):
            self.assertEqual(self.run_runner("../escape"), 1)
        self.assertEqual(self.panel.posts(), [])


class StandaloneTests(unittest.TestCase):
    def fake_manager(self, *, start_error=None, exit_after=3):
        manager = Mock()
        manager.app.return_value = {"id": "abc", "label": "X"}
        if start_error:
            manager.start.side_effect = ValueError(start_error)
        process = Mock()
        polls = {"count": 0}

        def poll():
            polls["count"] += 1
            return 0 if polls["count"] > exit_after else None

        process.poll.side_effect = poll
        manager.active = {"abc": (process, Mock())}
        return manager

    def run_standalone(self, manager):
        state = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(state, ignore_errors=True))
        with patch("ruleproxy.manager.Manager", Mock(return_value=manager)), patch.object(shortcut_launcher, "_stop_on_signal"):
            return shortcut_launcher.run("abc", state_dir=state, panel_port=free_port(), mixed_port=10809, controller_port=19097)

    def test_core_and_app_start_then_everything_closes_when_the_app_exits(self):
        manager = self.fake_manager()
        self.assertEqual(self.run_standalone(manager), 0)
        manager.start.assert_called_once_with()
        manager.launch.assert_called_once_with("abc")
        manager.close.assert_called_once_with()

    def test_a_start_failure_is_reported_and_still_cleans_up(self):
        manager = self.fake_manager(start_error="请先导入 YAML。")
        err = io.StringIO()
        with redirect_stderr(err), patch.object(shortcut_launcher.shutil, "which", return_value=None):
            self.assertEqual(self.run_standalone(manager), 1)
        self.assertIn("请先导入 YAML", err.getvalue())
        manager.launch.assert_not_called()
        manager.close.assert_called_once_with()

    def test_a_removed_app_is_reported_without_starting_a_core(self):
        manager = self.fake_manager()
        manager.app.return_value = None
        err = io.StringIO()
        with redirect_stderr(err), patch.object(shortcut_launcher.shutil, "which", return_value=None):
            self.assertEqual(self.run_standalone(manager), 1)
        manager.start.assert_not_called()
        self.assertIn("已不在面板的清单中", err.getvalue())

    def test_a_runtime_refusal_is_reported_and_still_cleans_up(self):
        manager = self.fake_manager()
        manager.launch.side_effect = RuntimeError("Windows 运行时拒绝启动")
        err = io.StringIO()
        with redirect_stderr(err), patch.object(shortcut_launcher.shutil, "which", return_value=None):
            self.assertEqual(self.run_standalone(manager), 1)
        self.assertIn("Windows 运行时拒绝启动", err.getvalue())
        manager.close.assert_called_once_with()

    def test_an_unexpected_failure_is_reported_not_silent(self):
        manager = self.fake_manager()
        manager.launch.side_effect = KeyError("pid")
        err = io.StringIO()
        with redirect_stderr(err), patch.object(shortcut_launcher.shutil, "which", return_value=None):
            self.assertEqual(self.run_standalone(manager), 1)
        self.assertIn("启动失败", err.getvalue())
        manager.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
