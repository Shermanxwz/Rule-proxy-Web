"""Shortcut runner: delegation to a running panel, and the panel it hosts when none runs."""
import io
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
import urllib.request
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch

from ruleproxy import shortcut_launcher
from ruleproxy.panel_client import panel_state


class FakePanel:
    """Answers the parts of the panel API that the runner uses, and records each request."""

    def __init__(self, *, running=False, launch_error=None, first_reply_delay=0.0):
        self.requests = []
        self.running = running
        self.launch_error = launch_error
        self.first_reply_delay = first_reply_delay
        panel = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_json(self, status, body):
                data = json.dumps(body).encode("utf-8")
                try:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass  # the client gave up waiting for a delayed reply

            def do_GET(self):
                panel.requests.append(("GET", self.path, None, None))
                if panel.first_reply_delay:
                    # A panel that is still starting: the first probe gets no timely answer.
                    delay, panel.first_reply_delay = panel.first_reply_delay, 0.0
                    time.sleep(delay)
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
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    def posts(self):
        return [(path, token, ctype) for method, path, token, ctype in self.requests if method == "POST"]


class FakeManager:
    """Stands in for Manager inside a hosted panel. Launched apps run until released."""

    token = "hosted-token"

    def __init__(self, *, known=("abc", "def"), start_error=None, launch_error=None):
        self.known = set(known)
        self.start_error = start_error
        self.launch_error = launch_error
        self.running = False
        self.launched = []
        self.released = threading.Event()
        self.close_calls = 0
        self.lock = threading.Lock()

    def app(self, ident):
        return {"id": ident} if ident in self.known else None

    def start(self):
        if self.start_error:
            raise ValueError(self.start_error)
        self.running = True

    def launch(self, ident):
        if self.launch_error:
            raise self.launch_error
        with self.lock:
            self.launched.append(ident)
        return {"pid": 1, "adapter": "chromium", "detail": "ok"}

    def has_active_apps(self):
        return bool(self.launched) and not self.released.is_set()

    def state(self, refresh_apps=False):
        return {"token": self.token, "version": "test", "running": self.running, "apps": []}

    def close(self):
        self.close_calls += 1

    def begin_quit(self):
        self.released.set()
        self.running = False


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def port_is_free(port):
    probe = socket.socket()
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def wait_until(predicate, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


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
        with patch.object(shortcut_launcher, "_notify"), redirect_stderr(err):
            self.assertEqual(self.run_runner("abc"), 1)
        self.assertIn("请先将应用加入待保护列表", err.getvalue())

    def test_an_invalid_id_never_reaches_the_panel(self):
        err = io.StringIO()
        with patch.object(shortcut_launcher, "_notify"), redirect_stderr(err):
            self.assertEqual(self.run_runner("../escape"), 1)
        self.assertEqual(self.panel.posts(), [])

    def test_waits_for_a_panel_that_is_still_starting(self):
        # The first probe times out while the port is already taken: the runner must
        # not start a second core, but wait for that panel and hand it the app.
        self.panel.first_reply_delay = 2.5
        factory = Mock()
        with patch("ruleproxy.manager.Manager", factory):
            self.assertEqual(self.run_runner("abc"), 0)
        factory.assert_not_called()
        self.assertEqual([path for path, _, _ in self.panel.posts()], ["/api/start", "/api/apps/abc/launch"])


class HostedPanelTests(unittest.TestCase):
    """No panel answers, so the first shortcut serves the panel itself."""

    def setUp(self):
        self.state = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.state, ignore_errors=True))
        self.port = free_port()
        self.manager = FakeManager()
        self.factory = Mock(return_value=self.manager)
        self.err = io.StringIO()
        for patcher in (
            patch("ruleproxy.manager.Manager", self.factory),
            patch.object(shortcut_launcher, "PANEL_IDLE_SECONDS", 0.2),
            patch.object(shortcut_launcher, "_stop_on_signal"),
            patch.object(shortcut_launcher, "_notify"),
            redirect_stderr(self.err),
        ):
            patcher.__enter__()
            self.addCleanup(patcher.__exit__, None, None, None)

    def run_runner(self, app_id):
        return shortcut_launcher.run(app_id, state_dir=self.state, panel_port=self.port, mixed_port=10809, controller_port=19097)

    def run_in_background(self, app_id):
        result = {}
        thread = threading.Thread(target=lambda: result.setdefault("code", self.run_runner(app_id)), daemon=True)
        thread.start()
        return thread, result

    def test_hosts_the_panel_and_exits_after_the_last_app_closes(self):
        thread, result = self.run_in_background("abc")
        self.assertTrue(wait_until(lambda: self.manager.launched == ["abc"]))
        state = panel_state(self.port)
        self.assertIsNotNone(state, "the hosted panel must answer on the panel port")
        self.assertTrue(state["hosted"])
        self.assertTrue(self.manager.running)
        self.manager.released.set()
        thread.join(10)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result["code"], 0)
        self.assertEqual(self.manager.close_calls, 1)
        self.assertTrue(port_is_free(self.port))

    def test_quit_on_the_page_ends_a_hosted_panel_while_apps_run(self):
        thread, result = self.run_in_background("abc")
        self.assertTrue(wait_until(lambda: self.manager.launched == ["abc"]))
        self.assertTrue(self.manager.has_active_apps())
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/quit", data=b"{}", method="POST",
            headers={"Content-Type": "application/json", "X-RuleProxy-Token": FakeManager.token},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(json.load(response), {"quitting": True})
        thread.join(10)
        self.assertFalse(thread.is_alive(), "quit must end the hosted panel even with an app still open")
        self.assertEqual(result["code"], 0)
        self.assertEqual(self.manager.close_calls, 1, "closing the manager stops the apps and the core")
        self.assertTrue(port_is_free(self.port))

    def test_a_later_shortcut_uses_the_hosted_panel(self):
        thread, result = self.run_in_background("abc")
        self.assertTrue(wait_until(lambda: self.manager.launched == ["abc"]))
        self.assertEqual(self.run_runner("def"), 0)
        self.assertEqual(self.manager.launched, ["abc", "def"])
        self.assertEqual(self.factory.call_count, 1)
        self.manager.released.set()
        thread.join(10)
        self.assertEqual(result["code"], 0)

    def test_shortcuts_started_together_share_one_panel(self):
        threads = [self.run_in_background(app_id) for app_id in ("abc", "def")]
        self.assertTrue(wait_until(lambda: sorted(self.manager.launched) == ["abc", "def"], timeout=20), self.err.getvalue())
        self.assertEqual(self.factory.call_count, 1, "only one shortcut may own the core")
        self.manager.released.set()
        for thread, result in threads:
            thread.join(10)
            self.assertEqual(result.get("code"), 0, self.err.getvalue())
        self.assertTrue(port_is_free(self.port))

    def test_an_open_panel_page_keeps_the_hosted_panel_alive(self):
        thread, _ = self.run_in_background("abc")
        self.assertTrue(wait_until(lambda: self.manager.launched == ["abc"]))
        with patch("ruleproxy.server.VIEWER_TIMEOUT_SECONDS", 1.5):
            # A page read (no probe header) marks the panel as being viewed.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(f"http://127.0.0.1:{self.port}/api/state", timeout=5) as response:
                self.assertTrue(json.load(response)["hosted"])
            self.manager.released.set()
            time.sleep(0.8)
            self.assertTrue(thread.is_alive(), "the panel must stay while its page is open")
            thread.join(10)
        self.assertFalse(thread.is_alive())

    def test_a_port_held_by_another_program_is_reported(self):
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", self.port))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        with patch.object(shortcut_launcher, "PANEL_START_WAIT_SECONDS", 0.5):
            self.assertEqual(self.run_runner("abc"), 1)
        self.factory.assert_not_called()
        self.assertIn(f"面板端口 {self.port} 被其他程序占用", self.err.getvalue())

    def test_a_start_failure_is_reported_and_still_cleans_up(self):
        self.manager.start_error = "请先导入 YAML。"
        self.assertEqual(self.run_runner("abc"), 1)
        self.assertIn("请先导入 YAML", self.err.getvalue())
        self.assertEqual(self.manager.launched, [])
        self.assertEqual(self.manager.close_calls, 1)
        self.assertTrue(port_is_free(self.port))

    def test_a_removed_app_is_reported_without_starting_a_core(self):
        self.manager.known = set()
        self.assertEqual(self.run_runner("abc"), 1)
        self.assertFalse(self.manager.running)
        self.assertIn("已不在面板的清单中", self.err.getvalue())
        self.assertTrue(port_is_free(self.port))

    def test_a_runtime_refusal_is_reported_and_still_cleans_up(self):
        self.manager.launch_error = RuntimeError("Windows 运行时拒绝启动")
        self.assertEqual(self.run_runner("abc"), 1)
        self.assertIn("Windows 运行时拒绝启动", self.err.getvalue())
        self.assertEqual(self.manager.close_calls, 1)

    def test_an_unexpected_failure_is_reported_not_silent(self):
        self.manager.launch_error = KeyError("pid")
        self.assertEqual(self.run_runner("abc"), 1)
        self.assertIn("启动失败", self.err.getvalue())
        self.assertEqual(self.manager.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
