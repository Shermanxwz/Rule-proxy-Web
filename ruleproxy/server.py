"""Localhost web panel with origin, Host and mutation-token checks."""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import signal
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser

from . import __version__
from .manager import Manager, ROOT, state_directory
from .panel_client import PROBE_HEADER, PanelError, panel_state, post, wait_for_panel


MAX_REQUEST = 2 * 1024 * 1024 + 65536
# An open panel page reads the state every few seconds, and at least once a minute
# from a background tab. A page that has not read it for this long counts as closed.
VIEWER_TIMEOUT_SECONDS = 150.0
# panel.log, kept when the panel runs without a console, starts over past this size.
LOG_LIMIT = 1024 * 1024


class PanelServer(ThreadingHTTPServer):
    """The panel's HTTP server. Exactly one panel may own a port."""

    daemon_threads = True
    # On Windows SO_REUSEADDR lets a second socket take over a port that is in use,
    # so a second panel would silently steal it. Ask for exclusive use there instead.
    allow_reuse_address = sys.platform != "win32"

    def __init__(self, port: int, manager: Manager | None = None, *, hosted: bool = False):
        self.manager = manager
        # A panel hosted by a desktop shortcut exits once nothing uses it.
        self.hosted = hosted
        # Monotonic time of the last state read by a panel page; None until a page reads it.
        self.last_view: float | None = None
        # Set by the page's "quit" button; whoever runs the panel then shuts it down and exits.
        self.quit_requested = threading.Event()
        super().__init__(("127.0.0.1", port), Handler)

    def server_bind(self):
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()

    def viewer_recent(self) -> bool:
        # The monotonic clock starts near zero at boot, so "never viewed" must not be 0.0.
        return self.last_view is not None and time.monotonic() - self.last_view < VIEWER_TIMEOUT_SECONDS


class Handler(BaseHTTPRequestHandler):
    server_version = "RuleProxy"

    def log_message(self, *_):
        pass

    def reply(self, status, body, content_type="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(body)

    def state_payload(self, **options):
        return {**self.server.manager.state(**options), "hosted": bool(getattr(self.server, "hosted", False))}

    def valid_origin(self, mutation=False):
        port = self.server.server_address[1]
        allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
        if self.headers.get("Host", "") not in allowed:
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {"http://" + host for host in allowed}:
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            return False
        if mutation and not secrets.compare_digest(self.headers.get("X-RuleProxy-Token", ""), self.server.manager.token):
            return False
        return True

    def do_GET(self):
        if not self.valid_origin():
            return self.reply(403, {"error": "仅允许从本机面板访问。"})
        url = urllib.parse.urlsplit(self.path)
        path = url.path
        if path == "/api/state":
            if self.headers.get(PROBE_HEADER) != "1":
                self.server.last_view = time.monotonic()
            refresh_apps = urllib.parse.parse_qs(url.query).get("refresh_apps") == ["1"]
            return self.reply(200, self.state_payload(refresh_apps=refresh_apps))
        allowed = {"/": "index.html", "/web/index.html": "index.html", "/web/app.js": "app.js", "/web/style.css": "style.css"}
        if path not in allowed:
            return self.reply(404, {"error": "不存在。"})
        file = ROOT / "web" / allowed[path]
        self.reply(200, file.read_bytes(), (mimetypes.guess_type(str(file))[0] or "text/plain") + "; charset=utf-8")

    def do_POST(self):
        self.mutate()

    def do_DELETE(self):
        self.mutate()

    def mutate(self):
        if not self.valid_origin(mutation=True):
            return self.reply(403, {"error": "请求来源或面板凭据无效，请刷新面板。"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 <= length <= MAX_REQUEST:
                return self.reply(413, {"error": "请求内容过大。"})
            if length and self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
                return self.reply(415, {"error": "请求必须是 JSON。"})
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("请求必须是对象。")
            path = urllib.parse.urlsplit(self.path).path
            manager = self.server.manager
            if self.command == "DELETE":
                if not path.startswith("/api/apps/") or len(path.split("/")) != 4:
                    return self.reply(404, {"error": "不存在。"})
                manager.change_app(path.split("/")[3], delete=True)
            elif path == "/api/import":
                manager.import_yaml(data.get("yaml"))
            elif path == "/api/settings":
                manager.save_settings(data)
            elif path == "/api/start":
                manager.start()
            elif path == "/api/autostart":
                manager.set_autostart(data.get("enabled"))
            elif path == "/api/quit":
                # Answer first: the page then knows the panel is going away on purpose.
                self.server.quit_requested.set()
                self.reply(200, {"quitting": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            elif path == "/api/stop":
                manager.stop()
            elif path == "/api/node":
                manager.select_node(data.get("name"))
            elif path == "/api/apps":
                manager.add_app(data)
            elif path == "/api/launch-enabled":
                results = []
                for app in list(manager.settings["apps"]):
                    if app["enabled"]:
                        try:
                            result = manager.launch(app["id"])
                        except Exception as exc:
                            result = {"error": str(exc)}
                        results.append({"id": app["id"], "label": app["label"], **result})
                return self.reply(200, {"results": results})
            elif path.startswith("/api/apps/"):
                parts = path.split("/")
                if len(parts) == 4:
                    manager.change_app(parts[3], data.get("enabled"))
                elif len(parts) == 5 and parts[4] == "shortcut":
                    created = manager.create_shortcuts(parts[3])
                    return self.reply(200, {**self.state_payload(), "created": created})
                elif len(parts) == 5 and parts[4] == "launch":
                    return self.reply(200, manager.launch(parts[3]))
                elif len(parts) == 5 and parts[4] == "stop":
                    manager.stop_app(parts[3])
                else:
                    return self.reply(404, {"error": "不存在。"})
            else:
                return self.reply(404, {"error": "不存在。"})
            self.reply(200, self.state_payload())
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            self.reply(400, {"error": str(exc)})
        except Exception:
            self.reply(500, {"error": "操作未完成；应用不会退回直连。请查看面板运行终端。"})


def _open_running_panel(args, url: str, state: dict) -> None:
    """Another panel already owns the port: use it instead of starting a second one."""
    print(f"RuleProxy 面板已在运行：{url}", flush=True)
    if args.start_core and not state.get("running"):
        try:
            post(args.port, state["token"], "/api/start")
        except PanelError as exc:
            raise SystemExit(f"RuleProxy: {exc}") from None
    if not args.no_browser:
        webbrowser.open(url)


def _running_as_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _refuse_root(platform: str | None = None) -> None:
    """Chromium-based apps start as root only with their sandbox disabled, which this tool never does."""
    platform = sys.platform if platform is None else platform
    if platform.startswith("linux") and _running_as_root():
        raise SystemExit("RuleProxy: 请用登录桌面的普通用户运行，不要用 sudo 或 root。root 下 Chrome、ChatGPT 等程序必须关闭浏览器沙箱才能启动，本工具不会这样做。")


def _tolerant_console() -> None:
    """Never crash on a message the console cannot encode (a redirected cp1252 pipe on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(errors="replace")
            except (OSError, ValueError):
                pass


def _windowless_log(state_dir: Path) -> bool:
    """Started without a console (pythonw): keep the panel's messages in panel.log in its data folder.

    Returns True when the panel has no console of its own.
    """
    if sys.stdout is not None and sys.stderr is not None:
        return False
    try:
        state_dir.mkdir(parents=True, exist_ok=True)
        path = state_dir / "panel.log"
        # Start over past the limit, so a panel that always runs in the background cannot grow it without end.
        mode = "w" if path.is_file() and path.stat().st_size > LOG_LIMIT else "a"
        stream = open(path, mode, encoding="utf-8", errors="replace", buffering=1)
    except OSError:
        return True
    stream.write(f"--- {time.strftime('%Y-%m-%d %H:%M:%S')} RuleProxy {__version__} ---\n")
    if sys.stdout is None:
        sys.stdout = stream
    if sys.stderr is None:
        sys.stderr = stream
    return True


def main():
    _tolerant_console()
    parser = argparse.ArgumentParser(description="RuleProxy local web panel")
    parser.add_argument("--port", type=int, default=8879, help="panel HTTP port (default: 8879)")
    parser.add_argument("--proxy-port", type=int, default=10809, help="local Mihomo mixed proxy port (default: 10809)")
    parser.add_argument("--controller-port", type=int, default=19097, help="local Mihomo controller port (default: 19097)")
    parser.add_argument("--start-core", action="store_true", help="start the core using the saved YAML on launch")
    parser.add_argument("--state-dir", type=Path, default=state_directory())
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--launch-app", metavar="APP_ID", help="start one saved app from a desktop shortcut, then exit when it closes")
    args = parser.parse_args()
    ports = (args.port, args.proxy_port, args.controller_port)
    if any(not 1025 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        parser.error("Panel, proxy, and controller ports must be 1025–65535 and all different")
    windowless = _windowless_log(args.state_dir)
    try:
        _run(args, windowless)
    except SystemExit as exc:
        # Without a console nobody would see why the panel did not start.
        if windowless and isinstance(exc.code, str):
            from .shortcut_launcher import _notify

            print(exc.code, file=sys.stderr, flush=True)
            _notify("RuleProxy", exc.code.removeprefix("RuleProxy: "))
        raise


def _run(args, windowless: bool):
    _refuse_root()
    if args.launch_app:
        from .shortcut_launcher import run as run_shortcut

        raise SystemExit(run_shortcut(args.launch_app, state_dir=args.state_dir, panel_port=args.port, mixed_port=args.proxy_port, controller_port=args.controller_port))

    url = f"http://127.0.0.1:{args.port}"
    existing = panel_state(args.port)
    if existing is not None:
        return _open_running_panel(args, url, existing)
    try:
        server = PanelServer(args.port)
    except OSError as exc:
        # Lost a race with another panel that is still starting, or a different program holds the port.
        existing = wait_for_panel(args.port, 5)
        if existing is not None:
            return _open_running_panel(args, url, existing)
        raise SystemExit(f"RuleProxy: 无法使用面板端口 {args.port}（{exc.strerror or exc}）。该端口可能被其他程序占用，可用 --port 指定其他端口。") from None

    manager = None
    try:
        manager = Manager(
            args.state_dir,
            args.port,
            mixed_port=args.proxy_port,
            controller_port=args.controller_port,
        )
        server.manager = manager
        for name in ("SIGINT", "SIGTERM"):
            signal.signal(getattr(signal, name), lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
        print("RuleProxy: " + url, flush=True)
        if windowless:
            print("Running without a window. Use Quit on the panel page to stop the panel and its protected applications.", flush=True)
        else:
            print("Press Ctrl+C, or use Quit on the panel page, to stop the panel and its protected applications.", flush=True)
        # The isolation check can take seconds; start it now so the page does not wait for it.
        threading.Thread(target=manager.protection, name="RuleProxyIsolationCheck", daemon=True).start()
        if args.start_core:
            try:
                manager.start()
            except ValueError as exc:
                raise SystemExit(f"RuleProxy: {exc}") from None
        if not args.no_browser:
            webbrowser.open(url)
        server.serve_forever(poll_interval=0.2)
    finally:
        try:
            if manager is not None:
                manager.close()
        finally:
            server.server_close()
