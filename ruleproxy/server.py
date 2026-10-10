"""Localhost web panel with origin, Host and mutation-token checks."""
from __future__ import annotations

import argparse
import json
import mimetypes
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import signal
import threading
import urllib.parse
import webbrowser

from .manager import Manager, ROOT, state_directory


MAX_REQUEST = 2 * 1024 * 1024 + 65536


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
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/state":
            return self.reply(200, self.server.manager.state())
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
                elif len(parts) == 5 and parts[4] == "launch":
                    return self.reply(200, manager.launch(parts[3]))
                elif len(parts) == 5 and parts[4] == "stop":
                    manager.stop_app(parts[3])
                else:
                    return self.reply(404, {"error": "不存在。"})
            else:
                return self.reply(404, {"error": "不存在。"})
            self.reply(200, manager.state())
        except (ValueError, TypeError, OSError, RuntimeError) as exc:
            self.reply(400, {"error": str(exc)})
        except Exception:
            self.reply(500, {"error": "操作未完成；应用不会退回直连。请查看面板运行终端。"})


def main():
    parser = argparse.ArgumentParser(description="RuleProxy local web panel")
    parser.add_argument("--port", type=int, default=8879, help="panel HTTP port (default: 8879)")
    parser.add_argument("--proxy-port", type=int, default=10809, help="local Mihomo mixed proxy port (default: 10809)")
    parser.add_argument("--controller-port", type=int, default=19097, help="local Mihomo controller port (default: 19097)")
    parser.add_argument("--start-core", action="store_true", help="start the core using the saved YAML on launch")
    parser.add_argument("--state-dir", type=Path, default=state_directory())
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    ports = (args.port, args.proxy_port, args.controller_port)
    if any(not 1025 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        parser.error("Panel, proxy, and controller ports must be 1025–65535 and all different")

    manager = None
    server = None
    try:
        manager = Manager(
            args.state_dir,
            args.port,
            mixed_port=args.proxy_port,
            controller_port=args.controller_port,
        )
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
        server.daemon_threads = True
        server.manager = manager
        for name in ("SIGINT", "SIGTERM"):
            signal.signal(getattr(signal, name), lambda *_: threading.Thread(target=server.shutdown, daemon=True).start())
        url = f"http://127.0.0.1:{args.port}"
        print("RuleProxy: " + url, flush=True)
        print("Close this window or press Ctrl+C to stop the panel and its protected applications.", flush=True)
        if args.start_core:
            manager.start()
        if not args.no_browser:
            webbrowser.open(url)
        server.serve_forever(poll_interval=0.2)
    finally:
        try:
            if manager is not None:
                manager.close()
        finally:
            if server is not None:
                server.server_close()
