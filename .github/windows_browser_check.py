"""Run real Edge in PSEC against a fixed local HTTP byte fixture.

Usage (with the package's x64 Python):
  python .github/windows_browser_check.py --root PACKAGE --allow-emulated-x64 --report browser.json

The fixture never resolves names or connects to a destination. This checks
real rendering and persistent cookies through the production file transport;
it does not establish real-node, HTTPS, session-login or download acceptance.
Exit 0 means these browser fixture checks passed, 3 means unsupported, 1 failed.
"""
from __future__ import annotations

import argparse
from http.cookies import CookieError, SimpleCookie
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import socketserver
import sys
import tempfile
import threading
import urllib.parse


ROOT = Path(__file__).resolve().parent.parent
HOST = "ruleproxy-browser-fixture.invalid"
COOKIE = "ruleproxy_browser_fixture"


def acceptance_helpers():
    path = ROOT / "scripts/windows-acceptance.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_browser_acceptance_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
        with fixture.lock:
            fixture.connections.add(self.request)
        try:
            self.request.settimeout(15)
            first = self.request.recv(1)
            if first == b"\x05":
                # The real guest startup check requests only SOCKS5 method
                # negotiation. No destination or CONNECT command is accepted.
                greeting = bytearray()
                while len(greeting) < 2:
                    part = self.request.recv(2 - len(greeting))
                    if not part:
                        return
                    greeting.extend(part)
                if greeting == b"\x01\x00":
                    self.request.sendall(b"\x05\x00")
                return
            if not first:
                return
            raw = bytearray(first)
            while not raw.endswith(b"\r\n\r\n"):
                if len(raw) >= 16 * 1024:
                    return
                part = self.request.recv(1)
                if not part:
                    return
                raw.extend(part)
            lines = raw.decode("iso-8859-1").split("\r\n")
            method, target, version = lines[0].split(" ")
            headers = {}
            for line in lines[1:-2]:
                key, value = line.split(":", 1)
                headers[key.lower()] = value.strip()
            status, body, extra = fixture.response(method, target, version, headers)
            response = (f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
                        f"Content-Length: {len(body)}\r\nCache-Control: no-store\r\n"
                        "Connection: close\r\n" + extra + "\r\n").encode("ascii")
            self.request.sendall(response + body)
        except (OSError, ValueError):
            # A browser may abandon speculative connections. Successful page
            # and DOM acknowledgements, rather than connection counts, gate it.
            pass
        finally:
            with fixture.lock:
                fixture.connections.discard(self.request)


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False


class BrowserFixture:
    """One fixed HTTP origin and SOCKS greeting; no forwarding or DNS API."""

    def __init__(self):
        self.nonce = secrets.token_hex(32)
        self.lock = threading.Lock()
        self.connections = set()
        self.phase = 0
        self.pages = {1: [], 2: []}
        self.acks = {1: [], 2: []}
        self.server = _Server(("127.0.0.1", 0), _Handler)
        self.server.fixture = self
        self.port = self.server.server_address[1]
        self.worker = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.1}, daemon=True)
        self.worker.start()

    def begin(self, phase):
        with self.lock:
            self.phase = phase

    def response(self, method, target, version, headers):
        url = urllib.parse.urlsplit(target)
        if method != "GET" or version not in ("HTTP/1.0", "HTTP/1.1") \
                or url.scheme != "http" or url.hostname != HOST or url.port not in (None, 80) \
                or url.username or url.password or url.fragment:
            return "403 Forbidden", b"fixture only", ""
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get("cookie", ""))
        except CookieError:
            return "400 Bad Request", b"invalid cookie", ""
        present = COOKIE in cookie and cookie[COOKIE].value == self.nonce
        with self.lock:
            phase = self.phase
            if url.path == f"/phase/{phase}" and phase in (1, 2) and not url.query:
                self.pages[phase].append(present)
                # Only the first launch may set this cookie. Restored tabs in
                # launch two cannot refresh it, masking failed persistence.
                extra = (f"Set-Cookie: {COOKIE}={self.nonce}; Path=/; Max-Age=3600; HttpOnly; SameSite=Lax\r\n"
                         if phase == 1 else "")
                body = ("<!doctype html><html><head><title>RuleProxy browser fixture</title></head>"
                        f'<body><output id="nonce">{self.nonce}</output><script>'
                        'const value = document.getElementById("nonce").textContent;'
                        'const request = new XMLHttpRequest();'
                        f'request.open("GET", "/ack/{phase}?nonce=" + encodeURIComponent(value), false);'
                        'request.send(null);'
                        'document.body.dataset.fixtureAck = String(request.status === 204);'
                        "</script></body></html>").encode("utf-8")
                return "200 OK", body, extra
            if url.path == f"/ack/{phase}" and phase in (1, 2) \
                    and urllib.parse.parse_qsl(url.query, keep_blank_values=True) == [("nonce", self.nonce)]:
                self.acks[phase].append(present)
                return "204 No Content", b"", ""
        return "403 Forbidden", b"fixture only", ""

    def check(self, phase):
        with self.lock:
            if not self.pages[phase] or not self.acks[phase] or not all(self.acks[phase]):
                raise RuntimeError("real browser did not acknowledge the DOM nonce with its cookie")
            if phase == 2 and not all(self.pages[phase]):
                raise RuntimeError("persistent cookie was absent on the second private-profile launch")

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def find_edge(explicit):
    candidates = [explicit] if explicit else [
        Path(os.environ.get(key, "")) / "Microsoft/Edge/Application/msedge.exe"
        for key in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA") if os.environ.get(key)
    ]
    for path in candidates:
        if Path(path).is_file():
            if Path(path).name.lower() != "msedge.exe":
                raise ValueError("--browser must name the actual Microsoft Edge msedge.exe")
            return Path(path).resolve(strict=True)
    raise FileNotFoundError("Microsoft Edge executable was not found; pass --browser")


class BrowserRun:
    def __init__(self, runtime, browser, profile_root, fixture):
        self.runtime, self.browser, self.profile_root, self.fixture = runtime, browser, profile_root, fixture
        self.wrapper = self.resources = None

    def run(self, phase, timeout):
        from ruleproxy import launcher, windows_runtime
        self.fixture.begin(phase)
        guest_port = windows_runtime.choose_guest_port(self.fixture.port)
        app = {"id": "browser", "label": "Real Edge fixture", "path": str(self.browser),
               "adapter": "chromium", "args": ["--headless=new", "--dump-dom", "--disable-gpu",
                                                "--no-default-browser-check", f"http://{HOST}/phase/{phase}"]}
        command, environment, _ = launcher.prepare_app(app, guest_port, self.profile_root)
        try:
            self.wrapper, self.resources = windows_runtime.launch(
                command, environment, self.profile_root / "browser", self.fixture.port,
                str(self.runtime), guest_listener_port=guest_port)
        except BaseException as exc:
            self.wrapper = getattr(exc, "process", None)
            self.resources = getattr(exc, "resource", None)
            raise
        # Natural headless exit is required before relaunch, so cookie flush
        # is checked without a kill/teardown manufacturing the result.
        code = self.wrapper.wait(timeout=timeout)
        if code:
            raise RuntimeError(f"real Edge/MXC workload exited with status {code}")
        self.fixture.check(phase)
        self.close()
        return {"check": f"real_edge_launch_{phase}", "status": "passed",
                "dom_nonce_via_page_ack": True, "cookie_request_verified": True,
                "natural_headless_exit": True, "private_profile_reused": phase == 2}

    def close(self):
        from ruleproxy import windows_runtime
        if self.wrapper is not None:
            windows_runtime.stop(self.wrapper)
        if self.resources is not None:
            self.resources.close()
        self.wrapper = self.resources = None


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--browser", type=Path, help="explicit real msedge.exe path")
    parser.add_argument("--allow-emulated-x64", action="store_true")
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--report", type=Path, default=Path("windows-browser.json"))
    args = parser.parse_args(arguments)
    if not 10 <= args.timeout <= 300:
        parser.error("--timeout must be between 10 and 300 seconds")
    helpers = acceptance_helpers()
    result = {"status": "failed", "browser_fixture_passed": False, "acceptance_passed": False,
              "real_node_passed": False, "checks": [],
              "limitations": ["Fixed local HTTP bytes only; no external node or HTTPS origin tested.",
                              "Only persistent cookies are in scope; session login and downloads remain unverified.",
                              "DOM is verified by its page acknowledgement; dumped stdout is not compared."]}
    fixture = owner = directory = before = None
    safe_cleanup = True
    code, phase = 1, "platform"
    try:
        facts = helpers.host_facts()
        result["host"] = facts
        if sys.platform != "win32" or facts.get("windows_product_type") != 1:
            result.update(status="unsupported", detail="Requires an actual Windows 11 workstation.")
            return 3
        if facts.get("python_pe_machine") != 0x8664 or (facts.get("native_machine") != 0x8664
                and not (args.allow_emulated_x64 and facts.get("native_machine") == 0xAA64)):
            result.update(status="unsupported", detail="Requires x64 Python; x64-on-ARM needs --allow-emulated-x64.")
            return 3
        root = args.root.resolve(strict=True)
        sys.path.insert(0, str(root))
        phase = "runtime_integrity"
        helpers.verify_project_origin(root)
        from ruleproxy import windows_runtime
        digests = helpers.verify_runtime_manifest(root)
        result["runtime_integrity"] = {"manifest_verified": True, "file_count": len(digests)}
        runtime = root / "bin/windows-amd64/wxc-exec.exe"
        phase = "request_probe"
        result["probe"] = windows_runtime.probe(str(runtime))
        if not result["probe"]["supported"]:
            result.update(status="unsupported", detail=result["probe"]["detail"])
            return 3
        phase = "real_browser"
        browser = find_edge(args.browser)
        browser_machine = helpers.executable_machine(browser)
        browser_scope = helpers.acceptance_scope(facts["native_machine"], browser_machine)
        result["browser"] = {"path": str(browser), "launcher_pe_machine": browser_machine,
                             "launcher_execution_scope": browser_scope.replace("native_arm64_probe", "native_arm64")}
        phase = "host_network_snapshot"
        before = helpers.network_snapshot()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-browser-"))
        fixture = BrowserFixture()
        owner = BrowserRun(runtime, browser, directory / "profiles", fixture)
        for number in (1, 2):
            phase = f"real_edge_launch_{number}"
            result["checks"].append(owner.run(number, args.timeout))
        result.update(status="browser_fixture_only", browser_fixture_passed=True)
        code = 0
    except Exception as exc:
        result.update(status="failed", detail=f"Browser check failed during {phase} ({type(exc).__name__}): {str(exc)[:400]}")
    finally:
        if owner is not None:
            try:
                owner.close()
            except Exception as exc:
                safe_cleanup = False
                result.update(status="failed", browser_fixture_passed=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        if fixture is not None:
            fixture.close()
        if before is not None:
            try:
                after = helpers.network_snapshot()
                unchanged = before == after
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                         "status": "passed" if unchanged else "failed"})
                if not unchanged:
                    result.update(status="failed", browser_fixture_passed=False)
                    code = 1
            except Exception as exc:
                result.update(status="failed", browser_fixture_passed=False,
                              host_snapshot_error=type(exc).__name__)
                code = 1
        if directory is not None and safe_cleanup:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                result.update(status="failed", browser_fixture_passed=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
        helpers.write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
