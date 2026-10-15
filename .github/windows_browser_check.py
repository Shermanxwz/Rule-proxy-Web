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
_RECOVERY_OWNERS = []
_RULEPROXY_LAUNCH_PHASES = frozenset({
    "unknown",
    "probe_request", "bridge_setup", "host_controls", "wrapper_spawn", "bridge_ready",
    "host_tcp_check", "startup_report", "udp_check", "bind_workload", "app_started",
})


def validated_launch_failure_facts(error):
    """Keep only the fixed, finite launch facts attached by windows_runtime."""
    raw = getattr(error, "_ruleproxy_launch_facts", None)
    required = {"schema_version", "phase", "wrapper_process_started", "wrapper_exit_observed",
                "wrapper_exit_code", "guest_status", "cleanup_proven", "resources_closed"}
    if type(raw) is not dict or set(raw) != required:
        return None
    if (type(raw["schema_version"]) is not int or raw["schema_version"] != 1
            or type(raw["phase"]) is not str or raw["phase"] not in _RULEPROXY_LAUNCH_PHASES
            or (raw["wrapper_process_started"] is not None
                and type(raw["wrapper_process_started"]) is not bool)
            or type(raw["wrapper_exit_observed"]) is not bool
            or (raw["wrapper_exit_code"] is not None and
                (type(raw["wrapper_exit_code"]) is not int
                 or not -(2**31) <= raw["wrapper_exit_code"] <= 0xffffffff))
            or (raw["cleanup_proven"] is not None and type(raw["cleanup_proven"]) is not bool)
            or (raw["resources_closed"] is not None and type(raw["resources_closed"]) is not bool)):
        return None
    guest = raw["guest_status"]
    if (type(guest) is not dict or type(guest.get("status")) is not str
            or guest["status"] not in {"observed", "missing", "unmatched", "invalid", "unavailable"}):
        return None
    safe_guest = {"status": guest["status"]}
    state = guest.get("state")
    if state is not None:
        if type(state) is not str or state not in {
                "GUEST_READY", "APP_STARTED", "APP_EXITED", "FAILED", "REJECTED"}:
            return None
        safe_guest["state"] = state
    if safe_guest["status"] == "observed" and "state" not in safe_guest:
        return None
    app_exit = guest.get("app_exit")
    if app_exit is not None:
        if type(app_exit) is not int or not -(2**31) <= app_exit <= 0xffffffff:
            return None
        safe_guest["app_exit"] = app_exit
    error_category = guest.get("detail_error_category")
    if error_category is not None:
        if type(error_category) is not str or error_category not in {"invalid_app_exit", "guest_failed"}:
            return None
        safe_guest["detail_error_category"] = error_category
    return {"schema_version": 1, "phase": raw["phase"],
            "wrapper_process_started": raw["wrapper_process_started"],
            "wrapper_exit_observed": raw["wrapper_exit_observed"],
            "wrapper_exit_code": raw["wrapper_exit_code"],
            "guest_status": safe_guest,
            "cleanup_proven": raw["cleanup_proven"],
            "resources_closed": raw["resources_closed"]}


def safe_failure_type(error):
    name = type(error).__name__
    return name if name in {"PermissionError", "FileNotFoundError", "OSError", "RuntimeError",
                            "TimeoutError", "ValueError", "TypeError", "AttributeError",
                            "NotImplementedError", "UnsupportedRuntimeError"} else "Exception"


def acceptance_helpers():
    path = ROOT / "scripts/windows-acceptance.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_browser_acceptance_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        fixture = self.server.fixture
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


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False

    def process_request(self, request, address):
        fixture = self.fixture
        def serve():
            try:
                self.process_request_thread(request, address)
            finally:
                with fixture.lock:
                    fixture.connections.discard(request)
                    fixture.handlers.discard(threading.current_thread())
        worker = threading.Thread(target=serve, name="RuleProxyBrowserFixtureHandler", daemon=True)
        with fixture.lock:
            if fixture.closed.is_set():
                request.close()
                return
            fixture.connections.add(request)
            fixture.handlers.add(worker)
        worker.start()


class BrowserFixture:
    """One fixed HTTP origin and SOCKS greeting; no forwarding or DNS API."""

    def __init__(self):
        self.nonce = secrets.token_hex(32)
        self.lock = threading.Lock()
        self.connections = set()
        self.handlers = set()
        self.closed = threading.Event()
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
        self.closed.set()
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        with self.lock:
            connections, handlers = list(self.connections), list(self.handlers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for handler in handlers:
            handler.join(timeout=2)
        if self.worker.is_alive() or any(handler.is_alive() for handler in handlers):
            raise RuntimeError("browser fixture retained a live worker after closure")


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
        self.attempts = []
        self.current_attempt = None
        self._launch_attempted = False
        self._launch_failed_cleanly = False
        self._owned_workload_cleanup_proven = False
        self._resources_closed = False

    def run(self, phase, timeout):
        from ruleproxy import launcher, windows_runtime
        attempt = {"check": f"real_edge_launch_{phase}", "status": "failed",
                   "wrapper_process_started": False, "wrapper_exit_observed": False,
                   "wrapper_exit_code": None, "natural_headless_exit": False,
                   "owned_workload_cleanup_proven": False, "resources_closed": False}
        self.current_attempt = attempt
        self.attempts.append(attempt)
        self._launch_attempted = False
        self._launch_failed_cleanly = False
        self._owned_workload_cleanup_proven = False
        self._resources_closed = False
        self.fixture.begin(phase)
        guest_port = windows_runtime.choose_guest_port(self.fixture.port)
        app = {"id": "browser", "label": "Real Edge fixture", "path": str(self.browser),
               "adapter": "chromium", "args": ["--headless=new", "--dump-dom", "--disable-gpu",
                                                "--no-default-browser-check", f"http://{HOST}/phase/{phase}"]}
        command, environment, _ = launcher.prepare_app(app, guest_port, self.profile_root)
        # An existing profile's session restore can bypass dump-dom's command
        # handler and natural-exit callback. This source-only capture fixture
        # checks a Max-Age cookie, so it does not require restoring old tabs.
        command = [argument for argument in command if argument != "--restore-last-session"]
        self._launch_attempted = True
        attempt["wrapper_process_started"] = None
        attempt["wrapper_exit_observed"] = None
        try:
            self.wrapper, self.resources = windows_runtime.launch(
                command, environment, self.profile_root / "browser", self.fixture.port,
                str(self.runtime), guest_listener_port=guest_port)
        except BaseException as exc:
            self.wrapper = getattr(exc, "process", None)
            self.resources = getattr(exc, "resource", None)
            launch_facts = validated_launch_failure_facts(exc)
            if self.wrapper is not None and launch_facts is not None \
                    and launch_facts["wrapper_process_started"] is not True:
                launch_facts = None
            attempt["wrapper_process_started"] = (True if self.wrapper is not None else
                launch_facts["wrapper_process_started"] if launch_facts is not None else None)
            if launch_facts is not None:
                attempt["wrapper_exit_observed"] = launch_facts["wrapper_exit_observed"]
                attempt["wrapper_exit_code"] = launch_facts["wrapper_exit_code"]
                attempt["ruleproxy_launch"] = launch_facts
            else:
                attempt["wrapper_exit_observed"] = None
            # A missing owner reference alone cannot distinguish pre-Popen
            # failure from a wrapper that launch() closed before re-raising.
            self._launch_failed_cleanly = self.wrapper is None and self.resources is None
            raise
        attempt["wrapper_process_started"] = True
        startup = acceptance_helpers().startup_evidence(self.resources)
        # Natural headless exit is required before relaunch, so cookie flush
        # is checked without a kill/teardown manufacturing the result.
        code = self.wrapper.wait(timeout=timeout)
        attempt.update(wrapper_exit_observed=True, wrapper_exit_code=code,
                       natural_headless_exit=(code == 0))
        if code:
            raise RuntimeError(f"real Edge/MXC workload exited with status {code}")
        self.fixture.check(phase)
        self.close()
        attempt.update(status="passed", dom_nonce_via_page_ack=True, cookie_request_verified=True,
                       private_profile_reused=phase == 2, **startup)
        return attempt

    def close(self):
        from ruleproxy import windows_runtime
        if self.wrapper is not None:
            windows_runtime.stop(self.wrapper)
            self._owned_workload_cleanup_proven = True
            if self.current_attempt is not None:
                self.current_attempt["owned_workload_cleanup_proven"] = True
        if self.resources is not None:
            self.resources.close()
            self._resources_closed = True
            if self.current_attempt is not None:
                self.current_attempt["resources_closed"] = True
        self.wrapper = self.resources = None
        if self.current_attempt is not None and not self._launch_attempted:
            self._owned_workload_cleanup_proven = True
            self._resources_closed = True
            self.current_attempt["owned_workload_cleanup_proven"] = True
            self.current_attempt["resources_closed"] = True
        if self.current_attempt is not None and self._launch_failed_cleanly:
            self._owned_workload_cleanup_proven = True
            self._resources_closed = True
            self.current_attempt["owned_workload_cleanup_proven"] = True
            self.current_attempt["resources_closed"] = True
        return self.cleanup_facts()

    def cleanup_facts(self):
        if self.current_attempt is None:
            return {"owned_workload_cleanup_proven": self._owned_workload_cleanup_proven,
                    "resources_closed": self._resources_closed}
        return {key: self.current_attempt.get(key) is True for key in (
            "owned_workload_cleanup_proven", "resources_closed")}


def fixture_workers_closed(fixture):
    if fixture is None:
        return True
    try:
        workers = [fixture.worker, *list(fixture.handlers)]
        return (fixture.closed.is_set() and not fixture.worker.is_alive()
                and all(not worker.is_alive() for worker in workers))
    except Exception:
        return False


def finalize_cleanup(result, owner, fixture, directory, before, network_snapshot):
    """Close owned resources and record explicit teardown facts without guessing."""
    owner_closed = owner is None
    resources_closed = owner is None
    fixture_closed = fixture is None
    safe_to_remove_profile = True
    if owner is not None:
        try:
            owner.close()
            facts = owner.cleanup_facts()
            owner_closed = facts.get("owned_workload_cleanup_proven") is True
            resources_closed = facts.get("resources_closed") is True
            if not owner_closed or not resources_closed:
                raise RuntimeError("browser owner did not prove workload and resource cleanup")
        except Exception as exc:
            safe_to_remove_profile = False
            result.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
            try:
                facts = owner.cleanup_facts()
                owner_closed = facts.get("owned_workload_cleanup_proven") is True
                resources_closed = facts.get("resources_closed") is True
            except Exception:
                owner_closed = resources_closed = False
    if fixture is not None:
        try:
            fixture.close()
            fixture_closed = fixture_workers_closed(fixture)
            if not fixture_closed:
                raise RuntimeError("browser fixture worker remained live")
        except Exception as exc:
            safe_to_remove_profile = False
            result.update(fixture_cleanup_error=type(exc).__name__, recovery_directory=str(directory))
            fixture_closed = False
    host_unchanged = None
    if before is not None:
        try:
            host_unchanged = before == network_snapshot()
        except Exception as exc:
            host_unchanged = None
            result["host_snapshot_error"] = type(exc).__name__
    result["host_network_unchanged"] = host_unchanged
    result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                             "status": "passed" if host_unchanged is True else "failed"})
    profile_removed = directory is None
    if directory is not None and safe_to_remove_profile:
        try:
            shutil.rmtree(directory)
            profile_removed = not directory.exists()
            if not profile_removed:
                raise RuntimeError("private browser profile remained after removal")
        except Exception as exc:
            result.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
            profile_removed = False
    result["owned_workload_cleanup_proven"] = owner_closed
    result["resources_closed"] = resources_closed
    result["fixture_workers_closed"] = fixture_closed
    result["private_profile_removed"] = profile_removed
    result["cleanup_proven"] = owner_closed and resources_closed and fixture_closed and profile_removed
    if not result["cleanup_proven"]:
        _RECOVERY_OWNERS.append((owner, fixture, directory))
    return result["cleanup_proven"]


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
              "full_acceptance_passed": False, "public_udp_proven": False, "system_dns_proven": False,
              "real_node_passed": False, "checks": [], "cleanup_proven": False,
              "owned_workload_cleanup_proven": False, "resources_closed": False,
              "fixture_workers_closed": False,
              "private_profile_removed": False, "host_network_unchanged": None,
              "limitations": ["Fixed local HTTP bytes only; no external node or HTTPS origin tested.",
                              "Only persistent cookies are in scope; session login and downloads remain unverified.",
                              "DOM is verified by its page acknowledgement; dumped stdout is not compared."]}
    fixture = owner = directory = before = None
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
        if owner is not None and owner.current_attempt is not None:
            owner.current_attempt["failure_type"] = safe_failure_type(exc)
    finally:
        finalize_cleanup(result, owner, fixture, directory, before,
                         helpers.network_snapshot if helpers is not None else None)
        if owner is not None:
            for attempt in owner.attempts:
                if not any(item is attempt for item in result["checks"]):
                    result["checks"].append(attempt)
        if (result["cleanup_proven"] is not True
                or (before is not None and result["host_network_unchanged"] is not True)):
            result.update(status="failed", browser_fixture_passed=False)
            code = 1
        args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
        helpers.write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
