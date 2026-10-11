"""Start the panel the way a user does, then drive it through its API.

Usage: python smoke_panel.py START_COMMAND [ARGS...]

The command (start-linux.sh, or Start-Windows.cmd in the release package) gets
--no-browser, private ports and a temporary state folder appended. The panel
must come up, import the example YAML, start the bundled core so that its
proxy port accepts connections, and stop it again.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "ruleproxy.example.yaml"
# Panel calls must not go through a system proxy; the probe header keeps them from counting as a page view.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
HEADERS = {"X-RuleProxy-Probe": "1"}


class SmokeFailure(Exception):
    pass


def free_ports(count: int) -> list[int]:
    sockets = [socket.socket() for _ in range(count)]
    try:
        for item in sockets:
            item.bind(("127.0.0.1", 0))
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:
            item.close()


def call(port: int, method: str, path: str, token: str | None = None, body: dict | None = None) -> dict:
    headers = dict(HEADERS)
    data = None
    if token is not None:
        headers["X-RuleProxy-Token"] = token
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with OPENER.open(request, timeout=60) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as exc:
        raise SmokeFailure(f"{method} {path}: HTTP {exc.code} {exc.read(4096).decode('utf-8', 'replace')}") from None


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            return True
    except OSError:
        return False


def wait_for(check, timeout: float, what: str, process: subprocess.Popen):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SmokeFailure(f"the panel exited with code {process.returncode} while waiting for {what}")
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise SmokeFailure(f"timed out waiting for {what}")


def drive(process: subprocess.Popen, panel: int, mixed: int) -> None:
    def state():
        try:
            return call(panel, "GET", "/api/state")
        except (OSError, ValueError, SmokeFailure):
            return None

    current = wait_for(state, 120, "the panel", process)
    print(f"Panel {current['version']} on {current['platform']} is up.", flush=True)
    print("Protection: " + json.dumps(current["protection"], ensure_ascii=False), flush=True)
    token = current["token"]
    current = call(panel, "POST", "/api/import", token, {"yaml": EXAMPLE.read_text(encoding="utf-8")})
    if not current["imported"] or not current["nodes"]:
        raise SmokeFailure("the example YAML was not imported: " + json.dumps(current, ensure_ascii=False)[:2000])
    current = call(panel, "POST", "/api/start", token, {})
    if not current["running"]:
        raise SmokeFailure("the core did not start: " + str(current.get("error")))
    wait_for(lambda: port_open(mixed), 60, "the core's proxy port", process)
    print(f"Core is running from the bundled runtime; proxy port {mixed} accepts connections.", flush=True)
    current = call(panel, "POST", "/api/stop", token, {})
    if current["running"]:
        raise SmokeFailure("the core is still running after stop")
    wait_for(lambda: not port_open(mixed), 30, "the core to stop", process)
    print("Core stopped.", flush=True)


def stop(process: subprocess.Popen, panel: int) -> None:
    """Ask the panel to exit as Ctrl+C would; on Windows end the console tree, as closing it would."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, check=False)
        process.wait(30)
        return
    os.killpg(process.pid, signal.SIGINT)
    try:
        code = process.wait(20)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        raise SmokeFailure("the panel did not exit after Ctrl+C") from None
    if code != 0:
        raise SmokeFailure(f"the panel exited with code {code} after Ctrl+C")
    if port_open(panel):
        raise SmokeFailure("the panel port is still taken after the panel exited")
    print("Panel exited cleanly on Ctrl+C.", flush=True)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    panel, mixed, controller = free_ports(3)
    with tempfile.TemporaryDirectory(prefix="ruleproxy-smoke-") as temp:
        log_path = Path(temp) / "panel.log"
        command = [*argv, "--no-browser", "--port", str(panel), "--proxy-port", str(mixed),
                   "--controller-port", str(controller), "--state-dir", str(Path(temp) / "state")]
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        with open(log_path, "wb") as log:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, **options)
            failure = None
            try:
                drive(process, panel, mixed)
            except SmokeFailure as exc:
                failure = exc
            finally:
                try:
                    stop(process, panel)
                except SmokeFailure as exc:
                    failure = failure or exc
        output = log_path.read_text(encoding="utf-8", errors="replace")
    print("--- panel output ---\n" + output.strip() + "\n---", flush=True)
    if failure:
        print(f"::error title=Panel smoke test::{failure}", flush=True)
        return 1
    print("Smoke test passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
