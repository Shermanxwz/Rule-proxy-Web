"""Start the panel the way a user does, then drive it through its API.

Usage: python smoke_panel.py START_COMMAND [ARGS...]

The command (start-linux.sh, or Start-Windows.cmd) gets --no-browser, private
ports and a temporary state folder appended. The panel must come up, import
the example YAML, start the bundled core so that its proxy port accepts
connections, and stop it again.

On Linux the start script keeps running as the panel, which then exits on
Ctrl+C. On Windows the start script returns at once and the panel runs without
a console, so it is stopped with the page's Quit request and must have written
its messages to panel.log.
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
import traceback
import urllib.error
import urllib.request

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "ruleproxy.example.yaml"
# Panel calls must not go through a system proxy; the probe header keeps them from counting as a page view.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
HEADERS = {"X-RuleProxy-Probe": "1"}
WINDOWS = os.name == "nt"


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


def wait_for(check, timeout: float, what: str, panel: subprocess.Popen | None = None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if panel is not None and panel.poll() is not None:
            raise SmokeFailure(f"the panel exited with code {panel.returncode} while waiting for {what}")
        value = check()
        if value:
            return value
        time.sleep(0.5)
    raise SmokeFailure(f"timed out waiting for {what}")


def drive(port: int, mixed: int, panel: subprocess.Popen | None) -> tuple[str, str]:
    """Import, start and stop the core. Returns the token and a summary."""
    def state():
        try:
            return call(port, "GET", "/api/state")
        except (OSError, ValueError, SmokeFailure):
            return None

    current = wait_for(state, 300, "the panel", panel)
    protection = json.dumps(current["protection"], ensure_ascii=False)
    print(f"Panel {current['version']} on {current['platform']} is up. Protection: {protection}", flush=True)
    token = current["token"]
    current = call(port, "POST", "/api/import", token, {"yaml": EXAMPLE.read_text(encoding="utf-8")})
    if not current["imported"] or not current["nodes"]:
        raise SmokeFailure("the example YAML was not imported: " + json.dumps(current, ensure_ascii=False)[:2000])
    current = call(port, "POST", "/api/start", token, {})
    if not current["running"]:
        raise SmokeFailure("the core did not start: " + str(current.get("error")))
    wait_for(lambda: port_open(mixed), 60, "the core's proxy port", panel)
    print(f"Core is running from the bundled runtime; proxy port {mixed} accepts connections.", flush=True)
    current = call(port, "POST", "/api/stop", token, {})
    if current["running"]:
        raise SmokeFailure("the core is still running after stop")
    wait_for(lambda: not port_open(mixed), 30, "the core to stop", panel)
    print("Core stopped.", flush=True)
    summary = (f"Panel {current['version']} on {current['platform']}: imported the example, started and stopped "
               f"the bundled core, autostart {current.get('autostart')}. Protection: {protection}")
    return token, summary


def quit_panel(port: int, mixed: int, token: str) -> None:
    """Stop the panel with the page's Quit request; it shuts down the core and frees both ports."""
    reply = call(port, "POST", "/api/quit", token, {})
    if reply.get("quitting") is not True:
        raise SmokeFailure(f"unexpected reply to quit: {reply}")
    wait_for(lambda: not port_open(port), 30, "the panel to quit")
    if port_open(mixed):
        raise SmokeFailure("the core's proxy port is still open after quitting")
    print("Panel quit from its page and freed its ports.", flush=True)


def interrupt(panel: subprocess.Popen, port: int) -> None:
    """Stop the panel as Ctrl+C in its terminal would."""
    os.killpg(panel.pid, signal.SIGINT)
    try:
        code = panel.wait(20)
    except subprocess.TimeoutExpired:
        os.killpg(panel.pid, signal.SIGKILL)
        raise SmokeFailure("the panel did not exit after Ctrl+C") from None
    if code != 0:
        raise SmokeFailure(f"the panel exited with code {code} after Ctrl+C")
    wait_for(lambda: not port_open(port), 10, "the panel port to close")
    print("Panel exited cleanly on Ctrl+C.", flush=True)


def annotate(kind: str, text: str) -> None:
    text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    print(f"::{kind} title=Panel smoke test::{text}", flush=True)


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    port, mixed, controller = free_ports(3)
    failure = summary = None
    # Files of a stopped panel may stay locked for a moment on Windows; leftovers in the temp folder do no harm.
    with tempfile.TemporaryDirectory(prefix="ruleproxy-smoke-", ignore_cleanup_errors=True) as temp:
        state_dir = Path(temp) / "state"
        launcher_log = Path(temp) / "launcher.log"
        command = [*argv, "--no-browser", "--port", str(port), "--proxy-port", str(mixed),
                   "--controller-port", str(controller), "--state-dir", str(state_dir)]
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if WINDOWS else {"start_new_session": True}
        token = None
        try:
            with open(launcher_log, "wb") as log:
                launcher = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, **options)
                try:
                    if WINDOWS:
                        # The launcher prepares a source checkout if needed, starts the panel without a console, and returns.
                        code = launcher.wait(600)
                        if code != 0:
                            raise SmokeFailure(f"the start script exited with code {code}")
                    token, summary = drive(port, mixed, None if WINDOWS else launcher)
                except Exception:  # report anything, expected or not, with its traceback
                    failure = traceback.format_exc()
                finally:
                    try:
                        if WINDOWS:
                            if token is None and port_open(port):
                                token = call(port, "GET", "/api/state")["token"]
                            if token:
                                quit_panel(port, mixed, token)
                        elif launcher.poll() is None:
                            interrupt(launcher, port)
                    except Exception:
                        failure = failure or traceback.format_exc()
        except Exception:
            failure = failure or traceback.format_exc()
        output = launcher_log.read_text(encoding="utf-8", errors="replace").strip() if launcher_log.exists() else ""
        panel_log = state_dir / "panel.log"
        logged = panel_log.read_text(encoding="utf-8", errors="replace").strip() if panel_log.exists() else ""
    print("--- start script output ---\n" + output + "\n---", flush=True)
    if WINDOWS:
        print("--- panel.log ---\n" + logged + "\n---", flush=True)
        if not failure and f"RuleProxy: http://127.0.0.1:{port}" not in logged:
            failure = "the panel ran without a console but did not write its address to panel.log"
    if failure:
        annotate("error", failure[-2500:] + "\n--- output ---\n" + (output + "\n" + logged)[-1500:])
        return 1
    annotate("notice", summary)
    print("Smoke test passed.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
