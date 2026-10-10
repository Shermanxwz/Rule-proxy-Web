"""Talk to a RuleProxy panel that is already running on this machine."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request


# Local panel calls must never be routed through a system proxy setting.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# State reads that carry this header are tool probes, not an open panel page.
PROBE_HEADER = "X-RuleProxy-Probe"
_MAX_RESPONSE = 2 * 1024 * 1024


class PanelError(RuntimeError):
    """A running panel refused a request, or could not be reached."""


def panel_state(port: int, timeout: float = 2) -> dict | None:
    """Return the running panel's state (it carries the mutation token), or None when no panel answers."""
    request = urllib.request.Request(f"http://127.0.0.1:{port}/api/state", headers={PROBE_HEADER: "1"})
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            state = json.loads(response.read(_MAX_RESPONSE))
    except (OSError, ValueError):
        return None
    if isinstance(state, dict) and isinstance(state.get("token"), str) and "version" in state:
        return state
    return None


def wait_for_panel(port: int, timeout: float) -> dict | None:
    """Poll until a panel answers on the port, for at most ``timeout`` seconds."""
    deadline = time.monotonic() + timeout
    while True:
        state = panel_state(port)
        if state is not None or time.monotonic() >= deadline:
            return state
        time.sleep(0.25)


def post(port: int, token: str, path: str, timeout: float = 60) -> dict:
    """Send an authorized mutation to the running panel and return its JSON reply."""
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json", "X-RuleProxy-Token": token},
    )
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            reply = json.loads(response.read(_MAX_RESPONSE) or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read(65536)).get("error")
        except (OSError, ValueError, AttributeError):
            message = None
        raise PanelError(message or f"面板拒绝了请求（HTTP {exc.code}）。") from exc
    except (OSError, ValueError) as exc:
        raise PanelError("无法与正在运行的面板通信，请稍后重试。") from exc
    return reply if isinstance(reply, dict) else {}
