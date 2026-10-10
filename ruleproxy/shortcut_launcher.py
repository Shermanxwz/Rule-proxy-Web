"""Start one saved app from a desktop shortcut without keeping the web panel open.

If a panel answers on its port, the shortcut asks that panel to start the core
(when needed) and the app, then exits: the panel keeps owning the protected
instance, exactly as if the button had been pressed there. Otherwise this process
starts its own core, launches the app, waits until the app closes and then stops
both, the same lifecycle as ``--start-core``.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import traceback
import urllib.error
import urllib.request


_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
# Local panel calls must not be routed through a system proxy setting.
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_TIMEOUT = 60


class LaunchError(RuntimeError):
    """A user-facing reason why the app did not start."""


def run(app_id: str, *, state_dir: Path, panel_port: int, mixed_port: int, controller_port: int) -> int:
    try:
        if not isinstance(app_id, str) or not _APP_ID_RE.fullmatch(app_id):
            raise LaunchError("快捷方式中的应用 ID 无效，请在面板中重新创建快捷方式。")
        state = _panel_state(panel_port)
        if state is not None:
            _launch_in_panel(panel_port, state, app_id)
        else:
            _launch_standalone(app_id, Path(state_dir), panel_port, mixed_port, controller_port)
        return 0
    except (RuntimeError, ValueError) as exc:  # LaunchError is a RuntimeError; so are the runtime's own refusals
        return _report(str(exc))
    except OSError as exc:
        return _report(f"系统拒绝了启动请求：{exc.strerror or exc}")
    except Exception as exc:
        # A desktop shortcut has no console, so even an unexpected failure must reach the user.
        if sys.stderr is not None:
            traceback.print_exc(file=sys.stderr)
        return _report(f"启动失败：{exc}")


def _panel_state(port: int) -> dict | None:
    """The running panel's state (it carries the mutation token), or None when no panel answers."""
    try:
        with _OPENER.open(f"http://127.0.0.1:{port}/api/state", timeout=2) as response:
            state = json.loads(response.read(2 * 1024 * 1024))
    except (OSError, ValueError):
        return None
    if isinstance(state, dict) and isinstance(state.get("token"), str) and "version" in state:
        return state
    return None


def _post(port: int, token: str, path: str) -> dict:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=b"{}",
        method="POST",
        headers={"Content-Type": "application/json", "X-RuleProxy-Token": token},
    )
    try:
        with _OPENER.open(request, timeout=_TIMEOUT) as response:
            return json.loads(response.read(2 * 1024 * 1024) or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            message = json.loads(exc.read(65536)).get("error")
        except (OSError, ValueError, AttributeError):
            message = None
        raise LaunchError(message or f"面板拒绝了请求（HTTP {exc.code}）。") from exc
    except OSError as exc:
        raise LaunchError("无法与正在运行的面板通信，请稍后重试。") from exc


def _launch_in_panel(port: int, state: dict, app_id: str) -> None:
    token = state["token"]
    if not state.get("running"):
        _post(port, token, "/api/start")
    _post(port, token, f"/api/apps/{app_id}/launch")


def _launch_standalone(app_id: str, state_dir: Path, panel_port: int, mixed_port: int, controller_port: int) -> None:
    from .manager import Manager

    stop = threading.Event()
    _stop_on_signal(stop)
    manager = Manager(state_dir, panel_port, mixed_port=mixed_port, controller_port=controller_port)
    try:
        if manager.app(app_id) is None:
            raise LaunchError("这个应用已不在面板的清单中。请在面板中重新添加后再创建快捷方式。")
        manager.start()
        manager.launch(app_id)
        while not stop.is_set():
            owned = manager.active.get(app_id)
            if owned is None or owned[0].poll() is not None:
                break
            stop.wait(0.5)
    finally:
        manager.close()


def _stop_on_signal(stop: threading.Event) -> None:
    def handler(*_):
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGHUP"):
        number = getattr(signal, name, None)
        if number is not None:
            try:
                signal.signal(number, handler)
            except (OSError, ValueError):
                pass


def _report(message: str) -> int:
    title = "RuleProxy 无法启动应用"
    if sys.stderr is not None:
        print(f"{title}：{message}", file=sys.stderr, flush=True)
    if sys.platform == "win32":
        try:
            import ctypes

            ctypes.windll.user32.MessageBoxW(None, message, title, 0x10)
        except (AttributeError, OSError):
            pass
    elif shutil.which("notify-send"):
        try:
            subprocess.run(["notify-send", "-a", "RuleProxy", title, message], capture_output=True, timeout=10, check=False)
        except (OSError, subprocess.SubprocessError):
            pass
    return 1
