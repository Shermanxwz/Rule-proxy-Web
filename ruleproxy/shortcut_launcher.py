"""Start one saved app from a desktop shortcut without opening the web panel.

A running panel owns the protected instances. When one answers on the panel port,
the shortcut asks it to start the core (when needed) and the app, then exits.

Otherwise the shortcut becomes that panel: it serves the web panel on the same
port without opening a browser, starts the core and the app, and exits once no
app has run and no panel page has been open for a short while. Later shortcuts
and the web page use this panel. The port is bound before anything else is
started, so shortcuts started together end up sharing one panel instead of
racing for the proxy ports.
"""
from __future__ import annotations

from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback

from .panel_client import panel_state, post, wait_for_panel


_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
# A hosted panel stays this long after its last app closed, so a quick relaunch reuses it.
PANEL_IDLE_SECONDS = 10.0
# How long to wait for a panel that another shortcut is starting on the same port.
PANEL_START_WAIT_SECONDS = 20.0


class LaunchError(RuntimeError):
    """A user-facing reason why the app did not start."""


def run(app_id: str, *, state_dir: Path, panel_port: int, mixed_port: int, controller_port: int) -> int:
    try:
        if not isinstance(app_id, str) or not _APP_ID_RE.fullmatch(app_id):
            raise LaunchError("快捷方式中的应用 ID 无效，请在面板中重新创建快捷方式。")
        state = panel_state(panel_port)
        if state is None:
            server = _bind_panel(panel_port)
            if server is not None:
                _host_panel(server, app_id, Path(state_dir), panel_port, mixed_port, controller_port)
                return 0
            state = wait_for_panel(panel_port, PANEL_START_WAIT_SECONDS)
            if state is None:
                raise LaunchError(f"面板端口 {panel_port} 被其他程序占用。请关闭占用它的程序，或在面板中换用其他端口后重新创建快捷方式。")
        _launch_in_panel(panel_port, state, app_id)
        return 0
    except (RuntimeError, ValueError) as exc:  # LaunchError, PanelError and the runtime's own refusals
        return _report(str(exc))
    except OSError as exc:
        return _report(f"系统拒绝了启动请求：{exc.strerror or exc}")
    except Exception as exc:
        # A desktop shortcut has no console, so even an unexpected failure must reach the user.
        if sys.stderr is not None:
            traceback.print_exc(file=sys.stderr)
        return _report(f"启动失败：{exc}")


def _launch_in_panel(port: int, state: dict, app_id: str) -> None:
    token = state["token"]
    if not state.get("running"):
        post(port, token, "/api/start")
    post(port, token, f"/api/apps/{app_id}/launch")


def _bind_panel(port: int):
    """Claim the panel port, or return None when another process already holds it."""
    from .server import PanelServer

    try:
        return PanelServer(port)
    except OSError:
        return None


def _host_panel(server, app_id: str, state_dir: Path, panel_port: int, mixed_port: int, controller_port: int) -> None:
    from .manager import Manager

    stop = threading.Event()
    _stop_on_signal(stop)
    manager = None
    serving = None
    try:
        manager = Manager(state_dir, panel_port, mixed_port=mixed_port, controller_port=controller_port)
        if manager.app(app_id) is None:
            raise LaunchError("这个应用已不在面板的清单中。请在面板中重新添加后再创建快捷方式。")
        server.manager = manager
        server.hosted = True
        serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, name="RuleProxyPanel", daemon=True)
        serving.start()
        manager.start()
        manager.launch(app_id)
        idle_since = None
        while not stop.wait(0.5):
            if manager.has_active_apps() or server.viewer_recent():
                idle_since = None
            elif idle_since is None:
                idle_since = time.monotonic()
            elif time.monotonic() - idle_since >= PANEL_IDLE_SECONDS:
                break
    finally:
        if serving is not None:
            server.shutdown()
        server.server_close()
        if manager is not None:
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
