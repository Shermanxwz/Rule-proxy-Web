"""Own only this panel's core and contained application instances."""
from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import uuid

from . import __version__, autostart
from .config import compile_config
from .launcher import discover_apps, validate_app, prepare_app
from .shortcuts import create_shortcut_files, remove_shortcut_files


ROOT = Path(__file__).resolve().parent.parent
# Installed apps are rescanned in the background when the last scan is older than this.
APP_SCAN_SECONDS = 30.0


def close_resource(resource):
    if resource:
        if hasattr(resource, "close"):
            resource.close()
        else:
            resource.cleanup()


def state_directory() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "RuleProxyWebSafe"
    return Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "ruleproxy-web-safe"


def write_private(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    try:
        with temp.open("x", encoding="utf-8") as output:
            if os.name != "nt":
                os.fchmod(output.fileno(), 0o600)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def stop_process(process: subprocess.Popen):
    if process.poll() is not None:
        return
    if os.name == "nt":
        # This helper stops the owned core; MXC workloads use a separate safe stop.
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=5)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        # The PID belongs to the subprocess we created, never a name-wide kill.
        subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=10)
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
        process.wait(timeout=4)


class Manager:
    def __init__(
        self,
        directory: Path,
        panel_port: int,
        *,
        mixed_port: int = 10809,
        controller_port: int = 19097,
    ):
        ports = {
            "panel_port": panel_port,
            "mixed_port": mixed_port,
            "controller_port": controller_port,
        }
        if any(
            isinstance(port, bool) or not isinstance(port, int) or not 1025 <= port <= 65535
            for port in ports.values()
        ):
            raise ValueError("panel, proxy, and controller ports must be between 1025 and 65535")
        if len(set(ports.values())) != len(ports):
            raise ValueError("panel, proxy, and controller ports must be different")
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.directory.chmod(0o700)
        self.lock = threading.RLock()
        self.token = secrets.token_urlsafe(32)
        self.secret = secrets.token_urlsafe(32)
        self.panel_port = panel_port
        self.mixed_port = mixed_port
        self.controller_port = controller_port
        self.core: subprocess.Popen | None = None
        self.core_log = None
        self.error = ""
        self.active = {}
        # bwrap --die-with-parent follows the creating THREAD on Linux. HTTP
        # request threads are short lived; all launches must have a stable owner.
        self.launch_owner = ThreadPoolExecutor(max_workers=1, thread_name_prefix="RuleProxyLaunchOwner")
        self.settings = {"core_path": "", "runtime_path": "", "selected_node": None, "apps": []}
        file = self.directory / "settings.json"
        if file.exists():
            data = json.loads(file.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                for key in self.settings:
                    if key in data:
                        self.settings[key] = data[key]
        self.source = (self.directory / "source.yaml").read_text(encoding="utf-8") if (self.directory / "source.yaml").exists() else None
        self.compiled = None
        if self.source:
            self._load_saved_config()
        self._probe_lock = threading.Lock()
        self._probe_cache = None
        # Installed-app discovery can take seconds on Windows, so it runs in the background.
        self._apps_lock = threading.Lock()
        self._apps: list | None = None
        self._apps_time = 0.0
        self._apps_scan: threading.Thread | None = None
        self.closed = threading.Event()
        threading.Thread(target=self._watch, daemon=True).start()

    def _save(self):
        write_private(self.directory / "settings.json", json.dumps(self.settings, ensure_ascii=False, indent=2))

    def _load_saved_config(self):
        """Compile the saved YAML. One that no longer compiles must not keep the panel from opening."""
        try:
            self.compiled = self._compile(self.source)
            return
        except ValueError:
            pass
        try:
            # The saved node may have gone; fall back to the first node of the same config.
            self.compiled = compile_config(self.source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port)
            self.settings["selected_node"] = self.compiled.selected_node
        except ValueError as exc:
            self.error = f"已保存的配置无法使用，请重新导入：{exc}"

    def _compile(self, source, selected=None):
        return compile_config(source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port, selected_node=selected if selected is not None else self.settings.get("selected_node"))

    def protection(self):
        """The isolation check, run once. It can take seconds, so callers hold no other lock."""
        with self._probe_lock:
            if self._probe_cache is None:
                self._probe_cache = self._check_isolation()
            return self._probe_cache

    def _check_isolation(self):
        try:
            if sys.platform == "linux":
                from .linux_runtime import probe
                return probe()
            if sys.platform == "win32":
                from .windows_runtime import probe, retire_unused_runtime_files
                if not self.settings.get("runtime_path"):
                    # Only the bundled runtime; a runtime the user pointed at is left as it is.
                    retire_unused_runtime_files(Path(self.runtime_path()).parent)
                return probe(self.runtime_path(), self.mixed_port)
            return {"supported": False, "backend": "不支持的系统", "detail": "当前仅支持 Windows 和 Linux。", "limitations": []}
        except Exception as exc:  # an unexpected failure means "not protected"; it must not take the panel down
            traceback.print_exc()
            return {"supported": False, "backend": None, "detail": f"隔离能力检查出错，受保护启动已禁用：{exc}", "limitations": []}

    def ports(self) -> tuple[int, int, int]:
        return (self.panel_port, self.mixed_port, self.controller_port)

    def autostart_status(self) -> str:
        try:
            return autostart.status(self.directory, self.ports())
        except OSError:
            return "off"

    def set_autostart(self, enabled) -> None:
        """Start this panel, quietly and with its ports and data folder, when the user logs in."""
        if not isinstance(enabled, bool):
            raise ValueError("请求无效。")
        try:
            if enabled:
                autostart.enable(self.directory, self.ports())
            else:
                autostart.disable()
        except OSError as exc:
            raise ValueError(f"无法更改登录后自动启动：{exc}") from exc

    def runtime_path(self):
        return self.settings.get("runtime_path") or str(ROOT / "bin/windows-amd64/wxc-exec.exe")

    def files_dir(self):
        """The folder isolated apps can read and write, shown in the panel; None when they get none."""
        if sys.platform != "linux":
            return None
        from .linux_runtime import downloads_folder

        folder = downloads_folder(self.directory)
        return str(folder[1]) if folder else None

    def _scan_apps(self):
        try:
            apps = discover_apps(refresh=True)
        except (OSError, ValueError, UnicodeError):
            apps = []  # a broken desktop entry or unreadable folder must not break the panel
        with self._apps_lock:
            self._apps, self._apps_time = apps, time.monotonic()

    def available_apps(self, *, refresh=False):
        """Installed apps for the add list, and whether a scan is still running.

        A state read never waits for a slow scan: it gets the last result while a
        background scan refreshes it. Only an explicit rescan waits.
        """
        if refresh:
            self._scan_apps()
        with self._apps_lock:
            stale = self._apps is None or time.monotonic() - self._apps_time > APP_SCAN_SECONDS
            if stale and (self._apps_scan is None or not self._apps_scan.is_alive()):
                self._apps_scan = threading.Thread(target=self._scan_apps, name="RuleProxyAppScan", daemon=True)
                self._apps_scan.start()
            scanning = self._apps_scan is not None and self._apps_scan.is_alive()
            return list(self._apps or []), scanning

    def state(self, *, refresh_apps=False):
        # Both reads below touch the disk, so they stay outside the manager lock.
        available, scanning = self.available_apps(refresh=refresh_apps)
        files_dir = self.files_dir()
        protection = self.protection()
        starts_at_login = self.autostart_status()
        with self.lock:
            running = bool(self.core and self.core.poll() is None)
            apps = []
            for app in self.settings["apps"]:
                owned = self.active.get(app["id"])
                alive = bool(owned and owned[0].poll() is None)
                pending = bool(alive and getattr(owned[1], "failed_process", None) is not None)
                apps.append({**app, "active": alive and not pending, "cleanup_pending": pending})
            compiled = self.compiled
            return {
                "token": self.token,
                "platform": "Windows" if sys.platform == "win32" else "Linux" if sys.platform == "linux" else sys.platform,
                "version": __version__,
                "imported": bool(compiled),
                "running": running,
                "error": self.error,
                "core_path": self.settings["core_path"],
                "runtime_path": self.settings["runtime_path"],
                "selected_node": compiled.selected_node if compiled else "",
                "nodes": compiled.nodes if compiled else [],
                "primary_group": compiled.primary_group if compiled else "",
                "apps": apps,
                "available_apps": available,
                "apps_scanning": scanning,
                "files_dir": files_dir,
                "proxy_url": f"http://127.0.0.1:{self.mixed_port}",
                "ports": {"mixed": self.mixed_port, "panel": self.panel_port},
                "protection": protection,
                "autostart": starts_at_login,
                "warnings": compiled.warnings if compiled else [],
            }

    def import_yaml(self, source):
        with self.lock:
            if self.core and self.core.poll() is None:
                raise ValueError("请先停止代理，再导入新配置。")
            compiled = compile_config(source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port)
            write_private(self.directory / "source.yaml", source)
            self.source, self.compiled = source, compiled
            self.settings["selected_node"] = compiled.selected_node
            self.error = ""
            self._save()

    def save_settings(self, data):
        with self.lock:
            if self.core and self.core.poll() is None:
                raise ValueError("请先停止代理，再修改程序路径。")
            for key in ("core_path", "runtime_path"):
                if key not in data:
                    continue
                value = data[key]
                if not isinstance(value, str) or "\0" in value or len(value) > 4096:
                    raise ValueError("程序路径无效。")
                self.settings[key] = value.strip()
            self._probe_cache = None
            self._save()

    def core_path(self):
        supplied = self.settings["core_path"]
        bundled = ROOT / "bin" / ("windows-amd64/mihomo.exe" if os.name == "nt" else "linux-amd64/mihomo")
        path = Path(supplied or (str(bundled) if bundled.is_file() else shutil.which("mihomo") or ""))
        if not path.is_file():
            raise ValueError("找不到 Mihomo。请先安装运行组件，或填写程序路径。")
        if os.name != "nt" and not os.access(path, os.X_OK):
            raise ValueError("Mihomo 文件没有执行权限。")
        return path.resolve()

    def _controller(self, method, path, data=None):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://127.0.0.1:{self.controller_port}" + path, data=json.dumps(data).encode() if data is not None else None, method=method, headers={"Authorization": "Bearer " + self.secret, "Content-Type": "application/json"})
        with opener.open(req, timeout=2) as response:
            body = response.read(2 * 1024 * 1024)
        return json.loads(body) if body else None

    def start(self):
        with self.lock:
            if self.core and self.core.poll() is None:
                return
            if not self.compiled:
                raise ValueError("请先导入 YAML。")
            self.compiled = self._compile(self.source)
            core = self.core_path()
            # Refuse occupied ports before spawning. No existing process is stopped.
            reservations = []
            try:
                for port in (self.mixed_port, self.controller_port):
                    reservation = socket.socket()
                    if sys.platform == "linux":
                        # A stopped local core can leave TCP TIME_WAIT sockets.
                        # Linux reuse permits these, while an active listener
                        # still makes this reservation fail.
                        reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    reservation.bind(("127.0.0.1", port))
                    reservations.append(reservation)
            except OSError as exc:
                raise ValueError("本地代理端口已被占用，请关闭占用程序后重试。") from exc
            finally:
                for reservation in reservations:
                    reservation.close()
            config = self.directory / "core/config.yaml"
            write_private(config, self.compiled.text)
            args = [str(core), "-d", str(config.parent), "-f", str(config)]
            self.core_log = (self.directory / "core.log").open("w", encoding="utf-8")
            if os.name != "nt":
                os.fchmod(self.core_log.fileno(), 0o600)
            try:
                validation = subprocess.run([str(core), "-t", *args[1:]], stdout=self.core_log, stderr=subprocess.STDOUT, timeout=30)
                if validation.returncode:
                    raise ValueError("Mihomo 配置校验未通过，应用未启动。详情保存在本机 core.log。")
                options = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
                self.core = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=self.core_log, stderr=subprocess.STDOUT, **options)
                for _ in range(50):
                    if self.core.poll() is not None:
                        break
                    try:
                        self._controller("GET", "/version")
                        self.error = ""
                        return
                    except Exception:
                        time.sleep(0.1)
                raise ValueError("Mihomo 未能启动；未启动任何应用。请查看本机 core.log。")
            except Exception:
                if self.core:
                    stop_process(self.core)
                    self.core = None
                self.core_log.close()
                self.core_log = None
                raise

    def select_node(self, name):
        with self.lock:
            if not isinstance(name, str) or not name:
                raise ValueError("请选择有效的代理节点。")
            if not self.source:
                raise ValueError("请先导入 YAML。")
            compiled = self._compile(self.source, name)
            if self.core and self.core.poll() is None:
                try:
                    self._controller("PUT", "/proxies/" + urllib.parse.quote(compiled.primary_group, safe=""), {"name": name})
                except (OSError, ValueError) as exc:
                    raise ValueError("切换节点失败：核心没有响应，请稍后重试。") from exc
            self.compiled = compiled
            self.settings["selected_node"] = name
            self._save()

    def add_app(self, data):
        with self.lock:
            normalized = validate_app(data)
            if any(app["path"] == normalized["path"] for app in self.settings["apps"]):
                raise ValueError("这个应用已在列表中。")
            normalized.update(id=uuid.uuid4().hex, enabled=data.get("enabled", True) is True)
            self.settings["apps"].append(normalized)
            self._save()

    def app(self, ident):
        return next((app for app in self.settings["apps"] if app["id"] == ident), None)

    def change_app(self, ident, enabled=None, delete=False):
        with self.lock:
            app = self.app(ident)
            if app is None:
                raise ValueError("应用不存在。")
            if delete or enabled is False:
                self.stop_app(ident)
            if delete:
                remove_shortcut_files(app)
                self.settings["apps"].remove(app)
            else:
                if not isinstance(enabled, bool):
                    raise ValueError("enabled 必须是布尔值。")
                app["enabled"] = enabled
            self._save()

    def create_shortcuts(self, ident):
        """Write launcher files that start this app headlessly; returns their paths."""
        with self.lock:
            app = self.app(ident)
            if app is None:
                raise ValueError("应用不存在。")
            created = create_shortcut_files(app, state_dir=self.directory, ports=(self.panel_port, self.mixed_port, self.controller_port))
            app["shortcuts"] = [str(path) for path in created]
            self._save()
            return list(app["shortcuts"])

    def launch(self, ident):
        with self.lock:
            app = self.app(ident)
            if not app or not app["enabled"]:
                raise ValueError("请先将应用加入待保护列表。")
            if not self.core or self.core.poll() is not None:
                raise ValueError("请先启动代理。")
            if not self.protection()["supported"]:
                raise ValueError(self.protection()["detail"])
            if ident in self.active and self.active[ident][0].poll() is None:
                if getattr(self.active[ident][1], "failed_process", None) is not None:
                    raise ValueError("上次启动的隔离守卫尚未完成清理，请先点击关闭守卫。")
                return {"pid": self.active[ident][0].pid, "adapter": app["adapter"], "detail": "这个应用已经在隔离中运行。"}
            if ident in self.active:
                self.stop_app(ident)
            profile = self.directory / "profiles" / ident
            app_proxy_port = self.mixed_port
            command, env, _detail = prepare_app(app, app_proxy_port, self.directory / "profiles")
            if sys.platform == "linux":
                from .linux_runtime import downloads_folder, launch
                downloads = downloads_folder(self.directory)
                process, resource = self.launch_owner.submit(launch, command, env, profile, self.mixed_port, downloads).result()
            elif sys.platform == "win32":
                from .windows_runtime import launch
                try:
                    process, resource = launch(command, env, profile, self.mixed_port, self.runtime_path())
                except Exception as exc:
                    failed_process = getattr(exc, "process", None)
                    failed_resource = getattr(exc, "resource", None)
                    if failed_process is not None and failed_resource is not None:
                        self.active[ident] = (failed_process, failed_resource)
                        self.error = "应用未启动；隔离守卫仍在清理中，请关闭该守卫后重试。"
                    raise
            else:
                raise ValueError("系统不支持应用隔离。")
            self.active[ident] = (process, resource)
            self.error = ""
            return {"pid": process.pid, "adapter": app["adapter"], "detail": "仅此隔离实例受保护。不支持的流量阻断，不会直连。"}

    def stop_app(self, ident):
        with self.lock:
            owned = self.active.get(ident)
            if owned:
                process, resource = owned
                if sys.platform == "win32":
                    from .windows_runtime import stop
                    stop(process)
                elif sys.platform == "linux":
                    from .linux_runtime import stop as stop_sandboxed_app
                    stop_sandboxed_app(process)
                else:
                    stop_process(process)
                close_resource(resource)
                self.active.pop(ident, None)

    def has_active_apps(self):
        """True while any instance this panel started is still running."""
        with self.lock:
            return any(process.poll() is None for process, _resource in self.active.values())

    def stop(self):
        with self.lock:
            for ident in list(self.active):
                self.stop_app(ident)
            if self.core:
                stop_process(self.core)
                self.core = None
            if self.core_log:
                self.core_log.close()
                self.core_log = None

    def _watch(self):
        while not self.closed.wait(0.5):
            with self.lock:
                if self.core and self.core.poll() is not None:
                    self.error = "代理核心已退出，受保护应用已关闭。"
                    try:
                        self.stop()
                    except Exception:
                        self.error = "代理核心已退出；部分隔离实例未能关闭，请手动关闭其窗口。隔离不会退回直连。"
                for ident, (process, resource) in list(self.active.items()):
                    if process.poll() is not None:
                        close_resource(resource)
                        self.active.pop(ident, None)

    def close(self):
        self.closed.set()
        try:
            self.stop()
        finally:
            self.launch_owner.shutdown(wait=True)
