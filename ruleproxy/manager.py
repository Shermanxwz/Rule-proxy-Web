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
import urllib.parse
import urllib.request
import uuid

from . import __version__
from .config import compile_config
from .launcher import discover_apps, validate_app, prepare_app


ROOT = Path(__file__).resolve().parent.parent


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
        # Let MXC's console-control cleanup run before the bounded fallback.
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
    def __init__(self, directory: Path, panel_port: int):
        self.directory = directory.resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            self.directory.chmod(0o700)
        self.lock = threading.RLock()
        self.token = secrets.token_urlsafe(32)
        self.secret = secrets.token_urlsafe(32)
        self.panel_port = panel_port
        self.mixed_port, self.controller_port = 10809, 19097
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
            self.compiled = self._compile(self.source)
        self._probe_cache = None
        self.closed = threading.Event()
        threading.Thread(target=self._watch, daemon=True).start()

    def _save(self):
        write_private(self.directory / "settings.json", json.dumps(self.settings, ensure_ascii=False, indent=2))

    def _compile(self, source, selected=None):
        return compile_config(source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port, selected_node=selected if selected is not None else self.settings.get("selected_node"))

    def protection(self):
        if self._probe_cache is None:
            if sys.platform == "linux":
                from .linux_runtime import probe
                self._probe_cache = probe()
            elif sys.platform == "win32":
                self._probe_cache = {"supported": False, "backend": "Windows 隔离待完善", "detail": "现有 Windows 代理隔离会允许部分入站通信，无法满足绝不直连要求，应用启动已禁用。", "limitations": ["YAML 导入和本地核心管理可用。", "严格应用隔离尚未开放，不会回退为直连启动。"]}
            else:
                self._probe_cache = {"supported": False, "backend": "不支持的系统", "detail": "当前仅支持 Windows 和 Linux。", "limitations": []}
        return self._probe_cache

    def runtime_path(self):
        return self.settings.get("runtime_path") or str(ROOT / "bin/windows-amd64/wxc-exec.exe")

    def state(self):
        with self.lock:
            running = bool(self.core and self.core.poll() is None)
            apps = [{**app, "active": app["id"] in self.active and self.active[app["id"]][0].poll() is None} for app in self.settings["apps"]]
            return {"token": self.token, "platform": "Windows" if sys.platform == "win32" else "Linux" if sys.platform == "linux" else sys.platform, "version": __version__, "imported": bool(self.compiled), "running": running, "error": self.error, "core_path": self.settings["core_path"], "runtime_path": self.settings["runtime_path"], "selected_node": self.compiled.selected_node if self.compiled else "", "nodes": self.compiled.nodes if self.compiled else [], "primary_group": self.compiled.primary_group if self.compiled else "", "apps": apps, "available_apps": discover_apps(), "proxy_url": f"http://127.0.0.1:{self.mixed_port}", "ports": {"mixed": self.mixed_port, "panel": self.panel_port}, "protection": self.protection(), "warnings": self.compiled.warnings if self.compiled else []}

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
                self._controller("PUT", "/proxies/" + urllib.parse.quote(compiled.primary_group, safe=""), {"name": name})
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
                self.settings["apps"].remove(app)
            else:
                if not isinstance(enabled, bool):
                    raise ValueError("enabled 必须是布尔值。")
                app["enabled"] = enabled
            self._save()

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
                return {"pid": self.active[ident][0].pid, "adapter": app["adapter"], "detail": "这个应用已经在隔离中运行。"}
            command, env, _detail = prepare_app(app, self.mixed_port, self.directory / "profiles")
            profile = self.directory / "profiles" / ident
            if sys.platform == "linux":
                from .linux_runtime import launch
                process, resource = self.launch_owner.submit(launch, command, env, profile, self.mixed_port).result()
            elif sys.platform == "win32":
                from .windows_runtime import launch
                process, resource = launch(command, env, profile, self.mixed_port, self.runtime_path())
            else:
                raise ValueError("系统不支持应用隔离。")
            self.active[ident] = (process, resource)
            return {"pid": process.pid, "adapter": app["adapter"], "detail": "仅此隔离实例受保护。不支持的流量阻断，不会直连。"}

    def stop_app(self, ident):
        with self.lock:
            owned = self.active.get(ident)
            if owned:
                process, resource = owned
                if sys.platform == "win32":
                    from .windows_runtime import stop
                    stop(process)
                else:
                    stop_process(process)
                close_resource(resource)
                self.active.pop(ident, None)

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
        self.stop()
        self.launch_owner.shutdown(wait=True)
