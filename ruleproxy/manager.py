"""Own only this panel's core and contained application instances."""
from __future__ import annotations

import json
import copy
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import re
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
from .config import CAPTURE_MODES, MAX_SOURCE_BYTES, compile_config
from .launcher import app_profile_directory, discover_apps, validate_app, prepare_app
from .shortcuts import create_shortcut_files, remove_shortcut_files


ROOT = Path(__file__).resolve().parent.parent
# Installed apps are rescanned in the background when the last scan is older than this.
APP_SCAN_SECONDS = 30.0
MAX_APPS = 128
MAX_SETTINGS_BYTES = 32 * 1024 * 1024
_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")


def valid_text(value, limit):
    if not isinstance(value, str) or "\0" in value or len(value) > limit:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return True


def read_saved_text(path: Path, limit: int):
    try:
        with path.open("rb") as source:
            data = source.read(limit + 1)
    except FileNotFoundError:
        return None
    if len(data) > limit:
        raise ValueError("saved file exceeds its size limit")
    return data.decode("utf-8")


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
        # Popen retains the owned core's kernel handle. Never kill by image name
        # or re-open a PID after it might have been recycled.
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT)
            process.wait(timeout=5)
            return
        except (OSError, subprocess.TimeoutExpired):
            pass
        process.terminate()
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
        self._core_job = None
        self._proxy_watchdog = None
        self.error = ""
        self.active = {}
        self._profile_preparing: set[str] = set()
        self._windows_backend = None
        self._windows_paths = []
        self._windows_family_paths = {}
        self._global_backend = None
        self._global_fault = False
        self._legacy_recovered = False
        self._restore_pending = False
        self._restore_retry_at = 0.0
        self.quitting = False
        # bwrap --die-with-parent follows the creating THREAD on Linux. HTTP
        # request threads are short lived; all launches must have a stable owner.
        self.launch_owner = ThreadPoolExecutor(max_workers=1, thread_name_prefix="RuleProxyLaunchOwner")
        self.settings = {"core_path": "", "runtime_path": "", "selected_node": None,
                         "capture_mode": "applications", "windows_app_guard": False, "apps": []}
        self.storage_warnings = []
        self._settings_need_backup = False
        self._restore_settings()
        try:
            self.source = read_saved_text(self.directory / "source.yaml", MAX_SOURCE_BYTES)
        except (OSError, ValueError, UnicodeError):
            self.source = None
            self.error = "已保存的 YAML 无法读取或过大，请重新导入；原文件仍保留在数据目录中。"
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
        from .system_proxy import BACKUP
        if (self.directory / BACKUP).exists() or self._legacy_artifacts_present():
            # Recovery is independent of the newly selected capture mode.
            # start() also waits for/retries it before launching any core.
            threading.Thread(target=self._recover_global, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def _legacy_artifacts_present(self):
        if sys.platform == 'win32':
            return (ROOT / 'deployment.json').exists()
        if sys.platform == 'linux':
            from .linux_global_runtime import INSTALL_ROOT, RUN_ROOT
            return INSTALL_ROOT.exists() or (RUN_ROOT / ('lease-' + str(os.getuid()) + '.json')).exists()
        return False

    def _recover_global(self, *, raise_errors=False):
        """Undo whatever a crashed panel or an older TUN version left behind."""
        with self.lock:
            if self.core is not None:
                return
            errors = []
            try:
                from . import system_proxy
                system_proxy.restore(self.directory)
            except Exception as exc:
                errors.append(f'上次的系统代理设置未能自动恢复：{exc}')
                self._restore_pending = True
            try:
                self._release_legacy_tun()
            except Exception as exc:
                errors.append(str(exc))
            if errors:
                self._global_fault = True
                self.error = '；'.join(errors)
                if raise_errors:
                    raise ValueError(self.error)
            else:
                self._global_fault = self._restore_pending = False

    def _release_legacy_tun(self):
        # Up to 0.3.0-rc.14 global mode was a privileged TUN whose guard kept
        # blocking after a failure. That mode is gone; only its cleanup stays.
        if self._legacy_recovered or sys.platform not in ('win32', 'linux'):
            return
        status = self.global_status()
        active = (status.get('running') or status.get('protection_active')
                or (status.get('guard') or {}).get('active')
                or (status.get('dns') or {}).get('active')
                or status.get('state') in {'blocked', 'unknown'})
        if (not active and not self._legacy_artifacts_present() and status.get('supported') is False):
            self._legacy_recovered = True
            return
        def clean(value):
            if not isinstance(value, dict) or value.get('running') is not False:
                return False
            if value.get('state') not in {'idle', 'stopped'}:
                return False
            if 'guard' in value or 'dns' in value:
                return all(isinstance(value.get(name), dict) and value[name].get('active') is False
                           and value[name].get('supported') is not False for name in ('guard', 'dns'))
            return value.get('protection_active') is False
        try:
            if not clean(status):
                # Checking/unavailable or incomplete WFP status is not proof
                # that the old rules are gone. The fixed recovery operation
                # reads them synchronously and confirms removal.
                result = self.global_backend().stop()
                if not clean(result):
                    raise ValueError('旧版网络保护尚未确认完全撤销。')
        except Exception as exc:
            self._global_fault = True
            self.error = (f'旧版全局 TUN 留下的网络规则未能自动清除：{exc}。'
                          '请点击停止重试，或运行卸载脚本恢复网络。')
            raise ValueError(self.error) from exc
        self._legacy_recovered = True

    def _restore_settings(self):
        """Restore bounded records without losing profiles for temporarily missing apps."""
        invalid = False
        try:
            raw = read_saved_text(self.directory / "settings.json", MAX_SETTINGS_BYTES)
            if raw is None:
                return
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("settings must be an object")
        except (OSError, ValueError, UnicodeError, RecursionError):
            data = {}
            invalid = True
        for key in ("core_path", "runtime_path", "selected_node"):
            if key not in data:
                continue
            value = data[key]
            if key == "selected_node" and value is None:
                continue
            if valid_text(value, 4096):
                self.settings[key] = value
            else:
                invalid = True
        mode = data.get("capture_mode", "applications")
        if isinstance(mode, str) and mode in CAPTURE_MODES:
            self.settings["capture_mode"] = mode
        else:
            invalid = True
        if "windows_app_guard" in data:
            if isinstance(data["windows_app_guard"], bool):
                self.settings["windows_app_guard"] = data["windows_app_guard"]
            else:
                invalid = True
        records = data.get("apps", [])
        if not isinstance(records, list):
            records = []
            invalid = True
        ids, paths = set(), set()
        for record in records[:MAX_APPS]:
            try:
                if not isinstance(record, dict):
                    raise ValueError("app must be an object")
                ident = record.get("id")
                enabled = record.get("enabled", True)
                if not isinstance(ident, str) or not _APP_ID_RE.fullmatch(ident) or not isinstance(enabled, bool):
                    raise ValueError("invalid app id or enabled state")
                app = validate_app(record, check_exists=False)
                path = os.path.normcase(app["path"])
                if ident in ids or path in paths:
                    raise ValueError("duplicate app")
                app.update(id=ident, enabled=enabled)
                shortcuts = record.get("shortcuts", [])
                if not isinstance(shortcuts, list) or len(shortcuts) > 4 or any(not valid_text(item, 4096) for item in shortcuts):
                    invalid = True
                elif shortcuts:
                    app["shortcuts"] = shortcuts
                self.settings["apps"].append(app)
                ids.add(ident)
                paths.add(path)
            except (OSError, ValueError, UnicodeError, RuntimeError):
                invalid = True
        if len(records) > MAX_APPS:
            invalid = True
        if invalid:
            self._settings_need_backup = True
            self.storage_warnings.append("已忽略无法使用的设置或应用记录；原 settings.json 保留，首次保存时会另存备份。")

    def _save(self):
        path = self.directory / "settings.json"
        backup = None
        if self._settings_need_backup:
            backup = path.with_name(f"settings.recovery-{uuid.uuid4().hex}.json")
            try:
                path.replace(backup)
            except FileNotFoundError:
                backup = None
            self._settings_need_backup = False
        try:
            write_private(path, json.dumps(self.settings, ensure_ascii=False, indent=2))
        except Exception:
            if backup is not None:
                backup.replace(path)
                self._settings_need_backup = True
            raise
        if backup is not None:
            self.storage_warnings = [f"原设置中的无效内容已忽略，原文件备份为 {backup.name}。"]

    def _load_saved_config(self):
        """Compile the saved YAML. One that no longer compiles must not keep the panel from opening."""
        try:
            self.compiled = self._compile(self.source)
            return
        except ValueError:
            pass
        try:
            # The saved node may have gone; fall back to the first node of the same config.
            self.compiled = compile_config(self.source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port, allow_udp=sys.platform == "win32", capture_mode=self.capture_mode)
            self.settings["selected_node"] = self.compiled.selected_node
        except ValueError as exc:
            self.error = f"已保存的配置无法使用，请重新导入：{exc}"

    def _compile(self, source, selected=None):
        return compile_config(source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port, selected_node=selected if selected is not None else self.settings.get("selected_node"), allow_udp=sys.platform == "win32", capture_mode=self.capture_mode)

    @property
    def capture_mode(self):
        return self.settings.get("capture_mode", "applications")

    def global_backend(self):
        if self._global_backend is None:
            if sys.platform == 'win32':
                from .windows_global_runtime import Runtime
                self._global_backend = Runtime(ROOT)
            elif sys.platform == 'linux':
                from .linux_global_runtime import Runtime
                self._global_backend = Runtime()
            else:
                raise ValueError('当前系统不支持全局接管。')
        return self._global_backend

    def global_status(self):
        try:
            status = self.global_backend().status()
            if not isinstance(status, dict):
                raise ValueError('Invalid global helper status')
            return status
        except Exception as exc:
            return {'supported': False, 'running': False, 'state': 'unavailable',
                    'detail': str(exc), 'backend': 'Mihomo TUN', 'strict_isolation': False,
                    'guard': {'active': None}, 'limitations': []}

    def set_capture_mode(self, mode):
        if not isinstance(mode, str) or mode not in CAPTURE_MODES:
            raise ValueError('请选择按应用或全局接管。')
        with self.lock:
            if self.quitting or self.closed.is_set():
                raise ValueError('面板正在退出，不能切换接管模式。')
            if self.core or self.active or self._profile_preparing:
                raise ValueError('请先关闭本工具启动的应用并停止核心，再切换接管模式。')
            if self._global_fault or self._restore_pending:
                raise ValueError('上次网络恢复尚未完成，请先点击停止重试。')
            if mode == self.capture_mode:
                return
            previous, previous_compiled = self.capture_mode, self.compiled
            self.settings['capture_mode'] = mode
            try:
                if self.source:
                    self.compiled = self._compile(self.source)
                self._save()
            except BaseException:
                self.settings['capture_mode'], self.compiled = previous, previous_compiled
                raise
            self._probe_cache = None

    def windows_backend(self):
        if self._windows_backend is None:
            from .windows_proxy_runtime import Runtime
            self._windows_backend = Runtime(ROOT)
        return self._windows_backend

    def _selected_windows_paths(self):
        paths, seen = [], set()
        families, updates, retained = {}, [], {}
        for saved_app in self.settings["apps"]:
            if not saved_app["enabled"]:
                continue
            app = copy.deepcopy(saved_app)
            self._bind_store_app(app)
            selected = [app["path"], *app.get("related_paths", [])]
            binding = app.get('store_binding')
            if binding:
                from .windows_app_family import resolve_store_family
                identity = (binding['package_family_name'], binding['application_id'])
                if identity not in families:
                    families[identity] = resolve_store_family(binding)
                family = families[identity]
                # Routing includes the current package's helpers. Retain an
                # extant old entry while it may still own a running instance.
                selected = [*family.paths, *app.get('related_paths', [])]
                previous = self._windows_family_paths.get(app['id'], ())
                selected.extend(path for path in previous if path not in selected and Path(path).is_file())
                if app['path'] != family.entry_path and Path(app['path']).is_file():
                    selected.append(app['path'])
                retained[app['id']] = tuple(dict.fromkeys(selected))
                app['path'] = str(family.entry_path)
            updates.append((saved_app, app))
            for path in selected:
                key = path.replace("/", "\\").casefold()
                if key not in seen:
                    seen.add(key)
                    paths.append(path)
        if len(paths) > 128:
            raise ValueError("启用的程序与相关程序合计不能超过 128 个路径。")
        # A later ambiguous or unavailable package must not partially migrate
        # earlier saved records while the complete policy is being resolved.
        for saved_app, app in updates:
            saved_app.update(app)
        self._windows_family_paths = retained
        return paths

    @staticmethod
    def _bind_store_app(app):
        if not app.get('store_binding') and any(
                part.casefold() == 'windowsapps' for part in Path(app['path']).parts):
            from .windows_app_family import binding_for_path
            binding = binding_for_path(app['path'])
            if binding:
                app['store_binding'] = binding

    def _sync_windows_policy(self):
        if self.capture_mode == 'global' or sys.platform != "win32" or not self.core or self.core.poll() is not None:
            return
        paths = self._selected_windows_paths()
        backend = self.windows_backend()
        if paths:
            backend.apply(paths, self.mixed_port, self.core.pid)
            if self.settings.get("windows_app_guard"):
                backend.app_guard_apply(self.mixed_port)
        else:
            backend.stop()
        self._windows_paths = paths
        self._probe_cache = None

    def _save_app_changes(self, previous):
        try:
            if sys.platform == "win32":
                from .windows_proxy_policy import normalize_paths
                paths = self._selected_windows_paths()
                if paths:
                    normalize_paths(paths, root=str(ROOT))
            self._sync_windows_policy()
            self._save()
        except Exception:
            self.settings["apps"] = previous
            try:
                self._sync_windows_policy()
            except Exception:
                self.error = "应用规则更新失败，旧规则也未能恢复；请停止核心后重试。"
                self.stop()
            raise

    def protection(self):
        """The isolation check, run once. It can take seconds, so callers hold no other lock."""
        with self._probe_lock:
            if self.capture_mode == 'global':
                from .system_proxy import available
                supported, detail = available()
                return {'supported': supported, 'backend': '系统代理', 'detail': detail,
                        'limitations': ['只覆盖遵循系统代理的应用；不读取系统代理的程序会直连。',
                                        '面板意外退出时系统代理会暂时指向已停止的端口，下次打开面板或点击停止即恢复。']}
            if sys.platform == "win32":
                return self._check_isolation()
            if self._probe_cache is None:
                self._probe_cache = self._check_isolation()
            return self._probe_cache

    def _check_isolation(self):
        try:
            if sys.platform == "linux":
                from .linux_runtime import probe
                return probe()
            if sys.platform == "win32":
                return self.windows_backend().probe()
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

    def set_app_guard(self, enabled) -> None:
        """Toggle the Windows per-application egress guard preference.

        The guard binds to the broker's currently routed path set, so while
        the core is running an enable applies immediately when paths are
        routed and a disable revokes immediately; otherwise the preference
        takes effect at the next policy sync.
        """
        if not isinstance(enabled, bool):
            raise ValueError("请求无效。")
        with self.lock:
            self.settings["windows_app_guard"] = enabled
            self._save()
            self._probe_cache = None
            if (sys.platform == "win32" and self.capture_mode == "applications"
                    and self.core and self.core.poll() is None):
                backend = self.windows_backend()
                if enabled:
                    if self._windows_paths:
                        backend.app_guard_apply(self.mixed_port)
                else:
                    backend.app_guard_revoke()

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
                pending = bool(owned and ((not alive and owned[1] is not None) or
                               (alive and getattr(owned[1], "failed_process", None) is not None)))
                record = {**app, "active": alive and not pending, "cleanup_pending": pending,
                          "profile_preparing": app["id"] in self._profile_preparing}
                if sys.platform == "win32" or self.capture_mode == 'global':
                    record["routed"] = running and (self.capture_mode == 'global' or
                        (app["enabled"] and bool(self._windows_paths)))
                apps.append(record)
            compiled = self.compiled
            return {
                "token": self.token,
                "platform": "Windows" if sys.platform == "win32" else "Linux" if sys.platform == "linux" else sys.platform,
                "version": __version__,
                "imported": bool(compiled),
                "running": running,
                "capture_mode": self.capture_mode,
                "windows_app_guard": bool(self.settings.get("windows_app_guard", False)),
                "effective_capture_mode": self.capture_mode if running else None,
                "global_fault": self._global_fault,
                "error": self.error,
                "core_path": self.settings["core_path"] if sys.platform != "win32" else "",
                "runtime_path": self.settings["runtime_path"] if sys.platform != "win32" else "",
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
                "warnings": [*self.storage_warnings, *(compiled.warnings if compiled else [])],
            }

    def import_yaml(self, source):
        with self.lock:
            if self.core and self.core.poll() is None:
                raise ValueError("请先停止代理，再导入新配置。")
            compiled = compile_config(source, secret=self.secret, mixed_port=self.mixed_port, controller_port=self.controller_port, allow_udp=sys.platform == "win32", capture_mode=self.capture_mode)
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
                if not valid_text(value, 4096):
                    raise ValueError("程序路径无效。")
                if sys.platform == "win32" and value.strip():
                    raise ValueError("Windows 使用安装包固定的 Mihomo 与 ProxiFyre 组件，请运行 Setup-Windows.cmd 安装或修复。")
                self.settings[key] = value.strip()
            self._probe_cache = None
            self._save()

    def core_path(self):
        supplied = self.settings["core_path"] if sys.platform != "win32" else ""
        bundled = ROOT / "bin" / ("windows-amd64/mihomo.exe" if sys.platform == "win32" else "linux-amd64/mihomo")
        path = bundled if sys.platform == "win32" else Path(supplied or (str(bundled) if bundled.is_file() else shutil.which("mihomo") or ""))
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
            if self.quitting or self.closed.is_set():
                raise ValueError("面板正在退出，不能启动核心。")
            if self.core and self.core.poll() is None:
                return
            if self.core is not None:
                self.stop()
            if not self.compiled:
                raise ValueError("请先导入 YAML。")
            self._recover_global(raise_errors=True)
            if sys.platform == "win32" and self.capture_mode != 'global':
                capability = self.protection()
                if not capability["supported"]:
                    raise ValueError(capability["detail"])
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
                hidden = {'creationflags': getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)} if os.name == 'nt' else {}
                validation = subprocess.run([str(core), "-t", *args[1:]], stdout=self.core_log,
                                            stderr=subprocess.STDOUT, timeout=30, **hidden)
                if validation.returncode:
                    raise ValueError("Mihomo 配置校验未通过，应用未启动。详情保存在本机 core.log。")
                options = {"start_new_session": True} if os.name != "nt" else {
                    'creationflags': getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200)
                    | getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000)}
                command = args
                if sys.platform == 'linux' and self.capture_mode == 'global':
                    from .linux_core_process import command_for_parent
                    command = command_for_parent(args)
                    # PR_SET_PDEATHSIG follows the creating thread. The HTTP
                    # request thread ends after start(); this owner survives
                    # until all cores/apps have been stopped by close().
                    self.core = self.launch_owner.submit(
                        subprocess.Popen, command, stdin=subprocess.DEVNULL,
                        stdout=self.core_log, stderr=subprocess.STDOUT, **options).result()
                else:
                    self.core = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=self.core_log, stderr=subprocess.STDOUT, **options)
                if sys.platform == "win32":
                    from .windows_core_process import CoreJob
                    self._core_job = CoreJob(self.core)
                for _ in range(50):
                    if self.core.poll() is not None:
                        break
                    try:
                        self._controller("GET", "/version")
                    except Exception:
                        time.sleep(0.1)
                        continue
                    self._sync_windows_policy()
                    if self.capture_mode == 'global':
                        from . import system_proxy
                        from .system_proxy_watchdog import start as watch_proxy
                        self._proxy_watchdog = watch_proxy(self.directory, self.core.pid)
                        system_proxy.enable(self.directory, self.mixed_port,
                                            watchdog_session=self._proxy_watchdog.nonce)
                        self._proxy_watchdog.arm()
                    self.error = ""
                    return
                raise ValueError("Mihomo 未能启动；未启动任何应用。请查看本机 core.log。")
            except Exception as original:
                proxy_failed = False
                try:
                    from . import system_proxy
                    system_proxy.restore(self.directory)
                except Exception as exc:
                    proxy_failed = self._restore_pending = self._global_fault = True
                    self._restore_retry_at = time.monotonic() + 2
                    self.error = f'启动未完成，系统代理恢复失败；核心与恢复记录已保留，请点击停止重试：{exc}'
                if not proxy_failed and self._proxy_watchdog is not None:
                    try:
                        self._proxy_watchdog.close()
                        self._proxy_watchdog = None
                    except Exception:
                        traceback.print_exc()
                if sys.platform == "win32" and self._windows_backend is not None:
                    try:
                        self._windows_backend.stop()
                    except Exception:
                        traceback.print_exc()
                    self._windows_paths = []
                if self.core and (not proxy_failed or self.core.poll() is not None):
                    stop_process(self.core)
                    self.core = None
                if self.core is None:
                    close_resource(self._core_job)
                    self._core_job = None
                    self.core_log.close()
                    self.core_log = None
                if proxy_failed:
                    raise ValueError(self.error) from original
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
                except (OSError, ValueError, RuntimeError) as exc:
                    raise ValueError("切换节点失败：核心没有响应，请稍后重试。") from exc
            self.compiled = compiled
            self.settings["selected_node"] = name
            self._save()

    def add_app(self, data):
        with self.lock:
            if len(self.settings["apps"]) >= MAX_APPS:
                raise ValueError(f"最多保存 {MAX_APPS} 个应用，请先删除不再使用的应用。")
            normalized = validate_app(data)
            if sys.platform == 'win32':
                self._bind_store_app(normalized)
            if any(os.path.normcase(app["path"]) == os.path.normcase(normalized["path"]) for app in self.settings["apps"]):
                raise ValueError("这个应用已在列表中。")
            normalized.update(id=uuid.uuid4().hex, enabled=data.get("enabled", True) is True)
            previous = copy.deepcopy(self.settings["apps"])
            self.settings["apps"].append(normalized)
            self._save_app_changes(previous)

    def app(self, ident):
        return next((app for app in self.settings["apps"] if app["id"] == ident), None)

    def change_app(self, ident, enabled=None, delete=False):
        with self.lock:
            app = self.app(ident)
            if app is None:
                raise ValueError("应用不存在。")
            if ident in self._profile_preparing:
                raise ValueError("正在准备此应用的原有资料，请完成后再修改应用。")
            if not delete and not isinstance(enabled, bool):
                raise ValueError("enabled 必须是布尔值。")
            previous = copy.deepcopy(self.settings["apps"])
            if delete or enabled is False:
                self.stop_app(ident)
            if delete:
                self.settings["apps"].remove(app)
            else:
                if not isinstance(enabled, bool):
                    raise ValueError("enabled 必须是布尔值。")
                app["enabled"] = enabled
            self._save_app_changes(previous)
            if delete:
                remove_shortcut_files(app)

    def set_app_profile(self, ident, use_original_data):
        """Select shared browser data without holding the manager lock during path checks."""
        if not isinstance(use_original_data, bool):
            raise ValueError("use_original_data 必须是布尔值。")
        with self.lock:
            app = self.app(ident)
            if app is None:
                raise ValueError("应用不存在。")
            if ident in self._profile_preparing:
                raise ValueError("正在准备此应用的原有资料，请稍候。")
            if ident in self.active and self.active[ident][0].poll() is None:
                raise ValueError("请先关闭此工具启动的应用，再切换资料模式。")
            candidate = validate_app({**app, "use_original_data": use_original_data}, check_exists=False)
            candidate["id"] = ident
            self._profile_preparing.add(ident)
        try:
            if use_original_data and sys.platform == "linux":
                from .app_profile_data import original_profile_source
                original_profile_source(candidate)
            with self.lock:
                if self.app(ident) is not app or self.quitting or self.closed.is_set():
                    raise ValueError("应用或面板状态已改变，请重新操作。")
                old = dict(app)
                app["use_original_data"] = use_original_data
                try:
                    self._save()
                except BaseException:
                    app.clear()
                    app.update(old)
                    raise
        finally:
            with self.lock:
                self._profile_preparing.discard(ident)

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
            if self.quitting or self.closed.is_set():
                raise ValueError("面板正在退出，不能启动应用。")
            if ident in self._profile_preparing:
                raise ValueError("正在检查此应用的原有资料，请完成后再启动。")
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
                return {"pid": self.active[ident][0].pid, "adapter": app["adapter"], "detail": "这个应用已经在运行。" if sys.platform == "win32" else "这个应用已经在隔离中运行。"}
            if ident in self.active:
                self.stop_app(ident)
            global_mode = self.capture_mode == 'global'
            if sys.platform == 'win32':
                if global_mode:
                    self._bind_store_app(app)
                    if app.get('store_binding'):
                        from .windows_app_family import resolve_store_family
                        app['path'] = resolve_store_family(app['store_binding']).entry_path
                else:
                    # Resolve current Store versions and cover package helpers
                    # before validating/starting the selected executable.
                    self._sync_windows_policy()
            profile = self.directory / "profiles" / ident
            options = ({'transparent': True, 'native_proxy': True, 'system_proxy': global_mode}
                       if sys.platform == 'win32' or global_mode else {})
            command, env, _detail = prepare_app(app, self.mixed_port, self.directory / "profiles", **options)
            if sys.platform == "linux" and not global_mode:
                from .linux_runtime import downloads_folder, launch
                downloads = downloads_folder(self.directory)
                options = ({"original_profile": app_profile_directory(self.directory / "profiles", app),
                            "profile_adapter": app["adapter"]} if app.get("use_original_data") else {})
                process, resource = self.launch_owner.submit(launch, command, env, profile,
                                                            self.mixed_port, downloads, **options).result()
            elif sys.platform == "win32":
                from .windows_app_process import launch
                # Native proxy inheritance must be an explicit launch option;
                # the Windows launcher distrusts all proxy values in ``env``.
                process = launch(command, env, native_proxy_port=self.mixed_port)
                resource = None
            elif sys.platform == 'linux' and global_mode:
                process = subprocess.Popen(command, env=env, start_new_session=True)
                resource = None
            else:
                raise ValueError("系统不支持应用隔离。")
            self.active[ident] = (process, resource)
            self.error = ""
            detail = ('全局系统代理已启用；应用同时继承本机代理设置。' if global_mode else
                      '兼容模式的程序及辅助路径代理已启用；支持原生代理的应用同时使用本机代理。' if sys.platform == 'win32' else
                      '仅此隔离实例受保护。不支持的流量阻断，不会直连。')
            if app.get("use_original_data"):
                detail += (" 使用原应用资料；启动请求可能交给已有窗口，已有进程不会由面板接管或关闭。"
                           if sys.platform == "win32" else " 直接共用原应用资料；修改会同步到原应用，请勿同时启动原应用。")
            return {"pid": process.pid, "adapter": app["adapter"], "detail": detail}

    def stop_app(self, ident):
        with self.lock:
            owned = self.active.get(ident)
            if owned:
                process, resource = owned
                if sys.platform == "win32":
                    process.terminate()
                    process.wait(timeout=10)
                elif sys.platform == "linux" and self.capture_mode != 'global':
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
            errors = []
            app_errors = []
            for ident in list(self.active):
                try:
                    self.stop_app(ident)
                except Exception as exc:
                    errors.append(f'应用未能关闭：{exc}')
                    app_errors.append(exc)
            # App cleanup cannot prevent desktop restoration. A saved journal
            # can belong to a previous mode, so recover it unconditionally.
            from . import system_proxy
            proxy_failed = False
            try:
                system_proxy.restore(self.directory)
                self._restore_pending = False
            except Exception as exc:
                proxy_failed = self._restore_pending = True
                self._restore_retry_at = time.monotonic() + 2
                errors.append(f'原系统代理未能恢复，记录已保留，请点击停止重试：{exc}')
            if not proxy_failed and self._proxy_watchdog is not None:
                try:
                    self._proxy_watchdog.close()
                    self._proxy_watchdog = None
                except Exception as exc:
                    errors.append(f'独立恢复进程尚未退出：{exc}')
            try:
                self._release_legacy_tun()
            except Exception as exc:
                errors.append(str(exc))
            keep_app_protection = bool(app_errors) and self.capture_mode != 'global'
            if sys.platform == "win32" and self._windows_backend is not None and not keep_app_protection:
                try:
                    self._windows_backend.stop()
                    self._windows_paths = []
                except Exception as exc:
                    errors.append(f'Windows 应用代理未能停止：{exc}')
            # If restoration failed while the core is still healthy, retain
            # it rather than deliberately turning the desktop proxy into a
            # dead port. The panel stays usable and the watcher retries.
            if self.core and not keep_app_protection and (not proxy_failed or self.core.poll() is not None):
                try:
                    stop_process(self.core)
                    self.core = None
                except Exception as exc:
                    errors.append(f'代理核心未能停止：{exc}')
            if self.core is None:
                try:
                    close_resource(self._core_job)
                    self._core_job = None
                    if self.core_log:
                        self.core_log.close()
                        self.core_log = None
                except Exception as exc:
                    errors.append(f'核心资源未能释放：{exc}')
            self._global_fault = bool(errors)
            if errors:
                self.error = '；'.join(errors)
                if keep_app_protection and not proxy_failed and len(errors) == len(app_errors):
                    raise app_errors[0]
                raise ValueError(self.error)

    def begin_quit(self):
        """Stop safely before preventing new launches; failures keep the panel usable."""
        with self.lock:
            self.stop()
            self.quitting = True

    def _watch(self):
        while not self.closed.wait(0.5):
            with self.lock:
                if self.core and self.core.poll() is not None:
                    try:
                        self.stop()
                        self.error = '代理核心已退出，原系统代理已恢复；本工具启动的应用已关闭。'
                    except Exception as exc:
                        self.error = f'代理核心已退出；网络或应用恢复尚未完成：{exc}'
                if self._restore_pending and time.monotonic() >= self._restore_retry_at:
                    try:
                        self.stop()
                    except Exception:
                        pass  # stop() retains the journal and its precise error.
                if sys.platform == "win32" and self._windows_paths and self.core:
                    try:
                        status = self.windows_backend().snapshot()
                        if status.get("state") not in {"running", "active"}:
                            self.error = "ProxiFyre 已停止，正在关闭此面板启动的应用。其他同路径实例可能恢复直连。"
                            self.stop()
                    except Exception:
                        self.error = "Windows 代理服务失去响应，正在关闭此面板启动的应用。其他同路径实例可能恢复直连。"
                        try:
                            self.stop()
                        except Exception:
                            traceback.print_exc()
                for ident, (process, resource) in list(self.active.items()):
                    if process.poll() is not None:
                        try:
                            close_resource(resource)
                        except Exception as exc:
                            self.error = f'应用已退出，保护规则尚待回收，请点击停止重试：{exc}'
                            self._global_fault = True
                            continue
                        self.active.pop(ident, None)

    def close(self, *, restore_global=True):
        # Every exit path restores the system proxy; ``restore_global`` is
        # kept only for callers written against the retired TUN mode.
        self.stop()
        self.closed.set()
        self.launch_owner.shutdown(wait=True)
