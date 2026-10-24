"""Product-facing Windows application-routing runtime; no fallback backend."""
from __future__ import annotations

import os
from pathlib import Path
import threading

from .windows_proxy_client import Client, current_user_sid
from .windows_proxy_policy import APP_GUARD_LIMITATIONS, LIMITATIONS, NAMESPACE_LIMITATIONS, ProxyError, build_policy
from .windows_proxy_service import load_deployment


class Runtime:
    def __init__(self, root: Path):
        self.root = Path(root)
        self._metadata = None
        self._client = None
        self._generation = 0
        self._lock = threading.RLock()

    def _connect(self):
        if os.name != "nt":
            raise ProxyError("setup_required", "Windows 后端需要在 Windows 中安装。")
        if self._metadata is None:
            metadata = load_deployment(self.root)
            if current_user_sid() != metadata["owner_sid"]:
                raise ProxyError("different_installation_user", "请使用安装此工具的 Windows 用户。")
            self._metadata = metadata
            self._client = Client(metadata["pipe_name"])
        return self._client

    def probe(self) -> dict:
        with self._lock:
            try:
                status = self._connect().request("status")
                self._generation = status["generation"]
                available = status.get("state") in {"idle", "running"}
                namespaced = status.get("namespace_ready") is True
                guarded = isinstance(status.get("app_guard"), dict) and status["app_guard"].get("active") is True
                return {"supported": available, "backend": "Windows 网络隔间 + Mihomo" if namespaced else "ProxiFyre + Mihomo",
                        "mode": "isolated_application" if namespaced else "application_proxy",
                        "strict_isolation": False, "state": status.get("state", "failed"),
                        "detail": ("Windows 独立网络实验已启动；系统 DNS 和服务代办仍可绕过。" if namespaced else
                                   "Windows 应用路径代理可用，出站守卫已启用。" if guarded else
                                   "Windows 应用路径代理可用。") if available else (
                            "另一程序正在管理 ProxiFyre，请先停止该程序的代理。" if
                            status.get("state") == "external_conflict" else "Windows 代理后端异常，请停止后重试。"),
                        "limitations": list(NAMESPACE_LIMITATIONS if namespaced else
                                            APP_GUARD_LIMITATIONS if guarded else LIMITATIONS), "status": status}
            except (OSError, ValueError, ProxyError) as exc:
                return {"supported": False, "backend": "ProxiFyre + Mihomo", "mode": "application_proxy",
                        "strict_isolation": False, "code": getattr(exc, "code", "backend_unavailable"),
                        "state": "setup_required" if getattr(exc, "code", None) == "setup_required" else "failed",
                        "detail": str(exc), "limitations": list(LIMITATIONS)}

    def apply(self, paths: list[str], proxy_port: int, mihomo_pid: int) -> dict:
        with self._lock:
            client = self._connect()
            build_policy(paths, proxy_port, root=self._metadata["root"],
                         proxifyre_root=self._metadata["proxifyre_root"],
                         windows_root=os.environ.get("SystemRoot", r"C:\Windows"))
            state = client.request("status")
            result = client.request("apply", paths=paths, proxy_port=proxy_port,
                                    mihomo_pid=mihomo_pid, generation=state["generation"] + 1)
            self._generation = result["generation"]
            return result

    def app_guard_apply(self, proxy_port: int) -> dict:
        with self._lock:
            return self._connect().request("app_guard_apply", proxy_port=proxy_port)

    def app_guard_revoke(self) -> dict:
        with self._lock:
            return self._connect().request("app_guard_revoke")

    def container_allow(self, container: str, proxy_port: int) -> dict:
        with self._lock:
            return self._connect().request("container_allow", container=container, proxy_port=proxy_port)

    def container_revoke(self, container: str) -> dict:
        with self._lock:
            return self._connect().request("container_revoke", container=container)

    def namespace_allow(self, container: str, proxy_port: int, job_handle: int) -> dict:
        with self._lock:
            return self._connect().request("namespace_allow", container=container,
                                           proxy_port=proxy_port, job_handle=job_handle)

    def namespace_prepare(self, proxy_port: int, mihomo_pid: int) -> dict:
        """Hold the panel/core lease without enabling executable-path routing."""
        with self._lock:
            client = self._connect()
            state = client.request("status")
            result = client.request("namespace_prepare", proxy_port=proxy_port, mihomo_pid=mihomo_pid,
                                    generation=state["generation"] + 1)
            self._generation = result["generation"]
            return result

    def namespace_revoke(self, container: str) -> dict:
        with self._lock:
            return self._connect().request("namespace_revoke", container=container)

    def stop(self) -> dict:
        with self._lock:
            if self._client is None:
                return {"stopped": True, "not_connected": True}
            return self._client.request("stop")

    def snapshot(self) -> dict:
        try:
            return self._connect().request("status")
        except (OSError, ValueError, ProxyError) as exc:
            return {"running": False, "backend": "ProxiFyre", "mode": "application_proxy",
                    "strict_isolation": False, "code": getattr(exc, "code", "backend_unavailable"),
                    "state": "setup_required" if getattr(exc, "code", None) == "setup_required" else "failed",
                    "detail": str(exc), "limitations": list(LIMITATIONS)}
