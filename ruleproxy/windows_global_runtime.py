"""Ordinary-user facade for the installed SYSTEM-owned global TUN core.

Only data crosses the authenticated control pipe. Executable paths, command
lines, output directories and imported TUN options are never caller choices.
"""
from __future__ import annotations

import os
from pathlib import Path
import threading

from .windows_proxy_client import Client, current_user_sid
from .windows_proxy_policy import GLOBAL_LIMITATIONS, ProxyError, validate_global_request
from .windows_proxy_service import load_deployment


class Runtime:
    def __init__(self, root: Path | None = None):
        self.root = Path(root) if root is not None else Path(__file__).resolve().parent.parent
        self._metadata = None
        self._client = None
        self._lock = threading.RLock()

    def _connect(self):
        if os.name != "nt":
            raise ProxyError("setup_required", "Windows 全局模式需要在 Windows 中安装。")
        if self._metadata is None:
            metadata = load_deployment(self.root)
            if current_user_sid() != metadata["owner_sid"]:
                raise ProxyError("different_installation_user", "请使用安装此工具的 Windows 用户。")
            if metadata.get("global_backend_version") != 1:
                raise ProxyError("setup_required", "已安装的控制服务不支持全局模式，请运行 Setup-Windows.cmd 修复安装。")
            self._metadata = metadata
            self._client = Client(metadata["pipe_name"])
        return self._client

    @staticmethod
    def _checked_status(result):
        if (not isinstance(result, dict) or result.get("global_schema_version") != 1
                or result.get("mode") != "global" or type(result.get("running")) is not bool
                or type(result.get("supported")) is not bool):
            raise ProxyError("setup_required", "Windows 控制服务协议过旧，请运行 Setup-Windows.cmd 修复安装。")
        if result["running"] and (type(result.get("pid")) is not int or result["pid"] <= 0):
            raise ProxyError("invalid_response", "Windows 全局核心进程状态无效。")
        return result

    def start(self, source: str, secret: str, mixed_port: int, controller_port: int,
              selected_node: str | None = None, *, require_strict: bool = False) -> dict:
        fields = dict(source=source, secret=secret, mixed_port=mixed_port,
                      controller_port=controller_port, selected_node=selected_node,
                      require_strict=require_strict)
        validate_global_request(fields)
        with self._lock:
            try:
                result = self._connect().request("global_start", **fields)
            except ProxyError as exc:
                if exc.code == "invalid_request":
                    raise ProxyError("setup_required", "Windows 控制服务不支持全局协议，请修复安装。") from exc
                raise
            return self._checked_status(result)

    def status(self) -> dict:
        with self._lock:
            try:
                return self._checked_status(self._connect().request("global_status"))
            except (OSError, ValueError, ProxyError) as exc:
                code = getattr(exc, "code", "backend_unavailable")
                setup = code in {"setup_required", "invalid_request", "invalid_response", "invalid_deployment",
                                 "installation_changed", "backend_unavailable"}
                detail = ("Windows 控制服务协议过旧，请运行 Setup-Windows.cmd 修复安装。"
                          if code in {"invalid_request", "invalid_response"} else str(exc))
                return {"global_schema_version": 1, "mode": "global", "backend": "Mihomo TUN",
                        "running": False, "pid": None, "supported": False, "component_supported": False,
                        "policy_ready": False, "setup_required": setup,
                        "state": "setup_required" if setup else "failed", "code": code,
                        "detail": detail, "strict_isolation": False, "protection": "unavailable",
                        "guard": {"supported": False, "active": False, "persistent": False,
                                  "detail": "尚未取得独立保护状态，不能确认故障后阻断。"},
                        "dns": {"supported": False, "active": None, "effective": False,
                                "native_qualified": False, "state": "unavailable",
                                "detail": "尚未取得有效 DNS 接管状态。"},
                        "limitations": list(GLOBAL_LIMITATIONS)}

    def stop(self) -> dict:
        # A previous panel may have crashed with a persistent guard still in
        # place. Reconnect even if this facade has never called start().
        with self._lock:
            return self._connect().request("global_stop")

    def select_node(self, name: str) -> dict:
        if not isinstance(name, str) or not name or len(name) > 4096 or "\0" in name:
            raise ProxyError("invalid_request", "所选节点无效。")
        with self._lock:
            return self._checked_status(self._connect().request("global_select_node", selected_node=name))

    snapshot = status
    probe = status
