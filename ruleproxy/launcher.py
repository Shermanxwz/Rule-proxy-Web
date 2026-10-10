"""Prepare per-app commands for a strict, externally enforced proxy runtime.

This module does not spawn processes. Windows execution must go through the
MXC ProcessContainer runtime; callers must not start the returned application
command directly. Unsupported network flows are expected to fail closed.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any


ADAPTERS = frozenset({"chromium", "firefox", "environment"})
_MAX_ARGS = 64
_MAX_ARG_LENGTH = 4096
_MAX_ARGS_TOTAL = 16384
_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")

# These switches can replace the isolated profile/proxy, or ask Chromium to
# launch externally supplied subprocesses. Users can still pass ordinary
# browser options, but the enforced values are appended by this module.
_CHROMIUM_RESERVED_PREFIXES = (
    "--proxy-",
    "--no-proxy-server",
    "--user-data-dir",
    "--profile-directory",
    "--host-resolver-rules",
    "--force-webrtc-ip-handling-policy",
    "--remote-debugging-",
    "--renderer-cmd-prefix",
    "--utility-cmd-prefix",
    "--browser-subprocess-path",
    "--gpu-launcher",
    "--plugin-launcher",
    "--zygote-cmd-prefix",
    "--load-extension",
    "--disable-extensions-except",
)
_FIREFOX_RESERVED = frozenset(
    {"-profile", "--profile", "-p", "-no-remote", "--no-remote", "-createprofile", "-profilemanager"}
)
_SHELL_EXECUTABLES = frozenset(
    {
        "bash",
        "cmd",
        "cmd.exe",
        "cscript.exe",
        "powershell.exe",
        "pwsh.exe",
        "sh",
        "wscript.exe",
    }
)


def _app(label: str, path: str | Path, adapter: str) -> dict[str, str]:
    return {"label": label, "path": str(path), "adapter": adapter}


def discover_apps() -> list[dict[str, str]]:
    """Return common browser installations without executing discovery targets."""
    found: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(label: str, path: str | Path | None, adapter: str) -> None:
        if not path:
            return
        candidate = Path(path).expanduser()
        try:
            if not candidate.is_file():
                return
            key = os.path.normcase(str(candidate.resolve()))
        except OSError:
            key = os.path.normcase(str(candidate.absolute()))
        if key not in seen:
            seen.add(key)
            found.append(_app(label, candidate, adapter))

    if sys.platform == "win32":
        roots = [
            Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
            Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
            Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")),
        ]
        candidates = [
            ("Google Chrome", roots[0] / "Google/Chrome/Application/chrome.exe", "chromium"),
            ("Google Chrome", roots[1] / "Google/Chrome/Application/chrome.exe", "chromium"),
            ("Microsoft Edge", roots[0] / "Microsoft/Edge/Application/msedge.exe", "chromium"),
            ("Microsoft Edge", roots[1] / "Microsoft/Edge/Application/msedge.exe", "chromium"),
            ("Microsoft Edge", roots[2] / "Microsoft/Edge/Application/msedge.exe", "chromium"),
            ("Brave", roots[0] / "BraveSoftware/Brave-Browser/Application/brave.exe", "chromium"),
            ("Brave", roots[1] / "BraveSoftware/Brave-Browser/Application/brave.exe", "chromium"),
            ("Brave", roots[2] / "BraveSoftware/Brave-Browser/Application/brave.exe", "chromium"),
            ("Mozilla Firefox", roots[0] / "Mozilla Firefox/firefox.exe", "firefox"),
            ("Mozilla Firefox", roots[1] / "Mozilla Firefox/firefox.exe", "firefox"),
        ]
        for label, path, adapter in candidates:
            add(label, path, adapter)
    else:
        for command, label, adapter in (
            ("google-chrome", "Google Chrome", "chromium"),
            ("google-chrome-stable", "Google Chrome", "chromium"),
            ("chromium", "Chromium", "chromium"),
            ("chromium-browser", "Chromium", "chromium"),
            ("microsoft-edge", "Microsoft Edge", "chromium"),
            ("microsoft-edge-stable", "Microsoft Edge", "chromium"),
            ("brave-browser", "Brave", "chromium"),
            ("firefox", "Mozilla Firefox", "firefox"),
        ):
            add(label, shutil.which(command), adapter)
    return found


def _validate_args(value: Any) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > _MAX_ARGS:
        raise ValueError("args must be a list of at most 64 strings")
    args: list[str] = []
    total = 0
    for arg in value:
        if not isinstance(arg, str) or "\0" in arg:
            raise ValueError("each argument must be a string without NUL characters")
        if len(arg) > _MAX_ARG_LENGTH:
            raise ValueError("an argument exceeds the 4096 character limit")
        total += len(arg)
        args.append(arg)
    if total > _MAX_ARGS_TOTAL:
        raise ValueError("combined arguments exceed the 16384 character limit")
    return args


def validate_app(data: dict) -> dict[str, Any]:
    """Validate and normalize an executable selection supplied by the user."""
    if not isinstance(data, dict):
        raise ValueError("application selection must be an object")
    label = data.get("label")
    raw_path = data.get("path")
    adapter = data.get("adapter")
    if not isinstance(label, str) or not label.strip() or len(label) > 200:
        raise ValueError("label must be a non-empty string of at most 200 characters")
    if not isinstance(raw_path, str) or not raw_path.strip() or "\0" in raw_path:
        raise ValueError("path must be a non-empty executable file path")
    if not isinstance(adapter, str) or adapter not in ADAPTERS:
        raise ValueError("adapter must be chromium, firefox, or environment")
    path = Path(raw_path).expanduser()
    try:
        path = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("executable path does not exist") from exc
    if not path.is_file():
        raise ValueError("executable path must refer to a file")
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise ValueError("executable file is not runnable")
    if path.name.lower() in _SHELL_EXECUTABLES:
        raise ValueError("shell executables cannot be selected as apps")
    args = _validate_args(data.get("args", []))
    return {"label": label.strip(), "path": str(path), "adapter": adapter, "args": args}


def _profile_for_app(profile_dir: Path, app: dict) -> Path:
    app_id = app.get("id")
    if not isinstance(app_id, str) or not _APP_ID_RE.fullmatch(app_id) or app_id in {".", ".."}:
        raise ValueError("saved application must have a safe id")
    return Path(profile_dir).expanduser() / app_id


def _validate_port(proxy_port: int) -> int:
    if isinstance(proxy_port, bool) or not isinstance(proxy_port, int) or not 1 <= proxy_port <= 65535:
        raise ValueError("proxy_port must be an integer from 1 through 65535")
    return proxy_port


def _reject_reserved_args(args: list[str], adapter: str) -> None:
    for arg in args:
        option = arg.split("=", 1)[0].lower()
        if arg == "--":
            raise ValueError("argument terminator is not allowed")
        if adapter == "chromium" and any(
            option.startswith(prefix)
            if prefix.endswith("-")
            else option == prefix or option.startswith(prefix + "=")
            for prefix in _CHROMIUM_RESERVED_PREFIXES
        ):
            raise ValueError(f"argument may override strict proxy/profile controls: {arg}")
        if adapter == "firefox" and option in _FIREFOX_RESERVED:
            raise ValueError(f"argument may override strict proxy/profile controls: {arg}")


def prepare_app(app: dict, proxy_port: int, profile_dir: Path) -> tuple[list[str], dict[str, str], str]:
    """Prepare an app command, child-only environment overrides, and limitations.

    The returned command is only safe when passed to the strict MXC runtime.
    Direct execution is deliberately not provided here.
    """
    normalized = validate_app(app)
    proxy_port = _validate_port(proxy_port)
    _reject_reserved_args(normalized["args"], normalized["adapter"])
    profile = _profile_for_app(profile_dir, app)
    profile.mkdir(parents=True, exist_ok=True)
    command = [normalized["path"], *normalized["args"]]
    # Keep the caller's GUI/session environment (DISPLAY, WAYLAND_DISPLAY,
    # XDG_RUNTIME_DIR, etc.); the platform runtime must apply its own safe
    # environment allowlist when entering isolation.
    env: dict[str, str] = os.environ.copy()
    proxy = f"http://127.0.0.1:{proxy_port}"
    env.update(
        {
            "HTTP_PROXY": proxy,
            "HTTPS_PROXY": proxy,
            "ALL_PROXY": proxy,
            "http_proxy": proxy,
            "https_proxy": proxy,
            "all_proxy": proxy,
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )

    if normalized["adapter"] == "chromium":
        command.extend(
            [
                f"--user-data-dir={profile}",
                f"--proxy-server=http://127.0.0.1:{proxy_port}",
                "--proxy-bypass-list=<-loopback>",
                "--disable-quic",
                "--disable-background-networking",
                "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--no-first-run",
            ]
        )
        detail = (
            "Strict runtime mode allows the configured proxy endpoint and blocks direct egress. "
            "Chromium HTTP/S uses the local proxy; unsupported flows fail closed."
        )
    elif normalized["adapter"] == "firefox":
        prefs = (
            'user_pref("network.proxy.type", 1);\n'
            'user_pref("network.proxy.socks", "127.0.0.1");\n'
            f'user_pref("network.proxy.socks_port", {proxy_port});\n'
            'user_pref("network.proxy.socks_version", 5);\n'
            'user_pref("network.proxy.socks_remote_dns", true);\n'
            'user_pref("network.proxy.socks5_remote_dns", true);\n'
            'user_pref("network.proxy.share_proxy_settings", true);\n'
            'user_pref("network.proxy.no_proxies_on", "");\n'
            'user_pref("network.proxy.allow_hijacking_localhost", true);\n'
            'user_pref("network.dns.disablePrefetch", true);\n'
            'user_pref("network.prefetch-next", false);\n'
            'user_pref("network.predictor.enabled", false);\n'
        )
        (profile / "user.js").write_text(prefs, encoding="utf-8")
        command.extend(["-no-remote", "-profile", str(profile)])
        detail = (
            "Strict runtime mode allows the configured proxy endpoint and blocks direct egress. "
            "Firefox uses SOCKS5 with remote DNS; unsupported flows fail closed."
        )
    else:
        detail = (
            "Proxy variables are child-only. Applications that ignore them will fail to connect "
            "because strict runtime mode blocks direct egress."
        )

    return command, env, detail
