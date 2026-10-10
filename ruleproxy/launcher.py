"""Prepare per-app commands for a strict, externally enforced proxy runtime.

This module does not spawn processes. Windows execution must go through the
MXC ProcessContainer runtime; callers must not start the returned application
command directly. Unsupported network flows are expected to fail closed.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
import threading
import time
from copy import deepcopy
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
_DISCOVERY_WRAPPERS = frozenset(
    {
        "env", "flatpak", "snap", "sh", "bash", "dash", "zsh", "fish", "csh",
        "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
        "sudo", "pkexec", "su", "doas", "runuser", "gtk-launch", "xdg-open",
        "gio", "wine", "wineserver", "python", "python3", "node", "java",
        "systemd-run", "dbus-run-session", "dbus-launch", "rundll32.exe", "regsvr32.exe",
        "msiexec.exe", "explorer.exe", "mmc.exe", "regedit.exe",
    }
)
_DISCOVERY_HELPER_RE = re.compile(
    r"(?:^|[-_.])(uninstall(?:er)?|unins\d*|setup|installer|updater?|crashpad|helper|launcher-helper)(?:$|[-_.])",
    re.IGNORECASE,
)
_DESKTOP_FIELD_RE = re.compile(r"%([fFuUickdDnNv%m])")
_DISCOVERY_LOCK = threading.Lock()
_DISCOVERY_CACHE: tuple[tuple[Any, ...], float, list[dict[str, Any]]] | None = None
_DISCOVERY_CACHE_SECONDS = 30.0


def _category(label: str, path: Path, desktop_categories: str = "") -> str:
    text = f"{label} {path} {desktop_categories}".lower()
    for category, words in (
        ("browser", ("browser", "webbrowser", "chrome", "chromium", "firefox", "brave", "edge")),
        ("communication", ("chat", "messag", "discord", "slack", "signal", "telegram", "zoom", "teams", "element")),
        ("productivity", ("office", "document", "spreadsheet", "calendar", "note", "obsidian", "libreoffice")),
        ("development", ("development", "ide", "editor", "code", "studio", "terminal")),
        ("media", ("audio", "video", "music", "media", "image", "photo")),
    ):
        if any(word in text for word in words):
            return category
    return "other"


def _compatibility(adapter: str) -> str:
    if adapter == "chromium":
        return "Chromium/Electron proxy flags are applied; unsupported traffic fails closed."
    if adapter == "firefox":
        return "Firefox uses SOCKS5 remote DNS; unsupported traffic fails closed."
    return "Requires HTTP(S)/ALL_PROXY support; unsupported traffic fails closed."


def _app(label: str, path: str | Path, adapter: str, *, args: list[str] | None = None, category: str | None = None) -> dict[str, Any]:
    candidate = Path(path)
    return {
        "label": label,
        "path": str(candidate),
        "adapter": adapter,
        "args": list(args or []),
        "category": category or _category(label, candidate),
        "compatibility": _compatibility(adapter),
    }


def _resolve_program(program: str) -> Path | None:
    if not program or "\0" in program:
        return None
    candidate = Path(program).expanduser()
    if candidate.is_absolute() or "/" in program or "\\" in program:
        try:
            candidate = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            return None
    else:
        found = shutil.which(program)
        if not found:
            return None
        candidate = Path(found).resolve()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    if sys.platform.startswith("linux"):
        try:
            with candidate.open("rb") as executable:
                if executable.read(2) == b"#!":
                    return None
        except OSError:
            return None
    return candidate


def _is_elf_executable(path: Path) -> bool:
    """Check the packaged ChatGPT target without invoking it."""
    try:
        with path.open("rb") as executable:
            return executable.read(4) == b"\x7fELF"
    except OSError:
        return False


def _infer_adapter(label: str, path: Path) -> str:
    name = path.name.lower()
    text = f"{label} {path}".lower()
    if name in {"firefox", "firefox-bin", "waterfox", "librewolf"} or "firefox" in text or "librewolf" in text:
        return "firefox"
    if name in {
        "chrome", "chrome.exe", "google-chrome", "google-chrome-stable", "chromium",
        "chromium-browser", "msedge", "msedge.exe", "microsoft-edge", "brave",
        "brave.exe", "brave-browser",
    }:
        return "chromium"
    if any(word in text for word in (
        "electron", "chatgpt", "discord", "slack", "signal", "teams", "element",
        "obsidian", "visual studio code", "code - oss", "vscode", "postman", "notion",
    )):
        return "chromium"
    # Electron bundles expose app.asar next to their executable. This is a
    # filesystem-only hint; discovery never starts a candidate to inspect it.
    parent = path.parent
    if any((base / marker).is_file() for base in (parent / "resources", parent.parent / "resources") for marker in ("app.asar", "app/main.js")):
        return "chromium"
    return "environment"


def _is_excluded_program(path: Path, label: str) -> bool:
    name = path.name.lower()
    label_lower = label.lower()
    if name in _SHELL_EXECUTABLES or name in _DISCOVERY_WRAPPERS:
        return True
    if _DISCOVERY_HELPER_RE.search(name) or _DISCOVERY_HELPER_RE.search(path.parent.name):
        return True
    if name in {
        "systemsettings", "systemsettings.exe", "systemsettings5", "systemsettings6",
        "control.exe", "ms-settings.exe", "systempropertiesadvanced.exe",
        "gnome-control-center", "xfce4-settings-manager", "mate-control-center",
        "unity-control-center", "cinnamon-settings", "lxqt-config",
    }:
        return True
    if any(term in label_lower for term in ("uninstaller", "software update", "crash reporter", "system settings", "control center")):
        return True
    return False


def _has_reserved_desktop_args(args: list[str], adapter: str) -> bool:
    for arg in args:
        option = arg.split("=", 1)[0].lower()
        if arg == "--":
            return True
        if any(
            option.startswith(prefix)
            if prefix.endswith("-")
            else option == prefix or option.startswith(prefix + "=")
            for prefix in _CHROMIUM_RESERVED_PREFIXES
        ):
            return True
        if option in _FIREFOX_RESERVED or option.startswith(("--profile=", "-profile=")):
            return True
    return False


def _desktop_exec_args(value: str) -> tuple[list[str], list[str]] | None:
    try:
        tokens = shlex.split(value, posix=True)
    except ValueError:
        return None
    if not tokens:
        return None
    result: list[str] = []
    for token in tokens[1:]:
        if token in {"%f", "%F", "%u", "%U", "%i", "%c", "%k", "%d", "%D", "%n", "%N", "%v", "%m"}:
            continue
        if "%" in token:
            # Field codes are launcher substitutions, never shell expansion.
            if token == "%%":
                result.append("%")
            elif _DESKTOP_FIELD_RE.search(token):
                continue
            else:
                return None
        else:
            result.append(token)
    return tokens, result


def _desktop_entry(path: Path) -> tuple[str, str, str, list[str], str] | None:
    fields: dict[str, str] = {}
    in_entry = False
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("[") and line.endswith("]"):
                in_entry = line == "[Desktop Entry]"
                continue
            if not in_entry or not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key not in fields:
                fields[key] = value
    except OSError:
        return None
    if fields.get("Type", "Application") != "Application" or fields.get("Hidden", "false").lower() == "true" or fields.get("NoDisplay", "false").lower() == "true":
        return None
    name = fields.get("Name", "").strip()
    raw_exec = fields.get("Exec", "").strip()
    if not name or not raw_exec:
        return None
    parsed = _desktop_exec_args(raw_exec)
    if parsed is None:
        return None
    tokens, args = parsed
    program = tokens[0]
    if Path(program).name.lower() in _DISCOVERY_WRAPPERS:
        return None
    candidate = _resolve_program(program)
    if candidate is None or _is_excluded_program(candidate, name):
        return None
    try_exec = fields.get("TryExec", "").strip()
    if try_exec and _resolve_program(try_exec) is None:
        return None
    adapter = _infer_adapter(name, candidate)
    if _has_reserved_desktop_args(args, adapter):
        return None
    categories = fields.get("Categories", "")
    return name, str(candidate), adapter, args, categories


def _linux_applications_dirs() -> list[Path]:
    home = Path.home()
    data_home = Path(os.environ.get("XDG_DATA_HOME", str(home / ".local/share"))).expanduser()
    data_dirs = os.environ.get("XDG_DATA_DIRS", "/usr/local/share:/usr/share").split(":")
    candidates = [data_home / "applications"] + [Path(item).expanduser() / "applications" for item in data_dirs if item]
    result: list[Path] = []
    seen: set[str] = set()
    for directory in candidates:
        try:
            resolved = directory.resolve()
        except OSError:
            resolved = directory
        key = os.path.normcase(str(resolved))
        if key not in seen and directory.is_dir():
            seen.add(key)
            result.append(directory)
    return result


def _linux_discover() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(
        label: str,
        path: Path,
        adapter: str,
        args: list[str] | None = None,
        categories: str = "",
        category: str | None = None,
    ) -> None:
        resolved = _resolve_program(str(path))
        if resolved is None or _is_excluded_program(resolved, label):
            return
        key = os.path.normcase(str(resolved))
        if key in seen:
            return
        if _has_reserved_desktop_args(args or [], adapter):
            return
        seen.add(key)
        found.append(_app(label, resolved, adapter, args=args, category=category or _category(label, resolved, categories)))

    # Prefer the packaged application binary over desktop launchers that may
    # point to a per-user wrapper such as sudo/root scripts.
    chatgpt = Path("/usr/lib/chatgpt/ChatGPT")
    chatgpt_executable = _resolve_program(str(chatgpt))
    if chatgpt_executable is not None and _is_elf_executable(chatgpt_executable):
        add("ChatGPT", chatgpt_executable, "chromium", category="communication")
        seen.add(os.path.normcase(str(chatgpt_executable)))

    for label, path, adapter in (
        ("Google Chrome", Path("/opt/google/chrome/chrome"), "chromium"),
        ("Chromium", Path("/usr/lib/chromium/chromium"), "chromium"),
        ("Chromium", Path("/usr/lib/chromium-browser/chromium-browser"), "chromium"),
        ("Microsoft Edge", Path("/opt/microsoft/msedge/msedge"), "chromium"),
        ("Brave", Path("/opt/brave.com/brave/brave"), "chromium"),
        ("Mozilla Firefox", Path("/usr/lib/firefox-esr/firefox"), "firefox"),
        ("Mozilla Firefox", Path("/usr/lib/firefox/firefox"), "firefox"),
        ("Mozilla Firefox", Path("/usr/lib64/firefox/firefox"), "firefox"),
        ("Mozilla Firefox ESR", Path("/usr/lib/firefox-esr/firefox-esr"), "firefox"),
    ):
        add(label, path, adapter)

    # PATH-based installs (including distro and user-local packages) remain
    # discoverable when they are not in one of the common filesystem paths.
    for program, label, adapter in (
        ("google-chrome", "Google Chrome", "chromium"),
        ("chromium", "Chromium", "chromium"),
        ("microsoft-edge", "Microsoft Edge", "chromium"),
        ("brave-browser", "Brave", "chromium"),
        ("firefox", "Mozilla Firefox", "firefox"),
        ("firefox-esr", "Mozilla Firefox ESR", "firefox"),
    ):
        candidate = _resolve_program(program)
        if candidate is not None:
            add(label, candidate, adapter)

    for directory in _linux_applications_dirs():
        try:
            entries = sorted(directory.glob("*.desktop"), key=lambda item: item.name.casefold())
        except OSError:
            continue
        for entry in entries:
            parsed = _desktop_entry(entry)
            if parsed is None:
                continue
            label, raw_path, adapter, args, categories = parsed
            path = Path(raw_path)
            if "chatgpt" in f"{label} {path}".lower():
                # Never list a ChatGPT desktop entry pointing to a wrapper;
                # only the package's actual GUI binary is eligible.
                preferred_chatgpt = chatgpt.resolve() if chatgpt.exists() else None
                if preferred_chatgpt is None or path.resolve() != preferred_chatgpt:
                    continue
            add(label, path, adapter, args=args, categories=categories)
    return found


def _win_registry_apps() -> list[tuple[str, Path]]:
    try:
        import winreg
    except ImportError:
        return []
    found: list[tuple[str, Path]] = []
    access = winreg.KEY_READ
    views = [0]
    for name in ("KEY_WOW64_64KEY", "KEY_WOW64_32KEY"):
        value = getattr(winreg, name, 0)
        if value and value not in views:
            views.append(value)
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in views:
            try:
                root = winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\App Paths", 0, access | view)
            except OSError:
                continue
            try:
                index = 0
                while True:
                    try:
                        subkey = winreg.EnumKey(root, index)
                    except OSError:
                        break
                    index += 1
                    if not subkey.lower().endswith(".exe") or _DISCOVERY_HELPER_RE.search(subkey):
                        continue
                    try:
                        with winreg.OpenKey(root, subkey, 0, access | view) as app_key:
                            value, _kind = winreg.QueryValueEx(app_key, None)
                    except OSError:
                        continue
                    if not isinstance(value, str):
                        continue
                    raw_path = os.path.expandvars(value.strip())
                    if raw_path.startswith('"') and raw_path.endswith('"'):
                        raw_path = raw_path[1:-1]
                    if '"' in raw_path or "\0" in raw_path:
                        continue
                    path = Path(raw_path)
                    if path.is_file() and path.suffix.lower() == ".exe" and not _is_excluded_program(path, path.stem):
                        found.append((path.stem, path))
            finally:
                winreg.CloseKey(root)
    return found


def _windows_discover() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(label: str, raw_path: str | Path | None) -> None:
        if not raw_path:
            return
        path = Path(raw_path).expanduser()
        try:
            path = path.resolve(strict=True)
        except (OSError, RuntimeError):
            return
        if not path.is_file() or path.suffix.lower() != ".exe" or _is_excluded_program(path, label):
            return
        key = os.path.normcase(str(path))
        if key in seen:
            return
        seen.add(key)
        adapter = _infer_adapter(label, path)
        found.append(_app(label, path, adapter, category=_category(label, path)))

    roots = [
        Path(os.environ.get("PROGRAMFILES", r"C:\Program Files")),
        Path(os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")),
    ]
    candidates = [
        ("Google Chrome", roots[0] / "Google/Chrome/Application/chrome.exe"),
        ("Google Chrome", roots[1] / "Google/Chrome/Application/chrome.exe"),
        ("Microsoft Edge", roots[0] / "Microsoft/Edge/Application/msedge.exe"),
        ("Microsoft Edge", roots[1] / "Microsoft/Edge/Application/msedge.exe"),
        ("Microsoft Edge", roots[2] / "Microsoft/Edge/Application/msedge.exe"),
        ("Brave", roots[0] / "BraveSoftware/Brave-Browser/Application/brave.exe"),
        ("Brave", roots[1] / "BraveSoftware/Brave-Browser/Application/brave.exe"),
        ("Brave", roots[2] / "BraveSoftware/Brave-Browser/Application/brave.exe"),
        ("Mozilla Firefox", roots[0] / "Mozilla Firefox/firefox.exe"),
        ("Mozilla Firefox", roots[1] / "Mozilla Firefox/firefox.exe"),
    ]
    for label, path in candidates:
        add(label, path)

    for label, path in _win_registry_apps():
        add(label, path)

    scan_roots = [roots[0], roots[1], roots[2] / "Programs"]
    for root in scan_roots:
        if not root.is_dir():
            continue
        try:
            children = list(root.iterdir())
        except OSError:
            continue
        for child in children:
            if not child.is_dir() or child.name.lower() in {"windowsapps", "uninstall", "updates", "update"}:
                continue
            try:
                entries = list(child.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_file() and entry.suffix.lower() == ".exe":
                    add(child.name, entry)
                elif entry.is_dir() and entry.name.lower() not in {"uninstall", "updates", "update", "crashpad"}:
                    try:
                        for nested in entry.iterdir():
                            if nested.is_file() and nested.suffix.lower() == ".exe":
                                add(child.name, nested)
                    except OSError:
                        pass
    return found


def _discovery_key() -> tuple[Any, ...]:
    return (
        sys.platform,
        os.environ.get("PATH", ""),
        os.environ.get("XDG_DATA_HOME", ""),
        os.environ.get("XDG_DATA_DIRS", ""),
        os.environ.get("PROGRAMFILES", ""),
        os.environ.get("PROGRAMFILES(X86)", ""),
        os.environ.get("LOCALAPPDATA", ""),
        id(shutil.which),
    )


def discover_apps(*, refresh: bool = False) -> list[dict[str, Any]]:
    """List installed desktop apps without executing candidates.

    Results are cached briefly because desktop-entry and install-root scans can
    be expensive. Set ``refresh=True`` when the user explicitly requests a new
    scan.
    """
    global _DISCOVERY_CACHE
    if not isinstance(refresh, bool):
        raise ValueError("refresh must be a boolean")
    key = _discovery_key()
    now = time.monotonic()
    with _DISCOVERY_LOCK:
        if (
            not refresh
            and _DISCOVERY_CACHE
            and _DISCOVERY_CACHE[0] == key
            and now - _DISCOVERY_CACHE[1] < _DISCOVERY_CACHE_SECONDS
        ):
            return deepcopy(_DISCOVERY_CACHE[2])
        if sys.platform == "win32":
            found = _windows_discover()
        elif sys.platform.startswith("linux"):
            found = _linux_discover()
        else:
            found = []
        found.sort(key=lambda item: (item["category"], item["label"].casefold(), item["path"].casefold()))
        _DISCOVERY_CACHE = (key, now, found)
        return deepcopy(found)


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
