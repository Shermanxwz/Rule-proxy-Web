"""Desktop launcher files that start one saved app through the headless runner.

Linux writes Desktop Entry files (applications menu, plus the Desktop folder when
present). Windows creates .lnk files through WScript.Shell in PowerShell. Both run
``Run-RuleProxy.py --launch-app <id>`` with the panel's ports and state directory
written in, so the shortcut works even when the web panel is closed.
"""
from __future__ import annotations

import base64
import binascii
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from .launcher import linux_desktop_icon


ROOT = Path(__file__).resolve().parent.parent
_APP_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_PLAIN_EXEC_ARG_RE = re.compile(r"[A-Za-z0-9_./:=,+@-]+\Z")
_INVALID_FILE_CHARS_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WINDOWS_SHORTCUT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$shell = New-Object -ComObject WScript.Shell
$name = $env:RULEPROXY_SHORTCUT_NAME + '.lnk'
if ($env:RULEPROXY_SHORTCUT_FOLDERS) {
    $folders = @($env:RULEPROXY_SHORTCUT_FOLDERS -split "`n" | Where-Object { $_ })
} else {
    $folders = @(
        [Environment]::GetFolderPath('Desktop'),
        (Join-Path ([Environment]::GetFolderPath('Programs')) 'RuleProxy Web')
    )
}
foreach ($folder in $folders) {
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $path = Join-Path $folder $name
    $link = $shell.CreateShortcut($path)
    $link.TargetPath = $env:RULEPROXY_SHORTCUT_TARGET
    $link.Arguments = $env:RULEPROXY_SHORTCUT_ARGUMENTS
    $link.WorkingDirectory = $env:RULEPROXY_SHORTCUT_WORKDIR
    $link.Description = $env:RULEPROXY_SHORTCUT_DESCRIPTION
    if ($env:RULEPROXY_SHORTCUT_ICON) { $link.IconLocation = $env:RULEPROXY_SHORTCUT_ICON }
    $link.Save()
    # Base64 keeps non-ASCII paths intact whatever the console code page is. Setting
    # [Console]::OutputEncoding instead fails in a process without a console.
    Write-Output ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($path)))
}
"""


def runner_argv(app_id: str, state_dir: Path, ports: tuple[int, int, int]) -> list[str]:
    """Command line that starts one saved app headlessly, using the panel's ports and state."""
    python = sys.executable
    if sys.platform == "win32":
        windowless = Path(python).with_name("pythonw.exe")
        if Path(python).name.lower() == "python.exe" and windowless.is_file():
            python = str(windowless)  # no console window for a desktop shortcut
    panel, mixed, controller = ports
    return [
        python, str(ROOT / "Run-RuleProxy.py"), "--launch-app", app_id,
        "--state-dir", str(state_dir), "--port", str(panel),
        "--proxy-port", str(mixed), "--controller-port", str(controller),
    ]


def _display_name(label: str) -> str:
    return f"{label} (RuleProxy)"


def _desktop_string(value: str) -> str:
    """Escape a value for a Desktop Entry string key (backslashes doubled, no newlines)."""
    return value.replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")


def _desktop_exec(argv: list[str]) -> str:
    """Quote an argument vector for an Exec key: quote arguments, escape reserved characters, then the file escaping."""
    parts = []
    for arg in argv:
        if arg and _PLAIN_EXEC_ARG_RE.fullmatch(arg):
            quoted = arg
        else:
            quoted = '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'
        parts.append(_desktop_string(quoted.replace("%", "%%")))
    return " ".join(parts)


def _desktop_entry(app_id: str, label: str, argv: list[str], icon: str | None = None) -> str:
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        "Version=1.0",
        f"Name={_desktop_string(_display_name(label))}",
        f"Comment={_desktop_string('通过 RuleProxy 隔离启动，使用面板中保存的代理和配置')}",
        *([f"Icon={_desktop_string(icon)}"] if icon else []),
        f"Exec={_desktop_exec(argv)}",
        f"Path={_desktop_string(str(ROOT))}",
        "Terminal=false",
        "StartupNotify=false",
        "Categories=Network;",
        f"X-RuleProxy-App={app_id}",
        "",
    ]
    return "\n".join(lines)


def _write_file(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        temp.write_text(text, encoding="utf-8")
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _best_effort(command: list[str]) -> None:
    if shutil.which(command[0]) is None:
        return
    try:
        subprocess.run(command, capture_output=True, timeout=20, check=False)
    except (OSError, subprocess.SubprocessError):
        pass


def _linux_shortcuts(app_id: str, label: str, argv: list[str], icon: str | None) -> list[Path]:
    text = _desktop_entry(app_id, label, argv, icon)
    data_home = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local/share")).expanduser()
    menu = data_home / "applications" / f"ruleproxy-{app_id}.desktop"
    _write_file(menu, text, 0o644)
    _best_effort(["update-desktop-database", str(menu.parent)])
    created = [menu]
    desktop = Path.home() / "Desktop"
    if desktop.is_dir():
        copy = desktop / f"ruleproxy-{app_id}.desktop"
        _write_file(copy, text, 0o755)  # Desktop launchers need the execute bit to be trusted
        _best_effort(["gio", "set", str(copy), "metadata::trusted", "true"])
        created.append(copy)
    return created


def _windows_shortcuts(app: dict, label: str, argv: list[str], folders: list[Path] | None = None) -> list[Path]:
    """Create .lnk files on the Desktop and in the Start menu, or in ``folders`` when given."""
    safe = _INVALID_FILE_CHARS_RE.sub(" ", _display_name(label)).strip(" .") or "RuleProxy"
    environment = {
        **os.environ,
        "RULEPROXY_SHORTCUT_NAME": safe,
        "RULEPROXY_SHORTCUT_TARGET": argv[0],
        "RULEPROXY_SHORTCUT_ARGUMENTS": subprocess.list2cmdline(argv[1:]),
        "RULEPROXY_SHORTCUT_WORKDIR": str(ROOT),
        "RULEPROXY_SHORTCUT_DESCRIPTION": f"RuleProxy 隔离启动：{label}",
        "RULEPROXY_SHORTCUT_ICON": f"{app['path']},0" if app.get("path") else "",
        "RULEPROXY_SHORTCUT_FOLDERS": "\n".join(str(folder) for folder in folders or []),
    }
    encoded = base64.b64encode(_WINDOWS_SHORTCUT_SCRIPT.encode("utf-16-le")).decode("ascii")
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            env=environment, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=60, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("无法运行 PowerShell 创建 Windows 快捷方式。") from exc
    try:
        created = [Path(base64.b64decode(line.strip(), validate=True).decode("utf-8")) for line in result.stdout.splitlines() if line.strip()]
    except (binascii.Error, UnicodeDecodeError):
        created = []
    if result.returncode != 0 or not created:
        reason = next((line.strip() for line in (result.stderr or "").splitlines() if line.strip()), "")
        raise ValueError("无法创建 Windows 快捷方式。请确认桌面和开始菜单目录可写。" + (f"（{reason[:300]}）" if reason else ""))
    return created


def create_shortcut_files(app: dict, *, state_dir: Path, ports: tuple[int, int, int]) -> list[Path]:
    """Create the platform launcher files for one saved app and return their paths."""
    app_id = app.get("id")
    if not isinstance(app_id, str) or not _APP_ID_RE.fullmatch(app_id):
        raise ValueError("应用 ID 无效，无法创建快捷方式。")
    label = str(app.get("label") or "应用").strip() or "应用"
    argv = runner_argv(app_id, Path(state_dir), ports)
    if sys.platform.startswith("linux"):
        return _linux_shortcuts(app_id, label, argv, linux_desktop_icon(str(app.get("path") or ""), label))
    if sys.platform == "win32":
        return _windows_shortcuts(app, label, argv)
    raise ValueError("当前系统不支持创建快捷方式。")


def remove_shortcut_files(app: dict) -> None:
    """Delete launcher files recorded for an app. Only files this module names are removed."""
    for raw in app.get("shortcuts") or []:
        if not isinstance(raw, str):
            continue
        path = Path(raw)
        ours = (path.suffix == ".desktop" and path.name.startswith("ruleproxy-")) or (path.suffix == ".lnk" and path.stem.endswith(" (RuleProxy)"))
        if ours and path.is_file():
            try:
                path.unlink()
            except OSError:
                pass
