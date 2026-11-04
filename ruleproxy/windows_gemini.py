"""Recognize Google's per-user Gemini launcher and its versioned executables."""

import os
from pathlib import Path
import re


_VERSION = re.compile(r"app-\d+(?:\.\d+){1,4}\Z", re.IGNORECASE)
_BINARIES = ("Gemini.exe", "GeminiAppLauncher.exe")


def _root() -> Path | None:
    local = os.environ.get("LOCALAPPDATA")
    if not local:
        return None
    return (Path(local) / "Google" / "Gemini").resolve()


def is_gemini(path: str | Path) -> bool:
    """Match only Gemini's expected per-user installation, not its display name."""
    root = _root()
    if root is None:
        return False
    candidate = Path(path).resolve()
    if candidate.name.casefold() not in {name.casefold() for name in _BINARIES}:
        return False
    parent = candidate.parent
    return (str(parent).casefold() == str(root).casefold() or
            (_VERSION.fullmatch(parent.name) is not None and
             str(parent.parent).casefold() == str(root).casefold()))


def routing_paths(path: str | Path) -> list[str]:
    """Resolve all installed version images before applying path-based routing.

    Do not follow a version directory or executable outside the Gemini root.
    Fail closed if a complete installed version cannot be identified.
    """
    root = _root()
    if root is None or not is_gemini(path):
        return []
    paths = []
    for name in _BINARIES:
        candidate = root / name
        if candidate.is_file() and is_gemini(candidate):
            paths.append(str(candidate.resolve()))
    versions = []
    for directory in root.iterdir():
        if not _VERSION.fullmatch(directory.name) or not directory.is_dir():
            continue
        if directory.resolve().parent != root:
            raise ValueError("Gemini 版本目录指向安装目录外，无法安全配置代理。")
        main = directory / "Gemini.exe"
        if not main.is_file() or not is_gemini(main):
            continue
        versions.append(directory)
        for name in _BINARIES:
            candidate = directory / name
            if candidate.is_file():
                if not is_gemini(candidate):
                    raise ValueError("Gemini 程序指向安装目录外，无法安全配置代理。")
                paths.append(str(candidate.resolve()))
    if not versions:
        raise ValueError("无法找到 Gemini 的版本程序，无法安全配置代理。")
    return list(dict.fromkeys(paths))
