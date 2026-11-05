"""Bounded Antigravity routing paths; no discovery execution or signature claim."""
from __future__ import annotations

import os
from pathlib import Path
import stat


def _root(*, local_app_data=None) -> Path | None:
    local = os.environ.get('LOCALAPPDATA') if local_app_data is None else local_app_data
    if not local or not Path(local).is_absolute():
        return None
    return Path(os.path.abspath(local)) / 'Programs' / 'antigravity'


def is_antigravity(path: str | Path, *, local_app_data=None) -> bool:
    """Recognize the lexical standard entry, before resolving any links.

    A linked standard entry must still enter routing validation and fail closed,
    rather than silently falling back to generic single-path routing.
    """
    root = _root(local_app_data=local_app_data)
    if root is None:
        return False
    candidate = Path(path)
    if not candidate.is_absolute() or '..' in candidate.parts:
        return False
    return str(candidate).replace('/', '\\').casefold() == str(root / 'Antigravity.exe').replace('/', '\\').casefold()


def _plain(path: Path, *, directory: bool) -> None:
    value = path.lstat()
    if (stat.S_ISLNK(value.st_mode)
            or getattr(value, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))):
        raise ValueError('Antigravity 路径包含链接、重解析点或非普通文件。')


def routing_paths(path: str | Path, *, local_app_data=None) -> list[str]:
    """Require exactly the main image and the known language-service image.

    Check every ancestor, including the standard root, without traversing any
    directory tree. This does not verify publisher signatures or prevent a
    concurrent replacement after validation.
    """
    root = _root(local_app_data=local_app_data)
    if root is None or not is_antigravity(path, local_app_data=local_app_data):
        return []
    targets = (root / 'Antigravity.exe', root / 'resources' / 'bin' / 'language_server.exe')
    try:
        # Check the lexical ancestors before canonicalizing the boundary: resolve
        # expands Windows 8.3 names, but must never hide a junction/symlink.
        for parent in reversed((root, *root.parents)):
            _plain(parent, directory=True)
        canonical_root = root.resolve(strict=True)
        for target in targets:
            for parent in reversed(target.parents):
                _plain(parent, directory=True)
            _plain(target, directory=False)
            resolved = target.resolve(strict=True)
            expected = canonical_root / target.relative_to(root)
            if str(resolved).casefold() != str(expected).casefold():
                raise ValueError('Antigravity 程序路径逃逸标准安装位置。')
        return [str(target) for target in targets]
    except (OSError, RuntimeError) as error:
        raise ValueError('Antigravity 主程序或语言服务缺失或路径检查失败；未应用不完整路径规则。') from error
