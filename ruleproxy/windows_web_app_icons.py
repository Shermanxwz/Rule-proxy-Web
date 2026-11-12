"""Copy one installed PWA's bounded ICO into this saved app's shortcut cache.

Only the current owner's selected browser/profile/_crx_<app_id> directory is
enumerated. No browser database, shortcut, network, or caller-supplied icon path
is consulted. Any missing, ambiguous, changed or unsafe input means fallback.
"""
from __future__ import annotations

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import re
import struct
import zlib

from .web_app_leveldb import (_Budget, _MetadataDirectory, _close_directory,
                             _local_path, _windows_signature)
from .windows_web_apps import _profile_path, validate_web_app

_MAX_ICON_BYTES = 4 * 1024**2
_MAX_ENTRIES = 64
_SAVED_ID = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z')
_DEVICE_NAME = re.compile(r'(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)


def _png_valid(data, width, height):
    position, chunks, image = 8, 0, False
    while position + 12 <= len(data) and chunks < 1024:
        size = struct.unpack_from('>I', data, position)[0]
        end = position + 12 + size
        if end > len(data):
            return False
        kind = data[position + 4:position + 8]
        body = data[position + 8:end - 4]
        if zlib.crc32(kind + body) & 0xffffffff != struct.unpack_from('>I', data, end - 4)[0]:
            return False
        if chunks == 0:
            if kind != b'IHDR' or size != 13 or struct.unpack_from('>II', body) != (width, height):
                return False
            depth, color, compression, filtering, interlace = body[8:]
            if (depth not in {0: (1, 2, 4, 8, 16), 2: (8, 16), 3: (1, 2, 4, 8), 4: (8, 16), 6: (8, 16)}.get(color, ())
                    or compression or filtering or interlace not in (0, 1)):
                return False
        elif kind == b'IHDR':
            return False
        if kind == b'IDAT':
            image = True
        if kind == b'IEND':
            return image and size == 0 and end == len(data)
        position, chunks = end, chunks + 1
    return False


def _valid_ico(data):
    """Validate container bounds and PNG/DIB framing, without rendering pixels."""
    if not 22 <= len(data) <= _MAX_ICON_BYTES:
        return False
    reserved, kind, count = struct.unpack_from('<HHH', data)
    if reserved or kind != 1 or not 1 <= count <= 64 or 6 + count * 16 > len(data):
        return False
    spans = []
    for index in range(count):
        width, height, colors, reserved, planes, bits, size, offset = struct.unpack_from('<BBBBHHII', data, 6 + index * 16)
        width, height = width or 256, height or 256
        if (reserved or planes not in (0, 1) or bits not in (0, 1, 4, 8, 16, 24, 32)
                or size < 40 or offset < 6 + count * 16 or offset + size > len(data)):
            return False
        spans.append((offset, offset + size))
        image = data[offset:offset + size]
        if image.startswith(b'\x89PNG\r\n\x1a\n'):
            if not _png_valid(image, width, height):
                return False
        else:
            header, dib_width, dib_height, dib_planes, dib_bits, compression = struct.unpack_from('<IiiHHI', image)
            if (header not in (40, 108, 124) or header > size or dib_width != width or dib_height != height * 2
                    or dib_planes != 1 or dib_bits not in (1, 4, 8, 16, 24, 32)
                    or bits not in (0, dib_bits) or compression != 0):
                return False
            palette = struct.unpack_from('<I', image, 32)[0]
            if dib_bits <= 8:
                if palette > 1 << dib_bits:
                    return False
                palette = palette or (1 << dib_bits)
            elif palette:
                return False
            minimum = header + palette * 4 + ((width * dib_bits + 31) // 32 * 4) * height
            minimum += ((width + 31) // 32 * 4) * height
            if size < minimum:
                return False
    return all(first[1] <= second[0] for first, second in zip(sorted(spans), sorted(spans)[1:]))


class _IconDirectory(_MetadataDirectory):
    def inventory(self):
        self._check_path()
        names = []
        with os.scandir(self.path if os.name == 'nt' else self.handle) as entries:
            for count, entry in enumerate(entries, 1):
                self.budget.check()
                if count > _MAX_ENTRIES:
                    raise ValueError('PWA icon directory exceeds limit')
                if entry.name.lower().endswith('.ico'):
                    if (len(entry.name) > 255 or any(c in entry.name for c in '\\/:')
                            or any(ord(c) < 32 for c in entry.name)):
                        raise ValueError('Invalid PWA icon filename')
                    names.append(entry.name)
        if len(names) != 1:
            raise ValueError('No unique installed PWA icon')
        self._check_path()
        self.name = names[0]
        return tuple(names)

    def finish(self):
        if self.inventory() != self.names:
            raise ValueError('Installed PWA icon changed')
        super().finish()


def _read_icon(directory, name, budget, *, choose=False):
    kind = _IconDirectory if choose else _MetadataDirectory
    with kind(directory, budget, name) as snapshot:
        name = snapshot.name
        if (directory / name).lstat().st_nlink != 1:
            raise ValueError('Hard-linked icon is not an independent file')
        with snapshot.file(name, _MAX_ICON_BYTES) as source:
            data = source.read(0, source.size)
        snapshot.finish()
    return data


def _cache_directory(path, parent=None):
    """Hold cache ancestors against Windows replacement until publication ends."""
    if os.name != 'nt':
        return os.open(str(path) if parent is None else path.name,
                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes, drive_type.restype = [wintypes.LPCWSTR], wintypes.UINT
    if drive_type(path.anchor) not in (2, 3):
        raise ValueError('Icon cache requires a local disk')
    create = kernel.CreateFileW
    create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create.restype = wintypes.HANDLE
    # Read attributes; share READ only, not WRITE/DELETE. Held ancestors cannot
    # be renamed/reparsed while child directories/files are created by pathname.
    handle = create(str(path), 0x80, 1, None, 3, 0x02200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError(ctypes.get_last_error(), 'Opening private icon cache failed')
    try:
        _windows_signature(handle, directory=True)
        return handle
    except BaseException:
        _close_directory(handle)
        raise


def _cache_icon(state_dir, saved_id, data):
    state_dir = _local_path(state_dir)
    filename = hashlib.sha256(data).hexdigest() + '.ico'
    with ExitStack() as held:
        parent = None
        for index in range(len(state_dir.parts)):
            directory = Path(*state_dir.parts[:index + 1])
            parent = _cache_directory(directory, parent)
            held.callback(_close_directory, parent)
        directory = state_dir
        for name in ('shortcut-icons', saved_id):
            directory = directory / name
            try:
                if os.name == 'nt':
                    directory.mkdir(mode=0o700)
                else:
                    os.mkdir(name, mode=0o700, dir_fd=parent)
            except FileExistsError:
                pass
            parent = _cache_directory(directory, parent)
            held.callback(_close_directory, parent)
        path = directory / filename
        try:
            fd = os.open(str(path) if os.name == 'nt' else filename,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0),
                         0o600, dir_fd=None if os.name == 'nt' else parent)
        except FileExistsError:
            pass  # Existing content must match; it is never truncated or replaced.
        else:
            with os.fdopen(fd, 'wb') as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
        if _read_icon(directory, filename, _Budget()) != data:
            raise ValueError('Cached PWA icon differs from its content hash')
        return path


def shortcut_icon(app: dict, state_dir: Path) -> Path | None:
    """Best-effort internal path only; never add an icon field to saved settings."""
    try:
        if not isinstance(app, dict) or not isinstance(app.get('path'), str):
            return None
        saved_id = app.get('id')
        if (not isinstance(saved_id, str) or not _SAVED_ID.fullmatch(saved_id)
                or saved_id.endswith('.') or _DEVICE_NAME.match(saved_id)):
            return None
        executable = Path(app.get('path') or '')
        if not executable.is_absolute() or not isinstance(state_dir, Path) or not state_dir.is_absolute():
            return None
        executable = _local_path(executable)
        metadata = validate_web_app(app.get('web_app'), executable)
        if not metadata['app_id']:
            return None
        budget = _Budget()
        with _MetadataDirectory(executable.parent, budget, executable.name) as held:
            held.watch(executable.name)  # Validate local executable identity, not its contents.
            held.finish()
        profile = _local_path(_profile_path(executable, metadata['browser'], metadata['profile_directory']))
        directory = profile / 'Web Applications' / ('_crx_' + metadata['app_id'])
        data = _read_icon(directory, '', budget, choose=True)
        if not _valid_ico(data):
            return None
        return _cache_icon(state_dir, saved_id, data)
    except (OSError, ValueError, OverflowError, struct.error):
        return None
