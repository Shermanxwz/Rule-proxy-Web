"""Bounded, read-only access to selected Chromium Web Applications LevelDB keys.

``read_values`` returns opaque bytes, not protobufs. Only CURRENT, its MANIFEST,
manifest-live tables, and recovery-live WALs are opened. Other values are skipped
by their encoded lengths; unrelated table data blocks are not read. No LevelDB
library, database lock, recovery, repair, browser API, or write is used.

This is deliberately a strict *observation* of a quiescent database, not a live
LevelDB client. Missing files, unsupported formats/comparators, corruption,
resource limits, and observed concurrent changes raise ValueError. Metadata is
checked before and after reading; as with any lock-free stat-based snapshot,
this does not promise isolation from adversarial timestamp/identity restoration.
Time limits are checked between bounded local-file reads and parsing steps (a
blocked OS filesystem call itself is not interruptible by this synchronous API).

Format references:
https://github.com/google/leveldb/blob/main/doc/table_format.md
https://github.com/google/leveldb/blob/main/doc/log_format.md
"""
from __future__ import annotations

from bisect import bisect_left
from dataclasses import dataclass, field
import os
from pathlib import Path
import re
import stat
import struct
import time


# Hard limits, intentionally not caller-configurable. A large/unusual database
# should produce an unresolved PWA URL, never an unbounded fallback scan.
_MAX_SECONDS = 5.0
_MAX_DIRECTORY_ENTRIES = 4096
_MAX_FILES = 512
_MAX_FILE_BYTES = 256 * 1024 * 1024
_MAX_MANIFEST_BYTES = 8 * 1024 * 1024
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_MAX_LOG_BYTES = 32 * 1024 * 1024
_MAX_READ_BYTES = 64 * 1024 * 1024
_MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_BLOCK_BYTES = 4 * 1024 * 1024
_MAX_RECORD_BYTES = 4 * 1024 * 1024
_MAX_RECORDS = 250_000
_MAX_KEYS = 1024
_MAX_KEY_BYTES = 4096
_MAX_VALUE_BYTES = 4 * 1024 * 1024
_MAX_RESULT_BYTES = 16 * 1024 * 1024
_MAX_SEQUENCE = (1 << 56) - 1
_LOG_BLOCK_BYTES = 32768
_TABLE_MAGIC = 0xDB4775248B80FB57
_CURRENT = re.compile(rb'MANIFEST-([0-9]{1,20})\n\Z')
_NUMBERED = re.compile(r'([0-9]{1,20})\.(log|ldb|sst)\Z')
_MANIFEST = re.compile(r'MANIFEST-[0-9]{1,20}\Z')


class _Budget:
    def __init__(self):
        self.deadline = time.monotonic() + _MAX_SECONDS
        self.read_bytes = 0
        self.decompressed_bytes = 0
        self.records = 0

    def check(self):
        if time.monotonic() >= self.deadline:
            raise ValueError('LevelDB time limit exceeded')

    def charge(self, field_name, size, maximum):
        self.check()
        total = getattr(self, field_name) + size
        if size < 0 or total > maximum:
            raise ValueError('LevelDB ' + field_name + ' limit exceeded')
        setattr(self, field_name, total)

    def record(self, count=1):
        self.charge('records', count, _MAX_RECORDS)


def _crc_table():
    result = []
    for number in range(256):
        for _ in range(8):
            number = (number >> 1) ^ (0x82F63B78 if number & 1 else 0)
        result.append(number)
    return tuple(result)


_CRC_TABLE = _crc_table()


def _crc32c(data, initial=0, budget=None):
    crc = initial ^ 0xFFFFFFFF
    for offset, byte in enumerate(data):
        if budget is not None and offset % 4096 == 0:
            budget.check()
        crc = _CRC_TABLE[(crc ^ byte) & 255] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _masked_crc(data, initial=0, budget=None):
    crc = _crc32c(data, initial, budget)
    return (((crc >> 15) | (crc << 17)) + 0xA282EAD8) & 0xFFFFFFFF


class _Cursor:
    def __init__(self, data):
        self.data = memoryview(data)
        self.pos = 0

    def varint(self, bits=64):
        number = 0
        for shift in range(0, bits, 7):
            if self.pos >= len(self.data):
                raise ValueError('Truncated LevelDB varint')
            byte = self.data[self.pos]
            self.pos += 1
            number |= (byte & 127) << shift
            if number >= 1 << bits:
                raise ValueError('Overflowing LevelDB varint')
            if byte < 128:
                if shift and byte == 0:
                    raise ValueError('Noncanonical LevelDB varint')
                return number
        raise ValueError('Overlong LevelDB varint')

    def take(self, length):
        end = self.pos + length
        if length < 0 or end > len(self.data):
            raise ValueError('Truncated LevelDB field')
        value = self.data[self.pos:end]
        self.pos = end
        return value

    def string(self, maximum):
        length = self.varint(32)
        if length > maximum:
            raise ValueError('LevelDB field limit exceeded')
        return self.take(length)

    def done(self):
        return self.pos == len(self.data)


def _snappy(data, budget):
    """Decode raw Snappy blocks, including overlapping COPY_1/2/4 operations."""
    cursor = _Cursor(data)
    size = cursor.varint(32)
    if size > _MAX_BLOCK_BYTES:
        raise ValueError('Snappy output limit exceeded')
    budget.charge('decompressed_bytes', size, _MAX_DECOMPRESSED_BYTES)
    result = bytearray()
    while not cursor.done():
        budget.record()
        tag = cursor.take(1)[0]
        kind = tag & 3
        if kind == 0:
            length = tag >> 2
            if length < 60:
                length += 1
            else:
                length = int.from_bytes(cursor.take(length - 59), 'little') + 1
            if length > size - len(result):
                raise ValueError('Snappy literal exceeds declared output')
            result.extend(cursor.take(length))
        else:
            if kind == 1:
                length = 4 + ((tag >> 2) & 7)
                offset = ((tag & 0xE0) << 3) | cursor.take(1)[0]
            else:
                length = 1 + (tag >> 2)
                offset = int.from_bytes(cursor.take(2 if kind == 2 else 4), 'little')
            if not offset or offset > len(result) or length > size - len(result):
                raise ValueError('Invalid Snappy copy')
            # Copy lengths are at most 64. Repetition handles offset < length
            # without a byte-at-a-time quadratic expansion.
            start = len(result) - offset
            pattern = result[start:start + min(length, offset)]
            result.extend((pattern * ((length + len(pattern) - 1) // len(pattern)))[:length])
    if len(result) != size:
        raise ValueError('Truncated Snappy output')
    return bytes(result)


def _signature(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _plain(value, directory=False):
    if (stat.S_ISLNK(value.st_mode)
            or getattr(value, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))):
        raise ValueError('LevelDB path is not a plain local file/directory')


def _local_path(directory):
    if not isinstance(directory, Path):
        raise ValueError('LevelDB directory must be a Path')
    text = str(directory)
    if (text.startswith(('\\\\', '//')) or '..' in directory.parts
            or '\x00' in text or (os.name != 'nt' and ('\\' in text or ':' in text))):
        raise ValueError('Invalid local LevelDB directory')
    path = directory.absolute()  # Do not resolve links, even temporarily.
    if os.name == 'nt' and ((directory.drive and not directory.is_absolute())
                            or not re.fullmatch(r'[A-Za-z]:', path.drive)
                            or any(':' in part for part in path.parts[1:])):
        raise ValueError('UNC, device and alternate-stream paths are unsupported')
    if len(path.parts) > 128 or len(str(path)) > 32760:
        raise ValueError('LevelDB path limit exceeded')
    return path


def _windows_open(name, parent=None, directory=False):
    """Open one component without following reparse points, including parents.

    NtCreateFile's RootDirectory is the Windows counterpart of openat. All
    handles share READ/WRITE/DELETE: this does not acquire the browser's LOCK or
    stop compaction/rotation. Root drive handles use CreateFileW once.
    """
    import ctypes
    from ctypes import wintypes
    import msvcrt

    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    close = kernel.CloseHandle
    close.argtypes = [wintypes.HANDLE]
    close.restype = wintypes.BOOL
    handle = wintypes.HANDLE()
    if parent is None:
        drive_type = kernel.GetDriveTypeW
        drive_type.argtypes = [wintypes.LPCWSTR]
        drive_type.restype = wintypes.UINT
        if drive_type(name) not in (2, 3):  # Removable or fixed local disk.
            raise ValueError('LevelDB drive is not a local disk')
        create = kernel.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        handle.value = create(name, 0x1200A9, 7, None, 3, 0x02200000, None)
        if handle.value == ctypes.c_void_p(-1).value:
            raise OSError(ctypes.get_last_error(), 'Opening LevelDB drive failed')
    else:
        class UnicodeString(ctypes.Structure):
            _fields_ = [('Length', wintypes.USHORT), ('MaximumLength', wintypes.USHORT),
                        ('Buffer', wintypes.LPWSTR)]

        class ObjectAttributes(ctypes.Structure):
            _fields_ = [('Length', wintypes.ULONG), ('RootDirectory', wintypes.HANDLE),
                        ('ObjectName', ctypes.POINTER(UnicodeString)), ('Attributes', wintypes.ULONG),
                        ('SecurityDescriptor', ctypes.c_void_p), ('SecurityQoS', ctypes.c_void_p)]

        class IOStatus(ctypes.Structure):
            _fields_ = [('Status', ctypes.c_void_p), ('Information', ctypes.c_size_t)]

        text = ctypes.create_unicode_buffer(name)
        length = len(name.encode('utf-16-le'))
        string = UnicodeString(length, length + 2, ctypes.cast(text, wintypes.LPWSTR))
        attributes = ObjectAttributes(ctypes.sizeof(ObjectAttributes), parent,
                                      ctypes.pointer(string), 0x40, None, None)
        io_status = IOStatus()
        create = ctypes.WinDLL('ntdll').NtCreateFile
        create.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                           ctypes.POINTER(ObjectAttributes), ctypes.POINTER(IOStatus),
                           ctypes.c_void_p, wintypes.ULONG, wintypes.ULONG, wintypes.ULONG,
                           wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG]
        create.restype = wintypes.LONG
        status = create(ctypes.byref(handle), 0x1200A9 if directory else 0x120089, ctypes.byref(attributes),
                        ctypes.byref(io_status), None, 0, 7, 1,
                        0x00200020 | (1 if directory else 0x40), None, 0)
        if status < 0:
            raise OSError('Opening LevelDB component failed: NTSTATUS %08x' % (status & 0xFFFFFFFF))
    transferred = False
    try:
        class AttributeTag(ctypes.Structure):
            _fields_ = [('Attributes', wintypes.DWORD), ('Tag', wintypes.DWORD)]

        info = AttributeTag()
        query = kernel.GetFileInformationByHandleEx
        query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        query.restype = wintypes.BOOL
        if not query(handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            raise OSError(ctypes.get_last_error(), 'Inspecting LevelDB handle failed')
        if info.Attributes & 0x400 or bool(info.Attributes & 0x10) != directory:
            raise ValueError('LevelDB reparse/nonregular component')
        if directory:
            transferred = True
            return handle.value
        fd = msvcrt.open_osfhandle(handle.value, os.O_RDONLY | os.O_BINARY)
        transferred = True  # The CRT file descriptor now owns the handle.
        return fd
    finally:
        if not transferred and handle.value is not None:
            close(handle)


def _close_directory(handle):
    if os.name == 'nt':
        import ctypes
        close = ctypes.WinDLL('kernel32').CloseHandle
        close.argtypes = [ctypes.c_void_p]
        close.restype = ctypes.c_int
        close(handle)
    else:
        os.close(handle)


def _windows_signature(handle, directory=False):
    """Use one native metadata representation, not mixed stat/fstat ctimes.

    Windows Python versions differ in whether path stat's st_ctime denotes
    creation time or change time, while descriptor stat may use the other one.
    FileBasicInfo supplies the actual ChangeTime consistently for both watches
    and open handles; FileIdInfo preserves the full 128-bit filesystem identity.
    """
    import ctypes
    from ctypes import wintypes

    class FileId(ctypes.Structure):
        _fields_ = [('VolumeSerialNumber', ctypes.c_uint64), ('FileId', ctypes.c_ubyte * 16)]

    class Basic(ctypes.Structure):
        _fields_ = [('CreationTime', ctypes.c_int64), ('LastAccessTime', ctypes.c_int64),
                    ('LastWriteTime', ctypes.c_int64), ('ChangeTime', ctypes.c_int64),
                    ('FileAttributes', wintypes.DWORD)]

    class Standard(ctypes.Structure):
        _fields_ = [('AllocationSize', ctypes.c_int64), ('EndOfFile', ctypes.c_int64),
                    ('NumberOfLinks', wintypes.DWORD), ('DeletePending', ctypes.c_ubyte),
                    ('Directory', ctypes.c_ubyte)]

    query = ctypes.WinDLL('kernel32', use_last_error=True).GetFileInformationByHandleEx
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    query.restype = wintypes.BOOL
    identity, basic, standard = FileId(), Basic(), Standard()
    for info_class, output in ((18, identity), (0, basic), (1, standard)):
        if not query(handle, info_class, ctypes.byref(output), ctypes.sizeof(output)):
            raise OSError(ctypes.get_last_error(), 'Reading LevelDB native file metadata failed')
    if (basic.FileAttributes & 0x400 or bool(basic.FileAttributes & 0x10) != directory
            or bool(standard.Directory) != directory or standard.DeletePending or standard.EndOfFile < 0):
        raise ValueError('LevelDB native file is reparse, deleted or nonregular')
    return (identity.VolumeSerialNumber, bytes(identity.FileId), basic.FileAttributes,
            standard.EndOfFile, basic.LastWriteTime, basic.ChangeTime)


def _file_signature(fd):
    if os.name == 'nt':
        import msvcrt
        return _windows_signature(msvcrt.get_osfhandle(fd))
    value = os.fstat(fd)
    _plain(value)
    return _signature(value)


class _File:
    def __init__(self, owner, name, maximum):
        self.owner = owner
        self.name = name
        self.before = owner.watch(name)
        self.size = self.before[3]
        if self.size > min(maximum, _MAX_FILE_BYTES):
            raise ValueError('LevelDB file size limit exceeded')
        if os.name == 'nt':
            self.fd = _windows_open(name, owner.handle)
        else:
            self.fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=owner.handle)
        try:
            if _file_signature(self.fd) != self.before:
                raise ValueError('LevelDB file changed while opening')
        except BaseException:
            os.close(self.fd)
            raise

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        try:
            if exc_type is None and _file_signature(self.fd) != self.before:
                raise ValueError('LevelDB file changed while reading')
        finally:
            os.close(self.fd)

    def read(self, offset, length):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise ValueError('Invalid LevelDB read bounds')
        self.owner.budget.charge('read_bytes', length, _MAX_READ_BYTES)
        os.lseek(self.fd, offset, os.SEEK_SET)
        result = bytearray()
        while len(result) < length:
            self.owner.budget.check()
            data = os.read(self.fd, min(length - len(result), 65536))
            if not data:
                raise ValueError('LevelDB file truncated while reading')
            result.extend(data)
        self.owner.budget.check()
        return bytes(result)


class _Directory:
    def __init__(self, path, budget):
        self.path = path
        self.budget = budget
        self.watched = {}
        self.handle = None
        self.ancestors = []

    def __enter__(self):
        try:
            for index, part in enumerate(self.path.parts):
                self.budget.check()
                path = Path(*self.path.parts[:index + 1])
                value = path.lstat()
                _plain(value, directory=True)
                self.ancestors.append((path, (value.st_dev, value.st_ino)))
                if os.name == 'nt':
                    opened = _windows_open(part, self.handle, directory=True)
                elif self.handle is None:
                    opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                else:
                    opened = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                     dir_fd=self.handle)
                if self.handle is not None:
                    _close_directory(self.handle)
                self.handle = opened
            self.root_signature = _signature(self.path.lstat())
            if os.name == 'nt':
                self.root_handle_signature = _windows_signature(self.handle, directory=True)
            self._check_path()
            self.names = self.inventory()
            return self
        except BaseException:
            if self.handle is not None:
                _close_directory(self.handle)
            raise

    def __exit__(self, exc_type, exc, traceback):
        _close_directory(self.handle)

    def _check_path(self):
        self.budget.check()
        for path, identity in self.ancestors:
            value = path.lstat()
            _plain(value, directory=True)
            if (value.st_dev, value.st_ino) != identity:
                raise ValueError('LevelDB ancestor changed')
        if _signature(self.path.lstat()) != self.root_signature:
            raise ValueError('LevelDB directory changed')
        if os.name == 'nt':
            if _windows_signature(self.handle, directory=True) != self.root_handle_signature:
                raise ValueError('LevelDB directory handle changed')
        elif _signature(os.fstat(self.handle)) != self.root_signature:
            raise ValueError('LevelDB directory identity changed')

    def inventory(self):
        self._check_path()
        result = []
        with os.scandir(self.path if os.name == 'nt' else self.handle) as entries:
            for count, entry in enumerate(entries, 1):
                self.budget.check()
                if count > _MAX_DIRECTORY_ENTRIES:
                    raise ValueError('LevelDB directory entry limit exceeded')
                if entry.name == 'CURRENT' or _NUMBERED.fullmatch(entry.name) or _MANIFEST.fullmatch(entry.name):
                    result.append(entry.name)
        self._check_path()
        return tuple(sorted(result))

    def watch(self, name):
        self.budget.check()
        if name not in self.names:
            raise ValueError('Missing live LevelDB file')
        if os.name == 'nt':
            self._check_path()
            _plain((self.path / name).lstat())
            fd = _windows_open(name, self.handle)
            try:
                signature = _file_signature(fd)
            finally:
                os.close(fd)
        else:
            value = os.stat(name, dir_fd=self.handle, follow_symlinks=False)
            _plain(value)
            signature = _signature(value)
        if name in self.watched and self.watched[name] != signature:
            raise ValueError('LevelDB file changed during snapshot')
        if name not in self.watched and len(self.watched) >= _MAX_FILES:
            raise ValueError('LevelDB live file limit exceeded')
        self.watched[name] = signature
        return signature

    def file(self, name, maximum):
        return _File(self, name, maximum)

    def finish(self, current):
        if self.inventory() != self.names:
            raise ValueError('LevelDB file inventory changed')
        if _read_current(self) != current:
            raise ValueError('LevelDB CURRENT changed')
        for name in tuple(self.watched):
            self.watch(name)
        if self.inventory() != self.names:
            raise ValueError('LevelDB file inventory changed')
        self.budget.check()


def _read_current(directory):
    with directory.file('CURRENT', 64) as source:
        value = source.read(0, source.size)
    match = _CURRENT.fullmatch(value)
    if not match or not 0 < int(match[1]) < 1 << 64:
        raise ValueError('Invalid LevelDB CURRENT')
    return value


def _log_records(source, budget):
    fragments = None
    zero_tail = False
    for offset in range(0, source.size, _LOG_BLOCK_BYTES):
        block = source.read(offset, min(_LOG_BLOCK_BYTES, source.size - offset))
        if zero_tail:
            budget.check()
            if any(block):
                raise ValueError('Nonzero data after LevelDB preallocated tail')
            continue
        pos = 0
        while pos < len(block):
            budget.record()
            remaining = len(block) - pos
            if remaining < 7:
                if len(block) != _LOG_BLOCK_BYTES or any(block[pos:]):
                    raise ValueError('Truncated or nonzero LevelDB log trailer')
                break
            checksum, length, kind = struct.unpack_from('<IHB', block, pos)
            pos += 7
            if checksum == length == kind == 0:
                if fragments is not None or any(block[pos:]):
                    raise ValueError('Invalid LevelDB preallocated tail')
                zero_tail = True
                break
            if kind not in (1, 2, 3, 4) or length > len(block) - pos:
                raise ValueError('Invalid LevelDB physical log record')
            payload = memoryview(block)[pos:pos + length]
            pos += length
            if _masked_crc(payload, _crc32c(bytes((kind,))), budget) != checksum:
                raise ValueError('LevelDB log CRC32C mismatch')
            if kind in (1, 2):
                if fragments is not None:
                    raise ValueError('Unfinished LevelDB fragmented record')
                if kind == 1:
                    if length > _MAX_RECORD_BYTES:
                        raise ValueError('LevelDB logical record limit exceeded')
                    yield payload
                    continue
                fragments = bytearray()
            elif fragments is None:
                raise ValueError('Orphan LevelDB log fragment')
            if len(fragments) + length > _MAX_RECORD_BYTES:
                raise ValueError('LevelDB logical record limit exceeded')
            fragments.extend(payload)
            if kind == 4:
                yield memoryview(bytes(fragments))
                fragments = None
    if fragments is not None:
        raise ValueError('Truncated LevelDB fragmented record')


def _internal(key):
    if len(key) < 8 or len(key) > _MAX_KEY_BYTES + 8:
        raise ValueError('Invalid LevelDB internal key length')
    tag = int.from_bytes(key[-8:], 'little')
    if tag & 255 not in (0, 1):
        raise ValueError('Unsupported LevelDB value type')
    return key[:-8], tag >> 8, tag & 255


def _order(key):
    user, sequence, kind = _internal(key)
    return user, -((sequence << 8) | kind)


@dataclass(frozen=True)
class _Table:
    level: int
    number: int
    size: int
    smallest: bytes
    largest: bytes


@dataclass
class _Version:
    comparator: bytes | None = None
    log: int | None = None
    previous_log: int = 0
    next_file: int | None = None
    sequence: int | None = None
    tables: dict[int, _Table] = field(default_factory=dict)


def _level(cursor):
    level = cursor.varint(32)
    if level > 6:
        raise ValueError('Unsupported LevelDB level')
    return level


def _read_manifest(directory, name):
    version = _Version()
    with directory.file(name, _MAX_MANIFEST_BYTES) as source:
        for record in _log_records(source, directory.budget):
            cursor = _Cursor(record)
            deleted, added, scalar_tags = [], [], set()
            while not cursor.done():
                directory.budget.record()
                tag = cursor.varint(32)
                if tag in (1, 2, 3, 4, 9):
                    if tag in scalar_tags:
                        raise ValueError('Duplicate LevelDB VersionEdit field')
                    scalar_tags.add(tag)
                if tag == 1:
                    comparator = bytes(cursor.string(256))
                    if comparator != b'leveldb.BytewiseComparator':
                        raise ValueError('Unsupported LevelDB comparator')
                    version.comparator = comparator
                elif tag in (2, 3, 4, 9):
                    value = cursor.varint()
                    if tag == 2:
                        version.log = value
                    elif tag == 3:
                        version.next_file = value
                    elif tag == 4:
                        if value > _MAX_SEQUENCE or (version.sequence is not None and value < version.sequence):
                            raise ValueError('Invalid LevelDB manifest sequence')
                        version.sequence = value
                    else:
                        version.previous_log = value
                elif tag == 5:
                    _level(cursor)
                    _internal(bytes(cursor.string(_MAX_KEY_BYTES + 8)))
                elif tag == 6:
                    deleted.append((_level(cursor), cursor.varint()))
                elif tag == 7:
                    level, number, size = _level(cursor), cursor.varint(), cursor.varint()
                    smallest = bytes(cursor.string(_MAX_KEY_BYTES + 8))
                    largest = bytes(cursor.string(_MAX_KEY_BYTES + 8))
                    if (not number or not 48 <= size <= _MAX_FILE_BYTES
                            or _order(smallest) > _order(largest)):
                        raise ValueError('Invalid LevelDB table metadata')
                    added.append(_Table(level, number, size, smallest, largest))
                else:
                    raise ValueError('Unsupported LevelDB VersionEdit tag')
                if len(deleted) > _MAX_FILES or len(added) > _MAX_FILES:
                    raise ValueError('LevelDB VersionEdit file limit exceeded')
            # VersionEdit applies deletions first, regardless of tag wire order.
            for level, number in deleted:
                existing = version.tables.get(number)
                if existing is None or existing.level != level:
                    raise ValueError('Deleting an unknown LevelDB table')
                del version.tables[number]
            for table in added:
                if table.number in version.tables:
                    raise ValueError('Duplicate active LevelDB table number')
                version.tables[table.number] = table
                if len(version.tables) > _MAX_FILES:
                    raise ValueError('LevelDB table count limit exceeded')
    if (version.comparator is None or version.log is None
            or version.next_file is None or version.sequence is None):
        raise ValueError('Incomplete LevelDB MANIFEST')
    if (version.next_file <= max([version.log, version.previous_log, *version.tables], default=0)
            or (version.previous_log and version.previous_log >= version.log)):
        raise ValueError('Invalid LevelDB file numbering')
    # Above level zero, *internal* key ranges must not overlap. Consecutive
    # tables can still contain different sequence versions of the same user.
    for level in range(1, 7):
        tables = sorted((t for t in version.tables.values() if t.level == level),
                        key=lambda t: _order(t.smallest))
        for previous, current in zip(tables, tables[1:]):
            if _order(previous.largest) >= _order(current.smallest):
                raise ValueError('Overlapping LevelDB table ranges')
    return version


def _entries(data, budget):
    if len(data) < 8:
        raise ValueError('Truncated LevelDB restart block')
    count = struct.unpack_from('<I', data, len(data) - 4)[0]
    if not count or count > (len(data) - 4) // 4 or count > _MAX_RECORDS:
        raise ValueError('Invalid LevelDB restart count')
    end = len(data) - 4 * (count + 1)
    restarts = [struct.unpack_from('<I', data, end + 4 * index)[0] for index in range(count)]
    if restarts[0] != 0 or any(a >= b for a, b in zip(restarts, restarts[1:])):
        raise ValueError('Invalid LevelDB restart ordering')
    if (end and restarts[-1] >= end) or (not end and restarts != [0]):
        raise ValueError('Invalid LevelDB restart bounds')
    cursor = _Cursor(memoryview(data)[:end])
    previous = b''
    restart_index = 0
    while not cursor.done():
        budget.record()
        start = cursor.pos
        shared, length, value_length = cursor.varint(32), cursor.varint(32), cursor.varint(32)
        if shared > len(previous) or shared + length > _MAX_KEY_BYTES + 8:
            raise ValueError('Invalid LevelDB prefix compression')
        if restart_index < len(restarts) and restarts[restart_index] <= start:
            if restarts[restart_index] != start or shared != 0:
                raise ValueError('Invalid LevelDB restart entry')
            restart_index += 1
        key = previous[:shared] + bytes(cursor.take(length))
        value = cursor.take(value_length)  # Opaque view; never decode other values.
        yield key, value
        previous = key
    if end and restart_index != len(restarts):
        raise ValueError('Unvisited LevelDB restart offset')


def _handle(cursor, limit):
    offset, size = cursor.varint(), cursor.varint()
    if size > _MAX_BLOCK_BYTES or size == 0 or offset + size + 5 > limit:
        raise ValueError('Invalid LevelDB block handle')
    return offset, size


def _read_block(source, handle, budget):
    offset, size = handle
    raw = source.read(offset, size + 5)
    payload, kind = memoryview(raw)[:size], raw[size]
    checksum = struct.unpack_from('<I', raw, size + 1)[0]
    if _masked_crc(memoryview(raw)[:size + 1], budget=budget) != checksum:
        raise ValueError('LevelDB block CRC32C mismatch')
    if kind == 0:
        budget.charge('decompressed_bytes', size, _MAX_DECOMPRESSED_BYTES)
        return bytes(payload)
    if kind == 1:
        return _snappy(payload, budget)
    raise ValueError('Unsupported LevelDB block compression')


class _Values:
    def __init__(self, keys):
        self.keys = keys
        self.sorted_keys = sorted(keys)
        self.versions = {}
        self.size = 0

    def intersects(self, smallest, largest):
        index = bisect_left(self.sorted_keys, smallest)
        return index < len(self.sorted_keys) and self.sorted_keys[index] <= largest

    def offer(self, key, sequence, kind, value):
        if key not in self.keys:
            return
        if kind == 0 and len(value):
            raise ValueError('Nonempty LevelDB deletion value')
        existing = self.versions.get(key)
        if existing is not None:
            if sequence < existing[0]:
                return
            if sequence == existing[0]:
                if kind != existing[1] or value != existing[2]:
                    raise ValueError('Conflicting LevelDB sequence')
                return
        if len(value) > _MAX_VALUE_BYTES:
            raise ValueError('LevelDB selected value limit exceeded')
        total = self.size + len(value) - (len(existing[2]) if existing else 0)
        if total > _MAX_RESULT_BYTES:
            raise ValueError('LevelDB result limit exceeded')
        self.versions[key] = (sequence, kind, bytes(value))
        self.size = total

    def result(self):
        return {key: value for key, (_, kind, value) in self.versions.items() if kind == 1}


def _read_table(directory, name, table, version_sequence, values):
    if not values.intersects(_internal(table.smallest)[0], _internal(table.largest)[0]):
        return
    with directory.file(name, _MAX_FILE_BYTES) as source:
        footer_offset = source.size - 48
        footer = source.read(footer_offset, 48)
        if struct.unpack_from('<Q', footer, 40)[0] != _TABLE_MAGIC:
            raise ValueError('Invalid LevelDB table magic')
        cursor = _Cursor(footer[:40])
        meta = _handle(cursor, footer_offset)
        index = _handle(cursor, footer_offset)
        if (any(cursor.take(40 - cursor.pos)) or meta[0] + meta[1] + 5 > index[0]
                or index[0] + index[1] + 5 != footer_offset):
            raise ValueError('Invalid LevelDB table footer layout')
        entries = []
        previous, previous_end = None, 0
        for key, value in _entries(_read_block(source, index, directory.budget), directory.budget):
            order = _order(key)
            if previous is not None and order <= previous:
                raise ValueError('Unsorted LevelDB table index')
            handle_cursor = _Cursor(value)
            handle = _handle(handle_cursor, meta[0])
            if not handle_cursor.done() or handle[0] < previous_end:
                raise ValueError('Overlapping/invalid LevelDB data blocks')
            entries.append((key, handle))
            previous, previous_end = order, handle[0] + handle[1] + 5
        if not entries or _order(entries[-1][0]) < _order(table.largest):
            raise ValueError('Incomplete LevelDB index')
        # Seek as LevelDB does with a maximal sequence. The first index entry
        # >= the lookup internal key contains the newest possible version in
        # this table; later blocks can only hold older versions of that user.
        index_orders = [_order(key) for key, _ in entries]
        chosen = {bisect_left(index_orders, (key, -((_MAX_SEQUENCE << 8) | 1)))
                  for key in values.sorted_keys
                  if _internal(table.smallest)[0] <= key <= _internal(table.largest)[0]}
        previous_separator = None
        for index_number, (separator, handle) in enumerate(entries):
            if index_number in chosen:
                previous_key, first, last = None, None, None
                for key, value in _entries(_read_block(source, handle, directory.budget), directory.budget):
                    order = _order(key)
                    if (previous_key is not None and order <= previous_key
                            or previous_separator is not None and order <= _order(previous_separator)
                            or order > _order(separator)
                            or order < _order(table.smallest) or order > _order(table.largest)):
                        raise ValueError('Invalid LevelDB data key range/order')
                    user, sequence, kind = _internal(key)
                    if sequence > version_sequence:
                        raise ValueError('SST sequence exceeds manifest sequence')
                    values.offer(user, sequence, kind, value)
                    previous_key, last = order, key
                    if first is None:
                        first = key
                if (first is None or index_number == 0 and first != table.smallest
                        or index_number == len(entries) - 1 and last != table.largest):
                    raise ValueError('LevelDB table boundary mismatch')
            previous_separator = separator


def _read_wal(directory, name, values):
    with directory.file(name, _MAX_LOG_BYTES) as source:
        for record in _log_records(source, directory.budget):
            cursor = _Cursor(record)
            sequence, count = struct.unpack('<QI', cursor.take(12))
            if sequence > _MAX_SEQUENCE or (count and count - 1 > _MAX_SEQUENCE - sequence):
                raise ValueError('LevelDB WAL sequence overflow')
            directory.budget.record(count)
            for index in range(count):
                directory.budget.check()
                kind = cursor.take(1)[0]
                if kind not in (0, 1):
                    raise ValueError('Unsupported LevelDB WAL operation')
                key = bytes(cursor.string(_MAX_KEY_BYTES))
                value = cursor.string(_MAX_RECORD_BYTES) if kind == 1 else memoryview(b'')
                values.offer(key, sequence + index, kind, value)
            if not cursor.done():
                raise ValueError('LevelDB WAL operation count mismatch')


def read_values(directory: Path, keys: set[bytes]) -> dict[bytes, bytes]:
    """Return the latest nondeleted values for exactly ``keys`` or raise ValueError.

    The caller normally supplies ``b'web_apps-dt-' + app_id`` keys. Keys/values
    remain opaque and this module never interprets any application's protobuf.
    An empty key set performs no filesystem I/O. All file access is read-only.
    """
    budget = _Budget()
    if not isinstance(keys, (set, frozenset)) or len(keys) > _MAX_KEYS:
        raise ValueError('Invalid LevelDB key set or key count limit')
    if any(not isinstance(key, bytes) or len(key) > _MAX_KEY_BYTES for key in keys):
        raise ValueError('Invalid LevelDB key or key size limit')
    values = _Values(frozenset(keys))
    if not keys:
        return {}
    path = _local_path(directory)
    try:
        with _Directory(path, budget) as snapshot:
            current = _read_current(snapshot)
            version = _read_manifest(snapshot, current[:-1].decode('ascii'))
            tables, logs = {}, {}
            for name in snapshot.names:
                budget.check()
                match = _NUMBERED.fullmatch(name)
                if not match:
                    continue
                number, extension = int(match[1]), match[2]
                if number >= 1 << 64:
                    raise ValueError('Overflowing LevelDB filename number')
                if extension == 'log' and (number >= version.log or number == version.previous_log != 0):
                    if number in logs:
                        raise ValueError('Ambiguous LevelDB log filenames')
                    logs[number] = name
                elif extension in ('ldb', 'sst') and number in version.tables:
                    if number in tables:
                        raise ValueError('Ambiguous LevelDB table filenames')
                    tables[number] = name
            if set(tables) != set(version.tables) or any(
                    number and number not in logs for number in (version.log, version.previous_log)):
                raise ValueError('Missing manifest-live LevelDB file')
            # Watch every live file before reading any table or WAL, even a
            # range-skipped table. Orphan files are never opened or interpreted.
            for number, name in tables.items():
                if snapshot.watch(name)[3] != version.tables[number].size:
                    raise ValueError('LevelDB table size disagrees with manifest')
            for name in logs.values():
                if snapshot.watch(name)[3] > min(_MAX_LOG_BYTES, _MAX_FILE_BYTES):
                    raise ValueError('LevelDB log file limit exceeded')
            for number, name in sorted(tables.items()):
                _read_table(snapshot, name, version.tables[number], version.sequence, values)
            for _, name in sorted(logs.items()):
                _read_wal(snapshot, name, values)
            snapshot.finish(current)
            return values.result()
    except (OSError, OverflowError, struct.error) as exc:
        raise ValueError('LevelDB snapshot could not be read: ' + str(exc)) from exc


class _MetadataDirectory(_Directory):
    """Watch exactly one allowlisted metadata file without enumerating a profile."""

    def __init__(self, path, budget, name):
        super().__init__(path, budget)
        self.name = name

    def inventory(self):
        self._check_path()
        return (self.name,)

    def finish(self):
        self._check_path()
        self.watch(self.name)
        self._check_path()
        self.budget.check()


def read_metadata_file(directory: Path, name: str) -> bytes:
    """Read one Preferences file through held, no-reparse directory handles.

    Only ``Preferences`` and ``Secure Preferences`` are accepted. The payload is
    opaque and capped at 8 MiB. Missing paths raise FileNotFoundError; invalid
    paths, concurrent changes and other read failures raise ValueError. No
    profile directory enumeration or ordinary path-based file open is used.
    """
    if not isinstance(name, str) or name not in ('Preferences', 'Secure Preferences'):
        raise ValueError('Unsupported Chromium metadata filename')
    budget = _Budget()
    path = _local_path(directory)
    try:
        with _MetadataDirectory(path, budget, name) as snapshot:
            with snapshot.file(name, _MAX_METADATA_BYTES) as source:
                value = source.read(0, source.size)
            snapshot.finish()
            return value
    except FileNotFoundError:
        raise
    except (OSError, OverflowError, struct.error) as exc:
        raise ValueError('Chromium metadata snapshot could not be read: ' + str(exc)) from exc
