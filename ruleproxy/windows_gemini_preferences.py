"""Reversible Gemini-only native proxy preference, never a desktop proxy.
Callers must stop all exact Gemini images before acquire/restore. The receipt
contains only the previous proxy key, not other profile contents or sessions.
Crash receipts are retained until a successful compare-and-restore.
"""
import json
import os
from pathlib import Path
import stat
import tempfile

LIMIT = 1024 * 1024
TARGET_KEYS = {'mode', 'server', 'bypass_list'}


def _safe(path):
    path = Path(path).absolute()
    for item in (path, *path.parents):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Gemini preference path contains a link')
        if item == path and not stat.S_ISDIR(info.st_mode):
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError('Gemini preference is not a single regular file')
    return path


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate preference key')
        result[key] = value
    return result


def _read(path):
    _safe(path)
    try:
        with open(path, 'rb') as f:
            value = f.read(LIMIT + 1)
    except FileNotFoundError:
        return None, {}
    if len(value) > LIMIT:
        raise ValueError('Gemini preference size limit')
    result = json.loads(value.decode('utf-8'), object_pairs_hook=_pairs)
    if not isinstance(result, dict):
        raise ValueError('Gemini preference must be an object')
    return value, result


def _atomic(path, value, expected):
    path = _safe(path)
    encoded = json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > LIMIT:
        raise ValueError('Gemini preference size limit')
    path.parent.mkdir(parents=True, exist_ok=True)
    _safe(path.parent)
    fd, name = tempfile.mkstemp(prefix='.ruleproxy-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(encoded)
            f.flush()
            os.fsync(f.fileno())
        current, _ = _read(path)
        if current != expected:
            raise ValueError('Gemini preference changed concurrently')
        _safe(path)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _proxy(port):
    if type(port) is not int or not 1025 <= port <= 65535:
        raise ValueError('Invalid proxy port')
    return {'mode': 'fixed_servers', 'server': f'http://127.0.0.1:{port}', 'bypass_list': '<-loopback>'}


def recover(profile, receipt):
    target = _safe(Path(profile) / 'Preferences')
    receipt = _safe(receipt)
    raw, saved = _read(receipt)
    if raw is None:
        return
    if (set(saved) != {'schema', 'path', 'existed', 'previous', 'installed', 'port'}
            or saved['schema'] != 1 or type(saved['existed']) is not bool
            or saved['path'] != str(target) or saved['installed'] != _proxy(saved['port'])):
        raise ValueError('Invalid Gemini preference receipt')
    current, prefs = _read(target)
    previous_matches = ('proxy' in prefs) == saved['existed'] and prefs.get('proxy') == saved['previous']
    if not previous_matches:
        if prefs.get('proxy') != saved['installed']:
            raise ValueError('Gemini proxy preference conflict; receipt retained')
        if saved['existed']:
            prefs['proxy'] = saved['previous']
        else:
            prefs.pop('proxy', None)
        _atomic(target, prefs, current)
    # Delete only the same receipt that was read; do not remove a newer lease.
    again, _ = _read(receipt)
    if again != raw:
        raise ValueError('Gemini receipt changed concurrently')
    receipt.unlink()


class _Lock:
    def __init__(self, receipt):
        path = _safe(str(receipt) + '.lock')
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = open(path, 'a+b')
        try:
            if self.file.seek(0, 2) == 0:
                self.file.write(b'0')
                self.file.flush()
            self.file.seek(0)
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(self.file.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.file.close()
            raise

    def close(self):
        self.file.close()


class Lease:
    def __init__(self, profile, receipt, check_idle, lock):
        self.profile, self.receipt, self.check_idle = profile, receipt, check_idle
        self.lock = lock
        self.closed = False

    def close(self):
        if not self.closed:
            self.check_idle()
            recover(self.profile, self.receipt)
            self.closed = True
            self.lock.close()


def acquire(profile, receipt, port, check_idle):
    installed = _proxy(port)
    profile = _safe(profile)
    receipt = _safe(receipt)
    lock = _Lock(receipt)
    try:
        check_idle()
        recover(profile, receipt)
        target = profile / 'Preferences'
        original, prefs = _read(target)
        saved = {'schema': 1, 'path': str(target), 'existed': 'proxy' in prefs,
                 'previous': prefs.get('proxy'), 'installed': installed, 'port': port}
        _atomic(receipt, saved, None)
        prefs['proxy'] = installed
        # A failed write intentionally keeps the durable recovery receipt.
        check_idle()
        _atomic(target, prefs, original)
        return Lease(profile, receipt, check_idle, lock)
    except BaseException:
        lock.close()
        raise
