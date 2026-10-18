"""Independent ordinary-user recovery after a panel or proxy core dies.

Held process handles/pidfds prevent PID-reuse mistakes. The parent must obtain
READY before enabling the desktop proxy, then call arm() after enable succeeds.
No elevation, TUN, route or foreign-setting changes are performed here.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
import json
import os
from pathlib import Path
import queue
import re
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time

STATUS = 'system-proxy-watchdog.json'


@contextmanager
def transaction_lock(directory, timeout=5):
    """Serialize enable/restore across the panel and its independent helper."""
    descriptor = os.open(Path(directory) / 'system-proxy.lock', os.O_RDWR | os.O_CREAT, 0o600)
    locked = False
    try:
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b'\0')
        deadline = time.monotonic() + timeout
        while not locked:
            try:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(descriptor, 0, 0)
                    msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except (BlockingIOError, PermissionError, OSError):
                if time.monotonic() >= deadline:
                    raise OSError('System proxy transaction is still busy')
                time.sleep(.05)
        yield
    finally:
        if locked:
            if os.name == 'nt':
                import msvcrt
                os.lseek(descriptor, 0, 0)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


class Identity:
    def __init__(self, pid, expected=None):
        if type(pid) is not int or pid <= 0:
            raise ValueError('Invalid process identity')
        self.handle = None
        if os.name == 'nt':
            from ctypes import wintypes as W
            self.api = ctypes.WinDLL('kernel32', use_last_error=True)
            self.api.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            self.api.OpenProcess.restype = W.HANDLE
            self.api.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]
            self.api.GetProcessTimes.argtypes = [W.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                                 ctypes.c_void_p, ctypes.c_void_p]
            self.api.CloseHandle.argtypes = [W.HANDLE]
            self.handle = self.api.OpenProcess(0x100000 | 0x1000, False, pid)
            if not self.handle:
                raise ctypes.WinError(ctypes.get_last_error())
            times = [ctypes.c_uint64() for _ in range(4)]
            if not self.api.GetProcessTimes(self.handle, *[ctypes.byref(value) for value in times]):
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())
            self.stamp = str(times[0].value)
        elif sys.platform.startswith('linux') and hasattr(os, 'pidfd_open'):
            self.handle = os.pidfd_open(pid, 0)
            try:
                value = Path('/proc', str(pid), 'stat').read_text()
                self.stamp = value[value.rfind(')') + 2:].split()[19]
            except BaseException:
                self.close()
                raise
        else:
            raise OSError('Reliable process-identity monitoring is unavailable')
        try:
            if self.dead() or expected is not None and self.stamp != expected:
                raise OSError('Process exited or identity changed')
        except BaseException:
            self.close()
            raise

    def dead(self):
        if os.name == 'nt':
            state = self.api.WaitForSingleObject(self.handle, 0)
            if state not in (0, 258):
                raise OSError('Process identity could not be queried')
            return state == 0
        poll = select.poll()
        poll.register(self.handle, select.POLLIN)
        return bool(poll.poll(0))

    def close(self):
        if self.handle is not None:
            if os.name == 'nt':
                self.api.CloseHandle(self.handle)
            else:
                os.close(self.handle)
            self.handle = None


def _environment():
    allowed = {'PATH', 'SYSTEMROOT', 'WINDIR', 'COMSPEC', 'PATHEXT', 'HOME', 'USERPROFILE',
               'APPDATA', 'LOCALAPPDATA', 'TEMP', 'TMP', 'LANG', 'LC_ALL', 'LC_CTYPE',
               'DBUS_SESSION_BUS_ADDRESS', 'XDG_RUNTIME_DIR', 'XDG_CONFIG_HOME', 'XDG_DATA_HOME',
               'XDG_DATA_DIRS', 'DCONF_PROFILE', 'DCONF_USER_CONFIG_DIR', 'GSETTINGS_BACKEND', 'GSETTINGS_SCHEMA_DIR'}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def _python():
    value = Path(sys.executable)
    if os.name == 'nt' and value.name.lower() == 'pythonw.exe':
        value = value.with_name('python.exe')
    if not value.is_file():
        raise OSError('Independent proxy recovery interpreter is unavailable')
    return value


def _options():
    return ({'creationflags': 0x08000000} if os.name == 'nt' else {'start_new_session': True})


def _command(*args):
    return [str(_python()), '-I', '-S', str(Path(__file__).resolve()), *map(str, args)]


def _line(process, expected):
    result = queue.Queue(maxsize=1)
    def read():
        try:
            result.put(process.stdout.readline(128))
        except (OSError, ValueError):
            result.put(b'')
    threading.Thread(target=read, daemon=True).start()
    try:
        line = result.get(timeout=5)
    except queue.Empty as error:
        raise OSError('Independent proxy recovery handshake timed out') from error
    # print() uses CRLF in a Windows text stream, while the control pipes are
    # deliberately binary. Accept only the two transport line endings; never
    # strip whitespace from the nonce or accept additional protocol content.
    crlf = expected[:-1] + b'\r\n' if expected.endswith(b'\n') else expected
    if line not in (expected, crlf):
        raise OSError('Independent proxy recovery did not confirm readiness')


class Watchdog:
    def __init__(self, process, nonce):
        self.process, self.nonce = process, nonce

    def arm(self):
        if self.process.poll() is not None:
            raise OSError('Independent proxy recovery exited before activation')
        self.process.stdin.write(b'ARM\n')
        self.process.stdin.flush()
        _line(self.process, ('ARMED ' + self.nonce + '\n').encode())

    def close(self):
        # EOF requests recovery as well; failed parent-side restoration must
        # never silently cancel the independent final attempt.
        if self.process.stdin and not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            return  # Its bounded restore attempts may finish independently.
        finally:
            if self.process.poll() is not None and self.process.stdout:
                self.process.stdout.close()


def start(directory, core_pid):
    directory = Path(directory).absolute()
    if not directory.is_dir() or core_pid == os.getpid():
        raise ValueError('Invalid independent proxy recovery session')
    parent, core = Identity(os.getpid()), None
    process = None
    try:
        core = Identity(core_pid)
        nonce = os.urandom(16).hex()
        process = subprocess.Popen(_command('--watch', directory, os.getpid(), core_pid,
                                            parent.stamp, core.stamp, nonce),
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=_environment(), close_fds=True, **_options())
        _line(process, ('READY ' + nonce + '\n').encode())
        if parent.dead() or core.dead():
            raise OSError('Panel or core exited before recovery was ready')
        return Watchdog(process, nonce)
    except BaseException:
        if process is not None:
            if process.stdin:
                process.stdin.close()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
            if process.stdout:
                process.stdout.close()
        raise
    finally:
        parent.close()
        if core is not None:
            core.close()


def _status(directory, restored, attempts, session):
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix='.proxy-watchdog-', dir=directory)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump({'schema': 1, 'restored': restored, 'attempts': attempts, 'session': session,
                       'scope': 'matching_transaction_only',
                       'error': None if restored else 'restore_failed_journal_retained'}, stream)
        os.replace(temporary, Path(directory) / STATUS)
    finally:
        if temporary and Path(temporary).exists():
            Path(temporary).unlink()


def _restore_bounded(directory, session):
    # The worker may invoke gsettings. Its whole process group is bounded, so
    # a hung desktop backend cannot strand this independent monitor forever.
    for attempt in range(1, 4):
        try:
            worker = subprocess.Popen(_command('--restore', directory, session), stdin=subprocess.DEVNULL,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      env=_environment(), close_fds=True, **_options())
        except OSError:
            if attempt < 3:
                time.sleep(attempt * .5)
                continue
            _status(directory, False, attempt, session)
            return False
        try:
            ok = worker.wait(timeout=20) == 0
        except subprocess.TimeoutExpired:
            if os.name == 'nt':
                worker.kill()  # The fixed Windows worker only uses registry APIs.
            else:
                os.killpg(worker.pid, signal.SIGKILL)
            worker.wait(timeout=3)
            ok = False
        if ok:
            _status(directory, True, attempt, session)
            return True
        if attempt < 3:
            time.sleep(attempt * .5)
    _status(directory, False, 3, session)
    return False


def _watch(directory, parent_pid, core_pid, parent_stamp, core_stamp, nonce, restore=_restore_bounded):
    if re.fullmatch(r'[a-f0-9]{32}', nonce) is None:
        raise ValueError('Invalid recovery handshake')
    parent, core = Identity(parent_pid, parent_stamp), None
    try:
        core = Identity(core_pid, core_stamp)
        commands = queue.Queue()
        def read_commands():
            try:
                commands.put(sys.stdin.buffer.readline(16))
                commands.put(sys.stdin.buffer.readline(16))
            except OSError:
                commands.put(b'')
        threading.Thread(target=read_commands, daemon=True).start()
        print('READY ' + nonce, flush=True)
        armed, deadline = False, time.monotonic() + 120
        while True:
            try:
                command = commands.get(timeout=.1)
            except queue.Empty:
                command = None
            if command == b'ARM\n' and not armed:
                if parent.dead() or core.dead():
                    restore(directory, nonce)
                    return 1
                armed = True
                print('ARMED ' + nonce, flush=True)
            elif command is not None or parent.dead() or armed and core.dead():
                return 0 if restore(directory, nonce) else 1
            elif not armed and time.monotonic() >= deadline:
                return 0 if restore(directory, nonce) else 1
    finally:
        parent.close()
        if core is not None:
            core.close()


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--restore', nargs=2)
    group.add_argument('--watch', nargs=6)
    args = parser.parse_args()
    if os.name == 'nt':
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ruleproxy.windows_proxy_client import current_user_sid
        if current_user_sid() == 'S-1-5-18':
            raise PermissionError('Proxy recovery requires the desktop user')
    if args.restore:
        directory, session = args.restore
        if re.fullmatch(r'[a-f0-9]{32}', session) is None:
            raise ValueError('Invalid recovery transaction')
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
        from ruleproxy.system_proxy import restore
        restore(Path(directory), expected_session=session)
        return 0
    directory, parent, core, parent_stamp, core_stamp, nonce = args.watch
    return _watch(Path(directory), int(parent), int(core), parent_stamp, core_stamp, nonce)


if __name__ == '__main__':
    raise SystemExit(main())
