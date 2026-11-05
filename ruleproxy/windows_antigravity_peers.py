"""Held native identities for one Manager-owned Antigravity Windows Job.

Only the owned Job's PIDs and IPv4 loopback LISTEN rows are considered. This
module changes no networking, process state, firewall rules, or app settings.
"""
import ctypes
from ctypes import wintypes
import ntpath
import socket

from .windows_antigravity_recovery import ListenerSnapshot


def _job_pids(process):
    class Pids(ctypes.Structure):
        _fields_ = [('assigned', wintypes.DWORD), ('count', wintypes.DWORD),
                    ('pids', ctypes.c_size_t * 256)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    query = kernel.QueryInformationJobObject
    query.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                      wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.BOOL
    data, length = Pids(), wintypes.DWORD()
    # WindowsAppProcess owns these handles. Its lock prevents stop/poll from
    # closing the Job while this read-only query uses it. No handle escapes.
    with process._lock:
        if process.poll() is not None or not process._job:
            raise ValueError('job_exited')
        if not query(process._job, 3, ctypes.byref(data), ctypes.sizeof(data), ctypes.byref(length)):
            raise ValueError('job_query')
    if not 1 <= data.count <= 256 or data.assigned < data.count:
        raise ValueError('job_count')
    return tuple(int(data.pids[i]) for i in range(data.count))


class NativePeers:
    def __init__(self, process, main_path, *, paths=None, owner_sid=None,
                 lease_factory=None, rows_factory=None, pids_factory=None):
        if paths is None:
            from .windows_antigravity import routing_paths
            paths = routing_paths(main_path)
        if len(paths) != 2 or self._path(paths[0]) != self._path(main_path):
            raise ValueError('app_pair')
        if owner_sid is None:
            from .windows_proxy_client import current_user_sid
            owner_sid = current_user_sid()
        if lease_factory is None or rows_factory is None:
            from .windows_proxy_service import ProcessLease, _tcp_connections
            lease_factory = lease_factory or ProcessLease
            rows_factory = rows_factory or (lambda: _tcp_connections(socket.AF_INET))
        self.process, self.paths, self.sid = process, tuple(paths), owner_sid
        self.lease_factory, self.rows_factory = lease_factory, rows_factory
        self.pids_factory = pids_factory or (lambda: _job_pids(process))
        self.main = self.helper = None
        self.helper_pid = None
        try:
            if process.poll() is not None:
                raise ValueError('main_exited')
            self.main = self.lease_factory(process.pid, self.sid)
            if (not self.main.alive() or process.poll() is not None
                    or self._path(self.main.image_path()) != self._path(paths[0])):
                raise ValueError('main_identity')
            self.created = self.main.creation_time()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _path(value):
        return ntpath.normcase(ntpath.normpath(str(value)))

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        try:
            if self.helper is not None:
                self.helper.close()
        finally:
            self.helper = None
            if self.main is not None:
                self.main.close()
                self.main = None

    def _identity(self, pids):
        return (self.main is not None and self.main.alive() and self.process.poll() is None
                and self.process.pid in pids and self.main.creation_time() == self.created
                and (self.helper is None or (self.helper.alive() and self.helper_pid in pids
                     and self.helper.creation_time() >= self.created)))

    @staticmethod
    def _ports(rows, pid):
        chosen = [row['local_port'] for row in rows if row['pid'] == pid]
        if len(chosen) > 8 or any(type(p) is not int or not 1025 <= p <= 65535 for p in chosen):
            raise ValueError('listener_bound')
        if len(set(chosen)) != len(chosen):
            raise ValueError('duplicate_listener')
        if any(sum(row['local_port'] == port for row in rows) != 1 for port in chosen):
            raise ValueError('ambiguous_owner')
        return tuple(sorted(chosen))

    def snapshot(self):
        pids = self.pids_factory()
        if len(pids) > 256 or any(type(pid) is not int or pid < 1 for pid in pids):
            raise ValueError('pids')
        if not self._identity(pids):
            raise ValueError('generation')
        raw = self.rows_factory()
        if not isinstance(raw, list) or len(raw) > 65536:
            raise ValueError('table')
        rows = [row for row in raw if row.get('state') == 2 and row.get('local') == '127.0.0.1']
        main_ports = self._ports(rows, self.process.pid)
        candidates = {row['pid'] for row in rows if row['pid'] in pids and row['pid'] != self.process.pid}
        helpers = []
        for pid in sorted(candidates):
            if pid == self.helper_pid:
                helpers.append(pid)
                continue
            peer = self.lease_factory(pid, self.sid)
            retain = False
            try:
                if not peer.alive():
                    raise ValueError('peer_exited')
                if self._path(peer.image_path()) != self._path(self.paths[1]):
                    continue
                if peer.creation_time() < self.created:
                    raise ValueError('older_helper')
                helpers.append(pid)
                if self.helper is None:
                    self.helper, self.helper_pid = peer, pid
                    retain = True
            finally:
                if not retain:
                    peer.close()
        if len(helpers) > 1 or (self.helper_pid is not None and helpers != [self.helper_pid]):
            raise ValueError('helper_changed')
        helper_ports = self._ports(rows, self.helper_pid) if self.helper is not None else ()
        if not self._identity(self.pids_factory()):
            raise ValueError('generation_changed')
        if not main_ports or not helper_ports:
            return None
        return ListenerSnapshot(main_ports, helper_ports)

    def valid(self, snapshot):
        try:
            return self.snapshot() == snapshot
        except Exception:
            return False
