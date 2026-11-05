"""Injected Antigravity listener discovery; no native operations or imports.

Held handles protect discovery from PID reuse, not WFP process-instance identity.
The broker owns path-generation changes: close this tracker before creating another.
"""
from dataclasses import dataclass
import ipaddress
import ntpath
import socket


class IPCError(RuntimeError):
    def __init__(self, code, message):
        self.code = code
        super().__init__(message)


class PeerRetired(IPCError):
    """Ordinary peer shutdown; recover only after confirmed full cleanup."""


@dataclass(frozen=True)
class Record:
    server_path: str
    client_path: str
    port: int
    pid: int
    created: int


def _path(value):
    if not isinstance(value, str) or not value or '\0' in value:
        raise ValueError('Invalid absolute executable path')
    value = ntpath.normpath(value)
    if not ntpath.isabs(value) or not ntpath.splitdrive(value)[0]:
        raise ValueError('Expected absolute Windows executable path')
    return ntpath.normcase(value)


def snapshot(rows_factory):
    """Return bounded LISTEN rows (family, normalized address, port, pid)."""
    result = []
    count = 0
    for family in (socket.AF_INET, socket.AF_INET6):
        for row in rows_factory(family):
            count += 1
            if count > 65536:
                raise IPCError('table_limit', 'TCP table exceeds bounded discovery limit')
            if row['state'] != 2:
                continue
            address = ipaddress.ip_address(row['local'])
            if address.version != (4 if family == socket.AF_INET else 6):
                raise IPCError('invalid_table', 'TCP address family mismatch')
            port, pid = row['local_port'], row['pid']
            if type(port) is not int or not 1 <= port <= 65535 or type(pid) is not int or pid <= 0:
                raise IPCError('invalid_table', 'Invalid listener port or PID')
            result.append((family, str(address), port, pid))
    return tuple(result)


class Tracker:
    """Fixed-epoch, single-owner coordinator; broker must serialize all calls.

    process_factory(pid, owner_sid) must validate the token owner, then return
    alive(), image_path(), creation_time() (integer FILETIME), close().
    It may return None only to indicate that this refresh did not confirm a
    peer belonging to the configured pair and owner. This does not classify
    that PID as safe or non-target. None grants nothing; unknown errors raise.
    apply receives an immutable tuple of Record; revoke closes the whole dynamic
    session, is idempotent, and must raise if revocation is not confirmed.
    """
    def __init__(self, main_path, helper_path, owner_sid, enabled_after,
                 *, rows_factory, process_factory, apply, revoke):
        main, helper = _path(main_path), _path(helper_path)
        if main == helper or not isinstance(owner_sid, str) or not owner_sid:
            raise ValueError('Distinct paths and owner SID required')
        if type(enabled_after) is not int or enabled_after <= 0:
            raise ValueError('Positive FILETIME threshold required')
        self._pair = (main, helper)
        self._owner = owner_sid
        self._threshold = enabled_after
        self._rows = rows_factory
        self._process = process_factory
        self._apply = apply
        self._revoke = revoke
        self._held = []
        self._peers = {}
        self._records = ()
        self._fault = None
        self._closed = False

    @property
    def records(self):
        return self._records

    @property
    def fault(self):
        return self._fault

    @staticmethod
    def _release(handles):
        errors = []
        for handle in list(handles):
            try:
                handle.close()
                handles.remove(handle)
            except Exception as exc:
                errors.append(exc)
        if errors:
            raise IPCError('handle_cleanup_failed', str(errors[0]))

    def _fail(self, error, fresh):
        self._fault = error
        self._held.extend(fresh)
        fresh.clear()
        try:
            self._revoke()
        except Exception as exc:
            raise IPCError('revoke_failed', f'{error}; revocation failed: {exc}') from exc
        self._records = ()
        self._release(self._held)
        raise error

    def _validate(self, rows, records, handles):
        retired = None
        for record in records:
            matches = [r for r in rows if r[2] == record.port and (
                r[0] == socket.AF_INET and r[1] in ('127.0.0.1', '0.0.0.0')
                or r[0] == socket.AF_INET6 and (
                    r[1] == '::' or ipaddress.ip_address(r[1]).ipv4_mapped is not None))]
            if matches and matches != [(socket.AF_INET, '127.0.0.1', record.port, record.pid)]:
                raise IPCError('listener_changed', 'Listener has conflicting ownership')
            handle = handles[record.pid]
            if not handle.alive():
                retired = PeerRetired('process_exited', 'Listener process exited')
            elif (_path(handle.image_path()) != record.server_path
                    or handle.creation_time() != record.created):
                raise IPCError('process_changed', 'Listener process identity changed')
            if not matches and retired is None:
                retired = PeerRetired('listener_disappeared', 'Listener disappeared')
        # A missing peer must not mask a simultaneous conflict/identity failure.
        if retired is not None:
            raise retired

    def refresh(self):
        if self._closed or self._fault is not None:
            raise IPCError('tracker_unavailable', 'Close and replace the faulted or closed tracker')
        fresh = []
        try:
            first = snapshot(self._rows)
            candidates = [r for r in first if r[0] == socket.AF_INET and r[1] == '127.0.0.1']
            processes, records, exited = {}, [], []
            for _, _, port, pid in candidates:
                if pid not in processes:
                    handle = self._process(pid, self._owner)
                    if handle is None:
                        processes[pid] = None
                        continue
                    fresh.append(handle)
                    if not handle.alive():
                        exited.append(pid)
                        processes[pid] = None
                        continue
                    path = _path(handle.image_path())
                    if path not in self._pair:
                        handle.close()
                        fresh.remove(handle)
                        processes[pid] = None
                        continue
                    created = handle.creation_time()
                    if type(created) is not int or created < self._threshold:
                        raise IPCError('requires_restart', 'Target listener predates guard intent; restart required')
                    processes[pid] = (handle, path, created)
                identity = processes[pid]
                if identity is None:
                    continue
                handle, path, created = identity
                records.append(Record(path, self._pair[1] if path == self._pair[0] else self._pair[0], port, pid, created))
                if len(records) > 16 or sum(r.pid == pid for r in records) > 8:
                    raise IPCError('endpoint_limit', 'IPC endpoint limit exceeded')
            records = tuple(sorted(records, key=lambda r: (r.port, r.pid)))
            handles = {pid: value[0] for pid, value in processes.items() if value is not None}
            # Reuse/identity change is never ordinary retirement. Check before
            # handling a missing endpoint, so it cannot mask a changed PID.
            for old_record in self._records:
                if old_record.pid in handles:
                    identity = processes[old_record.pid]
                    if (not self._peers[old_record.pid].alive()
                            or identity[1:] != (old_record.server_path, old_record.created)):
                        raise IPCError('process_changed', 'Previous listener process identity changed')
            # A disappearance between refreshes also retires the entire lease,
            # rather than silently replacing a subset and keeping old permits.
            omitted = tuple(r for r in self._records if
                            (socket.AF_INET, '127.0.0.1', r.port, r.pid) not in first)
            for _, _, port, pid in candidates:
                if pid in exited:
                    matches = [r for r in first if r[2] == port and (
                        r[0] == socket.AF_INET and r[1] in ('127.0.0.1', '0.0.0.0')
                        or r[0] == socket.AF_INET6 and (
                            r[1] == '::' or ipaddress.ip_address(r[1]).ipv4_mapped is not None))]
                    if matches != [(socket.AF_INET, '127.0.0.1', port, pid)]:
                        raise IPCError('listener_changed', 'Exited listener has conflicting ownership')
            self._validate(first, records + omitted, {**self._peers, **handles})
            self._validate(snapshot(self._rows), records, handles)
            if exited:
                raise PeerRetired('process_exited', 'Listener process exited')
            self._apply(records)
            self._validate(snapshot(self._rows), records, handles)
            old, self._held = self._held, fresh
            self._peers = handles
            fresh = []
            self._records = records
            try:
                self._release(old)
            finally:
                self._held.extend(old)
            return records
        except Exception as exc:
            return self._fail(exc, fresh)

    def close(self):
        # Revocation failure deliberately keeps all handles and permits a retry.
        try:
            self._revoke()
            self._records = ()
            self._release(self._held)
        except Exception as exc:
            self._fault = exc
            raise
        self._closed = True
