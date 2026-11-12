"""Bounded application-group loopback discovery with injected native boundaries.

The WFP identity remains executable path + owner SID, not a process-instance
identity. Handles and repeated table snapshots protect listener discovery only.
Groups are not merged transitively: sharing one helper grants no unrelated edge.
"""
from dataclasses import dataclass
import ipaddress
import socket

from .windows_antigravity_ipc import IPCError, PeerRetired, Tracker as PairTracker, _path, snapshot
from .windows_proxy_policy import MAX_IPC_CLIENT_RULES, normalize_ipc_groups


@dataclass(frozen=True)
class Record:
    server_path: str
    client_paths: tuple[str, ...]
    port: int
    pid: int
    created: int


class Tracker(PairTracker):
    """Reuse the pair tracker's exact identity checks and ordered revocation."""
    def __init__(self, groups, owner_sid, enabled_after, *, rows_factory,
                 process_factory, apply, revoke):
        groups = normalize_ipc_groups([list(group) for group in groups])
        if not groups or not isinstance(owner_sid, str) or not owner_sid:
            raise ValueError('Application groups and owner SID required')
        paths = tuple(sorted({path for group in groups for path in group}))
        epochs = enabled_after if type(enabled_after) is dict else dict.fromkeys(paths, enabled_after)
        if set(epochs) != set(paths) or any(type(value) is not int or value <= 0 for value in epochs.values()):
            raise ValueError('Positive FILETIME threshold for every path required')
        self._pair, self._owner, self._epochs = paths, owner_sid, dict(epochs)
        self._clients = {path: tuple(sorted({client for group in groups if path in group for client in group}))
                         for path in paths}
        self._rows, self._process, self._apply, self._revoke = rows_factory, process_factory, apply, revoke
        self._held, self._peers, self._records = [], {}, ()
        self._fault, self._closed = None, False
        self.waiting_restart_count = 0

    def refresh(self):
        if self._closed or self._fault is not None:
            raise IPCError('tracker_unavailable', 'Close and replace the faulted or closed tracker')
        fresh = []
        try:
            first = snapshot(self._rows)
            candidates = [row for row in first if row[0] == socket.AF_INET and row[1] == '127.0.0.1']
            processes, records, exited, waiting, unverified = {}, [], [], set(), set()
            for _, _, port, pid in candidates:
                if pid not in processes:
                    handle = self._process(pid, self._owner)
                    if handle is None:
                        processes[pid] = None
                        if pid in self._peers:
                            unverified.add(pid)
                        continue
                    fresh.append(handle)
                    if not handle.alive():
                        exited.append(pid)
                        processes[pid] = None
                        continue
                    path = _path(handle.image_path())
                    if path not in self._clients:
                        handle.close()
                        fresh.remove(handle)
                        processes[pid] = None
                        continue
                    created = handle.creation_time()
                    if type(created) is not int or created <= 0:
                        raise IPCError('process_changed', 'Invalid listener creation time')
                    if any(old.pid == pid and (not self._peers[pid].alive()
                           or (path, created) != (old.server_path, old.created)) for old in self._records):
                        raise IPCError('process_changed', 'Previous listener process identity changed')
                    if created < self._epochs[path]:
                        # Existing unrelated instances never gain a permit and do
                        # not prevent a different selected application starting.
                        waiting.add(pid)
                        handle.close()
                        fresh.remove(handle)
                        processes[pid] = None
                        continue
                    processes[pid] = (handle, path, created)
                identity = processes[pid]
                if identity is None:
                    continue
                handle, path, created = identity
                records.append(Record(path, self._clients[path], port, pid, created))
                if len(records) > 16 or sum(record.pid == pid for record in records) > 8:
                    raise IPCError('endpoint_limit', 'IPC endpoint limit exceeded')
                if sum(len(record.client_paths) for record in records) > MAX_IPC_CLIENT_RULES:
                    raise IPCError('client_limit', 'IPC client rule budget exceeded')
            records = tuple(sorted(records, key=lambda record: (record.port, record.pid)))
            handles = {pid: value[0] for pid, value in processes.items() if value is not None}
            for old in self._records:
                if old.pid in handles:
                    identity = processes[old.pid]
                    if (not self._peers[old.pid].alive()
                            or identity[1:] != (old.server_path, old.created)):
                        raise IPCError('process_changed', 'Previous listener process identity changed')
            omitted = tuple(record for record in self._records if
                            record.pid in unverified or
                            (socket.AF_INET, '127.0.0.1', record.port, record.pid) not in first)
            # The inherited validator checks wildcard/IPv6 conflicts even if
            # a simultaneous process exit would otherwise trigger retirement.
            exited_records = tuple(Record('', (), port, pid, 0) for _, _, port, pid in candidates if pid in exited)
            for record in exited_records:
                matches = [row for row in first if row[2] == record.port and
                           (row[0] == socket.AF_INET and row[1] in ('127.0.0.1', '0.0.0.0')
                            or row[0] == socket.AF_INET6 and
                            (row[1] == '::' or ipaddress.ip_address(row[1]).ipv4_mapped is not None))]
                if matches != [(socket.AF_INET, '127.0.0.1', record.port, record.pid)]:
                    raise IPCError('listener_changed', 'Exited listener has conflicting ownership')
            self._validate(first, records + omitted, {**self._peers, **handles})
            self._validate(snapshot(self._rows), records, handles)
            if unverified:
                raise PeerRetired('peer_unverified', 'Previously leased listener is no longer verified')
            if exited:
                raise PeerRetired('process_exited', 'Listener process exited')
            self._apply(records)
            self._validate(snapshot(self._rows), records, handles)
            old, self._held = self._held, fresh
            self._peers, self._records = handles, records
            self.waiting_restart_count = len(waiting)
            fresh = []
            try:
                self._release(old)
            finally:
                self._held.extend(old)
            return records
        except Exception as exc:
            return self._fail(exc, fresh)
