"""Windows strong per-app isolation through TCP/IP network compartments.

This is the Windows counterpart of the Linux network-namespace mode. A network
compartment is a kernel partition of the TCP/IP stack: a compartment created
with no configured interface keeps only its own loopback pseudo-interface and
has no route off the host, so a process bound into it cannot reach the network
at all. Windows enforces that in the kernel, independent of the process token
and of whether Windows Firewall is enabled, and every child process and nested
Job inherits the boundary.

The installed SYSTEM service binds the panel's Job object to a compartment, so
the launched application and all of its descendants run inside it. The service
then opens exactly one path out: a relay thread that listens on 127.0.0.1/::1
at the panel's proxy port *inside* the compartment and forwards to the engine
on the same port in the default compartment (port spaces are per-compartment).
With the relay stopped the compartment is sealed again, so revoking isolation
leaves the application with no network. Applications must speak to that
loopback proxy; the panel injects it through the process environment exactly as
the plain native-proxy launch already does, so the endpoint the app sees is
identical whether or not it is contained.

Native evidence: .github/windows_compartment_lab.py (Windows Server 2025).
Inside the compartment, direct TCP/UDP to the host, loopback services, IPv6,
public addresses, UDP 53 and getaddrinfo all fail; only the relayed proxy port
works; children, nested Jobs and in-process compartment re-bind attempts stay
contained; Edge, Chrome and Firefox render through the relay with their own
sandboxes intact. That experiment does not by itself qualify every application
or Windows build; product acceptance is gathered separately on real Windows.

The iphlpapi exports used here are declared in the Windows SDK netioapi.h and
are the same ones Microsoft's own hcsshim uses for container networking.
https://learn.microsoft.com/windows/win32/api/netioapi/
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
import hashlib
import re
import select
import socket
import threading
import uuid

from .windows_proxy_policy import ProxyError

NAMESPACE_RE = re.compile(r"RuleProxyNS\.[0-9a-f]{20}\Z")
DESCRIPTION = "RuleProxy network compartment"


def namespace_name(ident: str) -> str:
    """A stable, opaque compartment label; app labels and paths never reach the OS."""
    if not isinstance(ident, str) or not ident or "\0" in ident:
        raise ProxyError("invalid_request", "应用标识无效。")
    return "RuleProxyNS." + hashlib.sha256(("compartment\0" + ident).encode()).hexdigest()[:20]


def _check_name(name):
    if not isinstance(name, str) or not NAMESPACE_RE.fullmatch(name):
        raise ProxyError("invalid_request", "网络隔间名称无效。")
    return name


def _check_port(port):
    if type(port) is not int or not 1025 <= port <= 65535:
        raise ProxyError("invalid_request", "代理端口无效。")
    return port


class _GUID(C.Structure):
    _fields_ = [("Data1", C.c_uint32), ("Data2", C.c_uint16),
                ("Data3", C.c_uint16), ("Data4", C.c_ubyte * 8)]

    @classmethod
    def of(cls, value: uuid.UUID) -> "_GUID":
        result = cls()
        C.memmove(C.byref(result), value.bytes_le, 16)
        return result


class _Row(C.Structure):
    # netioapi.h MIB_COMPARTMENT_ROW: GUID CompartmentGuid;
    # NET_IF_COMPARTMENT_ID CompartmentId; WCHAR Description[IF_MAX_STRING_SIZE + 1]
    # with IF_MAX_STRING_SIZE == 256.
    _fields_ = [("CompartmentGuid", _GUID), ("CompartmentId", C.c_uint32),
                ("Description", C.c_wchar * 257)]


class _CompartmentAPI:
    """Privileged compartment control, only ever constructed in the SYSTEM service.

    All Windows handles are loaded lazily so the policy and lifecycle logic in
    this module can be exercised on other hosts with a fake API.
    """

    def __init__(self):
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.i = C.WinDLL("iphlpapi", use_last_error=True)
        pointer = C.c_void_p
        for owner, name, args, result in (
                (self.k, "GetCurrentProcess", [], W.HANDLE),
                (self.k, "OpenProcess", [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
                (self.k, "DuplicateHandle", [W.HANDLE, W.HANDLE, W.HANDLE, C.POINTER(W.HANDLE),
                                             W.DWORD, W.BOOL, W.DWORD], W.BOOL),
                (self.k, "CloseHandle", [W.HANDLE], W.BOOL),
                (self.i, "GetDefaultCompartmentId", [], C.c_uint32),
                (self.i, "SetCurrentThreadCompartmentId", [C.c_uint32], C.c_uint32),
                (self.i, "GetCurrentThreadCompartmentId", [], C.c_uint32),
                (self.i, "GetJobCompartmentId", [W.HANDLE], C.c_uint32),
                (self.i, "SetJobCompartmentId", [W.HANDLE, C.c_uint32], C.c_uint32),
                (self.i, "InitializeCompartmentEntry", [C.POINTER(_Row)], None),
                (self.i, "CreateCompartment", [C.POINTER(_Row)], C.c_uint32),
                (self.i, "DeleteCompartment", [C.c_uint32], C.c_uint32)):
            function = getattr(owner, name)
            function.argtypes, function.restype = args, result
        self.default = int(self.i.GetDefaultCompartmentId())

    def _fail(self, what):
        code = C.get_last_error()
        raise ProxyError("namespace_failed", f"{what}失败：{C.FormatError(code).strip()}（{code}）。")

    def create(self):
        """Create a fresh sealed compartment; return ``(compartment_id, guid)``."""
        row = _Row()
        self.i.InitializeCompartmentEntry(C.byref(row))
        guid = uuid.uuid4()
        row.CompartmentGuid = _GUID.of(guid)
        row.Description = DESCRIPTION
        code = int(self.i.CreateCompartment(C.byref(row)))
        if code != 0:
            raise ProxyError("namespace_failed", f"创建网络隔间失败（{code}）。")
        return int(row.CompartmentId), str(guid)

    def delete(self, cid):
        """Best effort. A compartment that has had a Job bound returns 1359."""
        return int(self.i.DeleteCompartment(C.c_uint32(cid)))

    def bind_job(self, pid, handle, cid):
        """Duplicate the panel's Job handle into this process and seal it into ``cid``.

        Returns the duplicated handle (kept open by the caller). The panel only
        ever hands us a handle in its own process; the broker has already
        confirmed ``pid`` is the owning panel it holds a lease on.
        """
        process = self.k.OpenProcess(0x0040 | 0x1000, False, pid)  # DUP_HANDLE | QUERY_LIMITED
        if not process:
            self._fail("打开面板进程")
        duplicate = W.HANDLE()
        try:
            if not self.k.DuplicateHandle(process, W.HANDLE(handle), self.k.GetCurrentProcess(),
                                          C.byref(duplicate), 0, False, 2):  # DUPLICATE_SAME_ACCESS
                self._fail("复制 Job 句柄")
        finally:
            self.k.CloseHandle(process)
        code = int(self.i.SetJobCompartmentId(duplicate, C.c_uint32(cid)))
        if code != 0 or int(self.i.GetJobCompartmentId(duplicate)) != cid:
            self.k.CloseHandle(duplicate)
            raise ProxyError("namespace_failed", f"绑定 Job 到网络隔间失败（{code}）。")
        return duplicate.value

    def close(self, handle):
        if handle:
            self.k.CloseHandle(W.HANDLE(handle))


class _Relay:
    """The one sealed path out of a compartment.

    The listener thread switches itself into the compartment and binds the
    proxy port on both loopback families there. Each accepted connection is
    pumped by a worker thread that switches into the default compartment and
    dials the engine on the same port, so the app's loopback proxy endpoint is
    unchanged by containment. Stopping closes every socket and ends the loop.
    """

    def __init__(self, api, cid, proxy_port, upstream_port=None):
        self.api, self.cid, self.proxy_port = api, cid, proxy_port
        # The engine listens on the same port number in the default compartment;
        # tests point the upstream at a distinct port on single-compartment hosts.
        self.upstream_port = upstream_port if upstream_port is not None else proxy_port
        self.listeners: list[socket.socket] = []
        self.connections: list[socket.socket] = []
        self.bound: list[str] = []
        self.errors: list[str] = []
        self.accepted = 0
        self.stopping = threading.Event()
        self.ready = threading.Event()
        self._lock = threading.Lock()

    def start(self):
        threading.Thread(target=self._listen, name="ruleproxy-ns-listen", daemon=True).start()
        self.ready.wait(10)
        if not self.bound:
            self.stop()
            raise ProxyError("namespace_failed", "网络隔间内未能建立代理监听。")
        return list(self.bound)

    def _track(self, sock):
        with self._lock:
            if self.stopping.is_set():
                sock.close()
                return False
            self.connections.append(sock)
            return True

    def _pump(self, source, target):
        try:
            while True:
                data = source.recv(65536)
                if not data:
                    break
                target.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (source, target):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _forward(self, accepted):
        upstream = None
        try:
            self.api.i.SetCurrentThreadCompartmentId(C.c_uint32(self.api.default))
            upstream = socket.create_connection(("127.0.0.1", self.upstream_port), timeout=5)
            if not self._track(upstream):
                return
            upstream.settimeout(None)
            accepted.settimeout(None)
            back = threading.Thread(target=self._pump, args=(upstream, accepted), daemon=True)
            back.start()
            self._pump(accepted, upstream)
            back.join(30)
        except OSError as exc:
            self.errors.append(str(exc)[:160])
        finally:
            for sock in (accepted, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

    def _listen(self):
        try:
            self.api.i.SetCurrentThreadCompartmentId(C.c_uint32(self.cid))
            if int(self.api.i.GetCurrentThreadCompartmentId()) != self.cid:
                self.errors.append("thread compartment switch did not take")
                return
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                sock = socket.socket(family, socket.SOCK_STREAM)
                try:
                    sock.bind((host, self.proxy_port))
                    sock.listen(64)
                    self.listeners.append(sock)
                    self.bound.append(host)
                except OSError as exc:
                    self.errors.append(f"{host}: {exc}"[:160])
                    sock.close()
        finally:
            self.ready.set()
        while not self.stopping.is_set():
            try:
                ready, _, _ = select.select(self.listeners, [], [], 0.5)
            except (OSError, ValueError):
                break
            for sock in ready:
                try:
                    accepted, _ = sock.accept()
                except OSError:
                    continue
                self.accepted += 1
                if self._track(accepted):
                    threading.Thread(target=self._forward, args=(accepted,),
                                     name="ruleproxy-ns-forward", daemon=True).start()

    def stop(self):
        self.stopping.set()
        with self._lock:
            socks = self.listeners + self.connections
            self.listeners, self.connections = [], []
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass


class NamespaceGate:
    """Service-side registry of per-app compartments, their bound Jobs and relays.

    One application identity maps to one compartment for the service lifetime.
    A compartment that has had a Job bound cannot be deleted, so it is kept and
    reused across restarts of the same app; ``allow`` rebinds the current Job
    and opens a fresh relay, ``revoke`` seals it again by stopping the relay and
    dropping the Job reference, and ``purge`` tears everything down.
    """

    def __init__(self, metadata, api=None, relay_factory=None):
        self.metadata = metadata
        self.owner_sid = metadata["owner_sid"]
        self.lock = threading.RLock()
        self._api = api
        self._relay_factory = relay_factory or _Relay
        self.active: dict[str, dict] = {}

    def api(self):
        if self._api is None:
            self._api = _CompartmentAPI()
        return self._api

    def _seal(self, record):
        """Stop the relay and release the Job; keep the compartment id for reuse."""
        relay = record.get("relay")
        if relay is not None:
            relay.stop()
        job = record.get("job")
        if job:
            self.api().close(job)
        record["relay"] = record["job"] = record["proxy_port"] = None
        record["open"] = False

    def allow(self, name: str, proxy_port: int, job_pid: int, job_handle: int) -> dict:
        _check_name(name)
        port = _check_port(proxy_port)
        if type(job_pid) is not int or not 1 <= job_pid <= 0xFFFFFFFF:
            raise ProxyError("invalid_request", "面板进程标识无效。")
        if type(job_handle) is not int or not 1 <= job_handle <= 0xFFFFFFFFFFFFFFFF:
            raise ProxyError("invalid_request", "Job 句柄无效。")
        with self.lock:
            api = self.api()
            record = self.active.get(name)
            if record is None:
                cid, guid = api.create()
                record = {"cid": cid, "guid": guid, "job": None,
                          "relay": None, "proxy_port": None, "open": False}
                self.active[name] = record
            else:
                # Replace any prior binding and relay before rebinding cleanly.
                self._seal(record)
                cid = record["cid"]
            job = relay = None
            try:
                job = api.bind_job(job_pid, job_handle, cid)
                relay = self._relay_factory(api, cid, port)
                relay.start()
            except BaseException:
                if relay is not None:
                    relay.stop()
                if job is not None:
                    api.close(job)
                raise
            record["job"], record["relay"] = job, relay
            record["proxy_port"], record["open"] = port, True
            return {"container": name, "compartment_id": cid, "proxy_port": port, "active": True}

    def revoke(self, name: str) -> dict:
        _check_name(name)
        with self.lock:
            record = self.active.get(name)
            if record is None or not record.get("open"):
                return {"container": name, "active": False}
            self._seal(record)
            return {"container": name, "active": False}

    def purge(self) -> dict:
        """Recover gates left by this or an earlier launch; never leave a path open."""
        with self.lock:
            purged = sorted(self.active)
            for record in self.active.values():
                self._seal(record)
                cid = record.get("cid")
                if cid is not None:
                    self.api().delete(cid)
            self.active.clear()
            return {"active": False, "purged": purged}


# ---------------------------------------------------------------- panel launch flow

class NamespaceLease:
    """Closes the service gate once the panel no longer owns the app."""

    def __init__(self, backend, name):
        self.backend, self.name = backend, name

    def close(self):
        if self.name:
            self.backend.namespace_revoke(self.name)
            self.name = None


def start_namespaced(backend, ident, command, env, *, proxy_port, launch):
    """Open the gate while the Job is still suspended, then launch confined.

    ``launch`` must accept a ``prepare_job`` callback that it invokes with the
    new Job handle after the Job is created and before the first instruction of
    the application runs. The service duplicates that handle out of this process
    and seals it into the compartment, so the app is contained from its very
    first instruction and can never observe an un-proxied moment.
    """
    name = namespace_name(ident)
    state: dict[str, NamespaceLease] = {}

    def prepare_job(job_handle):
        backend.namespace_allow(name, proxy_port, job_handle)
        state["lease"] = NamespaceLease(backend, name)

    try:
        process = launch(command, env, native_proxy_port=proxy_port, prepare_job=prepare_job)
    except BaseException:
        lease = state.get("lease")
        if lease is not None:
            lease.close()
        else:
            # ``allow`` may have committed just before a later failure in launch.
            backend.namespace_revoke(name)
        raise
    return process, state.get("lease") or NamespaceLease(backend, name)
