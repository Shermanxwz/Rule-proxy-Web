"""Windows strong per-app isolation through TCP/IP network compartments.

This is the Windows counterpart of the Linux network-namespace mode. A network
compartment is a kernel partition of the TCP/IP stack: a compartment created
with no configured interface keeps only its own loopback pseudo-interface and
has no route off the host, so a process bound into it cannot reach the network
at all. Windows enforces that in the kernel, independent of the process token
and of whether Windows Firewall is enabled. Directly created descendants and
nested Jobs inherit it; service-mediated work is a separate boundary.

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

Some compartment creation exports are not a current documented Win32 contract.
Their presence is checked at runtime; the CIM readback and native qualification
are both required. This module does not claim to block every DNS-service API.
"""
from __future__ import annotations

import ctypes as C
from ctypes import wintypes as W
from collections import deque
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import threading
import time
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
        for owner, name, args, result in (
                (self.k, "GetCurrentProcess", [], W.HANDLE),
                (self.k, "OpenProcess", [W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
                (self.k, "DuplicateHandle", [W.HANDLE, W.HANDLE, W.HANDLE, C.POINTER(W.HANDLE),
                                             W.DWORD, W.BOOL, W.DWORD], W.BOOL),
                (self.k, "CloseHandle", [W.HANDLE], W.BOOL),
                (self.k, "QueryInformationJobObject", [W.HANDLE, C.c_int, C.c_void_p,
                                                        W.DWORD, C.c_void_p], W.BOOL),
                (self.i, "GetDefaultCompartmentId", [], C.c_uint32),
                (self.i, "SetCurrentThreadCompartmentId", [C.c_uint32], C.c_uint32),
                (self.i, "GetCurrentThreadCompartmentId", [], C.c_uint32),
                (self.i, "GetJobCompartmentId", [W.HANDLE], C.c_uint32),
                (self.i, "SetJobCompartmentId", [W.HANDLE, C.c_uint32], C.c_uint32),
                (self.i, "InitializeCompartmentEntry", [C.POINTER(_Row)], None),
                (self.i, "CreateCompartment", [C.POINTER(_Row)], C.c_uint32)):
            function = getattr(owner, name)
            function.argtypes, function.restype = args, result
        self.default = int(self.i.GetDefaultCompartmentId())

    def _fail(self, what):
        code = C.get_last_error()
        raise ProxyError("namespace_failed", f"{what}失败：{C.FormatError(code).strip()}（{code}）。")

    def create(self, guid, description):
        """Create the journal-reserved GUID and return its new compartment ID."""
        row = _Row()
        self.i.InitializeCompartmentEntry(C.byref(row))
        row.CompartmentGuid = _GUID.of(uuid.UUID(guid))
        row.Description = description
        code = int(self.i.CreateCompartment(C.byref(row)))
        if code != 0:
            raise ProxyError("namespace_failed", f"创建网络隔间失败（{code}）。")
        return int(row.CompartmentId)

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
        try:
            from .windows_app_process import _JobExtendedLimitInfo, _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            limits = _JobExtendedLimitInfo()
            # No running process may retain sockets created before the binding.
            # Retaining a non-breakaway, kill-on-close Job is also necessary for
            # crash cleanup when either the panel or the broker disappears.
            if not self.k.QueryInformationJobObject(duplicate, 9, C.byref(limits), C.sizeof(limits), None):
                self._fail("核对隔离 Job 限制")
            flags = limits.BasicLimitInformation.LimitFlags
            if not flags & _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE or flags & (0x800 | 0x1000):
                raise ProxyError("namespace_failed", "隔离 Job 未设置关闭退出或允许脱离。")
            if self._active_processes(duplicate):
                raise ProxyError("namespace_failed", "隔离 Job 必须在创建应用进程前绑定。")
            code = int(self.i.SetJobCompartmentId(duplicate, C.c_uint32(cid)))
            if code != 0 or int(self.i.GetJobCompartmentId(duplicate)) != cid:
                raise ProxyError("namespace_failed", f"绑定 Job 到网络隔间失败（{code}）。")
        except BaseException:
            self.k.CloseHandle(duplicate)
            raise
        return duplicate.value

    def close(self, handle):
        if handle:
            if not self.k.CloseHandle(W.HANDLE(handle)):
                self._fail("关闭 Job 句柄")

    def _active_processes(self, handle):
        class Accounting(C.Structure):
            _fields_ = [(name, C.c_int64) for name in ("user", "kernel", "period_user", "period_kernel")]
            _fields_ += [(name, C.c_uint32) for name in ("faults", "total", "active", "terminated")]
        accounting = Accounting()
        if not self.k.QueryInformationJobObject(handle, 1, C.byref(accounting), C.sizeof(accounting), None):
            self._fail("核对隔间内进程")
        return accounting.active

    def terminate_job(self, handle):
        terminate = self.k.TerminateJobObject
        terminate.argtypes, terminate.restype = [W.HANDLE, W.UINT], W.BOOL
        if not terminate(W.HANDLE(handle), 1):
            self._fail("停止隔间内进程")
        deadline = time.monotonic() + 5
        while True:
            if self._active_processes(W.HANDLE(handle)) == 0:
                return
            if time.monotonic() >= deadline:
                raise ProxyError("cleanup_incomplete", "隔间内仍有进程，未允许复用。")
            time.sleep(0.02)

    def inspect(self, cid=None):
        """Read the documented NetTCPIP CIM provider, never guess private enum APIs."""
        command = "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new();"
        command += "$c=@(Get-NetCompartment | Select-Object CompartmentId,CompartmentGuid,CompartmentDescription);"
        if cid is None:
            command += "ConvertTo-Json -InputObject $c -Compress -Depth 4"
        else:
            if type(cid) is not int or cid <= 1:
                raise ProxyError("namespace_conflict", "隔间编号无效。")
            command += (
                f"$id={cid};"
                "$rawi=@(Get-NetIPInterface -IncludeAllCompartments | Where-Object CompartmentId -eq $id);"
                "$i=@($rawi | Select-Object InterfaceIndex);"
                # MSFT_NetIPAddress has no documented CompartmentId property;
                # associate exact CIM interfaces instead of filtering a null.
                "$a=@($rawi | ForEach-Object {Get-NetIPAddress -AssociatedIPInterface $_ -IncludeAllCompartments} | Select-Object InterfaceIndex,IPAddress);"
                "$r=@($rawi | ForEach-Object {Get-NetRoute -AssociatedIPInterface $_ -IncludeAllCompartments} | Select-Object DestinationPrefix,NextHop);"
                "@{compartments=$c;interfaces=$i;addresses=$a;routes=$r}|ConvertTo-Json -Compress -Depth 5")
        system = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "WindowsPowerShell" / "v1.0"
        env = dict(os.environ, PSModulePath=str(system / "Modules"))
        try:
            result = subprocess.run([str(system / "powershell.exe"), "-NoProfile", "-NonInteractive",
                                     "-EncodedCommand", base64.b64encode(command.encode("utf-16-le")).decode("ascii")],
                                    capture_output=True, timeout=15, env=env,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode or len(result.stdout) > 2_000_000:
                raise ValueError("NetTCPIP inspection failed")
            return json.loads(result.stdout.decode("utf-8-sig"))
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            raise ProxyError("namespace_unsupported", "无法读取 Windows 网络隔间状态，未启动隔离应用。") from exc


class _Relay:
    """The one sealed path out of a compartment.

    The listener thread switches itself into the compartment and binds the
    proxy port on both loopback families there. Each accepted connection is
    pumped by a worker thread that switches into the default compartment and
    dials the engine on the same port, so the app's loopback proxy endpoint is
    unchanged by containment. Stopping closes every socket and ends the loop.
    """

    MAX_CONNECTIONS = 64
    BUFFER_LIMIT = 262144
    _global_slots = threading.BoundedSemaphore(256)

    def __init__(self, api, cid, proxy_port, upstream_port=None, *, expected_core_pid,
                 core_alive, peer_verifier=None):
        if type(expected_core_pid) is not int or not 1 <= expected_core_pid <= 0xFFFFFFFF or not callable(core_alive):
            raise ProxyError("invalid_process", "代理中继必须绑定持有的 Mihomo 进程。")
        self.api, self.cid, self.proxy_port = api, cid, proxy_port
        self.expected_core_pid, self.core_alive = expected_core_pid, core_alive
        self._peer_verifier = peer_verifier or self._peer_owned
        # The engine listens on the same port number in the default compartment;
        # tests point the upstream at a distinct port on single-compartment hosts.
        self.upstream_port = upstream_port if upstream_port is not None else proxy_port
        self.listeners: list[socket.socket] = []
        self.connections: set[socket.socket] = set()
        self.bound: list[str] = []
        self.errors = deque(maxlen=32)
        self.accepted = 0
        self.stopping = threading.Event()
        self.ready = threading.Event()
        self._lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._listener = None

    def start(self):
        with self._lock:
            if self._listener is not None or self.stopping.is_set():
                raise ProxyError("namespace_failed", "代理中继不能重复启动。")
            self._listener = threading.Thread(target=self._listen, name="ruleproxy-ns-listen", daemon=True)
            try:
                self._listener.start()
            except BaseException:
                # An unstarted Thread cannot be joined. Retain a sealed relay
                # that NamespaceGate can stop again while unwinding the Job.
                self._listener = None
                self.stopping.set()
                raise
        if not self.ready.wait(10) or not self.bound or self.stopping.is_set():
            self.stop()
            raise ProxyError("namespace_failed", "网络隔间内未能建立代理监听。")
        return list(self.bound)

    def _track(self, sock):
        with self._lock:
            if self.stopping.is_set():
                sock.close()
                return False
            self.connections.add(sock)
            return True

    def _switch(self, cid):
        code = int(self.api.i.SetCurrentThreadCompartmentId(C.c_uint32(cid)))
        if code or int(self.api.i.GetCurrentThreadCompartmentId()) != cid:
            raise OSError(f"thread compartment switch failed ({code})")

    def _pump(self, first, second):
        """Bounded full-duplex copy: an EOF closes only the opposite write side."""
        peers = {first: second, second: first}
        pending = {first: bytearray(), second: bytearray()}
        reading = set(peers)
        write_closed = set()
        for sock in peers:
            sock.setblocking(False)
        while not self.stopping.is_set():
            for destination, source in peers.items():
                if source not in reading and not pending[destination] and destination not in write_closed:
                    destination.shutdown(socket.SHUT_WR)
                    write_closed.add(destination)
            if not reading and not any(pending.values()):
                return
            readers = [sock for sock in reading if len(pending[peers[sock]]) < self.BUFFER_LIMIT]
            writers = [sock for sock, data in pending.items() if data]
            ready_read, ready_write, _ = select.select(readers, writers, [], 0.25)
            for sock in ready_read:
                try:
                    data = sock.recv(min(65536, self.BUFFER_LIMIT - len(pending[peers[sock]])))
                except BlockingIOError:
                    continue
                if data:
                    pending[peers[sock]].extend(data)
                else:
                    reading.remove(sock)
            for sock in ready_write:
                try:
                    sent = sock.send(pending[sock])
                except BlockingIOError:
                    continue
                if sent == 0:
                    raise OSError("proxy connection closed while writing")
                del pending[sock][:sent]

    @staticmethod
    def _peer_owned(upstream, expected_pid):
        from .windows_proxy_service import _tcp_connections
        local, remote = upstream.getsockname(), upstream.getpeername()
        return any(row["state"] == 5 and row["pid"] == expected_pid
                   and row["local"] == remote[0] and row["local_port"] == remote[1]
                   and row["remote"] == local[0] and row["remote_port"] == local[1]
                   for row in _tcp_connections(socket.AF_INET))

    def _forward(self, accepted):
        upstream = None
        try:
            self._switch(self.api.default)
            upstream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if not self._track(upstream):
                return
            upstream.settimeout(5)
            upstream.connect(("127.0.0.1", self.upstream_port))
            # Authenticate the established peer before reading or forwarding
            # proxy bytes. A LISTEN check before connect would permit a port
            # replacement race after the held Mihomo process exits.
            if (not self.core_alive()
                    or self._peer_verifier(upstream, self.expected_core_pid) is not True
                    or not self.core_alive()):
                raise ProxyError("invalid_proxy_owner", "代理连接不属于持有的 Mihomo 进程，未转发数据。")
            self._pump(accepted, upstream)
        except Exception as exc:
            if not self.stopping.is_set():
                self.errors.append(str(exc)[:160])
        finally:
            for sock in (accepted, upstream):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            with self._lock:
                self.connections.discard(accepted)
                self.connections.discard(upstream)
                self._workers.discard(threading.current_thread())
            self._global_slots.release()

    def _listen(self):
        try:
            self._switch(self.cid)
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                sock = socket.socket(family, socket.SOCK_STREAM)
                try:
                    if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                    if family == socket.AF_INET6:
                        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    sock.bind((host, self.proxy_port))
                    sock.listen(64)
                    sock.setblocking(False)
                    with self._lock:
                        if self.stopping.is_set():
                            sock.close()
                            return
                        self.listeners.append(sock)
                        self.bound.append(host)
                except OSError as exc:
                    self.errors.append(f"{host}: {exc}"[:160])
                    sock.close()
            if "127.0.0.1" not in self.bound:
                raise OSError("IPv4 proxy listener is unavailable")
        except (OSError, ValueError) as exc:
            self.errors.append(str(exc)[:160])
            self.stopping.set()
        finally:
            self.ready.set()
        try:
            while not self.stopping.is_set():
                with self._lock:
                    listeners = list(self.listeners)
                try:
                    ready, _, _ = select.select(listeners, [], [], 0.25)
                except (OSError, ValueError):
                    break
                for sock in ready:
                    try:
                        accepted, _ = sock.accept()
                    except OSError:
                        continue
                    with self._lock:
                        if (self.stopping.is_set() or len(self._workers) >= self.MAX_CONNECTIONS
                                or not self._global_slots.acquire(blocking=False)):
                            accepted.close()
                            continue
                        self.accepted += 1
                        self.connections.add(accepted)
                        worker = threading.Thread(target=self._forward, args=(accepted,),
                                                  name="ruleproxy-ns-forward", daemon=True)
                        self._workers.add(worker)
                        try:
                            worker.start()
                        except RuntimeError:
                            self._global_slots.release()
                            self._workers.discard(worker)
                            self.connections.discard(accepted)
                            accepted.close()
        finally:
            # Unexpected listener failure must also close established forwarding.
            self.stopping.set()
            self._close_sockets()

    def _close_sockets(self):
        with self._lock:
            socks = [*self.listeners, *self.connections]
            self.listeners = []
        for sock in socks:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def stop(self):
        self.stopping.set()
        self._close_sockets()
        deadline = time.monotonic() + 7
        with self._lock:
            threads = [self._listener, *self._workers]
        for thread in threads:
            if thread is not None and thread is not threading.current_thread():
                thread.join(max(0, deadline - time.monotonic()))
        with self._lock:
            if any(thread is not None and thread.is_alive() for thread in threads):
                raise ProxyError("cleanup_incomplete", "网络中继尚未停止，未重新开放隔间。")
            self.connections.clear()


def _boot_identity():
    """A volatile SCM subkey survives service restarts, but not a kernel reboot."""
    import winreg
    advapi = C.WinDLL("advapi32", use_last_error=True)
    create = advapi.RegCreateKeyExW
    create.argtypes = [W.HANDLE, W.LPCWSTR, W.DWORD, W.LPWSTR, W.DWORD,
                       W.DWORD, C.c_void_p, C.POINTER(W.HANDLE), C.POINTER(W.DWORD)]
    create.restype = C.c_int32
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\RuleProxyControl", 0,
                            winreg.KEY_CREATE_SUB_KEY | winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as parent:
            handle, disposition = W.HANDLE(), W.DWORD()
            code = create(int(parent), "CompartmentBoot", 0, None, 1,  # REG_OPTION_VOLATILE
                          winreg.KEY_READ | winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY,
                          None, C.byref(handle), C.byref(disposition))
            if code:
                raise OSError(code, "Cannot create volatile compartment boot key")
            with winreg.HKEYType(handle.value) as key:
                try:
                    value, kind = winreg.QueryValueEx(key, "BootId")
                except FileNotFoundError:
                    value, kind = str(uuid.uuid4()), winreg.REG_SZ
                    winreg.SetValueEx(key, "BootId", 0, kind, value)
                if kind != winreg.REG_SZ or str(uuid.UUID(value)) != value:
                    raise ValueError("Invalid boot identity")
                return value
    except (OSError, ValueError) as exc:
        raise ProxyError("namespace_unsupported", "无法确认本次 Windows 启动身份，未复用网络隔间。") from exc


class NamespaceGate:
    """Persist sealed compartments; a crashed, unconfirmed Job is quarantined.

    A bound compartment is never deleted: some Windows builds return 1359 and
    may leave the object unusable. The protected journal limits allocations to
    128 per boot, retains identities across service restarts and never reopens
    a compartment whose previous Job termination could not be confirmed.
    """

    MAX_COMPARTMENTS = 128

    def __init__(self, metadata, api=None, relay_factory=None, *, boot_id=None):
        self.metadata = metadata
        self.owner_sid = metadata["owner_sid"]
        self.lock = threading.RLock()
        self._api = api
        self._relay_factory = relay_factory or _Relay
        self.active: dict[str, dict] = {}
        self._boot_id = boot_id
        self._loaded = False
        identity = self.owner_sid + "\0" + str(metadata["root"]).replace("/", "\\").casefold()
        self.identity = hashlib.sha256(identity.encode()).hexdigest()[:24]
        self.marker = "RuleProxyNS:" + self.identity + ":"
        directory = metadata.get("namespace_state_dir")
        self.path = Path(directory) / "compartments.json" if isinstance(directory, str) and directory else None

    def api(self):
        if self._api is None:
            try:
                self._api = _CompartmentAPI()
            except (OSError, AttributeError) as exc:
                raise ProxyError("namespace_unsupported", "本系统缺少所需网络隔间接口，未启动隔离应用。") from exc
        return self._api

    def _check_store(self):
        if type(self.metadata.get("namespace_backend_version")) is not int or self.metadata["namespace_backend_version"] != 1 or self.path is None:
            raise ProxyError("setup_required", "请重新运行 Setup-Windows.cmd 安装网络隔间组件。")
        for path in (self.path.parent, self.path):
            if path == self.path and not path.exists() and not path.is_symlink():
                continue
            try:
                if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
                    raise OSError("reparse point")
            except OSError as exc:
                raise ProxyError("unsafe_installation", "网络隔间状态目录无效，请修复安装。") from exc
            if os.name == "nt":
                from .windows_proxy_service import protected_path
                protected_path(path, private=True)

    def _save(self):
        self._check_store()
        data = {"version": 1, "identity": self.identity, "boot_id": self._boot_id,
                "compartments": {name: {key: record[key] for key in ("cid", "guid", "phase")}
                                 for name, record in self.active.items()}}
        raw = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
        temporary = self.path.with_name(".compartments-" + uuid.uuid4().hex + ".tmp")
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            raise ProxyError("namespace_failed", "无法保存隔间恢复记录，未开放网络。") from exc
        finally:
            temporary.unlink(missing_ok=True)

    def _inventory(self):
        rows = self.api().inspect()
        if not isinstance(rows, list) or len(rows) > 4096:
            raise ProxyError("namespace_conflict", "系统隔间清单无效。")
        found = {}
        try:
            for row in rows:
                guid = str(uuid.UUID(row["CompartmentGuid"]))
                cid = row["CompartmentId"]
                if type(cid) is not int or not 1 <= cid <= 0xFFFFFFFF or guid in found:
                    raise ValueError("invalid or duplicate compartment")
                found[guid] = (cid, row["CompartmentDescription"])
        except (ValueError, TypeError, KeyError) as exc:
            raise ProxyError("namespace_conflict", "无法核对系统隔间身份。") from exc
        return found

    def _load(self):
        if self._loaded:
            return
        self._check_store()
        self._boot_id = self._boot_id or _boot_identity()
        inventory = self._inventory()
        raw = None
        if self.path.exists():
            try:
                if self.path.stat().st_size > 131072:
                    raise ValueError("journal too large")
                raw = json.loads(self.path.read_text(encoding="ascii"))
                if (not isinstance(raw, dict) or set(raw) != {"version", "identity", "boot_id", "compartments"}
                        or raw["version"] != 1 or raw["identity"] != self.identity
                        or not isinstance(raw["compartments"], dict)
                        or len(raw["compartments"]) > self.MAX_COMPARTMENTS):
                    raise ValueError("invalid journal")
                uuid.UUID(raw["boot_id"])
                for name, record in raw["compartments"].items():
                    _check_name(name)
                    if not isinstance(record, dict) or set(record) != {"cid", "guid", "phase"}:
                        raise ValueError("invalid record")
                    if str(uuid.UUID(record["guid"])) != record["guid"]:
                        raise ValueError("invalid GUID")
                    if (record["phase"] not in {"creating", "clean", "dirty"}
                            or (record["cid"] is None and record["phase"] != "creating")
                            or (record["cid"] is not None and (type(record["cid"]) is not int or not 2 <= record["cid"] <= 0xFFFFFFFF))):
                        raise ValueError("invalid state")
            except (OSError, ValueError, TypeError, KeyError) as exc:
                raise ProxyError("namespace_conflict", "隔间恢复记录损坏，未创建或接管隔间。") from exc
        if raw and raw["boot_id"] != self._boot_id:
            if any(record["guid"] in inventory for record in raw["compartments"].values()):
                raise ProxyError("namespace_conflict", "启动身份已改变但旧隔间仍存在，需重启 Windows 后重试。")
            raw = None
        records = raw["compartments"] if raw else {}
        known = {record["guid"] for record in records.values()}
        if any(isinstance(description, str) and description.startswith(self.marker) and guid not in known
               for guid, (_, description) in inventory.items()):
            raise ProxyError("namespace_conflict", "存在无恢复记录的自有隔间，需重启 Windows 后重试。")
        restored = {}
        for name, saved in records.items():
            record = dict(saved)
            actual = inventory.get(record["guid"])
            if actual is None:
                if record["phase"] != "creating":
                    raise ProxyError("namespace_conflict", "本次启动中的自有隔间已消失，未重新分配编号。")
            elif actual != (record["cid"], self.marker + name.split(".")[1]):
                if record["phase"] != "creating" or actual[1] != self.marker + name.split(".")[1]:
                    raise ProxyError("namespace_conflict", "网络隔间归属或编号不匹配。")
                record["cid"], record["phase"] = actual[0], "clean"
            record.update(job=None, relay=None, proxy_port=None, open=False)
            restored[name] = record
        self.active = restored
        self._loaded = True

    def _verify(self, name, record):
        observation = self.api().inspect(record["cid"])
        try:
            matching = [row for row in observation["compartments"] if row["CompartmentId"] == record["cid"]]
            if (len(matching) != 1 or str(uuid.UUID(matching[0]["CompartmentGuid"])) != record["guid"]
                    or matching[0]["CompartmentDescription"] != self.marker + name.split(".")[1]):
                raise ValueError("compartment identity changed")
            loopback_indexes = set()
            for address in observation["addresses"]:
                if not ipaddress.ip_address(address["IPAddress"]).is_loopback:
                    raise ValueError("non-loopback address")
                loopback_indexes.add(address["InterfaceIndex"])
            if any(row["InterfaceIndex"] not in loopback_indexes for row in observation["interfaces"]):
                raise ValueError("non-loopback interface")
            for route in observation["routes"]:
                prefix = ipaddress.ip_network(route["DestinationPrefix"])
                address = prefix.network_address
                if (prefix.prefixlen == 0 or not (address.is_loopback or address.is_multicast
                                                  or str(prefix) == "255.255.255.255/32")
                        or not ipaddress.ip_address(route["NextHop"]).is_unspecified):
                    raise ValueError("external route")
        except (KeyError, ValueError, TypeError) as exc:
            raise ProxyError("namespace_conflict", "隔间身份或网络状态不符合独立回环要求，未开放网络。") from exc

    def _seal(self, record):
        """Stop the relay and release the Job; keep the compartment id for reuse."""
        errors = []
        record["open"] = False
        relay = record.get("relay")
        if relay is not None:
            try:
                relay.stop()
            except Exception as exc:
                errors.append(exc)
        job = record.get("job")
        if job:
            try:
                self.api().terminate_job(job)
            except Exception as exc:
                errors.append(exc)
        if errors:
            # Retain both ownership handles for a later cleanup attempt; never
            # mark clean or open another relay when either stop is unconfirmed.
            raise errors[0]
        if job:
            self.api().close(job)
        record["relay"] = record["job"] = record["proxy_port"] = None
        record["open"] = False
        if job:
            record["phase"] = "clean"
            try:
                self._save()
            except BaseException:
                record["phase"] = "dirty"
                raise

    def allow(self, name: str, proxy_port: int, job_pid: int, job_handle: int, *,
              core_pid: int, core_alive) -> dict:
        _check_name(name)
        port = _check_port(proxy_port)
        if type(job_pid) is not int or not 1 <= job_pid <= 0xFFFFFFFF:
            raise ProxyError("invalid_request", "面板进程标识无效。")
        if type(job_handle) is not int or not 1 <= job_handle <= 0xFFFFFFFFFFFFFFFF:
            raise ProxyError("invalid_request", "Job 句柄无效。")
        if type(core_pid) is not int or not 1 <= core_pid <= 0xFFFFFFFF or not callable(core_alive) or not core_alive():
            raise ProxyError("invalid_process", "网络隔间必须使用持有的 Mihomo 进程。")
        with self.lock:
            self._load()
            api = self.api()
            record = self.active.get(name)
            if record is None:
                if len(self.active) >= self.MAX_COMPARTMENTS:
                    raise ProxyError("namespace_quota", "本次 Windows 启动的隔间数已达上限，请重启 Windows 后重试。")
                record = {"cid": None, "guid": str(uuid.uuid4()), "phase": "creating", "job": None,
                          "relay": None, "proxy_port": None, "open": False}
                self.active[name] = record
                self._save()  # Reserve a GUID before any OS allocation.
            else:
                # Replace any prior binding and relay before rebinding cleanly.
                self._seal(record)
            if record["phase"] == "dirty":
                raise ProxyError("namespace_reboot_required", "上次隔离进程未能确认退出，已封闭该隔间；请重启 Windows 后重试。")
            if record["phase"] == "creating":
                self._save()
                record["cid"] = api.create(record["guid"], self.marker + name.split(".")[1])
                record["phase"] = "clean"
                self._save()
            cid = record["cid"]
            self._verify(name, record)
            record["phase"] = "dirty"
            self._save()  # Crash after this point must never silently reopen it.
            job = relay = None
            try:
                job = api.bind_job(job_pid, job_handle, cid)
                record["job"] = job
                relay = self._relay_factory(api, cid, port, expected_core_pid=core_pid, core_alive=core_alive)
                record["relay"] = relay
                relay.start()
            except BaseException:
                self._seal(record)
                raise
            record["job"], record["relay"] = job, relay
            record["proxy_port"], record["open"] = port, True
            return {"container": name, "compartment_id": cid, "proxy_port": port, "active": True}

    def revoke(self, name: str) -> dict:
        _check_name(name)
        with self.lock:
            self._load()
            record = self.active.get(name)
            if record is None:
                return {"container": name, "active": False}
            self._seal(record)
            return {"container": name, "active": False}

    def purge(self) -> dict:
        """Recover gates left by this or an earlier launch; never leave a path open."""
        with self.lock:
            if not self._loaded and (self.path is None or not self.path.exists()):
                return {"active": False, "purged": []}
            self._load()
            purged = sorted(self.active)
            errors = []
            for record in self.active.values():
                try:
                    self._seal(record)
                except Exception as exc:
                    errors.append(exc)
            if errors:
                raise ProxyError("cleanup_incomplete", "部分隔间仍待确认清理；所有中继均已请求停止。") from errors[0]
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
