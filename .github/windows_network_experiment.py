"""Collect fixed MXC policy experiments; never switch the product's provider.

CLI: package-python windows_network_experiment.py --root PACKAGE --report FILE
     [--allow-emulated-x64]
Exit 0 means bounded experimental observations were collected, including
unsupported policies and failed socket checks. Exit 1 means the experiment or
safe teardown failed. No real node, global network setting or firewall rule is
created. Only test nonce bytes traverse a fixed loopback source/sink.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from ctypes import wintypes
import importlib.util
import json
import os
import ntpath
import re
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
MODEL1_VARIANTS = ("model1_internal_ingress_deny", "model1_internal")
VARIANTS = ("model3", *MODEL1_VARIANTS, "model2_host")
MAX_REPORT_BYTES = 128 * 1024
ACTOR_WAIT_SECONDS = 45
MATRIX_PHASE_SECONDS = 440  # Leaves 120s for the final native CIM snapshot.
DESTINATION = b"ruleproxy-experiment.invalid"
UDP_CONTROL = b"RuleProxy fixed UDP observer control"


def write_json(path, value, *, limit=MAX_REPORT_BYTES):
    raw = json.dumps(value, ensure_ascii=True, indent=2).encode("ascii")
    if len(raw) > limit:
        raise RuntimeError("Experiment record exceeded its size limit")
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(raw)
    os.replace(temporary, path)


def read_json(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if len(raw) > MAX_REPORT_BYTES:
        raise RuntimeError("Experiment record exceeded its size limit")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("Experiment record must be an object")
    return value


def payload(token):
    if not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token):
        raise ValueError("Invalid fixture nonce")
    return token.encode("ascii") * 1024 + b"END"


def exact(connection, count):
    result = bytearray()
    deadline = time.monotonic() + 4
    while len(result) < count:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Fixed fixture read timed out")
        connection.settimeout(remaining)
        part = connection.recv(count - len(result))
        if not part:
            raise RuntimeError("Fixed fixture ended early")
        result.extend(part)
    return bytes(result)


class FixedProxy:
    """HTTP CONNECT / SOCKS to one fixed name, never a destination connector."""

    def __init__(self):
        self.token = secrets.token_hex(32)
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(8)
        self.socket.settimeout(0.1)
        self.port = self.socket.getsockname()[1]
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = set()
        self.roundtrips = 0
        self.errors = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections.add(connection)
                worker = threading.Thread(target=self.handle, args=(connection,), daemon=True)
                self.workers.add(worker)
            worker.start()

    def handle(self, connection):
        try:
            with connection:
                connection.settimeout(4)
                first = connection.recv(1)
                if not first:
                    return
                if first == b"\x05":
                    if exact(connection, 2) != b"\x01\x00":
                        raise RuntimeError("Fixture rejected SOCKS greeting")
                    connection.sendall(b"\x05\x00")
                    # The product's startup method-negotiation probe ends here.
                    first = connection.recv(1)
                    if not first:
                        return
                    request = first + exact(connection, 4)
                    if request != bytes((5, 1, 0, 3, len(DESTINATION))):
                        raise RuntimeError("Fixture rejected SOCKS destination type")
                    if exact(connection, len(DESTINATION) + 2) != DESTINATION + b"\x01\xbb":
                        raise RuntimeError("Fixture rejected unrelated destination")
                    connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
                else:
                    header = bytearray(first)
                    deadline = time.monotonic() + 4
                    while not header.endswith(b"\r\n\r\n"):
                        if len(header) >= 4096 or time.monotonic() >= deadline:
                            raise RuntimeError("Fixture rejected HTTP header")
                        header.extend(exact(connection, 1))
                    expected = b"CONNECT " + DESTINATION + b":443 HTTP/1.1"
                    if header.split(b"\r\n", 1)[0] != expected:
                        raise RuntimeError("Fixture rejected HTTP destination")
                    connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                expected = payload(self.token)
                if exact(connection, len(expected)) != expected or connection.recv(1):
                    raise RuntimeError("Fixture payload or FIN was invalid")
                connection.sendall(expected[::-1])
                connection.shutdown(socket.SHUT_WR)
                with self.lock:
                    self.roundtrips += 1
        except (OSError, RuntimeError, TimeoutError) as exc:
            if not self.closed.is_set():
                with self.lock:
                    self.errors.append(type(exc).__name__)
        finally:
            with self.lock:
                self.connections.discard(connection)
                self.workers.discard(threading.current_thread())

    def close(self):
        self.closed.set()
        self.socket.close()
        # An accept that already returned may still be registering its worker.
        # Stop the acceptor before taking the final owned-connection snapshot.
        self.thread.join(1)
        with self.lock:
            connections, workers = tuple(self.connections), tuple(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for worker in workers:
            worker.join(1)
        if self.thread.is_alive() or any(worker.is_alive() for worker in workers):
            raise RuntimeError("Fixed proxy workers remained alive after socket closure")


class DatagramObservers:
    """Receive only local test datagrams; a successful send is not deny proof."""

    def __init__(self):
        self.sockets, self.threads, self.received = [], [], [0, 0]
        self.positive_controls = []
        self.control_received = [threading.Event(), threading.Event()]
        self.closed = threading.Event()
        try:
            for index, (family, host) in enumerate(((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))):
                sock = socket.socket(family, socket.SOCK_DGRAM)
                self.sockets.append(sock)
                sock.bind((host, 0))
                sock.settimeout(0.1)
                thread = threading.Thread(target=self.observe, args=(index, sock), daemon=True)
                self.threads.append(thread)
                thread.start()
                with socket.socket(family, socket.SOCK_DGRAM) as sender:
                    sender.sendto(UDP_CONTROL, sock.getsockname())
                if not self.control_received[index].wait(2):
                    raise RuntimeError("Ordinary host could not reach its UDP observer")
                self.positive_controls.append({"family": "ipv4" if index == 0 else "ipv6", "received": True})
        except BaseException:
            self.close()
            raise

    def observe(self, index, sock):
        while not self.closed.is_set():
            try:
                data, _ = sock.recvfrom(1024)
            except socket.timeout:
                continue
            except OSError:
                return
            if data:
                self.received[index] += 1
                if data == UDP_CONTROL:
                    self.control_received[index].set()

    def close(self):
        self.closed.set()
        for sock in self.sockets:
            sock.close()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(1)
        if any(thread.is_alive() for thread in self.threads):
            raise RuntimeError("UDP observer thread remained alive after socket closure")


def proxy_roundtrip(port, token, protocol):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
        connection.settimeout(4)
        if protocol == "socks":
            connection.sendall(b"\x05\x01\x00")
            if exact(connection, 2) != b"\x05\x00":
                raise RuntimeError("Invalid SOCKS method")
            connection.sendall(bytes((5, 1, 0, 3, len(DESTINATION))) + DESTINATION + b"\x01\xbb")
            if exact(connection, 10) != b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00":
                raise RuntimeError("Invalid SOCKS fixture response")
        elif protocol == "http":
            connection.sendall(b"CONNECT " + DESTINATION + b":443 HTTP/1.1\r\nHost: " + DESTINATION + b":443\r\n\r\n")
            reply = bytearray()
            while not reply.endswith(b"\r\n\r\n"):
                if len(reply) >= 4096:
                    raise RuntimeError("Oversized fixture response")
                reply.extend(exact(connection, 1))
            if not reply.startswith(b"HTTP/1.1 200 "):
                raise RuntimeError("Invalid HTTP fixture response")
        else:
            raise ValueError("Unknown fixture protocol")
        expected = payload(token)
        connection.sendall(expected)
        connection.shutdown(socket.SHUT_WR)
        if exact(connection, len(expected)) != expected[::-1] or connection.recv(1):
            raise RuntimeError("Fixture reverse payload or FIN was invalid")


def network_policy(name, internal_port, proxy_port):
    if name not in VARIANTS or any(type(port) is not int or not 1 <= port <= 65535 for port in (internal_port, proxy_port)):
        raise ValueError("Invalid fixed policy variant or port")
    value = {"network": {"egress": {"default": "deny"},
                         "ingress": {"default": "deny", "hostLoopback": "deny"}}}
    if name in MODEL1_VARIANTS:
        value["network"]["ingress"]["default"] = "allow" if name == "model1_internal" else "deny"
        value["network"]["egress"]["allow"] = [{"to": [{"cidr": "127.0.0.1/32"}],
                                                    "ports": [{"protocol": "tcp", "port": internal_port}]}]
    elif name == "model2_host":
        value["network"]["ingress"] = {"default": "allow", "hostLoopback": "allow"}
        value["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{proxy_port}"}
    return value


def load_helpers():
    path = ROOT / "scripts/windows-acceptance.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_network_experiment_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def import_project(root):
    sys.path.insert(0, str(root))
    from ruleproxy import windows_runtime, windows_guest, file_bridge
    if Path(sys.modules["ruleproxy"].__file__).resolve().parent.parent != root:
        raise RuntimeError("Experiment imported product code from outside --root")
    return windows_runtime, windows_guest, file_bridge


def collect_actor_checks(config, role):
    runtime, guest, _ = import_project(Path(config["root"]))
    port = config["endpoint_port"]
    record = guest._run_network_probes(role, port, config["host_tcp_ports"][0])
    record.update(parent_pid=os.getppid(), phase="initial")
    api = runtime._WinProcessApi()
    api.kernel32.GetCurrentProcess.argtypes = []
    api.kernel32.GetCurrentProcess.restype = runtime.wintypes.HANDLE
    record["process_created"] = api.process_creation_time(
        runtime._raw_handle(api.kernel32.GetCurrentProcess()))
    for protocol in ("http", "socks"):
        record["checks"]["proxy_" + protocol] = guest._probe(
            lambda protocol=protocol: proxy_roundtrip(port, config["token"], protocol))
    record["checks"]["own_loopback_ipv6"] = guest._probe(lambda: guest._same_process_loopback(socket.AF_INET6))
    record["checks"]["host_loopback_ipv6"] = guest._probe(
        lambda: guest._socket_attempt(socket.AF_INET6, socket.SOCK_STREAM,
                                      ("::1", config["host_tcp_ports"][1], 0, 0)), deny=True)
    for index, (family, host) in enumerate(((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))):
        record["checks"][f"host_udp_ipv{4 if index == 0 else 6}"] = guest._probe(
            lambda family=family, host=host, index=index: guest._socket_attempt(
                family, socket.SOCK_DGRAM, (host, config["host_udp_ports"][index])), deny=True)
    return record


def actor(config_path, role):
    config = read_json(config_path)
    profile = config_path.parent
    _, guest, bridge_module = import_project(Path(config["root"]))
    stop = threading.Event()
    bridge_thread = child = None
    try:
        bridge_start_error = None
        if role == "parent":
            if config["variant"] != "model2_host":
                bridge_thread = threading.Thread(target=bridge_module.run_guest_bridge,
                    args=(config["endpoint_port"], config["bridge_directory"], config["bridge_nonce"], stop), daemon=True)
                bridge_thread.start()
                ready = Path(config["bridge_directory"]) / "bridge-ready.json"
                deadline = time.monotonic() + 8
                while not ready.is_file():
                    if not bridge_thread.is_alive() or time.monotonic() >= deadline:
                        bridge_start_error = "Experimental contained relay did not initialize"
                        break
                    time.sleep(0.05)
                if ready.is_file():
                    marker = read_json(ready)
                    if marker.get("ready") is not True or marker.get("nonce") != config["bridge_nonce"]:
                        bridge_start_error = "Experimental contained relay returned invalid ready evidence"
            child = subprocess.Popen([sys.executable, "-I", "-S", "-X", "utf8", __file__, "--actor",
                                      str(config_path), "--role", "child"], stdin=subprocess.DEVNULL)
        record = collect_actor_checks(config, role)
        if bridge_start_error:
            record["relay_start_error"] = bridge_start_error
        if role == "parent" and config["variant"] == "model3":
            try:
                ipc = subprocess.run([sys.executable, "-I", "-S", "-X", "utf8", config["pipe_script"]],
                    stdin=subprocess.DEVNULL, capture_output=True, timeout=20, encoding="utf-8", errors="replace")
                if len(ipc.stdout.encode("utf-8")) > 16 * 1024:
                    raise RuntimeError("IPC experiment returned oversized output")
                record["ipc"] = json.loads(ipc.stdout)
                record["ipc_exit_code"] = ipc.returncode
            except Exception as exc:
                record["ipc"] = {"status": "failed", "ipc_passed": False, "error": type(exc).__name__}
        write_json(profile / f"actor-{role}-initial.json", record)
        deadline = time.monotonic() + 85
        replaced = False
        while time.monotonic() < deadline:
            try:
                control = read_json(profile / "actor-control.json")
            except FileNotFoundError:
                control = {}
            if control.get("state") == "stop_bridge" and role == "parent" and bridge_thread is not None:
                stop.set()
                bridge_thread.join(5)
                write_json(profile / "bridge-stopped.json", {"stopped": not bridge_thread.is_alive()})
            if control.get("state") == "host_replaced" and not replaced:
                check = guest._probe(lambda: guest._socket_attempt(socket.AF_INET, socket.SOCK_STREAM,
                                     ("127.0.0.1", config["endpoint_port"])), deny=True)
                write_json(profile / f"actor-{role}-replacement.json", {"scope": role, "phase": "replacement",
                           "pid": os.getpid(), "parent_pid": os.getppid(), "checks": {"host_same_port": check}})
                replaced = True
            time.sleep(0.05)
        return 0
    finally:
        stop.set()
        if bridge_thread is not None:
            bridge_thread.join(5)
        # Normal SDK/PSEC job teardown owns the remaining child. The host
        # retains its process HANDLE and uses the production safe guardian.


def wait_actor_reports(profile, wrapper, phase, *, timeout=ACTOR_WAIT_SECONDS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        records = []
        for role in ("parent", "child"):
            try:
                value = read_json(profile / f"actor-{role}-{phase}.json")
            except (FileNotFoundError, json.JSONDecodeError):
                break
            if value.get("scope") != role or value.get("phase") != phase or type(value.get("pid")) is not int or value["pid"] <= 0:
                raise RuntimeError("Invalid actor identity report")
            records.append(value)
        if len(records) == 2:
            if records[1].get("parent_pid") != records[0]["pid"]:
                raise RuntimeError("Actor report did not prove parent/child relationship")
            return records
        if wrapper.poll() is not None:
            raise RuntimeError("MXC exited before independent actor reports completed")
        time.sleep(0.05)
    raise TimeoutError("Experimental actor reports timed out")


def held_image_diagnostic(api, handle):
    """Read one owned process HANDLE's image; this never authorizes a peer."""
    try:
        query = api.kernel32.QueryFullProcessImageNameW
        query.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        query.restype = wintypes.BOOL
        capacity = 32768
        path = ctypes.create_unicode_buffer(capacity)
        size = wintypes.DWORD(capacity)
        if not query(handle, 0, path, ctypes.byref(size)):
            return {"image_query_winerror": int(ctypes.get_last_error())}
        if not 0 < size.value < capacity or not path.value:
            return {"image_query_error": "invalid_length"}
        return {"image_path": path.value[:2048], "image_path_truncated": len(path.value) > 2048}
    except (AttributeError, OSError, TypeError) as exc:
        return {"image_query_error": type(exc).__name__}


def system_directory(api):
    """Obtain the trusted system directory from Windows, never environment."""
    query = api.kernel32.GetSystemDirectoryW
    query.argtypes = [wintypes.LPWSTR, wintypes.UINT]
    query.restype = wintypes.UINT
    buffer = ctypes.create_unicode_buffer(32768)
    length = query(buffer, len(buffer))
    if not 0 < length < len(buffer) or not ntpath.isabs(buffer.value):
        raise RuntimeError("Windows did not return a complete system directory")
    return buffer.value


def system_console_signature(directory, image):
    """Use Windows PowerShell's real embedded/catalog trust verification."""
    expected = ntpath.join(directory, "conhost.exe")
    if (image.get("image_path_truncated") is not False or not isinstance(image.get("image_path"), str)
            or ntpath.normcase(ntpath.normpath(image["image_path"])) != ntpath.normcase(ntpath.normpath(expected))):
        raise RuntimeError("Extra child was not the canonical system console image")
    encoded_target = base64.b64encode(expected.encode("utf-8")).decode("ascii")
    script = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'System Windows PowerShell required' }
foreach ($name in @('Microsoft.PowerShell.Security', 'Microsoft.PowerShell.Utility')) {
    $manifest = [IO.Path]::Combine($PSHOME, 'Modules', $name, ($name + '.psd1'))
    Import-Module -Name $manifest -Force -ErrorAction Stop -WarningAction SilentlyContinue
}
$target = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('TARGET'))
$sig = Microsoft.PowerShell.Security\Get-AuthenticodeSignature -LiteralPath $target -ErrorAction Stop
$publisher = ''
$thumbprint = ''
if ($null -ne $sig.SignerCertificate) {
    $publisher = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $thumbprint = $sig.SignerCertificate.Thumbprint
}
$stream = [IO.File]::OpenRead($target)
$sha = [Security.Cryptography.SHA256]::Create()
try { $hash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() }
finally { $sha.Dispose(); $stream.Dispose() }
@{signature_status=[string]$sig.Status; signature_type=[string]$sig.SignatureType;
  is_os_binary=[bool]$sig.IsOSBinary; publisher=[string]$publisher;
  signer_thumbprint=[string]$thumbprint; file_sha256=[string]$hash} |
    Microsoft.PowerShell.Utility\ConvertTo-Json -Compress
""".replace("TARGET", encoded_target)
    command = [ntpath.join(directory, "WindowsPowerShell", "v1.0", "powershell.exe"),
               "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
               base64.b64encode(script.encode("utf-16-le")).decode("ascii")]
    completed = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, timeout=12,
                               encoding="utf-8", errors="strict", shell=False)
    if completed.returncode or len(completed.stdout.encode("utf-8")) > 4096:
        raise RuntimeError("System console signature query did not complete")
    evidence = json.loads(completed.stdout)
    fields = {"signature_status", "signature_type", "is_os_binary", "publisher", "signer_thumbprint", "file_sha256"}
    if (not isinstance(evidence, dict) or set(evidence) != fields
            or evidence["signature_status"] != "Valid" or evidence["signature_type"] not in {"Authenticode", "Catalog"}
            or evidence["is_os_binary"] is not True or evidence["publisher"] != "Microsoft Windows"
            or not isinstance(evidence["signer_thumbprint"], str)
            or not re.fullmatch(r"[0-9a-fA-F]{40}", evidence["signer_thumbprint"])
            or not isinstance(evidence["file_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", evidence["file_sha256"])):
        error = RuntimeError("System console image lacked a valid Microsoft OS signature")
        if isinstance(evidence, dict):
            error.signature_evidence = {key: (value[:200] if isinstance(value, str) else value)
                for key, value in evidence.items() if key in fields and isinstance(value, (str, bool))}
        raise error
    return evidence


def retain_actor_handles(runtime, wrapper, reports, diagnostics=None):
    api = runtime._WinProcessApi()
    entries = []
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics.update(attestation_passed=False, wrapper_pid=wrapper.pid,
                       reported_parent_pid=reports[0]["pid"], reported_child_pid=reports[1]["pid"],
                       reported_parent_created=reports[0].get("process_created"),
                       reported_child_created=reports[1].get("process_created"), snapshots=[])

    def live_children(parent_pid, parent_created, report, scope):
        candidates = api.direct_children(parent_pid, parent_created)
        entries.extend(candidates)
        snapshot = {"scope": scope, "parent_pid": parent_pid, "parent_created": parent_created,
                    "returned_count": len(candidates), "returned_pids": [pid for pid, _ in candidates][:32],
                    "diagnostics_truncated": len(candidates) > 32, "children": []}
        diagnostics["snapshots"].append(snapshot)
        alive = []
        expected_exited = False
        for pid, handle in candidates:
            created = api.process_creation_time(handle)
            living = api.process_alive(handle)
            image = held_image_diagnostic(api, handle)
            if len(snapshot["children"]) < 32:
                snapshot["children"].append({"pid": pid, "process_created": created, "alive": living,
                                             **image})
            if created < parent_created:
                snapshot["failure"] = "child_predates_verified_parent"
                raise RuntimeError("A child process generation predates its verified parent")
            if living:
                alive.append((pid, handle, created, image))
            else:
                expected_exited = expected_exited or pid == report["pid"]
                # A completed diagnostic may remain enumerable while Windows
                # retains its process object. Only this held signaled HANDLE
                # permits excluding it from the unique-live-child check.
                api.close(handle)
                entries.remove((pid, handle))
        snapshot["live_count"] = len(alive)
        snapshot["live_pids"] = [item[0] for item in alive][:32]
        actors = [item for item in alive if item[0] == report["pid"]]
        extras = [item for item in alive if item[0] != report["pid"]]
        if len(actors) != 1 or (scope == "parent" and extras) or len(extras) > 1:
            snapshot["failure"] = ("reported_process_exited" if expected_exited else
                "unexpected_live_children" if len(alive) > 1 else
                "reported_process_absent_from_verified_snapshot")
            detail = ("MXC's unique verified workload" if scope == "parent" else
                      "the verified workload descendant")
            raise RuntimeError(f"Reported {scope} was not {detail}; live PIDs={snapshot['live_pids']}")
        _, _, created, _ = actors[0]
        if type(report.get("process_created")) is not int or report["process_created"] != created:
            snapshot["failure"] = "reported_process_generation_mismatch"
            raise RuntimeError(f"Reported {scope} process generation did not match its held HANDLE")
        if extras:
            pid, _handle, created, image = extras[0]
            try:
                signature = system_console_signature(system_directory(api), image)
            except Exception as exc:
                snapshot["failure"] = "unexpected_live_children"
                snapshot["helper_verification_error"] = type(exc).__name__
                if hasattr(exc, "signature_evidence"):
                    snapshot["helper_signature"] = exc.signature_evidence
                raise RuntimeError("Extra process was not a verified workload descendant system helper") from exc
            snapshot["accounted_system_helpers"] = [{"pid": pid, "process_created": created,
                "image_path": image["image_path"], "held_handle_generation_verified": True,
                "signature": signature}]
        snapshot["held_handle_generation_verified"] = True
        return actors[0][0], actors[0][1]

    try:
        parent_created = api.process_creation_time(runtime._raw_handle(wrapper._handle))
        diagnostics["wrapper_created"] = parent_created
        parent_pid, parent_handle = live_children(wrapper.pid, parent_created, reports[0], "parent")
        live_children(parent_pid, api.process_creation_time(parent_handle), reports[1], "child")
        if not all(api.process_alive(handle) for _, handle in entries):
            diagnostics["failure"] = "retained_actor_exited_after_verification"
            raise RuntimeError("A retained actor was no longer alive")
        diagnostics["attestation_passed"] = True
        return api, entries
    except BaseException as exc:
        diagnostics["error"] = f"{type(exc).__name__}: {exc}"[:700]
        for _, handle in entries:
            api.close(handle)
        raise


def pending_recovery(value):
    if isinstance(value, dict):
        return (any(key in value for key in ("cleanup_error", "recovery_directory"))
                or value.get("cleanup_proven") is False
                or bool(value.get("cleanup_errors"))) or any(
            pending_recovery(item) for item in value.values())
    if isinstance(value, list):
        return any(pending_recovery(item) for item in value)
    return False


def run_variant(name, profile, root, runtime, helpers, host_fixtures, udp, pipe_script, *, deadline=None):
    profile.mkdir()
    result = {"name": name, "status": "not_run", "process_started": False,
              "no_process_started": True, "checks": []}
    proxy = bridge = wrapper = api = None
    handles, safe = [], True
    udp_before = list(udp.received)
    host_fixtures.accepted.clear()
    deadline = deadline or time.monotonic() + 115
    try:
        proxy = FixedProxy()
        # Confirm fixture health through both real protocols before containment.
        for protocol in ("http", "socks"):
            proxy_roundtrip(proxy.port, proxy.token, protocol)
        endpoint = proxy.port if name == "model2_host" else runtime.choose_guest_port(proxy.port)
        if name != "model2_host":
            from ruleproxy.file_bridge import FileProxyBridge
            bridge = FileProxyBridge(proxy.port, profile / "relay")
        actor_file = profile / "experiment_actor.py"
        shutil.copyfile(__file__, actor_file)
        config_path = profile / "actor-config.json"
        config = {"variant": name, "root": str(root), "endpoint_port": endpoint, "token": proxy.token,
                  "host_tcp_ports": [sock.getsockname()[1] for sock in host_fixtures.sockets],
                  "host_udp_ports": [sock.getsockname()[1] for sock in udp.sockets], "pipe_script": str(pipe_script)}
        if bridge is not None:
            config.update(bridge_directory=str(bridge.directory), bridge_nonce=bridge.nonce)
        write_json(config_path, config)
        command = [sys.executable, "-I", "-S", "-X", "utf8", str(actor_file), "--actor", str(config_path), "--role", "parent"]
        policy = runtime.build_policy(command, {}, profile, endpoint)
        policy["process"]["commandLine"] = subprocess.list2cmdline(command)
        policy["process"]["timeout"] = 100000
        policy["filesystem"]["readonlyPaths"] = sorted(set(policy["filesystem"]["readonlyPaths"]) | {str(root), str(pipe_script.parent)})
        policy.update(network_policy(name, endpoint, proxy.port))
        result["policy"] = policy
        try:
            result["probe"] = runtime._probe_request(str(root / "bin/windows-amd64/wxc-exec.exe"), policy)
        except runtime.UnsupportedRuntimeError as exc:
            result.update(status="unsupported", detail=str(exc)[:700])
            return result
        actor_budget = min(ACTOR_WAIT_SECONDS, deadline - time.monotonic() - 50)
        if actor_budget < 5:
            raise TimeoutError("Matrix budget cannot safely start another contained actor")
        policy_file = profile / "policy.json"
        write_json(policy_file, policy)
        with (profile / "actor.log").open("wb") as output:
            wrapper = subprocess.Popen([str(root / "bin/windows-amd64/wxc-exec.exe"), "--config", str(policy_file)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, shell=False)
            result.update(process_started=True, no_process_started=False, descendant_cleanup_proven=False)
            reports = wait_actor_reports(profile, wrapper, "initial", timeout=actor_budget)
            result["actors"] = reports
            result["actor_attestation"] = {}
            api, handles = retain_actor_handles(runtime, wrapper, reports, result["actor_attestation"])
            if name != "model2_host":
                try:
                    with socket.create_connection(("127.0.0.1", endpoint), timeout=1):
                        host_reached = True
                except OSError:
                    host_reached = False
                result["checks"].append({"check": "host_to_contained_listener", "reachable": host_reached})
            if name in MODEL1_VARIANTS:
                write_json(profile / "actor-control.json", {"state": "stop_bridge"})
                deadline = time.monotonic() + 8
                while not (profile / "bridge-stopped.json").is_file():
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Contained relay did not stop for endpoint takeover")
                    time.sleep(0.05)
                if read_json(profile / "bridge-stopped.json").get("stopped") is not True:
                    raise RuntimeError("Contained relay survived its stop request")
                replacement = socket.socket()
                try:
                    replacement.bind(("127.0.0.1", endpoint))
                    replacement.listen(4)
                    replacement.settimeout(0.2)
                    # Same exact host endpoint is live; establish the positive
                    # control before asking both contained actors to attempt it.
                    with socket.create_connection(("127.0.0.1", endpoint), timeout=2):
                        connection, _ = replacement.accept()
                        connection.close()
                    write_json(profile / "actor-control.json", {"state": "host_replaced"})
                    result["replacement_actors"] = wait_actor_reports(profile, wrapper, "replacement", timeout=8)
                    try:
                        connection, _ = replacement.accept()
                    except socket.timeout:
                        reached = False
                    else:
                        connection.close()
                        reached = True
                    result["checks"].append({"check": "host_same_port_takeover", "host_listener_verified": True,
                                              "contained_connection_received": reached})
                finally:
                    replacement.close()
            result.update(status="observed", proxy_roundtrips=proxy.roundtrips - 2,
                          fixed_proxy_errors=list(proxy.errors),
                          transport_roundtrip_observed=all(report["checks"]["proxy_" + protocol]["ok"]
                              for report in reports for protocol in ("http", "socks")))
    except Exception as exc:
        result.update(status="failed", detail=f"{type(exc).__name__}: {exc}"[:700])
    finally:
        try:
            if wrapper is not None:
                if wrapper.poll() is None:
                    runtime.stop(wrapper, timeout=20)
                wrapper.wait(timeout=5)
                if api is not None and not all(api.wait(handle, 1000) for _, handle in handles):
                    raise RuntimeError("A retained actor survived normal PSEC teardown")
                if not handles:
                    raise RuntimeError("No retained actor handles were available to prove descendant teardown")
                result["descendant_cleanup_proven"] = True
                result["checks"].append({"check": "safe_guardian_teardown", "status": "passed",
                                          "held_handles_verified": bool(handles), "parent_and_child_exited": bool(handles),
                                          "retained_process_count": len(handles), "all_retained_processes_exited": True})
            if bridge is not None:
                bridge.close()
                with bridge._state_lock:
                    bridge_workers = tuple(bridge._workers)
                if bridge._dispatcher.is_alive() or any(worker.is_alive() for worker in bridge_workers):
                    raise RuntimeError("Production host relay threads remained alive after close")
            if proxy is not None:
                proxy.close()
            result["resources_closed"] = True
            if pending_recovery(result):
                raise RuntimeError("A nested experiment left pending recovery state")
        except Exception as exc:
            safe = False
            result.update(status="failed", cleanup_error=type(exc).__name__, recovery_directory=str(profile))
        finally:
            if api is not None:
                for _, handle in handles:
                    try:
                        api.close(handle)
                    except Exception as exc:
                        safe = False
                        result.update(status="failed", resources_closed=False,
                                      cleanup_error=type(exc).__name__, recovery_directory=str(profile))
        if safe:
            log = profile / "actor.log"
            if log.exists():
                with log.open("rb") as output:
                    result["log"] = output.read(8 * 1024).decode("utf-8", "replace")
            time.sleep(0.05)  # Let the already-received local fixture events settle.
            result["host_tcp_connection_received"] = host_fixtures.accepted.is_set()
            result["host_udp_datagrams_received"] = [now - before for now, before in zip(udp.received, udp_before)]
            result["host_udp_observer_positive_controls"] = list(udp.positive_controls)
    return result


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--allow-emulated-x64", action="store_true")
    args = parser.parse_args(arguments)
    args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
    result = {"status": "failed", "full_acceptance_passed": False, "acceptance_passed": False,
              "real_node_passed": False, "product_provider_changed": False, "cleanup_proven": False,
              "variants": [], "checks": []}
    directory = fixtures = udp = None
    safe = True
    code = 1
    before = None
    phase_deadline = time.monotonic() + MATRIX_PHASE_SECONDS
    try:
        helpers = load_helpers()
        root = args.root.resolve(strict=True)
        runtime, _, _ = import_project(root)
        helpers.verify_project_origin(root)
        result["runtime_integrity"] = {"verified_file_count": len(helpers.verify_runtime_manifest(root))}
        result["host"] = helpers.host_facts()
        host = result["host"]
        if host.get("python_pe_machine") != 0x8664 or (host.get("native_machine") != 0x8664 and not (
            args.allow_emulated_x64 and host.get("native_machine") == 0xAA64)):
            raise RuntimeError("Native x64 Windows or explicitly allowed x64-on-ARM execution is required")
        pipe_script = ROOT / ".github/windows_named_pipe_probe.py"
        if not pipe_script.is_file():
            raise RuntimeError("Named-pipe experiment script is missing")
        before = helpers.network_snapshot()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-network-experiment-"))
        fixtures, udp = helpers.HostFixtures(), DatagramObservers()
        for name in VARIANTS:
            if phase_deadline - time.monotonic() < 30:
                raise TimeoutError("Matrix budget was exhausted before the next experiment")
            variant = run_variant(name, directory / name, root, runtime, helpers, fixtures, udp, pipe_script,
                                  deadline=phase_deadline)
            result["variants"].append(variant)
            if pending_recovery(variant):
                safe = False
                result.update(cleanup_error=variant.get("cleanup_error", "NestedRecoveryPending"),
                              recovery_directory=str(directory))
                break
        if safe and len(result["variants"]) == len(VARIANTS) and all(
            variant["status"] in ("observed", "unsupported") for variant in result["variants"]
        ):
            result["status"], code = "experiment_only", 0
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}: {exc}"[:700]
    finally:
        if safe:
            try:
                if udp is not None:
                    udp.close()
                if fixtures is not None:
                    fixtures.close()
                    if any(thread.is_alive() for thread in fixtures.threads):
                        raise RuntimeError("Ordinary host TCP fixture threads remained alive after close")
                if directory is not None:
                    shutil.rmtree(directory)
                result["cleanup_proven"] = True
            except Exception as exc:
                result.update(status="failed", cleanup_error=type(exc).__name__,
                              recovery_directory=str(directory), cleanup_proven=False)
                code = 1
        if before is not None:
            try:
                after = helpers.network_snapshot()
                unchanged = before == after
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                          "status": "passed" if unchanged else "failed",
                                          "before_sha256": before, "after_sha256": after})
                if not unchanged:
                    result["status"], code = "failed", 1
            except Exception as exc:
                result.update(status="failed", host_snapshot_error=type(exc).__name__)
                code = 1
        write_json(args.report.resolve(), result, limit=256 * 1024)
        print(json.dumps({"status": result["status"], "cleanup_proven": result["cleanup_proven"],
                          "variants": [{"name": item["name"], "status": item["status"]}
                                       for item in result["variants"]]}, ensure_ascii=True), flush=True)
    return code


if __name__ == "__main__":
    if sys.argv[1:2] == ["--actor"]:
        actor_parser = argparse.ArgumentParser()
        actor_parser.add_argument("--actor", type=Path, required=True)
        actor_parser.add_argument("--role", choices=("parent", "child"), required=True)
        actor_args = actor_parser.parse_args()
        raise SystemExit(actor(actor_args.actor, actor_args.role))
    raise SystemExit(main(sys.argv[1:]))
