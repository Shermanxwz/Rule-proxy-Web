"""Collect fixed MXC policy experiments; never switch the product's provider.

CLI: package-python windows_network_experiment.py --root PACKAGE --report FILE
     [--allow-emulated-x64]
     [--test-psec-executor EXE --test-psec-manifest JSON] [--collect-native-dns]
     [--singleton-port-range]
     [--preferred-policy-only]
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
import hashlib
import importlib.util
import json
import os
import ntpath
import re
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
MODEL1_VARIANTS = ("model1_internal_ingress_deny", "model1_internal")
VARIANTS = ("model3", *MODEL1_VARIANTS, "model2_host")
PREFERRED_VARIANT = "model1_internal_ingress_deny"
MAX_REPORT_BYTES = 128 * 1024
ACTOR_WAIT_SECONDS = 45
MATRIX_PHASE_SECONDS = 440  # Leaves 120s for the final native CIM snapshot.
DESTINATION = b"ruleproxy-experiment.invalid"
UDP_CONTROL = b"RuleProxy fixed UDP observer control"
PSEC_UPSTREAM_COMMIT = "7bf210247986cb73b1b314df60c2f1109c479c0b"
PSEC_ORIGINAL_SOURCE_SHA256 = "a03b8889d8d92fe854f46d56c702360403c6889e79b48b42f8b2535b66189491"
PSEC_PATCH_SHA256 = "3b0c5e616e3575d5be0ec3f34abd9ba6dd8f213eb097e836ab80c7a60dda112a"
PSEC_PATCHED_SOURCE_SHA256 = "3809ab6269efaaf89011364c3f3355465ad11c7f5545f0a4f301181743bf926e"
PSEC_TEST_PATCH = {"name": "exact_internal_tcp_without_automatic_internet_client",
                   "capabilities_null": True, "network_table_unchanged": True,
                   "exact_internal_tcp_only": True, "caller_capabilities_must_be_empty": True}
PSEC_TEST_INGRESS_PATCH = {
    "name": "private_network_ingress_control_without_automatic_internet_client",
    "source_diagnostic_only": True,
    "release_eligible": False,
    "exact_internal_tcp_only": True,
    "caller_capabilities_must_be_empty": True,
    "network_table_unchanged": True,
    "host_loopback_must_remain_deny": True,
    "ingress_default_allow_or_deny": True,
    "automatic_internet_client_removed": True,
    "private_network_capability_preserved": True,
    "capabilities_null": False,
}
PSEC_INGRESS_PATCH_SHA256 = "c39ef13da834b330deb028a7a273ad154cbdd07ee5c60c917e9382cf25557a62"
PSEC_INGRESS_PATCHED_SOURCE_SHA256 = "4c6915b28b6e09a35508001f70087499ececc4861ba5e2b896c5dd122c5f3759"
_CONSOLE_RECOVERY_OWNERS = []


def strict_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate test executor manifest field")
        value[key] = item
    return value


def test_executor_file(path):
    if not path.is_absolute():
        raise ValueError("Test executor inputs must be absolute ordinary files")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or not info.st_size
                or path.is_symlink() or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("Test executor inputs must be nonempty ordinary files without reparse points")
        for parent in path.parents:
            attributes = parent.lstat()
            if (not stat.S_ISDIR(attributes.st_mode) or parent.is_symlink()
                    or getattr(attributes, "st_file_attributes", 0) & 0x400):
                raise ValueError("Test executor input directories must not be reparse points")
        return path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Test executor input file is unavailable") from exc


def verify_test_executor(root, executor, manifest, original_sha256, *, ingress_controls_diagnostic=False):
    """An explicit CI build artifact, never a replacement for product runtime.

    A matching local manifest proves integrity; the invoking workflow's pinned
    source and artifact checksum establish its source and build provenance.
    """
    if type(ingress_controls_diagnostic) is not bool:
        raise ValueError("Test executor diagnostic selector must be boolean")
    expected_patch = PSEC_TEST_INGRESS_PATCH if ingress_controls_diagnostic else PSEC_TEST_PATCH
    expected_patch_sha = PSEC_INGRESS_PATCH_SHA256 if ingress_controls_diagnostic else PSEC_PATCH_SHA256
    expected_patched_sha = PSEC_INGRESS_PATCHED_SOURCE_SHA256 if ingress_controls_diagnostic else PSEC_PATCHED_SOURCE_SHA256
    if ingress_controls_diagnostic and (not re.fullmatch(r"[0-9a-f]{64}", expected_patch_sha)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_patched_sha)):
        raise ValueError("The fixed ingress-control executor source pins are unavailable")
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Product root must be an existing directory")
    executor, manifest = test_executor_file(executor), test_executor_file(manifest)
    if (executor.is_relative_to(root / "bin") or manifest.is_relative_to(root / "bin")
            or executor.suffix.casefold() != ".exe" or executor == manifest):
        raise ValueError("Test executor must be separate from the product runtime directory")
    if not isinstance(original_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", original_sha256):
        raise ValueError("Original product executor integrity was not verified")
    with manifest.open("rb") as stream:
        raw = stream.read(MAX_REPORT_BYTES + 1)
    if not raw or len(raw) > MAX_REPORT_BYTES:
        raise ValueError("Test executor manifest exceeded its size limit")
    value = json.loads(raw, object_pairs_hook=strict_json_object)
    required = {"schema_version", "status", "upstream_commit", "executor_sha256", "patch",
                "original_file_sha256", "patch_sha256", "patched_file_sha256", "toolchain", "target"}
    if (not isinstance(value, dict) or set(value) != required
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["status"] != "built" or value["upstream_commit"] != PSEC_UPSTREAM_COMMIT
            or not isinstance(value["executor_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["executor_sha256"])
            or not isinstance(value["patch"], dict) or set(value["patch"]) != set(expected_patch)
            or any(type(value["patch"][key]) is not type(expected) or value["patch"][key] != expected
                   for key, expected in expected_patch.items())):
        raise ValueError("Test executor manifest did not describe the fixed source-only capability experiment")
    if (value["original_file_sha256"] != PSEC_ORIGINAL_SOURCE_SHA256
            or value["patch_sha256"] != expected_patch_sha
            or value["patched_file_sha256"] != expected_patched_sha
            or value["toolchain"] != "1.93" or value["target"] != "x86_64-pc-windows-msvc"):
        raise ValueError("Test executor manifest provenance did not match the fixed build")
    digest = hashlib.sha256()
    with executor.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != value["executor_sha256"]:
        raise ValueError("Test executor SHA-256 did not match its build manifest")
    return executor, {**value, "source_only_executor_changed": True,
        "original_runtime_sha256": original_sha256, "default_product_runtime_replaced": False,
        "capability_scope": ("empty caller capabilities; one exact internal TCP allow; automatic internetClient removed; privateNetworkClientServer preserved"
            if ingress_controls_diagnostic else "empty caller capabilities and one exact internal TCP allow only"),
        "origin_verification": "Pinned build workflow and external artifact checksum are required.",
        "acceptance_passed": False, "real_node_passed": False, "kernel_denial_proven": False}


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


def network_policy(name, internal_port, proxy_port, *, singleton_port_range=False,
                   ingress_default_allow_control=False):
    if name not in VARIANTS or any(type(port) is not int or not 1 <= port <= 65535 for port in (internal_port, proxy_port)):
        raise ValueError("Invalid fixed policy variant or port")
    if type(singleton_port_range) is not bool:
        raise ValueError("Invalid diagnostic port encoding")
    if type(ingress_default_allow_control) is not bool or (
            ingress_default_allow_control and (name != PREFERRED_VARIANT or singleton_port_range)):
        raise ValueError("Invalid single-factor ingress diagnostic policy")
    value = {"network": {"egress": {"default": "deny"},
                         "ingress": {"default": "deny", "hostLoopback": "deny"}}}
    if name in MODEL1_VARIANTS:
        value["network"]["ingress"]["default"] = "allow" if name == "model1_internal" else "deny"
        if ingress_default_allow_control:
            value["network"]["ingress"]["default"] = "allow"
        port_rule = {"protocol": "tcp", "port": internal_port}
        if singleton_port_range:
            port_rule["endPort"] = internal_port
        value["network"]["egress"]["allow"] = [{"to": [{"cidr": "127.0.0.1/32"}],
                                                    "ports": [port_rule]}]
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


def load_wire_helpers(path):
    spec = importlib.util.spec_from_file_location("ruleproxy_private_wire_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_dns_session():
    path = ROOT / ".github/windows_dns_session.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_experiment_dns_session", path)
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
    if config.get("wire_probes"):
        wire = load_wire_helpers(config["wire_script"])
        record["wire_execution"] = wire.send_probes(config["wire_probes"], role)
    if config.get("native_dns"):
        native = config["native_dns"]
        session = load_wire_helpers(native["session_script"])
        record["native_dns"] = session.collect_calls(native, role,
            Path(native["directory"]) / role, native["deadline"])
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
        bridge_stop_reported = False
        while time.monotonic() < deadline:
            try:
                control = read_json(profile / "actor-control.json")
            except FileNotFoundError:
                control = {}
            if control.get("state") == "stop_bridge" and role == "parent" and bridge_thread is not None \
                    and not bridge_stop_reported:
                stop.set()
                bridge_thread.join(5)
                write_json(profile / "bridge-stopped.json", {"stopped": not bridge_thread.is_alive()})
                # This persistent control is an instruction, not a request to
                # republish the same file every poll. On Windows replacing a
                # JSON file while the host reads it can fail with WinError 5.
                bridge_stop_reported = True
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


def read_actor_reports(profile, phase):
    records = []
    for role in ("parent", "child"):
        try:
            value = read_json(profile / f"actor-{role}-{phase}.json")
        except (FileNotFoundError, json.JSONDecodeError):
            break
        if value.get("scope") != role or value.get("phase") != phase or type(value.get("pid")) is not int or value["pid"] <= 0:
            raise RuntimeError("Invalid actor identity report")
        records.append(value)
    if len(records) == 2 and records[1].get("parent_pid") != records[0]["pid"]:
        raise RuntimeError("Actor report did not prove parent/child relationship")
    return records


def wait_actor_reports(profile, wrapper, phase, *, timeout=ACTOR_WAIT_SECONDS):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        records = read_actor_reports(profile, phase)
        code = wrapper.poll()
        if code is not None:
            # A final atomic publication can occur between the first read and
            # observing process exit. Read once more, without waiting for or
            # manufacturing a report after the workload has stopped.
            records = read_actor_reports(profile, phase)
            if code != 0:
                raise RuntimeError(f"MXC exited with status {code} before independent actor reports were accepted")
            if len(records) != 2:
                raise RuntimeError("MXC exited before independent actor reports completed")
        if len(records) == 2:
            return records
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


def canonical_console_image(directory, image):
    expected = ntpath.join(directory, "conhost.exe")
    if (image.get("image_path_truncated") is not False or not isinstance(image.get("image_path"), str)
            or ntpath.normcase(ntpath.normpath(image["image_path"])) != ntpath.normcase(ntpath.normpath(expected))):
        raise RuntimeError("Extra child was not the canonical system console image")
    return expected


def system_console_signature(directory, image):
    """Use Windows PowerShell's real embedded/catalog trust verification."""
    expected = canonical_console_image(directory, image)
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


class _ConsoleFileInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "attributes", "creation_low", "creation_high", "access_low", "access_high",
        "write_low", "write_high", "volume", "size_high", "size_low", "links", "id_high", "id_low")]


class _ConsoleFileApi:
    """Read and retain one canonical system image; no write/delete sharing."""
    def __init__(self):
        if sys.platform != "win32":
            raise OSError("System console file binding requires Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, dword = ctypes.c_void_p, ctypes.c_uint32
        signatures = {
            "CreateFileW": ([ctypes.c_wchar_p, dword, dword, handle, dword, dword, handle], handle),
            "GetFileInformationByHandle": ([handle, ctypes.POINTER(_ConsoleFileInfo)], ctypes.c_int32),
            "SetFilePointerEx": ([handle, ctypes.c_int64, ctypes.POINTER(ctypes.c_int64), dword], ctypes.c_int32),
            "ReadFile": ([handle, handle, dword, ctypes.POINTER(dword), handle], ctypes.c_int32),
            "CloseHandle": ([handle], ctypes.c_int32),
        }
        for name, (arguments, result) in signatures.items():
            function = getattr(self.kernel32, name)
            function.argtypes, function.restype = arguments, result

    @staticmethod
    def checked(value):
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def open(self, path):
        # OPEN_REPARSE_POINT makes a replaced leaf observable, not traversable.
        handle = self.kernel32.CreateFileW(path, 0x80000000, 1, None, 3, 0x00200080, None)
        if handle in (None, ctypes.c_void_p(-1).value):
            raise ctypes.WinError(ctypes.get_last_error())
        return handle

    def metadata(self, handle):
        info = _ConsoleFileInfo()
        self.checked(self.kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)))
        size, identity = info.size_high << 32 | info.size_low, info.id_high << 32 | info.id_low
        if info.attributes & 0x410 or not identity or not 0 < size <= 64 * 1024 * 1024:
            raise RuntimeError("System console file was not a bounded ordinary non-reparse image")
        return {"volume": info.volume, "file_id": identity, "size": size,
                "creation_filetime": info.creation_high << 32 | info.creation_low,
                "write_filetime": info.write_high << 32 | info.write_low,
                "attributes": info.attributes}

    def fingerprint(self, handle):
        before = self.metadata(handle)
        self.checked(self.kernel32.SetFilePointerEx(handle, 0, None, 0))
        checksum, total = hashlib.sha256(), 0
        buffer, count = ctypes.create_string_buffer(64 * 1024), ctypes.c_uint32()
        while True:
            self.checked(self.kernel32.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None))
            if not count.value:
                break
            total += count.value
            if count.value > len(buffer) or total > before["size"]:
                raise RuntimeError("System console file changed during its bounded read")
            checksum.update(buffer.raw[:count.value])
        if total != before["size"] or self.metadata(handle) != before:
            raise RuntimeError("System console file metadata changed during verification")
        return {**before, "sha256": checksum.hexdigest()}

    def close(self, handle):
        self.checked(self.kernel32.CloseHandle(handle))


class SystemConsoleTrustCache:
    """One matrix's real trust result, bound to continuously held file bytes."""
    def __init__(self, api=None):
        self.api = _ConsoleFileApi() if api is None else api
        self.directory = system_directory(self.api)
        self.image = {"image_path": ntpath.join(self.directory, "conhost.exe"), "image_path_truncated": False}
        self.handles, self.identity, self.signature = [], None, None
        self.prepared_at = self.started_at = self.capture_requested_at = None
        self.hits = self.revalidations = 0
        self.contaminated = False

    def _open(self):
        handle = self.api.open(self.image["image_path"])
        self.handles.append(handle)
        return handle

    def _close(self, handle):
        self.api.close(handle)
        self.handles.remove(handle)

    def prepare(self):
        if self.handles or self.signature is not None or self.capture_requested_at is not None:
            raise RuntimeError("System console trust is scoped to one matrix")
        self.started_at = time.monotonic()
        handle = self._open()
        before = self.api.fingerprint(handle)
        signature = system_console_signature(self.directory, self.image)
        after = self.api.fingerprint(handle)
        if before != after or signature["file_sha256"] != after["sha256"]:
            raise RuntimeError("System console signature was not bound to its held file bytes")
        self.identity, self.signature = after, signature
        self.prepared_at = time.monotonic()

    def before_capture(self):
        if self.signature is None or self.prepared_at is None or not self.handles or self.capture_requested_at is not None:
            raise RuntimeError("System console trust was not prepared before capture")
        self.capture_requested_at = time.monotonic()

    def verify(self, directory, image):
        canonical_console_image(directory, image)
        if (self.signature is None or self.capture_requested_at is None or self.contaminated or not self.handles
                or ntpath.normcase(directory) != ntpath.normcase(self.directory)):
            raise RuntimeError("System console pre-capture trust was unavailable")
        try:
            handle = self._open()
            try:
                unchanged = self.api.fingerprint(handle) == self.identity
            finally:
                self._close(handle)
        except Exception as exc:
            self.contaminated = True
            self.revalidations += 1
            system_console_signature(directory, image)
            raise RuntimeError("System console file binding could not be verified during capture") from exc
        if not unchanged:
            # Revalidation retains the original trust checks. Its possible
            # network effects contaminate this capture, even if it succeeds.
            self.contaminated = True
            self.revalidations += 1
            system_console_signature(directory, image)
            raise RuntimeError("System console file binding changed during capture")
        self.hits += 1
        return dict(self.signature)

    def close(self):
        failed = False
        for handle in tuple(self.handles):
            try:
                self._close(handle)
            except Exception:
                failed = True
        if failed:
            _CONSOLE_RECOVERY_OWNERS.append(self)
            raise RuntimeError("System console trust file handle cleanup was not proven")

    def summary(self):
        identity = json.dumps(self.identity, sort_keys=True, separators=(",", ":")).encode("ascii")
        return {"scope": "system_console_signature_pre_capture", "signature_prevalidated": self.signature is not None,
            "signature_type": self.signature["signature_type"] if self.signature else None,
            "warmup_completed_before_capture_request": (self.prepared_at is not None
                and self.capture_requested_at is not None and self.prepared_at <= self.capture_requested_at),
            "warmup_duration_ms": round((self.prepared_at - self.started_at) * 1000) if self.prepared_at else None,
            "file_identity_sha256": hashlib.sha256(identity).hexdigest() if self.identity else None,
            "file_sha256": self.identity["sha256"] if self.identity else None,
            "cache_hits": self.hits, "inside_capture_revalidations": self.revalidations,
            "capture_contaminated": self.contaminated, "cleanup_proven": not self.handles,
            "acceptance_passed": False, "kernel_denial_proven": False}


class _ObservedProcessCall:
    def __init__(self, observer, name, function):
        object.__setattr__(self, "observer", observer)
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "function", function)

    def __getattr__(self, name):
        return getattr(self.function, name)

    def __setattr__(self, name, value):
        setattr(self.function, name, value)

    def __call__(self, *arguments):
        return self.observer.invoke(self.name, self.function, arguments)


class _ProcessApiObservation:
    """Observe one private API instance without changing its calls or rights.

    In particular, failed OpenProcess calls retain the original last-error for
    the runtime's WinError. No handle values or unrelated snapshot PIDs are
    serialized. The production guardian constructs its own unmodified API.
    """

    OPERATIONS = frozenset({"CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
        "OpenProcess", "GetProcessTimes", "QueryFullProcessImageNameW", "WaitForSingleObject", "CloseHandle"})

    def __init__(self, kernel, diagnostics, *, get_error=None, set_error=None):
        self.kernel, self.diagnostics = kernel, diagnostics
        self.get_error = get_error or getattr(ctypes, "get_last_error", lambda: 0)
        self.set_error = set_error or getattr(ctypes, "set_last_error", lambda _value: None)
        self.scope, self.parent_pid = "wrapper", None
        self.open_counts, self.handles, self.functions = {}, {}, {}
        diagnostics["native_api_calls"] = []
        diagnostics["native_api_calls_truncated"] = False

    @staticmethod
    def number(value):
        value = getattr(value, "value", value)
        return value if type(value) is int and 0 <= value <= 0xffffffffffffffff else None

    def context(self, scope, parent_pid):
        self.scope, self.parent_pid = scope, parent_pid
        self.open_counts = {}

    def __getattr__(self, name):
        function = getattr(self.kernel, name)
        if name not in self.OPERATIONS:
            return function
        if name not in self.functions:
            self.functions[name] = _ObservedProcessCall(self, name, function)
        return self.functions[name]

    def invoke(self, name, function, arguments):
        pid, access, phase = None, None, None
        if name == "OpenProcess":
            access, pid = self.number(arguments[0]), self.number(arguments[2])
            count = self.open_counts.get(pid, 0) + 1
            self.open_counts[pid] = count
            phase = "first_open" if count == 1 else "reopen"
        elif name not in {"CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW"}:
            pid, access = self.handles.get(self.number(arguments[0]), (None, None))
        raised = None
        try:
            result = function(*arguments)
        except BaseException as exc:
            raised = exc
            raise
        finally:
            error = self.get_error()
            if raised is not None:
                succeeded = False
            elif name == "WaitForSingleObject":
                succeeded = result in (0, 258)
            elif name == "CreateToolhelp32Snapshot":
                succeeded = self.number(result) not in (None, ctypes.c_void_p(-1).value)
            else:
                succeeded = bool(result)
            # Normal end-of-enumeration and successful enumeration steps add
            # no diagnostic value and would enumerate unrelated host PIDs.
            record = name not in {"Process32FirstW", "Process32NextW"} or (
                not succeeded and not (name == "Process32NextW" and error in (0, 18)))
            if record:
                fact = {"operation": name, "scope": self.scope, "parent_pid": self.parent_pid,
                    "target_pid": pid, "desired_access": access, "open_phase": phase,
                    "succeeded": succeeded, "errno": getattr(raised, "errno", None),
                    "winerror": (getattr(raised, "winerror", None) or error) if not succeeded else None}
                calls = self.diagnostics["native_api_calls"]
                if len(calls) < 64:
                    calls.append(fact)
                else:
                    self.diagnostics["native_api_calls_truncated"] = True
                if not succeeded and "native_api_failure" not in self.diagnostics:
                    self.diagnostics["native_api_failure"] = fact.copy()
            if raised is None and succeeded:
                if name == "OpenProcess":
                    self.handles[self.number(result)] = (pid, access)
                elif name == "CloseHandle":
                    self.handles.pop(self.number(arguments[0]), None)
            self.set_error(error)
        return result


def retain_actor_handles(runtime, wrapper, reports, diagnostics=None, *, console_trust=None):
    api = runtime._WinProcessApi()
    entries = []
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics.update(attestation_passed=False, wrapper_pid=wrapper.pid,
                       reported_parent_pid=reports[0]["pid"], reported_child_pid=reports[1]["pid"],
                       reported_parent_created=reports[0].get("process_created"),
                       reported_child_created=reports[1].get("process_created"), snapshots=[])
    observed = _ProcessApiObservation(api.kernel32, diagnostics)
    api.kernel32 = observed
    observed.handles[runtime._raw_handle(wrapper._handle)] = (wrapper.pid, None)
    observed.context("wrapper", wrapper.pid)

    def live_children(parent_pid, parent_created, report, scope):
        snapshot = {"scope": scope, "parent_pid": parent_pid, "parent_created": parent_created,
                    "status": "querying", "children": []}
        diagnostics["snapshots"].append(snapshot)
        observed.context(scope, parent_pid)
        try:
            candidates = api.direct_children(parent_pid, parent_created)
        except BaseException as exc:
            snapshot.update(status="failed", error_type=type(exc).__name__,
                            errno=getattr(exc, "errno", None), winerror=getattr(exc, "winerror", None))
            raise
        entries.extend(candidates)
        snapshot.update(status="returned", returned_count=len(candidates),
                        returned_pids=[pid for pid, _ in candidates][:32],
                        diagnostics_truncated=len(candidates) > 32)
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
                directory = system_directory(api)
                signature = (console_trust.verify(directory, image) if console_trust is not None
                             else system_console_signature(directory, image))
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
            try:
                api.close(handle)
            except Exception as close_error:
                diagnostics.setdefault("cleanup_errors", []).append({"operation": "CloseHandle",
                    "error_type": type(close_error).__name__, "errno": getattr(close_error, "errno", None),
                    "winerror": getattr(close_error, "winerror", None)})
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


def run_variant(name, profile, root, runtime, helpers, host_fixtures, udp, pipe_script, *, deadline=None, wire=None, dns=None,
                executor=None, console_trust=None, singleton_port_range=False, psec_1_1_diagnostic=False,
                ingress_default_allow_control=False):
    if singleton_port_range and executor is not None:
        raise ValueError("Singleton-range diagnostic cannot be combined with a custom test executor")
    profile.mkdir()
    result = {"name": name, "status": "not_run", "process_started": False,
              "no_process_started": True, "checks": []}
    if ingress_default_allow_control:
        result.update(source_policy_variant="private_network_capability_control",
                      ingress_control={"default": "allow", "hostLoopback": "deny"},
                      production_policy_unchanged=True, acceptance_passed=False,
                      full_acceptance_passed=False, real_node_passed=False)
    proxy = bridge = wrapper = api = None
    handles, safe = [], True
    udp_before = list(udp.received)
    host_fixtures.accepted.clear()
    deadline = deadline or time.monotonic() + 115
    executor = executor if executor is not None else root / "bin/windows-amd64/wxc-exec.exe"
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
        if wire is not None:
            config.update(wire_probes=wire.for_variant(name), wire_script=str(ROOT / ".github/windows_wire_probe.py"))
        if dns is not None:
            config["native_dns"] = dns.actor_config(profile)
        if bridge is not None:
            config.update(bridge_directory=str(bridge.directory), bridge_nonce=bridge.nonce)
        write_json(config_path, config)
        command = [sys.executable, "-I", "-S", "-X", "utf8", str(actor_file), "--actor", str(config_path), "--role", "parent"]
        policy = runtime.build_policy(command, {}, profile, endpoint)
        policy["process"]["commandLine"] = subprocess.list2cmdline(command)
        policy["process"]["timeout"] = 100000
        policy["filesystem"]["readonlyPaths"] = sorted(set(policy["filesystem"]["readonlyPaths"]) | {str(root), str(pipe_script.parent)})
        policy.update(network_policy(name, endpoint, proxy.port, singleton_port_range=singleton_port_range,
                                     ingress_default_allow_control=ingress_default_allow_control))
        if psec_1_1_diagnostic:
            add_psec_1_1_diagnostic_path(policy, profile)
            result["psec_1_1_diagnostic"] = {"requested": True,
                "request_mechanism": "filesystem_enumerate_paths", "kernel_contract_version_confirmed": False,
                "acceptance_passed": False}
        result["policy"] = policy
        try:
            result["probe"] = runtime._probe_request(str(executor), policy)
        except runtime.UnsupportedRuntimeError as exc:
            result.update(status="failed" if psec_1_1_diagnostic else "unsupported", detail=str(exc)[:700])
            return result
        if psec_1_1_diagnostic:
            probes = result["probe"].get("probes") if isinstance(result["probe"], dict) else None
            if not isinstance(probes, dict) or probes.get("baseContainerSupportsEnumeratePaths") is not True:
                result.update(status="failed", detail="PSEC 1.1 diagnostic feature support was not confirmed")
                result["psec_1_1_diagnostic"]["feature_supported"] = False
                return result
            result["psec_1_1_diagnostic"]["feature_supported"] = True
        actor_budget = min(ACTOR_WAIT_SECONDS, deadline - time.monotonic() - 50)
        if actor_budget < 5:
            raise TimeoutError("Matrix budget cannot safely start another contained actor")
        if dns is not None:
            # One Windows monotonic clock is shared across these processes.
            # Leave two seconds to publish/read both actors' bounded reports.
            config["native_dns"]["deadline"] = time.monotonic() + actor_budget - 2
            write_json(config_path, config)
        policy_file = profile / "policy.json"
        write_json(policy_file, policy)
        with (profile / "actor.log").open("wb") as output:
            wrapper = subprocess.Popen([str(executor), "--config", str(policy_file)],
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT, shell=False)
            result.update(process_started=True, no_process_started=False, descendant_cleanup_proven=False)
            reports = wait_actor_reports(profile, wrapper, "initial", timeout=actor_budget)
            result["actors"] = reports
            result["actor_attestation"] = {}
            api, handles = retain_actor_handles(runtime, wrapper, reports, result["actor_attestation"],
                                                console_trust=console_trust)
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


def record_unselected_wire_probes(wire, unselected):
    """Keep the complete fixed manifest with explicit non-execution facts."""
    for name in unselected:
        wire.execution.extend({"id": probe["id"], "role": probe["role"], "attempted": False,
            "bind_attempted": False, "bind_succeeded": False, "send_attempted": False,
            "api_accepted": False, "errno": None} for probe in wire.for_variant(name))


def add_psec_1_1_diagnostic_path(policy, profile):
    """Request the SDK's 1.1 enumerate-path feature without broadening access."""
    profile = Path(profile).resolve(strict=True)
    filesystem = policy.get("filesystem")
    readwrite = filesystem.get("readwritePaths") if isinstance(filesystem, dict) else None
    if not isinstance(readwrite, list):
        raise RuntimeError("PSEC 1.1 diagnostic requires a verified writable profile")
    profile_text = str(profile)
    if profile_text not in readwrite:
        raise RuntimeError("PSEC 1.1 diagnostic profile is not an exact read-write grant")
    child = profile / ".psec-enumerate-path-diagnostic"
    child.mkdir()
    if any(child.iterdir()):
        raise RuntimeError("PSEC 1.1 diagnostic directory must be empty")
    process_container = policy.setdefault("processContainer", {})
    if not isinstance(process_container, dict):
        raise RuntimeError("PSEC 1.1 diagnostic process container is malformed")
    container_fs = process_container.setdefault("filesystem", {})
    if not isinstance(container_fs, dict) or container_fs.get("enumeratePaths"):
        raise RuntimeError("PSEC 1.1 diagnostic filesystem request is ambiguous")
    container_fs["enumeratePaths"] = [str(child)]


def pre_capture_candidate_probe(runtime, executor, metadata, directory, *, psec_1_1_diagnostic=False,
                                ingress_default_allow_control=False):
    """Warm the explicitly selected source-only executor outside any wire capture."""
    record = {"status": "failed", "scope": ("source_only_private_network_ingress_control_probe"
            if ingress_default_allow_control else "source_only_strict_policy_probe"),
              "warmup_before_capture": True, "acceptance_passed": False,
              "executor_sha256": metadata.get("executor_sha256") if isinstance(metadata, dict) else None}
    if ingress_default_allow_control:
        record.update(source_policy_variant="private_network_capability_control",
                      ingress_control={"default": "allow", "hostLoopback": "deny"},
                      production_policy_unchanged=True)
    if psec_1_1_diagnostic:
        record.update(psec_1_1_diagnostic_requested=True, request_mechanism="filesystem_enumerate_paths",
                      kernel_contract_version_confirmed=False)
    try:
        profile = directory / "candidate-prewarm"
        profile.mkdir()
        port = runtime.choose_guest_port(1)
        harmless_command = [sys.executable, "-I", "-S", "-c", "pass"]
        policy = runtime.build_policy(harmless_command, {}, profile, port)
        policy.update(network_policy(PREFERRED_VARIANT, port, port,
                                     ingress_default_allow_control=ingress_default_allow_control))
        if psec_1_1_diagnostic:
            add_psec_1_1_diagnostic_path(policy, profile)
        observed = runtime._probe_request(str(executor), policy)
        probes = observed.get("probes") if isinstance(observed, dict) else None
        if (not isinstance(observed, dict) or observed.get("tier") != "base-container"
                or not isinstance(probes, dict) or probes.get("baseContainerApiPresent") is not True
                or observed.get("needsDaclAugmentation") is not False):
            raise RuntimeError("strict backend confirmation was incomplete")
        if psec_1_1_diagnostic and probes.get("baseContainerSupportsEnumeratePaths") is not True:
            raise RuntimeError("PSEC 1.1 diagnostic feature support was not confirmed")
        record.update(status="probe_passed", backend_confirmation={
            "tier": "base-container", "base_container_api_present": True,
            "needs_dacl_augmentation": False})
        if psec_1_1_diagnostic:
            record["feature_supported"] = True
    except Exception as exc:
        record["failure_type"] = type(exc).__name__[:64]
        error = RuntimeError("Source-only candidate pre-capture strict probe failed")
        error.candidate_precapture_probe = record
        raise error from None
    return record


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--allow-emulated-x64", action="store_true")
    parser.add_argument("--vm-config", type=Path)
    parser.add_argument("--test-psec-executor", type=Path)
    parser.add_argument("--test-psec-manifest", type=Path)
    parser.add_argument("--collect-native-dns", action="store_true")
    parser.add_argument("--preferred-policy-only", action="store_true",
                        help="Observe only the fixed production-policy candidate; keep other policies unselected")
    parser.add_argument("--psec-1-1-diagnostic", action="store_true",
                        help="Diagnostic-only: request the BaseContainer enumerate-path contract selector")
    parser.add_argument("--singleton-port-range", action="store_true",
                        help="Diagnostic-only: encode the MODEL1 TCP port as equal port/endPort bounds")
    parser.add_argument("--ingress-controls-diagnostic", action="store_true",
                        help="Source-only G2 control: set ingress.default=allow and keep hostLoopback=deny")
    args = parser.parse_args(arguments)
    ingress_cli_invalid = args.ingress_controls_diagnostic and (
            args.test_psec_executor is None or args.test_psec_manifest is None
            or not args.preferred_policy_only or not args.psec_1_1_diagnostic
            or args.singleton_port_range or not args.collect_native_dns)
    selected = ((PREFERRED_VARIANT,) if args.ingress_controls_diagnostic else
                (("model3", PREFERRED_VARIANT) if args.psec_1_1_diagnostic and args.preferred_policy_only
                 else ((PREFERRED_VARIANT,) if args.preferred_policy_only else VARIANTS)))
    unselected = tuple(name for name in VARIANTS if name not in selected)
    args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
    result = {"status": "failed", "full_acceptance_passed": False, "acceptance_passed": False,
              "real_node_passed": False, "product_provider_changed": False, "cleanup_proven": False,
              "diagnostic_port_encoding": "singleton_range" if args.singleton_port_range else "single_port",
              "variants": [], "checks": [],
              "policy_selection": ("private_network_ingress_control" if args.ingress_controls_diagnostic else
                                   ("psec_1_1_diagnostic_pair" if args.psec_1_1_diagnostic and args.preferred_policy_only
                                    else ("preferred_only" if args.preferred_policy_only else "all_fixed"))),
              "psec_1_1_diagnostic_requested": args.psec_1_1_diagnostic,
              "psec_1_1_kernel_contract_confirmed": False,
              "ingress_controls_diagnostic_requested": args.ingress_controls_diagnostic,
              "selected_variants": list(selected),
              "unselected_variants": [{"name": name, "status": "unselected", "process_started": False,
                                       "no_process_started": True} for name in unselected]}
    if args.ingress_controls_diagnostic:
        result.update(source_policy_variant="private_network_capability_control",
                      ingress_control={"default": "allow", "hostLoopback": "deny"},
                      production_policy_unchanged=True, full_acceptance_passed=False,
                      acceptance_passed=False, real_node_passed=False)
    directory = fixtures = udp = wire = dns = console_trust = None
    safe = True
    code = 1
    before = None
    phase_deadline = time.monotonic() + MATRIX_PHASE_SECONDS
    try:
        if ingress_cli_invalid:
            raise ValueError("--ingress-controls-diagnostic requires paired test executor/manifest, "
                             "--preferred-policy-only, --psec-1-1-diagnostic, and --collect-native-dns; "
                             "it cannot use --singleton-port-range")
        if args.singleton_port_range and (args.test_psec_executor is not None or args.test_psec_manifest is not None):
            raise ValueError("Singleton-range diagnostic cannot be combined with a custom test executor")
        helpers = load_helpers()
        if (args.test_psec_executor is None) != (args.test_psec_manifest is None):
            raise ValueError("Test PSEC executor and manifest must be provided together")
        root = args.root.resolve(strict=True)
        runtime, _, _ = import_project(root)
        helpers.verify_project_origin(root)
        digests = helpers.verify_runtime_manifest(root)
        result["runtime_integrity"] = {"verified_file_count": len(digests)}
        executor = None
        if args.test_psec_executor is not None:
            executor, result["test_psec_executor"] = verify_test_executor(root, args.test_psec_executor,
                args.test_psec_manifest, digests.get("wxc-exec.exe"),
                ingress_controls_diagnostic=args.ingress_controls_diagnostic)
        result["host"] = helpers.host_facts()
        host = result["host"]
        if host.get("python_pe_machine") != 0x8664 or (host.get("native_machine") != 0x8664 and not (
            args.allow_emulated_x64 and host.get("native_machine") == 0xAA64)):
            raise RuntimeError("Native x64 Windows or explicitly allowed x64-on-ARM execution is required")
        if args.collect_native_dns and (host.get("platform") != "win32"
                or host.get("windows_product_type") != 1
                or type(host.get("windows_build")) is not int or host["windows_build"] < 22000):
            raise RuntimeError("Explicit native DNS diagnostics require an observed Windows 11 client")
        pipe_script = ROOT / ".github/windows_named_pipe_probe.py"
        if not pipe_script.is_file():
            raise RuntimeError("Named-pipe experiment script is missing")
        before = helpers.network_snapshot()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-network-experiment-"))
        if executor is not None:
            try:
                result["candidate_precapture_probe"] = pre_capture_candidate_probe(runtime, executor,
                    result.get("test_psec_executor"), directory,
                    psec_1_1_diagnostic=args.psec_1_1_diagnostic,
                    ingress_default_allow_control=args.ingress_controls_diagnostic)
            except Exception as exc:
                result["candidate_precapture_probe"] = getattr(exc, "candidate_precapture_probe", {
                    "status": "failed", "scope": ("source_only_private_network_ingress_control_probe"
                        if args.ingress_controls_diagnostic else "source_only_strict_policy_probe"),
                    "warmup_before_capture": True, "acceptance_passed": False,
                    "failure_type": type(exc).__name__[:64]})
                raise
        fixtures, udp = helpers.HostFixtures(), DatagramObservers()
        if args.vm_config is not None:
            # Trust verification may retrieve certificate/catalog data. Keep
            # that unchanged check outside the NIC capture, and hold its file
            # identity for every later helper binding check.
            console_trust = SystemConsoleTrustCache()
            console_trust.prepare()
            wire = load_wire_helpers(ROOT / ".github/windows_wire_probe.py").WireSession(args.vm_config, VARIANTS)
            console_trust.before_capture()
            wire.start()
            record_unselected_wire_probes(wire, unselected)
        if args.collect_native_dns or (wire is not None and host.get("native_machine") == 0x8664):
            dns = load_dns_session().DnsSession(directory / "native-dns-controls", phase_deadline)
            result["native_dns_scope"] = {"host_acceptance_scope": host.get("acceptance_scope"),
                "explicitly_requested": args.collect_native_dns, "wire_capture_available": wire is not None,
                "wire_observed": None if wire is not None else False,
                "default_system_server_list": True, "kernel_denial_proven": False, "acceptance_passed": False}
        for name in selected:
            if phase_deadline - time.monotonic() < 30:
                raise TimeoutError("Matrix budget was exhausted before the next experiment")
            if wire is not None:
                wire.control(name, "outside_before")
            preferred_dns = dns is not None and name == PREFERRED_VARIANT
            if preferred_dns:
                control = dns.control("outside_before", phase_deadline - 130)
                result["native_dns_controls"] = dns.controls
                if pending_recovery(control):
                    safe = False
                    result.update(cleanup_error="NativeDnsControlCleanupUnproven", recovery_directory=str(directory))
                    break
            variant = run_variant(name, directory / name, root, runtime, helpers, fixtures, udp, pipe_script,
                                  deadline=phase_deadline, **({"wire": wire} if wire is not None else {}),
                                  **({"dns": dns} if preferred_dns else {}),
                                  **({"console_trust": console_trust} if console_trust is not None else {}),
                                  **({"executor": executor} if executor is not None else {}),
                                  **({"singleton_port_range": True} if args.singleton_port_range else {}),
                                  **({"psec_1_1_diagnostic": True} if args.psec_1_1_diagnostic else {}),
                                  **({"ingress_default_allow_control": True}
                                     if args.ingress_controls_diagnostic else {}))
            if args.ingress_controls_diagnostic:
                variant.update(source_policy_variant="private_network_capability_control",
                               ingress_control={"default": "allow", "hostLoopback": "deny"},
                               production_policy_unchanged=True, acceptance_passed=False,
                               full_acceptance_passed=False, real_node_passed=False)
            result["variants"].append(variant)
            if wire is not None:
                wire.actors(variant)
            if preferred_dns:
                dns.actors(variant)
                if not pending_recovery(variant) and dns.safe:
                    dns.control("outside_after", phase_deadline - 50)
            if wire is not None:
                if not pending_recovery(variant) and (dns is None or dns.safe):
                    wire.control(name, "outside_after")
            if pending_recovery(variant) or (dns is not None and not dns.safe):
                safe = False
                result.update(cleanup_error=variant.get("cleanup_error", "NestedRecoveryPending"),
                              recovery_directory=str(directory))
                break
        if safe and len(result["variants"]) == len(selected) and all(
            variant["status"] in ("observed", "unsupported") for variant in result["variants"]
        ):
            result["status"], code = "experiment_only", 0
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}: {exc}"[:700]
    finally:
        if dns is not None:
            if wire is not None:
                payload = dns.finish_payload()
                if console_trust is not None and console_trust.contaminated:
                    # Preserve packet/API counters, but revoke the same actor
                    # identity claim for both raw UDP and optional DNS groups.
                    payload = {**payload, "actor_execution_attested": False}
                wire.dns_observation = payload
            recovery = dns.close()
            if recovery:
                safe = False
                result.update(status="failed", cleanup_error=recovery["cleanup_error"],
                              recovery_directory=str(directory), cleanup_proven=False)
                code = 1
        if wire is not None:
            try:
                if console_trust is not None and console_trust.contaminated:
                    wire.attested = False
                    result.update(status="failed", signature_binding_error="SystemConsoleChangedDuringCapture")
                    code = 1
                result["wire_observation"] = wire.finish()
            except Exception as exc:
                result.update(status="failed", wire_error=type(exc).__name__)
                code = 1
        if console_trust is not None:
            try:
                console_trust.close()
            except Exception:
                safe = False
                result.update(status="failed", cleanup_error="SystemConsoleTrustHandleCloseFailed",
                              recovery_directory=str(directory), cleanup_proven=False)
                code = 1
            result["system_console_signature_preflight"] = console_trust.summary()
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
