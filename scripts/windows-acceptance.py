"""Run real Windows PSEC acceptance, without changing host network settings.

Examples (use the package's x64 Python when testing a portable package):
  python scripts/windows-acceptance.py --probe-only
  python scripts/windows-acceptance.py --transport-fixture --allow-emulated-x64
  python scripts/windows-acceptance.py --manager-fixture --allow-emulated-x64
  python scripts/windows-acceptance.py --yaml C:\\private\\proxy.yaml

Real-node functionality checks need a working real proxy node. Full security
acceptance additionally needs separate external UDP and native DNS evidence;
this script does not produce that evidence. The YAML, controller token,
and downloaded page contents are never included in the JSON report. No mock
MXC, DACL fallback, firewall editing, or software VM fallback is used.
The bundled manifest verifies completeness and file integrity, not origin:
verify the release ZIP against its externally obtained checksum beforehand.
--transport-fixture exercises real PSEC with a fixed loopback byte fixture; it
does not verify a real proxy node, HTTPS origin, or Manager core-loss watcher.
--manager-fixture adds real Mihomo/Manager stop and core-loss checks, overriding
only this test's owned-core SOCKS endpoint through the official reload API.
Exit codes: 0 = requested checks passed, 1 = failed, 3 = unsupported host.
A successful --probe-only run explicitly does not pass full acceptance.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse


ROOT = Path(__file__).resolve().parent.parent
_PINS_SPEC = importlib.util.spec_from_file_location(
    "ruleproxy_windows_runtime_pins", ROOT / "ruleproxy" / "windows_runtime_pins.py")
if _PINS_SPEC is None or _PINS_SPEC.loader is None:
    raise RuntimeError("fixed Windows runtime pins module is unavailable")
_PINS = importlib.util.module_from_spec(_PINS_SPEC)
_PINS_SPEC.loader.exec_module(_PINS)
MXC_G_EXECUTOR_SHA256 = _PINS.MXC_G_EXECUTOR_SHA256
MXC_G_LICENSE_SHA256 = _PINS.MXC_G_LICENSE_SHA256

RUNTIME_VERSIONS = _PINS.expected_windows_record()
RUNTIME_REQUIRED_FILES = frozenset({"mihomo.exe", "wxc-exec.exe", "mxc_ffi.dll",
                                    "MIHOMO-LICENSE", "MXC-LICENSE.md"})
NETWORK_SNAPSHOT_TIMEOUT = 120
# Kept standalone for the profile's -I -S child; tested against windows_guest.
# Fixed DNS query: ruleproxy.invalid IN A, recursion disabled, no user data.
_UDP_PROBE_DATAGRAM = (
    b"\x52\x50\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x09ruleproxy\x07invalid\x00\x00\x01\x00\x01"
)


def verify_runtime_manifest(root: Path) -> dict[str, str]:
    """Check a source checkout or portable package without builder imports.

    Version labels and every flat-directory file digest must match the local
    manifest. An attacker replacing files and their manifest is outside this
    integrity check; the downloaded ZIP's external checksum establishes origin.
    """
    directory = root / "bin" / "windows-amd64"
    manifest = directory / "runtime.json"
    with manifest.open("rb") as stream:
        raw = stream.read(64 * 1024 + 1)
    if not raw or len(raw) > 64 * 1024:
        raise ValueError("runtime manifest has an invalid size")
    record = json.loads(raw.decode("utf-8"))
    if not isinstance(record, dict) or set(record) != {*RUNTIME_VERSIONS, "sha256"}:
        raise ValueError("runtime manifest fields are invalid")
    if any(record[name] != version for name, version in RUNTIME_VERSIONS.items()):
        raise ValueError("runtime manifest versions do not match this acceptance script")
    digests = record["sha256"]
    if not isinstance(digests, dict) or not 1 <= len(digests) <= 64:
        raise ValueError("runtime manifest digest map is invalid")
    if not RUNTIME_REQUIRED_FILES.issubset(digests):
        raise ValueError("runtime manifest omitted required runtime files")
    if (digests.get("wxc-exec.exe") != MXC_G_EXECUTOR_SHA256
            or digests.get("MXC-LICENSE.md") != MXC_G_LICENSE_SHA256):
        raise ValueError("runtime manifest does not identify the fixed G executor and license")
    for name, digest in digests.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", name)
                or name == "runtime.json" or not isinstance(digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("runtime manifest contains an invalid file name or SHA-256")
    if {item.name for item in directory.iterdir()} != {*digests, "runtime.json"}:
        raise ValueError("runtime directory contains missing or unlisted entries")
    for name in (*digests, "runtime.json"):
        path = directory / name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or not info.st_size
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("runtime files must be nonempty ordinary files without reparse points")
        if name == "runtime.json":
            continue
        actual = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                actual.update(block)
        if actual.hexdigest() != digests[name]:
            raise ValueError("runtime file SHA-256 did not match the manifest")
    return dict(digests)


def verify_project_origin(root: Path) -> None:
    """Refuse a previously imported checkout when --root names another one."""
    import ruleproxy
    package = (root / "ruleproxy").resolve(strict=True)
    if Path(ruleproxy.__file__).resolve(strict=True) != package / "__init__.py":
        raise ValueError("imported ruleproxy package does not belong to --root")
    if {Path(item).resolve(strict=True) for item in ruleproxy.__path__} != {package}:
        raise ValueError("imported ruleproxy package search path does not belong to --root")
    for name, module in tuple(sys.modules.items()):
        if name.startswith("ruleproxy.") and getattr(module, "__file__", None):
            try:
                Path(module.__file__).resolve(strict=True).relative_to(package)
            except ValueError as exc:
                raise ValueError("a loaded ruleproxy module does not belong to --root") from exc


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
    os.replace(temporary, path)


def strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError("acceptance report contained a duplicate field")
        result[key] = value
    return result


def check_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("acceptance URL must be an HTTPS URL without credentials")
    if parsed.port not in (None, 443) or parsed.fragment or any(c in value for c in "\r\n\0"):
        raise ValueError("acceptance URL must use port 443 without a fragment or control characters")
    host = parsed.hostname
    try:
        if not ipaddress.ip_address(host).is_global:
            raise ValueError("acceptance URL must have a public destination")
    except ValueError as exc:
        if "public destination" in str(exc):
            raise
        if "." not in host or host.endswith((".local", ".localhost", ".home.arpa")):
            raise ValueError("acceptance URL must have a public hostname") from exc
    return value


def denied(family: int, kind: int, address: tuple, name: str) -> dict:
    try:
        with socket.socket(family, kind) as connection:
            connection.settimeout(2)
            if kind == socket.SOCK_DGRAM:
                if connection.sendto(_UDP_PROBE_DATAGRAM, address) != len(_UDP_PROBE_DATAGRAM):
                    raise RuntimeError(f"{name}: UDP probe did not send its complete fixed datagram")
            else:
                connection.connect(address)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code != 10013:
            # Unreachable destinations and missing IPv6 are not policy evidence.
            raise RuntimeError(f"{name}: expected WSAEACCES 10013, got {code}") from exc
        return {"check": name, "status": "passed", "socket_error": code}
    raise RuntimeError(f"{name}: direct socket unexpectedly succeeded")


def proxy_https(url: str) -> dict:
    parsed = urllib.parse.urlsplit(check_url(url))
    proxy = urllib.parse.urlsplit(os.environ["HTTPS_PROXY"])
    if proxy.scheme != "http" or proxy.hostname != "127.0.0.1" or not proxy.port:
        raise RuntimeError("application proxy is not the prepared guest loopback endpoint")
    connection = http.client.HTTPSConnection(proxy.hostname, proxy.port, timeout=25,
                                              context=ssl.create_default_context())
    # HTTPSConnection uses CONNECT, then verifies the origin's TLS certificate.
    connection.set_tunnel(parsed.hostname, 443)
    try:
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.request("GET", path, headers={"Host": parsed.hostname,
                                                 "Connection": "close"})
        response = connection.getresponse()
        body = response.read(1024 * 1024 + 1)
        if response.status != 200 or not body or len(body) > 1024 * 1024:
            raise RuntimeError("real proxy HTTPS request did not return a bounded HTTP 200 body")
        return {"check": "real_proxy_https", "status": "passed", "http_status": 200,
                "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()}
    finally:
        connection.close()


def guest_host_ipv6_unavailable() -> bool:
    """Read only the runtime-forced config path, never the writable profile."""
    configured = os.environ.get("RULEPROXY_RUNTIME_CONFIG")
    if not configured:
        return False  # No trusted availability fact: keep the strict rule.
    path = Path(configured)
    with path.open("rb") as stream:
        raw = stream.read(128 * 1024 + 1)
    if not raw or len(raw) > 128 * 1024:
        raise RuntimeError("runtime readonly config had an invalid size")
    value = json.loads(raw, object_pairs_hook=strict_json_object)
    required = {"schema_version", "command", "env", "profile", "listener_port", "bridge_directory",
                "bridge_nonce", "host_fixture_port", "host_udp_ports", "host_ipv6_route_unavailable"}
    if (not isinstance(value, dict) or set(value) != required or type(value["schema_version"]) is not int
            or value["schema_version"] != 1 or type(value["host_ipv6_route_unavailable"]) is not bool
            or not isinstance(value["bridge_nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["bridge_nonce"])):
        raise RuntimeError("runtime readonly availability config was invalid")
    if not isinstance(value["profile"], str) or Path(value["profile"]).resolve() != Path.cwd().resolve():
        raise RuntimeError("runtime readonly availability config belonged to another profile")
    try:
        path.resolve().parent.relative_to(Path(value["profile"]).resolve())
    except ValueError:
        pass
    else:
        raise RuntimeError("runtime availability fact was inside the writable profile")
    return value["host_ipv6_route_unavailable"]


def network_checks(host_v4_port: int, host_v6_port: int, *, host_ipv6_route_unavailable=False) -> list[dict]:
    # The actual application's local IPv6 TCP check must still return 10013.
    first = denied(socket.AF_INET, socket.SOCK_STREAM, ("1.1.1.1", 443), "direct_ipv4_tcp")
    local = [denied(socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", host_v4_port), "guest_to_host_ipv4"),
             denied(socket.AF_INET6, socket.SOCK_STREAM, ("::1", host_v6_port, 0, 0), "guest_to_host_ipv6")]
    try:
        ipv6 = denied(socket.AF_INET6, socket.SOCK_STREAM, ("2606:4700:4700::1111", 443, 0, 0), "direct_ipv6_tcp")
    except RuntimeError as exc:
        original = exc.__cause__
        code = (getattr(original, "winerror", None) or original.errno) if isinstance(original, OSError) else None
        if host_ipv6_route_unavailable is not True or code != 10051:
            raise
        ipv6 = {"check": "direct_ipv6_tcp", "status": "unavailable", "socket_error": 10051, "ok": False}
    return [first, ipv6, *local]


def public_udp_diagnostics() -> dict:
    """Preserve sendto API results without claiming delivery or DNS isolation."""
    results = {}
    for name, family, address in (("ipv4_udp", socket.AF_INET, ("1.1.1.1", 53)),
                                  ("ipv6_udp", socket.AF_INET6, ("2606:4700:4700::1111", 53, 0, 0))):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sender:
                sender.settimeout(2)
                count = sender.sendto(_UDP_PROBE_DATAGRAM, address)
            code = "allowed" if count == len(_UDP_PROBE_DATAGRAM) else "short_send"
        except OSError as exc:
            code = getattr(exc, "winerror", None) or exc.errno
            if code is None:
                code = "timeout" if isinstance(exc, TimeoutError) else "io"
        except Exception:
            code = "error"
        results[name] = {"ok": code == 10013, "code": code}
    return results


def startup_evidence(resources) -> dict:
    """Copy the host's validated startup records before resources are released."""
    from ruleproxy import windows_guest
    report = copy.deepcopy(getattr(resources, "startup_diagnostics", None))
    observed = copy.deepcopy(getattr(resources, "udp_observation", None))
    route = copy.deepcopy(getattr(resources, "host_ipv6_observation", None))
    if (not isinstance(route, dict) or set(route) != {"scope", "host_ipv6_route_unavailable", "code", "kernel_denial_proven"}
            or route["scope"] != "fixed_ipv6_tcp_route_probe" or route["kernel_denial_proven"] is not False
            or type(route["host_ipv6_route_unavailable"]) is not bool
            or not ((type(route["code"]) is int and -65536 <= route["code"] <= 65536)
                    or (type(route["code"]) is str and route["code"] in {"connected", "timeout", "io"}))
            or (route["host_ipv6_route_unavailable"] and (type(route["code"]) is not int or route["code"] != 10051))):
        raise RuntimeError("runtime did not retain its actual host IPv6 observation")
    if not isinstance(report, dict):
        raise RuntimeError("runtime did not retain its actual startup diagnostic")
    windows_guest._validate_startup_report(report, report.get("nonce"))
    if not windows_guest._startup_checks_passed(report, host_ipv6_route_unavailable=route["host_ipv6_route_unavailable"]):
        raise RuntimeError("runtime did not establish its mandatory startup checks")
    if (not isinstance(observed, dict) or observed.get("scope") != "fixed_host_loopback_endpoints"
            or observed.get("non_delivery_observed") is not True
            or any(observed.get(key) is not False for key in ("kernel_denial_proven", "public_udp_proven", "dns_proven"))
            or not isinstance(observed.get("observations"), dict)
            or set(observed["observations"]) != {"ipv4", "ipv6"}):
        raise RuntimeError("runtime did not retain its scoped host UDP observation")
    for value in observed["observations"].values():
        if (not isinstance(value, dict) or set(value) != {"before_received", "after_received", "parent_received", "child_received"}
                or any(type(count) is not int for count in value.values())
                or value["before_received"] < 1 or value["after_received"] < 1
                or value["parent_received"] != 0 or value["child_received"] != 0):
            raise RuntimeError("runtime host UDP controls or zero counts were incomplete")
    report["nonce_sha256"] = hashlib.sha256(bytes.fromhex(report.pop("nonce"))).hexdigest()
    return {"startup_diagnostics": report, "host_udp_observation": observed, "host_ipv6_observation": route,
            "public_udp_proven": False, "system_dns_proven": False}


def fixture_payload(token: str) -> bytes:
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("invalid transport fixture token")
    # More than four production 16 KiB frames, with a recognizable per-run tag.
    return token.encode("ascii") + b":" + bytes(index % 251 for index in range(65573))


def fixture_destination(token: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("invalid transport fixture token")
    return f"m{token[:30]}.ruleproxy-acceptance.invalid"


def validate_connect_response(response: bytes) -> None:
    """Accept a bounded HTTP CONNECT 200, independent of its reason phrase."""
    if len(response) > 4096 or not response.endswith(b"\r\n\r\n"):
        raise RuntimeError("CONNECT response headers were incomplete or exceeded their limit")
    status_line = response.split(b"\r\n", 1)[0].split(b" ", 2)
    if len(status_line) < 2 or status_line[0] not in (b"HTTP/1.0", b"HTTP/1.1") or status_line[1] != b"200":
        raise RuntimeError("fixed loopback transport did not acknowledge CONNECT with HTTP 200")


def fixture_roundtrip(token: str, host: str = "ruleproxy-acceptance.invalid") -> dict:
    proxy = urllib.parse.urlsplit(os.environ["HTTPS_PROXY"])
    if proxy.scheme != "http" or proxy.hostname != "127.0.0.1" or not proxy.port:
        raise RuntimeError("transport proxy is not the prepared guest loopback endpoint")
    payload = fixture_payload(token)
    if host not in ("ruleproxy-acceptance.invalid", fixture_destination(token)):
        raise ValueError("transport destination is not the fixed fixture hostname")
    with socket.create_connection((proxy.hostname, proxy.port), timeout=5) as connection:
        connection.settimeout(20)
        connection.sendall((f"CONNECT {host}:443 HTTP/1.1\r\n"
                            f"X-RuleProxy-Fixture: {token}\r\n\r\n").encode("ascii"))
        response = bytearray()
        while not response.endswith(b"\r\n\r\n") and len(response) <= 4096:
            part = connection.recv(1)
            if not part:
                break
            response.extend(part)
        validate_connect_response(bytes(response))
        connection.sendall(payload)
        connection.shutdown(socket.SHUT_WR)
        echoed = bytearray()
        while len(echoed) <= len(payload):
            part = connection.recv(16384)
            if not part:
                break
            echoed.extend(part)
        if bytes(echoed) != payload[::-1]:
            raise RuntimeError("cross-frame payload or bidirectional FIN did not survive the file bridge")
    return {"check": "fixed_loopback_transport_cross_frame_fin", "status": "passed",
            "payload_bytes_each_direction": len(payload), "bidirectional_fin": True,
            "real_node_passed": False, "https_origin_verified": False}


def fixture_failure_checks(args) -> dict:
    checks = network_checks(args.host_v4_port, args.host_v6_port,
                            host_ipv6_route_unavailable=guest_host_ipv6_unavailable())
    try:
        fixture_roundtrip(args.fixture_token, args.fixture_host)
    except (OSError, RuntimeError):
        checks.append({"check": "proxy_fails_after_fixture_loss", "status": "passed"})
    else:
        raise RuntimeError("proxy transport succeeded after its fixed host endpoint closed")
    return {"role": args.role, "pid": os.getpid(), "parent_pid": os.getppid(), "run_token": args.run_token,
            "status": "passed", "checks": checks, "public_udp": public_udp_diagnostics()}


def guest_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=("parent", "child"), required=True)
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--url")
    transport.add_argument("--fixture-token")
    parser.add_argument("--fixture-host", default="ruleproxy-acceptance.invalid")
    parser.add_argument("--host-v4-port", type=int, required=True)
    parser.add_argument("--host-v6-port", type=int, required=True)
    parser.add_argument("--run-token", required=True)
    args = parser.parse_args(arguments)
    if not re.fullmatch(r"[0-9a-f]{64}", args.run_token):
        return 64
    report = {"role": args.role, "pid": os.getpid(), "parent_pid": os.getppid(), "run_token": args.run_token}
    listeners = []
    child = None
    try:
        for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            listener = socket.socket(family, socket.SOCK_STREAM)
            listeners.append(listener)
            listener.bind((host, 0))
            listener.listen(4)
        checks = network_checks(args.host_v4_port, args.host_v6_port,
                                host_ipv6_route_unavailable=guest_host_ipv6_unavailable())
        checks.append(fixture_roundtrip(args.fixture_token, args.fixture_host)
                      if args.fixture_token else proxy_https(args.url))
        report.update(status="passed", checks=checks,
                      listeners=[int(item.getsockname()[1]) for item in listeners],
                      public_udp=public_udp_diagnostics())
        write_json(Path(f"acceptance-{args.role}.json"), report)
        if args.role == "parent":
            transport_args = (["--fixture-token", args.fixture_token, "--fixture-host", args.fixture_host] if args.fixture_token
                              else ["--url", args.url])
            child = subprocess.Popen([sys.executable, "-I", "-S", "-X", "utf8", __file__,
                                      "--guest", "--role", "child", *transport_args,
                                      "--host-v4-port", str(args.host_v4_port),
                                      "--host-v6-port", str(args.host_v6_port), "--run-token", args.run_token],
                                     stdin=subprocess.DEVNULL, shell=False, close_fds=True)
        # Keep both generations and their listeners alive until the product
        # stops their owning PSEC workload. Do not self-clean the test child.
        loss_checked = False
        while True:
            if child is not None and child.poll() is not None:
                raise RuntimeError("acceptance descendant exited before lifecycle check")
            if args.fixture_token and not loss_checked:
                try:
                    raw = Path("acceptance-control.json").read_bytes()
                    if len(raw) > 1024:
                        raise RuntimeError("transport control record exceeded its size limit")
                    control = json.loads(raw)
                except (FileNotFoundError, json.JSONDecodeError):
                    control = None
                if control == {"token": args.fixture_token, "state": "fixture_stopped"}:
                    try:
                        lost = fixture_failure_checks(args)
                    except Exception as exc:
                        lost = {"role": args.role, "status": "failed", "error": str(exc)[:700]}
                    write_json(Path(f"acceptance-lost-{args.role}.json"), lost)
                    loss_checked = True
            time.sleep(0.2)
    except Exception as exc:
        report.update(status="failed", error=f"{type(exc).__name__}: {exc}"[:700])
        write_json(Path(f"acceptance-{args.role}.json"), report)
        return 1
    finally:
        for listener in listeners:
            listener.close()


def executable_machine(path: Path) -> int:
    """Read the executable's PE COFF architecture, including x64-on-ARM.

    IsWow64Process2 can report processMachine=UNKNOWN for translated x64 Python
    on Windows ARM64. The executable's own Machine field remains authoritative
    for which Python binary the acceptance run is actually exercising.
    """
    with path.open("rb") as stream:
        dos = stream.read(64)
        if len(dos) != 64 or dos[:2] != b"MZ":
            raise ValueError("executable does not have a DOS/PE header")
        offset = struct.unpack_from("<I", dos, 60)[0]
        if not 64 <= offset <= 16 * 1024 * 1024:
            raise ValueError("executable has an invalid PE header offset")
        stream.seek(offset)
        coff = stream.read(6)
    if len(coff) != 6 or coff[:4] != b"PE\0\0":
        raise ValueError("executable has an invalid PE signature")
    return struct.unpack_from("<H", coff, 4)[0]


def acceptance_scope(native_machine: int, python_machine: int) -> str:
    if native_machine == 0x8664 and python_machine == 0x8664:
        return "native_x64"
    if native_machine == 0xAA64 and python_machine == 0x8664:
        return "x64_on_arm_emulation"
    if native_machine == 0xAA64 and python_machine == 0xAA64:
        return "native_arm64_probe"
    return "other_windows_architecture"


def host_facts() -> dict:
    facts = {"platform": sys.platform, "python_architecture": platform.machine(),
             "pointer_bits": struct.calcsize("P") * 8}
    if sys.platform != "win32":
        return facts
    import ctypes
    from ctypes import wintypes
    current = sys.getwindowsversion()
    facts.update(windows_build=current.build, windows_product_type=current.product_type)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.IsWow64Process2.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.USHORT),
                                     ctypes.POINTER(wintypes.USHORT)]
    kernel.IsWow64Process2.restype = wintypes.BOOL
    process_machine, native_machine = wintypes.USHORT(), wintypes.USHORT()
    if not kernel.IsWow64Process2(kernel.GetCurrentProcess(), ctypes.byref(process_machine),
                                ctypes.byref(native_machine)):
        raise ctypes.WinError(ctypes.get_last_error())
    python_machine = executable_machine(Path(sys.executable))
    facts.update(process_machine=process_machine.value, native_machine=native_machine.value,
                 python_pe_machine=python_machine)
    facts["acceptance_scope"] = acceptance_scope(native_machine.value, python_machine)
    return facts


def select_powershell(native_machine: int) -> tuple[Path, int]:
    """Prefer a native system interpreter over an emulated PATH executable."""
    system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR")
    if not system_root:
        raise RuntimeError("Windows system directory is unavailable for the network snapshot")
    root = Path(system_root)
    native_types = {native_machine}
    if native_machine == 0xAA64:
        native_types.update((0xA641, 0xA64E))  # ARM64EC / ARM64X system binaries.
    found = []
    for folder in ("Sysnative", "System32"):
        candidate = root / folder / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if candidate.is_file():
            machine = executable_machine(candidate)
            if machine in native_types:
                return candidate, machine
            found.append((candidate, machine))
    if found:
        # Older images may ship only an emulated Windows PowerShell. Keep the
        # system-owned executable and explicitly record its architecture.
        return found[0]
    raise RuntimeError("system Windows PowerShell is unavailable for the network snapshot")


def snapshot_stage(output) -> str:
    """Extract only our fixed stage markers, never arbitrary process output."""
    if isinstance(output, bytes):
        output = output.decode("utf-8", "replace")
    stages = re.findall(r"^RULEPROXY_SNAPSHOT_STAGE=(proxy|dns|routes|winhttp|serialize)\r?$",
                        output or "", re.MULTILINE)
    return stages[-1] if stages else "startup"


def network_snapshot() -> str:
    # Read stable configuration fields only; leases/lifetimes change naturally.
    script = r'''
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
[Console]::Error.WriteLine('RULEPROXY_SNAPSHOT_STAGE=proxy')
$proxy = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
[Console]::Error.WriteLine('RULEPROXY_SNAPSHOT_STAGE=dns')
$dns = @(Get-DnsClientServerAddress | Sort-Object InterfaceIndex,AddressFamily | ForEach-Object {
    @{index=$_.InterfaceIndex;family=[int]$_.AddressFamily;servers=@($_.ServerAddresses)}
})
[Console]::Error.WriteLine('RULEPROXY_SNAPSHOT_STAGE=routes')
$routes = @(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0') |
    Sort-Object InterfaceIndex,DestinationPrefix,NextHop | ForEach-Object {
        @{index=$_.InterfaceIndex;prefix=$_.DestinationPrefix;next=$_.NextHop;metric=$_.RouteMetric}
    })
[Console]::Error.WriteLine('RULEPROXY_SNAPSHOT_STAGE=winhttp')
$winhttp = (& (Join-Path $env:SystemRoot 'System32\netsh.exe') winhttp show proxy | Out-String)
if ($LASTEXITCODE -ne 0) { throw 'WinHTTP proxy query failed.' }
[Console]::Error.WriteLine('RULEPROXY_SNAPSHOT_STAGE=serialize')
@{dns=$dns;routes=$routes;proxy=@{enable=$proxy.ProxyEnable;server=$proxy.ProxyServer;
override=$proxy.ProxyOverride;pac=$proxy.AutoConfigURL};winhttp=$winhttp} |
ConvertTo-Json -Depth 8 -Compress
'''
    native_machine = host_facts()["native_machine"]
    executable, machine = select_powershell(native_machine)
    started = time.monotonic()
    print(f"[Windows acceptance] host network snapshot started; PowerShell PE machine "
          f"0x{machine:04x}, budget {NETWORK_SNAPSHOT_TIMEOUT}s", file=sys.stderr, flush=True)
    try:
        result = subprocess.run([str(executable), "-NoLogo", "-NoProfile", "-NonInteractive",
                                 "-Command", script], capture_output=True, encoding="utf-8",
                                errors="replace", timeout=NETWORK_SNAPSHOT_TIMEOUT, check=True)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Host network snapshot exceeded {NETWORK_SNAPSHOT_TIMEOUT}s "
                           f"during {snapshot_stage(exc.stderr)}; acceptance cannot continue.") from None
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Host network snapshot failed during {snapshot_stage(exc.stderr)} "
                           f"(PowerShell exit {exc.returncode}); acceptance cannot continue.") from None
    value = json.loads(result.stdout.lstrip("\ufeff"))
    if (not isinstance(value, dict) or set(value) != {"dns", "routes", "proxy", "winhttp"}
            or not isinstance(value["dns"], list) or not isinstance(value["routes"], list)
            or not isinstance(value["proxy"], dict) or not isinstance(value["winhttp"], str)):
        raise RuntimeError("host network snapshot returned an incomplete configuration record")
    print(f"[Windows acceptance] host network snapshot completed in "
          f"{time.monotonic() - started:.1f}s", file=sys.stderr, flush=True)
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class HostFixtures:
    def __init__(self) -> None:
        self.sockets = []
        self.accepted = threading.Event()
        self.closed = threading.Event()
        self.threads = []
        try:
            for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                listener = socket.socket(family, socket.SOCK_STREAM)
                self.sockets.append(listener)
                listener.bind((host, 0))
                listener.listen(8)
                listener.settimeout(0.1)
                # First prove the ordinary host can reach each actual fixture.
                with socket.create_connection((host, listener.getsockname()[1]), timeout=2):
                    connection, _ = listener.accept()
                    connection.close()
                worker = threading.Thread(target=self._accept, args=(listener,), daemon=True)
                worker.start()
                self.threads.append(worker)
        except BaseException:
            self.close()
            raise

    def _accept(self, listener: socket.socket) -> None:
        while not self.closed.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted.set()
            connection.close()

    def close(self) -> None:
        self.closed.set()
        for listener in self.sockets:
            listener.close()
        for worker in self.threads:
            worker.join(timeout=1)


class FixedTransportFixture:
    """Local bytes only: no DNS, destination connections, or forwarding API."""

    def __init__(self) -> None:
        self.token = secrets.token_hex(32)
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.connections = set()
        self.workers = []
        self.errors = []
        self.roundtrips = 0
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.listener.listen(16)
            self.listener.settimeout(0.1)
        except BaseException:
            self.listener.close()
            raise
        self.port = int(self.listener.getsockname()[1])
        self.acceptor = threading.Thread(target=self._accept, daemon=True)
        self.acceptor.start()

    @staticmethod
    def _read_exact(connection: socket.socket, length: int) -> bytes:
        result = bytearray()
        while len(result) < length:
            part = connection.recv(length - len(result))
            if not part:
                raise RuntimeError("transport fixture request ended early")
            result.extend(part)
        return bytes(result)

    def _accept(self) -> None:
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                if self.closed.is_set():
                    connection.close()
                    return
                self.connections.add(connection)
                worker = threading.Thread(target=self._handle, args=(connection,), daemon=True)
                self.workers.append(worker)
            worker.start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(20)
            first = self._read_exact(connection, 1)
            if first == b"\x05":
                count = self._read_exact(connection, 1)[0]
                methods = self._read_exact(connection, count)
                if not count or b"\0" not in methods:
                    raise RuntimeError("transport fixture received an unsupported SOCKS greeting")
                connection.sendall(b"\x05\0")
                # Production startup asks only for SOCKS5 method negotiation.
                # Reject any CONNECT/destination command: this is not a proxy.
                if connection.recv(1):
                    raise RuntimeError("transport fixture never accepts SOCKS destination requests")
                return
            request = bytearray(first)
            while not request.endswith(b"\r\n\r\n") and len(request) <= 1024:
                request.extend(self._read_exact(connection, 1))
            expected = ("CONNECT ruleproxy-acceptance.invalid:443 HTTP/1.1\r\n"
                        f"X-RuleProxy-Fixture: {self.token}\r\n\r\n").encode("ascii")
            if bytes(request) != expected:
                raise RuntimeError("transport fixture accepts only its fixed CONNECT byte request")
            connection.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            expected_payload = fixture_payload(self.token)
            payload = bytearray()
            while len(payload) <= len(expected_payload):
                part = connection.recv(16384)
                if not part:
                    break
                payload.extend(part)
            if bytes(payload) != expected_payload:
                raise RuntimeError("transport fixture payload or guest-to-host FIN was invalid")
            connection.sendall(expected_payload[::-1])
            connection.shutdown(socket.SHUT_WR)
            with self.lock:
                self.roundtrips += 1
        except Exception as exc:
            if not self.closed.is_set():
                with self.lock:
                    self.errors.append(f"{type(exc).__name__}: {exc}"[:300])
        finally:
            connection.close()
            with self.lock:
                self.connections.discard(connection)

    def close(self) -> None:
        self.closed.set()
        self.listener.close()
        self.acceptor.join(timeout=2)
        with self.lock:
            connections, workers = list(self.connections), list(self.workers)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        for worker in workers:
            worker.join(timeout=2)


class FixedSocksFixture(FixedTransportFixture):
    """One named SOCKS destination, backed entirely by local fixture bytes."""

    @property
    def host(self) -> str:
        return fixture_destination(self.token)

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(20)
            version, count = self._read_exact(connection, 2)
            methods = self._read_exact(connection, count)
            if version != 5 or not count or b"\0" not in methods:
                raise RuntimeError("manager fixture received an unsupported SOCKS greeting")
            connection.sendall(b"\x05\0")
            if self._read_exact(connection, 4) != b"\x05\x01\0\x03":
                raise RuntimeError("manager fixture accepts only its fixed named SOCKS CONNECT")
            host = self._read_exact(connection, self._read_exact(connection, 1)[0])
            port = int.from_bytes(self._read_exact(connection, 2), "big")
            if host != self.host.encode("ascii") or port != 443:
                raise RuntimeError("manager fixture rejected an unrelated SOCKS destination")
            connection.sendall(b"\x05\0\0\x01\x7f\0\0\x01\0\0")
            expected = fixture_payload(self.token)
            payload = bytearray()
            while len(payload) <= len(expected):
                part = connection.recv(16384)
                if not part:
                    break
                payload.extend(part)
            if bytes(payload) != expected:
                raise RuntimeError("manager fixture payload or client FIN was invalid")
            connection.sendall(expected[::-1])
            connection.shutdown(socket.SHUT_WR)
            with self.lock:
                self.roundtrips += 1
        except Exception as exc:
            if not self.closed.is_set():
                with self.lock:
                    self.errors.append(f"{type(exc).__name__}: {exc}"[:300])
        finally:
            connection.close()
            with self.lock:
                self.connections.discard(connection)


def manager_fixture_source(fixture: FixedSocksFixture) -> str:
    return ("proxies:\n"
            f"  - {{name: manager-fixture, type: socks5, server: upstream.ruleproxy.invalid, port: {fixture.port}, udp: false}}\n"
            'rules: ["MATCH,DIRECT"]\n')


def reload_manager_fixture(manager, fixture: FixedSocksFixture) -> dict:
    """Override only our own core endpoint, after the normal importer/start.

    This never edits the product compiler, saved YAML, or runtime policy. The
    fixed local endpoint replaces exactly one compiled SOCKS server through
    Mihomo's official controller payload reload, solely for this test mode.
    """
    import yaml
    if manager.core is None or manager.core.poll() is not None:
        raise RuntimeError("manager fixture reload requires its privately owned running core")
    original = copy.deepcopy(manager.compiled.config)
    if (len(original.get("proxies", [])) != 1
            or original["proxies"][0].get("type") != "socks5"
            or original["proxies"][0].get("server") != "upstream.ruleproxy.invalid"
            or original["proxies"][0].get("port") != fixture.port):
        raise RuntimeError("manager fixture compiled configuration was not the controlled single SOCKS node")
    overridden = copy.deepcopy(original)
    overridden["proxies"][0]["server"] = "127.0.0.1"
    reverted = copy.deepcopy(overridden)
    reverted["proxies"][0]["server"] = "upstream.ruleproxy.invalid"
    if reverted != original or manager.compiled.config != original:
        raise RuntimeError("manager fixture override changed more than its owned-core node endpoint")
    manager._controller("PUT", "/configs?force=true",
                        {"payload": yaml.safe_dump(overridden, sort_keys=False)})
    return {"test_only_endpoint_override": True,
            "override_scope": "Owned Mihomo controller payload: sole SOCKS server changed to loopback.",
            "compiled_configuration_unchanged": True}


def ports() -> tuple[int, int, int]:
    reservations = []
    try:
        for _ in range(3):
            reservation = socket.socket()
            reservations.append(reservation)
            reservation.bind(("127.0.0.1", 0))
        return tuple(int(item.getsockname()[1]) for item in reservations)
    finally:
        for reservation in reservations:
            reservation.close()


def read_guest_reports(profile: Path, wrapper, timeout: float = 90, *, lost: bool = False, run_token: str,
                       host_ipv6_route_unavailable=False) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        reports = []
        for role in ("parent", "child"):
            try:
                prefix = "acceptance-lost" if lost else "acceptance"
                with (profile / f"{prefix}-{role}.json").open("rb") as stream:
                    raw = stream.read(16 * 1024 + 1)
                if len(raw) > 16 * 1024:
                    raise RuntimeError("acceptance guest report exceeded its size limit")
                value = json.loads(raw, object_pairs_hook=strict_json_object)
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("status") != "passed":
                raise RuntimeError(value.get("error", "acceptance guest checks failed") if isinstance(value, dict)
                                   else "acceptance guest report was not an object")
            expected = {"role", "pid", "parent_pid", "status", "checks", "public_udp", "run_token"}
            if (set(value) != expected | (set() if lost else {"listeners"}) or value["role"] != role
                    or value["run_token"] != run_token
                    or any(type(value[key]) is not int or not 0 < value[key] <= 0xFFFFFFFF for key in ("pid", "parent_pid"))
                    or not isinstance(value["checks"], list)):
                raise RuntimeError("acceptance guest report identity or fields were invalid")
            if not lost and (not isinstance(value["listeners"], list) or len(value["listeners"]) != 2
                             or any(type(port) is not int or not 1 <= port <= 65535 for port in value["listeners"])):
                raise RuntimeError("acceptance guest listeners were incomplete")
            names = [check.get("check") for check in value["checks"] if isinstance(check, dict)]
            required = {"direct_ipv4_tcp", "guest_to_host_ipv4", "guest_to_host_ipv6"}
            proxy_names = {"proxy_fails_after_fixture_loss"} if lost else {"real_proxy_https", "fixed_loopback_transport_cross_frame_fin"}
            if (len(value["checks"]) != 5 or len(names) != 5 or any(type(name) is not str for name in names)
                    or len(set(names)) != 5 or not required | {"direct_ipv6_tcp"} <= set(names)
                    or len(set(names) & proxy_names) != 1
                    or any(check.get("status") != "passed" for check in value["checks"] if check["check"] != "direct_ipv6_tcp")
                    or any(check.get("socket_error") != 10013 for check in value["checks"] if check["check"] in required)):
                raise RuntimeError("acceptance guest mandatory checks were incomplete")
            ipv6 = next(check for check in value["checks"] if check["check"] == "direct_ipv6_tcp")
            if not (ipv6 == {"check": "direct_ipv6_tcp", "status": "passed", "socket_error": 10013}
                    or (host_ipv6_route_unavailable is True and ipv6 == {
                        "check": "direct_ipv6_tcp", "status": "unavailable", "socket_error": 10051, "ok": False})):
                raise RuntimeError("acceptance guest public IPv6 lacked denial or confirmed unavailability")
            public = value["public_udp"]
            if not isinstance(public, dict) or set(public) != {"ipv4_udp", "ipv6_udp"}:
                raise RuntimeError("acceptance public UDP diagnostic was incomplete")
            for diagnostic in public.values():
                if (not isinstance(diagnostic, dict) or set(diagnostic) != {"ok", "code"} or type(diagnostic["ok"]) is not bool
                        or not ((type(diagnostic["code"]) is int and -65536 <= diagnostic["code"] <= 65536)
                                or (type(diagnostic["code"]) is str and diagnostic["code"] in {"allowed", "short_send", "timeout", "io", "error"}))
                        or diagnostic["ok"] != (diagnostic["code"] == 10013)):
                    raise RuntimeError("acceptance public UDP diagnostic was invalid")
            reports.append(value)
        if len(reports) == 2:
            if reports[1]["parent_pid"] != reports[0]["pid"]:
                raise RuntimeError("acceptance reports did not prove a parent/child relationship")
            return reports
        if wrapper.poll() is not None:
            raise RuntimeError("MXC wrapper exited before acceptance guest checks completed")
        time.sleep(0.1)
    raise RuntimeError("acceptance parent and child did not finish network checks before timeout")


def assert_host_cannot_reach_guest(reports: list[dict]) -> None:
    for report in reports:
        for host, port in zip(("127.0.0.1", "::1"), report["listeners"]):
            try:
                connection = socket.create_connection((host, port), timeout=1)
            except OSError:
                pass
            else:
                connection.close()
                raise RuntimeError("host reached a live contained application listener")


class TransportRun:
    """Own the actual production runtime while testing the local transport."""

    def __init__(self, profile: Path) -> None:
        self.profile = profile
        self.wrapper = None
        self.resources = None
        self.fixture = FixedTransportFixture()

    def run(self, runtime: Path, host_fixtures: HostFixtures) -> list[dict]:
        from ruleproxy import windows_runtime
        self.profile.mkdir(parents=True)
        helper = self.profile / "acceptance_guest.py"
        shutil.copyfile(__file__, helper)
        guest_port = windows_runtime.choose_guest_port(self.fixture.port)
        command = [sys.executable, "-I", "-S", "-X", "utf8", str(helper), "--guest",
                   "--role", "parent", "--fixture-token", self.fixture.token,
                   "--host-v4-port", str(host_fixtures.sockets[0].getsockname()[1]),
                   "--host-v6-port", str(host_fixtures.sockets[1].getsockname()[1]), "--run-token", self.fixture.token]
        env = dict(os.environ, HTTPS_PROXY=f"http://127.0.0.1:{guest_port}")
        try:
            self.wrapper, self.resources = windows_runtime.launch(
                command, env, self.profile, self.fixture.port, str(runtime),
                guest_listener_port=guest_port)
        except BaseException as exc:
            self.wrapper = getattr(exc, "process", None)
            self.resources = getattr(exc, "resource", None)
            raise
        api = windows_runtime._WinProcessApi()
        startup = startup_evidence(self.resources)
        handles = []
        try:
            host_ipv6_unavailable = startup["host_ipv6_observation"]["host_ipv6_route_unavailable"]
            reports = read_guest_reports(self.profile, self.wrapper, run_token=self.fixture.token,
                                         host_ipv6_route_unavailable=host_ipv6_unavailable)
            for report in reports:
                handle = api.kernel32.OpenProcess(api.PROCESS_ACCESS, False, report["pid"])
                if not handle:
                    raise RuntimeError("could not retain a live transport acceptance process handle")
                handles.append(handle)
                if not api.process_alive(handle):
                    raise RuntimeError("transport acceptance process exited before fixture loss")
            assert_host_cannot_reach_guest(reports)
            with self.fixture.lock:
                if self.fixture.errors or self.fixture.roundtrips != 2:
                    raise RuntimeError("fixed transport fixture did not complete both generation roundtrips")
            if host_fixtures.accepted.is_set():
                raise RuntimeError("a contained transport process reached an ordinary host listener")
            self.fixture.close()
            write_json(self.profile / "acceptance-control.json",
                       {"token": self.fixture.token, "state": "fixture_stopped"})
            lost = read_guest_reports(self.profile, self.wrapper, timeout=45, lost=True, run_token=self.fixture.token,
                                      host_ipv6_route_unavailable=host_ipv6_unavailable)
            if not all(api.process_alive(handle) for handle in handles):
                raise RuntimeError("fixture-loss checks did not run while both application generations were alive")
            if host_fixtures.accepted.is_set():
                raise RuntimeError("a contained process reached a host listener after fixture loss")
            windows_runtime.stop(self.wrapper)
            self.wrapper.wait(timeout=25)
            if not all(api.wait(handle, 5000) for handle in handles):
                raise RuntimeError("a transport acceptance process survived PSEC teardown")
            self.resources.close()
            return [
                {"check": "transport_parent_child", "status": "passed",
                 "host_to_guest_ipv4_ipv6": "denied", "guest_reports": reports, **startup},
                {"check": "fixture_loss", "status": "passed", "applications_alive_during_check": True,
                 "guest_reports": lost, "manager_watcher_verified": False},
                {"check": "safe_psec_stop", "status": "passed", "parent_and_child_exited": True},
            ]
        finally:
            for handle in handles:
                api.close(handle)

    def close(self) -> None:
        from ruleproxy import windows_runtime
        try:
            if self.wrapper is not None and self.wrapper.poll() is None:
                windows_runtime.stop(self.wrapper)
            if self.resources is not None:
                self.resources.close()
        finally:
            self.fixture.close()


def lifecycle_case(manager, fixtures: HostFixtures, url: str, case: str,
                   *, proxy_fixture: FixedSocksFixture | None = None) -> dict:
    from ruleproxy import windows_runtime
    manager.add_app({"label": "Windows acceptance", "path": sys.executable,
                     "adapter": "environment", "args": []})
    app = manager.settings["apps"][-1]
    profile = manager.directory / "profiles" / app["id"]
    profile.mkdir(parents=True)
    helper = profile / "acceptance_guest.py"
    shutil.copyfile(__file__, helper)
    transport_args = (["--fixture-token", proxy_fixture.token, "--fixture-host", proxy_fixture.host]
                      if proxy_fixture is not None else ["--url", url])
    run_token = secrets.token_hex(32)
    app["args"] = ["-I", "-S", "-X", "utf8", str(helper), "--guest", "--role", "parent",
                   *transport_args, "--host-v4-port", str(fixtures.sockets[0].getsockname()[1]),
                   "--host-v6-port", str(fixtures.sockets[1].getsockname()[1]), "--run-token", run_token]
    manager.launch(app["id"])
    wrapper = manager.active[app["id"]][0]
    resources = manager.active[app["id"]][1]
    startup = startup_evidence(resources)
    handles = []
    api = windows_runtime._WinProcessApi()
    try:
        reports = read_guest_reports(profile, wrapper, run_token=run_token,
                                     host_ipv6_route_unavailable=startup["host_ipv6_observation"]["host_ipv6_route_unavailable"])
        for report in reports:
            handle = api.kernel32.OpenProcess(api.PROCESS_ACCESS, False, report["pid"])
            if not handle:
                raise RuntimeError("could not retain a live acceptance process handle")
            handles.append(handle)
            if not api.process_alive(handle):
                raise RuntimeError("acceptance process exited before its lifecycle check")
        assert_host_cannot_reach_guest(reports)
        if fixtures.accepted.is_set():
            raise RuntimeError("a contained process reached an ordinary host listener")
        if case == "normal_stop":
            if proxy_fixture is not None:
                manager.stop()
            else:
                manager.stop_app(app["id"])
        else:
            # Kill only the private Mihomo instance created by this manager.
            core = manager.core
            if core is None or core.poll() is not None:
                raise RuntimeError("private core was not running before loss test")
            core.kill()
            core.wait(timeout=5)
        wrapper.wait(timeout=25)
        if not all(api.wait(handle, 5000) for handle in handles):
            raise RuntimeError("a parent or descendant survived PSEC workload teardown")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with manager.lock:
                if app["id"] not in manager.active:
                    break
            time.sleep(0.1)
        with manager.lock:
            if app["id"] in manager.active:
                raise RuntimeError("manager retained a stopped application's resources")
            if proxy_fixture is not None and (manager.core is not None or manager.core_log is not None):
                raise RuntimeError("manager fixture retained its stopped core or log")
        if not getattr(resources, "_closed", False):
            raise RuntimeError("manager did not finish releasing the Windows runtime resources")
        manager.change_app(app["id"], delete=True)
        result = {"check": f"manager_{case}" if proxy_fixture is not None else case,
                  "status": "passed", "parent_and_child_exited": True,
                  "held_handles_verified": True, "manager_active_removed": True,
                  "runtime_resources_closed": True,
                  "host_to_guest_ipv4_ipv6": "denied", "guest_reports": reports, **startup}
        if proxy_fixture is not None:
            result.update(manager_owned_core_stopped=True, manager_watcher_exercised=case == "core_loss")
        return result
    finally:
        for handle in handles:
            api.close(handle)


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--probe-only", action="store_true")
    modes.add_argument("--transport-fixture", action="store_true",
                       help="real PSEC and local file transport; no real node or HTTPS origin claim")
    modes.add_argument("--manager-fixture", action="store_true",
                       help="real PSEC/Mihomo/Manager lifecycle with test-only fixed SOCKS endpoint reload")
    parser.add_argument("--yaml", type=Path, help="private real-node YAML; never copied into the report")
    parser.add_argument("--node", help="optional selected node name")
    parser.add_argument("--url", default="https://example.com/", type=check_url)
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout or extracted package root")
    parser.add_argument("--report", type=Path, default=Path("windows-acceptance.json"))
    parser.add_argument("--allow-emulated-x64", action="store_true",
                        help="allow x64 Python on ARM64; report explicitly labels emulation")
    args = parser.parse_args(arguments)
    result = {"status": "failed", "acceptance_passed": False, "full_acceptance_passed": False,
              "public_udp_proven": False, "system_dns_proven": False,
              "transport_passed": False, "real_node_passed": False,
              "manager_fixture_passed": False, "manager_normal_stop_passed": False,
              "manager_core_loss_passed": False, "checks": []}
    manager, fixtures, directory, before = None, None, None, None
    transport_owner = None
    proxy_fixture = None
    safe_cleanup = True
    phase = "platform"
    code = 1
    try:
        result["host"] = host_facts()
        facts = result["host"]
        if sys.platform != "win32" or facts.get("windows_product_type") != 1 or facts.get("windows_build", 0) < 26100:
            result.update(status="unsupported", detail="Requires Windows 11 workstation, build 26100+; Server/Linux do not pass Windows 11 acceptance.")
            return 3
        root = args.root.resolve(strict=True)
        sys.path.insert(0, str(root))
        sys.path.insert(0, str(root / "vendor"))
        phase = "project_origin"
        verify_project_origin(root)
        from ruleproxy import windows_runtime
        verify_project_origin(root)
        runtime = root / "bin/windows-amd64/wxc-exec.exe"
        phase = "pinned_runtimes"
        digests = verify_runtime_manifest(root)
        result["runtime_integrity"] = {
            "versions": dict(RUNTIME_VERSIONS), "verified_file_count": len(digests),
            "manifest_verified": True,
            "origin_verification": "Release ZIP external checksum must be verified separately.",
        }
        result["runtime_sha256"] = digests["wxc-exec.exe"]
        result["core_sha256"] = digests["mihomo.exe"]
        phase = "request_probe"
        probe = windows_runtime.probe(str(runtime))
        result["probe"] = probe
        if not probe["supported"]:
            result.update(status="unsupported", detail=probe["detail"])
            return 3
        if args.probe_only:
            result.update(status="supported_only", detail="Request probe passed; full socket/proxy/lifecycle acceptance was not run.")
            return 0
        if args.yaml is None and not (args.transport_fixture or args.manager_fixture):
            raise ValueError("--yaml is required for real proxy acceptance")
        if facts["pointer_bits"] != 64 or facts["python_pe_machine"] != 0x8664:
            result.update(status="unsupported", detail="Full acceptance requires the package's x64 Python interpreter.")
            return 3
        if facts["native_machine"] != 0x8664 and not (args.allow_emulated_x64 and facts["native_machine"] == 0xAA64):
            result.update(status="unsupported", detail="Native x64 acceptance requires an x64 host; ARM emulation must be explicitly labeled with --allow-emulated-x64.")
            return 3
        phase = "host_network_snapshot"
        before = network_snapshot()
        phase = "host_ipv4_ipv6_fixtures"
        fixtures = HostFixtures()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-windows-acceptance-"))
        if args.transport_fixture:
            phase = "transport_fixture"
            transport_owner = TransportRun(directory / "profiles" / "transport")
            result["checks"].extend(transport_owner.run(runtime, fixtures))
            result.update(status="transport_only", transport_passed=True,
                          manager_core_loss_passed=False,
                          limitations=["Fixed loopback bytes only; no real proxy node or HTTPS origin tested.",
                                       "PSEC safe stop tested; Manager core-loss watcher requires --manager-fixture or --yaml mode."])
        else:
            from ruleproxy.manager import Manager
            panel_port, mixed_port, controller_port = ports()
            manager = Manager(directory, panel_port, mixed_port=mixed_port, controller_port=controller_port)
            manager.save_settings({"core_path": str(root / "bin/windows-amd64/mihomo.exe"),
                                   "runtime_path": str(runtime)})
            if args.manager_fixture:
                from ruleproxy.config import compile_config
                phase = "manager_fixture_import"
                proxy_fixture = FixedSocksFixture()
                source = manager_fixture_source(proxy_fixture)
                try:
                    compile_config(source.replace("upstream.ruleproxy.invalid", "127.0.0.1"),
                                   secret="manager-fixture-import-guard")
                except ValueError:
                    result["production_importer_rejects_loopback"] = True
                else:
                    raise RuntimeError("production importer unexpectedly permitted a loopback node")
                manager.import_yaml(source)
            else:
                phase = "private_yaml_import"
                # Bound reads before parsing; malformed YAML is never echoed to reports.
                with args.yaml.open("rb") as stream:
                    source = stream.read(2 * 1024 * 1024 + 1)
                if len(source) > 2 * 1024 * 1024:
                    raise ValueError("private YAML exceeded the import limit")
                manager.import_yaml(source.decode("utf-8-sig"))
                if args.node:
                    manager.select_node(args.node)
                phase = "core_start"
                manager.start()
            for case in ("normal_stop", "core_loss"):
                if proxy_fixture is not None:
                    phase = "manager_fixture_core_start"
                    manager.start()
                    phase = "manager_fixture_endpoint_reload"
                    result.update(reload_manager_fixture(manager, proxy_fixture))
                phase = f"manager_{case}" if proxy_fixture is not None else case
                result["checks"].append(lifecycle_case(manager, fixtures, args.url, case,
                                                       proxy_fixture=proxy_fixture))
            if proxy_fixture is not None:
                with proxy_fixture.lock:
                    if proxy_fixture.errors or proxy_fixture.roundtrips != 4:
                        raise RuntimeError("manager fixture did not complete both generations in both lifecycle cases")
                result.update(status="manager_fixture_only", manager_fixture_passed=True,
                              manager_normal_stop_passed=True, manager_core_loss_passed=True,
                              transport_passed=True,
                              limitations=["Test-only endpoint reload of this script's owned Mihomo core.",
                                           "Fixed local SOCKS bytes only; no real node or HTTPS origin tested."])
            else:
                result.update(status="real_node_functionality_only", real_node_passed=True,
                              manager_normal_stop_passed=True, manager_core_loss_passed=True,
                              limitations=["Real proxy HTTPS and lifecycle passed; external UDP and system DNS wire evidence was not collected.",
                                           "Host-local UDP zero counts do not prove public IPv4/IPv6 or native resolver isolation."])
        code = 0
    except Exception as exc:
        # Exceptions from YAML parsing can contain source lines and credentials.
        result.update(status="failed", acceptance_passed=False,
                      detail=f"Acceptance failed during {phase} ({type(exc).__name__}).")
        if args.transport_fixture or args.manager_fixture:
            # This mode never imports private YAML, so retain its socket/PSEC
            # diagnostics for CI without hiding an actionable failure reason.
            result["failure_detail"] = str(exc)[:700]
    finally:
        if transport_owner is not None:
            try:
                transport_owner.close()
            except Exception as exc:
                safe_cleanup = False
                result.update(status="failed", acceptance_passed=False, transport_passed=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        if manager is not None:
            try:
                manager.close()
            except Exception as exc:
                safe_cleanup = False
                result.update(status="failed", acceptance_passed=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        if fixtures is not None:
            fixtures.close()
        if proxy_fixture is not None:
            proxy_fixture.close()
        if before is not None:
            try:
                after = network_snapshot()
                unchanged = before == after
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                         "status": "passed" if unchanged else "failed",
                                         "before_sha256": before, "after_sha256": after})
                if not unchanged:
                    result.update(status="failed", acceptance_passed=False)
                    code = 1
            except Exception as exc:
                result.update(status="failed", acceptance_passed=False,
                              host_snapshot_error=type(exc).__name__)
                code = 1
        if directory is not None and safe_cleanup:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                result.update(status="failed", acceptance_passed=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        if result["status"] == "failed":
            # Lifecycle cleanup and the final host snapshot are part of each
            # requested mode, so a late failure must not retain a success flag.
            for name in ("acceptance_passed", "full_acceptance_passed", "transport_passed", "real_node_passed",
                         "manager_fixture_passed", "manager_normal_stop_passed",
                         "manager_core_loss_passed"):
                result[name] = False
        write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    if sys.argv[1:2] == ["--guest"]:
        raise SystemExit(guest_main(sys.argv[2:]))
    raise SystemExit(main(sys.argv[1:]))
