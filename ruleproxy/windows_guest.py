"""MXC-contained Windows guest wrapper for strict proxy launches.

The helper starts a localhost TCP bridge and proves its startup path before it
starts the selected application. The helper's host relay has no network API;
the file bridge relays bytes only to the configured Mihomo loopback listener.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
from typing import Any


_MAX_CONFIG_BYTES = 128 * 1024
_MAX_COMMAND_ARGS = 128
_MAX_COMMAND_TEXT = 16_384
_SOCKET_CHECK_TIMEOUT = 1.5
# Fixed DNS query: ruleproxy.invalid IN A, recursion disabled, no user data.
_UDP_PROBE_DATAGRAM = (
    b"\x52\x50\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    b"\x09ruleproxy\x07invalid\x00\x00\x01\x00\x01"
)
_BRIDGE_READY_TIMEOUT = 10.0
_HOST_DECISION_TIMEOUT = 45.0


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate runtime field")
        value[key] = item
    return value


def _valid_nonce(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(char in "0123456789abcdef" for char in value))


def _local_udp_marker(nonce: str, scope: str, family: str) -> bytes:
    if not _valid_nonce(nonce) or scope not in {"parent", "child"} or family not in {"ipv4", "ipv6"}:
        raise ValueError("invalid fixed UDP probe identity")
    return b"RuleProxy-UDP-v1\0" + hashlib.sha256(
        bytes.fromhex(nonce) + scope.encode("ascii") + b"\0" + family.encode("ascii")).digest()


def _atomic_status(directory: Path, nonce: str, state: str, detail: str = "") -> None:
    path = directory / "guest-status.json"
    value = {"nonce": nonce, "state": state}
    if detail:
        value["detail"] = detail[:700]
    temp = path.with_name(path.name + ".guest-tmp")
    with temp.open("w", encoding="ascii", newline="") as stream:
        json.dump(value, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def _read_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_CONFIG_BYTES + 1)
    if not raw or len(raw) > _MAX_CONFIG_BYTES:
        raise ValueError("guest runtime config has an invalid size")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_json_object)
    if not isinstance(value, dict):
        raise ValueError("guest runtime config must be an object")
    required = {
        "command",
        "env",
        "profile",
        "listener_port",
        "bridge_directory",
        "bridge_nonce",
        "host_fixture_port",
        "schema_version",
        "host_udp_ports",
        "host_ipv6_route_unavailable",
    }
    if set(value) != required:
        raise ValueError("guest runtime config fields are invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ValueError("guest runtime config version is invalid")
    command = value["command"]
    if (
        not isinstance(command, list)
        or not command
        or len(command) > _MAX_COMMAND_ARGS
        or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
        or sum(len(arg) for arg in command) > _MAX_COMMAND_TEXT
    ):
        raise ValueError("application command is invalid")
    if not isinstance(value["env"], dict) or any(
        not isinstance(key, str)
        or not isinstance(item, str)
        or "\0" in key
        or "\0" in item
        for key, item in value["env"].items()
    ):
        raise ValueError("application environment is invalid")
    for name in ("profile", "bridge_directory"):
        if not isinstance(value[name], str) or "\0" in value[name]:
            raise ValueError(f"{name} is invalid")
    for name in ("listener_port", "host_fixture_port"):
        port = value[name]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"{name} is invalid")
    nonce = value["bridge_nonce"]
    if not _valid_nonce(nonce):
        raise ValueError("bridge nonce is invalid")
    _validate_udp_ports(value["host_udp_ports"])
    if type(value["host_ipv6_route_unavailable"]) is not bool:
        raise ValueError("host IPv6 availability must be a boolean")
    return value


def _validate_udp_ports(ports):
    if (not isinstance(ports, list) or len(ports) != 2
            or any(type(port) is not int or not 1 <= port <= 65535 for port in ports)):
        raise ValueError("host UDP fixture ports are invalid")
    return ports


_CHILD_PROBE_TIMEOUT = 20.0
_SELF_CHECK_BUDGET = 22.0
_MAX_PROBE_OUTPUT_BYTES = 8192
_DENY_PROBES = ("own_loopback", "host_loopback", "ipv4_tcp", "ipv6_tcp", "ipv4_udp", "ipv6_udp")
_MANDATORY_DENY_PROBES = _DENY_PROBES[:-2]
_PROBE_CODES = frozenset({"ok", "allowed", "timeout", "reply", "io", "error", "cleanup", "short_send",
                          "child_timeout", "child_start", "child_exit", "invalid_report", "deadline"})


class _ProbeFailure(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _probe(operation, *, deny: bool = False) -> dict[str, Any]:
    """Record one result without letting it suppress later independent probes."""
    try:
        operation()
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        if code is None:
            code = "timeout" if isinstance(exc, TimeoutError) else "io"
        return {"ok": deny and code == 10013, "code": code}
    except _ProbeFailure as exc:
        return {"ok": False, "code": exc.code}
    except Exception:
        return {"ok": False, "code": "error"}
    return {"ok": not deny, "code": "allowed" if deny else "ok"}


def _socket_timeout(deadline=None) -> float:
    remaining = _SOCKET_CHECK_TIMEOUT if deadline is None else deadline - time.monotonic()
    if remaining <= 0:
        raise _ProbeFailure("deadline")
    return min(_SOCKET_CHECK_TIMEOUT, remaining)


def _receive_exact(connection, length: int, *, deadline=None) -> bytes:
    result = bytearray()
    deadline = min(deadline, time.monotonic() + _SOCKET_CHECK_TIMEOUT) if deadline is not None else time.monotonic() + _SOCKET_CHECK_TIMEOUT
    while len(result) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _ProbeFailure("timeout")
        connection.settimeout(remaining)
        part = connection.recv(length - len(result))
        if not part:
            raise _ProbeFailure("reply")
        result.extend(part)
    return bytes(result)


def _proxy_roundtrip(listener_port: int, *, deadline=None) -> None:
    import socket
    # Method negotiation has no CONNECT request, destination, or origin data.
    with socket.create_connection(("127.0.0.1", listener_port), timeout=_socket_timeout(deadline)) as connection:
        connection.settimeout(_socket_timeout(deadline))
        connection.sendall(b"\x05\x01\x00")
        if _receive_exact(connection, 2, deadline=deadline) != b"\x05\x00":
            raise _ProbeFailure("reply")


def _same_process_loopback(family: int | None = None, *, deadline=None) -> None:
    import socket
    family = socket.AF_INET if family is None else family
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    listener = socket.socket(family, socket.SOCK_STREAM)
    worker = None
    errors = []
    accepted = []
    accepted_lock = threading.Lock()
    finished = threading.Event()
    try:
        listener.bind((host, 0))
        listener.listen(1)
        listener.settimeout(min(0.1, _socket_timeout(deadline)))

        def echo():
            try:
                while not finished.is_set():
                    _socket_timeout(deadline)
                    try:
                        connection, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                with accepted_lock:
                    accepted.append(connection)
                with connection:
                    if finished.is_set():
                        return
                    connection.settimeout(_socket_timeout(deadline))
                    if _receive_exact(connection, 4, deadline=deadline) != b"RP01":
                        raise _ProbeFailure("reply")
                    connection.sendall(b"RP01")
            except Exception:
                errors.append(True)

        worker = threading.Thread(target=echo, name="ruleproxy-own-loopback-probe", daemon=True)
        worker.start()
        with socket.create_connection((host, listener.getsockname()[1]),
                                      timeout=_socket_timeout(deadline)) as connection:
            connection.settimeout(_socket_timeout(deadline))
            connection.sendall(b"RP01")
            if _receive_exact(connection, 4, deadline=deadline) != b"RP01":
                raise _ProbeFailure("reply")
        worker.join(timeout=_socket_timeout(deadline))
        if worker.is_alive():
            raise _ProbeFailure("cleanup")
        if errors:
            raise _ProbeFailure("reply")
    finally:
        finished.set()
        listener.close()
        with accepted_lock:
            for connection in accepted:
                connection.close()
        if worker is not None:
            worker.join(timeout=0.2)
            if worker.is_alive():
                raise _ProbeFailure("cleanup")


def _socket_attempt(family: int, kind: int, address: tuple, *, deadline=None) -> None:
    import socket
    with socket.socket(family, kind) as connection:
        connection.settimeout(_socket_timeout(deadline))
        if kind == socket.SOCK_DGRAM:
            # Attempt a complete nonempty datagram; only WSAEACCES proves denial.
            if connection.sendto(_UDP_PROBE_DATAGRAM, address) != len(_UDP_PROBE_DATAGRAM):
                raise _ProbeFailure("short_send")
        else:
            # TCP connect transmits SYN setup only, never application payload.
            connection.connect(address)


def _run_network_probes(scope: str, listener_port: int, host_fixture_port: int, *, deadline=None) -> dict[str, Any]:
    import socket
    if scope not in {"parent", "child"}:
        raise ValueError("invalid network probe scope")
    proxy_name = "proxy_self" if scope == "parent" else "proxy_parent"
    checks = {
        proxy_name: _probe(lambda: _proxy_roundtrip(listener_port, deadline=deadline)),
        "own_loopback": _probe(lambda: _same_process_loopback(deadline=deadline), deny=True),
    }
    for name, family, kind, address in (
        ("host_loopback", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", host_fixture_port)),
        ("ipv4_tcp", socket.AF_INET, socket.SOCK_STREAM, ("1.1.1.1", 443)),
        ("ipv6_tcp", socket.AF_INET6, socket.SOCK_STREAM, ("2606:4700:4700::1111", 443, 0, 0)),
        ("ipv4_udp", socket.AF_INET, socket.SOCK_DGRAM, ("1.1.1.1", 53)),
        ("ipv6_udp", socket.AF_INET6, socket.SOCK_DGRAM, ("2606:4700:4700::1111", 53, 0, 0)),
    ):
        checks[name] = _probe(lambda family=family, kind=kind, address=address:
                             _socket_attempt(family, kind, address, deadline=deadline), deny=True)
    return {"scope": scope, "pid": os.getpid(), "checks": checks}


def _unavailable_child(code: str) -> dict[str, Any]:
    return {"scope": "child", "pid": 0,
            "checks": {name: {"ok": False, "code": code}
                       for name in ("proxy_parent", *_DENY_PROBES)}}


def _validated_child_report(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > _MAX_PROBE_OUTPUT_BYTES:
        raise ValueError("oversized network probe response")
    value = json.loads(raw)
    expected = {"proxy_parent", *_DENY_PROBES}
    if (not isinstance(value, dict) or set(value) != {"scope", "pid", "checks"}
            or value["scope"] != "child" or type(value["pid"]) is not int
            or not 0 < value["pid"] <= 0xFFFFFFFF or not isinstance(value["checks"], dict)
            or set(value["checks"]) != expected):
        raise ValueError("invalid network probe response")
    for name, result in value["checks"].items():
        if not isinstance(result, dict) or set(result) != {"ok", "code"} or type(result["ok"]) is not bool:
            raise ValueError("invalid network probe result")
        code = result["code"]
        if not ((type(code) is int and -65536 <= code <= 65536)
                or (type(code) is str and code in _PROBE_CODES)):
            raise ValueError("invalid network probe error code")
        if result["ok"] and code != (10013 if name in _DENY_PROBES else "ok"):
            raise ValueError("network probe passed without the required evidence")
    return value


def _nested_network_report(listener_port: int, host_fixture_port: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-X", "utf8", str(Path(__file__).resolve()),
             "--network-probe", str(listener_port), str(host_fixture_port)],
            capture_output=True, encoding="utf-8", errors="replace",
            timeout=_CHILD_PROBE_TIMEOUT, check=False, shell=False,
        )
    except subprocess.TimeoutExpired:
        return _unavailable_child("child_timeout")
    except (OSError, subprocess.SubprocessError):
        return _unavailable_child("child_start")
    if result.returncode:
        report = _unavailable_child("child_exit")
        report["exit_code"] = int(result.returncode)
        return report
    try:
        return _validated_child_report(result.stdout)
    except (ValueError, TypeError):
        return _unavailable_child("invalid_report")


def _process_creation_time(handle=None) -> int:
    """Read FILETIME from the current process or an already held Popen handle."""
    if os.name != "nt":
        raise RuntimeError("Windows process identity is unavailable")
    class FileTime(ctypes.Structure):
        _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE, *([ctypes.POINTER(FileTime)] * 4)]
    kernel.GetProcessTimes.restype = wintypes.BOOL
    times = [FileTime() for _ in range(4)]
    if not kernel.GetProcessTimes(handle if handle is not None else kernel.GetCurrentProcess(),
                                  *(ctypes.byref(item) for item in times)):
        raise ctypes.WinError(ctypes.get_last_error())
    return (int(times[0].high) << 32) | int(times[0].low)


def _local_udp_attempt(scope: str, family: str, port: int, nonce: str, *, deadline) -> dict[str, Any]:
    import socket
    marker = _local_udp_marker(nonce, scope, family)
    kind, host = (socket.AF_INET, "127.0.0.1") if family == "ipv4" else (socket.AF_INET6, "::1")
    result = {"state": "invalid", "stage": "socket", "code": "error", "sent_bytes": None}
    try:
        _socket_timeout(deadline)
        with socket.socket(kind, socket.SOCK_DGRAM) as sender:
            sender.settimeout(_socket_timeout(deadline))
            result["stage"] = "bind"
            sender.bind((host, 0))
            result["stage"] = "send"
            sender.settimeout(_socket_timeout(deadline))
            count = sender.sendto(marker, (host, port))
            result["sent_bytes"] = count
            if count != len(marker):
                result["code"] = "short_send"
            else:
                result.update(state="accepted_full", stage="complete", code=None)
    except OSError as exc:
        code = getattr(exc, "winerror", None) or exc.errno
        result["code"] = code if code is not None else "timeout" if isinstance(exc, TimeoutError) else "io"
        if code == 10013:
            result["state"] = "access_denied"
    except _ProbeFailure as exc:
        result["code"] = exc.code
    except Exception:
        result["code"] = "error"
    return result


def _run_startup_probes(scope, listener_port, host_fixture_port, udp_ports, nonce, *, deadline):
    _validate_udp_ports(udp_ports)
    created = _process_creation_time()
    # Keep the public sendto diagnostics unchanged; these are not delivery or
    # kernel-denial proof when the API accepts a complete datagram.
    raw = _run_network_probes(scope, listener_port, host_fixture_port, deadline=deadline)
    public = {name: raw["checks"].pop(name) for name in ("ipv4_udp", "ipv6_udp")}
    local = {family: _local_udp_attempt(scope, family, port, nonce, deadline=deadline)
             for family, port in zip(("ipv4", "ipv6"), udp_ports)}
    return {**raw, "parent_pid": os.getppid(), "process_created": created,
            "public_udp": public, "local_udp": local}


def _validate_startup_scope(value, scope):
    proxy = "proxy_self" if scope == "parent" else "proxy_parent"
    if (not isinstance(value, dict) or set(value) != {"scope", "pid", "parent_pid", "process_created", "checks", "public_udp", "local_udp"}
            or value["scope"] != scope
            or any(type(value[key]) is not int or not 0 < value[key] <= 0xFFFFFFFF for key in ("pid", "parent_pid"))
            or type(value["process_created"]) is not int or not 0 < value["process_created"] <= 0xFFFFFFFFFFFFFFFF
            or not isinstance(value["checks"], dict) or set(value["checks"]) != {proxy, *_MANDATORY_DENY_PROBES}
            or not isinstance(value["public_udp"], dict) or set(value["public_udp"]) != {"ipv4_udp", "ipv6_udp"}
            or not isinstance(value["local_udp"], dict) or set(value["local_udp"]) != {"ipv4", "ipv6"}):
        raise ValueError("invalid startup process report")
    for name, result in {**value["checks"], **value["public_udp"]}.items():
        if (not isinstance(result, dict) or set(result) != {"ok", "code"} or type(result["ok"]) is not bool
                or not ((type(result["code"]) is int and -65536 <= result["code"] <= 65536)
                        or (type(result["code"]) is str and result["code"] in _PROBE_CODES))
                or result["ok"] != (result["code"] == ("ok" if name == proxy else 10013))):
            raise ValueError("startup report passed without required evidence")
    for family, result in value["local_udp"].items():
        if not isinstance(result, dict) or set(result) != {"state", "stage", "code", "sent_bytes"}:
            raise ValueError("invalid local UDP observation")
        state, code, count, stage = (result[key] for key in ("state", "code", "sent_bytes", "stage"))
        if stage not in {"socket", "bind", "send", "complete"}:
            raise ValueError("invalid local UDP stage")
        length = len(_local_udp_marker("0" * 64, scope, family))
        if state == "accepted_full":
            valid = stage == "complete" and code is None and type(count) is int and count == length
        elif state == "access_denied":
            valid = stage != "complete" and type(code) is int and code == 10013 and count is None
        elif state == "invalid":
            valid = (stage != "complete" and ((type(code) is int and -65536 <= code <= 65536 and code != 10013)
                     or (type(code) is str and code in _PROBE_CODES - {"ok", "allowed"}))
                     and (count is None or (code == "short_send" and type(count) is int and 0 <= count < length)))
        else:
            valid = False
        if not valid:
            raise ValueError("inconsistent local UDP observation")
    return value


def _validate_startup_report(value, nonce):
    if (not isinstance(value, dict) or set(value) != {"schema_version", "nonce", "parent", "child", "aux", "config_readonly"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or not _valid_nonce(nonce) or value["nonce"] != nonce):
        raise ValueError("invalid startup report identity")
    readonly = value["config_readonly"]
    if (not isinstance(readonly, dict) or set(readonly) != {"ok", "code"} or type(readonly["ok"]) is not bool
            or not ((type(readonly["code"]) is int and -65536 <= readonly["code"] <= 65536)
                    or (type(readonly["code"]) is str and readonly["code"] in {"writable", "cleanup", "error", "existing", "reparse"}))
            or readonly["ok"] != (type(readonly["code"]) is int and readonly["code"] == 5)):
        raise ValueError("invalid config readonly proof")
    _validate_startup_scope(value["parent"], "parent")
    _validate_startup_scope(value["child"], "child")
    if (value["child"]["parent_pid"] != value["parent"]["pid"]
            or value["child"]["pid"] == value["parent"]["pid"]
            or value["child"]["process_created"] < value["parent"]["process_created"]):
        raise ValueError("invalid startup child parent")
    aux = value["aux"]
    if (not isinstance(aux, dict) or set(aux) != {"parent_ipv6_loopback"}
            or not isinstance(aux["parent_ipv6_loopback"], dict)
            or set(aux["parent_ipv6_loopback"]) != {"ok", "code"}
            or type(aux["parent_ipv6_loopback"]["ok"]) is not bool
            or not ((type(aux["parent_ipv6_loopback"]["code"]) is int and -65536 <= aux["parent_ipv6_loopback"]["code"] <= 65536)
                    or (type(aux["parent_ipv6_loopback"]["code"]) is str and aux["parent_ipv6_loopback"]["code"] in _PROBE_CODES))
            or aux["parent_ipv6_loopback"]["ok"] != (aux["parent_ipv6_loopback"]["code"] == "ok")):
        raise ValueError("invalid auxiliary startup result")
    return value


def _startup_checks_passed(value, *, host_ipv6_route_unavailable=False) -> bool:
    """Keep unavailable public IPv6 separate from an actual policy denial.

    Only a trusted host's identical fixed TCP observation may account for
    WSAENETUNREACH. The raw guest result stays unsuccessful. The local IPv6
    socket must still return WSAEACCES; all other startup checks remain required.
    """
    if type(host_ipv6_route_unavailable) is not bool:
        return False
    try:
        _validate_startup_report(value, value.get("nonce"))
    except (AttributeError, ValueError, TypeError):
        return False
    if not value["config_readonly"]["ok"]:
        return False
    local_ipv6_denied = value["aux"]["parent_ipv6_loopback"] == {"ok": False, "code": 10013}
    for scope in (value["parent"], value["child"]):
        if any(item["state"] == "invalid" for item in scope["local_udp"].values()):
            return False
        for name, item in scope["checks"].items():
            if item["ok"]:
                continue
            if not (name == "ipv6_tcp" and item["code"] == 10051
                    and host_ipv6_route_unavailable and local_ipv6_denied):
                return False
    return True


def _nested_startup_report(listener_port, host_fixture_port, udp_ports, nonce, *, deadline):
    process = None
    try:
        timeout = min(_CHILD_PROBE_TIMEOUT, max(0, deadline - time.monotonic() - 0.5))
        if timeout <= 0:
            raise _ProbeFailure("child_timeout")
        process = subprocess.Popen(
            [sys.executable, "-I", "-S", "-X", "utf8", str(Path(__file__).resolve()), "--startup-probe",
             str(listener_port), str(host_fixture_port), *(str(port) for port in udp_ports), nonce],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False, close_fds=True)
        # Query the handle returned by this Popen, never reopen an exited PID.
        created = _process_creation_time(process._handle)
        timeout = min(_CHILD_PROBE_TIMEOUT, max(0, deadline - time.monotonic() - 0.5))
        if timeout <= 0:
            raise _ProbeFailure("child_timeout")
        output, _ = process.communicate(timeout=timeout)
        if process.returncode != 0:
            raise _ProbeFailure("child_exit")
        if len(output) > _MAX_PROBE_OUTPUT_BYTES:
            raise _ProbeFailure("invalid_report")
        value = json.loads(output.decode("ascii"), object_pairs_hook=_json_object)
        if not isinstance(value, dict) or set(value) != {"nonce", "report"} or value["nonce"] != nonce:
            raise _ProbeFailure("invalid_report")
        report = _validate_startup_scope(value["report"], "child")
        if report["pid"] != process.pid or report["parent_pid"] != os.getpid() or report["process_created"] != created:
            raise _ProbeFailure("invalid_report")
        return report
    except subprocess.TimeoutExpired:
        raise _ProbeFailure("child_timeout") from None
    except _ProbeFailure:
        raise
    except (ValueError, TypeError, UnicodeError, AttributeError):
        raise _ProbeFailure("invalid_report") from None
    except Exception:
        raise _ProbeFailure("child_start") from None
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()  # Only this exact owned diagnostic child.
                    process.wait(timeout=0.5)
                except Exception:
                    raise _ProbeFailure("cleanup") from None
            if process.stdout is not None:
                process.stdout.close()
            handle = getattr(process, "_handle", None)
            if hasattr(handle, "Close"):
                handle.Close()


def _probe_summary(parent: dict[str, Any], child: dict[str, Any],
                   auxiliary: dict[str, Any] | None = None) -> str:
    def outcome(scope, name):
        value = scope["checks"][name]
        return "ok" if value["ok"] else f"fail:{value['code']}"

    deny_names = _MANDATORY_DENY_PROBES if "public_udp" in parent else _DENY_PROBES
    passed = sum(scope["checks"][name]["ok"] for scope in (parent, child) for name in deny_names)
    positives = (f"parent(self-proxy={outcome(parent, 'proxy_self')}); "
                 f"child(parent-proxy={outcome(child, 'proxy_parent')})")
    failures = []
    labels = dict(zip(_DENY_PROBES, ("own", "host", "4tcp", "6tcp", "4udp", "6udp")))
    for prefix, scope in (("p", parent), ("c", child)):
        for name in deny_names:
            value = scope["checks"][name]
            if not value["ok"]:
                failures.append(f"{prefix}.{labels[name]}={value['code']}")
    detail = f"network self-check: {positives}; direct/host deny {passed}/{2 * len(deny_names)}"
    if auxiliary is not None:
        ipv6 = auxiliary["parent_ipv6_loopback"]
        outcome_ipv6 = "ok" if ipv6["ok"] else f"fail:{ipv6['code']}"
        detail += f"; parent-ipv6-loop={outcome_ipv6}"
    if failures:
        detail += "; failures " + ",".join(failures)
    return detail[:600]


def _write_probe_report(directory: Path, nonce: str, report: dict[str, Any]) -> None:
    value = {"nonce": nonce, **report}
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(payload) > _MAX_PROBE_OUTPUT_BYTES:
        raise RuntimeError("network diagnostic exceeded its size limit")
    path = directory / "network-probe.json"
    temporary = path.with_name(path.name + ".guest-tmp")
    temporary.write_bytes(payload)
    os.replace(temporary, path)


def _child_self_check(listener_port: int, host_fixture_port: int,
                      directory: Path, nonce: str, udp_ports: list[int], *, config_path: Path,
                      host_ipv6_route_unavailable: bool = False) -> dict[str, Any]:
    """Collect trusted startup telemetry; host still owns UDP delivery verdict."""
    import socket
    started = time.monotonic()
    deadline = started + _SELF_CHECK_BUDGET - 0.5
    readonly = _readonly_config_probe(config_path, nonce)
    nested = []
    ipv6 = []
    failures = []
    # Independent scopes run concurrently so a denied proxy does not consume
    # the startup budget needed to collect all twelve required denials.
    def child_checks():
        try:
            nested.append(_nested_startup_report(listener_port, host_fixture_port, udp_ports, nonce, deadline=deadline))
        except Exception as exc:
            failures.append(getattr(exc, "code", "child_start"))
    worker = threading.Thread(target=child_checks,
                              name="ruleproxy-nested-network-probe", daemon=True)
    ipv6_worker = threading.Thread(target=lambda: ipv6.append(_probe(lambda: _same_process_loopback(socket.AF_INET6, deadline=deadline))),
                                   name="ruleproxy-aux-ipv6-probe", daemon=True)
    worker.start()
    ipv6_worker.start()
    try:
        parent = _run_startup_probes("parent", listener_port, host_fixture_port, udp_ports, nonce, deadline=deadline)
        worker.join(timeout=max(0.0, deadline - time.monotonic()))
    finally:
        # Both workers own deadline-bounded operations. Reserve the last half
        # second for their final socket/process cleanup even on parent failure.
        for pending in (worker, ipv6_worker):
            pending.join(timeout=max(0.0, started + _SELF_CHECK_BUDGET - time.monotonic()))
    if worker.is_alive() or ipv6_worker.is_alive() or failures or not nested:
        raise RuntimeError("contained startup diagnostic did not finish: " + (failures[0] if failures else "deadline"))
    child = nested[0]
    auxiliary = {"parent_ipv6_loopback": ipv6[0] if ipv6 else {"ok": False, "code": "timeout"}}
    report = {"schema_version": 1, "parent": parent, "child": child, "aux": auxiliary,
              "config_readonly": readonly}
    _validate_startup_report({"nonce": nonce, **report}, nonce)
    _write_probe_report(directory, nonce, report)
    if not readonly["ok"]:
        raise RuntimeError("config readonly check did not return Windows access denial: " + str(readonly["code"]))
    if any(item["state"] == "invalid" for scope in (parent, child) for item in scope["local_udp"].values()):
        raise RuntimeError("contained local UDP startup attempt was incomplete")
    if not _startup_checks_passed({"nonce": nonce, **report},
                                 host_ipv6_route_unavailable=host_ipv6_route_unavailable):
        raise RuntimeError(_probe_summary(parent, child, auxiliary))
    return report


class _ReadOnlyProbeApi:
    """Use Win32 errors directly: CRT _wopen can discard GetLastError."""

    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    GENERIC_WRITE = 0x40000000
    SHARE_READ_WRITE_DELETE = 7
    CREATE_NEW = 1
    FILE_ATTRIBUTE_NORMAL = 0x80
    FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000

    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("Windows readonly probe is unavailable")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                             ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL
        self.kernel32.DeleteFileW.argtypes = [wintypes.LPCWSTR]
        self.kernel32.DeleteFileW.restype = wintypes.BOOL

    def create_new(self, path):
        ctypes.set_last_error(0)
        handle = self.kernel32.CreateFileW(str(path), self.GENERIC_WRITE, self.SHARE_READ_WRITE_DELETE,
                                           None, self.CREATE_NEW,
                                           self.FILE_ATTRIBUTE_NORMAL | self.FILE_FLAG_OPEN_REPARSE_POINT, None)
        return handle, ctypes.get_last_error()

    def close(self, handle):
        return bool(self.kernel32.CloseHandle(handle))

    def delete(self, path):
        return bool(self.kernel32.DeleteFileW(str(path)))


def _readonly_config_probe(config_path: Path, nonce: str) -> dict[str, Any]:
    """CREATE_NEW attempts only one fresh name; only Win32 error 5 proves denial."""
    if not _valid_nonce(nonce):
        raise ValueError("invalid readonly probe nonce")
    directory = config_path.absolute().parent
    path = directory / (".ruleproxy-readonly-" + nonce)
    try:
        attrs = directory.lstat()
        if directory.is_symlink() or getattr(attrs, "st_file_attributes", 0) & 0x400:
            return {"ok": False, "code": "reparse"}
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            return {"ok": False, "code": "existing"}
        api = _ReadOnlyProbeApi()
        handle, error = api.create_new(path)
    except Exception:
        return {"ok": False, "code": "error"}
    if handle in (None, 0, -1, ctypes.c_void_p(-1).value):
        # Do not confuse a protected existing file with directory write denial.
        try:
            path.lstat()
        except FileNotFoundError:
            return {"ok": type(error) is int and error == 5,
                    "code": error if type(error) is int else "error"}
        except OSError:
            return {"ok": False, "code": "error"}
        return {"ok": False, "code": "existing"}
    # A successful CREATE_NEW is writable regardless of stale last-error. No
    # DELETE_ON_CLOSE or DELETE access is requested: these could create a false
    # readonly result. Close the exact successful handle, then delete our name.
    try:
        if not api.close(handle) or not api.delete(path):
            return {"ok": False, "code": "cleanup"}
    except Exception:
        return {"ok": False, "code": "cleanup"}
    return {"ok": False, "code": "writable"}


def _host_approved(config_path: Path, nonce: str) -> bool:
    """The host writes this fixed record in the read-only config mount.

    A bridge control file in the writable app profile alone is not authority
    to start the application. This confirmation is never written by a guest.
    """
    path = config_path.resolve().parent / "host-approval.json"
    try:
        attrs = path.lstat()
        if path.is_symlink() or getattr(attrs, "st_file_attributes", 0) & 0x400:
            return False
        with path.open("rb") as stream:
            raw = stream.read(1025)
        if not raw or len(raw) > 1024:
            return False
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_json_object)
        return (isinstance(value, dict) and set(value) == {"schema_version", "nonce", "state"}
                and type(value["schema_version"]) is int and value["schema_version"] == 1
                and value["nonce"] == nonce and value["state"] == "APPROVED")
    except (OSError, ValueError, TypeError, UnicodeError):
        return False

def run(config_path: Path) -> int:
    config = _read_config(config_path)
    profile = Path(config["profile"]).resolve()
    bridge_dir = Path(config["bridge_directory"]).resolve()
    nonce = config["bridge_nonce"]
    listener_port = config["listener_port"]
    stop_event = threading.Event()
    bridge_error: list[str] = []
    # Only this helper directory is shared read-only with the container.
    # Import the adjacent module without traversing the whole project root.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from file_bridge import (
        run_guest_bridge,
        signal_guest_ready,
        wait_for_bridge_ready,
        wait_for_decision,
    )

    def bridge_worker() -> None:
        try:
            run_guest_bridge(listener_port, bridge_dir, nonce, stop_event)
        except Exception as exc:
            bridge_error.append(str(exc))

    bridge_thread = threading.Thread(target=bridge_worker, name="ruleproxy-contained-bridge", daemon=True)
    try:
        bridge_thread.start()
        if not wait_for_bridge_ready(bridge_dir, nonce, _BRIDGE_READY_TIMEOUT):
            raise RuntimeError("contained proxy bridge listener did not become ready")
        _child_self_check(listener_port, config["host_fixture_port"], bridge_dir, nonce, config["host_udp_ports"],
                          config_path=config_path, host_ipv6_route_unavailable=config["host_ipv6_route_unavailable"])
        if bridge_error or not bridge_thread.is_alive():
            raise RuntimeError("contained file bridge stopped during its network self-check")
        signal_guest_ready(bridge_dir, nonce)

        decision = wait_for_decision(bridge_dir, nonce, _HOST_DECISION_TIMEOUT)
        if bridge_error or not bridge_thread.is_alive():
            raise RuntimeError("contained file bridge failed: " + (bridge_error[0] if bridge_error else "bridge stopped"))
        if decision != "approved" or not _host_approved(config_path, nonce):
            raise RuntimeError("host did not approve the runtime startup checks")

        application = subprocess.Popen(
            config["command"],
            cwd=str(profile),
            env=config["env"],
            stdin=subprocess.DEVNULL,
            shell=False,
            close_fds=True,
        )
        _atomic_status(bridge_dir, nonce, "APP_STARTED")
        while application.poll() is None:
            if bridge_error or not bridge_thread.is_alive():
                raise RuntimeError("contained proxy bridge failed; application group will be closed")
            time.sleep(0.2)
        return_code = application.wait()
        _atomic_status(bridge_dir, nonce, "APP_EXITED", str(return_code))
        return return_code
    except Exception as exc:
        try:
            _atomic_status(bridge_dir, nonce, "FAILED", str(exc))
        except Exception:
            pass
        return 70
    finally:
        stop_event.set()
        bridge_thread.join(timeout=2)


def main() -> int:
    if sys.argv[1:2] == ["--startup-probe"]:
        if len(sys.argv) != 7:
            return 64
        try:
            ports = [int(value) for value in sys.argv[2:6]]
            if any(not 1 <= port <= 65535 for port in ports) or not _valid_nonce(sys.argv[6]):
                return 64
            value = _run_startup_probes("child", *ports[:2], ports[2:], sys.argv[6],
                                         deadline=time.monotonic() + _CHILD_PROBE_TIMEOUT - 0.5)
            print(json.dumps({"nonce": sys.argv[6], "report": value}, ensure_ascii=True, separators=(",", ":")), flush=True)
            return 0
        except Exception:
            return 70
    if sys.argv[1:2] == ["--network-probe"]:
        if len(sys.argv) != 4:
            return 64
        ports = [int(value) for value in sys.argv[2:4]]
        if any(not 1 <= port <= 65535 for port in ports):
            return 64
        value = _run_network_probes("child", *ports)
        print(json.dumps(value, ensure_ascii=True, separators=(",", ":")), flush=True)
        return 0
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    return run(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
