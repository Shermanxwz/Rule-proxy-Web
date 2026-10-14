"""MXC-contained Windows guest wrapper for deny-all proxy launches.

The helper starts a localhost TCP bridge and proves its startup path before it
starts the selected application. The helper's host relay has no network API;
the file bridge relays bytes only to the configured Mihomo loopback listener.
"""
from __future__ import annotations

import argparse
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
_BRIDGE_READY_TIMEOUT = 10.0
_HOST_DECISION_TIMEOUT = 45.0


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
    value = json.loads(raw.decode("utf-8"))
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
    }
    if set(value) != required:
        raise ValueError("guest runtime config fields are invalid")
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
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ValueError("bridge nonce is invalid")
    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise ValueError("bridge nonce is invalid") from exc
    return value


_CHILD_PROBE_TIMEOUT = 20.0
_SELF_CHECK_BUDGET = 22.0
_MAX_PROBE_OUTPUT_BYTES = 8192
_DENY_PROBES = ("host_loopback", "ipv4_tcp", "ipv6_tcp", "ipv4_udp", "ipv6_udp")
_PROBE_CODES = frozenset({"ok", "allowed", "timeout", "reply", "io", "error", "cleanup",
                          "child_timeout", "child_start", "child_exit", "invalid_report"})


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


def _receive_exact(connection, length: int) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + _SOCKET_CHECK_TIMEOUT
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


def _proxy_roundtrip(listener_port: int) -> None:
    import socket
    # Method negotiation has no CONNECT request, destination, or origin data.
    with socket.create_connection(("127.0.0.1", listener_port), timeout=_SOCKET_CHECK_TIMEOUT) as connection:
        connection.settimeout(_SOCKET_CHECK_TIMEOUT)
        connection.sendall(b"\x05\x01\x00")
        if _receive_exact(connection, 2) != b"\x05\x00":
            raise _ProbeFailure("reply")


def _same_process_loopback(family: int | None = None) -> None:
    import socket
    family = socket.AF_INET if family is None else family
    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    listener = socket.socket(family, socket.SOCK_STREAM)
    worker = None
    errors = []
    try:
        listener.bind((host, 0))
        listener.listen(1)
        listener.settimeout(_SOCKET_CHECK_TIMEOUT)

        def echo():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(_SOCKET_CHECK_TIMEOUT)
                    if _receive_exact(connection, 4) != b"RP01":
                        raise _ProbeFailure("reply")
                    connection.sendall(b"RP01")
            except Exception:
                errors.append(True)

        worker = threading.Thread(target=echo, name="ruleproxy-own-loopback-probe", daemon=True)
        worker.start()
        with socket.create_connection((host, listener.getsockname()[1]),
                                      timeout=_SOCKET_CHECK_TIMEOUT) as connection:
            connection.settimeout(_SOCKET_CHECK_TIMEOUT)
            connection.sendall(b"RP01")
            if _receive_exact(connection, 4) != b"RP01":
                raise _ProbeFailure("reply")
        worker.join(timeout=_SOCKET_CHECK_TIMEOUT + 0.2)
        if worker.is_alive():
            raise _ProbeFailure("cleanup")
        if errors:
            raise _ProbeFailure("reply")
    finally:
        listener.close()
        if worker is not None:
            worker.join(timeout=_SOCKET_CHECK_TIMEOUT + 0.2)


def _socket_attempt(family: int, kind: int, address: tuple) -> None:
    import socket
    with socket.socket(family, kind) as connection:
        connection.settimeout(_SOCKET_CHECK_TIMEOUT)
        if kind == socket.SOCK_DGRAM:
            # Exercise ALE_AUTH_CONNECT with an empty UDP datagram.
            connection.sendto(b"", address)
        else:
            # TCP connect transmits SYN setup only, never application payload.
            connection.connect(address)


def _run_network_probes(scope: str, listener_port: int, host_fixture_port: int) -> dict[str, Any]:
    import socket
    if scope not in {"parent", "child"}:
        raise ValueError("invalid network probe scope")
    proxy_name = "proxy_self" if scope == "parent" else "proxy_parent"
    checks = {
        proxy_name: _probe(lambda: _proxy_roundtrip(listener_port)),
        "own_loopback": _probe(_same_process_loopback),
    }
    for name, family, kind, address in (
        ("host_loopback", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", host_fixture_port)),
        ("ipv4_tcp", socket.AF_INET, socket.SOCK_STREAM, ("1.1.1.1", 443)),
        ("ipv6_tcp", socket.AF_INET6, socket.SOCK_STREAM, ("2606:4700:4700::1111", 443, 0, 0)),
        ("ipv4_udp", socket.AF_INET, socket.SOCK_DGRAM, ("1.1.1.1", 53)),
        ("ipv6_udp", socket.AF_INET6, socket.SOCK_DGRAM, ("2606:4700:4700::1111", 53, 0, 0)),
    ):
        checks[name] = _probe(lambda family=family, kind=kind, address=address:
                             _socket_attempt(family, kind, address), deny=True)
    return {"scope": scope, "pid": os.getpid(), "checks": checks}


def _unavailable_child(code: str) -> dict[str, Any]:
    return {"scope": "child", "pid": 0,
            "checks": {name: {"ok": False, "code": code}
                       for name in ("proxy_parent", "own_loopback", *_DENY_PROBES)}}


def _validated_child_report(raw: str) -> dict[str, Any]:
    if len(raw.encode("utf-8")) > _MAX_PROBE_OUTPUT_BYTES:
        raise ValueError("oversized network probe response")
    value = json.loads(raw)
    expected = {"proxy_parent", "own_loopback", *_DENY_PROBES}
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


def _probe_summary(parent: dict[str, Any], child: dict[str, Any],
                   auxiliary: dict[str, Any] | None = None) -> str:
    def outcome(scope, name):
        value = scope["checks"][name]
        return "ok" if value["ok"] else f"fail:{value['code']}"

    passed = sum(scope["checks"][name]["ok"] for scope in (parent, child) for name in _DENY_PROBES)
    positives = (f"parent(self-proxy={outcome(parent, 'proxy_self')},own-loop={outcome(parent, 'own_loopback')}); "
                 f"child(parent-proxy={outcome(child, 'proxy_parent')},own-loop={outcome(child, 'own_loopback')})")
    failures = []
    labels = dict(zip(_DENY_PROBES, ("host", "4tcp", "6tcp", "4udp", "6udp")))
    for prefix, scope in (("p", parent), ("c", child)):
        for name in _DENY_PROBES:
            value = scope["checks"][name]
            if not value["ok"]:
                failures.append(f"{prefix}.{labels[name]}={value['code']}")
    detail = f"network self-check: {positives}; direct/host deny {passed}/10"
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
                      directory: Path | None = None, nonce: str | None = None) -> dict[str, Any]:
    """Collect both generations independently, then reject any failed check."""
    import socket
    started = time.monotonic()
    nested = []
    ipv6 = []
    # Independent scopes run concurrently so a denied proxy does not consume
    # the startup budget needed to collect all ten direct/host denials.
    worker = threading.Thread(target=lambda: nested.append(_nested_network_report(listener_port, host_fixture_port)),
                              name="ruleproxy-nested-network-probe", daemon=True)
    ipv6_worker = threading.Thread(target=lambda: ipv6.append(_probe(lambda: _same_process_loopback(socket.AF_INET6))),
                                   name="ruleproxy-aux-ipv6-probe", daemon=True)
    worker.start()
    ipv6_worker.start()
    parent = _run_network_probes("parent", listener_port, host_fixture_port)
    worker.join(timeout=max(0.0, _SELF_CHECK_BUDGET - (time.monotonic() - started)))
    child = nested[0] if nested else _unavailable_child("child_timeout")
    # Collect auxiliary IPv6 under the same deadline, after the mandatory child.
    # Its result never changes the fourteen required startup checks.
    ipv6_worker.join(timeout=max(0.0, _SELF_CHECK_BUDGET - (time.monotonic() - started)))
    auxiliary = {"parent_ipv6_loopback": ipv6[0] if ipv6 else {"ok": False, "code": "timeout"}}
    report = {"parent": parent, "child": child, "aux": auxiliary}
    if directory is not None and nonce is not None:
        _write_probe_report(directory, nonce, report)
    if not all(item["ok"] for scope in (parent, child) for item in scope["checks"].values()):
        raise RuntimeError(_probe_summary(parent, child, auxiliary))
    return report

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
        _child_self_check(listener_port, config["host_fixture_port"], bridge_dir, nonce)
        if bridge_error or not bridge_thread.is_alive():
            raise RuntimeError("contained file bridge stopped during its network self-check")
        signal_guest_ready(bridge_dir, nonce)

        decision = wait_for_decision(bridge_dir, nonce, _HOST_DECISION_TIMEOUT)
        if bridge_error or not bridge_thread.is_alive():
            raise RuntimeError("contained file bridge failed: " + (bridge_error[0] if bridge_error else "bridge stopped"))
        if decision != "approved":
            raise RuntimeError("host did not approve the deny-all runtime self-check")

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
