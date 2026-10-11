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


def _child_self_check(listener_port: int, host_fixture_port: int) -> None:
    """Run network assertions in a nested child with the same PSEC identity."""
    script = r'''
import socket, sys
guest_port, fixture_port = map(int, sys.argv[1:3])
WSAEACCES = 10013
WSAEAFNOSUPPORT = 10047

def error_code(error):
    return getattr(error, "winerror", None) or error.errno

def denied(family, kind, address, label, *, udp=False, allow_family_unsupported=False):
    try:
        with socket.socket(family, kind) as sock:
            sock.settimeout(1.5)
            if udp:
                # ALE_AUTH_CONNECT runs on the first UDP packet, not connect().
                # An empty datagram contains no user or application data.
                sock.sendto(b"", address)
            else:
                # TCP connect sends only SYN setup, never application payload.
                sock.connect(address)
    except OSError as error:
        code = error_code(error)
        if code == WSAEACCES:
            return
        if allow_family_unsupported and code == WSAEAFNOSUPPORT:
            return
        raise RuntimeError(label + " was not explicitly denied (socket error %r)" % code) from error
    raise RuntimeError(label + " unexpectedly succeeded")

# Validate a bidirectional roundtrip through the guest helper to Mihomo. A
# SOCKS5 greeting contains no CONNECT command or destination, so it cannot
# request an origin connection.
with socket.create_connection(("127.0.0.1", guest_port), timeout=3) as sock:
    sock.settimeout(4)
    sock.sendall(b"\x05\x01\x00")
    response = b""
    while len(response) < 2:
        part = sock.recv(2 - len(response))
        if not part:
            break
        response += part
    if response != b"\x05\x00":
        raise RuntimeError("local proxy did not complete the SOCKS5 greeting")

# The host holds an actual listener at fixture_port. It must be unreachable
# from inside this ProcessContainer.
denied(socket.AF_INET, socket.SOCK_STREAM,
       ("127.0.0.1", fixture_port), "host loopback")

# Literal-address TCP connection checks send no application data. A successful
# connection is an immediate fail-closed result and is closed by this scope.
denied(socket.AF_INET, socket.SOCK_STREAM,
       ("1.1.1.1", 443), "direct IPv4 TCP")
denied(socket.AF_INET6, socket.SOCK_STREAM,
       ("2606:4700:4700::1111", 443, 0, 0), "direct IPv6 TCP",
       allow_family_unsupported=True)

# UDP needs a packet to reach ALE_AUTH_CONNECT. Only explicit WSAEACCES is
# evidence of policy denial; timeout and ordinary routing errors fail closed.
denied(socket.AF_INET, socket.SOCK_DGRAM,
       ("1.1.1.1", 53), "direct IPv4 UDP", udp=True)
denied(socket.AF_INET6, socket.SOCK_DGRAM,
       ("2606:4700:4700::1111", 53, 0, 0), "direct IPv6 UDP",
       udp=True, allow_family_unsupported=True)
'''
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(listener_port), str(host_fixture_port)],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
        shell=False,
    )
    if result.returncode:
        detail = (result.stderr or result.stdout or "contained network self-check failed").strip()
        raise RuntimeError(detail[:700])


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
        _child_self_check(listener_port, config["host_fixture_port"])
        signal_guest_ready(bridge_dir, nonce)

        decision = wait_for_decision(bridge_dir, nonce, _HOST_DECISION_TIMEOUT)
        if bridge_error:
            raise RuntimeError("contained file bridge failed: " + bridge_error[0])
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
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    return run(Path(args.config))


if __name__ == "__main__":
    raise SystemExit(main())
