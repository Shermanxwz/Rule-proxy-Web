#!/usr/bin/env python3
"""User-invoked, fail-closed MXC proxy-isolation smoke check for Windows.

No user app is launched and no firewall, route, DNS, proxy, or other machine
settings are changed. Direct-IP probes use documentation-only destinations and
send no application payload (UDP probes send an empty datagram). A failed TCP
connect alone is observational, not proof of filtering if the host has no route.
"""

from __future__ import annotations

import argparse
import json
import os
import select
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

# Make the repository package importable when this file is invoked directly.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ruleproxy import windows_runtime

_TIMEOUT = 2.0
_WRAPPER_TIMEOUT = 45.0

# Runs inside BaseContainer. It only probes the local proxy endpoint, one
# temporary host-loopback listener, and RFC 5737 / RFC 3849 documentation IPs.
_PROBE_CODE = r'''import json, socket, sys
port = int(sys.argv[1])
loopback_port = int(sys.argv[2])
result_path = sys.argv[3]
timeout = 2.0

def proxy_responds():
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            return s.recv(128).startswith(b"HTTP/")
    except OSError:
        return False

def tcp_unreachable(family, address):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((address, 443))
        return False
    except OSError:
        return True

def udp_send_blocked(family, address):
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(b"", (address, 9))
        return False
    except OSError:
        return True

def loopback_blocked():
    try:
        with socket.create_connection(("127.0.0.1", loopback_port), timeout=timeout):
            return False
    except OSError:
        return True

results = {
    "proxy_http_response": proxy_responds(),
    "nonproxy_loopback_tcp_blocked": loopback_blocked(),
    "ipv4_direct_tcp_unreachable": tcp_unreachable(socket.AF_INET, "198.51.100.1"),
    "ipv6_direct_tcp_unreachable": tcp_unreachable(socket.AF_INET6, "2001:db8::1"),
    "ipv4_direct_udp_send_blocked": udp_send_blocked(socket.AF_INET, "198.51.100.1"),
    "ipv6_direct_udp_send_blocked": udp_send_blocked(socket.AF_INET6, "2001:db8::1"),
}
print(json.dumps(results, sort_keys=True))
with open(result_path, "w", encoding="utf-8") as output:
    output.write(json.dumps(results, sort_keys=True))
'''


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def verify(runtime_path: Path, profile: Path, proxy_port: int) -> dict[str, bool]:
    if sys.platform != "win32":
        raise windows_runtime.UnsupportedRuntimeError("this smoke check must run on Windows")
    profile = profile.expanduser().resolve()
    profile.mkdir(parents=True, exist_ok=True)
    app_profile = profile / "windows-runtime-verify"
    app_profile.mkdir(parents=True, exist_ok=True)

    # A temporary listener lets the contained Python child attempt direct
    # non-proxy loopback without sending any bytes. It is scoped to this process.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.setblocking(False)
    loopback_port = listener.getsockname()[1]
    policy_path = app_profile / "windows-runtime-verify-policy.json"
    result_path = app_profile / "windows-runtime-verify-results.json"

    command = [
        sys.executable,
        "-I",
        "-c",
        _PROBE_CODE,
        str(proxy_port),
        str(loopback_port),
        str(result_path),
    ]
    policy = windows_runtime.build_policy(command, os.environ, app_profile, proxy_port)
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")

    try:
        # Request-aware probe with the exact Python command and strict policy.
        probed = windows_runtime._probe_request(runtime_path, policy)
        if probed.get("tier") != "base-container":
            raise windows_runtime.UnsupportedRuntimeError("MXC did not select BaseContainer")

        proc = subprocess.Popen(
            [str(runtime_path.resolve(strict=True)), "--config", str(policy_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        try:
            proc.wait(timeout=_WRAPPER_TIMEOUT)
        except subprocess.TimeoutExpired:
            try:
                windows_runtime.stop(proc, timeout=15.0)
            except windows_runtime.SafeStopError as exc:
                raise RuntimeError(
                    f"safe stop could not complete; MXC wrapper PID {proc.pid} was left running. "
                    "Close the contained window manually if it appears, then retry."
                ) from exc
        if proc.returncode != 0:
            raise RuntimeError(f"MXC verification process failed with status {proc.returncode}")
        try:
            values: Any = json.loads(result_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError("contained Python probe did not save valid JSON") from exc
        if not isinstance(values, dict) or any(type(value) is not bool for value in values.values()):
            raise RuntimeError("contained Python probe returned a non-boolean result")

        # The listener is nonblocking and carries no user data. A queued accept
        # proves the direct non-proxy localhost connection reached the host.
        readable, _, _ = select.select([listener], [], [], 0)
        if readable:
            conn, _ = listener.accept()
            conn.close()
            values["nonproxy_loopback_tcp_blocked"] = False

        result_path.write_text(json.dumps(values, indent=2, sort_keys=True), encoding="utf-8")
        return values
    finally:
        listener.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", required=True, type=Path, help="path to the already-installed MXC runtime")
    parser.add_argument("--profile", required=True, type=Path, help="directory for isolated profile and JSON results")
    parser.add_argument("--proxy-port", required=True, type=_port, help="local HTTP proxy port")
    args = parser.parse_args()
    try:
        results = verify(args.runtime, args.profile, args.proxy_port)
    except Exception as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(results, sort_keys=True))
    # False results are either observed bypasses or inconclusive UDP behavior;
    # never call the run successful unless each requested check passed.
    return 0 if all(results.values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())
