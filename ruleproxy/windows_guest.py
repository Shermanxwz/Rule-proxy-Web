"""Contained startup gate for the native, endpoint-scoped Windows proxy policy.

No listening TCP proxy or file byte relay runs in the container. The helper and
all descendants use the single host proxy authorized by the PSEC policy.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any

_MAX_CONFIG_BYTES = 128 * 1024
_HOST_DECISION_TIMEOUT = 45.0


def _atomic_status(directory: Path, nonce: str, state: str, detail: str = "", *, started: bool = False) -> None:
    path = directory / "guest-status.json"
    value = {"nonce": nonce, "state": state, "started": started}
    if detail:
        value["detail"] = detail[-1800:]
    temp = path.with_suffix(".tmp")
    with temp.open("w", encoding="ascii", newline="") as stream:
        json.dump(value, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)


def _read_config(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(_MAX_CONFIG_BYTES + 1)
    if not raw or len(raw) > _MAX_CONFIG_BYTES:
        raise ValueError("guest config has an invalid size")
    value = json.loads(raw.decode("utf-8"))
    required = {"command", "env", "profile", "proxy_port", "status_directory", "nonce", "fixtures"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("guest config fields are invalid")
    command = value["command"]
    if (not isinstance(command, list) or not command or len(command) > 128
            or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in command)
            or sum(len(arg) for arg in command) > 16_384):
        raise ValueError("application command is invalid")
    if not isinstance(value["env"], dict) or any(
        not isinstance(key, str) or not isinstance(item, str) or "\0" in key or "\0" in item
        for key, item in value["env"].items()
    ):
        raise ValueError("application environment is invalid")
    for name in ("profile", "status_directory"):
        if not isinstance(value[name], str) or not value[name] or "\0" in value[name]:
            raise ValueError(f"{name} is invalid")
    port = value["proxy_port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("proxy port is invalid")
    nonce = value["nonce"]
    if not isinstance(nonce, str) or len(nonce) != 64:
        raise ValueError("guest nonce is invalid")
    bytes.fromhex(nonce)
    fixtures = value["fixtures"]
    if not isinstance(fixtures, list) or not 2 <= len(fixtures) <= 4:
        raise ValueError("network fixtures are invalid")
    for fixture in fixtures:
        if not isinstance(fixture, dict) or set(fixture) != {"address", "port", "protocol"}:
            raise ValueError("network fixture fields are invalid")
        if fixture["address"] not in ("127.0.0.1", "::1") or fixture["protocol"] not in ("tcp", "udp"):
            raise ValueError("network fixtures must be loopback TCP/UDP endpoints")
        other = fixture["port"]
        if isinstance(other, bool) or not isinstance(other, int) or not 1 <= other <= 65535 or other == port:
            raise ValueError("network fixture port is invalid")
    if not all(any(f["address"] == "127.0.0.1" and f["protocol"] == protocol for f in fixtures)
               for protocol in ("tcp", "udp")):
        raise ValueError("IPv4 TCP and UDP fixtures are required")
    directory = Path(value["status_directory"]).resolve()
    directory.relative_to(Path(value["profile"]).resolve())
    return value


# A nested child exercises the same policy the application and its children
# inherit. Non-empty UDP packets target only controlled local test receivers.
SOCKET_CHECK_SCRIPT = r'''
import json, socket, sys
port, nonce, fixtures = int(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
with socket.create_connection(("127.0.0.1", port), timeout=3) as proxy:
    proxy.settimeout(4)
    proxy.sendall(b"\x05\x01\x00")
    response = b""
    while len(response) < 2:
        part = proxy.recv(2-len(response))
        if not part: break
        response += part
    if response != b"\x05\x00":
        raise RuntimeError("configured proxy failed the SOCKS5 handshake")
for fixture in fixtures:
    family = socket.AF_INET6 if fixture["address"] == "::1" else socket.AF_INET
    kind = socket.SOCK_STREAM if fixture["protocol"] == "tcp" else socket.SOCK_DGRAM
    address = (fixture["address"], fixture["port"])
    with socket.socket(family, kind) as sock:
        sock.settimeout(1.5)
        try:
            if kind == socket.SOCK_DGRAM:
                # A successful send is inconclusive; host receivers separately
                # require that none of these identifiable packets arrived.
                sock.sendto(nonce.encode("ascii"), address)
            else:
                sock.connect(address)
                raise RuntimeError("non-proxy TCP endpoint unexpectedly connected")
        except OSError as error:
            if (getattr(error, "winerror", None) or error.errno) != 10013:
                raise RuntimeError("endpoint was not explicitly denied: " + str(error)) from error
# A literal external IPv4 TCP destination must be rejected before any payload.
with socket.socket() as direct:
    direct.settimeout(1.5)
    try:
        direct.connect(("1.1.1.1", 443))
    except OSError as error:
        if (getattr(error, "winerror", None) or error.errno) != 10013:
            raise RuntimeError("direct IPv4 TCP was not explicitly denied: " + str(error)) from error
    else:
        raise RuntimeError("direct IPv4 TCP unexpectedly connected")
'''


def _child_self_check(proxy_port: int, fixtures: list[dict], nonce: str) -> None:
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-X", "utf8", "-c", SOCKET_CHECK_SCRIPT,
         str(proxy_port), nonce, json.dumps(fixtures)],
        capture_output=True, encoding="utf-8", errors="replace",
        timeout=20, check=False, shell=False,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "contained network check failed").strip()[-1800:])


def _wait_for_decision(directory: Path, nonce: str) -> bool:
    deadline = time.monotonic() + _HOST_DECISION_TIMEOUT
    while time.monotonic() < deadline:
        try:
            with (directory / "host-decision.json").open("rb") as stream:
                raw = stream.read(1025)
            if len(raw) > 1024:
                return False
            value = json.loads(raw.decode("ascii"))
            if isinstance(value, dict) and value.get("nonce") == nonce:
                if value.get("decision") == "approved":
                    return True
                if value.get("decision") == "rejected":
                    return False
        except (OSError, ValueError):
            pass
        time.sleep(0.05)
    return False


def run(config_path: Path) -> int:
    config = _read_config(config_path)
    profile = Path(config["profile"]).resolve()
    directory = Path(config["status_directory"]).resolve()
    nonce = config["nonce"]
    started = False
    try:
        _child_self_check(config["proxy_port"], config["fixtures"], nonce)
        _atomic_status(directory, nonce, "READY")
        if not _wait_for_decision(directory, nonce):
            raise RuntimeError("host did not approve the proxy policy self-check")
        application = subprocess.Popen(
            config["command"], cwd=str(profile), env=config["env"],
            stdin=subprocess.DEVNULL, shell=False, close_fds=True,
        )
        started = True
        _atomic_status(directory, nonce, "APP_STARTED", started=True)
        return_code = application.wait()
        _atomic_status(directory, nonce, "APP_EXITED", str(return_code), started=True)
        return return_code
    except Exception as exc:
        print(str(exc), file=sys.stderr, flush=True)
        _atomic_status(directory, nonce, "FAILED", str(exc), started=started)
        return 70


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", required=True)
    return run(Path(parser.parse_args().config))


if __name__ == "__main__":
    raise SystemExit(main())
