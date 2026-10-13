"""Local SOCKS5 witness for the disposable Windows WinDivert/WFP experiment.

This server does not contact the requested destination. An observed CONNECT
proves that the candidate diverted a probe to this listener, not that the
application has an end-to-end secure network path.
"""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path


def _read(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("short SOCKS5 request")
        data.extend(chunk)
    return bytes(data)


def _handle(sock: socket.socket, log: Path) -> None:
    with sock:
        sock.settimeout(5)
        version, methods = _read(sock, 2)
        if version != 5 or not methods:
            return
        offered = _read(sock, methods)
        if 0 not in offered:
            sock.sendall(b"\x05\xff")
            return
        sock.sendall(b"\x05\x00")
        version, command, _, address_type = _read(sock, 4)
        if version != 5 or command != 1:
            return
        if address_type == 1:
            address = socket.inet_ntop(socket.AF_INET, _read(sock, 4))
        elif address_type == 4:
            address = socket.inet_ntop(socket.AF_INET6, _read(sock, 16))
        elif address_type == 3:
            address = _read(sock, _read(sock, 1)[0]).decode("ascii", "replace")
        else:
            return
        port = int.from_bytes(_read(sock, 2), "big")
        with log.open("a", encoding="utf-8") as out:
            out.write(json.dumps({"address": address, "port": port}) + "\n")
        sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        try:
            sock.recv(4096)
            sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
        except (OSError, TimeoutError):
            pass


def serve(port_file: Path, log: Path) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port_file.write_text(str(server.getsockname()[1]), encoding="ascii")
        while True:
            sock, _ = server.accept()
            threading.Thread(target=_handle, args=(sock, log), daemon=True).start()


def profile(path: Path, port: int, exe: str) -> None:
    from ruleproxy.proxybridge_candidate import candidate_profile

    path.write_text(json.dumps(candidate_profile([exe], port)), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "serve":
        serve(Path(sys.argv[2]), Path(sys.argv[3]))
    elif len(sys.argv) == 5 and sys.argv[1] == "profile":
        profile(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
    else:
        raise SystemExit("usage: proxybridge_witness.py serve PORT_FILE LOG | profile PROFILE PORT EXE")
