"""Runs inside an empty Linux network namespace. No host IP socket is inherited."""
from __future__ import annotations

import json
import select
import signal
import socket
import subprocess
import sys
import threading


def bridge(client: socket.socket, endpoint: str) -> None:
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.connect(endpoint)
        sockets = (client, peer)
        while True:
            readable, _, _ = select.select(sockets, [], [], 60)
            for source in readable:
                chunk = source.recv(65536)
                if not chunk:
                    return
                target = peer if source is client else client
                target.sendall(chunk)
    except (OSError, ValueError):
        pass
    finally:
        client.close()
        peer.close()


def main() -> int:
    policy = json.load(sys.stdin)
    # Assert the boundary BEFORE exposing the proxy or executing the workload.
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise RuntimeError("Refusing to launch: this namespace has an uplink")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", policy["port"]))
    listener.listen(64)

    def accept() -> None:
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=bridge, args=(client, "/run/ruleproxy.sock"), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    print("RULEPROXY_NAMESPACE_READY", flush=True)
    child = subprocess.Popen(policy["command"], env=policy["env"], stdin=subprocess.DEVNULL)

    def ask_child_to_exit(*_: object) -> None:
        # Chromium skips writing cookies when it is stopped by SIGTERM (a
        # session-end path). SIGINT is its normal exit request, so relay that.
        if child.poll() is None:
            child.send_signal(signal.SIGINT)

    signal.signal(signal.SIGTERM, ask_child_to_exit)
    signal.signal(signal.SIGINT, ask_child_to_exit)
    return child.wait()


if __name__ == "__main__":
    sys.exit(main())
