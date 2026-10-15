"""Controlled A/B SOCKS paths for disposable Windows transparent-proxy trials.

This fixture owns Mihomo and two loopback SOCKS5 upstreams.  Upstreams return
synthetic HTTP/DNS responses bearing the selected node's identity; they never
forward to the requested Internet destination.  A matching transaction proves
which controlled path carried a request, not Internet access or an exit IP.
Explicit SOCKS readiness probes are labelled health and are not actor evidence.
No TUN, system proxy, DNS, route, firewall, driver, or service is configured.
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import secrets
import select
import socket
import struct
import subprocess
import threading
import time


MAX_HEADER_BYTES = 16384
MAX_TRANSACTIONS = 2048
NODES = ("A", "B")


def _exact(connection, count):
    data = bytearray()
    while len(data) < count:
        chunk = connection.recv(count - len(data))
        if not chunk:
            raise EOFError("controlled SOCKS stream closed")
        data.extend(chunk)
    return bytes(data)


def _address(connection):
    kind = _exact(connection, 1)[0]
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, _exact(connection, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, _exact(connection, 16))
    elif kind == 3:
        host = _exact(connection, _exact(connection, 1)[0]).decode("ascii")
    else:
        raise ValueError("unsupported SOCKS address")
    return host, struct.unpack("!H", _exact(connection, 2))[0]


def _encode_address(host, port):
    try:
        address = ipaddress.ip_address(host)
        encoded = bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        encoded_host = host.encode("ascii")
        if not 1 <= len(encoded_host) <= 255:
            raise ValueError("invalid SOCKS hostname")
        encoded = b"\x03" + bytes([len(encoded_host)]) + encoded_host
    return encoded + struct.pack("!H", port)


def _udp_address(data):
    if len(data) < 7 or data[:3] != b"\x00\x00\x00":
        raise ValueError("fragmented or invalid SOCKS datagram")
    kind, offset = data[3], 4
    if kind in (1, 4):
        count, family = (4, socket.AF_INET) if kind == 1 else (16, socket.AF_INET6)
        if len(data) < offset + count + 2:
            raise ValueError("short SOCKS datagram")
        host = socket.inet_ntop(family, data[offset:offset + count])
        offset += count
    elif kind == 3:
        count = data[offset]
        offset += 1
        if not count or len(data) < offset + count + 2:
            raise ValueError("short SOCKS hostname")
        host = data[offset:offset + count].decode("ascii")
        offset += count
    else:
        raise ValueError("unsupported SOCKS datagram address")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    return host, port, data[offset + 2:]


def _dns_response(query, node):
    """Return one standard synthetic IN A/AAAA answer and the exact question."""
    if len(query) < 17 or len(query) > 4096:
        raise ValueError("invalid fixed DNS query length")
    identifier, flags, questions, answers, authority, _additional = struct.unpack("!6H", query[:12])
    if flags & 0x8000 or flags & 0x7800 or questions != 1 or answers or authority:
        raise ValueError("unsupported DNS query")
    labels, offset = [], 12
    while True:
        if offset >= len(query):
            raise ValueError("short DNS question")
        count = query[offset]
        offset += 1
        if count == 0:
            break
        if count > 63 or offset + count > len(query):
            raise ValueError("compressed or invalid DNS question")
        labels.append(query[offset:offset + count].decode("ascii").lower())
        offset += count
        if offset > 267:
            raise ValueError("long DNS question")
    if offset + 4 > len(query):
        raise ValueError("short DNS type")
    query_type, query_class = struct.unpack("!HH", query[offset:offset + 4])
    if query_class != 1 or query_type not in (1, 28):
        raise ValueError("only fixed IN A/AAAA questions are supported")
    question = query[12:offset + 4]
    answer_ip = ("198.51.100.101" if node == "A" else "198.51.100.102") if query_type == 1 else (
        "2001:db8::a" if node == "A" else "2001:db8::b")
    packed = ipaddress.ip_address(answer_ip).packed
    header = struct.pack("!6H", identifier, 0x8080 | (flags & 0x0100), 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", query_type, 1, 0, len(packed)) + packed
    return header + question + answer, ".".join(labels) + ".", query_type, answer_ip


def _unused_port():
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        return connection.getsockname()[1]


class Fixture:
    def __init__(self, mihomo_path, directory, *, target_ipv4="1.1.1.1",
                 target_ipv6="2606:4700:4700::1111", target_host="example.com",
                 dns_target_ipv4="1.1.1.1", dns_target_ipv6="2606:4700:4700::1111"):
        self.mihomo_path = Path(mihomo_path).resolve()
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True)
        self.target_ipv4 = str(ipaddress.IPv4Address(target_ipv4))
        self.target_ipv6 = str(ipaddress.IPv6Address(target_ipv6))
        self.dns_target_ipv4 = str(ipaddress.IPv4Address(dns_target_ipv4))
        self.dns_target_ipv6 = str(ipaddress.IPv6Address(dns_target_ipv6))
        if not isinstance(target_host, str) or not target_host or len(target_host) > 253:
            raise ValueError("invalid controlled target hostname")
        self.target_host, self.http_port, self.dns_port = target_host, 80, 53
        self.nonce = secrets.token_hex(16)
        self.ports = {}
        for node in NODES:
            port = _unused_port()
            while port in self.ports.values():
                port = _unused_port()
            self.ports[node] = port
        self.process = None
        self.log = None
        self.readiness = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._listeners = {}
        self._connections = set()
        self._threads = []
        self._transactions = []
        self._errors = []
        self._dropped = 0
        self._generation = 0
        self._started_at = time.monotonic()
        self._closed = False

    def __enter__(self):
        try:
            for node in NODES:
                listener = socket.socket()
                listener.bind(("127.0.0.1", 0))
                listener.listen(32)
                listener.settimeout(.2)
                self._listeners[node] = listener
                self._thread(self._accept, node, listener)
            self.start_proxy()
            return self
        except BaseException:
            self.close()
            raise

    def __exit__(self, *ignored):
        self.close()

    def _thread(self, function, *args):
        thread = threading.Thread(target=function, args=args, daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()
        return thread

    def _error(self, error):
        with self._lock:
            if len(self._errors) < 64:
                self._errors.append(type(error).__name__)

    def _record(self, node, protocol, host, port, **fields):
        with self._lock:
            if len(self._transactions) >= MAX_TRANSACTIONS:
                self._dropped += 1
                return
            self._transactions.append({"sequence": len(self._transactions) + 1,
                "elapsed_seconds": round(time.monotonic() - self._started_at, 6),
                "proxy_generation": self._generation, "node": node, "protocol": protocol,
                "destination": host, "destination_port": port,
                "origin_kind": "controlled_synthetic_stub", **fields})

    def _accept(self, node, listener):
        while not self._stop.is_set():
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            connection.settimeout(5)
            with self._lock:
                self._connections.add(connection)
            self._thread(self._serve, node, connection)

    def _serve(self, node, connection):
        try:
            version, count = _exact(connection, 2)
            methods = _exact(connection, count)
            if version != 5 or not count or 0 not in methods:
                connection.sendall(b"\x05\xff")
                return
            connection.sendall(b"\x05\x00")
            version, command, reserved = _exact(connection, 3)
            host, port = _address(connection)
            if version != 5 or reserved or command not in (1, 3):
                connection.sendall(b"\x05\x07\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            if command == 3:
                self._associate(node, connection)
                return
            if host not in (self.target_ipv4, self.target_ipv6, self.target_host) or port != self.http_port:
                connection.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00")
                return
            connection.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            self._http(node, connection, host, port)
        except (OSError, EOFError, ValueError, UnicodeError) as exc:
            if not self._stop.is_set():
                self._error(exc)
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()

    def _http(self, node, connection, host, port):
        request = bytearray()
        while b"\r\n\r\n" not in request and len(request) < MAX_HEADER_BYTES:
            chunk = connection.recv(min(4096, MAX_HEADER_BYTES - len(request)))
            if not chunk:
                raise EOFError("HTTP request closed before headers")
            request.extend(chunk)
        if b"\r\n\r\n" not in request:
            raise ValueError("HTTP header exceeds fixed bound")
        line = bytes(request).split(b"\r\n", 1)[0].decode("ascii")
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "GET" or parts[2] not in ("HTTP/1.0", "HTTP/1.1"):
            raise ValueError("only fixed GET requests are supported")
        path = parts[1]
        if len(path) > 2048 or self.nonce not in path:
            raise ValueError("request has no matching round nonce")
        health = path.startswith("/health/")
        content = json.dumps({"node": node, "nonce": self.nonce, "request_target": path,
                              "origin_kind": "controlled_synthetic_stub"}, separators=(",", ":")).encode("ascii")
        self._record(node, "tcp_http", host, port, nonce=self.nonce, request_target=path,
                     evidence_role="health" if health else "actor", response_complete=False)
        connection.sendall(("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
            f"X-RuleProxy-Node: {node}\r\nX-RuleProxy-Nonce: {self.nonce}\r\n"
            "X-RuleProxy-Origin: controlled-synthetic-stub\r\n"
            f"Content-Length: {len(content)}\r\nConnection: close\r\n\r\n").encode("ascii") + content)
        self._record(node, "tcp_http_response", host, port, nonce=self.nonce, request_target=path,
                     evidence_role="health" if health else "actor", response_complete=True)

    def _associate(self, node, connection):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
            relay.bind(("127.0.0.1", 0))
            relay.setblocking(False)
            connection.sendall(b"\x05\x00\x00" + _encode_address(*relay.getsockname()))
            peer = None
            while not self._stop.is_set():
                ready, _, _ = select.select((connection, relay), (), (), .2)
                if connection in ready and not connection.recv(1):
                    return
                if relay not in ready:
                    continue
                packet, sender = relay.recvfrom(8192)
                if sender[0] != "127.0.0.1" or (peer is not None and peer != sender):
                    continue
                peer = sender
                try:
                    host, port, query = _udp_address(packet)
                    if host not in (self.dns_target_ipv4, self.dns_target_ipv6) or port != self.dns_port:
                        raise ValueError("UDP target outside fixed DNS stub")
                    response, qname, query_type, answer_ip = _dns_response(query, node)
                    if self.nonce not in qname.split("."):
                        raise ValueError("DNS question has no matching round nonce")
                    health = qname.startswith("health.")
                    self._record(node, "udp_dns", host, port, nonce=self.nonce, qname=qname,
                                 query_type=query_type, answer_ip=answer_ip,
                                 evidence_role="health" if health else "actor")
                    relay.sendto(b"\x00\x00\x00" + _encode_address(host, port) + response, sender)
                except (ValueError, UnicodeError) as exc:
                    self._error(exc)

    def _config(self):
        return {"mixed-port": 0, "port": 0, "socks-port": 0, "allow-lan": False,
            "bind-address": "127.0.0.1", "mode": "rule", "log-level": "warning",
            "ipv6": True, "tun": {"enable": False}, "dns": {"enable": False},
            "listeners": [{"name": "Trial" + node, "type": "socks", "listen": "127.0.0.1",
                "port": self.ports[node], "udp": True, "proxy": "Controlled" + node} for node in NODES],
            "proxies": [{"name": "Controlled" + node, "type": "socks5", "server": "127.0.0.1",
                "port": self._listeners[node].getsockname()[1], "udp": True} for node in NODES],
            "rules": ["MATCH,REJECT"]}

    def _health(self, node):
        with socket.create_connection(("127.0.0.1", self.ports[node]), timeout=2) as connection:
            connection.settimeout(2)
            connection.sendall(b"\x05\x01\x00")
            if _exact(connection, 2) != b"\x05\x00":
                return False
            connection.sendall(b"\x05\x01\x00" + _encode_address(self.target_ipv4, self.http_port))
            if _exact(connection, 3) != b"\x05\x00\x00":
                return False
            _address(connection)
            path = f"/health/{self.nonce}/{node}"
            connection.sendall(f"GET {path} HTTP/1.1\r\nHost: {self.target_host}\r\nConnection: close\r\n\r\n".encode("ascii"))
            response = bytearray()
            while len(response) < 65536:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response.extend(chunk)
            return (f"X-RuleProxy-Node: {node}\r\n".encode() in response
                    and f"X-RuleProxy-Nonce: {self.nonce}\r\n".encode() in response)

    def start_proxy(self):
        if self._closed or len(self._listeners) != 2:
            raise RuntimeError("fixture upstreams are unavailable")
        if self.process is not None and self.process.poll() is None:
            return {"started": False, "already_running": True, "pid": self.process.pid}
        path = self.directory / "mihomo-compare.json"
        path.write_text(json.dumps(self._config(), indent=2) + "\n", encoding="ascii")
        self.log = (self.directory / "mihomo-compare.log").open("ab")
        self._generation += 1
        try:
            self.process = subprocess.Popen([str(self.mihomo_path), "-d", str(self.directory), "-f", str(path)],
                stdin=subprocess.DEVNULL, stdout=self.log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if self.process.poll() is not None:
                    raise RuntimeError("owned Mihomo exited before readiness")
                readiness = {}
                for node in NODES:
                    try:
                        readiness[node] = self._health(node)
                    except (OSError, EOFError, ValueError):
                        readiness[node] = False
                if all(readiness.values()):
                    self.readiness = {"explicit_proxy_health_only": True, "transparent_evidence": False,
                                      "nodes": readiness, "proxy_generation": self._generation}
                    return {"started": True, "pid": self.process.pid, "readiness": self.readiness}
                time.sleep(.1)
            raise TimeoutError("owned A/B Mihomo readiness timeout")
        except BaseException:
            self.stop_proxy()
            raise

    def stop_proxy(self):
        process = self.process
        result = {"owned_process_started": process is not None, "exited": False, "exit_code": None}
        try:
            if process is not None:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                result.update(exited=process.poll() is not None, exit_code=process.returncode)
            return result
        finally:
            if self.log is not None:
                self.log.close()
                self.log = None

    def snapshot(self):
        with self._lock:
            transactions = json.loads(json.dumps(self._transactions))
            return {"schema_version": 1, "nonce": self.nonce, "transactions": transactions,
                    "transaction_count": len(transactions), "dropped_transactions": self._dropped,
                    "errors": list(self._errors), "counts": {node: {
                        protocol: sum(row["node"] == node and row["protocol"] == protocol
                                      and row["evidence_role"] == "actor" for row in transactions)
                        for protocol in ("tcp_http", "tcp_http_response", "udp_dns")} for node in NODES}}

    def facts(self):
        return {"schema_version": 1, "nonce": self.nonce, "listener_ports": dict(self.ports),
                "target_ipv4": self.target_ipv4, "target_ipv6": self.target_ipv6,
                "target_host": self.target_host, "http_port": self.http_port,
                "dns_target_ipv4": self.dns_target_ipv4, "dns_target_ipv6": self.dns_target_ipv6,
                "dns_port": self.dns_port, "origin_kind": "controlled_synthetic_stub",
                "http_internet_forwarded": False, "dns_internet_forwarded": False,
                "real_exit_ip_observed": False, "tun_enabled": False,
                "host_proxy_dns_routes_modified": False, "explicit_health": self.readiness,
                "ipv6_external_reachability": "unverified_by_fixture",
                "synthetic_dns_answers": {"A": "198.51.100.101", "B": "198.51.100.102"},
                "product_acceptance_passed": False}

    def close(self):
        if self._closed:
            return
        self.stop_proxy()
        self._stop.set()
        for listener in self._listeners.values():
            listener.close()
        with self._lock:
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        deadline = time.monotonic() + 6
        for thread in tuple(self._threads):
            thread.join(timeout=max(0, deadline - time.monotonic()))
        if any(thread.is_alive() for thread in self._threads):
            raise RuntimeError("controlled SOCKS workers remain alive after close")
        self._closed = True
