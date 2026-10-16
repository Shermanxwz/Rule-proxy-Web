"""Optional DNS qualification helpers; importing this file opens no sockets.

These helpers are for disposable Windows experiments, never a product backend.
The DoH fixture forwards opaque bytes to exactly 1.1.1.1:443 through an existing
loopback carrier. TLS and certificate verification remain with the real Mihomo
resolver. It never manufactures a DNS answer or changes network configuration.
"""
from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time


DNS_PEERS = frozenset(("198.18.0.2", "fdfe:dcba:8879::2"))
DOH_TARGET = ("1.1.1.1", 443)
MAX_DNS_MESSAGE = 65535
MAX_HEADER = 8192
MAX_RELAY_BYTES = 4 * 1024 * 1024
_QUERY = re.compile(r"rp-([0-9a-f]{8,32})\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.sslip\.io\.\Z")


class FixtureError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _timeout(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not .05 <= value <= 15:
        raise FixtureError("invalid_fixture_timeout")
    return float(value)


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise FixtureError("fixture_deadline_exhausted")
    return value


def _receive_exact(connection, length, deadline):
    output = bytearray()
    while len(output) < length:
        connection.settimeout(_remaining(deadline))
        block = connection.recv(length - len(output))
        if not block:
            raise FixtureError("short_fixture_stream")
        output.extend(block)
    return bytes(output)


def read_connect_response(connection, *, timeout=3.0, max_header=MAX_HEADER):
    """Require a complete HTTP 200 CONNECT response; consume no tunnel bytes."""
    timeout = _timeout(timeout)
    if type(max_header) is not int or not 16 <= max_header <= MAX_HEADER:
        raise FixtureError("invalid_connect_header_bound")
    deadline, header = time.monotonic() + timeout, bytearray()
    while not header.endswith(b"\r\n\r\n"):
        if len(header) >= max_header:
            raise FixtureError("connect_header_bound")
        header.extend(_receive_exact(connection, 1, deadline))
    lines = bytes(header[:-4]).split(b"\r\n")
    if not re.fullmatch(rb"HTTP/1\.[01] 200(?: [\x20-\x7e]*)?", lines[0]):
        raise FixtureError("connect_status_not_200")
    for line in lines[1:]:
        if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\x20-\x7e\t]*", line):
            raise FixtureError("invalid_connect_header")
        key, value = line.split(b":", 1)
        # A CONNECT tunnel has no response body. Ambiguous framing is refused.
        if key.lower() == b"transfer-encoding" or key.lower() == b"content-length" and value.strip() != b"0":
            raise FixtureError("invalid_connect_framing")
    return bytes(header)


def _close(connection):
    try:
        connection.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    finally:
        connection.close()


class DohRelay:
    """Whitelist-only transparent relay for an EchoNode SOCKS CONNECT branch.

    Call handle() after parsing SOCKS CONNECT. on_ready sends the existing
    fixture's SOCKS success reply, after the carrier confirms CONNECT 200.
    disable() closes all admitted sockets and invalidates pending connections;
    enable() starts a new generation. No TLS context is created by this helper.
    """
    def __init__(self, carrier_port, *, timeout=3.0, connector=None):
        if type(carrier_port) is not int or not 1025 <= carrier_port <= 65535:
            raise FixtureError("invalid_carrier_port")
        self.carrier = ("127.0.0.1", carrier_port)
        self.timeout = _timeout(timeout)
        self._connector = connector or socket.create_connection
        self._lock = threading.RLock()
        self._enabled, self._closed, self._generation = True, False, 0
        self._connections = {}
        self._next = 0
        self._stats = {key: 0 for key in ("offered", "accepted", "rejected", "failed", "completed",
                                         "bytes_to_resolver", "bytes_to_client")}

    def snapshot(self):
        with self._lock:
            return {**self._stats, "enabled": self._enabled, "closed": self._closed,
                    "generation": self._generation, "active": len(self._connections),
                    "target": "1.1.1.1:443", "carrier_scope": "loopback_http_connect"}

    def disable(self):
        with self._lock:
            self._enabled = False
            self._generation += 1
            admitted = dict(self._connections)
            connections = [connection for values in admitted.values() for connection in values]
        for connection in connections:
            _close(connection)
        with self._lock:
            for identity in admitted:
                self._connections.pop(identity, None)
        return self.snapshot()

    def enable(self):
        with self._lock:
            if self._closed:
                raise FixtureError("relay_permanently_closed")
            self._generation += 1
            self._enabled = True
        return self.snapshot()

    def close(self):
        with self._lock:
            self._closed = True
        return self.disable()

    def _current(self, generation):
        return self._enabled and not self._closed and self._generation == generation

    def handle(self, client, host, port, *, on_ready=None):
        """Forward one allowed stream; 'forwarded' means admitted, not DNS success."""
        with self._lock:
            self._stats["offered"] += 1
            if type(host) is not str or type(port) is not int or (host, port) != DOH_TARGET or not self._enabled or self._closed:
                self._stats["rejected"] += 1
                _close(client)
                return {"forwarded": False, "code": "relay_target_or_state_refused"}
            self._next += 1
            identity, generation = self._next, self._generation
            self._connections[identity] = [client]
        upstream, accepted, code = None, False, None
        deadline = time.monotonic() + self.timeout
        try:
            upstream = self._connector(self.carrier, timeout=_remaining(deadline))
            with self._lock:
                if not self._current(generation):
                    raise FixtureError("relay_disabled")
                self._connections[identity].append(upstream)
                upstream.settimeout(_remaining(deadline))
                upstream.sendall(b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
            read_connect_response(upstream, timeout=max(.05, _remaining(deadline)))
            with self._lock:
                if not self._current(generation):
                    raise FixtureError("relay_disabled")
                if on_ready is not None:
                    client.settimeout(_remaining(deadline))
                    on_ready(client)
                self._stats["accepted"] += 1
                accepted = True
            # One total deadline bounds even a peer that trickles bytes forever.
            total = 0
            while True:
                with self._lock:
                    if not self._current(generation):
                        raise FixtureError("relay_disabled")
                readable, _, _ = select.select((client, upstream), (), (), min(.1, _remaining(deadline)))
                for source in readable:
                    source.settimeout(_remaining(deadline))
                    block = source.recv(16384)
                    if not block:
                        with self._lock:
                            self._stats["completed"] += 1
                        return {"forwarded": accepted, "code": "eof"}
                    total += len(block)
                    if total > MAX_RELAY_BYTES:
                        raise FixtureError("relay_byte_bound")
                    destination = upstream if source is client else client
                    destination.settimeout(_remaining(deadline))
                    destination.sendall(block)
                    with self._lock:
                        self._stats["bytes_to_resolver" if source is client else "bytes_to_client"] += len(block)
        except (OSError, ValueError) as error:
            code = error.code if isinstance(error, FixtureError) else "relay_socket_failed"
            with self._lock:
                self._stats["failed"] += 1
            return {"forwarded": accepted, "code": code}
        finally:
            with self._lock:
                self._connections.pop(identity, None)
            if upstream is not None:
                _close(upstream)
            _close(client)


def query_name(expected_ip="1.2.3.4", nonce=None):
    try:
        address = ipaddress.IPv4Address(expected_ip)
    except (ValueError, TypeError, ipaddress.AddressValueError) as error:
        raise FixtureError("fixture_requires_ipv4_answer") from error
    nonce = secrets.token_hex(8) if nonce is None else nonce
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{8,32}", nonce) is None:
        raise FixtureError("invalid_query_nonce")
    return "rp-" + nonce + "." + str(address) + ".sslip.io."


def _query_name(name):
    if not isinstance(name, str) or len(name) > 253 or _QUERY.fullmatch(name) is None:
        raise FixtureError("invalid_fixture_query_name")
    match = _QUERY.fullmatch(name)
    if query_name(match[2], match[1]) != name:
        raise FixtureError("invalid_fixture_query_name")
    return name


def build_dns_query(name, transaction_id, qtype=1):
    name = _query_name(name)
    if type(transaction_id) is not int or not 0 <= transaction_id <= 65535 or qtype not in (1, 28) or type(qtype) is not int:
        raise FixtureError("invalid_dns_question")
    labels = b"".join(bytes((len(label),)) + label.encode("ascii") for label in name[:-1].split(".")) + b"\0"
    return struct.pack("!6H", transaction_id, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", qtype, 1)


def _dns_name(data, start):
    labels, position, end, visited = [], start, None, set()
    for _ in range(128):
        if position >= len(data) or position in visited:
            raise FixtureError("invalid_dns_name_pointer")
        visited.add(position)
        length = data[position]
        if length & 0xc0 == 0xc0:
            if position + 1 >= len(data):
                raise FixtureError("short_dns_name_pointer")
            pointer = ((length & 0x3f) << 8) | data[position + 1]
            if pointer >= position:
                raise FixtureError("invalid_dns_name_pointer")
            end = position + 2 if end is None else end
            position = pointer
            continue
        if length & 0xc0:
            raise FixtureError("invalid_dns_label")
        position += 1
        if not length:
            return ".".join(labels).lower() + ".", position if end is None else end
        if length > 63 or position + length > len(data):
            raise FixtureError("short_dns_label")
        label = data[position:position + length]
        if re.fullmatch(rb"[A-Za-z0-9_-]+", label) is None:
            raise FixtureError("invalid_dns_label")
        labels.append(label.decode("ascii"))
        if sum(map(len, labels)) + len(labels) > 254:
            raise FixtureError("dns_name_bound")
        position += length
    raise FixtureError("dns_pointer_bound")


def parse_dns_response(data, *, name, transaction_id, qtype=1, expected_ip=None):
    """Check transaction, exact question and answer ownership, including CNAME."""
    build_dns_query(name, transaction_id, qtype)
    if not isinstance(data, bytes) or not 12 <= len(data) <= MAX_DNS_MESSAGE:
        raise FixtureError("invalid_dns_message_size")
    actual_id, flags, questions, answers, authorities, additional = struct.unpack_from("!6H", data)
    if actual_id != transaction_id:
        raise FixtureError("dns_transaction_mismatch")
    if not flags & 0x8000 or flags & 0x7800 or flags & 0x0200 or flags & 15 or questions != 1:
        raise FixtureError("dns_response_not_success")
    if answers > 64 or authorities > 64 or additional > 64:
        raise FixtureError("dns_record_bound")
    actual_name, position = _dns_name(data, 12)
    if position + 4 > len(data) or actual_name != name.lower() or struct.unpack_from("!HH", data, position) != (qtype, 1):
        raise FixtureError("dns_question_mismatch")
    position += 4
    address_records, aliases = [], {}
    for index in range(answers + authorities + additional):
        owner, position = _dns_name(data, position)
        if position + 10 > len(data):
            raise FixtureError("short_dns_record")
        kind, klass, _ttl, size = struct.unpack_from("!HHIH", data, position)
        position += 10
        end = position + size
        if end > len(data):
            raise FixtureError("short_dns_rdata")
        if index < answers and klass == 1:
            if kind in (1, 28):
                if size != (4 if kind == 1 else 16):
                    raise FixtureError("invalid_dns_address_size")
                if kind == qtype:
                    address_records.append((owner, str(ipaddress.ip_address(data[position:end]))))
            elif kind == 5:
                target, consumed = _dns_name(data, position)
                if consumed != end or owner in aliases and aliases[owner] != target:
                    raise FixtureError("invalid_dns_cname")
                aliases[owner] = target
        position = end
    if position != len(data):
        raise FixtureError("dns_trailing_data")
    owner, chain = name.lower(), set()
    while owner in aliases:
        if owner in chain:
            raise FixtureError("dns_cname_cycle")
        chain.add(owner)
        owner = aliases[owner]
    if any(record_owner in aliases for record_owner, _address in address_records):
        raise FixtureError("dns_cname_address_conflict")
    addresses = sorted({address for record_owner, address in address_records if record_owner == owner})
    if not addresses:
        raise FixtureError("dns_answer_missing")
    if expected_ip is not None:
        try:
            expected = str(ipaddress.ip_address(expected_ip))
        except ValueError as error:
            raise FixtureError("invalid_expected_answer") from error
        if addresses != [expected]:
            raise FixtureError("dns_answer_mismatch")
    return {"transaction_id": actual_id, "query_name": name, "qtype": qtype,
            "addresses": addresses, "answer_count": answers, "validated": True}


def raw_dns_query(peer, *, name, expected_ip, protocol="udp", timeout=3.0, transaction_id=None):
    """Issue one bounded real DNS query to an exact virtual peer, never elsewhere."""
    if type(peer) is not str or peer not in DNS_PEERS or type(protocol) is not str or protocol not in ("udp", "tcp"):
        raise FixtureError("dns_peer_or_protocol_refused")
    timeout = _timeout(timeout)
    transaction_id = secrets.randbelow(65536) if transaction_id is None else transaction_id
    request = build_dns_query(name, transaction_id)
    deadline = time.monotonic() + timeout
    family = socket.AF_INET6 if ":" in peer else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM) as connection:
        connection.settimeout(_remaining(deadline))
        connection.connect((peer, 53))
        if protocol == "udp":
            if connection.send(request) != len(request):
                raise FixtureError("short_dns_send")
            connection.settimeout(_remaining(deadline))
            response = connection.recv(MAX_DNS_MESSAGE + 1)
        else:
            connection.settimeout(_remaining(deadline))
            connection.sendall(struct.pack("!H", len(request)) + request)
            length = struct.unpack("!H", _receive_exact(connection, 2, deadline))[0]
            if length < 12:
                raise FixtureError("invalid_dns_tcp_frame")
            response = _receive_exact(connection, length, deadline)
    result = parse_dns_response(response, name=name, transaction_id=transaction_id, expected_ip=expected_ip)
    return {**result, "peer": peer, "protocol": protocol}


def _system_query(name, expected_ip):
    _query_name(name)
    # The default Winsock resolver uses the Windows DNS client/NRPT. No explicit
    # DNS server, proxy setting, hosts file or adapter option is installed here.
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(name, None, socket.AF_INET, socket.SOCK_STREAM)})
    expected = str(ipaddress.IPv4Address(expected_ip))
    if addresses != [expected]:
        raise FixtureError("system_dns_answer_mismatch")
    return {"query_name": name, "addresses": addresses, "validated": True,
            "resolver": "windows_default_winsock", "explicit_dns_server": False}


def system_dns_query(name, expected_ip, *, timeout=3.0):
    """Bound a native resolver call in a separate process; no shared cache flush."""
    _query_name(name)
    expected = str(ipaddress.IPv4Address(expected_ip))
    timeout = _timeout(timeout)
    if os.name != "nt":
        raise FixtureError("windows_system_resolver_required")
    completed = subprocess.run([sys.executable, "-I", "-S", str(Path(__file__).resolve()),
        "--system-query-child", name, expected], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), check=False)
    if completed.returncode or len(completed.stdout) > 16384 or len(completed.stderr) > 16384:
        raise FixtureError("system_dns_child_failed")
    try:
        result = json.loads(completed.stdout.decode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise FixtureError("system_dns_child_invalid") from error
    if (not isinstance(result, dict) or result.get("validated") is not True or result.get("query_name") != name
            or result.get("addresses") != [expected] or result.get("explicit_dns_server") is not False
            or result.get("resolver") != "windows_default_winsock"):
        raise FixtureError("system_dns_child_invalid")
    return result


if __name__ == "__main__":
    # This private child entry point performs one name lookup, never a global
    # qualification run. The orchestrator supplies the deadline and unique name.
    if len(sys.argv) != 4 or sys.argv[1] != "--system-query-child" or os.name != "nt":
        raise SystemExit(2)
    try:
        print(json.dumps(_system_query(sys.argv[2], sys.argv[3]), ensure_ascii=True))
    except (OSError, ValueError):
        raise SystemExit(1)
