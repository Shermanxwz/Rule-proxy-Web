"""Protocol and causal-control checks; no external network or system mutation."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import subprocess
import threading
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location("windows_dns_fixture",
    Path(__file__).resolve().parents[1] / ".github/windows_global_dns_fixture.py")
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)
NAME = H.query_name("1.2.3.4", "aabbccdd")
TRANSACTION = 0x1234


def dns_name(name):
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in name[:-1].split(".")) + b"\0"


def rr(owner, kind, data):
    return owner + struct.pack("!HHIH", kind, 1, 60, len(data)) + data


def response(*, name=NAME, transaction=TRANSACTION, flags=0x8180, records=None):
    records = [rr(b"\xc0\x0c", 1, b"\x01\x02\x03\x04")] if records is None else records
    query = H.build_dns_query(name, transaction)
    return struct.pack("!6H", transaction, flags, 1, len(records), 0, 0) + query[12:] + b"".join(records)


class Stream:
    def __init__(self, blocks):
        self.blocks = bytearray(blocks)
        self.sent = bytearray()
        self.timeouts = []
        self.closed = False
        self.endpoint = None

    def settimeout(self, value):
        self.timeouts.append(value)

    def recv(self, length):
        # Deliberately partial reads exercise exact TCP framing/header handling.
        value = bytes(self.blocks[:min(length, 2)])
        del self.blocks[:len(value)]
        return value

    def sendall(self, value):
        self.sent.extend(value)

    def send(self, value):
        self.sendall(value)
        return len(value)

    def connect(self, endpoint):
        self.endpoint = endpoint

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.closed = True


class ConnectHeaderTests(unittest.TestCase):
    def test_partial_header_requires_200_and_preserves_opaque_tunnel_bytes(self):
        stream = Stream(b"HTTP/1.1 200 Connection established\r\nProxy-Agent: fixture\r\n\r\nTLS-BYTES")
        header = H.read_connect_response(stream)
        self.assertTrue(header.endswith(b"\r\n\r\n"))
        self.assertEqual(bytes(stream.blocks), b"TLS-BYTES")
        self.assertTrue(all(0 < timeout <= 3 for timeout in stream.timeouts))

    def test_non_200_partial_bad_framing_and_oversize_are_refused(self):
        cases = [b"HTTP/1.1 403 Forbidden\r\n\r\n", b"HTTP/1.1 200 OK\r\n",
                 b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\n invalid: folded\r\n\r\n",
                 b"HTTP/1.1 200 OK\r\nBad\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n"]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(H.FixtureError):
                H.read_connect_response(Stream(value))
        with self.assertRaisesRegex(H.FixtureError, "header_bound"):
            H.read_connect_response(Stream(b"HTTP/1.1 200 " + b"x" * 90), max_header=32)

    def test_one_total_deadline_even_when_header_keeps_arriving(self):
        with patch.object(H.time, "monotonic", side_effect=[100, 100, 104]), \
             self.assertRaisesRegex(H.FixtureError, "deadline"):
            H.read_connect_response(Stream(b"HTTP/1.1 200 OK\r\n\r\n"))


class DnsProtocolTests(unittest.TestCase):
    def parse(self, value, **kwargs):
        return H.parse_dns_response(value, name=NAME, transaction_id=TRANSACTION, expected_ip="1.2.3.4", **kwargs)

    def test_unique_closed_names_and_exact_question_bytes(self):
        self.assertEqual(NAME, "rp-aabbccdd.1.2.3.4.sslip.io.")
        self.assertNotEqual(H.query_name(), H.query_name())
        query = H.build_dns_query(NAME, TRANSACTION)
        self.assertEqual(struct.unpack_from("!6H", query), (TRANSACTION, 0x100, 1, 0, 0, 0))
        self.assertEqual(query[12:], dns_name(NAME) + b"\0\1\0\1")
        for name in ("example.com.", "rp-aabbccdd.1.2.3.4.evil.test.", NAME + ".", NAME.replace("aabbccdd", "abc")):
            with self.assertRaises(H.FixtureError):
                H.build_dns_query(name, TRANSACTION)
        for identity in (-1, 65536, True, "1"):
            with self.assertRaises(H.FixtureError):
                H.build_dns_query(NAME, identity)

    def test_success_exact_answer_and_transaction(self):
        self.assertEqual(self.parse(response())["addresses"], ["1.2.3.4"])
        for value in (response(transaction=1), response(name=H.query_name("1.2.3.4", "bbccddee")),
                      response(flags=0x8380), response(flags=0x8183), response(flags=0x180),
                      response()[:-1], response() + b"x"):
            with self.subTest(value=value[:12]), self.assertRaises(H.FixtureError):
                self.parse(value)

    def test_matching_address_on_unrelated_owner_does_not_count(self):
        with self.assertRaisesRegex(H.FixtureError, "answer_missing"):
            self.parse(response(records=[rr(dns_name("other.example."), 1, b"\x01\x02\x03\x04")]))
        with self.assertRaisesRegex(H.FixtureError, "answer_mismatch"):
            self.parse(response(records=[rr(b"\xc0\x0c", 1, b"\x05\x06\x07\x08")]))

    def test_cname_chain_must_reach_the_answer_and_cannot_conflict(self):
        alias = dns_name("alias.example.")
        value = response(records=[rr(b"\xc0\x0c", 5, alias), rr(alias, 1, b"\x01\x02\x03\x04")])
        self.assertEqual(self.parse(value)["addresses"], ["1.2.3.4"])
        cases = [
            [rr(b"\xc0\x0c", 5, alias), rr(b"\xc0\x0c", 1, b"\x01\x02\x03\x04")],
            [rr(b"\xc0\x0c", 5, alias), rr(alias, 5, b"\xc0\x0c")],
            [rr(b"\xc0\x0c", 5, alias), rr(b"\xc0\x0c", 5, dns_name("different.example."))],
        ]
        for records in cases:
            with self.assertRaises(H.FixtureError):
                self.parse(response(records=records))

    def test_name_pointer_cycles_forward_pointers_and_wrong_address_width_refused(self):
        query = H.build_dns_query(NAME, TRANSACTION)
        offset = len(query)
        for record in (rr(struct.pack("!H", 0xc000 | offset), 1, b"\x01\x02\x03\x04"),
                       rr(struct.pack("!H", 0xc000 | (offset + 2)), 1, b"\x01\x02\x03\x04"),
                       rr(b"\xc0\x0c", 1, b"\x01\x02\x03")):
            with self.assertRaises(H.FixtureError):
                self.parse(response(records=[record]))

    def test_tcp_exact_length_prefix_and_both_fixed_peer_families(self):
        for peer, family in (("198.18.0.2", socket.AF_INET), ("fdfe:dcba:8879::2", socket.AF_INET6)):
            packet = response()
            stream = Stream(struct.pack("!H", len(packet)) + packet)
            with patch.object(H.socket, "socket", return_value=stream) as constructor:
                result = H.raw_dns_query(peer, name=NAME, expected_ip="1.2.3.4", protocol="tcp", transaction_id=TRANSACTION)
            constructor.assert_called_once_with(family, socket.SOCK_STREAM)
            self.assertEqual(stream.endpoint, (peer, 53))
            self.assertEqual(bytes(stream.sent), struct.pack("!H", len(H.build_dns_query(NAME, TRANSACTION))) + H.build_dns_query(NAME, TRANSACTION))
            self.assertTrue(result["validated"])
            self.assertTrue(stream.closed)
        for data in (b"\0", b"\0\x03abc", b"\x00\x20short"):
            with patch.object(H.socket, "socket", return_value=Stream(data)), self.assertRaises(H.FixtureError):
                H.raw_dns_query("198.18.0.2", name=NAME, expected_ip="1.2.3.4", protocol="tcp", transaction_id=TRANSACTION)

    def test_udp_connected_peer_and_transaction_validation(self):
        stream = Stream(response())
        stream.recv = lambda _size: response()
        with patch.object(H.socket, "socket", return_value=stream) as constructor:
            result = H.raw_dns_query("198.18.0.2", name=NAME, expected_ip="1.2.3.4", transaction_id=TRANSACTION)
        constructor.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertEqual(result["protocol"], "udp")
        self.assertEqual(stream.endpoint, ("198.18.0.2", 53))
        self.assertEqual(bytes(stream.sent), H.build_dns_query(NAME, TRANSACTION))

    def test_non_peer_or_non_protocol_refused_before_opening_socket(self):
        with patch.object(H.socket, "socket") as constructor:
            for peer, protocol in (("1.1.1.1", "udp"), ("127.0.0.1", "tcp"), ([], "tcp"), ("198.18.0.2", "https")):
                with self.assertRaises(H.FixtureError):
                    H.raw_dns_query(peer, name=NAME, expected_ip="1.2.3.4", protocol=protocol)
        constructor.assert_not_called()


class RelayCausalTests(unittest.TestCase):
    def test_closed_targets_and_disabled_relay_never_contact_carrier(self):
        connector = Mock()
        relay = H.DohRelay(12345, connector=connector)
        for host, port in (("example.com", 443), ("1.1.1.1", 80), ("1.1.1.1.", 443), ("::1", 443), ("1.1.1.1", True)):
            client = Mock()
            self.assertFalse(relay.handle(client, host, port)["forwarded"])
            client.close.assert_called_once()
        relay.disable()
        self.assertFalse(relay.handle(Mock(), "1.1.1.1", 443)["forwarded"])
        connector.assert_not_called()
        self.assertEqual(relay.snapshot()["rejected"], 6)

    def test_real_opaque_socketpair_forwarding_disable_and_new_generation(self):
        client, outside = socket.socketpair()
        upstream, carrier = socket.socketpair()
        self.addCleanup(outside.close)
        self.addCleanup(carrier.close)
        outside.settimeout(2)
        carrier.settimeout(2)
        calls, result, header = [], [], bytearray()
        relay = H.DohRelay(12345, timeout=3, connector=lambda endpoint, timeout: calls.append(endpoint) or upstream)
        worker = threading.Thread(target=lambda: result.append(relay.handle(client, "1.1.1.1", 443,
            on_ready=lambda connection: connection.sendall(b"READY"))))
        worker.start()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(carrier.recv(1))
        self.assertEqual(bytes(header), b"CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n")
        carrier.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertEqual(outside.recv(5), b"READY")
        outside.sendall(b"opaque-client-TLS")
        self.assertEqual(carrier.recv(64), b"opaque-client-TLS")
        carrier.sendall(b"opaque-server-TLS")
        self.assertEqual(outside.recv(64), b"opaque-server-TLS")
        relay.disable()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outside.recv(1), b"")
        self.assertEqual(carrier.recv(1), b"")
        self.assertEqual(calls, [("127.0.0.1", 12345)])
        self.assertFalse(relay.handle(Mock(), "1.1.1.1", 443)["forwarded"])
        stats = relay.snapshot()
        self.assertEqual(stats["accepted"], 1)
        self.assertEqual(stats["active"], 0)
        self.assertEqual(stats["bytes_to_resolver"], len(b"opaque-client-TLS"))
        self.assertEqual(stats["bytes_to_client"], len(b"opaque-server-TLS"))
        self.assertTrue(relay.enable()["enabled"])
        relay.close()
        with self.assertRaises(H.FixtureError):
            relay.enable()

    def test_disable_while_carrier_connect_pending_sends_no_connect_request(self):
        client, outside = socket.socketpair()
        upstream, carrier = socket.socketpair()
        self.addCleanup(outside.close)
        self.addCleanup(carrier.close)
        entered, finish = threading.Event(), threading.Event()
        def connector(_endpoint, timeout):
            entered.set()
            self.assertTrue(finish.wait(2))
            return upstream
        relay = H.DohRelay(12345, connector=connector)
        worker = threading.Thread(target=relay.handle, args=(client, "1.1.1.1", 443))
        worker.start()
        self.assertTrue(entered.wait(1))
        relay.disable()
        # Re-enabling must not resurrect a connection admitted before disable.
        relay.enable()
        finish.set()
        worker.join(2)
        self.assertFalse(worker.is_alive())
        carrier.settimeout(1)
        self.assertEqual(carrier.recv(1), b"")
        self.assertEqual(relay.snapshot()["accepted"], 0)

    def test_reenable_allows_a_fresh_carrier_session_after_negative_control(self):
        relay = H.DohRelay(12345)
        relay.disable()
        self.assertFalse(relay.handle(Mock(), "1.1.1.1", 443)["forwarded"])
        relay.enable()
        client, outside = socket.socketpair()
        upstream, carrier = socket.socketpair()
        self.addCleanup(outside.close)
        self.addCleanup(carrier.close)
        outside.settimeout(2)
        carrier.settimeout(2)
        relay._connector = lambda endpoint, timeout: upstream
        worker = threading.Thread(target=relay.handle, args=(client, "1.1.1.1", 443),
            kwargs={"on_ready": lambda connection: connection.sendall(b"READY")})
        worker.start()
        header = bytearray()
        while not header.endswith(b"\r\n\r\n"):
            header.extend(carrier.recv(1))
        carrier.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        self.assertEqual(outside.recv(5), b"READY")
        outside.sendall(b"fresh-generation")
        self.assertEqual(carrier.recv(64), b"fresh-generation")
        self.assertEqual(relay.disable()["active"], 0)
        worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(relay.snapshot()["accepted"], 1)


class SystemResolverTests(unittest.TestCase):
    def test_explicit_windows_child_is_bounded_and_output_verified(self):
        payload = {"query_name": NAME, "addresses": ["1.2.3.4"], "validated": True,
                   "resolver": "windows_default_winsock", "explicit_dns_server": False}
        completed = subprocess.CompletedProcess([], 0, json.dumps(payload).encode("ascii"), b"")
        # Precompute Path before mocking os.name: pathlib chooses its class from it.
        filename = Path(H.__file__).resolve()
        with patch.object(H.os, "name", "nt"), patch.object(H, "Path", return_value=Mock(resolve=lambda: filename)), \
             patch.object(H.subprocess, "run", return_value=completed) as run:
            self.assertEqual(H.system_dns_query(NAME, "1.2.3.4", timeout=2), payload)
        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["-I", "-S"])
        self.assertEqual(command[-3:], ["--system-query-child", NAME, "1.2.3.4"])
        self.assertEqual(run.call_args.kwargs["timeout"], 2)
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_child_timeout_failure_or_mismatched_answer_never_passes(self):
        filename = Path(H.__file__).resolve()
        for completed in (subprocess.CompletedProcess([], 1, b"", b""),
                          subprocess.CompletedProcess([], 0, b"{}", b""),
                          subprocess.CompletedProcess([], 0, b"x" * 16385, b"")):
            with patch.object(H.os, "name", "nt"), patch.object(H, "Path", return_value=Mock(resolve=lambda: filename)), \
                 patch.object(H.subprocess, "run", return_value=completed), self.assertRaises(H.FixtureError):
                H.system_dns_query(NAME, "1.2.3.4")
        with patch.object(H.os, "name", "nt"), patch.object(H, "Path", return_value=Mock(resolve=lambda: filename)), \
             patch.object(H.subprocess, "run", side_effect=subprocess.TimeoutExpired("fixture", 1)), \
             self.assertRaises(subprocess.TimeoutExpired):
            H.system_dns_query(NAME, "1.2.3.4", timeout=1)

    def test_default_resolver_has_no_server_override_and_exact_answer(self):
        with patch.object(H.socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.2.3.4", 0))]) as lookup:
            self.assertTrue(H._system_query(NAME, "1.2.3.4")["validated"])
        lookup.assert_called_once_with(NAME, None, socket.AF_INET, socket.SOCK_STREAM)
        with patch.object(H.socket, "getaddrinfo", return_value=[]), self.assertRaises(H.FixtureError):
            H._system_query(NAME, "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
