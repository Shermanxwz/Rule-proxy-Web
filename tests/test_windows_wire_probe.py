"""Test fixed marker transport, never claim Windows container enforcement."""
import importlib.util
import json
from pathlib import Path
import socket
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_wire_test", ROOT / ".github/windows_wire_probe.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class WindowsWireProbeTests(unittest.TestCase):
    def test_fixed_markers_are_unique_valid_rd_zero_dns_questions(self):
        markers = [wire.dns_marker("model3", role) for role in wire.ROLES]
        self.assertEqual(len(set(markers)), 4)
        for marker in markers:
            _, flags, questions, answers, authorities, additionals = struct.unpack("!6H", marker[:12])
            self.assertEqual((flags, questions, answers, authorities, additionals), (0, 1, 0, 0, 0))
            labels, position = [], 12
            while marker[position]:
                length = marker[position]
                labels.append(marker[position + 1:position + 1 + length].decode("ascii"))
                position += length + 1
            self.assertEqual(labels[-1], "invalid")
            self.assertEqual(marker[position:], b"\0\0\1\0\1")
        with self.assertRaises(ValueError):
            wire.dns_marker("unrelated.name", "parent")

    def test_real_bound_udp_marker_reaches_only_its_local_observer(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as observer:
            observer.bind(("127.0.0.1", 0))
            observer.settimeout(2)
            marker = wire.dns_marker("model3", "parent")
            probes = [{"id": "model3.ipv4.parent", "role": "parent", "family": "ipv4",
                "source_ip": "127.0.0.1", "destination": "127.0.0.1", "port": observer.getsockname()[1],
                "payload_hex": marker.hex()}]
            evidence = wire.send_probes(probes, "parent")
            self.assertEqual(observer.recvfrom(512)[0], marker)
        self.assertEqual(evidence, [{"id": "model3.ipv4.parent", "role": "parent", "attempted": True,
            "bind_attempted": True, "bind_succeeded": True, "send_attempted": True,
            "api_accepted": True, "errno": None}])
        self.assertEqual(wire.send_probes(probes, "child"), [])
        self.assertNotIn("delivery_proven", evidence[0])

    def test_bind_denial_is_preserved_and_never_counted_as_send_acceptance(self):
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender
        sender.bind.side_effect = OSError(13, "denied")
        with mock.patch.object(wire.socket, "socket", return_value=sender):
            record = wire.send_probes([{"id": "model3.ipv4.parent", "role": "parent", "family": "ipv4",
                "source_ip": "10.0.2.15", "destination": "1.1.1.1", "port": 53,
                "payload_hex": "00"}], "parent")[0]
        self.assertEqual(record["errno"], 13)
        self.assertFalse(record["bind_succeeded"])
        self.assertTrue(record["bind_attempted"])
        self.assertFalse(record["send_attempted"])
        self.assertFalse(record["api_accepted"])
        sender.sendto.assert_not_called()

    def make_session(self, base=None):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        path = Path(folder.name) / "private.json"
        path.write_text(json.dumps({"host_url": base or "http://10.0.2.2:1234/" + "a" * 64}))
        return wire.WireSession(path, ("model3", "model1_internal_ingress_deny", "model1_internal", "model2_host"))

    def test_private_url_cannot_be_external_redirect_userinfo_query_or_other_path(self):
        for base in ("http://evil.example:1234/" + "a" * 64, "http://10.0.2.2:0/" + "a" * 64,
                     "http://10.0.2.2:1234/" + "a" * 64 + "?x=1",
                     "http://10.0.2.2:1234/" + "a" * 64 + "/payload.zip"):
            with self.subTest(base=base), self.assertRaisesRegex(ValueError, "endpoint_invalid"):
                self.make_session(base)

    def test_route_selection_sends_nothing_and_prepares_all_four_roles(self):
        session = self.make_session()
        route = mock.MagicMock()
        route.__enter__.return_value = route
        route.getsockname.side_effect = [("10.0.2.15", 4000), ("fec0::1234", 4001, 0, 0)]
        with mock.patch.object(session, "request", return_value={"schema_version": 1, "source_mac": wire.SOURCE_MAC}), \
                mock.patch.object(wire.socket, "socket", return_value=route):
            session.start()
        route.send.assert_not_called()
        route.sendto.assert_not_called()
        self.assertEqual(len(session.probes), 64)
        self.assertEqual(len({probe["id"] for probe in session.probes}), 64)
        self.assertEqual(len(session.for_variant("model1_internal")), 16)
        self.assertEqual({probe["source_mac"] for probe in session.probes}, {wire.SOURCE_MAC})
        self.assertEqual(len({probe["group"] for probe in session.probes}), 16)
        self.assertEqual(len({probe["payload_hex"] for probe in session.probes}), 64)
        for variant in wire.VARIANTS:
            for family in ("ipv4", "ipv6"):
                for suffix in ("", "_unbound"):
                    group = variant + "." + family + suffix
                    self.assertEqual({p["role"] for p in session.probes if p["group"] == group}, set(wire.ROLES))

    def test_private_request_exception_never_exposes_capability_url(self):
        session = self.make_session()
        session.opener = mock.Mock()
        session.opener.open.side_effect = RuntimeError(session.base)
        with self.assertRaises(RuntimeError) as failure:
            session.request("start", {})
        self.assertEqual(str(failure.exception), "private_wire_endpoint_failed")
        self.assertIsNone(failure.exception.__cause__)

    def test_lost_start_reply_still_requires_finish_and_never_assumes_no_host_filter(self):
        session = self.make_session()
        with mock.patch.object(session, "request", side_effect=RuntimeError("private_wire_endpoint_failed")):
            with self.assertRaises(RuntimeError):
                session.start()
        self.assertTrue(session.started)
        with mock.patch.object(session, "request", return_value={"acceptance_passed": False,
                "kernel_denial_proven": False}) as request:
            session.finish()
        self.assertEqual(request.call_args.args[0], "finish")

    def test_failed_actor_attestation_is_sent_to_host_and_cannot_be_reset_by_later_success(self):
        session = self.make_session()
        session.started = True
        session.actors({"process_started": True, "actor_attestation": {"attestation_passed": False}})
        session.actors({"process_started": True, "actor_attestation": {"attestation_passed": True}, "actors": []})
        with mock.patch.object(session, "request", return_value={"acceptance_passed": False,
                "kernel_denial_proven": False}) as request:
            session.finish()
            session.finish()
        request.assert_called_once()
        self.assertFalse(request.call_args.args[1]["actor_execution_attested"])
        self.assertEqual(request.call_args.args[1]["execution_schema_version"], 2)

    def test_real_unbound_sendto_reaches_observer_without_using_manifest_source(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as observer:
            observer.bind(("127.0.0.1", 0))
            observer.settimeout(2)
            marker = wire.dns_marker("model3", "parent")
            probe = {"id": "model3.ipv4_unbound.parent", "role": "parent", "family": "ipv4",
                "source_ip": "192.0.2.111", "destination": "127.0.0.1", "port": observer.getsockname()[1],
                "payload_hex": marker.hex()}
            evidence = wire.send_probes([probe], "parent")
            packet, peer = observer.recvfrom(512)
            self.assertEqual(packet, marker)
            self.assertEqual(peer[0], "127.0.0.1")
        self.assertEqual(evidence, [{"id": probe["id"], "role": "parent", "attempted": True,
            "bind_attempted": False, "bind_succeeded": False, "send_attempted": True,
            "api_accepted": True, "errno": None}])
        self.assertNotIn("delivery_proven", evidence[0])

    def test_unbound_never_calls_bind_and_send_errors_remain_api_facts(self):
        for error in (10013, 10051):
            with self.subTest(error=error):
                sender = mock.MagicMock()
                sender.__enter__.return_value = sender
                sender.bind.side_effect = AssertionError("unbound must not bind")
                sender.sendto.side_effect = OSError(error, "private text")
                probe = {"id": "model1_internal_ingress_deny.ipv6_unbound.child", "role": "child", "family": "ipv6",
                    "source_ip": "fec0::15", "destination": "2606:4700:4700::1111", "port": 53, "payload_hex": "00"}
                with mock.patch.object(wire.socket, "socket", return_value=sender):
                    record = wire.send_probes([probe], "child")[0]
                sender.bind.assert_not_called()
                sender.sendto.assert_called_once_with(b"\0", ("2606:4700:4700::1111", 53))
                self.assertFalse(record["bind_attempted"])
                self.assertFalse(record["bind_succeeded"])
                self.assertTrue(record["send_attempted"])
                self.assertFalse(record["api_accepted"])
                self.assertEqual(record["errno"], error)
                self.assertNotIn("kernel_denial_proven", record)

    def test_invalid_marker_or_address_never_fakes_a_send_or_bind_attempt(self):
        base = {"id": "model3.ipv4.parent", "role": "parent", "family": "ipv4",
            "source_ip": "10.0.2.15", "destination": "1.1.1.1", "port": 53, "payload_hex": "00"}
        for change in ({"payload_hex": "not hex"}, {"destination": "hostname.invalid"},
                       {"port": True}, {"id": "model3.ipv4_unbound.child"}):
            with self.subTest(change=change), mock.patch.object(wire.socket, "socket") as factory:
                record = wire.send_probes([{**base, **change}], "parent")[0]
            self.assertFalse(record["bind_attempted"])
            self.assertFalse(record["bind_succeeded"])
            self.assertFalse(record["send_attempted"])
            self.assertFalse(record["api_accepted"])
            self.assertEqual(record["errno"], -1)
            factory.assert_not_called()

    def test_dns_observation_is_optional_and_independent_in_finish_body(self):
        session = self.make_session()
        session.started = True
        observation = {"manifest": {}, "execution": [], "actor_execution_attested": False}
        session.dns_observation = observation
        with mock.patch.object(session, "request", return_value={"acceptance_passed": False,
                "kernel_denial_proven": False}) as request:
            session.finish()
        self.assertIs(request.call_args.args[1]["dns"], observation)
        self.assertTrue(request.call_args.args[1]["actor_execution_attested"])

    def test_unsupported_variant_cannot_poison_actually_started_groups_or_invent_execution(self):
        session = self.make_session()
        session.actors({"process_started": False, "status": "unsupported"})
        self.assertTrue(session.attested)
        self.assertEqual(session.execution, [])

    def test_wire_endpoint_cannot_claim_acceptance_or_kernel_denial(self):
        session = self.make_session()
        session.started = True
        with mock.patch.object(session, "request", return_value={"acceptance_passed": True,
                "kernel_denial_proven": False}), self.assertRaisesRegex(RuntimeError, "scope"):
            session.finish()
