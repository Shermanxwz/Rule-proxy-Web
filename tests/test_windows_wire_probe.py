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
            "bind_succeeded": True, "api_accepted": True, "errno": None}])
        self.assertEqual(wire.send_probes(probes, "child"), [])
        self.assertNotIn("delivery_proven", evidence[0])

    def test_bind_denial_is_preserved_and_never_counted_as_send_acceptance(self):
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender
        sender.bind.side_effect = OSError(13, "denied")
        with mock.patch.object(wire.socket, "socket", return_value=sender):
            record = wire.send_probes([{"id": "p", "role": "parent", "family": "ipv4",
                "source_ip": "10.0.2.15", "destination": "1.1.1.1", "port": 53,
                "payload_hex": "00"}], "parent")[0]
        self.assertEqual(record["errno"], 13)
        self.assertFalse(record["bind_succeeded"])
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
        self.assertEqual(len(session.probes), 32)
        self.assertEqual(len({probe["id"] for probe in session.probes}), 32)
        self.assertEqual(len(session.for_variant("model1_internal")), 8)
        self.assertEqual({probe["source_mac"] for probe in session.probes}, {wire.SOURCE_MAC})

    def test_private_request_exception_never_exposes_capability_url(self):
        session = self.make_session()
        session.opener = mock.Mock()
        session.opener.open.side_effect = RuntimeError(session.base)
        with self.assertRaises(RuntimeError) as failure:
            session.request("start", {})
        self.assertEqual(str(failure.exception), "private_wire_endpoint_failed")
        self.assertIsNone(failure.exception.__cause__)

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
