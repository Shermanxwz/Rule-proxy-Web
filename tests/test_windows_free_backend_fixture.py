import importlib.util
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("free_backend_fixture", ROOT / ".github/windows_free_backend_fixture.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class FreeBackendFixtureTests(unittest.TestCase):
    def test_udp_probe_records_complete_bounded_tuple_and_exact_payload(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver:
            receiver.bind(("127.0.0.1", 0))
            receiver.settimeout(2)
            destination_port = receiver.getsockname()[1]
            spec = {"nonce": "a" * 32, "udp4_host": "127.0.0.1",
                    "udp4_port": destination_port}
            record = fixture.udp_probe(spec, "udp4", "outside_before")
            payload, address = receiver.recvfrom(1024)
        self.assertTrue(record["send_ok"])
        self.assertTrue(record["metadata_complete"])
        self.assertEqual(record["family"], "ipv4")
        self.assertEqual(record["dest_ip"], "127.0.0.1")
        self.assertEqual(record["dest_port"], destination_port)
        self.assertEqual(record["source_ip"], address[0])
        self.assertEqual(record["timeout_ms"], 2000)
        self.assertEqual(bytes.fromhex(record["payload_hex"]), payload)
        self.assertEqual(payload, ("RPWFREE:" + "a" * 32 + ":outside_before").encode("ascii"))
        self.assertFalse(record["denial_proven"])

    def test_outside_wire_role_is_propagated_to_nested_child_without_dns(self):
        roles = []
        def fake_udp(_spec, label, role):
            roles.append((label, role))
            return {"attempted": True, "send_ok": False}
        def fake_child(args, **_kwargs):
            self.assertIn("--skip-native-dns", args)
            marker_index = args.index("--wire-role")
            self.assertEqual(args[marker_index + 1], "outside_after")
            Path(args[args.index("--report") + 1]).write_text(
                '{"schema_version":1,"role":"child"}', encoding="ascii")
            return mock.Mock(returncode=0)
        with tempfile.TemporaryDirectory() as temp:
            report = Path(temp) / "parent.json"
            with mock.patch.object(fixture, "http_probe", return_value={"ok": False}), \
                 mock.patch.object(fixture, "direct_probe", return_value={"connected": False}), \
                 mock.patch.object(fixture, "udp_probe", side_effect=fake_udp), \
                 mock.patch.object(fixture.subprocess, "run", side_effect=fake_child):
                value = fixture.worker({"nonce": "a" * 32}, "parent", report,
                                       collect_native_dns=False, wire_role="outside_after")
        self.assertTrue(all(role == "outside_after" for _, role in roles))
        self.assertEqual(len(roles), 4)
        self.assertEqual(value["native_dns"]["status"], "not_requested")

    @unittest.skipUnless(os.environ.get("RULEPROXY_TEST_MIHOMO"), "Requires explicitly selected real fixture Mihomo")
    def test_real_mihomo_domain_http_socks_receiver_controls_and_core_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            with fixture.Fixture(Path(os.environ["RULEPROXY_TEST_MIHOMO"]), Path(directory)) as control:
                self.assertTrue(fixture.http_probe(control.spec)["ok"])
                self.assertTrue(fixture.http_probe(control.spec, socks=True)["ok"])
                self.assertTrue(fixture.direct_probe(control.spec)["connected"])
                self.assertTrue(fixture.udp_probe(control.spec, "udp4", "outside_before")["send_ok"])
                deadline = time.monotonic() + 2
                while control.snapshot()["udp4_received"] == 0 and time.monotonic() < deadline:
                    time.sleep(.01)
                counts = control.snapshot()
                self.assertEqual(counts["proxy_requests"], 2)
                self.assertEqual(counts["origin_requests"], 2)
                self.assertEqual(counts["direct_connections"], 1)
                self.assertEqual(counts["udp4_by_role"], {"outside_before": 1})
                self.assertEqual(counts["errors"], [])
                self.assertTrue(control.stop_proxy()["exited"])
                self.assertFalse(fixture.http_probe(control.spec)["ok"])
                self.assertFalse(fixture.http_probe(control.spec, socks=True)["ok"])
                self.assertTrue(fixture.direct_probe(control.spec)["connected"])
            self.assertTrue(all(not thread.is_alive() for thread in control.threads))


if __name__ == "__main__":
    unittest.main()
