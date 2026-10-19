import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent))
import test_windows_dns_packet_evidence as dns_fixture

spec = importlib.util.spec_from_file_location("compartment_wire_test",
    Path(__file__).resolve().parent.parent / ".github/windows_compartment_wire.py")
wire = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wire)


class CompartmentWireTests(unittest.TestCase):
    def test_only_random_lab_name_hashes_are_retained(self):
        name = "a" * 32 + ".1.2.3.4.sslip.io"
        frames = [dns_fixture.frame({"qname": name}), dns_fixture.frame({"qname": name}),
                  dns_fixture.frame({"qname": "private-user.example.com"})]
        result = wire.observe(io.BytesIO(dns_fixture.wire.pcap(frames)))
        self.assertEqual(result["queries"], [{"qname_sha256": hashlib.sha256(name.encode()).hexdigest(),
                                             "query_type": 1, "count": 2}])
        self.assertNotIn(name, json.dumps(result))
        self.assertNotIn("private-user", json.dumps(result))
        self.assertFalse(result["absence_proven"])
        self.assertFalse(result["process_attribution_proven"])

    def test_empty_capture_does_not_prove_absence(self):
        result = wire.observe(io.BytesIO(dns_fixture.wire.pcap([])))
        self.assertEqual(result["queries"], [])
        self.assertFalse(result["absence_proven"])

    def test_truncated_capture_is_rejected(self):
        data = dns_fixture.wire.pcap([dns_fixture.frame({"qname": "a" * 32 + ".1.2.3.4.sslip.io"})])
        with self.assertRaises(ValueError):
            wire.observe(io.BytesIO(data[:-1]))

    def test_capture_flushes_before_parsing_and_removes_raw_file(self):
        with tempfile.TemporaryDirectory() as directory:
            qmp = mock.Mock()
            capture = wire.Capture(qmp, directory, directory)
            self.assertTrue(capture.start({})["started"])
            capture.private.write_bytes(dns_fixture.wire.pcap([]))
            result = capture.finish({})
            self.assertFalse(result["absence_proven"])
            self.assertFalse(capture.private.exists())
            self.assertEqual(qmp.execute.call_args.args, ("object-del", {"id": "compartment_wire"}))
            self.assertTrue((Path(directory) / "compartment-dns-wire-observations.json").is_file())

    def test_abort_closes_only_its_owned_capture_and_removes_raw_file(self):
        with tempfile.TemporaryDirectory() as directory:
            qmp = mock.Mock()
            capture = wire.Capture(qmp, directory, directory)
            capture.start({})
            capture.abort()
            self.assertFalse(capture.private.exists())
            self.assertEqual(capture.state, "aborted")
            with self.assertRaises(RuntimeError):
                capture.start({})


if __name__ == "__main__":
    unittest.main()
