"""Guard evidence boundaries and final artifact verification before native CI."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock
import zipfile
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / ".github/windows_proxifyre_product_acceptance.py"
SPEC = importlib.util.spec_from_file_location("windows_product_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class ProductArtifactTests(unittest.TestCase):
    def package(self, directory, members=None, manifest_path="ruleproxy/manager.py"):
        package = directory / "final.zip"
        payload = b"final product implementation\n"
        manifest = {"version": "0.3.0", "files": {manifest_path: hashlib.sha256(payload).hexdigest()}}
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("RuleProxy-Web/package-manifest.json", json.dumps(manifest))
            archive.writestr("RuleProxy-Web/ruleproxy/manager.py", payload)
            for name, value in members or []:
                archive.writestr(name, value)
        (directory / "SHA256SUMS.txt").write_text(acceptance.digest(package) + "  final.zip\n")
        return package

    def test_final_package_verifies_manifest_and_exact_zip(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory)
            root, facts = acceptance.unpack_package(directory, directory / "unpacked")
            self.assertEqual((root / "ruleproxy/manager.py").read_bytes(), b"final product implementation\n")
            self.assertTrue(facts["manifest_verified"])
            self.assertEqual(facts["files_verified"], 1)

    def test_modified_zip_cannot_pass_checksum(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            package = self.package(directory)
            with package.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "digest"):
                acceptance.unpack_package(directory, directory / "unpacked")

    def test_zip_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, [("../outside.txt", "escape")])
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                acceptance.unpack_package(directory, directory / "unpacked")
            self.assertFalse((directory / "outside.txt").exists())

    def test_manifest_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, manifest_path="../outside.txt")
            with self.assertRaisesRegex(ValueError, "Unsafe manifest"):
                acceptance.unpack_package(directory, directory / "unpacked")


class ReceiverEvidenceTests(unittest.TestCase):
    def phase(self, node="A"):
        return {"label": "raw socket", "token": "unique-phase-token", "expected_node": node,
                "actor": {"rows": [{}, {}]}}

    def transaction(self, *, node="A", role="actor", protocol="tcp_http_response"):
        return {"node": node, "evidence_role": role, "protocol": protocol,
                "request_target": "/nonce/unique-phase-token-0"}

    def verified(self, phase, rows):
        return acceptance.receiver_evidence([phase], {"transactions": rows})[0]

    def test_two_independent_matching_responses_qualify(self):
        value = self.verified(self.phase(), [self.transaction(), self.transaction(protocol="udp_dns")])
        self.assertTrue(value["passed"])
        self.assertEqual(value["receiver_node_counts"], {"A": 2, "B": 0})

    def test_explicit_health_cannot_qualify_transparent_actor(self):
        value = self.verified(self.phase(), [self.transaction(role="health"), self.transaction(role="health")])
        self.assertFalse(value["passed"])

    def test_wrong_node_or_missing_response_cannot_qualify(self):
        self.assertFalse(self.verified(self.phase(), [self.transaction()])["passed"])
        rows = [self.transaction(), self.transaction(), self.transaction(node="B")]
        self.assertFalse(self.verified(self.phase(), rows)["passed"])

    def test_unselected_control_must_never_reach_fixture(self):
        self.assertTrue(self.verified(self.phase(None), [self.transaction(role="health")])["passed"])
        self.assertFalse(self.verified(self.phase(None), [self.transaction()])["passed"])

    def test_browser_single_navigation_requires_independent_selected_b_response(self):
        phase = {"label": "system_edge", "token": "browser-navigation-token", "expected_node": "B",
                 "actor": {"rows": [{"browser": "system_edge"}]}}
        transaction = {"node": "B", "evidence_role": "actor", "protocol": "tcp_http_response",
                       "request_target": "/nonce/browser-navigation-token"}
        value = self.verified(phase, [transaction])
        self.assertTrue(value["passed"])
        self.assertEqual(value["attempts"], 1)
        self.assertEqual(value["receiver_node_counts"], {"A": 0, "B": 1})
        for rows in ([], [{**transaction, "node": "A"}], [{**transaction, "evidence_role": "health"}],
                     [{**transaction, "request_target": "/unrelated-navigation"}]):
            with self.subTest(rows=rows):
                self.assertFalse(self.verified(phase, rows)["passed"])


class PngDimensionsTests(unittest.TestCase):
    @staticmethod
    def png(width=1, height=1):
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        # A complete valid 1x1 RGBA image; alternate dimensions exercise the
        # metadata boundary without allocating their decoded pixel buffers.
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")) + chunk(b"IEND", b""))

    def dimensions(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser-screenshot.png"
            path.write_bytes(raw)
            return acceptance.png_dimensions(path)

    def test_valid_one_pixel_and_maximum_header_dimensions(self):
        self.assertEqual(self.dimensions(self.png()), (1, 1))
        self.assertEqual(self.dimensions(self.png(16384, 16384)), (16384, 16384))

    def test_zero_or_oversized_dimensions_are_rejected(self):
        for width, height in ((0, 1), (1, 0), (0, 0), (16385, 1), (1, 16385), (0xFFFFFFFF, 1)):
            with self.subTest(width=width, height=height), self.assertRaises(ValueError):
                self.dimensions(self.png(width, height))

    def test_signature_and_truncated_headers_are_rejected(self):
        valid = self.png()
        for raw in (b"not a PNG" + valid[9:], valid[:0], valid[:8], valid[:24], valid[:32]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.dimensions(raw)

    def test_only_the_33_byte_header_is_read(self):
        class HeaderStream(io.BytesIO):
            def __init__(self, raw):
                super().__init__(raw)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                if size != 33 or len(self.read_sizes) != 1:
                    raise AssertionError("Screenshot inspection must read only its first 33 bytes")
                return super().read(size)

        stream = HeaderStream(self.png())
        with mock.patch.object(Path, "open", return_value=stream), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Unbounded screenshot read")):
            self.assertEqual(acceptance.png_dimensions(Path("screenshot.png")), (1, 1))
        self.assertEqual(stream.read_sizes, [33])


if __name__ == "__main__":
    unittest.main()
