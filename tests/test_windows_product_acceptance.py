"""Guard evidence boundaries and final artifact verification before native CI."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile


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


if __name__ == "__main__":
    unittest.main()
