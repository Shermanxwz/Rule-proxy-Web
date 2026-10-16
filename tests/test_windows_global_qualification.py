"""Future release attestation admission; fixtures never qualify this release."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ruleproxy import windows_global_qualification as qualification
from ruleproxy.windows_proxy_policy import ProxyError


class QualificationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.program_files = Path(temporary.name)
        self.root = self.program_files / "RuleProxy-Web"
        self.entries = {}
        for name in qualification.CRITICAL_FILES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(("protected fixture " + name).encode())
            self.entries[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        self.os = {"major": 10, "minor": 0, "build": 26100, "ubr": 1234,
                   "product_type": 1, "architecture": "AMD64"}
        self.value = {"schema_version": 1, "profile": qualification.PROFILE,
                      "accepted": True, "runtime_only": True, "boot_protection": False,
                      "os": dict(self.os), "files": dict(self.entries), "source_commit": "a" * 40,
                      "scenarios": {name: {"result": "passed", "mode": "native_global_runtime_qualification",
                                           "artifact_sha256": "b" * 64, "summary_sha256": "c" * 64}
                                    for name in qualification.SCENARIOS}}
        self.metadata = {"root": str(self.root), "files": self.entries}
        environment = mock.patch.dict(os.environ, {"ProgramFiles": str(self.program_files)})
        environment.start()
        self.addCleanup(environment.stop)
        identity = mock.patch.object(qualification, "_os_identity", return_value=self.os)
        identity.start()
        self.addCleanup(identity.stop)
        acl = mock.patch("ruleproxy.windows_proxy_service.protected_path")
        self.acl = acl.start()
        self.addCleanup(acl.stop)

    def write(self, value=None, *, raw=None):
        raw = json.dumps(self.value if value is None else value).encode() if raw is None else raw
        path = self.root / qualification.RECEIPT
        path.write_bytes(raw)
        self.entries[qualification.RECEIPT] = hashlib.sha256(raw).hexdigest()
        return path

    def test_missing_receipt_is_false_without_os_acl_or_disk_hash_work(self):
        with mock.patch.object(qualification, "_digest") as digest, \
                mock.patch.object(qualification, "_os_identity") as identity:
            result = qualification.load_qualification(self.metadata)
        self.assertIs(result["native_qualified"], False)
        self.assertEqual(result["reason"], "qualification_missing")
        self.acl.assert_not_called()
        digest.assert_not_called()
        identity.assert_not_called()

    def test_complete_protected_runtime_fixture_qualifies_capability_only(self):
        self.write()
        result = qualification.load_qualification(self.metadata)
        self.assertIs(result["native_qualified"], True)
        self.assertIs(result["boot_protection"], False)
        self.assertIs(result["runtime_only"], True)
        self.assertNotIn("strict_isolation", result)
        self.assertIn(mock.call(self.root / qualification.RECEIPT), self.acl.call_args_list)
        for name in qualification.CRITICAL_FILES:
            self.assertIn(mock.call(self.root / name), self.acl.call_args_list)

    def test_tampering_manifest_omission_or_acl_failure_never_qualifies(self):
        path = self.write()
        path.write_bytes(path.read_bytes() + b" ")
        self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        self.write()
        with mock.patch("ruleproxy.windows_proxy_service.protected_path",
                        side_effect=ProxyError("unsafe_installation", "untrusted ACL")):
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        del self.entries[qualification.RECEIPT]
        self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)

    def test_every_critical_code_core_and_python_actual_hash_is_bound(self):
        self.write()
        for name in qualification.CRITICAL_FILES:
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + b"changed")
                self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
                path.write_bytes(original)
        name = "bin/windows-amd64/mihomo.exe"
        self.entries[name] = "d" * 64
        self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)

    def test_exact_os_revision_client_server_and_architecture_are_required(self):
        for key, wrong in (("build", 26101), ("ubr", 1235), ("product_type", 3),
                           ("architecture", "ARM64"), ("minor", False)):
            value = copy.deepcopy(self.value)
            value["os"][key] = wrong
            with self.subTest(key=key):
                self.write(value)
                self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        self.write()
        with mock.patch.object(qualification, "_os_identity", side_effect=OSError("unknown OS")):
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)

    def test_installed_python_extensions_and_vendor_code_cannot_be_omitted(self):
        for name in ("python/_ssl.pyd", "vendor/yaml/constructor.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixed interpreter extension or parser")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.entries[name] = digest
            self.write()
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
            self.value["files"][name] = digest
            self.write()
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], True)
            path.write_bytes(b"changed")
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
            path.write_bytes(b"fixed interpreter extension or parser")

    def test_receipt_read_is_bounded_even_if_file_grows_after_stat(self):
        from io import BytesIO
        from types import SimpleNamespace
        self.write()
        stream = mock.MagicMock(wraps=BytesIO(b"x" * (qualification.MAX_RECEIPT + 2)))
        stream.__enter__.return_value = stream
        with mock.patch.object(qualification, "_protected_file", return_value=mock.Mock(
                stat=mock.Mock(return_value=SimpleNamespace(st_size=1)),
                open=mock.Mock(return_value=stream))):
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        stream.read.assert_called_once_with(qualification.MAX_RECEIPT + 1)

    def test_closed_schema_no_duplicate_keys_no_boot_or_smoke_promotion(self):
        mutations = [{"accepted": False}, {"accepted": 1}, {"schema_version": True},
                     {"boot_protection": True}, {"boot_protection": 0}, {"runtime_only": 1},
                     {"profile": "windows-global-boot-v1"}, {"client_override": True},
                     {"source_commit": "not-a-commit"}]
        for changes in mutations:
            with self.subTest(changes=changes):
                self.write({**self.value, **changes})
                self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        raw = json.dumps(self.value).encode()
        for invalid in (raw[:-1] + b',"accepted":true}', b"[]", b"NaN", b" " * (qualification.MAX_RECEIPT + 1)):
            self.write(raw=invalid)
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        for field in ("files", "scenarios"):
            value = copy.deepcopy(self.value)
            value[field].pop(next(iter(value[field])))
            self.write(value)
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)
        for wrong in ({"mode": "disposable_windows_tun_startup_smoke"}, {"result": "pending"},
                      {"artifact_sha256": "bad"}, {"extra": True}):
            value = copy.deepcopy(self.value)
            value["scenarios"][next(iter(qualification.SCENARIOS))].update(wrong)
            self.write(value)
            self.assertIs(qualification.load_qualification(self.metadata)["native_qualified"], False)

    def test_no_accepted_receipt_ships_and_loader_is_packaged(self):
        root = Path(__file__).resolve().parents[1]
        self.assertFalse((root / qualification.RECEIPT).exists())
        spec = importlib.util.spec_from_file_location("qualification_package_builder",
                                                     root / ".github/build_windows_package.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        files = builder.project_files()
        self.assertIn("ruleproxy/windows_global_qualification.py", files)
        self.assertNotIn(qualification.RECEIPT, files)


if __name__ == "__main__":
    unittest.main()
