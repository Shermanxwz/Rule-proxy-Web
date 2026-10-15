"""Native qualification must prove client OS, package identity and ordinary actors."""
import importlib.util
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_proxifyre_native_vm", ROOT / ".github/windows_proxifyre_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


def successful_result():
    return {"status": "passed", "exit_code": 0, "user_cleanup_confirmed": True,
        "os": {"product_type": "WinNT", "native_architecture": "AMD64", "build": 26200},
        "reports": {"product": {"status": "passed_server_product_qualification", "hosts_restored": True,
            "actual_os": {"major": 10, "build": 26200, "product_type": 1, "architecture": "AMD64"},
            "checks": {"install_and_reinstall": True, "uninstall_preserves_user_state_and_shared_driver": True},
            "source_matches_bundle": {name: True for name in vm.SOURCE_IDENTITIES},
            "package": {"manifest_verified": True, "sha256": "a" * 64},
            "receiver_phase_evidence": [{"passed": True}],
            "ordinary_suite": {"status": "passed", "is_elevated": False, "panel_is_elevated": False,
                "checks": {name: True for name in ("suite_ordinary", "panel_ordinary", "installed_package_loaded", "holder_ordinary")}}}}}


class NativeProductEvidenceTests(unittest.TestCase):
    def test_controller_generic_status_needs_actual_windows_11_and_identity(self):
        result = successful_result()
        self.assertIs(vm.verify_result(result, package_sha256="a" * 64), result["reports"]["product"])
        with self.assertRaises(RuntimeError):
            vm.verify_result(result, package_sha256="b" * 64)

    def test_server_or_emulated_or_mismatched_os_cannot_claim_client_native_pass(self):
        changes = [("outer", "product_type", "ServerNT"), ("actual", "product_type", 3),
                   ("actual", "product_type", True), ("actual", "architecture", "ARM64"),
                   ("outer", "native_architecture", "ARM64"), ("actual", "build", 26100),
                   ("outer", "build", 20348), ("actual", "major", 6)]
        for scope, key, value in changes:
            with self.subTest(scope=scope, key=key, value=value):
                result = successful_result()
                target = result["os"] if scope == "outer" else result["reports"]["product"]["actual_os"]
                target[key] = value
                with self.assertRaises(RuntimeError):
                    vm.verify_result(result)

    def test_missing_source_identity_never_passes_vacuously(self):
        for identities in ({}, {"unrelated.py": True}, {name: True for name in vm.SOURCE_IDENTITIES - {"manager.py"}}):
            result = successful_result()
            result["reports"]["product"]["source_matches_bundle"] = identities
            with self.subTest(identities=identities), self.assertRaises(RuntimeError):
                vm.verify_result(result)

    def test_missing_ordinary_actor_receiver_or_cleanup_fails(self):
        for missing in ("is_elevated", "panel_is_elevated", "checks"):
            result = successful_result()
            result["reports"]["product"]["ordinary_suite"].pop(missing)
            with self.subTest(missing=missing), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        for field, value in (("receiver_phase_evidence", []), ("receiver_phase_evidence", [{"passed": False}]),
                             ("package", {"manifest_verified": False}), ("hosts_restored", False)):
            result = successful_result()
            result["reports"]["product"][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        result = successful_result()
        result["user_cleanup_confirmed"] = False
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)


class NativePackageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.package = Path(self.temporary.name) / "product.zip"

    def package_with(self, extra=None):
        with zipfile.ZipFile(self.package, "w") as archive:
            for name in ("python/python.exe", "package-manifest.json", "ruleproxy/windows_proxy_service.py", "scripts/windows-setup.ps1"):
                archive.writestr("RuleProxy-Web/" + name, b"fixture")
            if extra is not None:
                archive.writestr(extra, b"malicious")
        return vm.media.digest(self.package)

    def test_hash_tampering_rejected_before_payload_creation(self):
        digest = self.package_with()
        vm.verify_package(self.package, digest)
        self.package.write_bytes(self.package.read_bytes() + b"tampering")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            vm.verify_package(self.package, digest)

    def test_unsafe_paths_case_collisions_and_symlinks_are_rejected(self):
        for name in ("RuleProxy-Web/../escape", "C:/escape", "/escape", "RuleProxy-Web\\escape",
                     "other-root/escape", "RuleProxy-Web/PYTHON/PYTHON.EXE"):
            digest = self.package_with(name)
            with self.subTest(name=name), self.assertRaises(ValueError):
                vm.verify_package(self.package, digest)
        self.package_with()
        link = zipfile.ZipInfo("RuleProxy-Web/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(self.package, "a") as archive:
            archive.writestr(link, "../escape")
        with self.assertRaises(ValueError):
            vm.verify_package(self.package, vm.media.digest(self.package))


class NativeCleanupTests(unittest.TestCase):
    def test_owned_processes_stop_before_secret_directory_is_deleted(self):
        calls = []
        qemu, tpm = mock.Mock(), mock.Mock()
        qemu.poll.return_value = tpm.poll.return_value = 0
        server = mock.Mock()
        server.shutdown.side_effect = lambda: calls.append("server")
        with mock.patch.object(vm.media, "stop_owned", side_effect=lambda proc: calls.append("qemu" if proc is qemu else "tpm")), \
                mock.patch.object(vm.shutil, "rmtree", side_effect=lambda _: calls.append("delete")):
            self.assertEqual(vm.cleanup_owned(None, qemu, tpm, server, None, Path("private")), [])
        self.assertEqual(calls, ["qemu", "tpm", "server", "delete"])

    def test_live_vm_prevents_private_tree_unlink_even_if_termination_fails(self):
        process = mock.Mock()
        process.poll.return_value = None
        with mock.patch.object(vm.media, "stop_owned", side_effect=OSError("secret path omitted")), \
                mock.patch.object(vm.shutil, "rmtree") as remove:
            errors = vm.cleanup_owned(None, process, None, None, None, Path("private"))
        remove.assert_not_called()
        self.assertTrue(any(row["error_type"] == "OwnedProcessStillRunning" for row in errors))
        self.assertNotIn("secret path", str(errors))

    def test_bootstrap_does_not_repeat_reports_or_export_private_url_logs(self):
        script = (ROOT / ".github/windows-proxifyre-vm-run.ps1").read_text()
        self.assertLess(script.index("FileMode]::CreateNew"), script.index("Unregister-ScheduledTask"))
        self.assertNotIn("$result.logs.supervisor", script)
        self.assertIn("$request.Timeout = 15000", script)
        self.assertIn("$result.user_cleanup_confirmed", script)
        self.assertIn("Remove-Item Env:RULEPROXY_TEST_PASSWORD", script)


if __name__ == "__main__":
    unittest.main()
