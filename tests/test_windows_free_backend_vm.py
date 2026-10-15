import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("windows_free_backend_vm", ROOT / ".github/windows_free_backend_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


class BundleValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self._installer_pins = vm.INSTALLER_PIN.copy()
        test_installer = b"pinned installer"
        digest = hashlib.sha256(test_installer).hexdigest()
        vm.INSTALLER_PIN.update({name: (len(test_installer), digest) for name in vm.BACKENDS})

    def tearDown(self):
        vm.INSTALLER_PIN.clear()
        vm.INSTALLER_PIN.update(self._installer_pins)
        self.temp.cleanup()

    def make_bundle(self, backend="sandboxie", extra=None, alter_manifest=None):
        common = {
            "python/python.exe": b"python",
            "mihomo/mihomo.exe": b"mihomo",
            "chromium/chrome-win64/chrome.exe": b"chrome",
            "scripts/windows_native_dns_probe.py": b"dns probe",
            "scripts/windows_free_backend_fixture.py": b"fixture",
            f"scripts/windows_{backend}_control.py": b"backend script",
            vm.INSTALLER_MEMBER[backend]: b"pinned installer",
        }
        if extra:
            common.update(extra)
        rows = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "source_url": "https://example.invalid/fixed"} for name, data in common.items()]
        manifest = {"schema_version": 1, "backend": backend,
                    "release": vm.BACKEND_RELEASE[backend],
                    "source_diagnostic_only": True, "release_eligible": False, "files": rows}
        if alter_manifest:
            alter_manifest(manifest)
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        bundle = self.root / "bundle.zip"
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            for name, data in common.items():
                archive.writestr(name, data)
        return bundle, manifest_path, manifest

    def test_valid_fixed_backend_bundle_is_verified_member_by_member(self):
        bundle, manifest, _ = self.make_bundle()
        result = vm.validate_bundle(bundle, manifest, "sandboxie")
        self.assertEqual(result["backend"], "sandboxie")
        self.assertEqual(result["file_count"], 7)
        self.assertEqual(result["bundle_sha256"], vm.sha256_file(bundle))

    def test_rejects_wrong_backend_unsafe_names_extra_files_and_hash_mismatch(self):
        bundle, manifest, _ = self.make_bundle("proxybridge")
        with self.assertRaisesRegex(ValueError, "backend"):
            vm.validate_bundle(bundle, manifest, "sandboxie")

        def unsafe(value):
            value["files"][0]["path"] = "scripts/../../escape.py"
        bundle, manifest, _ = self.make_bundle(alter_manifest=unsafe)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            vm.validate_bundle(bundle, manifest, "sandboxie")

        bundle, manifest, _ = self.make_bundle()
        with zipfile.ZipFile(bundle, "a") as archive:
            archive.writestr("scripts/unlisted.py", b"extra")
        with self.assertRaisesRegex(ValueError, "exactly match"):
            vm.validate_bundle(bundle, manifest, "sandboxie")

        bundle, manifest, _ = self.make_bundle()
        changed = bundle.with_name("changed.zip")
        with zipfile.ZipFile(bundle) as source, zipfile.ZipFile(changed, "w") as output:
            for item in source.infolist():
                data = source.read(item.filename)
                if item.filename == "mihomo/mihomo.exe":
                    data = b"bad---"
                output.writestr(item.filename, data)
        bundle = changed
        with self.assertRaisesRegex(ValueError, "digest"):
            vm.validate_bundle(bundle, manifest, "sandboxie")

    def test_manifest_cannot_claim_non_https_download_origin(self):
        def bad_url(value):
            value["files"][0]["source_url"] = "http://example.invalid/file"
        bundle, manifest, _ = self.make_bundle(alter_manifest=bad_url)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            vm.validate_bundle(bundle, manifest, "sandboxie")

    def test_pinned_original_vm_helpers_import_without_running_the_vm(self):
        helpers = vm._load_vm_helpers()
        self.assertEqual(helpers.UPDATE_BUILD, 26200)
        self.assertEqual(helpers.UPDATE_UBR, 9711)


class ResultGateTests(unittest.TestCase):
    def result(self):
        return {
            "schema_version": 1, "status": "passed", "backend": "proxybridge",
            "diagnostic_only": True, "product_acceptance_passed": False,
            "ordinary_user": True, "is_elevated": False, "is_administrator": False,
            "windows_build": 26200, "windows_ubr": 9711,
            "capture": {"status": "stopped"},
            "reports": {
                "install": {"schema_version": 1, "status": "passed", "phase": "install", "backend": "proxybridge",
                            "ordinary_user": False, "is_elevated": True, "reboot_required": True,
                            "installer_sha256": vm.INSTALLER_PIN["proxybridge"][1],
                            "driver_signature": {"status": "Valid"},
                            "service_install": {"exists": True, "state": "running", "start_type": "auto"},
                            "target_user_authorized": True},
                "probe": {"schema_version": 1, "status": "passed", "phase": "probe", "backend": "proxybridge",
                          "ordinary_user": True, "is_elevated": False, "is_administrator": False,
                          "windows_build": 26200, "windows_ubr": 9711, "cleanup_proven": True,
                          "diagnostic_only": True, "product_acceptance_passed": False},
            },
        }

    def test_requires_nonadmin_probe_target_build_cleanup_and_capture(self):
        vm.verify_guest_result(self.result(), "proxybridge", 26200, 9711)
        for update in (
            {"ordinary_user": False}, {"is_administrator": True}, {"windows_ubr": 9710},
            {"capture": {"status": "not_started"}},
            {"reports": {"probe": {"status": "passed"}}},
        ):
            with self.subTest(update=update), self.assertRaises(ValueError):
                result = self.result()
                if "reports" in update:
                    result["reports"] = update["reports"]
                else:
                    result.update(update)
                vm.verify_guest_result(result, "proxybridge", 26200, 9711)

    def test_requires_installer_bytes_authenticode_and_target_user_authorization(self):
        for field, value in (("installer_sha256", "0" * 64),
                             ("driver_signature", {"status": "Unknown"}),
                             ("target_user_authorized", False)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                result = self.result()
                result["reports"]["install"][field] = value
                vm.verify_guest_result(result, "proxybridge", 26200, 9711)

    def test_partial_diagnostics_cannot_claim_product_acceptance(self):
        result = self.result()
        result["product_acceptance_passed"] = True
        with self.assertRaisesRegex(ValueError, "cannot claim product acceptance"):
            vm._safe_result(result)


class CaptureTests(unittest.TestCase):
    class Qmp:
        def __init__(self, pcap):
            self.pcap = pcap
            self.calls = []
        def execute(self, command, arguments):
            self.calls.append((command, arguments))
            if command == "object-add":
                self.pcap = arguments["file"]
            if command == "object-del":
                Path(self.pcap).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 40)

    def test_capture_has_one_bounded_start_stop_window_and_retains_raw_pcap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "artifacts").mkdir()
            qmp = self.Qmp(root / "private.pcap")
            capture = vm.ProbeCapture(qmp, root, root / "artifacts", root / "qemu.log")
            (root / "qemu.log").write_text("QEMU started", encoding="utf-8")
            self.assertEqual(capture.start({"probe_window_started": True})["status"], "active")
            with self.assertRaisesRegex(RuntimeError, "only once"):
                capture.start()
            result = capture.finish({"probe_window_finished": True})
            self.assertEqual(result["status"], "stopped")
            self.assertEqual(result["scope"], "qemu_vm_nic_probe_window_only")
            self.assertTrue((root / "artifacts/free-backend-probe.pcap").is_file())
            self.assertEqual([row[0] for row in qmp.calls], ["object-add", "object-del"])


if __name__ == "__main__":
    unittest.main()
