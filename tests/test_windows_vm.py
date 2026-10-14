"""Host-side VM controls cannot turn a skipped fixture into Windows acceptance."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_windows_vm", ROOT / ".github/windows_vm_test.py")
vm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vm)


class WindowsVmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def passed_result(self):
        return {
            "status": "passed", "ordinary_user": True,
            "phases": [{"name": name, "exit_code": 0} for name in ("probe", "transport", "browser", "package_tests")],
            "reports": {
                "probe": {"status": "supported_only", "probe": {"supported": True},
                          "acceptance_passed": False, "real_node_passed": False, "transport_passed": False},
                "transport": {"status": "transport_only", "transport_passed": True,
                              "acceptance_passed": False, "real_node_passed": False, "manager_core_loss_passed": False,
                              "host": {"acceptance_scope": "native_x64"}, "checks": [
                                  {"check": name, "status": "passed"} for name in (
                                      "transport_parent_child", "fixture_loss", "safe_psec_stop",
                                      "host_proxy_dns_default_routes_unchanged")]},
                "browser": {"status": "browser_fixture_only", "browser_fixture_passed": True,
                            "acceptance_passed": False, "real_node_passed": False,
                            "host": {"acceptance_scope": "native_x64"}, "checks": [
                                {"check": name, "status": "passed", "dom_nonce_via_page_ack": True,
                                 "cookie_request_verified": True, "natural_headless_exit": True,
                                 "private_profile_reused": True}
                                for name in ("real_edge_launch_1", "real_edge_launch_2")
                            ] + [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}]},
            }, "logs": {"tests": "Ran the release tests; environment-specific skips remain explicit."},
        }

    def test_complete_native_transport_report_is_accepted_without_claiming_real_nodes(self):
        vm.verify_result(self.passed_result())

    def test_zero_exit_does_not_replace_required_guest_evidence(self):
        cases = []
        bad = self.passed_result()
        bad["ordinary_user"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["transport"]["host"]["acceptance_scope"] = "emulated_x64_on_arm64"
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["transport"]["checks"][0]["status"] = "skipped"
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["transport"]["acceptance_passed"] = True
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["transport"]["real_node_passed"] = True
        cases.append(bad)
        bad = self.passed_result()
        bad["phases"][3]["exit_code"] = 1
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["browser"]["checks"][1]["private_profile_reused"] = False
        cases.append(bad)
        for result in cases:
            with self.subTest(result=result), self.assertRaises(RuntimeError):
                vm.verify_result(result)

    def test_rendered_answer_has_one_ordinary_user_no_key_and_bom_scripts(self):
        vm.prepare_seed(self.root, "TestPasswordCi!9", {"host_url": "http://10.0.2.2:10000/test"})
        document = ET.parse(self.root / "autounattend.xml")
        namespace = {"u": "urn:schemas-microsoft-com:unattend"}
        self.assertEqual(document.findtext(".//u:LocalAccount/u:Group", namespaces=namespace), "Users")
        self.assertEqual(document.findtext(".//u:AutoLogon/u:Username", namespaces=namespace), "RuleProxyCI")
        self.assertIsNone(document.find(".//u:ProductKey", namespace))
        self.assertEqual(document.findtext(".//u:LocalAccount/u:Password/u:Value", namespaces=namespace), "TestPasswordCi!9")
        for name in ("ruleproxy-vm-run.ps1", "ruleproxy-vm-setup.ps1"):
            self.assertTrue((self.root / name).read_bytes().startswith(b"\xef\xbb\xbf"))
        self.assertNotIn("@PASSWORD@", (self.root / "autounattend.xml").read_text())

    def test_external_checksum_and_safe_zip_members_are_required(self):
        path = self.root / "release.zip"
        with zipfile.ZipFile(path, "w") as archive:
            for name in ("python/python.exe", "ruleproxy/windows_runtime.py",
                         "bin/windows-amd64/wxc-exec.exe", "bin/windows-amd64/runtime.json"):
                archive.writestr("RuleProxy-Web/" + name, b"fixture")
        vm.verify_package(path, vm.digest(path))
        with self.assertRaises(ValueError):
            vm.verify_package(path, "0" * 64)
        with zipfile.ZipFile(path, "a") as archive:
            archive.writestr("RuleProxy-Web/../escape", b"bad")
        with self.assertRaises(ValueError):
            vm.verify_package(path, vm.digest(path))

    def test_local_result_endpoint_requires_its_nonce_and_preserves_guest_reports(self):
        payload = self.root / "payload.zip"
        payload.write_bytes(b"public test payload")
        server = vm.GuestServer(payload, self.root)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            worker.join(2)

        self.addCleanup(cleanup)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        with self.assertRaises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(base + "/wrong/payload.zip")
        self.assertEqual(failure.exception.code, 404)
        with urllib.request.urlopen(base + "/" + server.capability + "/payload.zip") as response:
            self.assertEqual(response.read(), payload.read_bytes())
        result = self.passed_result()
        request = urllib.request.Request(base + "/" + server.capability + "/result",
                                         data=json.dumps(result).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
        self.assertTrue(server.received.wait(2))
        vm.verify_result(server.result)
        self.assertEqual(json.loads((self.root / "windows-transport.json").read_text()), result["reports"]["transport"])
        self.assertEqual((self.root / "guest-tests.log").read_text(), result["logs"]["tests"])

    def test_unavailable_kvm_refuses_download_and_records_failed_acceptance(self):
        arguments = mock.Mock(artifacts=self.root, package=self.root / "absent.zip",
                              package_sha256="0" * 64, timeout_seconds=300)
        with mock.patch.object(vm, "require_kvm", side_effect=OSError("KVM unavailable")), mock.patch.object(
            vm.subprocess, "run"
        ) as run, mock.patch("builtins.print"):
            result = vm.run(arguments)
        run.assert_not_called()
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["transport_passed"])
        self.assertFalse(result["browser_fixture_passed"])
        self.assertEqual(json.loads((self.root / "windows-vm-summary.json").read_text()), result)


if __name__ == "__main__":
    unittest.main()
