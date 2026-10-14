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
            "phases": [{"name": name, "status": "passed", "exit_code": 0} for name in vm.PHASE_NAMES],
            "reports": {
                "probe": {"status": "supported_only", "probe": {"supported": True},
                          "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                                   "python_pe_machine": 0x8664}, "acceptance_passed": False,
                          "real_node_passed": False, "transport_passed": False},
                "transport": {"status": "transport_only", "transport_passed": True,
                              "acceptance_passed": False, "real_node_passed": False, "manager_core_loss_passed": False,
                              "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                                       "python_pe_machine": 0x8664}, "checks": [
                                  {"check": name, "status": "passed"} for name in (
                                      "transport_parent_child", "fixture_loss", "safe_psec_stop",
                                      "host_proxy_dns_default_routes_unchanged")]},
                "manager": {"status": "manager_fixture_only", "manager_fixture_passed": True,
                            "manager_normal_stop_passed": True, "manager_core_loss_passed": True,
                            "test_only_endpoint_override": True, "acceptance_passed": False,
                            "real_node_passed": False, "host": {"acceptance_scope": "native_x64",
                                                                  "native_machine": 0x8664, "python_pe_machine": 0x8664},
                            "checks": [{"check": name, "status": "passed", "parent_and_child_exited": True,
                                        "held_handles_verified": True, "manager_active_removed": True,
                                        "runtime_resources_closed": True, "manager_owned_core_stopped": True,
                                        "manager_watcher_exercised": True}
                                       for name in ("manager_normal_stop", "manager_core_loss")]
                                      + [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}]},
                "browser": {"status": "browser_fixture_only", "browser_fixture_passed": True,
                            "acceptance_passed": False, "real_node_passed": False,
                            "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                                     "python_pe_machine": 0x8664}, "checks": [
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
        bad["phases"][4]["exit_code"] = 1
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["browser"]["checks"][1]["private_profile_reused"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["checks"][1]["manager_watcher_exercised"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["test_only_endpoint_override"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["checks"][0]["held_handles_verified"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["checks"][0]["manager_owned_core_stopped"] = False
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["probe"]["host"]["acceptance_scope"] = "emulated_x64_on_arm64"
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["cleanup_error"] = "OSError"
        cases.append(bad)
        bad = self.passed_result()
        bad["phases"][1]["status"] = "blocked"
        cases.append(bad)
        bad = self.passed_result()
        bad["reports"]["manager"]["host"]["native_machine"] = 0xAA64
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
        self.assertEqual(json.loads((self.root / "windows-manager.json").read_text()), result["reports"]["manager"])
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
        self.assertFalse(result["manager_fixture_passed"])
        self.assertFalse(result["browser_fixture_passed"])
        self.assertEqual(json.loads((self.root / "windows-vm-summary.json").read_text()), result)

    def test_compatibility_readme_or_partial_udf_tree_cannot_reach_iso_rebuild(self):
        (self.root / "README.TXT").write_bytes(b"This disc uses the UDF file system.")
        with self.assertRaisesRegex(RuntimeError, "Windows boot file"):
            vm.validate_install_tree(self.root)
        for relative in ("boot/etfsboot.com", "efi/microsoft/boot/efisys_noprompt.bin", "sources/boot.wim"):
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fixture" * 100)
        with mock.patch.object(vm, "MIN_BOOT_IMAGE_BYTES", 512), mock.patch.object(vm, "MIN_INSTALL_IMAGE_BYTES", 512):
            with self.assertRaisesRegex(RuntimeError, "complete Windows install"):
                vm.validate_install_tree(self.root)
            (self.root / "sources/install.wim").write_bytes(b"truncated")
            with self.assertRaisesRegex(RuntimeError, "complete Windows install"):
                vm.validate_install_tree(self.root)
            (self.root / "sources/install.wim").write_bytes(b"fixture" * 100)
            self.assertEqual(vm.validate_install_tree(self.root), "efi/microsoft/boot/efisys_noprompt.bin")
            (self.root / "efi/microsoft/boot/efisys_noprompt.bin").rename(self.root / "efi/microsoft/boot/efisys.bin")
            self.assertEqual(vm.validate_install_tree(self.root), "efi/microsoft/boot/efisys.bin")
            (self.root / "efi/microsoft/boot/efisys.bin").unlink()
            with self.assertRaisesRegex(RuntimeError, "official Windows UEFI"):
                vm.validate_install_tree(self.root)

    def guest_control_workspace(self, overrides=None):
        """Real child interpreters test orchestration; they do not simulate PSEC proof."""
        workspace = self.root / "workspace"
        control = {name: {"report": report} for name, report in self.passed_result()["reports"].items()}
        control["package_tests"] = {}
        for name, changes in (overrides or {}).items():
            control[name].update(changes)
        workspace.mkdir()
        (workspace / "fixture-control.json").write_text(json.dumps(control), encoding="utf-8")
        script = '''import json, sys, time
from pathlib import Path
workspace = Path(__file__).resolve().parent.parent
if Path(__file__).name == 'run_tests.py':
    name = 'package_tests'
elif Path(__file__).name == 'windows_browser_check.py':
    name = 'browser'
else:
    name = 'probe' if '--probe-only' in sys.argv else ('manager' if '--manager-fixture' in sys.argv else 'transport')
configuration = json.loads((workspace / 'fixture-control.json').read_text(encoding='utf-8'))[name]
with (workspace / 'executed.txt').open('a', encoding='utf-8') as output:
    output.write(name + '\\n')
print(name + ' child interpreter ran', flush=True)
if configuration.get('log_bytes'):
    print('x' * configuration['log_bytes'], flush=True)
time.sleep(configuration.get('delay', 0))
if 'report' in configuration and not configuration.get('skip_report'):
    Path(sys.argv[sys.argv.index('--report') + 1]).write_text(json.dumps(configuration['report']), encoding='utf-8')
raise SystemExit(configuration.get('exit_code', 0))
'''
        for relative in ("scripts/windows-acceptance.py", ".github/windows_browser_check.py", ".github/run_tests.py"):
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(script, encoding="utf-8")
        return workspace

    def test_failed_transport_collects_manager_browser_and_package_results(self):
        failed = {"status": "failed", "acceptance_passed": False, "real_node_passed": False,
                  "failure_detail": "contained listener rejected the socket"}
        workspace = self.guest_control_workspace({"transport": {"exit_code": 1, "report": failed}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), list(vm.PHASE_NAMES))
        self.assertEqual(result["status"], "failed")
        self.assertEqual([phase["status"] for phase in result["phases"]],
                         ["passed", "failed", "passed", "passed", "passed"])
        self.assertEqual(result["reports"]["transport"], failed)
        self.assertEqual(result["recovery_records"], [])
        self.assertIn("manager child interpreter ran", result["logs"]["manager"])
        with self.assertRaises(RuntimeError):
            vm.verify_result(dict(result, ordinary_user=True))

    def test_failed_probe_blocks_contained_fixtures_but_runs_package_tests(self):
        workspace = self.guest_control_workspace({"probe": {"exit_code": 3, "report": {
            "status": "unsupported", "probe": {"supported": False}, "acceptance_passed": False,
            "real_node_passed": False, "transport_passed": False}}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe", "package_tests"])
        self.assertEqual([phase["status"] for phase in result["phases"]],
                         ["failed", "blocked", "blocked", "blocked", "passed"])
        self.assertEqual(result["status"], "failed")

    def test_pending_cleanup_preserves_recovery_and_blocks_new_containers(self):
        recovery = self.root / "retained-guard"
        recovery.mkdir()
        marker = recovery / "guard.json"
        marker.write_text("Retained recovery metadata")
        failed = {"status": "failed", "acceptance_passed": False, "real_node_passed": False,
                  "cleanup_error": "ChildIdentityUnproven", "recovery_directory": str(recovery)}
        workspace = self.guest_control_workspace({"transport": {"exit_code": 1, "report": failed}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe", "transport", "package_tests"])
        self.assertEqual(result["phases"][2]["status"], "blocked")
        self.assertEqual(result["phases"][3]["status"], "blocked")
        self.assertEqual(result["recovery_records"][0]["recovery_directory"], str(recovery))
        self.assertEqual(result["recovery_records"][0]["cleanup_error"], "ChildIdentityUnproven")
        self.assertFalse(result["recovery_records"][0]["descendant_cleanup_proven"])
        self.assertEqual(marker.read_text(), "Retained recovery metadata")

    def test_timeout_blocks_new_containers_and_keeps_unit_test_independent(self):
        workspace = self.guest_control_workspace({"transport": {"delay": 20}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", phase_timeout=3)
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe", "transport", "package_tests"])
        self.assertTrue(result["phases"][1]["timed_out"])
        self.assertIsNotNone(result["phases"][1]["exit_code"])
        self.assertFalse(result["recovery_records"][0]["descendant_cleanup_proven"])
        self.assertEqual(result["phases"][4]["status"], "passed")

    def test_stale_report_cannot_pass_and_phase_log_is_bounded(self):
        workspace = self.guest_control_workspace({"transport": {"skip_report": True},
                                                  "package_tests": {"log_bytes": vm.MAX_PHASE_RECORD_BYTES + 100}})
        reports = self.root / "reports"
        reports.mkdir()
        (reports / "transport.json").write_text(json.dumps(self.passed_result()["reports"]["transport"]))
        result = vm.run_guest_phases(self.root / "release", workspace, reports)
        self.assertEqual(result["phases"][1]["status"], "failed")
        self.assertNotIn("transport", result["reports"])
        self.assertFalse((reports / "transport.json").exists())
        self.assertEqual(result["phases"][2]["status"], "blocked")
        self.assertIn("truncated", result["logs"]["tests"])
        self.assertLess(len(result["logs"]["tests"]), vm.MAX_PHASE_RECORD_BYTES + 100)

    def test_guest_cli_emits_all_phase_results_without_claiming_user_proof(self):
        workspace = self.guest_control_workspace()
        report = self.root / "reports/guest-phases.json"
        with mock.patch("builtins.print"):
            code = vm.main(["--guest-phases", "--root", str(self.root / "release"),
                            "--workspace", str(workspace), "--report", str(report)])
        self.assertEqual(code, 0)
        result = json.loads(report.read_text())
        self.assertNotIn("ordinary_user", result)
        vm.verify_result(dict(result, ordinary_user=True))
        self.assertEqual(len(result["phases"]), 5)
        self.assertEqual(result["recovery_records"], [])


if __name__ == "__main__":
    unittest.main()
