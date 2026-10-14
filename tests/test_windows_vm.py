"""Host-side VM controls cannot turn a skipped fixture into Windows acceptance."""
import importlib.util
import ipaddress
import http.client
import json
import os
from pathlib import Path
import tempfile
import threading
import struct
import time
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

    def test_update_downloads_and_seed_require_external_bytes_and_hashes(self):
        import hashlib
        records = [{"filename": "checkpoint.msu", "url": "https://example.invalid/checkpoint.msu",
                    "sha256": hashlib.sha256(b"checkpoint").hexdigest(), "bytes": 10},
                   {"filename": "target.msu", "url": "https://example.invalid/target.msu",
                    "sha256": hashlib.sha256(b"target").hexdigest(), "bytes": 6}]
        data = {"checkpoint.msu": b"checkpoint", "target.msu": b"target"}

        def download(command, **_):
            path = Path(command[command.index("--output") + 1])
            path.write_bytes(data[path.name])

        updates = self.root / "updates"
        with mock.patch.object(vm, "UPDATE_PACKAGES", records), mock.patch.object(vm.subprocess, "run", side_effect=download), mock.patch("builtins.print"):
            verified = vm.download_updates(updates)
            self.assertTrue(all(item["verified"] for item in verified))
            tree = self.root / "seed"
            tree.mkdir()
            base = "http://10.0.2.2:12345/" + "a" * 64
            vm.prepare_seed(tree, "TestPasswordCi!9", {"host_url": base}, updates=updates)
            self.assertEqual(list((tree / "ruleproxy-updates/packages").iterdir()), [])
            self.assertEqual(list(tree.rglob("*.msu")), [])
            manifest = json.loads((tree / "ruleproxy-updates/update-manifest.json").read_text())
            self.assertEqual(manifest["target_package"], "target.msu")
            self.assertEqual(manifest["packages"], [
                {"filename": item["filename"], "sha256": item["sha256"], "bytes": item["bytes"],
                 "url": base + "/updates/" + item["filename"]} for item in records])
            self.assertEqual((updates / "target.msu").read_bytes(), b"target")
            self.assertTrue((tree / "ruleproxy-updates/windows-vm-update.ps1").read_bytes().startswith(b"\xef\xbb\xbf"))
            data["target.msu"] = b"broken"
            with self.assertRaisesRegex(RuntimeError, "size/SHA-256"):
                vm.download_updates(self.root / "bad-download")
            (updates / "target.msu").write_bytes(b"broken")
            other = self.root / "bad-seed"
            other.mkdir()
            with self.assertRaisesRegex(RuntimeError, "changed before seed"):
                vm.prepare_seed(other, "TestPasswordCi!9", {}, updates=updates)

    def test_private_update_routes_require_capability_and_exact_fixed_short_filename(self):
        import hashlib
        data = b"bounded deterministic MSU fixture"
        records = [{"filename": "catalog-original-hash.msu", "seed_filename": "target.msu",
                    "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}]
        updates = self.root / "updates"
        updates.mkdir()
        source = updates / records[0]["filename"]
        source.write_bytes(data)
        payload = self.root / "payload.zip"
        payload.write_bytes(b"payload")
        with mock.patch.object(vm, "UPDATE_PACKAGES", records):
            server = vm.GuestServer(payload, self.root, updates=updates)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            worker.join(2)

        self.addCleanup(cleanup)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        route = "/" + server.capability + "/updates/"
        for path in ("/wrong/updates/target.msu", route + records[0]["filename"],
                     route + "missing.msu", route + "../payload.zip",
                     route + "%2e%2e/payload.zip", route + "target.msu?other=1"):
            with self.subTest(path=path), self.assertRaises(urllib.error.HTTPError) as failure:
                urllib.request.urlopen(base + path, timeout=2)
            self.assertEqual(failure.exception.code, 404)
        with urllib.request.urlopen(base + route + "target.msu", timeout=2) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Length"], str(len(data)))
            self.assertEqual(response.read(), data)
        source.write_bytes(b"truncated")
        with self.assertRaises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(base + route + "target.msu", timeout=2)
        self.assertEqual(failure.exception.code, 503)

    def test_private_update_server_refuses_same_size_bytes_with_wrong_external_hash(self):
        import hashlib
        updates = self.root / "updates"
        updates.mkdir()
        data = b"verified MSU bytes"
        records = [{"filename": "target.msu", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}]
        (updates / "target.msu").write_bytes(b"x" * len(data))
        payload = self.root / "payload.zip"
        payload.write_bytes(b"payload")
        with mock.patch.object(vm, "UPDATE_PACKAGES", records), self.assertRaisesRegex(RuntimeError, "changed before seed"):
            vm.GuestServer(payload, self.root, updates=updates)

    def test_base_build_without_update_revision_cannot_pass_updated_vm_acceptance(self):
        result = self.passed_result()
        with self.assertRaises(RuntimeError):
            vm.verify_result(result, require_official_update=True)
        result["official_update"] = {"status": "completed", "completed": True, "packages_verified": True,
                                     "task_unregistered": True,
                                     "actual_build": vm.UPDATE_BUILD, "actual_ubr": vm.UPDATE_UBR - 1}
        with self.assertRaises(RuntimeError):
            vm.verify_result(result, require_official_update=True)
        result["official_update"]["actual_ubr"] = vm.UPDATE_UBR
        vm.verify_result(result, require_official_update=True)
        result["official_update"]["packages_verified"] = False
        with self.assertRaises(RuntimeError):
            vm.verify_result(result, require_official_update=True)

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

    def test_payload_contains_public_source_fixture_and_preserves_release_code_origin(self):
        package = self.root / "release.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("RuleProxy-Web/ruleproxy/__init__.py", "release-only product code")
        payload = self.root / "payload.zip"
        self.assertEqual(vm.make_payload(package, payload), vm.digest(payload))
        with zipfile.ZipFile(payload) as archive:
            names = set(archive.namelist())
            self.assertEqual(archive.read("package.zip"), package.read_bytes())
            self.assertEqual(archive.read("examples/ruleproxy.example.yaml"),
                             (ROOT / "examples/ruleproxy.example.yaml").read_bytes())
            self.assertTrue({"tests/test_manager_server.py", "scripts/windows-acceptance.py",
                             ".github/run_tests.py", ".github/windows_vm_test.py",
                             ".github/windows_browser_check.py", ".github/build_windows_package.py",
                             ".github/windows-vm-run.ps1", ".github/windows-vm-setup.ps1",
                             ".github/windows-vm-unattend.xml"} <= names)
            self.assertEqual({name for name in names if name.endswith((".yaml", ".yml"))},
                             {"examples/ruleproxy.example.yaml"})
            self.assertFalse(any(name.startswith(("ruleproxy/", "vendor/", "RuleProxy-Web/")) for name in names))
            self.assertNotIn("Run-RuleProxy.py", names)

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
            if name == "experiments":
                control[name] = {}
            control[name].update(changes)
        workspace.mkdir()
        (workspace / "fixture-control.json").write_text(json.dumps(control), encoding="utf-8")
        script = '''import json, sys, time
from pathlib import Path
workspace = Path(__file__).resolve().parent.parent
if Path(__file__).name == 'run_tests.py':
    name = 'package_tests'
elif Path(__file__).name == 'windows_network_experiment.py':
    name = 'experiments'
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
        if "experiments" in (overrides or {}):
            (workspace / ".github/windows_network_experiment.py").write_text(script, encoding="utf-8")
        return workspace

    def experiment_report(self):
        return {"status": "experiment_only", "full_acceptance_passed": False,
                "acceptance_passed": False, "real_node_passed": False,
                "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                         "python_pe_machine": 0x8664},
                "cleanup_proven": True,
                "variants": [{"name": "deny_all", "status": "transport_unavailable", "process_started": True,
                              "descendant_cleanup_proven": True, "resources_closed": True}],
                "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}]}

    def test_collected_experiment_cannot_replace_failed_required_product_phase(self):
        workspace = self.guest_control_workspace({
            "experiments": {"report": self.experiment_report()},
            "transport": {"exit_code": 1, "report": {"status": "failed", "acceptance_passed": False,
                                                        "real_node_passed": False}}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual(result["experiments_phase"]["status"], "passed")
        self.assertEqual(result["reports"]["experiments"], self.experiment_report())
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["experiments", *vm.PHASE_NAMES])
        self.assertEqual(result["status"], "failed")
        with self.assertRaises(RuntimeError):
            vm.verify_result(dict(result, ordinary_user=True))

    def test_unproven_experiment_cleanup_blocks_contained_product_fixtures(self):
        report = self.experiment_report()
        report["cleanup_error"] = "UnverifiedGuardTeardown"
        report["recovery_directory"] = str(self.root / "retained")
        workspace = self.guest_control_workspace({"experiments": {"report": report, "exit_code": 1}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(),
                         ["experiments", "probe", "package_tests"])
        self.assertEqual(result["recovery_records"][0]["phase"], "experiments")
        self.assertEqual(result["recovery_records"][0]["recovery_directory"], report["recovery_directory"])
        self.assertTrue(all(result["phases"][i]["status"] == "blocked" for i in (1, 2, 3)))
        self.assertEqual(result["phases"][4]["status"], "passed")

    def test_nested_or_missing_variant_cleanup_cannot_pass_collection(self):
        cases = []
        report = self.experiment_report()
        report["variants"][0]["actor"] = {"cleanup_error": "Unproven"}
        cases.append(report)
        report = self.experiment_report()
        report["variants"][0]["actor"] = {"ipc": {"cleanup_proven": False, "cleanup_errors": []}}
        cases.append(report)
        report = self.experiment_report()
        report["variants"][0]["actor"] = {"ipc": {"cleanup_proven": True, "cleanup_errors": [{"operation": "CloseHandle"}]}}
        cases.append(report)
        report = self.experiment_report()
        report["variants"][0]["descendant_cleanup_proven"] = False
        cases.append(report)
        report = self.experiment_report()
        del report["variants"][0]["process_started"]
        cases.append(report)
        report = self.experiment_report()
        del report["cleanup_proven"]
        cases.append(report)
        report = self.experiment_report()
        report["variants"] = [{"name": "unsupported", "process_started": False}]
        cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(RuntimeError):
                vm.verify_phase_report("experiments", report)
        report = self.experiment_report()
        report["variants"] = [{"name": "unsupported", "process_started": False, "no_process_started": True}]
        vm.verify_phase_report("experiments", report)

    def test_host_verification_cannot_ignore_failed_experiment_or_recovery(self):
        result = self.passed_result()
        result["experiments_phase"] = {"status": "failed", "exit_code": 1}
        result["reports"]["experiments"] = self.experiment_report()
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)
        result["experiments_phase"] = {"status": "passed", "exit_code": 0}
        vm.verify_result(result)
        result["recovery_records"] = [{"phase": "experiments", "descendant_cleanup_proven": False}]
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

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


class WindowsWireCaptureTests(unittest.TestCase):
    """Actual private HTTP requests and constructed PCAPs; no PSEC claim."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "qemu.log"
        self.log.write_bytes(b"")
        self.qmp = mock.Mock()
        self.controller = vm.WireCaptureController(self.qmp, self.root, self.root, self.log)
        if os.name != "posix":
            # Windows source tests exercise the real format parser. Private
            # POSIX file ownership is separately required on the Linux host.
            self.controller.packet.analyze_capture = lambda path, value: self.controller.packet.analyze_bytes(path.read_bytes(), value)
        probes = []
        for variant in vm.WIRE_VARIANTS:
            for family in ("ipv4", "ipv6"):
                for role in self.controller.packet.ROLES:
                    group = variant + "." + family
                    probes.append({"id": group + "." + role, "group": group, "role": role,
                        "family": family, "protocol": "udp", "source_mac": vm.VM_NIC_MAC,
                        "source_ip": "10.0.2.15" if family == "ipv4" else "fec0::15",
                        "destination": "1.1.1.1" if family == "ipv4" else "2606:4700:4700::1111",
                        "port": 53, "payload_hex": ("fixed-marker-" + str(len(probes))).encode().hex()})
        self.manifest = {"schema_version": 1, "probes": probes}
        self.execution = [{"id": p["id"], "role": p["role"], "attempted": True, "bind_succeeded": True,
                           "api_accepted": True, "errno": None} for p in probes]

    def capture(self):
        packets = []
        for role in ("outside_before", "outside_after"):
            for p in self.manifest["probes"]:
                if p["role"] != role:
                    continue
                source = ipaddress.ip_address(p["source_ip"]).packed
                destination = ipaddress.ip_address(p["destination"]).packed
                marker = bytes.fromhex(p["payload_hex"])
                udp = struct.pack("!HHHH", 45123, 53, len(marker) + 8, 0) + marker
                if p["family"] == "ipv4":
                    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, len(udp) + 20, 1, 0, 64, 17, 0, source, destination)
                    ethertype = 0x0800
                else:
                    header = struct.pack("!IHBB16s16s", 6 << 28, len(udp), 17, 64, source, destination)
                    ethertype = 0x86dd
                packets.append(b"\0" * 6 + bytes.fromhex(vm.VM_NIC_MAC.replace(":", "")) + struct.pack("!H", ethertype) + header + udp)
        data = struct.pack("<IHHiiII", 0xa1b2c3d4, 2, 4, 0, 0, 65536, 1)
        for index, packet in enumerate(packets):
            data += struct.pack("<IIII", 1000 + index, 0, len(packet), len(packet)) + packet
        self.controller.pcap.write_bytes(data)

    def finish(self, execution=None):
        return self.controller.finish({"manifest": self.manifest,
            "execution": self.execution if execution is None else execution, "actor_execution_attested": True})

    def test_real_http_routes_allow_only_one_fixed_capture_and_return_sanitized_evidence(self):
        payload = self.root / "payload.zip"; payload.write_bytes(b"payload")
        server = vm.GuestServer(payload, self.root, capture=self.controller)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), worker.join(2)))
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def post(path, value):
            request = urllib.request.Request(base + path, data=json.dumps(value).encode(), headers={"Content-Type": "application/json"})
            return urllib.request.urlopen(request, timeout=3)

        unauthorized = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        unauthorized.putrequest("POST", "/wrong/capture/start")
        unauthorized.putheader("Content-Length", "2")
        unauthorized.endheaders()
        self.assertEqual(unauthorized.getresponse().status, 404)
        unauthorized.close()
        route = "/" + server.capability + "/capture/"
        with self.assertRaises(urllib.error.HTTPError) as error:
            post(route + "start", {"file": "/unowned", "netdev": "other"})
        self.assertEqual(error.exception.code, 409)
        self.qmp.execute.assert_not_called()
        with post(route + "start", {}) as response:
            self.assertEqual(json.load(response), {"schema_version": 1, "source_mac": vm.VM_NIC_MAC})
        if os.name == "posix":
            self.assertEqual(self.controller.pcap.stat().st_mode & 0o777, 0o600)
        self.qmp.execute.assert_called_once_with("object-add", {"qom-type": "filter-dump", "id": "ruleproxy_wire",
            "netdev": "vmnet", "file": str(self.controller.pcap)})
        with self.assertRaises(urllib.error.HTTPError) as error:
            post(route + "start", {})
        self.assertEqual(error.exception.code, 409)
        self.capture()
        with post(route + "finish", {"manifest": self.manifest, "execution": self.execution, "actor_execution_attested": True}) as response:
            result = json.load(response)
        self.assertTrue(result["absence_observed"])
        self.assertTrue(result["execution_proven"])
        self.assertFalse(result["kernel_denial_proven"])
        self.assertFalse(result["acceptance_passed"])
        serialized = json.dumps(result)
        for private in (server.capability, str(self.root), "1.1.1.1", self.manifest["probes"][0]["payload_hex"]):
            self.assertNotIn(private, serialized)
        self.assertFalse(self.controller.active)
        self.qmp.execute.assert_called_with("object-del", {"id": "ruleproxy_wire"})
        with self.assertRaises(urllib.error.HTTPError) as error:
            post(route + "finish", {})
        self.assertEqual(error.exception.code, 409)

    def test_unsupported_group_stays_unknown_without_discarding_executed_model1_groups(self):
        self.controller.start({}); self.capture()
        partial = [row for row in self.execution if not (row["id"].startswith("model2_host.") and row["role"] in ("parent", "child"))]
        result = self.finish(partial)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result["absence_observed"])
        groups = {g["id"]: g for g in result["groups"]}
        for family in ("ipv4", "ipv6"):
            self.assertTrue(groups["model1_internal_ingress_deny." + family]["absence_observed"])
            self.assertFalse(groups["model2_host." + family]["execution_proven"])
            self.assertIsNone(groups["model2_host." + family]["contained_markers_absent"])
        self.assertEqual(len(result["counts"]), 32)

    def test_missing_bind_or_attestation_cannot_turn_zero_markers_into_absence(self):
        self.controller.start({}); self.capture()
        self.execution[1]["bind_succeeded"] = False
        result = self.finish()
        self.assertFalse(result["absence_observed"])
        self.assertFalse(result["groups"][0]["absence_observed"])
        self.assertTrue(result["groups"][1]["absence_observed"])

    def test_unattested_sender_claims_never_prove_any_group_absence(self):
        self.controller.start({}); self.capture()
        result = self.controller.finish({"manifest": self.manifest, "execution": self.execution,
                                         "actor_execution_attested": False})
        self.assertFalse(result["execution_proven"])
        self.assertTrue(all(not group["absence_observed"] and group["contained_markers_absent"] is None
                            for group in result["groups"]))

    def test_malformed_manifest_flushes_and_missing_finish_is_closed_by_owned_filter_only(self):
        self.controller.start({})
        result = self.controller.finish({"manifest": {"schema_version": 1, "probes": []}})
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(result["capture_flushed"])
        self.assertFalse(self.controller.active)
        self.assertEqual([call.args[0] for call in self.qmp.execute.call_args_list], ["object-add", "object-del"])
        with self.assertRaises(RuntimeError):
            self.controller.start({})

    def test_oversized_finish_body_flushes_active_capture(self):
        payload = self.root / "payload.zip"; payload.write_bytes(b"payload")
        server = vm.GuestServer(payload, self.root, capture=self.controller)
        worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), worker.join(2)))
        self.controller.start({})
        connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
        connection.putrequest("POST", "/" + server.capability + "/capture/finish")
        connection.putheader("Content-Length", str(vm.MAX_CAPTURE_REQUEST_BYTES + 1))
        connection.endheaders()  # Rejection must precede reading an upload.
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        response.read()
        connection.close()
        self.assertFalse(self.controller.active)
        self.assertFalse(self.controller.result["absence_observed"])

    def test_missing_finish_closes_only_the_owned_filter_once(self):
        self.controller.start({}); self.capture()
        self.controller.close()
        self.controller.close()
        self.assertFalse(self.controller.active)
        self.assertFalse(self.controller.result["absence_observed"])
        self.assertEqual([call.args[0] for call in self.qmp.execute.call_args_list], ["object-add", "object-del"])

    def test_late_dump_write_failure_invalidates_saved_evidence(self):
        self.controller.start({}); self.capture()
        self.assertTrue(self.finish()["absence_observed"])
        self.log.write_text("qemu: filter-dump: error writing packet dump\n")
        self.controller.close()
        self.assertTrue(self.controller.collection_error)
        self.assertFalse(self.controller.result["absence_observed"])
        self.assertEqual(json.loads((self.root / "windows-wire-evidence.json").read_text())["status"], "incomplete")

    def test_flush_error_retains_active_state_for_final_cleanup_and_never_claims_absence(self):
        self.controller.start({}); self.capture()
        self.qmp.execute.side_effect = RuntimeError("private path MUST_NOT_EXPORT")
        result = self.finish()
        self.assertFalse(result["capture_flushed"])
        self.assertTrue(self.controller.active)
        self.assertNotIn("MUST_NOT_EXPORT", json.dumps(result))
        self.qmp.execute.side_effect = None
        self.controller.close()
        self.assertFalse(self.controller.active)
        self.assertTrue(self.controller.collection_error)

    def test_qmp_parallel_commands_cannot_consume_each_others_response(self):
        connection = object.__new__(vm.Qmp)
        connection.lock = threading.RLock()

        class File:
            request = None
            def write(self, data):
                self.request = json.loads(data)["execute"]
                time.sleep(0.015)
            def flush(self):
                pass
            def readline(self):
                return json.dumps({"return": self.request}).encode()

        connection.file = File()
        answers = {}
        workers = [threading.Thread(target=lambda name=name: answers.update({name: connection.execute(name)}))
                   for name in ("capture", "screenshot")]
        for worker in workers: worker.start()
        for worker in workers: worker.join(2)
        self.assertEqual(answers, {"capture": "capture", "screenshot": "screenshot"})

    def test_private_vm_configuration_is_passed_only_to_network_experiment(self):
        workspace = self.root / "workspace"
        (workspace / ".github").mkdir(parents=True)
        (workspace / ".github/windows_network_experiment.py").write_text("# fixture")
        config = self.root / "private-config.json"
        calls = []

        def phase(name, command, *args, **kwargs):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, None, ""

        with mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            vm.run_guest_phases(self.root, workspace, self.root / "reports", vm_config=config)
        self.assertEqual(calls[0][1][-2:], ["--vm-config", str(config)])
        self.assertTrue(all("--vm-config" not in command for _, command in calls[1:]))


if __name__ == "__main__":
    unittest.main()
