"""Host-side VM controls cannot turn a skipped fixture into Windows acceptance."""
import importlib.util
import copy
import hashlib
import ipaddress
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import struct
import time
import unittest
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from types import SimpleNamespace
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
                            "cleanup_proven": True, "owned_workload_cleanup_proven": True,
                            "resources_closed": True,
                            "fixture_workers_closed": True, "private_profile_removed": True,
                            "host_network_unchanged": True,
                            "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                                     "python_pe_machine": 0x8664}, "checks": [
                                {"check": name, "status": "passed", "dom_nonce_via_page_ack": True,
                                 "cookie_request_verified": True, "natural_headless_exit": True,
                                 "wrapper_exit_observed": True, "wrapper_exit_code": 0,
                                 "owned_workload_cleanup_proven": True, "resources_closed": True,
                                 "private_profile_reused": True}
                                for name in ("real_edge_launch_1", "real_edge_launch_2")
                            ] + [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}]},
                "gui": {"status": "gui_fixture_only", "gui_fixture_passed": True, "cleanup_proven": True,
                        "acceptance_passed": False, "real_node_passed": False,
                        "full_acceptance_passed": False, "public_udp_proven": False, "system_dns_proven": False,
                        "interactive": {"ordinary_interactive": True},
                        "browser": {"headless": False, "sandbox_weakened": False},
                        "host": {"acceptance_scope": "native_x64", "native_machine": 0x8664,
                                 "python_pe_machine": 0x8664}, "checks": [
                            {"check": name, "status": "passed", "visible_window_verified": True,
                             "visible_window_rects": [[20, 20, 820, 620]], "dom_nonce_via_page_ack": True,
                             "cookie_request_verified": True, "wm_close_requested": True,
                             "natural_helper_wrapper_exit": True, "held_handles_verified": True,
                             "descendant_cleanup_proven": True, "resources_closed": True,
                             "private_profile_reused": True}
                            for name in ("real_edge_gui_1", "real_edge_gui_2")
                        ] + [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}]},
            }, "logs": {"tests": "Ran the release tests; environment-specific skips remain explicit."},
        }

    def test_complete_native_transport_report_is_accepted_without_claiming_real_nodes(self):
        vm.verify_result(self.passed_result())

    def test_browser_cleanup_predicate_requires_all_explicit_facts_even_for_failed_headless_result(self):
        report = copy.deepcopy(self.passed_result()["reports"]["browser"])
        report.update(status="failed", browser_fixture_passed=False)
        self.assertTrue(vm.browser_teardown_proven(report))
        for key in ("cleanup_proven", "owned_workload_cleanup_proven", "resources_closed", "fixture_workers_closed",
                    "private_profile_removed", "host_network_unchanged"):
            bad = copy.deepcopy(report)
            bad[key] = False
            with self.subTest(key=key):
                self.assertFalse(vm.browser_teardown_proven(bad))
            missing = copy.deepcopy(report)
            del missing[key]
            with self.subTest(missing=key):
                self.assertFalse(vm.browser_teardown_proven(missing))
        bad = copy.deepcopy(report)
        bad["checks"][-1]["status"] = "failed"
        self.assertFalse(vm.browser_teardown_proven(bad))
        for status in ("passed", "failed"):
            duplicate = copy.deepcopy(report)
            duplicate["checks"].append({"check": "host_proxy_dns_default_routes_unchanged", "status": status})
            with self.subTest(duplicate_snapshot=status):
                self.assertFalse(vm.browser_teardown_proven(duplicate))

    def test_browser_missing_cleanup_facts_block_gui_after_preserving_report(self):
        report = copy.deepcopy(self.passed_result()["reports"]["browser"])
        report["fixture_workers_closed"] = False
        workspace = self.guest_control_workspace({"browser": {"report": report}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(),
                         ["probe", "transport", "manager", "browser", "package_tests"])
        self.assertEqual(result["reports"]["browser"], report)
        self.assertEqual(result["recovery_records"][0]["phase"], "browser")
        self.assertEqual(next(item for item in result["phases"] if item["name"] == "gui")["status"], "blocked")
        self.assertEqual(result["status"], "failed")

    def test_gui_verifier_selects_chromium_names_only_for_explicit_source_control_report(self):
        result = self.passed_result()
        report = result["reports"]["gui"]
        report.update(chromium_gui_control_diagnostic=True, source_diagnostic_only=True,
                      product_browser_replaced=False)
        report["browser"]["application"] = "chrome_for_testing_control"
        for check in report["checks"][:2]:
            check["check"] = check["check"].replace("real_edge_gui", "real_chromium_control_gui")
        vm.verify_result(result)

        # Chrome-labelled checks cannot satisfy an Edge/default report.
        del report["chromium_gui_control_diagnostic"]
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

    def test_chrome_control_marker_cannot_pass_with_edge_check_names(self):
        result = self.passed_result()
        report = result["reports"]["gui"]
        report.update(chromium_gui_control_diagnostic=True, source_diagnostic_only=True,
                      product_browser_replaced=False)
        report["browser"]["application"] = "chrome_for_testing_control"
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

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
                                     "actual_build": 26300, "actual_ubr": vm.UPDATE_UBR}
        with self.assertRaisesRegex(RuntimeError, "pinned official cumulative update"):
            vm.verify_result(result, require_official_update=True)
        result["official_update"]["actual_build"] = vm.UPDATE_BUILD
        result["official_update"]["actual_ubr"] = vm.UPDATE_UBR - 1
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
                             ".github/windows_chromium_control.py",
                             ".github/windows-vm-run.ps1", ".github/windows-vm-setup.ps1",
                             ".github/workflows/check.yml",
                             ".github/windows-vm-unattend.xml"} <= names)
            self.assertEqual(archive.read(".github/workflows/check.yml"),
                             (ROOT / ".github/workflows/check.yml").read_bytes())
            self.assertEqual({name for name in names if name.endswith((".yaml", ".yml"))},
                             {"examples/ruleproxy.example.yaml", ".github/workflows/check.yml"})
            self.assertEqual({name for name in names if name.startswith("ruleproxy/")},
                             {"ruleproxy/windows_runtime_pins.py"})
            self.assertNotIn("ruleproxy/__init__.py", names)
            self.assertFalse(any(name.startswith(("vendor/", "RuleProxy-Web/")) for name in names))
            self.assertNotIn("Run-RuleProxy.py", names)

    def test_payload_acceptance_host_pins_load_in_fresh_isolated_process(self):
        package = self.root / "release.zip"
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("RuleProxy-Web/ruleproxy/__init__.py", "release-only product code")
        payload = self.root / "payload.zip"
        vm.make_payload(package, payload)
        extracted = self.root / "extracted"
        extracted.mkdir()
        with zipfile.ZipFile(payload) as archive:
            names = set(archive.namelist())
            self.assertIn("ruleproxy/windows_runtime_pins.py", names)
            self.assertNotIn("ruleproxy/__init__.py", names)
            self.assertEqual({name for name in names if name.startswith("ruleproxy/")},
                             {"ruleproxy/windows_runtime_pins.py"})
            archive.extractall(extracted)
        code = (
            "import importlib.util,json,sys; "
            "p=sys.argv[1]; s=importlib.util.spec_from_file_location('acceptance',p); "
            "m=importlib.util.module_from_spec(s); s.loader.exec_module(m); "
            "m._initialize_runtime_pins(); "
            "print(json.dumps({'pins_loaded': bool(m.MXC_G_EXECUTOR_SHA256 and "
            "m.MXC_G_LICENSE_SHA256 and m.RUNTIME_VERSIONS), "
            "'isolated_stdlib_only': 'site' not in sys.modules, "
            "'product_package_not_imported': 'ruleproxy' not in sys.modules}))"
        )
        acceptance = extracted / "scripts/windows-acceptance.py"
        result = subprocess.run([sys.executable, "-I", "-S", "-c", code, str(acceptance)],
                                cwd=self.root, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout),
                         {"pins_loaded": True, "isolated_stdlib_only": True,
                          "product_package_not_imported": True})

    def test_payload_adds_pinned_chromium_control_outside_product_zip(self):
        package = self.root / "release.zip"
        package.write_bytes(b"product package bytes")
        control = self.root / "chromium-control.zip"
        control.write_bytes(b"pinned archive fixture")
        payload = self.root / "payload.zip"
        helper = SimpleNamespace(ARCHIVE_SHA256="a" * 64, _check_archive=mock.Mock(return_value="a" * 64))
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper):
            vm.make_payload(package, payload, chromium_control_archive=control)
        helper._check_archive.assert_called_once_with(control)
        with zipfile.ZipFile(payload) as archive:
            self.assertEqual(archive.read("package.zip"), package.read_bytes())
            self.assertEqual(archive.read(vm.CHROMIUM_CONTROL_ARCHIVE_MEMBER), control.read_bytes())
            self.assertEqual(archive.getinfo(vm.CHROMIUM_CONTROL_ARCHIVE_MEMBER).compress_type,
                             zipfile.ZIP_STORED)
            self.assertNotIn("chromium-control/chrome.exe", archive.namelist())

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
        result['outside_edge_phase'] = {'status': 'passed', 'exit_code': 0}
        result['reports']['outside_edge'] = self.outside_edge_report()
        result['logs']['outside_edge'] = 'Independent outside health control completed.'
        request = urllib.request.Request(base + "/" + server.capability + "/result",
                                         data=json.dumps(result).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)
        self.assertTrue(server.received.wait(2))
        vm.verify_result(server.result)
        self.assertEqual(json.loads((self.root / "windows-transport.json").read_text()), result["reports"]["transport"])
        self.assertEqual(json.loads((self.root / "windows-manager.json").read_text()), result["reports"]["manager"])
        self.assertEqual(json.loads((self.root / "windows-outside_edge.json").read_text()), result['reports']['outside_edge'])
        self.assertEqual((self.root / 'guest-outside_edge.log').read_text(), result['logs']['outside_edge'])
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
        self.assertFalse(result["baseline_diagnostic"])
        self.assertTrue(result["official_update"]["required"])
        self.assertEqual(json.loads((self.root / "windows-vm-summary.json").read_text()), result)

    def test_baseline_is_explicit_and_cannot_be_promoted_to_default_updated_success(self):
        arguments = ["--package", str(self.root / "release.zip"), "--package-sha256", "a" * 64,
                     "--artifacts", str(self.root)]
        baseline = {"status": "baseline_transport_and_package_tests_passed", "baseline_diagnostic": True,
                    "official_update": {"required": False}, "network_boundary_passed": True}
        updated = {"status": "transport_and_package_tests_passed", "baseline_diagnostic": False,
                   "official_update": {"required": True}, "network_boundary_passed": True}
        with mock.patch.object(vm, "run", return_value=baseline) as run:
            self.assertEqual(vm.main(arguments), 1)
            self.assertFalse(run.call_args.args[0].baseline_diagnostic)
            self.assertEqual(vm.main(arguments + ["--baseline-diagnostic"]), 0)
            self.assertTrue(run.call_args.args[0].baseline_diagnostic)
        with mock.patch.object(vm, "run", return_value=updated):
            self.assertEqual(vm.main(arguments), 0)
            self.assertEqual(vm.main(arguments + ["--baseline-diagnostic"]), 1)
        with mock.patch.object(vm, "run", return_value={**updated, "official_update": {}}):
            self.assertEqual(vm.main(arguments), 1)

    def test_only_explicit_baseline_skips_update_downloads_and_seed_requirement(self):
        for baseline in (False, True):
            with self.subTest(baseline=baseline):
                import hashlib
                package = self.root / "package.zip"
                with zipfile.ZipFile(package, "w") as archive:
                    for name in ("python/python.exe", "ruleproxy/windows_runtime.py",
                                 "bin/windows-amd64/wxc-exec.exe", "bin/windows-amd64/runtime.json"):
                        archive.writestr("RuleProxy-Web/" + name, b"public fixture")
                work = self.root / ("baseline-work" if baseline else "updated-work")
                work.mkdir()
                iso_data = b"public small ISO fixture, never booted"
                def subprocess_run(command, **_):
                    if command[0] == "curl":
                        Path(command[command.index("--output") + 1]).write_bytes(iso_data)
                server = mock.Mock(server_address=("127.0.0.1", 43210), capability="a" * 64)
                args = SimpleNamespace(artifacts=self.root, package=package,
                    package_sha256=vm.digest(package), timeout_seconds=300, baseline_diagnostic=baseline)
                with mock.patch.object(vm, "require_kvm", return_value=12), \
                        mock.patch.object(vm.shutil, "which", return_value="fixture-tool"), \
                        mock.patch.object(vm.shutil, "disk_usage", return_value=SimpleNamespace(free=100 * 1024**3)), \
                        mock.patch.object(vm.Path, "is_file", return_value=True), \
                        mock.patch.object(vm.tempfile, "TemporaryDirectory") as directory, \
                        mock.patch.object(vm, "ISO_BYTES", len(iso_data)), \
                        mock.patch.object(vm, "ISO_SHA256", hashlib.sha256(iso_data).hexdigest()), \
                        mock.patch.object(vm.subprocess, "run", side_effect=subprocess_run), \
                        mock.patch.object(vm, "download_updates", return_value=[]) as download, \
                        mock.patch.object(vm, "make_payload", return_value="b" * 64), \
                        mock.patch.object(vm, "GuestServer", return_value=server) as guest_server, \
                        mock.patch.object(vm, "validate_install_tree", return_value="efi/microsoft/boot/efisys_noprompt.bin"), \
                        mock.patch.object(vm, "prepare_seed", side_effect=RuntimeError("test stopped before rebuild/boot")) as seed, \
                        mock.patch("builtins.print"):
                    directory.return_value.__enter__.return_value = str(work)
                    result = vm.run(args)
                self.assertEqual(result["error"], "RuntimeError: test stopped before rebuild/boot")
                expected_updates = None if baseline else work / "official-updates"
                self.assertEqual(download.call_count, 0 if baseline else 1)
                self.assertEqual(guest_server.call_args.kwargs["updates"], expected_updates)
                self.assertEqual(seed.call_args.kwargs["updates"], expected_updates)
                self.assertIs(seed.call_args.args[2]["require_official_update"], not baseline)
                self.assertIs(result["baseline_diagnostic"], baseline)
                self.assertIs(result["official_update"]["required"], not baseline)
                self.assertEqual(result["status"], "failed")  # No VM execution simulated.
                self.assertFalse(result["full_acceptance_passed"])
                self.assertFalse(result["real_node_passed"])
                if baseline:
                    self.assertNotIn("packages", result["official_update"])

    def test_host_fetches_and_seeds_chromium_only_for_explicit_gui_control(self):
        package = self.root / "package.zip"
        with zipfile.ZipFile(package, "w") as archive:
            for name in ("python/python.exe", "ruleproxy/windows_runtime.py",
                         "bin/windows-amd64/wxc-exec.exe", "bin/windows-amd64/runtime.json"):
                archive.writestr("RuleProxy-Web/" + name, b"fixture")
        work = self.root / "chromium-work"
        work.mkdir()
        iso_data = b"public small ISO fixture, never booted"

        def subprocess_run(command, **_):
            if command[0] == "curl":
                Path(command[command.index("--output") + 1]).write_bytes(iso_data)

        def fetch_archive(path):
            path.write_bytes(b"pinned chromium archive")
            return "c" * 64

        helper = SimpleNamespace(ARCHIVE_SHA256="c" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 fetch_archive=mock.Mock(side_effect=fetch_archive))
        server = mock.Mock(server_address=("127.0.0.1", 43210), capability="a" * 64)
        args = SimpleNamespace(artifacts=self.root, package=package, package_sha256=vm.digest(package),
                               timeout_seconds=300, baseline_diagnostic=True, gui_diagnostic_only=True,
                               chromium_gui_control=True, standard_profile_layout_control=True)
        with mock.patch.object(vm, "require_kvm", return_value=12), \
                mock.patch.object(vm.shutil, "which", return_value="fixture-tool"), \
                mock.patch.object(vm.shutil, "disk_usage", return_value=SimpleNamespace(free=100 * 1024**3)), \
                mock.patch.object(vm.Path, "is_file", return_value=True), \
                mock.patch.object(vm.tempfile, "TemporaryDirectory") as directory, \
                mock.patch.object(vm, "ISO_BYTES", len(iso_data)), \
                mock.patch.object(vm, "ISO_SHA256", hashlib.sha256(iso_data).hexdigest()), \
                mock.patch.object(vm.subprocess, "run", side_effect=subprocess_run), \
                mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "make_payload", return_value="b" * 64) as make_payload, \
                mock.patch.object(vm, "GuestServer", return_value=server), \
                mock.patch.object(vm, "validate_install_tree", return_value="efi/microsoft/boot/efisys_noprompt.bin"), \
                mock.patch.object(vm, "prepare_seed", side_effect=RuntimeError("stop before boot")) as seed, \
                mock.patch("builtins.print"):
            directory.return_value.__enter__.return_value = str(work)
            result = vm.run(args)
        self.assertEqual(result["error"], "RuntimeError: stop before boot")
        helper.fetch_archive.assert_called_once_with(work / vm.CHROMIUM_CONTROL_ARCHIVE_MEMBER)
        make_payload.assert_called_once_with(package.resolve(strict=True), work / "payload.zip", test_executor_bundle=None,
                                             chromium_control_archive=work / vm.CHROMIUM_CONTROL_ARCHIVE_MEMBER)
        config = seed.call_args.args[2]
        self.assertTrue(config["gui_diagnostic_only"])
        self.assertTrue(config["chromium_gui_control_diagnostic"])
        self.assertTrue(config["standard_profile_layout_control"])
        self.assertEqual(config["chromium_gui_control_archive_sha256"], "c" * 64)
        self.assertEqual(result["chromium_gui_control"]["archive_sha256"], "c" * 64)
        self.assertFalse(result["full_acceptance_passed"])

    def test_remastered_layout_keeps_only_actual_fixed_boot_wim_extent_facts(self):
        iso = self.root / "remastered.iso"
        iso.write_bytes(b"public media fixture")
        output = (b"File data lba:  0 , 123 , 64 , 131072 , '/sources/boot.wim'\n"
                  b"File data lba:  0 , 999 , 1 , 40 , '/autounattend.xml'\n"
                  b"Drive current: private-work/password-token\n")
        with mock.patch.object(vm.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=output)) as call:
            result = vm.installer_layout(iso)
        self.assertEqual(result["bytes"], iso.stat().st_size)
        self.assertEqual(result["boot_wim_layout_status"], "reported")
        self.assertEqual(result["boot_wim_extents"], [{"extent_index": 0, "lba": 123, "blocks": 64,
            "file_bytes": 131072, "byte_offset": 123 * 2048}])
        self.assertNotIn("password-token", json.dumps(result))
        self.assertNotIn("autounattend", json.dumps(result))
        self.assertEqual(call.call_args.args[0][-5:], ["-find", "/sources/boot.wim", "-exec", "report_lba", "--"])
        self.assertNotIn("sort", " ".join(call.call_args.args[0]))
        self.assertEqual(call.call_args.kwargs["timeout"], 30)

    def test_missing_layout_output_never_fabricates_an_extent_or_blocks_boot(self):
        iso = self.root / "remastered.iso"
        iso.write_bytes(b"public media fixture")
        for response in (SimpleNamespace(returncode=1, stdout=b""), SimpleNamespace(returncode=0, stdout=b"changed-format")):
            with self.subTest(response=response), mock.patch.object(vm.subprocess, "run", return_value=response):
                result = vm.installer_layout(iso)
            self.assertEqual(result["boot_wim_layout_status"], "unavailable")
            self.assertEqual(result["boot_wim_extents"], [])
            self.assertEqual(result["bytes"], iso.stat().st_size)

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
            if name in ("experiments", "outside_edge", "edge_ui"):
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
elif Path(__file__).name == 'windows_edge_outside_control.py':
    name = 'outside_edge'
elif Path(__file__).name == 'windows_edge_policy_experiment.py':
    name = 'edge_ui'
elif Path(__file__).name == 'windows_browser_check.py':
    name = 'browser'
elif Path(__file__).name == 'windows_gui_check.py':
    name = 'gui'
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
        for relative in ("scripts/windows-acceptance.py", ".github/windows_browser_check.py",
                         ".github/windows_gui_check.py", ".github/run_tests.py"):
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(script, encoding="utf-8")
        if "experiments" in (overrides or {}):
            (workspace / ".github/windows_network_experiment.py").write_text(script, encoding="utf-8")
        if "outside_edge" in (overrides or {}):
            (workspace / ".github/windows_edge_outside_control.py").write_text(script, encoding="utf-8")
        if "edge_ui" in (overrides or {}):
            (workspace / ".github/windows_edge_policy_experiment.py").write_text(script, encoding="utf-8")
        return workspace

    def outside_edge_report(self):
        return {'schema_version': 1, 'status': 'outside_control_only', 'scope': vm.OUTSIDE_EDGE_SCOPE,
            'outside_psec': True, 'outside_headless_control_passed': True, 'cleanup_proven': True,
            'ordinary_user': True, 'host_network_unchanged': True,
            'host': copy.deepcopy(self.passed_result()['reports']['probe']['host']),
            **{key: False for key in vm.OUTSIDE_EDGE_FALSE_FLAGS},
            'checks': [{'phase': phase, 'edge_exit_code': 0, 'edge_exit_hex': '0x00000000',
                'command_template_sha256': hashlib.sha256(str(phase).encode()).hexdigest(),
                'assigned_before_resume': True, 'natural_root_and_job_exit': True,
                'dom_nonce_via_page_ack': True, 'cookie_request_verified': True,
                'private_profile_reused': phase == 2, 'owned_job_cleanup_proven': True} for phase in (1, 2)]}

    def test_outside_edge_runs_before_capture_source_and_cannot_replace_product_browser(self):
        workspace = self.guest_control_workspace({'outside_edge': {'report': self.outside_edge_report()},
                                                 'experiments': {'report': self.experiment_report()}})
        result = vm.run_guest_phases(self.root / 'release', workspace, self.root / 'reports')
        self.assertEqual((workspace / 'executed.txt').read_text().splitlines(),
                         ['outside_edge', 'experiments', *vm.PHASE_NAMES])
        self.assertEqual([phase['name'] for phase in result['phases']], list(vm.PHASE_NAMES))
        self.assertEqual(result['outside_edge_phase']['status'], 'passed')
        self.assertIn('outside_edge child interpreter ran', result['logs']['outside_edge'])
        vm.verify_result(dict(result, ordinary_user=True))
        result['reports']['browser']['browser_fixture_passed'] = False
        with self.assertRaises(RuntimeError):
            vm.verify_result(dict(result, ordinary_user=True))

    def test_failed_outside_health_with_proven_teardown_collects_later_fixtures_but_stays_failed(self):
        report = self.outside_edge_report()
        report.update(status='failed', outside_headless_control_passed=False, checks=[], host_network_unchanged=None)
        workspace = self.guest_control_workspace({'outside_edge': {'report': report, 'exit_code': 1},
                                                 'experiments': {'report': self.experiment_report()}})
        result = vm.run_guest_phases(self.root / 'release', workspace, self.root / 'reports')
        self.assertEqual((workspace / 'executed.txt').read_text().splitlines(),
                         ['outside_edge', 'experiments', *vm.PHASE_NAMES])
        self.assertEqual(result['outside_edge_phase']['status'], 'failed')
        self.assertEqual(result['recovery_records'], [])
        self.assertEqual(result['reports']['outside_edge'], report)
        self.assertEqual(result['status'], 'failed')

    def test_unproven_outside_cleanup_blocks_every_later_process_except_package_units(self):
        report = self.outside_edge_report()
        report.update(status='failed', outside_headless_control_passed=False, cleanup_proven=False,
                      recovery_retained=True)
        workspace = self.guest_control_workspace({'outside_edge': {'report': report, 'exit_code': 1},
            'experiments': {'report': self.experiment_report()}, 'edge_ui': {}})
        result = vm.run_guest_phases(self.root / 'release', workspace, self.root / 'reports')
        self.assertEqual((workspace / 'executed.txt').read_text().splitlines(), ['outside_edge', 'package_tests'])
        self.assertEqual(result['recovery_records'][0]['phase'], 'outside_edge')
        self.assertFalse(result['recovery_records'][0]['descendant_cleanup_proven'])
        self.assertTrue(all(phase['status'] == 'blocked' for phase in result['phases'][:-1]))
        self.assertEqual(result['phases'][-1]['status'], 'passed')

    def test_outside_control_success_requires_live_two_launch_cookie_and_job_evidence(self):
        vm.verify_phase_report('outside_edge', self.outside_edge_report())
        cases = []
        for key, value in (('schema_version', True), ('scope', 'product'), ('outside_psec', False),
                           ('host_network_unchanged', None), ('ordinary_user', False), ('cleanup_proven', False),
                           ('outside_headless_control_passed', False), ('recovery_retained', True)):
            report = self.outside_edge_report(); report[key] = value; cases.append(report)
        for key in vm.OUTSIDE_EDGE_FALSE_FLAGS:
            report = self.outside_edge_report(); report[key] = True; cases.append(report)
            report = self.outside_edge_report(); del report[key]; cases.append(report)
        for key, value in (('phase', 1), ('edge_exit_code', False), ('edge_exit_hex', '0x00000001'),
                           ('private_profile_reused', False), ('command_template_sha256', 'not-a-hash'),
                           ('natural_root_and_job_exit', False), ('owned_job_cleanup_proven', False),
                           ('cookie_request_verified', False), ('assigned_before_resume', False)):
            report = self.outside_edge_report(); report['checks'][1][key] = value; cases.append(report)
        report = self.outside_edge_report(); report['checks'].pop(); cases.append(report)
        for report in cases:
            with self.subTest(report=report), self.assertRaises(RuntimeError):
                vm.verify_phase_report('outside_edge', report)

    def test_outside_record_and_report_are_both_required_without_promoting_old_payloads(self):
        vm.verify_result(self.passed_result())  # A previous payload has no outside helper or report.
        result = self.passed_result()
        result['outside_edge_phase'] = {'status': 'passed', 'exit_code': 0}
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)
        result['reports']['outside_edge'] = self.outside_edge_report()
        vm.verify_result(result)
        del result['outside_edge_phase']
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

    def test_outside_timeout_or_missing_report_cannot_use_reported_cleanup_to_start_psec(self):
        workspace = self.root / 'workspace'
        (workspace / '.github').mkdir(parents=True)
        (workspace / '.github/windows_edge_outside_control.py').write_text('# control')
        (workspace / '.github/windows_network_experiment.py').write_text('# no new PSEC')
        for timed_out, report in ((True, self.outside_edge_report()), (False, None)):
            calls = []
            def phase(name, command, *_, **options):
                calls.append((name, command, options))
                return {'name': name, 'status': 'failed', 'exit_code': 1, 'timed_out': timed_out}, report, ''
            with self.subTest(timed_out=timed_out), mock.patch.object(vm, 'run_guest_phase', side_effect=phase):
                result = vm.run_guest_phases(self.root, workspace, self.root / ('timeout' if timed_out else 'missing'))
            self.assertEqual([name for name, _, _ in calls], ['outside_edge', 'package_tests'])
            self.assertEqual(calls[0][1][-2:], ['--timeout', '45'])
            self.assertEqual(calls[0][2]['timeout'], 420)
            self.assertEqual(result['status'], 'failed')

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
                         ["experiments", "package_tests"])
        self.assertEqual(result["recovery_records"][0]["phase"], "experiments")
        self.assertEqual(result["recovery_records"][0]["recovery_directory"], report["recovery_directory"])
        self.assertTrue(all(phase["status"] == "blocked" for phase in result["phases"][:-1]))
        self.assertEqual(result["phases"][-1]["status"], "passed")

    def test_failed_clean_collection_allows_independent_fixtures_but_still_fails_acceptance(self):
        report = self.experiment_report()
        report["status"] = "failed"
        report["variants"][0]["status"] = "failed"
        report["variants"][0]["detail"] = "An actor report was incomplete"
        workspace = self.guest_control_workspace({"experiments": {"report": report, "exit_code": 1}})
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports")
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["experiments", *vm.PHASE_NAMES])
        self.assertEqual(result["experiments_phase"]["status"], "failed")
        self.assertEqual(result["reports"]["experiments"]["status"], "failed")
        self.assertEqual(result["recovery_records"], [])
        self.assertEqual(result["status"], "failed")
        with self.assertRaises(RuntimeError):
            vm.verify_result(dict(result, ordinary_user=True))

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
                         ["passed", "failed", "passed", "passed", "passed", "passed"])
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
                         ["failed", "blocked", "blocked", "blocked", "blocked", "passed"])
        self.assertEqual(result["status"], "failed")

    def test_gui_diagnostic_only_runs_strict_probe_then_packaged_gui_and_marks_every_omission(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True}), encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                     vm_config=config)
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe", "gui"])
        self.assertEqual([phase["name"] for phase in result["phases"]], list(vm.PHASE_NAMES))
        self.assertEqual([phase["status"] for phase in result["phases"]],
                         ["passed", "skipped", "skipped", "skipped", "passed", "skipped"])
        gui_command = next(line for line in result["logs"]["gui"].splitlines() if "child interpreter ran" in line)
        self.assertIn("gui child interpreter ran", gui_command)
        self.assertTrue(result["gui_diagnostic_only"])
        self.assertTrue(result["source_diagnostic_only"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_acceptance_passed"])
        self.assertTrue(result["reports"]["gui"]["gui_fixture_passed"])
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result(dict(result, status="passed", ordinary_user=True,
                                  phases=[{"name": name, "status": "passed", "exit_code": 0}
                                          for name in vm.PHASE_NAMES]))

    def test_gui_diagnostic_stages_pinned_chromium_and_passes_only_control_root(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-chromium-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
                                      "chromium_gui_control_diagnostic": True,
                                      "chromium_gui_control_archive_sha256": "d" * 64}), encoding="utf-8")
        staged_exe = self.root / "private-chrome" / "chrome-win64" / "chrome.exe"
        staged_exe.parent.mkdir(parents=True)
        staged_exe.write_bytes(b"pinned control executable")
        def extract(archive, destination):
            self.assertEqual(archive, workspace / vm.CHROMIUM_CONTROL_ARCHIVE_MEMBER)
            self.assertEqual(destination, self.root / "gui-reports" / "chromium-control")
            return staged_exe
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=extract)
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else {"gui_fixture_passed": True}, "child ran"
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                         vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "gui"])
        gui_command = calls[1][1]
        self.assertIn("--chromium-control-root", gui_command)
        self.assertEqual(gui_command[gui_command.index("--chromium-control-root") + 1],
                         str(self.root / "gui-reports" / "chromium-control"))
        self.assertEqual(result["chromium_gui_control"]["status"], "ready")
        self.assertEqual(result["chromium_gui_control"]["chrome_exe_sha256"], hashlib.sha256(
            b"pinned control executable").hexdigest())
        self.assertFalse(result["product_acceptance_passed"])

    def test_chromium_gui_control_uses_verified_source_executor_only_for_gui_command(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-chromium-source-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
            "chromium_gui_control_diagnostic": True, "chromium_gui_control_archive_sha256": "d" * 64,
            "test_psec_executor_diagnostic": True, "test_psec_executor_sha256": "e" * 64,
            "test_psec_original_runtime_sha256": "f" * 64}), encoding="utf-8")
        chrome_exe = self.root / "chrome.exe"
        chrome_exe.write_bytes(b"pinned Chrome for Testing fixture")
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=mock.Mock(return_value=chrome_exe))
        executor, manifest = workspace / "test-psec-executor/wxc-exec.exe", workspace / "test-psec-executor/build-manifest.json"
        metadata = {"executor_sha256": "e" * 64, "source_only_executor_changed": True,
                    "default_product_runtime_replaced": False, "acceptance_passed": False,
                    "real_node_passed": False, "kernel_denial_proven": False}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            report = {"status": "supported_only"} if name == "probe" else {"gui_fixture_passed": True}
            return {"name": name, "status": "passed", "exit_code": 0}, report, "child ran"
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "guest_test_executor", return_value=(executor, manifest, metadata)) as verify, \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                         vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "gui"])
        self.assertNotIn("--test-psec-executor", calls[0][1])
        self.assertIn("--test-psec-executor", calls[1][1])
        self.assertEqual(calls[1][1][calls[1][1].index("--test-psec-executor") + 1], str(executor))
        self.assertEqual(calls[1][1][calls[1][1].index("--test-psec-manifest") + 1], str(manifest))
        verify.assert_called_once_with(self.root / "release", workspace, config)
        self.assertEqual(result["execution_mode"], "source_executor_diagnostic")
        self.assertEqual(result["test_psec_executor"], metadata)
        self.assertFalse(result["product_runtime_replaced"])
        self.assertTrue(result["source_diagnostic_only"])
        self.assertFalse(result["product_acceptance_passed"])

    def test_g2_ingress_control_runs_only_source_gui_with_cft_and_cannot_accept(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-g2-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
            "chromium_gui_control_diagnostic": True, "chromium_gui_control_archive_sha256": "d" * 64,
            "test_psec_executor_diagnostic": True, "test_psec_executor_sha256": "e" * 64,
            "test_psec_original_runtime_sha256": "f" * 64, "ingress_controls_diagnostic": True}),
            encoding="utf-8")
        chrome_exe = self.root / "g2-chrome.exe"
        chrome_exe.write_bytes(b"fixed CfT fixture")
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=mock.Mock(return_value=chrome_exe))
        executor, manifest = workspace / "test-psec-executor/wxc-exec.exe", workspace / "test-psec-executor/build-manifest.json"
        metadata = {"executor_sha256": "e" * 64, "source_only_executor_changed": True,
                    "default_product_runtime_replaced": False, "acceptance_passed": False}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            report = {"status": "supported_only"} if name == "probe" else {"gui_fixture_passed": True}
            return {"name": name, "status": "passed", "exit_code": 0}, report, "child ran"
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "guest_test_executor", return_value=(executor, manifest, metadata)), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-g2-reports",
                                         vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "gui"])
        self.assertIn("--ingress-controls-diagnostic", calls[1][1])
        self.assertIn("--chromium-control-root", calls[1][1])
        self.assertIn("--test-psec-executor", calls[1][1])
        self.assertTrue(result["ingress_controls_diagnostic"])
        self.assertEqual(result["source_policy_variant"], "private_network_and_localappdata_control")
        self.assertTrue(result["source_diagnostic_only"])
        self.assertFalse(result["product_runtime_replaced"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_acceptance_passed"])
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result({**self.passed_result(), **result, "status": "passed", "ordinary_user": True})

    def test_chromium_source_executor_validation_failure_blocks_gui_launch(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-chromium-source-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
            "chromium_gui_control_diagnostic": True, "chromium_gui_control_archive_sha256": "d" * 64,
            "test_psec_executor_diagnostic": True}), encoding="utf-8")
        chrome_exe = self.root / "chrome.exe"
        chrome_exe.write_bytes(b"pinned Chrome for Testing fixture")
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=mock.Mock(return_value=chrome_exe))
        calls = []
        def phase(name, command, *_, **__):
            calls.append(name)
            return {"name": name, "status": "passed", "exit_code": 0}, {"status": "supported_only"}, ""
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "guest_test_executor", side_effect=ValueError("invalid source manifest")), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                         vm_config=config)
        self.assertEqual(calls, ["probe"])
        self.assertEqual(result["executor_validation_error"], "ValueError")
        self.assertEqual(result["phases"][4]["reason"], "executor_validation_failed")
        self.assertFalse(result["product_runtime_replaced"])
        self.assertFalse(result["product_acceptance_passed"])

    def test_gui_diagnostic_chromium_failure_blocks_before_gui_launch(self):
        workspace = self.guest_control_workspace()
        config = self.root / "gui-chromium-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
                                      "chromium_gui_control_diagnostic": True,
                                      "chromium_gui_control_archive_sha256": "d" * 64}), encoding="utf-8")
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=mock.Mock(side_effect=ValueError("invalid archive")))
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                         vm_config=config)
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe"])
        self.assertEqual(result["phases"][4]["status"], "blocked")
        self.assertEqual(result["phases"][4]["reason"], "pinned_chromium_control_unavailable")
        self.assertEqual(result["chromium_gui_control"]["error_type"], "ValueError")
        self.assertFalse(result["product_acceptance_passed"])

    def test_gui_diagnostic_only_probe_failure_blocks_gui_and_never_runs_package_tests(self):
        workspace = self.guest_control_workspace({"probe": {"exit_code": 3, "report": {
            "status": "unsupported", "probe": {"supported": False}, "acceptance_passed": False,
            "real_node_passed": False, "transport_passed": False}}})
        config = self.root / "gui-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True}), encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                     vm_config=config)
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe"])
        self.assertEqual(result["phases"][0]["status"], "failed")
        self.assertEqual(result["phases"][4]["status"], "blocked")
        self.assertEqual(result["phases"][5]["status"], "skipped")

    def test_gui_diagnostic_only_retains_unproven_gui_cleanup_and_component_report(self):
        report = copy.deepcopy(self.passed_result()["reports"]["gui"])
        report["cleanup_error"] = "OwnedWindowStillRunning"
        report["recovery_directory"] = str(self.root / "retained-gui-recovery")
        workspace = self.guest_control_workspace({"gui": {"report": report, "exit_code": 1}})
        config = self.root / "gui-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True}), encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "gui-reports",
                                     vm_config=config)
        self.assertEqual(result["reports"]["gui"], report)
        self.assertEqual(result["recovery_records"][0]["phase"], "gui")
        self.assertFalse(result["recovery_records"][0]["descendant_cleanup_proven"])
        self.assertEqual(result["recovery_records"][0]["cleanup_error"], "OwnedWindowStillRunning")
        self.assertEqual(result["phases"][4]["status"], "failed")
        self.assertEqual(result["phases"][5]["status"], "skipped")

    def test_gui_diagnostic_configuration_requires_a_real_boolean_and_rejects_partial_verify(self):
        config = self.root / "gui-vm-config.json"
        for value in (1, "true", None):
            config.write_text(json.dumps({"gui_diagnostic_only": value}), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(ValueError):
                vm.guest_gui_diagnostic_only(config)
        config.write_text(json.dumps({"gui_diagnostic_only": True,
                                      "test_psec_executor_diagnostic": True}), encoding="utf-8")
        with self.assertRaises(ValueError):
            vm.guest_gui_diagnostic_only(config)
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result(self.passed_result(), gui_diagnostic_only=True)

    def test_chromium_gui_control_config_requires_manual_gui_only_and_fixed_hash_shape(self):
        config = self.root / "gui-chromium-vm-config.json"
        valid = {"gui_diagnostic_only": True, "chromium_gui_control_diagnostic": True,
                 "chromium_gui_control_archive_sha256": "d" * 64}
        config.write_text(json.dumps(valid), encoding="utf-8")
        self.assertTrue(vm.guest_diagnostic_options(config)[3])
        invalid = [
            {"chromium_gui_control_diagnostic": True, "chromium_gui_control_archive_sha256": "d" * 64},
            {**valid, "chromium_gui_control_diagnostic": 1},
            {**valid, "network_diagnostic_only": True},
            {**valid, "chromium_gui_control_archive_sha256": "not-a-digest"},
            {"gui_diagnostic_only": True, "chromium_gui_control_archive_sha256": "d" * 64},
        ]
        for value in invalid:
            config.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(value=value), self.assertRaises(ValueError):
                vm.guest_diagnostic_options(config)
        config.write_text(json.dumps({**valid, "test_psec_executor_diagnostic": True}), encoding="utf-8")
        self.assertTrue(vm.guest_diagnostic_options(config)[0])

    def test_standard_profile_layout_control_requires_gui_cft_and_rejects_g2_or_network_axes(self):
        config = self.root / "standard-profile-vm-config.json"
        valid = {"gui_diagnostic_only": True, "chromium_gui_control_diagnostic": True,
                 "chromium_gui_control_archive_sha256": "d" * 64,
                 "standard_profile_layout_control": True}
        config.write_text(json.dumps(valid), encoding="utf-8")
        self.assertTrue(vm.guest_diagnostic_options(config)[7])
        for invalid in (
                {**valid, "standard_profile_layout_control": 1},
                {**valid, "standard_profile_layout_control": "true"},
                {**valid, "chromium_gui_control_diagnostic": False},
                {**valid, "ingress_controls_diagnostic": True,
                 "test_psec_executor_diagnostic": True},
                {**valid, "network_diagnostic_only": True},
                {**valid, "psec_1_1_diagnostic": True},
                {**valid, "singleton_port_range_diagnostic": True},
        ):
            config.write_text(json.dumps(invalid), encoding="utf-8")
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                vm.guest_diagnostic_options(config)

    def test_internal_tcp_policy_guest_mode_is_exact_enum_and_network_executor_only(self):
        config = self.root / "internal-tcp-policy-options.json"
        valid = {"network_diagnostic_only": True, "test_psec_executor_diagnostic": True,
                 "internal_tcp_policy_diagnostic": "singleton", "psec_1_1_diagnostic": True}
        config.write_text(json.dumps(valid), encoding="utf-8")
        self.assertEqual(vm.guest_diagnostic_options(config)[8], "singleton")
        for invalid in (
                {**valid, "internal_tcp_policy_diagnostic": True},
                {**valid, "internal_tcp_policy_diagnostic": "all"},
                {**valid, "network_diagnostic_only": False},
                {**valid, "test_psec_executor_diagnostic": False},
                {**valid, "gui_diagnostic_only": True},
                {**valid, "chromium_gui_control_diagnostic": True},
                {**valid, "singleton_port_range_diagnostic": True},
                {**valid, "ingress_controls_diagnostic": True},
        ):
            config.write_text(json.dumps(invalid), encoding="utf-8")
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                vm.guest_diagnostic_options(config)

    def test_standard_profile_layout_guest_gui_keeps_cft_but_adds_no_enum_axis(self):
        workspace = self.guest_control_workspace()
        config = self.root / "standard-profile-vm-config.json"
        config.write_text(json.dumps({"gui_diagnostic_only": True,
            "chromium_gui_control_diagnostic": True,
            "chromium_gui_control_archive_sha256": "d" * 64,
            "standard_profile_layout_control": True}), encoding="utf-8")
        chrome_exe = self.root / "standard-profile-chrome.exe"
        chrome_exe.write_bytes(b"pinned CfT fixture")
        helper = SimpleNamespace(ARCHIVE_SHA256="d" * 64, VERSION="154.0.8037.92", PLATFORM="win64",
                                 extract_archive=mock.Mock(return_value=chrome_exe))
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else {"gui_fixture_passed": True}, "child ran"
        with mock.patch.object(vm, "load_chromium_control_helper", return_value=helper), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace,
                                         self.root / "standard-profile-reports", vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "gui"])
        command = calls[1][1]
        self.assertIn("--chromium-control-root", command)
        self.assertIn("--standard-profile-layout-control", command)
        self.assertNotIn("--ingress-controls-diagnostic", command)
        self.assertTrue(result["standard_profile_layout_control"])
        self.assertEqual(result["source_policy_variant"],
                         "standard_profile_layout_without_extra_directory_grants")
        self.assertFalse(result["additional_directory_grants"])
        self.assertFalse(result["directory_query_list_permission_changed"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_acceptance_passed"])

    def test_network_diagnostic_only_runs_probe_then_preferred_experiment_and_never_accepts(self):
        workspace = self.guest_control_workspace({"experiments": {"report": {
            "cleanup_proven": True, "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
            "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                          "resources_closed": True}]}}})
        config = self.root / "network-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True}), encoding="utf-8")
        calls = []
        clean_report = {"cleanup_proven": True,
                        "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                        "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                                      "resources_closed": True}]}
        def phase(name, command, *_, **__):
            calls.append((name, command))
            report = {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean_report)
            return {"name": name, "status": "passed", "exit_code": 0}, report, ""
        with mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "network-reports",
                                         vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        experiment_command = calls[1][1]
        self.assertIn("--preferred-policy-only", experiment_command)
        self.assertIn("--vm-config", experiment_command)
        self.assertTrue(result["network_diagnostic_only"])
        self.assertTrue(result["source_diagnostic_only"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_acceptance_passed"])
        self.assertFalse(result["acceptance_passed"])
        self.assertFalse(result["real_node_passed"])
        self.assertEqual(result["outside_edge_phase"]["status"], "skipped")
        self.assertEqual(result["edge_ui_phase"]["status"], "skipped")
        self.assertEqual(result["reports"]["experiments"]["variants"][0]["process_started"], True)
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result(dict(result, status="passed", ordinary_user=True))
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result(self.passed_result(), network_diagnostic_only=True)

    def test_network_diagnostic_probe_failure_blocks_experiment_and_skips_every_other_phase(self):
        workspace = self.guest_control_workspace({
            "probe": {"exit_code": 3, "report": {"status": "unsupported", "probe": {"supported": False}}},
            "experiments": {"report": {"cleanup_proven": True}}})
        config = self.root / "network-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True}), encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "network-reports",
                                     vm_config=config)
        self.assertEqual((workspace / "executed.txt").read_text().splitlines(), ["probe"])
        self.assertEqual(result["experiments_phase"]["status"], "blocked")
        self.assertEqual(result["status"], "failed")

    def test_g3_internal_tcp_policy_is_strictly_network_source_only_and_never_accepts(self):
        workspace = self.guest_control_workspace({"experiments": {}})
        config = self.root / "internal-tcp-policy-vm-config.json"
        valid = {"network_diagnostic_only": True, "test_psec_executor_diagnostic": True,
                 "internal_tcp_policy_diagnostic": "loopback"}
        config.write_text(json.dumps(valid), encoding="utf-8")
        clean = {"cleanup_proven": True,
                 "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                 "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                               "resources_closed": True}]}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean), ""
        metadata = {"diagnostic_internal_tcp_policy": "loopback",
                    "network_scope": "all TCP destinations under 127.0.0.1/32",
                    "source_diagnostic_only": True, "release_eligible": False,
                    "default_product_runtime_replaced": False}
        bundle = (workspace / "candidate.exe", workspace / "candidate.json", metadata)
        with mock.patch.object(vm, "guest_test_executor", return_value=bundle), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "g3-reports",
                                         vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        command = calls[1][1]
        index = command.index("--internal-tcp-policy-diagnostic")
        self.assertEqual(command[index + 1], "loopback")
        self.assertIn("--test-psec-executor", command)
        self.assertIn("--preferred-policy-only", command)
        self.assertTrue(result["source_diagnostic_only"])
        self.assertEqual(result["internal_tcp_policy_diagnostic"], "loopback")
        self.assertEqual(result["source_policy_variant"], "internal_tcp_loopback_control")
        self.assertFalse(result["product_acceptance_passed"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_runtime_replaced"])

    def test_g3_private_config_rejects_wrong_modes_and_axes_before_processes(self):
        config = self.root / "internal-tcp-policy-invalid.json"
        workspace = self.guest_control_workspace()
        base = {"network_diagnostic_only": True, "test_psec_executor_diagnostic": True,
                "internal_tcp_policy_diagnostic": "singleton"}
        invalid = [
            {**base, "internal_tcp_policy_diagnostic": "other"},
            {**base, "internal_tcp_policy_diagnostic": True},
            {**base, "network_diagnostic_only": False},
            {**base, "test_psec_executor_diagnostic": False},
            {**base, "gui_diagnostic_only": True},
            {**base, "ingress_controls_diagnostic": True},
            {**base, "singleton_port_range_diagnostic": True},
        ]
        for value in invalid:
            config.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(value=value), mock.patch.object(vm, "run_guest_phase") as phase:
                result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports",
                                             vm_config=config)
                phase.assert_not_called()
            self.assertEqual(result["diagnostic_configuration_error"], "invalid_private_configuration")

    def test_g3_cli_requires_network_and_candidate_and_rejects_other_control_axes(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--internal-tcp-policy-diagnostic", "singleton"]
        executor = ["--test-psec-executor", "candidate.exe", "--test-psec-manifest", "candidate.json"]
        with mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as failure:
                vm.main(base + ["--network-diagnostic-only"] + executor + ["--ingress-controls-diagnostic"])
            self.assertEqual(failure.exception.code, 2)
            run.assert_not_called()
        with mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as failure:
                vm.main(base + ["--network-diagnostic-only"])
            self.assertEqual(failure.exception.code, 2)
            run.assert_not_called()
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(base + ["--network-diagnostic-only"] + executor
                                     + ["--psec-1-1-diagnostic"]), 1)
            self.assertEqual(run.call_args.args[0].internal_tcp_policy_diagnostic, "singleton")

    def test_unset_internal_policy_cli_defaults_to_none_for_normal_runtime(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts")]
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            vm.main(base)
            self.assertIsNone(run.call_args.args[0].internal_tcp_policy_diagnostic)
        for args in (SimpleNamespace(artifacts=self.root / "run-none"),
                     SimpleNamespace(artifacts=self.root / "run-absent")):
            if hasattr(args, "internal_tcp_policy_diagnostic"):
                args.internal_tcp_policy_diagnostic = None
            with mock.patch.object(vm, "require_kvm", side_effect=RuntimeError("stop before VM setup")):
                result = vm.run(args)
            self.assertEqual(result["internal_tcp_policy_diagnostic"], "none")
            self.assertFalse(result["source_diagnostic_only"])

    def test_g3_host_report_attestation_requires_mode_scope_and_source_candidate_digest(self):
        network_module = vm.network_executor_verifier(ROOT)

        def report_for(mode):
            scope = ("127.0.0.1/32 TCP with the selected exact port" if mode == "singleton"
                     else "all TCP destinations under 127.0.0.1/32")
            metadata = {"executor_sha256": "a" * 64, "diagnostic_internal_tcp_policy": mode,
                        "network_scope": scope, "source_diagnostic_only": True,
                        "release_eligible": False, "default_product_runtime_replaced": False}
            policy = network_module.network_policy(network_module.PREFERRED_VARIANT, 43871, 42111,
                                                   internal_tcp_policy=mode)
            report = {"internal_tcp_policy_diagnostic": mode,
                      "internal_tcp_policy_diagnostic_requested": mode,
                      "source_policy_variant": f"internal_tcp_{mode}_control",
                      "policy_selection": f"internal_tcp_{mode}_control",
                      "selected_variants": [network_module.PREFERRED_VARIANT],
                      "diagnostic_port_encoding": "singleton_range" if mode == "singleton" else "all_tcp_loopback_ports",
                      "source_diagnostic_only": True, "production_policy_unchanged": True,
                      "product_runtime_replaced": False, "full_acceptance_passed": False,
                      "acceptance_passed": False, "real_node_passed": False,
                      "selected_executor": {"selection": "source_candidate", "executor_sha256": "a" * 64,
                                            "product_runtime_replaced": False},
                      "test_psec_executor": {**metadata, "executor_sha256": "a" * 64},
                      "selected_executor_precapture_probe": {
                          "status": "probe_passed", "scope": "source_only_internal_tcp_policy_control_probe",
                          "executor_selection": "source_candidate", "executor_sha256": "a" * 64,
                          "source_policy_variant": f"internal_tcp_{mode}_control",
                          "internal_tcp_policy_diagnostic": mode, "production_policy_unchanged": True,
                          "warmup_before_capture": True,
                          "backend_confirmation": {"tier": "base-container", "needs_dacl_augmentation": False}},
                      "variants": [{"name": network_module.PREFERRED_VARIANT,
                                    "internal_tcp_policy_diagnostic": mode,
                                    "source_policy_variant": f"internal_tcp_{mode}_control",
                                    "production_policy_unchanged": True, "policy": policy}]}
            report["candidate_precapture_probe"] = copy.deepcopy(report["selected_executor_precapture_probe"])
            return metadata, report

        for mode in ("singleton", "loopback"):
            metadata, report = report_for(mode)
            vm.verify_internal_tcp_policy_report(report, mode, metadata)
        for key, value in (("internal_tcp_policy_diagnostic", "singleton"),
                           ("production_policy_unchanged", False),
                           ("source_diagnostic_only", False)):
            invalid = copy.deepcopy(report_for("loopback")[1])
            invalid[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "did not attest"):
                vm.verify_internal_tcp_policy_report(invalid, "loopback", report_for("loopback")[0])
        metadata, report = report_for("loopback")
        invalid = copy.deepcopy(report)
        invalid["test_psec_executor"]["executor_sha256"] = "b" * 64
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            vm.verify_internal_tcp_policy_report(invalid, "loopback", metadata)
        invalid = copy.deepcopy(report)
        invalid["variants"][0]["policy"]["network"]["ingress"]["hostLoopback"] = "allow"
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            vm.verify_internal_tcp_policy_report(invalid, "loopback", metadata)
        invalid = copy.deepcopy(report)
        invalid["variants"][0]["policy"]["network"]["egress"]["allow"][0]["to"].append({"cidr": "10.0.0.0/8"})
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            vm.verify_internal_tcp_policy_report(invalid, "loopback", metadata)
        invalid = copy.deepcopy(report)
        invalid["variants"][0]["policy"]["capabilities"] = ["internetClient"]
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            vm.verify_internal_tcp_policy_report(invalid, "loopback", metadata)
        metadata, invalid = report_for("singleton")
        invalid["variants"][0]["policy"]["network"]["egress"]["allow"][0]["ports"][0]["unexpected"] = True
        with self.assertRaisesRegex(RuntimeError, "did not attest"):
            vm.verify_internal_tcp_policy_report(invalid, "singleton", metadata)

    def test_singleton_encoding_is_forwarded_only_in_original_sdk_network_diagnostics(self):
        workspace = self.guest_control_workspace({"experiments": {}})
        config = self.root / "singleton-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True,
                                      "singleton_port_range_diagnostic": True}))
        clean = {"cleanup_proven": True,
                 "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                 "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                               "resources_closed": True}]}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean), ""
        with mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        self.assertIn("--singleton-port-range", calls[1][1])
        self.assertNotIn("--test-psec-executor", calls[1][1])
        self.assertTrue(result["singleton_port_range_diagnostic"])
        self.assertEqual(result["execution_mode"], "packaged_product_runtime")
        self.assertEqual(result["status"], "failed")
        self.assertFalse(result["product_acceptance_passed"])

    def test_invalid_singleton_configuration_starts_no_guest_phase(self):
        workspace = self.guest_control_workspace()
        config = self.root / "singleton-vm-config.json"
        for value in ({"singleton_port_range_diagnostic": True},
                      {"network_diagnostic_only": True, "singleton_port_range_diagnostic": True,
                       "test_psec_executor_diagnostic": True},
                      {"network_diagnostic_only": True, "singleton_port_range_diagnostic": 1}):
            config.write_text(json.dumps(value))
            with self.subTest(value=value), mock.patch.object(vm, "run_guest_phase") as phase:
                result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", vm_config=config)
                phase.assert_not_called()
            self.assertEqual(result["diagnostic_configuration_error"], "invalid_private_configuration")
            self.assertTrue(all(p["status"] == "blocked" for p in result["phases"]))

    def test_psec_1_1_requires_network_only_and_rejects_conflicting_diagnostic_axes(self):
        config = self.root / "psec-vm-config.json"
        workspace = self.guest_control_workspace()
        for value in (
                {"psec_1_1_diagnostic": True},
                {"network_diagnostic_only": True, "psec_1_1_diagnostic": True,
                 "singleton_port_range_diagnostic": True},
                {"network_diagnostic_only": True, "psec_1_1_diagnostic": 1},
                {"network_diagnostic_only": True, "psec_1_1_diagnostic": True,
                 "gui_diagnostic_only": True}):
            config.write_text(json.dumps(value))
            with self.subTest(value=value), mock.patch.object(vm, "run_guest_phase") as phase:
                result = vm.run_guest_phases(self.root / "release", workspace,
                                             self.root / "reports", vm_config=config)
                phase.assert_not_called()
            self.assertEqual(result["diagnostic_configuration_error"], "invalid_private_configuration")

    def test_psec_1_1_is_forwarded_alongside_valid_source_candidate_only_as_nonrelease_diagnostic(self):
        workspace = self.guest_control_workspace({"experiments": {}})
        config = self.root / "psec-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True, "psec_1_1_diagnostic": True,
                                      "test_psec_executor_diagnostic": True}), encoding="utf-8")
        clean = {"cleanup_proven": True,
                 "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                 "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                               "resources_closed": True}]}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean), ""
        bundle = (workspace / "candidate.exe", workspace / "candidate.json", {"sha256": "host-verified"})
        with mock.patch.object(vm, "guest_test_executor", return_value=bundle), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        command = calls[1][1]
        self.assertIn("--psec-1-1-diagnostic", command)
        self.assertIn("--preferred-policy-only", command)
        self.assertIn("--test-psec-executor", command)
        self.assertNotIn("--singleton-port-range", command)
        self.assertTrue(result["psec_1_1_diagnostic"])
        self.assertTrue(result["source_diagnostic_only"])
        self.assertEqual(result["execution_mode"], "source_executor_diagnostic")
        self.assertFalse(result["product_acceptance_passed"])

    def test_ingress_control_rejects_missing_source_selector_or_conflicting_modes_before_launch(self):
        valid = {"network_diagnostic_only": True, "psec_1_1_diagnostic": True,
                 "test_psec_executor_diagnostic": True, "ingress_controls_diagnostic": True}
        config = self.root / "ingress-control-config.json"
        workspace = self.guest_control_workspace()
        invalid = [{**valid, key: False} for key in (
            "network_diagnostic_only", "psec_1_1_diagnostic", "test_psec_executor_diagnostic")]
        invalid += [{**valid, key: True} for key in (
            "gui_diagnostic_only", "chromium_gui_control_diagnostic", "singleton_port_range_diagnostic")]
        invalid += [{**valid, "ingress_controls_diagnostic": value} for value in (1, "true", None)]
        for value in invalid:
            config.write_text(json.dumps(value))
            with self.subTest(value=value), mock.patch.object(vm, "run_guest_phase") as phase:
                result = vm.run_guest_phases(self.root / "release", workspace,
                                             self.root / "reports", vm_config=config)
                phase.assert_not_called()
            self.assertEqual(result["diagnostic_configuration_error"], "invalid_private_configuration")
        config.write_text(json.dumps(valid))
        self.assertTrue(vm.guest_diagnostic_options(config)[6])
        with self.assertRaisesRegex(RuntimeError, "cannot qualify product acceptance"):
            vm.verify_result({**self.passed_result(), "ingress_controls_diagnostic": True})

    def test_ingress_capability_control_reaches_only_network_experiment_and_cannot_accept(self):
        workspace = self.guest_control_workspace({"experiments": {}})
        config = self.root / "ingress-control-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True, "psec_1_1_diagnostic": True,
            "test_psec_executor_diagnostic": True, "ingress_controls_diagnostic": True}))
        clean = {"cleanup_proven": True,
                 "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                 "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                               "resources_closed": True}]}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean), ""
        bundle = (workspace / "candidate.exe", workspace / "candidate.json", {"sha256": "host-verified"})
        with mock.patch.object(vm, "guest_test_executor", return_value=bundle), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        self.assertIn("--ingress-controls-diagnostic", calls[1][1])
        self.assertIn("--psec-1-1-diagnostic", calls[1][1])
        self.assertTrue(result["ingress_controls_diagnostic"])
        self.assertEqual(result["source_policy_variant"], "private_network_capability_control")
        self.assertFalse(result["product_acceptance_passed"])
        self.assertFalse(result["full_acceptance_passed"])
        self.assertFalse(result["product_runtime_replaced"])

    def test_psec_1_1_cli_is_network_only_diagnostic_and_allows_source_candidate(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--psec-1-1-diagnostic"]
        for extra in ([], ["--network-diagnostic-only", "--singleton-port-range-diagnostic"]):
            with self.subTest(extra=extra), mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    vm.main(base + extra)
                self.assertEqual(failure.exception.code, 2)
                run.assert_not_called()
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(base + ["--network-diagnostic-only", "--test-psec-executor",
                                             str(self.root / "candidate.exe"), "--test-psec-manifest",
                                             str(self.root / "candidate.json")]), 1)
            self.assertTrue(run.call_args.args[0].psec_1_1_diagnostic)

    def test_ingress_g2_cli_accepts_only_network_or_gui_pairings(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--ingress-controls-diagnostic",
                "--test-psec-executor", str(self.root / "candidate.exe"),
                "--test-psec-manifest", str(self.root / "candidate.json")]
        valid_gui = base + ["--gui-diagnostic-only", "--chromium-gui-control"]
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(valid_gui), 1)
            self.assertTrue(run.call_args.args[0].ingress_controls_diagnostic)
            self.assertTrue(run.call_args.args[0].chromium_gui_control)
        invalid = [
            ["--gui-diagnostic-only"],
            ["--gui-diagnostic-only", "--chromium-gui-control", "--psec-1-1-diagnostic"],
            ["--gui-diagnostic-only", "--chromium-gui-control", "--network-diagnostic-only"],
            ["--gui-diagnostic-only", "--chromium-gui-control", "--singleton-port-range-diagnostic"],
            ["--network-diagnostic-only"],
            ["--network-diagnostic-only", "--psec-1-1-diagnostic", "--gui-diagnostic-only"],
        ]
        for extra in invalid:
            with self.subTest(extra=extra), mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    vm.main(base + extra)
                self.assertEqual(failure.exception.code, 2)
                run.assert_not_called()

    def test_singleton_cli_requires_original_sdk_network_mode_and_never_accepts(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--singleton-port-range-diagnostic"]
        for extra in ([], ["--network-diagnostic-only", "--test-psec-executor", "candidate.exe",
                           "--test-psec-manifest", "candidate.json"]):
            with self.subTest(extra=extra), mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failed:
                    vm.main(base + extra)
                self.assertEqual(failed.exception.code, 2)
                run.assert_not_called()
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(base + ["--network-diagnostic-only"]), 1)
            self.assertTrue(run.call_args.args[0].singleton_port_range_diagnostic)

    def test_network_diagnostic_retains_failed_experiment_and_cleanup_recovery(self):
        report = {"cleanup_proven": False, "cleanup_error": "retained", "recovery_directory": "private",
                  "checks": [], "variants": []}
        workspace = self.guest_control_workspace({"experiments": {"report": report, "exit_code": 1}})
        config = self.root / "network-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True}), encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "network-reports",
                                     vm_config=config)
        self.assertEqual(result["reports"]["experiments"], report)
        self.assertEqual(result["recovery_records"][0]["phase"], "experiments")
        self.assertFalse(result["recovery_records"][0]["descendant_cleanup_proven"])
        self.assertFalse(result["product_acceptance_passed"])

    def test_network_diagnostic_config_allows_executor_but_rejects_gui_and_invalid_values(self):
        config = self.root / "network-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True,
                                      "test_psec_executor_diagnostic": True}), encoding="utf-8")
        self.assertEqual(vm.guest_diagnostic_modes(config), (False, True))
        config.write_text(json.dumps({"network_diagnostic_only": True, "gui_diagnostic_only": True}),
                          encoding="utf-8")
        with self.assertRaises(ValueError):
            vm.guest_diagnostic_modes(config)
        config.write_text(json.dumps({"network_diagnostic_only": 1}), encoding="utf-8")
        with self.assertRaises(ValueError):
            vm.guest_diagnostic_modes(config)

    def test_network_diagnostic_passes_only_host_validated_executor_pair_to_experiment(self):
        workspace = self.guest_control_workspace({"experiments": {}})
        config = self.root / "network-vm-config.json"
        config.write_text(json.dumps({"network_diagnostic_only": True,
                                      "test_psec_executor_diagnostic": True}), encoding="utf-8")
        clean = {"cleanup_proven": True,
                 "checks": [{"check": "host_proxy_dns_default_routes_unchanged", "status": "passed"}],
                 "variants": [{"process_started": True, "descendant_cleanup_proven": True,
                               "resources_closed": True}]}
        calls = []
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, \
                {"status": "supported_only"} if name == "probe" else copy.deepcopy(clean), ""
        bundle = (workspace / "custom.exe", workspace / "custom.json", {"sha256": "host-verified"})
        with mock.patch.object(vm, "guest_test_executor", return_value=bundle), \
                mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            result = vm.run_guest_phases(self.root / "release", workspace, self.root / "reports", vm_config=config)
        self.assertEqual([name for name, _ in calls], ["probe", "experiments"])
        command = calls[1][1]
        self.assertEqual(command[command.index("--test-psec-executor") + 1], str(bundle[0]))
        self.assertEqual(command[command.index("--test-psec-manifest") + 1], str(bundle[1]))
        self.assertEqual(result["execution_mode"], "source_executor_diagnostic")
        self.assertFalse(result["product_runtime_replaced"])

    def test_network_diagnostic_cli_is_manual_and_mutually_exclusive_with_gui(self):
        arguments = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                     "--artifacts", str(self.root / "artifacts"), "--network-diagnostic-only"]
        summary = {"status": "transport_and_package_tests_passed", "baseline_diagnostic": False,
                   "network_boundary_passed": True, "official_update": {"required": True}}
        with mock.patch.object(vm, "run", return_value=summary) as run, mock.patch("sys.stderr"):
            self.assertEqual(vm.main(arguments), 1)
            self.assertTrue(run.call_args.args[0].network_diagnostic_only)
        with mock.patch.object(vm, "run", return_value=summary) as run, mock.patch("sys.stderr"):
            self.assertEqual(vm.main(arguments + ["--test-psec-executor", str(self.root / "executor.exe"),
                                                  "--test-psec-manifest", str(self.root / "manifest.json")]), 1)
            self.assertTrue(run.call_args.args[0].network_diagnostic_only)
        with mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as failure:
                vm.main(arguments + ["--gui-diagnostic-only"])
            self.assertEqual(failure.exception.code, 2)
            run.assert_not_called()

    def test_invalid_gui_config_fails_before_launching_any_guest_phase(self):
        workspace = self.guest_control_workspace()
        config = self.root / "invalid-vm-config.json"
        config.write_text('{"gui_diagnostic_only": true, "gui_diagnostic_only": false}', encoding="utf-8")
        result = vm.run_guest_phases(self.root / "release", workspace, self.root / "invalid-reports",
                                     vm_config=config)
        self.assertFalse((workspace / "executed.txt").exists())
        self.assertEqual(result["diagnostic_configuration_error"], "invalid_private_configuration")
        self.assertTrue(all(phase["status"] == "blocked" for phase in result["phases"]))
        self.assertEqual(result["status"], "failed")

    def test_gui_diagnostic_cli_requires_chromium_control_for_source_executor(self):
        arguments = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                     "--artifacts", str(self.root / "artifacts"), "--gui-diagnostic-only"]
        summary = {"status": "transport_and_package_tests_passed", "baseline_diagnostic": False,
                   "network_boundary_passed": True, "official_update": {"required": True}}
        with mock.patch.object(vm, "run", return_value=summary) as run, mock.patch("sys.stderr"):
            self.assertEqual(vm.main(arguments), 1)
            self.assertTrue(run.call_args.args[0].gui_diagnostic_only)
        with mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
            with self.assertRaises(SystemExit) as failure:
                vm.main(arguments + ["--test-psec-executor", str(self.root / "executor.exe"),
                                     "--test-psec-manifest", str(self.root / "manifest.json")])
            self.assertEqual(failure.exception.code, 2)
            run.assert_not_called()
        with mock.patch.object(vm, "run", return_value=summary) as run:
            self.assertEqual(vm.main(arguments + ["--chromium-gui-control", "--test-psec-executor",
                                                   str(self.root / "executor.exe"), "--test-psec-manifest",
                                                   str(self.root / "manifest.json")]), 1)
            self.assertTrue(run.call_args.args[0].chromium_gui_control)
            self.assertTrue(run.call_args.args[0].gui_diagnostic_only)

    def test_chromium_control_cli_requires_gui_only_and_allows_source_executor(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--chromium-gui-control"]
        for extra in ([], ["--gui-diagnostic-only", "--network-diagnostic-only"]):
            with self.subTest(extra=extra), mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    vm.main(base + extra)
                self.assertEqual(failure.exception.code, 2)
                run.assert_not_called()
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(base + ["--gui-diagnostic-only", "--test-psec-executor", "candidate.exe",
                                             "--test-psec-manifest", "candidate.json"]), 1)
            self.assertTrue(run.call_args.args[0].chromium_gui_control)

    def test_standard_profile_layout_cli_requires_cft_gui_and_rejects_g2_network_axes(self):
        base = ["--package", str(self.root / "release.zip"), "--package-sha256", "0" * 64,
                "--artifacts", str(self.root / "artifacts"), "--standard-profile-layout-control"]
        for extra in ([], ["--chromium-gui-control"], ["--gui-diagnostic-only"],
                      ["--gui-diagnostic-only", "--chromium-gui-control", "--ingress-controls-diagnostic",
                       "--test-psec-executor", "candidate.exe", "--test-psec-manifest", "candidate.json"],
                      ["--gui-diagnostic-only", "--chromium-gui-control", "--network-diagnostic-only"],
                      ["--gui-diagnostic-only", "--chromium-gui-control", "--psec-1-1-diagnostic"],
                      ["--gui-diagnostic-only", "--chromium-gui-control", "--singleton-port-range-diagnostic"]):
            with self.subTest(extra=extra), mock.patch.object(vm, "run") as run, mock.patch("sys.stderr"):
                with self.assertRaises(SystemExit) as failure:
                    vm.main(base + extra)
                self.assertEqual(failure.exception.code, 2)
                run.assert_not_called()
        valid = base + ["--gui-diagnostic-only", "--chromium-gui-control"]
        with mock.patch.object(vm, "run", return_value=self.passed_result()) as run:
            self.assertEqual(vm.main(valid), 1)
            self.assertTrue(run.call_args.args[0].standard_profile_layout_control)

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
        self.assertEqual(result["phases"][-1]["status"], "passed")

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
        self.assertEqual(len(result["phases"]), len(vm.PHASE_NAMES))
        self.assertEqual(result["recovery_records"], [])


class WindowsNetworkBoundaryTests(unittest.TestCase):
    """Release guards require actual scoped evidence, not aggregate green flags."""

    def evidence(self):
        preferred = 'model1_internal_ingress_deny'
        def scope(groups, *, dns=False):
            value = {'schema_version': 1, 'status': 'complete',
                'scope': 'default_test_vm_resolver_configuration_observed' if dns else 'captured_qemu_vm_nic_egress',
                'capture_format_complete': True, 'capture_flushed': True, 'actor_execution_attested': True,
                'capture_sha256': 'a' * 64, 'capture_bytes': 4096, 'packet_records': 32,
                'unknown_records': 0, 'unknown_reasons': {}, 'acceptance_passed': False,
                'kernel_denial_proven': False, 'groups': [], 'counts': []}
            for suffix in groups:
                group = preferred + '.' + suffix
                absent = 'contained_questions_absent' if dns else 'contained_markers_absent'
                observed = {'id': group, 'execution_proven': True, 'positive_controls_complete': True,
                    'control_window_ordered': True, 'absence_observed': True, absent: True}
                if dns:
                    observed.update(api=suffix, query_type={'getaddrinfo': None, 'dns_a': 1, 'dns_aaaa': 28}[suffix])
                value['groups'].append(observed)
                for role in ('outside_before', 'parent', 'child', 'outside_after'):
                    row = {'id': group + '.' + role, 'group': group, 'role': role,
                           'count': 1 if role.startswith('outside_') else 0}
                    row['qname_sha256' if dns else 'payload_sha256'] = hashlib.sha256(row['id'].encode()).hexdigest()
                    if dns:
                        row.update(api=suffix, query_type=observed['query_type'])
                    value['counts'].append(row)
            return value
        value = scope(('ipv4', 'ipv4_unbound', 'ipv6', 'ipv6_unbound'))
        value['native_dns'] = scope(('getaddrinfo', 'dns_a', 'dns_aaaa'), dns=True)
        return value

    def test_all_preferred_modes_and_default_dns_can_pass_only_their_scoped_guard(self):
        value = self.evidence()
        result = vm.verify_network_boundary(value)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['udp_groups_verified']), 4)
        self.assertEqual(len(result['native_dns_groups_verified']), 3)
        self.assertFalse(result['kernel_denial_proven'])
        self.assertFalse(result['full_acceptance_passed'])
        self.assertFalse(result['real_node_passed'])

    def test_native_cli_cannot_return_success_for_old_fixture_only_green_status(self):
        for baseline in (False, True):
            status = 'baseline_transport_and_package_tests_passed' if baseline else 'transport_and_package_tests_passed'
            result = {'status': status, 'baseline_diagnostic': baseline,
                      'official_update': {'required': not baseline}}
            args = ['--package', 'public-fixture.zip', '--package-sha256', 'a' * 64, '--artifacts', 'unused']
            if baseline:
                args.append('--baseline-diagnostic')
            with mock.patch.object(vm, 'run', return_value=result):
                self.assertEqual(vm.main(args), 1)
                result['network_boundary_passed'] = False
                self.assertEqual(vm.main(args), 1)
                result['network_boundary_passed'] = True
                self.assertEqual(vm.main(args), 0)

    def test_unsupported_unrelated_model2_never_requires_diagnostic_success(self):
        value = self.evidence()
        for capture in (value, value['native_dns']):
            capture.update(status='incomplete', execution_proven=False, packet_analysis_complete=False,
                           absence_observed=False)
            capture['groups'].append({'id': 'model2_host.unavailable', 'execution_proven': False,
                'positive_controls_complete': False, 'control_window_ordered': False, 'absence_observed': False})
        value['error'] = 'capture_sender_execution_incomplete'
        value['native_dns']['error'] = 'capture_native_dns_execution_incomplete'
        self.assertEqual(vm.verify_network_boundary(value)['status'], 'passed')

    def test_parent_or_child_wire_leak_cannot_be_hidden_by_positive_summary_flags(self):
        for dns in (False, True):
            for role in ('parent', 'child'):
                value = self.evidence()
                scope = value['native_dns'] if dns else value
                row = next(row for row in scope['counts'] if row['role'] == role)
                row['count'] = 1
                with self.subTest(dns=dns, role=role), self.assertRaisesRegex(RuntimeError, 'contained traffic'):
                    vm.verify_network_boundary(value)

    def test_unexecuted_sender_missing_control_or_unordered_window_remains_unverified(self):
        for dns in (False, True):
            for field in ('execution_proven', 'positive_controls_complete', 'control_window_ordered', 'absence_observed'):
                value = self.evidence()
                scope = value['native_dns'] if dns else value
                scope['groups'][-1][field] = False
                with self.subTest(dns=dns, field=field), self.assertRaises(RuntimeError):
                    vm.verify_network_boundary(value)
            value = self.evidence()
            scope = value['native_dns'] if dns else value
            scope['counts'][-1]['count'] = 0
            with self.subTest(dns=dns, control='actual count'), self.assertRaisesRegex(RuntimeError, 'positive control'):
                vm.verify_network_boundary(value)

    def test_missing_bound_unbound_or_native_api_group_cannot_pass_a_partial_scope(self):
        for dns in (False, True):
            for index in range(3 if dns else 4):
                value = self.evidence()
                scope = value['native_dns'] if dns else value
                scope['groups'].pop(index)
                with self.subTest(dns=dns, index=index), self.assertRaises(RuntimeError):
                    vm.verify_network_boundary(value)
        value = self.evidence()
        del value['native_dns']
        with self.assertRaises(RuntimeError):
            vm.verify_network_boundary(value)

    def test_unknown_opaque_unflushed_or_unattested_capture_is_not_absence(self):
        for dns in (False, True):
            for field, replacement in (('unknown_records', 1), ('unknown_records', False),
                    ('unknown_reasons', {'opaque_dns_tcp_or_https': 1}), ('capture_format_complete', False),
                    ('capture_flushed', False), ('actor_execution_attested', False),
                    ('error', 'capture_analysis_or_flush_failed')):
                value = self.evidence()
                scope = value['native_dns'] if dns else value
                scope[field] = replacement
                with self.subTest(dns=dns, field=field), self.assertRaises(RuntimeError):
                    vm.verify_network_boundary(value)

    def test_counter_identity_types_uniqueness_and_same_capture_are_required(self):
        changes = [('count', False), ('count', -1), ('count', '0'), ('role', 'outside_before'),
                   ('group', 'model2_host.ipv4'), ('payload_sha256', 'invalid')]
        for field, replacement in changes:
            value = self.evidence()
            value['counts'][1][field] = replacement
            with self.subTest(field=field, replacement=replacement), self.assertRaises(RuntimeError):
                vm.verify_network_boundary(value)
        value = self.evidence()
        value['counts'][1]['payload_sha256'] = value['counts'][0]['payload_sha256']
        with self.assertRaises(RuntimeError):
            vm.verify_network_boundary(value)
        value = self.evidence()
        value['native_dns']['counts'][4]['query_type'] = True
        with self.assertRaises(RuntimeError):
            vm.verify_network_boundary(value)
        value = self.evidence()
        value['counts'].append(copy.deepcopy(value['counts'][0]))
        with self.assertRaises(RuntimeError):
            vm.verify_network_boundary(value)
        for field, replacement in (('capture_sha256', 'b' * 64), ('capture_bytes', 4097), ('packet_records', 33)):
            value = self.evidence()
            value['native_dns'][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'same capture'):
                vm.verify_network_boundary(value)


class WindowsWireCaptureTests(unittest.TestCase):
    """Actual private HTTP requests and constructed PCAPs; no PSEC claim."""

    @staticmethod
    def dns_message(name, query_type=1):
        labels = name.rstrip(".").split(".")
        return (struct.pack("!6H", 123, 0, 1, 0, 0, 0)
            + b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels)
            + b"\0" + struct.pack("!HH", query_type, 1))

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
            self.controller.dns_packet.analyze_capture = lambda path, value: self.controller.dns_packet.analyze_bytes(path.read_bytes(), value)
        probes = []
        for variant in vm.WIRE_VARIANTS:
            for family in ("ipv4", "ipv6"):
                for role in self.controller.packet.ROLES:
                    group = variant + "." + family
                    probes.append({"id": group + "." + role, "group": group, "role": role,
                        "family": family, "protocol": "udp", "source_mac": vm.VM_NIC_MAC,
                        "source_ip": "10.0.2.15" if family == "ipv4" else "fec0::15",
                        "destination": "1.1.1.1" if family == "ipv4" else "2606:4700:4700::1111",
                        "port": 53, "payload_hex": self.dns_message("wire-" + str(len(probes)) + ".invalid").hex()})
        self.manifest = {"schema_version": 1, "probes": probes}
        self.execution = [{"id": p["id"], "role": p["role"], "attempted": True, "bind_succeeded": True,
                           "api_accepted": True, "errno": None} for p in probes]
        self.execution_schema_version = None

    def dual_mode(self):
        bound = self.manifest["probes"]
        unbound = []
        for p in bound:
            group = p["group"] + "_unbound"
            unbound.append({**p, "id": group + "." + p["role"], "group": group,
                           "payload_hex": self.dns_message("unbound-" + str(len(unbound)) + ".invalid").hex()})
        self.manifest["probes"] = bound + unbound
        self.execution = [{"id": p["id"], "role": p["role"], "attempted": True,
            "bind_attempted": not p["group"].endswith("_unbound"),
            "bind_succeeded": not p["group"].endswith("_unbound"),
            "send_attempted": True, "api_accepted": True, "errno": None} for p in self.manifest["probes"]]
        self.execution_schema_version = 2

    def dns_observation(self):
        preferred, nonce = "model1_internal_ingress_deny", "b" * 32
        probes, execution = [], []
        for api in ("getaddrinfo", "dns_a", "dns_aaaa"):
            for role in self.controller.packet.ROLES:
                group = preferred + "." + api
                name = f"{nonce}.{api.replace('_', '-')}.{role.replace('_', '-')}.ruleproxy-ci.example.com."
                probe = {"id": group + "." + role, "group": group, "role": role, "api": api, "qname": name}
                if api != "getaddrinfo":
                    probe["query_type"] = 1 if api == "dns_a" else 28
                probes.append(probe)
                execution.append({"id": probe["id"], "role": role, "api": api, "qname": name,
                    "requested_role": role, "pid": 2000 + len(probes), "ppid": 1000,
                    "process_created": 100000 + len(probes), "worker_exit_code": 0,
                    "outcome": "returned",
                    "attempted": True, "api_returned": True, "native_completion_proven": True,
                    "entry_lease_published": True, "worker_cleanup_proven": True,
                    "worker_exit_verified": True, "worker_handle_closed": True, "records_released": True,
                    "default_system_server_list": True, "server_list_override": False,
                    "dns_blocked_proven": False, "acceptance_passed": False,
                    "return_code": 11001 if api == "getaddrinfo" else 9003,
                    "query_options": 0 if api == "getaddrinfo" else 0x108})
                if api != "getaddrinfo":
                    execution[-1]["query_status"] = 9003
        return {"manifest": {"schema_version": 1, "source_mac": vm.VM_NIC_MAC, "probes": probes},
                "execution": execution, "actor_execution_attested": True}

    def capture(self, additional=()):
        packets = []
        for role in self.controller.packet.ROLES:
            controls = self.manifest["probes"] if role in ("outside_before", "outside_after") else []
            for p in controls + list(additional):
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

    def finish(self, execution=None, dns=None):
        value = {"manifest": self.manifest,
            "execution": self.execution if execution is None else execution, "actor_execution_attested": True}
        if self.execution_schema_version is not None:
            value["execution_schema_version"] = self.execution_schema_version
        if dns is not None:
            value["dns"] = dns
        return self.controller.finish(value)

    def dns_capture_probes(self, observation):
        return [{**p, "family": "ipv4", "source_ip": "10.0.2.15", "destination": "10.0.2.3",
            "payload_hex": self.dns_message(p["qname"], p.get("query_type", 1)).hex()}
            for p in observation["manifest"]["probes"] if p["role"] in ("outside_before", "outside_after")]

    def test_dual_mode_sixty_four_rows_require_actual_mode_specific_send_attempts(self):
        self.dual_mode()
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertTrue(result["execution_proven"])
        self.assertTrue(result["absence_observed"])
        self.assertEqual(len(result["groups"]), 16)
        self.assertEqual(len(result["counts"]), 64)
        self.assertFalse(result["kernel_denial_proven"])
        self.assertFalse(result["acceptance_passed"])
        self.assertTrue(all(group["execution_proven"] for group in result["groups"]))

    def test_release_guard_accepts_real_parsed_preferred_groups_with_unsupported_model2(self):
        self.dual_mode()
        self.execution = [row for row in self.execution if not row['id'].startswith('model2_host.')]
        dns = self.dns_observation()
        self.controller.start({}); self.capture(self.dns_capture_probes(dns))
        result = self.finish(dns=dns)
        self.assertEqual(result['status'], 'incomplete')
        self.assertFalse(result['execution_proven'])
        self.assertTrue(all(group['absence_observed'] for group in result['groups']
            if group['id'].startswith('model1_internal_ingress_deny.')))
        self.assertEqual(vm.verify_network_boundary(result)['status'], 'passed')

    def test_release_guard_rejects_real_parsed_contained_default_resolver_question(self):
        self.dual_mode()
        dns = self.dns_observation()
        controls = self.dns_capture_probes(dns)
        parent = next(probe for probe in dns['manifest']['probes']
                      if probe['api'] == 'getaddrinfo' and probe['role'] == 'parent')
        leaked = {**parent, 'family': 'ipv4', 'source_ip': '10.0.2.15', 'destination': '10.0.2.3',
                  'payload_hex': self.dns_message(parent['qname']).hex()}
        self.controller.start({}); self.capture(controls + [leaked])
        result = self.finish(dns=dns)
        self.assertTrue(result['absence_observed'])  # Fixed raw UDP markers were absent.
        self.assertEqual(next(row['count'] for row in result['native_dns']['counts']
            if row['id'] == parent['id']), 1)
        with self.assertRaisesRegex(RuntimeError, 'contained traffic'):
            vm.verify_network_boundary(result)

    def test_unbound_send_not_attempted_and_bound_bind_denied_leave_own_groups_unknown(self):
        self.dual_mode()
        for row in self.execution:
            if row["id"] in ("model3.ipv4_unbound.parent", "model1_internal.ipv6.child"):
                row.update(send_attempted=False, bind_succeeded=False, api_accepted=False, errno=10013)
        self.controller.start({}); self.capture()
        result = self.finish()
        groups = {x["id"]: x for x in result["groups"]}
        for key in ("model3.ipv4_unbound", "model1_internal.ipv6"):
            self.assertFalse(groups[key]["execution_proven"])
            self.assertFalse(groups[key]["absence_observed"])
            self.assertIsNone(groups[key]["contained_markers_absent"])
        self.assertTrue(groups["model3.ipv4"]["absence_observed"])
        self.assertTrue(groups["model1_internal.ipv6_unbound"]["absence_observed"])
        self.assertFalse(result["absence_observed"])

    def test_dual_schema_and_legacy_rows_cannot_be_mixed_to_invent_send_evidence(self):
        self.dual_mode()
        self.execution_schema_version = None
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertTrue(all(not x["execution_proven"] for x in result["groups"]))
        self.assertFalse(result["absence_observed"])

    def test_new_send_fields_cannot_be_smuggled_into_legacy_thirty_two_rows(self):
        for row in self.execution:
            row.update(bind_attempted=True, send_attempted=True)
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertTrue(all(not x["execution_proven"] for x in result["groups"]))
        self.assertFalse(result["absence_observed"])

    def test_v2_header_cannot_turn_legacy_thirty_two_rows_into_dual_mode_evidence(self):
        self.execution_schema_version = 2
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertTrue(all(not x["execution_proven"] for x in result["groups"]))
        self.assertFalse(result["absence_observed"])

    def test_unbound_actual_source_drift_remains_unknown_instead_of_a_false_zero(self):
        self.dual_mode()
        probe = next(p for p in self.manifest["probes"] if p["id"] == "model3.ipv4_unbound.parent")
        self.controller.start({}); self.capture([{**probe, "source_ip": "10.0.2.99"}])
        result = self.finish()
        self.assertTrue(result["execution_proven"])
        self.assertFalse(result["absence_observed"])
        self.assertIsNone(result["contained_markers_absent"])
        self.assertEqual(result["unknown_reasons"]["probe_marker_unexpected_source_ip"], 1)
        self.assertTrue(all(group["contained_markers_absent"] is None for group in result["groups"]))

    def test_unbound_bind_success_is_rejected_instead_of_relabelled_as_an_unbound_send(self):
        self.dual_mode()
        next(row for row in self.execution if "_unbound" in row["id"]).update(bind_attempted=True, bind_succeeded=True)
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertFalse(result["absence_observed"])
        self.assertTrue(all(not x["execution_proven"] for x in result["groups"]))

    def test_legacy_marker_setup_error_after_bind_does_not_prove_send_attempt(self):
        self.execution[1].update(api_accepted=False, errno=-1)
        self.controller.start({}); self.capture()
        result = self.finish()
        self.assertFalse(result["groups"][0]["execution_proven"])
        self.assertIsNone(result["groups"][0]["contained_markers_absent"])
        self.assertTrue(result["groups"][1]["absence_observed"])

    def test_optional_native_dns_is_sanitized_and_does_not_promote_to_kernel_denial(self):
        self.dual_mode()
        dns = self.dns_observation()
        self.controller.start({}); self.capture(self.dns_capture_probes(dns))
        result = self.finish(dns=dns)
        self.assertTrue(result["absence_observed"])
        native = result["native_dns"]
        self.assertEqual(native["status"], "complete")
        self.assertTrue(native["execution_proven"])
        self.assertTrue(native["absence_observed"])
        self.assertFalse(native["kernel_denial_proven"])
        self.assertFalse(native["acceptance_passed"])
        self.assertEqual(len(native["groups"]), 3)
        self.assertEqual(len(native["counts"]), 12)
        serialized = json.dumps(result)
        self.assertNotIn(dns["manifest"]["probes"][0]["qname"], serialized)
        self.assertNotIn('"pid":', serialized)
        self.assertNotIn("10.0.2.3", serialized)

    def test_dns_deadline_invalid_request_or_unattested_actor_never_closes_zero_dns(self):
        dns = self.dns_observation()
        dns["execution"][1].update(outcome="deadline", api_returned=False, native_completion_proven=False)
        dns["execution"][5]["return_code"] = 87
        self.controller.start({}); self.capture(self.dns_capture_probes(dns))
        result = self.finish(dns=dns)
        self.assertTrue(result["absence_observed"])
        native = result["native_dns"]
        self.assertEqual(native["status"], "incomplete")
        self.assertFalse(native["absence_observed"])
        self.assertIsNone(native["contained_questions_absent"])
        groups = {x["api"]: x for x in native["groups"]}
        self.assertIsNone(groups["getaddrinfo"]["contained_questions_absent"])
        self.assertIsNone(groups["dns_a"]["contained_questions_absent"])
        self.assertTrue(groups["dns_aaaa"]["absence_observed"])
        dns["actor_execution_attested"] = False
        self.assertFalse(any(self.controller.dns_execution_groups(dns).values()))

    def test_actual_contained_dns_question_is_reported_without_discarding_raw_udp_evidence(self):
        dns = self.dns_observation()
        parent = next(p for p in dns["manifest"]["probes"] if p["api"] == "getaddrinfo" and p["role"] == "parent")
        packet = {**parent, "family": "ipv4", "source_ip": "10.0.2.15", "destination": "10.0.2.3",
                  "payload_hex": self.dns_message(parent["qname"]).hex()}
        self.controller.start({}); self.capture(self.dns_capture_probes(dns) + [packet])
        result = self.finish(dns=dns)
        self.assertTrue(result["absence_observed"])
        native = result["native_dns"]
        self.assertTrue(native["execution_proven"])
        self.assertFalse(native["absence_observed"])
        self.assertFalse(native["contained_questions_absent"])
        self.assertEqual(next(row["count"] for row in native["counts"] if row["id"] == parent["id"]), 1)
        self.assertFalse(native["kernel_denial_proven"])

    def test_arbitrary_dns_ids_or_query_scope_cannot_enter_artifacts(self):
        dns = self.dns_observation()
        dns["manifest"]["probes"][0]["id"] = "private-secret-value"
        self.controller.start({}); self.capture()
        result = self.finish(dns=dns)
        self.assertTrue(result["absence_observed"])
        self.assertFalse(result["native_dns"]["absence_observed"])
        self.assertNotIn("private-secret-value", json.dumps(result))
        dns = self.dns_observation()
        dns["manifest"]["probes"][0]["query_type"] = 1
        with self.assertRaises(ValueError):
            self.controller.fixed_dns_manifest(dns["manifest"])

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
        config.write_text('{}', encoding='ascii')
        calls = []

        def phase(name, command, *args, **kwargs):
            calls.append((name, command))
            return {"name": name, "status": "passed", "exit_code": 0}, None, ""

        with mock.patch.object(vm, "run_guest_phase", side_effect=phase):
            vm.run_guest_phases(self.root, workspace, self.root / "reports", vm_config=config)
        self.assertEqual(calls[0][1][-2:], ["--vm-config", str(config)])
        self.assertIn("--preferred-policy-only", calls[0][1])
        self.assertTrue(all("--vm-config" not in command for _, command in calls[1:]))
        self.assertTrue(all("--preferred-policy-only" not in command for _, command in calls[1:]))


class WindowsDiagnosticExecutorTests(unittest.TestCase):
    """Synthetic build bytes check routing/integrity, never claim native PSEC."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.product = self.base / 'product'
        runtime = self.product / 'bin/windows-amd64'
        runtime.mkdir(parents=True)
        self.verifier = vm.network_executor_verifier(ROOT)
        from ruleproxy import windows_runtime_pins
        helpers = self.verifier.load_helpers()
        hashes = {}
        for name in helpers.RUNTIME_REQUIRED_FILES:
            path = runtime / name
            path.write_bytes(('original product ' + name).encode())
            hashes[name] = vm.digest(path)
        for field, value in (("MXC_G_EXECUTOR_SHA256", hashes['wxc-exec.exe']),
                             ("MXC_G_LICENSE_SHA256", hashes['MXC-LICENSE.md'])):
            pin = mock.patch.object(windows_runtime_pins, field, value)
            pin.start()
            self.addCleanup(pin.stop)
            setattr(helpers, field, value)
        helpers.RUNTIME_VERSIONS = windows_runtime_pins.expected_windows_record()
        self.runtime_versions = copy.deepcopy(helpers.RUNTIME_VERSIONS)
        (runtime / 'runtime.json').write_text(json.dumps({**helpers.RUNTIME_VERSIONS, 'sha256': hashes}))
        self.original = hashes['wxc-exec.exe']
        self.package = self.base / 'product.zip'
        with zipfile.ZipFile(self.package, 'w') as archive:
            for path in runtime.iterdir():
                archive.write(path, 'RuleProxy-Web/bin/windows-amd64/' + path.name)
            archive.writestr('RuleProxy-Web/python/python.exe', b'public fixture python')
            archive.writestr('RuleProxy-Web/ruleproxy/windows_runtime.py', '# public fixture')
        self.bundle = self.base / 'downloaded'
        self.bundle.mkdir()
        self.executor = self.bundle / 'wxc-exec.exe'
        self.executor.write_bytes(b'public synthetic diagnostic executor, not runnable')
        self.manifest = self.bundle / 'build-manifest.json'
        self.value = {'schema_version': 1, 'status': 'built',
            'upstream_commit': self.verifier.PSEC_UPSTREAM_COMMIT,
            'executor_sha256': vm.digest(self.executor), 'patch': self.verifier.PSEC_TEST_PATCH,
            'original_file_sha256': self.verifier.PSEC_ORIGINAL_SOURCE_SHA256,
            'patch_sha256': self.verifier.PSEC_PATCH_SHA256,
            'patched_file_sha256': self.verifier.PSEC_PATCHED_SOURCE_SHA256,
            'toolchain': '1.93', 'target': 'x86_64-pc-windows-msvc'}
        self.manifest.write_text(json.dumps(self.value))
        license_path = self.bundle / 'MXC-LICENSE.md'
        license_path.write_bytes(b'public test MIT license fixture')
        self.license_digest = vm.digest(license_path)
        patch = mock.patch.object(vm, 'TEST_EXECUTOR_LICENSE_SHA256', self.license_digest)
        patch.start()
        self.addCleanup(patch.stop)

    def workspace(self):
        workspace = self.base / 'workspace'
        for relative in ('.github/windows_network_experiment.py', 'scripts/windows-acceptance.py'):
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, path)
        # The isolated acceptance helper now imports its pinned runtime identity
        # from the workspace. Mirror the synthetic package pins in this fixture
        # so the guest-side verifier authenticates the same product bytes.
        pins = workspace / 'ruleproxy/windows_runtime_pins.py'
        pins.parent.mkdir(parents=True, exist_ok=True)
        pins.write_text(
            f"MXC_G_EXECUTOR_SHA256 = {self.original!r}\n"
            f"MXC_G_LICENSE_SHA256 = {vm.digest(self.product / 'bin/windows-amd64/MXC-LICENSE.md')!r}\n"
            f"def expected_windows_record():\n    return {self.runtime_versions!r}\n",
            encoding='utf-8')
        (workspace / '.github/windows_edge_policy_experiment.py').write_text('# not executed in routing test')
        vm.stage_test_executor(workspace / vm.TEST_EXECUTOR_DIRECTORY, self.executor, self.manifest, self.original)
        config = self.base / 'vm-config.json'
        config.write_text(json.dumps({'test_psec_executor_diagnostic': True,
            'test_psec_executor_sha256': self.value['executor_sha256'],
            'test_psec_original_runtime_sha256': self.original, 'host_url': 'http://private.invalid/SECRET'}))
        return workspace, config

    def test_product_digest_is_bound_to_actual_release_bytes_before_diagnostic_use(self):
        vm.verify_package(self.package, vm.digest(self.package))
        self.assertEqual(vm.package_executor_sha256(self.package), self.original)
        altered = self.base / 'tampered-product.zip'
        with zipfile.ZipFile(self.package) as source, zipfile.ZipFile(altered, 'w') as target:
            for entry in source.infolist():
                raw = source.read(entry)
                if entry.filename.endswith('/wxc-exec.exe'):
                    raw += b'tampered'
                target.writestr(entry.filename, raw)
        with self.assertRaisesRegex(ValueError, 'Original release executor'):
            vm.package_executor_sha256(altered)

    def test_staged_payload_preserves_product_zip_and_only_adds_separate_bundle(self):
        staged = self.base / 'staged'
        metadata = vm.stage_test_executor(staged, self.executor, self.manifest, self.original)
        self.assertEqual(metadata['original_runtime_sha256'], self.original)
        self.assertFalse(metadata['default_product_runtime_replaced'])
        self.assertFalse(metadata['acceptance_passed'])
        payload = self.base / 'payload.zip'
        vm.make_payload(self.package, payload, test_executor_bundle=staged)
        with zipfile.ZipFile(payload) as archive:
            self.assertEqual(archive.read('package.zip'), self.package.read_bytes())
            members = {name for name in archive.namelist() if name.startswith(vm.TEST_EXECUTOR_DIRECTORY + '/')}
            self.assertEqual(members, {vm.TEST_EXECUTOR_DIRECTORY + '/' + name for name in vm.TEST_EXECUTOR_FILES})
            self.assertEqual(archive.read(vm.TEST_EXECUTOR_DIRECTORY + '/wxc-exec.exe'), self.executor.read_bytes())
            self.assertFalse(any(name.startswith('bin/') for name in archive.namelist()))
        with self.assertRaises(FileExistsError):
            vm.stage_test_executor(staged, self.executor, self.manifest, self.original)

    def test_bad_hash_provenance_license_and_product_directory_are_refused(self):
        for field, value in (('upstream_commit', 'a' * 40), ('patch_sha256', 'b' * 64),
                             ('toolchain', '1.93.0'), ('executor_sha256', '0' * 64)):
            with self.subTest(field=field):
                self.manifest.write_text(json.dumps({**self.value, field: value}))
                with self.assertRaises(ValueError):
                    vm.verify_executor_bundle(self.product, ROOT, self.executor, self.manifest, self.original)
        self.manifest.write_text(json.dumps(self.value))
        (self.bundle / 'MXC-LICENSE.md').write_bytes(b'changed license')
        with self.assertRaisesRegex(ValueError, 'license'):
            vm.verify_executor_bundle(self.product, ROOT, self.executor, self.manifest, self.original)
        with self.assertRaisesRegex(ValueError, 'separate'):
            vm.verify_executor_bundle(self.product, ROOT, self.product / 'bin/windows-amd64/wxc-exec.exe',
                                      self.manifest, self.original)

    def test_invalid_custom_build_is_refused_before_downloading_or_starting_vm(self):
        self.manifest.write_text(json.dumps({**self.value, 'toolchain': 'unverified'}))
        args = SimpleNamespace(artifacts=self.base / 'artifacts', package=self.package,
            package_sha256=vm.digest(self.package), timeout_seconds=300, baseline_diagnostic=False,
            test_psec_executor=self.executor, test_psec_manifest=self.manifest)
        with mock.patch.object(vm, 'require_kvm', return_value=12), \
                mock.patch.object(vm.subprocess, 'run') as command, mock.patch('builtins.print'):
            result = vm.run(args)
        command.assert_not_called()
        self.assertEqual(result['execution_mode'], 'source_executor_diagnostic')
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['network_boundary_passed'])
        self.assertFalse(result['product_runtime_replaced'])

    def test_custom_seed_selects_verified_payload_without_skipping_default_cu(self):
        work = self.base / 'private-work'
        work.mkdir()
        iso = b'public tiny ISO test fixture, never booted'
        def command(arguments, **_):
            if arguments[0] == 'curl':
                Path(arguments[arguments.index('--output') + 1]).write_bytes(iso)
        server = mock.Mock(server_address=('127.0.0.1', 43210), capability='a' * 64)
        args = SimpleNamespace(artifacts=self.base / 'artifacts', package=self.package,
            package_sha256=vm.digest(self.package), timeout_seconds=300, baseline_diagnostic=False,
            test_psec_executor=self.executor, test_psec_manifest=self.manifest)
        with mock.patch.object(vm, 'require_kvm', return_value=12), \
                mock.patch.object(vm.shutil, 'which', return_value='fixture-tool'), \
                mock.patch.object(vm.shutil, 'disk_usage', return_value=SimpleNamespace(free=100 * 1024**3)), \
                mock.patch.object(vm.Path, 'is_file', return_value=True), \
                mock.patch.object(vm.tempfile, 'TemporaryDirectory') as directory, \
                mock.patch.object(vm, 'ISO_BYTES', len(iso)), \
                mock.patch.object(vm, 'ISO_SHA256', hashlib.sha256(iso).hexdigest()), \
                mock.patch.object(vm.subprocess, 'run', side_effect=command), \
                mock.patch.object(vm, 'download_updates', return_value=[]) as updates, \
                mock.patch.object(vm, 'GuestServer', return_value=server), \
                mock.patch.object(vm, 'validate_install_tree', return_value='efi/microsoft/boot/efisys_noprompt.bin'), \
                mock.patch.object(vm, 'prepare_seed', side_effect=RuntimeError('stop before boot')) as seed, \
                mock.patch('builtins.print'):
            directory.return_value.__enter__.return_value = str(work)
            result = vm.run(args)
        updates.assert_called_once_with(work / 'official-updates')
        config = seed.call_args.args[2]
        self.assertTrue(config['require_official_update'])
        self.assertTrue(config['test_psec_executor_diagnostic'])
        self.assertEqual(config['test_psec_executor_sha256'], self.value['executor_sha256'])
        self.assertEqual(config['test_psec_original_runtime_sha256'], self.original)
        with zipfile.ZipFile(work / 'payload.zip') as archive:
            self.assertEqual(archive.read('package.zip'), self.package.read_bytes())
            self.assertEqual(archive.read(vm.TEST_EXECUTOR_DIRECTORY + '/build-manifest.json'), self.manifest.read_bytes())
            self.assertEqual(archive.read(vm.TEST_EXECUTOR_DIRECTORY + '/MXC-LICENSE.md'), (self.bundle / 'MXC-LICENSE.md').read_bytes())
        self.assertEqual(result['status'], 'failed')
        self.assertFalse(result['network_boundary_passed'])
        self.assertEqual(result['diagnostic_network_boundary']['status'], 'not_collected')

    def test_guest_reverifies_bundle_and_routes_pair_only_to_source_diagnostics(self):
        workspace, config = self.workspace()
        calls = []
        clean = {'cleanup_proven': True, 'checks': [
            {'check': 'host_proxy_dns_default_routes_unchanged', 'status': 'passed'}],
            'variants': [{'process_started': True, 'descendant_cleanup_proven': True,
                          'resources_closed': True, 'cleanup_proven': True}]}
        def phase(name, command, *_, **__):
            calls.append((name, command))
            return {'name': name, 'status': 'passed', 'exit_code': 0}, copy.deepcopy(clean), ''
        with mock.patch.object(vm, 'run_guest_phase', side_effect=phase):
            result = vm.run_guest_phases(self.product, workspace, self.base / 'reports', vm_config=config)
        self.assertEqual(result['execution_mode'], 'source_executor_diagnostic')
        self.assertFalse(result['product_runtime_replaced'])
        self.assertEqual([name for name, _ in calls], ['experiments', 'edge_ui', *vm.PHASE_NAMES])
        for name, command in calls:
            self.assertIs('--test-psec-executor' in command, name in ('experiments', 'edge_ui'))
            self.assertIs('--preferred-policy-only' in command, name == 'experiments')
            if name in ('experiments', 'edge_ui'):
                index = command.index('--test-psec-executor')
                self.assertEqual(command[index + 1], str(workspace / vm.TEST_EXECUTOR_DIRECTORY / 'wxc-exec.exe'))
        (workspace / vm.TEST_EXECUTOR_DIRECTORY / 'wxc-exec.exe').write_bytes(b'replaced in guest')
        calls.clear()
        with mock.patch.object(vm, 'run_guest_phase', side_effect=phase):
            failed = vm.run_guest_phases(self.product, workspace, self.base / 'tampered-reports', vm_config=config)
        self.assertEqual([name for name, _ in calls], ['package_tests'])
        self.assertEqual(failed['status'], 'failed')
        self.assertIn('executor_validation_error', failed)
        self.assertNotIn('SECRET', json.dumps(failed))

    def test_guest_cannot_select_custom_executor_by_untrusted_path_or_truthy_flag(self):
        workspace, config = self.workspace()
        value = json.loads(config.read_text())
        for replacement in ('true', 1, None):
            config.write_text(json.dumps({**value, 'test_psec_executor_diagnostic': replacement}))
            with self.subTest(flag=replacement), self.assertRaises(ValueError):
                vm.guest_test_executor(self.product, workspace, config)
        config.write_text(json.dumps({**value, 'test_psec_executor_sha256': 'f' * 64}))
        with self.assertRaisesRegex(ValueError, 'host-verified'):
            vm.guest_test_executor(self.product, workspace, config)
        config.write_text('{"test_psec_executor_diagnostic":false,"test_psec_executor_diagnostic":true}')
        with self.assertRaises(ValueError):
            vm.guest_test_executor(self.product, workspace, config)
        config.write_text('{}')
        self.assertIsNone(vm.guest_test_executor(self.product, workspace, config))

    def test_custom_wire_pass_never_returns_original_product_release_success(self):
        evidence = WindowsNetworkBoundaryTests().evidence()
        verdict = vm.diagnostic_network_boundary(evidence, executor_attested=True)
        self.assertEqual(verdict['status'], 'passed')
        self.assertEqual(verdict['executor_scope'], 'source_only_test_executor')
        self.assertFalse(verdict['product_acceptance_passed'])
        self.assertFalse(verdict['full_acceptance_passed'])
        self.assertEqual(vm.diagnostic_network_boundary(evidence, executor_attested=False)['status'], 'failed')
        self.assertEqual(vm.diagnostic_network_boundary(evidence, executor_attested=True, collection_failed=True)['status'], 'failed')
        evidence['native_dns']['counts'][1]['count'] = 1
        self.assertEqual(vm.diagnostic_network_boundary(evidence, executor_attested=True)['status'], 'failed')
        arguments = ['--package', str(self.package), '--package-sha256', vm.digest(self.package),
                     '--artifacts', str(self.base), '--test-psec-executor', str(self.executor)]
        with mock.patch.object(vm, 'run') as run, mock.patch('sys.stderr'):
            with self.assertRaises(SystemExit) as failure:
                vm.main(arguments)
            self.assertEqual(failure.exception.code, 2)
            run.assert_not_called()
        misleading_green = {'status': 'transport_and_package_tests_passed', 'baseline_diagnostic': False,
                            'network_boundary_passed': True, 'official_update': {'required': True}}
        with mock.patch.object(vm, 'run', return_value=misleading_green):
            self.assertEqual(vm.main(arguments + ['--test-psec-manifest', str(self.manifest)]), 1)

    def test_workflow_custom_download_is_manual_and_fixed_to_the_actual_g_artifact(self):
        import yaml
        workflow = yaml.safe_load((ROOT / '.github/workflows/check.yml').read_text(encoding="utf-8"))
        trigger = workflow.get('on', workflow.get(True))
        option = trigger['workflow_dispatch']['inputs']['capability_executor_diagnostic']
        self.assertEqual(option, {'description': option['description'], 'required': False,
                                  'type': 'boolean', 'default': False})
        gui_option = trigger['workflow_dispatch']['inputs']['gui_diagnostic_only']
        self.assertEqual(gui_option, {'description': gui_option['description'], 'required': False,
                                      'type': 'boolean', 'default': False})
        chromium_option = trigger['workflow_dispatch']['inputs']['chromium_gui_control_diagnostic']
        self.assertEqual(chromium_option, {'description': chromium_option['description'], 'required': False,
                                           'type': 'boolean', 'default': False})
        standard_profile_option = trigger['workflow_dispatch']['inputs']['standard_profile_layout_control']
        self.assertEqual(standard_profile_option,
                         {'description': standard_profile_option['description'], 'required': False,
                          'type': 'boolean', 'default': False})
        job = workflow['jobs']['windows-11-x64']
        network_option = trigger['workflow_dispatch']['inputs']['network_diagnostic_only']
        self.assertEqual(network_option, {'description': network_option['description'], 'required': False,
                                          'type': 'boolean', 'default': False})
        validation = next(step for step in job['steps'] if step.get('name') == 'Validate mutually exclusive diagnostic modes')
        self.assertIn("github.event_name == 'workflow_dispatch'", validation['if'])
        run_step = next(step for step in job['steps'] if step.get('name') == 'Run a checksum-verified official Windows 11 evaluation guest')
        self.assertIn('inputs.gui_diagnostic_only', run_step['env']['RULEPROXY_VM_GUI_DIAGNOSTIC'])
        self.assertIn('--gui-diagnostic-only', run_step['run'])
        self.assertIn('inputs.chromium_gui_control_diagnostic', run_step['env']['RULEPROXY_VM_CHROMIUM_CONTROL'])
        self.assertIn('--chromium-gui-control', run_step['run'])
        self.assertIn('CHROMIUM_CONTROL', validation['env'])
        self.assertIn('CHROMIUM_CONTROL', validation['run'])
        self.assertIn('CAPABILITY_DIAGNOSTIC', validation['run'])
        self.assertIn('[ "$CHROMIUM_CONTROL" != \'true\' ]', validation['run'])
        self.assertIn('STANDARD_PROFILE_CONTROL', validation['env'])
        self.assertIn('inputs.standard_profile_layout_control', run_step['env']['RULEPROXY_VM_STANDARD_PROFILE_CONTROL'])
        self.assertIn('--standard-profile-layout-control', run_step['run'])
        self.assertIn('cannot combine with G2', validation['run'])
        self.assertIn('inputs.network_diagnostic_only', run_step['env']['RULEPROXY_VM_NETWORK_DIAGNOSTIC'])
        self.assertIn('--network-diagnostic-only', run_step['run'])
        singleton_option = trigger['workflow_dispatch']['inputs']['singleton_port_range_diagnostic']
        self.assertEqual(singleton_option, {'description': singleton_option['description'], 'required': False,
                                            'type': 'boolean', 'default': False})
        self.assertIn('inputs.singleton_port_range_diagnostic', run_step['env']['RULEPROXY_VM_SINGLETON_DIAGNOSTIC'])
        self.assertIn('--singleton-port-range-diagnostic', run_step['run'])
        self.assertIn('SINGLETON_DIAGNOSTIC', validation['run'])
        psec_option = trigger['workflow_dispatch']['inputs']['psec_1_1_diagnostic']
        self.assertEqual(psec_option, {'description': psec_option['description'], 'required': False,
                                       'type': 'boolean', 'default': False})
        self.assertIn('inputs.psec_1_1_diagnostic', run_step['env']['RULEPROXY_VM_PSEC_1_1_DIAGNOSTIC'])
        self.assertIn('--psec-1-1-diagnostic', run_step['run'])
        self.assertIn('PSEC_1_1_DIAGNOSTIC', validation['run'])
        self.assertIn('G2 GUI+CfT', validation['run'])
        internal_option = trigger['workflow_dispatch']['inputs']['internal_tcp_policy_diagnostic']
        self.assertEqual(internal_option['type'], 'choice')
        self.assertEqual(internal_option['options'], ['none', 'singleton', 'loopback'])
        self.assertEqual(internal_option['default'], 'none')
        self.assertIn('inputs.internal_tcp_policy_diagnostic', run_step['env']['RULEPROXY_VM_INTERNAL_TCP_POLICY'])
        self.assertIn('--internal-tcp-policy-diagnostic', run_step['run'])
        self.assertIn('INTERNAL_TCP_POLICY', validation['env'])
        self.assertIn('G3', validation['run'])
        self.assertIn('gui_args+=(--ingress-controls-diagnostic)', run_step['run'])
        g2_step = next(step for step in job['steps'] if step.get('with', {}).get('name') == 'mxc-ingress-control-executor')
        self.assertEqual(g2_step['with']['run-id'], 38699568831)
        self.assertIn('inputs.ingress_controls_diagnostic', g2_step['if'])
        guest_runner = (ROOT / '.github/windows-vm-run.ps1').read_text(encoding='utf-8')
        self.assertIn("$result.test_psec_executor = $collected.test_psec_executor", guest_runner)
        self.assertIn("'ingress_controls_diagnostic'", guest_runner)
        self.assertIn("'internal_tcp_policy_diagnostic'", guest_runner)
        self.assertIn("'standard_profile_layout_control'", guest_runner)
        self.assertIn("'additional_directory_grants'", guest_runner)
        step = next(step for step in job['steps'] if step.get('with', {}).get('name') == 'mxc-capability-executor')
        self.assertEqual(step['uses'], 'actions/download-artifact@v8')
        self.assertEqual(step['with']['run-id'], 38660663692)
        self.assertEqual(step['with']['digest-mismatch'], 'error')
        self.assertIn("github.event_name == 'workflow_dispatch'", step['if'])
        self.assertIn('inputs.capability_executor_diagnostic', step['if'])
        self.assertEqual(job['permissions']['actions'], 'read')
        self.assertEqual(workflow['jobs']['release']['if'], "github.event_name == 'push' && github.ref == 'refs/heads/main'")

    def test_g3_producer_is_manual_boolean_build_and_keeps_existing_g_artifact_path(self):
        import yaml
        producer = yaml.safe_load((ROOT / '.github/workflows/mxc-capability.yml').read_text(encoding='utf-8'))
        trigger = producer.get('on', producer.get(True))
        option = trigger['workflow_dispatch']['inputs']['diagnostic_internal_tcp_policy']
        self.assertEqual(option, {'description': option['description'], 'required': False,
                                  'type': 'boolean', 'default': False})
        build = next(step for step in producer['jobs']['executor']['steps']
                     if step.get('name') == 'Build only the diagnostic native executor')
        self.assertIn('--diagnostic-internal-tcp-policy', build['run'])
        uploads = [step for step in producer['jobs']['executor']['steps'] if step.get('uses') == 'actions/upload-artifact@v7']
        self.assertEqual(len(uploads), 2)
        self.assertIn("!inputs.diagnostic_internal_tcp_policy", uploads[0]['if'])
        self.assertIn("inputs.diagnostic_internal_tcp_policy", uploads[1]['if'])
        self.assertEqual(uploads[1]['with']['name'], 'mxc-internal-tcp-policy-executor')
        self.assertIn("!inputs.diagnostic_internal_tcp_policy", producer['jobs']['arm-observation']['if'])
        guest_runner = (ROOT / '.github/windows-vm-run.ps1').read_text(encoding='utf-8')
        self.assertIn("'internal_tcp_policy_diagnostic'", guest_runner)


if __name__ == "__main__":
    unittest.main()
