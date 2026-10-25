"""Native qualification must prove client OS, package identity and ordinary actors."""
import importlib.util
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile
import zlib


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_proxifyre_native_vm", ROOT / ".github/windows_proxifyre_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


def minimal_png(width=1, height=1):
    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", binascii.crc32(kind + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"\0\x11\x22\x33\xff")) + chunk(b"IEND", b""))


def successful_result():
    screenshot = minimal_png()
    return {"status": "passed", "exit_code": 0, "user_cleanup_confirmed": True, "actor_session_id": 1,
        "os": {"product_type": "WinNT", "native_architecture": "AMD64", "build": 26200},
        "reports": {"product": {"status": "passed_server_product_qualification", "hosts_restored": True,
            "gui_verified": True,
            "ordinary_launcher": {"method": "WTSQueryUserToken+CreateProcessAsUserW", "session_id": 1},
            "actual_os": {"major": 10, "build": 26200, "product_type": 1, "architecture": "AMD64"},
            "checks": {"install_and_reinstall": True, "uninstall_preserves_user_state_and_shared_driver": True},
            "source_matches_bundle": {name: True for name in vm.SOURCE_IDENTITIES},
            "package": {"manifest_verified": True, "sha256": "a" * 64},
            "receiver_phase_evidence": [{"label": "real_edge_visible", "passed": True}],
            "ordinary_suite": {"status": "passed", "is_elevated": False, "panel_is_elevated": False,
                "interactive_session_id": 1, "visible_gui_local_checks_passed": True,
                "browser_visible": {"screenshot_png_base64": base64.b64encode(screenshot).decode("ascii"),
                                    "screenshot_sha256": hashlib.sha256(screenshot).hexdigest()},
                "checks": {name: True for name in vm.VISIBLE_GUI_CHECKS | {
                    "suite_ordinary", "panel_ordinary", "installed_package_loaded", "holder_ordinary"}}}}}}


class NativeProductEvidenceTests(unittest.TestCase):
    def test_native_pass_requires_the_same_positive_interactive_session_at_every_layer(self):
        cases = [("outer", "actor_session_id", value) for value in (None, 0, -1, True, "1", 2)]
        cases += [("launcher", "session_id", value) for value in (None, 0, True, "1", 2)]
        cases += [("suite", "interactive_session_id", value) for value in (None, 0, True, "1", 2)]
        cases += [("launcher", "method", "LogonUserW+CreateProcessWithTokenW")]
        for scope, key, value in cases:
            with self.subTest(scope=scope, key=key, value=value):
                result = successful_result()
                report = result["reports"]["product"]
                target = result if scope == "outer" else report["ordinary_launcher"] if scope == "launcher" else report["ordinary_suite"]
                target[key] = value
                with self.assertRaises(RuntimeError):
                    vm.verify_result(result)

    def test_visible_checks_flags_and_independent_receiver_phase_are_mandatory(self):
        for check in vm.VISIBLE_GUI_CHECKS:
            result = successful_result()
            result["reports"]["product"]["ordinary_suite"]["checks"].pop(check)
            with self.subTest(check=check), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        for scope, field in (("report", "gui_verified"), ("suite", "visible_gui_local_checks_passed")):
            result = successful_result()
            report = result["reports"]["product"]
            (report if scope == "report" else report["ordinary_suite"])[field] = False
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        result = successful_result()
        result["reports"]["product"]["receiver_phase_evidence"][0]["label"] = "real_edge_headless"
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

    def test_visible_screenshot_valid_png_decodes_but_tampering_and_invalid_headers_fail(self):
        result = successful_result()
        report = result["reports"]["product"]
        self.assertEqual(vm.visible_screenshot_bytes(report), minimal_png())
        browser = report["ordinary_suite"]["browser_visible"]
        browser["screenshot_sha256"] = "0" * 64
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)
        for raw in (b"not a PNG", minimal_png()[:-1], minimal_png(width=0),
                    minimal_png()[:29] + b"bad!" + minimal_png()[33:]):
            result = successful_result()
            browser = result["reports"]["product"]["ordinary_suite"]["browser_visible"]
            browser.update(screenshot_png_base64=base64.b64encode(raw).decode("ascii"),
                           screenshot_sha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(raw=raw[:20]), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        result = successful_result()
        result["reports"]["product"]["ordinary_suite"]["browser_visible"]["screenshot_png_base64"] += "\n"
        with self.assertRaises(RuntimeError):
            vm.verify_result(result)

    def test_visible_screenshot_is_required_and_total_result_size_is_bounded(self):
        for field in ("screenshot_png_base64", "screenshot_sha256"):
            result = successful_result()
            result["reports"]["product"]["ordinary_suite"]["browser_visible"].pop(field)
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                vm.verify_result(result)
        result = successful_result()
        result["padding"] = "x" * vm.MAX_GUEST_RESULT_BYTES
        with self.assertRaisesRegex(RuntimeError, "8 MiB"):
            vm.verify_result(result)

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
                # ZipInfo normalizes os.sep in its constructor on Windows.
                # Assign afterwards so the archive contains the malicious raw
                # spelling rather than a harmless normalized substitute.
                entry = zipfile.ZipInfo()
                entry.filename = extra
                entry.orig_filename = extra
                archive.writestr(entry, b"malicious")
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
            with zipfile.ZipFile(self.package) as archive:
                self.assertIn(name, [entry.orig_filename for entry in archive.infolist()])
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

    def test_raw_backslash_fixture_survives_windows_zipinfo_normalization(self):
        original_init = zipfile.ZipInfo.__init__

        def windows_init(entry, filename="NoName", date_time=(1980, 1, 1, 0, 0, 0)):
            original_init(entry, filename, date_time)
            entry.filename = entry.filename.replace("\\", "/")

        name = "RuleProxy-Web\\escape"
        with mock.patch.object(zipfile.ZipInfo, "__init__", windows_init):
            digest = self.package_with(name)
            with zipfile.ZipFile(self.package) as archive:
                entry = archive.infolist()[-1]
                self.assertEqual(entry.orig_filename, name)
                self.assertNotEqual(entry.filename, entry.orig_filename)
            with self.assertRaises(ValueError):
                vm.verify_package(self.package, digest)


class NativeCleanupTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "POSIX runner cancellation")
    def test_real_sigint_and_sigterm_leave_a_complete_cancelled_summary(self):
        for number in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=number), tempfile.TemporaryDirectory() as directory:
                code = f'''
import argparse, importlib.util, pathlib, sys, time
spec = importlib.util.spec_from_file_location('native_vm_signal_test', {str(ROOT / '.github/windows_proxifyre_vm.py')!r})
vm = importlib.util.module_from_spec(spec); spec.loader.exec_module(vm)
folder = pathlib.Path({directory!r})
def blocked_preflight():
    (folder / 'ready').write_text('ready')
    time.sleep(60)
vm.media.require_kvm = blocked_preflight
with vm.cancellation_signals():
    result = vm.run(argparse.Namespace(artifacts=folder, timeout_seconds=2700))
sys.exit(0 if result['status'] == 'cancelled' else 1)
'''
                process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    deadline = time.monotonic() + 10
                    while not (Path(directory) / "ready").exists():
                        if process.poll() is not None or time.monotonic() > deadline:
                            self.fail("Cancellation fixture did not enter its interruptible preflight")
                        time.sleep(.02)
                    process.send_signal(number)
                    stdout, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, stderr.decode(errors="replace"))
                    summary = json.loads((Path(directory) / "native-product-summary.json").read_text())
                    self.assertEqual(summary["status"], "cancelled")
                    self.assertEqual(summary["phase"], "finished")
                    self.assertEqual(summary["cancellation_signal"], signal.Signals(number).name)
                    self.assertIs(summary["native_windows_11_product_passed"], False)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate(timeout=5)

    def test_cancellation_persists_summary_before_cleanup_without_inventing_product_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            args = mock.Mock(artifacts=Path(directory), timeout_seconds=2700, suite="product",
                             psec_media="serviced-25h2")
            with mock.patch.object(vm.media, "require_kvm", side_effect=vm.QualificationInterrupted(signal.SIGTERM)), \
                    mock.patch.object(vm, "cleanup_owned", return_value=[]) as cleanup:
                result = vm.run(args)
            saved = json.loads((Path(directory) / "native-product-summary.json").read_text())
            self.assertEqual(result, saved)
            self.assertEqual(saved["status"], "cancelled")
            self.assertEqual(saved["cancellation_signal"], "SIGTERM")
            self.assertIs(saved["product_execution_confirmed"], False)
            self.assertIs(saved["native_windows_11_product_passed"], False)
            self.assertNotIn("error", saved)
            self.assertIn("cleanup", [row["phase"] for row in saved["phases"]])
            cleanup.assert_called_once()

    def test_underprovisioned_host_fails_before_download_and_retains_resource_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            args = mock.Mock(artifacts=Path(directory), timeout_seconds=2700, suite="product",
                             psec_media="serviced-25h2")
            facts = {"effective_cpu_count": 2, "MemAvailable": 7 * 1024**3}
            with mock.patch.object(vm.media, "require_kvm", return_value=12), \
                    mock.patch.object(vm, "host_resources", return_value=facts), \
                    mock.patch.object(vm.subprocess, "run") as command, mock.patch("builtins.print"):
                saved = vm.run(args)
            self.assertEqual(saved["status"], "failed")
            self.assertEqual(saved["failure_phase"], "host_resources_recorded")
            self.assertEqual(saved["host_preflight"], facts)
            command.assert_not_called()
        vm.check_host_resources({"effective_cpu_count": 4, "MemAvailable": 8 * 1024**3})
        with self.assertRaises(RuntimeError):
            vm.check_host_resources({"effective_cpu_count": 4, "MemAvailable": 12 * 1024**3,
                                     "cgroup_memory_available": 7 * 1024**3})

    def test_signal_handlers_are_restored_and_second_signal_cannot_interrupt_cleanup(self):
        handlers = {}
        def install(number, handler):
            previous = handlers.get(number, signal.SIG_DFL)
            handlers[number] = handler
            return previous
        with mock.patch.object(vm.signal, "signal", side_effect=install):
            with self.assertRaises(vm.QualificationInterrupted):
                with vm.cancellation_signals():
                    handlers[signal.SIGTERM](signal.SIGTERM, None)
        self.assertEqual(handlers, {signal.SIGINT: signal.SIG_DFL, signal.SIGTERM: signal.SIG_DFL})

    def test_qmp_samples_export_counters_without_private_disk_paths(self):
        qmp = mock.Mock()
        qmp.execute.side_effect = [{"running": True, "status": "running"},
            [{"device": "system", "filename": "private-configuration.iso",
              "stats": {"rd_bytes": 123, "wr_bytes": 456, "secret": "private-capability"}}]]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(vm, "host_resources", return_value={}):
            sample = vm.vm_sample(Path(directory), None, qmp)
        self.assertEqual(sample["blockstats"][0]["stats"], {"rd_bytes": 123, "wr_bytes": 456})
        self.assertTrue(sample["qmp_status"]["running"])
        self.assertNotIn("private", json.dumps(sample))

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
        self.assertGreater(script.index("Unregister-ScheduledTask"), script.index("$submitted = $true"))
        self.assertIn("$result.logs.supervisor = (Read-DiagnosticTail", script)
        self.assertIn("$request.Timeout = 15000", script)
        self.assertIn("$result.user_cleanup_confirmed", script)
        self.assertIn("Remove-Item Env:RULEPROXY_TEST_PASSWORD", script)
        self.assertIn("error_type='BootstrapIncomplete'", script)
        self.assertIn("$result.failure_phase = $result.phase", script)
        self.assertLess(script.index("$result.failure_phase = $result.phase"), script.index("Write-BootstrapStep 'cleanup_before'"))
        self.assertLess(script.index("'bootstrap-result.json'"), script.index("'/result'"))

    def test_native_bootstrap_uses_fixed_windows_powershell_and_system_modules(self):
        script = (ROOT / ".github/windows-proxifyre-vm-setup.ps1").read_text()
        self.assertIn("System32\\WindowsPowerShell\\v1.0\\powershell.exe", script)
        self.assertIn("-Execute $powershell", script)
        self.assertIn("-NoProfile -NonInteractive", script)
        self.assertIn("System32\\WindowsPowerShell\\v1.0\\Modules", script)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows PowerShell")
    def test_native_diagnostics_redact_secrets_and_read_powershell_utf16_logs(self):
        # Execute only the diagnostic functions found by the actual PS parser;
        # never invoke account/service/VM bootstrap actions during a unit test.
        command = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_NATIVE_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Bootstrap PowerShell syntax error' }
# Stub only the COM1 transport: unit diagnostics must not touch a host serial port.
$script:beacons = @()
function Send-SerialBeacon([string]$Text) { $script:beacons += $Text }
foreach ($name in @('Protect-DiagnosticText', 'Read-DiagnosticTail', 'Add-BootstrapError', 'Write-BootstrapStep')) {
    $definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $true)
    if ($null -eq $definition) { throw 'Missing diagnostic function' }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:passwordText = 'SyntheticSecretQ7!'
$script:configuration = [pscustomobject]@{host_url='http://10.0.2.2:12345/private-capability'}
$script:root = $env:RULEPROXY_NATIVE_TEST_ROOT
$script:utf8 = [Text.UTF8Encoding]::new($false)
$script:result = @{steps=@(); errors=@(); phase='start'}
$path = Join-Path $script:root 'utf16.log'
[IO.File]::WriteAllText($path, ('prefix ' * 30000) + ' SyntheticSecretQ7! http://10.0.2.2:12345/private-capability/result', [Text.Encoding]::Unicode)
$tail = Read-DiagnosticTail $path
Write-BootstrapStep 'product_controller_before'
$script:result.failure_phase = $script:result.phase
try { throw 'SyntheticSecretQ7! http://10.0.2.2:12345/private-capability/result' }
catch { [void](Add-BootstrapError $script:result.phase $_) }
Write-BootstrapStep 'cleanup_before'
$value = @{tail=$tail; detail='https://example.invalid/path/"quoted"'; result=$script:result; beacons=$script:beacons} | ConvertTo-Json -Depth 12 -Compress
Protect-DiagnosticText $value
'''
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, RULEPROXY_NATIVE_SCRIPT=str(ROOT / ".github/windows-proxifyre-vm-run.ps1"),
                               RULEPROXY_NATIVE_TEST_ROOT=directory)
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            environment["PSModulePath"] = str(powershell.parent / "Modules")
            completed = subprocess.run([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                                       env=environment, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            data = json.loads(completed.stdout)
            self.assertNotIn("SyntheticSecretQ7!", completed.stdout)
            self.assertNotIn("private-capability", completed.stdout)
            self.assertNotIn("http://", completed.stdout)
            self.assertNotIn("https://", completed.stdout)
            self.assertIn("[PASSWORD REDACTED]", data["tail"])
            self.assertNotIn("\x00", data["tail"])
            self.assertLessEqual(len(data["tail"]), 65536)
            self.assertEqual(data["result"]["failure_phase"], "product_controller_before")
            self.assertEqual(data["beacons"], ["phase product_controller_before", "phase cleanup_before"])
            self.assertEqual(data["result"]["phase"], "cleanup_before")
            self.assertEqual(data["result"]["errors"][0]["phase"], "product_controller_before")


if __name__ == "__main__":
    unittest.main()
