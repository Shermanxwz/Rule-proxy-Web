"""Guest serial-console progress beacons and the host's cleanup reserve."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_proxifyre_native_vm_beacons", ROOT / ".github/windows_proxifyre_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)

SUMMARY = ('{"error":"RuntimeError:explicit_global_stop_not_restored C:\\\\Program Files\\\\RuleProxy-Web",'
           '"failed_stage":"explicit_global_stop","note":"100%25 via https://example.invalid/x"}')


def serial_log(directory):
    path = Path(directory) / "serial.log"
    path.write_bytes(b"\x1b[2JBdsDxe: loading Boot0001\r\n"
                     b"RPBEACON phase global_install\r\n"
                     b"noise \xff\xfe RPBEACON phase global_capture_running\r\n"
                     b"RPBEACON capture ::notice title=Global capture stage::global_start t=21.4\r\n"
                     b"RPBEACON capture ::error title=Global capture summary::" + SUMMARY.encode() + b"\r\n"
                     b"RPBEACON error global_capture_running System.Exception owner S-1-5-21-1-2-3-1001\r\n")
    return path


class SerialBeaconTests(unittest.TestCase):
    def test_beacons_are_extracted_in_order_without_line_endings_or_noise(self):
        with tempfile.TemporaryDirectory() as work:
            beacons = vm.serial_beacons(serial_log(work))
        self.assertEqual(beacons[:3], ["phase global_install", "phase global_capture_running",
                                       "capture ::notice title=Global capture stage::global_start t=21.4"])
        self.assertEqual(len(beacons), 5)
        self.assertFalse(any("\r" in item or "\n" in item for item in beacons))

    def test_only_the_bounded_tail_is_read(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "serial.log"
            path.write_bytes(b"RPBEACON phase early\r\n" + b"x" * 4096 + b"\r\nRPBEACON phase late\r\n")
            self.assertEqual(vm.serial_beacons(path, limit=1024), ["phase late"])
            self.assertEqual(vm.serial_beacons(Path(work) / "missing.log"), [])

    def test_printed_annotations_are_redacted_and_restore_the_harness_payload(self):
        with tempfile.TemporaryDirectory() as work, contextlib.redirect_stdout(io.StringIO()) as output:
            vm.print_serial_beacons("error", serial_log(work))
        lines = output.getvalue().splitlines()
        self.assertEqual([line.split("::")[1] for line in lines],
                         ["error title=Win11 guest serial progress", "error title=Win11 guest capture summary"])
        progress = json.loads(lines[0].split("::", 2)[2])
        self.assertEqual(progress["count"], 5)
        self.assertIn("error global_capture_running System.Exception owner [SID REDACTED]", progress["last"])
        summary = json.loads(lines[1].split("::", 2)[2].replace("%25", "%"))["payload"]
        self.assertIn('"failed_stage":"explicit_global_stop"', summary)
        self.assertIn("100% via [URL REDACTED]", summary)
        self.assertIn("[PATH REDACTED]", summary)
        self.assertNotIn("Program Files", output.getvalue())
        self.assertNotIn("S-1-5-21", output.getvalue())

    def test_missing_serial_log_still_reports_an_empty_progress_digest(self):
        with tempfile.TemporaryDirectory() as work, contextlib.redirect_stdout(io.StringIO()) as output:
            vm.print_serial_beacons("error", Path(work) / "serial.log")
        self.assertEqual(output.getvalue(),
                         '::error title=Win11 guest serial progress::{"count":0,"last":[]}\n')

    def test_nic_is_plugged_in_only_after_a_guest_beacon(self):
        class Qmp:
            calls = []

            def execute(self, command, arguments=None):
                self.calls.append((command, arguments))
                return {}
        qmp = Qmp()
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "serial.log"
            path.write_bytes(b'BdsDxe: starting Boot0003 "Windows Boot Manager"\r\n')
            self.assertFalse(vm.plug_network_after_beacon(qmp, path))
            self.assertFalse(vm.plug_network_after_beacon(qmp, Path(work) / "missing.log"))
            self.assertEqual(qmp.calls, [])
            with path.open("ab") as stream:
                stream.write(b"RPBEACON phase global_configuration\r\n")
            self.assertTrue(vm.plug_network_after_beacon(qmp, path))
        self.assertEqual(qmp.calls, [("set_link", {"name": "vmnet", "up": True})])

    def test_global_suite_keeps_the_nic_unplugged_until_the_guest_waits_for_it(self):
        source = (ROOT / ".github/windows_proxifyre_vm.py").read_text()
        self.assertIn('"-netdev", "user,id=vmnet"', source)
        self.assertIn('network_pending = suite in {"global-capture", "compartment-lab"}', source)
        self.assertLess(source.index('qmp.execute("set_link", {"name": "vmnet", "up": False})'),
                        source.index('stage("guest_installation_or_qualification_wait")'))
        script = (ROOT / ".github/windows-global-vm-run.ps1").read_text()
        self.assertLess(script.index("Write-BootstrapStep 'global_configuration'"),
                        script.index("while (-not (Test-HostReachable $hostUri))"))
        self.assertLess(script.index("while (-not (Test-HostReachable $hostUri))"), script.index("/payload.zip"))
        setup = (ROOT / ".github/windows-proxifyre-vm-setup.ps1").read_text()
        self.assertLess(setup.index("/v BypassNRO /t REG_DWORD /d 1"), setup.index("Register-ScheduledTask"))

    def test_guest_waits_for_a_quick_harness_query_before_the_timed_experiment(self):
        script = (ROOT / ".github/windows-global-vm-run.ps1").read_text()
        harness = (ROOT / ".github/check_windows_global_capture.py").read_text()
        call = script.index("    Wait-SystemSettled 600")
        self.assertLess(script.index("    Initialize-FixtureTrust (Join-Path"), script.index("Write-BootstrapStep 'global_settle'"))
        self.assertLess(script.index("Write-BootstrapStep 'global_settle'"), call)
        self.assertLess(call, script.index("Register-ScheduledTask -TaskName $captureTask"))
        probe = script[script.index("function Wait-SystemSettled"):call]
        default_nic = harness[harness.index("def default_nic"):harness.index("def nic_components")]
        for cmdlet in ("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore", "Get-NetAdapter",
                       "Get-NetIPAddress"):
            self.assertIn(cmdlet, default_nic)
            self.assertIn(cmdlet, probe)
        self.assertIn("$env:PSModulePath=Join-Path $PSHOME 'Modules'", harness)
        self.assertIn("`$env:PSModulePath=Join-Path `$PSHOME 'Modules'", probe)
        setup = (ROOT / ".github/windows-proxifyre-vm-setup.ps1").read_text()
        for policy in ("/v NoAutoUpdate /t REG_DWORD /d 1", "/v AutoDownload /t REG_DWORD /d 2"):
            self.assertLess(setup.index(policy), setup.index("Register-ScheduledTask"))

    def test_cleanup_reserve_leaves_a_positive_wait_for_the_smallest_budget(self):
        self.assertGreater(300 - vm.CLEANUP_RESERVE_SECONDS, 0)
        self.assertGreaterEqual(vm.CLEANUP_RESERVE_SECONDS, 60)

    @unittest.skipUnless(os.name == "nt", "requires actual Windows PowerShell process handles")
    def test_compartment_child_exit_status_output_and_timeout_are_observed(self):
        # Parse just the process-owner function; no VM/account/network setup runs.
        command = r'''
$ErrorActionPreference = 'Stop'
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($env:RULEPROXY_NATIVE_SCRIPT, [ref]$tokens, [ref]$errors)
if ($errors.Count -ne 0) { throw 'Compartment bootstrap PowerShell syntax error' }
$definition = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Invoke-OwnedPython' }, $true)
if ($null -eq $definition) { throw 'Missing owned-process function' }
. ([scriptblock]::Create($definition.Extent.Text))
$script:root = $env:RULEPROXY_NATIVE_TEST_ROOT
$script:result = @{}
$arguments = '-I -B "' + $env:RULEPROXY_NATIVE_WORKER + '" '
$noisy = Invoke-OwnedPython $env:RULEPROXY_NATIVE_PYTHON ($arguments + 'noise') 10 'noise'
$fast = Invoke-OwnedPython $env:RULEPROXY_NATIVE_PYTHON ($arguments + 'fast') 10 'fast'
$timer = [Diagnostics.Stopwatch]::StartNew()
$timeoutFailed = $false
try { Invoke-OwnedPython $env:RULEPROXY_NATIVE_PYTHON ($arguments + 'sleep') 1 'sleep' | Out-Null }
catch { $timeoutFailed = $true }
$timer.Stop()
$startFailed = $false
try { Invoke-OwnedPython (Join-Path $root 'missing-python.exe') '' 1 'missing' | Out-Null }
catch { $startFailed = $true }
@{noisy=$noisy; fast=$fast; timeout_failed=$timeoutFailed; timeout_seconds=$timer.Elapsed.TotalSeconds;
  start_failed=$startFailed; children=$script:result.child_processes} | ConvertTo-Json -Depth 8 -Compress
'''
        with tempfile.TemporaryDirectory(prefix="ruleproxy child with spaces ") as directory:
            worker = Path(directory) / "worker.py"
            worker.write_text("import os, sys, time\n"
                              "if sys.argv[1] == 'noise':\n"
                              " os.write(1, b'O' * 200000); os.write(2, b'E' * 200000); sys.exit(7)\n"
                              "if sys.argv[1] == 'sleep': time.sleep(30)\n", encoding="ascii")
            environment = dict(os.environ,
                RULEPROXY_NATIVE_SCRIPT=str(ROOT / ".github/windows-compartment-vm-run.ps1"),
                RULEPROXY_NATIVE_TEST_ROOT=directory, RULEPROXY_NATIVE_WORKER=str(worker),
                RULEPROXY_NATIVE_PYTHON=sys.executable)
            powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
            completed = subprocess.run([str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                                       env=environment, capture_output=True, text=True, timeout=45)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            data = json.loads(completed.stdout)
            self.assertEqual((data["noisy"], data["fast"]), (7, 0))
            self.assertEqual((Path(directory) / "noise-stdout.log").read_bytes(), b"O" * 200000)
            self.assertEqual((Path(directory) / "noise-stderr.log").read_bytes(), b"E" * 200000)
            for name in ("noise", "fast"):
                self.assertTrue(data["children"][name]["handle_captured"])
                self.assertTrue(data["children"][name]["drain_complete"])
            self.assertTrue(data["timeout_failed"])
            self.assertLess(data["timeout_seconds"], 15)
            self.assertTrue(data["children"]["sleep"]["timed_out"])
            self.assertTrue(data["children"]["sleep"]["termination_confirmed"])
            self.assertIsNone(data["children"]["sleep"]["exit_code"])
            self.assertTrue(data["start_failed"])
            self.assertIsNone(data["children"]["missing"]["exit_code"])


if __name__ == "__main__":
    unittest.main()
