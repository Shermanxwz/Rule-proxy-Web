"""The short client-OS experiment cannot become a product/GUI qualification."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_global_capture_vm", ROOT / ".github/windows_proxifyre_vm.py")
vm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vm)


def evidence():
    identity = {"tested_source_commit": "a" * 40,
        "source_sha256": {name: "b" * 64 for name in vm.GLOBAL_SOURCE_IDENTITIES},
        "harness_sha256": "c" * 64}
    expected_guid = str(vm.uuid.UUID(bytes_le=vm.hashlib.md5(b"wintunRuleProxyTun").digest()))
    capture = {"mode": "disposable_windows_native_capture", "passed": True, "strict_qualified": False,
        "raw_capture_exported": False, "ipv6_public_egress_qualified": False, "dns_qualified": False,
        "rdp_qualified": False, "ipv4_physical_scope_passed": True, "tun_tcp_udp_v4_v6_passed": True,
        "explicit_global_stop": True, "system_core_carrier_http": True, "recovery": {"recovered": True},
        "ipv6_scoped_action": {"passed": True}, "tun_identity": {"identity_matches": True, "start_guard_tun_ready": True,
            "alias": "RuleProxyTun", "interface_guid": expected_guid, "expected_guid": expected_guid,
            "interface_index": 14, "luid": 1583296743997440, "native_qualified": False},
        "guard_after_service_death": {"active": True, "persistent": True}, "windows_build": [10, 0, 26200],
        "fixed_core_sha256": "d" * 64, "guard_source_sha256": "b" * 64}
    capture["phases"] = {name: {"tcp_syn": int(name.startswith("outside")), "udp_marker": int(name.startswith("outside")),
        "packets_parsed": 2, "captures": [{"component": 3, "sha256": "f" * 64, "bytes": 128}],
        "actor": {protocol: {"executed": True, "socket_ok": False, "stage": "connect" if protocol == "tcp" else "send",
                             "error": 10060} for protocol in ("tcp", "udp")}}
        for name in ("outside_before", "running_guard", "core_dead", "service_stopped", "outside_after")}
    capture["components"] = {"capture_components": [3]}
    for phase in capture["phases"].values():
        phase["declared_components"], phase["etl_count"] = [3], 1
        phase["components"] = {"3": {key: phase[key] for key in ("tcp_syn", "udp_marker", "packets_parsed")}}
        phase["components"]["3"]["captures"] = [{"sha256": "f" * 64, "bytes": 128}]
        phase["capture_loss_verified"] = True
        phase["capture_diagnostics"] = {"declared_components": [3], "component_results": phase["components"],
            "buffer_info": {"events_lost": 0, "buffers_lost": 0}, "restore": {"stopped": True,
                "cli_metadata": {"stop": {"final_events_lost": 0, "log_parent_is_private_run_directory": True,
                                           "log_matches_owned_prefix": True}}}}
    capture["tun_echo"] = {family: {protocol: {"executed": True, "socket_ok": True, "stage": "send", "received_echo": True}
        for protocol in ("tcp", "udp")} for family in ("4", "6")}
    capture["synthetic_node_counts"] = {protocol + family: 1 for family in ("4", "6") for protocol in ("tcp", "udp")}
    return {"suite": "global-capture", "status": "passed", "exit_code": 0,
        "user_cleanup_confirmed": True, "task_cleanup_confirmed": True, "installation_cleanup_confirmed": True,
        "os": {"product_type": "WinNT", "native_architecture": "AMD64", "build": 26200},
        "owner": {"sid": "S-1-5-21-1-2-3-1001", "elevated": True, "sid_matches_installation": True},
        "package": {"manifest_verified": True, "sha256": "e" * 64, "fixed_core_sha256": "d" * 64},
        "source_identity": identity, "reports": {"global_capture": capture}}


class GlobalCaptureVMTests(unittest.TestCase):
    def verify(self, value):
        return vm.verify_global_result(value, package_sha256="e" * 64, source_identity=evidence()["source_identity"])

    def test_bounded_capture_pass_does_not_satisfy_product_gui_qualification(self):
        value = evidence()
        self.assertIs(self.verify(value), value["reports"]["global_capture"])
        with self.assertRaises(RuntimeError):
            vm.verify_result(value, package_sha256="e" * 64)

    def test_os_owner_package_and_checkout_must_match(self):
        for key, field, bad in (("os", "product_type", "ServerNT"), ("os", "build", 21999),
                ("os", "native_architecture", "ARM64"), ("owner", "elevated", 1),
                ("owner", "sid_matches_installation", False), ("owner", "sid", "S-1-5-18"),
                ("package", "sha256", "f" * 64), ("source_identity", "harness_sha256", "f" * 64)):
            with self.subTest(key=key, field=field):
                value = evidence()
                value[key][field] = bad
                with self.assertRaises(RuntimeError):
                    self.verify(value)

    def test_missing_stage_or_cleanup_cannot_report_success(self):
        for field in ("user_cleanup_confirmed", "task_cleanup_confirmed", "installation_cleanup_confirmed"):
            for bad in (None, 1, False):
                value = evidence()
                value[field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(RuntimeError):
                    self.verify(value)
        for stage, field in (("recovery", "recovered"), ("tun_identity", "identity_matches"),
                             ("tun_identity", "start_guard_tun_ready"), ("guard_after_service_death", "persistent")):
            value = evidence()
            value["reports"]["global_capture"][stage].pop(field)
            with self.subTest(stage=stage, field=field), self.assertRaises(RuntimeError):
                self.verify(value)

    def test_capture_cannot_claim_unmeasured_qualification_or_export_raw_packets(self):
        for field in ("strict_qualified", "ipv6_public_egress_qualified", "dns_qualified", "rdp_qualified",
                      "raw_capture_exported"):
            value = evidence()
            value["reports"]["global_capture"][field] = True
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.verify(value)
        value = evidence()
        value["reports"]["global_capture"]["task_cleanup_errors"] = ["unconfirmed"]
        with self.assertRaises(RuntimeError):
            self.verify(value)

    def test_partial_true_flags_cannot_replace_physical_controls_or_executed_denials(self):
        for name in ("outside_before", "running_guard", "core_dead", "service_stopped", "outside_after"):
            for field, bad in (("tcp_syn", 0 if name.startswith("outside") else 1), ("captures", [])):
                value = evidence()
                value["reports"]["global_capture"]["phases"][name][field] = bad
                with self.subTest(name=name, field=field), self.assertRaises(RuntimeError):
                    self.verify(value)
            value = evidence()
            value["reports"]["global_capture"]["phases"][name]["actor"]["tcp"].update(stage="bind", executed=False)
            with self.subTest(name=name, field="actor"), self.assertRaises(RuntimeError):
                self.verify(value)
        value = evidence()
        value["reports"]["global_capture"]["phases"]["running_guard"]["tcp_syn"] = False
        with self.assertRaises(RuntimeError):
            self.verify(value)

    def test_tun_echo_requires_all_protocol_receivers_and_real_interface_identity(self):
        for family in ("4", "6"):
            for protocol in ("tcp", "udp"):
                value = evidence()
                value["reports"]["global_capture"]["tun_echo"][family][protocol]["received_echo"] = False
                with self.subTest(family=family, protocol=protocol), self.assertRaises(RuntimeError):
                    self.verify(value)
                value = evidence()
                value["reports"]["global_capture"]["synthetic_node_counts"][protocol + family] = 0
                with self.subTest(family=family, protocol=protocol, missing="receiver"), self.assertRaises(RuntimeError):
                    self.verify(value)
        for field, bad in (("interface_guid", "00000000-0000-0000-0000-000000000000"),
                           ("expected_guid", "00000000-0000-0000-0000-000000000000"),
                           ("interface_index", 0), ("luid", True)):
            value = evidence()
            value["reports"]["global_capture"]["tun_identity"][field] = bad
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.verify(value)

    def test_all_declared_component_etl_pairs_are_required_and_independently_zero(self):
        value = evidence()
        report = value["reports"]["global_capture"]
        report["components"]["capture_components"] = [3, 11]
        for phase in report["phases"].values():
            phase["declared_components"] = [3, 11]
            phase["components"]["11"] = {"tcp_syn": 0, "udp_marker": 0, "packets_parsed": 0,
                "captures": [{"sha256": "f" * 64, "bytes": 128}]}
            phase["captures"].append({"component": 11, "sha256": "f" * 64, "bytes": 128})
            phase["capture_diagnostics"]["declared_components"] = [3, 11]
        self.verify(value)
        phase = report["phases"]["running_guard"]
        phase["components"]["11"]["udp_marker"] = 1
        with self.assertRaises(RuntimeError):
            self.verify(value)
        phase["components"]["11"]["udp_marker"] = 0
        phase["components"]["11"]["captures"].clear()
        with self.assertRaises(RuntimeError):
            self.verify(value)

    def test_etw_unknown_or_nonzero_loss_cannot_be_hidden_by_verified_boolean(self):
        for field in ("events_lost", "buffers_lost"):
            for bad in (None, 1, False):
                value = evidence()
                value["reports"]["global_capture"]["phases"]["running_guard"]["capture_diagnostics"]["buffer_info"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(RuntimeError):
                    self.verify(value)
        value = evidence()
        value["reports"]["global_capture"]["phases"]["running_guard"]["capture_diagnostics"]["restore"]["cli_metadata"]["stop"]["final_events_lost"] = 1
        with self.assertRaises(RuntimeError):
            self.verify(value)

    def test_four_components_times_four_etls_accepts_exactly_bound_sixteen_receipts(self):
        value = evidence()
        report = value["reports"]["global_capture"]
        declared = [3, 11, 13, 17]
        report["components"]["capture_components"] = declared
        for phase in report["phases"].values():
            phase["declared_components"], phase["etl_count"] = declared, 4
            for component in declared:
                row = phase["components"].setdefault(str(component),
                    {"tcp_syn": 0, "udp_marker": 0, "packets_parsed": 0})
                row["captures"] = [{"sha256": "f" * 64, "bytes": 128} for _ in range(4)]
            phase["captures"] = [{"component": component, **row} for component in declared
                for row in phase["components"][str(component)]["captures"]]
            phase["capture_diagnostics"]["declared_components"] = declared
        self.verify(value)
        report["phases"]["running_guard"]["components"].pop("17")
        with self.assertRaises(RuntimeError):
            self.verify(value)

    def test_payload_includes_non_python_source_for_three_way_hash_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            package, payload = Path(directory) / "package.zip", Path(directory) / "payload.zip"
            package.write_bytes(b"offline fixture")
            vm.make_payload(package, payload, include_global_sources=True)
            with zipfile.ZipFile(payload) as archive:
                self.assertTrue(vm.GLOBAL_SOURCE_IDENTITIES.issubset(archive.namelist()))
                self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
                self.assertEqual(archive.read("web/app.js"), (ROOT / "web/app.js").read_bytes())

    def test_product_payload_includes_only_the_required_shared_native_proxy_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            package, payload = Path(directory) / "package.zip", Path(directory) / "payload.zip"
            package.write_bytes(b"offline fixture")
            vm.make_payload(package, payload)
            with zipfile.ZipFile(payload) as archive:
                helper = "tests/test_windows_native_proxy.py"
                self.assertEqual({name for name in archive.namelist() if name.startswith("tests/")}, {helper})
                self.assertEqual(archive.read(helper), (ROOT / helper).read_bytes())

    def test_global_cancel_keeps_product_and_capture_qualification_false(self):
        with tempfile.TemporaryDirectory() as directory:
            args = SimpleNamespace(suite="global-capture", artifacts=Path(directory), timeout_seconds=1800)
            with mock.patch.object(vm.media, "require_kvm", side_effect=vm.QualificationInterrupted(signal.SIGTERM)), \
                    mock.patch.object(vm, "cleanup_owned", return_value=[]):
                value = vm.run(args)
            self.assertEqual(value["status"], "cancelled")
            self.assertIs(value["native_windows_11_product_passed"], False)
            self.assertIs(value["native_windows_11_global_capture_passed"], False)
            self.assertIs(value["gui_verified"], False)

    @unittest.skipUnless(os.name == "nt", "requires native Windows PowerShell parser")
    def test_global_guest_and_embedded_owner_scripts_parse_without_execution(self):
        command = r'''
$errors=$null; $tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:RP_GLOBAL_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$embedded=$ast.Find({param($node) $node -is [Management.Automation.Language.StringConstantExpressionAst] -and $node.Value.Contains('Highest owner token required')},$true)
if ($null -eq $embedded) { throw 'Missing owner script' }
$null=[Management.Automation.Language.Parser]::ParseInput($embedded.Value,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
'''
        result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            env={**os.environ, "RP_GLOBAL_SCRIPT": str(ROOT / ".github/windows-global-vm-run.ps1")},
            capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def _native_helper_prelude(self):
        # Import only the helper/diagnostic definitions from the exact guest
        # source. Never execute its account, installer, task or network code.
        return r'''
$ErrorActionPreference='Stop'
$errors=$null; $tokens=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:RP_GLOBAL_SCRIPT,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Invoke-BoundedScript','Protect-DiagnosticText','Read-DiagnosticTail','Export-GlobalDiagnostics')) {
    $definition=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true)
    if ($null -eq $definition) { throw ('Missing helper: ' + $name) }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$root=$env:RP_GLOBAL_HELPER_ROOT
$powershell=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:result=@{logs=@{}}
$script:passwordText='SyntheticHelperSecretQ7!'
$script:configuration=[pscustomobject]@{host_url='http://127.0.0.1:12345/private-test-capability'}
'''

    @unittest.skipUnless(os.name == "nt", "requires native Windows child-process and PowerShell handles")
    def test_native_helper_retains_real_zero_and_seventeen_exit_codes_and_separate_redacted_logs(self):
        command = self._native_helper_prelude() + r'''
$zero=Join-Path $root 'zero spaced 脚本.ps1'
$nonzero=Join-Path $root 'nonzero spaced.ps1'
[IO.File]::WriteAllText($zero,'[Console]::Out.WriteLine("SETUP-OUT SyntheticHelperSecretQ7!"); [Console]::Error.WriteLine("SETUP-ERR"); exit 0')
[IO.File]::WriteAllText($nonzero,'[Console]::Out.WriteLine("UNINSTALL-OUT"); [Console]::Error.WriteLine("UNINSTALL-ERR http://127.0.0.1:12345/private-test-capability/result"); exit 17')
Invoke-BoundedScript $zero '' 10 'setup'
if ($script:result.child_scripts.setup.exit_code -isnot [int] -or $script:result.child_scripts.setup.exit_code -ne 0) { throw 'Real exit zero was not retained' }
$refused=$false
try { Invoke-BoundedScript $nonzero '' 10 'uninstall' }
catch {
    if ($_.Exception.Message -notmatch 'uninstall failed or requires reboot: 17') { throw }
    $refused=$true
}
if (-not $refused -or $script:result.child_scripts.uninstall.exit_code -ne 17) { throw 'Real exit seventeen was accepted or lost' }
Export-GlobalDiagnostics
foreach ($name in @('setup','uninstall')) {
    $receipt=$script:result.child_scripts[$name]
    if (-not $receipt.handle_captured -or -not $receipt.exited -or -not $receipt.drain_complete) { throw 'Incomplete held-process receipt' }
}
$logs=$script:result.logs.tests
foreach ($marker in @('SETUP-OUT','SETUP-ERR','UNINSTALL-OUT','UNINSTALL-ERR','[PASSWORD REDACTED]')) {
    if (-not $logs.Contains($marker)) { throw ('Missing independent log: ' + $marker) }
}
if ($logs.Contains('SyntheticHelperSecretQ7!') -or $logs.Contains('private-test-capability')) { throw 'Private child diagnostic escaped redaction' }
if ($logs.Length -gt 5*131072+512) { throw 'Exported log tails exceeded bound' }
@{zero=$script:result.child_scripts.setup.exit_code; nonzero=$script:result.child_scripts.uninstall.exit_code; redacted=$true}|ConvertTo-Json -Compress
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                env={**os.environ, "RP_GLOBAL_SCRIPT": str(ROOT / ".github/windows-global-vm-run.ps1"),
                     "RP_GLOBAL_HELPER_ROOT": directory}, capture_output=True, text=True, timeout=35)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout.strip()), {"zero": 0, "nonzero": 17, "redacted": True})

    @unittest.skipUnless(os.name == "nt", "requires native Windows child-process and PowerShell handles")
    def test_native_helper_timeout_terminates_owned_child_and_never_invents_exit_zero(self):
        command = self._native_helper_prelude() + r'''
$slow=Join-Path $root 'slow child.ps1'
[IO.File]::WriteAllText($slow,'Start-Sleep -Seconds 30; exit 0')
$timer=[Diagnostics.Stopwatch]::StartNew()
$refused=$false
try { Invoke-BoundedScript $slow '' 1 'timeout' }
catch {
    if ($_.Exception.Message -notmatch 'exceeded its deadline') { throw }
    $refused=$true
}
$timer.Stop()
$receipt=$script:result.child_scripts.timeout
if (-not $refused -or -not $receipt.timed_out -or -not $receipt.handle_captured -or -not $receipt.termination_confirmed -or -not $receipt.exited) { throw 'Timeout did not stop the held child' }
if ($null -ne $receipt.exit_code -or $timer.Elapsed.TotalSeconds -gt 15) { throw 'Timeout invented success or cleanup exceeded its bound' }
@{timed_out=$true; exit_code=$receipt.exit_code; terminated=$receipt.termination_confirmed}|ConvertTo-Json -Compress
'''
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
                env={**os.environ, "RP_GLOBAL_SCRIPT": str(ROOT / ".github/windows-global-vm-run.ps1"),
                     "RP_GLOBAL_HELPER_ROOT": directory}, capture_output=True, text=True, timeout=25)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout.strip()), {"timed_out": True, "exit_code": None, "terminated": True})
