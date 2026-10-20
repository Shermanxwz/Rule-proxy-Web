"""Source-contract checks only; real Windows PS parsing/runtime remain separate gates."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GITHUB = ROOT / '.github'
SETUP = (GITHUB / 'windows-identity-serviced-stage0-setup.ps1').read_text()
RUN = (GITHUB / 'windows-identity-serviced-stage0-run.ps1').read_text()
UPDATE = (GITHUB / 'windows-identity-serviced-update.ps1').read_text()

class ServicedGuestContractTests(unittest.TestCase):
    def test_worker_is_protected_and_not_user_workspace(self):
        self.assertIn("$protected='C:\\RuleProxyCIUpdates'", SETUP)
        self.assertIn('$acl.SetAccessRuleProtection($true,$false)', SETUP)
        self.assertIn("$users,'ReadAndExecute'", SETUP)
        self.assertLess(SETUP.index('Set-Acl -LiteralPath $protected'), SETUP.index('Copy-Item -LiteralPath (Join-Path'))
        self.assertLess(SETUP.index('Assert-ProtectedUpdatePath $worker'), SETUP.index('Register-ScheduledTask'))
        self.assertIn("-UserId 'SYSTEM' -LogonType ServiceAccount", SETUP)
        self.assertIn('-MultipleInstances IgnoreNew', SETUP)
        self.assertIn('Start-ScheduledTask -TaskName $script:UpdateTaskName', SETUP)

    def test_no_accounts_or_extra_policy(self):
        for content in (SETUP, RUN, UPDATE):
            for forbidden in ('New-LocalUser', 'net user', 'Set-ExecutionPolicy', 'IgnoreCheck', 'DisableRealtimeMonitoring'):
                # A warning comment mentioning IgnoreCheck is not an argument.
                self.assertNotIn("'/' + 'IgnoreCheck'", content)
                if forbidden != 'IgnoreCheck': self.assertNotIn(forbidden, content)
        self.assertEqual(SETUP.count('reg.exe add'), 2)

    def test_media_is_optical_and_exact_pinned_two_members(self):
        self.assertIn("-Filter 'DriveType=5'", UPDATE)
        self.assertIn("$_.VolumeName -ceq 'RULEPROXY_UPDATE'", UPDATE)
        self.assertIn('if ($opticalDrives.Count -ne 1)', UPDATE)
        self.assertIn('if ($items.Count -ne 2)', UPDATE)
        self.assertIn("filename='windows11.0-kb5043080-x64.msu'; bytes=533761740L", UPDATE)
        self.assertIn("filename='windows11.0-kb5127648-x64.msu'; bytes=4775050195L", UPDATE)
        for digest in ('819632610a101af11c72907fb13ff05b5fb4222c0e263ee9a03bcc1d1d5f26a4',
                       '8a1067c763121953876e2e0dcbf5e2c5832545a44ef6baba362938287e05fcfb'):
            self.assertIn(digest, UPDATE)
        self.assertIn('(Get-ServicedOpticalRoot) -cne $Root', UPDATE)

    def test_no_guest_package_download_or_copy(self):
        for forbidden in ('DownloadFile', 'HttpWebRequest', 'Copy-Item', 'Save-UpdatePackage', 'Stage-UpdatePackages'):
            self.assertNotIn(forbidden, UPDATE)
        self.assertIn('$packagePath=Join-Path $optical $script:Packages[1].filename', UPDATE)
        self.assertIn("'/Online','/Add-Package'", UPDATE)

    def test_forced_reboot_before_completion_even_exit_zero(self):
        self.assertIn('$state.dism_exit_code -notin @(0,3010)', UPDATE)
        self.assertIn("$state.status='reboot_pending'", UPDATE)
        self.assertIn('Restart-Computer -Force', UPDATE)
        self.assertIn('$state.after_boot -ceq $state.before_boot', UPDATE)
        self.assertIn('Get-CimInstance -ClassName Win32_OperatingSystem', UPDATE)
        self.assertIn('$state.actual_ubr -ne 9711', UPDATE)
        self.assertNotIn('$os.ubr -ge', UPDATE)
        self.assertIn('if (Test-ServicedPendingReboot)', UPDATE)
        self.assertLess(UPDATE.index('Unregister-ScheduledTask'), UPDATE.index("$state.status='completed'"))
        self.assertIn("Get-ScheduledTask | Where-Object", UPDATE)

    def test_installed_stock_beacon_after_required_gate(self):
        beacon = RUN.index('RPBEACON identity-stock-installed-ready')
        for marker in ("$gates.product_winnt=($Facts.product -ceq 'WinNT')",
                       "$gates.arch_amd64=($Facts.architecture -ceq 'AMD64')",
                       "$gates.fixed_drive=($null -ne $Facts.drive_type -and $Facts.drive_type -eq 3)",
                       "$gates.image_complete=($Facts.image -ceq 'IMAGE_STATE_COMPLETE')",
                       "if ([int]$bootVersion.UBR -eq 6584)"):
            self.assertLess(RUN.index(marker), beacon)
        self.assertLess(RUN.index('$service.task_unregistered -ne $true'), RUN.index('RPBEACON identity-ordinary-ready'))

    def test_ordinary_acceptance_waits_protected_receipt_and_reboot(self):
        self.assertIn('Assert-ProtectedUpdatePath $statePath', RUN)
        self.assertIn('$item.Length -gt 4096', RUN)
        self.assertIn('$service.after_boot -cne $bootOS.LastBootUpTime', RUN)
        self.assertIn('$service.before_boot -ceq $service.after_boot', RUN)
        self.assertIn('$service.reboot_observed -ne $true', RUN)
        self.assertLess(RUN.index('$service.task_unregistered -ne $true'), RUN.index("$phase='claim'"))
        self.assertIn('windows_identity_serviced_stage0.py', RUN)
        self.assertNotIn('windows_identity_stock_stage0.py', RUN)
        self.assertIn('-MemberCount 10', RUN)

    def test_public_projection_never_exports_boot_identity(self):
        final = RUN[RUN.index("$serviceFacts=@{"):]
        self.assertNotIn('before_boot', final)
        self.assertNotIn('after_boot', final)
        self.assertIn("Set-ClosedResultField 'servicing_diagnostic' $serviceFacts", final)
        self.assertIn("$state.failure=if ($message -cin $allowed)", UPDATE)
        self.assertNotIn('error_detail', UPDATE)
        self.assertIn('ConvertTo-Json -Depth 10 -Compress', RUN)


    def test_early_failure_serial_is_closed_and_before_http(self):
        self.assertIn("'RPDIAG1 '+$json", RUN)
        self.assertIn('ASCII.GetByteCount($json) -gt 2048', RUN)
        self.assertIn("if ($failed -and -not $earlyBootGateCompleted) {", RUN)
        self.assertLess(RUN.index('try { Write-ClosedEarlyDiagnostic'), RUN.index('for ($i=0; $i -lt 3; $i++)'))
        self.assertIn("$phase='installed_setup_wait'", RUN)
        self.assertIn('AddSeconds(120)', RUN)
        self.assertIn("$failureCategory='installed_setup_deadline'", RUN)
        self.assertNotRegex(UPDATE, r'(?i)\$matches\s*=')
        self.assertNotRegex(UPDATE, r'(?i)\$error\s*=')

    def test_actual_windows_branch_harness_exists(self):
        test=(GITHUB / 'test-windows-identity-serviced-gates.ps1').read_text()
        self.assertIn("'C:\\WINDOWS'", test)
        self.assertIn('Invalid directory accepted', test)
        self.assertIn('Invalid synthetic gates accepted', test)
        self.assertIn('Optical root regex regression', test)
        self.assertIn('Ambiguous optical root accepted', test)
        self.assertIn('runtime_acceptance=$false', test)

    def test_wire_parity_uses_owned_ascii_file_not_native_stdin(self):
        test=(GITHUB / 'test-windows-identity-serviced-gates.ps1').read_text()
        self.assertIn('with open(sys.argv[2], encoding="ascii") as wire_file:', test)
        self.assertIn('rows=json.load(wire_file)', test)
        self.assertIn('assert len(rows)==11', test)
        self.assertIn("if ($wireRecords.Count -ne 11)", test)
        self.assertNotIn('json.load(sys.stdin)', test)
        self.assertNotIn('| & python', test)
        self.assertEqual(test.count('[IO.FileMode]::CreateNew'), 2)
        for name in ('wire', 'parity'):
            self.assertIn('$'+name+'Owned=$true', test)
            self.assertIn('if ($'+name+'Owned) { Remove-Item -LiteralPath $'+name+'Path -Force }', test)
        self.assertIn('[Text.Encoding]::ASCII.GetBytes($wireJson)', test)
        self.assertIn('if ($wireBytes.Length -eq 0)', test)

    def test_wire_hresult_has_typed_boundary_and_rejection_cases(self):
        test=(GITHUB / 'test-windows-identity-serviced-gates.ps1').read_text()
        self.assertIn('-HResult ([int]-2146233087)', test)
        self.assertNotIn('-HResult -2146233087', test)
        for marker in ('[int]::MinValue', '[int]::MaxValue', '[long]-2147483649',
                       '[long]2147483648', "value='-2146233087'", '[double]-2146233087',
                       'value=$true', 'value=$null', 'Wire HRESULT value or JSON numeric type changed'):
            self.assertIn(marker, test)

    def test_guest_deadline_is_seed_bound_protected_and_never_reset(self):
        self.assertIn("Join-Path $PSScriptRoot 'service-budget.json'", SETUP)
        self.assertIn('$hostDeadline=ConvertTo-ServicedDeadline', SETUP)
        self.assertIn('$serviceDeadline=$now.AddMinutes(110)', SETUP)
        self.assertIn('if ($serviceDeadline -gt $hostDeadline)', SETUP)
        self.assertIn('Assert-ProtectedUpdatePath $budgetPath', SETUP)
        self.assertIn('-Minutes 110', SETUP)
        self.assertIn('$serviceDeadline=Get-ServicedDeadline', UPDATE)
        self.assertIn('$servicingDeadline=Get-ServicedDeadline', RUN)
        self.assertNotIn('AddMinutes(80)', RUN)
        self.assertNotIn('AddMinutes(110)', UPDATE)
        self.assertIn('AddMinutes(45)', UPDATE)
        self.assertIn('if ($mediaDeadline -gt $serviceDeadline)', UPDATE)
        self.assertIn('if ($setupDeadline -gt $serviceDeadline)', UPDATE)
        self.assertIn('[Math]::Min(40*60*1000,($serviceDeadline-', UPDATE)
        self.assertIn('Wait-ServicedDism $process $dismMilliseconds $state', UPDATE)
        self.assertNotIn('$Process.Kill()', UPDATE)
        self.assertIn('$State.dism_exit_observation_available=$true', UPDATE)
        self.assertIn("'service_deadline'", UPDATE)
        self.assertIn("'service_deadline'", RUN)
        gate=(GITHUB / 'test-windows-identity-serviced-gates.ps1').read_text()
        self.assertIn('ConvertTo-ServicedDeadline ([long]($fixedEpoch+$offset))', gate)
        self.assertIn('Invalid or expired deadline accepted', gate)
        self.assertIn('Assert-ServicedTime ([DateTime]::UtcNow.AddSeconds(-1))', gate)
        for source in (RUN, UPDATE):
            function=source[source.index('function Get-ServicedDeadline'):]
            function=function[:function.index('\n}')+2]
            self.assertNotIn('AddMinutes', function)
            self.assertNotIn('Write', function)
            self.assertIn('Assert-ProtectedUpdatePath $path', function)
        self.assertLess(UPDATE.index('Assert-ServicedMedia $optical'), UPDATE.index('$process=Start-Process'))


if __name__ == '__main__': unittest.main()
