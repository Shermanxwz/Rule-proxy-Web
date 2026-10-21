"""COM2 advisory source contracts; actual Windows execution is a separate CI gate."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
G=ROOT/'.github'
HELPER=(G/'windows-identity-serviced-telemetry.ps1').read_text()
UPDATE=(G/'windows-identity-serviced-update.ps1').read_text()
RUN=(G/'windows-identity-serviced-stage0-run.ps1').read_text()
SETUP=(G/'windows-identity-serviced-stage0-setup.ps1').read_text()
GATE=(G/'test-windows-identity-serviced-telemetry.ps1').read_text()

class ServicedTelemetryTests(unittest.TestCase):
    def test_separate_closed_serial(self):
        self.assertIn("SerialPort('COM2',115200)",HELPER)
        self.assertNotIn('COM1',HELPER)
        self.assertIn("$record=[ordered]@{v=1;s=$Role;p=$Stage;m=$null;n=$null;f=$null}",HELPER)
        self.assertIn('$line.Length -gt 256',HELPER)
        self.assertIn('$pending.c -is [bool] -and $pending.w -is [bool] -and $pending.r -is [bool]',HELPER)
        self.assertIn('$State.extra_reboots -is [int] -or $State.extra_reboots -is [long]',HELPER)
        self.assertIn("'report_attempt'",HELPER)
        self.assertIn("'RPBEACON",RUN.replace('"RPBEACON',"'RPBEACON"))

    def test_fixed_protected_helper_and_no_new_identity(self):
        self.assertIn("$telemetryHelper=Join-Path $protected 'windows-identity-serviced-telemetry.ps1'",SETUP)
        self.assertLess(SETUP.index('Assert-ProtectedUpdatePath $telemetryHelper'),SETUP.index('Register-ScheduledTask'))
        for source in (RUN,UPDATE):
            body=source[source.index('function Send-ServicedTelemetry'):]
            body=body[:body.index('\n}')+2]
            self.assertLess(body.index('Assert-ProtectedUpdatePath $telemetryHelper'),body.index('. $telemetryHelper'))
            self.assertIn('catch { }',body)
        for forbidden in ('Register-ScheduledTask','New-LocalUser','Set-Date','Stop-Process','taskkill','Set-ItemProperty'):
            self.assertNotIn(forbidden,HELPER)
        self.assertIn('-NoProfile -NonInteractive',HELPER)
        self.assertIn('$info.UseShellExecute=$false',HELPER)
        self.assertNotIn('-EncodedCommand',HELPER)

    def test_quota_and_same_token_owned_paths(self):
        self.assertIn("if ($Role -ceq 'system') { 20 } elseif ($Role -ceq 'ordinary') { 12 }",HELPER)
        self.assertIn('[IO.FileMode]::CreateNew',HELPER)
        self.assertIn("($Role -ceq 'ordinary' -and $system)",HELPER)
        self.assertLess(HELPER.index("throw 'telemetry_role_token'"),HELPER.index('if (-not (Reserve-TelemetrySlot $Role $root))'))
        self.assertLess(HELPER.index('if (-not (Reserve-TelemetrySlot $Role $root))'),HELPER.index('$process=Start-TelemetryChild $info'))
        self.assertEqual(HELPER.count('Reserve-TelemetrySlot $Role $root'),1)
        self.assertNotIn('Start-Sleep',HELPER)

    def test_owned_child_wait_kill_observe(self):
        self.assertIn('$Process.WaitForExit(3000)',HELPER)
        self.assertIn('$Process.WaitForExit(1000)',HELPER)
        self.assertEqual(HELPER.count('$Process.Kill()'),1)
        self.assertIn('$observed -is [bool]',HELPER)
        self.assertIn('if (-not $facts.exited -or -not $facts.disposed) { $script:TelemetryDisabled=$true }',HELPER)
        self.assertIn('$Process.Dispose()',HELPER)

    def test_telemetry_does_not_skip_restart_reserve(self):
        extra=UPDATE[UPDATE.index('function Request-ServicedExtraReboot'):UPDATE.index('function Invoke-ServicedUpdate')]
        self.assertLess(extra.index("'extra_reboot_before'"),extra.rindex('Assert-ServicedRestartReserve $Deadline'))
        self.assertLess(extra.rindex('Assert-ServicedRestartReserve $Deadline'),extra.index('Restart-Computer'))
        self.assertIn("Send-ServicedTelemetry 'system' 'initial_reboot_before' $state\n        Assert-ServicedTime $serviceDeadline\n        Restart-Computer",UPDATE)
        for stage in ('entry','prior_valid','media_verified','initial_reboot_before','initial_reboot_returned','extra_reboot_before','extra_reboot_returned','completed','failed'):
            self.assertIn("'system' '"+stage+"'",UPDATE)
        for stage in ('entry','service_wait','report_attempt'):
            self.assertIn("'ordinary' '"+stage+"'",RUN)

    def test_sender_outcomes_and_actual_child_entry_seam(self):
        self.assertIn('$exitCode=$Process.ExitCode',HELPER)
        self.assertLess(HELPER.index('$exitCode=$Process.ExitCode'),HELPER.index('$Process.Dispose()'))
        self.assertIn('$facts.timed_out=(-not $observed)',HELPER)
        self.assertIn('$script:TelemetryCounters[0]',HELPER)
        self.assertIn('Get-ClosedSenderCounters',RUN)
        self.assertIn("Set-ClosedResultField 'sender_stats' ($systemSenders+$ordinarySenders)",RUN)
        self.assertIn('$TelemetryState.sender_stats=Get-TelemetryCounters',UPDATE)
        for text in ('Unique telemetry child entry required','Actual telemetry child entry failed','Actual child telemetry stream parity failed','guards_substituted','serial_sink_substituted','Natural exit sender counters failed','Invalid sender counters accepted'):
            self.assertIn(text,GATE)
        self.assertIn('if($created -and $cleanupOk)',GATE)
        self.assertIn("assert facts['records']==expected",GATE)

    def test_real_windows_gate_has_negative_and_cleanup_controls(self):
        for text in ('foreach ($mask in 0..7)', 'Telemetry unknown leaked','Telemetry invalid frame accepted','Telemetry quota exceeded','Durable exhausted quota launched child','Spawn failure refunded durable quota','SYSTEM ordinary role touched quota path','host.parse_progress(line)','Telemetry untrusted write accepted',"@('exit','hang')",'$observer.WaitForExit(1000)','actual_child_timeout_kill=$true','serial_hardware_tested=$false','Telemetry fixture cleanup boundary'):
            self.assertIn(text,GATE)
        self.assertNotIn("Write-TelemetryPort $line",GATE)

if __name__=='__main__':unittest.main()
