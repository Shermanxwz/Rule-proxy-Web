from pathlib import Path
import unittest
G=Path(__file__).resolve().parents[1]/'.github'
RUN=(G/'windows-identity-serviced-stage0-run.ps1').read_text()
UPDATE=(G/'windows-identity-serviced-update.ps1').read_text()
GATE=(G/'test-windows-identity-serviced-receipt.ps1').read_text()
class ReceiptSnapshotTests(unittest.TestCase):
    def test_only_exact_io_sharing_is_retried(self):
        self.assertIn('$current -is [IO.IOException] -and $current.HResult -eq -2147024864',RUN)
        self.assertIn('$depth -lt 4',RUN)
        self.assertIn('$attempt -lt 4',RUN)
        self.assertIn('Test-ServicedReceiptSharing $_.Exception',RUN)
        self.assertIn('[Math]::Min(100,[Math]::Floor($remaining))',RUN)
        self.assertNotIn('-band 0xffff',RUN)
    def test_trusted_bounded_open_handle_snapshot(self):
        body=RUN[RUN.index('function Read-ServicedReceiptSnapshot'):RUN.index('function Get-ClosedSenderCounters')]
        for text in ('Assert-ProtectedUpdatePath ([IO.Path]::GetDirectoryName($Path)) -Directory -ProtectedDacl','Assert-ProtectedUpdatePath $Path','[IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete','$stream.Length -gt 4096','New-Object byte[] 4097','$total -gt 4096','Text.UTF8Encoding($false,$true)','$stream.Dispose()'):
            self.assertIn(text,body)
        self.assertGreaterEqual(body.count('[DateTime]::UtcNow -ge $Deadline'),2)
        self.assertNotIn('AddSeconds',body)
        self.assertIn('$rawService=Read-ServicedReceiptSnapshot $statePath $servicingDeadline',RUN)
        self.assertIn('$service=$rawService | ConvertFrom-Json',RUN)
        self.assertIn('[IO.File]::Replace($temporary,$path',UPDATE)
    def test_actual_windows_two_process_and_negative_fixtures(self):
        for text in ("Start-ReceiptFixtureChild 'lock'","Start-ReceiptFixtureChild 'stress'",'Write-ServicedState @{','Get-Content -LiteralPath $path -Raw','[IO.FileShare]::None','Exclusive holder baseline not reproduced','Concurrent mixed receipt accepted','Sharing retry extended deadline',"'oversize','utf8','json','expired','acl'",'ordinary_token_tested=$false','receipt_snapshot_cleanup','Valid 4096-byte receipt rejected','Actual denied read classification failed','if($created -and $cleanup)','$timer.ElapsedMilliseconds -gt 2000','$boundedFailure='):
            self.assertIn(text,GATE)
        for text in ("$fixtureStep='snapshot'", "$fixtureStep='json'", "$fixtureStep='validate'", "$childStep='writer_call'", 'New-Object byte[] 257', 'child_exit_code=$childExitCode', 'read_step=$readStep', 'temporary_exists=', 'adjacent, non-atomic'):
            self.assertIn(text,GATE)
        self.assertIn('$info.RedirectStandardError=$true',GATE)
        self.assertNotIn('ReadToEnd()',GATE)
if __name__=='__main__':unittest.main()
