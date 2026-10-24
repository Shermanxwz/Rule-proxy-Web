"""Source parity; actual extracted PowerShell helpers have their separate Windows gate."""
import hashlib
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
S=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
def section(name,next_name):return S[S.index('function '+name):S.index('function '+next_name)].rstrip()
class TransportTests(unittest.TestCase):
    def test_original_finally_extractor_unchanged(self):
        final=S[S.index('} finally {\n    if ($failed'):S.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(),'7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extraction=S[S.index('function Expand-CheckedStage0Zip {'):S.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extraction.encode()).hexdigest(),'6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
    def test_udp_routes_clock_and_bounds(self):
        part=section('Send-N0aUdpReports','Invoke-N0aUdpGuestDiagnostic')
        self.assertEqual(part.count('New-N0aReportingClock'),1)
        self.assertLess(part.index('/udp-capture-result'),part.index('/udp-runner-flow'))
        self.assertIn('schema_version=3;udp=$Envelope',part)
        self.assertIn('$body.Length -gt 4096',part)
        self.assertIn('$clock.ElapsedMilliseconds -lt 10000',part)
        self.assertNotIn('/n0a-result',part)
    def test_udp_same_budget_and_sticky_candidate(self):
        part=section('Invoke-N0aUdpGuestDiagnostic','Expand-CheckedStage0Zip')
        for text in ('$workEnd=$Deadline-20*$Frequency','windows_n0a_udp_guest.py','public-n0a-udp.json',
                     'if (-not $OriginalReady)','if (-not $OriginalDelivered)','$envelope.report=$value',
                     "if ($null -ne $executionFailure) { $launcher.failure=$executionFailure }"):
            self.assertIn(text,part)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('$n0aEnabled -or $udpEnabled',S)
        self.assertLess(S.index("$configuration.host_url + '/result'"),S.rindex('Invoke-N0aUdpGuestDiagnostic'))
    def test_payload_exclusive_exact17(self):
        self.assertIn('-MemberCount 17',S)
        part=section('Get-N0aUdpPayloadNames','Get-N0aUdpFlowCommitment')
        for item in ('udp/actor.exe','udp/build-manifest.json','windows_n0a_control.py','windows_n0a_guest.py',
                     'windows_n0a_udp.py','windows_n0a_udp_guest.py','windows_n0a_udp_flow.py'):self.assertIn(item,part)
        self.assertNotIn('windows_n0a_flow.py',part)
        self.assertIn("if ('n0a' -cin @($configuration.PSObject.Properties.Name) -or",S)
    def test_flow_protocol_domain_private_path(self):
        part=section('Get-N0aUdpFlowCommitment','Send-N0aUdpReports')
        for text in ('N0AU-ordinary-reports-v1',"$value.protocol -cne 'udp'",'65537','65536',"'private-udp'",'Get-N0aUdpFlowCommitment $body'):
            self.assertIn(text,part)
    def test_actual_gate_has_failure_ordering_timeout_fixtures(self):
        g=(ROOT/'.github/test-windows-udp-guest-gates.ps1').read_text()
        for text in ('FunctionDefinitionAst','work_budget_exhausted','original_transport','ReferenceEquals',
                     'ElapsedMilliseconds=10000','resultOkay=$false','prepareThrows=$true','selected_echo_observed',
                     'process_and_transport_mocked=$true'):
            self.assertIn(text,g)
        self.assertNotIn('& $source',g)
if __name__=='__main__':unittest.main()
