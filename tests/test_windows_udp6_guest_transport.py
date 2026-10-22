"""Source parity; actual extracted PowerShell helpers have their separate Windows gate."""
import hashlib
import re
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
        part=section('Send-N0aUdp6Reports','Invoke-N0aUdp6GuestDiagnostic')
        self.assertEqual(part.count('New-N0aReportingClock'),1)
        self.assertLess(part.index('/udp6-capture-result'),part.index('/udp6-runner-flow'))
        self.assertIn('schema_version=5;udp6=$Envelope',part)
        self.assertIn('$body.Length -gt 4096',part)
        self.assertIn('$clock.ElapsedMilliseconds -lt 10000',part)
        self.assertNotIn('/n0a-result',part)
    def test_udp_same_budget_and_sticky_candidate(self):
        part=section('Invoke-N0aUdp6GuestDiagnostic','Get-N0aUdpPayloadNames')
        for text in ('$workEnd=$Deadline-20*$Frequency','windows_n0a_udp6_guest.py','public-n0a-udp6.json',
                     'if (-not $OriginalReady)','if (-not $OriginalDelivered)','$envelope.report=$value',
                     "if ($null -ne $executionFailure) { $launcher.failure=$executionFailure }"):
            self.assertIn(text,part)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('$n0aEnabled -or $udpEnabled',S)
        self.assertLess(S.index("$configuration.host_url + '/result'"),S.rindex('Invoke-N0aUdp6GuestDiagnostic'))
    def test_payload_exclusive_exact17(self):
        self.assertIn('-MemberCount 17',S)
        part=section('Get-N0aUdp6PayloadNames','Get-N0aUdp6FlowCommitment')
        for item in ('udp6/actor.exe','udp6/build-manifest.json','windows_n0a_control.py','windows_n0a_guest.py',
                     'windows_n0a_udp6.py','windows_n0a_udp6_guest.py','windows_n0a_udp6_flow.py'):self.assertIn(item,part)
        self.assertNotIn('windows_n0a_flow.py',part)
        self.assertIn("if ('n0a' -cin @($configuration.PSObject.Properties.Name) -or",S)
    def test_flow_protocol_domain_private_path(self):
        part=section('Get-N0aUdp6FlowCommitment','Send-N0aUdp6Reports')
        for text in ('N0AU6-ordinary-reports-v1',"$value.protocol -cne 'udp6'",'65537','65536',"'private-udp6'",'Get-N0aUdp6FlowCommitment $body'):
            self.assertIn(text,part)
    def test_actual_gate_has_failure_ordering_timeout_fixtures(self):
        g=(ROOT/'.github/test-windows-udp6-guest-gates.ps1').read_text()
        for text in ('FunctionDefinitionAst','work_budget_exhausted','original_transport','ReferenceEquals',
                     'ElapsedMilliseconds=10000','resultOkay=$false','prepareThrows=$true','selected_echo_observed',
                     'process_and_transport_mocked=$true'):
            self.assertIn(text,g)
        self.assertNotIn('& $source',g)
    def test_udp6_dispatch_and_actual_python_parity(self):
        self.assertIn('Invoke-N0aUdp6GuestDiagnostic $configuration $workspace $python $n0aDeadline $n0aFrequency $n0aOriginalReady $delivered',S)
        selector=S[S.index("    $udp6Present="):S.index("    $parentUdpPresent=")]
        for name in ('n0a','n0a_udp','n0a_udp_parent'):self.assertIn("'"+name+"' -cin",selector)
        self.assertIn('Get-N0aUdp6PayloadNames',selector)
        gate=(ROOT/'.github/test-windows-udp6-guest-gates.ps1').read_text()
        for text in ('fixture.f.commitment(raw)','fixture.f.encode(fixture.value())','test_windows_client_n0a_udp6_flow.py',"open(sys.argv[2],'xb')",'$sent.schema_version -eq 5'):
            self.assertIn(text,gate)
        old=(ROOT/'.github/windows_n0a_udp6_guest.py').read_text()
        for path in ('public-n0a-udp6.json','private-udp6','udp6/actor.exe'):
            self.assertIn(path,old)
    def test_all_preexisting_functions_remain_byte_identical(self):
        baseline={'Test-InstalledDriveC': '9f8a5c8d1238a54b12e55b2c1b7ed3efd3d79abd3a9947c3c4abc3e79f643474', 'Test-InstalledWindowsDirectory': '8855b056089e51d350dc4efcc8fea577b0d9fd13e4504dbeaba0cb095d346e2c', 'Get-InstalledBootGates': '31f799076877f4c0fb9fecc23df1c39acbe0518d070d1ffaa3a044dd32a188da', 'Get-ClosedEarlyDiagnostic': '625865f6fdcee03f2ab0a74ff68abdd9e17ffee37e1f08e99abfd878ad8d5dc9', 'Write-ClosedEarlyDiagnostic': '6a16a0c476e2393758b96e63684ee1ba8a0d4c7c01724c821653c863e71932b3', 'Set-ClosedResultField': '8f6214fbfceb24c6ea214629a0483bcf98791467a7ac293c10a1bd6b3c5b361b', 'Test-N0aConfiguration': '879ef24156389e001e4ec5cb3f7e78b541c77aef81f90ce9c13d7d61bb4d382b', 'Get-N0aRemainingMilliseconds': '25639c939abb87765e35d7b92e737671cd43b7a675c3db7bc71287bb1eac02b3', 'Wait-N0aOwnedChild': '1ee8a1f77e67c359cbda94ddabea77da84051fcfa16b80f3a4ecb4b0dcea0c9f', 'Write-N0aBoundedBody': 'e2262287c7ee7fb2168309fcbc2c549827e3796362e2a0eb1775800e2d8b7f66', 'Send-N0aClosedReport': '6486fcaf89f70be96e32f7dd510da925967d20758877c649d2d1aeb21556a355', 'Test-N0aCaptureConfiguration': '6041c88b5787bcaa2c121428a4c20b141035c2d257a9fe90c1765a35dfb0818f', 'Get-N0aSha256': 'b0cf380460dfaa1ef2a6279212364a757c4800f15c4e6b9785ac24fbd2141212', 'Get-N0aFlowCommitment': 'bade45119d878d27941420ac5e2fb3c783fbb216930a7e5ff4dd19330b88d10f', 'Read-N0aPrivateFlow': 'ed35d64dd3d5004e8ce0f68b602da9d7b37a0d85f3042e702ea0f9d27b9b4bb2', 'New-N0aReportingClock': 'aa32e90dea482924803c2fc39a1f386166214a0583728983bf04bd64a642563d', 'Send-N0aCaptureRequest': 'a923b927e5da2d60ebbb3d62fab4f1a14a42d2c4767739bba5aee099199eacd3', 'Invoke-N0aGuestDiagnostic': '513e40521477fb7c84c08af1609db9b849bb03de009b2cf6918fbbe2a2a35788', 'Get-N0aUdpPayloadNames': 'dd3513f28d237fa9600e60cb9fa7cca03882f46e7f2536e008d535c564e72158', 'Get-N0aUdpFlowCommitment': 'c9568dff0b8e36252b50c3ddfd71c538bdb9f7db26b358977440652fae9208e1', 'Read-N0aUdpPrivateFlow': '1433037d8ab81907f49d9a948a404a86bde2f9da92b2ec085362302989ef4f40', 'Send-N0aUdpReports': '8e456798564e95e3f7a077ef97cc51d11602936c44a0ba7594650bf1f577ffc1', 'Invoke-N0aUdpGuestDiagnostic': '2c9e76e3dd8596b5a5f69a9295aac12b3348932e4a02c574d63738b5aeead1f1', 'Test-N0aUdpParentConfiguration': '05951a4b77053aeefaa2af73aa38966639ef6ae4c32cf1937e369a19bc3d42d4', 'Get-N0aUdpParentPayloadNames': 'f6d7458a3f0fe219397b8fd863db87cbdc7836a19cea960ac6c0021b1c4b1031', 'Get-N0aUdpParentFlowCommitment': 'b51f0e0ae164cb061eba4ac377b479a129f1ef12e888f33d36e7a2204acf939f', 'Read-N0aUdpParentPrivateFlow': '2b2a7dd20277c18a8edb6f9f5877c02bdce1a93cdab3c5b3d9dc6fd544b386bb', 'Send-N0aUdpParentReports': '51d053f9b266045cccaca751b4ab88827138c31da50fd180560416f8cbc00929', 'Invoke-N0aUdpParentGuestDiagnostic': '5df07d7cfad9c8bb57a50262d92c3d3df4aec6467d44eba794e0d569955c43ce', 'Expand-CheckedStage0Zip': '6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140'}
        actual={m.group(1):hashlib.sha256(m.group(0).encode()).hexdigest() for m in re.finditer(r'^function (\S+?)(?:\(|\s).*?^}',S,re.M|re.S)}
        self.assertTrue(all(actual.get(k)==v for k,v in baseline.items()))
        self.assertEqual(set(actual)-set(baseline),{'Test-Stage0bConfiguration','Get-Stage0bPayloadNames','Test-Stage0bStagingBound','Assert-Stage0bStagingBound','Test-Stage0bPublic','Invoke-Stage0bGuestDiagnostic','Wait-Stage0bOwnedChild','ConvertFrom-Stage0bPublic','Get-N0aUdp6PayloadNames','Get-N0aUdp6FlowCommitment','Read-N0aUdp6PrivateFlow','Send-N0aUdp6Reports','Invoke-N0aUdp6GuestDiagnostic'})
if __name__=='__main__':unittest.main()
