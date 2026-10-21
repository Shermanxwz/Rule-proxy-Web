"""Parent-only PS branch contracts; native Windows helper execution remains separate."""
import hashlib
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
S=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
G=(ROOT/'.github/test-windows-udp-parent-guest-gates.ps1').read_text()
def part(a,b):return S[S.index('function '+a):S.index('function '+b)]
class ParentTransportTests(unittest.TestCase):
    def test_original_finally_extractor_preserved(self):
        final=S[S.index('} finally {\n    if ($failed'):S.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(),'7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extraction=S[S.index('function Expand-CheckedStage0Zip {'):S.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extraction.encode()).hexdigest(),'6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
    def test_new_branch_strict_config_and_22_exactmembers(self):
        cfg=part('Test-N0aUdpParentConfiguration','Get-N0aUdpParentPayloadNames')
        for name in ('parent_sha256','parent_manifest_sha256','parent_source_sha256','child_sha256','child_manifest_sha256','child_source_sha256','identity_source_sha256','executor_sha256'):
            self.assertIn(name,cfg)
        for fragment in ('-isnot [bool]','-isnot [int]','-isnot [long]','Properties).Count -ne $keys.Count'):
            self.assertIn(fragment,cfg)
        selector=S[S.index("    $parentUdpPresent="):S.index("    $phase='payload_extract'")]
        self.assertIn("'n0a' -cin",selector);self.assertIn("'n0a_udp' -cin",selector)
        for n in (10,14,15,17,22):self.assertIn('-MemberCount '+str(n),S)
        names=part('Get-N0aUdpParentPayloadNames','Get-N0aUdpParentFlowCommitment')
        self.assertIn('Get-N0aUdpPayloadNames',names)
        for name in ('parent/actor.exe','parent/build-manifest.json','windows_n0a_udp_parent_control.py','windows_n0a_udp_parent_guest.py','windows_n0a_udp_parent_flow.py'):self.assertIn(name,names)
        self.assertNotIn('TEST_ONLY',names)
    def test_payload_paths_link_actual_guest_adapter(self):
        guest=(ROOT/'.github/windows_n0a_udp_parent_guest.py').read_text()
        for fragment in ("ROOT/'parent/actor.exe'", "ROOT/'parent/build-manifest.json'", "ROOT/'udp/actor.exe'", "ROOT/'private-parent-udp/runner-flow.json'", "ROOT/'public-n0a-udp-parent.json'"):
            self.assertIn(fragment,guest)
        self.assertNotIn("ROOT/'udp-parent/",guest)
    def test_parent_transport_schema_order_and_budget(self):
        send=part('Send-N0aUdpParentReports','Invoke-N0aUdpParentGuestDiagnostic')
        self.assertEqual(send.count('New-N0aReportingClock'),1)
        self.assertIn('schema_version=4;parent_udp=$Envelope',send)
        self.assertLess(send.index('/udp-parent-capture-result'),send.index('/udp-parent-runner-flow'))
        for value in ('$body.Length -gt 4096','$clock.ElapsedMilliseconds -lt 10000'):
            self.assertIn(value,send)
        call=part('Invoke-N0aUdpParentGuestDiagnostic','Expand-CheckedStage0Zip')
        for value in ('$workEnd=$Deadline-20*$Frequency','parent_sha256=$Configuration.n0a_udp_parent.parent_sha256','child_sha256=$Configuration.n0a_udp_parent.child_sha256','windows_n0a_udp_parent_guest.py','public-n0a-udp-parent.json','$envelope.report=$value'):
            self.assertIn(value,call)
        self.assertNotIn('actor_sha256=',call)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('$n0aEnabled -or $udpEnabled -or $parentUdpEnabled',S)
    def test_pair_commitments_and_actual_crosslanguage_gate(self):
        body=part('Get-N0aUdpParentFlowCommitment','Send-N0aUdpParentReports')
        for fragment in ('N0AUP-ordinary-v1','N0AUP-contained-v1',"'udp-parent'","@('parent_source','child_source')",'8192','32768','65536','65537',"'private-parent-udp'"):
            self.assertIn(fragment,body)
        for fragment in ('module.commitment(raw)','windows_n0a_udp_parent_flow.py','ReferenceEquals','ElapsedMilliseconds=10000','prepareThrows=$true','original_transport','work_budget_exhausted','schema_version -eq 4','process_and_transport_mocked=$true'):
            self.assertIn(fragment,G)
        self.assertNotIn('& $source',G)
if __name__=='__main__':unittest.main()
