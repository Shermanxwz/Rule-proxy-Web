"""Closed Stage0b dispatch and source invariants; actual PS gate is Windows-only."""
import ast
import hashlib
import importlib.util
from pathlib import Path
import re
import unittest
ROOT=Path(__file__).resolve().parents[1]
S=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
def part(name):return re.search(r'^function '+re.escape(name)+r'(?:\(|\s).*?^}',S,re.M|re.S).group()
class TransportTests(unittest.TestCase):
    def test_exact_fourteen_additions_and_exclusion(self):
        names=set(re.findall("'([^']+)'",part('Get-Stage0bPayloadNames')))
        self.assertEqual(names,{'.github/windows_identity_pipe_probe.py','.github/windows_identity_ordinary_launcher.py','ruleproxy/windows_app_process.py','.github/windows_identity_stage0b_guest.py'})
        selector=S[S.index('    $stage0bPresent='):S.index('    $udp6Present=')]
        for name in ('n0a','capture','n0a_udp','n0a_udp_parent','n0a_udp6'):self.assertIn("'"+name+"'",selector)
        self.assertIn('Assert-Stage0bStagingBound $payload',S)
        self.assertIn('-MemberCount 14 -ExactBytes 0 -MaximumBytes 134217728',S)
    def test_same_original_deadline_and_clipped_cleanup(self):
        p=part('Invoke-Stage0bGuestDiagnostic');w=part('Wait-Stage0bOwnedChild')
        self.assertIn('$workEnd=$Deadline',p);self.assertNotIn('$Deadline-',p);self.assertNotIn('120*',p)
        self.assertIn('Wait-Stage0bOwnedChild $process $workEnd $Frequency',p)
        self.assertEqual(S.count('$n0aDeadline=$now+120*$n0aFrequency'),1)
        self.assertIn('Get-N0aRemainingMilliseconds $Deadline $Frequency',w)
        self.assertNotIn('WaitForExit(5000)',w)
        self.assertIn('--deadline-qpc',p);self.assertIn('--qpc-frequency',p)
        self.assertIn('Invoke-Stage0bGuestDiagnostic $configuration $workspace $python $n0aDeadline $n0aFrequency $n0aOriginalReady $delivered',S)
    def test_original_result_finalizer_and_extractor(self):
        final=S[S.index('} finally {\n    if ($failed'):S.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(),'7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extraction=S[S.index('function Expand-CheckedStage0Zip {'):S.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extraction.encode()).hexdigest(),'6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
    def test_actual_schema_parity_and_no_observation_erasure(self):
        spec=importlib.util.spec_from_file_location('stage0b_ps_schema',ROOT/'.github/windows_identity_stage0b_guest.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        p=part('Test-Stage0bPublic')
        booleans=set(re.findall("'([^']+)'",p.split('$booleans=@(',1)[1].split(')',1)[0]))
        self.assertEqual(booleans,set(m.BOOL_FIELDS))
        self.assertTrue(all("'"+x+"'" in p for x in m.FAILURES))
        inv=part('Invoke-Stage0bGuestDiagnostic')
        self.assertEqual(inv.count('$envelope.stage0b=$value'),1)
        self.assertNotIn('$envelope.stage0b=$null',inv)
        self.assertIn("'/stage0b-result'",inv);self.assertIn('Send-N0aClosedReport',inv)
        self.assertIn('4097',inv);self.assertIn('$body.Length -gt 4096',inv)
    def test_actual_windows_gate_uses_production_ast_and_mocks(self):
        gate=(ROOT/'.github/test-windows-stage0b-guest-gates.ps1').read_text()
        for text in ('FunctionDefinitionAst','m.default_public','m.validate_public','Test-Stage0bPublic','Invoke-Stage0bGuestDiagnostic','Wait-Stage0bOwnedChild','process_and_transport_mocked=$true','original_transport','work_budget_exhausted','case_nonce_sha256','--deadline-qpc '):self.assertIn(text,gate)
        self.assertNotIn('& $source',gate)
        self.assertIn('[IO.Directory]::Delete($root,$false)',gate)
if __name__=='__main__':unittest.main()
