"""Scoped source contracts; actual PS execution is a separate Windows gate."""
import hashlib
import pathlib
import unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN = (ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
class N0aGuestContracts(unittest.TestCase):
    def test_original_finally_and_extraction_unchanged(self):
        final = RUN[RUN.index('} finally {\n    if ($failed'):RUN.index('\n# Original Stage0 delivery above')]
        self.assertEqual(hashlib.sha256(final.encode()).hexdigest(), '7e10be5db5c65d9c7b18cd10004d15f1be9339bdd4a3c10ceb5a2abd721cdb2b')
        extraction = RUN[RUN.index('function Expand-CheckedStage0Zip {'):RUN.index('\ntry {\n    $configuration')]
        self.assertEqual(hashlib.sha256(extraction.encode()).hexdigest(), '6e754133def219c06d5a6f3d96b5a5d88640383f9da6c62e889313df7c519140')
    def test_optional_payload_and_deadline(self):
        self.assertIn('-MemberCount 14', RUN)
        self.assertIn('-MemberCount 10', RUN)
        self.assertIn('$child.WaitForExit(120000)', RUN)
        self.assertEqual(RUN.count('$n0aDeadline=$now+120*$n0aFrequency'), 1)
        self.assertIn('$workEnd=$Deadline-20*$Frequency', RUN)
        self.assertIn('--deadline-qpc ', RUN)
        self.assertIn('--qpc-frequency ', RUN)
    def test_independent_result_order(self):
        self.assertLess(RUN.index("$configuration.host_url + '/result'"), RUN.rindex('[void](Invoke-N0aGuestDiagnostic'))
        self.assertEqual(RUN.count("$configuration.host_url + '/result'"),1)
        self.assertIn("$Configuration.host_url+'/n0a-result'",RUN)
        self.assertIn("if (-not $OriginalReady)",RUN)
        self.assertIn("if (-not $OriginalDelivered)",RUN)
        self.assertIn("$launcher.failure='work_budget_exhausted'",RUN)
    def test_separate_closed_limits(self):
        self.assertIn('$Body.Length -gt 4096',RUN)
        self.assertIn('$body.Length -gt 16384',RUN)
        self.assertIn('$request.AllowAutoRedirect=$false',RUN)
        self.assertIn('$waitCompleted=$true',RUN)
        self.assertIn('if ($started -and -not $waitCompleted)',RUN)
        self.assertNotIn('TEST_ONLY', RUN)
    def test_gate_extracts_only_helpers(self):
        text=(ROOT/'.github/test-windows-n0a-guest-gates.ps1').read_text()
        self.assertIn('FunctionDefinitionAst', text)
        self.assertNotIn('& $source',text)
        self.assertIn('work_budget_exhausted',text)
if __name__=='__main__': unittest.main()
