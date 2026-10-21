"""Publication boundaries for standalone N0a-connect gates, never a VM."""
import hashlib
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github/workflows/windows-n0a-connect-gates.yml'


class N0aWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding='utf-8')

    def test_only_two_explicit_branch_marker_jobs(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$', self.text.split('jobs:', 1)[1], re.M), ['host-unit', 'native-fixture'])
        self.assertEqual(self.text.count("contains(github.event.head_commit.message, '[n0a-connect-gates]')"), 2)
        self.assertEqual(self.text.count("github.ref == 'refs/heads/dot/windows-isolation-proof'"), 2)
        self.assertNotIn('workflow_dispatch:', self.text)
        self.assertNotIn('pull_request', self.text)
        self.assertNotIn('schedule:', self.text)

    def test_standard_small_jobs_and_no_upload_or_runtime(self):
        self.assertIn('runs-on: windows-2025', self.text)
        self.assertIn('runs-on: ubuntu-24.04', self.text)
        self.assertIn('timeout-minutes: 8', self.text)
        self.assertIn('timeout-minutes: 5', self.text)
        self.assertNotIn('actions/upload-artifact', self.text)
        self.assertNotIn('windows_identity_direct_stage0.py', self.text)
        self.assertNotIn('windows_identity_serviced_stage0.py', self.text)
        self.assertNotIn('continue-on-error', self.text)
        self.assertNotIn('sudo ', self.text)
        self.assertIn('cancel-in-progress: false', self.text)

    def test_fixture_is_distinct_and_explicitly_opted_in(self):
        self.assertIn('n0a-production-build/windows_n0a_actor.exe', self.text)
        self.assertIn('n0a-TEST-ONLY-build/windows_n0a_TEST_ONLY_fixture.exe', self.text)
        self.assertIn('TEST-ONLY-manifest.json', self.text)
        self.assertIn('--run-owned-loopback-fixtures', self.text)
        self.assertIn('$fixture.deployable', self.text)
        self.assertIn('$production.testOnly', self.text)

    def test_source_hash_pins_match_exact_files(self):
        for filename in ('windows_n0a_actor.cpp', 'windows_identity_actor.cpp', 'windows_n0a_fixture.cpp'):
            digest = hashlib.sha256((ROOT / '.github/native' / filename).read_bytes()).hexdigest()
            self.assertIn(digest, self.text)

    def test_required_tests_cannot_pass_zero_or_skips(self):
        for name in ('test_windows_n0a_actor.py', 'test_windows_client_n0a_control.py', 'test_windows_n0a_workflow.py'):
            self.assertEqual(self.text.count("'" + name + "'"), 2)
            self.assertTrue((ROOT / 'tests' / name).is_file())
        self.assertEqual(self.text.count('suite.countTestCases()>=30'), 2)
        self.assertEqual(self.text.count('bool(result.skipped)'), 2)
        self.assertEqual(self.text.count('persist-credentials: false'), 2)
        self.assertIn('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }', self.text)


if __name__ == '__main__':
    unittest.main()
