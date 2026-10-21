"""Publication boundaries for standalone N0a-connect gates, never a VM."""
import ast
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
        self.assertNotIn('python3 -B .github/windows_identity_direct_stage0.py', self.text)
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
        for name in ('test_windows_n0a_actor.py', 'test_windows_client_n0a_control.py', 'test_windows_n0a_workflow.py', 'test_windows_client_n0a_adapter.py', 'test_windows_client_n0a_host.py', 'test_windows_n0a_guest.py', 'test_windows_client_direct_stage0.py', 'test_windows_client_direct_guest.py', 'test_windows_client_direct_actor_projection.py', 'test_windows_client_direct_workflow.py'):
            self.assertEqual(self.text.count("'" + name + "'"), 2)
            self.assertTrue((ROOT / 'tests' / name).is_file())
        self.assertEqual(self.text.count('suite.countTestCases()>=43'), 2)
        self.assertEqual(self.text.count('bool(result.skipped)'), 2)
        self.assertEqual(self.text.count('all(p.countTestCases()>0 for p in parts)'), 2)
        self.assertEqual(self.text.count('persist-credentials: false'), 2)
        self.assertIn('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }', self.text)


class N0aDirectWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/windows-identity-direct-stage0.yml').read_text()

    def native_allowed(self, message, branch='refs/heads/dot/windows-isolation-proof', event='push'):
        expression = self.text.split('  native:',1)[1].split('if: ${{',1)[1].split('}}',1)[0].strip()
        expression = re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",
                            lambda m: str(m.group(1) in message), expression)
        expression = expression.replace('github.ref', repr(branch)).replace('github.event_name', repr(event))
        expression = re.sub(r'\btrue\b','True',expression)
        expression = re.sub(r'\bfalse\b','False',expression)
        expression = expression.replace('&&',' and ').replace('||',' or ').replace('!',' not ')
        tree=ast.parse(expression.strip(), mode='eval')
        self.assertTrue(all(isinstance(node,(ast.Expression,ast.BoolOp,ast.UnaryOp,ast.Compare,ast.Constant,
            ast.And,ast.Or,ast.Not,ast.Eq,ast.Load)) for node in ast.walk(tree)))
        return eval(compile(tree,'<actual-workflow-if>','eval'), {'__builtins__':{}}, {})

    def test_actual_native_condition_truth_table(self):
        self.assertTrue(self.native_allowed('[identity-direct-stage0-runtime]'))
        for message in ('unrelated','[identity-direct-stage0-gates]','[n0a-connect-gates]',
                        '[n0a-connect-runtime]', '[identity-direct-stage0-runtime] [n0a-connect-runtime]'):
            self.assertFalse(self.native_allowed(message),message)
        self.assertFalse(self.native_allowed('[identity-direct-stage0-runtime]', branch='refs/heads/main'))
        self.assertFalse(self.native_allowed('[identity-direct-stage0-runtime]', event='workflow_dispatch'))

    def test_optional_artifact_matches_actual_host_output(self):
        source = (ROOT / '.github/windows_identity_direct_stage0.py').read_text()
        names = {node.value for node in ast.walk(ast.parse(source))
                 if isinstance(node, ast.Constant) and isinstance(node.value, str)
                 and node.value.startswith('n0a-') and node.value.endswith('.json')}
        self.assertEqual(names, {'n0a-connect-public.json'})
        self.assertIn('path: client-stage0-public/' + next(iter(names)), self.text)

    def test_production_upload_disabled_and_fixture_excluded(self):
        step=self.text.split('name: n0a-connect-production-actor',1)[0].rsplit('- uses: actions/upload-artifact@v7',1)[1]
        self.assertIn("false && contains(github.event.head_commit.message, '[n0a-connect-runtime]')",step)
        self.assertIn('n0a-production-build/windows_n0a_actor.exe',self.text)
        self.assertIn('n0a-production-build/build-manifest.json',self.text)
        self.assertNotIn('TEST_ONLY',self.text)
        self.assertNotIn('TEST-ONLY',self.text)
        self.assertNotIn('build_windows_n0a_fixture',self.text)
        self.assertIn('timeout-minutes: 120',self.text)
        self.assertIn('--timeout-seconds 6600',self.text)
        self.assertIn('Read-only provider capacity admission, never cache deletion',self.text)


if __name__ == '__main__':
    unittest.main()
