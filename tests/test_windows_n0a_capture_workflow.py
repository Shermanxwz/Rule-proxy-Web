"""Closed publication boundary for the standalone capture mechanism gate."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

class CaptureWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / '.github/workflows/windows-n0a-capture-gates.yml').read_text()

    def allowed(self, message, branch='refs/heads/dot/windows-isolation-proof', event='push'):
        source = self.text.split('if: ${{', 1)[1].split('}}', 1)[0].strip()
        source = re.sub(r"contains\(github.event.head_commit.message, '([^']+)'\)",
                        lambda m: str(m.group(1) in message), source)
        source = source.replace('github.ref', repr(branch)).replace('github.event_name', repr(event)).replace('&&', ' and ')
        tree = ast.parse(source, mode='eval')
        self.assertTrue(all(isinstance(n, (ast.Expression, ast.BoolOp, ast.Compare,
            ast.Constant, ast.And, ast.Eq, ast.Load)) for n in ast.walk(tree)))
        return eval(compile(tree, '<capture-trigger>', 'eval'), {'__builtins__': {}}, {})

    def test_exact_trigger_truth_table(self):
        self.assertTrue(self.allowed('[n0a-capture-gates]'))
        for marker in ('unrelated', '[n0a-connect-runtime]', '[identity-direct-stage0-runtime]', '[n0a-connect-gates]'):
            self.assertFalse(self.allowed(marker))
        self.assertFalse(self.allowed('[n0a-capture-gates]', branch='refs/heads/main'))
        self.assertFalse(self.allowed('[n0a-capture-gates]', event='workflow_dispatch'))
        self.assertNotIn('workflow_dispatch:', self.text)
        self.assertNotIn('pull_request:', self.text)

    def test_bounded_standard_readonly_job_no_deployment(self):
        self.assertEqual(re.findall(r'^  ([a-z][a-z-]+):$', self.text.split('jobs:', 1)[1], re.M), ['capture-mechanism'])
        self.assertIn('runs-on: ubuntu-24.04', self.text)
        self.assertIn('timeout-minutes: 8', self.text)
        self.assertIn('contents: read', self.text)
        self.assertIn('persist-credentials: false', self.text)
        self.assertIn('--no-install-recommends --no-remove qemu-system-x86', self.text)
        for forbidden in ('actions/upload-artifact', 'actions/download-artifact', 'windows_identity_direct_stage0.py', 'windows_identity_serviced_stage0.py', 'continue-on-error', 'secrets.', 'workflow_dispatch:'):
            self.assertNotIn(forbidden, self.text)

    def test_actual_opt_in_and_required_no_skip_units(self):
        self.assertIn('python3 -B .github/test_windows_n0a_capture_qemu.py --run-actual-qemu', self.text)
        self.assertIn('python3 -B .github/test_windows_n0a_capture_child_qemu.py --run-actual-qemu', self.text)
        for name in ('test_windows_client_n0a_capture.py', 'test_windows_n0a_capture_qemu.py', 'test_windows_n0a_capture_workflow.py', 'test_windows_client_n0a_capture_child.py', 'test_windows_client_n0a_packet.py', 'test_windows_n0a_capture_child_qemu.py'):
            self.assertIn("'" + name + "'", self.text)
        self.assertIn('all(p.countTestCases()>0 for p in parts)', self.text)
        self.assertIn('bool(result.skipped)', self.text)
        self.assertIn("assert all((pathlib.Path('tests')/n).is_file() for n in names)", self.text)

if __name__ == '__main__':
    unittest.main()
