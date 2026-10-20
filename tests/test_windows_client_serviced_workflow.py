"""Source gates only: these tests do not establish a serviced Windows runtime."""
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]

class ServicedWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.stock = (ROOT / '.github/workflows/windows-identity-stock-stage0.yml').read_text()
        self.serviced = (ROOT / '.github/workflows/windows-identity-serviced-stage0.yml').read_text()

    def test_runtime_activation_keeps_exact_scope(self):
        self.assertRegex(self.serviced, r"if: \$\{\{ (?:false|true) && github\.ref == 'refs/heads/dot/windows-isolation-proof'")
        self.assertIn("github.event_name == 'push'", self.serviced)
        self.assertIn('[identity-serviced-stage0-runtime]', self.serviced)
        self.assertNotIn('[identity-stock-stage0-runtime]', self.serviced)

    def test_recovery_source_is_unchanged(self):
        def body(text):
            return text.split("<<'REVIEWED_RECOVERY'", 1)[1].split('\n          REVIEWED_RECOVERY', 1)[0]
        self.assertEqual(body(self.stock), body(self.serviced))

    def test_budget_and_dependencies_remain_bounded(self):
        for fragment in ('timeout-minutes: 180', ' + 10500 ', '--timeout-seconds 9600',
                         '--job-deadline-epoch "$STOCK_HOST_DEADLINE"',
                         'qemu-system-x86 qemu-utils ovmf swtpm xorriso curl 7zip',
                         'artifact-ids: 11938733475', 'persist-credentials: false'):
            self.assertIn(fragment, self.serviced)
        self.assertIn('test "$remaining" -ge 9000', self.serviced)
        self.assertIn('if [ "$minutes" -gt 161 ]; then minutes=161; fi', self.serviced)
        self.assertIn('minutes * 60 - 30', self.serviced)
        self.assertNotIn('udftools', self.serviced)
        self.assertNotIn('genisoimage', self.serviced)

    def test_parse_and_units_before_native(self):
        self.assertIn("@('stage0-setup', 'stage0-run', 'update')", self.serviced)
        self.assertIn('.github/windows-identity-serviced-$name.ps1', self.serviced)
        self.assertIn('test_windows_client_serviced*.py', self.serviced)
        self.assertIn('needs: [compile, host-unit, qmp-media-gate]', self.serviced)
        self.assertIn('timeout-minutes: 5', self.serviced)
        self.assertIn('Pure Linux host tests are separate', self.serviced)
        self.assertIn('s.countTestCases() >= 7', self.serviced)
        self.assertIn('Required serviced tests missing', self.serviced)
        self.assertIn('test_windows_client_serviced_diagnostics.py', self.serviced)
        self.assertIn('run: ./.github/test-windows-identity-serviced-gates.ps1', self.serviced)

    def test_gate_only_marker_cannot_enter_native(self):
        compile_job = self.serviced.split('  compile:\n', 1)[1].split('  host-unit:\n', 1)[0]
        host_job = self.serviced.split('  host-unit:\n', 1)[1].split('  qmp-media-gate:\n', 1)[0]
        native_job = self.serviced.split('  native:\n', 1)[1]
        for job in (compile_job, host_job):
            self.assertIn('[identity-serviced-stage0-gates]', job)
            self.assertNotIn('sudo ', job)
            self.assertNotIn('REVIEWED_RECOVERY', job)
        native_condition = native_job.split('    needs:', 1)[0]
        self.assertIn('[identity-serviced-stage0-runtime]', native_condition)
        self.assertNotIn('[identity-serviced-stage0-gates]', native_condition)
        self.assertNotIn('always()', native_condition)

    def test_synthetic_qmp_gate_is_separate_and_required(self):
        job = self.serviced.split('  qmp-media-gate:\n', 1)[1].split('  native:\n', 1)[0]
        self.assertIn('[identity-serviced-stage0-gates]', job)
        self.assertIn('timeout-minutes: 5', job)
        self.assertIn('--no-install-recommends --no-remove qemu-system-x86', job)
        self.assertIn('run: python3 -B .github/test_windows_serviced_qmp.py --run-actual-qemu', job)
        self.assertNotIn('REVIEWED_RECOVERY', job)
        self.assertNotIn('windows_vm_test.py', job)
        self.assertNotIn('sudo /usr/bin/python3', job)
        self.assertIn('needs: [compile, host-unit, qmp-media-gate]', self.serviced)

    @unittest.skipUnless(sys.platform == 'linux', 'actual workflow bash gate is Linux-only')
    def test_absolute_deadline_shell_boundaries(self):
        block = self.serviced.split('          now=$(date +%s)', 1)[1].split('      - name:', 1)[0]
        block = 'now=$(date +%s)' + block
        block = '\n'.join(line.strip() for line in block.splitlines())
        self.assertEqual(block.count('date +%s'), 1)
        # Delayed entry and minute-edge values remain below the original deadline.
        for now, deadline in ((1000, 1060), (1000, 1119), (1000, 1120),
                              (1000, 20000), (10000, 10500)):
            with tempfile.NamedTemporaryFile() as output:
                command = 'set -eu; date() { echo ' + str(now) + '; };\n' + block
                result = subprocess.run(['bash', '-c', command], env={
                    'STOCK_JOB_DEADLINE': str(deadline), 'GITHUB_OUTPUT': output.name},
                    capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0)
                values = dict(line.split('=', 1) for line in Path(output.name).read_text().splitlines())
                self.assertLessEqual(int(values['deadline']), deadline)
                self.assertEqual(int(values['deadline']), now + min((deadline-now)//60, 161)*60-30)

    def test_existing_native_source_controls_are_required(self):
        compile_job = self.serviced.split('  compile:\n', 1)[1].split('  host-unit:\n', 1)[0]
        self.assertIn('run: ./.github/test-windows-identity-direct-gates.ps1', compile_job)
        self.assertIn('--run-source-token-control --actor', compile_job)
        self.assertIn('--actor-sha256 $digest', compile_job)
        self.assertIn("if ($LASTEXITCODE -ne 0)", compile_job)

    def test_only_new_runtime_host_changes(self):
        self.assertIn('sudo /usr/bin/python3 -B .github/windows_identity_serviced_stage0.py', self.serviced)
        self.assertIn('.github/windows_identity_stock_stage0.py --check-preparation', self.serviced)
        self.assertIn('windows-11-serviced-ordinary-stage0-public', self.serviced)
        self.assertNotIn('sudo /usr/bin/python3 -B .github/windows_identity_stock_stage0.py \\', self.serviced)

if __name__ == '__main__':
    unittest.main()
