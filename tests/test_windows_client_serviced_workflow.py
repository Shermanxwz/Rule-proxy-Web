"""Source gates only: these tests do not establish a serviced Windows runtime."""
from pathlib import Path
import unittest

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
        for fragment in ('timeout-minutes: 120', ' + 6900 ', '--timeout-seconds 6600',
                         '--job-deadline-epoch "$STOCK_HOST_DEADLINE"',
                         'qemu-system-x86 qemu-utils ovmf swtpm xorriso curl 7zip',
                         'artifact-ids: 11938733475', 'persist-credentials: false'):
            self.assertIn(fragment, self.serviced)
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

    def test_only_new_runtime_host_changes(self):
        self.assertIn('sudo /usr/bin/python3 -B .github/windows_identity_serviced_stage0.py', self.serviced)
        self.assertIn('.github/windows_identity_stock_stage0.py --check-preparation', self.serviced)
        self.assertIn('windows-11-serviced-ordinary-stage0-public', self.serviced)
        self.assertNotIn('sudo /usr/bin/python3 -B .github/windows_identity_stock_stage0.py \\', self.serviced)

if __name__ == '__main__':
    unittest.main()
