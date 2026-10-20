"""Direct 26300.9457 is exploratory only; source gates do not prove runtime."""
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
class DirectWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text=(ROOT/'.github/workflows/windows-identity-direct-stage0.yml').read_text()
    def test_exact_experimental_scope_and_no_automatic_native(self):
        self.assertIn("github.ref == 'refs/heads/dot/windows-isolation-proof'",self.text)
        self.assertIn("github.event_name == 'push'",self.text)
        self.assertIn('[identity-direct-stage0-gates]',self.text)
        native=self.text.split('  native:\n',1)[1].split('    needs:',1)[0]
        self.assertIn('[identity-direct-stage0-runtime]',native)
        self.assertNotIn('[identity-direct-stage0-gates]',native)
        self.assertNotIn('always()',native)
        self.assertNotIn('[identity-serviced-stage0-runtime]',self.text)
    def test_recovery_bytes_and_pins_unchanged(self):
        old=(ROOT/'.github/workflows/windows-identity-stock-stage0.yml').read_text()
        def body(t):return t.split("<<'REVIEWED_RECOVERY'",1)[1].split('\n          REVIEWED_RECOVERY',1)[0]
        self.assertEqual(body(old),body(self.text))
        self.assertIn('artifact-ids: 11938733475',self.text)
        self.assertIn('530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553',self.text)
    def test_same_fixed_budgets_and_dependencies(self):
        for value in ('timeout-minutes: 120',' + 6900 ','--timeout-seconds 6600','needs: [compile, host-unit]',
            'qemu-system-x86 qemu-utils ovmf swtpm xorriso curl 7zip','persist-credentials: false'):
            self.assertIn(value,self.text)
        self.assertNotIn('qmp-media-gate:',self.text)
    def test_required_parse_semantic_and_linux_gates(self):
        self.assertIn("@('stage0-setup', 'stage0-run')",self.text)
        self.assertIn('run: ./.github/test-windows-identity-direct-gates.ps1',self.text)
        self.assertIn('test_windows_client_direct*.py',self.text)
        self.assertIn('not r.wasSuccessful() or bool(r.skipped)',self.text)
        self.assertIn('Required direct tests missing',self.text)
        self.assertIn('s.countTestCases() >= 7',self.text)
    def test_pure_jobs_never_run_vm_or_recovery(self):
        pure=self.text.split('jobs:\n',1)[1].split('  native:\n',1)[0]
        self.assertNotIn('sudo ',pure)
        self.assertNotIn('REVIEWED_RECOVERY',pure)
        self.assertNotIn('--approved-disposable-vm',pure)
    def test_bounded_source_token_negative_control_after_compile(self):
        self.assertIn('--run-source-token-control',self.text)
        self.assertIn('.Trim().ToLowerInvariant()',self.text)
        self.assertIn('test_windows_client_direct_actor_projection.py',self.text)
        self.assertLess(self.text.index('Compile the pinned zero-network native actor'),self.text.index('Source-token actor projection negative control'))
        self.assertLess(self.text.index('Source-token actor projection negative control'),self.text.index('Pure unit tests, not Windows runtime acceptance'))
        control=self.text.split('      - name: Source-token actor projection negative control',1)[1].split('      - name:',1)[0]
        self.assertIn('timeout-minutes: 1',control)
        self.assertNotIn('upload-artifact',control)
    def test_direct_host_only_and_label(self):
        self.assertIn('exploratory below support floor',self.text)
        self.assertIn('sudo /usr/bin/python3 -B .github/windows_identity_direct_stage0.py',self.text)
        self.assertNotIn('sudo /usr/bin/python3 -B .github/windows_identity_serviced_stage0.py',self.text)
        self.assertIn('windows-11-direct-ordinary-stage0-public',self.text)
        self.assertNotIn('windows-identity-direct-update.ps1',self.text)
if __name__=='__main__':unittest.main()
