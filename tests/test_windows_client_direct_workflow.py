"""Direct 26300.9457 is exploratory only; source gates do not prove runtime."""
from pathlib import Path
import unittest
import ast
import importlib.util
import json
import os
import tempfile
import textwrap
from types import SimpleNamespace
from unittest.mock import patch
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
    def test_no_provider_deletion_and_pins_unchanged(self):
        for forbidden in ('REVIEWED_RECOVERY','execute-reviewed-recovery','provider_cache_recovery',
                          'reviewed.py','identity-stock-recovery','direct-provider-recovery-public'):
            self.assertNotIn(forbidden,self.text)
        self.assertIn('artifact-ids: 11938733475',self.text)
        self.assertIn('530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553',self.text)
        code=self.preflight()
        calls={node.func.attr if isinstance(node.func,ast.Attribute) else node.func.id
               for node in ast.walk(ast.parse(code)) if isinstance(node,ast.Call)
               and isinstance(node.func,(ast.Attribute,ast.Name))}
        self.assertEqual(calls,{'Path','mkdir','stat','disk_usage','write_text','dumps','SystemExit'})
        self.assertIn('exist_ok=False',code)
        self.assertIn('direct-capacity-preflight-public',self.text)
        self.assertLess(self.text.index('Read-only provider capacity admission'),self.text.index('Observe preparation baseline'))
        native=self.text.split('  native:\n',1)[1]
        self.assertLess(native.index('Read-only provider capacity admission'),native.index('actions/checkout@v5'))

    def preflight(self):
        return textwrap.dedent(self.text.split("<<'READ_ONLY_CAPACITY'\n",1)[1].split('          READ_ONLY_CAPACITY',1)[0])

    def baseline(self):
        block=self.text.split('      - name: Observe preparation baseline',1)[1]
        return textwrap.dedent(block.split("<<'PY'\n",1)[1].split('          PY',1)[0])

    def test_actual_preflight_capacity_edges_and_filesystem(self):
        required=32*1024**3+512*1024**2
        for free,same in ((required-1,True),(required,True),(required+1,True),(required+1,False)):
            with self.subTest(free=free,same=same), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary);workspace=root/'workspace';workspace.mkdir()
                actual_stat=Path.stat
                def observed_stat(path,*args,**kwargs):
                    value=actual_stat(path,*args,**kwargs)
                    return SimpleNamespace(st_dev=value.st_dev+1) if not same and path==workspace else value
                with patch.dict(os.environ,{'RUNNER_TEMP':str(root),'GITHUB_WORKSPACE':str(workspace)}), \
                     patch('shutil.disk_usage',return_value=SimpleNamespace(free=free)), \
                     patch.object(Path,'stat',observed_stat):
                    if free>=required and same: exec(compile(self.preflight(),'<capacity>','exec'),{})
                    else:
                        with self.assertRaises(SystemExit): exec(compile(self.preflight(),'<capacity>','exec'),{})
                report=json.loads((root/'identity-direct-capacity/public.json').read_text())
                self.assertEqual(report['status'],'admitted' if free>=required and same else 'insufficient_capacity')
                self.assertEqual(report['required_free_bytes'],required)
                self.assertEqual(report['observed_free_bytes'],free)
                self.assertEqual(report['same_filesystem'],same)
                for field in ('provider_changes','provider_deletion_attempted','recovery_performed'):
                    self.assertIs(report[field],False)
                self.assertEqual(list(workspace.iterdir()),[])

    def test_actual_baseline_consumed_by_unchanged_stock_and_direct_helpers(self):
        required=32*1024**3+512*1024**2
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);workspace=root/'workspace';workspace.mkdir()
            environment=root/'env';environment.write_text('')
            with patch.dict(os.environ,{'RUNNER_TEMP':str(root),'GITHUB_WORKSPACE':str(workspace),'GITHUB_ENV':str(environment)}), \
                 patch('shutil.disk_usage',return_value=SimpleNamespace(free=required)),patch('sys.version_info',(3,12,0)):
                exec(compile(self.preflight(),'<capacity>','exec'),{})
                exec(compile(self.baseline(),'<baseline>','exec'),{})
            baseline=root/'identity-direct-capacity/preparation-public.json'
            self.assertIn('STOCK_PREP_DEVICE_ID='+str(workspace.stat().st_dev),environment.read_text())
            for route in ('stock','direct'):
                spec=importlib.util.spec_from_file_location('baseline_'+route,ROOT/f'.github/windows_identity_{route}_stage0.py')
                module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
                result=module.preparation_record(baseline)
                self.assertEqual(result['baseline_free_bytes'],required)
                self.assertEqual(result['minimum_free_bytes'],32*1024**3)
                self.assertEqual(result['allowance_bytes'],512*1024**2)
                self.assertEqual(result['samples'],[{'phase':'before_checkout','free_bytes':required,'net_decline_bytes':0}])

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
        self.assertIn('sudo "${capture_source_args[@]}" /usr/bin/python3 -B .github/windows_identity_direct_stage0.py',self.text)
        self.assertIn('capture_source_args=()',self.text)
        self.assertNotIn('sudo /usr/bin/python3 -B .github/windows_identity_serviced_stage0.py',self.text)
        self.assertIn('windows-11-direct-ordinary-stage0-public',self.text)
        self.assertNotIn('windows-identity-direct-update.ps1',self.text)
if __name__=='__main__':unittest.main()
