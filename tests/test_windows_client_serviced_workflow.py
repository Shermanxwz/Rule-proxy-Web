"""Source gates only: these tests do not establish a serviced Windows runtime."""
from pathlib import Path
import unittest
import subprocess
import sys
import tempfile
import os
import json
from types import SimpleNamespace
from unittest.mock import patch

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

    def test_advisory_sender_gates_are_required_without_native_activation(self):
        self.assertIn("@('stage0-setup', 'stage0-run', 'update', 'telemetry')", self.serviced)
        self.assertIn('run: ./.github/test-windows-identity-serviced-telemetry.ps1', self.serviced)
        for name in ('telemetry', 'progress', 'progress_qmp'):
            self.assertIn(f"'test_windows_client_serviced_{name}.py'", self.serviced)
            self.assertIn(f'test -f tests/test_windows_client_serviced_{name}.py', self.serviced)
        self.assertIn('test_windows_serviced_progress_qmp.py --run-actual-qemu --output', self.serviced)
        self.assertIn('briefly runs packaged firmware', self.serviced)
        native=self.serviced.split('  native:', 1)[1]
        condition=native.split('if:',1)[1].split('\n',1)[0]
        self.assertIn('[identity-serviced-stage0-runtime]', condition)
        self.assertNotIn('[identity-serviced-stage0-gates]', condition)

    def test_provider_cleanup_is_absent(self):
        self.assertNotIn('REVIEWED_RECOVERY', self.serviced)
        self.assertNotIn('--execute-reviewed-recovery', self.serviced)
        self.assertNotIn('provider_cache_recovery', self.serviced)
        self.assertNotIn('serviced-provider-recovery-public', self.serviced)
        self.assertIn('serviced-capacity-preflight-public', self.serviced)
        self.assertIn('if [ "$minutes" -gt 2 ]; then minutes=2; fi', self.serviced)
        self.assertIn('--execute-reviewed-recovery', self.stock)  # other path untouched

    def test_actual_readonly_capacity_script_boundaries_and_owned_report(self):
        body = self.serviced.split("<<'READ_ONLY_CAPACITY'",1)[1].split('\n          READ_ONLY_CAPACITY',1)[0]
        import textwrap
        body=textwrap.dedent(body)
        for forbidden in ('rmtree', '.unlink(', 'os.remove', 'os.rmdir', 'subprocess', 'chmod', 'chown'):
            self.assertNotIn(forbidden, body)
        threshold=64*1024**3+512*1024**2
        for free in (threshold-1,threshold,threshold+1):
            with tempfile.TemporaryDirectory() as temporary:
                workspace=Path(temporary)/'workspace';workspace.mkdir()
                with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(workspace),'RUNNER_TEMP':temporary}), patch('shutil.disk_usage',return_value=SimpleNamespace(free=free)):
                    if free<threshold:
                        with self.assertRaises(SystemExit): exec(compile(body,'readonly-capacity','exec'),{})
                    else: exec(compile(body,'readonly-capacity','exec'),{})
                report=json.loads((Path(temporary)/'identity-serviced-capacity/public.json').read_text())
                self.assertEqual(report['kind'],'read_only_capacity_preflight')
                self.assertEqual(report['status'],'admitted' if free>=threshold else 'insufficient_capacity')
                self.assertFalse(report['provider_changes']);self.assertFalse(report['provider_deletion_attempted'])
                self.assertFalse(report['recovery_performed'])
                # A second invocation cannot overwrite or relabel the prior observation.
                with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(workspace),'RUNNER_TEMP':temporary}):
                    with self.assertRaises(FileExistsError): exec(compile(body,'readonly-capacity','exec'),{})

    def test_readonly_capacity_rejects_cross_filesystem(self):
        import textwrap
        body=textwrap.dedent(self.serviced.split("<<'READ_ONLY_CAPACITY'",1)[1].split('\n          READ_ONLY_CAPACITY',1)[0])
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary)/'workspace';workspace.mkdir()
            def fake_stat(path, *args, **kwargs): return SimpleNamespace(st_dev=1 if path==workspace else 2)
            with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(workspace),'RUNNER_TEMP':temporary}), patch('shutil.disk_usage',return_value=SimpleNamespace(free=100*1024**3)), patch.object(Path,'stat',fake_stat):
                with self.assertRaises(SystemExit): exec(compile(body,'readonly-capacity','exec'),{})
            report=json.loads((Path(temporary)/'identity-serviced-capacity/public.json').read_text())
            self.assertFalse(report['same_filesystem']);self.assertEqual(report['status'],'insufficient_capacity')
            self.assertFalse(report['provider_changes'])

    def test_embedded_baseline_matches_actual_preparation_consumer(self):
        import importlib.util, re, textwrap
        consumers=set(re.findall(r'/usr/bin/python3 -B (\.github/[^ ]+\.py) --check-(?:preparation|apt-plan)',self.serviced))
        self.assertEqual(consumers,{'.github/windows_identity_serviced_stage0.py'})
        selected=next(iter(consumers))
        spec=importlib.util.spec_from_file_location('serviced_workflow_capacity_contract',ROOT/selected)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        step=self.serviced.split('      - name: Observe preparation baseline',1)[1].split('      - ',1)[0]
        body=textwrap.dedent(step.split("<<'PY'",1)[1].split('\n          PY',1)[0])
        free=80*1024**3
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary)/'workspace';workspace.mkdir()
            directory=Path(temporary)/'identity-serviced-capacity';directory.mkdir()
            environment=Path(temporary)/'job-env'
            with patch.dict(os.environ,{'GITHUB_WORKSPACE':str(workspace),'RUNNER_TEMP':temporary,'GITHUB_ENV':str(environment)}), patch.object(sys,'version_info',(3,12,0)), patch('shutil.disk_usage',return_value=SimpleNamespace(free=free)):
                exec(compile(body,'actual-workflow-baseline','exec'),{})
                path=directory/'preparation-public.json'
                record=module.preparation_record(path)
                self.assertEqual(record['minimum_free_bytes'],64*1024**3)
                device=environment.read_text().strip().split('=',1)[1]
                with patch.dict(os.environ,{'STOCK_PREP_DEVICE_ID':device}), patch.object(module,'ROOT',workspace):
                    self.assertEqual(module.preparation_checkpoint(path,'post_checkout'),0)
                self.assertEqual(len(module.preparation_record(path)['samples']),2)
                value=json.loads(path.read_text());value['minimum_free_bytes']=32*1024**3
                path.write_text(json.dumps(value))
                with self.assertRaises(ValueError):module.preparation_record(path)
        self.assertNotIn('floor=32*1024**3',self.serviced)
        self.assertNotIn('windows_identity_stock_stage0.py --check-',self.serviced)

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
        self.assertIn("@('stage0-setup', 'stage0-run', 'update', 'telemetry')", self.serviced)
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
        self.assertIn('.github/windows_identity_serviced_stage0.py --check-preparation', self.serviced)
        self.assertIn('windows-11-serviced-ordinary-stage0-public', self.serviced)
        self.assertNotIn('sudo /usr/bin/python3 -B .github/windows_identity_stock_stage0.py \\', self.serviced)

if __name__ == '__main__':
    unittest.main()
