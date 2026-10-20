"""Pure/fake APT tests; subprocess tests execute only this interpreter's inert snippets."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('apt_diagnostic', ROOT / '.github/windows_identity_apt_diagnostic.py')
diag = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(diag)
stock = diag.load_frozen_stock()


class Fixture:
    def __init__(self, *, count=1, size=100, installed=10, old=None, summary=None,
                 metadata=None, current=None, failure=None, refresh_code=0):
        self.count, self.size, self.installed, self.old = count, size, installed, old
        self.summary, self.metadata, self.current, self.failure = summary, metadata, current, failure
        self.refresh_code, self.calls, self.options = refresh_code, [], []

    def __call__(self, argv, **kwargs):
        self.calls.append(tuple(argv)); self.options.append(kwargs)
        if self.failure is not None:
            self.failure(argv)
        executable = Path(argv[0]).name
        if executable == 'apt-get':
            text = self.summary
            if text is None:
                text = (f'{self.count if self.old else 0} upgraded, {0 if self.old else self.count} newly installed, '
                        '0 to remove and 0 not upgraded.\n')
                text += ''.join(f'Inst fixture{i}' + (f' [{self.old}]' if self.old else '') +
                                ' (2.0 Ubuntu:stable [amd64])\n' for i in range(self.count))
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        if executable == 'apt-cache':
            name = argv[2].split('=')[0]
            text = (f'Package: {name}\nVersion: 2.0\nArchitecture: amd64\nSize: {self.size}\n'
                    f'Installed-Size: {self.installed}\n')
            if self.metadata is not None:
                text = self.metadata(text)
            return SimpleNamespace(returncode=0, stdout=text, stderr='')
        if executable == 'dpkg-query':
            if self.current is not None:
                return self.current
            return SimpleNamespace(returncode=0 if self.old else 1,
                                   stdout=f'installed\n5\n{self.old}\n' if self.old else '', stderr='')
        if executable == 'sudo':
            return SimpleNamespace(returncode=self.refresh_code, stdout='', stderr='private refresh diagnostic')
        raise AssertionError('Unexpected executable')


def run_probe(fixture):
    return diag.probe(stock, 'before_refresh', deadline=time.monotonic() + 60, executor=fixture)


class AptDiagnosticTests(unittest.TestCase):
    def test_frozen_runtime_source_and_all_acceptance_ceilings_are_unchanged(self):
        self.assertEqual(hashlib.sha256((ROOT / '.github/windows_identity_stock_stage0.py').read_bytes()).hexdigest(), diag.STOCK_SHA256)
        self.assertEqual((stock.APT_PACKAGE_CEILING, stock.APT_DOWNLOAD_CEILING, stock.APT_INSTALLED_GROWTH_CEILING),
                         (23, 25315786, 115948544))
        self.assertEqual(tuple(diag.SIMULATION[-7:]), stock.VM_PACKAGES)
        self.assertEqual(diag.blank_phase('before_refresh')['ceilings'],
                         dict(package_count=23, download_bytes=25315786, positive_installed_growth_bytes=115948544))

    def test_complete_new_and_upgrade_growth_and_cached_queries(self):
        for old, growth in ((None, 10240), ('1.0', 5120)):
            fixture = Fixture(old=old)
            result = run_probe(fixture)
            self.assertTrue(result['frozen_gate_accepted'])
            self.assertTrue(result['frozen_gate_completed'])
            self.assertEqual(result['status'], 'observed')
            self.assertTrue(result['totals_complete'])
            self.assertEqual(result['download_bytes'], 100)
            self.assertEqual(result['positive_installed_growth_bytes'], growth)
            self.assertTrue(all(result['ceiling_verdicts'].values()))
            self.assertEqual(len(fixture.calls), 3)  # Frozen/parser passes share exact query bytes.
            self.assertEqual(result['rows'][0]['installed']['old_version_in_simulation'], old is not None)

    def test_maximum_closed_report_is_bounded_and_contains_no_raw_package_identity(self):
        result = run_probe(Fixture(count=256, metadata=lambda x: '\n'.join([x] * 16)))
        self.assertEqual(len(result['rows']), 256)
        data = json.dumps(result, sort_keys=True, ensure_ascii=True)
        self.assertLess(len(data), diag.MAX_REPORT)
        self.assertNotIn('fixture', data)
        self.assertNotIn('Ubuntu:stable', data)

    def test_original_23_count_rejects_but_24_rows_are_fully_observed(self):
        fixture = Fixture(count=24)
        result = run_probe(fixture)
        self.assertEqual(result['frozen_gate_error'], 'simulation_count')
        self.assertFalse(result['ceiling_verdicts']['package_count'])
        self.assertEqual(len(result['rows']), 24)
        self.assertTrue(result['totals_complete'])
        self.assertEqual(result['download_bytes'], 2400)
        self.assertEqual(len(fixture.calls), 49)

    def test_observation_256_bound_does_not_become_acceptance_expansion(self):
        result = run_probe(Fixture(count=257))
        self.assertFalse(result['frozen_gate_accepted'])
        self.assertEqual(len(result['rows']), 256)
        self.assertEqual(result['stop_reason'], 'row_bound')
        self.assertFalse(result['totals_complete'])
        self.assertIsNone(result['download_bytes'])
        self.assertEqual(result['partial_download_bytes'], 25600)
        self.assertIsNone(result['ceiling_verdicts']['download_bytes'])

    def test_bad_summary_duplicate_names_and_unsafe_row_remain_independently_observable(self):
        cases = [
            ('unexpected summary\nInst fixture0 (2.0 Ubuntu [amd64])\n', 'simulation_summary', 1),
            ('0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n' +
             'Inst fixture0 (2.0 Ubuntu [amd64])\n' * 2, 'simulation_count', 2),
            ('0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.\n'
             'Inst --unsafe (2.0 Ubuntu)\nInst fixture0 (2.0 Ubuntu)\n', 'simulation_row', 2),
            ('0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.\nRemv fixture\n',
             'simulation_removal_or_bound', 0),
        ]
        for summary, category, rows in cases:
            with self.subTest(category=category):
                result = run_probe(Fixture(summary=summary))
                self.assertEqual(result['frozen_gate_error'], category)
                self.assertEqual(len(result['rows']), rows)
                if rows:
                    self.assertIsNotNone(result['rows'][-1]['installed'])

    def test_metadata_all_fields_and_duplicate_presence_are_closed(self):
        cases = [
            (lambda x: x.replace('Size: 100\n', ''), 'metadata_required_fields'),
            (lambda x: x + 'Size: 100\n', 'metadata_duplicate_field'),
            (lambda x: x + 'Private-Field: /private/raw\nPrivate-Field: secret\n', 'metadata_duplicate_field'),
            (lambda x: x.replace('amd64', 'arm64'), 'metadata_required_fields'),
            (lambda x: x.replace('Version: 2.0', 'Version: unexpected'), 'metadata_required_fields'),
            (lambda x: x.replace('Package: fixture0', 'Package: other'), 'metadata_required_fields'),
            (lambda x: x.replace('Size: 100\n', 'Size: -1\n'), 'metadata_required_fields'),
        ]
        for transform, category in cases:
            with self.subTest(category=category):
                result = run_probe(Fixture(metadata=transform))
                self.assertEqual(result['frozen_gate_error'], category)
                self.assertEqual(result['frozen_gate_row_index'], 0)
                row = result['rows'][0]
                self.assertIsNotNone(row['metadata'])
                self.assertIsNotNone(row['installed'])
                self.assertFalse(result['totals_complete'])
                self.assertEqual(set(row['metadata']['records'][0]['required_field_counts']), set(diag.FIELDS))
                public = json.dumps(result)
                for private in ('/private/raw', 'secret', 'unexpected', 'arm64', 'fixture0', 'Private-Field'):
                    self.assertNotIn(private, public)

    def test_multiple_records_include_missing_size_and_disagreement(self):
        for second, category in ((lambda x: x.replace('Size: 100\n', ''), 'metadata_required_fields'),
                                 (lambda x: x.replace('Size: 100\n', 'Size: 101\n'), 'metadata_size_disagreement')):
            result = run_probe(Fixture(metadata=lambda x: x + '\n' + second(x)))
            self.assertEqual(result['frozen_gate_error'], category)
            self.assertEqual(result['rows'][0]['metadata']['record_count'], 2)
            self.assertEqual(len(result['rows'][0]['metadata']['records']), 2)
            self.assertIsNotNone(result['rows'][0]['installed'])
        result = run_probe(Fixture(metadata=lambda x: x + '\n' + x))
        self.assertTrue(result['frozen_gate_accepted'])
        self.assertTrue(result['totals_complete'])

    def test_metadata_record_limit_keeps_independent_dpkg_and_later_rows(self):
        result = run_probe(Fixture(count=2, metadata=lambda x: '\n'.join([x] * 17)))
        self.assertTrue(result['frozen_gate_accepted'])  # Diagnostic bound is not a new acceptance rule.
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['stop_reason'], 'record_bound')
        self.assertEqual(len(result['rows'][0]['metadata']['records']), 16)
        self.assertIsNotNone(result['rows'][1]['installed'])
        self.assertFalse(result['totals_complete'])

    def test_installed_state_version_size_and_command_codes(self):
        for code, text, category in (
                (0, 'installed\n5\nwrong\n', 'installed_version_or_size'),
                (0, 'installed\nnot-number\n1.0\n', 'installed_version_or_size'),
                (1, '', 'installed_metadata'),
                (0, 'config-files\n5\n1.0\n', 'installed_metadata'),
                (2, 'private raw error', 'command_result')):
            with self.subTest(category=category):
                result = run_probe(Fixture(old='1.0', current=SimpleNamespace(returncode=code, stdout=text, stderr='private')))
                self.assertEqual(result['frozen_gate_error'], category)
                self.assertEqual(result['frozen_gate_stage'], 'installed')
                self.assertFalse(result['rows'][0]['installed']['valid'])
                self.assertNotIn('private', json.dumps(result))

    def test_every_original_numeric_ceiling_verdict_is_reported(self):
        for size, installed, download_ok, growth_ok in (
                (25315786, 113231, True, True),
                (25315787, 10, False, True),
                (100, 113232, True, False)):
            result = run_probe(Fixture(size=size, installed=installed))
            self.assertTrue(result['totals_complete'])
            self.assertEqual(result['ceiling_verdicts']['download_bytes'], download_ok)
            self.assertEqual(result['ceiling_verdicts']['positive_installed_growth_bytes'], growth_ok)
            self.assertEqual(result['frozen_gate_accepted'], download_ok and growth_ok)
            if not result['frozen_gate_accepted']:
                self.assertEqual(result['frozen_gate_error'], 'numeric_ceiling')

    def test_individual_command_failure_does_not_hide_other_fields_or_rows(self):
        for reason in ('command_timeout', 'command_launch', 'command_encoding', 'output_bound'):
            def fail(argv):
                if Path(argv[0]).name == 'apt-cache' and argv[2].startswith('fixture0='):
                    raise diag.Stopped(reason)
            fixture = Fixture(count=2, failure=fail)
            result = run_probe(fixture)
            self.assertEqual(result['frozen_gate_error'], reason)
            self.assertFalse(result['frozen_gate_completed'])
            self.assertEqual(result['status'], 'partial')
            self.assertEqual(result['rows'][0]['metadata_command']['status'], reason)
            self.assertIsNotNone(result['rows'][0]['installed'])
            self.assertTrue(result['rows'][1]['complete_sizes'])
            self.assertEqual(result['partial_download_bytes'], 100)
            self.assertIsNone(result['download_bytes'])
            self.assertEqual(sum('fixture0=2.0' in call for call in fixture.calls), 1)

    def test_exhausted_global_limits_stop_without_multiplying_per_command_timeout(self):
        for reason in ('time_bound', 'capture_bound'):
            def fail(argv):
                if Path(argv[0]).name == 'apt-cache':
                    raise diag.Stopped(reason)
            fixture = Fixture(count=24, failure=fail)
            result = run_probe(fixture)
            self.assertEqual(result['stop_reason'], reason)
            self.assertEqual(len(fixture.calls), 2)
            self.assertFalse(result['totals_complete'])

    def test_partial_lower_bound_can_disprove_but_never_prove_ceiling(self):
        def fail(argv):
            if Path(argv[0]).name == 'apt-cache' and argv[2].startswith('fixture1='):
                raise diag.Stopped('time_bound')
        result = run_probe(Fixture(count=2, size=stock.APT_DOWNLOAD_CEILING + 1, failure=fail))
        self.assertFalse(result['totals_complete'])
        self.assertFalse(result['ceiling_verdicts']['download_bytes'])
        self.assertIsNone(result['ceiling_verdicts']['positive_installed_growth_bytes'])

    def test_allowlist_cannot_request_update_install_or_arbitrary_package_switch(self):
        fixture = Fixture()
        recorder = diag.Recorder(time.monotonic() + 60, fixture)
        for argv in (['apt-get', 'update'], ['apt-get', 'install', 'qemu-utils'],
                     ['apt-cache', 'show', '--option=2.0'], ['dpkg-query', '-W', diag.DPKG_FORMAT, '../private']):
            with self.assertRaises(diag.Stopped): recorder(argv)
        self.assertFalse(fixture.calls)

    def test_exact_image_and_system_python_gate(self):
        env = {'ImageOS': 'ubuntu24', 'ImageVersion': '20261012.334.1', 'GITHUB_ACTIONS': 'true',
               'RUNNER_ENVIRONMENT': 'github-hosted', 'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}
        with patch.object(diag.sys, 'platform', 'linux'), patch.object(diag.sys, 'version_info', (3, 12)):
            self.assertTrue(diag.reviewed_environment(env))
            for key in env:
                self.assertFalse(diag.reviewed_environment(dict(env, **{key: 'unknown'})))
        with patch.object(diag.sys, 'version_info', (3, 14)):
            self.assertFalse(diag.reviewed_environment(env))

    def test_unknown_image_or_invalid_deadline_writes_two_closed_reports_and_runs_nothing(self):
        for allowed, remaining in ((False, 400), (True, 481), (True, 9)):
            with tempfile.TemporaryDirectory() as directory, patch.object(diag, 'reviewed_environment', return_value=allowed):
                fixture = Fixture()
                self.assertEqual(diag.diagnose(Path(directory), time.time() + remaining, executor=fixture), 1)
                self.assertFalse(fixture.calls)
                for phase in diag.PHASES:
                    result = json.loads((Path(directory) / (phase + '.json')).read_text())
                    self.assertEqual(result['status'], 'blocked')
                    self.assertFalse(result['refresh']['attempted'])

    def test_frozen_source_mismatch_prevents_all_commands(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(diag, 'reviewed_environment', return_value=True), \
             patch.object(diag, 'load_frozen_stock', side_effect=ValueError('/private/error')):
            fixture = Fixture()
            self.assertEqual(diag.diagnose(Path(directory), time.time() + 400, executor=fixture), 1)
            self.assertFalse(fixture.calls)
            self.assertNotIn('/private', (Path(directory) / 'after_refresh.json').read_text())

    def test_successful_orchestrator_only_refreshes_once_and_uses_one_absolute_deadline(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(diag, 'reviewed_environment', return_value=True):
            fixture = Fixture()
            start = time.monotonic()
            self.assertEqual(diag.diagnose(Path(directory), time.time() + 400, executor=fixture), 0)
            refresh = [call for call in fixture.calls if call[0] == '/usr/bin/sudo']
            self.assertEqual(len(refresh), 1)
            self.assertEqual(refresh[0], ('/usr/bin/sudo', '-n', '/usr/bin/timeout', '--signal=TERM',
                                         '--kill-after=5s', '110s', '/usr/bin/apt-get', 'update'))
            self.assertTrue(all(option['deadline'] <= start + 400 for option in fixture.options))
            for phase in diag.PHASES:
                result = json.loads((Path(directory) / (phase + '.json')).read_text())
                self.assertTrue(result['refresh']['completed'])
                self.assertFalse(result['packages_installed'])
                self.assertFalse(result['vm_created'])
                self.assertNotIn('private refresh', json.dumps(result))

    def test_refresh_failure_preserves_before_and_blocks_after_probe(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(diag, 'reviewed_environment', return_value=True):
            fixture = Fixture(refresh_code=100)
            self.assertEqual(diag.diagnose(Path(directory), time.time() + 400, executor=fixture), 1)
            before = json.loads((Path(directory) / 'before_refresh.json').read_text())
            after = json.loads((Path(directory) / 'after_refresh.json').read_text())
            self.assertEqual(before['status'], 'observed')
            self.assertEqual(after['stop_reason'], 'refresh_nonzero')
            self.assertEqual(len(fixture.calls), 4)

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX diagnostic transport only')
    def test_live_pipe_reader_bounds_both_streams_total_capture_and_command_time(self):
        for script, options, expected in (
                ('import sys; sys.stdout.write("x"*600000)', {}, 'output_bound'),
                ('import sys; sys.stderr.write("x"*600000)', {}, 'output_bound'),
                ('print("x"*2048)', {'capture_remaining': 1024}, 'capture_bound'),
                ('import time; time.sleep(5)', {'timeout': 0.05}, 'command_timeout')):
            processes = []
            real = subprocess.Popen
            def spawn(*args, **kwargs):
                process = real(*args, **kwargs); processes.append(process); return process
            with self.subTest(expected=expected), patch.object(diag.subprocess, 'Popen', side_effect=spawn):
                with self.assertRaises(diag.Stopped) as raised:
                    diag.bounded_command([sys.executable, '-I', '-S', '-c', script], deadline=time.monotonic() + 10, **options)
                self.assertEqual(raised.exception.reason, expected)
                self.assertTrue(all(process.poll() is not None for process in processes))

    def test_expired_absolute_budget_spawns_no_process(self):
        with patch.object(diag.subprocess, 'Popen') as spawn:
            with self.assertRaises(diag.Stopped) as raised:
                diag.bounded_command(['never'], deadline=time.monotonic() + 1)
            self.assertEqual(raised.exception.reason, 'time_bound')
            spawn.assert_not_called()

    def test_workflow_is_separate_bounded_no_cleanup_install_or_vm(self):
        workflow = (ROOT / '.github/workflows/windows-identity-apt-diagnostic.yml').read_text()
        self.assertIn('[identity-win11-apt-diagnostic-01]', workflow)
        self.assertIn('timeout-minutes: 10', workflow)
        self.assertIn('int(time.time()) + 480', workflow)
        self.assertIn('fetch-depth: 1', workflow)
        self.assertIn('persist-credentials: false', workflow)
        self.assertIn('if: always()', workflow)
        self.assertEqual(workflow.count('/before_refresh.json'), 1)
        self.assertEqual(workflow.count('/after_refresh.json'), 1)
        for forbidden in ('setup-python', 'workflow_dispatch', 'apt-get install', 'rm -', 'recovery.py',
                          'approved-disposable-vm', 'download-artifact', 'secrets.', 'sudo '):
            self.assertNotIn(forbidden, workflow)


if __name__ == '__main__':
    unittest.main()
