"""A copied portable interpreter must run before any primary experiment starts."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


SOURCE = Path(__file__).resolve().parents[1] / '.github/windows_restricted_primary_lab.py'
SPEC = importlib.util.spec_from_file_location('windows_primary_runtime_preflight', SOURCE)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class CopiedRuntimePreflightTests(unittest.TestCase):
    def experiment(self, directory):
        base, work = directory / 'portable', directory / 'work'
        base.mkdir()
        work.mkdir()
        for name in ('python.exe', 'python314.dll', 'python314.zip', 'python314._pth',
                     '_ctypes.pyd', '_socket.pyd', '_ssl.PYD'):
            (base / name).write_bytes(('fixture:' + name).encode('ascii'))
        probe = directory / 'probe.py'
        probe.write_text('# No probe may run during runtime preparation.\n', encoding='utf-8')
        experiment = object.__new__(lab.Experiment)
        experiment.work = work
        experiment.args = SimpleNamespace(probe_script=probe)
        experiment.report = {'identity': 'S-1-5-18', 'variants': {}, 'cleanup': {}}
        experiment.lab = SimpleNamespace(
            BROKER_CHILD='# fixture\n', Fixture=mock.Mock(), Controller=mock.Mock(),
            write_json=lambda path, value: path.write_text(json.dumps(value), encoding='utf-8'))
        for name in ('privileges', 'make_user', 'make_desktop', 'case'):
            setattr(experiment, name, mock.Mock())
        experiment.controller = experiment.fixture = experiment.direct = None
        experiment.desktop = experiment.station = experiment.loaded = experiment.account = None
        experiment.token = lab.W.HANDLE()
        experiment.bits_names = []
        experiment.allocated_sids = []
        return experiment, base

    def test_portable_root_extensions_are_copied_before_import_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            experiment, base = self.experiment(Path(temporary))

            def check_copied_interpreter(argv, **options):
                target = experiment.work / 'runtime' / 'python.exe'
                self.assertEqual(Path(argv[0]), target)
                self.assertEqual(argv[1:5], ['-I', '-S', '-B', '-c'])
                self.assertEqual(argv[5], 'import ctypes, socket, ssl')
                self.assertEqual(options['timeout'], 20)
                for name in ('_ctypes.pyd', '_socket.pyd', '_ssl.PYD'):
                    self.assertEqual((target.parent / name).read_bytes(), (base / name).read_bytes())
                return subprocess.CompletedProcess(argv, 0, stderr=b'')

            with mock.patch.object(lab.sys, 'base_prefix', str(base)), \
                    mock.patch.object(lab.sys, 'executable', str(base / 'python.exe')), \
                    mock.patch.object(lab.subprocess, 'run', side_effect=check_copied_interpreter) as runner:
                experiment.copy_runtime()
            runner.assert_called_once()
            self.assertTrue(experiment.report['runtime']['import_preflight']['passed'])
            self.assertTrue(experiment.probe.is_file())

    def test_failed_or_timed_out_preflight_stops_experiment_without_exporting_child_output(self):
        secret = 'PRIVATE_SENTINEL_MUST_NOT_BE_EXPORTED'
        cases = (
            ('missing_extension', subprocess.CompletedProcess(
                [], 1, stderr=("ModuleNotFoundError: No module named '_ctypes'\n" + secret).encode())),
            ('timeout', subprocess.TimeoutExpired(['private-command'], 20, stderr=secret.encode())),
            ('start_error', OSError(5, secret)),
        )
        for name, result in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as temporary:
                experiment, base = self.experiment(Path(temporary))
                options = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
                with mock.patch.object(lab.sys, 'base_prefix', str(base)), \
                        mock.patch.object(lab.sys, 'executable', str(base / 'python.exe')), \
                        mock.patch.object(lab.subprocess, 'run', **options), \
                        contextlib.redirect_stdout(io.StringIO()) as output:
                    code = experiment.run()
                report = json.loads((experiment.work / 'report.json').read_text(encoding='utf-8'))
                self.assertEqual(code, 1)
                self.assertIn('copied Python import preflight', report['error'])
                facts = report['runtime']['import_preflight']
                self.assertFalse(facts['passed'])
                self.assertEqual(facts['timed_out'], name == 'timeout')
                if name == 'missing_extension':
                    self.assertEqual(facts['exit_code'], 1)
                    self.assertEqual(facts['error_type'], 'ModuleNotFoundError')
                    self.assertEqual(facts['module'], '_ctypes')
                experiment.lab.Fixture.assert_not_called()
                experiment.lab.Controller.assert_not_called()
                experiment.case.assert_not_called()
                self.assertEqual(report['variants'], {})
                self.assertFalse((experiment.work / 'dns_probe.py').exists())
                self.assertNotIn(secret, json.dumps(report) + output.getvalue())


if __name__ == '__main__':
    unittest.main()
