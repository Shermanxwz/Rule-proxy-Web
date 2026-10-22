"""Pure entry/admission/evidence tests; never execute a real worker or Win32 API."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / '.github/test_windows_identity_local_job_mechanism.py'
SPEC = importlib.util.spec_from_file_location('local_job_mechanism_entry_test', WRAPPER)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class EntryTests(unittest.TestCase):
    def test_default_entry_refuses_before_runtime_or_native_construction(self):
        output = io.StringIO()
        with mock.patch.object(m, 'run') as run, mock.patch.object(m, 'ObservedAPI') as native, \
             mock.patch.object(m.sys, 'stdout', output):
            self.assertEqual(m.main([]), 2)
        run.assert_not_called(); native.assert_not_called()
        value = json.loads(output.getvalue())
        self.assertEqual(value['status'], 'not_requested')
        self.assertIs(value['execution_requested'], False)
        self.assertIs(value['network_tested'], False)
        self.assertIs(value['product_acceptance'], False)

    def test_private_parent_option_alone_does_not_authorize_execution(self):
        with mock.patch.object(m, 'run') as run, mock.patch.object(m.sys, 'stdout', io.StringIO()):
            self.assertEqual(m.main(['--work-parent', 'private']), 2)
        run.assert_not_called()

    def test_explicit_flag_dispatches_exact_parent_without_native_in_test(self):
        with mock.patch.object(m, 'run', return_value=7) as run, mock.patch.object(m, 'ObservedAPI') as native:
            self.assertEqual(m.main(['--run-local-job-mechanism', '--work-parent', 'private']), 7)
        run.assert_called_once_with(work_parent=Path('private'))
        native.assert_not_called()

    def test_parent_must_exist_inside_private_and_admission_does_not_create_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(FileNotFoundError):
                m.admit_work_parent(root / 'private', root=root)
            self.assertFalse((root / 'private').exists())
            private = root / 'private'; private.mkdir()
            child = private / 'existing'; child.mkdir()
            self.assertEqual(m.admit_work_parent(None, root=root), private.resolve())
            self.assertEqual(m.admit_work_parent(child, root=root), child.resolve())
            with self.assertRaises(m.m.launcher.GateFailure):
                m.admit_work_parent(root, root=root)
            self.assertEqual(sorted(p.name for p in private.iterdir()), ['existing'])


class EvidenceTests(unittest.TestCase):
    def evidence(self):
        return json.loads((ROOT / 'verification/windows-2026-10-22/local-job-mechanism-01.json').read_text(encoding='ascii'))

    def test_actual_runner_and_helper_binding_are_distinct_from_unexecuted_wrapper(self):
        value = self.evidence()
        archived = ROOT / 'verification/windows-2026-10-22/local-job-mechanism-01-runner.py'
        self.assertEqual(hashlib.sha256(archived.read_bytes()).hexdigest(), value['observed_runner']['sha256'])
        self.assertIs(value['observed_runner']['actual_execution'], True)
        self.assertIs(value['repository_wrapper']['actual_execution'], False)
        self.assertEqual(hashlib.sha256(WRAPPER.read_bytes()).hexdigest(), value['repository_wrapper']['sha256'])
        self.assertEqual(value['local_helper_sha256'], value['observed_result']['source_sha256'])
        self.assertEqual(hashlib.sha256(m.m.encode(value['observed_result'])).hexdigest(), value['observed_public_sha256'])
        self.assertEqual(value['claim_scope'], 'ordinary-python-job-list-only')
        self.assertEqual(value['observed_result']['status'], 'passed')
        self.assertTrue(all(value['observed_result']['facts'].values()))

    def test_wrapper_public_schema_rejects_raw_identity_or_broadened_claims(self):
        value = self.evidence()['observed_result']
        value.update(runner_kind='repository-wrapper', runner_sha256=hashlib.sha256(WRAPPER.read_bytes()).hexdigest())
        m.validate_public(value)
        for mutate in (lambda v: v.update(raw_sid='private'), lambda v: v.update(network_tested=True),
                       lambda v: v['facts'].update(job_empty=False), lambda v: v.update(journal_retained=False)):
            changed = copy.deepcopy(value); mutate(changed)
            with self.assertRaises(ValueError):
                m.validate_public(changed)


if __name__ == '__main__':
    unittest.main()
