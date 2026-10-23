"""Pure file/fake regressions for the attempt03 archive projection only."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
ROOT=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
archive=load('archive03_pure_tests',ROOT/'archive_psec_lpac_identity_03.py')
fixture=load('archive03_owner_fakes',ROOT/'Rule-proxy-Web/tests/test_windows_identity_psec_lpac_bridge.py')

class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.owner=fixture.BridgeTests();self.owner.setUp();self.addCleanup(self.owner.doCleanups)
    def project(self,fault=None):
        cell,api,j,p=self.owner.run_cell(fault)
        projection,physical=archive.job_admissions_projection(cell.root,j['tasks'],j,cell.c,SimpleNamespace(core=fixture.m),
            source_commit='a'*40,result_validated=True)
        return cell,j,projection,physical
    def test_api_success_is_separate_from_false_membership_and_no_private_scalars(self):
        cell,j,p,physical=self.project('inner-false')
        self.assertEqual(len(p['records']),1);record=p['records'][0]
        self.assertIs(record['inner_query']['api_success'],True)
        self.assertIs(record['inner_query']['membership'],False)
        self.assertEqual(record['inner_query']['immediate_win32_error'],0)
        self.assertIs(record['outer_query']['membership'],True)
        self.assertFalse(record['admission_verified']);self.assertFalse(record['exact_inner_and_outer_membership_verified'])
        self.assertTrue(record['generation_before']['held_generation_verified'])
        self.assertFalse(record['query_resources']['protected_handle_alias']);self.assertTrue(record['query_resources']['one_shot_close_source_bound'])
        self.assertEqual(len(physical),1)
        text=archive.encode(p).decode('ascii')
        for key in ('process','pid','created','inner_job','outer_job','protected_handles','handle_value','before_qpc','after_qpc','decision_qpc'):
            self.assertNotIn('"'+key+'":',text)
        self.assertNotIn(cell.c['guard_job_name'],text)
    def test_failed_api_never_fakes_membership(self):
        _,_,p,_=self.project('inner-api-error');record=p['records'][0]
        self.assertIs(record['inner_query']['api_success'],False);self.assertIsNone(record['inner_query']['membership'])
        self.assertEqual(record['inner_query']['immediate_win32_error'],5);self.assertFalse(record['admission_verified'])
    def test_both_exact_queries_and_physical_receipts_closed_for_full_fake(self):
        _,_,p,physical=self.project()
        self.assertGreater(len(p['records']),2);self.assertEqual(p['physical_receipt_count'],len(physical))
        self.assertTrue(all(row['admission_verified'] for row in p['records']))
        self.assertTrue(all(row['bound_to_validated_held_worker_result'] for row in p['physical_receipts']))
    def test_missing_or_modified_claimed_disk_receipt_rejected(self):
        cell,_,j,_=self.owner.run_cell('inner-false')
        path=next((cell.root/'job-admissions').iterdir());raw=path.read_bytes();path.unlink()
        args=(cell.root,j['tasks'],j,cell.c,SimpleNamespace(core=fixture.m))
        with self.assertRaisesRegex(ValueError,'every_claimed_job_admission_on_disk'):
            archive.job_admissions_projection(*args,source_commit='a'*40,result_validated=True)
        path.write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError,'disk_job_admission_exact_text_digest'):
            archive.job_admissions_projection(*args,source_commit='a'*40,result_validated=True)
    def test_unbound_physical_receipt_cannot_supply_runtime_facts(self):
        cell,_,j,_=self.owner.run_cell('inner-false')
        p,physical=archive.job_admissions_projection(cell.root,[],None,cell.c,SimpleNamespace(core=fixture.m),
            source_commit='a'*40,result_validated=False)
        self.assertEqual(p['records'],[]);self.assertEqual(p['job_admission_record_count'],0)
        self.assertEqual(p['held_bound_physical_receipt_count'],0);self.assertEqual(len(physical),1)
        self.assertTrue(p['physical_receipts'][0]['unvalidated_or_incomplete_forensic_only'])
        self.assertFalse(p['unbound_files_used_for_qualification']);self.assertIsNone(p['query_resource_cleanup_verified'])

if __name__=='__main__':unittest.main(verbosity=2)
