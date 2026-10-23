"""Pure projected transfer and partial-proof evidence; no native API call."""
from pathlib import Path
import importlib.util
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
a=load('postassign_archive_projection_test',BASE/'archive_psec_lpac_postassign_identity_01.py')
f=load('postassign_archive_owner_fake',BASE/'Rule-proxy-Web/tests/test_windows_identity_psec_lpac_postassign_bridge.py')

class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.owner=f.BridgeTests();self.owner.setUp();self.addCleanup(self.owner.doCleanups)
    def transfer(self,cell,j):
        return a.transfers_projection(cell.root,j['tasks'],j,cell.c,NS(core=f.m),source_commit='a'*40,result_validated=True)
    def test_one_raw_assign_per_arm_and_physical_binding(self):
        cell,_,j,_=self.owner.run_cell();v,raw=self.transfer(cell,j)
        self.assertEqual(v['assign_attempted_count'],2);self.assertEqual(v['verified_transfer_count'],2)
        self.assertEqual(v['physical_receipt_count'],6);self.assertEqual(len(raw),6)
        for row in v['records']:
            self.assertIs(row['pretransfer_guard']['inner_query']['membership'],False)
            self.assertIs(row['pretransfer_guard']['outer_query']['membership'],True)
            self.assertEqual(row['raw_assign_observation']['return_value'],1)
            self.assertEqual(row['raw_assign_observation']['immediate_win32_error'],0)
            self.assertTrue(row['all_recorded_post_assignment_exact_jobs_verified'])
            self.assertFalse(row['pretransfer_guard']['query_resources']['protected_handle_alias'])
    def test_assign_error_is_not_success_or_membership(self):
        cell,_,j,_=self.owner.run_cell('assign-false');v,_=self.transfer(cell,j);row=v['records'][0]
        self.assertEqual(row['raw_assign_observation']['return_value'],0)
        self.assertIs(row['raw_assign_observation']['api_success'],False)
        self.assertEqual(row['raw_assign_observation']['immediate_win32_error'],5)
        self.assertFalse(row['transfer_verified']);self.assertEqual(row['post_assignment_job_observation_count'],0)
    def test_missing_and_modified_physical_return_receipts_rejected(self):
        cell,_,j,_=self.owner.run_cell();receipt=j['tasks'][0]['transfer']['receipt'];path=cell.root/'transfers'/receipt['name']
        raw=path.read_bytes();path.unlink()
        with self.assertRaisesRegex(ValueError,'every_claimed_transfer_receipt_on_disk'):self.transfer(cell,j)
        path.write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError,'disk_transfer_exact_text_digest'):self.transfer(cell,j)
    def test_unbound_physical_files_do_not_supply_transfer_qualification(self):
        cell,_,j,_=self.owner.run_cell()
        v,raw=a.transfers_projection(cell.root,[],None,cell.c,NS(core=f.m),source_commit='a'*40,result_validated=False)
        self.assertEqual(v['records'],[]);self.assertEqual(v['verified_transfer_count'],0)
        self.assertEqual(v['held_bound_physical_receipt_count'],0);self.assertEqual(len(raw),6)
        self.assertTrue(all(row['unvalidated_or_incomplete_forensic_only'] for row in v['physical_receipts']))
    def test_lpac_first_grant3_retains_one_call_and_no_complete_matrix(self):
        original=f.Probe.access_check
        def access_check(api,*args):
            result=original(api,*args)
            return (True,True,3,0,None) if api.role=='lpac' and api.descriptors[args[0]]=='combined' else result
        with patch.object(f.Probe,'access_check',access_check):cell,_,j,_=self.owner.run_cell()
        arms={row['name']:row for row in j['tasks']}
        projected={proof['expected_role']:a.proof_projection(proof,arms[proof['expected_role']],cell.c,f.m.access) for proof in j['proofs']}
        self.assertEqual(projected['ac']['observed_matrix'],[3,0,1,2]);self.assertTrue(projected['ac']['qualified'])
        value=projected['lpac'];self.assertEqual(value['attempted_call_count'],1);self.assertIsNone(value['observed_matrix'])
        self.assertFalse(value['qualified']);self.assertTrue(value['partial_observation_preserved']);self.assertEqual(len(value['unattempted_call_labels']),3)
        first=value['observed_calls'][0];self.assertTrue(first['api_success']);self.assertTrue(first['access_status'])
        self.assertEqual(first['granted_access'],3);self.assertEqual(first['privilege_count'],0)

if __name__=='__main__':unittest.main(verbosity=2)
