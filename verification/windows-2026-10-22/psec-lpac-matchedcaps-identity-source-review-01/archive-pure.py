"""Pure file/fake regressions for the new reader; no Archive or native APIs."""
from pathlib import Path
from types import SimpleNamespace as NS
import copy
import importlib.util
import json
import re
import unittest
from unittest.mock import patch

BASE=Path(__file__).resolve().parent
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
a=load('matchedcaps_safe_archive_work',BASE/'archive_psec_lpac_matchedcaps_identity_01.py')
f=load('matchedcaps_archive_inert_fixtures',BASE/'psec-lpac-matchedcaps-candidate/tests/test_windows_identity_psec_lpac_matchedcaps_bridge.py')

class ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.case=f.MatchedCapsTests('test_three_held_complete_same_environment_sc_only_aap_differs_and_never_resume')
        cls.case.setUp();cls.cell,cls.api,cls.j,cls.obs=cls.case.run_cell()
        cls.m=NS(core=f.m)
    @classmethod
    def tearDownClass(cls):cls.case.doCleanups()
    def project(self,j=None,*,trusted=True):
        value=self.j if j is None else j
        return a.security_capabilities_projection(self.cell.root,value['tasks'] if trusted else [],value if trusted else None,
            self.cell.c,self.m,source_commit='1'*40,result_validated=trusted)
    def test_preactual_pin_guard_precedes_evidence_reads(self):
        with patch.object(a,'ACTUAL_SOURCE_COMMIT',None),patch.object(a,'bounded',side_effect=AssertionError('no private read')):
            with self.assertRaisesRegex(ValueError,'actual_pins_pending_no_archive'):a.prepare(NS())
    def test_complete_three_roles_sc_and_jobs_are_safe_without_raw_ids_or_clocks(self):
        value,raw=self.project();self.assertTrue(value['security_capabilities_verified'])
        self.assertEqual(value['physical_receipt_count'],1);self.assertEqual(value['physical_held_bound_receipt_count'],1)
        self.assertEqual([row['role'] for row in value['measured_arms']],['ac','lpac'])
        self.assertTrue(value['same_input_for_all_recorded_measured_arms'])
        self.assertTrue(all(row['bootstrap_rechecked_before_create'] and row['bootstrap_rechecked_before_primary'] for row in value['measured_arms']))
        self.assertFalse(value['psec_network_preservation_proven']);self.assertFalse(value['linux_equivalence_proven'])
        encoded=a.encode(value);self.assertIsNone(re.search(rb'S-\d+(?:-\d+){2,}',encoded))
        self.assertNotIn(str(self.cell.root).encode(),encoded);self.assertNotIn(self.j['first_appcontainer_sid'].encode(),encoded)
        for key in ('package_sid','agentic_sid','pncs_sid'):
            self.assertNotIn(self.j['security_capabilities']['value'][key].encode(),encoded)
        jobs,jobraw=a.job_admissions_projection(self.cell.root,self.j['tasks'],self.j,self.cell.c,self.m,source_commit='1'*40,result_validated=True)
        transfers,transferraw=a.transfers_projection(self.cell.root,self.j['tasks'],self.j,self.cell.c,self.m,source_commit='1'*40,result_validated=True)
        self.assertEqual({row['role'] for row in jobs['records']},{'bootstrap','ac','lpac'})
        self.assertEqual(transfers['verified_transfer_count'],3);self.assertEqual(transfers['physical_receipt_count'],9)
        self.assertGreater(len(jobraw),0);self.assertEqual(len(raw),1);self.assertEqual(len(transferraw),9)
    def test_unbound_sc_file_keeps_only_forensic_metadata(self):
        value,raw=self.project(trusted=False)
        self.assertIsNone(value['security_capabilities_verified']);self.assertIsNone(value['same_input_for_all_recorded_measured_arms'])
        self.assertEqual(value['input_sid_byte_metadata'],[]);self.assertEqual(value['measured_arms'],[])
        self.assertEqual(value['physical_receipt_count'],1);self.assertEqual(value['physical_held_bound_receipt_count'],0)
        self.assertTrue(value['physical_receipts'][0]['unvalidated_forensic_only']);self.assertEqual(len(raw),1)
    def test_changed_physical_sc_never_uses_valid_report_as_substitute(self):
        path=self.cell.root/'security-capabilities/held-bootstrap.json';old=path.read_bytes()
        try:
            path.write_bytes(old+b' ')
            with self.assertRaisesRegex(ValueError,'sc_original_disk_text_digest'):self.project()
        finally:path.write_bytes(old)
    def test_partial_typed10_retains_api_never_entered_and_no_missing_lpac(self):
        cell,api,j,obs=self.case.run_cell('ac-precreate-false')
        value,raw=a.security_capabilities_projection(cell.root,j['tasks'],j,cell.c,self.m,source_commit='1'*40,result_validated=True)
        self.assertEqual([row['role'] for row in value['measured_arms']],['ac'])
        self.assertFalse(value['complete_two_measured_inputs_recorded']);self.assertEqual(j['proofs'],[])
        operation=next(op for op in j['operations'] if op['label']=='ac')
        intentrow=next(row for row in j['intents'] if row['action']=='ac')
        frame=a.returned_frame(operation['receipt']['text'].encode('ascii'),cell.c,{'action':'ac','raw':intentrow['text'].encode('ascii')},self.m)
        self.assertEqual(frame['return_status'],10);self.assertEqual(frame['native']['api_entered'],0)
        projection=a.native_projection(operation,cell.c)
        self.assertFalse(projection['api_entered']);self.assertFalse(projection['api_returned']);self.assertEqual(projection['wrapper_status'],10)
        self.assertEqual(frame['pi'],dict.fromkeys(('process','thread','process_id','thread_id'),0))
        self.assertFalse(obs['inner_complete']);self.assertTrue(j['workload_cleanup'])
    def test_partial_proof_does_not_synthesize_full_vector(self):
        proof=copy.deepcopy(self.j['proofs'][1]);proof['calls']=proof['calls'][:1]
        proof.update(qualified=False,observation_complete=False,failure='mask')
        proof['calls'][0]['granted_access']=3
        arm=self.j['tasks'][2]
        # Shape/closed proof admission belongs to the source-bound production
        # validator. This probe isolates safe projection of already observed rows.
        with patch.object(f.m.access,'validate_proof'):
            value=a.proof_projection(proof,arm,self.cell.c,f.m.access)
        self.assertEqual(value['observed_matrix'],None);self.assertEqual(value['attempted_call_count'],1)
        self.assertEqual(value['unattempted_call_labels'],['world','aap','arap'])
        self.assertEqual(value['observed_calls'][0]['granted_access'],3);self.assertTrue(value['partial_observation_preserved'])

if __name__=='__main__':unittest.main(verbosity=2)
