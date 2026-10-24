"""Pure historical-schema adapter checks; never calls the actual auditor."""
import importlib.util
from pathlib import Path
import unittest

P=Path(__file__).with_name('verify_psec_lpac_matchedcaps_actual_01_reader02.py')
spec=importlib.util.spec_from_file_location('file_reader02_pure',P)
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class ReaderSchemaTests(unittest.TestCase):
    def test_nested_result_is_explicit_and_absent_top_remains_null(self):
        for name in ('model2-dns-01-public.json','model2-raw-dns-02-public.json'):
            value=m.prior_evidence_product_fields(name,dict(result=dict(product_acceptance=False)))
            self.assertEqual(value['product_acceptance_source'],'result')
            self.assertTrue(value['product_acceptance_field_present']);self.assertIs(value['product_acceptance_recorded_value'],False)
            self.assertEqual(value['top_product_acceptance'],dict(present=False,recorded_value=None))
    def test_direct_historical_schema_uses_only_its_recorded_field(self):
        for name in ('psec-lpac-postassign-identity-local-01-public.json','lpac-semantic-dns-local-02-public.json'):
            value=m.prior_evidence_product_fields(name,dict(product_acceptance=False))
            self.assertEqual(value['product_acceptance_source'],'top');self.assertIs(value['product_acceptance'],False)
            self.assertEqual(value['top_product_acceptance'],dict(present=True,recorded_value=False))
    def test_missing_field_is_never_filled_with_false(self):
        for name,raw in (('model2-dns-01-public.json',dict(result={})),('lpac-semantic-dns-local-02-public.json',{})):
            value=m.prior_evidence_product_fields(name,raw)
            self.assertFalse(value['product_acceptance_field_present']);self.assertIsNone(value['product_acceptance'])
            self.assertIsNone(value['product_acceptance_recorded_value'])
    def test_wrong_nested_shape_and_nonboolean_value_are_rejected(self):
        for raw in ({},dict(result=None),dict(result=[]),dict(result=dict(product_acceptance=0))):
            with self.subTest(raw=raw),self.assertRaises(ValueError):m.prior_evidence_product_fields('model2-dns-01-public.json',raw)
    def test_recorded_true_and_conflicting_top_are_preserved_not_qualified(self):
        value=m.prior_evidence_product_fields('model2-dns-01-public.json',dict(product_acceptance=False,result=dict(product_acceptance=True)))
        self.assertIs(value['product_acceptance'],True);self.assertEqual(value['top_product_acceptance'],dict(present=True,recorded_value=False))
        self.assertNotIn('qualified',value)

if __name__=='__main__':unittest.main()
