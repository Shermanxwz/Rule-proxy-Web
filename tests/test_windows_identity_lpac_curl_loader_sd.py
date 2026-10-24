"""Pure closed-SDDL and real-owner/adapter fakes; no Windows library or API.

The existing frozen fixtures are imported for callbacks, never discovered as
tests. Only this new file runs; production initializers and WinDLL are trapped.
"""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def fixture_module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'tests'/file)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
co=fixture_module('sd03_owner_fixture','test_windows_identity_lpac_curl_loader.py')
be=fixture_module('sd03_adapter_fixture','test_windows_identity_lpac_curl_loader_backend.py')
m=co.m
SID=co.b.SID
def descriptor(system='0x1fffff',parent='0x1fffff',sid=SID):return 'D:P(A;;'+system+';;;SY)(A;;'+parent+';;;'+sid+')'


class ClosedProcessThreadSDTests(unittest.TestCase):
    def setUp(self):
        self.old_fixture=co.LoaderTests(methodName='runTest');self.old_fixture.setUp();self.addCleanup(self.old_fixture.doCleanups)
        p=mock.patch.object(be.m.NativeAPI,'__init__',side_effect=AssertionError('production backend forbidden'));p.start();self.addCleanup(p.stop)

    def owner(self,sddl):
        root,c,api,owner=self.old_fixture.fixture();api.kernel_sddl=lambda h:sddl
        return root,c,api,owner

    def complete(self,sddl):
        root,c,api,owner=self.owner(sddl);result=owner.run()
        m.validate_result(result,c,parent=co.b.PARENT,root=root)
        return root,c,api,owner,result,m.project(result,c,parent=co.b.PARENT,root=root)

    def test_only_two_exact_masks_two_exact_trustees_protected_allow_layout(self):
        for a in ('GA','0x1fffff'):
            for b in ('GA','0x1fffff'):
                with self.subTest(system=a,parent=b):self.assertTrue(m.private_process_thread_sddl(descriptor(a,b),SID))
        self.assertEqual(0x000f0000|0x00100000|0xffff,0x1fffff)

    def test_extra_wider_lower_reordered_inherited_nonprotected_or_wrong_type_reject(self):
        good=descriptor()
        bad=[None,True,good.encode(),[],{},good+'(A;;GA;;;WD)',good.replace('0x1fffff','0x3fffff',1),
            good.replace('0x1fffff','0x1ffffe',1),good.replace('0x1fffff','0x10000000',1),
            good.replace('0x1fffff','GAWD',1),good.replace('0x1fffff','0x1FFFFF',1),
            good.replace('D:P','D:'),good.replace('D:P','D:PAI'),good.replace('(A;;','(A;ID;',1),
            good.replace('(A;;','(A;CI;',1),good.replace('(A;;','(D;;',1),good.replace(';;;SY',';;;BA'),
            good.replace(SID,SID+'-1'),'D:P(A;;0x1fffff;;;'+SID+')(A;;0x1fffff;;;SY)',
            good+' ',good.replace(';;;SY',';object;;SY'),good+'S:(ML;;NW;;;LW)']
        for value in bad:
            with self.subTest(value=value):self.assertFalse(m.private_process_thread_sddl(value,SID))
        for sid in (None,1,[],SID+')(A;;GA;;;WD',SID+'\n'):
            with self.subTest(parent_type_or_injection=sid):self.assertFalse(m.private_process_thread_sddl(good,sid))

    def test_numeric_raw_kernel_adapter_output_survives_both_known_allocation_closes(self):
        f=be.Fixture();raw=descriptor();sd=C.create_string_buffer(64);text=C.create_unicode_buffer(raw)
        sdptr,textptr=C.addressof(sd),C.addressof(text)
        def get_security(handle,kind,information,owner,group,dacl,sacl,out):
            self.assertEqual((kind,information),(6,4));C.cast(out,C.POINTER(C.c_void_p))[0]=sdptr;return 0
        def convert(value,revision,information,out,length):
            self.assertEqual((value.value,revision,information),(sdptr,1,4))
            C.cast(out,C.POINTER(C.c_void_p))[0]=textptr;return 1
        f.api.a.GetSecurityInfo=be.Fn(get_security);f.api.a.ConvertSecurityDescriptorToStringSecurityDescriptorW=be.Fn(convert)
        observed=f.api.kernel_sddl(0x42)
        self.assertEqual(observed,raw);self.assertTrue(be.m.private_process_thread_sddl(observed,SID))
        self.assertEqual(f.free_calls,[textptr,sdptr]);self.assertFalse(f.api.controls_uncertain)

    def test_real_owner_numeric_sd_keeps_raw_strings_and_complete_private_validator(self):
        raw=descriptor();root,c,api,owner,result,view=self.complete(raw)
        self.assertIsNone(result['failure']);self.assertTrue(view['observation_complete'])
        curl_rows=[r for r in result['tasks'] if r['name'] in ('before','selected','after')]
        self.assertEqual(len(curl_rows),3)
        for row in curl_rows:
            self.assertTrue(row['admitted'] and row['resumed'] and row['natural_exit'])
            self.assertEqual(row['kernel_security'],dict(process=raw,thread=raw))
            self.assertTrue(row['held_checks']);self.assertTrue(all(h['kernel_security']==row['kernel_security'] for h in row['held_checks']))
        self.assertTrue(all(view[k] for k in m.CLEAN_KEYS));self.assertFalse(any(view[k] for k in m.FALSE_CLAIMS))
        self.assertEqual([r for r in api.calls if r[0]=='resume'],[('resume',False),('resume',True),('resume',False)])

    def test_original_symbolic_sd_still_completes_and_raw_representation_change_is_rejected(self):
        self.assertTrue(self.complete(descriptor('GA','GA'))[-1]['observation_complete'])
        root,c,api,owner=self.owner(descriptor());owner.job=api.owned_job(owner.owners)
        row=owner.spawn('before',owner.budget.cutoff(25))
        api.kernel_sddl=lambda h:descriptor('GA','GA')
        with self.assertRaisesRegex(ValueError,'loader_kernel_SD_changed'):owner.held(row,owner.budget.cutoff(25))
        self.assertFalse(row['resumed']);self.assertEqual(row['kernel_security'],dict(process=descriptor(),thread=descriptor()))

    def test_bad_sd_before_resume_and_private_validator_never_promote(self):
        root,c,api,owner=self.owner(descriptor().replace('0x1fffff','0x3fffff',1));result=owner.run()
        m.validate_result(result,c,parent=co.b.PARENT,root=root)
        self.assertEqual(result['failure'],'ordinary_before');self.assertNotIn(('resume',False),api.calls)
        self.assertFalse(m.project(result,c,parent=co.b.PARENT,root=root)['observation_complete'])
        root,c,api,owner,result,view=self.complete(descriptor())
        for mutate in ('mask','extra','keys','wrong_parent'):
            changed=copy.deepcopy(result);row=next(r for r in changed['tasks'] if r['name']=='selected')
            if mutate=='keys':row['kernel_security']['other']=descriptor()
            else:
                bad=descriptor().replace('0x1fffff','0x3fffff',1) if mutate=='mask' else descriptor()+'(A;;GA;;;WD)' if mutate=='extra' else descriptor(sid=SID+'-1')
                row['kernel_security']=dict(process=bad,thread=bad)
                for held in row['held_checks']:held['kernel_security']=row['kernel_security'].copy()
            with self.subTest(mutate=mutate),self.assertRaisesRegex(ValueError,'loader_private_process_thread'):
                m.validate_result(changed,c,parent=co.b.PARENT,root=root)


if __name__=='__main__':unittest.main()
