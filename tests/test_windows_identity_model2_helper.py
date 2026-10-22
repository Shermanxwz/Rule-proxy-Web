"""Explicit system-helper admission fakes; no Windows actors or policy run."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('helper_fixtures',Path(__file__).with_name('test_windows_identity_model2_ownership.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
l=f.l


class API(f.GateAPI):
    def __init__(self,path,fault=None): super().__init__('two_children');self.path,self.helper_fault=path,fault
    def process_id(self,h): return 40 if h==1 else h%1000
    def creation_time(self,h): return 201 if h==2051 and self.helper_fault=='generation' else super().creation_time(h)
    def process_image(self,h): return str(self.path/('conhost.exe' if h%1000==51 else 'actor.exe'))
    def system_conhost_path(self): return str(self.path/'conhost.exe')
    def verify_job(self,job,h):
        if h==2051 and self.helper_fault=='job': raise ValueError('wrong_helper_job')
        super().verify_job(job,h)
    def verify_image(self,h,image):
        if Path(self.process_image(h))!=image: raise ValueError('wrong_image')
    def identity(self,t):
        if t!=5051: return f.selected()
        value=f.ordinary()
        if self.helper_fault=='user': value['sid']='S-1-5-21-9-9-9-1000'
        if self.helper_fault=='elevated': value['elevated']=True
        if self.helper_fault=='integrity': value['integrity_rid']=12288
        if self.helper_fault=='capability': value['capability_count']=1
        return value
    def groups(self,t,*args): return [('S-1-15-3-999',4)] if t==5051 and self.helper_fault=='capability' else [] if t==5051 else [(f.AGENTIC,4),(l.PNCS,4)]


class HelperTests(unittest.TestCase):
    def attempt(self,fault=None,explicit=True):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);path=Path(temporary.name)
        (path/'conhost.exe').write_bytes(b'fixed-conhost');(path/'actor.exe').write_bytes(b'fixed-actor')
        api=API(path,fault);owners=l.helpers.OneShotHandles(api.close);registered=[];scopes=[]
        admission=l.system_conhost_record(api) if explicit else None
        def outer(api,h,name,*,owners): owners.add(900);owners.close(900)
        with mock.patch.object(l,'verify_exact_guard_member',side_effect=outer),mock.patch.object(l.helpers,'verify_copied_actor'):
            try:
                result=l.admit_selected(api,owners,l.launcher.QpcBudget(api,121000,1000),g_process=1,g_created=100,
                    job=7,image=path/'actor.exe',image_hash=l.sha(b'fixed-actor'),parent=f.ordinary(),
                    capability_profile='agentic-pncs',catalog=f.CATALOG,diagnostic_guard_name='Local\\RuleProxy.LocalGuard.'+'1'*32,
                    diagnostic_scoped_owners=scopes,selected_admission=admission,auxiliary_register=registered.append)
                return result,registered,owners,scopes,None
            except ValueError as exc: return None,registered,owners,scopes,str(exc)

    def test_explicit_exact_pair_holds_both_roles_and_default_still_rejects(self):
        result,registered,owners,scopes,error=self.attempt()
        self.assertIsNone(error);self.assertEqual(result['pid'],50);self.assertEqual(result['auxiliary']['pid'],51)
        self.assertEqual(len(registered),1);self.assertEqual(registered[0]['handle'],2051)
        self.assertEqual(result['discovery']['first_children'],[50,51])
        self.assertFalse(result['auxiliary']['externally_held_before_first_resume'])
        self.assertTrue(result['auxiliary']['externally_held_before_network_go'])
        self.assertEqual(owners.pending,{1050,1051,2050,2051,5050,5051})
        self.assertTrue(all(scope.confirmed_closed for scope in scopes))
        self.assertEqual(self.attempt(explicit=False)[-1],'selected_child_set_changed')

    def test_unknown_helper_identity_or_job_never_admits_and_partial_owned_helper_is_registered(self):
        for fault in ('user','elevated','integrity','capability','job'):
            with self.subTest(fault=fault):
                result,registered,owners,_,error=self.attempt(fault)
                self.assertIsNone(result);self.assertIsNotNone(error);self.assertEqual(len(registered),1)
                self.assertIn(2051,owners.pending)

    def test_generation_mismatch_never_registers_termination_authority(self):
        result,registered,owners,_,error=self.attempt('generation')
        self.assertIsNone(result);self.assertEqual(error,'selected_pid_reuse');self.assertEqual(registered,[])
        self.assertIn(2051,owners.pending)


if __name__=='__main__': unittest.main()
