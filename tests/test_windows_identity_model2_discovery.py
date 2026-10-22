"""Rejected child-set observations are private facts, never network admission."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('held_discovery_test',ROOT/'.github/windows_identity_model2_live.py')
l=importlib.util.module_from_spec(spec);spec.loader.exec_module(l)


class API:
    def __init__(self, path, fault=None): self.path,self.fault,self.now,self.closed,self.generations=path,fault,1000,[],{}
    def qpc(self): self.now+=1;return self.now
    def qpc_frequency(self): return 1000
    def close(self,h):
        self.closed.append(h)
        if self.fault=='close' and h==900: raise OSError('fake')
    def wait(self,h,ms): return False
    def creation_time(self,h):
        if h==1: return 100
        self.generations[h]=self.generations.get(h,0)+1
        return 201 if self.fault=='generation' and self.generations[h]>1 else 200
    def process_id(self,h): return 40 if h==1 else h-1000
    def parent_snapshot(self):
        self.last_snapshot_images={50:'actor.exe',51:'conhost.exe'}
        return {50:40,51:40}
    def open_query_process(self,pid): return 1000+pid
    def open_owned_process(self,pid): raise AssertionError('Rejected diagnostics cannot open admission handles')
    def process_image(self,h): return str(self.path/('actor.exe' if h==1050 else 'conhost.exe'))
    def system_conhost_path(self): return str(self.path/'conhost.exe')
    def token_for_process(self,h): return h+3000
    def identity(self,t): return {'observed_token':t}
    def groups(self,t,*args): return [('S-1-15-3-3',4)] if t==4050 else []
    def verify_job(self,job,h):
        if self.fault=='job': raise ValueError('not_member')


class HeldDiscoveryTests(unittest.TestCase):
    def test_complete_held_facts_still_refuse_two_children_and_keep_handles_owned(self):
        self.exercise()

    def test_membership_and_generation_failures_are_facts_not_adaptive_admission(self):
        self.exercise('job')
        self.exercise('generation')

    def test_temporary_outer_query_uncertain_close_is_retained_in_cleanup_scope(self):
        self.exercise('close')

    def exercise(self,fault=None):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)
            (path/'actor.exe').write_bytes(b'actor');(path/'conhost.exe').write_bytes(b'fixed-system-fixture')
            api=API(path,fault);owners=l.helpers.OneShotHandles(api.close);scopes=[]
            def outer(api,process,name,*,owners):
                owners.add(900)
                try:
                    if fault=='job': raise ValueError('not_member')
                finally: owners.close(900)
            with mock.patch.object(l,'verify_exact_guard_member',side_effect=outer),self.assertRaises(ValueError) as caught:
                l.admit_selected(api,owners,l.launcher.QpcBudget(api,121000,1000),g_process=1,g_created=100,
                    job=7,image=path/'actor.exe',image_hash='a'*64,parent={},capability_profile='agentic-pncs',catalog={},
                    diagnostic_guard_name='Local\\RuleProxy.LocalGuard.'+'a'*32,diagnostic_scoped_owners=scopes)
            self.assertEqual(str(caught.exception),'selected_child_set_changed')
            rows=caught.exception.discovery['held_observations']
            self.assertEqual(len(rows),2)
            self.assertTrue(all(not row['network_authorized'] for row in rows))
            self.assertTrue(rows[1]['system_conhost_image_equal'])
            self.assertFalse(rows[0]['system_conhost_image_equal'])
            self.assertEqual(rows[1]['image_sha256'],l.sha(b'fixed-system-fixture'))
            self.assertEqual(rows[1]['capabilities'],[])
            self.assertEqual(owners.pending,{1050,1051,4050,4051})
            self.assertEqual(len(scopes),2)
            self.assertEqual(all(x.confirmed_closed for x in scopes),fault!='close')
            self.assertEqual(rows[1]['creation_stable'],fault!='generation')
            self.assertEqual(rows[1]['workload_job_verified'],fault!='job')


if __name__=='__main__': unittest.main()
