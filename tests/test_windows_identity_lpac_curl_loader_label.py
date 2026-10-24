"""Future cleanup batch regression under a pure inherited-label model.

This proves the ordering behavior under that model, not the unknown precise
node/API cause of the historical actual03 label restoration failure.
"""
import ast
import hashlib
import ctypes as C
import importlib.util
from pathlib import Path
import unittest
from unittest import mock
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('label04_owner_fixture',ROOT/'tests/test_windows_identity_lpac_curl_loader.py')
co=importlib.util.module_from_spec(spec);spec.loader.exec_module(co);m=co.m
# Exact production Owner.cleanup from the frozen actual03 core (source SHA below).
# This historical fixture is embedded so main/CI never needs WORK or Git history.
HISTORICAL_CORE_SHA256='c3029985b98b0f0cee084239fef1885420d4d0c5beb2e6789c40ccb53fa0817d'
HISTORICAL_CLEANUP="def cleanup(self):\n        try:\n            if any(r['info'].hProcess and not r['exited'] for r in self.children):self.journal('workload-stop')\n            rows=[r for r in self.children if not base.known_no_child(r,start=self.c['start_qpc'])]\n            clean,empty,_=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(8)),self.job,rows,self.owners)\n            self.j.update(workload_cleanup=clean,workload_job_empty=empty)\n        except BaseException:pass\n        closable=[*self.stdio_ledgers,self.signal_owners]+([self.resources] if self.j['workload_cleanup'] else [])\n        for ledger in closable:\n            for h in tuple(ledger.pending):\n                try:ledger.close(h)\n                except BaseException:self.api.controls_uncertain=True\n        self.j['parent_event_stdio_closed']=all(x.confirmed_closed for x in [*self.stdio_ledgers,self.signal_owners]) and self.resources.confirmed_closed\n        self.j['marker_file_closed']=self.resources.confirmed_closed\n        if not self.j['workload_cleanup'] and self.resources.pending:launcher._RETAINED_SCOPED_OWNERS.append((self.api,self.resources,'loader-live-target-file-events'))\n        if not self.j['parent_event_stdio_closed'] or not self.j['marker_file_closed']:self.api.controls_uncertain=True\n        observer_count=sum(decode(r['text'].encode('ascii'))['action'].startswith('observe-') for r in self.j['intents'])\n        if len(self.j['proofs'])!=observer_count:self.j['observer_resources_cleanup_verified']=False\n        if not self.j['observer_resources_cleanup_verified'] or self.context_bound:self.api.controls_uncertain=True\n        if self.j['workload_cleanup'] and self.j['observer_resources_cleanup_verified'] and not self.api.controls_uncertain:\n            try:\n                if self.j['labels']:\n                    self.journal('label-restore')\n                    for p in reversed(base.owned_tree(self.root/'selected-output')):\n                        self.api.label_set(p,None);require(self.api.label_read(p) is None,'loader_label_restore')\n                    self.j['labels'][0]['restored']=True\n                self.j['labels_restored']=True\n                if self.profile['created']:\n                    ledger=helpers.OneShotHandles(self.api.close);rows=[];job=None\n                    try:\n                        job=self.api.owned_job(ledger);self.journal('acl-remove');self.tool([str(self.fixed_tool('icacls.exe')),str(self.root),'/remove:g','*'+self.profile['sid'],'/T','/Q'],\n                            'remove',cleanup=True,owners=ledger,children=rows,job=job);self.scope_acl(True);self.j['acl_removed']=True\n                    finally:\n                        if job is not None:self.j['cleanup_tools']=base.ac._cleanup(self.api,live.CleanupView(self.budget,self.budget.cutoff(3)),job,rows,ledger)[0]\n                        self.j['cleanup_tasks']=[task_projection(x) for x in rows]\n                    if self.j['acl_removed'] and self.j['cleanup_tools']:\n                        self.journal('profile-delete');self.api.delete_profile(self.j['profile_name']);self.j['profile_deleted']=True\n                elif not self.profile['attempted']:self.j.update(acl_removed=True,cleanup_tools=True,profile_deleted=True)\n            except BaseException:pass\n        try:self.api.release_profile_sid(self.profile);self.j['sid_released']=True\n        except BaseException:pass\n        if not all(self.j[k] for k in CLEAN_KEYS):self.j['failure']=self.j['failure'] or 'cleanup'"
HISTORICAL_CLEANUP_SHA256='9f77e1773eb49b3d72c91c38a28afcb5e6d0f60bc2265d4e551ff66a218f3f8b'

class InheritingAPI(co.API):
    def __init__(self,*a,**k):super().__init__(*a,**k);self.label_trace=[]
    def label_read(self,path):
        path=Path(path);self.label_trace.append(('read',path))
        value=super().label_read(path);parent=self.root/'selected-output'
        if value is None and parent in path.parents and self.labels.get(parent)==m.zero.LOW_LABEL:
            return m.zero.LOW_LABEL[:9]+b'\x13'+m.zero.LOW_LABEL[10:]
        if self.fault=='readback-remains' and path==parent and parent in self.labels and self.labels[parent] is None:return m.zero.LOW_LABEL
        return value
    def label_set(self,path,value):
        path=Path(path);self.label_trace.append(('write',path,value))
        if self.fault=='write-unknown' and value is None and path.name=='stdout':raise OSError('fake unknown label write')
        return super().label_set(path,value)

class BatchCleanupTests(unittest.TestCase):
    def setUp(self):
        self.fixtures=co.LoaderTests(methodName='runTest');self.fixtures.setUp();self.addCleanup(self.fixtures.doCleanups)
        p=mock.patch.object(co,'API',InheritingAPI);p.start();self.addCleanup(p.stop)
    def run_case(self,fault=None):
        root,c,api,owner=self.fixtures.fixture(fault);j=owner.run();m.validate_result(j,c,parent=co.b.PARENT,root=root)
        return root,c,api,owner,j,m.project(j,c,parent=co.b.PARENT,root=root)
    def test_exact_historical_cleanup_fails_model_and_new_real_owner_finishes_all_readbacks(self):
        self.assertEqual(hashlib.sha256(HISTORICAL_CLEANUP.encode('utf-8')).hexdigest(),HISTORICAL_CLEANUP_SHA256)
        tree=ast.parse(HISTORICAL_CLEANUP)
        old=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='cleanup')
        ns=dict(m.__dict__);exec(compile(ast.fix_missing_locations(ast.Module(body=[old],type_ignores=[])),'frozen-actual03-production-cleanup','exec'),ns)
        with mock.patch.object(m.Owner,'cleanup',ns['cleanup']):
            root,c,api,owner,j,v=self.run_case()
        self.assertFalse(j['labels_restored']);self.assertFalse(j['acl_removed']);self.assertFalse(j['profile_deleted']);self.assertFalse(v['observation_complete'])
        root,c,api,owner,j,v=self.run_case();self.assertIsNone(j['failure']);self.assertTrue(v['observation_complete'])
        self.assertTrue(all(v[k] for k in m.CLEAN_KEYS));self.assertTrue(j['labels'][0]['restored'])
        clear=[i for i,x in enumerate(api.label_trace) if x[0]=='write' and x[2] is None]
        self.assertEqual(len(clear),4);last=max(clear)
        self.assertEqual({x[1] for x in api.label_trace[last+1:] if x[0]=='read'},set(m.base.owned_tree(root/'selected-output')))
        self.assertTrue(all(api.label_read(p) is None for p in m.base.owned_tree(root/'selected-output')))
        self.assertFalse(any(v[k] for k in m.FALSE_CLAIMS))
    def test_unknown_write_keeps_label_acl_and_profile_cleanup_unqualified(self):
        root,c,api,owner,j,v=self.run_case('write-unknown')
        self.assertFalse(j['labels_restored']);self.assertFalse(j['labels'][0]['restored']);self.assertFalse(j['acl_removed']);self.assertFalse(j['profile_deleted'])
        self.assertFalse(v['observation_complete']);self.assertNotIn('acl-remove',[m.decode(r['text'].encode('ascii'))['action'] for r in j['intents']])
    def test_readback_remains_strict_and_never_deletes_profile_after_failed_batch(self):
        root,c,api,owner,j,v=self.run_case('readback-remains')
        self.assertFalse(j['labels_restored']);self.assertFalse(j['acl_removed']);self.assertFalse(j['profile_deleted']);self.assertFalse(v['observation_complete'])
        clear=[x for x in api.label_trace if x[0]=='write' and x[2] is None];self.assertEqual(len(clear),4)
        self.assertTrue(j['workload_cleanup'] and j['workload_job_empty'] and j['parent_event_stdio_closed'])

if __name__=='__main__':unittest.main()
