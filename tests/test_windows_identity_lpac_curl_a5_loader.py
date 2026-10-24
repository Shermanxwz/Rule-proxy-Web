"""A5 injected coordination/resource tests. Never constructs a real backend."""
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
with patch.object(C,'WinDLL',side_effect=AssertionError('native library forbidden'),create=True):
    spec=importlib.util.spec_from_file_location('A5_owner_inert',ROOT/'.github/windows_identity_lpac_curl_a5_loader.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Budget:
    frequency=1000;deadline=116000
    def __init__(self):self.now=1200
    def read(self):self.now+=1;return self.now
    def cutoff(self,n):return self.deadline-n*1000
    def require_ms(self,end):
        if self.read()>=end:raise ValueError('expired')
        return 1

class API:
    def __init__(self):self.a5_calls=[];self.controls_uncertain=False;self.closed=[];self.labels={}
    def close(self,h):self.closed.append(h)
    def a5_close(self,h,**kw):self.close(h)
    def a5_external_close(self,h,**kw):self.close(h)
    def release_profile_sid(self,p):p['pointer']=None
    def label_set(self,p,value):self.labels[Path(p)]=value
    def label_read(self,p):return self.labels.get(Path(p))

class OwnerTests(unittest.TestCase):
    def setUp(self):
        for obj,key in ((C,'WinDLL'),(m,'NativeAPI')):
            trap=patch.object(obj,key,side_effect=AssertionError('production backend forbidden'),create=True)
            trap.start();self.addCleanup(trap.stop)
    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for p in ('journal','returns','selected-output'):(root/p).mkdir()
        c=dict(run='1'*32,case='2'*32,frequency=1000,start_qpc=1000,root_deadline_qpc=121000,
            deadline_qpc=116000,curl_path=r'C:\Windows\System32\curl.exe',proxy={'ports':{'origin_port':53001,'proxy_port':53002}})
        api=API();return root,api,m.Owner(root,c,{'sid':'S-1-5-21-1-2-3-1001'},api,Budget())
    def test_ready_metadata_is_boolean_and_original_windows_are_separate(self):
        self.assertIs(type(m.ACTUAL_READY),bool)
        _,_,o=self.fixture();e=m.pair_epochs(o.c,2000)
        self.assertEqual(e,dict(start=2000,app_end=10000,relay_end=12000,frequency=1000))
        self.assertEqual(m.barrier_cutoff(e,9000),9000);self.assertEqual(m.barrier_cutoff(e,13000),10000)
        with self.assertRaises(ValueError):m.pair_epochs(o.c,m.work_cutoff(o.c)-9999)
    def test_owned_tree_1024_boundary_and_depth_byte_limits(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve()
            for i in range(1023):(root/str(i)).write_bytes(b'')
            self.assertEqual(len(m.owned_tree(root)),1024)
            (root/'overflow').write_bytes(b'')
            with self.assertRaisesRegex(ValueError,'owned_tree_nodes'):m.owned_tree(root)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td).resolve();(root/'bytes').write_bytes(b'ab')
            with self.assertRaisesRegex(ValueError,'owned_tree_bytes'):m.owned_tree(root,max_bytes=1)
            p=root
            for i in range(17):p=p/'x';p.mkdir()
            with self.assertRaisesRegex(ValueError,'owned_tree_depth'):m.owned_tree(root)
    def test_parent_four_closes_all_attempted_and_unknown_never_retried(self):
        _,api,o=self.fixture();seen=[]
        def close(h):
            seen.append(h)
            if h==12:raise OSError('known close uncertain')
        o.pipe_owners=m.helpers.OneShotHandles(close)
        for h in (11,12,13,14):o.pipe_owners.add(h)
        o.proxy_leg=NS(parent_closes=[],sync=lambda:None)
        with self.assertRaisesRegex(ValueError,'parent_four'):o.close_parent_pipes()
        self.assertEqual(set(seen),{11,12,13,14});self.assertEqual(len(seen),4)
        self.assertFalse(o.pipe_owners.pending);self.assertTrue(api.controls_uncertain)
        self.assertFalse(o.j['parent_pipe_handles_closed']);self.assertEqual(len(o.proxy_leg.parent_closes),4)
        with self.assertRaises(ValueError):o.close_parent_pipes()
        self.assertEqual(len(seen),4)
    def test_selected_pipeline_preserves_held_memory_proofs_before_both_resumes(self):
        root,api,o=self.fixture();events=[];o.window={'start':1100,'end':100000};o.j['window']=o.window
        r={'info':NS(hThread=22,hProcess=21),'resumed':False,'exit_code':None,'natural_exit':False}
        o.base_probe=lambda r:(events.append('base') or (0x10000,b''))
        o.memory_sequence=lambda *a:events.append('memory');o.payload=lambda *a:events.append('payload')
        o.semantic=lambda *a:events.append('proof2');o.close_parent_pipes=lambda:events.append('fourcloses')
        o.held=lambda *a:events.append('held');o.lease_check=lambda *a:events.append('lease_after')
        api.resume_raw=lambda h:(events.append('curl_resume') or (1,None))
        def waited(r,end):events.append('curl_wait');r.update(exited=True,natural_exit=True,exit_code=0)
        o.wait_curl=waited;o.trace_after_exit=lambda r:(events.append('trace') or {'transport':{'transport_candidate':True}})
        o.proxy_leg=NS(rows={'ordinary-pipe-relay':{}},publish=lambda:events.append('arm'),
            resume=lambda *a:events.append('relay_resume'),barrier=lambda:events.append('barrier'),
            finish=lambda:events.append('origin_exit'),stop_core=lambda:events.append('core_stop'))
        def output(*a):events.append('HTTP_output');return {'exact_HTTP_body':True}
        with patch.object(m.http_report,'selected_output',side_effect=output):o.selected_run(r)
        self.assertEqual(events,['base','memory','payload','proof2','fourcloses','arm','relay_resume','held','curl_resume',
            'barrier','curl_wait','origin_exit','HTTP_output','trace','lease_after','core_stop'])
        self.assertTrue(r['resumed']);self.assertIsNotNone(o.j['resume_observation'])
    def test_late_resume_raw_is_durable_and_barrier_is_not_entered(self):
        _,api,o=self.fixture();o.window={'start':1100,'end':10000}
        r={'info':NS(hThread=22),'resumed':False}
        o.base_probe=lambda r:(0x10000,b'');o.memory_sequence=lambda *a:None;o.payload=lambda *a:None
        o.semantic=lambda *a:None;o.close_parent_pipes=lambda:None;o.held=lambda *a:None
        called=[];o.proxy_leg=NS(rows={'ordinary-pipe-relay':{}},publish=lambda:None,resume=lambda *a:None,barrier=lambda:called.append('bad'))
        def resume(h):o.budget.now=9999;return 1,None
        api.resume_raw=resume
        with self.assertRaisesRegex(ValueError,'a5_resume_once'):o.selected_run(r)
        self.assertEqual(called,[]);raw=m.decode(o.j['resume_observation']['text'].encode())['data']
        self.assertEqual(raw['count'],1);self.assertEqual(raw['returned_qpc'],10000);self.assertTrue(r['resumed'])
    def test_unknown_pipe_resource_blocks_profile_delete(self):
        _,api,o=self.fixture();o.profile.update(attempted=True,returned=True,created=True,pointer=123,sid='S-1-15-2-1')
        o.j.update(profile_created=True,profile_sid=o.profile['sid']);o.pipe_allocation_unknown=True
        deleted=[];api.delete_profile=lambda p:deleted.append(p)
        with patch.object(m.base.ac,'_cleanup',return_value=(True,True,[])):o.cleanup()
        self.assertTrue(api.controls_uncertain);self.assertFalse(o.j['profile_deleted']);self.assertEqual(deleted,[])
    def test_core_stop_is_consumed_even_when_held_or_terminate_fails(self):
        _,api,o=self.fixture();p=m.proxy_runtime.ProxyLeg(o,m._context())
        p.rows['mihomo-core']={'pid':42,'created':123,'image_sha256':'a'*64,'info':NS(hProcess=10)}
        calls=[];o.held=lambda *a:(_ for _ in ()).throw(OSError('held unknown'))
        api.terminate_core=lambda *a:calls.append('terminate')
        with self.assertRaises(OSError):p.stop_core()
        first=p.j['core_stop']
        with self.assertRaisesRegex(ValueError,'core_stop_once'):p.stop_core()
        self.assertIs(p.j['core_stop'],first);self.assertEqual(calls,[])

class APIShapeTests(unittest.TestCase):
    def test_create_pipe_buffer65536_and_failed_or_max_outputs_unowned(self):
        # Bypass backend construction. Only this Python-shaped ctypes callback runs.
        for success,values in ((True,(41,42)),(False,(0,0)),(True,(0xffffffffffffffff,42))):
            with self.subTest(success=success,values=values):
                api=object.__new__(m.API);api.controls_uncertain=False;seen=[]
                def create(rd,wr,sa,size):
                    seen.append(size);rd._obj.value=values[0];wr._obj.value=values[1];return success
                api.k=NS(CreatePipe=create,LocalFree=lambda p:0);api.pipe_descriptor=lambda sid:(123,'expected')
                api.pipe_sddl=lambda h:'expected';api.pipe_flags=lambda h:1;api.pipe_type=lambda h:3
                state={};ledger=m.helpers.OneShotHandles(lambda h:None)
                with patch.object(C,'get_last_error',return_value=5,create=True):
                    if success and max(values)<0xffffffffffffffff:
                        self.assertEqual(api.allocate_pipe(ledger,(),'',state,Budget(),100000),values)
                    else:
                        with self.assertRaises((ValueError,OSError)):api.allocate_pipe(ledger,(),'',state,Budget(),100000)
                        self.assertFalse(ledger.pending);self.assertTrue(state['unknown'])
                self.assertEqual(seen,[65536]);self.assertEqual(state['allocation_size'],65536)
    def test_normal320_and_total384_keep_cleanup_reservation(self):
        api=object.__new__(m.API);api.controls_uncertain=False;api.a5_calls=[{}]*320
        emit=NS(intent=lambda *a:'a'*64);emit.__call__=lambda *a:None
        invoked=[]
        with self.assertRaisesRegex(ValueError,'capacity'):
            api._record('CloseHandle',{'handle':1},lambda:invoked.append(1),lambda:({},b''),budget=Budget(),end=100000,emit=emit)
        self.assertEqual(invoked,[])
        api.a5_calls=[{}]*384
        with self.assertRaisesRegex(ValueError,'capacity'):
            api._record('CloseHandle',{'handle':1},lambda:invoked.append(1),lambda:({},b''),budget=Budget(),end=100000,emit=emit,known_close=True)
        self.assertEqual(invoked,[])

if __name__=='__main__':unittest.main()
