"""Source-only injected tests for the new owner's bounded coordination seams.

These tests do not execute a kernel binding, a DLL, curl, a compiler, a network
operation or an inherited CMM run. They do not claim a complete A4 observation.
"""
import ctypes as C
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
with patch.object(C,'WinDLL',side_effect=AssertionError('WinDLL forbidden'),create=True):
    spec=importlib.util.spec_from_file_location('a4_owner_inert_source',ROOT/'.github/windows_identity_lpac_curl_a4_loader.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

SID='S-1-5-21-1-2-3-1001'
class Budget:
    frequency=1000;deadline=116000
    def __init__(self):self.now=1100
    def read(self):self.now+=1;return self.now
    def cutoff(self,seconds):return self.deadline-seconds*self.frequency
    def require_ms(self,end):
        if self.read()>=end:raise ValueError('clock expired')
        return 1

class API:
    def __init__(self):self.controls_uncertain=False;self.a4_calls=[];self.closed=[];self.labels={};self.unmaps=[];self.fault=None
    def close(self,h):self.closed.append(h)
    def a4_close(self,h,**kw):self.close(h)
    def unmap(self,view,**kw):
        self.unmaps.append(view)
        if self.fault=='unmap':raise OSError('unknown view close')
    def label_set(self,path,value):self.labels[Path(path)]=value
    def label_read(self,path):
        path=Path(path)
        for node in (path,*path.parents):
            if self.labels.get(node) is not None:return self.labels[node]
        return None
    def release_profile_sid(self,profile):profile['pointer']=None
    def process_id(self,h):return 42
    def creation_time(self,h):return 123456789012345678
    def wait(self,h,ms):return False
    def verify_job(self,*a):pass
    def verify_outer(self,*a):pass
    def verify_image(self,*a):pass
    def kernel_sddl(self,h):return 'D:P(A;;GA;;;SY)(A;;GA;;;'+SID+')'
    def current_primary(self,process,ledger,other,**kw):ledger.add(500);return 500

class OwnerTests(unittest.TestCase):
    def setUp(self):
        for obj,key in ((C,'WinDLL'),(m,'NativeAPI')):
            trap=patch.object(obj,key,side_effect=AssertionError('backend forbidden'),create=True);trap.start();self.addCleanup(trap.stop)
    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('journal','returns','selected-output'):(root/name).mkdir()
        c=dict(run='1'*32,frequency=1000,start_qpc=1000,deadline_qpc=116000,root_deadline_qpc=121000,
            guard_job_name='Local\\RuleProxy.LocalGuard.'+'1'*32,curl_path=r'C:\Windows\System32\curl.exe')
        api=API();owner=m.Owner(root,c,dict(sid=SID),api,Budget());return root,api,owner
    def test_current_primary_is_opened_afresh_and_changed_object_rejected(self):
        root,api,o=self.fixture();o.job=900
        row=dict(info=SimpleNamespace(hProcess=400,hThread=401),pid=42,created=123456789012345678,
            token=499,lpac_expected=False,expected_primary={'token_id':10},kernel_security={'process':api.kernel_sddl(400),'thread':api.kernel_sddl(401)},held_checks=[])
        seen=[]
        def capture(api_value,token,*args):seen.append(token);return {'token_id':20}
        with patch.object(m.zero,'capture_primary',side_effect=capture):
            with self.assertRaisesRegex(ValueError,'a4_current_primary_changed'):o.held(row,100000)
        self.assertEqual(seen,[500]);self.assertNotIn(499,seen);self.assertEqual(api.closed,[500]);self.assertTrue(o.j['query_resources_closed'])
    def test_second_observer_exception_cannot_borrow_first_cleanup(self):
        root,api,o=self.fixture();o.held=lambda *args:None
        row=dict(info=SimpleNamespace(hProcess=400),expected_primary={'token_id':10},pid=42,created=123456789012345678)
        proof={'qualified':True,'resource_cleanup_verified':True}
        with patch.object(m.zero,'observe_held',side_effect=[proof,OSError('second observation unknown')]):
            api.access_api=lambda:object();o.semantic(row,'before-memory',100000)
            with self.assertRaises(OSError):o.semantic(row,'before-resume',100000)
        self.assertEqual(len(o.j['proofs']),1);self.assertTrue(o.j['proofs'][0]['value']['qualified'])
        self.assertFalse(o.j['observer_resources_cleanup_verified'])
    def test_inherited_low_labels_are_all_written_before_any_readback(self):
        root,api,o=self.fixture();child=root/'selected-output'/'stdout';child.write_bytes(b'')
        api.labels[root/'selected-output']=m.zero.LOW_LABEL
        api.label_set(child,None);self.assertEqual(api.label_read(child),m.zero.LOW_LABEL)
        o.j['labels']=[dict(name='selected-output',attempted=True,lowered=True,restored=False)];o.j['labels_restored']=False
        with patch.object(m.base.ac,'_cleanup',return_value=(True,True,[])):o.cleanup()
        self.assertTrue(o.j['labels_restored']);self.assertIsNone(api.label_read(child));self.assertIsNone(api.label_read(child.parent))
        self.assertTrue(all(o.j[k] for k in m.CLEAN_KEYS))
    def test_unknown_view_unmap_consumed_once_and_blocks_profile_deletion(self):
        root,api,o=self.fixture();api.fault='unmap';o.view=0x123000;o.j['trace_view_unmapped']=False
        o.mapping_owners.add(700);o.j['trace_mapping_closed']=False;o.profile.update(attempted=True,created=True,sid='S-1-15-2-1',pointer=800)
        with patch.object(m.base.ac,'_cleanup',return_value=(True,True,[])):
            o.cleanup();o.cleanup()
        self.assertEqual(api.unmaps,[0x123000]);self.assertEqual(api.closed.count(700),1)
        self.assertFalse(o.j['trace_view_unmapped']);self.assertFalse(o.j['profile_deleted']);self.assertTrue(api.controls_uncertain)
    def test_fixed_payload_framing_has_exact_source_owned_offsets(self):
        config=bytes(range(256))*8;raw=m.payload_framing(config)
        self.assertEqual(len(raw),2504);self.assertEqual(raw[456:],config)
        self.assertEqual(raw[:2],b'MZ');self.assertEqual(struct.unpack_from('<I',raw,60)[0],64)
        self.assertEqual(raw[64:68],b'PE\0\0');self.assertEqual(raw[328:336],b'.detour\0')
        self.assertEqual(struct.unpack_from('<4I',raw,368),(64,0x00727444,64,2136))
        self.assertEqual(struct.unpack_from('<II',raw,432),(2072,0));self.assertEqual(raw[440:456],m.GUID_BYTES)

if __name__=='__main__':unittest.main()
