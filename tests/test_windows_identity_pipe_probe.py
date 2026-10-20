import copy
import importlib.util
from pathlib import Path
import unittest
import tempfile

PATH=Path(__file__).resolve().parents[1]/'.github/windows_identity_pipe_probe.py'
SPEC=importlib.util.spec_from_file_location('identity_pipe_probe',PATH)
pipe=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(pipe)
N='a'*32; SID='S-1-15-2-1-2-3-4-5-6-7'

def good():
    return {'child_pid':42,'controller_identity':{'sid':'S-1-5-21-1-2-3-1001'},'nonce':N,'derived_sid':SID,'observed_child_sid':SID,'echo_matched':True,'exit_code':0,
            'pipe_eof_observed':True,'actor':{'schemaVersion':1,'pid':42,'tokenUserSid':'S-1-5-21-1-2-3-1001','mode':'actor-pipe','nonce':N,'tokenAppContainerSid':SID,
            'tokenIsAppContainer':True,'tokenElevated':False,'isProcessInJob':True,'queriesSucceeded':True,
            'errors':[],'pipeSucceeded':True,'tokenCapabilities':[]},
            'cleanup':{'job_closed':True,'profile_deleted':True,'handles_closed':True,'owned_aces_removed':True,'job_empty':True,'errors':[]}}

class PipeEvidenceTests(unittest.TestCase):
    def test_complete_passes(self): self.assertTrue(all(pipe.checks(good()).values()))
    def test_empty_fails(self): self.assertFalse(all(pipe.checks({}).values()))
    def test_wrong_sid_fails(self):
        r=good();r['observed_child_sid']=SID+'-8';self.assertFalse(all(pipe.checks(r).values()))
    def test_nonce_replay_fails(self):
        r=good();r['actor']['nonce']='b'*32;self.assertFalse(all(pipe.checks(r).values()))
    def test_transport_missing_or_error_fails(self):
        for key,val in [('echo_matched',False),('exit_code',1),('pipe_eof_observed',False)]:
            r=good();r[key]=val
            with self.subTest(key=key):self.assertFalse(all(pipe.checks(r).values()))
    def test_capability_grant_fails_zero_capability_stage(self):
        r=good();r['actor']['tokenCapabilities']=['S-1-15-3-3'];self.assertFalse(all(pipe.checks(r).values()))
    def test_cleanup_failure_fails(self):
        for key in ('job_closed','profile_deleted','handles_closed','owned_aces_removed','job_empty'):
            r=good();r['cleanup'][key]=False
            with self.subTest(key=key):self.assertFalse(all(pipe.checks(r).values()))
    def test_owned_tree_is_bounded(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for i in range(33): (root/str(i)).write_text('fixture')
            with self.assertRaises(RuntimeError):pipe.owned_paths(root)
    def test_owned_tree_rejects_symlink_before_recursing(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); target=root/'target';target.mkdir()
            try:(root/'alias').symlink_to(target,target_is_directory=True)
            except OSError:self.skipTest('symlink creation unavailable')
            with self.assertRaises(RuntimeError):pipe.owned_paths(root)
    def test_owned_tree_lists_fresh_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/'inputs').mkdir();(root/'inputs'/'actor').write_text('fixture')
            self.assertEqual(len(pipe.owned_paths(root)),3)
    def test_sid_pointer_accepts_only_bounded_valid_sid(self):
        C=pipe.C; header=C.sizeof(C.c_void_p)
        buf=C.create_string_buffer(header+12)
        C.c_void_p.from_buffer(buf).value=C.addressof(buf)+header
        C.c_ubyte.from_buffer(buf,header).value=1
        C.c_ubyte.from_buffer(buf,header+1).value=1
        self.assertEqual(pipe.checked_sid_pointer(buf,len(buf)),C.addressof(buf)+header)
        for returned in (0,header,len(buf)-1,len(buf)+1):
            with self.subTest(returned=returned),self.assertRaises(RuntimeError):
                pipe.checked_sid_pointer(buf,returned)
        C.c_ubyte.from_buffer(buf,header+1).value=16
        with self.assertRaises(RuntimeError):pipe.checked_sid_pointer(buf,len(buf))
    def test_sid_pointer_rejects_null_or_external_pointer(self):
        C=pipe.C;buf=C.create_string_buffer(32)
        for pointer in (None,C.addressof(buf)-1,C.addressof(buf)+28):
            C.c_void_p.from_buffer(buf).value=pointer
            with self.subTest(pointer=pointer),self.assertRaises(RuntimeError):
                pipe.checked_sid_pointer(buf,len(buf))
    def test_runtime_requires_permission(self):
        class Args: disposable_ci=False;approved_security_test=False
        with self.assertRaises(PermissionError):pipe.run(Args())

if __name__=='__main__':unittest.main()
