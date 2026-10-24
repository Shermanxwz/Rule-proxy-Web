"""Diagnostic-only fake tests; no target, library, compiler or Windows API."""
import ast
import ctypes as C
import importlib.util
from pathlib import Path
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('A5_failure_capture_fixture',HERE/'test_windows_identity_lpac_curl_a5_loader.py')
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
m=fixture.m

class FailureCaptureTests(unittest.TestCase):
    def setUp(self):
        for obj,key in ((C,'WinDLL'),(m,'NativeAPI')):
            guard=patch.object(obj,key,side_effect=AssertionError('production backend forbidden'),create=True)
            guard.start();self.addCleanup(guard.stop)
    def owner(self):
        root,api,o=fixture.OwnerTests.fixture(self)
        o.j['failure']='proxy';o.j['failure_detail']={'type':'GateFailure','operation':'proxy','message':'qpc_expired'}
        o.window=dict(start=1100,end=1500);o.j['window']=dict(o.window);o.budget.now=2000
        o.mapping_handle=123;o.mapping_owners.add(123);o.view=0x100000
        o.tasks['selected']=dict(exited=True,exit_code=27,exit_observed_qpc=1900,pid=42,created=123456789,
            natural_exit=False,info=NS(hProcess=400,hThread=401))
        return root,api,o
    def test_memory_producer_and_physical_consumer_share_A5_scope(self):
        seen=[];coordinator=object.__new__(m.memory.Coordinator)
        coordinator.bindings=NS(source='synthetic');coordinator.epoch=NS(window_start=1,window_end=2)
        coordinator.journal=lambda value,raw:(seen.append((value,raw)) or 'a'*64)
        self.assertEqual(coordinator._persist({'kind':'synthetic'},b''),'a'*64)
        actual=seen[0][0]['scope'];self.assertEqual(actual,'A5-fixed-two-descriptor-memory-v1')
        tree=ast.parse(Path(m.memory_physical.__file__).read_bytes())
        constants={n.value for n in ast.walk(tree) if isinstance(n,ast.Constant) and type(n.value)is str}
        self.assertIn(actual,constants);self.assertNotIn('A4-fixed-two-descriptor-memory-v1',constants)
    def test_late_app_window_is_saved_only_as_private_diagnostic(self):
        root,api,o=self.owner();original_failure=dict(o.j['failure_detail']);trace=bytes(m.TRACE_BYTES)
        with patch.object(C,'string_at',return_value=trace) as read:
            value=o.capture_failure_trace()
        self.assertEqual(read.call_args_list,[unittest.mock.call(0x100000,m.TRACE_BYTES)]*2)
        self.assertTrue(value['complete']);self.assertFalse(value['within_original_window'])
        self.assertTrue(value['within_original_cleanup']);self.assertEqual(value['original_window_deadline'],1500)
        self.assertEqual(value['cleanup_cutoff'],o.budget.cutoff(8));self.assertTrue(value['diagnostic_only'])
        for key in ('successful_observation','HTTP_qualified','window_qualification'):self.assertFalse(value[key])
        self.assertIsNone(o.j['trace_binary']);self.assertIsNone(o.j['trace_review'])
        self.assertEqual(o.j['failure'],'proxy');self.assertEqual(o.j['failure_detail'],original_failure)
        self.assertEqual((root/'a5-failure-trace.bin').read_bytes(),trace)
        side=m.decode((root/'a5-failure-trace-capture.json').read_bytes());self.assertEqual(side,value)
        with patch.object(C,'string_at',side_effect=AssertionError('capture must be once')):
            self.assertIsNone(o.capture_failure_trace())
    def test_unknown_exit_or_unowned_view_never_reads(self):
        for mode in ('unknown_exit','missing_generation','view_consumed','mapping_consumed','mapping_uncertain'):
            with self.subTest(mode=mode):
                root,api,o=self.owner()
                if mode=='unknown_exit':o.tasks['selected']['exited']=False
                elif mode=='missing_generation':o.tasks['selected']['created']=None
                elif mode=='view_consumed':o.view_consumed=True
                elif mode=='mapping_consumed':o.mapping_owners.pending.clear()
                else:o.mapping_owners.uncertain=True
                with patch.object(C,'string_at',side_effect=AssertionError('not owned/known')) as read:
                    result=o.capture_failure_trace()
                self.assertFalse(result['complete']);read.assert_not_called()
                self.assertFalse((root/'a5-failure-trace.bin').exists())
    def test_original_cleanup_expiry_before_and_after_read(self):
        for when in ('before','after'):
            with self.subTest(when=when):
                root,api,o=self.owner();end=o.budget.cutoff(8)
                clock=[end] if when=='before' else [2001,end]
                with patch.object(o.budget,'read',side_effect=clock),patch.object(C,'string_at',return_value=bytes(m.TRACE_BYTES)) as read:
                    result=o.capture_failure_trace()
                self.assertFalse(result['complete']);self.assertEqual(result['cleanup_cutoff'],end)
                self.assertEqual(read.call_count,0 if when=='before' else 2)
                self.assertFalse((root/'a5-failure-trace.bin').exists())
    def test_exact_size_and_stability_are_required_before_binary_write(self):
        for samples,code in (((bytes(m.TRACE_BYTES-1),bytes(m.TRACE_BYTES)),'exact_trace_size_mismatch'),
                             ((bytes(m.TRACE_BYTES),bytes(m.TRACE_BYTES-1)+b'1'),'trace_unstable')):
            with self.subTest(code=code):
                root,api,o=self.owner()
                with patch.object(C,'string_at',side_effect=samples):result=o.capture_failure_trace()
                self.assertEqual(result['status'],code);self.assertFalse(result['complete'])
                self.assertFalse((root/'a5-failure-trace.bin').exists())
    def test_only_exact_diagnostic_filename_gets_large_binary_exception(self):
        root,api,o=self.owner()
        for size in (0,m.TRACE_BYTES-1,m.TRACE_BYTES+1):
            with self.subTest(size=size),self.assertRaisesRegex(ValueError,'a5_trace_binary_size'):
                m.binary_record(root,'a5-failure-trace.bin',bytes(size))
        with self.assertRaisesRegex(ValueError,'durable_bound'):
            m.binary_record(root,'other-failure.bin',bytes(m.TRACE_BYTES))
        self.assertFalse((root/'other-failure.bin').exists())
    def test_run_captures_before_unmap_and_capture_failure_never_skips_cleanup(self):
        for capture_error in (False,True):
            with self.subTest(capture_error=capture_error):
                root,api,o=self.owner();events=[]
                o.stop_selected=lambda:events.append('exit_confirmed')
                def cleanup():
                    events.append('cleanup')
                    self.assertFalse(o.view_consumed);self.assertIn(o.mapping_handle,o.mapping_owners.pending)
                    self.assertTrue((root/'a5-failure-trace-capture.json').is_file())
                    self.assertEqual((root/'a5-failure-trace.bin').exists(),not capture_error)
                    o.view_consumed=True
                o.cleanup=cleanup
                def read(*args):
                    events.append('read')
                    if capture_error:raise RuntimeError('private secret must never appear in sidecar')
                    return bytes(m.TRACE_BYTES)
                with patch.object(m,'verify_artifacts',side_effect=ValueError('original setup failure')),patch.object(C,'string_at',side_effect=read):
                    result=o.run()
                self.assertEqual(events[0],'exit_confirmed');self.assertEqual(events[-1],'cleanup')
                self.assertTrue(o.view_consumed);self.assertEqual(result['failure'],'setup')
                side=(root/'a5-failure-trace-capture.json').read_text()
                self.assertNotIn('private secret',side)
                self.assertFalse(m.decode(side.encode('ascii'))['successful_observation'])
    def test_sidecar_write_failure_does_not_replace_run_failure_or_skip_cleanup(self):
        root,api,o=self.owner();o.tasks['selected']['exited']=False;called=[]
        o.stop_selected=lambda:None;o.cleanup=lambda:called.append('cleanup')
        original=m.base.durable_private
        def write(path,raw):
            if Path(path).name=='a5-failure-trace-capture.json':raise OSError('unwritable owned directory')
            return original(path,raw)
        with patch.object(m,'verify_artifacts',side_effect=ValueError('original setup failure')), \
             patch.object(m.base,'durable_private',side_effect=write):
            result=o.run()
        self.assertEqual(result['failure'],'setup');self.assertEqual(called,['cleanup'])

if __name__=='__main__':unittest.main()
