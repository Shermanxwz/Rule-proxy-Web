"""Unexecuted fake-only source for the A4 parent primitive boundary.

NativeAPI.__new__ deliberately bypasses __init__. The only callable API inputs
are Python lambdas. No Windows DLL, native binding, process, memory or actor is
created. These tests do not replace the eventual held-owner/physical evidence
validator or authorize Resume.
"""
import copy
import ctypes
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    'curl_a4_primitive_inert_test',ROOT/'.github/windows_identity_lpac_curl_a4_loader.py')
m=importlib.util.module_from_spec(spec)
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True):
    spec.loader.exec_module(m)


class Budget:
    def __init__(self,steps,events):self.steps=list(steps);self.events=events;self.reads=0
    def read(self):
        self.reads+=1;self.events.append('clock-'+str(self.reads))
        if not self.steps:raise AssertionError('unexpected clock read')
        step=self.steps.pop(0)
        if isinstance(step,BaseException):raise step
        return step() if callable(step) else step


class Emitter:
    def __init__(self,events):self.events=events;self.intents=[];self.returned=[]
    def intent(self,operation,arguments,tick):
        self.events.append('intent');self.intents.append((operation,copy.deepcopy(arguments),tick))
        return 'a'*64
    def __call__(self,row,raw):
        self.events.append('emit');self.returned.append((copy.deepcopy(row),bytes(raw)))


class PrimitiveTests(unittest.TestCase):
    def setUp(self):
        self.trap=patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True)
        self.trap.start();self.addCleanup(self.trap.stop)

    def api(self):
        api=m.NativeAPI.__new__(m.NativeAPI)
        api.a4_calls=[];api.controls_uncertain=False
        return api

    def test_known_true_is_sealed_and_adopted_before_late_postclock(self):
        api=self.api();events=[];owned=[];emitter=Emitter(events)
        def invoke():events.append('invoke');return 0x120
        def last_error():events.append('last-error');return 0
        def outputs():events.append('outputs');return ({'handle':0x120},b'known-output')
        def adopt(row):
            events.append('adopt')
            self.assertIs(api.a4_calls[-1],row)
            self.assertTrue(row['returned']);self.assertEqual(row['raw_return'],0x120)
            self.assertTrue(row['error_captured']);self.assertEqual(row['error'],0)
            self.assertEqual(row['output_sha256'],m.sha(b'known-output'))
            self.assertIsNone(row['post_call_qpc']);owned.append(row['raw_return'])
        def late():
            self.assertEqual(owned,[0x120]);self.assertEqual(len(api.a4_calls),1)
            return 25
        budget=Budget((10,11,late),events)
        with patch.object(m.C,'get_last_error',side_effect=last_error,create=True):
            with self.assertRaisesRegex(ValueError,'a4_parent_raw_or_clock'):
                api._record('DuplicateHandle',{'inherited':True},invoke,outputs,
                    budget=budget,end=20,emit=emitter,adopt=adopt)
        self.assertEqual(owned,[0x120]);self.assertEqual(budget.reads,3)
        self.assertEqual(events,['clock-1','intent','clock-2','invoke','last-error','outputs','adopt','clock-3','emit'])
        row,raw=emitter.returned[0]
        self.assertTrue(row['returned']);self.assertTrue(row['clock_known']);self.assertFalse(row['timely'])
        self.assertEqual((row['raw_return'],row['error'],raw),(0x120,0,b'known-output'))

    def test_invoke_exception_preserves_sealed_partial_and_sticky_unknown(self):
        api=self.api();events=[];emitter=Emitter(events);invocations=[]
        def invoke():invocations.append(1);raise OSError('inert unreturned call')
        with patch.object(m.C,'get_last_error',side_effect=AssertionError('no returned API'),create=True):
            with self.assertRaisesRegex(ValueError,'a4_parent_raw_or_clock'):
                api._record('CreateFileMappingW',{'bytes':557312},invoke,
                    lambda:({'partial_output':17},b'partial'),
                    budget=Budget((10,11,12),events),end=20,emit=emitter)
        self.assertEqual(invocations,[1]);self.assertTrue(api.controls_uncertain)
        self.assertEqual(len(api.a4_calls),1);self.assertEqual(len(emitter.returned),1)
        row,raw=emitter.returned[0]
        self.assertTrue(row['entered']);self.assertFalse(row['returned']);self.assertIsNone(row['raw_return'])
        self.assertEqual(row['native_exception'],'OSError');self.assertFalse(row['error_captured'])
        self.assertIsNone(row['error']);self.assertEqual(row['outputs'],{'partial_output':17})
        self.assertEqual((raw,row['output_sha256']),(b'partial',m.sha(b'partial')))

    def test_postclock_unknown_keeps_known_handle_and_raw_return(self):
        api=self.api();events=[];owned=[];emitter=Emitter(events)
        with patch.object(m.C,'get_last_error',return_value=0,create=True):
            with self.assertRaisesRegex(ValueError,'a4_parent_raw_or_clock'):
                api._record('DuplicateHandle',{},lambda:0x130,lambda:({'handle':0x130},b'raw'),
                    budget=Budget((10,11,OSError('inert postclock failure')),events),end=20,
                    emit=emitter,adopt=lambda row:owned.append(row['raw_return']))
        self.assertEqual(owned,[0x130]);self.assertEqual(len(api.a4_calls),1)
        row,raw=emitter.returned[0]
        self.assertTrue(row['returned']);self.assertEqual(row['raw_return'],0x130)
        self.assertEqual(row['error'],0);self.assertTrue(row['error_captured'])
        self.assertFalse(row['clock_known']);self.assertFalse(row['timely'])
        self.assertIsNone(row['post_call_qpc']);self.assertEqual(row['clock_error'],'OSError')
        self.assertEqual(raw,b'raw');self.assertTrue(api.controls_uncertain)

    def test_known_close_consumed_before_clock_failure_still_invokes_once(self):
        for name,first,intent_tick in (('both-preclocks-fail',OSError('first preclock'),None),
                ('second-preclock-only-fails',10,10)):
            with self.subTest(case=name):
                api=self.api();events=[];emitter=Emitter(events);pending={0x140};closed=[]
                # Consumption belongs to the caller ledger and precedes the raw close.
                pending.remove(0x140)
                def close():
                    self.assertNotIn(0x140,pending);closed.append(0x140);return 1
                with patch.object(m.C,'get_last_error',return_value=0,create=True):
                    with self.assertRaisesRegex(ValueError,'a4_parent_raw_or_clock'):
                        api._record('CloseHandle',{'handle':0x140},close,lambda:({},b''),
                            budget=Budget((first,OSError('second preclock'),15),events),
                            end=20,emit=emitter,known_close=True)
                self.assertEqual(closed,[0x140]);self.assertFalse(pending)
                self.assertEqual(len(emitter.intents),1);self.assertEqual(emitter.intents[0][2],intent_tick)
                row,raw=emitter.returned[0]
                self.assertTrue(row['returned']);self.assertEqual(row['raw_return'],1)
                self.assertTrue(row['error_captured']);self.assertEqual(row['error'],0)
                self.assertTrue(row['clock_known']);self.assertEqual(row['post_call_qpc'],15)
                # A good first clock cannot substitute for the failed immediate
                # pre-invoke admission clock, even with a good post-return clock.
                self.assertFalse(row['timely']);self.assertEqual(raw,b'')

    def test_false_error_zero_and_partial_count_are_not_rewritten(self):
        api=self.api();events=[];emitter=Emitter(events)
        with patch.object(m.C,'get_last_error',return_value=0,create=True):
            row=api._record('WriteProcessMemory',{'requested':4},lambda:0,
                lambda:({'written':2},b'xy'),budget=Budget((10,11,12),events),end=20,emit=emitter)
        # _record preserves the primitive result; the operation-specific caller
        # must reject BOOL0/short count. A typed raw receipt is not API success.
        self.assertTrue(row['returned']);self.assertEqual(row['raw_return'],0)
        self.assertTrue(row['error_captured']);self.assertEqual(row['error'],0)
        self.assertEqual(row['outputs'],{'written':2});self.assertEqual(row['output_bytes'],2)
        self.assertEqual(emitter.returned[0][1],b'xy');self.assertEqual(row['output_sha256'],m.sha(b'xy'))

    def test_pack_config_uses_real_closed_reader_schema_and_original_bounds(self):
        config=dict(run='1'*32,trace_case='2'*32,source_sha256='3'*64,
            artifacts=copy.deepcopy(m.FROZEN_ARTIFACTS),
            frequency=1000,start_qpc=100000,root_deadline_qpc=220000)
        row={'pid':1024,'created':123456};window={'start':110000,'end':118000}
        private=r'C:\owned\windows_identity_lpac_curl_ws2_shim.dll'
        system=r'C:\Windows\System32\WS2_32.dll'
        raw=m.pack_config(config,row,window,0x100,private,system)
        value=m.trace_reader.validate_config(raw,schema_metadata=m.trace_reader.SCHEMA_METADATA)
        self.assertEqual(len(raw),2048)
        self.assertEqual(value['config_sha256'],bytes.fromhex(m.sha(m.encode(config))))
        self.assertEqual(value['source_sha256'],bytes.fromhex(config['source_sha256']))
        self.assertEqual(value['shim_sha256'],bytes.fromhex(config['artifacts']['shim']['sha256']))
        self.assertEqual(value['private_path'],private);self.assertEqual(value['system_ws2_path'],system)
        self.assertEqual((value['frequency'],value['root_start'],value['root_deadline'],value['work_deadline']),
            (1000,100000,220000,185000))
        self.assertEqual((value['window_start'],value['window_end']),(110000,118000))
        self.assertEqual((value['target_pid'],value['target_creation'],value['trace_handle']),(1024,123456,0x100))
        self.assertEqual(m.trace_reader.SCHEMA_METADATA['ABI']['sha256'],m.TRACE_ABI_SHA256)
        # Full ABI documentation has a different closed shape. It cannot be
        # silently passed in place of the independent reader metadata table.
        abi_path=ROOT/m.TRACE_ABI_MODULE;abi_raw=abi_path.read_bytes()
        self.assertEqual(m.sha(abi_raw),m.TRACE_ABI_SHA256)
        with self.assertRaisesRegex(ValueError,'schema_mismatch'):
            m.trace_reader.validate_config(raw,schema_metadata=m.decode(abi_raw))


if __name__=='__main__':unittest.main()
