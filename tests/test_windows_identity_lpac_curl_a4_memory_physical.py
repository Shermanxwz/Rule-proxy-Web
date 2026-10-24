"""Unexecuted pure file/recorder tests for A4 memory physical validation.

The actual NativeAPI._record method is reached only through __new__, with
Python invoke/output/clock callbacks and a WinDLL trap. The PE below is an
explicit injected fixture used only by an incomplete PBI/PEB probe prefix;
there is no real target, PE mutation, full memory qualification or native API.
"""
import copy
import ctypes
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True):
    core=load('a4_memory_physical_core_fixture','windows_identity_lpac_curl_a4_loader.py')
    physical=load('a4_memory_physical_under_test','windows_identity_lpac_curl_a4_memory_physical.py')


class Clock:
    def __init__(self,steps):self.steps=iter(steps)
    def read(self):
        value=next(self.steps)
        if isinstance(value,BaseException):raise value
        return value


class Recorder:
    def __init__(self,fixture):self.f=fixture
    def intent(self,operation,arguments,qpc):
        f=self.f;index=len(f.j['api_intents'])
        value=f.envelope(index=index,operation=operation,arguments=arguments,qpc=qpc)
        row=f.json_file('api-calls','%03d-intent.json'%index,value)
        f.j['api_intents'].append(row);return row['sha256']
    def __call__(self,row,raw):
        f=self.f;index=len(f.j['api_calls']);binary=f.binary('api-%03d.bin'%index,raw)
        value=f.envelope(index=index,call=copy.deepcopy(row),output=binary)
        f.j['api_calls'].append(f.json_file('api-calls','%03d-return.json'%index,value))


class Fixture:
    def __init__(self,root):
        self.root=root
        for name in ('journal','returns','memory','api-calls'):(root/name).mkdir()
        self.c=dict(run='1'*32,source_sha256='2'*64,recovery_plan_sha256='3'*64,
            frequency=1000,start_qpc=100000,root_deadline_qpc=220000,deadline_qpc=215000,
            curl_path=str(root/'fixed-fixture.bin'))
        image=b'injected fixed image bytes, not curl\n';Path(self.c['curl_path']).write_bytes(image)
        self.c['artifacts']={'curl':dict(bytes=len(image),sha256=core.sha(image))}
        self.m=SimpleNamespace(**vars(core))
        self.m.builder=SimpleNamespace(SIZE_IMAGE=0xD0000,SIZE_HEADERS=1024,
            verify_fixed_pe=lambda supplied:SimpleNamespace(header=b'MZ'+bytes(1022)))
        self.j=dict(intents=[],returns=[],memory_records=[],api_calls=[],api_intents=[],
            window=dict(start=110000,end=118000),base_provenance=None,memory_summary=None,
            payload=None,config_binary=None,mapping=None)
        selected_return=self.root_intent('create-selected',100001)
        receipt=self.root_return('create-selected',selected_return,
            {'raw_pi':[201,202,77,78]},100010)
        self.selected=dict(receipt=receipt,pid=77,created=123456,resumed=False,
            inherited_handles=[101,102,103,104],held_checks=[])
        self.root_intent('base-probe',110001)
        self.api=core.NativeAPI.__new__(core.NativeAPI)
        self.api.a4_calls=[];self.api.controls_uncertain=False
        self.recorder=Recorder(self)
    def envelope(self,**extra):
        return dict(schema_version=1,scope=core.SCOPE,run=self.c['run'],
            config_sha256=core.sha(core.encode(self.c)),**extra)
    def json_file(self,directory,name,value):
        raw=core.encode(value);(self.root/directory/name).write_bytes(raw)
        return dict(name=name,text=raw.decode('ascii'),sha256=core.sha(raw))
    def binary(self,name,raw):
        (self.root/name).write_bytes(raw);return dict(name=name,bytes=len(raw),sha256=core.sha(raw))
    def root_intent(self,action,qpc):
        row=self.json_file('journal','%03d-%s.json'%(len(self.j['intents']),action),
            self.envelope(action=action,qpc=qpc,frequency=self.c['frequency'],deadline_qpc=self.c['deadline_qpc']))
        self.j['intents'].append(row);return row
    def root_return(self,action,intent,data,qpc):
        row=self.json_file('returns','%03d-%s.json'%(len(self.j['returns']),action),
            self.envelope(action=action,intent_sha256=intent['sha256'],qpc=qpc,data=data))
        self.j['returns'].append(row);return row
    def pbi(self,mode='returned'):
        raw=bytearray(48);struct.pack_into('<Q',raw,8,0x200000);struct.pack_into('<Q',raw,32,77)
        def invoke():
            if mode=='exception':raise OSError('inert unreturned PBI')
            return 0
        clock=Clock((110002,110003,OSError('postclock unknown') if mode=='unknown-clock' else 110004))
        try:
            with patch.object(core.C,'get_last_error',return_value=0,create=True):
                core.NativeAPI._record(self.api,'NtQueryInformationProcess(PBI48)',
                    dict(process=201,information_class=0,bytes=48),invoke,
                    lambda:(dict(returned_length=48),bytes(raw)),budget=clock,end=118000,emit=self.recorder)
        except ValueError:
            if mode=='returned':raise
        return self.api.a4_calls[-1]
    def probe(self,success=True):
        args=dict(process=201,address=0x200000,bytes=32,argument=0)
        record=dict(kind='a4-probe-intent',operation='read',arguments=args,qpc=110005)
        reference=self.memory_record(record,b'')
        data=bytearray(32)
        if success:struct.pack_into('<Q',data,16,0x140000000)
        raw=core.memory.Raw('read',True,1 if success else 0,True,0,None,
            (('transferred',32 if success else 0),),bytes(data))
        record=dict(kind='a4-probe-return',operation='read',arguments=args,intent_sha256=reference,
            entered_qpc=110006,raw=raw.record(),returned_qpc=110007,
            return_clock_known=True,timely=True,clock_error=None)
        self.memory_record(record,raw.data);return raw
    def memory_record(self,record,raw):
        index=len(self.j['memory_records']);binary=self.binary('memory-%03d.bin'%index,raw)
        value=self.envelope(index=index,record=copy.deepcopy(record),output=binary)
        row=self.json_file('memory','%03d.json'%index,value);self.j['memory_records'].append(row)
        return row['sha256']
    def review(self):
        return physical.validate_memory_records(self.m,self.j,self.c,self.root,self.selected)
    def change_api_row(self,change):
        descriptor=self.j['api_calls'][0];value=core.decode(descriptor['text'].encode('ascii'))
        change(value['call'])
        self.j['api_calls'][0]=self.json_file('api-calls',descriptor['name'],value)


class MemoryPhysicalTests(unittest.TestCase):
    def setUp(self):
        trap=patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True)
        trap.start();self.addCleanup(trap.stop)
    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        return Fixture(Path(td.name).resolve())
    def test_production_recorder_prefix_matches_required_schema_and_stays_partial(self):
        f=self.fixture();row=f.pbi();f.probe()
        self.assertIs(row['admission_known'],True)
        value=f.review()
        self.assertEqual(value,dict(base=None,memory_complete=False,payload_pointer=False,payload_readonly=False,config=None))
        # PBI/one PEB read is a legal physical prefix, not full base provenance
        # or a successful 23-call memory publication.
        self.assertEqual(len(f.j['api_calls']),1);self.assertEqual(len(f.j['memory_records']),2)
    def test_rehashed_admission_field_drift_cannot_qualify_following_probe(self):
        for kind in ('missing','bool-type','not-admitted'):
            f=self.fixture();f.pbi();f.probe()
            def mutate(row):
                if kind=='missing':del row['admission_known']
                elif kind=='bool-type':row['admission_known']=1
                else:row['admission_known']=False;row['timely']=False
            f.change_api_row(mutate)
            with self.subTest(kind=kind),self.assertRaises(ValueError):f.review()
    def test_physical_json_and_binary_tampering_are_not_replaced_by_metadata(self):
        for kind in ('JSON','API-binary','probe-binary'):
            f=self.fixture();f.pbi();f.probe()
            if kind=='JSON':(f.root/'api-calls'/'000-return.json').write_bytes(b'{}')
            elif kind=='API-binary':(f.root/'api-000.bin').write_bytes(bytes(48))
            else:(f.root/'memory-001.bin').write_bytes(bytes(32))
            with self.subTest(kind=kind),self.assertRaises(ValueError):f.review()
    def test_false_error_zero_and_unknown_PBI_remain_partial_raw_evidence(self):
        f=self.fixture();f.pbi();raw=f.probe(success=False);value=f.review()
        self.assertEqual(raw.value,0);self.assertEqual(raw.error,0)
        self.assertTrue(raw.record()['failure_error_valid'])
        self.assertIsNone(value['base']);self.assertFalse(value['memory_complete'])
        for mode in ('exception','unknown-clock'):
            f=self.fixture();row=f.pbi(mode);value=f.review()
            self.assertFalse(value['memory_complete']);self.assertFalse(value['payload_readonly'])
            self.assertTrue(f.api.controls_uncertain)
            if mode=='exception':
                self.assertFalse(row['returned']);self.assertIsNone(row['raw_return'])
            else:
                self.assertTrue(row['returned']);self.assertEqual(row['raw_return'],0)
                self.assertFalse(row['clock_known']);self.assertEqual(row['error'],0)


if __name__=='__main__':unittest.main()
