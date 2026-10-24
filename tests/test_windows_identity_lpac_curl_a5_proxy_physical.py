"""Focused fake records only; no owner import, Windows API or network."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
import unittest

PATH=Path(__file__).resolve().parents[1]/'.github/windows_identity_lpac_curl_a5_proxy_physical.py'
SPEC=importlib.util.spec_from_file_location('a5_proxy_physical_test_module',PATH)
P=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(P)
def need(value,label):
    if not value:raise ValueError(label)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')
def integer(value,low,high):return type(value) is int and low<=value<=high
def descriptor(value):
    raw=encode(value);return dict(name='000-fake.json',text=raw.decode('ascii'),sha256=sha(raw))

TASK_KEYS={'name','attempted','assigned','exited','exit_code','pid','created','process_returned','resumed','admitted','image_sha256',
    'admission_qpc','resume_qpc','resume_intent_qpc','exit_observed_qpc','natural_exit','identity','capabilities','lpac','lpac_expected',
    'expected_primary','held_checks','receipt','create_observation','constructor_return_qpc','inherited_handles','parent_copies_closed','kernel_security'}
TASK_BOOLS={'attempted','assigned','exited','process_returned','resumed','admitted','natural_exit','lpac_expected','parent_copies_closed'}


class RawAuthority(unittest.TestCase):
    def setUp(self):
        self.m=SimpleNamespace(require=need,sha=sha,encode=encode,decode=json.loads,
            live=SimpleNamespace(integer=integer),mm=SimpleNamespace(TASK_KEYS=TASK_KEYS,TASK_BOOLS=TASK_BOOLS))
        self.close=dict(operation='CloseHandle(A5_external)',arguments={'handle':77},
            admission_known=True,entered=True,returned=True,clock_known=True,timely=True,raw_return=1,
            error_captured=True,native_exception=None,error_exception=None,output_error=None,clock_error=None,
            outputs={},output_bytes=0,output_sha256=sha(b''),intent_sha256='i',entered_qpc=30,post_call_qpc=31)
        self.value=dict(action='close-core-stdio',qpc=32,data={'handle':77,'confirmed':True,'call_sha256':'close'},intent_sha256='outer')
        self.desc=descriptor(self.value);self.returns={self.desc['sha256']:self.value}
        self.calls={'close':self.close}
    def close_it(self,used=None):
        return P._close(self.m,self.desc,self.returns,self.calls,'close-core-stdio',77,20,40,set() if used is None else used)
    def test_external_close_requires_raw_success_and_is_once(self):
        used=set();self.assertEqual(self.close_it(used),32)
        with self.assertRaisesRegex(ValueError,'close_receipt'):self.close_it(used)
    def test_confirmed_bool_cannot_replace_raw_close(self):
        mutations=[('raw_return',0),('raw_return',True),('returned',False),('timely',False),
            ('clock_known',False),('error_captured',False),('native_exception','SEH'),('post_call_qpc',41),
            ('operation','CloseHandle'),('arguments',{'handle':78})]
        for key,bad in mutations:
            old=self.close[key];self.close[key]=bad
            with self.subTest(key=key,bad=bad):
                with self.assertRaises(ValueError):self.close_it()
            self.close[key]=old
    def test_close_receipt_cross_handle_or_call_rejected(self):
        for key,bad in [('handle',78),('call_sha256','missing'),('confirmed',False)]:
            old=self.value['data'][key];self.value['data'][key]=bad
            desc=descriptor(self.value)
            with self.subTest(key=key):
                with self.assertRaises(ValueError):P._close(self.m,desc,{desc['sha256']:self.value},self.calls,'close-core-stdio',77,20,40,set())
            self.value['data'][key]=old
    def open_fixture(self):
        root=Path('owned');role='mihomo-core';kind='stdout'
        intent={'qpc':10,'action':'open-core-stdio'};intent_desc=descriptor(intent)
        opening=dict(operation='CreateFileW(A5_stdio)',arguments={'path':str(root/role/kind),'read':False},
            entered=True,returned=True,raw_return=77,native_exception=None,outputs={},output_bytes=0,output_sha256=sha(b''))
        value={'action':'open-core-stdio','intent_sha256':intent_desc['sha256'],'qpc':20,
            'data':{'role':role,'kind':kind,'handle':77,'call_sha256':'open'}}
        saved=descriptor(value)
        item=dict(role=role,kind=kind,handle=77,confirmed=True,receipt=self.desc,
            open_call_sha256='open',open_intent=intent_desc,open_receipt=saved)
        return root,item,{intent_desc['sha256']:intent},{saved['sha256']:value},opening
    def test_actual_open_then_exact_close_lineage(self):
        root,item,intents,returns,opening=self.open_fixture();calls={'open':opening,**self.calls};used=set()
        tick=P._stdio_open(self.m,item,root,intents,returns,calls,used)
        self.assertEqual(tick,20)
        self.assertEqual(P._close(self.m,self.desc,self.returns,calls,'close-core-stdio',item['handle'],tick,40,used),32)
        with self.assertRaises(ValueError):P._stdio_open(self.m,item,root,intents,returns,calls,used)
    def test_opened_flag_or_expected_handle_cannot_replace_raw_return(self):
        root,item,intents,returns,opening=self.open_fixture()
        for key,bad in [('raw_return',78),('returned',False),('operation','CreateFileW'),
                ('arguments',{'path':str(root/'other'/'stdout'),'read':False}),('native_exception','SEH')]:
            original=opening[key];opening[key]=bad
            with self.subTest(key=key):
                with self.assertRaises(ValueError):P._stdio_open(self.m,item,root,intents,returns,{'open':opening},set())
            opening[key]=original
    def test_cleanup_after_open_post_clock_failure_still_has_authority(self):
        root,item,intents,returns,opening=self.open_fixture()
        opening.update(clock_known=False,post_call_qpc=None,timely=False,clock_error='ClockError')
        self.assertEqual(P._stdio_open(self.m,item,root,intents,returns,{'open':opening},set()),20)


class CleanupIndependence(unittest.TestCase):
    setUp=RawAuthority.setUp
    def empty(self):
        return dict(tasks=[],port_lease=None,core_stdio=[],pair=None,reports={},
            physical={'intents':[],'returns':[],'pipe_allocations':[],'parent_pipe_closes':[],
                'api_intents':[],'api_calls':[],'api_raw_calls':[]})
    def row(self,*,returned=True,exited=True,exit_code=5):
        row=dict.fromkeys(TASK_KEYS,None);row.update(dict.fromkeys(TASK_BOOLS,False))
        role='ordinary-origin-fixture';row.update(name=role,role=role,command=[],ends=[],resume_receipt=None,
            attempted=True,process_returned=returned,exited=exited,exit_code=exit_code if exited else None,
            pid=123 if returned else None,held_checks=[],inherited_handles=[])
        data=dict(creation_attempted=True,creation_unknown=False,create_status='returned_true' if returned else 'returned_false',
            raw_return=1 if returned else 0,raw_error=None if returned else 5,
            raw_pi=[11,12,123,124] if returned else [0,0,0,0],returned_qpc=10,
            handle_list=[],stdio=[0,0,0],handle_flags=[],inherit_handles=False)
        value=dict(action='create-'+role,qpc=11,data=data);row['receipt']=descriptor(value)
        return row,{row['receipt']['sha256']:value}
    def test_known_nonzero_terminated_child_can_be_clean_without_HTTP(self):
        p=self.empty();row,returns=self.row();p['tasks']=[row]
        self.assertFalse(row['natural_exit']);self.assertEqual(row['exit_code'],5)
        self.assertTrue(P._cleanup(self.m,p,{'start_qpc':1,'deadline_qpc':100},None,{},returns,{}))
    def test_exact_create_false_no_child_is_known_clean(self):
        p=self.empty();row,returns=self.row(returned=False,exited=False);p['tasks']=[row]
        self.assertTrue(P._cleanup(self.m,p,{'start_qpc':1,'deadline_qpc':100},None,{},returns,{}))
        next(iter(returns.values()))['data']['raw_pi'][0]=55
        with self.assertRaises(ValueError):P._cleanup(self.m,p,{'start_qpc':1,'deadline_qpc':100},None,{},returns,{})
    def test_worker_cleanup_bool_cannot_hide_unexited_child(self):
        p=self.empty();row,returns=self.row(exited=False);p.update(tasks=[row],workload_stop=True)
        with self.assertRaises(ValueError):P._cleanup(self.m,p,{'start_qpc':1,'deadline_qpc':100},None,{},returns,{})
    def test_missing_close_stays_unknown_despite_confirmed_summary(self):
        p=self.empty();p['core_stdio_closed']=True
        p['core_stdio']=[{'role':'mihomo-core','kind':'stdout','handle':77,'confirmed':True,'receipt':None,
            'open_call_sha256':'missing','open_intent':None,'open_receipt':None}]
        with self.assertRaises((ValueError,TypeError)):P._cleanup(self.m,p,{'start_qpc':1,'deadline_qpc':100},None,{}, {},{})
    def test_public_empty_partial_cleanup_does_not_imply_transport(self):
        p=self.empty();p['ports']={'origin_port':51001,'proxy_port':51002}
        c={'run':'12'*16,'case':'34'*16,'start_qpc':1,'deadline_qpc':100,'proxy':{'ports':p['ports']}}
        self.m.SCOPE='local-lpac-curl-a5-http';self.m._journal_graph=lambda *a:({}, {})
        result=P.validate_proxy_result(self.m,p,c,parent={},root=None,selected=None)
        self.assertEqual(set(result),{'scope','run','case','selected_pid','selected_creation','request_bytes',
            'response_bytes','transport_positive','byte_sinks_verified','cleanup_verified'})
        self.assertTrue(result['cleanup_verified'])
        self.assertFalse(result['transport_positive']);self.assertFalse(result['byte_sinks_verified'])
        self.assertEqual((result['request_bytes'],result['response_bytes']),(0,0))


class ResumeBinding(unittest.TestCase):
    setUp=RawAuthority.setUp
    def fixture(self):
        parent={'sid':'same','session_id':1,'integrity_rid':8192}
        primary=dict(sid='same',session_id=1,token_type=1,capabilities=[],appcontainer=False,
            appcontainer_sid=None,elevated=False,ui_access=False,integrity_rid=8192)
        identity=dict(primary,capability_count=0);security={'process':'private','thread':'private'}
        row,returns=CleanupIndependence.row(self,exit_code=0)
        row.update(assigned=True,admitted=True,resumed=True,natural_exit=True,parent_copies_closed=True,
            created=456,image_sha256='a'*64,identity=identity,expected_primary=primary,capabilities=[],
            kernel_security=security,constructor_return_qpc=12,admission_qpc=15,resume_intent_qpc=20,
            resume_qpc=21,exit_observed_qpc=30,create_observation={'status':'returned_true','winerror':None,
            'process_information':'nonzero','returned_qpc':10,'work_cutoff':100,'exception_detail':None})
        row['held_checks']=[dict(qpc=tick,pid=123,created=456,image_sha256='a'*64,primary=primary,
            inner_job=True,outer_job=True,kernel_security=security) for tick in (14,19)]
        intent={'action':'resume-proxy-ordinary-origin-fixture','qpc':20}
        idesc=descriptor(intent)
        raw=dict(entered=True,returned=True,count=1,error=None,returned_qpc=21,clock_error=False,exception=False)
        value=dict(action='resume-proxy-ordinary-origin-fixture',qpc=22,intent_sha256=idesc['sha256'],data=raw)
        row['resume_receipt']=descriptor(value);returns[row['resume_receipt']['sha256']]=value
        self.m.launcher=SimpleNamespace(token_is_ordinary=lambda v:not v['appcontainer'],same_identity=lambda v,p:v['sid']==p['sid'])
        self.m.access=SimpleNamespace(identity_shape=lambda value:None)
        self.m.private_process_thread_sddl=lambda value,sid:value=='private';self.m.work_cutoff=lambda c:100
        self.m.proxy_leg=SimpleNamespace(expected_argv=lambda *args:[])
        c={'start_qpc':1,'frequency':1,'proxy':{'artifacts':{'network_actor':{'sha256':'a'*64}}}}
        return row,c,parent,{'start':50,'end':60},{idesc['sha256']:intent},returns,raw,value
    def test_raw_resume_one_bound_to_exact_child_row(self):
        row,c,parent,epoch,intents,returns,_,_=self.fixture()
        self.assertIs(P._task(self.m,row,c,parent,Path('owned'),epoch,intents,returns),row)
    def test_resumed_worker_flag_cannot_replace_raw_resume(self):
        for key,bad in [('count',0),('count',2),('count',True),('returned',False),('entered',False),
                ('error',5),('clock_error',True),('exception',True),('returned_qpc',19)]:
            row,c,parent,epoch,intents,returns,raw,value=self.fixture();raw[key]=bad
            previous=row['resume_receipt']['sha256'];row['resume_receipt']=descriptor(value)
            del returns[previous];returns[row['resume_receipt']['sha256']]=value
            with self.subTest(key=key,bad=bad):
                with self.assertRaises(ValueError):P._task(self.m,row,c,parent,Path('owned'),epoch,intents,returns)


if __name__=='__main__':unittest.main()
