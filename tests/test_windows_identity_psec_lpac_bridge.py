"""CPSE owner API-shaped fakes; no WinDLL, CPSE, actor or network call."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('cpse_owner_tests',ROOT/'.github/windows_identity_psec_lpac_bridge.py')
fixture=load('cpse_previous_pure_fixture',Path(__file__).with_name('test_windows_identity_lpac_identity_cell.py'))
b=fixture.base
F,T,D=b.F,b.T,b.D

def config(root):
    hashes=dict.fromkeys(m.SOURCES,b.H)
    return dict(schema_version=1,scope=m.SCOPE,variant=m.VARIANT,**{n:'%032x'%(i+1) for i,n in enumerate(m.NONCES)},frequency=F,
        start_qpc=T,root_deadline_qpc=T+120*F,deadline_qpc=D,guard_job_name='Local\\RuleProxy.LocalGuard.'+'%032x'%1,
        source_hashes=hashes,source_sha256=m.sha(m.encode(hashes)),device_sha256=b.H,actor_sha256=m.sha(b'x'*512),manifest_sha256=b.H,
        dll_sha256=b.H,dll_manifest_sha256=b.H,processmodel_sha256=m.sha(b'fake model'),spec_sha256=m.sha(m.spec.build(str(root/'inputs'))),
        recovery_plan_sha256=b.H,capability_catalog=copy.deepcopy(b.CATALOG))

def native(label,now,state=0):
    v=dict.fromkeys(m.RESULT_FIELDS,0);v.update(size=96,version=1,operation=m.OPS[label],wrapper_status=0,api_entered=1,api_returned=1,
        within_deadline=1,before_qpc=now,after_qpc=now,environment_state=state)
    if label=='bind':v.update(hresult_valid=1,support_flags=8,schema_major_available=1,schema_minor=1)
    if label=='create':v.update(hresult_valid=1)
    if label in ('close','unbind'):v.update(close_invoked_once=1,close_returned_normally=1)
    if label=='unbind':v.update(module_close_attempted=1,module_close_confirmed=1)
    return v

class Function:
    def __init__(self,fn):self.fn=fn
    def __call__(self,*args):return self.fn(*args)

class JobKernel:
    """ctypes-shaped kernel callbacks: no OS handle or native call is used."""
    def __init__(self,api):
        self.api=api;self.calls=[];self.closed=[];self.next_handle=900001
        self.IsProcessInJob=Function(self.query);self.OpenJobObjectW=Function(self.open);self.CloseHandle=Function(self.close)
    def query(self,process,job,out):
        a=self.api;inner=job==a.owner.job;label='inner' if inner else 'outer';self.calls.append(('query',process,job))
        # A failed API may leave stale TRUE in the caller buffer. It must not
        # become membership evidence, even when the immediate error is valid.
        m.C.cast(out,m.C.POINTER(m.C.c_int))[0]=1
        if a.fault==label+'-api-error':m.C.set_last_error(5 if inner else 87);return 0
        if a.fault==label+'-exception':raise OSError('pure query exception')
        if a.fault==label+'-no-output':m.C.cast(out,m.C.POINTER(m.C.c_int))[0]=-1;return 1
        if a.fault in (label+'-false','outerjob' if not inner else ''):m.C.cast(out,m.C.POINTER(m.C.c_int))[0]=0
        if a.fault=='held-inner-false' and inner and sum(call[0]=='query' and call[2]==job for call in self.calls)>=2:
            m.C.cast(out,m.C.POINTER(m.C.c_int))[0]=0
        if a.fault=='query-late' and not inner:a.now=m.work_cutoff(a.owner.c)
        return 1
    def open(self,access,inherit,name):
        self.calls.append(('open',access,inherit,name))
        if self.api.fault=='open-null':m.C.set_last_error(5);return None
        if self.api.fault=='open-exception':raise OSError('pure open unknown')
        if self.api.fault=='open-invalid':return (1<<64)-1
        if self.api.fault=='open-alias':return self.api.alias
        return self.next_handle
    def close(self,handle):
        self.calls.append(('close-query',handle));self.closed.append(handle)
        if self.api.fault=='query-close-false':m.C.set_last_error(6);return 0
        if self.api.fault=='query-close-exception':raise OSError('pure close unknown')
        return 1

class Probe(fixture.Probe):
    def verify_process(self,process,pid,creation):
        return not self.parent.wait(process,0) and pid==self.parent.process_id(process) and creation==self.parent.creation_time(process)
    def identity(self,token):
        row=next(row for row in self.parent.owner.rows if row['name']==self.parent.rows[self.process]['role'])
        result=copy.deepcopy(row['expected_primary'])
        if token==12:result.update(token_type=2,impersonation_level=1,token_id=result['token_id']+1)
        return result

class FakeBridge:
    def __init__(self,api):self.api=api;self.state=0
    def invoke(self,*args,**kwargs):
        value=self._invoke(*args,**kwargs);return value['wrapper_status'],value
    def _invoke(self,label,c,*,raw=None,inputs=None,child=None,pi=None):
        a=self.api;a.now+=1;a.events.append(label);v=native(label,a.now,self.state)
        if label=='bind':return v
        if label=='create':
            m.spec.verify(raw,inputs)
            if a.fault=='create-exception':raise OSError('unknown opaque return')
            if a.fault in ('create-failed-null','create-failed-nonnull'):
                self.state=1;v.update(wrapper_status=6,hresult_valid=1,hresult=-2147024891,environment_state=1,
                    opaque_outcome_unknown=int(a.fault.endswith('nonnull')));return v
            self.state=2;v.update(environment_state=2)
            if a.fault=='create-late':a.now=m.work_cutoff(c);v.update(wrapper_status=5,within_deadline=0,after_qpc=a.now)
            return v
        if label in ('ac','lpac'):
            self.api.children_inputs.append(copy.deepcopy(child)|{'policy':0 if label=='ac' else 1})
            if label=='ac' and a.fault in ('arm-false','arm-false-zero','arm-partial','arm-exception'):
                if a.fault=='arm-exception':raise OSError('unknown suspended create')
                if a.fault=='arm-partial':pi.thread=9009
                v.update(wrapper_status=6,win32_error=0 if a.fault=='arm-false-zero' else 5);return v
            a.next+=10;pid=a.next;h=pid+(0x100000000 if a.fault=='filetime-real' else 0)
            pi.process=h;pi.thread=h+1;pi.process_id=pid;pi.thread_id=pid+100
            a.rows[h]=dict(argv=[child['image']],job=child['job'],pid=pid,lpac=True,role=label,exited=False)
            return v
        if label=='close':
            # Real adapter queries the *same still-open* Job handle. This fake
            # rejects the old wrong order rather than supplying only empty=True.
            job=self.api.owner.job
            assert job not in a.closed and a.job_empty(job),'Job must stay held through VOID close'
            assert all(r['info'].hProcess in a.closed and r['info'].hThread in a.closed and (r['token'] is None or r['token'] in a.closed)
                for r in a.owner.rows if r['info'].hProcess),'kernel handles must close before opaque'
            if a.fault=='close-exception':raise OSError('VOID close did not return')
            self.state=3;v.update(environment_state=3)
            if a.fault=='close-late':a.now=D;v.update(wrapper_status=5,within_deadline=0,after_qpc=a.now)
            return v
        assert label=='unbind';v.update(environment_state=self.state)
        if self.state==1:v.update(close_invoked_once=0,close_returned_normally=0)
        if a.fault=='unbind-false':v.update(wrapper_status=8,module_close_confirmed=0)
        if a.now>=D:v.update(wrapper_status=5,within_deadline=0)
        return v

class API(fixture.API):
    def __init__(self,root,fault=None,probe_fault=None):
        super().__init__(root,fault,probe_fault);self.children_inputs=[];self.loaded=[]
        self.kernel=JobKernel(self)
        for name in ('IsProcessInJob','OpenJobObjectW','CloseHandle'):setattr(self.k,name,getattr(self.kernel,name))
    query_exact_jobs=m.NativeAPI.query_exact_jobs
    def bridge(self,path):self.loaded.append(path);return FakeBridge(self)
    def processmodel_path(self):return self.root/'processmodel.dll'
    def access_api(self):return Probe(self)
    def creation_time(self,h):return 133900000000000000+h if self.fault=='filetime-real' else super().creation_time(h)
    def process_id(self,h):return self.rows[h].get('pid',h)
    def close(self,h):self.events.append(('close',h));return super().close(h)
    def token_for_process(self,h):self.events.append(('open-primary',h));return super().token_for_process(h)
    def terminate_process(self,h):self.events.append(('terminate-process',h));return super().terminate_process(h)
    def resume(self,*a):raise AssertionError('CPSE identity actors must never resume')

class BridgeTests(unittest.TestCase):
    def setUp(self):
        # Linux ctypes lacks these Windows entry points. Only the fake's error
        # slot is supplied; the production backend receives no fallback API.
        errors={'value':0}
        self.enterContext(patch.object(m.C,'set_last_error',side_effect=lambda value:errors.update(value=value),create=True))
        self.enterContext(patch.object(m.C,'get_last_error',side_effect=lambda:errors['value'],create=True))
        # Lifecycle fakes use the host's TemporaryDirectory syntax. Only this
        # fixture's path-syntax seam is replaced on POSIX; production remains
        # Windows-only and SpecTests always exercise real Windows syntax.
        if os.name!='nt':self.enterContext(patch.object(m.spec,'path',side_effect=lambda value:value))
    def run_cell(self,fault=None,probe_fault=None,*,validate=True):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'inputs').mkdir()
        (root/'inputs'/m.live.ACTOR).write_bytes(b'x'*512);(root/'processmodel.dll').write_bytes(b'fake model')
        c=config(root);(root/'spec.bin').write_bytes(m.spec.build(str(root/'inputs')))
        api=API(root,fault,probe_fault);budget=m.launcher.QpcBudget(api,D,F);cell=m.Cell(root,c,b.PARENT,api,budget);api.owner=cell
        with patch.object(m.base,'fixed_catalog',return_value=b.CATALOG):j=cell.execute()
        if validate:m.validate_result(j,c,parent=b.PARENT)
        return cell,api,j,m.project(j,c,parent=b.PARENT) if validate else None
    def test_full_owner_one_environment_exact_matched_inputs_and_ordered_cleanup(self):
        cell,api,j,p=self.run_cell();self.assertIsNone(j['failure']);self.assertTrue(p['inner_complete'])
        self.assertEqual([p['ac_granted_access'],p['lpac_granted_access']],[[3,0,1,2],[2,0,0,2]])
        left,right=copy.deepcopy(api.children_inputs);self.assertEqual(left.pop('policy'),0);self.assertEqual(right.pop('policy'),1);self.assertEqual(left,right)
        self.assertEqual(api.events.count('create'),1);self.assertEqual(api.events.count('close'),1)
        self.assertLess(api.events.index('close'),api.events.index('unbind'));self.assertLess(api.events.index('unbind'),api.events.index(('close',cell.job)))
        self.assertTrue(all(r['exited'] and r['exit_code']==1 and not r['resumed'] for r in j['tasks']))
        self.assertEqual(cell.budget.deadline,D);self.assertFalse(j['external_environment_absence_verified']);self.assertFalse(j['broker_cancellation_proven'])
    def test_same_import_native_and_full_report_validators_use_distinct_bool_sets(self):
        cell,_,j,_=self.run_cell()
        for op in j['operations']:m.validate_native(op['native'],op['label'],cell.c)
        m.validate_result(j,cell.c,parent=b.PARENT);self.assertEqual(m.abi_layout(),True)
    def test_failed_null_no_owned_handle_differs_from_nonnull_unknown(self):
        for fault,unknown in (('create-failed-null',False),('create-failed-nonnull',True),('create-exception',True)):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);self.assertFalse(p['inner_complete']);self.assertEqual(j['opaque_outcome_unknown'],unknown)
                self.assertEqual(j['tasks'],[]);self.assertNotIn('close',api.events)
                self.assertEqual(j['api_obligations_closed'],not unknown);self.assertFalse(j['external_environment_absence_verified'])
    def test_late_s_ok_owned_result_closes_once_but_never_qualifies(self):
        _,api,j,p=self.run_cell('create-late');self.assertEqual(j['failure'],'environment');self.assertFalse(p['inner_complete'])
        self.assertFalse(j['opaque_outcome_unknown']);self.assertEqual(api.events.count('close'),1);self.assertTrue(j['api_obligations_closed'])
        self.assertTrue(j['workload_cleanup']);self.assertEqual(j['tasks'],[])
        _,api,j,p=self.run_cell('close-late');self.assertEqual(j['failure'],'cleanup');self.assertFalse(p['inner_complete'])
        self.assertTrue(j['api_obligations_closed']);self.assertTrue(j['module_unbound']);self.assertFalse(j['opaque_outcome_unknown'])
        self.assertEqual(api.events.count('close'),1)
    def test_early_known_false_and_unknown_partial_child_do_not_fabricate_exit(self):
        for fault,clean in (('arm-false',True),('arm-false-zero',False),('arm-partial',False),('arm-exception',False)):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);self.assertFalse(p['inner_complete']);self.assertEqual(j['workload_cleanup'],clean)
                self.assertEqual(len(j['tasks']),1);self.assertFalse(j['tasks'][0]['exited']);self.assertIsNone(j['tasks'][0]['exit_code'])
                self.assertNotIn('lpac',api.events);self.assertEqual('close' in api.events,clean)
                if fault=='arm-partial':self.assertEqual(api.closed.count(9009),1)
    def test_held_identity_generation_job_caps_gate_precedes_observer(self):
        for fault in ('medium','outerjob'):
            with self.subTest(fault=fault):
                _,_,j,p=self.run_cell(fault);self.assertFalse(p['inner_complete']);self.assertEqual(j['proofs'],[])
    def test_unknown_observer_or_void_close_cannot_be_recovered_from_job_empty(self):
        for fault,probe in ((None,'close-false'),('close-exception',None)):
            with self.subTest(fault=fault,probe=probe):
                _,api,j,p=self.run_cell(fault,probe);self.assertFalse(p['inner_complete'])
                if probe:self.assertNotIn('close',api.events);self.assertFalse(j['observer_resources_cleanup_verified'])
                else:self.assertTrue(j['opaque_outcome_unknown']);self.assertFalse(j['api_obligations_closed'])
    def test_closed_result_rejects_unknown_wash_wrong_caps_preintent_and_missing_calls(self):
        cell,_,j,_=self.run_cell()
        def rejected(change,value=j):
            bad=copy.deepcopy(value);change(bad)
            with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(bad,cell.c,parent=b.PARENT)
        rejected(lambda x:x.update(actor_resumed=True));rejected(lambda x:x.update(api_obligations_closed=False))
        rejected(lambda x:x['tasks'][0]['expected_primary']['capabilities'][0].update(attributes=0))
        rejected(lambda x:x['operations'][0]['native'].update(api_entered=0,api_returned=0,hresult_valid=0))
        rejected(lambda x:x['operations'][2]['native'].update(api_entered=0,api_returned=0))
        rejected(lambda x:x['proofs'][0].update(start_qpc=T-1))
        _,_,unknown,_=self.run_cell('create-failed-nonnull')
        rejected(lambda x:x.update(opaque_outcome_unknown=False),unknown)
    def test_public_projection_contains_only_safe_masks_and_no_false_network_claim(self):
        _,_,j,p=self.run_cell();raw=m.encode(p)
        for item in (b.SID,b.ACSID,'failure_detail','inputs_directory','token_id','authentication_id'):
            self.assertNotIn(item.encode(),raw)
        self.assertFalse(any(j[k] for k in ('network_tested','dns_tested','proxy_tested','product_acceptance','actor_resumed','token_class46_queried')))
    def test_native_scalar_type_unknown_slots_clock_and_return_gates(self):
        cell,_,_,_=self.run_cell();v=native('ac',T+1,2);m.validate_native(v,'ac',cell.c);self.assertTrue(m.native_ok(v))
        for change in ({'api_entered':False},{'extra':0},{'after_qpc':m.work_cutoff(cell.c)},{'hresult_valid':1}):
            bad=v|change
            if change=={'hresult_valid':1}:
                with self.assertRaises(ValueError):m.validate_native(bad,'ac',cell.c)
            else:
                with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_native(bad,'ac',cell.c)
        self.assertFalse(m.native_ok(v|{'api_entered':0,'api_returned':0}))
    def test_real_ctypes_adapter_layout_alignment_original_bytes_and_exact_call_signatures(self):
        # The real adapter executes against Python callables shaped as C exports.
        # No WinDLL or processmodel module is actually loaded.
        events=[];inputs=r'C:\RuleProxyProof\synthetic\inputs';raw=m.spec.build(inputs);c=config(Path(r'C:\RuleProxyProof\synthetic'))
        class Function:
            def __init__(self,fn):self.fn=fn
            def __call__(self,*args):return self.fn(*args)
        def output(label,result,state):
            for k,v in native(label,T+1,state).items():setattr(result._obj,k,v)
            return 0
        def verify(buffer,size,path,units):
            self.assertEqual(bytes(buffer),raw);self.assertEqual(size,len(raw))
            self.assertEqual(m.C.string_at(path,units*2).decode('utf-16-le'),inputs);events.append('verify');return 0
        def bind(context,plan,result):
            self.assertEqual(context.value%16,0);self.assertEqual(m.C.string_at(context,512),bytes(512))
            self.assertEqual((plan._obj.size,plan._obj.work_cutoff_qpc),(48,m.work_cutoff(c)));events.append('bind');return output('bind',result,0)
        def create(context,buffer,size,path,units,result):
            self.assertEqual(bytes(buffer),raw);events.append('create');return output('create',result,2)
        def arm(context,child,pi,result):
            v=child._obj;self.assertEqual((v.size,v.version,v.reserved,v.job),(88,1,0,50))
            self.assertEqual(m.C.string_at(v.inputs_directory,v.inputs_directory_units*2).decode('utf-16-le'),inputs)
            self.assertEqual(v.policy,0);pi._obj.process=101;pi._obj.thread=102;pi._obj.process_id=201;pi._obj.thread_id=202
            events.append('ac');return output('ac',result,2)
        dll=type('DLL',(),{})()
        functions={'pb_abi_version':lambda:1,'pb_build_spec':lambda *a:1,'pb_verify_spec':verify,'pb_bind':bind,
            'pb_create_environment':create,'pb_create_arm':arm,
            'pb_close_environment':lambda context,result:output('close',result,3),'pb_unbind':lambda context,result:output('unbind',result,3)}
        for name,fn in functions.items():setattr(dll,name,Function(fn))
        with patch.object(m.C,'WinDLL',return_value=dll,create=True) as loader:
            bridge=m.Bridge(Path(r'C:\fixed\bridge.dll'))
            loader.assert_called_once_with(r'C:\fixed\bridge.dll',use_last_error=True,winmode=0x900)
            for label in ('bind','create'):
                status,value=bridge.invoke(label,c,**({'raw':raw,'inputs':inputs} if label=='create' else {}));self.assertEqual(status,value['wrapper_status']);m.validate_native(value,label,c);self.assertTrue(m.native_ok(value))
            pi=m.PI();status,v=bridge.invoke('ac',c,child=dict(job=50,image=inputs+'\\'+m.live.ACTOR,inputs_directory=inputs,
                system_root=r'C:\Windows',local_appdata=r'C:\Users\fixture\AppData\Local'),pi=pi)
            self.assertEqual((pi.process,pi.thread,pi.process_id,pi.thread_id),(101,102,201,202));self.assertTrue(m.native_ok(v))
            self.assertEqual(events,['bind','verify','create','ac'])
    def test_realistic_filetime_and_u64_handles_remain_distinct_from_dword_ids(self):
        cell,_,j,p=self.run_cell('filetime-real');self.assertTrue(p['inner_complete'])
        self.assertTrue(all(row['created']>0xffffffff and row['pi']['process']>0xffffffff and row['pi']['thread']>0xffffffff
            and row['pid']<=0xffffffff and row['pi']['thread_id']<=0xffffffff for row in j['tasks']))
        for field,value in (('created',True),('created',0),('created',1<<64),('pid',1<<32)):
            bad=copy.deepcopy(j);bad['tasks'][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaisesRegex(ValueError,'cpse_task_number'):
                m.validate_result(bad,cell.c,parent=b.PARENT)
    def test_returned_receipts_bind_original_intent_status_raw_pi_before_validation(self):
        cell,_,j,p=self.run_cell('filetime-real');self.assertTrue(p['inner_complete'])
        for operation in j['operations']:
            receipt=operation['receipt'];self.assertIsNotNone(receipt)
            raw=(cell.root/'receipts'/receipt['name']).read_bytes();self.assertEqual(raw,receipt['text'].encode('ascii'))
            self.assertEqual(m.sha(raw),receipt['sha256']);value=m.decode(raw)
            self.assertEqual(value['native'],operation['native']);self.assertEqual(value['return_status'],operation['return_status'])
            self.assertEqual(value['config_sha256'],m.sha(m.encode(cell.c)))
            intent=next(row for row in j['intents'] if row['action']==operation['label']);self.assertEqual(value['intent_sha256'],intent['sha256'])
        bad=copy.deepcopy(j);bad['operations'][0]['receipt']['sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'cpse_returned_receipt'):m.validate_result(bad,cell.c,parent=b.PARENT)
    def test_invalid_function_status_does_not_lose_returned_original_tuple(self):
        original=FakeBridge.invoke
        def wrong_status(instance,label,*args,**kwargs):
            status,value=original(instance,label,*args,**kwargs)
            return (9 if label=='ac' else status),value
        with patch.object(FakeBridge,'invoke',wrong_status):cell,_,j,p=self.run_cell()
        self.assertFalse(p['inner_complete']);self.assertEqual(j['failure'],'construct')
        record=next(row for row in j['operations'] if row['label']=='ac');raw=m.decode(record['receipt']['text'].encode('ascii'))
        self.assertEqual(raw['return_status'],9);self.assertEqual(raw['native']['wrapper_status'],0);self.assertTrue(all(raw['pi'].values()))
        self.assertTrue(j['workload_cleanup'])
    def test_receipt_write_error_does_not_erase_known_owned_environment_close_authority(self):
        writer=m.base.durable_private
        def write(path,raw):
            if path.name=='01-create-returned.json':raise OSError('fake returned-receipt disk write failure')
            return writer(path,raw)
        with patch.object(m.base,'durable_private',side_effect=write):_,api,j,p=self.run_cell()
        self.assertEqual(j['failure'],'environment');self.assertFalse(p['inner_complete']);self.assertFalse(j['opaque_outcome_unknown'])
        self.assertTrue(j['api_obligations_closed']);self.assertTrue(j['module_unbound']);self.assertEqual(api.events.count('close'),1)
        create=next(row for row in j['operations'] if row['label']=='create');self.assertIsNone(create['receipt']);self.assertIsNotNone(create['exception'])
        self.assertEqual(create['native']['hresult'],0);self.assertEqual(create['native']['environment_state'],2)
    def test_malformed_native_snapshot_is_saved_with_pi_before_semantic_validator_rejects(self):
        original=FakeBridge.invoke
        def malformed(instance,label,*args,**kwargs):
            status,value=original(instance,label,*args,**kwargs)
            if label=='ac':value['size']=95
            return status,value
        with patch.object(FakeBridge,'invoke',malformed):cell,_,j,_=self.run_cell(validate=False)
        row=next(row for row in j['operations'] if row['label']=='ac');raw=(cell.root/'receipts'/row['receipt']['name']).read_bytes()
        value=m.decode(raw);self.assertEqual(value['native']['size'],95);self.assertTrue(all(value['pi'].values()))
        self.assertIsNotNone(row['exception']);self.assertEqual(j['failure'],'construct')
        with self.assertRaises(ValueError):m.validate_result(j,cell.c,parent=b.PARENT)

    def test_exact_job_known_false_or_api_error_records_both_before_token(self):
        for fault,key,api_success,error in (('inner-false','inner',True,0),('outer-false','outer',True,0),
                ('inner-api-error','inner',False,5),('outer-api-error','outer',False,87)):
            with self.subTest(fault=fault):
                cell,api,j,p=self.run_cell(fault);row=j['tasks'][0];entry=row['job_admissions'][0];q=entry['query']
                self.assertEqual(j['failure'],'admission');self.assertFalse(p['inner_complete']);self.assertEqual(len(j['tasks']),1)
                self.assertEqual(q[key]['api_success'],api_success);self.assertEqual(q[key]['win32_error'],error)
                self.assertEqual(q[key]['membership'],False if api_success else None)
                self.assertEqual([call[0] for call in api.kernel.calls[:4]],['query','open','query','close-query'])
                self.assertTrue(q['resource_cleanup_verified']);self.assertFalse(row['assigned']);self.assertFalse(row['admitted'])
                self.assertIsNone(row['expected_primary']);self.assertFalse(any(isinstance(x,tuple) and x[0]=='open-primary' for x in api.events))
                self.assertNotIn('lpac',api.events);self.assertEqual(j['proofs'],[])
                raw=(cell.root/'job-admissions'/entry['receipt']['name']).read_bytes();value=m.decode(raw)
                self.assertEqual(raw,entry['receipt']['text'].encode('ascii'));self.assertEqual(m.sha(raw),entry['receipt']['sha256'])
                self.assertFalse(value['admission_decision_recorded']);self.assertEqual(value['query'],q)
                operation=next(op for op in j['operations'] if op['label']=='ac')
                self.assertEqual(value['pi_receipt_sha256'],operation['receipt']['sha256'])
                self.assertTrue(j['api_obligations_closed']);self.assertTrue(row['exited'])

    def test_exact_job_native_shaped_signatures_and_immediate_errors(self):
        # This invokes production code via __new__, not an overridden query
        # method. A later QPC call deliberately changes the fake last-error.
        c=config(Path(r'C:\RuleProxyProof\synthetic'));state=NS(now=T+1,fault='inner-api-error',owner=NS(job=50,c=c))
        kernel=JobKernel(state);api=m.NativeAPI.__new__(m.NativeAPI);api.k=kernel;api.controls_uncertain=False
        class Clock:
            frequency=F;deadline=D
            def read(self):m.C.set_last_error(999);return state.now
        q=api.query_exact_jobs(100,50,c['guard_job_name'],Clock(),m.work_cutoff(c),protected_handles=(50,100,101,102))
        m.validate_job_query(q,c,process=100,inner=50)
        self.assertEqual(q['inner']['win32_error'],5);self.assertIsNone(q['inner']['membership']);self.assertFalse(q['inner']['api_success'])
        self.assertTrue(q['outer']['membership']);self.assertEqual(kernel.closed,[900001]);self.assertFalse(api.controls_uncertain)
        self.assertEqual(kernel.calls[1],('open',4,False,c['guard_job_name']))
        self.assertEqual(kernel.IsProcessInJob.argtypes,[m.C.c_void_p,m.C.c_void_p,m.C.POINTER(m.C.c_int)])
        self.assertIs(kernel.IsProcessInJob.restype,m.C.c_int)
        self.assertEqual(kernel.OpenJobObjectW.argtypes,[m.C.c_uint32,m.C.c_int,m.C.c_wchar_p]);self.assertIs(kernel.OpenJobObjectW.restype,m.C.c_void_p)
        self.assertEqual(kernel.CloseHandle.argtypes,[m.C.c_void_p]);self.assertIs(kernel.CloseHandle.restype,m.C.c_int)

    def test_exact_job_query_handle_alias_invalid_and_null_never_blind_close(self):
        c=config(Path(r'C:\RuleProxyProof\synthetic'))
        for fault,alias in [('open-alias',h) for h in (50,100,101,102)]+[('open-invalid',None),('open-null',None)]:
            with self.subTest(fault=fault,alias=alias):
                state=NS(now=T+1,fault=fault,alias=alias,owner=NS(job=50,c=c));kernel=JobKernel(state)
                api=m.NativeAPI.__new__(m.NativeAPI);api.k=kernel;api.controls_uncertain=False
                budget=NS(frequency=F,deadline=D,read=lambda:state.now)
                q=api.query_exact_jobs(100,50,c['guard_job_name'],budget,m.work_cutoff(c),protected_handles=(50,100,101,102))
                m.validate_job_query(q,c,process=100,inner=50);self.assertFalse(m.job_query_passed(q));self.assertEqual(kernel.closed,[])
                self.assertFalse(q['outer']['attempted']);self.assertEqual(api.controls_uncertain,fault!='open-null')
                self.assertEqual(q['resource_cleanup_verified'],fault=='open-null')

    def test_exact_job_query_close_unknown_keeps_recovery_and_consumes_once(self):
        for fault in ('query-close-false','query-close-exception','open-exception'):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);q=j['tasks'][0]['job_admissions'][0]['query']
                self.assertFalse(p['inner_complete']);self.assertFalse(j['job_query_resources_cleanup_verified'])
                self.assertFalse(j['api_obligations_closed']);self.assertFalse(j['module_unbound']);self.assertNotIn('close',api.events)
                self.assertTrue(api.controls_uncertain);self.assertEqual(len(api.kernel.closed),0 if fault=='open-exception' else 1)
                self.assertFalse(q['resource_cleanup_verified']);self.assertTrue(q['outer_resource']['close_uncertain'])
                if fault=='query-close-false':self.assertEqual(q['outer_resource']['close_win32_error'],6)

    def test_exact_job_durable_failure_prevents_admission_without_erasing_query(self):
        writer=m.base.durable_private
        def write(path,raw):
            if path.parent.name=='job-admissions':raise OSError('pure job observation write failure')
            return writer(path,raw)
        with patch.object(m.base,'durable_private',side_effect=write):_,api,j,p=self.run_cell()
        row=j['tasks'][0];entry=row['job_admissions'][0]
        self.assertFalse(row['assigned']);self.assertFalse(row['admitted']);self.assertIsNone(entry['receipt']);self.assertIsNotNone(entry['exception'])
        self.assertTrue(m.job_query_passed(entry['query']));self.assertTrue(j['job_query_resources_cleanup_verified']);self.assertFalse(p['inner_complete'])
        self.assertNotIn('lpac',api.events);self.assertIsNone(row['expected_primary']);self.assertEqual(j['proofs'],[])

    def test_durable_job_write_consumes_original_budget_before_any_admission(self):
        original=API.qpc
        def qpc(api):
            if (api.root/'job-admissions'/'ac-01.json').exists():api.now=m.work_cutoff(api.owner.c)
            return original(api)
        with patch.object(API,'qpc',qpc):cell,api,j,p=self.run_cell()
        row=j['tasks'][0];entry=row['job_admissions'][0]
        self.assertIsNotNone(entry['receipt']);self.assertTrue(m.job_query_passed(entry['query']))
        self.assertEqual(entry['decision_qpc'],m.work_cutoff(cell.c));self.assertIsNotNone(entry['exception'])
        self.assertFalse(row['assigned']);self.assertIsNone(row['expected_primary']);self.assertFalse(p['inner_complete'])
        self.assertNotIn('lpac',api.events);self.assertEqual(cell.budget.deadline,D)

    def test_later_job_false_keeps_historical_assignment_but_exact_stops_held_actor(self):
        _,api,j,p=self.run_cell('held-inner-false');row=j['tasks'][0]
        self.assertTrue(row['assigned']);self.assertFalse(row['admitted']);self.assertEqual(len(row['job_admissions']),2)
        self.assertTrue(m.job_admission_passed(row['job_admissions'][0],row,config(api.root)))
        self.assertFalse(m.job_query_passed(row['job_admissions'][-1]['query']));self.assertIn(('terminate-process',row['pi']['process']),api.events)
        self.assertTrue(row['exited']);self.assertEqual(row['exit_code'],1);self.assertFalse(p['inner_complete']);self.assertEqual(j['proofs'],[])

    def test_query_late_or_unwritten_success_output_never_admits_or_extends_budget(self):
        for fault in ('query-late','inner-no-output','outer-no-output'):
            with self.subTest(fault=fault):
                cell,api,j,p=self.run_cell(fault);row=j['tasks'][0]
                self.assertFalse(p['inner_complete']);self.assertFalse(row['assigned']);self.assertIsNone(row['expected_primary'])
                self.assertEqual(cell.budget.deadline,D);self.assertEqual(len(api.kernel.closed),1)
                self.assertNotIn('lpac',api.events);self.assertTrue(j['job_query_resources_cleanup_verified'])

    def test_job_admission_receipt_and_cleanup_boolean_cannot_be_rewritten_to_qualify(self):
        cell,_,j,_=self.run_cell()
        def rejected(mut,value=j):
            bad=copy.deepcopy(value);mut(bad)
            with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(bad,cell.c,parent=b.PARENT)
        rejected(lambda x:x['tasks'][0]['job_admissions'][0]['receipt'].update(sha256='0'*64))
        rejected(lambda x:x['tasks'][0]['job_admissions'][0]['query']['inner'].update(membership=False))
        rejected(lambda x:x['tasks'][0]['job_admissions'][0]['query'].update(outer_job='Local\\wrong'))
        rejected(lambda x:x.update(job_query_resources_cleanup_verified=False))
        _,_,failed,_=self.run_cell('query-close-false')
        rejected(lambda x:x.update(job_query_resources_cleanup_verified=True),failed)
        rejected(lambda x:x.update(api_obligations_closed=True),failed)
if __name__=='__main__':unittest.main()
