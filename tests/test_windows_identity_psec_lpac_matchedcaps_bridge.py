"""Three-held WORK candidate: pure production composition, never a DLL/API run."""
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
m=load('matchedcaps_core_tests',ROOT/'.github/windows_identity_psec_lpac_matchedcaps_bridge.py')
f=load('matchedcaps_existing_pure_fixtures',Path(__file__).with_name('test_windows_identity_psec_lpac_postassign_bridge.py'))
# This separately loaded fixture module never enters unittest discovery. Its
# existing API-shaped Job and token callbacks are reused, not run as old tests.
f.m=m
b=f.b;F,T,D=f.F,f.T,f.D

def config(root):return f.config(root)

class FakeBridge(f.FakeBridge):
    def _invoke(self,label,c,*,raw=None,inputs=None,child=None,pi=None,security_capabilities=None):
        if label not in ('bootstrap','ac','lpac'):
            return super()._invoke(label,c,raw=raw,inputs=inputs,child=child,pi=pi)
        a=self.api;a.now+=1;a.events.append(label);v=f.native(label,a.now,self.state)
        if label=='bootstrap':assert security_capabilities is None
        else:
            m.validate_security_capabilities(security_capabilities,c['capability_catalog'])
            assert a.owner.j['security_capabilities_verified']
            assert a.owner.rows[0]['admitted']
            assert (a.root/'security-capabilities'/'held-bootstrap.json').is_file()
        a.children_inputs.append(copy.deepcopy(child)|{'policy':int(label=='lpac'),'role':label,
            'security_capabilities':copy.deepcopy(security_capabilities)})
        if a.fault in (label+'-precreate-false',label+'-precreate-error0',label+'-precreate-partial',label+'-precreate-late'):
            v.update(wrapper_status=10,api_entered=0,api_returned=0,win32_error=0 if a.fault.endswith('error0') else 87)
            if a.fault.endswith('partial'):pi.thread=9009
            if a.fault.endswith('late'):
                a.now=m.work_cutoff(c);v.update(within_deadline=0,after_qpc=a.now)
            return v
        if a.fault==label+'-create-false':
            v.update(wrapper_status=6,win32_error=5);return v
        if a.fault==label+'-create-exception':raise OSError('pure create did not return')
        a.next+=10;pid=a.next;h=pid+0x100000000
        pi.process=h;pi.thread=h+1;pi.process_id=pid;pi.thread_id=pid+100
        a.rows[h]=dict(argv=[child['image']],job=None,pid=pid,lpac=True,role=label,exited=False)
        if a.fault==label+'-late':
            a.now=m.work_cutoff(c);v.update(wrapper_status=5,within_deadline=0,after_qpc=a.now)
        return v

class API(f.API):
    def bridge(self,path):self.loaded.append(path);return FakeBridge(self)
    def identity(self,token):
        result=super().identity(token)
        process=next((h for h in self.rows if token==h+10000),None)
        # Existing base fixture uses token handles derived from process HANDLE.
        if self.fault=='bootstrap-medium' and self.rows.get(process,{}).get('role')=='bootstrap':result['integrity_rid']=8192
        return result

class MatchedCapsTests(unittest.TestCase):
    def setUp(self):
        errors={'value':0}
        self.enterContext(patch.object(m.C,'set_last_error',side_effect=lambda value:errors.update(value=value),create=True))
        self.enterContext(patch.object(m.C,'get_last_error',side_effect=lambda:errors['value'],create=True))
        if os.name!='nt':self.enterContext(patch.object(m.spec,'path',side_effect=lambda value:value))
    def run_cell(self,fault=None,probe_fault=None,*,validate=True):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'inputs').mkdir()
        (root/'inputs'/m.live.ACTOR).write_bytes(b'x'*512);(root/'processmodel.dll').write_bytes(b'fake model')
        c=config(root);(root/'spec.bin').write_bytes(m.spec.build(str(root/'inputs')))
        api=API(root,fault,probe_fault);budget=m.launcher.QpcBudget(api,D,F);cell=m.Cell(root,c,b.PARENT,api,budget);api.owner=cell
        with patch.object(m.base,'fixed_catalog',return_value=b.CATALOG):j=cell.execute()
        if validate:m.validate_result(j,c,parent=b.PARENT,root=root)
        return cell,api,j,m.project(j,c,parent=b.PARENT,root=root) if validate else None
    def test_three_held_complete_same_environment_sc_only_aap_differs_and_never_resume(self):
        cell,api,j,p=self.run_cell();self.assertIsNone(j['failure']);self.assertTrue(p['inner_complete'])
        self.assertEqual([r['name'] for r in j['tasks']],['bootstrap','ac','lpac'])
        self.assertEqual([proof['expected_role'] for proof in j['proofs']],['ac','lpac'])
        self.assertTrue(all(row['admitted'] and row['exited'] and row['exit_code']==1 and not row['resumed'] for row in j['tasks']))
        bootstrap,ac,lpac=copy.deepcopy(api.children_inputs)
        self.assertIsNone(bootstrap.pop('security_capabilities'));self.assertEqual(bootstrap.pop('role'),'bootstrap');self.assertEqual(bootstrap.pop('policy'),0)
        self.assertEqual(ac.pop('role'),'ac');self.assertEqual(lpac.pop('role'),'lpac')
        self.assertEqual(ac.pop('policy'),0);self.assertEqual(lpac.pop('policy'),1);self.assertEqual(ac,lpac)
        sc=ac.pop('security_capabilities');self.assertEqual(ac,bootstrap)
        self.assertEqual(sc,m.security_capabilities_value(j['tasks'][0]['expected_primary'],cell.c['capability_catalog']))
        self.assertEqual(p['ac_granted_access'],[3,0,1,2]);self.assertEqual(p['lpac_granted_access'],[2,0,0,2])
        self.assertEqual(api.events.count('create'),1);self.assertEqual(api.events.count('close'),1)
        self.assertLess(api.events.index('close'),api.events.index('unbind'));self.assertLess(api.events.index('unbind'),api.events.index(('close',cell.job)))
        self.assertEqual(cell.budget.deadline,D);self.assertFalse(p['psec_network_preservation_proven'])
        self.assertLess(len(m.encode(j)),m.MAX_REPORT)
    def test_sc64_canonical_binary_schema_roundtrip_and_attributes_cannot_adapt(self):
        cell,_,j,_=self.run_cell();v=j['security_capabilities']['value'];record,buffers=m.security_capabilities_record(v,cell.c['capability_catalog'])
        self.assertTrue(m.abi_layout());self.assertEqual((record.size,record.version,record.capability_count,record.reserved,record.reserved2),(64,3,2,0,0))
        self.assertEqual(record.agentic_attributes,4);self.assertEqual(record.pncs_attributes,4)
        self.assertEqual(m.C.string_at(record.package_sid,record.package_bytes),m.sid_bytes(b.ACSID))
        self.assertEqual(bytes(buffers['agentic_sid']),m.sid_bytes(cell.c['capability_catalog']['AgenticAppContainer']))
        self.assertEqual(m.security_capabilities_bytes(v,cell.c['capability_catalog'])[:4],b'SCI3')
        for mutate in (lambda x:x.update(agentic_attributes=0),lambda x:x.update(pncs_attributes=True),
                lambda x:x.update(package_sid=x['package_sid'][:-2]),lambda x:x.update(pncs_sid=x['agentic_sid']),
                lambda x:x.update(extra=1)):
            bad=copy.deepcopy(v);mutate(bad)
            with self.assertRaises(ValueError):m.validate_security_capabilities(bad,cell.c['capability_catalog'])
        for value in ('S-1-15-02-1','S-1-15-2-4294967296','S-1-15-2-1-','S-1-15-2-+1'):
            with self.assertRaises(ValueError):m.sid_bytes(value)
    def test_bootstrap_identity_and_both_jobs_stop_before_sc_and_any_measured_child(self):
        for fault in ('medium','outer-false','inner-api-error','pre-inner-true','assign-false','assign-no-effect','query-close-false'):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);self.assertFalse(p['inner_complete']);self.assertEqual(len(j['tasks']),1)
                self.assertFalse(j['security_capabilities_verified']);self.assertEqual(j['proofs'],[])
                self.assertNotIn('ac',api.events);self.assertNotIn('lpac',api.events)
                if fault=='query-close-false':self.assertFalse(j['api_obligations_closed'])
    def test_bootstrap_known_create_false_and_unknown_exception_preserve_different_cleanup(self):
        for fault,clean in (('bootstrap-create-false',True),('bootstrap-create-exception',False)):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);self.assertFalse(p['inner_complete']);self.assertEqual(len(j['tasks']),1)
                self.assertFalse(j['tasks'][0]['exited']);self.assertIsNone(j['tasks'][0]['exit_code'])
                self.assertEqual(j['workload_cleanup'],clean);self.assertEqual('close' in api.events,clean)
                self.assertFalse(j['security_capabilities_verified']);self.assertNotIn('ac',api.events)
    def test_sc_receipt_failure_and_fsync_deadline_do_not_create_measured_actor(self):
        original=m.base.durable_private
        for late in (False,True):
            api_box=[]
            def write(path,raw):
                if path.name=='held-bootstrap.json' and not late:raise OSError('pure SC write failure')
                result=original(path,raw)
                if path.name=='held-bootstrap.json' and late:api_box[0].now=m.work_cutoff(api_box[0].owner.c)
                return result
            original_init=API.__init__
            def init(api,*args,**kwargs):original_init(api,*args,**kwargs);api_box.append(api)
            with self.subTest(late=late),patch.object(API,'__init__',init),patch.object(m.base,'durable_private',side_effect=write):
                cell,api,j,p=self.run_cell();self.assertFalse(p['inner_complete']);self.assertFalse(j['security_capabilities_verified'])
                self.assertEqual(len(j['tasks']),1);self.assertNotIn('ac',api.events);self.assertEqual(cell.budget.deadline,D)
                self.assertIsNotNone(j['security_capabilities']['exception'])
    def test_live_bootstrap_generation_and_caps_rechecked_before_measured_create_and_token(self):
        original=m.Cell.held
        for boundary in ('before-create','before-token'):
            calls=[0]
            def held(cell,row):
                if row['name']=='bootstrap':
                    calls[0]+=1
                    trigger=3 if boundary=='before-create' else 4
                    if calls[0]==trigger:raise ValueError('pure bootstrap changed')
                return original(cell,row)
            with self.subTest(boundary=boundary),patch.object(m.Cell,'held',held):
                _,api,j,p=self.run_cell();self.assertFalse(p['inner_complete']);self.assertEqual(j['proofs'],[])
                if boundary=='before-create':self.assertNotIn('ac',api.events)
                else:
                    row=j['tasks'][-1];self.assertEqual(row['name'],'ac');self.assertIsNone(row['expected_primary'])
                    self.assertFalse(row['admitted']);self.assertIsNone(row['bootstrap_before_token_check_qpc'])
                self.assertNotIn('lpac',api.events)
    def test_measured_create_partial_failure_still_stops_all_three_known_children(self):
        for fault,expected in (('ac-create-false',2),('lpac-create-false',3)):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault);self.assertEqual(len(j['tasks']),expected);self.assertFalse(p['inner_complete'])
                self.assertTrue(j['workload_cleanup']);self.assertTrue(j['api_obligations_closed']);self.assertEqual(j['proofs'],[])
                self.assertTrue(all(row['exited'] for row in j['tasks'][:-1]));self.assertFalse(j['tasks'][-1]['exited'])
    def test_typed_precreate_status10_api_never_entered_cleans_without_inventing_create_failure(self):
        for role in ('bootstrap','ac','lpac'):
            for suffix in ('precreate-false','precreate-error0'):
                with self.subTest(role=role,suffix=suffix):
                    cell,api,j,p=self.run_cell(role+'-'+suffix);row=j['tasks'][-1]
                    self.assertEqual(row['name'],role);self.assertEqual(row['return_status'],10)
                    self.assertEqual((row['native']['api_entered'],row['native']['api_returned']),(0,0))
                    self.assertTrue(m.known_no_child(row,cell.c));self.assertFalse(row['exited']);self.assertIsNone(row['exit_code'])
                    self.assertTrue(j['workload_cleanup']);self.assertTrue(j['api_obligations_closed']);self.assertFalse(p['inner_complete'])
                    self.assertEqual(api.events.count('close'),1);self.assertEqual(j['proofs'],[])
    def test_partial_or_late_precreate_return_is_unknown_and_never_qualifies(self):
        for suffix in ('precreate-partial','precreate-late','create-exception','late'):
            with self.subTest(suffix=suffix):
                cell,api,j,p=self.run_cell('ac-'+suffix);row=j['tasks'][-1]
                self.assertFalse(m.known_no_child(row,cell.c));self.assertFalse(p['inner_complete'])
                self.assertFalse(row['admitted']);self.assertNotIn('lpac',api.events)
                if suffix in ('precreate-partial','precreate-late','create-exception'):
                    self.assertFalse(j['workload_cleanup']);self.assertFalse(j['api_obligations_closed']);self.assertNotIn('close',api.events)
                    if suffix=='precreate-late':self.assertEqual(row['native']['wrapper_status'],10);self.assertFalse(row['native']['within_deadline'])
                else:self.assertTrue(j['workload_cleanup']);self.assertTrue(j['api_obligations_closed'])
    def test_raw_constructor_receipts_and_sc_physical_file_reject_tampering(self):
        cell,_,j,_=self.run_cell()
        sc=j['security_capabilities'];self.assertEqual((cell.root/'security-capabilities'/sc['receipt']['name']).read_bytes(),sc['receipt']['text'].encode('ascii'))
        for role in ('bootstrap','ac','lpac'):
            op=next(op for op in j['operations'] if op['label']==role);raw=m.decode(op['receipt']['text'].encode('ascii'))
            self.assertEqual(raw['security_capabilities_sha256'],None if role=='bootstrap' else sc['raw_sha256'])
            row=next(row for row in j['tasks'] if row['name']==role);self.assertEqual(raw['pi'],row['pi'])
        path=cell.root/'security-capabilities'/'held-bootstrap.json';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'physical_receipt_bytes'):m.validate_result(j,cell.c,parent=b.PARENT,root=cell.root)
    def test_strict_validator_rejects_cached_bootstrap_and_fake_third_actor_or_proof(self):
        cell,_,j,_=self.run_cell()
        def reject(change):
            bad=copy.deepcopy(j);change(bad)
            with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(bad,cell.c,parent=b.PARENT)
        reject(lambda x:x.update(security_capabilities_verified=False))
        reject(lambda x:x['tasks'][1].update(security_capabilities_sha256='0'*64))
        reject(lambda x:x['tasks'][1].update(bootstrap_before_create_check_qpc=None))
        reject(lambda x:x['tasks'][2].update(bootstrap_before_token_check_qpc=None))
        reject(lambda x:x['tasks'][0].update(admitted=False))
        reject(lambda x:x['proofs'][0].update(expected_role='bootstrap'))
        reject(lambda x:x.update(psec_network_preservation_proven=True))
        reject(lambda x:x['security_capabilities']['value'].update(agentic_attributes=0))
    def test_observer_and_void_unknown_stay_unclosed_even_with_three_exited_children(self):
        for fault,probe in ((None,'close-false'),('close-exception',None)):
            with self.subTest(fault=fault,probe=probe):
                _,api,j,p=self.run_cell(fault,probe);self.assertFalse(p['inner_complete']);self.assertFalse(j['api_obligations_closed'])
                self.assertTrue(j['workload_cleanup']);self.assertTrue(all(row['exited'] for row in j['tasks']))
                self.assertEqual(api.events.count('close'),0 if probe else 1)
    def test_real_abi3_adapter_uses_role0_null_then_identical_sc64_for_role1_role2(self):
        cell,_,j,_=self.run_cell();c=cell.c;sc=j['security_capabilities']['value'];events=[]
        def result(label,out):
            for k,v in f.native(label,T+1,2).items():setattr(out._obj,k,v)
            return 0
        def child(context,record,role,security,pi,out):
            self.assertEqual(context.value%16,0);self.assertEqual(record._obj.size,88)
            self.assertEqual(record._obj.policy,int(role==2));self.assertEqual(record._obj.reserved,0)
            if role==0:self.assertIsNone(security);value=None
            else:
                s=security._obj;self.assertEqual((s.size,s.version,s.capability_count,s.reserved,s.reserved2),(64,3,2,0,0))
                value=tuple(m.C.string_at(getattr(s,k),getattr(s,k.replace('_sid','_bytes'))) for k in ('package_sid','agentic_sid','pncs_sid'))
                self.assertEqual((s.agentic_attributes,s.pncs_attributes),(4,4))
            events.append((role,value));pi._obj.process=100+role*10;pi._obj.thread=101+role*10;pi._obj.process_id=200+role;pi._obj.thread_id=300+role
            return result(('bootstrap','ac','lpac')[role],out)
        dll=NS();names=('pb_abi_version','pb_build_spec','pb_verify_spec','pb_bind','pb_create_environment','pb_create_matched_child','pb_close_environment','pb_unbind')
        for name in names:setattr(dll,name,f.Function((lambda:3) if name=='pb_abi_version' else child if name=='pb_create_matched_child' else lambda *args:0))
        with patch.object(m.C,'WinDLL',return_value=dll,create=True):
            bridge=m.Bridge(Path(r'C:\fixed\bridge.dll'))
            values=dict(job=50,image=r'C:\proof\inputs\actor.exe',inputs_directory=r'C:\proof\inputs',system_root=r'C:\Windows',local_appdata=r'C:\proof\local')
            for role in ('bootstrap','ac','lpac'):
                pi=m.PI();status,raw=bridge.invoke(role,c,child=values,pi=pi,security_capabilities=None if role=='bootstrap' else sc)
                self.assertEqual(status,0);m.validate_native(raw,role,c)
            self.assertEqual(events[0],(0,None));self.assertEqual(events[1][1],events[2][1])
            self.assertEqual(dll.pb_create_matched_child.argtypes,[m.C.c_void_p,m.C.POINTER(m.Child),m.C.c_uint32,m.C.POINTER(m.SecurityCapabilities),m.C.POINTER(m.PI),m.C.POINTER(m.Result)])

if __name__=='__main__':unittest.main()
