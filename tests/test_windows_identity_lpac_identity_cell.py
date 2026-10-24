"""Pure matched-cell lifecycle; injected APIs never load DLLs or create actors."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('matched_cell_pure',ROOT/'.github/windows_identity_lpac_identity_cell.py')
base=load('matched_cell_base_fixture',Path(__file__).with_name('test_windows_identity_lpac_dns_local.py'))
af=load('matched_cell_access_fixture',Path(__file__).with_name('test_windows_identity_lpac_accesscheck.py'))
F,T,D=base.F,base.T,base.D

def config():
    c={k:v for k,v in base.config().items() if k not in base.m.NONCES}
    c.update(scope=m.SCOPE,**{n:'%032x'%(i+1) for i,n in enumerate(m.NONCES)})
    c['source_hashes']=dict.fromkeys((*m.SOURCES,m.LOCAL_MODULE),base.H)
    c['source_sha256']=m.sha(m.encode(c['source_hashes']));return c

class Probe(af.FakeAPI):
    def __init__(self,parent):super().__init__();self.parent=parent;self.process=None
    def qpc(self):self.parent.now+=1;return self.parent.now
    def frequency(self):return F
    def verify_process(self,process,pid,creation):
        return not self.parent.wait(process,0) and pid==process and creation==self.parent.creation_time(process)
    def open_token(self,process,rights):
        self.process=process;self.role=self.parent.rows[process]['role'];self.fault=self.parent.probe_fault
        return super().open_token(process,rights)
    def identity(self,token):
        role=self.parent.rows[self.process]['role'];result=copy.deepcopy(self.parent.owner.tasks[role]['expected_primary'])
        if token==12:result.update(token_type=2,impersonation_level=1,token_id=result['token_id']+1)
        if self.fault=='primary-mismatch' and token==11:result['token_id']+=1
        return result
    def access_check(self,*args):
        value=super().access_check(*args)
        if self.fault=='late':self.parent.now=D-25*F
        return value

class API(base.API):
    def __init__(self,root,fault=None,probe_fault=None):
        super().__init__(root,fault);self.probe_fault=probe_fault;self.constructs=[];self.native.query=self.statistics
        original=self.native.environment;self.tool_environments=[]
        def environment(work):
            value=original(work)
            if work.parent==self.root/'tools':
                self.assert_existing_temp(work);self.tool_environments.append((work,value))
            return value
        self.native.environment=environment
    def assert_existing_temp(self,work):
        assert work.is_dir() and (work/'temp').is_dir(), 'ordinary tool environment must exist'
    def process_id(self,h):return h
    def statistics(self,token,kind,label):
        assert kind==10
        statistics=m.access.TOKEN_STATISTICS();statistics.TokenType=1;statistics.TokenId.LowPart=10000+token
        statistics.AuthenticationId.LowPart=20
        raw=C.create_string_buffer(C.string_at(C.byref(statistics),C.sizeof(statistics)))
        return raw,C.sizeof(statistics)
    def acl_read(self,path,sid):return m.expected_acl(self.root,path) if self.granted and not self.removed else []
    def create_matched_suspended(self,info,actor,cwd,environment,job,owners,state,*,profile_pointer,catalog,policy,budget,cutoff):
        self.constructs.append(dict(actor=str(actor),cwd=str(cwd),environment=environment,job=job,profile=profile_pointer,
            catalog=copy.deepcopy(catalog),policy=policy))
        try:self.atomic_spawn(info,[str(actor)],cwd,job,owners,state,environment=environment,stdio=(),profile_pointer=profile_pointer,catalog=catalog)
        finally:
            if info.hProcess:self.rows[info.hProcess]['role']='ac' if policy==0 else 'lpac'
            state['returned_qpc']=self.now if state['create_status'] in ('returned_false','returned_true') else None
    def resume(self,thread):
        assert 'role' not in self.rows[thread-1], 'actor must never resume'
        return super().resume(thread)
    def wait(self,h,ms):return self.rows[h]['exited']
    def exit_code(self,h):return 1 if 'role' in self.rows[h] and self.rows[h]['exited'] else 0
    def access_api(self):return Probe(self)
    def lpac_flag(self,token):raise AssertionError('no class46 query in matched cell')

class CellTests(unittest.TestCase):
    def run_cell(self,fault=None,probe_fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('inputs','tools','guard'):(root/name).mkdir()
        (root/'inputs'/m.live.ACTOR).write_bytes(b'x'*512)
        p=root/'win/System32/icacls.exe';p.parent.mkdir(parents=True);p.write_bytes(b'tool')
        c=config();api=API(root,fault,probe_fault);budget=m.launcher.QpcBudget(api,D,F)
        instance=m.CellOwner(root,c,base.PARENT,api,budget);api.owner=instance;j=instance.execute()
        m.validate_result(j,c,parent=base.PARENT)
        return instance,api,j,m.project(j,c,parent=base.PARENT)

    def test_full_real_owner_shape_matched_only_policy_difference_and_never_resume(self):
        instance,api,j,projection=self.run_cell()
        self.assertIsNone(j['failure']);self.assertTrue(projection['inner_complete'])
        self.assertEqual(projection['ac_granted_access'],[3,0,1,2]);self.assertEqual(projection['lpac_granted_access'],[2,0,0,2])
        left,right=copy.deepcopy(api.constructs);self.assertEqual(left.pop('policy'),0);self.assertEqual(right.pop('policy'),1)
        self.assertEqual(left,right);self.assertEqual(len([e for e in api.events if e==('resume',False)]),3)
        arms=[r for r in j['tasks'] if r['role']]
        self.assertTrue(all(not r['resumed'] and r['exit_code']==1 and r['go_qpc']==[] for r in arms))
        self.assertTrue(all(j[k] for k in m.BOOL_KEYS if k!='workload_stop') and j['workload_stop'])
        self.assertLess(api.events.index('remove-acl'),api.events.index('delete-profile'))
        self.assertFalse(any(j[k] for k in ('network_tested','dns_tested','actor_resumed','token_class46_queried')))
        self.assertEqual(instance.budget.deadline,D)

    def test_known_folder_failure_creates_no_profile_or_actor_and_no_observer_resource_debt(self):
        _,api,j,p=self.run_cell('env-query')
        self.assertEqual(j['failure'],'setup');self.assertEqual(api.constructs,[]);self.assertNotIn('create-profile',api.events)
        self.assertFalse(p['inner_complete']);self.assertTrue(p['observer_resources_cleanup_verified'])
        self.assertTrue(all(j[k] for k in ('workload_cleanup','workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released')))

    def test_unknown_create_and_partial_create_remain_recovery_obligations(self):
        for fault in ('unknowncreate','create-false-thread','create-false-pid','create-false-clock','create-false-error0'):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(fault)
                self.assertFalse(p['inner_complete']);self.assertFalse(j['workload_cleanup']);self.assertFalse(api.deleted)
                self.assertEqual(j['proofs'],[]);self.assertEqual(j['tasks'][-1]['name'],'ac')

    def test_typed_timely_false_zero_information_cleans_without_inventing_exit(self):
        _,api,j,p=self.run_cell('create-false')
        row=j['tasks'][-1]
        self.assertTrue(row['attempted']);self.assertFalse(row['exited']);self.assertIsNone(row['exit_code'])
        self.assertTrue(m.owner.known_no_child(row,start=T));self.assertTrue(j['workload_cleanup']);self.assertTrue(api.deleted)
        self.assertFalse(p['inner_complete']);self.assertTrue(p['observer_resources_cleanup_verified'])

    def test_external_identity_caps_generation_job_fail_before_accesscheck(self):
        for fault in ('sid','medium','outerjob'):
            with self.subTest(fault=fault):
                _,_,j,p=self.run_cell(fault)
                self.assertIsNotNone(j['failure']);self.assertFalse(p['inner_complete']);self.assertEqual(j['proofs'],[])

    def test_matrix_mismatch_is_clean_failed_observation_not_profile_leak(self):
        _,api,j,p=self.run_cell(probe_fault='wrong-mask')
        self.assertEqual(j['failure'],'accesscheck');self.assertFalse(p['inner_complete'])
        self.assertTrue(j['observer_resources_cleanup_verified']);self.assertTrue(api.deleted)
        self.assertFalse(p['ac_accesscheck_verified'])

    def test_observer_unknown_create_alias_or_close_blocks_profile_deletion(self):
        for fault in ('open-unknown','duplicate-alias','close-false','free-false'):
            with self.subTest(fault=fault):
                _,api,j,p=self.run_cell(probe_fault=fault)
                self.assertFalse(p['inner_complete']);self.assertFalse(j['observer_resources_cleanup_verified']);self.assertFalse(api.deleted)

    def test_original_clock_late_observation_never_qualifies_and_does_not_renew(self):
        instance,_,j,p=self.run_cell(probe_fault='late')
        self.assertFalse(p['inner_complete']);self.assertEqual(instance.budget.deadline,D)
        self.assertEqual(j['failure'],'accesscheck')

    def test_closed_result_rejects_resume_scope_missing_cleanup_and_wrong_primary_binding(self):
        instance,_,j,_=self.run_cell()
        def check(mut):
            value=copy.deepcopy(j);mut(value)
            with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(value,instance.c,parent=base.PARENT)
        for key in ('actor_resumed','network_tested','token_class46_queried'):
            check(lambda v,key=key:v.update({key:True}))
        for key in ('profile_created','acl_attempted','workload_cleanup','observer_resources_cleanup_verified','profile_deleted'):
            check(lambda v,key=key:v.update({key:False}))
        check(lambda v:v['tasks'][2].update(resumed=True,resume_qpc=T+500))
        check(lambda v:v['tasks'][2]['expected_primary'].update(token_id=999))
        check(lambda v:v['tasks'][2]['expected_primary']['capabilities'][0].update(attributes=0))
        check(lambda v:v['common'].update(parent=base.PARENT|{'sid':'S-1-5-21-9'}))
        check(lambda v:v['proofs'][0]['calls'][0].update(granted_access=2))
        check(lambda v:v['intents'][0].update(sha256='0'*64))
        check(lambda v:v['cleanup_tasks'][0].update(exit_code=1))

    def test_config_nonce_clock_catalog_source_and_plan_are_closed(self):
        c=config();m.config_validate(c)
        for update in ({'lpac_nonce':c['ac_nonce']},{'deadline_qpc':D+1},{'scope':'old-dns'},{'extra':True}):
            with self.subTest(update=update),self.assertRaises((ValueError,m.launcher.GateFailure)):m.config_validate(c|update)
        value=dict(schema_version=1,scope=m.SCOPE,device_sha256=base.H,source_sha256=base.H,actor_sha256=base.H,manifest_sha256=base.H,
            fresh_profile_owned_acl_acknowledged=True,never_resume_acknowledged=True,semantics_only_acknowledged=True,recovery_reference='existing restore record')
        m.validate_plan(value,device=base.H,source=base.H,actor=base.H,manifest=base.H)
        with self.assertRaises((ValueError,m.launcher.GateFailure)):
            m.validate_plan(value|{'never_resume_acknowledged':False},device=base.H,source=base.H,actor=base.H,manifest=base.H)

    def test_api_import_only_and_safe_projection_no_private_identity(self):
        self.assertEqual(m.api_version(),1);self.assertFalse(m.NETWORK_AUTHORIZED)
        _,_,_,p=self.run_cell();raw=m.encode(p)
        for private in (base.SID,base.ACSID,'TokenId','actor_path','environment_sha256','failure_detail'):
            self.assertNotIn(private.encode(),raw)
        self.assertEqual(set(p),{'failure','ac_held_verified','lpac_held_verified','common_inputs_verified','ac_accesscheck_verified',
            'lpac_accesscheck_verified','ac_granted_access','lpac_granted_access','observer_resources_cleanup_verified','never_resumed',
            'workload_cleanup','workload_job_empty','acl_removed','cleanup_tools','profile_deleted','sid_released','inner_complete'})

    def test_all_ordinary_tool_environments_use_existing_own_temp_not_health(self):
        _,api,j,_=self.run_cell()
        self.assertIsNone(j['failure'])
        self.assertEqual([path.name for path,_ in api.tool_environments],['grant-root','grant-inputs','remove'])
        for path,block in api.tool_environments:
            values=dict(value.split('=',1) for value in block.rstrip('\0').split('\0'))
            self.assertEqual(values['TEMP'],str(path/'temp'));self.assertEqual(values['TMP'],str(path/'temp'))
            self.assertNotIn('health',str(path))

    def test_second_observer_unknown_return_cannot_borrow_first_closed_proof_cleanup(self):
        original=m.access.observe_held
        def observe(*args,**kwargs):
            if kwargs['expected_role']=='lpac':raise OSError('unknown observer return')
            return original(*args,**kwargs)
        with patch.object(m.access,'observe_held',side_effect=observe):instance,api,j,p=self.run_cell()
        self.assertEqual(len(j['proofs']),1);self.assertFalse(j['observer_resources_cleanup_verified']);self.assertFalse(api.deleted)
        self.assertFalse(p['inner_complete'])
        altered=copy.deepcopy(j);altered['observer_resources_cleanup_verified']=True
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(altered,instance.c,parent=base.PARENT)

    def native_constructor(self,*,fail_attribute=None,free_unknown=False,alias=False):
        # Instantiate only the Python adapter object. All SDK calls below are
        # Python functions inspecting ctypes buffers; no native DLL is loaded.
        api=m.NativeCellAPI.__new__(m.NativeCellAPI);api.controls_uncertain=False;api.proc=base.proc
        events=[];attrs=[];created=[];freed=[];allocated=[]
        def initialize(buffer,count,flags,size):
            self.assertEqual(count,3);size._obj.value=256;return int(buffer is not None)
        def update(buffer,flags,kind,value,size,previous,returned):
            attrs.append(kind)
            if kind==m.owner.JOB_LIST:self.assertEqual(C.cast(value,C.POINTER(C.c_void_p))[0],99)
            elif kind==m.owner.ALL_APPLICATION_PACKAGES_POLICY:events.append(('policy',C.cast(value,C.POINTER(C.c_uint32))[0]))
            else:
                caps=value._obj;self.assertEqual((caps.CapabilityCount,caps.Reserved),(2,0))
                entries=C.cast(caps.Capabilities,C.POINTER(m.launcher.SIDAndAttributes))
                self.assertEqual([entries[i].Attributes for i in range(2)],[4,4])
            return int(kind!=fail_attribute)
        def sid(text,pointer):
            pointer._obj.value=100 if alias else 100+len(allocated)
            allocated.append(pointer._obj.value);return 1
        def create(actor,command,sa,ta,inherit,flags,environment,cwd,startup,info):
            self.assertFalse(inherit);self.assertTrue(flags&api.proc._CREATE_SUSPENDED)
            self.assertEqual(startup._obj.StartupInfo.dwFlags,0)
            created.append((actor,command.value,flags,cwd));info._obj.hProcess=201;info._obj.hThread=202
            info._obj.dwProcessId=203;info._obj.dwThreadId=204;return 1
        def free(pointer):freed.append(pointer.value);return 1 if free_unknown else 0
        api.k=NS(InitializeProcThreadAttributeList=initialize,UpdateProcThreadAttribute=update,
            DeleteProcThreadAttributeList=lambda value:events.append('attributes-deleted'),CreateProcessW=create,LocalFree=free)
        api.a=NS(ConvertStringSidToSidW=sid)
        def check(value,operation):
            if not value:raise ValueError(operation)
            return value
        api.native=NS(check=check,resume=lambda thread:events.append(('native-resume',thread)))
        return api,events,attrs,created,freed

    def test_real_adapter_shape_atomic_job_caps_policy_and_no_inheritance_with_ordinary_resume(self):
        for policy in (0,1):
            with self.subTest(policy=policy):
                api,events,attrs,created,freed=self.native_constructor()
                # Underlying ordinary ResumeThread remains available. Actor
                # authorization is denied by the owner before this method.
                api.resume(777);self.assertIn(('native-resume',777),events)
                info=base.proc._ProcessInfo();owners=m.helpers.OneShotHandles(lambda value:None);state={'creation_attempted':False}
                clock=NS(qpc=lambda:T+100,qpc_frequency=lambda:F);budget=m.launcher.QpcBudget(clock,D,F)
                api.create_matched_suspended(info,Path(m.live.ACTOR),Path('inputs'),'SystemRoot=C:\\Windows\0LOCALAPPDATA=x\0\0',99,owners,state,
                    profile_pointer=77,catalog=base.CATALOG,policy=policy,budget=budget,cutoff=D-25*F)
                self.assertEqual(attrs,[m.owner.JOB_LIST,m.owner.SECURITY_CAPABILITIES,m.owner.ALL_APPLICATION_PACKAGES_POLICY])
                self.assertIn(('policy',policy),events);self.assertEqual(len(created),1);self.assertEqual(len(freed),2)
                self.assertTrue(state['creation_attempted']);self.assertEqual(state['create_status'],'returned_true')
                self.assertEqual(set(owners.pending),{201,202})
        instance,api,_,_=self.run_cell()
        for role in ('ac','lpac'):
            with self.assertRaises(ValueError):instance.resume(instance.tasks[role])

    def test_constructor_attribute_failure_never_calls_create_and_unknown_cap_free_stays_uncertain(self):
        for failed,uncertain in ((m.owner.JOB_LIST,False),(None,True)):
            with self.subTest(failed=failed,uncertain=uncertain):
                api,_,_,created,_=self.native_constructor(fail_attribute=failed,free_unknown=uncertain)
                owners=m.helpers.OneShotHandles(lambda value:None);state={'creation_attempted':False}
                clock=NS(qpc=lambda:T+100,qpc_frequency=lambda:F);budget=m.launcher.QpcBudget(clock,D,F)
                with self.assertRaises(ValueError):
                    api.create_matched_suspended(base.proc._ProcessInfo(),Path(m.live.ACTOR),Path('inputs'),
                        'SystemRoot=C:\\Windows\0LOCALAPPDATA=x\0\0',99,owners,state,
                        profile_pointer=77,catalog=base.CATALOG,policy=1,budget=budget,cutoff=D-25*F)
                self.assertEqual(bool(created),uncertain);self.assertEqual(state['creation_attempted'],uncertain)
                self.assertEqual(api.controls_uncertain,uncertain)

    def test_constructor_alias_pointer_is_consumed_once_without_create(self):
        api,_,_,created,freed=self.native_constructor(alias=True)
        owners=m.helpers.OneShotHandles(lambda value:None);state={'creation_attempted':False}
        budget=m.launcher.QpcBudget(NS(qpc=lambda:T+100,qpc_frequency=lambda:F),D,F)
        with self.assertRaisesRegex(ValueError,'matched_capability_alias'):
            api.create_matched_suspended(base.proc._ProcessInfo(),Path(m.live.ACTOR),Path('inputs'),
                'SystemRoot=C:\\Windows\0LOCALAPPDATA=x\0\0',99,owners,state,
                profile_pointer=77,catalog=base.CATALOG,policy=1,budget=budget,cutoff=D-25*F)
        self.assertEqual(freed,[100]);self.assertFalse(created);self.assertFalse(state['creation_attempted'])
        self.assertTrue(api.controls_uncertain)

if __name__=='__main__':unittest.main()
