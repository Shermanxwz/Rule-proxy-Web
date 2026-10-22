"""Pure semantic DNS composition; no DLL, process, capability, ACL or socket API."""
import copy
import ctypes as C
import importlib.util
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('semantic_dns_pure',ROOT/'.github/windows_identity_lpac_semantic_dns.py')
old=load('semantic_dns_old_fixture',Path(__file__).with_name('test_windows_identity_lpac_dns_local.py'))
af=load('semantic_dns_access_fixture',Path(__file__).with_name('test_windows_identity_lpac_accesscheck.py'))
F,T,D=old.F,old.T,old.D

def config():
    c=old.config();c.update(scope=m.SCOPE,identity_basis=m.IDENTITY_BASIS)
    c['source_hashes']=dict.fromkeys((*m.SOURCES,m.LOCAL_MODULE),old.H);c['source_sha256']=m.sha(m.encode(c['source_hashes']))
    return c

def public_base():
    v=m.blank('runtime');v.update(source_sha256=old.H,actor_sha256=old.H,manifest_sha256=old.H,recovery_plan_sha256=old.H,tree_retained=True)
    v['checks'].update(dict.fromkeys(('ordinary','sources','artifact','plan','guard','worker_exit','outer_cleanup','worker_bound'),True));return v

class StrictFixture(old.FakeFixture):
    """Match the real fixture's keyword-only deadline, including finish."""
    def __init__(self,cases,*,deadline,socket_factory=None,thread_factory=None,clock=None):
        assert socket_factory is thread_factory is clock is None
        assert type(deadline) is float and time.monotonic()<deadline<=time.monotonic()+120
        super().__init__(cases,deadline=deadline);self.snapshot_deadlines=[];self.finish_deadlines=[]
    def snapshot(self,*,deadline):
        assert type(deadline) is float and deadline>time.monotonic()
        self.snapshot_deadlines.append(deadline)
        if getattr(self,'snapshot_late',False):self.owner.api.now=self.owner.budget.cutoff(20)
        return old.FakeFixture.snapshot(self,deadline=deadline)
    def finish(self,*,deadline):
        self.finish_deadlines.append(deadline)
        if self.cleanup_error:self.query_observed.set();raise OSError('fake unknown cleanup')
        return old.FakeFixture.snapshot(self,deadline=deadline)|dict(socket_close_attempted=True,socket_close_uncertain=False,
            socket_closed=True,thread_stopped=True,cleanup_confirmed=True)

class Probe(af.FakeAPI):
    def __init__(self,api):super().__init__();self.api=api;self.role='lpac'
    def frequency(self):return F
    def qpc(self):self.api.now+=1;return self.api.now
    def verify_process(self,h,pid,creation):return pid==h and creation==self.api.creation_time(h) and not self.api.wait(h,0)
    def open_token(self,h,rights):
        purpose=self.api.owner.j['semantic_checks'][-1]['purpose'];self.api.events.append(('matrix',purpose));self.fault=None
        if self.api.fault=='matrix-admission':self.fault='wrong-mask'
        if self.api.fault=='matrix-resume' and purpose=='resume':self.fault='wrong-mask'
        if self.api.fault=='observer-unknown' and purpose=='dns-go':self.fault='open-unknown'
        if self.api.fault=='matrix-after-wire' and self.api.owner.selected_wire:self.fault='wrong-mask'
        if self.api.fault=='observer-close' and purpose=='resume':self.fault='close-false'
        return super().open_token(h,rights)
    def identity(self,token):
        value=copy.deepcopy(self.api.owner.primary)
        if token==12:value.update(token_type=2,impersonation_level=1,token_id=value['token_id']+1)
        return value

class API(old.API):
    def __init__(self,root,fault=None):super().__init__(root,fault);self.native.query=self.statistics
    def process_id(self,h):return h
    def lpac_flag(self,token):raise AssertionError('semantic DNS must never call class46')
    def statistics(self,token,kind,label):
        assert kind==10
        s=m.access.TOKEN_STATISTICS();s.TokenType=1;s.TokenId.LowPart=10000+token;s.AuthenticationId.LowPart=20
        if self.fault=='primary-before-go' and ('go','before') in self.events:s.TokenId.LowPart+=1
        return C.create_string_buffer(C.string_at(C.byref(s),C.sizeof(s))),C.sizeof(s)
    def access_api(self):return Probe(self)

class SemanticDNSTests(unittest.TestCase):
    def run_owner(self,fault=None,status=5):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('inputs','lpac-report','lpac-control','health','health-control','tools'):(root/name).mkdir()
        for name in ('lpac-report','health'):(root/name/'temp').mkdir()
        (root/'inputs'/m.live.ACTOR).write_bytes(b'x'*512)
        for name in ('icacls.exe','WindowsPowerShell/v1.0/powershell.exe'):
            path=root/'win/System32'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(b'tool')
        script=root/m.live.dns.INVENTORY;script.parent.mkdir(parents=True);script.write_bytes(b'fixed readonly inventory')
        c=config();c['source_hashes'][m.live.dns.INVENTORY]=m.sha(script.read_bytes());c['source_sha256']=m.sha(m.encode(c['source_hashes']))
        api=API(root,fault);owner=m.Owner(root,c,old.PARENT,api,m.launcher.QpcBudget(api,D,F),fixture_factory=StrictFixture);api.owner=owner
        def read(api,budget,path,process,cutoff):
            name='selected' if path.parent.name=='lpac-report' else 'health';task=owner.tasks[name]
            if path.name=='ready.json':value=old.ready(task,c,name)
            else:
                ticket=owner.j['go'][-1];label=ticket['label'];fields=ticket['fields'];api.events.append(('go',label))
                if fault=='malformed-wire' and label=='selected':
                    owner.fixture.seen['selected']=1;owner.fixture.query_observed.set();raise ValueError('malformed native bytes')
                value=old.phase(task,c,name,label,fields,status if label=='selected' else 0)
                if label!='selected' or status==0:owner.fixture.seen[label]+=1
                if label=='selected' and status==0:owner.fixture.query_observed.set()
                if fault=='fixture-cleanup':owner.fixture.cleanup_error=True
                if fault=='snapshot-late':owner.fixture.snapshot_late=True;owner.fixture.owner=owner
                if fault=='inventory-stale' and label=='before':api.now+=6*F
                if fault=='selected-late' and label=='selected':
                    value['dns']['result'].update(within_deadline=False,end_qpc=fields['phase_deadline'])
                    value['phase_qpc'][2]=fields['phase_deadline'];value['failure']='deadline'
            raw=m.encode(value);path.write_bytes(raw);return value,raw
        original_wait=owner.wait
        def wait(row,end,code=0):
            if row['name'] in ('selected','health'):
                name=row['name'];path=root/('lpac-report' if name=='selected' else 'health')/'final.json';path.write_bytes(m.encode(old.final(row,c,name)))
            return original_wait(row,end,code)
        owner.wait=wait
        with patch.object(m.contracts,'read_when_closed',side_effect=read):j=owner.execute()
        m.validate_result(j,c,parent=old.PARENT);v=m.public_result(j,c,public_base(),parent=old.PARENT);m.validate_public(v)
        return owner,api,j,v

    def test_real_composition_all_three_phases_with_fresh_semantic_resume_go_and_no_class46(self):
        owner,api,j,v=self.run_owner()
        self.assertTrue(callable(owner.phase));self.assertEqual(j['failure'],None)
        self.assertTrue(j['semantic_resources_cleanup']);self.assertTrue(j['semantic_resume_go_verified'])
        self.assertEqual([(r['kind'],r['label']) for r in j['semantic_authorizations']],
            [('resume','selected'),('dns-go','before'),('dns-go','selected'),('dns-go','after'),('finish','selected')])
        self.assertEqual([r['label'] for r in j['inventory_gates']],['bind','before','selected','after'])
        self.assertEqual([r['label'] for r in j['go']],['before','selected','after','finish','finish'])
        self.assertEqual(len(j['native']),7);self.assertGreaterEqual(len(j['semantic_checks']),5)
        self.assertEqual(j['tasks'][4]['lpac'],None);self.assertFalse(j['token_class46_queried'])
        self.assertTrue(v['access_denial_observed']);self.assertEqual(v['status'],'observed');self.assertFalse(v['recovery_required'])
        self.assertEqual(v['selected_semantic_matrix'],[2,0,0,2]);self.assertFalse(v['dns_isolation_qualified'])
        self.assertEqual(owner.budget.deadline,D);self.assertTrue(api.deleted)

    def test_real_fixture_keyword_only_snapshot_and_finish_deadlines_bind_original_qpc(self):
        import inspect
        expected=m.live.dns.fixture.DnsCasesFixture
        self.assertEqual(inspect.signature(StrictFixture.__init__),inspect.signature(expected.__init__))
        self.assertEqual(inspect.signature(StrictFixture.snapshot),inspect.signature(expected.snapshot))
        self.assertEqual(inspect.signature(StrictFixture.finish),inspect.signature(expected.finish))
        owner,_,j,v=self.run_owner()
        self.assertEqual(len(owner.fixture.snapshot_deadlines),2);self.assertEqual(len(owner.fixture.finish_deadlines),1)
        self.assertTrue(j['ordinary_before'] and j['ordinary_after'] and j['natural_exits']);self.assertTrue(v['access_denial_observed'])
        for projected in owner.fixture.snapshot_deadlines:
            self.assertLessEqual(projected-time.monotonic(),(D-20*F-T)/F)
        with self.assertRaises(TypeError):owner.fixture.snapshot()

    def test_snapshot_crossing_original_work_cutoff_cannot_reach_selected_go(self):
        owner,_,j,v=self.run_owner('snapshot-late')
        self.assertEqual([row['label'] for row in j['go']],['before']);self.assertEqual(owner.budget.deadline,D)
        self.assertIsNotNone(j['failure']);self.assertFalse(v['observation_complete']);self.assertFalse(v['access_denial_observed'])

    def test_mismatched_admission_or_resume_matrix_never_resumes_selected_or_queries(self):
        for fault in ('matrix-admission','matrix-resume'):
            with self.subTest(fault=fault):
                owner,api,j,v=self.run_owner(fault)
                selected=next(r for r in j['tasks'] if r['name']=='selected')
                self.assertFalse(selected['resumed']);self.assertFalse(v['observation_complete']);self.assertEqual(j['go'],[])
                self.assertIsNone(owner.fixture);self.assertTrue(j['semantic_resources_cleanup']);self.assertTrue(api.deleted)

    def test_changed_primary_before_selected_go_is_rejected_without_rebasing_expected_token(self):
        _,_,j,v=self.run_owner('primary-before-go')
        self.assertEqual([r['label'] for r in j['go']],['before']);self.assertFalse(v['observation_complete'])
        self.assertIsNone(v['selected_api']);self.assertFalse(v['selected_wire_query_observed'])

    def test_observer_unknown_or_close_uncertain_blocks_profile_deletion_and_qualification(self):
        for fault in ('observer-unknown','observer-close'):
            with self.subTest(fault=fault):
                _,api,j,v=self.run_owner(fault)
                self.assertFalse(j['semantic_resources_cleanup']);self.assertFalse(api.deleted);self.assertTrue(v['recovery_required'])
                self.assertFalse(v['access_denial_observed'])

    def test_stale_once_inventory_rejects_selected_go_under_original_deadline(self):
        owner,_,j,v=self.run_owner('inventory-stale')
        self.assertEqual(j['failure'],'inventory');self.assertEqual([r['label'] for r in j['go']],['before'])
        self.assertFalse(v['observation_complete']);self.assertFalse(v['access_denial_observed']);self.assertEqual(owner.budget.deadline,D)

    def test_receiver_hit_precedes_native_or_matrix_parse_cleanup_failure_and_stays_failed(self):
        for fault in (None,'malformed-wire','matrix-after-wire','fixture-cleanup'):
            with self.subTest(fault=fault):
                _,_,j,v=self.run_owner(fault,status=0)
                self.assertTrue(v['selected_wire_query_observed']);self.assertTrue(v['network_tested']);self.assertEqual(v['status'],'failed')
                self.assertFalse(v['access_denial_observed']);self.assertFalse(v['dns_isolation_qualified'])
        _,_,j,_=self.run_owner(status=0);j['semantic_checks'][-1]['intent_sha256']='0'*64;v=public_base()
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.public_result(j,config(),v,parent=old.PARENT)
        self.assertTrue(v['selected_wire_query_observed']);self.assertEqual(v['status'],'failed')

    def test_typed_late_or_api87_never_becomes_api5_denial(self):
        for fault,status in (('selected-late',5),(None,87)):
            with self.subTest(fault=fault,status=status):
                _,_,_,v=self.run_owner(fault,status=status)
                self.assertEqual(v['status'],'inconclusive');self.assertFalse(v['access_denial_observed'])

    def test_closed_independent_fixture_hit_survives_corrupt_false_event_but_bad_fixture_is_unknown(self):
        owner,_,j,_=self.run_owner(status=0);j['selected_wire_query_observed']=False;v=public_base()
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.public_result(j,owner.c,v,parent=old.PARENT)
        self.assertTrue(v['selected_wire_query_observed']);self.assertTrue(v['network_tested']);self.assertEqual(v['status'],'failed')
        damaged=copy.deepcopy(j);damaged['fixture_final']['unknown_counter']=1;v=public_base()
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.public_result(damaged,owner.c,v,parent=old.PARENT)
        self.assertFalse(v['selected_wire_query_observed']);self.assertFalse(v['network_tested']);self.assertEqual(v['status'],'inconclusive')

    def test_external_parent_catalog_stats_authorization_and_resource_claim_mutations_rejected(self):
        owner,_,j,_=self.run_owner()
        def reject(mut):
            value=copy.deepcopy(j);mut(value)
            with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(value,owner.c,parent=old.PARENT)
        reject(lambda v:v.update(token_class46_queried=True))
        reject(lambda v:v['tasks'][4].update(lpac=1))
        reject(lambda v:v['selected_primary'].update(token_id=999))
        reject(lambda v:v['selected_primary']['capabilities'][0].update(attributes=0))
        reject(lambda v:v['semantic_authorizations'][2].update(proof_sequence=v['semantic_authorizations'][1]['proof_sequence']))
        reject(lambda v:v['semantic_checks'][-1].update(proof=None,held_after_qpc=None))
        reject(lambda v:v['semantic_checks'][0]['proof']['calls'][0].update(granted_access=3))
        reject(lambda v:v.update(semantic_checks=[]))
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.validate_result(j,owner.c,parent=old.PARENT|{'sid':'S-1-5-21-9'})

    def test_old_class46_default_entry_is_unchanged_and_still_rejects_real_api_shape87(self):
        native=m.launcher.NativeAPI.__new__(m.launcher.NativeAPI)
        def information(token,kind,value,size,returned):C.set_last_error(87);return 0
        from types import SimpleNamespace
        native.a=SimpleNamespace(GetTokenInformation=information)
        adapter=m.base.LPACAPI.__new__(m.base.LPACAPI);adapter.native=native
        with self.assertRaises(m.launcher.NativeFailure):adapter.lpac_flag(123)
        c=config();m.config_validate(c);self.assertEqual(len(c['source_hashes']),35)
        with self.assertRaises((ValueError,m.launcher.GateFailure)):m.base.config_validate(c)

if __name__=='__main__':unittest.main()
