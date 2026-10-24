"""Stage0b host prerequisites only: inert payloads and closed transport, never VM."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest
from unittest.mock import Mock,patch
import zipfile
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,ROOT/path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=load('stage0b_host_test','.github/windows_identity_direct_stage0.py')
f=load('stage0b_payload_test','.github/test_windows_udp_payload.py')
CONFIG=dict(enabled=True,case_nonce='a'*32,actor_sha256='b'*64)
def envelope():
    return dict(schema_version=1,stage0b=h.stage0b_helpers().default_public(CONFIG['case_nonce'],CONFIG['actor_sha256']),launcher=dict(phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True,timed_out=False,budget_exhausted=False))
class HostTests(unittest.TestCase):
    def test_default_off_before_load_or_owned_resources(self):
        with patch.object(h,'STAGE0B_EXECUTION_ENABLED',False),patch.object(h,'load') as loader,patch.object(h,'stage0b_helpers') as adapter:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(stage0b=True))
            loader.assert_not_called();adapter.assert_not_called()
    def test_every_optional_conflict_precedes_load(self):
        for key in ('n0a','n0a_capture_runner','n0a_udp_runner','n0a_udp_parent_runner','n0a_udp6_runner'):
            with self.subTest(key=key),patch.object(h,'load') as loader:
                with self.assertRaises(ValueError):h.host(SimpleNamespace(stage0b=True,**{key:True}))
                loader.assert_not_called()
    def test_adapter_flag_also_required_before_resources(self):
        with patch.object(h,'STAGE0B_EXECUTION_ENABLED',True),patch.object(h,'stage0b_helpers',return_value=SimpleNamespace(EXECUTION_ENABLED=False)),patch.object(h,'load') as loader:
            with self.assertRaises(PermissionError):h.host(SimpleNamespace(stage0b=True))
            loader.assert_not_called()
    def test_real_fourteen_payload_exact_sources_and_no_extra_binary(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)/'owned';f.generate(root)
            with zipfile.ZipFile(root/'baseline.zip') as z:base=set(z.namelist())
            with zipfile.ZipFile(root/'stage0b.zip') as z:
                self.assertEqual(set(z.namelist()),base|set(h.STAGE0B_FILES));self.assertEqual(len(z.namelist()),14)
                for name in h.STAGE0B_FILES:self.assertEqual(z.read(name),(ROOT/name).read_bytes())
                self.assertEqual([x for x in z.namelist() if x.endswith('actor.exe')],['actor.exe'])
                a=z.getinfo('actor.exe').file_size;e=sum(x.file_size for x in z.infolist())
            result=h.stage0b_staging_capacity(root/'stage0b.zip',a)
            self.assertEqual(result['total'],(root/'stage0b.zip').stat().st_size+e+24405990+2*a+1048576)
            for i,bad in enumerate(f.STAGE0B_FORBIDDEN):
                with zipfile.ZipFile(root/f'stage0b-bad-{i}.zip') as z:self.assertEqual(len(z.namelist()),14);self.assertIn(bad,z.namelist())
    def test_capacity_bound_and_actor_types(self):
        a=512;e=10000;p=134217728-e-24405990-2*a-1048576
        entries=[SimpleNamespace(filename='actor.exe',file_size=a)]+[SimpleNamespace(filename=str(i),file_size=0) for i in range(12)]+[SimpleNamespace(filename='last',file_size=e-a)]
        z=Mock();z.__enter__=Mock(return_value=z);z.__exit__=Mock(return_value=False);z.infolist.return_value=entries
        with patch.object(h.zipfile,'ZipFile',return_value=z),patch.object(h.Path,'stat',return_value=SimpleNamespace(st_size=p)):
            self.assertEqual(h.stage0b_staging_capacity('fixture',a)['total'],134217728)
        with patch.object(h.zipfile,'ZipFile',return_value=z),patch.object(h.Path,'stat',return_value=SimpleNamespace(st_size=p+1)):
            with self.assertRaises(ValueError):h.stage0b_staging_capacity('fixture',a)
        for bad in (True,511,8388609,'512'):
            with self.assertRaises(ValueError):h.stage0b_staging_capacity('not-opened',bad)
    def test_closed_report_strict_commitments_and_unknown(self):
        value=envelope();self.assertEqual(h.validate_stage0b_envelope(value,CONFIG),value)
        value['stage0b']=None;self.assertIsNone(h.validate_stage0b_envelope(value,CONFIG)['stage0b'])
        for change in (lambda v:v.update(schema_version=True),lambda v:v.update(raw='private'),lambda v:v['launcher'].update(python_exit_code=True),lambda v:v['stage0b'].update(case_nonce_sha256='0'*64),lambda v:v['stage0b'].update(actor_creation_observed=None),lambda v:v['stage0b'].update(pipe_echo_verified=True)):
            v=envelope();change(v)
            with self.assertRaises(ValueError):h.validate_stage0b_envelope(v,CONFIG)
        with self.assertRaises(ValueError):h.stage0b_unique([('x',1),('x',2)])
    def test_full_fixed_schemas_fit_without_nulling(self):
        v=envelope();v['launcher'].update(phase='configuration',failure='work_budget_exhausted',python_exit_code=-2147483648,process_exit_confirmed=False)
        v['stage0b']['failure']='configuration'
        h.validate_stage0b_envelope(v,CONFIG)
        full=dict(schema_version=1,stage='stage0b-host',report=v,report_validation='unavailable',original_stage0_passed=False,vm_destroyed=False,product_acceptance=False,stage0b_ipc_qualified=False)
        self.assertLess(len(json.dumps(full,ensure_ascii=True).encode('ascii'))+1,4096)
        self.assertNotIn(CONFIG['case_nonce'],json.dumps(full))
    def test_host_qualification_requires_outer_lifecycle_without_erasing_inner(self):
        value=envelope()
        for key in h.stage0b_helpers().REQUIRED_FACTS:value['stage0b'][key]=True
        value['stage0b'].update(stage0b_passed=True,status='passed',failure=None)
        value['stage0b']['child_environment']=dict(environment_version=1,variant='systemroot_localappdata_v1',lookup_state='ready',hresult=0,release_attempted=True,release_returned=True,exact_child_keyset=True,com=[True,0,True,True],deadline_verified=True)
        value['stage0b']['child_environment_source']='report'
        value['stage0b']['diagnostic']['reads'][1]='parsed';value['stage0b']['diagnostic']['bindings'][1]='verified'
        h.validate_stage0b_envelope(value,CONFIG)
        self.assertTrue(h.stage0b_ipc_qualified(value,True))
        combined=dict(original_stage0_passed=False,stage0b_ipc_qualified=h.stage0b_ipc_qualified(value,True),product_acceptance=False)
        self.assertFalse(combined['original_stage0_passed']);self.assertTrue(combined['stage0b_ipc_qualified']);self.assertFalse(combined['product_acceptance'])
        for changes in ({'timed_out':True},{'budget_exhausted':True},{'failure':'handle_dispose'},{'process_exit_confirmed':None},{'python_exit_code':None},{'python_exit_code':True}):
            row=copy.deepcopy(value);row['launcher'].update(changes)
            self.assertFalse(h.stage0b_ipc_qualified(row,True));self.assertTrue(row['stage0b']['stage0b_passed'])
        self.assertFalse(h.stage0b_ipc_qualified(value,False))
    def test_schema3_old_history_rejected_and_known_positive_retained(self):
        value=envelope();self.assertEqual(value['stage0b']['schema_version'],3)
        value['stage0b']['launcher_creation_observed']=True
        value['stage0b']['diagnostic']['reads']=['missing']*3
        observed=h.validate_stage0b_envelope(value,CONFIG)
        self.assertTrue(observed['stage0b']['launcher_creation_observed'])
        self.assertFalse(observed['stage0b']['stage0b_passed'])
        self.assertEqual(observed['stage0b']['diagnostic']['reads'],['missing']*3)
        old=copy.deepcopy(value);old['stage0b']['schema_version']=1;del old['stage0b']['diagnostic']
        with self.assertRaises(ValueError):h.validate_stage0b_envelope(old,CONFIG)
        self.assertEqual(old['stage0b']['schema_version'],1)
    def test_schema3_independent_maxima_public_wrapper_below4096(self):
        g=h.stage0b_helpers();l=g.launcher_module();longest=lambda labels:max(labels,key=len)
        value=envelope();public=value['stage0b'];public['failure']=longest(g.FAILURES)
        public.update(child_environment=dict(environment_version=1,variant=l.CHILD_ENVIRONMENT_VARIANT,lookup_state=max(l.CHILD_ENVIRONMENT_STATES,key=len),hresult=4294967295,release_attempted=False,release_returned=False,exact_child_keyset=False,com=[False,4294967295,False,False],deadline_verified=False),child_environment_source='owned_stdout')
        public['diagnostic']=dict(v=1,held=dict(created=False,resumed=False,exit_observed=False,exit_code=4294967295,cleanup_confirmed=False),reads=[longest(g.READ_STATES)]*3,bindings=[longest(g.BINDING_STATES)]*3,stdout_reads=[longest(g.READ_STATES)]*2,execution_sources=['owned_stdout']*3,execution=[[longest(l.DIAGNOSTIC_STAGES),longest(l.DIAGNOSTIC_STAGES),longest(l.DIAGNOSTIC_CATEGORIES),longest(l.DIAGNOSTIC_OPERATIONS),4294967295]]*3)
        value['launcher'].update(phase='configuration',failure='work_budget_exhausted',python_exit_code=-2147483648,process_exit_confirmed=False)
        full=dict(schema_version=1,stage='stage0b-host',report=value,report_validation='unavailable',original_stage0_passed=False,vm_destroyed=False,product_acceptance=False,stage0b_ipc_qualified=False)
        # Independent longest fields deliberately include impossible combinations:
        # this is a conservative byte upper bound, not an accepted report fixture.
        for row in (public,value,full):self.assertLessEqual(len((json.dumps(row,ensure_ascii=True,indent=2)+'\n').encode('ascii')),4096)
    def test_transport_result_first_bound_duplicate_and_route(self):
        def request(value,path='stage0b-result',ready=True):
            server=SimpleNamespace(capability='fixed',received=threading.Event(),n0a_received=threading.Event(),n0a_expected=CONFIG,stage0b_validation='unavailable')
            if ready:server.received.set()
            raw=json.dumps(value).encode();obj=object.__new__(h.Stage0bClosedHandler);obj.server=server;obj.path='/fixed/'+path;obj.headers={'Content-Length':str(len(raw))};obj.rfile=io.BytesIO(raw);obj.send_error=Mock();obj.send_response=Mock();obj.end_headers=Mock();obj.do_POST();return obj,server
        obj,s=request(envelope(),ready=False);obj.send_error.assert_called_once_with(409)
        obj,s=request(envelope());obj.send_response.assert_called_once_with(200);self.assertTrue(s.n0a_received.is_set())
        obj,s=request(envelope(),path='n0a-result');obj.send_error.assert_called_once_with(404)
        obj,s=request({'raw':'x'*4096});obj.send_error.assert_called_once_with(400)
if __name__=='__main__':unittest.main()
