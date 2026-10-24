"""Unexecuted pure source for A4 physical task/control validation.

All files and identities are synthetic. The small stdout baseline is explicitly
injected as a unit-test expectation; it is not an observed curl version. Actual
pure token, SID/SD, source/config digest and physical receipt validators remain
in the production path. No backend, DLL, target or Windows API is constructed.
"""
import copy
import ctypes
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
def load(name,filename):
    spec=importlib.util.spec_from_file_location(name,ROOT/'.github'/filename)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True):
    core=load('curl_a4_physical_core_fixture','windows_identity_lpac_curl_a4_loader.py')
    physical=load('curl_a4_physical_under_test','windows_identity_lpac_curl_a4_physical.py')

PARENT=dict(sid='S-1-5-21-1-2-3-1001',session_id=1,token_type=1,elevation_type=3,
    elevated=False,integrity_rid=8192,admin_attributes=16,appcontainer=False,
    appcontainer_sid=None,capability_count=0,ui_access=False)
BASELINE=b'inert fixed version fixture\n'


class PhysicalTests(unittest.TestCase):
    def setUp(self):
        trap=patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True)
        trap.start();self.addCleanup(trap.stop)

    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('returns','journal','ordinary-before','ordinary-after'):(root/name).mkdir()
        m=SimpleNamespace(**vars(core))
        m.BASELINE_BYTES=len(BASELINE);m.BASELINE_SHA256=core.sha(BASELINE)
        hashes={name:core.sha(b'inert immutable source fixture\n') for name in core.SOURCES}
        c=dict(schema_version=1,scope=core.SCOPE,profile=core.PROFILE,
            **{name:str(i+1)*32 for i,name in enumerate(core.NONCES)},frequency=100,start_qpc=10000,
            root_deadline_qpc=22000,deadline_qpc=21500,guard_job_name='Local\\RuleProxy.LocalGuard.'+'1'*32,
            source_hashes=hashes,source_sha256=core.sha(core.encode(hashes)),device_sha256='5'*64,
            recovery_plan_sha256='6'*64,artifacts=copy.deepcopy(core.FROZEN_ARTIFACTS),curl_path=str(root/'curl.exe'))
        return dict(m=m,c=c,root=root)

    def store_return(self,f,task,value):
        raw=core.encode(value);name=task['receipt']['name']
        (f['root']/'returns'/name).write_bytes(raw)
        task['receipt']=dict(name=name,text=raw.decode('ascii'),sha256=core.sha(raw))

    def task(self,f,name):
        selected=name=='selected';identity=copy.deepcopy(PARENT)
        identity.update(appcontainer=selected,appcontainer_sid='S-1-15-2-1-2-3-4-5-6-7' if selected else None,
            integrity_rid=4096 if selected else 8192)
        primary=dict(sid=PARENT['sid'],session_id=1,token_type=1,impersonation_level=None,
            appcontainer=selected,appcontainer_sid=identity['appcontainer_sid'],integrity_rid=identity['integrity_rid'],
            elevated=False,ui_access=False,capabilities=[],token_id=33,authentication_id=44)
        security=dict.fromkeys(('process','thread'),'D:P(A;;GA;;;SY)(A;;0x1fffff;;;'+PARENT['sid']+')')
        task=dict(name=name,attempted=True,assigned=True,exited=True,exit_code=0,pid=77,created=123456,
            process_returned=True,resumed=True,admitted=True,image_sha256=core.CURL_SHA256,
            admission_qpc=10021,resume_qpc=10032,resume_intent_qpc=10031,exit_observed_qpc=10040,
            natural_exit=True,identity=identity,capabilities=[],lpac=None,lpac_expected=selected,
            expected_primary=primary,held_checks=[],receipt=None,
            create_observation=dict(status='returned_true',winerror=None,process_information='nonzero',
                returned_qpc=10010,work_cutoff=10800,exception_detail=None),
            constructor_return_qpc=10012,inherited_handles=[101,102,103,104] if selected else [101,102,103],
            parent_copies_closed=True,kernel_security=security)
        for tick in (10020,10030):
            task['held_checks'].append(dict(qpc=tick,pid=77,created=123456,image_sha256=core.CURL_SHA256,
                primary=copy.deepcopy(primary),inner_job=True,outer_job=True,kernel_security=copy.deepcopy(security)))
        number={'before':0,'selected':1,'after':2}[name]
        intent=dict(schema_version=1,scope=core.SCOPE,run=f['c']['run'],config_sha256=core.sha(core.encode(f['c'])),
            frequency=100,deadline_qpc=f['c']['deadline_qpc'],qpc=10001,action='create-'+name)
        intent_raw=core.encode(intent);receipt_name='%03d-create-%s.json'%(number,name)
        (f['root']/'journal'/receipt_name).write_bytes(intent_raw)
        value=dict(schema_version=1,scope=core.SCOPE,run=f['c']['run'],config_sha256=core.sha(core.encode(f['c'])),
            intent_sha256=core.sha(intent_raw),action='create-'+name,qpc=10011,
            data=dict(creation_attempted=True,creation_unknown=False,create_status='returned_true',
                raw_return=1,raw_error=None,raw_pi=[201,202,77,78],returned_qpc=10010))
        task['receipt']={'name':receipt_name};self.store_return(f,task,value)
        return task

    def control(self,f,role):
        task=self.task(f,role);directory=f['root']/('ordinary-'+role)
        (directory/'stdout').write_bytes(BASELINE);(directory/'stderr').write_bytes(b'')
        value=dict(schema_version=1,scope=core.SCOPE,run=f['c']['run'],config_sha256=core.sha(core.encode(f['c'])),
            parent_sha256=core.sha(core.encode(PARENT)),role=role,case=f['c'][role+'_case'],deadline_qpc=10800,
            task=task,output=dict(stdout_bytes=len(BASELINE),stdout_sha256=core.sha(BASELINE),stderr_bytes=0,
                stderr_sha256=core.sha(b''),exact_baseline=True),positive=True)
        (f['root']/('control-'+role+'.json')).write_bytes(core.encode(value));return value

    def test_positive_task_roles_have_exact_handle_counts_and_physical_PI(self):
        f=self.fixture()
        for role,expected in (('before',3),('selected',4),('after',3)):
            task=self.task(f,role)
            self.assertIs(physical.task_validate(f['m'],task,f['c'],PARENT,f['root'],curl=True),task)
            self.assertEqual(len(task['inherited_handles']),expected)
            for bad_handles in (task['inherited_handles'][:-1],[101]*expected):
                bad=copy.deepcopy(task);bad['inherited_handles']=bad_handles
                with self.subTest(role=role,handles=bad_handles),self.assertRaises(ValueError):
                    physical.task_validate(f['m'],bad,f['c'],PARENT,f['root'],curl=True)

    def test_PI_envelope_and_raw_return_clock_cannot_contradict_admission(self):
        f=self.fixture()
        def data_tick(value):value['data']['returned_qpc']=10009
        def receipt_tick(value):value['qpc']=10009
        def receipt_late(value):value['qpc']=10013
        def bool_return(value):value['data']['raw_return']=True
        def unknown_creation(value):value['data']['creation_unknown']=True
        def bad_schema(value):value['schema_version']=True
        def bad_intent(value):value['intent_sha256']='not-a-digest'
        def extra(value):value['unrecognized']=1
        for change in (data_tick,receipt_tick,receipt_late,bool_return,unknown_creation,bad_schema,bad_intent,extra):
            task=self.task(f,'before');value=core.decode(task['receipt']['text'].encode('ascii'));change(value)
            self.store_return(f,task,value)
            with self.subTest(change=change.__name__),self.assertRaises(ValueError):
                physical.task_validate(f['m'],task,f['c'],PARENT,f['root'],curl=True)

    def test_fresh_ordinary_primary_and_ordered_held_brackets_are_required(self):
        f=self.fixture()
        for kind in ('ordinary-low','preconstructor','no-resume-held','backwards','wrong-job','changed-SD','float-cutoff'):
            task=self.task(f,'before')
            if kind=='ordinary-low':
                task['identity']['integrity_rid']=4096;task['expected_primary']['integrity_rid']=4096
                for held in task['held_checks']:held['primary']['integrity_rid']=4096
            elif kind=='preconstructor':task['held_checks'][0]['qpc']=10005
            elif kind=='no-resume-held':task['held_checks']=task['held_checks'][:1]
            elif kind=='backwards':task['held_checks'][1]['qpc']=10019
            elif kind=='wrong-job':task['held_checks'][1]['outer_job']=False
            elif kind=='changed-SD':task['held_checks'][1]['kernel_security']['thread']='D:P(A;;GA;;;SY)'
            else:task['create_observation']['work_cutoff']=10800.0
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                physical.task_validate(f['m'],task,f['c'],PARENT,f['root'],curl=True)

    def test_control_physical_bytes_keep_valid_peer_when_other_is_bad_or_missing(self):
        f=self.fixture();before=self.control(f,'before');self.control(f,'after')
        physical.validate_ordinary_control(f['m'],before,f['c'],role='before',parent=PARENT,root=f['root'])
        self.assertEqual(physical.ordinary_controls(f['m'],f['root'],f['c'],PARENT),dict(before=True,after=True))
        (f['root']/'ordinary-after'/'stdout').write_bytes(b'different physical stdout')
        self.assertEqual(physical.ordinary_controls(f['m'],f['root'],f['c'],PARENT),dict(before=True,after=False))
        (f['root']/'control-after.json').write_bytes(b'{malformed')
        self.assertEqual(physical.ordinary_controls(f['m'],f['root'],f['c'],PARENT),dict(before=True,after=False))
        (f['root']/'control-after.json').unlink()
        self.assertEqual(physical.ordinary_controls(f['m'],f['root'],f['c'],PARENT),dict(before=True,after=False))
        # A claimed output digest is not a substitute for physical stdout.
        (f['root']/'ordinary-before'/'stdout').write_bytes(b'tamper')
        self.assertEqual(physical.ordinary_controls(f['m'],f['root'],f['c'],PARENT),dict(before=False,after=False))

    def test_record_namespace_inside_root_and_scope_config_are_closed(self):
        f=self.fixture();task=self.task(f,'before');record=task['receipt'];path=f['root']/'returns'/record['name']
        physical.physical_record(f['m'],record,path,f['root'])
        for name in ('00-create-before.json','0000-create-before.json','../000-create-before.json'):
            bad=copy.deepcopy(record);bad['name']=name
            with self.subTest(name=name),self.assertRaises(ValueError):
                physical.physical_record(f['m'],bad,path,f['root'])
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        outside=Path(td.name)/record['name'];outside.write_bytes(record['text'].encode('ascii'))
        with self.assertRaises((ValueError,core.launcher.GateFailure)):
            physical.physical_record(f['m'],record,outside,f['root'])
        for key,value in (('scope','another-scope'),('run','f'*32),('config_sha256','0'*64)):
            bad=self.task(f,'before');envelope=core.decode(bad['receipt']['text'].encode('ascii'));envelope[key]=value
            self.store_return(f,bad,envelope)
            with self.subTest(key=key),self.assertRaises(ValueError):
                physical.task_validate(f['m'],bad,f['c'],PARENT,f['root'],curl=True)

    def test_complete_observation_requires_causal_chain_and_all14_cleanup_flags(self):
        f=self.fixture();m=f['m']
        observation=dict.fromkeys((*m.OBS_BOOLS,*m.FALSE_CLAIMS),False)
        observation.update(dict.fromkeys(m.OBS_BOOLS,True))
        observation.update(failure=None,selected_exit_code=0,trace_call_count=1)
        physical.validate_observation(m,observation)
        self.assertEqual(len(m.CLEAN_KEYS),14)
        for key in (*m.CLEAN_KEYS,'selected_resumed','payload_carrier_returned_nonnull','trace_header_bound'):
            bad=copy.deepcopy(observation);bad[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):physical.validate_observation(m,bad)
        partial=copy.deepcopy(observation);partial.update(failure='cleanup',observation_complete=False)
        partial[m.CLEAN_KEYS[-1]]=False
        physical.validate_observation(m,partial)
        self.assertTrue(partial['ordinary_before_positive']);self.assertTrue(partial['ordinary_after_positive'])
        for key in m.FALSE_CLAIMS:
            bad=copy.deepcopy(partial);bad[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):physical.validate_observation(m,bad)


if __name__=='__main__':unittest.main()
