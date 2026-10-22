"""Pure held-owner/API models, not Windows execution or IPC evidence."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('proxy_ac_guest_test',ROOT/'.github/windows_identity_proxy_pipe_ac_guest.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
CONFIG=dict(enabled=True,run_nonce='1'*32,case_nonce='2'*32,actor_sha256='3'*64,manifest_sha256='4'*64)


def pair():
    return dict(case=0,admitted=True,created=3,resumed=3,exit_observed=3,identity_verified=3,
        parent_data_closed=True,reports_bound=3,observations=[177,78],core_failure=[0,0],
        pipe_eof=[True,True],native_close=[True,True],cleanup_confirmed=True,job_empty=True,
        watchdog_stop=False,expected_outcome=True,failure=None)


def projection():
    return dict(facts={key:True for key in g.FACTS},pair=pair(),ac_failure=None,
        diagnostic=dict(phase='complete',error_domain='none',error_code=None,controller_report='bound'))


def ordinary():
    return dict(sid='S-1-5-21-1-2-3-1001',session_id=1,token_type=1,elevation_type=1,elevated=False,
        integrity_rid=8192,admin_attributes=None,appcontainer=False,appcontainer_sid=None,
        capability_count=0,ui_access=False)


class GuestTests(unittest.TestCase):
    def controller(self):return g.controller_module()

    def positive(self):
        value=g.default_public(CONFIG);value.update(projection(),status='passed',ac_pipe_passed=True)
        return value

    def test_default_off_never_constructs_native_api(self):
        with mock.patch.object(g,'controller_module',return_value=types.SimpleNamespace(AC_EXECUTION_ENABLED=False)):
            value=g.execute(CONFIG,120000,1000)
        self.assertEqual(value['status'],'not_requested');self.assertFalse(value['ac_pipe_passed'])
        self.assertIsNone(value['pair'])

    def test_config_exact_types_and_closed_commitments(self):
        value=g.default_public(CONFIG)
        self.assertEqual(value['run_nonce_sha256'],hashlib.sha256(CONFIG['run_nonce'].encode('ascii')).hexdigest())
        self.assertNotIn(CONFIG['run_nonce'],json.dumps(value))
        for field,bad in [('enabled',1),('run_nonce','A'*32),('case_nonce','0'*31),('actor_sha256',False)]:
            config=dict(CONFIG);config[field]=bad
            with self.assertRaises(ValueError):g.default_public(config)
        with self.assertRaises(ValueError):g.default_public(dict(CONFIG,extra=True))

    def test_public_positive_and_failed_partial_pair(self):
        self.assertEqual(g.validate_public(self.positive(),CONFIG)['status'],'passed')
        value=self.positive();value['facts']['outer_cleanup_verified']=False
        value.update(status='inconclusive',ac_pipe_passed=False,ac_failure='cleanup')
        self.assertEqual(g.validate_public(value,CONFIG)['pair']['observations'],[177,78])
        value['ac_pipe_passed']=True
        with self.assertRaises(ValueError):g.validate_public(value,CONFIG)

    def test_public_rejects_open_types_raw_fields_and_changed_binding(self):
        for mutate in (lambda v:v.update(raw_sid='private'),lambda v:v.update(actor_sha256='f'*64),
                lambda v:v['facts'].update(images_verified=1),lambda v:v['diagnostic'].update(error_code=True),
                lambda v:v['pair'].update(created=True),lambda v:v['pair'].update(observations=[256,0])):
            value=self.positive();mutate(value)
            with self.assertRaises(ValueError):g.validate_public(value,CONFIG)

    def test_error_or_unbound_diagnostics_cannot_claim_pass(self):
        for fields in ({'controller_report':'read_error'},{'controller_report':'not_attempted'},
                       {'error_domain':'win32','error_code':123},{'error_domain':'internal'}):
            value=self.positive();value['diagnostic'].update(fields)
            with self.assertRaises(ValueError):g.validate_public(value,CONFIG)

    def test_json_duplicates_nonfinite_and_bound(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'\xff'):
            with self.assertRaises((ValueError,UnicodeError)):g.decode(raw)

    def test_command_original_deadline_and_fixed_controller_only(self):
        command=g.fixed_command('python.exe','controller.py','actor.exe','manifest.json',Path('work'),CONFIG,123456,1000)
        self.assertEqual(command.count('--run-ac-pair'),1)
        self.assertEqual(command[command.index('--deadline-qpc')+1],'123456')
        self.assertEqual(command[command.index('--qpc-frequency')+1],'1000')
        self.assertNotIn('--run-suite',command)

    def exercise(self,*,bad_identity=False,close_fail=False,launch_error=False,missing=False,unknown_exit=False,late=False,private_fixture=None):
        real=self.controller();events=[];parent=ordinary();calls={};config=dict(CONFIG);deadline=120000
        private=None
        if private_fixture is not None:
            private,expected=private_fixture
            config={k:expected[k] for k in ('run_nonce','case_nonce','actor_sha256','manifest_sha256')};config['enabled']=True
            parent['sid']=expected['controller_sid'];parent['session_id']=expected['controller_session'];deadline=expected['deadline_qpc']
        if bad_identity:parent['elevated']=True
        cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,process_exit_confirmed=not unknown_exit,
                     close_uncertain=False,errors=[])
        launch=dict(started=True,resumed=True,native_identity_verified_before_resume=True,child_pid=123,
                    exit_code=0,cleanup=cleanup,timed_out=False)
        if private_fixture is not None:launch['child_pid']=expected['controller_pid']
        if launch_error:launch['error']={'reason':'closed'};cleanup['close_uncertain']=True
        class API:
            def current_token(self):events.append('token');return 7
            def identity(self,t):return parent
            def compartment(self):return 1
            def close(self,t):
                events.append('close')
                if close_fail:raise OSError('private')
        class Budget:
            def __init__(self,api,d,f):self.deadline=d;calls['df']=(d,f)
            def cutoff(self,reserve):return self.deadline-reserve*1000
            def require_ms(self,cutoff):
                if late and cutoff==self.deadline:raise TimeoutError('private')
                return 5
        def owned(api,command,work,expected,observed,**kwargs):
            events.append('launch');calls.update(command=command,kwargs=kwargs)
            child=work/'controller';child.mkdir()
            if not missing:(child/'private-ac.json').write_bytes(json.dumps(private if private is not None else {'private':'fixture'}).encode('ascii'))
            return launch
        def validate(value,expected):
            calls['expected']=expected
            if private_fixture is not None:return real.validate_private_report(value,expected)
            self.assertEqual(value,{'private':'fixture'})
            return projection()
        launcher=types.SimpleNamespace(NativeAPI=API,QpcBudget=Budget,token_is_ordinary=real.launcher.token_is_ordinary,
            checked_path=lambda p,**kw:Path(p),launch_owned=owned,
            read_private_bytes=lambda p,limit:Path(p).read_bytes(),GateFailure=real.launcher.GateFailure)
        controller=types.SimpleNamespace(AC_EXECUTION_ENABLED=True,launcher=launcher,verify_ac_artifact=lambda a,m,h,e:(a,config['actor_sha256']),
            validate_private_report=validate,validate_pair=real.validate_pair,AC_PHASES=real.AC_PHASES,
            AC_FAILURES=real.AC_FAILURES,AC_REPORT_STATES=real.AC_REPORT_STATES,AC_ERROR_DOMAINS=real.AC_ERROR_DOMAINS)
        with tempfile.TemporaryDirectory() as directory:
            with (mock.patch.object(g,'os',types.SimpleNamespace(name='nt')),
                 mock.patch.object(g,'controller_module',return_value=controller),mock.patch.object(g,'sys',types.SimpleNamespace(base_prefix=directory,executable=str(Path(directory)/'python.exe'))),
                 mock.patch.object(g.shutil,'disk_usage',return_value=types.SimpleNamespace(free=100*1024*1024))):
                result=g.execute(config,deadline,1000,root=Path(directory),api=API())
            self.assertFalse((Path(directory)/'private-proxy-pipe-ac/controller').exists() and bad_identity)
        return result,events,calls

    def test_actual_execute_owned_launcher_and_strict_binding(self):
        value,events,calls=self.exercise()
        self.assertTrue(value['ac_pipe_passed']);self.assertEqual(events,['token','launch','close'])
        self.assertEqual(calls['df'],(120000,1000))
        self.assertEqual(calls['kwargs']['work_cutoff'],115000);self.assertEqual(calls['kwargs']['cleanup_cutoff'],120000)
        self.assertEqual(calls['expected']['controller_pid'],123)
        self.assertEqual(calls['expected']['controller_session'],1)

    def test_ordinary_failure_no_controller_work(self):
        value,events,calls=self.exercise(bad_identity=True)
        self.assertEqual(events,['token','close']);self.assertFalse(value['ac_pipe_passed']);self.assertIsNone(value['pair'])

    def test_late_and_cleanup_failure_preserve_bound_partial_positives(self):
        for opts in ({'close_fail':True},{'launch_error':True},{'late':True}):
            value,events,calls=self.exercise(**opts)
            self.assertFalse(value['ac_pipe_passed']);self.assertEqual(value['pair']['observations'],[177,78])
            self.assertEqual(events.count('close'),1)

    def test_unknown_exit_or_missing_report_never_fabricates_pair(self):
        for opts in ({'unknown_exit':True},{'missing':True}):
            value,events,calls=self.exercise(**opts)
            self.assertFalse(value['ac_pipe_passed']);self.assertIsNone(value['pair']);self.assertNotIn('expected',calls)

    def test_binding_requires_actual_held_controller_before_validator(self):
        controller=types.SimpleNamespace(validate_private_report=mock.Mock())
        for launch in ({},{'started':True,'resumed':True,'child_pid':123,'cleanup':{'process_exit_confirmed':True}}):
            with self.assertRaises(ValueError):g.bind_controller({},launch,CONFIG,ordinary(),120000,1000,controller)
        controller.validate_private_report.assert_not_called()

    def test_actual_controller_fixture_through_guest_execute_and_validator(self):
        spec=importlib.util.spec_from_file_location('proxy_ac_controller_fixture',ROOT/'tests/test_windows_identity_proxy_pipe_probe.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        private,expected,_=fixture.ac_fixture()
        value,events,calls=self.exercise(private_fixture=(private,expected))
        self.assertTrue(value['ac_pipe_passed'])
        self.assertEqual(calls['expected'],expected)
        for field,bad in (('controller_pid',expected['controller_pid']+1),('case_nonce','e'*32)):
            changed=copy.deepcopy(private);changed[field]=bad
            value,_,_=self.exercise(private_fixture=(changed,expected))
            self.assertFalse(value['ac_pipe_passed']);self.assertIsNone(value['pair'])
        changed=copy.deepcopy(private);changed['controller_identity']['sid']='S-1-5-21-8-9-10-1001'
        value,_,_=self.exercise(private_fixture=(changed,expected))
        self.assertFalse(value['ac_pipe_passed']);self.assertIsNone(value['pair'])
        private,expected,_=fixture.ac_fixture('profile_delete')
        value,_,_=self.exercise(private_fixture=(private,expected))
        self.assertFalse(value['ac_pipe_passed']);self.assertEqual(value['pair']['observations'],[177,78])

    def test_canonical_controller_identity_and_wrong_cache_refused(self):
        import sys
        controller=self.controller()
        self.assertIs(controller,g.controller_module())
        key='identity_proxy_pipe_controller'
        fake=types.SimpleNamespace(__file__=controller.__file__,__spec__=controller.__spec__,_source_sha256='0'*64)
        with mock.patch.dict(sys.modules,{key:fake}):
            with self.assertRaises(ValueError):g.controller_module()
        self.assertIs(controller,g.controller_module())

    def test_complete_wrapper_independent_width_ceiling(self):
        value=self.positive();value.update(status='not_requested',ac_failure='configuration',ac_pipe_passed=False)
        value['facts']={k:False for k in g.FACTS}
        value['diagnostic']=dict(phase='frontend_identity',error_domain='hresult',error_code=4294967295,controller_report='close_uncertain')
        value['pair'].update(observations=[255,255],core_failure=[None,None],failure='configuration')
        wire=dict(schema_version=1,proxy_pipe_ac=value,launcher=dict(phase='configuration',failure='work_budget_exhausted',
            python_exit_code=-2147483648,process_exit_confirmed=False,timed_out=False,budget_exhausted=False))
        self.assertLessEqual(len((json.dumps(wire,indent=2)+'\n').encode('ascii')),4096)


if __name__=='__main__':unittest.main()
