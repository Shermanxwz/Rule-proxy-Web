"""Fake-only source for the A4 outer guard.

The production guard is imported with a DLL-construction trap. Tests inject
only file/identity adapters and never construct a production backend, load a
DLL, run curl, or infer that an injected inner report proves the A4 mechanism.
The small observation adapter below deliberately leaves qualification to the
guard so these tests exercise its independent outer admission and cleanup gates.
"""
import copy
import ctypes
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location(
    'curl_a4_local_inert_test',ROOT/'.github/windows_identity_lpac_curl_a4_loader_local.py')
m=importlib.util.module_from_spec(spec)
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('forbidden DLL construction'),create=True):
    spec.loader.exec_module(m)


class ReadonlyAPI:
    def __init__(self):self.calls=[]
    def windows_x64(self):self.calls.append('windows_x64');return True
    def device_sha256(self):self.calls.append('device_sha256');return '1'*64


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.traps=ExitStack();self.addCleanup(self.traps.close)
        self.traps.enter_context(patch.object(ctypes,'WinDLL',
            side_effect=AssertionError('forbidden DLL construction'),create=True))
        self.outer_factory=self.traps.enter_context(patch.object(m.local,'LocalNativeAPI',
            side_effect=AssertionError('forbidden outer backend')))
        self.inner_factory=self.traps.enter_context(patch.object(m.core,'NativeAPI',
            side_effect=AssertionError('forbidden inner backend'),create=True))
        self.launch=self.traps.enter_context(patch.object(m.launcher,'launch_owned',
            side_effect=AssertionError('forbidden actor launch')))

    def fixture(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup)
        root=Path(td.name).resolve();(root/'private').mkdir()
        files={name:b'# inert source bytes; never imported as a worker\n' for name in m.SOURCES}
        hashes={name:m.sha(raw) for name,raw in files.items()}
        source=m.sha(m.encode(hashes))
        paths={key:root/name for key,name in (
            ('shim',m.core.SHIM),('carrier',m.core.CARRIER),
            ('manifest',m.core.MANIFEST),('curl','curl.exe'))}
        # These are inert fixture files. Artifact byte/PE verification is an
        # explicit adapter in guard tests; the real plan/pin schema is retained.
        for key,path in paths.items():path.write_bytes(b'inert-'+key.encode('ascii'))
        artifacts=copy.deepcopy(m.core.FROZEN_ARTIFACTS)
        plan=dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,
            **{key:str(i+1)*32 for i,key in enumerate(m.core.NONCES)},
            device_sha256='1'*64,source_sha256=source,artifacts=artifacts,
            curl_path=str(paths['curl']),recovery_reference='inert bounded recovery source reference '*16,
            **dict.fromkeys(m.core.ACKS,True))
        path=root/'plan.json';path.write_bytes(m.encode(plan))
        return dict(root=root,files=files,hashes=hashes,source=source,paths=paths,
            artifacts=artifacts,plan=plan,plan_path=path)

    def args(self,f):
        return tuple(f['paths'][key] for key in ('shim','carrier','manifest','curl'))+(
            f['artifacts'],f['root']/'private',f['plan_path'])

    def config(self,f):
        start,frequency=10000,100
        return dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,
            **{key:f['plan'][key] for key in m.core.NONCES},start_qpc=start,frequency=frequency,
            root_deadline_qpc=start+120*frequency,deadline_qpc=start+115*frequency,
            guard_job_name='Local\\RuleProxy.LocalGuard.'+f['plan']['run'],source_hashes=f['hashes'],
            source_sha256=f['source'],device_sha256='1'*64,
            recovery_plan_sha256=m.sha(f['plan_path'].read_bytes()),
            artifacts=f['artifacts'],curl_path=str(f['paths']['curl']))

    def observation(self):
        value=dict.fromkeys((*m.core.OBS_BOOLS,*m.core.FALSE_CLAIMS),False)
        value.update(dict.fromkeys(m.core.OBS_BOOLS,True))
        value.update(failure=None,selected_exit_code=0,trace_call_count=1)
        return value

    def observation_adapter(self,value):
        if (type(value) is not dict or set(value)!=set(m.core.OBS_KEYS)
                or any(type(value[key]) is not bool for key in (*m.core.OBS_BOOLS,*m.core.FALSE_CLAIMS))
                or any(value[key] for key in m.core.FALSE_CLAIMS)):
            raise ValueError('inert observation schema')
        return value

    def complete_public(self):
        value=m.blank('runtime')
        value.update(status='observed',source_sha256='2'*64,recovery_plan_sha256='3'*64,
            outer_launch_report_sha256='4'*64,artifacts=copy.deepcopy(m.core.FROZEN_ARTIFACTS),
            tree_retained=True,observation=self.observation(),observation_complete=True)
        value['checks']=dict.fromkeys(m.CHECKS,True)
        value['ordinary_controls']=dict(before=True,after=True)
        return value

    def test_default_CLI_and_mixed_worker_args_never_construct_backend(self):
        for ready in (False,True):
            with self.subTest(ready=ready),patch.object(m.core,'ACTUAL_READY',ready),patch('builtins.print'):
                self.assertEqual(m.main([]),1)
                with self.assertRaisesRegex(ValueError,'exact_worker_args'):
                    m.main(['--worker','unused','--run-local-lpac-curl-a4-loader'])
        f=self.fixture();pins=f['root']/'pins.json';pins.write_bytes(m.encode(f['artifacts']))
        argv=[]
        for name,path in (('shim',f['paths']['shim']),('carrier',f['paths']['carrier']),
                ('manifest',f['paths']['manifest']),('curl',f['paths']['curl']),('artifact-pins',pins),
                ('work-parent',f['root']/'private'),('recovery-plan',f['plan_path'])):
            argv.extend(('--'+name,str(path)))
        with patch.object(m,'preflight',return_value=m.blank('preflight')) as preview,\
                patch.object(m,'run_local',side_effect=AssertionError('runtime without opt-in')),patch('builtins.print'):
            self.assertEqual(m.main(argv),1)
            preview.assert_called_once()
        self.outer_factory.assert_not_called();self.inner_factory.assert_not_called();self.launch.assert_not_called()

    def test_ready_and_explicit_optin_are_independent_runtime_gates(self):
        for ready,approved in ((False,False),(False,True),(True,False)):
            with self.subTest(ready=ready,approved=approved),patch.object(m.core,'ACTUAL_READY',ready):
                value=m.run_local(*(None,)*7,approved=approved)
            self.assertEqual(value['failure'],'disabled')
            self.assertFalse(value['tree_retained']);self.assertFalse(value['recovery_required'])
            self.assertFalse(value['observation_complete'])
        self.outer_factory.assert_not_called();self.inner_factory.assert_not_called();self.launch.assert_not_called()

    def test_preflight_without_runtime_optin_is_readonly_and_has_no_runtime_facts(self):
        f=self.fixture();api=ReadonlyAPI()
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),\
                patch.object(m,'inputs',return_value=f['paths']),\
                patch.object(m.local,'ordinary',return_value={'inert_parent':True}),\
                patch.object(m.core,'verify_system_curl',return_value=f['paths']['curl']),\
                patch.object(m.core,'ACTUAL_READY',False):
            value=m.preflight(*self.args(f),api=api,root=f['root'])
        self.assertEqual(value['status'],'ready')
        self.assertTrue(all(value['checks'][key] for key in m.CHECKS[:4]))
        self.assertFalse(any(value['checks'][key] for key in m.CHECKS[4:]))
        self.assertEqual(value['ordinary_controls'],dict(before=False,after=False))
        self.assertIsNone(value['observation']);self.assertFalse(value['observation_complete'])
        self.assertFalse(value['tree_retained']);self.assertFalse(value['recovery_required'])
        self.assertEqual(api.calls,['windows_x64','device_sha256'])
        self.outer_factory.assert_not_called();self.inner_factory.assert_not_called();self.launch.assert_not_called()

    def test_false_ready_preflight_without_injection_stops_after_file_gates(self):
        f=self.fixture()
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),\
                patch.object(m,'inputs',return_value=f['paths']),patch.object(m.core,'ACTUAL_READY',False):
            value=m.preflight(*self.args(f),root=f['root'])
        self.assertEqual(value['failure'],'disabled')
        self.assertTrue(value['checks']['sources']);self.assertTrue(value['checks']['artifacts'])
        self.assertFalse(value['checks']['ordinary']);self.assertFalse(value['checks']['plan'])
        self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_unsafe_or_noncanonical_plan_is_rejected_before_factory(self):
        f=self.fixture()
        changes=(lambda p:p.update(schema_version=True),lambda p:p.update(unrecognized=True),
            lambda p:p.update({m.core.ACKS[0]:False}),lambda p:p.update(source_sha256='f'*64),
            lambda p:p.update({m.core.NONCES[-1]:p['run']}))
        for index,change in enumerate(changes):
            plan=copy.deepcopy(f['plan']);change(plan);f['plan_path'].write_bytes(m.encode(plan))
            with self.subTest(index=index),patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),\
                    patch.object(m,'inputs',return_value=f['paths']),patch.object(m.core,'ACTUAL_READY',True):
                value=m.preflight(*self.args(f),root=f['root'])
            self.assertEqual(value['failure'],'plan');self.assertFalse(value['checks']['ordinary'])
        self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_snapshot_missing_source_and_nonvendor_CR_stop_before_factory(self):
        f=self.fixture();path=f['root']/'present.py';path.write_bytes(b'pass\n')
        with patch.object(m,'SOURCES',('present.py','missing.py')),\
                patch.object(m,'inputs',side_effect=AssertionError('must not inspect artifacts')):
            value=m.preflight(*self.args(f),root=f['root'])
        self.assertEqual(value['failure'],'inputs');self.assertFalse(value['checks']['sources'])
        with patch.object(m,'SOURCES',('present.py',)):
            _,hashes,digest=m.snapshot(f['root'])
            self.assertEqual(digest,m.sha(m.encode(hashes)))
            path.write_bytes(b'pass\r\n')
            with self.assertRaisesRegex(ValueError,'source_lf'):m.snapshot(f['root'])
        self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_hidden_worker_source_ready_gate_precedes_backend(self):
        f=self.fixture();config=self.config(f)
        stage=f['root']/m.core.stage_name(config['run']);stage.mkdir()
        path=stage/'worker-config.json';path.write_bytes(m.encode(config))
        with patch.object(m,'snapshot',return_value=(f['files'],f['hashes'],f['source'])),\
                patch.object(m.core,'ACTUAL_READY',False):
            with self.assertRaisesRegex(ValueError,'source_ready'):m.worker(path,root=stage)
        self.inner_factory.assert_not_called();self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_forged_complete_public_cannot_borrow_worker_outer_or_cleanup(self):
        with patch.object(m,'validate_observation',side_effect=self.observation_adapter):
            good=self.complete_public();m.validate_public(good)
            for kind in ('worker','outer','cleanup','absent_observation','control'):
                value=copy.deepcopy(good)
                if kind=='worker':value['checks']['worker_bound']=False
                elif kind=='outer':value['outer_launch_report_sha256']=None
                elif kind=='cleanup':value['observation'][m.core.CLEAN_KEYS[-1]]=False
                elif kind=='absent_observation':value['observation']=None
                else:value['ordinary_controls']['before']=False
                with self.subTest(kind=kind),self.assertRaises(ValueError):m.validate_public(value)
        unknown=m.blank('runtime');unknown['tree_retained']=True
        with self.assertRaisesRegex(ValueError,'unknown_cleanup'):m.validate_public(unknown)
        unknown['recovery_required']=True;m.validate_public(unknown)

    def test_preflight_cannot_relabel_runtime_facts(self):
        value=m.blank('preflight');value['checks']['guard']=True
        value['outer_launch_report_sha256']='a'*64
        with self.assertRaisesRegex(ValueError,'readonly_preflight'):m.validate_public(value)
        for key in m.core.FALSE_CLAIMS:
            value=m.blank('preflight');value[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(value)

    def test_worker_binding_uses_physical_outer_bytes_and_exact_held_envelope(self):
        f=self.fixture();parent={'inert_parent':True};config={'inert_config':True}
        # The outer safe-identity function is itself an explicit adapter here;
        # no synthetic dictionary is presented as a production ordinary token.
        launch=dict(started=True,resumed=True,child_pid=77,child_identity={'inert_safe':True},
            native_identity_verified_before_resume=True,cleanup=dict(process_exit_confirmed=True))
        raw=m.encode(launch);path=f['root']/'outer-launch-report.json';path.write_bytes(raw)
        observation=self.observation()
        report=dict(schema_version=1,stage='curl-a4-loader-worker',config=config,worker_pid=77,
            worker_identity=parent,result={'inert_observation':observation})
        result=m.blank('runtime');result['outer_launch_report_sha256']=m.sha(raw)
        result['checks'].update(guard=True,worker_exit=True,outer_cleanup=True)
        with patch.object(m.launcher,'safe_identity',return_value={'inert_safe':True}),\
                patch.object(m.core,'validate_result',return_value=report['result'],create=True),\
                patch.object(m.core,'project',return_value=observation,create=True),\
                patch.object(m.core,'ordinary_controls',return_value=dict(before=True,after=True),create=True),\
                patch.object(m,'validate_observation',side_effect=self.observation_adapter):
            m.bind_report(report,config,parent,launch,result,root=f['root'])
            self.assertTrue(result['checks']['worker_bound']);self.assertTrue(result['checks']['mechanism'])
            self.assertFalse(result['recovery_required'])
            path.write_bytes(b'{}')
            with self.assertRaisesRegex(ValueError,'outer_physical'):
                m.bind_report(report,config,parent,launch,result,root=f['root'])
            path.write_bytes(raw);bad=copy.deepcopy(report);bad['worker_pid']=78
            with self.assertRaisesRegex(ValueError,'worker_binding'):
                m.bind_report(bad,config,parent,launch,result,root=f['root'])
        self.inner_factory.assert_not_called();self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_final_reports_over_512KiB_persist_real_256_row_review_as_inert_payload(self):
        # Reuse the source-only byte fixture, then call the real pure decoder.
        # This is a file-capacity test, never an actual worker qualification.
        spec=importlib.util.spec_from_file_location('a4_full_trace_file_fixture',
            Path(__file__).with_name('test_windows_identity_lpac_curl_a4_binary_reader.py'))
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        rows=fixture.bootstrap_fixture()
        while len(rows)<256:
            slot=len(rows);rows.append(fixture.row_fixture(111,slot,110200+slot*4,value=0,sdk=False))
        trace=fixture.trace_fixture(rows)
        review=m.core.trace_reader.review(trace,expected_config2048=fixture.config_fixture(),
                                          schema_metadata=m.core.trace_reader.SCHEMA_METADATA)
        self.assertEqual(review['row_count'],256)
        raw=m.encode(dict(schema_version=1,stage='inert-final-report-capacity-fixture',
            returns=[dict(data=dict(review=review))],trace_review=dict(data=dict(review=review)),
            unrelated_inert_payload='x'*300000))
        self.assertGreater(len(raw),512*1024);self.assertLessEqual(len(raw),m.MAX_REPORT)
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        with patch.object(m.base,'durable_private',side_effect=AssertionError('shared512K writer must not be used')):
            for name in ('worker-result-forensic.json','worker-report.json'):
                with self.subTest(name=name):
                    m.durable_worker_report(root,name,raw)
                    self.assertEqual((root/name).read_bytes(),raw)
                    self.assertEqual(m.decode((root/name).read_bytes())['trace_review']['data']['review']['row_count'],256)
        self.inner_factory.assert_not_called();self.outer_factory.assert_not_called();self.launch.assert_not_called()

    def test_final_report_bound_exclusive_names_and_physical_readback(self):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve()
        for name in ('other.json','worker-report.json/other','../worker-report.json'):
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'a4_worker_report_bound'):
                m.durable_worker_report(root,name,b'{}')
        with self.assertRaisesRegex(ValueError,'a4_worker_report_bound'):
            m.durable_worker_report(root,'worker-report.json',bytes(m.MAX_REPORT+1))
        self.assertFalse((root/'worker-report.json').exists())
        raw=bytes(m.MAX_REPORT);m.durable_worker_report(root,'worker-report.json',raw)
        self.assertEqual((root/'worker-report.json').read_bytes(),raw)
        with self.assertRaises(FileExistsError):m.durable_worker_report(root,'worker-report.json',b'{}')
        self.assertEqual((root/'worker-report.json').read_bytes(),raw)
        bounded=m.local.bounded
        def damaged(path,limit):
            value=bounded(path,limit)
            return value[:-1]+b'!' if Path(path).name=='worker-result-forensic.json' else value
        with patch.object(m.local,'bounded',side_effect=damaged):
            with self.assertRaisesRegex(ValueError,'a4_worker_report_readback'):
                m.durable_worker_report(root,'worker-result-forensic.json',b'{}\n')
        self.assertEqual((root/'worker-result-forensic.json').read_bytes(),b'{}\n')


if __name__=='__main__':unittest.main()
