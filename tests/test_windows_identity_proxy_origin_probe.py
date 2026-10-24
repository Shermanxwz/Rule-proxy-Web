"""Pure B ownership/report models; no profile, process, Winsock or network."""
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
spec=importlib.util.spec_from_file_location('origin_probe_test',ROOT/'.github/windows_identity_proxy_origin_probe.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec=importlib.util.spec_from_file_location('origin_legacy_fake',ROOT/'tests/test_windows_identity_proxy_pipe_probe.py')
legacy=importlib.util.module_from_spec(spec);spec.loader.exec_module(legacy)


def identity_report(run,pid,sid,ac=None):
    return dict(schemaVersion=1,mode='actor',nonce=run,pid=pid,tokenUserSid=sid,
        tokenIsAppContainer=ac is not None,tokenAppContainerSid=ac,tokenElevated=False,isProcessInJob=True,
        tokenCapabilities=[],queriesSucceeded=True,errors=[])


def relay(port,case):
    request,response=m.payloads(case,port)
    return dict(port=port,**{k:True for k in m.RELAY_BOOLS},local_port=55000,peer_port=port,
        request_bytes=len(request),response_bytes=len(response),socket_close='confirmed',failure=None,wsa_error=None)


def fixture(command,pid,start):
    _,_,run,case,report,ready,frequency,deadline,sid=command;request,response=m.payloads(case,54321)
    return dict(schema_version=1,stage='bridge-origin-fixture',run_id=run,case_id=case,pid=pid,
        identity=identity_report(run,pid,sid),qpc=[int(frequency),start+1,int(deadline),start+2],
        socket=dict(**{k:True for k in m.FIXTURE_BOOLS},port=54321,peer_port=55000,
            request_bytes=len(request),response_bytes=len(response),listener_close='confirmed',connection_close='confirmed'),
        ready_published=True,failure=None,wsa_error=None,network_scope='ordinary-loopback-origin',
        network_tested=True,proxy_tested=False,product_acceptance=False)


class FakeOriginAPI(legacy.FakeACAPI):
    def open_stdio_file(self,path,*,read=False):
        handle=self.handle();self.log.append(('origin_stdio',handle,read));return handle
    def create_suspended(self,info,command,work,stdio,token):
        self.log.append(('origin_create',tuple(command)))
        if self.fault=='origin_create_unknown':raise OSError('private')
        self.created+=1;info.hProcess=self.handle();info.hThread=self.handle();info.dwProcessId=info.hProcess+1000
        self.processes[info.hProcess]={'info':info,'command':command,'exited':False,'code':None,'resumed':False,'job':None}
    def resume(self,thread):
        self.log.append(('resume',thread));row=next(x for x in self.processes.values() if x['info'].hThread==thread)
        row['resumed']=True;command=row['command']
        if command[1]=='origin-fixture':
            ready=dict(schema_version=1,stage='bridge-origin-ready',run_id=command[2],case_id=command[3],
                pid=row['info'].dwProcessId,port=54321,qpc_frequency=int(command[6]),deadline_qpc=int(command[7]),loopback_ipv4=True)
            if self.fault!='ready_missing':Path(command[5]).write_bytes(m.encode(ready))
        peers=[self.processes[x] for x in self.jobs[row['job']]]
        if len(peers)!=3 or not all(x['resumed'] for x in peers):return
        for item in peers:
            cmd=item['command'];item.update(exited=True,code=0)
            if cmd[1]=='origin-fixture':
                value=fixture(cmd,item['info'].dwProcessId,1000)
                if self.fault=='tuple_mismatch':value['socket']['peer_port']=55001
                if self.fault!='origin_report_missing':Path(cmd[4]).write_bytes(m.encode(value))
                if self.fault in ('origin_delayed_exit','origin_exit_timeout'):item['exited']=False
                continue
            ipc=legacy.native_report(cmd[:13],item['info'].dwProcessId)
            if cmd[1]=='pipe-front':ipc['identity'].update(tokenIsAppContainer=True,tokenAppContainerSid=self.SID)
            value=dict(schema_version=1,stage='bridge-origin-pipe-test',role=cmd[1],run_id=cmd[2],case_id=cmd[3],
                pid=item['info'].dwProcessId,ipc_mechanics=ipc,origin=None if cmd[1]=='pipe-front' else relay(int(cmd[13]),cmd[3]),
                http_boundary=m.BOUNDARY,network_tested=cmd[1]=='pipe-relay',proxy_tested=False,product_acceptance=False)
            if not (self.fault=='relay_report_missing' and cmd[1]=='pipe-relay'):Path(cmd[4]).write_bytes(m.encode(value))
    def close(self,handle):
        if (self.fault=='origin_close' and handle in self.processes
                and self.processes[handle]['command'][1]=='origin-fixture'):
            self.log.append(('close',handle));self.closes[handle]=self.closes.get(handle,0)+1;raise OSError('private')
        return super().close(handle)
    def wait(self,process,ms):
        if (self.fault=='origin_delayed_exit' and ms>0 and self.processes[process]['command'][1]=='origin-fixture'):
            self.log.append(('origin_normal_exit_wait',ms));self.now+=50;self.processes[process]['exited']=True
        if (self.fault=='origin_wait_unknown' and self.processes[process]['command'][1]=='origin-fixture'):
            raise OSError('private')
        return super().wait(process,ms)


def exercise(fault=None):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory).resolve();bridge=root/'bridge';bridge.mkdir();actor=bridge/m.ACTOR;actor.write_bytes(b'MZ'+b'x'*510)
        digest=hashlib.sha256(actor.read_bytes()).hexdigest();api=FakeOriginAPI(fault)
        config=dict(pair=dict(enabled=True,run_nonce='a'*32,case_nonce='c'*32,actor_sha256=digest,manifest_sha256='b'*64),
            deadline_qpc=121000,qpc_frequency=1000)
        with mock.patch.object(m,'verify_artifact',side_effect=lambda *args,**kwargs:(actor,digest)):
            value=m.run_controller(config,root=root,api=api)
        expected={k:config['pair'][k] for k in ('run_nonce','case_nonce','actor_sha256','manifest_sha256')}
        expected.update(deadline_qpc=121000,qpc_frequency=1000,controller_pid=value['controller_pid'],
            controller_sid=legacy.ordinary_identity()['sid'],controller_session=1)
        return value,expected,api,m.validate_private(value,expected)


class ControllerTests(unittest.TestCase):
    def test_three_held_processes_one_job_independent_origin_report(self):
        value,expected,api,result=exercise()
        self.assertTrue(result['origin_roundtrip_verified']);self.assertTrue(result['network_tested'])
        self.assertTrue(result['mechanics']['pair']['expected_outcome']);self.assertEqual(value['mechanics_projection']['pair']['created'],3)
        self.assertEqual(api.created,3);self.assertTrue(all(n==1 for n in api.closes.values()))
        fixture_create=next(i for i,x in enumerate(api.log) if x[0]=='origin_create')
        first_resume=next(i for i,x in enumerate(api.log) if x[0]=='resume')
        self.assertLess(fixture_create,first_resume)
        self.assertTrue(any(x[0]=='identity' and x[1] is not None for x in api.log[:first_resume]))
        self.assertEqual(value['origin_fixture']['deadline'],91000)
        self.assertEqual(value['mechanics_projection']['deadline_qpc'],121000)
        self.assertEqual(result['mechanics']['pair']['reports_bound'],3)
        self.assertEqual(value['mechanics_projection_report_kind'],'canonical-ipc-view-not-raw-native')

    def test_original_a_entry_rejects_b_native_report(self):
        value,expected,_,_=exercise();native=m.read_record(value['pair_native'][0],8192)
        row=value['mechanics_projection']['children'][0];q=value['mechanics_projection']['pair_qpc']
        with self.assertRaises(ValueError):
            m.a.validate_ac_native(native,role='pipe-front',run_id=expected['run_nonce'],case_id=expected['case_nonce'],
                pid=row['pid'],identity=row['identity'],frequency=1000,start=q[0],end=q[1],expected_ac_sid=FakeOriginAPI.SID)

    def test_raw_hash_is_not_canonical_projection_hash(self):
        value,_,_,_=exercise()
        for i in range(2):
            raw=value['pair_native'][i];row=value['mechanics_projection']['children'][i]
            self.assertNotEqual(raw['sha256'],row['native_sha256'])
            self.assertEqual(row['native_sha256'],m.sha(m.encode(row['native'])))
            self.assertEqual(row['native_bytes'],len(m.encode(row['native'])))

    def test_missing_origin_report_does_not_erase_real_pair_or_connect_observations(self):
        value,_,_,result=exercise('origin_report_missing')
        self.assertFalse(result['origin_roundtrip_verified']);self.assertTrue(result['network_tested'])
        self.assertEqual(result['mechanics']['pair']['observations'],[177,78])
        self.assertFalse(result['origin']['report_bound'])

    def test_missing_relay_report_cannot_erase_independent_accepted_observation(self):
        _,_,_,result=exercise('relay_report_missing')
        self.assertFalse(result['origin_roundtrip_verified']);self.assertTrue(result['network_tested'])
        self.assertTrue(result['origin']['accepted_observed']);self.assertTrue(result['origin']['request_exact'])
        self.assertFalse(result['origin']['connect_attempted_observed'])

    def test_third_process_uncertainty_blocks_profile_removal_and_closes_once(self):
        for fault in ('origin_create_unknown','origin_close','origin_wait_unknown'):
            with self.subTest(fault=fault):
                value,_,api,result=exercise(fault)
                self.assertFalse(result['origin_roundtrip_verified'])
                self.assertFalse(value['mechanics_projection']['pair']['cleanup_confirmed'])
                self.assertFalse(any(x[0] in ('remove_acl','profile_delete') for x in api.log))
                self.assertTrue(all(n==1 for n in api.closes.values()))

    def test_extra_unknown_spawn_cannot_be_hidden_by_two_process_cleanup_projection(self):
        value,expected,_,_=exercise('origin_create_unknown')
        self.assertTrue(value['origin_fixture']['attempted']);self.assertIsNone(value['origin_fixture']['pid'])
        mechanics=value['mechanics_projection']
        mechanics['cleanup']={k:True for k in mechanics['cleanup']}
        mechanics['pair'].update(cleanup_confirmed=True,job_empty=True)
        # The legacy projection only knows its two pair children. B separately
        # recomputes the third held owner before accepting profile deletion.
        m.a.validate_private_report(mechanics,expected)
        with self.assertRaises(ValueError):m.validate_private(value,expected)

    def test_tuple_binding_is_independent_of_green_ipc(self):
        _,_,_,result=exercise('tuple_mismatch')
        self.assertTrue(result['mechanics']['pair']['expected_outcome'])
        self.assertFalse(result['origin']['peer_tuple_bound']);self.assertFalse(result['origin_roundtrip_verified'])

    def test_ready_delay_consumes_original_clock_and_never_resumes_pair(self):
        value,_,api,result=exercise('ready_missing')
        self.assertFalse(result['origin_roundtrip_verified']);self.assertEqual(value['mechanics_projection']['pair']['resumed'],0)
        self.assertLessEqual(api.now,91000);self.assertTrue(all(n==1 for n in api.closes.values()))

    def test_origin_normal_exit_wait_uses_same_pair_end_before_cleanup(self):
        value,_,api,result=exercise('origin_delayed_exit')
        self.assertTrue(result['origin_roundtrip_verified'])
        self.assertTrue(any(x[0]=='origin_normal_exit_wait' for x in api.log))
        self.assertFalse(any(x[0]=='stop_job' for x in api.log))
        self.assertEqual(value['mechanics_projection']['pair_qpc'],[1000,11000])

    def test_origin_exit_timeout_is_cleanup_fallback_and_inconclusive(self):
        value,_,api,result=exercise('origin_exit_timeout')
        self.assertFalse(result['origin_roundtrip_verified'])
        self.assertFalse(value['mechanics_projection']['pair']['expected_outcome'])
        self.assertTrue(any(x[0]=='stop_job' for x in api.log))


class SchemaTests(unittest.TestCase):
    def test_relay_closed_schema_exact_byte_counts_and_eof(self):
        good=relay(54321,'c'*32);m.validate_relay(good,54321,'c'*32);self.assertTrue(m.relay_passed(good,'c'*32))
        for mutate in (lambda v:v.update(port=54322),lambda v:v.update(connect_completed=1),
                       lambda v:v.update(raw_peer='private'),lambda v:v.update(response_bytes=9999)):
            value=copy.deepcopy(good);mutate(value)
            with self.assertRaises(ValueError):m.validate_relay(value,54321,'c'*32)
        value=copy.deepcopy(good);value['response_eof']=False
        m.validate_relay(value,54321,'c'*32);self.assertFalse(m.relay_passed(value,'c'*32))

    def test_native_raw_duplicate_or_mutated_binding_is_rejected(self):
        value,expected,_,_=exercise()
        for mutate in (lambda v:v.update(controller_pid=999),lambda v:v['origin_fixture'].update(pid=999),
                       lambda v:v['pair_native'][1].update(sha256='f'*64),lambda v:v.update(raw_sid='private'),
                       lambda v:v['origin_fixture']['ready'].update(raw='{"x":1,"x":2}')):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_private(changed,expected)

    def test_overlength_failure_reports_keep_connect_and_accepted_sticky(self):
        original,expected,_,_=exercise()
        for where in ('relay','fixture'):
            value=copy.deepcopy(original)
            if where=='relay':
                native=m.read_record(value['pair_native'][1],8192)
                native['origin'].update(response_bytes=257,response_exact=False,failure='response',wsa_error=None)
                value['pair_native'][1]=m.raw_record(m.encode(native))
            else:
                native=m.read_record(value['origin_fixture']['report'],8192)
                native['socket'].update(request_bytes=257,request_exact=False)
                native['failure']='request';value['origin_fixture']['report']=m.raw_record(m.encode(native))
            result=m.validate_private(value,expected)
            self.assertFalse(result['origin_roundtrip_verified']);self.assertTrue(result['network_tested'])
            self.assertTrue(result['origin']['connect_attempted_observed']);self.assertTrue(result['origin']['accepted_observed'])

    def test_b_recovery_scope_cannot_be_substituted_by_a_no_network_plan(self):
        plan=dict(schema_version=1,scope=m.SCOPE,device_sha256='1'*64,actor_sha256='2'*64,manifest_sha256='3'*64,
            source_sha256='4'*64,recovery_reference='owned loopback origin, fresh profile, retained ownership journal',residue_review_acknowledged=True)
        pins=dict(device='1'*64,actor_hash='2'*64,manifest_hash='3'*64,source_hash='4'*64)
        m.valid_plan(plan,**pins)
        with self.assertRaises(ValueError):m.valid_plan(dict(plan,scope='one-local-zero-cap-pair-no-network-v1'),**pins)

    def test_default_cli_and_missing_approval_do_not_construct_native(self):
        value=m.blank('preflight');value['failure']='inputs'
        with mock.patch.object(m,'preflight',return_value=value),mock.patch.object(m,'run_local') as run,mock.patch.object(m.sys,'stdout'):
            self.assertEqual(m.main([]),1)
        run.assert_not_called()
        with mock.patch.object(m.local,'LocalNativeAPI') as api:
            result=m.run_local(None,None,None,None,None,None)
        api.assert_not_called();self.assertFalse(result['local_origin_qualified'])

    def test_private_identity_never_enters_closed_public(self):
        value=m.blank('runtime');value['failure']='report';m.validate_public(value)
        for mutate in (lambda v:v.update(raw_sid='private'),lambda v:v.update(product_acceptance=True),
                       lambda v:v.update(selected_application_tested=True),lambda v:v.update(origin_roundtrip_verified=True)):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_public(changed)

    def test_readonly_preflight_rejects_runtime_facts_even_when_not_qualified(self):
        value=m.blank('preflight');value['failure']='inputs';m.validate_public(value)
        for mutate in (lambda v:v['facts'].update(current_ordinary_verified=True),lambda v:v.update(network_tested=True),
                       lambda v:v['origin'].update(ready_bound=True),lambda v:v.update(run_nonce_sha256='a'*64)):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_public(changed)


class FakeGuardAPI:
    def __init__(self):self.now=1000;self.atomic_job_requested=False;self.created=[]
    def qpc_frequency(self):return 1000
    def qpc(self):return self.now
    def current_token(self):return 41
    def identity(self,token):return legacy.ordinary_identity()
    def compartment(self):return 1
    def close(self,handle):pass
    def windows_x64(self):return True
    def device_sha256(self):return '1'*64
    def private_directory(self,path,sid):self.created.append(path);path.mkdir()


class GuardTests(unittest.TestCase):
    def exercise(self,*,exit_code=0,unknown_exit=False,missing=False):
        private,expected,_,_=exercise();api=FakeGuardAPI();calls={}
        files={name:b'# fixed fixture\n' for name in m.SOURCES};hashes={name:m.sha(raw) for name,raw in files.items()}
        source=m.sha(m.encode(hashes));actor_hash=expected['actor_sha256']
        plan=dict(schema_version=1,scope=m.SCOPE,device_sha256='1'*64,actor_sha256=actor_hash,manifest_sha256='b'*64,
            source_sha256=source,recovery_reference='fresh profile and owned loopback origin only',residue_review_acknowledged=True)
        ready=m.blank('preflight');ready.update(status='ready',checks={k:True for k in ready['checks']},source_sha256=source,
            actor_sha256=actor_hash,manifest_sha256='b'*64,recovery_plan_sha256=m.sha(m.encode(plan)),device_bound=True)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve();actor=root/m.ACTOR;actor.write_bytes(b'MZ'+b'x'*510)
            manifest=root/m.MANIFEST;manifest.write_bytes(b'{}\n');recovery=root/'plan.json';recovery.write_bytes(m.encode(plan))
            def launch(unused_api,command,work,parent,again,**kwargs):
                calls.update(command=command,kwargs=kwargs);api.atomic_job_requested=True
                config=m.decode((work.parent/'origin-config.json').read_bytes());calls['config']=config
                if not missing:(work.parent/'private-origin.json').write_bytes(m.encode(private))
                return dict(started=True,resumed=True,native_identity_verified_before_resume=True,child_pid=private['controller_pid'],
                    exit_code=exit_code,timed_out=False,cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,
                        process_exit_confirmed=not unknown_exit,close_uncertain=False,errors=[]))
            ids=iter(('a'*32,'c'*32))
            with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')),mock.patch.object(m,'preflight',return_value=ready), \
                 mock.patch.object(m,'admitted_inputs',return_value=(files,hashes,source,actor,manifest,root)), \
                 mock.patch.object(m,'verify_artifact',side_effect=lambda path,*args,**kwargs:(path,actor_hash)), \
                 mock.patch.object(m.launcher,'launch_owned',side_effect=launch):
                value=m.run_local(actor,manifest,actor_hash,'b'*64,root,recovery,approved=True,api=api,root=root,ids=lambda n:next(ids))
        return value,calls

    def test_guard_binds_controller_held_pid_and_same_original_qpc(self):
        value,calls=self.exercise();self.assertTrue(value['local_origin_qualified']);self.assertEqual(value['status'],'passed')
        self.assertEqual(calls['config']['deadline_qpc'],121000)
        self.assertEqual(calls['kwargs']['work_cutoff'],118000);self.assertEqual(calls['kwargs']['cleanup_cutoff'],121000)
        self.assertEqual(calls['command'][1:4],['-I','-S','-B'])
        self.assertFalse(value['cleanup']['recovery_required']);self.assertTrue(value['network_tested'])
        text=m.encode(value).decode('ascii')
        for secret in ('a'*32,'c'*32,legacy.ordinary_identity()['sid'],'controller_pid','127.0.0.1:'):
            self.assertNotIn(secret,text)

    def test_known_clean_late_controller_failure_keeps_positive_without_resource_recovery(self):
        value,_=self.exercise(exit_code=1)
        self.assertFalse(value['local_origin_qualified']);self.assertTrue(value['origin_roundtrip_verified'])
        self.assertEqual(value['pair']['observations'],[177,78]);self.assertTrue(value['cleanup']['outer_cleanup_verified'])
        self.assertFalse(value['cleanup']['recovery_required'])

    def test_unknown_exit_or_report_requires_recovery_and_cannot_publish_qualified(self):
        for options in ({'unknown_exit':True},{'missing':True}):
            value,_=self.exercise(**options)
            self.assertFalse(value['local_origin_qualified']);self.assertTrue(value['cleanup']['recovery_required'])

    def test_internal_controller_in_regular_checkout_rejected_before_native(self):
        config=dict(schema_version=1,stage='proxy-origin-owned-input',pair=dict(enabled=True,run_nonce='a'*32,case_nonce='c'*32,
            actor_sha256='1'*64,manifest_sha256='2'*64),deadline_qpc=121000,qpc_frequency=1000,source_hashes={},
            source_sha256='3'*64,device_sha256='4'*64,recovery_plan_sha256='5'*64,guard_job_name='Local\\RuleProxy.LocalGuard.'+'a'*32)
        with mock.patch.object(m.launcher,'checked_path',return_value=m.ROOT/'origin-config.json'), \
             mock.patch.object(m.local,'bounded',return_value=m.encode(config)),mock.patch.object(m,'OriginAPI') as native:
            with self.assertRaises(ValueError):m.owned_controller(m.ROOT/'origin-config.json')
        native.assert_not_called()


if __name__=='__main__':unittest.main()
