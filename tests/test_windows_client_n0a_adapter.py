import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
adapter=load('n0a_adapter_tests',ROOT/'.github/windows_n0a_guest.py');engine=adapter.engine
fixture=load('n0a_adapter_fixture',ROOT/'tests/test_windows_client_n0a_control.py')
B=fixture.B

def event(pid=123,code=0,**changes):
    value=dict(event='mxc.ProcessExited',backend='processcontainer',identity='redacted',tier='base-container',pid=pid,exit_code=code)
    value.update(changes);return b'[1792560000] '+json.dumps(value,separators=(',',':')).encode()+b'\n'

def envelope():
    sys.path.insert(0,str(ROOT))
    from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
    result=engine.evaluate(fixture.cases(),B)
    return {'schema_version':1,'case_nonce':B.nonce,'actor_sha256':B.actor_sha256,
        'report':{'schema_version':1,'binding':{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256,
            'executor_sha256':MXC_G_EXECUTOR_SHA256,'build':26300,'ubr':9457},'result':result,
            'execution':{'phase':'completed','failed':False,'cleanup_confirmed':True},
            'receiver':{'socket_cleanup_confirmed':True,'endpoint_error':False,'receiver_counts':
                {'accepted':128,'ordinary_verified_frames':128,'contained_verified_frames':0,'rejected':128,'timed_out':128}}},
        'launcher':{'phase':'completed','failure':'none','python_exit_code':0,'process_exit_confirmed':True,'timed_out':False,'budget_exhausted':False}}

class AuditTests(unittest.TestCase):
    def test_exact_dedicated_event_signed_exit_pid_correlation(self):
        for code in (0,1,-1,-2147483648,2147483647):
            value=engine.audit_exit(event(code=code),123,321)
            self.assertEqual(value,{'pid_verified':True,'pid_binding':'executor_audit','child_exit_code':code})
    def test_missing_duplicate_malformed_wrong_scope_fail_closed(self):
        for data in (b'',event()+event(),event().replace(b'"pid":123',b'"pid":123,"pid":123'),
                     event().replace(b'[1792560000]',b'[x]'),event(pid=True),event(pid=0),event(pid=2**32),
                     event(code=2**31),event(code=True),event(identity='PRIVATE'),event(tier='appcontainer-dacl'),
                     event(extra='PRIVATE'),b'x'*(engine.MAX_AUDIT+1),event().replace(b'"event":',b'"event":null,"event":')):
            self.assertIsNone(engine.audit_exit(data,123,321),data[:80])
        escaped=event().replace(b'mxc.ProcessExited',b'mxc.\\u0050rocessExited')
        self.assertIsNone(engine.audit_exit(event()+escaped,123,321))
        self.assertIsNone(engine.audit_exit(b'prefix'+b'\xe2\x80\xa8'+event(),123,321))
        self.assertIsNone(engine.audit_exit(event(),123,123))
        self.assertIsNone(engine.audit_exit(event(),124,321))
        self.assertIsNone(engine.audit_exit(b'process created (PID: 123)\n',123,321))
    def test_nonzero_exit_correlation_retains_failure_not_denial(self):
        cases=fixture.cases();contained=cases['runner']['contained'];contained['child_exit_code']=-1
        self.assertEqual(engine.evaluate(cases,B)['status'],'inconclusive')
        contained['actor']['n0a']['attempts'][0]['connectSucceeded']=True
        self.assertEqual(engine.evaluate(cases,B)['status'],'connect_succeeded')
        contained['pid_verified']=False
        self.assertEqual(engine.evaluate(cases,B)['status'],'inconclusive')
    def test_arguments_reject_log_injection(self):
        for text in ('path\nprocess created','C:\rPRIVATE','KEY=VALUE\0'):
            with self.assertRaises(ValueError):engine.safe_argument(text)

class WireTests(unittest.TestCase):
    def test_host_independent_nonce_hash_build_binding_and_redaction(self):
        value=envelope();expected={'case_nonce':B.nonce,'actor_sha256':B.actor_sha256}
        public=engine.validate_host_n0a_envelope(value,expected)
        self.assertTrue(public['receipt_verified']);self.assertEqual(public['result']['status'],'observed_connect_denial')
        self.assertNotIn(B.nonce,json.dumps(public));self.assertNotIn('PRIVATE',json.dumps(public))
        for key in ('case_nonce','actor_sha256','executor_sha256','build','ubr'):
            changed=copy.deepcopy(value);changed['report']['binding'][key]='PRIVATE'
            with self.assertRaises(ValueError):engine.validate_host_n0a_envelope(changed,expected)
    def test_entire_optional_wire_worstcase_under4096(self):
        # Enumerate all semantically valid endpoint flags/count/status combinations;
        # retain longest row per status, then compose both endpoint statuses.
        value=envelope(); longest={}
        flags=('profile_verified','controls_verified','window_overlap_verified','connect_success_observed')
        for status,bits,count in itertools.product(('inconclusive','connect_succeeded','observed_connect_denial'),itertools.product((False,True),repeat=4),range(4)):
            row=dict(zip(flags,bits),status=status,explicit_denials=count)
            candidate=copy.deepcopy(value['report']['result'])
            candidate.update(status=status,endpoints={name:dict(row) for name in engine.ENDPOINTS})
            try: engine.closed_result(candidate)
            except ValueError: continue
            if status not in longest or len(json.dumps(row))>len(json.dumps(longest[status])):longest[status]=row
        self.assertEqual(set(longest),{'inconclusive','connect_succeeded','observed_connect_denial'})
        value['launcher'].update(phase=max(engine.LAUNCHER_PHASES,key=len),failure=max(engine.LAUNCHER_FAILURES,key=len),
             python_exit_code=-2147483648,process_exit_confirmed=False,timed_out=False,budget_exhausted=False)
        value['report']['execution'].update(phase=max(engine.EXECUTION_PHASES,key=len),failed=False,cleanup_confirmed=False)
        value['report']['receiver'].update(socket_cleanup_confirmed=False,endpoint_error=False)
        # Under total<=128, a 3-digit plus 2-digit role count is the widest legal pair.
        value['report']['receiver']['receiver_counts'].update(ordinary_verified_frames=100,contained_verified_frames=28)
        maximum=0
        for left,right in itertools.product(longest,longest):
            result=value['report']['result'];result['endpoints']={'guest':longest[left],'runner':longest[right]}
            result['status']='connect_succeeded' if 'connect_succeeded' in (left,right) else ('observed_connect_denial' if left==right=='observed_connect_denial' else 'inconclusive')
            for present,exit_code,exit_seen in itertools.product((False,True),(None,-2147483648,2147483647),(None,False,True)):
                candidate=copy.deepcopy(value)
                if not present:candidate['report']=None
                candidate['launcher'].update(python_exit_code=exit_code,process_exit_confirmed=exit_seen)
                body=json.dumps(candidate,ensure_ascii=True)
                maximum=max(maximum,len(body));self.assertLessEqual(len(body),4096)
                engine.validate_host_n0a_envelope(json.loads(body),{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256})
        self.assertEqual(maximum, 1680)
    def test_cleanup_launcher_failure_never_masks_attributed_connect_success(self):
        value=envelope();value['report']['result']['endpoints']['guest'].update(status='connect_succeeded',connect_success_observed=True)
        value['report']['result']['status']='connect_succeeded'
        value['report']['execution']['cleanup_confirmed']=False;value['launcher']['timed_out']=True
        public=engine.validate_host_n0a_envelope(value,{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256})
        self.assertEqual(public['result']['status'],'connect_succeeded')
    def test_unknown_or_inconsistent_receiver_evidence_is_inconclusive(self):
        for counts in (None,{'accepted':4,'ordinary_verified_frames':4,'contained_verified_frames':0,'rejected':0,'timed_out':0},
                       {'accepted':6,'ordinary_verified_frames':5,'contained_verified_frames':1,'rejected':0,'timed_out':0}):
            value=envelope();value['report']['receiver']['receiver_counts']=counts
            public=engine.validate_host_n0a_envelope(value,{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256})
            self.assertEqual(public['result']['status'],'inconclusive')

    def test_malformed_receiver_types_unknowns_and_false_denial(self):
        for change in ('bool_count','extra','contradictory'):
            value=envelope()
            if change=='bool_count':value['report']['receiver']['receiver_counts']['accepted']=True
            if change=='extra':value['report']['execution']['PRIVATE']='PRIVATE'
            if change=='contradictory':value['report']['result']['endpoints']['guest']['controls_verified']=False
            with self.assertRaises(ValueError):engine.validate_host_n0a_envelope(value,{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256})
        value=envelope();value['launcher']['failure']='work_budget_exhausted';value['report']=None
        public=engine.validate_host_n0a_envelope(value,{'case_nonce':B.nonce,'actor_sha256':B.actor_sha256})
        self.assertFalse(public['receipt_verified'])

class ManifestTests(unittest.TestCase):
    def make(self,root):
        actor=root/'actor.exe';actor.write_bytes(b'actor-fixture'*100)
        config={'actor_source_sha256':'1'*64,'identity_source_sha256':'2'*64,'actor_sha256':hashlib.sha256(actor.read_bytes()).hexdigest()}
        manifest={'schemaVersion':1,'sourceSha256':'1'*64,'identitySourceSha256':'2'*64,'executableSha256':config['actor_sha256'],
                  'targetArchitecture':'x64','staticCrt':True,'httpCompiled':False,'rawTcpCompiled':True,'compileOnly':True,
                  'testOnly':False,'actorRole':'n0a-tcp','builtAtUtc':'2026-10-21T00:00:00.000Z'}
        return actor,config,manifest
    def test_only_production_both_sources_pinned_and_no_fixture(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);actor,config,value=self.make(root);path=root/'manifest.json'
            for key,bad in ((None,None),('testOnly',True),('sourceSha256','3'*64),('identitySourceSha256','3'*64),
                            ('executableSha256','3'*64),('httpCompiled',True),('rawTcpCompiled',False),('schemaVersion',True)):
                candidate=dict(value)
                if key:candidate[key]=bad
                path.write_text(json.dumps(candidate));config['manifest_sha256']=hashlib.sha256(path.read_bytes()).hexdigest()
                if key:
                    with self.assertRaises(ValueError):adapter.verify_production(config,actor,path)
                else:self.assertEqual(adapter.verify_production(config,actor,path),value)
    def test_inactive_runtime_returns_null_without_native_or_socket(self):
        with patch.object(adapter,'qpc_budget') as qpc,patch.object(engine.NonceEndpoint,'start') as start:
            self.assertIsNone(adapter.run('unused',123,1000))
        qpc.assert_not_called();start.assert_not_called()

class AdapterLifecycleTests(unittest.TestCase):
    def make(self,root):
        inputs=root/'inputs';inputs.mkdir();actor=inputs/'actor.exe';actor.write_bytes(b'a'*600)
        executor=inputs/'wxc-exec.exe';executor.write_bytes(b'g'*600)
        binding=engine.Binding(B.nonce,hashlib.sha256(actor.read_bytes()).hexdigest(),hashlib.sha256(executor.read_bytes()).hexdigest(),
                               B.agentic_sid,B.ports,1,False,False)
        with patch.object(adapter,'os',SimpleNamespace(name='nt')),patch.object(engine,'EXECUTION_ENABLED',True):
            return adapter.WindowsExecution(binding,actor,executor,['SYSTEMROOT=C:\\Windows','LOCALAPPDATA=C:\\Users\\Fixture\\AppData\\Local'],root,100,approved=True)
    def test_audit_is_fresh_sibling_outside_granted_directories(self):
        with tempfile.TemporaryDirectory() as temp:
            execution=self.make(Path(temp));case=execution.endpoint_case('guest',B.ports[0])
            policy=json.loads(case['policy'].read_text())
            audit=case['directory']/'audit.private'
            for grant in policy['filesystem']['readonlyPaths']+policy['filesystem']['readwritePaths']:
                self.assertNotIn(Path(grant),audit.parents)
            self.assertEqual(policy['network'],{'egress':{'default':'deny'},'ingress':{'default':'deny','hostLoopback':'deny'}})
    def test_close_kills_waits_only_owned_handle_and_closes_files(self):
        with tempfile.TemporaryDirectory() as temp:
            execution=self.make(Path(temp));process=Mock();process.poll.side_effect=[None,0];process._handle=Mock()
            owned={'process':process,'out':Mock(),'err':Mock()}
            with patch.object(adapter.time,'monotonic',return_value=99):self.assertTrue(execution.close_owned(owned))
            process.kill.assert_called_once();process.wait.assert_called_once_with(timeout=1)
            process._handle.Close.assert_called_once();owned['out'].close.assert_called_once()
    def test_unconfirmed_exit_or_fileclose_never_claim_cleanup(self):
        with tempfile.TemporaryDirectory() as temp:
            execution=self.make(Path(temp));process=Mock();process.poll.return_value=None
            process.wait.side_effect=TimeoutError('PRIVATE');process._handle=Mock()
            stream=Mock();stream.close.side_effect=OSError('PRIVATE')
            self.assertFalse(execution.close_owned({'process':process,'out':stream,'err':None}))
            process._handle.Close.assert_not_called()

    def test_wait_error_still_reads_existing_native_report_and_audit(self):
        with tempfile.TemporaryDirectory() as temp:
            execution=self.make(Path(temp));case=execution.endpoint_case('guest',B.ports[0])
            case['probe']=fixture.case('guest')['contained']['probe'];case['probe_exit']=0
            report=case['profile']/'actor.json';actor=fixture.case('guest')['contained']['actor']
            actor['pid']=123;actor['n0a']['attempts'][0]['connectSucceeded']=True
            report.write_text(json.dumps(actor));audit=case['directory']/'audit.private';audit.write_bytes(event())
            state=audit.stat();process=Mock(pid=321,returncode=None);process.poll.return_value=None
            process.wait.side_effect=OSError('PRIVATE');process._handle=Mock()
            owned={'process':process,'role':'contained','pattern':'single','endpoint':'guest','report':report,
                   'audit':audit,'audit_identity':(state.st_dev,state.st_ino),'timed_out':False,'out':None,'err':None}
            with patch.object(adapter.time,'monotonic',return_value=1):result=execution.wait(owned,5)
            self.assertTrue(result['pid_verified']);self.assertTrue(result['harness_error'])
            outcome=engine.endpoint_result({'contained':result,'cleanup_confirmed':False,'driver_error':True},execution.binding,'guest')
            self.assertEqual(outcome['status'],'connect_succeeded');process._handle.Close.assert_not_called()

class QpcTests(unittest.TestCase):
    def test_sampling_delay_does_not_extend_deadline(self):
        kernel=Mock()
        def frequency(pointer):pointer._obj.value=100;return 1
        def counter(pointer):pointer._obj.value=1000;return 1
        kernel.QueryPerformanceFrequency.side_effect=frequency;kernel.QueryPerformanceCounter.side_effect=counter
        with patch.object(adapter,'os',SimpleNamespace(name='nt')),patch.object(adapter.ctypes,'WinDLL',return_value=kernel,create=True), \
             patch.object(adapter.time,'monotonic',side_effect=[10,99]) as clock:
            self.assertEqual(adapter.qpc_budget(1500,100),15)
        self.assertEqual(clock.call_count,1)

if __name__=='__main__':unittest.main()
