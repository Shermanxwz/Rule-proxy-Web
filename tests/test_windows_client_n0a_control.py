import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('n0a_control_test',ROOT/'.github/windows_n0a_control.py')
n=importlib.util.module_from_spec(spec);sys.modules[spec.name]=n;spec.loader.exec_module(n)
B=n.Binding('a'*32,'b'*64,'c'*64,'S-1-15-3-1024-1-2-3-4-5-6-7-8',(19001,19002),1,False,False)

def row(index,start,okay=True):
    return dict(index=index,attempted=True,bindSucceeded=True,localPort=30000+index,
                localIpv4=0,connectStartQpc=start,connectEndQpc=start+1,
                connectSucceeded=okay,nonceMatched=okay,exchangeEndQpc=start+2,
                win32Error=0 if okay else 10013,failure='none' if okay else 'connect',closed=True)

def report(endpoint,role,pattern,starts):
    contained=role=='contained';rows=[row(i,v,not contained) for i,v in enumerate(starts)]
    actor=dict(schemaVersion=1,mode='actor-n0a',nonce=B.nonce,pid=42,queriesSucceeded=True,errors=[],
               tokenElevated=False,tokenIsAppContainer=contained,isProcessInJob=True,
               tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7' if contained else None,
               tokenCapabilities=[{'sid':B.agentic_sid,'attributes':4}] if contained else [],
               tokenUserSid='PRIVATE_USER_SENTINEL',n0a=dict(version=1,port=B.ports[tuple(n.ENDPOINTS).index(endpoint)],
               startupError=0,endpoint=endpoint,role=role,pattern=pattern,profileMatched=True,
               windowStartQpc=starts[0],windowEndQpc=starts[-1]+2,qpcFrequency=1000,attempts=rows))
    return dict(nonce=B.nonce,actor_sha256=B.actor_sha256,executor_sha256=B.executor_sha256,build=26300,ubr=9457,
                actor=actor,pid_verified=True,pid_binding='executor_audit' if contained else 'ordinary_handle',child_exit_code=0,exit_code=0,timed_out=False,harness_error=False,actual_tiers=['base-container'],
                probe_exit_code=0,probe={'tier':'base-container','needsDaclAugmentation':False,
                'probes':{'baseContainerApiPresent':True},'error':None})

def case(endpoint):
    return dict(cleanup_confirmed=True,driver_error=False,
                before=report(endpoint,'ordinary','single',[1000]),
                during=report(endpoint,'ordinary','sample',[1500,2200,3300]),
                contained=report(endpoint,'contained','single',[2000,2500,3000]),
                after=report(endpoint,'ordinary','single',[4000]))

def cases():return {endpoint:case(endpoint) for endpoint in n.ENDPOINTS}

class N0aEvaluatorTests(unittest.TestCase):
    def test_complete_controls_explicit_denial_not_isolation(self):
        value=n.evaluate(cases(),B)
        self.assertEqual(value['status'],'observed_connect_denial')
        for field in ('stage0_passed','packet_egress_tested','privacy_qualified','product_acceptance',
                      'psec_cleanup_independently_verified','continuous_token_identity_proven'):
            self.assertIs(value[field],False)
        self.assertNotIn('PRIVATE',json.dumps(value));self.assertNotIn(B.nonce,json.dumps(value))
        self.assertNotIn(B.agentic_sid,json.dumps(value))
    def test_connect_success_sticky_over_echo_exit_cleanup_and_bad_timing(self):
        for mutation in ('echo','exit','cleanup','timing','profile','other_row'):
            value=cases();target=value['runner'];actor=target['contained']['actor'];r=actor['n0a']['attempts'][0]
            r['connectSucceeded']=True # nonce remainsfalse: still FAIL.
            if mutation=='exit':target['contained']['exit_code']=4
            if mutation=='cleanup':target['cleanup_confirmed']=False
            if mutation=='timing':r['connectStartQpc']=True
            if mutation=='profile':actor['tokenElevated']=True
            if mutation=='other_row':actor['n0a']['attempts'][1]['failure']='PRIVATE'
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive' if mutation=='profile' else 'connect_succeeded',mutation)
            self.assertTrue(n.evaluate(value,B)['endpoints']['runner']['connect_success_observed'])
    def test_every_noncap_identity_conjunct_is_required(self):
        changes={'schemaVersion':True,'mode':'actor','nonce':'d'*32,'queriesSucceeded':False,'errors':['PRIVATE'],
                 'tokenIsAppContainer':False,'tokenAppContainerSid':'PRIVATE','tokenElevated':True,
                 'isProcessInJob':False,'pid':True}
        for key,bad in changes.items():
            value=cases();value['guest']['contained']['actor'][key]=bad
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive',key)
    def test_exact_agentic_attributes_and_no_extra_capability(self):
        for caps in ([],[{'sid':B.agentic_sid,'attributes':7}],[{'sid':'S-1-15-3-1','attributes':4}],
                     [{'sid':B.agentic_sid,'attributes':4}]*2):
            value=cases();value['guest']['contained']['actor']['tokenCapabilities']=caps
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_error10013_wrong_phase_not_denial(self):
        for phase in n.FAILURES:
            value=cases()
            for r in value['guest']['contained']['actor']['n0a']['attempts']:r['failure']=phase
            self.assertEqual(n.evaluate(value,B)['status'],
                'observed_connect_denial' if phase in ('connect','completion') else 'inconclusive',phase)
    def test_timeout_refused_unreachable_unattempted_never_denial(self):
        for code in (0,10060,10061,10065):
            value=cases();value['guest']['contained']['actor']['n0a']['attempts'][0]['win32Error']=code
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
        for field in ('attempted','bindSucceeded','closed'):
            value=cases();value['guest']['contained']['actor']['n0a']['attempts'][0][field]=False
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_actual_tier_probe_exit_and_profile_requirements(self):
        for key,bad in [('actual_tiers',['appcontainer-dacl']),('actual_tiers',['base-container']*2),
                        ('probe_exit_code',1),('timed_out',True),('harness_error',True)]:
            value=cases();value['guest']['contained'][key]=bad
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
        for key,bad in [('profileMatched',False),('startupError',10013)]:
            value=cases();value['guest']['contained']['actor']['n0a'][key]=bad
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_same_endpoint_actual_window_not_process_lifetime(self):
        for starts in ([1500,1800,3300],[2100,2200,3300],[1500,2200,2900],[1500,3001,3300]):
            value=cases();value['guest']['during']=report('guest','ordinary','sample',starts)
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
        value=cases();value['guest']['during']=value['runner']['during']
        self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_control_errors_frequency_and_snapshot_requirements(self):
        for key in ('before','during','after'):
            for mutation in ('failed','frequency','identity'):
                value=cases();actor=value['guest'][key]['actor']
                if mutation=='failed':actor['n0a']['attempts'][0]['nonceMatched']=False
                if mutation=='frequency':actor['n0a']['qpcFrequency']=1001
                if mutation=='identity':actor['tokenIsAppContainer']=True
                self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_private_binding_and_exact_qpc_types(self):
        for key in ('nonce','actor_sha256','executor_sha256','build','ubr'):
            value=cases();value['guest']['contained'][key]='PRIVATE'
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
        for key in ('windowStartQpc','windowEndQpc','qpcFrequency'):
            for bad in (True,-1,2**63,1.0):
                value=cases();value['guest']['contained']['actor']['n0a'][key]=bad
                self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_three_attempts_exact_window_no_padding(self):
        for mutation in ('missing','extra','padded','short'):
            value=cases();net=value['guest']['contained']['actor']['n0a']
            if mutation=='missing':net['attempts'].pop()
            if mutation=='extra':net['attempts'].append(row(3,3100,False))
            if mutation=='padded':net['windowEndQpc']+=100
            if mutation=='short':net['qpcFrequency']=10000
            self.assertEqual(n.evaluate(value,B)['status'],'inconclusive')
    def test_original_policy_and_stage0_gate_unchanged(self):
        proof=n.proof_helpers();env=['SYSTEMROOT=C:\\Windows','LOCALAPPDATA=C:\\Users\\Fixture\\AppData\\Local']
        old=proof.policy('input','profile','actor.exe',B.nonce,required_environment=env)
        new=n.contained_policy('input','profile','actor.exe',B,'guest',B.ports[0],env)
        command=new['process'].pop('commandLine');old['process'].pop('commandLine')
        self.assertEqual(new,old);self.assertIn('n0a-tcp',command)
        self.assertFalse(proof.stage0_checks({'nonce':B.nonce,'actor':case('guest')['contained']['actor']})['native_identity'])
    def test_report_bounds_duplicate_keys_and_no_arbitrary_frame(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'actor.json'
            for data in (b'x'*(n.MAX_REPORT+1),b'{"x":1,"x":2}',b'[]'):
                path.write_bytes(data)
                with self.assertRaises(ValueError):n.read_report(path)
        self.assertEqual(n.nonce_frame(B.nonce,'guest','ordinary'),b'N0A1 '+b'a'*32+b' guest ordinary\n')
        for args in [('PRIVATE','guest','ordinary'),(B.nonce,'external','ordinary'),(B.nonce,'runner','SYSTEM')]:
            with self.assertRaises(ValueError):n.nonce_frame(*args)

class BindingTests(unittest.TestCase):
    def test_binding_requires_actual_ordinary_controller_and_exact_build(self):
        from dataclasses import replace
        for change in ({'controller_compartment':2},{'controller_compartment':True},
                       {'controller_elevated':True},{'controller_appcontainer':True},
                       {'build':26200},{'ubr':9550},{'ports':(80,19002)},
                       {'actor_sha256':'PRIVATE'},{'nonce':'PRIVATE'}):
            self.assertFalse(replace(B,**change).valid())
    def test_endpoint_port_mismatch_rejected_before_execution(self):
        with self.assertRaises(ValueError):n.command('actor.exe','report.json',B,'guest',19002,'contained','single')
        execution=Mock()
        with patch.object(n,'EXECUTION_ENABLED',True),self.assertRaises(ValueError):
            n.run_endpoint(execution,B,'guest',19002,100,approved=True)
        execution.probe.assert_not_called();execution.start.assert_not_called()

    def test_verify_binding_uses_native_catalog_and_existing_pinned_executor_check(self):
        import hashlib
        data=b'fixture'*100;digest=hashlib.sha256(data).hexdigest()
        proof=Mock();proof.smoke.identity_snapshot.return_value={'cid':1,'elevated':False,'appcontainer':False}
        proof.smoke.verify_executor.return_value={'executor_sha256':B.executor_sha256}
        proof.WindowsCapabilityObserver.return_value.catalog.return_value={'AgenticAppContainer':B.agentic_sid}
        proof.WindowsCapabilityObserver.return_value.source.return_value=[]
        registry=Mock();registry.QueryValueEx.side_effect=[('WinNT',1),('26300',1),(9457,1)]
        registry.OpenKey.return_value=Mock(__enter__=Mock(return_value=object()),__exit__=Mock(return_value=False))
        with tempfile.TemporaryDirectory() as temporary:
            actor=Path(temporary)/'actor.exe';actor.write_bytes(data)
            # Patch the module's os view, not global os.name/Path platform choice.
            with patch.object(n,'os',type('OS',(),{'name':'nt'})()),patch.object(n,'proof_helpers',return_value=proof),patch.object(n,'native_amd64',return_value=True),patch.dict(sys.modules,{'winreg':registry}):
                actual=n.verify_binding(actor,digest,'executor.exe','manifest.json',B.nonce,B.ports)
        self.assertTrue(actual.valid())
        proof.smoke.verify_executor.assert_called_once_with('executor.exe','manifest.json')
        proof.WindowsCapabilityObserver.return_value.catalog.assert_called_once_with()
        proof.WindowsCapabilityObserver.return_value.source.assert_called_once_with()

    def test_observed_source_nonempty_unavailable_and_nonclient_rejected(self):
        import hashlib
        data=b'fixture'*100;digest=hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            actor=Path(temporary)/'actor.exe';actor.write_bytes(data)
            for source,product,arch in ((None,'WinNT',True),([{'sid':'PRIVATE','attributes':4}],'WinNT',True),
                                        ([], 'ServerNT',True),([], 'WinNT',False)):
                proof=Mock();proof.smoke.identity_snapshot.return_value={'cid':1,'elevated':False,'appcontainer':False}
                proof.smoke.verify_executor.return_value={'executor_sha256':B.executor_sha256}
                proof.WindowsCapabilityObserver.return_value.catalog.return_value={'AgenticAppContainer':B.agentic_sid}
                proof.WindowsCapabilityObserver.return_value.source.return_value=source
                registry=Mock();registry.QueryValueEx.side_effect=[(product,1),('26300',1),(9457,1)]
                registry.OpenKey.return_value=Mock(__enter__=Mock(return_value=object()),__exit__=Mock(return_value=False))
                with patch.object(n,'os',type('OS',(),{'name':'nt'})()),patch.object(n,'proof_helpers',return_value=proof), \
                     patch.object(n,'native_amd64',return_value=arch),patch.dict(sys.modules,{'winreg':registry}),self.assertRaises(ValueError):
                    n.verify_binding(actor,digest,'executor.exe','manifest.json',B.nonce,B.ports)

class DriverTests(unittest.TestCase):
    def test_inactive_by_default_and_deadline_clipping(self):
        with self.assertRaises(PermissionError):n.run_endpoint(Mock(),B,'guest',19001,100,approved=True)
        self.assertEqual(n.clipped_timeout(10,30,clock=lambda:5),3)
        with self.assertRaises(TimeoutError):n.clipped_timeout(7,30,clock=lambda:5)
    def test_owned_cleanup_failure_retains_connect_success(self):
        execution=Mock();value=case('guest')
        value['contained']['actor']['n0a']['attempts'][0]['connectSucceeded']=True
        execution.invoke.side_effect=[value['before'],value['contained'],value['after']]
        execution.wait.return_value=value['during'];execution.close_owned.side_effect=OSError('PRIVATE')
        with patch.object(n,'EXECUTION_ENABLED',True):
            result=n.run_endpoint(execution,B,'guest',19001,100,approved=True,clock=lambda:1,sleep=lambda _:None)
        self.assertFalse(result['cleanup_confirmed'])
        self.assertEqual(n.endpoint_result(result,B,'guest')['status'],'connect_succeeded')
    def test_deadline_after_start_cleans_only_owned_handle(self):
        execution=Mock();execution.start.return_value=object();execution.close_owned.return_value=True
        values=iter([1,1,100])
        with patch.object(n,'EXECUTION_ENABLED',True):
            result=n.run_endpoint(execution,B,'guest',19001,100,approved=True,clock=lambda:next(values),sleep=lambda _:None)
        self.assertTrue(result['driver_error']);execution.close_owned.assert_called_once_with(execution.start.return_value)

class EndpointTests(unittest.TestCase):
    def test_actual_endpoint_reads_only_fixed_bounded_ascii_frame(self):
        endpoint=n.NonceEndpoint(B.nonce,'runner',100)
        connection=Mock();payload=iter(n.nonce_frame(B.nonce,'runner','ordinary'))
        connection.recv.side_effect=lambda _size:bytes([next(payload)])
        listener=Mock();endpoint.listener=listener
        listener.accept.side_effect=[(connection,('private',1)),OSError('closed')]
        with patch.object(n.time,'monotonic',return_value=1):endpoint.serve()
        connection.sendall.assert_called_once_with(n.nonce_frame(B.nonce,'runner','ordinary'))
        connection.close.assert_called_once();self.assertIsNone(endpoint.connection)
        closed=endpoint.finish()
        self.assertEqual(closed['receiver_counts'],{'accepted':1,'ordinary_verified_frames':1,
            'contained_verified_frames':0,'rejected':0,'timed_out':0})
    def test_private_bad_or_overlong_frame_never_echoed(self):
        for data in (b'PRIVATE_SENTINEL\n',b'x'*96):
            endpoint=n.NonceEndpoint(B.nonce,'guest',100);connection=Mock();payload=iter(data)
            connection.recv.side_effect=lambda _size:bytes([next(payload)])
            endpoint.listener=Mock();endpoint.listener.accept.side_effect=[(connection,None),OSError('stop')]
            with patch.object(n.time,'monotonic',return_value=1):endpoint.serve()
            connection.sendall.assert_not_called();connection.close.assert_called_once()
            self.assertEqual(endpoint.finish()['receiver_counts']['rejected'],1)
    def test_idle_polls_do_not_exhaust_accept_quota(self):
        endpoint=n.NonceEndpoint(B.nonce,'guest',100);connection=Mock()
        payload=iter(n.nonce_frame(B.nonce,'guest','ordinary'))
        connection.recv.side_effect=lambda _size:bytes([next(payload)])
        endpoint.listener=Mock()
        endpoint.listener.accept.side_effect=[n.socket.timeout()]*130+[(connection,None),OSError('stop')]
        with patch.object(n.time,'monotonic',return_value=1):endpoint.serve()
        connection.sendall.assert_called_once()
    def test_drip_feed_clips_each_receive_to_same_absolute_bound(self):
        endpoint=n.NonceEndpoint(B.nonce,'guest',100);connection=Mock();connection.recv.return_value=b'N'
        endpoint.listener=Mock();endpoint.listener.accept.side_effect=[(connection,None),OSError('stop')]
        ticks=iter([1,1,1.1,1.6,2])
        with patch.object(n.time,'monotonic',side_effect=lambda:next(ticks)):endpoint.serve()
        self.assertEqual(connection.recv.call_count,1)
        self.assertAlmostEqual(connection.settimeout.call_args.args[0],.4)
        connection.sendall.assert_not_called();connection.close.assert_called_once()
        self.assertEqual(endpoint.finish()['receiver_counts']['timed_out'],1)

    def test_close_error_and_living_owned_thread_never_confirm_cleanup(self):
        for mode in ('socket','thread'):
            endpoint=n.NonceEndpoint(B.nonce,'guest',100);endpoint.listener=Mock();endpoint.thread=Mock()
            endpoint.thread.is_alive.return_value=mode=='thread'
            if mode=='socket':endpoint.listener.close.side_effect=OSError('PRIVATE')
            result=endpoint.finish();self.assertFalse(result['socket_cleanup_confirmed'])
            if mode=='thread':self.assertIsNone(result['receiver_counts'])
            self.assertNotIn('PRIVATE',json.dumps(result));endpoint.thread.join.assert_called_once_with(1)
    def test_endpoint_is_exact_local_bind_and_finite_backlog(self):
        endpoint=n.NonceEndpoint(B.nonce,'runner',100);listener=Mock()
        listener.getsockname.return_value=('127.0.0.1',19002)
        thread=Mock();thread.is_alive.return_value=False
        with patch.object(n.socket,'socket',return_value=listener) as factory,patch.object(n.threading,'Thread',return_value=thread):
            self.assertEqual(endpoint.start(),19002)
        factory.assert_called_once_with(n.socket.AF_INET,n.socket.SOCK_STREAM)
        listener.bind.assert_called_once_with(('127.0.0.1',0));listener.listen.assert_called_once_with(4)
        self.assertTrue(endpoint.finish()['socket_cleanup_confirmed'])

if __name__=='__main__':unittest.main()
