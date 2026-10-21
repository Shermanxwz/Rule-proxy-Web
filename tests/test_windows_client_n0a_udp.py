import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_test',ROOT/'.github/windows_n0a_udp.py');u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
NONCE='a'*32

def row(phase,index,start,accepted=True,denied=False):
    return dict(index=index,attempted=True,socketCreated=True,bindSucceeded=True,localPort=45000+index,localIpv4=0,
        sendStartQpc=start,sendEndQpc=start+1,sendAccepted=accepted,sendBytes=len(u.frame(NONCE,phase,index)) if accepted else -1,
        nonceMatched=accepted,exchangeEndQpc=start+2,win32Error=10013 if denied else 0,failure='sendto' if denied else 'none',closed=True,closeError=0,closeQpc=10000)
def network(phase,starts,production=True,denied=False):
    rows=[row(phase,i,start,not denied,denied) for i,start in enumerate(starts)]
    return dict(version=1,endpoint='runner' if production else 'fixture-loopback',phase=phase,port=40000,profileMatched=production,startupError=0,qpcFrequency=1000,windowStartQpc=starts[0],windowEndQpc=starts[-1]+2,attempts=rows,testOnly=not production,socketsCleanupConfirmed=True)
def reports(production=True,denied=True):
    return {phase:network(phase,starts,production,denied and phase=='contained') for phase,starts in [('before',[10]),('sample',[100,600,1800]),('contained',[500,1000,1500]),('after',[2000])]}

class ControlTests(unittest.TestCase):
    def test_fixed_frame_role_phase_index_nonce_no_dns(self):
        self.assertEqual(u.frame(NONCE,'contained',2),b'N0AU1 '+b'a'*32+b' contained 2\n')
        for phase,index in [('after',1),('sample',40),('contained',3),('PRIVATE',0)]:
            with self.assertRaises(ValueError):u.frame(NONCE,phase,index)
        with self.assertRaises(ValueError):u.frame('a'*31,'before',0)
    def test_send_denial_independent_of_delivery_and_capture(self):
        value=u.controls(reports(),NONCE,40000)
        self.assertTrue(value['explicit_send_denial']);self.assertTrue(value['all_selected_sendto_invoked']);self.assertTrue(value['ordinary_controls_verified']);self.assertFalse(value['runtime_acceptance'])
        value=u.controls(reports(denied=False),NONCE,40000)
        self.assertFalse(value['explicit_send_denial']);self.assertEqual(value['selected_send_accepted_count'],3);self.assertTrue(value['selected_echo_observed'])
        self.assertNotIn('bounded_no_selected_udp_datagram',value)
    def test_actual_invocation_required_and_10013_phase_exact(self):
        for field,value in [('attempted',False),('failure','bind'),('failure','recvfrom'),('win32Error',10035)]:
            data=reports();data['contained']['attempts'][0][field]=value
            self.assertFalse(u.controls(data,NONCE,40000)['explicit_send_denial'])
    def test_full_inside_qpc_control_and_profile_flags(self):
        data=reports();data['sample']=network('sample',[100,1800])
        self.assertFalse(u.controls(data,NONCE,40000)['ordinary_controls_verified'])
        data=reports();data['contained']['profileMatched']=False
        self.assertFalse(u.controls(data,NONCE,40000)['all_selected_sendto_invoked'])
        fixture=reports(production=False,denied=False)
        self.assertTrue(u.controls(fixture,NONCE,40000,production=False)['ordinary_controls_verified'])
        self.assertFalse(u.controls(fixture,NONCE,40000)['ordinary_controls_verified'])
    def test_schema_types_bounds_duplicate_and_private_sentinel(self):
        data=network('contained',[500,1000,1500]);self.assertIs(u.validate_network(data,NONCE,'contained',40000),data)
        for mutate in [lambda d:d.update(extra='PRIVATE'),lambda d:d.update(port=True),lambda d:d['attempts'][0].update(sendBytes=True),lambda d:d['attempts'][0].update(closeQpc=1),lambda d:d['attempts'][0].update(localPort=0),lambda d:d['attempts'][0].update(sendBytes=1),lambda d:d.update(testOnly=True)]:
            changed=json.loads(json.dumps(data));mutate(changed)
            with self.assertRaises(ValueError):u.validate_network(changed,NONCE,'contained',40000)
        for raw in (b'{"x":1,"x":2}',b'['*1200+b']'*1200,b'x'*32769,b'{"x":NaN}'):
            with self.assertRaises(ValueError):u.parse(raw)
    def test_native_identity_exact_profile_not_stage0_acceptance(self):
        sid='S-1-15-3-1';actor=dict(schemaVersion=1,mode='actor-n0a-udp',nonce=NONCE,queriesSucceeded=True,errors=[],tokenElevated=False,pid=10,tokenIsAppContainer=True,isProcessInJob=True,tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7',tokenCapabilities=[dict(sid=sid,attributes=4)])
        self.assertTrue(u.native_identity(actor,NONCE,'contained',sid))
        for key,value in [('tokenElevated',True),('isProcessInJob',False),('mode','actor-n0a'),('tokenCapabilities',[]),('pid',True)]:
            bad=dict(actor);bad[key]=value;self.assertFalse(u.native_identity(bad,NONCE,'contained',sid))
        actor.update(tokenIsAppContainer=False,tokenAppContainerSid=None,tokenCapabilities=[])
        self.assertTrue(u.native_identity(actor,NONCE,'before',sid))

class EndpointTests(unittest.TestCase):
    def serve(self,events,send_error=False):
        endpoint=u.UdpEndpoint(NONCE,60)
        class FakeSocket:
            def recvfrom(self,size):
                if not events:endpoint.stop.set();raise socket.timeout()
                event=events.pop(0)
                if isinstance(event,Exception):raise event
                return event,('127.0.0.1',45000)
            def sendto(self,data,peer):
                if send_error:raise OSError('PRIVATE')
                return len(data)
            def settimeout(self,value):pass
        endpoint.socket=FakeSocket()
        with patch.object(u.time,'monotonic',return_value=1):endpoint.serve()
        return endpoint
    def test_counts_all_datagrams_but_not_idle_and_sticky_before_send_error(self):
        e=self.serve([socket.timeout(),b'',b'x'*129,u.frame(NONCE,'contained',0)],True)
        self.assertEqual(e.counts['datagrams'],3);self.assertEqual(e.counts['oversized'],1);self.assertEqual(e.counts['rejected'],1)
        self.assertTrue(e.contained_observed.is_set());self.assertTrue(e.error);self.assertEqual(e.counts['echoed'],0)
    def test_cap_windows_oversize_and_no_prefix_parse(self):
        error=OSError('private');error.winerror=10040
        e=self.serve([error,u.frame(NONCE,'before',0)])
        self.assertEqual(e.counts['oversized'],1);self.assertEqual(e.counts['verified'],1)
        events=[b'']*130;e=self.serve(events);self.assertEqual(e.counts['datagrams'],128);self.assertEqual(len(events),2);self.assertTrue(e.error)
    def test_partial_start_owns_socket_and_unknown_thread_forbids_cleanup(self):
        e=u.UdpEndpoint(NONCE,60);sock=Mock();sock.bind.side_effect=OSError('private');sock.fileno.return_value=-1
        with patch.object(u.time,'monotonic',return_value=1),patch.object(u.socket,'socket',return_value=sock):
            with self.assertRaises(OSError):e.start()
        self.assertIs(e.socket,sock)
        e.thread=Mock();e.thread.is_alive.return_value=True
        with patch.object(u.time,'monotonic',return_value=59):result=e.finish(100)
        e.thread.join.assert_called_once_with(1);self.assertFalse(result['cleanup_confirmed']);self.assertIsNone(result['counts'])
    def test_close_uncertainty_sticky(self):
        e=u.UdpEndpoint(NONCE,60);e.socket=Mock();e.socket.close.side_effect=OSError('private');e.socket.fileno.return_value=-1
        self.assertFalse(e.finish(60)['cleanup_confirmed']);e.socket.close.side_effect=None;self.assertFalse(e.finish(60)['cleanup_confirmed'])
if __name__=='__main__':unittest.main()

class IntegrationControlTests(unittest.TestCase):
    def binding(self):return u.UDPBinding(NONCE,'a'*64,'b'*64,'S-1-15-3-1',40000,1,False,False)
    def cases(self,accepted=False):
        binding=self.binding();result=dict(driver_error=False,cleanup_confirmed=True)
        for phase,net in reports(denied=not accepted).items():
            actor=dict(schemaVersion=1,mode='actor-n0a-udp',nonce=NONCE,queriesSucceeded=True,errors=[],tokenElevated=False,pid=123,
                tokenIsAppContainer=phase=='contained',isProcessInJob=True,tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7' if phase=='contained' else None,
                tokenCapabilities=[{'sid':binding.agentic_sid,'attributes':4}] if phase=='contained' else [],udp=net)
            result[phase]=dict(nonce=NONCE,actor_sha256=binding.actor_sha256,executor_sha256=binding.executor_sha256,build=26300,ubr=9457,
                actor=actor,pid_verified=True,pid_binding='executor_audit' if phase=='contained' else 'ordinary_handle',child_exit_code=0,
                probe={},probe_exit_code=0,actual_tiers=['base-container'],exit_code=0,timed_out=False,harness_error=False)
        return result
    def test_frozen_runner_binding_exact_argv_and_mode(self):
        b=self.binding();self.assertTrue(b.valid());self.assertEqual(u.command('actor','report',b,'contained'),['actor','n0a-udp',NONCE,'report','40000','contained'])
        with self.assertRaises(Exception):b.runner_port=5
        with self.assertRaises(ValueError):u.command('actor','report',b,'guest')
        case=self.cases()['contained'];case['actor']['mode']='actor-n0a';self.assertIsNone(u.bound_actor(case,b))
    def test_provenance_control_and_sticky_accepted_echo(self):
        from types import SimpleNamespace
        helpers=SimpleNamespace(proof_helpers=lambda:SimpleNamespace(smoke=SimpleNamespace(base_container_selected=lambda p,e:True)))
        with patch.object(u,'tcp_helpers',return_value=helpers):
            cases=self.cases();value=u.evaluate(cases,self.binding());self.assertTrue(value['explicit_send_denial']);self.assertTrue(value['ordinary_controls_verified'])
            for key,bad in [('pid_verified',False),('pid_binding','ordinary_handle'),('actual_tiers',['app-container']),('child_exit_code',True)]:
                changed=self.cases();changed['contained'][key]=bad;self.assertFalse(u.evaluate(changed,self.binding())['explicit_send_denial'])
            cases=self.cases(True);cases['contained']['child_exit_code']=4;cases['contained']['harness_error']=True;cases['driver_error']=True
            result=u.evaluate(cases,self.binding());self.assertEqual(result['selected_send_accepted_count'],3);self.assertTrue(result['selected_echo_observed']);self.assertFalse(result['ordinary_controls_verified'])
            del cases['sample'];self.assertTrue(u.evaluate(cases,self.binding())['selected_echo_observed'])
    def test_disabled_driver_and_exact_phase_dispatch(self):
        with self.assertRaises(PermissionError):u.run_endpoint(Mock(),self.binding(),100,approved=True)
        execution=Mock();execution.close_owned.return_value=True
        with patch.object(u,'EXECUTION_ENABLED',True):
            result=u.run_endpoint(execution,self.binding(),100,approved=True,clock=lambda:0,sleep=lambda _:None)
        self.assertEqual([call.args[1] for call in execution.invoke.call_args_list],['before','contained','after'])
        self.assertEqual(execution.start.call_args.args,('ordinary','sample','runner',40000));self.assertFalse(result['driver_error'])
    def test_closed_result_rejects_extra_types_and_acceptance(self):
        value=u.evaluate({},None);self.assertEqual(u.closed_result(value),value)
        for key,bad in [('stage0_passed',True),('selected_send_accepted_count',True),('profile_verified',{'before':True})]:
            changed=dict(value);changed[key]=bad
            with self.assertRaises(ValueError):u.closed_result(changed)

class IndependentDenialTests(unittest.TestCase):
    binding=IntegrationControlTests.binding
    cases=IntegrationControlTests.cases
    def test_bound_three_sendto_denials_survive_unrelated_failure(self):
        from types import SimpleNamespace
        helpers=SimpleNamespace(proof_helpers=lambda:SimpleNamespace(smoke=SimpleNamespace(base_container_selected=lambda p,e:True)))
        with patch.object(u,'tcp_helpers',return_value=helpers):
            for failure in ('ordinary','driver','cleanup','selected_exit'):
                cases=self.cases()
                if failure=='ordinary':del cases['sample']
                if failure=='driver':cases['driver_error']=True
                if failure=='cleanup':cases['cleanup_confirmed']=False
                if failure=='selected_exit':cases['contained']['child_exit_code']=4;cases['contained']['harness_error']=True
                result=u.evaluate(cases,self.binding());self.assertTrue(result['explicit_send_denial']);self.assertFalse(result['ordinary_controls_verified']);self.assertFalse(result['runtime_acceptance'])
            cases=self.cases();cases['contained']['actor']['udp']['attempts'][0]['attempted']=False
            self.assertFalse(u.evaluate(cases,self.binding())['explicit_send_denial'])
