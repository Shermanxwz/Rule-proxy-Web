import importlib.util
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_test',ROOT/'.github/windows_n0a_udp6.py');u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
NONCE='a'*32

def row(phase,index,start,accepted=True,denied=False):
    return dict(index=index,attempted=True,socketCreated=True,bindSucceeded=True,localPort=45000+index,localIpv6='0'*32,localScopeId=0,v6OnlySet=True,v6OnlyVerified=True,v6OnlyGetReturn=0,v6OnlyGetError=None,v6OnlyGetLength=4,v6OnlyGetValue=1,v6OnlyGetStage='nonzero',
        sendStartQpc=start,sendEndQpc=start+1,sendAccepted=accepted,sendBytes=len(u.frame(NONCE,phase,index)) if accepted else -1,
        nonceMatched=accepted,exchangeEndQpc=start+2,win32Error=10013 if denied else 0,failure='sendto' if denied else 'none',closed=True,closeError=0,closeQpc=10000)
def network(phase,starts,production=True,denied=False):
    rows=[row(phase,i,start,not denied,denied) for i,start in enumerate(starts)]
    return dict(version=1,endpoint='runner-v6' if production else 'fixture-loopback-v6',phase=phase,port=40000,profileMatched=production,startupError=0,qpcFrequency=1000,windowStartQpc=starts[0],windowEndQpc=starts[-1]+2,attempts=rows,testOnly=not production,socketsCleanupConfirmed=True)
def reports(production=True,denied=True):
    return {phase:network(phase,starts,production,denied and phase=='contained') for phase,starts in [('before',[10]),('sample',[100,600,1800]),('contained',[500,1000,1500]),('after',[2000])]}

class ControlTests(unittest.TestCase):
    def test_fixed_frame_role_phase_index_nonce_no_dns(self):
        self.assertEqual(u.frame(NONCE,'contained',2),b'N0AU6 '+b'a'*32+b' contained 2\n')
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
        sid='S-1-15-3-1';actor=dict(schemaVersion=1,mode='actor-n0a-udp6',nonce=NONCE,queriesSucceeded=True,errors=[],tokenElevated=False,pid=10,tokenIsAppContainer=True,isProcessInJob=True,tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7',tokenCapabilities=[dict(sid=sid,attributes=4)])
        self.assertTrue(u.native_identity(actor,NONCE,'contained',sid))
        for key,value in [('tokenElevated',True),('isProcessInJob',False),('mode','actor-n0a'),('tokenCapabilities',[]),('pid',True)]:
            bad=dict(actor);bad[key]=value;self.assertFalse(u.native_identity(bad,NONCE,'contained',sid))
        actor.update(tokenIsAppContainer=False,tokenAppContainerSid=None,tokenCapabilities=[])
        self.assertTrue(u.native_identity(actor,NONCE,'before',sid))

class EndpointTests(unittest.TestCase):
    def serve(self,events,send_error=False):
        endpoint=u.Udp6Endpoint(NONCE,60)
        class FakeSocket:
            def recvfrom(self,size):
                if not events:endpoint.stop.set();raise socket.timeout()
                event=events.pop(0)
                if isinstance(event,Exception):raise event
                return event,('::1',45000,0,0)
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
        self.assertEqual(e.counts['observed_bytes'],len(u.frame(NONCE,'before',0)))
        events=[b'']*130;e=self.serve(events);self.assertEqual(e.counts['datagrams'],128);self.assertEqual(len(events),2);self.assertTrue(e.error)
    def test_partial_start_owns_socket_and_unknown_thread_forbids_cleanup(self):
        e=u.Udp6Endpoint(NONCE,60);sock=Mock();sock.getsockopt.return_value=1;sock.bind.side_effect=OSError('private');sock.fileno.return_value=-1
        with patch.object(u.time,'monotonic',return_value=1),patch.object(u.socket,'socket',return_value=sock):
            with self.assertRaises(OSError):e.start()
        self.assertIs(e.socket,sock)
        e.thread=Mock();e.thread.is_alive.return_value=True
        with patch.object(u.time,'monotonic',return_value=59):result=e.finish(100)
        e.thread.join.assert_called_once_with(1);self.assertFalse(result['cleanup_confirmed']);self.assertIsNone(result['counts'])
    def test_close_uncertainty_sticky(self):
        e=u.Udp6Endpoint(NONCE,60);e.socket=Mock();e.socket.close.side_effect=OSError('private');e.socket.fileno.return_value=-1
        self.assertFalse(e.finish(60)['cleanup_confirmed']);e.socket.close.side_effect=None;self.assertFalse(e.finish(60)['cleanup_confirmed'])
class Ipv6BoundaryTests(unittest.TestCase):
    def test_strict_v6only_scope_address_and_no_ipv4_schema(self):
        for changes in ({'v6OnlySet':False},{'v6OnlyVerified':False},{'v6OnlyVerified':1},
                        {'localScopeId':1},{'localScopeId':True},{'localIpv6':'0'*20+'ffff7f000001'},
                        {'localIpv6':'::1'},{'localIpv6':'F'*32},{'localIpv4':0}):
            value=network('contained',[500,1000,1500]);value['attempts'][0].update(changes)
            with self.assertRaises(ValueError):u.validate_network(value,NONCE,'contained',40000)
        for failure in ('socket','v6only_set','v6only_get','bind','getsockname','recvfrom'):
            value=reports();value['contained']['attempts'][0]['failure']=failure
            self.assertFalse(u.controls(value,NONCE,40000)['explicit_send_denial'])
    def test_real_owned_v6_loopback_echo_only_no_fallback(self):
        import time
        endpoint=u.Udp6Endpoint(NONCE,time.monotonic()+3)
        client=None
        try:
            port=endpoint.start()
            self.assertEqual(endpoint.socket.family,socket.AF_INET6)
            self.assertEqual(endpoint.socket.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY),1)
            client=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);client.settimeout(1)
            payload=u.frame(NONCE,'contained',0);client.sendto(payload,('::1',port,0,0))
            self.assertEqual(client.recvfrom(129)[0],payload)
        finally:
            if client is not None:client.close()
            facts=endpoint.finish(time.monotonic()+2)
        self.assertTrue(facts['cleanup_confirmed']);self.assertTrue(facts['contained_observed'])
        self.assertEqual(facts['counts']['verified'],1)
    def test_bad_peer_scope_mapped_address_and_port_rejected(self):
        for peer in [('127.0.0.1',45000),('::ffff:127.0.0.1',45000,0,0),('::1',45000,0,1),('::1',0,0,0),('::1',True,0,0)]:
            e=u.Udp6Endpoint(NONCE,60);sock=Mock();e.socket=sock
            def receive(size):
                e.stop.set();return u.frame(NONCE,'contained',0),peer
            sock.recvfrom.side_effect=receive
            with patch.object(u.time,'monotonic',return_value=1):e.serve()
            self.assertEqual(e.counts['rejected'],1);sock.sendto.assert_not_called()
    def test_v6only_refusal_never_binds_or_falls_back(self):
        e=u.Udp6Endpoint(NONCE,60);sock=Mock();sock.getsockopt.return_value=0;sock.fileno.return_value=-1
        with patch.object(u.time,'monotonic',return_value=1),patch.object(u.socket,'socket',return_value=sock) as create:
            with self.assertRaises(ValueError):e.start()
        create.assert_called_once_with(socket.AF_INET6,socket.SOCK_DGRAM);sock.bind.assert_not_called()
        self.assertTrue(e.finish(60)['cleanup_confirmed'])
    def test_unstarted_real_thread_is_owned_and_cleanup_observed(self):
        import threading
        e=u.Udp6Endpoint(NONCE,60);e.thread=threading.Thread(target=lambda:None)
        self.assertTrue(e.finish(60)['thread_stopped'])

class V6OnlyReadbackTests(unittest.TestCase):
    def test_actual_typed_readback_matrix(self):
        for observed in (1,2,0xffffffff):
            value=network('contained',[500,1000,1500]);value['attempts'][0]['v6OnlyGetValue']=observed
            self.assertIs(u.validate_network(value,NONCE,'contained',40000),value)
        for stage,returned,error,length,observed,failure,code in (
            ('api_error',-1,10022,4,None,'v6only_get',10022),
            ('length_mismatch',0,None,3,None,'v6only_length',0),
            ('length_mismatch',0,None,8,None,'v6only_length',0),
            ('zero',0,None,4,0,'v6only_zero',0)):
            value=network('before',[500]);row=value['attempts'][0]
            row.update(v6OnlyGetStage=stage,v6OnlyGetReturn=returned,v6OnlyGetError=error,v6OnlyGetLength=length,v6OnlyGetValue=observed,
                       v6OnlyVerified=False,attempted=False,bindSucceeded=False,sendAccepted=False,nonceMatched=False,
                       sendBytes=-1,sendStartQpc=0,sendEndQpc=0,localPort=0,failure=failure,win32Error=code)
            self.assertIs(u.validate_network(value,NONCE,'before',40000),value)
        value=network('before',[500]);row=value['attempts'][0]
        row.update(v6OnlySet=False,v6OnlyVerified=False,v6OnlyGetStage='not_attempted',v6OnlyGetReturn=None,v6OnlyGetError=None,
                   v6OnlyGetLength=None,v6OnlyGetValue=None,attempted=False,bindSucceeded=False,sendAccepted=False,
                   nonceMatched=False,sendBytes=-1,sendStartQpc=0,sendEndQpc=0,localPort=0,failure='v6only_set',win32Error=10022)
        self.assertIs(u.validate_network(value,NONCE,'before',40000),value)
    def test_contradictory_null_bool_length_value_and_stage_fail(self):
        for change in ({'v6OnlyGetReturn':True},{'v6OnlyGetError':0},{'v6OnlyGetLength':True},
                       {'v6OnlyGetValue':True},{'v6OnlyGetValue':0},{'v6OnlyGetValue':None},
                       {'v6OnlyGetStage':'PRIVATE'},{'v6OnlyGetLength':8},{'v6OnlyGetStage':'api_error'}):
            value=network('before',[500]);value['attempts'][0].update(change)
            with self.assertRaises(ValueError):u.validate_network(value,NONCE,'before',40000)
    def test_receiver_nonzero_boolean_readback_including_signed_representation(self):
        for value in (1,2,0xffffffff,-1):
            endpoint=u.Udp6Endpoint(NONCE,60);sock=Mock();sock.getsockopt.return_value=value
            sock.getsockname.return_value=('::1',45000,0,0);sock.fileno.return_value=-1
            with patch.object(u.time,'monotonic',return_value=1),patch.object(u.socket,'socket',return_value=sock),patch.object(u.threading,'Thread') as thread:
                thread.return_value.start.side_effect=endpoint.ready.set
                self.assertEqual(endpoint.start(),45000)
            sock.bind.assert_called_once_with(('::1',0,0,0))

if __name__=='__main__':unittest.main()

