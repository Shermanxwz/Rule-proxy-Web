"""Frozen C03 native JSON fixtures only; no actor, process, policy or socket."""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('model2_native_schema_pure',ROOT/'.github/windows_identity_model2_controller.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RUN='1'*32;BOOT='2'*32;CASE='3'*32;ADMISSION='4'*32
USER='S-1-5-21-1-2-3-1001';AC='S-1-15-2-1-2-3-4-5-6-7'
PNCS='S-1-15-3-3';AGENTIC='S-1-15-3-1024-1-2-3-4-5-6-7-8'
F=1000;T0=10000;D=125000;PAIR=20000;END=30000;PHASE_END=29000
P=51001;Q=51002;O=51003
CONFIG=dict(run=RUN,boot_case=BOOT,positive_case=CASE,frequency=F,start_qpc=T0,deadline_qpc=D)


def task(profile='agentic-pncs',pid=101):
    capabilities=[] if profile=='ordinary' else [{'sid':PNCS,'attributes':4}]
    if profile=='agentic-pncs':capabilities.append({'sid':AGENTIC,'attributes':4})
    container=profile!='ordinary'
    return dict(pid=pid,identity=dict(sid=USER,session_id=1,token_type=1,elevation_type=1,elevated=False,
        integrity_rid=4096 if container else 8192,admin_attributes=None,appcontainer=container,
        appcontainer_sid=AC if container else None,capability_count=len(capabilities),ui_access=False),capabilities=capabilities)


def native_identity(held):
    return dict(schemaVersion=1,mode='actor',nonce=RUN,pid=held['pid'],tokenUserSid=USER,
        tokenIsAppContainer=held['identity']['appcontainer'],tokenAppContainerSid=held['identity']['appcontainer_sid'],
        tokenElevated=False,isProcessInJob=True,tokenCapabilities=copy.deepcopy(held['capabilities']),queriesSucceeded=True,errors=[])


def prefix(stage,held,role,boot=BOOT):
    return dict(schema_version=1,stage=stage,role=role,run_id=RUN,boot_case_id=boot,
        pid=held['pid'],identity=native_identity(held))


def qualification(profile):
    return dict(capability_profile=profile,capability_profile_verified=True,catalog_cleanup_verified=True)


def ready_client(held=None):
    held=task() if held is None else held
    return dict(prefix('proxy-c-client-ready',held,'selected-client'),**qualification('agentic-pncs'),
        qpc=[F,T0,D,21000],admission_nonce=ADMISSION,ready=True,network_initialized=False,failure=None)


def transport(case=CASE,port=P,operation='proxy-get'):
    request,response=m.transport_payload(case,port,operation)
    value={key:True for key in m.live.origin.RELAY_BOOLS}
    value.update(port=port,local_port=55000,peer_port=port,request_bytes=len(request),response_bytes=len(response),
        socket_close='confirmed',failure=None,wsa_error=None)
    return value


def phase(held=None,operation='proxy-get',port=P):
    held=task() if held is None else held
    return dict(prefix('proxy-c-client-phase',held,'selected-client'),case_id=CASE,sequence=1,
        operation=operation,target_port=port,admission_nonce=ADMISSION,root_qpc=[F,T0,D],
        phase_qpc=[21000,PHASE_END,22000],command_close_verified=True,network=transport(port=port,operation=operation),
        failure=None,proxy_tested=False,product_acceptance=False)


def client_final(held=None):
    held=task() if held is None else held
    return dict(prefix('proxy-c-client-final',held,'selected-client'),**qualification('agentic-pncs'),qpc=[F,T0,D,40000],
        phase_count=2,finished=True,network_initialized_before_go=False,network_initialized=True,
        command_close_verified=True,failure=None,proxy_tested=False,product_acceptance=False)


def ready_listener(held,role='health-origin',profile='ordinary',port=O,start=T0,deadline=D):
    return dict(prefix('proxy-c-listener-ready',held,role),**qualification(profile),qpc=[F,start,deadline,start+1000],
        port=port,ready=True,network_initialized=True,failure=None)


def receipt(held=None):
    held=task('ordinary',104) if held is None else held
    request,response=m.live.origin.payloads(CASE,O)
    return dict(schema_version=1,stage='proxy-c-listener-receipt',role='health-origin',run_id=RUN,boot_case_id=BOOT,
        case_id=CASE,pid=held['pid'],index=2,port=O,peer_port=54000,qpc=[F,21000,D,22000],
        request_bytes=len(request),request_exact=True,request_eof=True,response_bytes=len(response),
        response_complete=True,send_shutdown=True,connection_close='confirmed',failure=None,wsa_error=None)


def listener_final(held=None):
    held=task('ordinary',104) if held is None else held
    return dict(prefix('proxy-c-listener-final',held,'health-origin'),**qualification('ordinary'),qpc=[F,T0,D,40000],
        port=O,accepted_count=4,receipt_count=4,finished=True,listener_close='confirmed',wsa_startup=True,wsa_cleanup=True,
        command_close_verified=True,failure=None,wsa_error=None)


def mechanics(held,front):
    return dict(schema_version=1,stage='bridge-pipe-test',role='pipe-front' if front else 'pipe-relay',run_id=RUN,
        case_id=CASE,pid=held['pid'],identity=native_identity(held),qpc=[F,PAIR,END,22000],
        pipe=dict(read_bytes=96 if front else 144,write_bytes=144 if front else 96,read_frames=2 if front else 3,
            write_frames=3 if front else 2,inheritance_cleared=True,eof_observed=True,reader_close='confirmed',
            writer_close='confirmed',requires_controller_timeout=True),
        core=dict(failure=0,observations=177 if front else 78,requested=7 if front else 56,confirmed=7 if front else 56,uncertain=0),
        synthetic_http=dict(request_checked=True,response_checked=True,client_sink_checked=front),
        failure=None,win32_error=None,network_tested=False,proxy_tested=False,product_acceptance=False)


def front_report(held=None):
    held=task('pncs',102) if held is None else held
    request,response=m.transport_payload(CASE,P,'proxy-get')
    return dict(schema_version=1,stage='proxy-c-live-front',role='pipe-live-front',run_id=RUN,case_id=CASE,pid=held['pid'],
        identity=native_identity(held),**qualification('pncs'),ipc_mechanics=mechanics(held,True),
        listener=dict(port=P,listener_created=True,inheritance_cleared=True,exclusive=True,bind_loopback=True,
            accepted=True,peer_loopback=True,peer_port=55000,listener_close='confirmed'),
        client=dict(request_bytes=len(request),request_exact=True,request_eof=True,response_bytes=len(response),
            response_complete=True,send_shutdown=True,connection_close='confirmed'),
        wsa_startup=True,wsa_cleanup=True,failure=None,wsa_error=None,
        http_boundary='real-client-request-and-response-socket',network_tested=True,proxy_tested=False,product_acceptance=False)


def relay_report(held=None):
    held=task('ordinary',103) if held is None else held
    return dict(schema_version=1,stage='bridge-origin-pipe-test',role='pipe-relay',run_id=RUN,case_id=CASE,pid=held['pid'],
        ipc_mechanics=mechanics(held,False),origin=transport(port=O,operation='direct-tcp'),
        http_boundary=m.live.origin.BOUNDARY,network_tested=True,proxy_tested=False,product_acceptance=False)


class NativeSchemaTests(unittest.TestCase):
    def check_phase(self,value,operation='proxy-get',port=P):
        return m.client_phase(value,task(),CONFIG,role='selected-client',boot=BOOT,admission=ADMISSION,
            sequence=1,case=CASE,operation=operation,target_port=port,phase_deadline=PHASE_END)

    def test_native_real_operation_names_and_absolute_vs_relative_byte_counts(self):
        expected={1:'proxy-get',2:'direct-tcp',3:'wrong-port',4:'wrong-peer',5:'proxy-after-death',6:'dns-query',255:'finish'}
        self.assertEqual(m.live.OPS,expected)
        source=(ROOT/'.github/native/windows_identity_proxy_c_contract.hpp').read_text()
        for operation in expected.values():self.assertIn('"'+operation+'"',source)
        absolute,response=m.transport_payload(CASE,P,'proxy-get');relative,_=m.transport_payload(CASE,O,'direct-tcp')
        self.assertEqual(absolute,('GET http://ruleproxy-identity-proof.invalid/'+CASE+' HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n').encode())
        self.assertEqual(relative,m.live.origin.payloads(CASE,O)[0]);self.assertNotEqual(len(absolute),len(relative))
        self.assertTrue(response.endswith(CASE.encode()));self.assertTrue(m.phase_passed(self.check_phase(phase()),CASE))
        self.assertTrue(m.phase_passed(self.check_phase(phase(operation='direct-tcp',port=O),'direct-tcp',O),CASE))
        wrong=phase();wrong['network']['request_bytes']=len(relative)
        with self.assertRaises(ValueError):self.check_phase(wrong)

    def test_client_ready_matches_held_identity_and_forbids_network_before_go(self):
        value=ready_client();m.ready_client(value,task(),CONFIG,role='selected-client',boot=BOOT,admission=ADMISSION,profile='agentic-pncs')
        mutations=[lambda v:v.update(network_initialized=True),lambda v:v.update(admission_nonce='f'*32),
            lambda v:v.update(pid=999),lambda v:v.update(capability_profile_verified=False),
            lambda v:v['identity']['tokenCapabilities'][0].update(attributes=0),lambda v:v['qpc'].__setitem__(2,D+1),
            lambda v:v.update(raw='unknown')]
        for mutate in mutations:
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.ready_client(changed,task(),CONFIG,role='selected-client',boot=BOOT,admission=ADMISSION,profile='agentic-pncs')

    def test_phase_binding_late_and_overflow_keep_actual_connect_and_eof(self):
        value=phase();self.check_phase(value)
        for key,bad in (('operation','proxy'),('sequence',2),('target_port',Q),('case_id','f'*32),('command_close_verified',False)):
            changed=copy.deepcopy(value);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.check_phase(changed)
        late=phase();late['phase_qpc'][2]=PHASE_END+1;late['network']['failure']='deadline'
        self.check_phase(late);self.assertFalse(m.phase_passed(late,CASE));self.assertTrue(late['network']['connect_completed'])
        self.assertTrue(late['network']['response_eof'])
        overflow=phase();overflow['network'].update(response_bytes=257,response_exact=False,response_eof=False,failure='response')
        self.check_phase(overflow);self.assertFalse(m.phase_passed(overflow,CASE))
        self.assertTrue(overflow['network']['connect_completed']);self.assertEqual(overflow['network']['response_bytes'],257)
        overflow['network']['response_bytes']=258
        with self.assertRaises(ValueError):self.check_phase(overflow)

    def test_client_final_requires_exact_count_finish_and_observed_close(self):
        value=client_final();m.client_final(value,task(),CONFIG,role='selected-client',boot=BOOT,profile='agentic-pncs',count=2)
        for key,bad in (('phase_count',True),('phase_count',1),('finished',False),('network_initialized_before_go',True),
                        ('command_close_verified',False),('catalog_cleanup_verified',False)):
            changed=copy.deepcopy(value);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.client_final(changed,task(),CONFIG,role='selected-client',boot=BOOT,profile='agentic-pncs',count=2)

    def test_listener_ready_carries_actual_port_clock_and_ordinary_or_pncs_identity(self):
        origin=task('ordinary',104);value=ready_listener(origin)
        m.ready_listener(value,origin,CONFIG,role='health-origin',boot=BOOT,profile='ordinary')
        front=task('pncs',102);value=ready_listener(front,'pipe-live-front','pncs',P,PAIR,END)
        m.ready_listener(value,front,CONFIG,role='pipe-live-front',boot=BOOT,profile='pncs',start=PAIR,deadline=END)
        for mutate in (lambda v:v.update(port=49152),lambda v:v.update(network_initialized=False),
                       lambda v:v['identity'].update(tokenIsAppContainer=False),lambda v:v.update(capability_profile='ordinary')):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.ready_listener(changed,front,CONFIG,role='pipe-live-front',boot=BOOT,profile='pncs',start=PAIR,deadline=END)

    def test_health_receipt_and_final_are_independent_closed_origin_evidence(self):
        origin=task('ordinary',104);value=receipt(origin)
        m.receipt(value,origin,CONFIG,boot=BOOT,port=O,index=2);self.assertTrue(m.receipt_passed(value))
        late=copy.deepcopy(value);late['qpc'][3]=D+1
        m.receipt(late,origin,CONFIG,boot=BOOT,port=O,index=2);self.assertFalse(m.receipt_passed(late));self.assertTrue(late['request_exact'])
        wrong=copy.deepcopy(value);wrong['index']=3
        with self.assertRaises(ValueError):m.receipt(wrong,origin,CONFIG,boot=BOOT,port=O,index=2)
        final=listener_final(origin);m.listener_final(final,origin,CONFIG,boot=BOOT,port=O,receipt_count=4)
        for key,bad in (('accepted_count',5),('receipt_count',3),('listener_close','uncertain'),('finished',False)):
            changed=copy.deepcopy(final);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.listener_final(changed,origin,CONFIG,boot=BOOT,port=O,receipt_count=4)

    def test_pncs_front_uses_c_admission_without_weakening_old_a_zero_capability_gate(self):
        held=task('pncs',102);value=front_report(held)
        m.validate_front(value,held,CONFIG,P,O,PAIR,END)
        with self.assertRaises(ValueError):m.ac.validate_ac_native(value['ipc_mechanics'],role='pipe-front',run_id=RUN,case_id=CASE,
            pid=held['pid'],identity=held['identity'],frequency=F,start=PAIR,end=END,expected_ac_sid=AC)
        for mutate in (lambda v:v.update(http_boundary=m.live.origin.BOUNDARY),
            lambda v:v['listener'].update(peer_loopback=False),lambda v:v['client'].update(request_eof=False),
            lambda v:v['client'].update(request_bytes=len(m.live.origin.payloads(CASE,O)[0])),
            lambda v:v['ipc_mechanics']['core'].update(observations=176),
            lambda v:v['ipc_mechanics']['identity'].update(tokenCapabilities=[])):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_front(changed,held,CONFIG,P,O,PAIR,END)

    def test_relay_retains_ordinary_identity_relative_http_and_legacy_mechanics(self):
        held=task('ordinary',103);value=relay_report(held)
        m.validate_relay(value,held,CONFIG,O,PAIR,END)
        for mutate in (lambda v:v['origin'].update(request_bytes=len(m.transport_payload(CASE,P,'proxy-get')[0])),
            lambda v:v['ipc_mechanics']['identity'].update(tokenCapabilities=[{'sid':PNCS,'attributes':4}]),
            lambda v:v['origin'].update(response_eof=False),lambda v:v.update(network_tested=False)):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_relay(changed,held,CONFIG,O,PAIR,END)


if __name__=='__main__':unittest.main()
