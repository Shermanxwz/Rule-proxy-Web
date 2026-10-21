import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
m=load('udp_adapter_test',ROOT/'.github/windows_n0a_udp_capture_adapter.py')
f=load('udp_flow_fixture',ROOT/'tests/test_windows_client_n0a_udp_flow.py')
p=load('udp_packet_fixture',ROOT/'tests/test_windows_client_n0a_udp_packet.py')
c=load('capture_facts_fixture',ROOT/'tests/test_windows_client_n0a_capture_adapter.py')

def pipeline(selected=False):
    value=f.value();raw=f.f.encode(value);expected=f.expected(value,raw);normalized=f.f.normalize(raw,expected);manifest=json.loads(normalized['manifest_bytes'])
    frames=[p.frame(r['source_port'],p.p.payload('a'*32,r['phase'],r['index']),dport=44000) for r in manifest['ordinary']]
    if selected:frames.insert(0,p.frame(42000,p.p.payload('a'*32,'contained',0),dport=44000))
    return raw,expected,p.pcap(frames)

def final(expected):
    original=dict(guest_result_provenance_verified=True,vm_destroyed=True)
    value=dict(expected['controller_result'],vm_destroyed=True,original_stage0_receipt_verified=True)
    value['host_receiver']=dict(cleanup_confirmed=True,error=False,contained_observed=False,counts=dict(datagrams=5,observed_bytes=300,verified=5,echoed=5,rejected=0,oversized=0,send_errors=0),verified_indices=dict(before=[0],sample=[0,1,2],contained=[],after=[0]))
    return original,value

class AdapterTests(unittest.TestCase):
    def test_real_flow_and_packet_pipeline_accepted_send_can_absence(self):
        raw,expected,data=pipeline()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'pcap';path.write_bytes(data)
            value=m.parse_before_cleanup(path,c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)
        self.assertEqual(value['status'],'bounded_no_selected_udp_datagram')
        original,receipt=final(expected);self.assertTrue(m.qualify(value,original,receipt)['packet']['bounded_no_selected_udp_datagram'])
        receipt['host_receiver']['cleanup_confirmed']=False
        self.assertFalse(m.qualify(value,original,receipt)['packet']['bounded_no_selected_udp_datagram'])
    def test_positive_survives_capture_and_host_failure(self):
        raw,expected,data=pipeline(True);facts=c.facts();facts['qemu_forced']=True
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'pcap';path.write_bytes(data)
            result=m.parse_before_cleanup(path,facts,raw,expected,header_before_link=True,terminal_before_shutdown=False)
        self.assertTrue(result['selected_payload_observed'])
        original,receipt=final(expected);original['vm_destroyed']=False;receipt['host_receiver']['contained_observed']=True
        final_result=m.qualify(result,original,receipt);self.assertTrue(final_result['selected_payload_observed']);self.assertTrue(final_result['receiver_selected_observed']);self.assertFalse(final_result['isolation_acceptance'])
    def test_unknown_exit_no_read_and_close_error_blocks_cleanup(self):
        raw,expected,data=pipeline();facts=c.facts();facts['child_exit_observed']=False
        with patch.object(m.helper('lifecycle'),'read_capture') as read:
            self.assertEqual(m.parse_before_cleanup(Path('missing'),facts,raw,expected,header_before_link=True,terminal_before_shutdown=True)['reason'],'capture_file');read.assert_not_called()
        with patch.object(m.helper('lifecycle'),'read_capture',side_effect=m.helper('lifecycle').CaptureReadCloseError()):
            self.assertFalse(m.parse_before_cleanup(Path('missing'),c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)['capture_read_cleanup_confirmed'])
    def test_commitment_missing_duplicate_and_wrong_digest(self):
        raw,expected,data=pipeline()
        for change,reason in ((None,'commitment_missing'),(dict(expected['flow_commitment'],sha256='0'*64),'body_digest')):
            expected['flow_commitment']=change
            self.assertEqual(m.parse_before_cleanup(Path('missing'),c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)['reason'],reason)
        with self.assertRaises(ValueError):m.validate_capture_envelope(dict(schema_version=2,legacy={},flow_commitment=None),{})
    def test_admission_unchanged_actual_payload_and_reserve(self):
        self.assertTrue(m.admit(24*1024**2,1024**3,0)['planning_only'])
        with self.assertRaises(ValueError):m.admit(24*1024**2+1,1024**3,0)
        with self.assertRaises(ValueError):m.admit(1,65*1024**2-1,0)
    def test_production_manifest_exact_test_only_refused(self):
        with tempfile.TemporaryDirectory() as root:
            actor=Path(root)/'windows_n0a_udp_actor.exe';actor.write_bytes(b'X'*512)
            manifest=Path(root)/'N0A-UDP-manifest.json'
            value=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,
                actorSourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp_actor.cpp').read_bytes()).hexdigest(),
                identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            manifest.write_text(json.dumps(value));self.assertTrue(m.verify_inputs(actor,manifest)['config']['enabled'])
            for key,bad in [('testOnly',True),('deployable',False),('schemaVersion',True),('actorSourceSha256','0'*64)]:
                changed=dict(value);changed[key]=bad;manifest.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):m.verify_inputs(actor,manifest)
    def test_entire_result_commitment_wire_bounded_and_strict(self):
        u=m.helper('control');from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        expected=dict(case_nonce='a'*32,actor_sha256='b'*64)
        launcher=dict(u.default_host_udp()['launcher'],phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True)
        result=u.evaluate({},None)
        report=dict(schema_version=1,binding=dict(expected,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase='completed',failed=False,cleanup_confirmed=True))
        outer=dict(schema_version=1,**expected,report=report,launcher=launcher)
        raw,context,data=pipeline();wrapper=dict(schema_version=3,udp=outer,flow_commitment=context['flow_commitment'])
        self.assertLessEqual(len(json.dumps(wrapper).encode()),4096);self.assertTrue(m.validate_capture_envelope(wrapper,expected)['legacy']['receipt_verified'])
        wrapper['udp']['report']['result']['runtime_acceptance']=True
        with self.assertRaises(ValueError):m.validate_capture_envelope(wrapper,expected)

class ReceiverConsistencyTests(unittest.TestCase):
    def test_positive_contradictions_and_impossible_counts_refuse_absence(self):
        raw,expected,data=pipeline();_,receipt=final(expected);receiver=receipt['host_receiver']
        self.assertTrue(m.receiver_complete(receiver))
        for key,value in [('contained_observed',True),('contained_observed',None)]:
            changed=copy.deepcopy(receiver);changed[key]=value;self.assertFalse(m.receiver_complete(changed))
        for key,value in [('verified',129),('echoed',6),('datagrams',4),('observed_bytes',646),('send_errors',1)]:
            changed=copy.deepcopy(receiver);changed['counts'][key]=value;self.assertFalse(m.receiver_complete(changed))
        for phase,indices in [('sample',[0,0,1]),('sample',[0,1,True]),('before',[]),('contained',[0])]:
            changed=copy.deepcopy(receiver);changed['verified_indices'][phase]=indices;self.assertFalse(m.receiver_complete(changed))

class WireBoundTests(unittest.TestCase):
    def test_full_maximal_legal_wire_and_nullable_exit_edges(self):
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        u=m.helper('control');old=u.tcp_helpers();expected=dict(case_nonce='a'*32,actor_sha256='b'*64)
        maximum=0
        for exit_code in (-2147483648,2147483647,None):
            for observed in (False,True,None):
                result=u.evaluate({},None);result['selected_send_accepted_count']=3
                launcher=dict(phase=max(old.LAUNCHER_PHASES,key=len),failure=max(old.LAUNCHER_FAILURES,key=len),python_exit_code=exit_code,process_exit_confirmed=observed,timed_out=False,budget_exhausted=False)
                report=dict(schema_version=1,binding=dict(expected,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase=max(old.EXECUTION_PHASES,key=len),failed=False,cleanup_confirmed=False))
                wrapper=dict(schema_version=3,udp=dict(schema_version=1,**expected,report=report,launcher=launcher),flow_commitment=dict(sha256='c'*64,bytes=65536,contained_report_sha256='d'*64,ordinary_report_sha256='e'*64))
                wire=json.dumps(wrapper,ensure_ascii=True).encode('ascii');maximum=max(maximum,len(wire))
                self.assertTrue(m.validate_capture_envelope(json.loads(wire),expected)['legacy']['receipt_verified'])
        self.assertEqual(maximum,1704);self.assertLessEqual(maximum,4096)

class DenialReceiptTests(unittest.TestCase):
    def test_launcher_cleanup_failure_preserves_bound_api_fact_not_controls(self):
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        u=m.helper('control');expected=dict(case_nonce='a'*32,actor_sha256='b'*64)
        result=u.evaluate({},None);result.update(explicit_send_denial=True,all_selected_sendto_invoked=True,ordinary_controls_verified=True,sockets_cleanup_confirmed=True)
        result['profile_verified']['contained']=True;result['provenance_verified']['contained']=True
        launcher=dict(u.default_host_udp()['launcher'],phase='python_wait',failure='timeout',timed_out=True,process_exit_confirmed=False,python_exit_code=None)
        report=dict(schema_version=1,binding=dict(expected,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase='cleanup',failed=True,cleanup_confirmed=False))
        value=u.validate_host_udp_envelope(dict(schema_version=1,**expected,report=report,launcher=launcher),expected)
        self.assertTrue(value['result']['explicit_send_denial']);self.assertFalse(value['result']['ordinary_controls_verified']);self.assertFalse(value['result']['sockets_cleanup_confirmed'])

class FlowDiagnosticTests(unittest.TestCase):
    def test_fixed_admission_states_and_normalization_are_distinct(self):
        raw,expected,data=pipeline();commitment=expected['flow_commitment']
        cases=[(raw,None,'commitment_missing'),(raw,{},'commitment_invalid'),(None,commitment,'body_missing'),
               ('PRIVATE_PATH_SECRET',commitment,'body_type'),(b'',commitment,'body_size'),
               (b'X'*len(raw),commitment,'body_digest'),(raw,commitment,'body_verified')]
        for body,meta,state in cases:
            self.assertEqual(m.flow_body_state(body,meta),state)
            if state!='body_verified':
                context=dict(expected,flow_commitment=meta)
                result=m.parse_before_cleanup(Path('PRIVATE_PATH_SECRET'),c.facts(),body,context,header_before_link=True,terminal_before_shutdown=True)
                self.assertEqual(result['reason'],state);self.assertIsNone(result['selected_payload_observed']);self.assertNotIn('PRIVATE_PATH_SECRET',json.dumps(result))
        self.assertEqual(m.parse_before_cleanup(Path('missing'),c.facts(),raw,None,header_before_link=True,terminal_before_shutdown=True)['reason'],'flow_context')
        with patch.object(m.helper('flow'),'normalize',side_effect=ValueError('PRIVATE_PATH_SECRET')):
            result=m.parse_before_cleanup(Path('missing'),c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)
        self.assertEqual(result['reason'],'normalization');self.assertNotIn('PRIVATE_PATH_SECRET',json.dumps(result))
    def test_transport_preserves_handler_invalid_commitment_discriminator(self):
        u=m.helper('control');source=u.default_host_udp();source['receipt_verified']=True
        source['result']['selected_send_accepted_count']=3;source['result']['selected_echo_observed']=True
        raw,expected,data=pipeline()
        server=SimpleNamespace(n0a_result=source,capture_commitment=None,capture_commitment_error=True,capture_private_body=None)
        result=m.compose(server,{},'received');self.assertEqual(result['flow_transport_state'],'commitment_invalid')
        self.assertEqual(result['result']['selected_send_accepted_count'],3);self.assertTrue(result['result']['selected_echo_observed'])
        server.capture_commitment_error=False
        self.assertEqual(m.compose(server,{},'received')['flow_transport_state'],'commitment_missing')
        server.capture_commitment=expected['flow_commitment']
        self.assertEqual(m.compose(server,{},'received')['flow_transport_state'],'body_missing')
        server.capture_private_body=raw
        self.assertEqual(m.compose(server,{},'received')['flow_transport_state'],'body_verified')
        self.assertEqual(m.compose(None,{},'not_started')['flow_transport_state'],'not_observed')
        self.assertNotIn('flow_transport_state',source)
    def test_unknown_reason_and_invalid_metadata_never_export_sentinel(self):
        value=m.unavailable('PRIVATE_PATH_SECRET');self.assertEqual(value['reason'],'unavailable')
        self.assertNotIn('PRIVATE_PATH_SECRET',json.dumps(value))
        for meta in ({'sha256':'PRIVATE_PATH_SECRET'},[],True,{'bytes':True}):
            self.assertEqual(m.flow_body_state(b'PRIVATE_PATH_SECRET',meta),'commitment_invalid')
