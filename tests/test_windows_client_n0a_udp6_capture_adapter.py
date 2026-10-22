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
m=load('udp6_adapter_test',ROOT/'.github/windows_n0a_udp6_capture_adapter.py')
f=load('udp6_flow_fixture',ROOT/'tests/test_windows_client_n0a_udp6_flow.py')
p=load('udp6_packet_fixture',ROOT/'tests/test_windows_client_n0a_udp6_packet.py')
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
    value['mapped_provenance']=dict(schema_version=1,failure=False,admitted=True,pre_stop_verified=True,close_confirmed=True)
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
            actor=Path(root)/'windows_n0a_udp6_actor.exe';actor.write_bytes(b'X'*512)
            manifest=Path(root)/'N0A-UDP6-manifest.json'
            value=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,
                actorSourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp6_actor.cpp').read_bytes()).hexdigest(),
                identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            manifest.write_text(json.dumps(value));self.assertTrue(m.verify_inputs(actor,manifest)['config']['enabled'])
            for key,bad in [('testOnly',True),('deployable',False),('schemaVersion',True),('actorSourceSha256','0'*64)]:
                changed=dict(value);changed[key]=bad;manifest.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):m.verify_inputs(actor,manifest)
    def test_entire_result_commitment_wire_bounded_and_strict(self):
        u=m.helper('control');from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        expected=dict(case_nonce='a'*32,actor_sha256='b'*64)
        launcher=dict(u.default_host_udp6()['launcher'],phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True)
        result=u.evaluate({},None)
        report=dict(schema_version=1,binding=dict(expected,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase='completed',failed=False,cleanup_confirmed=True))
        outer=dict(schema_version=1,**expected,report=report,launcher=launcher)
        raw,context,data=pipeline();wrapper=dict(schema_version=5,udp6=outer,flow_commitment=context['flow_commitment'])
        self.assertLessEqual(len(json.dumps(wrapper).encode()),4096);self.assertTrue(m.validate_capture_envelope(wrapper,expected)['legacy']['receipt_verified'])
        wrapper['udp6']['report']['result']['runtime_acceptance']=True
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
                wrapper=dict(schema_version=5,udp6=dict(schema_version=1,**expected,report=report,launcher=launcher),flow_commitment=dict(sha256='c'*64,bytes=65536,contained_report_sha256='d'*64,ordinary_report_sha256='e'*64))
                wire=json.dumps(wrapper,ensure_ascii=True).encode('ascii');maximum=max(maximum,len(wire))
                self.assertTrue(m.validate_capture_envelope(json.loads(wire),expected)['legacy']['receipt_verified'])
        self.assertGreater(maximum,1600);self.assertLessEqual(maximum,4096)

class DenialReceiptTests(unittest.TestCase):
    def test_launcher_cleanup_failure_preserves_bound_api_fact_not_controls(self):
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        u=m.helper('control');expected=dict(case_nonce='a'*32,actor_sha256='b'*64)
        result=u.evaluate({},None);result.update(explicit_send_denial=True,all_selected_sendto_invoked=True,ordinary_controls_verified=True,sockets_cleanup_confirmed=True)
        result['profile_verified']['contained']=True;result['provenance_verified']['contained']=True
        launcher=dict(u.default_host_udp6()['launcher'],phase='python_wait',failure='timeout',timed_out=True,process_exit_confirmed=False,python_exit_code=None)
        report=dict(schema_version=1,binding=dict(expected,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase='cleanup',failed=True,cleanup_confirmed=False))
        value=u.validate_host_udp6_envelope(dict(schema_version=1,**expected,report=report,launcher=launcher),expected)
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
        u=m.helper('control');source=u.default_host_udp6();source['receipt_verified']=True
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

class ProvenanceTests(unittest.TestCase):
    def test_mapped_uncertainty_prevents_absence_never_erases_positive(self):
        raw,expected,data=pipeline()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'pcap';path.write_bytes(data)
            tentative=m.parse_before_cleanup(path,c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)
        original,receipt=final(expected)
        for key in ('admitted','pre_stop_verified','close_confirmed'):
            changed=copy.deepcopy(receipt);changed['mapped_provenance'][key]=False
            self.assertFalse(m.qualify(tentative,original,changed)['packet']['bounded_no_selected_udp_datagram'])
        for change in ({'failure':True},{'failure':None},{'schema_version':True},{'schema_version':2}):
            changed=copy.deepcopy(receipt);changed['mapped_provenance'].update(change)
            self.assertFalse(m.qualify(tentative,original,changed)['packet']['bounded_no_selected_udp_datagram'])
        positive=copy.deepcopy(tentative);positive['selected_payload_observed']=True
        receipt['mapped_provenance']=None
        self.assertTrue(m.qualify(positive,original,receipt)['selected_payload_observed'])
    def test_canonical_loader_and_exact_ipv6_context(self):
        self.assertIs(m.helper('control'),m.helper('flow').engine())
        raw,expected,_=pipeline();b=expected['binding']
        config={key:b[key] for key in ('case_nonce','actor_sha256','actor_source_sha256','identity_source_sha256')};config['runner_port']=44000
        capture=dict(run_nonce=b['run_nonce'],source_commit=b['source_commit'],vm_mac=expected['endpoint']['vm_mac'])
        server=SimpleNamespace(capture_commitment=expected['flow_commitment'],n0a_result=expected['controller_result'])
        context=m.flow_context(capture,config,server,True)
        self.assertEqual(context['endpoint'],expected['endpoint'])
        self.assertNotIn('destination_ipv4',context['endpoint'])

# Reuse the already reviewed bounded owned verifier lifecycle. The isolated
# program still imports the actual host entry and verifies actual artifact bytes.
verifier=load('udp6_owned_isolated_verifier',ROOT/'tests/test_windows_client_n0a_udp_parent_capture_adapter.py')
ISOLATED_VERIFY=verifier.ISOLATED_VERIFY.replace(
    "value=host.parent_udp_capture_helpers().verify_inputs(*(pathlib.Path(p) for p in sys.argv[2:6]))",
    "adapter=host.udp6_capture_helpers();value=adapter.verify_inputs(*(pathlib.Path(p) for p in sys.argv[2:4]));value['config']['executor_sha256']=adapter.runtime_executor_pin()")
def isolated_verify_inputs(actor,manifest,poison=False):
    with patch.object(verifier,'ISOLATED_VERIFY',ISOLATED_VERIFY):
        return verifier.isolated_verify_inputs(actor,manifest,actor,manifest,poison=poison)

class IsolatedTests(unittest.TestCase):
    def test_actual_script_entry_without_ambient_root(self):
        with verifier.isolated_fixture_root() as root:
            actor=root/'windows_n0a_udp6_actor.exe';actor.write_bytes(b'X'*512)
            manifest=root/'N0A-UDP6-manifest.json'
            value=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,
                actorSourceSha256=hashlib.sha256((ROOT/'.github/native/windows_n0a_udp6_actor.cpp').read_bytes()).hexdigest(),
                identitySourceSha256=hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            manifest.write_text(json.dumps(value))
            for poison in (False,True):
                code,result=isolated_verify_inputs(actor,manifest,poison)
                self.assertEqual(code,0);self.assertTrue(result['inputs_verified']);self.assertTrue(result['root_absent_after']);self.assertTrue(result['verifier_cleanup']['cleanup_confirmed'])
            value['testOnly']=True;manifest.write_text(json.dumps(value))
            code,result=isolated_verify_inputs(actor,manifest)
            self.assertEqual(code,1);self.assertFalse(result['inputs_verified'])

class FullBoundaryTests(unittest.TestCase):
    def test_actual_loaders_audit_snapshot_receipt_body_packet_and_qualification(self):
        from dataclasses import replace
        fixture=load('udp6_full_boundary',ROOT/'tests/test_windows_udp6_flow_composed.py')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);b,cases,execution,config,capture=fixture.Composed().collected(root)
            b=replace(b,executor_sha256=m.runtime_executor_pin())
            for phase in fixture.f.ROLES:cases[phase]['executor_sha256']=b.executor_sha256
            raw=fixture.f.build_bundle({'capture':capture,'n0a_udp6':config},b,cases,execution.snapshots)
            result=fixture.g.engine.evaluate(cases,b)
            launcher=dict(phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True,timed_out=False,budget_exhausted=False)
            report=dict(schema_version=1,binding=dict(case_nonce=b.nonce,actor_sha256=b.actor_sha256,executor_sha256=b.executor_sha256,build=b.build,ubr=b.ubr),result=result,execution=dict(phase='completed',failed=False,cleanup_confirmed=True))
            envelope=dict(schema_version=5,udp6=dict(schema_version=1,case_nonce=b.nonce,actor_sha256=b.actor_sha256,report=report,launcher=launcher),flow_commitment=fixture.f.commitment(raw))
            admitted=m.validate_capture_envelope(envelope,dict(case_nonce=b.nonce,actor_sha256=b.actor_sha256))
            self.assertTrue(m.accept_private_body(raw,admitted['commitment']))
            config.update(case_nonce=b.nonce,actor_sha256=b.actor_sha256,runner_port=b.runner_port)
            server=SimpleNamespace(capture_commitment=admitted['commitment'],n0a_result=admitted['legacy'])
            expected=m.flow_context(capture,config,server,True)
            normalized=m.helper('flow').normalize(raw,expected);manifest=json.loads(normalized['manifest_bytes'])
            frames=[p.frame(r['source_port'],p.p.payload(b.nonce,r['phase'],r['index']),dport=b.runner_port) for r in manifest['ordinary']]
            path=root/'capture';path.write_bytes(p.pcap(frames))
            tentative=m.parse_before_cleanup(path,c.facts(),raw,expected,header_before_link=True,terminal_before_shutdown=True)
            original,receipt=final(expected)
            self.assertTrue(m.qualify(tentative,original,receipt)['packet']['bounded_no_selected_udp_datagram'])
            self.assertEqual(receipt['result']['selected_send_accepted_count'],3)
            receipt['mapped_provenance']['pre_stop_verified']=False
            self.assertFalse(m.qualify(tentative,original,receipt)['packet']['bounded_no_selected_udp_datagram'])
            self.assertEqual(receipt['result']['selected_send_accepted_count'],3)
            self.assertEqual(m.parse_before_cleanup(path,c.facts(),None,expected,header_before_link=True,terminal_before_shutdown=True)['reason'],'body_missing')

class CaptureDiagnosticTests(unittest.TestCase):
    @staticmethod
    def facts():
        value=c.facts();value.update(schema_version=1,fixture=False,execution_model='owned_child')
        value['capture'].update(retained=67108864,drained=2**64-1,overflow=True)
        value['drain_complete']=False
        return value

    def test_snapshot_available_without_flow_and_unknown_is_null(self):
        facts=self.facts()
        value=m.parse_before_cleanup(Path('unused'),facts,None,None,header_before_link=False,terminal_before_shutdown=False)
        self.assertEqual(value['reason'],'flow_context')
        self.assertEqual(value['capture_diagnostic']['drained'],2**64-1)
        self.assertEqual(value['capture_diagnostic']['limit_bytes'],67108864)
        self.assertIsNone(value['packet'])
        facts['final_status_observed']=False
        self.assertFalse(m.capture_diagnostic(facts)['final_status_observed'])
        for bad in (None,{},dict(facts,capture=None)):
            self.assertIsNone(m.capture_diagnostic(bad))

    def test_exact_types_bounds_and_contradictions(self):
        facts=self.facts();self.assertIsNotNone(m.capture_diagnostic(facts))
        changes=[('fixture',True),('fixture',0),('execution_model','owner_threads'),('schema_version',True),('schema_version',2),('descriptors_closed',False),
                 ('drain_complete',True),('status_eof',1)]
        for key,value in changes:
            bad=copy.deepcopy(facts);bad[key]=value
            self.assertIsNone(m.capture_diagnostic(bad),(key,value))
        for key,value in [('retained',True),('retained',-1),('retained',67108865),
                          ('drained',0),('drained',2**64),('overflow',1)]:
            bad=copy.deepcopy(facts);bad['capture'][key]=value
            self.assertIsNone(m.capture_diagnostic(bad),(key,value))
        bad=copy.deepcopy(facts);bad['capture']['drained']=67108864
        self.assertIsNone(m.capture_diagnostic(bad))
        # A write failure can make drained exceed capacity without filling the
        # retained file; no invented overflow equivalence.
        bad['capture'].update(retained=0,overflow=False)
        self.assertIsNotNone(m.capture_diagnostic(bad))

    def test_diagnostic_survives_read_and_normalization_errors(self):
        raw,expected,_=pipeline();facts=self.facts()
        for error in (OSError('PRIVATE'),m.helper('lifecycle').CaptureReadCloseError()):
            with patch.object(m.helper('lifecycle'),'read_capture',side_effect=error):
                result=m.parse_before_cleanup(Path('SECRET'),facts,raw,expected,header_before_link=False,terminal_before_shutdown=False)
            self.assertEqual(result['capture_diagnostic'],m.capture_diagnostic(facts))
            self.assertNotIn('PRIVATE',json.dumps(result));self.assertNotIn('SECRET',json.dumps(result))
        with patch.object(m.helper('flow'),'normalize',side_effect=ValueError('SECRET')):
            result=m.parse_before_cleanup(Path('unused'),facts,raw,expected,header_before_link=False,terminal_before_shutdown=False)
        self.assertEqual(result['reason'],'normalization');self.assertIsNotNone(result['capture_diagnostic'])

    def test_malformed_diagnostic_cannot_erase_selected_positive(self):
        raw,expected,data=pipeline(True);facts=self.facts();facts['capture']['retained']=True
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'pcap';path.write_bytes(data)
            result=m.parse_before_cleanup(path,facts,raw,expected,header_before_link=False,terminal_before_shutdown=False)
        self.assertIsNone(result['capture_diagnostic']);self.assertTrue(result['selected_payload_observed'])
        original,receipt=final(expected);receipt['vm_destroyed']=False
        self.assertTrue(m.qualify(result,original,receipt)['selected_payload_observed'])

class HostProjectionSizeTests(unittest.TestCase):
    @staticmethod
    def upper_projection():
        raw,expected,data=pipeline(True)
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'pcap';path.write_bytes(data)
            result=m.parse_before_cleanup(path,CaptureDiagnosticTests.facts(),raw,expected,header_before_link=False,terminal_before_shutdown=False)
        original,receipt=final(expected);result=m.qualify(result,original,receipt)
        packet=result['packet']
        result['status']='bounded_no_selected_udp_datagram'
        for key,value in result['capture_diagnostic'].items():
            if type(value) is bool:result['capture_diagnostic'][key]=False
        # Conservative serialization upper composition: these maxima need not
        # coexist in one capture. This is not a fabricated valid packet trace.
        for obj in (result,packet):
            for key,value in obj.items():
                if type(value) is bool:obj[key]=False
        packet.update(status='bounded_no_selected_udp_datagram',selected_payload_count=3,
                      unknown_flow_packets=262144,records=262144)
        packet['reasons']=sorted({'binding','manifest','capture_bound','header','record_bound','truncated','record','frame_bound','ethernet','encapsulation','ipv6','jumbo_unsupported','fragment','opaque_protocol','extension_bound','hop_order','extension','routing_unsupported','udp','payload_port_mismatch','payload_mismatch','unknown_flow','empty','port_collision','port_unavailable','controls','cleanup','send_unattempted','capture_lifecycle','ordinary_payload','host_prerequisites'})
        packet['decoder_diagnostic']=dict(v=1,opaque_next_header_counts=[[i,262144] for i in range(240,256)],
            omitted_category_count=240,omitted_event_count=262144,detail_complete=False,truncated_counts=[1,262144,1])
        return result

    def test_packet_projection_compact_pretty_and_host_nested_bound(self):
        value=self.upper_projection()
        compact=json.dumps(value,separators=(',',':')).encode('ascii')
        pretty=(json.dumps(value,indent=2)+'\n').encode('ascii')
        # Actual host writer nests this under packet; account for its extra
        # indentation too, not only a convenient compact representation.
        nested=(json.dumps({'packet':value},indent=2)+'\n').encode('ascii')
        self.assertLessEqual(len(compact),4096)
        self.assertLessEqual(len(pretty),4096)
        self.assertLessEqual(len(nested),4096)
        self.assertEqual(len(value['packet']['decoder_diagnostic']['opaque_next_header_counts']),16)

    @staticmethod
    def full_host_upper():
        # Independent field maxima, not a jointly valid semantic report.
        u=m.helper('control');value=u.default_host_udp6()
        value['packet']=HostProjectionSizeTests.upper_projection()
        value['result']['selected_send_accepted_count']=3
        d=value['result']['diagnostic']
        d.update(stage=max(u.DIAGNOSTIC_STAGES,key=len),failed_stage=max(u.DIAGNOSTIC_STAGES,key=len),failure='operation')
        d['phases']=[[False]*6+['unavailable','unavailable'] for _ in range(4)]
        d['before']=dict(context=[1,1023,1023],checks=[False]*13,validation=max(u.VALIDATION_REASONS,key=len),network=[4294967295,False,40],
            attempt=[False]*5+[-2147483648,4294967295,-2147483648,4294967295,'length_mismatch',False,128,False,4294967295,max(u.FAILURES,key=len),False,4294967295]+[False]*6)
        u.validate_diagnostic(d)
        old=u.tcp_helpers()
        value['reason']=max(old.LAUNCHER_FAILURES,key=len)
        value['execution']=dict(phase=max(old.EXECUTION_PHASES,key=len),failed=False,cleanup_confirmed=False)
        value['launcher']=dict(phase=max(old.LAUNCHER_PHASES,key=len),failure=max(old.LAUNCHER_FAILURES,key=len),python_exit_code=-2147483648,process_exit_confirmed=False,timed_out=False,budget_exhausted=False)
        value.update(flow_transport_state='commitment_invalid',original_stage0_receipt_verified=False,vm_destroyed=False,host_wait_state='capture_body_deadline')
        value['host_receiver']=dict(thread_stopped=False,socket_closed=False,datagram_observed=False,cleanup_confirmed=False,socket_cleanup_confirmed=False,error=True,endpoint_error=True,contained_observed=True,
            counts=dict(datagrams=128,observed_bytes=16512,verified=128,echoed=128,rejected=128,oversized=128,send_errors=128),
            verified_indices=dict(before=[0],sample=list(range(40)),contained=[0,1,2],after=[0]))
        metadata=lambda name:dict(sha256='f'*64,name=name,architecture='amd64',version='9'*128,local_integrity_verified=False)
        value['mapped_provenance']=dict(schema_version=1,admitted=False,pre_stop_verified=False,close_confirmed=False,
            qemu=metadata('qemu-system-x86'),libslirp=metadata('libslirp0'),failure=True,resident_bytes_verified=False,source_equivalence_verified=False)
        return value

    def test_full_host_actual_serialization_is_measured_not_guest_wire_capped(self):
        value=self.full_host_upper();raw=(json.dumps(value,indent=2)+'\n').encode('ascii')
        self.assertEqual(json.loads(raw),value)
        # The full host artifact is not the 4096-byte guest envelope or packet
        # projection. No production writer cap is introduced or claimed here.
        self.assertGreater(len(raw),4096)
        self.assertIn('capture_diagnostic',value['packet'])

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Isolated UDP6 production artifact verification; no PE execution')
    parser.add_argument('--verify-production-inputs',action='store_true',required=True)
    parser.add_argument('--actor',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True)
    args=parser.parse_args()
    try:
        observations=[isolated_verify_inputs(args.actor,args.manifest,p) for p in (False,True)]
        okay=all(code==0 for code,_ in observations)
        print(json.dumps(dict(schema_version=1,isolated_production_inputs_verified=okay,observations=[v for _,v in observations],network_executed=False,vm_executed=False),separators=(',',':')))
        raise SystemExit(0 if okay else 1)
    except Exception:
        print('{"schema_version":1,"isolated_production_inputs_verified":false,"failure":"verification","network_executed":false,"vm_executed":false}')
        raise SystemExit(1)
