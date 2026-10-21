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
m=load('parent_adapter_test',ROOT/'.github/windows_n0a_udp_parent_capture_adapter.py')

def receipt():
    phases=('before','sample','contained','after')
    result={k:{p:True for p in phases} for k in ('profile_verified','provenance_verified','chain_verified')}
    result.update(ordinary_controls_verified=True,all_selected_sendto_invoked=True,sockets_cleanup_confirmed=True,descendant_cleanup_confirmed=True)
    receiver=dict(cleanup_confirmed=True,error=False,contained_observed=False,counts=dict(datagrams=5,observed_bytes=300,verified=5,echoed=5,rejected=0,oversized=0,send_errors=0),verified_indices=dict(before=[0],sample=[0,1,2],contained=[],after=[0]))
    return dict(receipt_verified=True,vm_destroyed=True,result=result,host_receiver=receiver)
class AdapterTests(unittest.TestCase):
    def test_missing_chain_or_descendant_cleanup_cannot_authorize_absence(self):
        original=dict(guest_result_provenance_verified=True,vm_destroyed=True)
        tentative=m.unavailable();tentative.update(status='bounded_no_selected_udp_datagram',packet=dict(bounded_no_selected_udp_datagram=True,status='bounded_no_selected_udp_datagram',reasons=[]))
        good=receipt();self.assertTrue(m.qualify(tentative,original,good)['host_prerequisites_verified'])
        for change in ('chain','cleanup','receiver','vm'):
            bad=copy.deepcopy(good)
            if change=='chain':bad['result']['chain_verified']['contained']=False
            elif change=='cleanup':bad['result']['descendant_cleanup_confirmed']=False
            elif change=='receiver':bad['host_receiver']['cleanup_confirmed']=False
            else:bad['vm_destroyed']=False
            result=m.qualify(tentative,original,bad)
            self.assertFalse(result['host_prerequisites_verified']);self.assertFalse(result['packet']['bounded_no_selected_udp_datagram'])
    def test_positive_bytes_and_receiver_survive_cleanup_failure(self):
        original=dict(guest_result_provenance_verified=False,vm_destroyed=False);value=receipt();value['host_receiver']['contained_observed']=True
        tentative=m.unavailable();tentative.update(selected_payload_observed=True,packet=dict(bounded_no_selected_udp_datagram=False,status='selected_udp_datagram',reasons=[]))
        result=m.qualify(tentative,original,value);self.assertTrue(result['selected_payload_observed']);self.assertTrue(result['receiver_selected_observed']);self.assertFalse(result['isolation_acceptance'])
    def test_missing_wrong_type_digest_and_normalizer_closed_reasons(self):
        raw=b'{}';commit=dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=2,contained_report_sha256='a'*64,ordinary_report_sha256='b'*64)
        for body,commitment,reason in ((raw,None,'commitment_missing'),(None,commit,'body_missing'),('PRIVATE',commit,'body_type'),(b'x',commit,'body_size'),(b'xx',commit,'body_digest')):
            result=m.parse_before_cleanup(Path('PRIVATE'),{},body,dict(flow_commitment=commitment),header_before_link=False,terminal_before_shutdown=False)
            self.assertEqual(result['reason'],reason);self.assertNotIn('PRIVATE',json.dumps(result))
        with patch.object(m.helper('flow'),'normalize',side_effect=ValueError('PRIVATE')):
            self.assertEqual(m.parse_before_cleanup(Path('PRIVATE'),{},raw,dict(flow_commitment=commit),header_before_link=False,terminal_before_shutdown=False)['reason'],'normalization')
    def test_exact_production_pair_pins_and_no_test_only(self):
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);parent=root/'windows_n0a_udp_parent.exe';parent.write_bytes(b'P'*512)
            child=root/'windows_n0a_udp_actor.exe';child.write_bytes(b'C'*512)
            cm=root/'N0A-UDP-manifest.json';pm=root/'N0A-UDP-PARENT-manifest.json'
            digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
            common=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,identitySourceSha256=digest(ROOT/'.github/native/windows_identity_actor.cpp'))
            cv=dict(common,actorSourceSha256=digest(ROOT/'.github/native/windows_n0a_udp_actor.cpp'),executableSha256=digest(child));cm.write_text(json.dumps(cv))
            pv=dict(common,parentSourceSha256=digest(ROOT/'.github/native/windows_n0a_udp_parent.cpp'),childActorSourceSha256=cv['actorSourceSha256'],executableSha256=digest(parent));pm.write_text(json.dumps(pv))
            value=m.verify_inputs(parent,pm,child,cm);self.assertEqual(value['config']['child_sha256'],digest(child));self.assertEqual(value['config']['parent_sha256'],digest(parent))
            for key,bad in [('testOnly',True),('deployable',False),('childActorSourceSha256','0'*64),('parentSourceSha256','0'*64)]:
                changed=dict(pv);changed[key]=bad;pm.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):m.verify_inputs(parent,pm,child,cm)
    def test_context_does_not_alias_parent_to_child_actor_hash(self):
        config={k:'a'*64 for k in ('parent_sha256','child_sha256','parent_manifest_sha256','child_manifest_sha256','parent_source_sha256','child_source_sha256','identity_source_sha256','executor_sha256')};config.update(case_nonce='a'*32,runner_port=40000)
        value=m.flow_context(dict(run_nonce='b'*32,source_commit='c'*40,vm_mac='020000000001'),config,SimpleNamespace(capture_commitment=None,n0a_result=None),False)
        self.assertNotIn('actor_sha256',value['binding']);self.assertIn('parent_sha256',value['binding']);self.assertIn('child_sha256',value['binding']);self.assertFalse(value['cleanup_verified'])
    def test_same_capacity_limits(self):
        self.assertTrue(m.admit(24*1024**2,1024**3,0)['planning_only'])
        with self.assertRaises(ValueError):m.admit(24*1024**2+1,1024**3,0)

class ComposedPipelineTests(unittest.TestCase):
    def pipeline(self,selected=False):
        f=load('parent_adapter_composed',ROOT/'tests/test_windows_udp_parent_composed.py')
        packet=load('parent_packet_frames',ROOT/'tests/test_windows_client_n0a_udp_packet.py')
        b,cases,execution,config,capture=f.candidate()
        raw=f.f.build_bundle({'capture':capture,'n0a_udp_parent':config},b,cases,execution.snapshots)
        value=f.f.bundle(raw);result=f.c.evaluate(cases,b)
        expected=dict(binding=value['binding'],endpoint=value['endpoint'],flow_commitment=f.f.commitment(raw),controller_result=dict(receipt_verified=True,result=result),cleanup_verified=True)
        normalized=f.f.normalize(raw,expected);manifest=json.loads(normalized['manifest_bytes'])
        frames=[packet.frame(r['source_port'],packet.p.payload(b.nonce,r['phase'],r['index']),dport=b.runner_port) for r in manifest['ordinary']]
        if selected:frames.insert(0,packet.frame(manifest['selected'][0]['source_port'],packet.p.payload(b.nonce,'contained',0),dport=b.runner_port))
        facts=load('parent_capture_facts',ROOT/'tests/test_windows_client_n0a_capture_adapter.py').facts()
        return raw,expected,packet.pcap(frames),facts
    def test_actual_loader_chain_to_commitment_to_packet_and_final_cleanup(self):
        raw,expected,data,facts=self.pipeline()
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture';path.write_bytes(data)
            result=m.parse_before_cleanup(path,facts,raw,expected,header_before_link=True,terminal_before_shutdown=True)
        self.assertEqual(result['status'],'bounded_no_selected_udp_datagram',result)
        original=dict(guest_result_provenance_verified=True,vm_destroyed=True);public=receipt();public['result']=expected['controller_result']['result']
        self.assertTrue(m.qualify(result,original,public)['packet']['bounded_no_selected_udp_datagram'])
        public['result']['descendant_cleanup_confirmed']=False
        self.assertFalse(m.qualify(result,original,public)['packet']['bounded_no_selected_udp_datagram'])
    def test_actual_bound_packet_survives_forced_capture_and_cleanup_failure(self):
        raw,expected,data,facts=self.pipeline(True);facts['qemu_forced']=True
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'capture';path.write_bytes(data)
            result=m.parse_before_cleanup(path,facts,raw,expected,header_before_link=True,terminal_before_shutdown=False)
        self.assertTrue(result['selected_payload_observed']);self.assertFalse(m.qualify(result,{},receipt())['isolation_acceptance'])
