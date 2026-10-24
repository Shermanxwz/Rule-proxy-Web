"""Actual guest/flow loader composition; synthetic reports, no process or network."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module
g=load('udp_composed_guest',ROOT/'.github/windows_n0a_udp_guest.py')
f=g.flow_helpers()
a=load('udp_composed_adapter',ROOT/'.github/windows_n0a_udp_capture_adapter.py')
fixture=load('udp_composed_network_fixture',ROOT/'tests/test_windows_client_n0a_udp_flow.py')

class Composed(unittest.TestCase):
    def make(self):
        b=g.engine.UDPBinding('a'*32,'b'*64,'c'*64,'S-1-15-3-1',44000,1,False,False)
        cases={'driver_error':False,'cleanup_confirmed':True};snapshots={}
        nets=fixture.value()['reports']
        for phase in f.ROLES:
            net=copy.deepcopy(nets[phase]['udp'])
            if phase=='contained':
                for row in net['attempts']:row.update(nonceMatched=False,failure='recv_select',win32Error=10060)
            actor=dict(schemaVersion=1,mode='actor-n0a-udp',nonce=b.nonce,queriesSucceeded=True,errors=[],tokenElevated=False,pid=123,
                tokenIsAppContainer=phase=='contained',isProcessInJob=True,tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7' if phase=='contained' else None,
                tokenCapabilities=[{'sid':b.agentic_sid,'attributes':4}] if phase=='contained' else [],udp=net)
            cases[phase]=dict(nonce=b.nonce,actor_sha256=b.actor_sha256,executor_sha256=b.executor_sha256,build=b.build,ubr=b.ubr,
                actor=actor,pid_verified=True,pid_binding='executor_audit' if phase=='contained' else 'ordinary_handle',child_exit_code=0,
                probe={'tier':'base-container','needsDaclAugmentation':False,'probes':{'baseContainerApiPresent':True}},probe_exit_code=0,
                actual_tiers=['base-container'],exit_code=0,timed_out=False,harness_error=False)
            raw=f.encode(actor);snapshots[id(actor)]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        config={'actor_source_sha256':'d'*64,'identity_source_sha256':'e'*64}
        capture={'run_nonce':'f'*32,'source_commit':'1'*40,'vm_mac':'525400123456'}
        return b,cases,types.SimpleNamespace(snapshots=snapshots),config,capture
    def test_actual_guest_loader_prepare_file_commitment_host_normalize(self):
        self.assertIs(g.engine,f.engine())
        b,cases,execution,config,capture=self.make()
        result=g.engine.evaluate(cases,b)
        self.assertEqual(result['selected_send_accepted_count'],3)
        self.assertFalse(result['selected_echo_observed']);self.assertTrue(result['ordinary_controls_verified'])
        with tempfile.TemporaryDirectory() as root,patch.object(g,'ROOT',Path(root)):
            (Path(root)/'private-udp').mkdir()
            self.assertTrue(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            raw=(Path(root)/'private-udp/runner-flow.json').read_bytes()
        commit=f.commitment(raw);self.assertTrue(a.accept_private_body(raw,commit))
        bundle=f.bundle(raw)
        expected=dict(binding=bundle['binding'],endpoint=bundle['endpoint'],flow_commitment=commit,
            controller_result={'receipt_verified':True,'result':result},cleanup_verified=True)
        normalized=a.helper('flow').normalize(raw,expected)
        self.assertTrue(normalized['controls_verified'])
        self.assertEqual(len(a.helper('control').parse(normalized['manifest_bytes'])['selected']),3)
        self.assertFalse(a.accept_private_body(raw+b' ',commit))
    def test_actual_prepare_rejects_altered_bound_envelope(self):
        b,cases,execution,config,capture=self.make();cases['contained']['actor_sha256']='0'*64
        with tempfile.TemporaryDirectory() as root,patch.object(g,'ROOT',Path(root)):
            (Path(root)/'private-udp').mkdir()
            self.assertFalse(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            self.assertFalse((Path(root)/'private-udp/runner-flow.json').exists())
    def test_original_alias_counterexample_remains_rejected(self):
        other=load('udp_composed_wrong_alias',ROOT/'.github/windows_n0a_udp.py')
        b,cases,_,_,_=self.make();wrong=other.UDPBinding(**vars(b))
        self.assertTrue(wrong.valid());self.assertIsNotNone(other.bound_actor(cases['contained'],wrong))
        self.assertIsNone(g.engine.bound_actor(cases['contained'],wrong))
    def test_cache_wrong_path_spec_digest_and_class_fail_closed(self):
        module=f.engine()
        for target,key,value in [(module,'__file__','wrong'),(module.__spec__,'origin','wrong'),
                (module.__spec__,'name','wrong'),(module,'_udp_source_sha256','0'*64),
                (module.UDPBinding,'__module__','wrong')]:
            with patch.object(target,key,value):
                with self.assertRaises(ValueError):f.engine()
            self.assertIs(f.engine(),module)

if __name__=='__main__':unittest.main()
