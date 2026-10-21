"""Actual guest/flow loader composition; synthetic reports, no process or network."""
import copy
import io
import json
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
g=load('udp6_composed_guest',ROOT/'.github/windows_n0a_udp6_guest.py')
f=g.flow_helpers()

fixture=load('udp6_composed_network_fixture',ROOT/'tests/test_windows_client_n0a_udp6_flow.py')

class Composed(unittest.TestCase):
    def make(self):
        b=g.engine.UDP6Binding('a'*32,'b'*64,'c'*64,'S-1-15-3-1',44000,1,False,False)
        cases={'driver_error':False,'cleanup_confirmed':True};snapshots={}
        nets=fixture.value()['reports']
        for phase in f.ROLES:
            net=copy.deepcopy(nets[phase]['udp6'])
            if phase=='contained':
                for row in net['attempts']:row.update(nonceMatched=False,failure='recv_select',win32Error=10060)
            actor=dict(schemaVersion=1,mode='actor-n0a-udp6',nonce=b.nonce,queriesSucceeded=True,errors=[],tokenElevated=False,pid=123,
                tokenIsAppContainer=phase=='contained',isProcessInJob=True,tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7' if phase=='contained' else None,
                tokenCapabilities=[{'sid':b.agentic_sid,'attributes':4}] if phase=='contained' else [],udp6=net)
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
            (Path(root)/'private-udp6').mkdir()
            self.assertTrue(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            raw=(Path(root)/'private-udp6/runner-flow.json').read_bytes()
        commit=f.commitment(raw);self.assertEqual(commit['sha256'],hashlib.sha256(raw).hexdigest())
        bundle=f.bundle(raw)
        expected=dict(binding=bundle['binding'],endpoint=bundle['endpoint'],flow_commitment=commit,
            controller_result={'receipt_verified':True,'result':result},cleanup_verified=True)
        normalized=f.normalize(raw,expected)
        self.assertTrue(normalized['controls_verified'])
        self.assertEqual(len(g.engine.parse(normalized['manifest_bytes'])['selected']),3)
        self.assertNotEqual(hashlib.sha256(raw+b' ').hexdigest(),commit['sha256'])
    def test_actual_prepare_rejects_altered_bound_envelope(self):
        b,cases,execution,config,capture=self.make();cases['contained']['actor_sha256']='0'*64
        with tempfile.TemporaryDirectory() as root,patch.object(g,'ROOT',Path(root)):
            (Path(root)/'private-udp6').mkdir()
            self.assertFalse(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            self.assertFalse((Path(root)/'private-udp6/runner-flow.json').exists())
    def test_original_alias_counterexample_remains_rejected(self):
        other=load('udp6_composed_wrong_alias',ROOT/'.github/windows_n0a_udp6.py')
        b,cases,_,_,_=self.make();wrong=other.UDP6Binding(**vars(b))
        self.assertTrue(wrong.valid());self.assertIsNotNone(other.bound_actor(cases['contained'],wrong))
        self.assertIsNone(g.engine.bound_actor(cases['contained'],wrong))
    def test_cache_wrong_path_spec_digest_and_class_fail_closed(self):
        module=f.engine()
        for target,key,value in [(module,'__file__','wrong'),(module.__spec__,'origin','wrong'),
                (module.__spec__,'name','wrong'),(module,'_udp6_source_sha256','0'*64),
                (module.UDP6Binding,'__module__','wrong')]:
            with patch.object(target,key,value):
                with self.assertRaises(ValueError):f.engine()
            self.assertIs(f.engine(),module)

    def collected(self,root,*,wrong_pid=False,unknown_exit=False):
        from tests.test_windows_client_n0a_udp6_guest import Process
        b,source,_,config,capture=self.make()
        execution=g.WindowsExecution.__new__(g.WindowsExecution)
        execution.binding=b;execution.capture=True;execution.snapshots={};execution.owned=[]
        execution.deadline=time.monotonic()+20;execution.pin=lambda:None
        execution.cases={'runner-v6':{'directory':root,'profile':root,
            'probe':source['contained']['probe'],'probe_exit':0}}
        cases={'driver_error':False,'cleanup_confirmed':True}
        for phase in f.ROLES:
            actor=copy.deepcopy(source[phase]['actor']);actor['pid']=200 if phase=='contained' else 100
            report=root/(phase+'.json');raw=b' '+f.encode(actor)+b'\n';report.write_bytes(raw)
            process=Process(kill_failure=unknown_exit,alive=unknown_exit);process.pid=900 if phase=='contained' else 100;process.returncode=None if unknown_exit else 0
            if unknown_exit:process.wait=lambda timeout:(_ for _ in ()).throw(OSError('fixture'))
            owned=dict(process=process,out=io.BytesIO(),err=io.BytesIO(),role='contained' if phase=='contained' else 'ordinary',
                endpoint='runner-v6',report=report,timed_out=False,cleanup=False)
            if phase=='contained':
                audit=root/'audit';event={'event':'mxc.ProcessExited','backend':'processcontainer','identity':'redacted',
                    'tier':'base-container','pid':900 if wrong_pid else 200,'exit_code':0}
                audit.write_bytes(('[1] '+json.dumps(event)+'\n').encode('utf-8'))
                st=audit.stat();owned.update(audit=audit,audit_identity=(st.st_dev,st.st_ino))
            execution.owned.append(owned);cases[phase]=execution.wait(owned,1)
            parsed=cases[phase]['actor'];snapshot=execution.snapshots[id(parsed)]
            self.assertEqual(snapshot,dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw)))
        cases['cleanup_confirmed']=execution.finish()
        return b,cases,execution,config,capture
    def test_inherited_wait_actual_audit_snapshot_to_packet(self):
        packet_fixture=load('udp6_composed_packet_fixture',ROOT/'tests/test_windows_client_n0a_udp6_packet.py')
        with tempfile.TemporaryDirectory() as directory,patch.object(g,'ROOT',Path(directory)):
            root=Path(directory);(root/'private-udp6').mkdir()
            b,cases,execution,config,capture=self.collected(root)
            self.assertEqual(cases['contained']['actor']['pid'],200)
            self.assertEqual(cases['contained']['pid_binding'],'executor_audit')
            self.assertTrue(cases['contained']['pid_verified'])
            result=g.engine.evaluate(cases,b);self.assertEqual(result['selected_send_accepted_count'],3)
            self.assertTrue(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            raw=(root/'private-udp6/runner-flow.json').read_bytes();v=f.bundle(raw)
        normalized=f.normalize(raw,dict(binding=v['binding'],endpoint=v['endpoint'],flow_commitment=f.commitment(raw),
            controller_result=dict(receipt_verified=True,result=result),cleanup_verified=True))
        m=json.loads(normalized['manifest_bytes']);pf=packet_fixture
        frames=[pf.frame(r['source_port'],pf.p.payload(b.nonce,r['phase'],r['index']),dport=b.runner_port) for r in m['ordinary']]
        data=pf.pcap(frames)
        outcome=pf.p.evaluate(data,normalized['manifest_bytes'],normalized['expected'],pf.capture(data))
        self.assertTrue(outcome['bounded_no_selected_udp_datagram'])
        # Positive bytes survive a later cleanup failure, but never authenticate actor origin.
        data=pf.pcap(frames+[pf.frame(m['selected'][0]['source_port'],pf.p.payload(b.nonce,'contained',0),dport=b.runner_port)])
        normalized['expected']['cleanup_verified']=False
        outcome=pf.p.evaluate(data,normalized['manifest_bytes'],normalized['expected'],pf.capture(data))
        self.assertTrue(outcome['selected_payload_observed']);self.assertFalse(outcome['bounded_no_selected_udp_datagram'])
    def test_wrong_actual_audit_or_missing_report_no_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            b,cases,execution,config,capture=self.collected(Path(directory),wrong_pid=True)
            self.assertFalse(cases['contained']['pid_verified'])
            with self.assertRaises(ValueError):f.build_bundle({'capture':capture,'n0a_udp6':config},b,cases,execution.snapshots)
        b,cases,execution,config,capture=self.make();del cases['after']
        self.assertEqual(g.engine.evaluate(cases,b)['selected_send_accepted_count'],3)
        with self.assertRaises(KeyError):f.build_bundle({'capture':capture,'n0a_udp6':config},b,cases,execution.snapshots)
    def test_unknown_wrapper_cleanup_keeps_bound_send_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            b,cases,execution,config,capture=self.collected(Path(directory),unknown_exit=True)
            self.assertFalse(cases['cleanup_confirmed'])
            result=g.engine.evaluate(cases,b)
            self.assertEqual(result['selected_send_accepted_count'],3)
            self.assertFalse(result['ordinary_controls_verified'])

    def test_public_wrapper_bound_and_private_40_samples(self):
        b,cases,execution,config,capture=self.make()
        for code in (None,-2147483648,2147483647):
            result=g.engine.evaluate(cases,b)
            d=result['diagnostic'];d.update(stage='before_admission',failed_stage='contained_invoke',failure='operation')
            d['phases']=[[False,False,False,False,False,False,'unavailable','unavailable'] for _ in range(4)]
            d['before']=dict(checks=[False]*13,validation='v6only_unattempted',network=[4294967295,False,40],
                attempt=[False]*5+[-2147483648,4294967295,-2147483648,4294967295,'length_mismatch',False,128,False,4294967295,max(g.engine.FAILURES,key=len),False,4294967295]+[False]*6)
            g.engine.validate_diagnostic(d)
            report=dict(schema_version=1,binding=dict(case_nonce=b.nonce,actor_sha256=b.actor_sha256,executor_sha256=b.executor_sha256,build=26300,ubr=9457),result=result,
                execution=dict(phase='configuration',failed=True,cleanup_confirmed=False))
            launcher=dict(phase='configuration',failure='work_budget_exhausted',python_exit_code=code,process_exit_confirmed=None,timed_out=True,budget_exhausted=True)
            raw=f.build_bundle({'capture':capture,'n0a_udp6':config},b,cases,execution.snapshots)
            envelope=dict(schema_version=5,udp6=dict(schema_version=1,case_nonce=b.nonce,actor_sha256=b.actor_sha256,report=report,launcher=launcher),flow_commitment=f.commitment(raw))
            self.assertLessEqual(len(f.encode(envelope)),4096)
        v=fixture.value([100+i*250 for i in range(40)])
        v['reports']['after']['udp6']=fixture.network('after',[11000])
        for source in v['reports'].values():
            source['bytes']=32768
            for row in source['udp6']['attempts']:
                for key in g.engine.PEER_DIAGNOSTIC_KEYS:row[key]=False
        self.assertLessEqual(len(f.encode(v)),65536)
        normalized=f.normalize(f.encode(v),fixture.expected(v,f.encode(v)))
        self.assertEqual(len(json.loads(normalized['manifest_bytes'])['ordinary']),42)

if __name__=='__main__':unittest.main()
