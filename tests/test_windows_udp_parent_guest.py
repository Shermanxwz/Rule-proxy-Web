"""Parent guest lifecycle seams, no native process or network execution."""
import ast
import hashlib
import importlib.util
import json
import io
import time
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('parent_guest_cases',ROOT/'tests/test_windows_udp_parent_composed.py');fix=importlib.util.module_from_spec(spec);sys.modules[spec.name]=fix;spec.loader.exec_module(fix)
g=fix.g;c=fix.c;f=fix.f
class Guest(unittest.TestCase):
    def test_production_parent_child_manifests_and_pins(self):
        _,_,_,config,_=fix.candidate()
        with tempfile.TemporaryDirectory() as root:
            root=Path(root);parent=root/'parent';child=root/'child';pm=root/'pm';cm=root/'cm'
            for role,path,manifest in [('parent',parent,pm),('child',child,cm)]:
                raw=(role.encode()*600);path.write_bytes(raw);config[role+'_sha256']=hashlib.sha256(raw).hexdigest()
                value=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,identitySourceSha256=config['identity_source_sha256'],executableSha256=config[role+'_sha256'])
                if role=='parent':value.update(parentSourceSha256=config['parent_source_sha256'],childActorSourceSha256=config['child_source_sha256'])
                else:value.update(actorSourceSha256=config['child_source_sha256'])
                data=f.encode(value);manifest.write_bytes(data);config[role+'_manifest_sha256']=hashlib.sha256(data).hexdigest()
            g.verify_production(config,parent,pm,child,cm)
            value=json.loads(pm.read_bytes());value['testOnly']=True;data=f.encode(value);pm.write_bytes(data);config['parent_manifest_sha256']=hashlib.sha256(data).hexdigest()
            with self.assertRaises(ValueError):g.verify_production(config,parent,pm,child,cm)
    def test_policy_same_deadline_passed_before_spawn(self):
        source=(ROOT/'.github/windows_n0a_udp_parent_guest.py').read_text();tree=ast.parse(source)
        cls=next(x for x in tree.body if isinstance(x,ast.ClassDef));invoke=next(x for x in cls.body if isinstance(x,ast.FunctionDef) and x.name=='invoke')
        text=ast.get_source_segment(source,invoke)
        self.assertLess(text.index('deadline=self.phase_deadline'),text.index('self.spawn'))
        self.assertLess(text.index('self.write_policy(case,deadline)'),text.index('self.spawn'))
        self.assertNotIn('deadline_qpc=',text)
        self.assertIn("self.child.name!='windows_n0a_udp_actor.exe'",source)
    def test_phase_caps_not_reset_and_expiry_before_spawn(self):
        obj=object.__new__(g.WindowsExecution);obj.frequency=1000;obj.deadline_qpc=100000
        with patch.object(g,'qpc_now',return_value=1000):
            self.assertEqual(obj.phase_deadline('before'),6000);self.assertEqual(obj.phase_deadline('sample'),16000)
        obj.deadline_qpc=999
        with patch.object(g,'qpc_now',return_value=1000),patch.object(obj,'endpoint_case',return_value={}),patch.object(obj,'spawn',side_effect=AssertionError):
            with self.assertRaises(TimeoutError):obj.invoke('contained','contained','runner',44000,15)
    def test_no_old_mode_alias_or_g_child_substitution(self):
        source=(ROOT/'.github/windows_n0a_udp_parent_guest.py').read_text()
        self.assertIn("parent_exit_code=event['child_exit_code']",source)
        self.assertIn("parent.get('pid'),owned['process'].pid",source)
        self.assertNotIn("result.update(event)",source)
        self.assertIn("child_snapshot=cs",source)
        self.assertNotIn("actor-n0a-udp'",source)
    def test_run_endpoint_deadline_finite_and_no_start_after_error(self):
        b,_,_,_,_=fix.candidate();calls=[]
        class Execution:
            def probe(self,*a,**k):calls.append('probe');raise TimeoutError()
            def invoke(self,*a,**k):calls.append('invoke');raise AssertionError()
        with patch.object(c,'EXECUTION_ENABLED',True):result=c.run_endpoint(Execution(),b,100,approved=True,clock=lambda:10,sleep=lambda _:None)
        self.assertTrue(result['driver_error']);self.assertEqual(calls,['probe'])
    def test_payload_paths_match_actual_host_and_ps_selection(self):
        source=(ROOT/'.github/windows_n0a_udp_parent_guest.py').read_text()
        host=(ROOT/'.github/windows_identity_direct_stage0.py').read_text()
        ps=(ROOT/'.github/windows-identity-direct-stage0-run.ps1').read_text()
        for path in ('parent/actor.exe','parent/build-manifest.json','udp/actor.exe','udp/build-manifest.json'):
            self.assertIn("ROOT/'"+path+"'",source)
            self.assertIn(path,host);self.assertIn(path,ps)
        self.assertNotIn("ROOT/'udp-parent/",source)
    def test_snapshot_reparse_and_parent_bound(self):
        with tempfile.TemporaryDirectory() as root:
            p=Path(root)/'p';p.write_bytes(b'{}');link=Path(root)/'l'
            try:link.symlink_to(p)
            except OSError:return
            with self.assertRaises(ValueError):f.read_snapshot(link,8192)
    def envelope_case(self,root,*,change=None,missing_parent=False,unknown=False):
        binding,cases,_,_,_=fix.candidate();source=cases['contained']
        parent=json.loads(json.dumps(source['parent']));child=json.loads(json.dumps(source['child']))
        if change=='digest':parent['parent']['childReportSha256']='0'*64
        if change=='pid':parent['parent']['childPid']=201
        root=Path(root);parent_path=root/'parent.json';child_path=root/'child.json';audit=root/'audit'
        if not missing_parent:parent_path.write_bytes(f.encode(parent))
        child_path.write_bytes(f.encode(child))
        event=dict(event='mxc.ProcessExited',backend='processcontainer',identity='redacted',tier='base-container',pid=100,exit_code=0)
        if change=='audit_child':event['pid']=200
        audit.write_bytes(('[1] '+json.dumps(event)+'\n').encode('utf-8'));state=audit.stat()
        class Process:
            pid=900
            returncode=None if unknown else 0
            def __init__(self):self.calls=[];self._handle=types.SimpleNamespace(Close=lambda:self.calls.append('handle_close'))
            def wait(self,timeout):
                self.calls.append('wait')
                if unknown:raise TimeoutError('mock wait failure')
                return 0
            def poll(self):self.calls.append('poll');return self.returncode
            def kill(self):self.calls.append('kill');raise OSError('mock kill failure')
        process=Process();obj=object.__new__(g.WindowsExecution)
        obj.binding=binding;obj.deadline=time.monotonic()+10;obj.snapshots={};obj.pin=lambda:None
        obj.cases={'runner':{'probe':source['probe'],'probe_exit':0}}
        owned=dict(endpoint='runner',role='contained',report=parent_path,child_report=child_path,audit=audit,audit_identity=(state.st_dev,state.st_ino),
            process=process,out=io.BytesIO(),err=io.BytesIO(),timed_out=False,cleanup=False)
        obj.owned=[owned]
        envelope=obj.wait(owned,1) # Actual inherited wait/completed + UDP close_owned + new envelope.
        cases['contained']=envelope
        return obj,owned,cases,binding,process
    def test_actual_wait_envelope_reads_same_buffers_and_binds_g_to_parent(self):
        with tempfile.TemporaryDirectory() as root:
            obj,owned,cases,binding,process=self.envelope_case(root)
            v=cases['contained'];self.assertTrue(c.attributed(v,binding,'contained'))
            self.assertEqual(v['parent_exit_code'],0);self.assertEqual(v['parent']['pid'],100);self.assertEqual(v['child']['pid'],200)
            self.assertEqual(v['child_snapshot']['sha256'],hashlib.sha256(owned['child_report'].read_bytes()).hexdigest())
            self.assertEqual(obj.snapshots[id(v['parent'])]['sha256'],hashlib.sha256(owned['report'].read_bytes()).hexdigest())
            self.assertIn('wait',process.calls);self.assertIn('handle_close',process.calls)
            self.assertTrue(owned['out'].closed and owned['err'].closed)
        for change in ('digest','pid','audit_child'):
            with tempfile.TemporaryDirectory() as root:
                _,_,cases,binding,_=self.envelope_case(root,change=change)
                self.assertFalse(c.attributed(cases['contained'],binding,'contained'),change)
                self.assertFalse(c.evaluate(cases,binding)['descendant_cleanup_confirmed'])
    def test_missing_parent_and_unknown_wrapper_cleanup_cannot_confirm_descendants(self):
        with tempfile.TemporaryDirectory() as root:
            _,_,cases,binding,_=self.envelope_case(root,missing_parent=True)
            self.assertFalse(c.evaluate(cases,binding)['descendant_cleanup_confirmed'])
        with tempfile.TemporaryDirectory() as root:
            _,owned,cases,binding,process=self.envelope_case(root,unknown=True)
            self.assertFalse(owned['cleanup']);self.assertIn('kill',process.calls)
            self.assertTrue(c.attributed(cases['contained'],binding,'contained'))
            result=c.evaluate(cases,binding)
            self.assertEqual(result['selected_send_accepted_count'],3)
            self.assertFalse(result['descendant_cleanup_confirmed'])
        binding,cases,_,_,_=fix.candidate();cases['cleanup_confirmed']=False
        self.assertFalse(c.evaluate(cases,binding)['descendant_cleanup_confirmed'])
    def test_public_receipt_binds_both_binaries_and_cleanup_downgrades(self):
        b,cases,_,config,_=fix.candidate();result=c.evaluate(cases,b)
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        launcher=dict(phase='completed',failure='none',python_exit_code=0,process_exit_confirmed=True,timed_out=False,budget_exhausted=False)
        value=dict(schema_version=1,case_nonce=b.nonce,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,launcher=launcher,
          report=dict(schema_version=1,binding=dict(case_nonce=b.nonce,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,execution=dict(phase='completed',failed=False,cleanup_confirmed=True)))
        self.assertTrue(c.validate_host_parent_udp_envelope(value,config)['receipt_verified'])
        value['launcher']['timed_out']=True;observed=c.validate_host_parent_udp_envelope(value,config)
        self.assertEqual(observed['result']['selected_send_accepted_count'],3);self.assertFalse(observed['result']['descendant_cleanup_confirmed'])
        value['child_sha256']='0'*64
        with self.assertRaises(ValueError):c.validate_host_parent_udp_envelope(value,config)
        self.assertLess(len(f.encode(value)),4096)
if __name__=='__main__':unittest.main()
