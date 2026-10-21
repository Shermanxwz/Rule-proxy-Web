"""Pure actual-loader descendant chain; synthetic observations, no native execution."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
g=load('parent_composed_guest',ROOT/'.github/windows_n0a_udp_parent_guest.py');f=g.flow;c=g.engine
fixtures=load('parent_composed_networks',ROOT/'tests/test_windows_client_n0a_udp_flow.py')
p=load('parent_composed_packet',ROOT/'.github/windows_n0a_udp_packet.py')

def candidate():
    b=c.ParentUDPBinding('a'*32,'b'*64,'c'*64,'d'*64,'S-1-15-3-1',44000,1,False,False)
    reports=fixtures.value()['reports'];cases={'driver_error':False,'cleanup_confirmed':True};snapshots={}
    for phase in c.PHASES:
        net=copy.deepcopy(reports[phase]['udp'])
        if phase=='contained':
            for r in net['attempts']:r.update(nonceMatched=False,failure='recv_select',win32Error=10060)
        common=dict(schemaVersion=1,nonce=b.nonce,queriesSucceeded=True,errors=[],tokenElevated=False,tokenIsAppContainer=phase=='contained',isProcessInJob=True,
            tokenAppContainerSid='S-1-15-2-1-2-3-4-5-6-7' if phase=='contained' else None,tokenCapabilities=[{'sid':b.agentic_sid,'attributes':4}] if phase=='contained' else [])
        child=dict(common,mode='actor-n0a-udp',pid=200,udp=net);childraw=f.encode(child);cs=dict(sha256=hashlib.sha256(childraw).hexdigest(),bytes=len(childraw))
        native={k:True for k in c.PARENT_BOOL};native.update(testOnly=False,timedOut=False,terminateAttempted=False,terminationSucceeded=False,
            version=1,phase=phase,childPid=200,parentAppContainer=phase=='contained',childAppContainer=phase=='contained',sidEqual=True if phase=='contained' else None,
            resumeCount=1,childExitCode=0,childReportBytes=cs['bytes'],childReportSha256=cs['sha256'],failure='none')
        parent=dict(common,mode='actor-n0a-udp-parent',pid=100,parent=native);parentraw=f.encode(parent);ps=dict(sha256=hashlib.sha256(parentraw).hexdigest(),bytes=len(parentraw))
        snapshots[id(parent)]=ps;snapshots[id(child)]=cs
        cases[phase]=dict(nonce=b.nonce,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,executor_sha256=b.executor_sha256,build=b.build,ubr=b.ubr,
            parent=parent,child=child,child_snapshot=cs,parent_exit_code=0,pid_verified=True,pid_binding='executor_audit' if phase=='contained' else 'ordinary_handle',
            probe={'tier':'base-container','needsDaclAugmentation':False,'probes':{'baseContainerApiPresent':True}},probe_exit_code=0,actual_tiers=['base-container'],timed_out=False,harness_error=False)
    config={k:'e'*64 for k in g.CONFIG_KEYS-{'enabled','case_nonce','runner_port'}}
    config.update(enabled=True,case_nonce=b.nonce,runner_port=b.runner_port,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,executor_sha256=b.executor_sha256)
    capture=dict(enabled=True,run_nonce='f'*32,source_commit='1'*40,vm_mac='525400123456')
    return b,cases,types.SimpleNamespace(snapshots=snapshots),config,capture

class ParentComposed(unittest.TestCase):
    def test_actual_loader_prepare_commitment_normalize_packet(self):
        self.assertIs(c,f.engine());b,cases,execution,config,capture=candidate();result=c.evaluate(cases,b)
        self.assertTrue(all(result['chain_verified'].values()));self.assertEqual(result['selected_send_accepted_count'],3);self.assertFalse(result['selected_echo_observed'])
        with tempfile.TemporaryDirectory() as root,patch.object(g,'ROOT',Path(root)):
            (Path(root)/'private-parent-udp').mkdir();self.assertTrue(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10))
            raw=(Path(root)/'private-parent-udp/runner-flow.json').read_bytes()
        v=f.bundle(raw);commit=f.commitment(raw)
        self.assertEqual(commit['sha256'],hashlib.sha256(raw).hexdigest())
        expected=dict(binding=v['binding'],endpoint=v['endpoint'],flow_commitment=commit,controller_result={'receipt_verified':True,'result':result},cleanup_verified=True)
        normalized=f.normalize(raw,expected);self.assertTrue(normalized['controls_verified']);manifest,collision=p.validate_manifest(normalized['manifest_bytes'],normalized['expected'])
        self.assertFalse(collision);self.assertEqual(len(manifest['selected']),3)
        self.assertNotIn(b'S-1-15',raw);self.assertNotIn(b'childPid',raw);self.assertLess(len(raw),65536)
    def test_every_chain_requirement_rejects_mismatch(self):
        changes=[('childPid',201),('resumeCount',0),('resumeCount',True),('waitSignaled',False),('childExitCode',-1),('childExitCode',True),('childReportSha256','0'*64),('childReportBytes',True),('deadlineVerified',False),('sidEqual',False),('testOnly',True),('childHashVerified',False)]
        for key,value in changes:
            b,cases,_,_,_=candidate();cases['contained']['parent']['parent'][key]=value
            self.assertFalse(c.attributed(cases['contained'],b,'contained'),key)
        for role in ('parent','child'):
            b,cases,_,_,_=candidate();cases['contained'][role]['tokenAppContainerSid']='S-1-15-2-9-2-3-4-5-6-7'
            self.assertFalse(c.attributed(cases['contained'],b,'contained'))
    def test_signed_parent_unsigned_child_kept_separate(self):
        b,cases,_,_,_=candidate();v=cases['contained'];v['parent_exit_code']=-1;v['parent']['parent']['childExitCode']=0xffffffff
        self.assertTrue(c.attributed(v,b,'contained'));r=c.evaluate(cases,b);self.assertEqual(r['selected_send_accepted_count'],3);self.assertFalse(r['ordinary_controls_verified'])
        v['parent_exit_code']=0xffffffff;self.assertFalse(c.attributed(v,b,'contained'))
    def test_positive_sticky_after_cleanup_and_control_failure(self):
        b,cases,execution,config,capture=candidate();cases['contained']['child']['udp']['attempts'][0]['nonceMatched']=True
        cases['contained']['parent']['parent']['cleanupConfirmed']=False;cases['sample']['child']['udp']['attempts'][1]['nonceMatched']=False
        r=c.evaluate(cases,b);self.assertTrue(r['selected_echo_observed']);self.assertFalse(r['ordinary_controls_verified']);self.assertFalse(r['descendant_cleanup_confirmed'])
        raw=f.build_bundle({'capture':capture,'n0a_udp_parent':config},b,cases,execution.snapshots);v=f.bundle(raw)
        e=dict(binding=v['binding'],endpoint=v['endpoint'],flow_commitment=f.commitment(raw),controller_result={'receipt_verified':True,'result':r},cleanup_verified=False)
        n=f.normalize(raw,e);self.assertFalse(n['expected']['cleanup_verified']);self.assertEqual(len(json.loads(n['manifest_bytes'])['selected']),3)
    def test_bad_binding_no_file_and_old_class_refused(self):
        b,cases,execution,config,capture=candidate();cases['contained']['child_sha256']='0'*64
        with tempfile.TemporaryDirectory() as root,patch.object(g,'ROOT',Path(root)):
            (Path(root)/'private-parent-udp').mkdir();self.assertFalse(g.prepare_flow(config,capture,b,cases,execution,time.monotonic()+10));self.assertFalse((Path(root)/'private-parent-udp/runner-flow.json').exists())
        other=load('parent_wrong_alias',ROOT/'.github/windows_n0a_udp_parent_control.py');wrong=other.ParentUDPBinding(**vars(b))
        self.assertFalse(c.attributed(cases['before'],wrong,'before'))
    def test_native_pid_cannot_be_replaced_with_g_parent(self):
        b,cases,_,_,_=candidate();cases['contained']['parent']['parent']['childPid']=100
        self.assertFalse(c.attributed(cases['contained'],b,'contained'))
    def test_cache_wrong_source_and_origin_closed(self):
        for obj,key,value in ((c,'_source_sha256','0'*64),(c.__spec__,'origin','wrong'),(c,'__file__','wrong')):
            with patch.object(obj,key,value):
                with self.assertRaises(ValueError):f.engine()
    def test_same_buffer_snapshots_and_bounds(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'source';raw=b'{ "schemaVersion":1 }\n';path.write_bytes(raw);parsed,s=f.read_snapshot(path,8192)
            self.assertEqual(s['sha256'],hashlib.sha256(raw).hexdigest());self.assertNotEqual(s['sha256'],hashlib.sha256(f.encode(parsed)).hexdigest())
            path.write_bytes(b' '*8193)
            with self.assertRaises(ValueError):f.read_snapshot(path,8192)
    def test_deadline_before_g_no_renewal_and_command(self):
        b,_,_,_,_=candidate();obj=object.__new__(g.WindowsExecution);obj.frequency=1000;obj.deadline_qpc=12000
        with patch.object(g,'qpc_now',return_value=10000):
            self.assertEqual(obj.phase_deadline('contained'),12000);self.assertEqual(obj.phase_deadline('before'),12000)
        with patch.object(g,'qpc_now',return_value=12000):
            with self.assertRaises(TimeoutError):obj.phase_deadline('contained')
        args=c.command('parent','pr','windows_n0a_udp_actor.exe','cr',b,'contained',12000,1000)
        self.assertEqual(args[-2:],['12000','1000']);self.assertEqual(args[1],'n0a-udp-parent')
    def test_all_40_samples_private_bound_and_paired_hashes(self):
        b,cases,execution,config,capture=candidate()
        sample=fixtures.network('sample',[100+i*250 for i in range(40)])
        cases['sample']['child']['udp']=sample
        cases['after']['child']['udp']=fixtures.network('after',[11000])
        # Refresh source snapshots and parent native read-back binding for the
        # actual expanded original buffers, not reusing old source hashes.
        for phase in c.PHASES:
            v=cases[phase];raw=f.encode(v['child']);cs=dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
            v['child_snapshot']=cs;v['parent']['parent'].update(childReportSha256=cs['sha256'],childReportBytes=cs['bytes'])
            execution.snapshots[id(v['child'])]=cs;raw=f.encode(v['parent'])
            execution.snapshots[id(v['parent'])]=dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
        raw=f.build_bundle({'capture':capture,'n0a_udp_parent':config},b,cases,execution.snapshots)
        self.assertLessEqual(len(raw),65536);v=f.bundle(raw);result=c.evaluate(cases,b)
        normalized=f.normalize(raw,dict(binding=v['binding'],endpoint=v['endpoint'],flow_commitment=f.commitment(raw),controller_result={'receipt_verified':True,'result':result},cleanup_verified=True))
        self.assertEqual(len(json.loads(normalized['manifest_bytes'])['ordinary']),42)
        before=f.source_digests(v['reports']);v['reports']['contained']['parent_source']['bytes']+=1
        self.assertNotEqual(f.source_digests(v['reports'])[0],before[0])
    def test_complete_public_wrapper_bound_4096(self):
        b,cases,execution,config,capture=candidate();result=c.evaluate(cases,b)
        raw=f.build_bundle({'capture':capture,'n0a_udp_parent':config},b,cases,execution.snapshots)
        old=c.udp().tcp_helpers();maximum=0;commit=f.commitment(raw)
        # Every variable-width result scalar at its legal maximum: false is
        # longer than true, while the one count is always a single digit.
        result=c.evaluate({},None)
        for phase in old.LAUNCHER_PHASES:
            for failure in old.LAUNCHER_FAILURES:
                for exitcode in (None,-2147483648,2147483647):
                    envelope=dict(schema_version=1,case_nonce=b.nonce,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,
                        report=dict(schema_version=1,binding=dict(case_nonce=b.nonce,parent_sha256=b.parent_sha256,child_sha256=b.child_sha256,executor_sha256=b.executor_sha256,build=26300,ubr=9457),result=result,execution=dict(phase=max(old.EXECUTION_PHASES,key=len),failed=False,cleanup_confirmed=False)),
                        launcher=dict(phase=phase,failure=failure,python_exit_code=exitcode,process_exit_confirmed=False,timed_out=False,budget_exhausted=False))
                    wrapper=dict(schema_version=4,parent_udp=envelope,flow_commitment=commit)
                    maximum=max(maximum,len(f.encode(wrapper)))
        self.assertLessEqual(maximum,4096)
    def test_default_off_no_work(self):
        self.assertFalse(c.EXECUTION_ENABLED)
        with patch.object(g,'configuration',side_effect=AssertionError):self.assertIsNone(g.run('unused',1,1))

if __name__=='__main__':unittest.main()
