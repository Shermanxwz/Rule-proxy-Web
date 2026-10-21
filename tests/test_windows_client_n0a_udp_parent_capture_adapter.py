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

# Reusable actual-artifact gate. Neither this parent nor its isolated verifier
# executes a PE file, starts a VM, or performs network I/O.
ISOLATED_VERIFY = r'''
import hashlib,importlib.util,json,os,pathlib,sys,types
root=pathlib.Path(sys.argv[1]).resolve()
sys.path[:]=[str(root/'.github')]+[p for p in sys.path if p and pathlib.Path(p).resolve() not in (root,root/'.github')]
def absent():return all(not p or pathlib.Path(p).resolve()!=root for p in sys.path)
result=dict(schema_version=1,root_absent_before=absent(),root_absent_after=False,pythonpath_absent='PYTHONPATH' not in os.environ,
            inputs_verified=False,executor_pin_matches_source=False,poisoned_cache=sys.argv[6]=='poison',failure='verification')
try:
    if result['poisoned_cache']:
        for name in ('ruleproxy','ruleproxy.windows_runtime_pins','parent_host_runtime_pins'):
            fake=types.ModuleType(name);fake.MXC_G_EXECUTOR_SHA256='0'*64;sys.modules[name]=fake
    spec=importlib.util.spec_from_file_location('isolated_direct_script',root/'.github/windows_identity_direct_stage0.py')
    host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)
    value=host.parent_udp_capture_helpers().verify_inputs(*(pathlib.Path(p) for p in sys.argv[2:6]))
    # Independent source literal extraction, not another package import.
    import ast
    tree=ast.parse((root/'ruleproxy/windows_runtime_pins.py').read_text(encoding='utf-8'))
    pin=next(ast.literal_eval(n.value) for n in tree.body if isinstance(n,ast.Assign)
             and any(isinstance(t,ast.Name) and t.id=='MXC_G_EXECUTOR_SHA256' for t in n.targets))
    result['executor_pin_matches_source']=value['config']['executor_sha256']==pin
    result['inputs_verified']=True;result['failure']='none'
except Exception:
    pass  # Fixed closed outcome only; never disclose paths, argv or exception text.
result['root_absent_after']=absent()
print(json.dumps(result,separators=(',',':')))
sys.exit(0 if all(result[k] for k in ('root_absent_before','root_absent_after','pythonpath_absent','inputs_verified','executor_pin_matches_source')) else 1)
'''

class ClosedVerifierError(ValueError):
    def __init__(self,cleanup):
        super().__init__('isolated verification unavailable')
        self.cleanup=cleanup

_UNCONFIRMED_VERIFIERS=[]

def finish_verifier(process,deadline):
    import time
    facts=dict(exit_observed=process is None,kill_attempted=False,handles_closed=process is None,reader_stopped=process is None,cleanup_confirmed=False)
    uncertain=False
    if process is not None:
        try:facts['exit_observed']=type(process.poll()) is int
        except Exception:uncertain=True
        if not facts['exit_observed']:
            facts['kill_attempted']=True
            try:process.kill()
            except Exception:uncertain=True
            try:process.wait(timeout=max(0,deadline-time.monotonic()))
            except Exception:uncertain=True
            try:facts['exit_observed']=type(process.poll()) is int
            except Exception:uncertain=True
        if facts['exit_observed']:
            reader=getattr(process,'_stdout_thread',None)
            if reader is None:facts['reader_stopped']=True
            else:
                try:reader.join(timeout=max(0,deadline-time.monotonic()));facts['reader_stopped']=not reader.is_alive()
                except Exception:uncertain=True
            closed=facts['reader_stopped']
            if facts['reader_stopped']:
                for stream in (getattr(process,'stdout',None),getattr(process,'stderr',None)):
                    if stream is not None:
                        try:stream.close();closed=closed and stream.closed is True
                        except Exception:closed=False
            else:_UNCONFIRMED_VERIFIERS.append(process)
            try:
                handle=getattr(process,'_handle',None)
                if handle is not None:handle.Close()
            except Exception:closed=False
            facts['handles_closed']=closed
        else:
            # Retain the exact object/handles; never infer exit from kill success.
            _UNCONFIRMED_VERIFIERS.append(process)
    facts['cleanup_confirmed']=facts['exit_observed'] and facts['handles_closed'] and facts['reader_stopped'] and not uncertain
    if not facts['cleanup_confirmed'] and process is not None and all(p is not process for p in _UNCONFIRMED_VERIFIERS):
        _UNCONFIRMED_VERIFIERS.append(process)  # Fixed CLI runs at most two children; no close retry.
    return facts

def isolated_verify_inputs(parent,parent_manifest,child,child_manifest,*,poison=False):
    import os,subprocess,sys,time
    environment=dict(os.environ);environment.pop('PYTHONPATH',None)
    deadline=time.monotonic()+20;process=None;raw=None;failed=False;code=None;spawn_attempted=False
    try:
        spawn_attempted=True
        process=subprocess.Popen([sys.executable,'-I','-B','-c',ISOLATED_VERIFY,str(ROOT),str(Path(parent).resolve()),str(Path(parent_manifest).resolve()),
            str(Path(child).resolve()),str(Path(child_manifest).resolve()),'poison' if poison else 'clean'],
            cwd=ROOT,env=environment,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
        raw,_=process.communicate(timeout=max(0,deadline-2-time.monotonic()));code=process.returncode
    except Exception:failed=True
    finally:
        try:
            cleanup=finish_verifier(process,deadline)
            if spawn_attempted and process is None:
                cleanup=dict(exit_observed=False,kill_attempted=False,handles_closed=False,reader_stopped=False,cleanup_confirmed=False)
        except Exception:
            if process is not None:_UNCONFIRMED_VERIFIERS.append(process)
            cleanup=dict(exit_observed=False,kill_attempted=False,handles_closed=False,reader_stopped=False,cleanup_confirmed=False)
    try:
        if failed or not cleanup['cleanup_confirmed'] or type(code) is not int:raise ValueError()
        # Fixed trusted child emits one small closed record. This is post-capture
        # admission, not a general-purpose hostile-output memory-limit claim.
        if type(raw) is not bytes or len(raw)>2048:raise ValueError()
        value=json.loads(raw)
        keys={'schema_version','root_absent_before','root_absent_after','pythonpath_absent','inputs_verified','executor_pin_matches_source','poisoned_cache','failure'}
        if type(value) is not dict or set(value)!=keys or type(value['schema_version']) is not int or value['schema_version']!=1:raise ValueError()
        if any(type(value[k]) is not bool for k in keys-{'schema_version','failure'}) or value['failure'] not in ('none','verification'):raise ValueError()
        if value['poisoned_cache'] is not poison:raise ValueError()
        value['verifier_cleanup']=cleanup
        return code,value
    except Exception:raise ClosedVerifierError(cleanup) from None

from contextlib import contextmanager
@contextmanager
def isolated_fixture_root():
    import shutil
    root=Path(tempfile.mkdtemp(prefix='isolated-pin-fixture-'));remove=True
    try:yield root
    except ClosedVerifierError as exc:
        remove=exc.cleanup.get('cleanup_confirmed') is True
        raise
    finally:
        if remove:
            try:shutil.rmtree(root)
            except Exception:raise ClosedVerifierError(dict(exit_observed=False,kill_attempted=False,handles_closed=False,reader_stopped=False,cleanup_confirmed=False)) from None

class IsolatedPreflightTests(unittest.TestCase):
    def inputs(self,root):
        parent=root/'windows_n0a_udp_parent.exe';parent.write_bytes(b'P'*512)
        child=root/'windows_n0a_udp_actor.exe';child.write_bytes(b'C'*512)
        pm=root/'N0A-UDP-PARENT-manifest.json';cm=root/'N0A-UDP-manifest.json'
        digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
        common=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True,identitySourceSha256=digest(ROOT/'.github/native/windows_identity_actor.cpp'))
        cv=dict(common,actorSourceSha256=digest(ROOT/'.github/native/windows_n0a_udp_actor.cpp'),executableSha256=digest(child))
        pv=dict(common,parentSourceSha256=digest(ROOT/'.github/native/windows_n0a_udp_parent.cpp'),childActorSourceSha256=cv['actorSourceSha256'],executableSha256=digest(parent))
        pm.write_text(json.dumps(pv));cm.write_text(json.dumps(cv));return parent,pm,child,cm
    def test_actual_script_import_environment_without_repository_or_pythonpath(self):
        with isolated_fixture_root() as root:
            inputs=self.inputs(Path(root))
            for poison in (False,True):
                code,value=isolated_verify_inputs(*inputs,poison=poison)
                self.assertEqual(code,0,value);self.assertTrue(value['inputs_verified']);self.assertTrue(value['root_absent_after'])
    def test_isolated_script_keeps_production_manifest_and_byte_checks(self):
        with isolated_fixture_root() as root:
            inputs=self.inputs(Path(root));value=json.loads(inputs[1].read_text());value['testOnly']=True;inputs[1].write_text(json.dumps(value))
            code,result=isolated_verify_inputs(*inputs);self.assertNotEqual(code,0);self.assertFalse(result['inputs_verified'])
            inputs=self.inputs(Path(root));inputs[2].write_bytes(b'PRIVATE'+bytes(512))
            code,result=isolated_verify_inputs(*inputs);self.assertNotEqual(code,0);self.assertFalse(result['inputs_verified']);self.assertNotIn('PRIVATE',json.dumps(result))
    def test_pin_loader_never_changes_search_path_or_uses_cached_module(self):
        import sys,types
        before=list(sys.path);fake=types.ModuleType('parent_host_runtime_pins');fake.MXC_G_EXECUTOR_SHA256='0'*64
        with patch.dict(sys.modules,{'parent_host_runtime_pins':fake}):
            value=m.runtime_executor_pin()
        self.assertEqual(sys.path,before);self.assertNotEqual(value,'0'*64)

class IsolatedVerifierFailureTests(unittest.TestCase):
    def fake(self):
        from unittest.mock import Mock
        process=Mock();process.poll.return_value=0;process.stdout.closed=True;process.stderr=None;process.returncode=0;process._stdout_thread=None
        return process
    def test_poll_and_kill_failure_do_not_skip_wait(self):
        for broken in ('poll','kill'):
            process=self.fake();process.poll.side_effect=[OSError('PRIVATE'),0] if broken=='poll' else [None,0]
            if broken=='kill':process.kill.side_effect=OSError('PRIVATE')
            with patch('time.monotonic',return_value=10):facts=finish_verifier(process,20)
            process.kill.assert_called_once();process.wait.assert_called_once_with(timeout=10)
            self.assertTrue(facts['exit_observed']);self.assertFalse(facts['cleanup_confirmed']);self.assertIn(process,_UNCONFIRMED_VERIFIERS)
            _UNCONFIRMED_VERIFIERS.remove(process)
    def test_unknown_exit_retains_exact_handle_and_root(self):
        process=self.fake();process.poll.return_value=None;process.wait.side_effect=OSError('PRIVATE')
        with patch('time.monotonic',return_value=10):facts=finish_verifier(process,10)
        self.assertFalse(facts['handles_closed']);process._handle.Close.assert_not_called();process.stdout.close.assert_not_called()
        self.assertIn(process,_UNCONFIRMED_VERIFIERS)
        root=None
        try:
            with isolated_fixture_root() as root:raise ClosedVerifierError(facts)
        except ClosedVerifierError:pass
        self.assertTrue(root.exists())
        # Test owns this empty root and mocked process only; no live reader.
        root.rmdir();_UNCONFIRMED_VERIFIERS.remove(process)
    def test_timeout_spawn_error_and_malformed_output_never_disclose_argv(self):
        import subprocess
        from unittest.mock import Mock
        for failure in ('timeout','spawn','malformed'):
            process=self.fake()
            if failure=='timeout':process.communicate.side_effect=subprocess.TimeoutExpired(['PRIVATE_PATH'],18,output=b'PRIVATE_BODY')
            else:process.communicate.return_value=(b'PRIVATE_BODY',None)
            with patch('subprocess.Popen',side_effect=OSError('PRIVATE_PATH') if failure=='spawn' else None,return_value=process):
                with self.assertRaises(ClosedVerifierError) as caught:isolated_verify_inputs('PRIVATE_PATH','a','b','c')
                self.assertEqual(str(caught.exception),'isolated verification unavailable')
                self.assertNotIn('PRIVATE',str(caught.exception));self.assertEqual(caught.exception.cleanup['cleanup_confirmed'],failure!='spawn')
    def test_spawn_uncertainty_retains_test_root(self):
        root=None
        try:
            with isolated_fixture_root() as root,patch('subprocess.Popen',side_effect=OSError('PRIVATE_PATH')):
                isolated_verify_inputs(root/'parent',root/'manifest',root/'child',root/'child-manifest')
        except ClosedVerifierError as exc:self.assertFalse(exc.cleanup['cleanup_confirmed'])
        self.assertTrue(root.exists());root.rmdir()
    def test_removal_error_remains_closed(self):
        root=None
        try:
            with self.assertRaises(ClosedVerifierError) as caught:
                with patch('shutil.rmtree',side_effect=OSError('PRIVATE_PATH')):
                    with isolated_fixture_root() as root:
                        raise ClosedVerifierError(dict(cleanup_confirmed=True))
        finally:
            if root is not None and root.exists():root.rmdir()
        self.assertEqual(str(caught.exception),'isolated verification unavailable');self.assertFalse(caught.exception.cleanup['cleanup_confirmed'])
    def test_windows_communicate_reader_thread_must_stop(self):
        from unittest.mock import Mock
        process=self.fake();reader=Mock();reader.is_alive.return_value=True;process._stdout_thread=reader
        with patch('time.monotonic',return_value=10):facts=finish_verifier(process,12)
        reader.join.assert_called_once_with(timeout=2)
        self.assertFalse(facts['reader_stopped']);self.assertFalse(facts['cleanup_confirmed']);process.stdout.close.assert_not_called()
        _UNCONFIRMED_VERIFIERS.remove(process)
    def test_pipe_close_error_truthful_cleanup(self):
        process=self.fake();process.stdout.close.side_effect=OSError('PRIVATE')
        facts=finish_verifier(process,0);self.assertTrue(facts['exit_observed']);self.assertFalse(facts['handles_closed']);self.assertFalse(facts['cleanup_confirmed'])
        self.assertIn(process,_UNCONFIRMED_VERIFIERS);process.stdout.close.assert_called_once();process._handle.Close.assert_called_once()
        _UNCONFIRMED_VERIFIERS.remove(process)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser(description='Isolated no-network production artifact preflight gate')
    parser.add_argument('--verify-production-inputs',action='store_true',required=True)
    for name in ('parent','parent-manifest','child','child-manifest'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    try:
        observations=[isolated_verify_inputs(args.parent,args.parent_manifest,args.child,args.child_manifest,poison=p) for p in (False,True)]
        okay=all(code==0 for code,value in observations)
        print(json.dumps(dict(schema_version=1,isolated_production_inputs_verified=okay,observations=[v for _,v in observations],network_executed=False,vm_executed=False),separators=(',',':')))
        raise SystemExit(0 if okay else 1)
    except Exception:
        print('{"schema_version":1,"isolated_production_inputs_verified":false,"failure":"verification","network_executed":false,"vm_executed":false}')
        raise SystemExit(1)
