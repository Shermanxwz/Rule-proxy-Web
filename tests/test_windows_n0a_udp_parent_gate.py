import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_parent_gate_test',ROOT/'.github/test_windows_n0a_udp_parent.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class OwnedParentTests(unittest.TestCase):
    def test_poll_and_kill_errors_do_not_skip_wait(self):
        for broken in ('poll','kill'):
            owned=m.OwnedParent(Path('unused'));process=Mock();owned.process=process
            process.poll.side_effect=[OSError('private'),0] if broken=='poll' else [None,0]
            if broken=='kill':process.kill.side_effect=OSError('private')
            with patch.object(m.time,'monotonic',return_value=10):result=owned.finish(12)
            process.kill.assert_called_once();process.wait.assert_called_once_with(timeout=2)
            self.assertFalse(result['parent_cleanup_confirmed']);self.assertTrue(result['parent_exit_observed'])
    def test_unknown_exit_retains_handle_and_never_claims_descendant(self):
        owned=m.OwnedParent(Path('unused'));owned.process=Mock();owned.process.poll.return_value=None;owned.process.wait.side_effect=TimeoutError()
        with patch.object(m.time,'monotonic',return_value=20):result=owned.finish(19)
        owned.process.wait.assert_called_once_with(timeout=0);owned.process._handle.Close.assert_not_called()
        self.assertFalse(result['parent_handles_closed']);self.assertNotIn('descendant_cleanup_confirmed',result)
    def test_close_once_sticky_uncertainty(self):
        owned=m.OwnedParent(Path('unused'));owned.process=Mock();owned.process.poll.return_value=0;owned.process._handle.Close.side_effect=OSError('private')
        self.assertFalse(owned.finish(100)['parent_cleanup_confirmed']);self.assertFalse(owned.finish(100)['parent_cleanup_confirmed'])
        owned.process._handle.Close.assert_called_once();owned.process.kill.assert_not_called()
    def test_create_new_and_registration_before_spawn(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'report';path.write_bytes(b'{}');owned=m.OwnedParent(path)
            with patch.object(m.subprocess,'Popen') as popen:
                with self.assertRaises(ValueError):owned.start(['invalid'])
                popen.assert_not_called()
    def test_report_binary_bound_duplicate_no_raw_projection(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'report'
            for raw in (b'x'*32769,b'{"a":1,"a":2}',b'\xff'):
                path.write_bytes(raw)
                with self.assertRaises(ValueError):m.read_report(path)
    def test_no_deadline_renewal_or_extra_wait_on_exhaustion(self):
        with patch.object(m.time,'monotonic',return_value=50):
            self.assertEqual(m.bounded_deadline(70,30),60)
            with self.assertRaises(ValueError):m.bounded_deadline(60,30)

def parent_row():
    return dict(version=1,testOnly=True,phase='before',profileMatched=False,childHashVerified=True,childCreated=True,childPid=222,
        tokenQuerySucceeded=True,parentAppContainer=False,childAppContainer=False,sidEqual=None,sidMatched=True,resumeAttempted=True,
        resumeCount=1,resumed=True,waitSignaled=True,childExitCode=0,timedOut=False,terminateAttempted=False,terminationSucceeded=False,
        cleanupConfirmed=True,childReportObserved=True,childReportBytes=10,childReportSha256='a'*64,failure='none')

class ProjectionTests(unittest.TestCase):
    def parent(self,row=None):
        return dict(schemaVersion=1,mode='actor-n0a-udp-parent',nonce='a'*32,pid=111,queriesSucceeded=True,errors=[],parent=parent_row() if row is None else row)
    def test_parent_pid_nonce_schema_types_and_unknown_fields(self):
        owned=SimpleNamespace(report=Path('unused'),process=SimpleNamespace(pid=111))
        good=self.parent()
        with patch.object(m,'read_report',return_value=good):self.assertEqual(m.parent_report(owned,'a'*32,'before',('none',))[1],good['parent'])
        for key,bad in [('childPid',True),('resumeCount',True),('cleanupConfirmed',1),('childReportSha256','PRIVATE_PATH'),('failure','PRIVATE_ERROR')]:
            row=parent_row();row[key]=bad
            with patch.object(m,'read_report',return_value=self.parent(row)):
                with self.assertRaises(ValueError):m.parent_report(owned,'a'*32,'before',('none',))
        for key,bad in [('pid',222),('nonce','b'*32),('mode','actor-n0a-udp')]:
            value=self.parent();value[key]=bad
            with patch.object(m,'read_report',return_value=value):
                with self.assertRaises(ValueError):m.parent_report(owned,'a'*32,'before',('none',))
    def test_closed_projection_no_private_identifiers(self):
        value=m.projected_parent(parent_row())
        self.assertNotIn('childPid',value);self.assertNotIn('childReportSha256',value)
        self.assertTrue(value['held_wait_observed']);self.assertTrue(value['descendant_cleanup_confirmed'])
        row=parent_row();row['waitSignaled']=False;self.assertFalse(m.projected_parent(row)['descendant_cleanup_confirmed'])

import json
import hashlib
import sys
spec2=importlib.util.spec_from_file_location('udp_parent_network_fixtures',ROOT/'tests/test_windows_client_n0a_udp.py');nf=importlib.util.module_from_spec(spec2);spec2.loader.exec_module(nf)

class SnapshotTests(unittest.TestCase):
    def test_actual_child_buffer_commitment_and_network_validator(self):
        with tempfile.TemporaryDirectory() as root:
            path=Path(root)/'child';value=dict(schemaVersion=1,mode='actor-n0a-udp',nonce=nf.NONCE,pid=222,queriesSucceeded=True,errors=[],udp=nf.network('before',[10],False))
            raw=json.dumps(value).encode();path.write_bytes(raw);row=parent_row();row.update(childReportBytes=len(raw),childReportSha256=hashlib.sha256(raw).hexdigest())
            self.assertEqual(m.verified_child(path,nf.NONCE,'before',40000,row),value)
            for key,bad in [('childHashVerified',False),('childPid',333),('childReportBytes',len(raw)+1),('childReportSha256','b'*64),('waitSignaled',False)]:
                changed=dict(row);changed[key]=bad
                with self.assertRaises(ValueError):m.verified_child(path,nf.NONCE,'before',40000,changed)
    def test_manifest_exact_source_child_and_fixture_pins(self):
        with tempfile.TemporaryDirectory() as root:
            actor=Path(root)/'windows_n0a_UDP_PARENT_TEST_ONLY_fixture.exe';actor.write_bytes(b'MZ'+bytes(510))
            manifest=Path(root)/'PARENT-TEST-ONLY-manifest.json'
            value=dict(schemaVersion=1,testOnly=True,deployable=False,compileOnly=True,
                executableSha256=hashlib.sha256(actor.read_bytes()).hexdigest())
            for key,name in [('parentSourceSha256','windows_n0a_udp_parent.cpp'),('identitySourceSha256','windows_identity_actor.cpp'),('childActorSourceSha256','windows_n0a_udp_actor.cpp'),('fixtureSourceSha256','windows_n0a_udp_parent_fixture.cpp')]:
                value[key]=hashlib.sha256((m.ROOT/'native'/name).read_bytes()).hexdigest()
            manifest.write_text(json.dumps(value));self.assertEqual(m.verify_parent(actor,manifest,True),actor.read_bytes())
            for key,bad in [('testOnly',False),('childActorSourceSha256','0'*64),('extra','PRIVATE')]:
                changed=dict(value);changed[key]=bad;manifest.write_text(json.dumps(changed))
                with self.assertRaises(ValueError):m.verify_parent(actor,manifest,True)

class ComposedTests(unittest.TestCase):
    def exercise(self,cleanup_failure=False,ordinary_failure=False,wrapper_timeout=False,finish_error=False):
        parents=[];endpoints=[];rows={};commands=[]
        class Parent:
            def __init__(self,report):self.report=Path(report);self.process=SimpleNamespace(pid=100+len(parents),returncode=0);parents.append(self)
            def start(self,argv):
                commands.append(argv);self.argv=argv
                if argv[1]=='--invalid-mechanics-control':self.process.returncode=2;return
                name=self.report.parent.name if self.report.name!='profile.json' else 'profile';self.name=name
                row=parent_row();row['phase']='profile' if name=='profile' else argv[8]
                if name=='profile':row.update(childCreated=False,childPid=0,tokenQuerySucceeded=False,resumeAttempted=False,resumeCount=None,resumed=False,waitSignaled=False,childExitCode=None,childReportObserved=False,childReportBytes=0,childReportSha256=None,failure='profile_only')
                if name in ('token_failure','sid_mismatch','resume_failure','timeout'):
                    row.update(failure={'token_failure':'token','sid_mismatch':'sid','resume_failure':'resume_fixture','timeout':'timeout'}[name],resumeAttempted=name=='timeout',resumed=name=='timeout',resumeCount=1 if name=='timeout' else None,terminateAttempted=True,terminationSucceeded=True,childExitCode=5,childReportObserved=False,childReportBytes=0,childReportSha256=None,timedOut=name=='timeout');self.process.returncode=5
                if cleanup_failure and name=='contained':row['cleanupConfirmed']=False
                rows[id(self)]=row
            def wait(self,deadline):return not(wrapper_timeout and getattr(self,'name','')=='contained')
            def finish(self,deadline):
                if finish_error and getattr(self,'name','')=='contained':raise OSError('PRIVATE')
                return dict(parent_exit_observed=True,parent_killed=wrapper_timeout and getattr(self,'name','')=='contained',parent_handles_closed=True,parent_cleanup_confirmed=True)
        class Endpoint:
            def __init__(self,nonce,deadline):self.index=len(endpoints);endpoints.append(self)
            def start(self):return 40000
            def finish(self,deadline):return dict(cleanup_confirmed=True,error=False,counts=dict(datagrams=45 if self.index==0 else 1 if self.index==4 else 0,rejected=0,oversized=0,send_errors=0),verified_indices=dict(contained=[0,1,2] if self.index==0 else []))
        def report(parent,nonce,phase,failures):return dict(tokenElevated=True),rows[id(parent)]
        networks=nf.reports(False,False)
        def child(path,nonce,phase,port,row):
            if ordinary_failure and phase=='after':raise ValueError('child_binding')
            return dict(udp=networks[phase])
        real_mkdtemp=m.tempfile.mkdtemp;roots=[]
        def mkdtemp(**kw):value=real_mkdtemp(**kw);roots.append(Path(value));return value
        # Patch only platform string, leaving pathlib's concrete platform choice intact.
        with patch.object(m,'os',SimpleNamespace(name='nt')),patch.object(m,'OwnedParent',Parent),patch.object(m.u,'UdpEndpoint',Endpoint),patch.object(m,'verify_parent',return_value=b'MZ'+bytes(510)),patch.object(m.mechanics,'verify'),patch.object(m.mechanics,'read',return_value=b'MZ'+bytes(510)),patch.object(m,'parent_report',side_effect=report),patch.object(m,'verified_child',side_effect=child),patch.object(m.secrets,'token_hex',return_value=nf.NONCE),patch.object(m.time,'sleep'),patch.object(m.tempfile,'mkdtemp',side_effect=mkdtemp):
            result=m.run(Path('windows_n0a_udp_parent.exe'),Path('prod.json'),Path('windows_n0a_UDP_PARENT_TEST_ONLY_fixture.exe'),Path('fixture.json'),Path('windows_n0a_UDP_TEST_ONLY_fixture.exe'),Path('child.json'))
        for root in roots:
            if root.exists():m.shutil.rmtree(root)
        return result,commands
    def test_complete_sequence_and_no_valid_production_network_command(self):
        result,commands=self.exercise();self.assertTrue(result['mechanics_complete'],result)
        self.assertEqual(len(commands),10);self.assertEqual(commands[-1],['windows_n0a_udp_parent.exe','--invalid-mechanics-control'])
        self.assertTrue(result['profile_only_verified']);self.assertTrue(result['cases']['timeout']['expected_refusal'])
        self.assertFalse(result['appcontainer_inheritance_tested']);self.assertEqual(result['fixture_send_accepted_count'],3)
    def test_sticky_bound_send_facts_after_unrelated_cleanup_or_control_failure(self):
        for kwargs in ({'cleanup_failure':True},{'ordinary_failure':True}):
            result,_=self.exercise(**kwargs);self.assertFalse(result['mechanics_complete']);self.assertEqual(result['fixture_send_accepted_count'],3);self.assertEqual(result['fixture_echo_count'],3)
        result,_=self.exercise(cleanup_failure=True);self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['work_removed'])
    def test_wrapper_timeout_never_proves_descendant_cleanup(self):
        result,_=self.exercise(wrapper_timeout=True);self.assertFalse(result['descendant_cleanup_confirmed']);self.assertFalse(result['work_removed']);self.assertTrue(result['receivers'])

    def test_one_parent_cleanup_exception_does_not_skip_others_or_receivers(self):
        result,_=self.exercise(finish_error=True)
        self.assertEqual(len(result['parents_cleanup']),10);self.assertEqual(len(result['receivers']),5)
        self.assertFalse(result['cleanup_confirmed']);self.assertFalse(result['work_removed'])
        self.assertEqual(result['fixture_send_accepted_count'],3)
