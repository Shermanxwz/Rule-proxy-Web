"""No DNS/socket/process APIs: hostile reports and supervised-owner fake seam."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_v1_owner_test',ROOT/'.github/windows_identity_dns_v1_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
RUN='1'*32;ACTOR_RUN='2'*32;SID='S-1-5-21-1';H='a'*64
def launch(pid):
    return dict(started=True,resumed=True,timed_out=False,exit_code=0,child_pid=pid,
        native_identity_verified_before_resume=True,
        cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,process_exit_confirmed=True,close_uncertain=False,errors=[]))
def native():
    return dict(schema_version=1,stage='dns-v1-native',qpc_frequency=10,deadline_qpc=1100,
        identity=dict(schemaVersion=1,mode='actor',nonce=ACTOR_RUN,pid=501,tokenUserSid=SID,tokenIsAppContainer=False,
            tokenAppContainerSid=None,tokenElevated=False,isProcessInJob=True,tokenCapabilities=[],queriesSucceeded=True,errors=[]),
        result=dict(configured=True,called=True,completed=True,pending=False,answer_match=True,records_released=True,
            context_retained=False,within_deadline=True,api_status=0,query_status=0,record_count=1,start_qpc=100,end_qpc=105))
def fixture():
    return dict(ready=True,socket_closed=True,thread_stopped=True,cleanup_confirmed=True,error='none',
        counts=dict(datagrams=1,bytes=60,matched_queries=1,answers_sent=1,rejected=0,oversized=0,send_failed=0),
        query_observed=True,byte_count_is_observed_lower_bound=True,broker_cancellation_proven=False)
class API:
    atomic_job_requested=True
    def qpc_frequency(self):return 10
    def qpc(self):return 100
    def device_sha256(self):return H
    def private_directory(self,path,sid):path.mkdir()
class DnsV1LocalTests(unittest.TestCase):
    def owner(self,*,raw=None,inner=None,outer=None,receiver=None,worker_failure=None):
        raw=m.encode(native()) if raw is None else raw
        text,status,digest=m.native_text(raw)
        report=dict(schema_version=1,run=RUN,actor_run=ACTOR_RUN,worker_pid=500,worker_sid=SID,
            source_sha256=H,frequency=10,deadline=1250,failure=worker_failure,
            launch=launch(501) if inner is None else inner,fixture=fixture() if receiver is None else receiver,
            native=text,native_status=status,native_sha256=digest,actor_atomic=True)
        pre=m.blank('preflight');pre.update(status='ready',source_sha256=H,actor_sha256=H,manifest_sha256=H,recovery_plan_sha256=m.sha(b'plan'))
        for key in ('ordinary','device_plan','source_bound','artifact_bound'):pre['checks'][key]=True
        def bounded(path,limit):
            name=Path(path).name
            if name=='plan.json':return b'plan'
            if name=='dns-worker-report.json':return m.encode(report)
            return b'native'
        with tempfile.TemporaryDirectory() as temp:
            parent=Path(temp)
            with patch.object(m.local,'LocalNativeAPI',API),patch.object(m.local,'ordinary',return_value={'sid':SID}),\
                 patch.object(m,'preflight',return_value=pre),patch.object(m,'snapshot',return_value=({}, {}, H)),\
                 patch.object(m,'artifact',return_value=None),patch.object(m.local,'bounded',side_effect=bounded),\
                 patch.object(m.launcher,'write_private_bytes',side_effect=lambda p,raw:p.write_bytes(raw)),\
                 patch.object(m.launcher,'launch_owned',return_value=launch(500) if outer is None else outer),\
                 patch.object(m.secrets,'token_hex',side_effect=[RUN,ACTOR_RUN]):
                return m.run_local(parent/'actor',parent/'manifest',H,H,parent,parent/'plan.json',approved=True)
    def test_full_same_api_receiver_positive(self):
        value=self.owner();self.assertEqual(value['status'],'passed');self.assertTrue(value['mechanism_passed'])
        self.assertFalse(value['default_resolver_tested']);self.assertFalse(value['dns_isolation_qualified'])
    def test_malformed_json_retains_receiver_positive(self):
        value=self.owner(raw=b'{');self.assertEqual(value['status'],'inconclusive')
        self.assertTrue(value['owned_query_observed']);self.assertTrue(value['network_tested']);self.assertIsNone(value['api'])
    def test_non_ascii_retains_receiver_positive(self):
        value=self.owner(raw=b'\xff',worker_failure='report');self.assertTrue(value['owned_query_observed'])
        self.assertEqual(value['status'],'inconclusive');self.assertIsNone(value['api'])
    def test_wrong_pid_keeps_receiver_but_rejects_native(self):
        v=native();v['identity']['pid']=502;out=self.owner(raw=m.encode(v))
        self.assertTrue(out['owned_query_observed']);self.assertIsNone(out['api']);self.assertFalse(out['mechanism_passed'])
    def test_wrong_user_rejects(self):
        v=native();v['identity']['tokenUserSid']='S-1-5-21-2';self.assertFalse(self.owner(raw=m.encode(v))['mechanism_passed'])
    def test_bool_version_rejects(self):
        v=native();v['identity']['schemaVersion']=True;self.assertIsNone(self.owner(raw=m.encode(v))['api'])
    def test_unknown_native_field_rejects(self):
        v=native();v['extra']=0;self.assertIsNone(self.owner(raw=m.encode(v))['api'])
    def test_non_boolean_result_rejects_before_public_assignment(self):
        v=native();v['result']['called']='yes';out=self.owner(raw=m.encode(v));self.assertTrue(out['owned_query_observed']);self.assertIsNone(out['api'])
    def test_actor_timeout_cannot_pass_even_after_positive_report(self):
        l=launch(501);l['timed_out']=True;v=self.owner(inner=l)
        self.assertTrue(v['owned_query_observed']);self.assertTrue(v['api']['answer_match']);self.assertFalse(v['mechanism_passed'])
    def test_actor_error_or_nonzero_exit_cannot_pass(self):
        for key,value in (('error','fake'),('exit_code',5),('started',False),('resumed',False)):
            with self.subTest(key=key):
                l=launch(501);l[key]=value;self.assertFalse(self.owner(inner=l)['mechanism_passed'])
    def test_outer_timeout_cannot_pass(self):
        l=launch(500);l['timed_out']=True;self.assertFalse(self.owner(outer=l)['mechanism_passed'])
    def test_api_invalid_parameter_is_not_wire_or_denial(self):
        v=native();v['result'].update(api_status=87,query_status=0,answer_match=False,record_count=0)
        f=fixture();f['query_observed']=False
        for key in ('datagrams','bytes','matched_queries','answers_sent'):f['counts'][key]=0
        out=self.owner(raw=m.encode(v),receiver=f)
        self.assertTrue(out['api']['called']);self.assertFalse(out['network_tested']);self.assertFalse(out['mechanism_passed'])
    def test_partial_receiver_snapshot_keeps_positive_and_uncertain_cleanup(self):
        f=fixture();f.update(counts=None,thread_stopped=False,cleanup_confirmed=False)
        v=self.owner(receiver=f);self.assertTrue(v['owned_query_observed']);self.assertTrue(v['recovery_required']);self.assertFalse(v['mechanism_passed'])
    def test_pending_context_is_retained_and_cannot_pass(self):
        v=native();v['result'].update(completed=False,pending=True,answer_match=False,records_released=False,context_retained=True,record_count=0)
        self.assertFalse(self.owner(raw=m.encode(v))['mechanism_passed'])
    def test_unretained_pending_rejected(self):
        v=native();v['result'].update(completed=False,pending=True,answer_match=False,records_released=False,context_retained=False,record_count=0)
        self.assertIsNone(self.owner(raw=m.encode(v))['api'])
    def test_after_deadline_answer_rejected(self):
        v=native();v['result']['end_qpc']=1100;self.assertIsNone(self.owner(raw=m.encode(v))['api'])
    def test_preflight_refuses_runtime_facts(self):
        v=m.blank('preflight');v['api']={k:x for k,x in native()['result'].items() if k not in ('start_qpc','end_qpc')}
        with self.assertRaises(ValueError):m.validate(v)
    def test_ready_cannot_be_claimed_without_all_preflight_checks(self):
        v=m.blank('preflight');v['status']='ready'
        with self.assertRaises(ValueError):m.validate(v)
    def test_native_text_non_ascii_has_digest_and_no_decode_exception(self):
        text,status,digest=m.native_text(b'\xff');self.assertIsNone(text);self.assertEqual(status,'non-ascii');self.assertEqual(digest,m.sha(b'\xff'))
    def test_partial_receiver_cannot_invent_exact_counts(self):
        f=fixture();f['thread_stopped']=False
        with self.assertRaises(ValueError):m.receiver_projection(f)
    def test_selected_scope_cannot_be_claimed(self):
        v=self.owner();v['selected_application_tested']=True
        with self.assertRaises(ValueError):m.validate(v)
if __name__=='__main__':unittest.main()
