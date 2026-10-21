"""Default-OFF UDP6 orchestration contracts; no actual child or socket execution."""
import copy
import types
import unittest
from unittest.mock import patch
from tests import test_windows_udp6_flow_composed as fixture
g=fixture.g

class Control(unittest.TestCase):
    def fixture(self):
        binding,cases,*_=fixture.Composed().make()
        calls=[]
        class Execution:
            def probe(self,*a,**kw):calls.append('probe')
            def invoke(self,role,phase,*a,**kw):calls.append(phase);return cases[phase]
            def start(self,*a,**kw):calls.append('start');return object()
            def wait(self,*a,**kw):calls.append('sample');return cases['sample']
            def close_owned(self,*a):calls.append('close');return True
        return binding,cases,Execution(),calls
    def test_default_off_and_explicit_approval(self):
        b,c,e,calls=self.fixture();self.assertTrue(g.engine.EXECUTION_ENABLED)
        with patch.object(g.engine,'EXECUTION_ENABLED',False):
            with self.assertRaises(PermissionError):g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0)
        with patch.object(g.engine,'EXECUTION_ENABLED',True):
            with self.assertRaises(PermissionError):g.engine.run_endpoint(e,b,100,approved=False,clock=lambda:0)
        self.assertEqual(calls,[])
    def test_success_order_and_one_deadline(self):
        b,c,e,calls=self.fixture()
        with patch.object(g.engine,'EXECUTION_ENABLED',True):
            result=g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0,sleep=lambda _:None)
        self.assertEqual(calls,['probe','before','start','contained','sample','after','close'])
        self.assertTrue(result['cleanup_confirmed']);self.assertFalse(result['driver_error'])
    def test_failed_ordinary_echo_or_identity_never_launches_contained(self):
        for failure in ('echo','profile','pid','timeout','family','sockets'):
            b,c,e,calls=self.fixture()
            if failure=='echo':c['before']['actor']['udp6']['attempts'][0]['nonceMatched']=False
            if failure=='profile':c['before']['actor']['tokenElevated']=True
            if failure=='pid':c['before']['pid_verified']=False
            if failure=='timeout':c['before']['timed_out']=True
            if failure=='sockets':c['before']['actor']['udp6']['socketsCleanupConfirmed']=False
            if failure=='family':c['before']['actor']['udp6']['endpoint']='runner'
            with patch.object(g.engine,'EXECUTION_ENABLED',True):
                result=g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0,sleep=lambda _:None)
            self.assertEqual(calls,['probe','before']);self.assertTrue(result['driver_error'])
            self.assertNotIn('contained',result)
    def test_expired_does_not_probe_or_renew(self):
        b,c,e,calls=self.fixture()
        with patch.object(g.engine,'EXECUTION_ENABLED',True):
            result=g.engine.run_endpoint(e,b,1,approved=True,clock=lambda:2,sleep=lambda _:None)
        self.assertEqual(calls,[]);self.assertTrue(result['driver_error'])
    def test_bound_positive_survives_missing_after_and_cleanup_failure(self):
        b,c,e,calls=self.fixture();del c['after'];c['cleanup_confirmed']=False;c['driver_error']=True
        result=g.engine.evaluate(c,b)
        self.assertEqual(result['selected_send_accepted_count'],3)
        self.assertFalse(result['ordinary_controls_verified']);self.assertFalse(result['sockets_cleanup_confirmed'])
    def test_no_duck_binding_and_ipv4_actor_relabel(self):
        b,c,e,calls=self.fixture()
        self.assertIsNone(g.engine.bound_actor(c['contained'],types.SimpleNamespace(**vars(b))))
        c['contained']['actor']['mode']='actor-n0a-udp'
        self.assertEqual(g.engine.evaluate(c,b)['selected_send_accepted_count'],0)

    def test_failed_runner_phase_closed_receipt_preserves_observation(self):
        from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
        b,c,e,calls=self.fixture();result=g.engine.evaluate(c,b)
        report=dict(schema_version=1,binding=dict(case_nonce=b.nonce,actor_sha256=b.actor_sha256,
            executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457),result=result,
            execution=dict(phase='runner',failed=True,cleanup_confirmed=False))
        outer=dict(schema_version=1,case_nonce=b.nonce,actor_sha256=b.actor_sha256,report=report,
            launcher=dict(phase='completed',failure='operation_failed',python_exit_code=1,
                          process_exit_confirmed=True,timed_out=False,budget_exhausted=False))
        observed=g.engine.validate_host_udp6_envelope(outer,dict(case_nonce=b.nonce,actor_sha256=b.actor_sha256))
        self.assertTrue(observed['receipt_verified']);self.assertEqual(observed['result']['selected_send_accepted_count'],3)
        self.assertFalse(observed['result']['ordinary_controls_verified'])

if __name__=='__main__':unittest.main()
