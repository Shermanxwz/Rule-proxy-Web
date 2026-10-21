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

    def test_every_driver_operation_failure_is_labeled_not_guessed(self):
        mapping={'probe':'probe','before':'before_invoke','start':'sample_start','delay':'overlap_delay','contained':'contained_invoke','sample':'sample_wait','after':'after_invoke','close':'sampler_cleanup'}
        for target,expected in mapping.items():
            b,c,e,calls=self.fixture()
            def fail(name,original):
                def call(*a,**kw):
                    if name==target:raise RuntimeError('private text not exported')
                    return original(*a,**kw)
                return call
            e.probe=fail('probe',e.probe);e.start=fail('start',e.start);e.wait=fail('sample',e.wait);e.close_owned=fail('close',e.close_owned)
            original=e.invoke
            def invoke(role,phase,*a,**kw):return fail(phase,original)(role,phase,*a,**kw)
            e.invoke=invoke
            sleep=fail('delay',lambda _:None)
            with patch.object(g.engine,'EXECUTION_ENABLED',True):
                result=g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0,sleep=sleep)
            d=g.engine.evaluate(result,b)['diagnostic'];self.assertEqual(d['failed_stage'],expected)
            g.engine.validate_diagnostic(d)
            self.assertNotIn('private text',str(d))
            if target in ('sample','after','close'):
                self.assertEqual(g.engine.evaluate(result,b)['selected_send_accepted_count'],3)
            if target=='before':self.assertEqual(d['phases'][0][:2],[True,False])
            if target=='start':self.assertEqual(d['phases'][1][:2],[True,False])
            if target=='contained':self.assertEqual(d['phases'][2][:2],[True,False])
    def test_before_validation_diagnostic_never_changes_admission(self):
        b,c,e,calls=self.fixture();c['before']['actor']['udp6']['attempts'][0]['sendBytes']=True
        result=g.engine.evaluate(c,b);d=result['diagnostic']['before']
        self.assertTrue(result['profile_verified']['before']) # Historical flag semantics preserved.
        self.assertEqual(d['checks'][:4],[True,True,True,False]);self.assertEqual(d['validation'],'row')
        self.assertIsNone(d['attempt'][11]);self.assertIsNone(d['checks'][12])
        c['before']['actor']['nonce']='b'*32
        d=g.engine.evaluate(c,b)['diagnostic']['before'];self.assertIsNone(d['attempt']);self.assertEqual(d['network'],[None]*3)
    def test_peer_diagnostics_types_and_no_new_acceptance_predicate(self):
        b,c,e,calls=self.fixture();network=c['before']['actor']['udp6']
        for key in g.engine.PEER_DIAGNOSTIC_KEYS:network['attempts'][0][key]=False
        self.assertIsNotNone(g.engine.invocation_valid(c['before'],b,'before'))
        self.assertTrue(g.engine.echo_success(network['attempts'][0]))
        self.assertEqual(g.engine.evaluate(c,b)['diagnostic']['before']['attempt'][17:],[False]*6)
        network['attempts'][0][g.engine.PEER_DIAGNOSTIC_KEYS[0]]=1
        with self.assertRaises(ValueError):g.engine.validate_network(network,b.nonce,'before',b.runner_port)
    def test_diagnostic_closed_shape_rejects_extra_and_wrong_types(self):
        import copy
        b,c,e,calls=self.fixture();d=g.engine.evaluate(c,b)['diagnostic']
        for mutate in (lambda x:x.update(pid=123),lambda x:x['phases'][0].__setitem__(0,1),
                       lambda x:x['before']['checks'].__setitem__(0,1),lambda x:x['before']['attempt'].__setitem__(17,1)):
            changed=copy.deepcopy(d);mutate(changed)
            with self.assertRaises(ValueError):g.engine.validate_diagnostic(changed)

    def test_unsigned_readback_and_cleanup_false_are_truthful(self):
        self.assertEqual(g.engine.diagnostic_scalar(8,4294967295),4294967295)
        self.assertIsNone(g.engine.diagnostic_scalar(8,-1))
        b,c,e,calls=self.fixture();e.close_owned=lambda _:False
        with patch.object(g.engine,'EXECUTION_ENABLED',True):
            result=g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0,sleep=lambda _:None)
        self.assertEqual(result['driver_diagnostic']['failed_stage'],'sampler_cleanup')
        self.assertEqual(result['driver_diagnostic']['failure'],'cleanup')
        self.assertFalse(result['cleanup_confirmed'])
        c['before']['actor']['udp6']['attempts'][0]['nonceMatched']=False
        with patch.object(g.engine,'EXECUTION_ENABLED',True):
            result=g.engine.run_endpoint(e,b,100,approved=True,clock=lambda:0,sleep=lambda _:None)
        self.assertEqual(result['driver_diagnostic']['failed_stage'],'before_admission')

if __name__=='__main__':unittest.main()
