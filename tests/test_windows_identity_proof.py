import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('windows_identity_proof', ROOT / '.github/windows_identity_proof.py')
proof = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(proof)
N = 'a' * 32
SID = 'S-1-15-2-1-2-3-4-5-6-7'

def proxy():
    return dict(profile='RuleProxy.IdentityProof.' + N, derived_sid=SID, token_sid=SID, appcontainer=True, port=31001)

def probe():
    return dict(tier='base-container', needsDaclAugmentation=False, probes={'baseContainerApiPresent': True}, error=None)

def evidence():
    return dict(nonce=N, probe=probe(), probe_exit_code=0, actual_tiers=['base-container'], executor_exit_code=0,
                timed_out=False, actor=dict(schemaVersion=1, mode='actor', nonce=N, queriesSucceeded=True, errors=[],
                tokenIsAppContainer=True, tokenAppContainerSid=SID, tokenElevated=False, isProcessInJob=True, tokenCapabilities=[], pid=123))

class PolicyTests(unittest.TestCase):
    def test_stage_zero_has_no_proxy_or_network_grants(self):
        p = proof.policy('inputs', 'profile', 'actor.exe', N)
        self.assertEqual(p['network'], {'egress': {'default': 'deny'}, 'ingress': {'default': 'deny', 'hostLoopback': 'deny'}})
        self.assertNotIn('runtimeConfig', p)
        self.assertNotIn('processContainer', p)
        self.assertEqual(p['fallback'], {'allowDaclMutation': False})
        self.assertIs(p['process']['inheritDefaultEnv'], False)
    def test_identity_policy_never_opens_general_host_loopback(self):
        p = proof.policy('inputs', 'profile', 'actor.exe', N, proxy=proxy())
        self.assertEqual(p['network'], {'egress': {'default': 'deny'}, 'ingress': {'default': 'allow', 'hostLoopback': 'deny'}})
        self.assertEqual(p['processContainer']['network']['allowedProxyPeer'], proxy()['profile'])
        self.assertEqual(p['runtimeConfig']['networkProxy'], 'http://127.0.0.1:31001')
        self.assertIn('actor-http', p['process']['commandLine'])
    def test_bad_nonce_rejected(self):
        for n in ('', 'A'*32, 'a'*31, N+'\n', None):
            with self.subTest(n=n), self.assertRaises(ValueError): proof.policy('i','p','a',n)
    def test_identity_mismatch_rejected(self):
        for key, val in [('token_sid', 'S-1-15-2-9-2-3-4-5-6-7'), ('appcontainer', False), ('profile', 'MXC-Loopback'),
                         ('derived_sid', ''), ('port', 80), ('port', 65536), ('port', True), ('port', '31001')]:
            p=proxy(); p[key]=val
            with self.subTest(key=key,val=val), self.assertRaises(ValueError): proof.policy('i','p','a',N,proxy=p)
    def test_missing_or_extra_identity_field_rejected(self):
        for p in ({}, {'profile':'foo'}, dict(proxy(), invented=True)):
            with self.assertRaises(ValueError): proof.policy('i','p','a',N,proxy=p)

class EvidenceTests(unittest.TestCase):
    def test_complete_evidence_passes(self): self.assertTrue(all(proof.stage0_checks(evidence()).values()))
    def test_tier_extraction_is_exact(self):
        self.assertEqual(proof.actual_tiers(b'selected isolation tier: base-container\r\n'), ['base-container'])
        self.assertEqual(proof.actual_tiers(b'fake selected isolation tier: base-container\n'), [])
        self.assertEqual(proof.actual_tiers(b'x'*(proof.MAX_OUTPUT+1)), [])
    def test_duplicate_tier_is_not_success(self):
        r=evidence(); r['actual_tiers']*=2
        self.assertFalse(proof.stage0_checks(r)['actual_base_container'])
    def test_fallback_and_missing_evidence_fail(self):
        for key,val in [('actual_tiers', []), ('actual_tiers',['appcontainer-bfs']), ('probe_exit_code',1),
                        ('executor_exit_code',1), ('timed_out',True), ('nonce','b'*32)]:
            r=evidence(); r[key]=val
            with self.subTest(key=key): self.assertFalse(all(proof.stage0_checks(r).values()))
    def test_actor_identity_failures(self):
        for key,val in [('tokenIsAppContainer',False), ('tokenAppContainerSid',None), ('tokenElevated',True),
                        ('isProcessInJob',False), ('queriesSucceeded',False), ('errors',['failed']), ('pid',True),
                        ('mode','actor-http'), ('nonce','b'*32)]:
            r=evidence(); r['actor'][key]=val
            with self.subTest(key=key): self.assertFalse(all(proof.stage0_checks(r).values()))
    def test_empty_report_never_passes(self): self.assertFalse(all(proof.stage0_checks({}).values()))

class RunnerTests(unittest.TestCase):
    def test_unsupported_never_executes_actor(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, json.dumps(dict(probe(), tier='appcontainer-bfs')).encode(), b''))
        with tempfile.TemporaryDirectory() as d:
            r=proof.run_case('executor.exe', {}, d, runner=runner)
        self.assertEqual(r['status'],'unsupported'); self.assertFalse(r['started']); self.assertEqual(runner.call_count,1)
    def test_malformed_probe_never_executes_actor(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, b'garbage', b''))
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=runner)
        self.assertFalse(r['started']); self.assertEqual(runner.call_count,1)
    def test_oversize_probe_fails_closed(self):
        runner=Mock(return_value=subprocess.CompletedProcess([], 0, b' '*(proof.MAX_OUTPUT+1), b''))
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=runner)
        self.assertFalse(r['started'])
    def test_runtime_tier_is_not_copied_from_probe(self):
        def run(args, **kw):
            if '--probe' in args: return subprocess.CompletedProcess(args,0,json.dumps(probe()).encode(),b'')
            kw['stderr'].write(b'selected isolation tier: appcontainer-bfs\n')
            return subprocess.CompletedProcess(args,0)
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=run)
        self.assertEqual(r['actual_tiers'], ['appcontainer-bfs'])
    def test_timeout_is_preserved(self):
        def run(args, **kw):
            if '--probe' in args: return subprocess.CompletedProcess(args,0,json.dumps(probe()).encode(),b'')
            raise subprocess.TimeoutExpired(args,35)
        with tempfile.TemporaryDirectory() as d: r=proof.run_case('executor.exe',{},d,runner=run)
        self.assertTrue(r['timed_out']); self.assertIsNone(r['executor_exit_code'])
    def test_runtime_requires_explicit_windows_approval(self):
        class Args: disposable_ci=False; approved_security_test=False
        with self.assertRaises(PermissionError): proof.controller(Args())

if __name__=='__main__': unittest.main()
