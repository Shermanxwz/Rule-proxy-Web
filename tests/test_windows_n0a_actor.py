"""Pure source/fixture contract tests; no claim of native Windows execution."""
from pathlib import Path
import ast
import hashlib
import unittest
import importlib.util
from unittest import mock
import subprocess

ROOT=Path(__file__).resolve().parents[1]
ACTOR=(ROOT/'.github/native/windows_n0a_actor.cpp').read_text()
BUILD=(ROOT/'.github/build_windows_n0a_actor.ps1').read_text()
FIXTURE=(ROOT/'.github/native/windows_n0a_fixture.cpp').read_text()
FIXTURE_BUILD=(ROOT/'.github/build_windows_n0a_fixture.ps1').read_text()
GATE=(ROOT/'.github/test_windows_n0a_actor.py').read_text()

class N0aActorContractTests(unittest.TestCase):
    def test_unchanged_identity_dependency_reused_only(self):
        self.assertEqual(hashlib.sha256((ROOT/'.github/native/windows_identity_actor.cpp').read_bytes()).hexdigest(),
                         '530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553')
        self.assertIn('#define RULEPROXY_IDENTITY_ONLY 1',ACTOR)
        self.assertIn('#define wmain UnusedIdentityEntry',ACTOR)
        self.assertIn('#include "windows_identity_actor.cpp"',ACTOR)
        self.assertIn('MakeReport("actor-n0a"',ACTOR)
        self.assertNotIn('WinHttp',ACTOR)

    def test_destinations_numeric_fixed_and_no_resolver(self):
        self.assertIn('runner?0x0a000202UL:0x7f000001UL',ACTOR)
        for forbidden in ('getaddrinfo','gethostbyname','DnsQuery','SetCurrentThreadCompartmentId','GetCurrentThreadCompartmentId','SO_REUSEADDR'):
            self.assertNotIn(forbidden,ACTOR)
        self.assertIn('role==L"contained" && pattern!=L"single"',ACTOR)
        self.assertIn('result<1025 || result>65535',ACTOR)

    def test_profile_before_socket_startup(self):
        run=ACTOR[ACTOR.index('int Run(int argc,wchar_t* argv[])'):]
        self.assertLess(run.index('ObserveNativeIdentity()'),run.index('Profile(identity,contained)'))
        self.assertLess(run.index('if (profile)'),run.index('WSAStartup'))
        self.assertIn('capability.attributes != SE_GROUP_ENABLED',ACTOR)
        self.assertIn('EqualSid(actual,ids.capabilities[0])',ACTOR)
        self.assertIn('identity.tokenCapabilities.size()==1',ACTOR)
        self.assertIn('identity.tokenCapabilities.empty()',ACTOR)

    def test_source_hashes_both_pinned_before_after(self):
        for field in ('ExpectedSourceSha256','ExpectedIdentitySourceSha256','identitySourceSha256','identityHashAfter','sourceHashAfter'):
            self.assertIn(field,BUILD)
        self.assertIn('windows_n0a_actor.exe',BUILD)
        self.assertNotIn('windows_n0a_TEST_ONLY_fixture.exe',BUILD)

    def test_fixture_binary_separate_nondeployable(self):
        self.assertIn('#define RULEPROXY_N0A_FIXTURE 1',FIXTURE)
        self.assertIn('#ifndef RULEPROXY_N0A_FIXTURE',ACTOR)
        self.assertIn('windows_n0a_TEST_ONLY_fixture.exe',FIXTURE_BUILD)
        self.assertIn('TEST-ONLY-manifest.json',FIXTURE_BUILD)
        self.assertIn('deployable=$false',FIXTURE_BUILD)
        self.assertNotIn('GITHUB_OUTPUT',FIXTURE_BUILD)
        self.assertNotIn('--owned-loopback-fixture',ACTOR)

    def test_absolute_finite_schedule(self):
        self.assertIn('ContainedBudget = 3000',ACTOR)
        self.assertIn('SampleBudget = 10000',ACTOR)
        self.assertIn('MaxSamples = 40',ACTOR)
        self.assertIn('const ULONGLONG deadline=start+',ACTOR)
        self.assertIn('std::min(deadline,now+(sample?500:1000))',ACTOR)
        self.assertIn('start+static_cast<ULONGLONG>(index)*(sample?250:500)',ACTOR)
        self.assertIn('attempts.back().exchangeEndQpc',ACTOR)
        self.assertIn('sample?MaxSamples:(contained?3:1)',ACTOR)

    def test_native_error_origin_and_sticky_connection(self):
        self.assertIn('Error(result,"connect",error)',ACTOR)
        self.assertIn('Error(result,"completion",socketError)',ACTOR)
        self.assertIn('Error(result,"getsockopt_error",WSAGetLastError())',ACTOR)
        self.assertEqual(ACTOR.count('result.connectSucceeded=true'),2)
        self.assertNotIn('result.connectSucceeded=false',ACTOR)
        self.assertLess(ACTOR.index('if (!Wait(owned.value,true,true'),ACTOR.index('getsockopt(owned.value'))
        self.assertIn('if (socketError!=0)',ACTOR)

    def test_every_sample_owns_fresh_socket(self):
        self.assertIn('Socket owned;',ACTOR)
        self.assertIn('owned.value=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP)',ACTOR)
        self.assertIn('attempts.push_back(Probe(',ACTOR)
        self.assertIn('result.closed=owned.close()',ACTOR)
        self.assertIn('local.sin_port=0',ACTOR)
        self.assertIn('getsockname',ACTOR)

    def test_report_composition_bounded_and_fixture_executed(self):
        self.assertIn('MaxReport = 32768',ACTOR)
        self.assertIn('report.size()>MaxReport',ACTOR)
        self.assertIn('std::vector<n0a::Attempt> attempts(40)',FIXTURE)
        self.assertIn("'--report-shape'",GATE)
        self.assertIn("json.loads(shaped.stdout)",GATE)
        self.assertIn('len(shaped.stdout) <= 32768',GATE)
        self.assertIn('engine.observation(envelope, binding',GATE)
        self.assertIn("'wire_binding_synthetic': True",GATE)

    def test_cleanup_attempts_both_streams_after_kill_and_wait_failure(self):
        spec=importlib.util.spec_from_file_location('n0a_native_gate_cleanup',ROOT/'.github/test_windows_n0a_actor.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        child=mock.Mock()
        child.poll.return_value=None
        child.kill.side_effect=OSError('private failure')
        child.wait.side_effect=subprocess.TimeoutExpired('private argv',2)
        child.stdout.closed=True;child.stderr.closed=True
        self.assertEqual(gate.finish_child(child),(False,False))
        child.kill.assert_called_once();child.wait.assert_called_once_with(timeout=2)
        child.stdout.close.assert_called_once();child.stderr.close.assert_called_once()

    def test_cleanup_finished_child_and_absent_child(self):
        spec=importlib.util.spec_from_file_location('n0a_native_gate_cleanup',ROOT/'.github/test_windows_n0a_actor.py')
        gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
        self.assertEqual(gate.finish_child(None),(True,True))
        child=mock.Mock();child.poll.return_value=0
        child.stdout.closed=True;child.stderr.closed=True
        self.assertEqual(gate.finish_child(child),(True,True));child.kill.assert_not_called()

    def test_gate_is_explicit_and_redacts_private_records(self):
        ast.parse(GATE)
        self.assertIn("'--run-owned-loopback-fixtures'",GATE)
        self.assertIn("if os.name != 'nt'",GATE)
        self.assertIn("'token_guard_exercised_by_socket_fixture': False",GATE)
        self.assertIn("'runtime_acceptance': False",GATE)
        self.assertIn("('good', 'wrong', 'timeout')",GATE)
        self.assertIn("value['n0a']['profileMatched'] is False",GATE)
        self.assertIn('if confirmed:',GATE)
        self.assertIn("value['tokenElevated'] is True",GATE)
        self.assertIn("production_guard(args.actor_exe, 'ordinary')",GATE)
        self.assertNotIn('54321',GATE)
        self.assertNotIn('print(record',GATE)
        self.assertNotIn('print(value',GATE)
        self.assertIn('except BaseException as failure:',GATE)
        self.assertIn("'failure_kind': kind",GATE)

if __name__=='__main__': unittest.main()
