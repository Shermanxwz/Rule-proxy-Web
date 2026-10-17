"""CI-only network reclaim and public annotation checks for the global capture harness."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

SPEC = importlib.util.spec_from_file_location('windows_capture_harness_ci',
    Path(__file__).resolve().parents[1] / '.github/check_windows_global_capture.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


class CiNetworkReclaimTests(unittest.TestCase):
    def recovery_mocks(self, work, dns_stop):
        from contextlib import ExitStack
        from types import SimpleNamespace
        from unittest.mock import Mock
        from ruleproxy import windows_proxy_service as service
        from ruleproxy import windows_global_dns as dns
        from ruleproxy import windows_global_guard as guard
        state = Path(work) / 'state.json'
        H.write_json(state, {'root': work, 'nonce': 'unit', 'route_created': True})
        lease = Mock()
        if isinstance(dns_stop, BaseException):
            lease.normal_stop.side_effect = dns_stop
        else:
            lease.normal_stop.return_value = dns_stop
        mocks = SimpleNamespace(state=state)
        previous_path = list(sys.path)
        self.addCleanup(sys.path.__setitem__, slice(None), previous_path)
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(patch.object(service, 'load_deployment', return_value={'root': work}))
        stack.enter_context(patch.object(service, 'protected_path'))
        stack.enter_context(patch.object(dns, 'DnsLease', return_value=lease))
        mocks.control = stack.enter_context(patch.object(H, 'service_state'))
        mocks.scope = stack.enter_context(patch.object(H, 'scoped_guard'))
        mocks.full = stack.enter_context(patch.object(guard, 'Guard'))
        mocks.full.return_value.normal_stop.return_value = {'active': False}
        mocks.powershell = stack.enter_context(patch.object(H, 'ps', return_value='ok'))
        mocks.capture = stack.enter_context(patch.object(H, 'restore_capture', return_value={'stopped': True}))
        return mocks

    def test_strict_recovery_stops_at_first_failed_step_and_keeps_result_contract(self):
        with tempfile.TemporaryDirectory() as work:
            mocks = self.recovery_mocks(work, RuntimeError('dns_probe_failed'))
            result = H._recover_locked(mocks.state)
            self.assertEqual(result, {'schema_version': 1, 'recovered': False, 'errors': ['RuntimeError:dns_probe_failed']})
            mocks.control.assert_called_once_with({'root': work}, False)
            mocks.scope.assert_not_called()
            mocks.full.assert_not_called()
            mocks.powershell.assert_not_called()
            mocks.capture.assert_not_called()
            self.assertTrue((Path(work) / 'recovery-result.json').is_file())
            self.assertFalse((Path(work) / 'ci-network-reclaim-result.json').exists())

    def test_best_effort_reclaim_runs_remaining_steps_and_is_never_counted_as_recovered(self):
        from unittest.mock import call
        with tempfile.TemporaryDirectory() as work:
            mocks = self.recovery_mocks(work, RuntimeError('dns_probe_failed'))
            result = H._recover_locked(mocks.state, best_effort=True)
            self.assertIs(result['recovered'], False)
            self.assertIs(result['best_effort'], True)
            self.assertEqual(result['errors'], ['RuntimeError:dns_probe_failed'])
            mocks.scope.return_value.normal_stop.assert_called_once_with()
            mocks.full.return_value.normal_stop.assert_called_once_with()
            mocks.powershell.assert_called_once()
            self.assertIn('Remove-NetRoute', mocks.powershell.call_args.args[0])
            self.assertEqual(mocks.control.call_args_list, [call({'root': work}, False), call({'root': work}, True)])
            mocks.capture.assert_called_once_with(mocks.state)
            self.assertFalse((Path(work) / 'recovery-result.json').exists())
            self.assertEqual(H.read_json(Path(work) / 'ci-network-reclaim-result.json'), result)

    def test_best_effort_reclaim_reports_recovered_only_when_every_step_succeeds(self):
        with tempfile.TemporaryDirectory() as work:
            mocks = self.recovery_mocks(work, {'active': False, 'supported': True})
            result = H._recover_locked(mocks.state, best_effort=True)
            self.assertEqual(result, {'schema_version': 1, 'recovered': True, 'errors': [], 'best_effort': True,
                                      'capture': {'stopped': True}})
            self.assertFalse((Path(work) / 'recovery-result.json').exists())
            self.assertTrue((Path(work) / 'ci-network-reclaim-result.json').is_file())

    def test_recover_forwards_best_effort_flag_inside_the_recovery_mutex(self):
        from unittest.mock import Mock, call
        kernel = Mock()
        kernel.CreateMutexW.return_value = 1
        kernel.WaitForSingleObject.return_value = 0
        with patch.object(H.ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(H, 'read_json', return_value={'nonce': 'unit'}), \
             patch.object(H, '_recover_locked', return_value={'recovered': False}) as locked:
            H.recover('state.json', best_effort=True)
            H.recover('state.json')
        self.assertEqual(locked.call_args_list, [call('state.json', best_effort=True), call('state.json', best_effort=False)])

    def test_ci_annotation_is_silent_without_actions_and_escapes_inside_actions(self):
        import io
        from contextlib import redirect_stdout
        with patch.dict(os.environ), redirect_stdout(io.StringIO()) as silent:
            os.environ.pop('GITHUB_ACTIONS', None)
            H._ci_annotation('error', 'Global capture summary', 'bad 100%\nline\rend')
        self.assertEqual(silent.getvalue(), '')
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), redirect_stdout(io.StringIO()) as output:
            H._ci_annotation('error', 'Global capture summary', 'bad 100%\nline\rend')
            H._ci_annotation('notice', 'Global capture stage', {'b': 1, 'a': 'x'})
            H._ci_annotation('notice', 'Global capture stage', 'y' * 2000)
        self.assertEqual(output.getvalue().split('\n'), [
            '::error title=Global capture summary::bad 100%25%0Aline%0Dend',
            '::notice title=Global capture stage::{"a":"x","b":1}',
            '::notice title=Global capture stage::' + 'y' * 1800,
            ''])

    def test_budget_stage_emits_notice_only_for_ci_milestones(self):
        import io
        from contextlib import redirect_stdout
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), \
             patch.object(H.time, 'monotonic', side_effect=[100.0, 101.0, 112.0, 113.0, 120.5, 121.0]):
            budget = H.ExperimentBudget()
            with redirect_stdout(io.StringIO()) as output:
                budget.stage('dns_carrier_prepare')
                budget.stage('global_start')
                budget.stage('ipv6_native_after_start')
                budget.stage('explicit_global_stop')
                budget.stage(None)
        self.assertEqual(output.getvalue(),
                         '::notice title=Global capture stage::global_start t=12.0\n'
                         '::notice title=Global capture stage::explicit_global_stop t=20.5\n')

    def test_system_operation_recover_adds_best_effort_reclaim_only_when_strict_failed_and_flagged(self):
        from unittest.mock import call
        from ruleproxy import windows_proxy_service as service
        failed = {'schema_version': 1, 'recovered': False, 'errors': ['RuntimeError:dns']}
        reclaim = {'schema_version': 1, 'recovered': False, 'best_effort': True, 'errors': ['RuntimeError:route']}
        recovered = {'schema_version': 1, 'recovered': True, 'errors': []}
        cases = (
            ('flagged_failed', True, [dict(failed), dict(reclaim)], 2, reclaim),
            ('flagged_reclaim_raises', True, [dict(failed), RuntimeError('boom')], 2,
             {'recovered': False, 'errors': ['RuntimeError:boom']}),
            ('unflagged_failed', False, [dict(failed)], 1, None),
            ('flagged_recovered', True, [dict(recovered)], 1, None),
        )
        for name, flag, returns, count, expected in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as work:
                state = Path(work) / 'state.json'
                H.write_json(state, {'root': work, 'nonce': 'unit', 'ci_network_reclaim': flag})
                previous_path = list(sys.path)
                try:
                    with patch.object(service, 'load_deployment', return_value={'root': work}), \
                         patch.object(service, 'protected_path'), \
                         patch.object(H, 'scoped_guard'), \
                         patch.object(H, 'recover', side_effect=returns) as recover:
                        result = H.system_operation(state, 'recover')
                finally:
                    sys.path[:] = previous_path
                self.assertEqual(recover.call_count, count)
                self.assertEqual(recover.call_args_list[0], call(state))
                if expected is None:
                    self.assertNotIn('ci_network_reclaim', result)
                else:
                    self.assertEqual(result['ci_network_reclaim'], expected)
                    self.assertEqual(recover.call_args_list[1], call(state, best_effort=True))

    def test_ci_summary_is_bounded_and_drops_paths_nonce_and_tokens(self):
        nonce = 'deadbeefcafe0123'
        private = ('C:\\ProgramData\\RuleProxy-Web\\capture-' + nonce, 'C:\\Program Files\\RuleProxy-Web', nonce)
        budget = H.ExperimentBudget()
        budget.stages = [{'stage': 'global_start', 'started_seconds': 1.0, 'elapsed_seconds': 2.5},
                         {'stage': 'final_recovery', 'started_seconds': 3.5, 'elapsed_seconds': 4.0}]
        report = {'passed': False, 'startup_smoke_passed': False, 'dns_smoke_passed': False,
                  'failed_stage': 'final_recovery',
                  'error': "RuntimeError:powershell_operation_failed:Cannot find path '" + private[0] + "\\state.json' " + 'x' * 500,
                  'recovery': {'recovered': False, 'errors': ["FileNotFoundError:'" + private[0] + "\\state.json'",
                                                              'OSError:second', 'OSError:third']},
                  'ci_network_reclaim': {'recovered': False, 'errors': ['RuntimeError:' + 'A' * 40]},
                  'capture_failure': {'code': 'pktmon_status_unknown', 'evidence': {'path': private[0]}}}
        summary = H._ci_summary(report, budget, private)
        text = json.dumps(summary, sort_keys=True)
        self.assertEqual(set(summary), {'passed', 'startup_smoke_passed', 'dns_smoke_passed', 'failed_stage', 'error',
                                        'stages', 'last_stage_elapsed', 'recovery', 'ci_network_reclaim',
                                        'capture_failure_code', 'capture'})
        self.assertLessEqual(len(summary['error']), 300)
        self.assertEqual(len(summary['recovery']['errors']), 2)
        self.assertTrue(all(len(item) <= 200 for item in summary['recovery']['errors']))
        self.assertEqual(summary['stages'], ['global_start', 'final_recovery'])
        self.assertEqual(summary['last_stage_elapsed'], 4.0)
        self.assertEqual(summary['capture_failure_code'], 'pktmon_status_unknown')
        for leaked in (nonce, 'C:', 'capture-', 'AAAA', 'evidence'):
            self.assertNotIn(leaked, text)
        self.assertEqual(summary['capture'], {'components': None, 'filter_confirmed': False, 'etl_file_bytes': None,
                                              'matching_etl_bytes': None, 'start': None, 'buffer_info': None})
        minimal = H._ci_summary({'passed': True, 'recovery': {'recovered': True}}, budget)
        self.assertEqual(set(minimal), {'passed', 'startup_smoke_passed', 'failed_stage', 'error', 'stages',
                                        'last_stage_elapsed', 'recovery'})

    def test_capture_digest_keeps_only_sizes_counters_and_component_count(self):
        evidence = {'declared_components': [11, 12, 13], 'filter': {'name': 'RuleProxyCaptureDest', 'confirmed': True},
                    'filter_before': 'C:\\private listing',
                    'inventory_after_flush_wait': {'matching_etl_bytes': 70000000, 'files': [
                        {'basename': 'wire-before.etl', 'bytes': 16777216, 'matches_expected_capture_glob': True},
                        {'basename': 'wire-before_1.etl', 'bytes': 53222784, 'matches_expected_capture_glob': True},
                        {'basename': 'other.pcapng', 'bytes': 5, 'matches_expected_capture_glob': False}]},
                    'start': {'log_basename': 'wire-before.etl', 'maximum_file_size': '16 MB', 'idle_reported': False,
                              'logging_mode': 'multi-file'},
                    'buffer_info': {'events_logged': 1234, 'buffers_written': 4096, 'buffer_size': '1,024 KB',
                                    'log_parent_is_private_run_directory': True, 'note': 'C:\\x'}}
        digest = H._ci_capture_digest(evidence)
        self.assertEqual(digest, {'components': 3, 'filter_confirmed': True, 'etl_file_bytes': [16777216, 53222784],
                                  'matching_etl_bytes': 70000000,
                                  'start': {'idle_reported': False, 'maximum_file_size': '16 MB'},
                                  'buffer_info': {'buffer_size': '1,024 KB', 'buffers_written': 4096, 'events_logged': 1234,
                                                  'log_parent_is_private_run_directory': True}})
        text = json.dumps(digest)
        for leaked in ('C:', 'wire-before', 'RuleProxyCaptureDest', 'multi-file', 'pcapng'):
            self.assertNotIn(leaked, text)
        self.assertIsNone(H._ci_capture_digest('not a dict'))


if __name__ == '__main__':
    unittest.main()
