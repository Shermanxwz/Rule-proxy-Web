"""Hard deadline, CI reclaim and guest progress relay checks for the global capture harness."""
import importlib.util
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, call, patch

SPEC = importlib.util.spec_from_file_location('windows_capture_harness_deadline',
    Path(__file__).resolve().parents[1] / '.github/check_windows_global_capture.py')
H = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(H)


def mutex_kernel(wait_result):
    kernel = Mock()
    kernel.CreateMutexW.return_value = 1
    kernel.WaitForSingleObject.return_value = wait_result
    return kernel


class CaptureDeadlineTests(unittest.TestCase):
    def test_best_effort_reclaim_bypasses_a_held_mutex_but_strict_recovery_does_not(self):
        kernel = mutex_kernel(0x102)  # WAIT_TIMEOUT: a wedged orchestrator holds the mutex.
        with patch.object(H.ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(H, 'read_json', return_value={'nonce': 'unit'}), \
             patch.object(H, '_recover_locked', return_value={'recovered': False, 'errors': ['x']}) as locked:
            with self.assertRaisesRegex(RuntimeError, 'recovery_mutex_timeout'):
                H.recover('state.json')
            self.assertEqual(locked.call_count, 0)
            result = H.recover('state.json', best_effort=True)
        self.assertEqual(locked.call_args_list, [call('state.json', best_effort=True)])
        self.assertIs(result['mutex_bypassed'], True)
        kernel.ReleaseMutex.assert_not_called()
        self.assertEqual(kernel.CloseHandle.call_count, 2)

    def test_acquired_mutex_never_marks_bypass(self):
        kernel = mutex_kernel(0)
        with patch.object(H.ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(H, 'read_json', return_value={'nonce': 'unit'}), \
             patch.object(H, '_recover_locked', return_value={'recovered': True, 'errors': []}):
            result = H.recover('state.json', best_effort=True)
        self.assertNotIn('mutex_bypassed', result)
        kernel.ReleaseMutex.assert_called_once_with(1)

    def run_watchdog(self, flag, returns):
        from ruleproxy import windows_proxy_service as service
        with tempfile.TemporaryDirectory() as work:
            state = Path(work) / 'state.json'
            H.write_json(state, {'root': work, 'nonce': 'unit', 'ci_network_reclaim': flag})
            previous_path = list(sys.path)
            try:
                with patch.object(service, 'load_deployment', return_value={'root': work}), \
                     patch.object(service, 'protected_path'), \
                     patch.object(H, 'scoped_guard'), \
                     patch.object(H, 'recover', side_effect=returns) as recover:
                    return H.system_operation(state, 'recover'), recover.call_args_list, state
            finally:
                sys.path[:] = previous_path

    def test_strict_recovery_exception_still_runs_the_flagged_ci_reclaim(self):
        reclaim = {'recovered': True, 'best_effort': True, 'errors': [], 'mutex_bypassed': True}
        result, calls, state = self.run_watchdog(True, [RuntimeError('recovery_mutex_timeout'), dict(reclaim)])
        self.assertIs(result['recovered'], False)
        self.assertEqual(result['errors'], ['RuntimeError:recovery_mutex_timeout'])
        self.assertEqual(result['ci_network_reclaim'], reclaim)
        self.assertEqual(calls, [call(state), call(state, best_effort=True)])

    def test_strict_recovery_exception_still_raises_without_the_ci_flag(self):
        with self.assertRaisesRegex(RuntimeError, 'recovery_mutex_timeout'):
            self.run_watchdog(False, [RuntimeError('recovery_mutex_timeout')])

    def test_progress_sink_receives_the_bounded_line_without_actions(self):
        with tempfile.TemporaryDirectory() as work:
            progress = Path(work) / 'capture-progress.log'
            with patch.dict(os.environ, {'RULEPROXY_CAPTURE_PROGRESS': str(progress)}), \
                 redirect_stdout(io.StringIO()) as output:
                os.environ.pop('GITHUB_ACTIONS', None)
                H._ci_annotation('notice', 'Global capture stage', 'global_start t=1.0')
                H._ci_annotation('error', 'Global capture summary', {'b': '100%\n'})
            self.assertEqual(output.getvalue(), '')
            self.assertEqual(progress.read_text(encoding='ascii').split('\n'), [
                '::notice title=Global capture stage::global_start t=1.0',
                '::error title=Global capture summary::{"b":"100%25\\n"}', ''])
            with patch.dict(os.environ, {'RULEPROXY_CAPTURE_PROGRESS': str(Path(work) / 'missing' / 'x.log')}):
                H._ci_annotation('notice', 'Global capture stage', 'unwritable sink is ignored')

    def test_hang_frames_are_innermost_first_and_path_free(self):
        def nested():
            return H._hang_frames(threading.get_ident(), limit=3)
        frames = nested()
        self.assertEqual(len(frames), 3)
        self.assertTrue(frames[0].startswith('check_windows_global_capture.py:_hang_frames:'))
        self.assertTrue(frames[1].startswith('test_windows_global_capture_deadline.py:nested:'))
        self.assertFalse(any(os.sep in item or '/' in item for item in frames))

    def deadline_fixture(self, work):
        nonce = 'deadbeefcafe0123'
        H.write_json(Path(work) / 'recover.result.json', {'ok': True, 'result': {
            'recovered': False, 'errors': ['RuntimeError:owned_dns_restore_unconfirmed C:\\ProgramData\\RuleProxy-Web\\capture-' + nonce],
            'ci_network_reclaim': {'recovered': True, 'errors': [], 'mutex_bypassed': True}}})
        H.write_json(Path(work) / 'ci-network-reclaim-result.json', {'recovered': True, 'errors': [], 'mutex_bypassed': True})
        budget = H.ExperimentBudget()
        budget.stages.extend([{'stage': 'global_start', 'started_seconds': 1.0}])
        report = {'passed': False, 'phases': {}, 'time_budget': {}}
        return nonce, budget, report

    def test_hard_deadline_emits_bounded_digest_writes_failure_and_exits(self):
        with tempfile.TemporaryDirectory() as work:
            nonce, budget, report = self.deadline_fixture(work)
            output = Path(work) / 'results' / 'summary.json'
            exit_process = Mock()
            with patch.object(H, 'HARD_DEADLINE_SECONDS', 0), patch.object(H.os, '_exit', exit_process), \
                 patch.dict(os.environ, {'GITHUB_ACTIONS': 'true'}), redirect_stdout(io.StringIO()) as printed:
                H._hard_deadline(threading.Event(), report, budget, (work, nonce), work, output, threading.get_ident())
            exit_process.assert_called_once_with(3)
            lines = printed.getvalue().splitlines()
            self.assertEqual([line.split('::')[1] for line in lines], [
                'error title=Global capture hard deadline', 'error title=Global capture watchdog',
                'error title=Global capture summary'])
            hang = json.loads(lines[0].split('::', 2)[2])
            self.assertEqual(hang['stage'], 'global_start')
            self.assertTrue(hang['frames'][0].startswith('check_windows_global_capture.py:_hang_frames:'))
            watchdog = json.loads(lines[1].split('::', 2)[2])
            self.assertEqual(watchdog['watchdog']['ci_network_reclaim'],
                             {'recovered': True, 'mutex_bypassed': True, 'errors': []})
            self.assertEqual(watchdog['reclaim_file']['recovered'], True)
            self.assertNotIn('strict_file', watchdog)
            self.assertNotIn(nonce, printed.getvalue())
            self.assertNotIn('ProgramData', printed.getvalue())
            written = H.read_json(output)
            self.assertIs(written['passed'], False)
            self.assertIs(written['hard_deadline_exceeded'], True)
            self.assertEqual(written['failed_stage'], 'global_start')
            self.assertEqual(written['error'], 'RuntimeError:orchestrator_hard_deadline')

    def test_hard_deadline_does_nothing_after_the_run_finished(self):
        finished = threading.Event()
        finished.set()
        exit_process = Mock()
        with patch.object(H.os, '_exit', exit_process), redirect_stdout(io.StringIO()) as printed, \
             tempfile.TemporaryDirectory() as work:
            H._hard_deadline(finished, {}, H.ExperimentBudget(), (), work, Path(work) / 'summary.json', 0)
        exit_process.assert_not_called()
        self.assertEqual(printed.getvalue(), '')


if __name__ == '__main__':
    unittest.main()
