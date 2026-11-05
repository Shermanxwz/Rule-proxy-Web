import unittest
from unittest.mock import Mock
from ruleproxy.windows_antigravity_task import RecoveryTask


class TaskTests(unittest.TestCase):
    def make(self):
        self.now = 0.
        self.peer = Mock()
        self.peer.__enter__ = Mock(return_value=self.peer)
        self.peer.__exit__ = Mock(return_value=False)
        self.factory = Mock(return_value=self.peer)
        self.check = Mock(return_value=True)
        self.recover = Mock(return_value={'state': 'not_needed', 'reload_attempted': False})
        return RecoveryTask(object(), 'fixture', self.check, peers_factory=self.factory,
                            recover=self.recover, clock=lambda: self.now)

    def test_runs_once_and_releases_peers(self):
        task = self.make()
        task.start()
        task.thread.join(2)
        self.assertFalse(task.thread.is_alive())
        self.assertEqual(task.result['state'], 'not_needed')
        self.recover.assert_called_once()
        self.peer.__exit__.assert_called_once()

    def test_cancel_before_start_does_no_native_work(self):
        task = self.make()
        task.cancel()
        task._run()
        self.factory.assert_not_called()
        self.assertEqual(task.result['state'], 'cancelled')

    def test_delayed_start_does_not_extend_budget(self):
        task = self.make()
        self.now = 21.
        task._run()
        self.factory.assert_not_called()
        self.assertEqual(task.result['state'], 'cancelled')

    def test_cancel_during_readiness_read(self):
        task = self.make()
        self.check.side_effect = lambda: task.cancel() or True
        self.assertIs(task._ready(), False)

    def test_deadline_during_readiness_read(self):
        task = self.make()
        def delay():
            self.now = 21.
            return True
        self.check.side_effect = delay
        self.assertIs(task._ready(), False)

    def test_native_failure_has_only_fixed_status(self):
        task = self.make()
        self.factory.side_effect = OSError('private failure text')
        task._run()
        self.assertEqual(task.result, {'state': 'unavailable', 'reload_attempted': False})

    def test_cleanup_failure_preserves_reload_attempt(self):
        task = self.make()
        self.recover.return_value = {'state': 'recovered', 'reload_attempted': True}
        self.peer.__exit__.side_effect = OSError('fixture cleanup error')
        task._run()
        self.assertEqual(task.result, {'state': 'reload_unverified', 'reload_attempted': True})
        self.recover.assert_called_once()

    def test_watch_state_can_enter_bounded_recovery(self):
        task = self.make()
        self.check.return_value = None
        task._run()
        self.recover.assert_called_once()
        self.assertEqual(self.recover.call_args.args[2], 20.)


if __name__ == '__main__':
    unittest.main()
