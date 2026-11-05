"""Broker lifecycle contract tests; mocks do NOT qualify native WFP traffic."""
import unittest
from unittest.mock import patch

from ruleproxy.windows_proxy_service import Broker


class Lease:
    def __init__(self, pid, alive=True):
        self.pid, self.live, self.closed = pid, alive, False
    def alive(self):
        return self.live and not self.closed
    def close(self):
        self.closed = True


class Control:
    def __init__(self):
        self.state, self.fail = 4, False
    def status(self):
        return {'state': self.state}
    def set_running(self, running):
        if self.fail:
            raise OSError('injected stop failure')
        self.state = 4 if running else 1
        return self.status()


class Gate:
    def __init__(self):
        self.active, self.purges = True, 0
    def status(self):
        return {'active': self.active, 'persistent': self.active}
    def purge(self):
        self.purges += 1
        self.active = False
        return self.status()


def broker_fixture():
    gate, control = Gate(), Control()
    broker = Broker({}, control=control, app_guard_factory=lambda _: gate)
    broker.app_guard_gate = gate
    broker.app_guard_intent = True
    broker.panel, broker.core = Lease(101), Lease(102)
    broker.engine_owned = True
    broker.paths, broker.port = ['fixture.exe'], 10809
    return broker, gate, control


class FailureRetentionTests(unittest.TestCase):
    def assert_retained(self, broker, gate):
        self.assertTrue(gate.active)
        self.assertEqual(gate.purges, 0)
        self.assertTrue(broker.app_guard_intent)

    def test_core_exit_keeps_guard_and_closes_leases(self):
        broker, gate, control = broker_fixture()
        panel, core = broker.panel, broker.core
        core.live = False
        broker.check_lease()
        self.assert_retained(broker, gate)
        self.assertTrue(panel.closed and core.closed)
        self.assertFalse(broker.engine_owned)
        self.assertEqual(control.state, 1)

    def test_panel_exit_keeps_guard(self):
        broker, gate, _ = broker_fixture()
        broker.panel.live = False
        broker.check_lease()
        self.assert_retained(broker, gate)
        self.assertIsNone(broker.panel)

    def test_missing_core_keeps_guard(self):
        broker, gate, _ = broker_fixture()
        broker.core = None
        broker.check_lease()
        self.assert_retained(broker, gate)

    def test_broker_shutdown_keeps_guard(self):
        broker, gate, _ = broker_fixture()
        broker.shutdown()
        self.assert_retained(broker, gate)
        self.assertIsNone(broker.core)

    def test_engine_cleanup_failure_retains_guard_and_retry_authority(self):
        broker, gate, control = broker_fixture()
        broker.core.live = False
        control.fail = True
        with patch('ruleproxy.windows_proxy_service._log_service_error'):
            broker.check_lease()
        self.assert_retained(broker, gate)
        self.assertTrue(broker.engine_owned)
        self.assertIsNotNone(broker.core)
        self.assertEqual(broker.error['code'], 'cleanup_incomplete')
        control.fail = False
        broker.check_lease()
        self.assert_retained(broker, gate)
        self.assertIsNone(broker.error)
        self.assertIsNone(broker.core)

    def test_explicit_stop_is_distinct_and_revokes_guard(self):
        broker, gate, _ = broker_fixture()
        broker.stop()
        self.assertFalse(gate.active)
        self.assertEqual(gate.purges, 1)
        self.assertFalse(broker.app_guard_intent)

    def test_stopped_backend_snapshot_reports_retained_guard(self):
        broker, gate, _ = broker_fixture()
        broker.core.live = False
        broker.check_lease()
        snapshot = broker.snapshot()
        self.assertFalse(snapshot['running'])
        self.assertTrue(snapshot['app_guard']['active'])
        self.assertTrue(snapshot['app_guard']['persistent'])

    def test_unexpected_engine_exit_does_not_revoke_guard(self):
        broker, gate, control = broker_fixture()
        control.state = 1
        broker.check_lease()
        self.assert_retained(broker, gate)
        self.assertFalse(broker.snapshot()['running'])


if __name__ == '__main__':
    unittest.main()
