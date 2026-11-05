"""Mock broker handoff tests, not native WFP or socket-binding qualification."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ruleproxy.windows_proxy_service import Broker, ProxyError


SID = 'S-1-5-21-1-2-3-1001'
PANEL = 101


class Gate:
    def __init__(self, events, active=True):
        self.events = events
        self.active = active
        self.purges = 0
        self.applies = []
        self.fail_apply = False

    def status(self):
        return {'active': self.active, 'persistent': self.active}

    def purge(self):
        self.events.append('guard-purge')
        self.purges += 1
        self.active = False
        return self.status()

    def apply(self, paths, port):
        self.events.append(('guard-replace', self.active, port))
        if self.fail_apply:
            raise OSError('injected guard transaction failure')
        self.applies.append((paths, port))
        self.active = True
        return self.status()


class Containers:
    def __init__(self):
        self.purges = 0
        self.fail = False

    def purge(self):
        self.purges += 1
        if self.fail:
            raise OSError('injected container cleanup failure')
        return {'active': False}


class Control:
    def __init__(self, gate, events):
        self.gate, self.events = gate, events
        self.state = 1
        self.fail_starts = 0

    def verify(self, metadata):
        pass

    def status(self):
        return {'state': self.state}

    def set_running(self, running):
        self.events.append(('engine', running, self.gate.active))
        if running and self.fail_starts:
            self.fail_starts -= 1
            raise OSError('injected engine start failure')
        self.state = 4 if running else 1
        return self.status()


class Lease:
    def __init__(self, pid, image):
        self.pid, self.image, self.closed = pid, image, False

    def alive(self):
        return not self.closed

    def image_path(self):
        return self.image

    def close(self):
        self.closed = True


class GuardRestartRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ruleproxy-guard-handoff-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'app-config.json'
        self.config.write_bytes(b'old configuration')
        self.events = []
        self.guard = Gate(self.events)
        self.containers = Containers()
        self.control = Control(self.guard, self.events)
        self.leases = []
        metadata = {'owner_sid': SID, 'root': str(self.root),
                    'proxifyre_root': str(self.root)}

        def lease_factory(pid, sid):
            self.assertEqual(sid, SID)
            lease = Lease(pid, str(self.root / 'bin/windows-amd64/mihomo.exe'))
            self.leases.append(lease)
            return lease

        self.broker = Broker(metadata, control=self.control, lease_factory=lease_factory,
                             app_guard_factory=lambda _: self.guard)
        self.broker.container_gate = self.containers
        self.addCleanup(patch.stopall)
        patch('ruleproxy.windows_proxy_service.verify_selected_paths').start()
        patch('ruleproxy.windows_proxy_service.policy.build_policy',
              side_effect=lambda paths, port, **kwargs:
              {'proxies': [{'appNames': paths, 'socks5ProxyEndpoint': f'127.0.0.1:{port}'}]}).start()

    def request(self, op, **kwargs):
        return self.broker.handle({'op': op, 'client_pid': PANEL, **kwargs}, PANEL, SID)

    def apply(self, pid=102, port=10809):
        return self.request('apply', generation=self.broker.generation + 1,
                            paths=['fixture.exe'], proxy_port=port, mihomo_pid=pid)

    def assert_retained(self):
        self.assertTrue(self.guard.active)
        self.assertEqual(self.guard.purges, 0)
        self.assertNotIn('guard-purge', self.events)
        for event in self.events:
            if isinstance(event, tuple) and event[0] == 'engine':
                self.assertTrue(event[2], event)

    def test_fresh_broker_retains_preexisting_guard_until_explicit_replacement(self):
        self.assertIsNone(self.broker.core)
        self.assertIsNone(self.broker.app_guard_gate)
        self.assertFalse(self.broker.app_guard_intent)
        result = self.apply()
        self.assertTrue(result['running'])
        self.assertTrue(result['app_guard']['active'])
        self.assertFalse(result['app_guard_intent'])  # No invented ownership intent.
        self.assertEqual(self.containers.purges, 1)
        self.assert_retained()
        self.request('app_guard_apply', proxy_port=10809)
        self.assertEqual(self.guard.applies, [(['fixture.exe'], 10809)])
        self.assertTrue(self.broker.app_guard_intent)
        self.assertEqual(self.events[-1], ('guard-replace', True, 10809))
        self.assert_retained()

    def test_changed_core_retains_guard_and_releases_previous_leases(self):
        self.apply()
        self.request('app_guard_apply', proxy_port=10809)
        old_panel, old_core = self.broker.panel, self.broker.core
        self.apply(pid=103)
        self.assertTrue(old_panel.closed and old_core.closed)
        self.assertEqual(self.broker.core.pid, 103)
        self.assertEqual(self.containers.purges, 2)
        self.assertTrue(self.broker.app_guard_intent)
        self.assert_retained()

    def test_changed_port_retains_previous_filters_until_replacement(self):
        self.apply()
        self.apply(port=10810)
        self.assertEqual(self.broker.port, 10810)
        self.assertEqual(self.containers.purges, 2)
        self.assert_retained()
        self.request('app_guard_apply', proxy_port=10810)
        self.assertEqual(self.guard.applies, [(['fixture.exe'], 10810)])
        self.assert_retained()

    def test_fresh_backend_start_failure_retains_guard_and_restores_config(self):
        self.control.fail_starts = 1
        with self.assertRaisesRegex(OSError, 'engine start failure'):
            self.apply()
        self.assertEqual(self.config.read_bytes(), b'old configuration')
        self.assertEqual(self.control.state, 1)
        self.assertFalse(self.broker.engine_owned)
        self.assertIsNone(self.broker.core)
        self.assertTrue(all(lease.closed for lease in self.leases))
        self.assert_retained()

    def test_changed_core_start_failure_restores_old_engine_and_retains_guard(self):
        self.apply()
        previous_config = self.config.read_bytes()
        old_panel, old_core = self.broker.panel, self.broker.core
        self.control.fail_starts = 1
        with self.assertRaisesRegex(OSError, 'engine start failure'):
            self.apply(pid=103)
        self.assertEqual(self.config.read_bytes(), previous_config)
        self.assertEqual(self.control.state, 4)
        self.assertTrue(self.broker.engine_owned)
        self.assertIs(self.broker.panel, old_panel)
        self.assertIs(self.broker.core, old_core)
        self.assertTrue(old_panel.alive() and old_core.alive())
        self.assertTrue(all(lease.closed for lease in self.leases[-2:]))
        self.assert_retained()

    def test_container_cleanup_failure_blocks_apply_without_revoking_guard(self):
        self.containers.fail = True
        with self.assertRaises(ProxyError) as caught:
            self.apply()
        self.assertEqual(caught.exception.code, 'cleanup_incomplete')
        self.assertEqual(self.control.state, 1)
        self.assertEqual(self.config.read_bytes(), b'old configuration')
        self.assert_retained()

    def test_guard_replacement_failure_does_not_pre_purge_previous_filters(self):
        self.apply()
        self.guard.fail_apply = True
        with self.assertRaisesRegex(OSError, 'guard transaction failure'):
            self.request('app_guard_apply', proxy_port=10809)
        self.assertTrue(self.broker.app_guard_intent)
        self.assert_retained()

    def test_explicit_stop_still_purges_retained_guard(self):
        self.apply()
        self.request('stop')
        self.assertFalse(self.guard.active)
        self.assertEqual(self.guard.purges, 1)
        self.assertFalse(self.broker.app_guard_intent)
        self.assertEqual(self.control.state, 1)

    def test_explicit_revoke_still_purges_retained_guard(self):
        self.apply()
        self.request('app_guard_revoke')
        self.assertFalse(self.guard.active)
        self.assertEqual(self.guard.purges, 1)
        self.assertFalse(self.broker.app_guard_intent)
        self.assertEqual(self.control.state, 4)

    def test_default_transition_cleanup_still_purges_both_gates(self):
        self.broker._purge_gates()
        self.assertEqual(self.containers.purges, 1)
        self.assertFalse(self.guard.active)
        self.assertEqual(self.guard.purges, 1)

    def test_default_cleanup_attempts_guard_even_if_container_cleanup_fails(self):
        self.containers.fail = True
        with self.assertRaises(ProxyError):
            self.broker._purge_gates()
        self.assertEqual(self.containers.purges, 1)
        self.assertFalse(self.guard.active)
        self.assertEqual(self.guard.purges, 1)

    def test_wrong_owner_still_rejected_before_apply_or_guard_changes(self):
        with self.assertRaises(ProxyError) as caught:
            self.broker.handle({'op': 'apply', 'client_pid': PANEL}, PANEL, 'wrong-owner')
        self.assertEqual(caught.exception.code, 'access_denied')
        self.assertEqual(self.events, [])
        self.assertEqual(self.containers.purges, 0)
        self.assert_retained()


if __name__ == '__main__':
    unittest.main()
