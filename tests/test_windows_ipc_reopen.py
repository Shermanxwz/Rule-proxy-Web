"""v10 lifecycle regression: injected TCP/process/WFP; no live application I/O."""
import socket
import unittest
from unittest.mock import Mock
import test_windows_broker_antigravity_ipc as fixtures
from ruleproxy.windows_antigravity_ipc import Tracker, IPCError, PeerRetired, Record

PAIR = fixtures.PAIR


def row(port=5000, pid=10, address='127.0.0.1'):
    return dict(state=2, local=address, local_port=port, pid=pid)


class Reopen(unittest.TestCase):
    setUp = fixtures.BrokerIPC.setUp
    request = fixtures.BrokerIPC.request
    handle = fixtures.BrokerIPC.handle
    ready = fixtures.BrokerIPC.ready
    enable = fixtures.BrokerIPC.enable

    def prepare(self):
        self.ready()
        self.rows = [row()]
        self.events, self.trackers, self.peers = [], [], []
        self.created = None
        self.live = True
        self.revoke_error = False
        self.close_error = False
        self.apply_hook = None
        self.broker.ipc_factory = Mock(side_effect=self.factory)

    def factory(self, broker, pair, epoch):
        self.events.append(('new', pair, epoch))
        def process(pid, owner):
            peer = Mock()
            peer.alive.return_value = self.live
            peer.image_path.return_value = pair[0]
            peer.creation_time.return_value = epoch + 1 if self.created is None else self.created
            def close():
                self.events.append('handle_close')
                if self.close_error:
                    raise OSError('handle release failed')
            peer.close.side_effect = close
            self.peers.append(peer)
            return peer
        def apply(records):
            self.events.append(('apply', records))
            if self.apply_hook:
                self.apply_hook()
        def revoke():
            self.events.append('revoke')
            if self.revoke_error:
                raise OSError('revocation unconfirmed')
        tracker = Tracker(*pair, 'owner', epoch,
                          rows_factory=lambda f: self.rows if f == socket.AF_INET else [],
                          process_factory=process, apply=apply, revoke=revoke)
        self.trackers.append(tracker)
        return tracker

    def assert_base_untouched(self):
        self.guard.purge.assert_not_called()
        self.guard.apply.assert_not_called()
        self.assertTrue(self.broker.app_guard_intent)

    def test_shutdown_then_reopen_preserves_epoch_and_waits_one_call(self):
        self.prepare()
        first = self.enable()
        self.assertTrue(first['active'])
        self.events.clear()
        self.rows = []
        self.broker.check_lease()
        self.assertEqual(self.events, ['revoke', 'handle_close', 'revoke',
                                      ('new', PAIR, first['enabled_after'])])
        status = self.broker._ipc_status()
        self.assertEqual(status['state'], 'watching')
        self.assertEqual(status['enabled_after'], first['enabled_after'])
        self.assertIsNone(status['error'])
        with self.assertRaisesRegex(IPCError, 'Close and replace'):
            self.trackers[0].refresh()
        self.rows = [row(port=6000, pid=20)]
        self.assertTrue(self.enable()['active'])
        self.assertEqual(self.broker.ipc_enabled_after, first['enabled_after'])
        self.assert_base_untouched()

    def test_post_apply_disappearance_revokes_before_rebuild(self):
        self.prepare()
        self.apply_hook = lambda: self.rows.clear()
        status = self.enable()
        self.assertEqual(status['state'], 'watching')
        self.assertEqual(len(self.trackers), 2)
        self.assertEqual(len([e for e in self.events if isinstance(e, tuple) and e[0] == 'apply']), 1)
        self.assertLess(self.events.index('revoke'), self.events.index('handle_close'))
        self.assertEqual(self.events[-1][0], 'new')
        self.assert_base_untouched()

    def test_process_exit_retires_without_querying_dead_identity(self):
        self.prepare(); self.live = False
        self.assertEqual(self.enable()['state'], 'watching')
        self.peers[0].image_path.assert_not_called()
        self.assertEqual(len(self.trackers), 2)

    def test_recovery_never_advances_old_epoch_threshold(self):
        self.prepare(); epoch = self.enable()['enabled_after']
        self.rows = []; self.broker.check_lease()
        self.created = epoch - 1; self.rows = [row(pid=20)]
        with self.assertRaises(fixtures.policy.ProxyError) as caught:
            self.enable()
        self.assertEqual(caught.exception.code, 'requires_restart')
        self.assertEqual(self.broker.ipc_error['code'], 'requires_restart')
        self.assertEqual(len(self.trackers), 2)
        self.assert_base_untouched()

    def test_conflicting_owner_is_sticky(self):
        self.prepare(); self.enable()
        self.rows = [row(pid=20)]
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'listener_changed')
        self.broker.check_lease()
        with self.assertRaises(Exception): self.enable()
        self.assertEqual(len(self.trackers), 1)
        self.assert_base_untouched()

    def test_same_pid_new_creation_is_sticky(self):
        self.prepare(); epoch = self.enable()['enabled_after']
        self.created = epoch + 2
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'process_changed')
        self.assertEqual(len(self.trackers), 1)

    def test_revoke_failure_keeps_handles_and_sticky_error(self):
        self.prepare(); self.enable(); self.events.clear()
        self.rows = []; self.revoke_error = True
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'ipc_cleanup_incomplete')
        self.assertNotIn('handle_close', self.events)
        self.assertIs(self.broker.ipc_tracker, self.trackers[0])
        self.revoke_error = False
        self.broker.check_lease()
        self.assertEqual(len(self.trackers), 1)
        with self.assertRaises(Exception): self.enable()
        self.assert_base_untouched()

    def test_first_revoke_failure_stays_sticky_even_if_close_retry_succeeds(self):
        self.prepare(); self.enable(); self.rows = []
        self.trackers[0]._revoke = Mock(side_effect=[OSError('failed once'), None])
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'revoke_failed')
        self.assertIsNone(self.broker.ipc_tracker)
        self.assertEqual(len(self.trackers), 1)

    def test_handle_release_failure_never_rebuilds(self):
        self.prepare(); self.enable(); self.rows = []; self.close_error = True
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'ipc_cleanup_incomplete')
        self.assertEqual(len(self.trackers), 1)
        self.assertTrue(self.trackers[0]._held)
        self.assert_base_untouched()

    def test_base_revalidation_failure_is_sticky(self):
        self.prepare(); self.enable(); self.rows = []
        self.broker._verify_ipc_base.side_effect = [None, IPCError('ipc_guard_changed', 'guard changed')]
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'ipc_guard_changed')
        self.assertEqual(len(self.trackers), 1)
        self.assert_base_untouched()

    def test_constructor_failure_is_sticky(self):
        self.prepare(); self.enable(); self.rows = []
        self.broker.ipc_factory.side_effect = OSError('construction failed')
        self.broker.check_lease()
        self.assertEqual(self.broker.ipc_error['code'], 'ipc_failed')
        self.assertIsNone(self.broker.ipc_tracker)
        self.assert_base_untouched()

    def test_churn_has_one_replacement_per_call_no_busy_retry(self):
        self.prepare(); self.live = False
        for n in range(12):
            self.assertEqual(self.enable()['state'], 'watching')
            self.assertEqual(len(self.trackers), n + 2)
        self.assertFalse(any(isinstance(e, tuple) and e[0] == 'apply' for e in self.events))
        self.assert_base_untouched()

    def test_error_code_alone_does_not_trigger_recovery(self):
        self.prepare(); self.enable()
        self.trackers[0].refresh = Mock(side_effect=IPCError('listener_disappeared', 'not a retirement'))
        self.broker.check_lease()
        self.assertEqual(len(self.trackers), 1)
        self.assertIsNotNone(self.broker.ipc_error)

    def test_missing_peer_does_not_mask_second_peer_conflict_or_identity_change(self):
        self.prepare(); self.enable()
        tracker = self.trackers[0]
        records = (Record(*PAIR, 5000, 10, 101), Record(*PAIR, 6000, 20, 101))
        peers = {pid: Mock(alive=Mock(return_value=True), image_path=Mock(return_value=PAIR[0]),
                           creation_time=Mock(return_value=101)) for pid in (10, 20)}
        with self.assertRaises(IPCError) as caught:
            tracker._validate(((socket.AF_INET, '0.0.0.0', 6000, 30),), records, peers)
        self.assertNotIsInstance(caught.exception, PeerRetired)
        self.assertEqual(caught.exception.code, 'listener_changed')
        peers[20].creation_time.return_value = 102
        with self.assertRaises(IPCError) as caught:
            tracker._validate((), records, peers)
        self.assertEqual(caught.exception.code, 'process_changed')

    def test_existing_enable_request_does_not_grant_after_same_tick_retirement(self):
        self.prepare(); self.enable(); self.events.clear()
        self.apply_hook = lambda: self.rows.clear()
        status = self.enable()
        self.assertEqual(status['state'], 'watching')
        self.assertEqual(len(self.trackers), 2)
        self.assertEqual(self.events[-1][0], 'new')
        self.assertEqual(len([e for e in self.events if isinstance(e, tuple) and e[0] == 'apply']), 1)
        self.assert_base_untouched()

    def test_exited_candidate_does_not_mask_wildcard_conflict(self):
        self.prepare(); self.live = False
        self.rows.append(row(pid=30, address='0.0.0.0'))
        with self.assertRaises(IPCError) as caught:
            self.enable()
        self.assertEqual(caught.exception.code, 'listener_changed')
        self.assertEqual(len(self.trackers), 1)
        self.assertIsNotNone(self.broker.ipc_error)

    def test_empty_watch_does_not_rebuild_or_change_epoch(self):
        self.prepare(); epoch = self.enable()['enabled_after']
        self.rows = []; self.broker.check_lease()
        for _ in range(10):
            self.broker.check_lease()
        self.assertEqual(len(self.trackers), 2)
        self.assertEqual(self.broker.ipc_enabled_after, epoch)
        self.assertEqual(self.broker._ipc_status()['state'], 'watching')
        self.assert_base_untouched()

    def test_disable_after_retirement_closes_watcher_and_clears_epoch(self):
        self.prepare(); self.enable(); self.rows = []
        self.broker.check_lease()
        status = self.handle('antigravity_ipc', enabled=False)
        self.assertEqual(status['state'], 'inactive')
        self.assertIsNone(status['enabled_after'])
        self.assertEqual(self.broker.ipc_pair, ())
        self.assert_base_untouched()


if __name__ == '__main__':
    unittest.main()
