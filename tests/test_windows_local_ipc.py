"""Injected group discovery tests: no DLL, socket or process execution."""
import socket
import unittest
from unittest.mock import Mock

from ruleproxy.windows_local_ipc import Tracker, IPCError, PeerRetired

MAIN, HELPER, OTHER = (r'c:\apps\main.exe', r'c:\apps\helper.exe', r'c:\apps\other.exe')


def row(port=5000, pid=10, address='127.0.0.1'):
    return dict(state=2, local=address, local_port=port, pid=pid)


def peer(path=MAIN, created=101):
    return Mock(alive=Mock(return_value=True), image_path=Mock(return_value=path),
                creation_time=Mock(return_value=created), close=Mock())


class GroupTrackerTests(unittest.TestCase):
    def setUp(self):
        self.rows, self.v6 = [row()], []
        self.peers = {10: peer()}
        self.apply, self.revoke = Mock(), Mock()
        self.factory = Mock(side_effect=lambda pid, sid: self.peers.get(pid))

    def tracker(self, groups=None, epoch=100):
        return Tracker(groups or [[MAIN]], 'owner', epoch,
                       rows_factory=lambda family: self.rows if family == socket.AF_INET else self.v6,
                       process_factory=self.factory, apply=self.apply, revoke=self.revoke)

    def test_one_image_can_call_its_own_verified_listener(self):
        tracker = self.tracker()
        record, = tracker.refresh()
        self.assertEqual(record.client_paths, (MAIN,))
        self.assertEqual(record.server_path, MAIN)
        self.factory.assert_called_once_with(10, 'owner')
        self.peers[10].close.assert_not_called()

    def test_multiple_helpers_share_one_endpoint_only_within_their_group(self):
        extra = r'c:\apps\helper2.exe'
        tracker = self.tracker([[MAIN, HELPER, extra], [OTHER]])
        record, = tracker.refresh()
        self.assertEqual(set(record.client_paths), {MAIN, HELPER, extra})
        self.assertNotIn(OTHER, record.client_paths)

    def test_shared_image_does_not_merge_groups_transitively(self):
        tracker = self.tracker([[MAIN, HELPER], [HELPER, OTHER]])
        record, = tracker.refresh()
        self.assertEqual(set(record.client_paths), {MAIN, HELPER})
        self.peers[10].image_path.return_value = OTHER
        tracker.close()
        other = self.tracker([[MAIN, HELPER], [HELPER, OTHER]])
        self.assertEqual(set(other.refresh()[0].client_paths), {HELPER, OTHER})

    def test_preexisting_listener_is_skipped_without_breaking_other_apps(self):
        self.peers[10].creation_time.return_value = 99
        self.rows.append(row(port=6000, pid=20))
        self.peers[20] = peer(OTHER)
        tracker = self.tracker([[MAIN], [OTHER]])
        records = tracker.refresh()
        self.assertEqual([record.server_path for record in records], [OTHER])
        self.assertEqual(tracker.waiting_restart_count, 1)
        self.peers[10].close.assert_called_once()
        self.revoke.assert_not_called()

    def test_path_epochs_preserve_old_group_and_wait_for_new_group_restart(self):
        self.rows.append(row(port=6000, pid=20))
        self.peers[20] = peer(OTHER, created=150)
        tracker = self.tracker([[MAIN], [OTHER]], {MAIN: 100, OTHER: 200})
        self.assertEqual([record.server_path for record in tracker.refresh()], [MAIN])
        self.assertEqual(tracker.waiting_restart_count, 1)

    def test_unknown_or_foreign_owner_peer_never_gets_an_endpoint(self):
        self.factory.return_value = None
        self.factory.side_effect = None
        tracker = self.tracker()
        self.assertEqual(tracker.refresh(), ())
        self.apply.assert_called_once_with(())

    def test_nonmember_peer_is_closed_without_grant(self):
        self.peers[10].image_path.return_value = OTHER
        self.assertEqual(self.tracker().refresh(), ())
        self.peers[10].close.assert_called_once()

    def test_existing_unverified_peer_retires_whole_generation_before_releasing(self):
        self.rows.append(row(port=6000, pid=20))
        self.peers[20] = peer(OTHER)
        tracker = self.tracker([[MAIN], [OTHER]])
        tracker.refresh()
        old = self.peers.pop(10)
        events = []
        self.revoke.side_effect = lambda: events.append('revoke')
        old.close.side_effect = lambda: events.append('close_old')
        with self.assertRaises(PeerRetired) as caught:
            tracker.refresh()
        self.assertEqual(caught.exception.code, 'peer_unverified')
        self.assertEqual(self.apply.call_count, 1)
        self.assertLess(events.index('revoke'), events.index('close_old'))
        self.assertEqual(tracker.records, ())

    def test_pid_reuse_is_sticky_not_ordinary_retirement(self):
        tracker = self.tracker()
        tracker.refresh()
        old = self.peers[10]
        old.alive.return_value = False
        self.peers[10] = peer(created=102)
        with self.assertRaises(IPCError) as caught:
            tracker.refresh()
        self.assertEqual(caught.exception.code, 'process_changed')
        self.assertNotIsInstance(caught.exception, PeerRetired)
        self.revoke.assert_called_once()

    def test_unverified_old_peer_does_not_hide_a_port_ownership_conflict(self):
        tracker = self.tracker()
        tracker.refresh()
        self.factory.side_effect = None
        self.factory.return_value = None
        self.rows.append(row(pid=20, address='0.0.0.0'))
        with self.assertRaises(IPCError) as caught:
            tracker.refresh()
        self.assertEqual(caught.exception.code, 'listener_changed')
        self.assertNotIsInstance(caught.exception, PeerRetired)

    def test_wildcards_and_mapped_ipv6_are_conflicts(self):
        for family, address in ((4, '0.0.0.0'), (6, '::'), (6, '::ffff:127.0.0.1')):
            with self.subTest(address=address):
                self.rows, self.v6 = [row()], []
                (self.rows if family == 4 else self.v6).append(row(pid=20, address=address))
                with self.assertRaises(IPCError) as caught:
                    self.tracker().refresh()
                self.assertEqual(caught.exception.code, 'listener_changed')

    def test_exited_peer_does_not_mask_mapped_conflict(self):
        self.peers[10].alive.return_value = False
        self.v6 = [row(pid=20, address='::ffff:127.0.0.1')]
        with self.assertRaises(IPCError) as caught:
            self.tracker().refresh()
        self.assertEqual(caught.exception.code, 'listener_changed')

    def test_post_apply_validation_and_revocation_failure_retain_handles(self):
        tracker = self.tracker()
        self.apply.side_effect = lambda records: self.rows.clear()
        self.revoke.side_effect = OSError('close unconfirmed')
        with self.assertRaises(IPCError) as caught:
            tracker.refresh()
        self.assertEqual(caught.exception.code, 'revoke_failed')
        self.peers[10].close.assert_not_called()
        self.revoke.side_effect = None
        tracker.close()
        self.peers[10].close.assert_called_once()

    def test_budget_counts_client_edges_not_only_endpoints(self):
        paths = [fr'c:\apps\p{index}.exe' for index in range(128)]
        self.rows = [row(5000 + index, 10 + index) for index in range(3)]
        self.peers = {10 + index: peer(path=paths[index]) for index in range(3)}
        tracker = self.tracker([paths])
        with self.assertRaises(IPCError) as caught:
            tracker.refresh()
        self.assertEqual(caught.exception.code, 'client_limit')
        self.apply.assert_not_called()

    def test_endpoint_and_per_process_limits(self):
        self.rows = [row(5000 + index) for index in range(9)]
        with self.assertRaises(IPCError) as caught:
            self.tracker().refresh()
        self.assertEqual(caught.exception.code, 'endpoint_limit')

    def test_large_store_group_is_supported_within_client_budget(self):
        paths = [MAIN] + [fr'c:\apps\p{index}.exe' for index in range(127)]
        records = self.tracker([paths]).refresh()
        self.assertEqual(len(records[0].client_paths), 128)

    def test_global_endpoint_limit(self):
        self.rows = [row(5000 + index, 10 + index) for index in range(17)]
        self.peers = {10 + index: peer() for index in range(17)}
        with self.assertRaises(IPCError) as caught:
            self.tracker().refresh()
        self.assertEqual(caught.exception.code, 'endpoint_limit')

    def test_second_snapshot_failure_prevents_apply(self):
        tracker = self.tracker()
        tracker._rows = Mock(side_effect=[self.rows, [], [], []])
        with self.assertRaises(PeerRetired):
            tracker.refresh()
        self.apply.assert_not_called()
        self.revoke.assert_called_once()

    def test_unknown_identity_error_revokes_instead_of_skipping(self):
        tracker = self.tracker()
        tracker.refresh()
        self.factory.side_effect = OSError('identity unavailable')
        with self.assertRaises(OSError):
            tracker.refresh()
        self.revoke.assert_called_once()
        self.peers[10].close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
