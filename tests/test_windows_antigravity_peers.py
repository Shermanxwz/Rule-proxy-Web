"""Held-identity peer tests with no native process or network operations."""
import unittest
from unittest.mock import Mock
from ruleproxy.windows_antigravity_peers import NativePeers
from ruleproxy.windows_antigravity_recovery import ListenerSnapshot

MAIN = r'C:\App\Antigravity.exe'
HELPER = r'C:\App\resources\bin\language_server.exe'


class Lease:
    def __init__(self, path, created=100):
        self.path, self.created, self.live, self.closed = path, created, True, False
    def alive(self):
        return self.live and not self.closed
    def image_path(self):
        return self.path
    def creation_time(self):
        return self.created
    def close(self):
        self.closed = True


def row(pid, port, local='127.0.0.1', state=2):
    return {'pid': pid, 'local_port': port, 'local': local, 'state': state}


class PeerTests(unittest.TestCase):
    def setUp(self):
        self.process = Mock(pid=1, poll=Mock(return_value=None))
        self.main, self.helper = Lease(MAIN), Lease(HELPER, 101)
        self.leases = {1: self.main, 2: self.helper}
        self.factory = Mock(side_effect=lambda pid, sid: self.leases[pid])
        self.rows = [row(1, 22095), row(2, 22097)]
        self.members = [1, 2]
        self.peers = NativePeers(self.process, MAIN, paths=[MAIN, HELPER], owner_sid='SID',
                                 lease_factory=self.factory, rows_factory=lambda: self.rows,
                                 pids_factory=lambda: tuple(self.members))
        self.addCleanup(self.peers.close)

    def test_owned_pair_held_and_revalidated(self):
        value = self.peers.snapshot()
        self.assertEqual(value, ListenerSnapshot((22095,), (22097,)))
        self.assertTrue(self.peers.valid(value))
        self.assertEqual(self.factory.call_count, 2)
        self.assertFalse(self.helper.closed)

    def test_unrelated_listener_not_opened(self):
        self.rows.append(row(99, 22111))
        self.peers.snapshot()
        self.assertEqual([v.args[0] for v in self.factory.call_args_list], [1, 2])

    def test_same_job_nonhelper_closed(self):
        other = Lease(MAIN, 101)
        self.leases[3] = other
        self.members.append(3)
        self.rows.append(row(3, 22111))
        self.assertIsNotNone(self.peers.snapshot())
        self.assertTrue(other.closed)

    def test_helper_outside_job_never_adopted(self):
        self.members.remove(2)
        self.assertIsNone(self.peers.snapshot())
        self.assertEqual(self.factory.call_count, 1)

    def test_old_helper_rejected_and_closed(self):
        self.helper.created = 99
        with self.assertRaises(ValueError):
            self.peers.snapshot()
        self.assertTrue(self.helper.closed)

    def test_duplicate_local_listener_owner_rejected(self):
        self.rows.append(row(99, 22095))
        with self.assertRaises(ValueError):
            self.peers.snapshot()

    def test_wildcard_or_established_not_discovered(self):
        for entry in (row(2, 22097, '0.0.0.0'), row(2, 22097, state=5)):
            self.rows[:] = [row(1, 22095), entry]
            self.assertIsNone(self.peers.snapshot())

    def test_pinned_helper_exit_or_replacement_invalidates(self):
        value = self.peers.snapshot()
        self.helper.live = False
        self.assertFalse(self.peers.valid(value))
        self.assertEqual(self.factory.call_count, 2)

    def test_root_exit_invalidates(self):
        value = self.peers.snapshot()
        self.process.poll.return_value = 0
        self.assertFalse(self.peers.valid(value))

    def test_port_change_invalidates(self):
        value = self.peers.snapshot()
        self.rows[1] = row(2, 22099)
        self.assertFalse(self.peers.valid(value))

    def test_two_helpers_rejected(self):
        self.leases[3] = Lease(HELPER, 102)
        self.members.append(3)
        self.rows.append(row(3, 22099))
        with self.assertRaises(ValueError):
            self.peers.snapshot()
        self.assertTrue(self.leases[3].closed)

    def test_job_changed_during_snapshot(self):
        self.peers.pids_factory = Mock(side_effect=[(1, 2), (1,)])
        with self.assertRaises(ValueError):
            self.peers.snapshot()

    def test_close_releases_both_held_handles(self):
        self.peers.snapshot()
        self.peers.close()
        self.peers.close()
        self.assertTrue(self.main.closed)
        self.assertTrue(self.helper.closed)

    def test_port_bound(self):
        self.rows[:] = [row(1, 80), row(2, 22097)]
        with self.assertRaises(ValueError):
            self.peers.snapshot()

    def test_pid_bound(self):
        self.members[:] = range(1, 258)
        with self.assertRaises(ValueError):
            self.peers.snapshot()

    def test_init_identity_failure_releases_handle(self):
        other = Lease(r'C:\Other.exe')
        with self.assertRaises(ValueError):
            NativePeers(self.process, MAIN, paths=[MAIN, HELPER], owner_sid='SID',
                        lease_factory=lambda *a: other, rows_factory=lambda: [], pids_factory=lambda: (1,))
        self.assertTrue(other.closed)


if __name__ == '__main__':
    unittest.main()
