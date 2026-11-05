"""Pure injected tests; no native imports or executable launches."""
import importlib.util
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import Mock

SPEC = importlib.util.spec_from_file_location('ipc_discovery_tested', Path(__file__).resolve().parents[1] / 'ruleproxy/windows_antigravity_ipc.py')
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
Tracker, IPCError = MODULE.Tracker, MODULE.IPCError
MAIN, HELPER = r'C:\Apps\main.exe', r'C:\Apps\helper.exe'


def row(port=5000, pid=10, address='127.0.0.1'):
    return dict(state=2, local=address, local_port=port, pid=pid)


def process(path=MAIN, created=101):
    return Mock(alive=Mock(return_value=True), image_path=Mock(return_value=path),
                creation_time=Mock(return_value=created), close=Mock())


class Tests(unittest.TestCase):
    def setUp(self):
        self.v4, self.v6 = [row()], []
        self.handle = process()
        self.factory = Mock(return_value=self.handle)
        self.apply, self.revoke = Mock(), Mock()
        self.t = Tracker(MAIN, HELPER, 'S-1-5-21-1', 100,
                         rows_factory=lambda family: self.v4 if family == socket.AF_INET else self.v6,
                         process_factory=self.factory, apply=self.apply, revoke=self.revoke)

    def failure(self, code=None):
        with self.assertRaises(Exception) as caught:
            self.t.refresh()
        if code:
            self.assertEqual(caught.exception.code, code)
        self.revoke.assert_called_once()
        self.assertIsNotNone(self.t.fault)

    def test_pair_and_owner(self):
        records = self.t.refresh()
        self.assertEqual((records[0].server_path, records[0].client_path), (MAIN.lower(), HELPER.lower()))
        self.factory.assert_called_once_with(10, 'S-1-5-21-1')
        self.apply.assert_called_once_with(records)
        self.handle.close.assert_not_called()

    def test_helper_direction(self):
        self.handle.image_path.return_value = HELPER
        self.assertEqual(self.t.refresh()[0].client_path, MAIN.lower())

    def test_unrelated_skipped(self):
        self.handle.image_path.return_value = r'C:\Other\other.exe'
        self.assertEqual(self.t.refresh(), ())
        self.handle.creation_time.assert_not_called()
        self.handle.close.assert_called_once()

    def test_old_requires_restart(self):
        self.handle.creation_time.return_value = 99
        self.failure('requires_restart')
        self.apply.assert_not_called()

    def test_dead_process(self):
        self.handle.alive.return_value = False
        self.failure('process_exited')

    def test_wrong_owner(self):
        self.factory.side_effect = PermissionError('SID mismatch')
        self.failure()

    def test_invalid_path(self):
        self.handle.image_path.return_value = 'relative.exe'
        self.failure()

    def test_duplicate_port(self):
        self.v4.append(row())
        self.failure('listener_changed')

    def test_wildcard_v4(self):
        self.v4.append(row(pid=20, address='0.0.0.0'))
        self.failure('listener_changed')

    def test_wildcard_v6(self):
        self.v6.append(row(pid=20, address='::'))
        self.failure('listener_changed')

    def test_mapped_v6(self):
        self.v6.append(row(pid=20, address='::ffff:127.0.0.1'))
        self.failure('listener_changed')

    def test_second_snapshot_change(self):
        self.t._rows = Mock(side_effect=[[row()], [], [], []])
        self.failure('listener_disappeared')
        self.apply.assert_not_called()

    def test_third_snapshot_change(self):
        self.t._rows = Mock(side_effect=[[row()], [], [row()], [], [], []])
        self.failure('listener_disappeared')
        self.apply.assert_called_once()

    def test_table_failure(self):
        self.t._rows = Mock(side_effect=OSError('table failed'))
        self.failure()

    def test_table_bound(self):
        self.v4 = [dict(state=1)] * 65537
        self.failure('table_limit')

    def test_per_pid_bound(self):
        self.v4 = [row(port=5000+i) for i in range(9)]
        self.failure('endpoint_limit')

    def test_total_bound(self):
        self.v4 = [row(port=5000+i, pid=10+i//6) for i in range(17)]
        self.factory.side_effect = lambda *args: process()
        self.failure('endpoint_limit')

    def test_apply_failure(self):
        self.apply.side_effect = OSError('transaction failed')
        self.failure()
        self.handle.close.assert_called_once()

    def test_revoke_failure_retains_handle_then_close_retries(self):
        self.apply.side_effect = OSError('apply failed')
        self.revoke.side_effect = OSError('revoke failed')
        self.failure('revoke_failed')
        self.handle.close.assert_not_called()
        self.revoke.side_effect = None
        self.t.close()
        self.handle.close.assert_called_once()

    def test_close_order_and_retry(self):
        self.t.refresh()
        events = []
        self.revoke.side_effect = lambda: events.append('revoke')
        self.handle.close.side_effect = lambda: events.append('close')
        self.t.close()
        self.assertEqual(events, ['revoke', 'close'])
        with self.assertRaises(IPCError):
            self.t.refresh()

    def test_close_failed_preserves(self):
        self.t.refresh()
        self.revoke.side_effect = OSError('failed')
        with self.assertRaises(OSError):
            self.t.close()
        self.handle.close.assert_not_called()
        self.revoke.side_effect = None
        self.t.close()
        self.handle.close.assert_called_once()

    def test_replacement_order(self):
        self.t.refresh()
        second = process()
        self.factory.return_value = second
        events = []
        self.apply.side_effect = lambda records: events.append('apply')
        self.handle.close.side_effect = lambda: events.append('old_close')
        self.t.refresh()
        self.assertEqual(events, ['apply', 'old_close'])
        second.close.assert_not_called()

    def test_pid_reuse_old_handle_dead(self):
        self.t.refresh()
        self.handle.alive.return_value = False
        self.factory.return_value = process(created=200)
        self.failure('process_changed')
        self.assertEqual(self.apply.call_count, 1)

    def test_creation_changed_between_snapshots(self):
        self.handle.creation_time.side_effect = [101, 102]
        self.failure('process_changed')

    def test_handle_close_failure_retry(self):
        self.t.refresh()
        self.handle.close.side_effect = OSError('close failed')
        with self.assertRaises(IPCError):
            self.t.close()
        self.assertTrue(self.t._held)
        self.handle.close.side_effect = None
        self.t.close()
        self.assertFalse(self.t._held)

    def test_none_grants_nothing_and_is_cached_per_pid(self):
        self.factory.return_value = None
        self.v4.append(row(port=5001))
        self.assertEqual(self.t.refresh(), ())
        self.factory.assert_called_once_with(10, 'S-1-5-21-1')
        self.apply.assert_called_once_with(())
        self.revoke.assert_not_called()
        self.assertIsNone(self.t.fault)

    def test_none_replaces_old_plan_before_closing_even_dead_handle(self):
        self.t.refresh()
        self.handle.alive.return_value = False
        self.factory.return_value = None
        events = []
        def replace(records):
            self.assertEqual(records, ())
            self.handle.close.assert_not_called()
            events.append('replace_empty')
        self.apply.side_effect = replace
        self.handle.close.side_effect = lambda: events.append('close_old')
        self.assertEqual(self.t.refresh(), ())
        self.assertEqual(events, ['replace_empty', 'close_old'])
        self.assertFalse(self.t._held)
        self.revoke.assert_not_called()

    def test_none_replacement_failure_revokes_before_releasing(self):
        self.t.refresh()
        self.factory.return_value = None
        events = []
        self.apply.side_effect = OSError('replacement failed')
        self.revoke.side_effect = lambda: events.append('revoke')
        self.handle.close.side_effect = lambda: events.append('close_old')
        self.failure()
        self.assertEqual(events, ['revoke', 'close_old'])

    def test_none_replacement_revoke_failure_retains_old_handle(self):
        self.t.refresh()
        self.factory.return_value = None
        self.apply.side_effect = OSError('replacement failed')
        self.revoke.side_effect = OSError('revocation failed')
        self.failure('revoke_failed')
        self.handle.close.assert_not_called()
        self.revoke.side_effect = None
        self.t.close()
        self.handle.close.assert_called_once()

    def test_factory_error_with_existing_lease_still_faults(self):
        self.t.refresh()
        self.factory.side_effect = OSError('unknown native lookup error')
        self.failure()
        self.assertEqual(self.apply.call_count, 1)
        self.handle.close.assert_called_once()

    def test_empty_plan(self):
        self.v4 = []
        self.assertEqual(self.t.refresh(), ())
        self.apply.assert_called_once_with(())


if __name__ == '__main__':
    unittest.main()
