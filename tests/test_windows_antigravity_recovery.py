"""Lifecycle/navigation fixtures: no real sockets, processes, or browser content."""
import unittest
from unittest.mock import Mock

from ruleproxy.windows_antigravity_navigation import NavigationError
from ruleproxy.windows_antigravity_recovery import ListenerSnapshot, recover_once


FAILED = {'id': 'FRAME', 'loaderId': 'OLD', 'url': 'chrome-error://chromewebdata/',
          'unreachableUrl': 'https://127.0.0.1:22097/'}
LOADED = {'id': 'FRAME', 'loaderId': 'NEW', 'url': 'https://127.0.0.1:22097/welcome', 'unreachableUrl': ''}
TARGET = {'type': 'page', 'url': 'chrome-error://chromewebdata/',
          'webSocketDebuggerUrl': 'ws://127.0.0.1:22095/devtools/page/A'}


class Clock:
    def __init__(self):
        self.now = 0.
    def __call__(self):
        return self.now
    def sleep(self, seconds):
        self.now += seconds


class Session:
    def __init__(self, frames):
        self.frames = list(frames)
        self.reloads = 0
        self.closed = False
        self.reload_error = False
    def __enter__(self):
        return self
    def __exit__(self, *args):
        self.closed = True
    def frame(self):
        if len(self.frames) > 1:
            return self.frames.pop(0)
        return self.frames[0]
    def reload(self):
        self.reloads += 1
        if self.reload_error:
            raise NavigationError('reply_lost')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.peers = Mock()
        self.snapshot = ListenerSnapshot((22095,), (22097, 22098))
        self.peers.snapshot.return_value = self.snapshot
        self.peers.valid.return_value = True
        self.check = Mock(return_value=True)
        self.session = Session([FAILED, FAILED, LOADED])
        self.client = Mock()
        self.client.targets.return_value = [TARGET]
        self.client.connect.return_value = self.session
        self.factory = Mock(return_value=self.client)

    def run_recovery(self, deadline=2):
        return recover_once(self.peers, self.check, deadline,
                            client_factory=self.factory, clock=self.clock, sleep=self.clock.sleep)

    def test_one_reload_recovers_same_frame_new_loader(self):
        self.assertEqual(self.run_recovery(), {'state': 'recovered', 'reload_attempted': True})
        self.assertEqual(self.session.reloads, 1)
        self.assertTrue(self.session.closed)
        self.client.connect.assert_called_once_with(TARGET['webSocketDebuggerUrl'])

    def test_final_frame_races_with_stop(self):
        original = self.session.frame
        def frame():
            value = original()
            if self.session.reloads:
                self.check.return_value = False
            return value
        self.session.frame = frame
        self.assertEqual(self.run_recovery(), {'state': 'cancelled', 'reload_attempted': True})
        self.assertEqual(self.session.reloads, 1)

    def test_final_frame_races_with_peer_exit(self):
        original = self.session.frame
        def frame():
            value = original()
            if self.session.reloads:
                self.peers.valid.return_value = False
            return value
        self.session.frame = frame
        self.assertEqual(self.run_recovery()['state'], 'cancelled')

    def test_final_frame_arrives_after_deadline(self):
        original = self.session.frame
        def frame():
            value = original()
            if self.session.reloads:
                self.clock.now = 3.
            return value
        self.session.frame = frame
        self.assertEqual(self.run_recovery(), {'state': 'reload_unverified', 'reload_attempted': True})

    def test_healthy_page_not_reloaded(self):
        self.session.frames = [LOADED]
        self.client.targets.return_value = [{**TARGET, 'url': LOADED['url']}]
        self.assertEqual(self.run_recovery()['state'], 'not_needed')
        self.assertEqual(self.session.reloads, 0)

    def test_cancelled_before_discovery(self):
        self.check.return_value = False
        self.assertEqual(self.run_recovery()['state'], 'cancelled')
        self.factory.assert_not_called()
        self.peers.snapshot.assert_not_called()

    def test_waiting_never_connects(self):
        self.check.return_value = None
        self.assertEqual(self.run_recovery()['state'], 'expired')
        self.factory.assert_not_called()
        self.assertLessEqual(self.clock.now, 2.000001)

    def test_readiness_later_succeeds(self):
        self.check.side_effect = [None, True, True, True, True, True, True, True]
        self.assertEqual(self.run_recovery()['state'], 'recovered')
        self.assertEqual(self.session.reloads, 1)

    def test_missing_peers_expires(self):
        self.peers.snapshot.return_value = None
        self.assertEqual(self.run_recovery()['state'], 'expired')
        self.factory.assert_not_called()

    def test_invalid_snapshot_fails_closed(self):
        for snapshot in (ListenerSnapshot((80,), (22097,)), ListenerSnapshot((True,), (22097,)),
                         ListenerSnapshot(tuple(range(22000, 22009)), (22097,))):
            with self.subTest(snapshot=snapshot):
                self.peers.snapshot.return_value = snapshot
                self.assertEqual(self.run_recovery()['state'], 'unavailable')
        self.factory.assert_not_called()

    def test_generation_changed_before_connect(self):
        self.peers.valid.return_value = False
        self.assertEqual(self.run_recovery()['state'], 'cancelled')
        self.factory.assert_not_called()

    def test_generation_changed_after_frame_read(self):
        self.peers.valid.side_effect = [True, False]
        self.assertEqual(self.run_recovery()['state'], 'cancelled')
        self.assertEqual(self.session.reloads, 0)
        self.assertTrue(self.session.closed)

    def test_navigation_changed_during_confirmation(self):
        self.session.frames = [FAILED, LOADED]
        self.assertEqual(self.run_recovery()['state'], 'navigation_changed')
        self.assertEqual(self.session.reloads, 0)

    def test_same_failure_new_loader_not_reloaded(self):
        self.session.frames = [FAILED, {**FAILED, 'loaderId': 'DIFFERENT'}]
        self.assertEqual(self.run_recovery()['state'], 'navigation_changed')
        self.assertEqual(self.session.reloads, 0)

    def test_recheck_readiness_immediately_before_reload(self):
        self.check.side_effect = [True, True, True, True, False]
        self.assertEqual(self.run_recovery()['state'], 'cancelled')
        self.assertEqual(self.session.reloads, 0)

    def test_other_failed_navigation_never_reloaded(self):
        for url in ('https://example.test/', 'https://127.0.0.1:22099/', 'http://127.0.0.1:22097/',
                    'https://127.0.0.1:22097/chat', 'https://127.0.0.1:22097/?q=x',
                    'https://127.0.0.1:22097/#x', 'https://user@127.0.0.1:22097/',
                    'https://127.0.0.1:99999/', 'https://127.0.0.1:22097/\n'):
            with self.subTest(url=url):
                self.session.frames = [{**FAILED, 'unreachableUrl': url}]
                self.assertEqual(self.run_recovery()['state'], 'not_initial_failure')
        self.assertEqual(self.session.reloads, 0)

    def test_ambiguous_pages_not_connected(self):
        self.client.targets.return_value = [TARGET, TARGET]
        self.assertEqual(self.run_recovery()['state'], 'ambiguous')
        self.client.connect.assert_not_called()

    def test_unrelated_pages_not_connected(self):
        self.client.targets.return_value = [{**TARGET, 'url': 'https://example.test/'},
                                            {**TARGET, 'url': 'data:text/html,curtain'}]
        self.assertEqual(self.run_recovery()['state'], 'expired')
        self.client.connect.assert_not_called()

    def test_non_cdp_listener_skipped(self):
        self.peers.snapshot.return_value = ListenerSnapshot((22096, 22095), (22097,))
        other = Mock()
        other.targets.side_effect = NavigationError('http_response')
        self.factory.side_effect = [other, self.client]
        self.assertEqual(self.run_recovery()['state'], 'recovered')
        other.connect.assert_not_called()

    def test_lost_reload_reply_is_never_retried(self):
        self.session.reload_error = True
        self.assertEqual(self.run_recovery(), {'state': 'reload_unverified', 'reload_attempted': True})
        self.assertEqual(self.session.reloads, 1)
        self.factory.assert_called_once()
        self.assertTrue(self.session.closed)

    def test_failed_reload_navigation_is_bounded(self):
        self.session.frames = [FAILED]
        self.assertEqual(self.run_recovery()['state'], 'reload_unverified')
        self.assertEqual(self.session.reloads, 1)
        self.assertLessEqual(self.clock.now, 2.000001)

    def test_other_frame_or_helper_does_not_claim_success(self):
        for current in ({**LOADED, 'id': 'OTHER'}, {**LOADED, 'loaderId': 'OLD'},
                        {**LOADED, 'url': 'https://127.0.0.1:22098/welcome'}):
            with self.subTest(current=current):
                self.clock.now = 0
                self.session.frames = [FAILED, FAILED, current]
                self.assertEqual(self.run_recovery()['state'], 'reload_unverified')

    def test_deadline_invalid_or_expired(self):
        for deadline in (True, float('nan'), float('inf'), '2', -1, 0):
            with self.subTest(deadline=deadline):
                result = self.run_recovery(deadline)
                self.assertIn(result['state'], ('unavailable', 'expired'))
                self.assertFalse(result['reload_attempted'])
        self.factory.assert_not_called()

    def test_native_failure_does_not_change_protection(self):
        self.peers.snapshot.side_effect = OSError('private details')
        self.assertEqual(self.run_recovery(), {'state': 'unavailable', 'reload_attempted': False})
        self.factory.assert_not_called()


if __name__ == '__main__':
    unittest.main()
