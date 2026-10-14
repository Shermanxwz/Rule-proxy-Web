import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock

from ruleproxy import file_bridge, windows_guest


class WindowsGuestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = {
            "command": [r"C:\Apps\browser.exe"],
            "env": {}, "profile": str(root), "listener_port": 19001,
            "bridge_directory": str(root), "bridge_nonce": "a" * 64,
            "host_fixture_port": 19002,
        }

    def helper_setup(self, bridge_worker, decision="approved"):
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.dict(sys.modules, {"file_bridge": file_bridge}))
        stack.enter_context(mock.patch.object(sys, "path", sys.path.copy()))
        stack.enter_context(mock.patch.object(windows_guest, "_read_config", return_value=self.config))
        status = stack.enter_context(mock.patch.object(windows_guest, "_atomic_status"))
        check = stack.enter_context(mock.patch.object(windows_guest, "_child_self_check"))
        stack.enter_context(mock.patch.object(file_bridge, "run_guest_bridge", side_effect=bridge_worker))
        stack.enter_context(mock.patch.object(file_bridge, "wait_for_bridge_ready", return_value=True))
        ready = stack.enter_context(mock.patch.object(file_bridge, "signal_guest_ready"))
        host_decision = stack.enter_context(mock.patch.object(file_bridge, "wait_for_decision", return_value=decision))
        application = mock.Mock()
        application.poll.return_value = 0
        application.wait.return_value = 0
        popen = stack.enter_context(mock.patch.object(windows_guest.subprocess, "Popen", return_value=application))
        return status, check, ready, host_decision, popen

    @staticmethod
    def running_bridge(_port, _directory, _nonce, stop):
        stop.wait(4)

    def test_application_starts_only_after_live_bridge_self_check_and_approval(self):
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        events = []
        check.side_effect = lambda *args: events.append("network check")
        ready.side_effect = lambda *args: events.append("guest ready")
        decision.side_effect = lambda *args: events.append("host approval") or "approved"
        app = popen.return_value
        popen.side_effect = lambda *args, **kwargs: events.append("application") or app
        self.assertEqual(windows_guest.run(Path("config")), 0)
        self.assertEqual(events, ["network check", "guest ready", "host approval", "application"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        self.assertTrue(popen.call_args.kwargs["close_fds"])
        self.assertEqual(status.call_args_list[-1].args[2], "APP_EXITED")

    def test_self_check_failure_never_publishes_ready_or_starts_application(self):
        status, check, ready, decision, popen = self.helper_setup(self.running_bridge)
        check.side_effect = RuntimeError("direct UDP was not denied")
        self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(status.call_args.args[2], "FAILED")

    def test_host_rejection_never_starts_application(self):
        _, _, _, _, popen = self.helper_setup(self.running_bridge, "rejected")
        self.assertEqual(windows_guest.run(Path("config")), 70)
        popen.assert_not_called()

    def test_bridge_normal_exit_before_approval_never_starts_application(self):
        stopped = threading.Event()
        bridge_threads = []

        def exited_bridge(*args):
            bridge_threads.append(threading.current_thread())
            stopped.set()

        _, check, ready, decision, popen = self.helper_setup(exited_bridge)

        def finish_check(*args):
            self.assertTrue(stopped.wait(2))
            bridge_threads[0].join(2)

        check.side_effect = finish_check
        self.assertEqual(windows_guest.run(Path("config")), 70)
        ready.assert_not_called()
        decision.assert_not_called()
        popen.assert_not_called()

    def test_bridge_normal_exit_during_host_decision_never_starts_application(self):
        leave_bridge = threading.Event()
        bridge_left = threading.Event()
        bridge_threads = []

        def bridge(*args):
            bridge_threads.append(threading.current_thread())
            leave_bridge.wait(4)
            bridge_left.set()

        _, _, _, decision, popen = self.helper_setup(bridge)

        def approve(*args):
            leave_bridge.set()
            self.assertTrue(bridge_left.wait(2))
            bridge_threads[0].join(2)
            return "approved"

        decision.side_effect = approve
        self.assertEqual(windows_guest.run(Path("config")), 70)
        popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
