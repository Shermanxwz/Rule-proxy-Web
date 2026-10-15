"""Browser fixture cleanup facts must be explicit and fail closed."""
from pathlib import Path
import importlib.util
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_windows_browser_check", ROOT / ".github/windows_browser_check.py")
browser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(browser)


class _Owner:
    def __init__(self, *, fail=False):
        self.fail = fail
        self.closed = False

    def close(self):
        if self.fail:
            raise RuntimeError("owned workload stop unproven")
        self.closed = True

    def cleanup_facts(self):
        return {"owned_workload_cleanup_proven": self.closed,
                "resources_closed": self.closed}


class _Fixture:
    def __init__(self, *, fail=False, live_worker=False):
        self.closed = threading.Event()
        self.worker = mock.Mock()
        self.worker.is_alive.return_value = live_worker
        self.handlers = set()
        self.fail = fail

    def close(self):
        if self.fail:
            raise RuntimeError("fixture close failed")
        self.closed.set()


class WindowsBrowserCheckTests(unittest.TestCase):
    def setUp(self):
        browser._RECOVERY_OWNERS.clear()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "private-profile"
        self.directory.mkdir()

    def result(self):
        return {"status": "failed", "browser_fixture_passed": False, "checks": [],
                "cleanup_proven": False, "host_network_unchanged": None}

    def finalize(self, owner, fixture, snapshot=lambda: "same", before="same"):
        return browser.finalize_cleanup(self.result(), owner, fixture, self.directory, before, snapshot)

    def test_clean_close_proves_owner_fixture_profile_and_unchanged_host(self):
        result = self.result()
        self.assertTrue(browser.finalize_cleanup(result, _Owner(), _Fixture(), self.directory,
                                                 "same", lambda: "same"))
        self.assertTrue(result["cleanup_proven"])
        self.assertTrue(result["owned_workload_cleanup_proven"])
        self.assertTrue(result["fixture_workers_closed"])
        self.assertTrue(result["private_profile_removed"])
        self.assertTrue(result["host_network_unchanged"])
        self.assertFalse(self.directory.exists())

    def test_owner_stop_failure_retains_profile_and_recovery_owners(self):
        result = self.result()
        owner, fixture = _Owner(fail=True), _Fixture()
        self.assertFalse(browser.finalize_cleanup(result, owner, fixture, self.directory,
                                                  "same", lambda: "same"))
        self.assertFalse(result["owned_workload_cleanup_proven"])
        self.assertFalse(result["cleanup_proven"])
        self.assertTrue(self.directory.exists())
        self.assertIs(browser._RECOVERY_OWNERS[-1][0], owner)

    def test_safe_stop_failure_retains_browser_process_and_resources_for_retry(self):
        from ruleproxy import windows_runtime
        owner = browser.BrowserRun("runtime", "edge", self.directory, mock.Mock())
        owner.wrapper, owner.resources = mock.Mock(), mock.Mock()
        wrapper, resources = owner.wrapper, owner.resources
        with mock.patch.object(windows_runtime, "stop", side_effect=RuntimeError("stop unproven")):
            with self.assertRaisesRegex(RuntimeError, "stop unproven"):
                owner.close()
        self.assertIs(owner.wrapper, wrapper)
        self.assertIs(owner.resources, resources)
        resources.close.assert_not_called()
        self.assertFalse(owner.cleanup_facts()["owned_workload_cleanup_proven"])
        self.assertFalse(owner.cleanup_facts()["resources_closed"])

    def test_resource_close_failure_keeps_resource_reference_and_distinct_facts(self):
        from ruleproxy import windows_runtime
        owner = browser.BrowserRun("runtime", "edge", self.directory, mock.Mock())
        owner.wrapper, owner.resources = mock.Mock(), mock.Mock()
        resources = owner.resources
        resources.close.side_effect = RuntimeError("resource close failed")
        with mock.patch.object(windows_runtime, "stop"):
            with self.assertRaisesRegex(RuntimeError, "resource close failed"):
                owner.close()
        self.assertIs(owner.resources, resources)
        self.assertTrue(owner.cleanup_facts()["owned_workload_cleanup_proven"])
        self.assertFalse(owner.cleanup_facts()["resources_closed"])

    def test_launch_exception_with_attached_live_wrapper_records_started_and_retains_owner(self):
        from ruleproxy import launcher, windows_runtime
        fixture = mock.Mock(port=19002)
        owner = browser.BrowserRun("runtime", "edge", self.directory, fixture)
        wrapper, resources = mock.Mock(), mock.Mock()
        failure = RuntimeError("startup failed after wrapper launch")
        failure.process, failure.resource = wrapper, resources
        with mock.patch.object(windows_runtime, "choose_guest_port", return_value=19001), \
                mock.patch.object(launcher, "prepare_app", return_value=([], {}, "")), \
                mock.patch.object(windows_runtime, "launch", side_effect=failure):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                owner.run(1, 90)
        self.assertTrue(owner.current_attempt["wrapper_process_started"])
        self.assertNotIn("process_started", owner.current_attempt)
        self.assertIs(owner.wrapper, wrapper)
        self.assertIs(owner.resources, resources)
        self.assertFalse(owner.cleanup_facts()["owned_workload_cleanup_proven"])
        self.assertFalse(owner.cleanup_facts()["resources_closed"])

    def test_fixture_close_failure_or_live_handler_retains_profile(self):
        for fixture in (_Fixture(fail=True), _Fixture(live_worker=True)):
            with self.subTest(fixture=fixture):
                self.directory.mkdir(exist_ok=True)
                result = self.result()
                self.assertFalse(browser.finalize_cleanup(result, _Owner(), fixture, self.directory,
                                                          "same", lambda: "same"))
                self.assertFalse(result["fixture_workers_closed"])
                self.assertFalse(result["cleanup_proven"])
                self.assertTrue(self.directory.exists())

    def test_profile_remove_failure_is_not_reported_as_clean(self):
        result = self.result()
        with mock.patch.object(browser.shutil, "rmtree", side_effect=PermissionError):
            self.assertFalse(browser.finalize_cleanup(result, _Owner(), _Fixture(), self.directory,
                                                      "same", lambda: "same"))
        self.assertFalse(result["private_profile_removed"])
        self.assertFalse(result["cleanup_proven"])
        self.assertIn("recovery_directory", result)

    def test_missing_or_failed_network_snapshot_never_defaults_to_unchanged(self):
        result = self.result()
        self.assertTrue(browser.finalize_cleanup(result, _Owner(), _Fixture(), None, None,
                                                 lambda: self.fail("must not query without baseline")))
        self.assertIsNone(result["host_network_unchanged"])
        result = self.result()
        self.assertTrue(browser.finalize_cleanup(result, _Owner(), _Fixture(), None, "before",
                                                 lambda: (_ for _ in ()).throw(OSError("snapshot failed"))))
        self.assertIsNone(result["host_network_unchanged"])
        self.assertEqual(result["checks"][-1]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
