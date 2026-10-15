"""Verify the outside-only browser control's owned process-tree boundary."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("ruleproxy_test_edge_outside", ROOT / ".github/windows_edge_outside_control.py")
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class FakeApi:
    def __init__(self, *, natural=True):
        self.calls = []
        self.natural = natural
        self.exited = False
        self.active_count = 0
        self.fail = {}
        self.exit_status = 0

    def call(self, name, *arguments):
        self.calls.append((name, *arguments))
        if self.fail.get(name):
            self.fail[name] -= 1
            error = PermissionError(13, "private details must not be published")
            error.winerror = 5
            raise error

    def create_job(self):
        self.call("create_job")
        return 10

    def set_limits(self, job):
        self.call("limits", job)

    def create_suspended(self, command, environment, cwd):
        self.call("create_suspended", tuple(command))
        return 20, 30, 1234, 1235

    def assign(self, job, process):
        self.call("assign", job, process)
        self.active_count = 1

    def resume(self, thread):
        self.call("resume", thread)
        self.exited = self.natural
        self.active_count = 0 if self.natural else 2

    def wait(self, process, milliseconds):
        self.call("wait", process, milliseconds)
        return self.exited

    def exit_code(self, process):
        self.call("exit_code", process)
        return self.exit_status

    def active(self, job):
        self.call("active", job)
        return self.active_count

    def terminate_job(self, job):
        self.call("terminate_job", job)
        self.exited, self.active_count = True, 0

    def terminate_suspended(self, process):
        self.call("terminate_suspended", process)
        self.exited = True

    def close(self, handle):
        self.call("close_" + str(handle), handle)


class OwnedJobTests(unittest.TestCase):
    def start(self, api=None):
        api = api or FakeApi()
        owner = control.OwnedJobProcess(api)
        owner.start(["stock-edge", "fixed-page"], {"ONLY": "child"}, Path("private-profile"))
        return owner, api

    def test_suspend_assign_resume_precedes_any_workload_and_natural_tree_exit(self):
        owner, api = self.start()
        self.assertEqual([row[0] for row in api.calls],
                         ["create_job", "limits", "create_suspended", "assign", "resume", "close_30"])
        self.assertTrue(owner.assigned and owner.resumed)
        self.assertEqual(owner.wait_natural(1), 0)
        self.assertTrue(owner.natural_tree_exit)
        owner.close()
        self.assertTrue(owner.cleanup_proven)
        self.assertFalse(any(row[0].startswith("terminate") for row in api.calls))

    def test_assignment_failure_never_resumes_and_only_terminates_its_owned_suspended_root(self):
        api = FakeApi()
        api.fail["assign"] = 1
        owner = control.OwnedJobProcess(api)
        with self.assertRaises(PermissionError):
            owner.start(["edge"], {}, Path("profile"))
        owner.close()
        names = [row[0] for row in api.calls]
        self.assertNotIn("resume", names)
        self.assertIn("terminate_suspended", names)
        self.assertNotIn("terminate_job", names)
        self.assertTrue(owner.cleanup_proven)

    def test_resume_failure_after_assignment_uses_only_owned_job_teardown(self):
        api = FakeApi()
        api.fail["resume"] = 1
        owner = control.OwnedJobProcess(api)
        with self.assertRaises(PermissionError):
            owner.start(["edge"], {}, Path("profile"))
        owner.close()
        names = [row[0] for row in api.calls]
        self.assertIn("terminate_job", names)
        self.assertNotIn("terminate_suspended", names)
        self.assertTrue(owner.cleanup_proven)

    def test_zero_root_exit_with_live_descendants_cannot_count_as_natural_success(self):
        owner, api = self.start()
        api.active_count = 1
        with mock.patch.object(control.time, "monotonic", side_effect=[0, 0, 2]), \
                mock.patch.object(control.time, "sleep"):
            with self.assertRaises(TimeoutError):
                owner.wait_natural(1)
        self.assertFalse(owner.natural_tree_exit)
        owner.close()
        self.assertTrue(owner.forced_teardown)

    def test_raw_windows_access_violation_code_is_preserved(self):
        owner, api = self.start()
        api.exit_status = 0xC0000005
        self.assertEqual(owner.wait_natural(1), 3221225477)
        self.assertFalse(owner.natural_tree_exit)
        owner.close()

    def test_handle_close_failure_retains_only_pending_handles_for_retry(self):
        owner, api = self.start()
        api.fail["close_10"] = 1
        with self.assertRaises(PermissionError):
            owner.close()
        self.assertIsNone(owner.process)
        self.assertEqual(owner.job, 10)
        self.assertFalse(owner.cleanup_proven)
        before = len(api.calls)
        owner.close()
        self.assertNotIn(("close_20", 20), api.calls[before:])
        self.assertTrue(owner.cleanup_proven)

    def test_unproven_job_exit_retains_real_owner_and_all_live_process_handles(self):
        owner, api = self.start(FakeApi(natural=False))
        original = api.terminate_job
        api.terminate_job = lambda job: api.call("terminate_job_without_exit", job)
        with mock.patch.object(control.time, "monotonic", side_effect=[0, 6]):
            with self.assertRaises(RuntimeError):
                owner.close()
        self.assertFalse(owner.cleanup_proven)
        self.assertEqual((owner.process, owner.job), (20, 10))
        self.assertNotIn(("close_10", 10), api.calls)
        api.terminate_job = original
        owner.close()
        self.assertTrue(owner.cleanup_proven)

    def test_limit_failure_creates_no_process_and_still_closes_its_owned_job(self):
        api = FakeApi()
        api.fail["limits"] = 1
        owner = control.OwnedJobProcess(api)
        with self.assertRaises(PermissionError):
            owner.start(["edge"], {}, Path("profile"))
        owner.close()
        self.assertNotIn("create_suspended", [row[0] for row in api.calls])
        self.assertTrue(owner.cleanup_proven)


class OutsideFixtureTests(unittest.TestCase):
    def run_control(self, directory, *, cleanup_failure=False, snapshot_changed=False):
        browser = directory / "msedge.exe"
        browser.write_bytes(b"public deterministic Edge placeholder; never executed")
        browser.chmod(0o755)
        fixture = mock.Mock(port=12345)
        fixture.HOST = "ruleproxy-browser-fixture.invalid"
        helper = SimpleNamespace(
            host_facts=lambda: {"windows_build": 26300, "windows_product_type": 1,
                                "python_pe_machine": 0x8664, "native_machine": 0x8664},
            verify_project_origin=mock.Mock(), executable_machine=lambda _: 0x8664,
            network_snapshot=mock.Mock(side_effect=["before", "after" if snapshot_changed else "before"]))
        module = SimpleNamespace(acceptance_helpers=lambda: helper,
                                 find_edge=lambda _: browser, BrowserFixture=lambda: fixture,
                                 HOST="ruleproxy-browser-fixture.invalid")
        owners = []

        def create():
            api = FakeApi()
            if cleanup_failure:
                api.fail["close_10"] = 100
            owner = self.owner_class(api)
            owners.append(owner)
            return owner

        # Do not patch sys.platform globally on actual Windows: real module
        # imports still select the platform's genuine ABI implementations.
        shell = SimpleNamespace(IsUserAnAdmin=mock.Mock(return_value=0))
        report = directory / "outside.json"
        with mock.patch.object(control, "browser_helpers", return_value=module), \
                mock.patch.object(control, "OwnedJobProcess", side_effect=create), \
                mock.patch.object(control.sys, "platform", "win32"), \
                mock.patch.object(control.ctypes, "WinDLL", return_value=shell, create=True), \
                mock.patch("builtins.print"):
            code = control.main(["--root", str(ROOT), "--report", str(report)])
        return code, json.loads(report.read_text()), fixture, owners

    def setUp(self):
        self.owner_class = control.OwnedJobProcess

    def test_actual_prepared_windows_command_preserves_stock_sandbox_and_private_environment(self):
        from ruleproxy import launcher, windows_runtime
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary).resolve()
            edge = directory / "msedge.exe"
            edge.write_bytes(b"public test executable placeholder; never run")
            edge.chmod(0o755)
            with mock.patch.object(launcher.sys, "platform", "win32"):
                command, environment, _ = control.prepare_control(launcher, edge, directory / "profiles",
                                                                  12345, 1, "ruleproxy-browser-fixture.invalid")
            environment = windows_runtime._profile_environment(environment, directory / "profiles/browser")
            self.assertEqual(command[1:6], ["--headless=new", "--dump-dom", "--disable-gpu",
                                           "--no-default-browser-check", "http://ruleproxy-browser-fixture.invalid/phase/1"])
            self.assertIn("--proxy-server=http://127.0.0.1:12345", command)
            self.assertIn("--proxy-bypass-list=<-loopback>", command)
            self.assertIn("--restore-last-session", command)
            self.assertFalse(any("no-sandbox" in flag or "disable-setuid" in flag for flag in command))
            self.assertEqual(environment["LOCALAPPDATA"], str(directory / "profiles/browser/localappdata"))
            self.assertEqual(environment["HTTP_PROXY"], "http://127.0.0.1:12345")

    def test_command_fingerprint_ignores_only_owned_profile_and_proxy_values(self):
        one = ["C:\\Edge\\msedge.exe", "--headless=new", "--user-data-dir=C:\\privateA", "--proxy-server=http://127.0.0.1:1"]
        two = ["C:\\Edge\\msedge.exe", "--headless=new", "--user-data-dir=C:\\privateB", "--proxy-server=http://127.0.0.1:2"]
        self.assertEqual(control.command_template_hash(one), control.command_template_hash(two))
        self.assertNotEqual(control.command_template_hash(one), control.command_template_hash(two + ["--no-sandbox"]))

    def test_failure_facts_do_not_publish_private_path_or_command(self):
        error = PermissionError(13, "secret-path and command", "private-profile")
        error.winerror = 5
        self.assertEqual(control.error_facts(error, "job_assign"),
                         {"stage": "job_assign", "error_type": "PermissionError", "errno": 13, "winerror": 5})

    def test_outside_result_never_grants_psec_or_network_acceptance(self):
        value = control.initial_result()
        for key in ("acceptance_passed", "full_acceptance_passed", "real_node_passed", "browser_fixture_passed",
                    "browser_sandbox_weakened", "public_udp_proven", "system_dns_proven"):
            self.assertIs(value[key], False)
        self.assertIs(value["outside_psec"], True)

    def test_complete_two_launch_health_control_never_promotes_psec_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, value, fixture, owners = self.run_control(Path(temporary))
        self.assertEqual(code, 0)
        self.assertEqual(value["status"], "outside_control_only")
        self.assertIs(value["outside_headless_control_passed"], True)
        self.assertIs(value["host_network_unchanged"], True)
        self.assertEqual(fixture.check.call_args_list, [mock.call(1), mock.call(2)])
        self.assertEqual(len(owners), 2)
        self.assertTrue(all(owner.cleanup_proven for owner in owners))
        self.assertTrue(all(row["natural_root_and_job_exit"] for row in value["checks"]))
        for key in ("acceptance_passed", "full_acceptance_passed", "real_node_passed", "browser_fixture_passed"):
            self.assertIs(value[key], False)

    def test_unproven_owner_close_stops_next_launch_and_retains_the_actual_owner(self):
        before = len(control._RECOVERY_OWNERS)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                code, value, _, owners = self.run_control(Path(temporary), cleanup_failure=True)
            self.assertEqual(code, 1)
            self.assertEqual(len(owners), 1)
            self.assertIs(value["cleanup_proven"], False)
            self.assertIs(value["outside_headless_control_passed"], False)
            self.assertIs(value["recovery_retained"], True)
            held, _, profile_directory = control._RECOVERY_OWNERS[-1]
            self.assertIs(held, owners[0])
            self.assertEqual(held.job, 10)
            self.assertTrue(profile_directory.exists())
            self.assertNotIn(str(profile_directory), json.dumps(value))
        finally:
            import shutil
            for _, _, path in control._RECOVERY_OWNERS[before:]:
                if path is not None:
                    shutil.rmtree(path)
            del control._RECOVERY_OWNERS[before:]

    def test_snapshot_change_invalidates_health_even_after_two_natural_launches(self):
        with tempfile.TemporaryDirectory() as temporary:
            code, value, _, _ = self.run_control(Path(temporary), snapshot_changed=True)
        self.assertEqual(code, 1)
        self.assertEqual(value["status"], "failed")
        self.assertIs(value["outside_headless_control_passed"], False)
        self.assertIs(value["cleanup_proven"], True)


@unittest.skipUnless(sys.platform == "win32", "Windows owned-job ABI only; not an Edge or PSEC result")
class WindowsJobAbiTests(unittest.TestCase):
    def test_real_suspended_assignment_tracks_descendant_and_tears_down_only_its_owned_job(self):
        owner = control.OwnedJobProcess()
        command = [sys.executable, "-I", "-S", "-c",
                   "import subprocess,sys,time;subprocess.Popen([sys.executable,'-I','-S','-c','import time;time.sleep(20)']);time.sleep(20)"]
        try:
            owner.start(command, os.environ.copy(), Path.cwd())
            deadline = time.monotonic() + 5
            while owner.api.active(owner.job) < 2 and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertGreaterEqual(owner.api.active(owner.job), 2)
            self.assertEqual(ctypes.sizeof(control._ExtendedLimits), 144)
            self.assertEqual(ctypes.sizeof(control._Accounting), 48)
        finally:
            owner.close()
        self.assertTrue(owner.cleanup_proven)
        self.assertTrue(owner.forced_teardown)
        print("Outside Windows job ABI only: suspended assignment, owned descendants, exact-handle teardown verified")


if __name__ == "__main__":
    unittest.main()
