"""Validate the read-only job ABI/command boundary without simulating PSEC."""
import copy
import ctypes
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("ruleproxy_job_context_test", ROOT / ".github/windows_job_context_probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class WindowsJobContextTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.edge = self.root / "msedge.exe"
        self.edge.write_bytes(b"Not executed by mocked unit tests")
        self.command_file, self.report = self.root / "edge-command.json", self.root / "job-context.json"
        self.config = {"schema_version": 1, "nonce": "a" * 64, "proxy_port": 19001, "profile": str(self.root),
            "command": [str(self.edge), "--headless=new", "--dump-dom", "--disable-gpu",
                        f"--user-data-dir={self.root}", "--proxy-server=http://127.0.0.1:19001",
                        "--proxy-bypass-list=<-loopback>", "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "http://ruleproxy-browser-fixture.invalid/phase/1"]}

    def kernel(self, mask=0x2F9, in_job=True, membership_success=True, query_success=True, length=4):
        kernel = mock.Mock()
        kernel.GetCurrentProcess.return_value = -1
        def membership(handle, job, result):
            self.assertEqual(handle, -1)
            self.assertIsNone(job)
            result._obj.value = int(in_job)
            return membership_success
        def query(job, information_class, result, size, written):
            self.assertIsNone(job, "query must observe this caller's immediate job")
            self.assertEqual(information_class, 4)
            self.assertEqual(size, 4)
            result._obj.UIRestrictionsClass = mask
            written._obj.value = length
            return query_success
        kernel.IsProcessInJob.side_effect, kernel.QueryInformationJobObject.side_effect = membership, query
        return kernel

    def test_current_process_pseudohandle_null_job_and_exact_dword_query_preserve_mask(self):
        self.assertEqual(ctypes.sizeof(probe.BasicUIRestrictions), 4)
        kernel = self.kernel()
        result = probe.query_job_context(kernel, lambda: 5)
        self.assertEqual(result["status"], "observed")
        self.assertEqual(result["ui_restrictions"], 0x2F9)
        self.assertTrue(result["is_process_in_job"])
        self.assertEqual(result["query_return_length"], 4)
        self.assertIsNone(result["query_ui_restrictions_error"])

    def test_failed_query_never_fabricates_zero_mask(self):
        result = probe.query_job_context(self.kernel(query_success=False), lambda: 5)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["query_ui_restrictions_error"], 5)
        self.assertIsNone(result["ui_restrictions"])
        result = probe.query_job_context(self.kernel(membership_success=False), lambda: 6)
        self.assertEqual(result["is_process_in_job_error"], 6)
        self.assertIsNone(result["ui_restrictions"])

    def test_successful_zero_is_distinct_from_no_job_inconsistent_or_short_result(self):
        observed = probe.query_job_context(self.kernel(mask=0), lambda: 0)
        self.assertEqual((observed["status"], observed["ui_restrictions"]), ("observed", 0))
        for kernel in (self.kernel(in_job=False), self.kernel(length=0)):
            result = probe.query_job_context(kernel, lambda: 0)
            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(result["ui_restrictions"])

    def test_api_binding_exception_is_bounded_and_never_contains_a_private_message(self):
        kernel = self.kernel()
        kernel.IsProcessInJob.side_effect = OSError("PRIVATE_ENV_AND_PATH")
        result = probe.query_job_context(kernel, lambda: 5)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["error"], "OSError")
        self.assertNotIn("PRIVATE_ENV", json.dumps(result))

    def test_only_prepared_edge_command_with_exact_profile_proxy_and_fixture_is_accepted(self):
        self.assertEqual(probe.validate_configuration(self.config, self.command_file, self.report), self.config["command"])
        for argument in ("--no-sandbox", "--disable-gpu-sandbox", "--allow-no-sandbox-job",
                         "--renderer-cmd-prefix=cmd.exe", "--remote-debugging-port=9222", "https://external.example"):
            value = copy.deepcopy(self.config); value["command"].append(argument)
            with self.subTest(argument=argument), self.assertRaises(ValueError):
                probe.validate_configuration(value, self.command_file, self.report)
        for argument in ("--proxy-server=http://127.0.0.1:12345", "--user-data-dir=C:\\Outside",
                         "--proxy-bypass-list=*"):
            value = copy.deepcopy(self.config); value["command"].append(argument)
            with self.assertRaises(ValueError): probe.validate_configuration(value, self.command_file, self.report)
        value = copy.deepcopy(self.config); value["command"][0] = str(self.root / "cmd.exe")
        with self.assertRaises(ValueError): probe.validate_configuration(value, self.command_file, self.report)

    def test_schema_nonce_boolean_port_size_and_report_boundary_reject_before_process_launch(self):
        for key, bad in (("nonce", "stale"), ("proxy_port", True), ("schema_version", True), ("profile", ".")):
            value = copy.deepcopy(self.config); value[key] = bad
            with self.assertRaises(ValueError): probe.validate_configuration(value, self.command_file, self.report)
        value = copy.deepcopy(self.config); value["env"] = {"SECRET": "not accepted"}
        with self.assertRaises(ValueError): probe.validate_configuration(value, self.command_file, self.report)
        with self.assertRaises(ValueError): probe.validate_configuration(self.config, self.command_file, self.command_file)
        with tempfile.TemporaryDirectory() as elsewhere:
            with self.assertRaises(ValueError):
                probe.validate_configuration(self.config, self.command_file, Path(elsewhere) / "report.json")
        self.command_file.write_text('{"nonce":"a","nonce":"b"}')
        with self.assertRaises(ValueError): probe.read_configuration(self.command_file)
        self.command_file.write_bytes(b"x" * (probe.MAX_CONFIG_BYTES + 1))
        with self.assertRaises(ValueError): probe.read_configuration(self.command_file)

    @unittest.skipUnless(os.name == "posix", "POSIX directory-alias simulation, not Windows execution proof")
    def test_equivalent_absolute_profile_alias_is_accepted_and_other_directory_still_rejected(self):
        alias = self.root / "profile-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        value = copy.deepcopy(self.config)
        profile_arg = next(index for index, arg in enumerate(value["command"]) if arg.startswith("--user-data-dir="))
        value["command"][profile_arg] = f"--user-data-dir={alias}"
        self.assertEqual(alias.resolve(strict=True), self.root.resolve(strict=True))
        self.assertEqual(probe.validate_configuration(value, self.command_file, self.report), value["command"])
        elsewhere = self.root / "other-profile"
        elsewhere.mkdir()
        for target in (str(elsewhere), str(self.root / "missing-profile"), "."):
            value["command"][profile_arg] = f"--user-data-dir={target}"
            with self.subTest(target=Path(target).name), self.assertRaises(ValueError):
                probe.validate_configuration(value, self.command_file, self.report)

    def test_actual_windows_prepared_fixture_command_is_accepted_without_adding_flags_or_grants(self):
        from ruleproxy import launcher
        self.edge.chmod(0o700)  # POSIX mock executable; never actually launched.
        profile_root = self.root / "profiles"
        app = {"id": "browser", "label": "Real Edge fixture", "path": str(self.edge), "adapter": "chromium",
               "args": ["--headless=new", "--dump-dom", "--disable-gpu", "--no-default-browser-check",
                        "http://ruleproxy-browser-fixture.invalid/phase/1"]}
        with mock.patch.object(launcher.sys, "platform", "win32"):
            command, _, _ = launcher.prepare_app(app, 19001, profile_root)
        profile = profile_root / "browser"
        value = dict(self.config, command=command, profile=str(profile.resolve(strict=True)))
        accepted = probe.validate_configuration(value, profile / "command.json", profile / "report.json")
        self.assertEqual(accepted, command)
        self.assertNotIn("--no-sandbox", accepted)
        self.assertNotIn("--disable-setuid-sandbox", accepted)

    def permission_error(self):
        error = PermissionError(13, "PRIVATE_COMMAND_TOKEN", "PRIVATE_PATH")
        error.winerror = 5
        return error

    def assert_failure_output(self, raw, stage):
        value = json.loads(raw)
        self.assertEqual(value, {"stage": stage, "errno": 13, "winerror": 5, "class": "PermissionError"})
        for secret in (str(self.root), "PRIVATE_COMMAND_TOKEN", "PRIVATE_PATH", self.config["nonce"], "--proxy-server"):
            self.assertNotIn(secret, raw)

    def test_read_config_failure_publishes_fixed_facts_before_any_process_is_started(self):
        output = io.StringIO()
        with mock.patch.object(probe, "read_configuration", side_effect=self.permission_error()), \
                mock.patch.object(probe.subprocess, "Popen") as launch, contextlib.redirect_stdout(output):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, 1)
        self.assert_failure_output(output.getvalue(), "read_config")
        self.assertFalse(self.report.exists())
        launch.assert_not_called()

    def test_profile_resolve_failure_retains_winerror_and_specific_stage_without_wider_access(self):
        self.command_file.write_text(json.dumps(self.config))
        original = Path.resolve
        def resolve(path, *args, **kwargs):
            if path == self.root:
                raise self.permission_error()
            return original(path, *args, **kwargs)
        output = io.StringIO()
        with mock.patch.object(Path, "resolve", autospec=True, side_effect=resolve), \
                mock.patch.object(probe.subprocess, "Popen") as launch, contextlib.redirect_stdout(output):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, 1)
        self.assert_failure_output(output.getvalue(), "validate_profile_resolve")
        launch.assert_not_called()

    def test_initial_report_publication_failure_is_not_an_edge_crash(self):
        self.command_file.write_text(json.dumps(self.config))
        output = io.StringIO()
        with mock.patch.object(probe, "write_report", side_effect=self.permission_error()), \
                mock.patch.object(probe.subprocess, "Popen") as launch, contextlib.redirect_stdout(output):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, 1)
        self.assert_failure_output(output.getvalue(), "publish_initial")
        launch.assert_not_called()

    def test_wrapper_publishes_context_before_running_edge_naturally_and_preserves_dword_crash(self):
        self.command_file.write_text(json.dumps(self.config))
        process = mock.Mock()
        process.wait.return_value = 0xC0000005
        windows = SimpleNamespace(name="nt", getpid=os.getpid, getppid=os.getppid, replace=os.replace, fsync=os.fsync)
        context = probe.query_job_context(self.kernel(), lambda: 0)
        def create(command, **kwargs):
            before = json.loads(self.report.read_text())
            self.assertEqual(before["nonce"], self.config["nonce"])
            self.assertEqual(before["job_context"], context)
            self.assertFalse(before["edge_launched"])
            self.assertEqual(command, self.config["command"])
            self.assertEqual(kwargs, {"shell": False, "stdin": probe.subprocess.DEVNULL, "close_fds": True})
            return process
        with mock.patch.object(probe, "os", windows), mock.patch.object(probe, "query_job_context", return_value=context), \
                mock.patch.object(probe.subprocess, "Popen", side_effect=create):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, -1073741819)
        self.assertEqual(code & 0xffffffff, 0xC0000005)
        actual = json.loads(self.report.read_text())
        self.assertEqual(actual["edge_exit_code"], 0xC0000005)
        self.assertEqual(actual["edge_exit_code_hex"], "0xC0000005")
        self.assertEqual(actual["scope"], probe.SCOPE)
        self.assertFalse(actual["acceptance_passed"])
        process.wait.assert_called_once_with()
        process.kill.assert_not_called(); process.terminate.assert_not_called()
        for private in (str(self.root), "--proxy-server", "ruleproxy-browser-fixture.invalid"):
            self.assertNotIn(private, self.report.read_text())

    def test_high_windows_codes_use_equivalent_signed_systemexit(self):
        for raw in (0, 1, 0x7FFFFFFF, 0x80000000, 0xC0000005, 0xFFFFFFFF, -1073741819):
            self.assertEqual(probe.signed_exit_code(raw) & 0xffffffff, raw & 0xffffffff)
        for raw in (True, 0x100000000, -0x80000001):
            with self.assertRaises(ValueError): probe.signed_exit_code(raw)

    @unittest.skipUnless(os.name == "nt", "Real outside Windows job ABI only, not PSEC evidence")
    def test_actual_windows_current_job_query_is_outside_only(self):
        result = probe.query_job_context()
        self.assertNotIn("error", result)
        self.assertIs(type(result["is_process_in_job"]), bool)
        if result["status"] == "observed":
            self.assertIs(type(result["ui_restrictions"]), int)
            self.assertEqual(result["query_return_length"], 4)
        else:
            self.assertIsNone(result["ui_restrictions"])
            self.assertIs(type(result["query_ui_restrictions_error"]), int)
        print("Outside current-job ABI observation only: " + json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    unittest.main()
