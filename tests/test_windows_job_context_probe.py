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
        self.root = Path(self.temp.name).resolve()
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

    def path_kernel(self, *, attributes=0x10, identifiers=None, opened=True):
        kernel = mock.Mock()
        opened_paths = {}
        def create(path, access, share, security, disposition, flags, template):
            self.assertEqual((access, share, security, disposition, flags, template),
                             (0x80, 7, None, 3, 0x02200000, None))
            handle = 100 + len(opened_paths)
            opened_paths[handle] = path
            return handle
        def info(handle, kind, target, count):
            if kind == 9:
                self.assertEqual(count, 8)
                target._obj.attributes = attributes
            else:
                self.assertEqual(kind, 18)
                self.assertEqual(count, 24)
                target._obj.volume = 10
                target._obj.file_id[0] = (identifiers or {}).get(opened_paths[handle], 1)
            return 1
        def name(handle, buffer, capacity, flags):
            self.assertEqual((capacity, flags), (32768, 8))
            buffer.value = r"\\?\C:\owned\profile"
            return len(buffer.value) if opened else 0
        kernel.CreateFileW.side_effect = create
        kernel.GetFileInformationByHandleEx.side_effect = info
        kernel.GetFinalPathNameByHandleW.side_effect = name
        kernel.CloseHandle.return_value = 1
        return kernel

    def path_identities(self, kernel):
        return probe.WindowsPathIdentities(kernel, lambda: 5, lambda code: self.permission_error())

    def test_windows_owned_alias_uses_held_file_id_without_any_normalized_resolve(self):
        alias = self.root / "OWNED~1"
        value = copy.deepcopy(self.config)
        index = next(i for i, arg in enumerate(value["command"]) if arg.startswith("--user-data-dir="))
        value["command"][index] = f"--user-data-dir={alias}"
        kernel = self.path_kernel()
        identities = self.path_identities(kernel)
        with mock.patch.object(probe, "use_windows_path_identities", return_value=True), \
                mock.patch.object(probe, "WindowsPathIdentities", return_value=identities), \
                mock.patch.object(Path, "resolve", side_effect=self.permission_error()):
            self.assertEqual(probe.validate_configuration(value, self.command_file, self.report), value["command"])
        self.assertEqual(kernel.CloseHandle.call_count, 4)
        self.assertEqual(identities.handles, [])
        self.assertEqual(ctypes.sizeof(probe.FileAttributeTagInfo), 8)
        self.assertEqual(ctypes.sizeof(probe.FileIdInfo), 24)

    def test_different_windows_owned_directory_identity_still_rejects_profile_override(self):
        other = self.root / "different"
        value = copy.deepcopy(self.config)
        index = next(i for i, arg in enumerate(value["command"]) if arg.startswith("--user-data-dir="))
        value["command"][index] = f"--user-data-dir={other}"
        kernel = self.path_kernel(identifiers={str(other): 2})
        identities = self.path_identities(kernel)
        with mock.patch.object(probe, "use_windows_path_identities", return_value=True), \
                mock.patch.object(probe, "WindowsPathIdentities", return_value=identities):
            with self.assertRaises(ValueError):
                probe.validate_configuration(value, self.command_file, self.report)
        self.assertEqual(kernel.CloseHandle.call_count, 4)
        self.assertEqual(identities.handles, [])

    def test_held_directory_identity_needs_no_opened_name_query_and_keeps_object_checks(self):
        kernel = self.path_kernel(opened=False)
        kernel.GetFinalPathNameByHandleW.side_effect = self.permission_error()
        identities = self.path_identities(kernel)
        with mock.patch.object(probe, "use_windows_path_identities", return_value=True), \
                mock.patch.object(probe, "WindowsPathIdentities", return_value=identities):
            self.assertEqual(probe.validate_configuration(self.config, self.command_file, self.report), self.config["command"])
        kernel.GetFinalPathNameByHandleW.assert_not_called()
        self.assertEqual(identities.handles, [])
        for attributes, identity_fail, expected in ((0x410, False, "validate_profile_attributes"),
                                                   (0, False, "validate_profile_attributes"),
                                                   (0x10, True, "validate_profile_identity")):
            kernel = self.path_kernel(attributes=attributes, opened=False)
            if identity_fail:
                original = kernel.GetFileInformationByHandleEx.side_effect
                kernel.GetFileInformationByHandleEx.side_effect = lambda handle, kind, target, count: 0 if kind == 18 else original(handle, kind, target, count)
            identities = self.path_identities(kernel)
            with self.subTest(stage=expected), mock.patch.object(probe, "use_windows_path_identities", return_value=True), \
                    mock.patch.object(probe, "WindowsPathIdentities", return_value=identities):
                with self.assertRaises((ValueError, PermissionError)) as observed:
                    probe.validate_configuration(self.config, self.command_file, self.report)
            facts = probe.failure_facts(observed.exception, "validate_profile_resolve")
            self.assertEqual(facts["stage"], expected)
            if identity_fail:
                self.assertEqual((facts["class"], facts["errno"], facts["winerror"]), ("PermissionError", 13, 5))
            kernel.GetFinalPathNameByHandleW.assert_not_called()
            self.assertEqual(kernel.CreateFileW.call_count, 1)
            self.assertEqual(kernel.CloseHandle.call_count, 1)
            self.assertEqual(identities.handles, [])

    def test_failed_directory_handle_close_is_reported_and_keeps_only_unclosed_handle(self):
        kernel = self.path_kernel()
        identities = self.path_identities(kernel)
        kernel.CloseHandle.side_effect = [0, 1]
        with self.assertRaises(PermissionError) as observed:
            with identities:
                identities.identity(self.root, "validate_profile")
                identities.identity(self.root, "validate_config_parent")
        self.assertEqual(probe.failure_facts(observed.exception, "validate_profile_resolve")["stage"], "validate_directory_close")
        self.assertEqual(identities.handles, [100])
        kernel.CloseHandle.side_effect = None
        with identities:
            pass
        self.assertEqual(identities.handles, [])
        self.assertEqual([call.args[0] for call in kernel.CloseHandle.call_args_list], [100, 101, 100])

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
                mock.patch.object(probe, "use_windows_path_identities", return_value=False), \
                mock.patch.object(probe.subprocess, "Popen") as launch, contextlib.redirect_stdout(output):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, 1)
        self.assert_failure_output(output.getvalue(), "validate_profile_resolve")
        launch.assert_not_called()

    def test_initial_report_publication_failure_is_not_an_edge_crash(self):
        self.command_file.write_text(json.dumps(self.config))
        output = io.StringIO()
        diagnostics = io.StringIO()
        with mock.patch.object(probe, "write_report", side_effect=self.permission_error()), \
                mock.patch.object(probe, "query_job_context", return_value={"status": "incomplete",
                    "error": "Win32ApiFailure"}), \
                mock.patch.object(probe.subprocess, "Popen") as launch, \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(diagnostics):
            code = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(code, 1)
        self.assert_failure_output(output.getvalue(), "publish_initial")
        self.assertEqual(json.loads(diagnostics.getvalue()), {"stage": "query_job", "errno": None,
                                                              "winerror": None, "class": "Win32ApiFailure"})
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
        self.assertEqual(actual["edge_identity"], probe.incomplete_edge_identity(source_unavailable=True))
        process.wait.assert_called_once_with()
        process.kill.assert_not_called(); process.terminate.assert_not_called()
        for private in (str(self.root), "--proxy-server", "ruleproxy-browser-fixture.invalid"):
            self.assertNotIn(private, self.report.read_text())

    def test_adjacent_source_capture_receives_only_actual_popen_and_original_image(self):
        identity = {"status": "observed", "scope": "borrowed_popen_edge_process_handle", "pid": 102,
                    "process_created": 134365000000000001, "image_sha256": "b" * 64,
                    "held_handle_verified": True, "error": None}
        process, helper = mock.Mock(), mock.Mock()
        helper.capture_held_edge_identity.return_value = identity
        helper.validate_identity.side_effect = lambda value: value
        spec = mock.Mock()
        with mock.patch.object(probe.importlib.util, "spec_from_file_location", return_value=spec) as lookup, \
                mock.patch.object(probe.importlib.util, "module_from_spec", return_value=helper):
            self.assertIs(probe.capture_edge_identity(process, self.edge), identity)
        self.assertEqual(lookup.call_args.args[1], Path(probe.__file__).with_name("ruleproxy-edge-crash-evidence.py"))
        spec.loader.exec_module.assert_called_once_with(helper)
        helper.capture_held_edge_identity.assert_called_once_with(process, self.edge)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        process.wait.assert_not_called()

    def test_identity_diagnostics_do_not_replace_actual_natural_edge_crash_or_weaken_command(self):
        self.command_file.write_text(json.dumps(self.config))
        process = mock.Mock()
        process.wait.return_value = 0xC0000005
        identity = probe.incomplete_edge_identity()
        identity["error"].update(stage="identity_image", error_type="PermissionError", errno=13, winerror=5)
        windows = SimpleNamespace(name="nt", getpid=os.getpid, getppid=os.getppid, replace=os.replace, fsync=os.fsync)
        with mock.patch.object(probe, "os", windows), mock.patch.object(probe, "query_job_context", return_value={}), \
                mock.patch.object(probe, "capture_edge_identity", return_value=identity) as capture, \
                mock.patch.object(probe.subprocess, "Popen", return_value=process) as launch:
            result = probe.main(["--command", str(self.command_file), "--report", str(self.report)])
        self.assertEqual(result & 0xffffffff, 0xC0000005)
        actual = json.loads(self.report.read_text())
        self.assertEqual(actual["edge_identity"], identity)
        self.assertEqual(actual["edge_exit_code"], 0xC0000005)
        capture.assert_called_once_with(process, self.config["command"][0])
        self.assertEqual(launch.call_args.args[0], self.config["command"])
        process.wait.assert_called_once_with()
        process.kill.assert_not_called()

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

    @unittest.skipUnless(os.name == "nt", "Real outside Windows held-file-id ABI only, not PSEC evidence")
    def test_actual_windows_directory_held_identity_is_outside_only(self):
        with probe.WindowsPathIdentities() as identities:
            first = identities.identity(self.root, "validate_profile")
            second = identities.identity(self.root / ".", "validate_config_parent")
            self.assertEqual(first, second)
            self.assertEqual(len(first[1]), 16)
            self.assertTrue(any(first[1]))
        self.assertEqual(identities.handles, [])
        print("Outside file-id ABI only: read_attributes/shared_open/nonreparse/held_identity/close verified")


if __name__ == "__main__":
    unittest.main()
