import ctypes
import os
import subprocess
import unittest
from unittest import mock

from ruleproxy import windows_app_process as app_process


class FakeAPI:
    def __init__(self, failure=None, *, elevated=False):
        self.failure = failure
        self.calls = []
        self.exited = False
        self.exit_status = 0
        self.environment = None
        self.elevated = elevated

    def record(self, action, *args):
        self.calls.append((action, *args))
        if self.failure == action:
            raise OSError("injected " + action)

    def is_elevated(self):
        self.record("elevation")
        return self.elevated

    def create_job(self):
        self.record("create_job")
        return 101

    def configure_job(self, job, flags):
        self.record("configure_job", job, flags)

    def create_process(self, command, environment, cwd, info):
        # Also model a failed API that left partially populated output handles.
        info.hProcess, info.hThread, info.dwProcessId = 201, 202, 987
        self.environment = environment
        self.record("create_process", list(command), cwd)

    def assign_job(self, job, process):
        self.record("assign_job", job, process)

    def resume_thread(self, thread):
        self.record("resume_thread", thread)

    def terminate_process(self, process):
        self.record("terminate_process", process)
        self.exited = True
        self.exit_status = 1

    def terminate_job(self, job):
        self.record("terminate_job", job)
        self.exited = True
        self.exit_status = 1

    def wait_process(self, process, milliseconds):
        self.record("wait_process", process, milliseconds)
        return app_process._WAIT_OBJECT_0 if self.exited else app_process._WAIT_TIMEOUT

    def exit_code(self, process):
        self.record("exit_code", process)
        return self.exit_status

    def duplicate_handle(self, handle):
        self.record("duplicate_handle", handle)
        return 301

    def close_handle(self, handle):
        self.record("close_handle", handle)


class WindowsAppProcessTests(unittest.TestCase):
    command = [r"C:\Program Files\Example\app.exe", "argument with spaces"]

    def start(self, api=None, env=None, **options):
        api = api or FakeAPI()
        with mock.patch.object(app_process, "_get_api", return_value=api):
            process = app_process.launch(self.command, env or {"PATH": r"C:\Windows"}, r"C:\Work", **options)
        self.addCleanup(self.dispose, process)
        return api, process

    @staticmethod
    def dispose(process):
        if process.returncode is None:
            process.kill()
            process.wait(1)

    def test_creation_assigns_before_resuming_and_closes_only_thread(self):
        api, process = self.start()
        self.assertEqual(process.pid, 987)
        self.assertEqual(process.args, self.command)
        self.assertEqual(api.calls, [
            ("elevation",), ("create_job",),
            ("configure_job", 101, app_process._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE),
            ("create_process", self.command, r"C:\Work"),
            ("assign_job", 101, 201), ("resume_thread", 202), ("close_handle", 202),
        ])

    def test_explicit_environment_filters_all_proxy_casings_without_modifying_input(self):
        env = {"HTTPS_PROXY": "x", "http_proxy": "x", "Ftp_Proxy": "x",
               "ALL_PROXY": "x", "no_proxy": "*", "SOCKS_PROXY": "x",
               "CUSTOM_PROXY": "x", "NODE_USE_ENV_PROXY": "1",
               "PATH": r"C:\Windows", "CUSTOM": "你好"}
        original = dict(env)
        api, _ = self.start(env=env)
        self.assertEqual(env, original)
        self.assertEqual(api.environment, "CUSTOM=你好\0PATH=C:\\Windows\0\0")

    def test_explicit_native_proxy_rebuilds_only_the_owned_endpoint_for_both_tokens(self):
        env = {"http_proxy": "http://untrusted.invalid:1", "HTTP_PROXY": "http://other.invalid:2",
               "Https_Proxy": "http://untrusted.invalid:3", "ALL_PROXY": "socks5://untrusted.invalid:4",
               "NO_PROXY": "*", "no_proxy": "*", "SOCKS_PROXY": "untrusted",
               "CUSTOM_PROXY": "untrusted", "Node_Use_Env_Proxy": "0", "PATH": r"C:\Windows"}
        original = dict(env)
        expected = {"HTTP_PROXY": "http://127.0.0.1:18809", "HTTPS_PROXY": "http://127.0.0.1:18809",
                    "ALL_PROXY": "http://127.0.0.1:18809", "NO_PROXY": "localhost,127.0.0.1,::1",
                    "NODE_USE_ENV_PROXY": "1", "PATH": r"C:\Windows"}
        for elevated in (False, True):
            with self.subTest(elevated=elevated):
                api, _ = self.start(FakeAPI(elevated=elevated), env, native_proxy_port=18809)
                entries = api.environment.rstrip("\0").split("\0")
                self.assertEqual(dict(entry.split("=", 1) for entry in entries), expected)
                self.assertEqual(len(entries), len(expected))
                self.assertEqual(env, original)

    def test_native_proxy_port_is_validated_before_any_native_process_operations(self):
        with mock.patch.object(app_process, "_get_api") as api:
            for port in (True, False, "18809", "http://127.0.0.1:18809", 18809.0, 0, 1024, 65536):
                with self.subTest(port=port), self.assertRaises(ValueError):
                    app_process.launch(self.command, {}, native_proxy_port=port)
            api.assert_not_called()

    def test_elevated_context_still_assigns_job_before_resuming(self):
        api, process = self.start(FakeAPI(elevated=True))
        self.assertEqual(process.pid, 987)
        actions = [call[0] for call in api.calls]
        self.assertEqual(actions[0], 'elevation')
        self.assertLess(actions.index('assign_job'), actions.index('resume_thread'))

    def test_token_query_failure_creates_nothing(self):
        api = FakeAPI("elevation")
        with mock.patch.object(app_process, "_get_api", return_value=api):
            with self.assertRaises(OSError):
                app_process.launch(self.command, {})
        self.assertEqual(api.calls, [("elevation",)])

    def test_configuration_failure_closes_job_without_creating_application(self):
        api = FakeAPI("configure_job")
        with mock.patch.object(app_process, "_get_api", return_value=api):
            with self.assertRaisesRegex(OSError, "configure_job"):
                app_process.launch(self.command, {})
        self.assertEqual(api.calls[-1], ("close_handle", 101))
        self.assertNotIn("create_process", [call[0] for call in api.calls])

    def test_partial_creation_and_assignment_failures_abort_suspended_application(self):
        for failure in ("create_process", "assign_job"):
            with self.subTest(failure=failure):
                api = FakeAPI(failure)
                with mock.patch.object(app_process, "_get_api", return_value=api):
                    with self.assertRaisesRegex(OSError, failure):
                        app_process.launch(self.command, {})
                self.assertNotIn("resume_thread", [call[0] for call in api.calls])
                self.assertEqual(api.calls[-5:], [
                    ("terminate_process", 201), ("wait_process", 201, 5000),
                    ("close_handle", 202), ("close_handle", 101), ("close_handle", 201),
                ])

    def test_resume_failure_terminates_whole_assigned_job(self):
        api = FakeAPI("resume_thread")
        with mock.patch.object(app_process, "_get_api", return_value=api):
            with self.assertRaisesRegex(OSError, "resume_thread"):
                app_process.launch(self.command, {})
        self.assertEqual(api.calls[-5:], [
            ("terminate_job", 101), ("wait_process", 201, 5000),
            ("close_handle", 202), ("close_handle", 101), ("close_handle", 201),
        ])

    def test_termination_cleanup_failure_still_attempts_every_handle(self):
        api = FakeAPI("resume_thread")
        api.terminate_job = mock.Mock(side_effect=OSError("termination failed"))
        with mock.patch.object(app_process, "_get_api", return_value=api):
            with self.assertRaisesRegex(RuntimeError, "cleanup could not be confirmed"):
                app_process.launch(self.command, {})
        self.assertEqual(api.calls[-3:], [
            ("close_handle", 202), ("close_handle", 101), ("close_handle", 201),
        ])

    def test_kill_targets_job_handle_and_never_reused_pid(self):
        api, process = self.start()
        process.kill()
        self.assertEqual(api.calls[-1], ("terminate_job", 101))
        self.assertEqual(process.wait(1), 1)
        self.assertEqual(process.poll(), 1)
        self.assertNotIn("terminate_process", [call[0] for call in api.calls])
        self.assertIn(("close_handle", 101), api.calls)
        self.assertIn(("close_handle", 201), api.calls)
        self.assertIn(("close_handle", 301), api.calls)

    def test_wait_timeout_preserves_process_and_job_and_closes_duplicate(self):
        api, process = self.start()
        self.assertIsNone(process.poll())
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            process.wait(0.001)
        self.assertEqual(raised.exception.cmd, self.command)
        self.assertEqual(api.calls[-3:], [
            ("duplicate_handle", 201), ("wait_process", 301, 1), ("close_handle", 301),
        ])
        self.assertNotIn(("close_handle", 101), api.calls)
        self.assertNotIn(("close_handle", 201), api.calls)

    def test_observing_natural_root_exit_closes_job_and_caches_exit_code(self):
        api, process = self.start()
        api.exited, api.exit_status = True, 7
        self.assertEqual(process.poll(), 7)
        self.assertEqual(api.calls[-3:], [
            ("exit_code", 201), ("close_handle", 101), ("close_handle", 201),
        ])
        previous = list(api.calls)
        self.assertEqual(process.wait(), 7)
        process.terminate()
        self.assertEqual(api.calls, previous)

    def test_wait_retains_its_duplicate_when_poll_closes_original(self):
        api, process = self.start()
        api.exited = True
        original_wait = api.wait_process

        def concurrent_poll(handle, milliseconds):
            if handle == 301:
                self.assertEqual(process.poll(), 0)
                self.assertNotIn(("close_handle", 301), api.calls)
            return original_wait(handle, milliseconds)

        api.wait_process = concurrent_poll
        self.assertEqual(process.wait(1), 0)
        self.assertEqual(api.calls[-1], ("close_handle", 301))

    def test_invalid_input_is_rejected_before_native_api_initialization(self):
        with mock.patch.object(app_process, "_get_api") as api:
            for command, env, cwd in (([], {}, None), (["x\0y"], {}, None),
                                      (["x"], {"A": "\0"}, None), (["x"], {}, "\0"),
                                      (["x"], {"Path": "x", "PATH": "y"}, None)):
                with self.subTest(command=command, env=env, cwd=cwd):
                    with self.assertRaises(ValueError):
                        app_process.launch(command, env, cwd)
            api.assert_not_called()

    @unittest.skipIf(os.name == "nt", "non-Windows import guard")
    def test_linux_import_does_not_initialize_windows_libraries(self):
        with self.assertRaisesRegex(OSError, "only available on Windows"):
            app_process.launch(["example.exe"], {})


class NativeAPIBindingTests(unittest.TestCase):
    def api(self):
        with mock.patch.object(ctypes, "WinDLL", create=True) as loader:
            kernel, advapi = mock.Mock(), mock.Mock()
            loader.side_effect = [kernel, advapi]
            api = app_process._KernelAPI()
        return api, kernel, advapi

    def test_create_process_uses_suspended_unicode_flags_without_handle_inheritance(self):
        api, kernel, _ = self.api()
        kernel.CreateProcessW.return_value = 1
        info = app_process._ProcessInfo()
        api.create_process([r"C:\Program Files\app.exe", "has spaces"], "A=b\0\0", None, info)
        args = kernel.CreateProcessW.call_args.args
        self.assertEqual(args[0], r"C:\Program Files\app.exe")
        self.assertEqual(args[1].value, '"C:\\Program Files\\app.exe" "has spaces"')
        self.assertFalse(args[4])
        self.assertEqual(args[5], app_process._CREATE_SUSPENDED | app_process._CREATE_UNICODE_ENVIRONMENT)
        self.assertEqual(args[6][:5], "A=b\0\0")
        startup = ctypes.cast(args[8], ctypes.POINTER(app_process._StartupInfo)).contents
        self.assertEqual(startup.cb, ctypes.sizeof(app_process._StartupInfo))
        self.assertIsNone(startup.lpDesktop)

    def test_job_has_kill_on_close_and_no_breakaway_flags(self):
        api, kernel, _ = self.api()
        kernel.SetInformationJobObject.return_value = 1
        api.configure_job(101, app_process._JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        args = kernel.SetInformationJobObject.call_args.args
        self.assertEqual(args[:2], (101, 9))
        limits = ctypes.cast(args[2], ctypes.POINTER(app_process._JobExtendedLimitInfo)).contents
        self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2000)

    def test_token_elevation_is_checked_and_token_is_always_closed(self):
        api, kernel, advapi = self.api()
        kernel.CloseHandle.return_value = 1

        def token_open(_process, _access, token):
            ctypes.cast(token, ctypes.POINTER(app_process._HANDLE)).contents.value = 555
            return 1

        def information(_token, info_type, result, length, returned):
            self.assertEqual(info_type, 20)
            ctypes.cast(result, ctypes.POINTER(app_process._DWORD)).contents.value = 1
            ctypes.cast(returned, ctypes.POINTER(app_process._DWORD)).contents.value = length
            return 1

        advapi.OpenProcessToken.side_effect = token_open
        advapi.GetTokenInformation.side_effect = information
        with self.assertRaises(PermissionError):
            api.assert_unelevated()
        kernel.CloseHandle.assert_called_once_with(555)


if __name__ == "__main__":
    unittest.main()
