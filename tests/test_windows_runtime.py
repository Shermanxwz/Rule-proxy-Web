import json
import ctypes
import stat
import struct
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import windows_runtime


def supported_probe_json():
    return json.dumps(
        {
            "tier": "base-container",
            "needsDaclAugmentation": False,
            "warnings": [],
            "probes": {"baseContainerApiPresent": True, "baseContainerSupportsIdentitylessLoopbackProxy": True},
            "error": None,
        }
    )


class WindowsRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.runtime = self.root / "wxc-exec.exe"
        self.runtime.write_text("", encoding="utf-8")
        self.runtime.chmod(self.runtime.stat().st_mode | stat.S_IXUSR)
        self.profile = self.root / "profiles" / "saved-app-1"

    def test_build_policy_denies_direct_egress_and_allows_only_the_kernel_proxy(self):
        policy = windows_runtime.build_policy(
            [r"C:\Program Files\Browser\browser.exe", "--proxy-server=http://127.0.0.1:19001", "https://example.test"],
            {"HTTP_PROXY": "http://127.0.0.1:19001", "CUSTOM": "ok"},
            self.profile,
            19001,
        )
        self.assertEqual(policy["version"], "1.0.0")
        self.assertEqual(policy["containment"], "processcontainer")
        self.assertEqual(policy["runtimeConfig"], {"networkProxy": "http://127.0.0.1:19001"})
        self.assertEqual(policy["network"]["egress"], {"default": "deny"})
        self.assertEqual(
            policy["network"]["ingress"],
            {"default": "allow", "hostLoopback": "allow"},
        )
        self.assertIn(str(self.profile.resolve()), policy["filesystem"]["readwritePaths"])
        readonly = policy["filesystem"]["readonlyPaths"]
        self.assertIn(r"C:\Program Files\Browser", readonly)
        self.assertTrue(any(path.endswith("ruleproxy") for path in readonly))
        self.assertEqual(policy["process"]["cwd"], str(self.profile.resolve()))
        self.assertEqual(policy["ui"], {"disable": False})
        self.assertEqual(
            policy["processContainer"]["ui"], {"isolation": "container"}
        )
        self.assertIn("-I", policy["process"]["commandLine"])
        self.assertIn("-S", policy["process"]["commandLine"])
        self.assertIn("windows_guest.py", policy["process"]["commandLine"])
        self.assertNotIn("--new-window", policy["process"]["commandLine"])
        env = policy["process"]["env"]
        self.assertIn("HTTP_PROXY=http://127.0.0.1:19001", env)
        self.assertIn("HTTPS_PROXY=http://127.0.0.1:19001", env)
        self.assertIn("NO_PROXY=", env)
        self.assertIn("CUSTOM=ok", env)
        self.assertIn(f"TEMP={self.profile.resolve() / 'temp'}", env)
        self.assertIn(f"TMP={self.profile.resolve() / 'temp'}", env)
        self.assertIn(f"LOCALAPPDATA={self.profile.resolve() / 'localappdata'}", env)
        self.assertIn(f"APPDATA={self.profile.resolve() / 'appdata'}", env)
        self.assertIn(f"USERPROFILE={self.profile.resolve() / 'home'}", env)
        self.assertTrue((self.profile / "temp").is_dir())
        self.assertTrue((self.profile / "localappdata").is_dir())
        self.assertTrue(policy["process"]["inheritDefaultEnv"])

    def test_profile_environment_overrides_windows_vars_case_insensitively(self):
        policy = windows_runtime.build_policy(
            [r"C:\Apps\browser.exe"],
            {
                "temp": r"C:\Users\User\AppData\Local\Temp",
                "LOCALAPPDATA": r"C:\Users\User\AppData\Local",
                "SystemRoot": r"C:\Windows",
                "PATH": r"C:\Windows\System32",
            },
            self.profile,
            10809,
        )
        entries = policy["process"]["env"]
        self.assertEqual(sum(e.split("=", 1)[0].upper() == "TEMP" for e in entries), 1)
        self.assertIn(f"TEMP={self.profile.resolve() / 'temp'}", entries)
        self.assertIn(f"LOCALAPPDATA={self.profile.resolve() / 'localappdata'}", entries)
        self.assertIn(r"SYSTEMROOT=C:\Windows", entries)
        self.assertIn(r"PATH=C:\Windows\System32", entries)

    def test_windows_environment_names_allow_standard_parentheses_and_unicode(self):
        environment = windows_runtime._validate_env({"CommonProgramFiles(x86)": r"C:\Program Files (x86)\Common Files", "目录": "值"}, 10809)
        self.assertIn("CommonProgramFiles(x86)", environment)
        self.assertEqual(environment["目录"], "值")
        for key in ("", "BAD=KEY", "BAD\0KEY"):
            with self.assertRaises(ValueError): windows_runtime._validate_env({key:"x"}, 10809)

    def test_volume_root_metadata_keeps_explicit_application_grants(self):
        policy = windows_runtime.build_policy([r"E:\Apps\Browser\browser.exe"], {}, self.profile, 10809)
        paths = policy["filesystem"]["readonlyPaths"]
        self.assertIn("E:\\", paths)
        self.assertIn(r"E:\Apps\Browser", paths)
        self.assertNotIn(r"E:\Apps", paths)
        self.assertNotIn(r"C:\Users", paths)

    def test_build_policy_rejects_bad_command_profile_or_port(self):
        cases = [
            ([], {}, self.profile, 10809),
            (["browser", "bad\0arg"], {}, self.profile, 10809),
            (["browser"], {"BAD=KEY": "x"}, self.profile, 10809),
            (["browser"], {}, self.root / "profiles" / "invalid app id", 10809),
            (["browser"], {}, self.profile, 0),
        ]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(ValueError):
                windows_runtime.build_policy(*args)

    def test_os_gate_rejects_linux_windows_10_and_old_windows_11(self):
        cases = [("linux", (10, 26100)), ("win32", (10, 19045)), ("win32", (10, 22631))]
        for platform_name, version in cases:
            with self.subTest(platform=platform_name, version=version):
                with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
                    windows_runtime._check_windows_version(platform_name, version)
        windows_runtime._check_windows_version("win32", (10, 26100))

    def test_probe_uses_exact_cli_and_requires_supported_base_container(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=supported_probe_json(), stderr=""
        )
        with mock.patch.object(windows_runtime.subprocess, "run", return_value=completed) as run:
            result = windows_runtime._probe_request(
                self.runtime,
                windows_runtime.build_policy(["browser.exe"], {}, self.profile, 10809),
                platform_name="win32",
                version=(10, 26100),
            )
        self.assertEqual(result["tier"], "base-container")
        args = run.call_args.args[0]
        self.assertEqual(args[:3], [str(self.runtime), "--probe", "--config"])
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], windows_runtime.PROBE_TIMEOUT_SECONDS)
        # MXC writes UTF-8; the locale code page (GBK on Chinese Windows) must not be used to read it.
        self.assertEqual((run.call_args.kwargs["encoding"], run.call_args.kwargs["errors"]), ("utf-8", "replace"))

    def test_probe_reads_utf8_output_whatever_the_locale(self):
        # A stand-in runtime that fails with UTF-8 text no single-byte or GBK decoding reads back intact.
        script = self.root / "fake_mxc.py"
        script.write_text(
            "import sys\n"
            "sys.stderr.buffer.write('无法创建容器 — 0x8007 “拒绝”'.encode('utf-8'))\n"
            "sys.exit(3)\n",
            encoding="utf-8",
        )

        def runner(args, **options):
            return subprocess.run([sys.executable, str(script), *args[1:]], **options)

        with self.assertRaises(windows_runtime.UnsupportedRuntimeError) as failure:
            windows_runtime._probe_request(
                self.runtime,
                windows_runtime.build_policy(["browser.exe"], {}, self.profile, 10809),
                runner=runner,
                platform_name="win32",
                version=(10, 26100),
            )
        self.assertIn("status 3", str(failure.exception))
        self.assertIn("无法创建容器 — 0x8007 “拒绝”", str(failure.exception))

    def probe_with(self, completed):
        with mock.patch.object(windows_runtime.subprocess, "run", return_value=completed):
            with self.assertRaises(windows_runtime.UnsupportedRuntimeError) as failure:
                windows_runtime._probe_request(
                    self.runtime,
                    windows_runtime.build_policy(["browser.exe"], {}, self.profile, 10809),
                    platform_name="win32",
                    version=(10, 26100),
                )
        return str(failure.exception)

    def test_mxc_crashing_on_a_chinese_top_folder_gets_a_clear_way_out(self):
        # What MXC 1.0.0 printed on a user's machine with the package in C:\应用.
        panic = (
            "thread 'main' (3244) panicked at mxc-sdk\\src\\core\\plm\\trust.rs:396:39:\n"
            "byte index 4 is not a char boundary; it is inside '应' (bytes 3..6) of "
            "`C:\\应用\\RuleProxy-Web\\bin\\windows-amd64\\plm.exe`\n"
        )
        message = self.probe_with(subprocess.CompletedProcess(args=[], returncode=101, stdout="", stderr=panic))
        self.assertIn("顶层文件夹名", message)
        self.assertIn("C:\\RuleProxy-Web", message)
        self.assertIn("byte index 4", message, "the original message is kept for reference")

    def test_a_missing_base_container_api_names_the_windows_version_needed(self):
        weak = json.dumps({"tier": "appcontainer-dacl", "error": None, "needsDaclAugmentation": True,
                           "probes": {"baseContainerApiPresent": False}, "warnings": []})
        message = self.probe_with(subprocess.CompletedProcess(args=[], returncode=0, stdout=weak, stderr=""))
        self.assertIn("BaseContainer 接口", message)
        self.assertIn("26100.9278", message)

    def test_unused_runtime_files_are_retired_and_the_rest_kept(self):
        runtime = self.root / "bin" / "windows-amd64"
        runtime.mkdir(parents=True)
        for name in ("plm.exe", "wxc-exec.exe", "mxc_ffi.dll"):
            (runtime / name).write_bytes(b"x")
        windows_runtime.retire_unused_runtime_files(runtime)
        self.assertEqual(sorted(path.name for path in runtime.iterdir()), ["mxc_ffi.dll", "wxc-exec.exe"])
        windows_runtime.retire_unused_runtime_files(runtime)  # nothing left to remove is fine

    def test_a_failed_probe_without_output_is_still_a_clear_refusal(self):
        # What a crashed output reader leaves behind: no text at all.
        completed = subprocess.CompletedProcess(args=[], returncode=5, stdout=None, stderr=None)
        with mock.patch.object(windows_runtime.subprocess, "run", return_value=completed):
            with self.assertRaises(windows_runtime.UnsupportedRuntimeError) as failure:
                windows_runtime._probe_request(
                    self.runtime,
                    windows_runtime.build_policy(["browser.exe"], {}, self.profile, 10809),
                    platform_name="win32",
                    version=(10, 26100),
                )
        self.assertEqual(str(failure.exception), "MXC support probe exited with status 5")

    def test_probe_rejects_bad_json_error_weak_tier_and_missing_base_api_fact(self):
        output_cases = [
            ("not json", 0),
            (json.dumps({"tier": "base-container", "error": "bad", "probes": {}}), 0),
            (json.dumps({"tier": "appcontainer", "error": None, "needsDaclAugmentation": False, "probes": {"baseContainerApiPresent": True}}), 0),
            (json.dumps({"tier": "base-container", "error": None, "needsDaclAugmentation": False, "probes": {}}), 0),
            (json.dumps({"tier": "base-container", "error": None, "needsDaclAugmentation": True, "probes": {"baseContainerApiPresent": True}}), 0),
            (supported_probe_json(), 1),
        ]
        for stdout, returncode in output_cases:
            completed = subprocess.CompletedProcess(
                args=[], returncode=returncode, stdout=stdout, stderr="probe failure"
            )
            with self.subTest(stdout=stdout, returncode=returncode):
                with mock.patch.object(windows_runtime.subprocess, "run", return_value=completed):
                    with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
                        windows_runtime._probe_request(
                            self.runtime,
                            windows_runtime.build_policy(["browser.exe"], {}, self.profile, 10809),
                            platform_name="win32",
                            version=(10, 26100),
                        )

    def test_public_probe_returns_contract_for_root_manager(self):
        with mock.patch.object(
            windows_runtime, "_probe_request", return_value=json.loads(supported_probe_json())
        ):
            with mock.patch.object(windows_runtime, "_check_windows_version"):
                result = windows_runtime.probe(str(self.runtime), 10809)
        self.assertEqual(result["supported"], True)
        self.assertEqual(result["backend"], "base-container")
        self.assertTrue(result["limitations"])

    def test_public_probe_fails_closed_on_os_or_runtime_problem(self):
        with mock.patch.object(
            windows_runtime, "_check_windows_version", side_effect=windows_runtime.UnsupportedRuntimeError("unsupported OS")
        ):
            result = windows_runtime.probe(str(self.runtime))
        self.assertFalse(result["supported"])
        self.assertIsNone(result["backend"])
        self.assertIn("unsupported OS", result["detail"])
        self.assertEqual(result["limitations"], [], "a refusal does not list what a working setup would do")

    def test_launch_uses_one_proxy_endpoint_and_approves_only_after_checks(self):
        class Proc:
            pid = 987
            returncode = 0
            def poll(self): return 0

        events = []
        class Fixture:
            endpoints = [{"address": "127.0.0.1", "port": 19002, "protocol": "tcp"},
                         {"address": "127.0.0.1", "port": 19003, "protocol": "udp"}]
            def __init__(self, excluded_port): self.accepted = threading.Event()
            def start(self): events.append("fixtures-ready")
            def close(self): events.append("fixtures-closed")

        def wait(directory, nonce, state, process, timeout):
            decision = directory / "host-decision.json"
            if state == "READY":
                self.assertFalse(decision.exists())
                events.append("checks-passed")
            else:
                self.assertEqual(json.loads(decision.read_text())["decision"], "approved")
                events.append("application-started")

        command = [r"C:\Program Files\Browser\browser.exe", "--proxy-server=http://127.0.0.1:10809"]
        with mock.patch.object(windows_runtime, "_probe_request", return_value=json.loads(supported_probe_json())) as probe, mock.patch.object(
            windows_runtime.subprocess, "Popen", return_value=Proc()
        ) as popen, mock.patch.object(windows_runtime, "_HostLoopbackFixture", Fixture), mock.patch.object(
            windows_runtime, "_wait_for_status", side_effect=wait
        ):
            proc, resource = windows_runtime.launch(command, {}, self.profile, 10809, str(self.runtime))
        try:
            self.assertEqual(proc.pid, 987)
            self.assertEqual(probe.call_count, 1)
            args = popen.call_args.args[0]
            self.assertEqual(args[:2], [str(self.runtime.resolve()), "--config"])
            policy = json.loads(Path(args[2]).read_text(encoding="utf-8"))
            self.assertEqual(policy["network"]["egress"], {"default": "deny"})
            self.assertEqual(policy["runtimeConfig"], {"networkProxy": "http://127.0.0.1:10809"})
            self.assertIn("windows_guest.py", policy["process"]["commandLine"])
            self.assertFalse(popen.call_args.kwargs["shell"])
            self.assertEqual(events[:3], ["fixtures-ready", "checks-passed", "application-started"])
        finally:
            resource.close()
        self.assertFalse(resource.status_dir.exists())

    def test_missing_proxy_capability_is_refused_even_when_base_container_exists(self):
        output = json.loads(supported_probe_json())
        output["probes"].pop("baseContainerSupportsIdentitylessLoopbackProxy")
        self.assertIn("未确认", self.probe_with(subprocess.CompletedProcess([], 0, json.dumps(output), "")))

    def test_startup_failure_retains_the_original_contained_error(self):
        self.profile.mkdir(parents=True)
        nonce = "a" * 64
        (self.profile / "guest-status.json").write_text(json.dumps({"nonce": nonce, "state": "FAILED", "detail": "socket: 10013"}))
        process = mock.Mock()
        process.poll.return_value = None
        with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "socket: 10013"):
            windows_runtime._wait_for_status(self.profile, nonce, "READY", process, .1)

    def test_an_old_nonce_cannot_approve_a_new_launch(self):
        self.profile.mkdir(parents=True)
        (self.profile / "guest-status.json").write_text(json.dumps({"nonce": "old", "state": "READY"}))
        process = mock.Mock()
        process.poll.return_value = None
        with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "超时"):
            windows_runtime._wait_for_status(self.profile, "new", "READY", process, .01)

    def test_completed_short_command_is_still_a_successful_launch(self):
        self.profile.mkdir(parents=True)
        (self.profile / "guest-status.json").write_text(json.dumps({"nonce": "x", "state": "APP_EXITED", "started": True}))
        process = mock.Mock()
        process.poll.return_value = 0
        windows_runtime._wait_for_status(self.profile, "x", "APP_STARTED", process, .1)

    def test_adapter_must_use_the_same_port_as_the_kernel_policy(self):
        with self.assertRaisesRegex(ValueError, "kernel policy"):
            windows_runtime._require_proxy_endpoint(["browser.exe", "--proxy-server=http://127.0.0.1:19000"], {}, self.profile, 10809)

    def test_listener_identity_requires_exact_address_port_and_pid(self):
        def row(address, port, pid):
            return struct.pack("<6I", 2, address, socket.htons(port), 0, 0, pid)
        table = struct.pack("<I", 3) + row(0x0100007f, 10809, 123) + row(0, 10809, 456) + row(0x0100007f, 10810, 789)
        self.assertEqual(windows_runtime._tcp_listener_owners(table, 10809), {123})
        with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
            windows_runtime._tcp_listener_owners(table[:-1], 10809)

    def test_safe_stop_terminates_only_verified_direct_child_then_waits_wrapper(self):
        class Process:
            pid = 500
            _handle = 99

            def __init__(self):
                self.returncode = None
                self.wait_calls = []

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                self.wait_calls.append(timeout)
                self.returncode = 0
                return self.returncode

        class Api:
            def __init__(self):
                self.terminated = []
                self.waited = []
                self.closed = []

            def process_creation_time(self, handle):
                self.parent_handle = handle
                return 100

            def process_alive(self, handle):
                self.alive_handle = handle
                return True

            def direct_children(self, parent_pid, parent_created):
                self.parent_pid = parent_pid
                self.parent_created = parent_created
                return [(501, 101)]

            def terminate(self, handle):
                self.terminated.append(handle)

            def wait(self, handle, timeout_ms):
                self.waited.append((handle, timeout_ms))
                return True

            def close(self, handle):
                self.closed.append(handle)

        process, api = Process(), Api()
        windows_runtime._stop_with_api(
            process, api, timeout=1, poll_interval=0.001
        )
        self.assertEqual(api.parent_handle, 99)
        self.assertEqual(api.alive_handle, 99)
        self.assertEqual(api.parent_pid, 500)
        self.assertEqual(api.parent_created, 100)
        self.assertEqual(api.terminated, [101])
        self.assertEqual(api.waited[0][0], 101)
        self.assertEqual(api.closed, [101])
        self.assertEqual(process.returncode, 0)
        self.assertEqual(len(process.wait_calls), 1)

    def test_safe_stop_refuses_ambiguous_children_without_terminating_any(self):
        class Process:
            pid = 500
            _handle = 99

            def poll(self):
                return None

        class Api:
            def __init__(self):
                self.closed = []
                self.terminated = []

            def process_creation_time(self, _handle):
                return 100

            def process_alive(self, _handle):
                return True

            def direct_children(self, _pid, _created):
                return [(501, 101), (502, 102)]

            def close(self, handle):
                self.closed.append(handle)

        api = Api()
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "ambiguous"):
            windows_runtime._stop_with_api(
                Process(), api, timeout=1, poll_interval=0.001
            )
        self.assertEqual(api.closed, [101, 102])
        self.assertEqual(api.terminated, [])

    def test_safe_stop_times_out_without_child_and_leaves_wrapper(self):
        class Process:
            pid = 500
            _handle = 99
            returncode = None

            def poll(self):
                return self.returncode

        class Api:
            def process_creation_time(self, _handle):
                return 100

            def process_alive(self, _handle):
                return True

            def direct_children(self, _pid, _created):
                return []

        with self.assertRaisesRegex(windows_runtime.SafeStopError, "left running"):
            windows_runtime._stop_with_api(
                Process(), Api(), timeout=0.01, poll_interval=0.001
            )

    def test_public_safe_stop_rejects_non_windows(self):
        with mock.patch.object(windows_runtime.sys, "platform", "linux"):
            with self.assertRaises(windows_runtime.SafeStopError):
                windows_runtime.stop(object())

    def test_toolhelp_child_handle_requests_synchronize_access(self):
        api = windows_runtime._WinProcessApi
        self.assertTrue(api.PROCESS_ACCESS & api.SYNCHRONIZE)
        self.assertEqual(api.SYNCHRONIZE, 0x00100000)
        self.assertEqual(api.PROCESS_ACCESS, 0x00101001)
        self.assertEqual(windows_runtime._raw_handle(321), 321)
        self.assertEqual(windows_runtime._raw_handle(ctypes.c_void_p(321)), 321)

    def test_toolhelp_revalidation_rejects_pid_reuse(self):
        api = object.__new__(windows_runtime._WinProcessApi)

        class Kernel:
            def __init__(self):
                self.opened = []
                self.closed = []

            def OpenProcess(self, _access, _inherit, pid):
                handle = len(self.opened) + 101
                self.opened.append((pid, handle))
                return handle

            def CloseHandle(self, handle):
                self.closed.append(handle)

        api.kernel32 = Kernel()
        api._snapshot_parent_ids = mock.Mock(
            side_effect=[{501: 500}, {501: 999}]
        )
        api._creation_time = mock.Mock(return_value=150)
        self.assertEqual(api.direct_children(500, 100), [])
        self.assertEqual(api.kernel32.closed, [101])

    def test_toolhelp_revalidation_rejects_changed_process_creation_time(self):
        api = object.__new__(windows_runtime._WinProcessApi)

        class Kernel:
            def __init__(self):
                self.opened = []
                self.closed = []

            def OpenProcess(self, _access, _inherit, pid):
                handle = len(self.opened) + 101
                self.opened.append((pid, handle))
                return handle

            def CloseHandle(self, handle):
                self.closed.append(handle)

        api.kernel32 = Kernel()
        api._snapshot_parent_ids = mock.Mock(
            side_effect=[{501: 500}, {501: 500}]
        )
        api._creation_time = mock.Mock(side_effect=[150, 151])
        self.assertEqual(api.direct_children(500, 100), [])
        self.assertEqual(api.kernel32.closed, [102, 101])


if __name__ == "__main__":
    unittest.main()
