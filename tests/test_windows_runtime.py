import json
import ctypes
import stat
import subprocess
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
            "probes": {"baseContainerApiPresent": True},
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

    def test_build_policy_is_exact_model_3_and_starts_guest_helper(self):
        policy = windows_runtime.build_policy(
            [r"C:\Program Files\Browser\browser.exe", "--proxy-server=http://127.0.0.1:19001", "https://example.test"],
            {"HTTP_PROXY": "http://127.0.0.1:19001", "CUSTOM": "ok"},
            self.profile,
            19001,
        )
        self.assertEqual(policy["version"], "1.0.0")
        self.assertEqual(policy["containment"], "processcontainer")
        self.assertEqual(policy["network"]["egress"], {"default": "deny"})
        self.assertEqual(
            policy["network"]["ingress"],
            {"default": "deny", "hostLoopback": "deny"},
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

    def test_launch_probes_runs_only_guest_helper_and_gates_app(self):
        class Proc:
            pid = 987

            def poll(self):
                return 0

        class Bridge:
            def __init__(self, host_proxy_port, directory):
                self.directory = Path(tempfile.mkdtemp(dir=directory))
                self.nonce = "a" * 64
                self.last_error = None
                self.approved = False

            def wait_ready(self, timeout):
                return True

            def approve(self):
                self.approved = True

            def reject(self, reason):
                pass

            def close(self):
                pass

        class Fixture:
            def __init__(self):
                self.port = 19002
                self.accepted = threading.Event()

            def start(self):
                pass

            def close(self):
                pass

        command = [r"C:\Program Files\Browser\browser.exe", "--proxy-server=http://127.0.0.1:19001"]
        env = {"HTTP_PROXY": "http://127.0.0.1:19001"}
        with mock.patch.object(windows_runtime, "_probe_request", return_value=json.loads(supported_probe_json())) as probe, mock.patch.object(
            windows_runtime.subprocess, "Popen", return_value=Proc()
        ) as popen, mock.patch.object(windows_runtime, "_check_windows_version"), mock.patch(
            "ruleproxy.file_bridge.FileProxyBridge", Bridge
        ), mock.patch.object(windows_runtime, "_HostLoopbackFixture", Fixture), mock.patch.object(windows_runtime, "_host_can_reach_guest", return_value=False), mock.patch.object(
            windows_runtime, "_wait_for_status", return_value=True
        ):
            proc, resource = windows_runtime.launch(
                command,
                env,
                self.profile,
                10809,
                str(self.runtime),
                guest_listener_port=19001,
            )
        self.addCleanup(resource.close)
        self.assertEqual(proc.pid, 987)
        self.assertEqual(probe.call_count, 1)
        args = popen.call_args.args[0]
        self.assertEqual(args[:2], [str(self.runtime.resolve()), "--config"])
        self.assertTrue(Path(args[2]).is_file())
        policy = json.loads(Path(args[2]).read_text(encoding="utf-8"))
        self.assertEqual(policy["network"]["egress"]["default"], "deny")
        self.assertEqual(policy["network"]["ingress"], {"default": "deny", "hostLoopback": "deny"})
        self.assertNotIn("runtimeConfig", policy)
        self.assertIn("windows_guest.py", policy["process"]["commandLine"])
        self.assertFalse(popen.call_args.kwargs["shell"])

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
