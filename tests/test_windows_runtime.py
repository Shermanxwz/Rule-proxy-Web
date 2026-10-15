import json
import ctypes
import socket
import time
from contextlib import ExitStack
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import windows_runtime, windows_guest


def startup_report(nonce="a" * 64):
    scopes = {}
    for role, pid, parent_pid in (("parent", 123, 100), ("child", 456, 123)):
        proxy = "proxy_self" if role == "parent" else "proxy_parent"
        scopes[role] = {"scope": role, "pid": pid, "parent_pid": parent_pid, "process_created": pid * 100,
                        "checks": {proxy: {"ok": True, "code": "ok"},
                                   **{name: {"ok": True, "code": 10013} for name in windows_guest._MANDATORY_DENY_PROBES}},
                        "public_udp": {"ipv4_udp": {"ok": False, "code": "allowed"},
                                       "ipv6_udp": {"ok": False, "code": 10051}},
                        "local_udp": {family: {"state": "accepted_full", "stage": "complete", "code": None,
                                               "sent_bytes": len(windows_guest._local_udp_marker(nonce, role, family))}
                                      for family in ("ipv4", "ipv6")}}
    return {"schema_version": 1, "nonce": nonce, "config_readonly": {"ok": True, "code": 5}, **scopes,
            "aux": {"parent_ipv6_loopback": {"ok": False, "code": 10013}}}


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

    def test_build_policy_allows_exact_internal_tcp_endpoint_and_starts_guest_helper(self):
        policy = windows_runtime.build_policy(
            [r"C:\Program Files\Browser\browser.exe", "--proxy-server=http://127.0.0.1:19001", "https://example.test"],
            {"HTTP_PROXY": "http://127.0.0.1:19001", "CUSTOM": "ok"},
            self.profile,
            19001,
        )
        self.assertEqual(policy["version"], "1.0.0")
        self.assertEqual(policy["containment"], "processcontainer")
        self.assertEqual(policy["fallback"], {"allowDaclMutation": False})
        self.assertEqual(policy["network"]["egress"], {"default": "deny", "allow": [{
            "to": [{"cidr": "127.0.0.1/32"}], "ports": [{"protocol": "tcp", "port": 19001}],
        }]})
        self.assertEqual(
            policy["network"]["ingress"],
            {"default": "deny", "hostLoopback": "deny"},
        )
        self.assertIn(str(self.profile.resolve()), policy["filesystem"]["readwritePaths"])
        readonly = policy["filesystem"]["readonlyPaths"]
        self.assertIn(r"C:\Program Files\Browser", readonly)
        self.assertTrue(any(path.endswith("ruleproxy") for path in readonly))
        self.assertEqual(policy["process"]["cwd"], str(self.profile.resolve()))
        self.assertEqual(policy["ui"], {"disable": False, "clipboard": "all"})
        self.assertEqual(
            policy["processContainer"]["ui"], {"isolation": "container", "ime": True}
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

    def test_internal_endpoint_allowance_never_adds_other_addresses_ports_protocols_or_proxy_modes(self):
        for port in (1, 19001, 65535):
            with self.subTest(port=port):
                policy = windows_runtime.build_policy([r"C:\Apps\browser.exe"], {}, self.profile, port)
                self.assertEqual(policy["network"], {
                    "egress": {"default": "deny", "allow": [{
                        "to": [{"cidr": "127.0.0.1/32"}],
                        "ports": [{"protocol": "tcp", "port": port}],
                    }]},
                    "ingress": {"default": "deny", "hostLoopback": "deny"},
                })
                self.assertNotIn("runtimeConfig", policy)
                self.assertEqual(policy["processContainer"], {"ui": {"isolation": "container", "ime": True}})

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

    def test_policy_accepts_real_windows_architecture_and_user_environment_names(self):
        environment = {
            "CommonProgramFiles(Arm)": r"C:\Program Files (Arm)\Common Files",
            "ProgramFiles(Arm)": r"C:\Program Files (Arm)",
            "CommonProgramFiles(x86)": r"C:\Program Files (x86)\Common Files",
            "ProgramFiles(x86)": r"C:\Program Files (x86)",
            "CommonProgramW6432": r"C:\Program Files\Common Files",
            "ProgramW6432": r"C:\Program Files",
            "Vendor.Options": "custom",
            "User setting": "with spaces",
            "应用设置": "中文 🚀",
        }
        policy = windows_runtime.build_policy([r"C:\Apps\browser.exe"], environment, self.profile, 10809)
        entries = policy["process"]["env"]
        for key, value in environment.items():
            with self.subTest(key=key):
                self.assertIn(f"{key.upper()}={value}", entries)
        self.assertEqual(policy["network"]["egress"]["default"], "deny")

    def test_environment_entry_injection_is_rejected_before_serializing_policy(self):
        bad_names = ("", "BAD=KEY", "=C:", "KEY\0OTHER", None, 123)
        for key in bad_names:
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "variable name"):
                windows_runtime.build_policy(["browser.exe"], {key: "value"}, self.profile, 10809)
        for value in ("value\0OTHER=changed", None, 123):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "environment value"):
                windows_runtime.build_policy(["browser.exe"], {"CUSTOM": value}, self.profile, 10809)

    def test_punctuation_and_policy_looking_values_remain_literal_json_environment_entries(self):
        name = 'Custom "setting"; (extra)'
        value = 'value=still-value\r\n"}],"network":{"egress":{"default":"allow"}}'
        policy = windows_runtime.build_policy(
            [r"C:\Apps\browser.exe"], {name: value, "http_proxy": "http://unsafe.invalid"}, self.profile, 10809)
        path = windows_runtime._write_policy(policy, self.root)
        decoded = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(decoded, policy)
        self.assertIn(f"{name.upper()}={value}", decoded["process"]["env"])
        self.assertIn("HTTP_PROXY=http://127.0.0.1:10809", decoded["process"]["env"])
        self.assertNotIn("HTTP_PROXY=http://unsafe.invalid", decoded["process"]["env"])
        self.assertEqual(decoded["network"]["egress"]["default"], "deny")

    def test_unencodable_environment_text_is_rejected_without_echoing_the_value(self):
        for surrogate in ("\ud800", "\udfff"):
            with self.subTest(surrogate=repr(surrogate)), self.assertRaisesRegex(
                ValueError, "variable name: not valid Unicode text"
            ):
                windows_runtime.build_policy(["browser.exe"], {f"NAME{surrogate}": "ordinary"}, self.profile, 10809)
            private = f"private credential before {surrogate} and after"
            with self.subTest(surrogate=repr(surrogate)), self.assertRaisesRegex(
                ValueError, "environment value.*not valid Unicode text"
            ) as raised:
                windows_runtime.build_policy(["browser.exe"], {"PRIVATE": private}, self.profile, 10809)
            self.assertNotIn("private credential", str(raised.exception))
            self.assertNotIn(surrogate, str(raised.exception))

    def test_build_policy_rejects_bad_command_profile_or_port(self):
        cases = [
            ([], {}, self.profile, 10809),
            (["browser", "bad\0arg"], {}, self.profile, 10809),
            (["browser"], {"BAD=KEY": "x"}, self.profile, 10809),
            (["browser"], {}, self.root / "profiles" / "invalid app id", 10809),
            (["browser"], {}, self.profile, 0),
            (["browser"], {}, self.profile, True),
            (["browser"], {}, self.profile, -1),
            (["browser"], {}, self.profile, 65536),
            (["browser"], {}, self.profile, 10809.0),
            (["browser"], {}, self.profile, "10809"),
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

    def test_a_missing_base_container_api_requires_complete_runtime_probe_not_a_build_number(self):
        weak = json.dumps({"tier": "appcontainer-dacl", "error": None, "needsDaclAugmentation": True,
                           "probes": {"baseContainerApiPresent": False}, "warnings": []})
        message = self.probe_with(subprocess.CompletedProcess(args=[], returncode=0, stdout=weak, stderr=""))
        self.assertIn("BaseContainer 接口", message)
        self.assertIn("MXC 1.0.0", message)
        self.assertNotIn("26600", message)
        self.assertIn("完整请求的运行时探测", message)
        self.assertIn("版本或更新编号不能保证支持", message)

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
        ), mock.patch.object(windows_runtime, "_read_startup_report", return_value=startup_report()), mock.patch.object(
            windows_runtime, "_bind_startup_workload"
        ) as binding, mock.patch.object(windows_runtime, "_host_ipv6_route_probe", return_value={
            "scope": "fixed_ipv6_tcp_route_probe", "host_ipv6_route_unavailable": True,
            "code": 10051, "kernel_denial_proven": False,
        }):
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
        self.assertEqual(policy["network"]["egress"]["allow"], [{
            "to": [{"cidr": "127.0.0.1/32"}], "ports": [{"protocol": "tcp", "port": 19001}],
        }])
        self.assertEqual(policy["network"]["ingress"], {"default": "deny", "hostLoopback": "deny"})
        self.assertNotIn("runtimeConfig", policy)
        self.assertIn("windows_guest.py", policy["process"]["commandLine"])
        self.assertFalse(popen.call_args.kwargs["shell"])
        config = json.loads((Path(args[2]).parent / "guest-config.json").read_text())
        self.assertEqual(config["schema_version"], 1)
        self.assertTrue(config["host_ipv6_route_unavailable"])
        self.assertEqual(config["env"]["RULEPROXY_RUNTIME_CONFIG"], str(Path(args[2]).parent / "guest-config.json"))
        binding.assert_called_once_with(proc, resource.startup_diagnostics, str(Path(sys.executable).resolve()))
        self.assertEqual(resource.host_ipv6_observation["code"], 10051)
        self.assertEqual(config["host_udp_ports"], list(resource.udp_fixture.ports))
        self.assertTrue(resource.udp_observation["non_delivery_observed"])
        self.assertFalse(resource.udp_observation["public_udp_proven"])
        self.assertFalse(resource.udp_observation["dns_proven"])
        self.assertEqual(resource.startup_diagnostics["parent"]["public_udp"]["ipv4_udp"],
                         {"ok": False, "code": "allowed"})
        self.assertTrue((Path(args[2]).parent / "host-approval.json").is_file())
        self.assertIn(str(Path(args[2]).parent.resolve()), policy["filesystem"]["readonlyPaths"])

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
                if handle == 99:
                    self.parent_handle = handle
                return 100

            def process_alive(self, handle):
                if handle == 99:
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

    def _failed_launch_setup(self, process):
        bridge = mock.Mock()
        bridge.directory = self.root / "failed-bridge"
        bridge.directory.mkdir()
        bridge.nonce = "a" * 64
        bridge.last_error = "contained network check failed"
        bridge.wait_ready.return_value = False
        fixture = mock.Mock(port=19002, accepted=threading.Event())
        stack = ExitStack()
        self.addCleanup(stack.close)
        stack.enter_context(mock.patch.object(windows_runtime, "_probe_request", return_value=json.loads(supported_probe_json())))
        stack.enter_context(mock.patch("ruleproxy.file_bridge.FileProxyBridge", return_value=bridge))
        stack.enter_context(mock.patch.object(windows_runtime, "_HostLoopbackFixture", return_value=fixture))
        stack.enter_context(mock.patch.object(windows_runtime, "_host_ipv6_route_probe", return_value={
            "scope": "fixed_ipv6_tcp_route_probe", "host_ipv6_route_unavailable": False,
            "code": "timeout", "kernel_denial_proven": False,
        }))
        popen = stack.enter_context(mock.patch.object(windows_runtime.subprocess, "Popen", return_value=process))
        return bridge, fixture, popen

    def _launch_for_failure(self):
        return windows_runtime.launch(
            [r"C:\Apps\browser.exe", "--proxy-server=http://127.0.0.1:19001"],
            {}, self.profile, 10809, str(self.runtime), guest_listener_port=19001,
        )

    def test_startup_refusal_rejects_guest_and_cleans_after_wrapper_exit(self):
        process = mock.Mock(pid=900)
        process.poll.return_value = 70
        bridge, fixture, popen = self._failed_launch_setup(process)
        with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "contained network check failed"):
            self._launch_for_failure()
        bridge.reject.assert_called_once()
        bridge.approve.assert_not_called()
        bridge.close.assert_called_once()
        fixture.close.assert_called_once()
        process.wait.assert_called_once_with(timeout=12)
        process.terminate.assert_not_called()
        self.assertEqual(popen.call_count, 1)
        self.assertEqual(popen.call_args.args[0][0], str(self.runtime.resolve()))
        self.assertFalse(Path(popen.call_args.args[0][2]).exists())

    def test_startup_timeout_preserves_live_wrapper_and_resources_for_retry(self):
        process = mock.Mock(pid=900)
        process.poll.return_value = None
        process.wait.side_effect = subprocess.TimeoutExpired("mxc", 12)
        bridge, fixture, popen = self._failed_launch_setup(process)
        with self.assertRaises(windows_runtime.UnsupportedRuntimeError) as failure:
            self._launch_for_failure()
        resource = failure.exception.resource
        self.assertIs(failure.exception.process, process)
        self.assertIs(resource.failed_process, process)
        bridge.reject.assert_called_once()
        bridge.close.assert_not_called()
        fixture.close.assert_not_called()
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        self.assertTrue(Path(popen.call_args.args[0][2]).exists())
        with self.assertRaises(windows_runtime.SafeStopError):
            resource.close()
        process.poll.return_value = 70
        resource.close()
        bridge.close.assert_called_once()
        fixture.close.assert_called_once()
        self.assertFalse(Path(popen.call_args.args[0][2]).exists())

    def test_status_reader_rejects_non_ascii_control_records(self):
        directory = self.root / "status"
        directory.mkdir()
        (directory / "guest-status.json").write_bytes(b'\xff{"state":"APP_STARTED"}')
        process = mock.Mock()
        process.poll.return_value = None
        self.assertFalse(windows_runtime._wait_for_status(directory, "a" * 64, "APP_STARTED", process, 0.01))

    def test_fixture_cleanup_error_preserves_resource_for_retry_without_killing_wrapper(self):
        process = mock.Mock(pid=900)
        process.poll.return_value = 70
        bridge, fixture, _ = self._failed_launch_setup(process)
        fixture.close.side_effect = windows_runtime.SafeStopError("fixture cleanup failed")
        with self.assertRaises(windows_runtime.SafeStopError) as raised:
            self._launch_for_failure()
        resource = raised.exception.resource
        self.assertIs(raised.exception.process, process)
        self.assertIs(resource.failed_process, process)
        self.assertTrue(resource.udp_fixture.closed.is_set())
        self.assertTrue(all(not thread.is_alive() for thread in resource.udp_fixture.threads))
        self.assertTrue(bridge.directory.exists())
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        fixture.close.side_effect = None
        resource.close()
        self.assertFalse(bridge.directory.exists())

    def test_live_udp_observer_received_marker_blocks_host_approval(self):
        process = mock.Mock(pid=900)
        process.poll.return_value = 70
        bridge, _, _ = self._failed_launch_setup(process)
        bridge.wait_ready.return_value = True
        def ready(_timeout):
            # Use the concrete config handed to this exact wrapper launch.
            policy_path = Path(process._test_policy_path)
            config = json.loads((policy_path.parent / "guest-config.json").read_text())
            for role in ("parent", "child"):
                for family, kind, host, port in zip(("ipv4", "ipv6"), (socket.AF_INET, socket.AF_INET6),
                                                   ("127.0.0.1", "::1"), config["host_udp_ports"]):
                    with socket.socket(kind, socket.SOCK_DGRAM) as sender:
                        marker = windows_guest._local_udp_marker(config["bridge_nonce"], role, family)
                        self.assertEqual(sender.sendto(marker, (host, port)), len(marker))
            (bridge.directory / "network-probe.json").write_text(json.dumps(startup_report(bridge.nonce)))
            return True
        bridge.wait_ready.side_effect = ready
        def launch_wrapper(args, **kwargs):
            process._test_policy_path = args[2]
            return process
        windows_runtime.subprocess.Popen.side_effect = launch_wrapper
        with mock.patch.object(windows_runtime, "_host_can_reach_guest", return_value=False):
            with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "reached a fixed host endpoint"):
                self._launch_for_failure()
        bridge.approve.assert_not_called()
        bridge.reject.assert_called_once()
        process.kill.assert_not_called()

    def test_invalid_or_missing_udp_report_never_approves_even_when_guest_ready(self):
        process = mock.Mock(pid=900)
        process.poll.return_value = 70
        bridge, _, _ = self._failed_launch_setup(process)
        bridge.wait_ready.return_value = True
        with mock.patch.object(windows_runtime, "_host_can_reach_guest", return_value=False):
            with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "report was invalid or incomplete"):
                self._launch_for_failure()
        bridge.approve.assert_not_called()
        bridge.reject.assert_called_once()

    def test_safe_stop_releases_child_handles_if_wrapper_verification_fails(self):
        process = mock.Mock(pid=500, _handle=99)
        process.poll.return_value = None
        api = mock.Mock()
        api.process_creation_time.return_value = 100
        api.direct_children.return_value = [(501, 101), (502, 102)]
        api.process_alive.side_effect = OSError("wrapper handle query failed")
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "could not verify MXC wrapper"):
            windows_runtime._stop_with_api(process, api, timeout=1, poll_interval=0.001)
        self.assertEqual(api.close.call_args_list, [mock.call(101), mock.call(102)])
        api.terminate.assert_not_called()
        process.wait.assert_not_called()

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

    def test_toolhelp_excludes_older_foreign_child_before_requesting_denied_termination_access(self):
        api = object.__new__(windows_runtime._WinProcessApi)
        requested, closed = [], []

        class Kernel:
            def OpenProcess(self, access, inherit, pid):
                requested.append((pid, access))
                # The old process is queryable but denies termination access.
                return 0 if access & api.PROCESS_TERMINATE else 101

            def CloseHandle(self, handle):
                closed.append(handle)
                return True

        api.kernel32 = Kernel()
        api._snapshot_parent_ids = mock.Mock(side_effect=[{501: 500}, {501: 500}])
        api._creation_time = mock.Mock(return_value=50)
        self.assertEqual(api.direct_children(500, 100), [])
        self.assertEqual(requested, [(501, api.PROCESS_QUERY_LIMITED_INFORMATION)])
        self.assertEqual(api._creation_time.call_count, 1)
        self.assertEqual(closed, [101])

    def assert_toolhelp_permission_rejection_keeps_wrapper(self, denied_access):
        api = object.__new__(windows_runtime._WinProcessApi)
        requested, closed = [], []
        kernel = mock.Mock()

        def open_process(access, inherit, pid):
            requested.append((pid, access))
            return 0 if access == denied_access else 101

        kernel.OpenProcess.side_effect = open_process
        kernel.CloseHandle.side_effect = lambda handle: closed.append(handle) or True
        api.kernel32 = kernel
        api._snapshot_parent_ids = mock.Mock(side_effect=[{501: 500}, {501: 500}])
        api._creation_time = mock.Mock(side_effect=lambda handle: 100 if handle == 99 else 150)
        process = mock.Mock(pid=500, _handle=99)
        process.poll.return_value = None
        error = PermissionError(13, "simulated process access denial")
        error.winerror = 5
        with mock.patch.object(ctypes, "WinError", return_value=error, create=True), \
                mock.patch.object(ctypes, "get_last_error", return_value=5, create=True):
            with self.assertRaises(windows_runtime.SafeStopError) as raised:
                windows_runtime._stop_with_api(process, api, timeout=1, poll_interval=0.001)
        self.assertIs(raised.exception.__cause__, error)
        process.terminate.assert_not_called()
        process.kill.assert_not_called()
        process.wait.assert_not_called()
        kernel.TerminateProcess.assert_not_called()
        return requested, closed

    def test_toolhelp_query_denial_remains_strict_and_never_terminates_wrapper(self):
        access = windows_runtime._WinProcessApi.PROCESS_QUERY_LIMITED_INFORMATION
        requested, closed = self.assert_toolhelp_permission_rejection_keeps_wrapper(access)
        self.assertEqual(requested, [(501, access)])
        self.assertEqual(closed, [])

    def test_toolhelp_second_snapshot_termination_denial_keeps_wrapper_and_closes_query_handle(self):
        api = windows_runtime._WinProcessApi
        requested, closed = self.assert_toolhelp_permission_rejection_keeps_wrapper(api.PROCESS_ACCESS)
        self.assertEqual(requested, [(501, api.PROCESS_QUERY_LIMITED_INFORMATION), (501, api.PROCESS_ACCESS)])
        self.assertEqual(closed, [101])

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


class OwnedWindowsWorkloadTests(unittest.TestCase):
    PYTHON = r"C:\RuleProxy\python\python.exe"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        owner = self

        class Process:
            pid, _handle = 100, 99
            returncode = None
            wait_failure = False

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                if self.wait_failure:
                    raise subprocess.TimeoutExpired("mxc", timeout)
                self.returncode = 0
                for record in owner.records.values():
                    if not record.get("survivor"):
                        record["alive"] = False
                return 0

        class Api:
            def __init__(self):
                self.opened, self.closed, self.terminated = [], [], []
                self.handles = {}
                self.fail_close = None

            def process_creation_time(self, handle):
                return 10000 if handle == 99 else self.handles[handle]["created"]

            def process_alive(self, handle):
                return owner.process.returncode is None if handle == 99 else self.handles[handle]["alive"]

            def process_image(self, handle):
                return self.handles[handle]["image"]

            def direct_children(self, pid, created):
                owner.assertEqual((pid, created), (100, 10000))
                values = []
                for child_pid, record in owner.records.items():
                    if record["alive"]:
                        handle = 1000 + len(self.opened)
                        self.opened.append(handle)
                        self.handles[handle] = record
                        values.append((child_pid, handle))
                return values

            def terminate(self, handle):
                self.terminated.append(handle)
                self.handles[handle]["alive"] = False

            def wait(self, handle, timeout_ms):
                return not self.handles[handle]["alive"]

            def close(self, handle):
                if handle == self.fail_close:
                    raise OSError("close failed")
                owner.assertNotIn(handle, self.closed, "a HANDLE must be closed exactly once")
                self.closed.append(handle)

        self.records = {
            900: {"created": 11000, "image": r"C:\Windows\System32\conhost.exe", "alive": True},
            123: {"created": 12300, "image": self.PYTHON, "alive": True},
        }
        self.process, self.api = Process(), Api()

    def bind(self, report=None):
        return windows_runtime._bind_startup_workload(self.process, report or startup_report(),
                                                       self.PYTHON, api=self.api)

    def resource(self):
        directory = tempfile.TemporaryDirectory(dir=self.root)
        (Path(directory.name) / "guest-config.json").write_text("kept until all handles exit")
        bridge = mock.Mock(directory=self.root / "bridge")
        bridge.directory.mkdir()
        value = windows_runtime._WindowsRuntimeResources(directory, mock.Mock(), bridge)
        value.process = self.process
        self.addCleanup(directory.cleanup)
        return value

    def test_two_direct_children_bind_exact_generation_and_only_terminate_python(self):
        state = self.bind()
        handles = dict(state.children)
        helper, console = handles[(123, 12300)], handles[(900, 11000)]
        windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        self.assertEqual(self.api.terminated, [helper])
        self.assertNotIn(console, self.api.terminated)
        self.assertNotIn(99, self.api.terminated)
        self.assertTrue(state.closed)
        self.assertFalse(state.children)
        self.assertEqual(set(self.api.closed), set(self.api.opened))

    def test_report_pid_generation_parent_or_unknown_image_never_binds(self):
        for kind in ("pid", "created", "parent", "image"):
            with self.subTest(kind=kind):
                report = startup_report()
                original = self.records[123]["image"]
                if kind == "pid":
                    report["parent"]["pid"] = 124
                    report["child"]["parent_pid"] = 124
                elif kind == "created":
                    report["parent"]["process_created"] += 1
                elif kind == "parent":
                    report["parent"]["parent_pid"] = 101
                else:
                    self.records[123]["image"] = r"C:\Unknown\python.exe"
                with self.assertRaisesRegex(windows_runtime.SafeStopError, "exact trusted"):
                    self.bind(report)
                state = windows_runtime._owned_stop_state(self.process)
                self.assertIsNone(state.workload)
                self.assertFalse(state.closed)
                with self.assertRaisesRegex(windows_runtime.SafeStopError, "no startup-bound"):
                    windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
                self.assertFalse(self.api.terminated)
                self.process.wait()
                state.release_exited()
                self.process.returncode = None
                for record in self.records.values(): record["alive"] = True
                self.records[123]["image"] = original

    def test_two_same_python_images_are_ambiguous_despite_one_matching_report(self):
        self.records[900]["image"] = self.PYTHON.upper()
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "exact trusted"):
            self.bind()
        self.assertFalse(self.api.terminated)
        self.process.wait()
        windows_runtime._owned_stop_state(self.process).release_exited()

    def test_unknown_owned_child_surviving_wrapper_preserves_resources_then_retry_releases(self):
        state = self.bind()
        self.records[900].update(image=r"C:\Unknown\helper.exe", survivor=True)
        resource = self.resource()
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "survived SDK"):
            windows_runtime._stop_with_api(self.process, self.api, timeout=0.01, poll_interval=0.001)
        self.assertEqual(self.process.returncode, 0)
        self.assertFalse(state.closed)
        self.assertTrue(state.children)
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "remains alive"):
            resource.close()
        resource.bridge.close.assert_not_called()
        self.assertTrue((Path(resource.run_dir.name) / "guest-config.json").exists())
        self.assertTrue(resource.bridge.directory.exists())
        self.records[900]["alive"] = False
        windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        resource.close()
        self.assertTrue(state.closed)
        self.assertFalse(Path(resource.run_dir.name).exists())
        self.assertFalse(resource.bridge.directory.exists())
        self.assertEqual(len(self.api.terminated), 1)
        self.assertEqual(set(self.api.closed), set(self.api.opened))

    def test_wrapper_teardown_timeout_preserves_target_handle_and_does_not_kill_twice(self):
        state = self.bind()
        self.process.wait_failure = True
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "normal teardown"):
            windows_runtime._stop_with_api(self.process, self.api, timeout=0.01, poll_interval=0.001)
        self.assertFalse(state.closed)
        self.assertIn(state.workload, state.children)
        self.assertEqual(len(self.api.terminated), 1)
        self.process.wait_failure = False
        windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        self.assertTrue(state.closed)
        self.assertEqual(len(self.api.terminated), 1)

    def test_partial_handle_close_failure_is_retryable_after_wrapper_exit(self):
        state = self.bind()
        self.process.wait()
        remaining = state.children[(123, 12300)]
        self.api.fail_close = remaining
        with self.assertRaises(OSError):
            state.release_exited()
        self.assertEqual(state.children, {(123, 12300): remaining})
        self.assertFalse(state.closed)
        self.api.fail_close = None
        windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        self.assertTrue(state.closed)
        self.assertEqual(set(self.api.closed), set(self.api.opened))

    def test_real_close_api_checks_kernel_boolean_instead_of_claiming_release(self):
        api = object.__new__(windows_runtime._WinProcessApi)
        api.kernel32 = mock.Mock()
        api.kernel32.CloseHandle.return_value = False
        with mock.patch.object(windows_runtime.ctypes, "get_last_error", return_value=6, create=True), mock.patch.object(
            windows_runtime.ctypes, "WinError", side_effect=lambda code: OSError(code, "CloseHandle"), create=True
        ):
            with self.assertRaises(OSError):
                api.close(1001)
        api.kernel32.CloseHandle.assert_called_once_with(1001)

    def test_kernel_terminated_helper_is_not_reopened_by_pid_after_wrapper_exit(self):
        state = self.bind()
        self.process.wait()
        self.api.direct_children = mock.Mock(side_effect=AssertionError("must use held handles"))
        state.stop(timeout=1)
        self.api.direct_children.assert_not_called()
        self.assertTrue(state.closed)

    def test_repeated_stop_after_closed_state_never_queries_released_handles(self):
        state = self.bind()
        state.stop(timeout=1)
        self.api.process_creation_time = mock.Mock(side_effect=AssertionError("released HANDLE query"))
        self.api.wait = mock.Mock(side_effect=AssertionError("released HANDLE wait"))
        state.stop(timeout=1)
        state.release_exited()
        self.api.wait.assert_not_called()

    def test_unreported_product_console_child_cannot_gain_single_child_kill_authority(self):
        self.process._ruleproxy_python_executable = self.PYTHON
        del self.records[123]
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "not the trusted Python"):
            windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        state = windows_runtime._owned_stop_state(self.process)
        self.assertFalse(self.api.terminated)
        self.assertIsNone(state.workload)
        self.assertTrue(state.children)
        self.process.wait()
        state.release_exited()

    def test_product_single_child_fallback_still_requires_exact_python_image(self):
        self.process._ruleproxy_python_executable = self.PYTHON
        del self.records[900]
        windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        self.assertEqual(len(self.api.terminated), 1)
        self.assertTrue(windows_runtime._owned_stop_state(self.process).closed)

    def test_unreported_ambiguous_product_children_are_retained_without_kill_authority(self):
        self.process._ruleproxy_python_executable = self.PYTHON
        self.records[900]["survivor"] = True
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "ambiguous"):
            windows_runtime._stop_with_api(self.process, self.api, timeout=1, poll_interval=0.001)
        state = windows_runtime._owned_stop_state(self.process)
        self.assertIsNone(state.workload)
        self.assertEqual(len(state.children), 2)
        self.assertFalse(self.api.closed)
        self.assertFalse(self.api.terminated)
        self.process.wait()
        with self.assertRaises(windows_runtime.SafeStopError):
            state.release_exited()
        self.records[900]["alive"] = False
        state.release_exited()
        self.assertEqual(set(self.api.closed), set(self.api.opened))

    def test_changed_wrapper_generation_never_terminates_bound_helper(self):
        state = self.bind()
        original = self.api.process_creation_time
        self.api.process_creation_time = lambda handle: 20000 if handle == 99 else original(handle)
        with self.assertRaisesRegex(windows_runtime.SafeStopError, "identity changed"):
            state.stop(timeout=1)
        self.assertFalse(self.api.terminated)
        self.assertFalse(state.closed)
        self.process.wait()
        state.release_exited()

    def test_host_route_fact_requires_actual_windows_10051_without_changing_raw_probes(self):
        success = mock.MagicMock()
        success.__enter__.return_value = success
        with mock.patch.object(windows_runtime.socket, "socket", return_value=success):
            result = windows_runtime._host_ipv6_route_probe()
        self.assertFalse(result["host_ipv6_route_unavailable"])
        self.assertEqual(result["code"], "connected")
        for code, expected in ((10051, True), (10013, False), (10047, False), (101, False), (None, False)):
            error = TimeoutError() if code is None else OSError(code, "fixed route diagnostic")
            if code != 101:
                error.winerror = code
            connection = mock.Mock()
            connection.__enter__ = mock.Mock(return_value=connection)
            connection.__exit__ = mock.Mock(return_value=False)
            connection.connect.side_effect = error
            with self.subTest(code=code), mock.patch.object(windows_runtime.socket, "socket", return_value=connection):
                result = windows_runtime._host_ipv6_route_probe()
            self.assertEqual(result["host_ipv6_route_unavailable"], expected)
            self.assertFalse(result["kernel_denial_proven"])
            connection.settimeout.assert_called_once_with(1)
            connection.connect.assert_called_once_with(("2606:4700:4700::1111", 443, 0, 0))

    def test_host_10051_only_permits_matching_guest_unavailable_and_internal_ipv6_denied(self):
        report = startup_report()
        for role in ("parent", "child"):
            report[role]["checks"]["ipv6_tcp"] = {"ok": False, "code": 10051}
        (self.root / "network-probe.json").write_text(json.dumps(report))
        with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
            windows_runtime._read_startup_report(self.root, report["nonce"])
        actual = windows_runtime._read_startup_report(self.root, report["nonce"], host_ipv6_route_unavailable=True)
        self.assertEqual(actual["parent"]["checks"]["ipv6_tcp"], {"ok": False, "code": 10051})
        report["parent"]["checks"]["ipv4_tcp"] = {"ok": False, "code": "allowed"}
        (self.root / "network-probe.json").write_text(json.dumps(report))
        with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
            windows_runtime._read_startup_report(self.root, report["nonce"], host_ipv6_route_unavailable=True)


class HostUDPObserverTests(unittest.TestCase):
    def setUp(self):
        self.fixture = windows_runtime._HostUDPFixture("a" * 64)
        self.addCleanup(self.fixture.close)
        self.fixture.control_before()

    def test_real_before_after_controls_validate_only_fixed_endpoint_absence(self):
        result = self.fixture.verify(startup_report())
        self.assertTrue(result["non_delivery_observed"])
        self.assertFalse(result["kernel_denial_proven"])
        self.assertFalse(result["public_udp_proven"])
        self.assertFalse(result["dns_proven"])
        for family in ("ipv4", "ipv6"):
            self.assertGreaterEqual(result["observations"][family]["before_received"], 1)
            self.assertGreaterEqual(result["observations"][family]["after_received"], 1)
            self.assertEqual(result["observations"][family]["parent_received"], 0)
            self.assertEqual(result["observations"][family]["child_received"], 0)
        # The private host controls are not one of the guest's role markers.
        for family in ("ipv4", "ipv6"):
            self.assertNotIn(self.fixture.markers[family]["before"],
                             [windows_guest._local_udp_marker("a" * 64, role, family) for role in ("parent", "child")])

    def test_real_uncontained_parent_child_sends_are_received_and_rejected(self):
        report = startup_report()
        for role in ("parent", "child"):
            for family, port in zip(("ipv4", "ipv6"), self.fixture.ports):
                report[role]["local_udp"][family] = windows_guest._local_udp_attempt(
                    role, family, port, "a" * 64, deadline=time.monotonic() + 1)
        with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "reached a fixed host endpoint"):
            self.fixture.verify(report)
        for family in ("ipv4", "ipv6"):
            self.assertEqual(self.fixture.counts[family, "parent"], 1)
            self.assertEqual(self.fixture.counts[family, "child"], 1)
            self.assertGreaterEqual(self.fixture.counts[family, "after"], 1)

    def test_dead_receiver_or_missing_after_control_is_not_zero_delivery_proof(self):
        self.fixture.sockets[1].close()
        self.fixture.threads[1].join(1)
        with self.assertRaises(windows_runtime.UnsupportedRuntimeError):
            self.fixture.verify(startup_report())
        self.assertFalse(self.fixture._verified)

    def test_stale_session_marker_contaminates_instead_of_silently_passing(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(windows_guest._local_udp_marker("b" * 64, "parent", "ipv4"),
                          ("127.0.0.1", self.fixture.ports[0]))
        with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "contaminated"):
            self.fixture.verify(startup_report())

    def test_guest_cannot_supply_host_control_counts_or_override_observer_verdict(self):
        report = startup_report()
        report["observer_counts"] = {"parent": 0, "child": 0, "before": 1, "after": 1}
        with self.assertRaises(ValueError):
            self.fixture.verify(report)
        self.assertFalse(self.fixture._verified)

    def test_after_control_counts_are_required_even_if_control_wait_returns(self):
        with mock.patch.object(self.fixture, "_control"):
            with self.assertRaisesRegex(windows_runtime.UnsupportedRuntimeError, "controls were incomplete"):
                self.fixture.verify(startup_report())

    def test_close_finishes_real_observer_threads_and_is_idempotent(self):
        self.fixture.close()
        self.assertTrue(all(not thread.is_alive() for thread in self.fixture.threads))
        self.assertTrue(all(sock.fileno() == -1 for sock in self.fixture.sockets))
        self.fixture.close()


if __name__ == "__main__":
    unittest.main()
