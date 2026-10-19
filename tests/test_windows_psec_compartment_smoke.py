import copy
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


PATH = Path(__file__).resolve().parents[1] / ".github/windows_psec_compartment_smoke.py"
SPEC = importlib.util.spec_from_file_location("windows_psec_compartment_smoke", PATH)
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


def config(directory):
    return {"inputs": str(directory / "inputs"), "runtime": str(directory / "runtime"),
            "profile": str(directory), "executor": str(directory / "wxc-exec.exe"),
            "config_path": str(directory / "config.json"), "actor_report": str(directory / "actor.json"),
            "sid": "S-1-5-21-1-2-3-1001", "cid": 2, "port": 12345, "marker": "a" * 32,
            "browser": None}


def probe():
    return {"tier": "base-container", "needsDaclAugmentation": False,
            "probes": {"baseContainerApiPresent": True}, "error": None}


def passing_report():
    identity = {"sid": "S-1-5-21-1-2-3-1001", "cid": 2, "elevated": False, "appcontainer": False}
    return {"cid": 2, "ordinary_identity": identity, "fixture_control": {"marker_matched": True},
            "launcher_exit_code": 0, "launcher_timed_out": False,
            "launcher": {"identity": identity, "relay_control": {"marker_matched": True},
                         "probe": probe(), "probe_exit_code": 0, "started": True, "exit_code": 0,
                         "actor": {"identity": identity, "child": {"identity": identity}, "child_exit_code": 0,
                                   "proxy": {"marker_matched": True},
                                   "browser": {"dom_marker_matched": True, "exit_code": 0, "timed_out": False}}},
            "fixture_requests": {"inside": 1, "browser": 1}, "browser_requested": True,
            "cleanup": {"job_empty": True, "account": {
                "account_delete_status": 0, "environment_freed": True, "profile_unloaded": True,
                "profile_deleted": True, "token_closed": True, "desktop_closed": True, "station_closed": True}}}


class PsecCompartmentSmokeTests(unittest.TestCase):
    def test_embedded_python_keeps_native_extensions_beside_the_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary) / "embedded"
            base.mkdir()
            # The embedded distribution puts these beside python.exe, while
            # the full installation uses DLLs/. The former was being lost.
            for name in ("python.exe", "_ctypes.pyd", "_socket.pyd", "_ssl.pyd", "python314.zip", "python314._pth"):
                (base / name).write_bytes(name.encode("ascii"))
            (base / "user-state.txt").write_text("unrelated")
            target = Path(temporary) / "copied"
            with mock.patch.object(smoke.sys, "base_prefix", str(base)), \
                    mock.patch.object(smoke.sys, "executable", str(base / "python.exe")):
                executable = smoke.copy_python(target)
            self.assertEqual(executable, target / "python.exe")
            self.assertEqual((target / "_ctypes.pyd").read_bytes(), b"_ctypes.pyd")
            self.assertTrue((target / "_socket.pyd").is_file())
            self.assertTrue((target / "_ssl.pyd").is_file())
            self.assertFalse((target / "user-state.txt").exists())

    def test_model2_has_only_runtime_proxy_and_deny_direct_egress(self):
        value = smoke.build_policy(config(Path("private")), ["python.exe", "actor.py"])
        self.assertEqual(value["version"], "1.0.0")
        self.assertEqual(value["network"]["egress"], {"default": "deny"})
        self.assertEqual(value["network"]["ingress"], {"default": "allow", "hostLoopback": "allow"})
        self.assertEqual(value["runtimeConfig"], {"networkProxy": "http://127.0.0.1:12345"})
        self.assertEqual(value["fallback"], {"allowDaclMutation": False})
        self.assertFalse(value["ui"]["disable"])

    def test_browser_has_proxy_and_no_sandbox_disabling_flags(self):
        argv = smoke.browser_command("edge.exe", Path("profile"), 12345, "a" * 32)
        self.assertIn("--proxy-server=http://127.0.0.1:12345", argv)
        self.assertFalse(any("no-sandbox" in item or "disable-sandbox" in item for item in argv))
        self.assertTrue(argv[-1].startswith("http://" + smoke.HOST + "/"))

    def test_fixed_proxy_serves_only_the_expected_local_fixture_request(self):
        fixture = smoke.FixedHTTPProxy("a" * 32)
        try:
            result = smoke.proxy_get(fixture.port, "a" * 32, "inside")
            self.assertEqual(result["status"], 200)
            self.assertTrue(result["marker_matched"])
            connection = http.client.HTTPConnection("127.0.0.1", fixture.port, timeout=2)
            try:
                connection.request("GET", "http://unrelated.invalid/")
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                response.read()
            finally:
                connection.close()
            self.assertEqual(fixture.requests["inside"], 1)
            self.assertEqual(fixture.rejected, 1)
        finally:
            fixture.close()

    def test_unsupported_probe_never_executes_the_workload(self):
        for facts in ({}, {**probe(), "tier": "app-container"}, {**probe(), "needsDaclAugmentation": True},
                      {**probe(), "probes": None}, [], {**probe(), "error": "unsupported"}):
            with self.subTest(probe=facts), tempfile.TemporaryDirectory() as temporary:
                cfg = config(Path(temporary))
                identity = {"sid": cfg["sid"], "cid": 2, "elevated": False, "appcontainer": False}
                runner = mock.Mock(return_value=subprocess.CompletedProcess(
                    [], 0, json.dumps(facts).encode(), b""))
                with mock.patch.object(smoke, "identity_snapshot", return_value=identity), \
                        mock.patch.object(smoke, "proxy_get", return_value={"marker_matched": True}):
                    result = smoke.run_psec(cfg, runner)
                self.assertEqual(result["status"], "unsupported")
                self.assertFalse(result["started"])
                runner.assert_called_once()
                self.assertIn("--probe", runner.call_args.args[0])

    def test_mismatched_ordinary_identity_never_calls_executor(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = mock.Mock()
            cfg = config(Path(temporary))
            identity = {"sid": cfg["sid"], "cid": 1, "elevated": False, "appcontainer": False}
            with mock.patch.object(smoke, "identity_snapshot", return_value=identity):
                with self.assertRaisesRegex(RuntimeError, "compartment differs"):
                    smoke.run_psec(cfg, runner)
            runner.assert_not_called()

    def test_executor_failure_keeps_only_bounded_structured_diagnostics(self):
        with tempfile.TemporaryDirectory() as temporary:
            cfg = config(Path(temporary))
            identity = {"sid": cfg["sid"], "cid": 2, "elevated": False, "appcontainer": False}
            calls = []

            def runner(argv, **kwargs):
                calls.append(argv)
                if "--probe" in argv:
                    return subprocess.CompletedProcess(argv, 0, json.dumps(probe()).encode(), b"")
                kwargs["stderr"].write(b"AssignProcessToJobObject: Access denied (os error 5), HRESULT 0x80070005\n"
                                       b"private-user-secret=do-not-export\n")
                kwargs["stderr"].write(json.dumps({"error": {
                    "code": "backend_error",
                    "message": "failed to create the process security environment: do-not-export",
                    "extended_error": "CreateProcessSecurityEnvironment failed: WIN32_ERROR(1920) "
                                      "C:\\private\\do-not-export",
                }}).encode() + b"\n")
                kwargs["stdout"].write(b"private child output: do-not-export\n" + json.dumps({"error": {
                    "code": "policy_validation",
                    "message": "network.ingress.hostLoopback='allow' requires Process Security Environment contract version 1.1",
                }}).encode() + b"\n")
                return subprocess.CompletedProcess(argv, 1)

            with mock.patch.object(smoke, "identity_snapshot", return_value=identity), \
                    mock.patch.object(smoke, "proxy_get", return_value={"marker_matched": True}):
                result = smoke.run_psec(cfg, runner)
            self.assertEqual(len(calls), 2)
            self.assertTrue(result["started"])
            self.assertEqual(result["exit_code"], 1)
            self.assertFalse(result["timed_out"])
            diagnostic = result["executor_diagnostic"]
            self.assertEqual(diagnostic["stream"], "stderr")
            self.assertIn("permission", diagnostic["categories"])
            self.assertIn("AssignProcessToJobObject", diagnostic["operations"])
            self.assertEqual(diagnostic["native_codes"], ["0x80070005", "1920", "5"])
            envelope = diagnostic["error_envelopes"][0]
            self.assertEqual(envelope["code"], "backend_error")
            self.assertEqual(envelope["message_class"], "psec_environment_create")
            self.assertEqual(envelope["native_codes"], ["1920"])
            self.assertTrue(envelope["has_extended_error"])
            stdout = result["executor_stdout_diagnostic"]
            self.assertEqual(stdout["stream"], "stdout")
            self.assertEqual(stdout["error_envelopes"][0]["code"], "policy_validation")
            self.assertEqual(stdout["error_envelopes"][0]["message_class"], "host_loopback_contract")
            self.assertEqual(stdout["native_codes"], [])
            self.assertNotIn("do-not-export", json.dumps(result))
            large = smoke.executor_diagnostic(b"secret" * 20000)
            self.assertTrue(large["inspection_truncated"])
            self.assertLess(len(json.dumps(large)), 2048)

    def test_error_envelope_can_follow_unterminated_stderr_without_exporting_text(self):
        error = {"error": {"code": "backend_error", "message": "private-unclassified-message",
                           "extended_error": "HRESULT(0x80070057) private-details"}}
        # The pinned CLI uses eprint!(standard_err) then eprintln!(envelope).
        raw = b"private-prefix-without-newline" + json.dumps(error).encode() + b"\r\n"
        value = smoke.executor_diagnostic(raw)
        self.assertEqual(len(value["error_envelopes"]), 1)
        envelope = value["error_envelopes"][0]
        self.assertEqual(envelope["code"], "backend_error")
        self.assertEqual(envelope["message_class"], "unclassified")
        self.assertEqual(envelope["native_codes"], ["0x80070057"])
        self.assertEqual(envelope["message_sha256"], hashlib.sha256(b"private-unclassified-message").hexdigest())
        self.assertNotIn("private-", json.dumps(value))

    def test_error_envelopes_reject_other_shapes_and_bound_retained_records(self):
        invalid = [
            {"error": {"code": "backend_error", "message": 5}},
            {"error": {"code": "backend_error", "message": "text", "extended_error": {"code": 5}}},
            {"error": {"code": "backend_error", "message": "text", "child_log": "private"}},
            {"error": {"code": "backend_error", "message": "text"}, "result": "private"},
            {"error": {"code": "unrecognized", "message": "text"}},
            {"error": {"code": "backend_error", "message": "x" * 8193}},
            {"error": "arbitrary browser error"},
        ]
        encoded = [json.dumps(value).encode() for value in invalid]
        encoded.extend([
            b'{"error":{"code":"backend_error","code":"policy_validation","message":"text"}}',
            b'{"error":{"code":"backend_error","message":"text"}} trailing child text',
            b'{"error":' + b'[' * 1500,
        ])
        for raw in encoded:
            with self.subTest(data_length=len(raw)):
                self.assertEqual(smoke.executor_diagnostic(raw)["error_envelopes"], [])
        valid = b"\n".join(json.dumps({"error": {
            "code": "backend_error", "message": f"private-{i}",
        }}).encode() for i in range(8))
        summary = smoke.executor_diagnostic(valid)
        self.assertEqual(len(summary["error_envelopes"]), 4)
        self.assertNotIn("private-", json.dumps(summary))
        truncated = smoke.executor_diagnostic(b"x" * 65536 + valid)
        self.assertTrue(truncated["inspection_truncated"])
        self.assertEqual(truncated["error_envelopes"], [])

    def test_preflight_rejection_writes_source_and_nonqualification_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "nested" / "report.json"
            with mock.patch.object(smoke, "controller", side_effect=ValueError("fixed pin mismatch")), \
                    mock.patch.dict(smoke.os.environ, {"GITHUB_SHA": "A" * 40}):
                code = smoke.main(["--disposable-ci", "--executor", "wxc-exec.exe", "--manifest", "manifest.json",
                                   "--work", "unused-work", "--report", str(report)])
            self.assertEqual(code, 1)
            value = smoke.read(report)
            self.assertEqual(value["source_commit"], "a" * 40)
            for key in ("privacy_qualified", "product_acceptance", "functionality_passed"):
                self.assertIs(value[key], False)
            self.assertEqual(value["preflight_error"]["type"], "ValueError")

    def test_functional_success_requires_real_reports_exit_and_cleanup(self):
        report = passing_report()
        self.assertTrue(all(smoke.checks(report).values()))
        # The observed AppContainer bit is retained, but this functionality
        # report does not turn it into an unsupported security qualification.
        self.assertFalse(report["launcher"]["actor"]["identity"]["appcontainer"])
        mutations = [
            ("launcher_exit_code", 5), ("launcher_timed_out", True), ("error", {"type": "OSError"}),
        ]
        for key, value in mutations:
            altered = copy.deepcopy(report)
            altered[key] = value
            self.assertFalse(all(smoke.checks(altered).values()), key)
        for key in ("profile_deleted", "profile_unloaded", "desktop_closed", "station_closed"):
            altered = copy.deepcopy(report)
            altered["cleanup"]["account"][key] = False
            self.assertFalse(smoke.checks(altered)["account_cleanup"], key)
        altered = copy.deepcopy(report)
        altered["launcher"]["actor"]["child"]["identity"]["cid"] = 1
        self.assertFalse(smoke.checks(altered)["psec_child_in_cid"])
        altered = copy.deepcopy(report)
        altered["fixture_requests"]["inside"] = 0
        self.assertFalse(smoke.checks(altered)["proxy_request"])
        altered = copy.deepcopy(report)
        altered["launcher"]["probe"]["probes"] = None
        self.assertFalse(smoke.checks(altered)["psec_selected"])

    def test_executor_manifest_cannot_supply_its_own_new_hash(self):
        from ruleproxy import windows_runtime_pins as pins
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            executor, manifest = directory / "wxc-exec.exe", directory / "build-manifest.json"
            executor.write_bytes(b"different executable")
            untrusted = copy.deepcopy(pins.MXC_G_BUILD_MANIFEST)
            untrusted["executor_sha256"] = hashlib.sha256(executor.read_bytes()).hexdigest()
            smoke.save(manifest, untrusted)
            with self.assertRaisesRegex(ValueError, "fixed G artifact"):
                smoke.verify_executor(executor, manifest)


if __name__ == "__main__":
    unittest.main()
