"""UI diagnostic ownership and policy equality; no live Edge/PSEC claim."""
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("edge_policy_experiment", ROOT / ".github/windows_edge_policy_experiment.py")
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)


def baseline():
    return {"version": "1.0.0", "containment": "processcontainer", "fallback": {"allowDaclMutation": False},
            "ui": {"disable": False, "clipboard": "all"},
            "processContainer": {"ui": {"isolation": "container", "ime": True}, "untouched": False},
            "network": {"egress": {"default": "deny", "allow": [{"to": [{"cidr": "127.0.0.1/32"}],
                                                                  "ports": [{"protocol": "tcp", "port": 34567}]}]},
                        "ingress": {"default": "deny", "hostLoopback": "deny"}},
            "filesystem": {"readonlyPaths": ["owned-readonly"], "readwritePaths": ["owned-profile"]},
            "process": {"commandLine": "trusted helper", "env": ["PRIVATE_TOKEN=do-not-print-this"]}}


class UiPolicyTests(unittest.TestCase):
    def setUp(self):
        source = tempfile.TemporaryDirectory()
        self.addCleanup(source.cleanup)
        self.source = Path(source.name)
        (self.source / ".github").mkdir()
        (self.source / ".github/windows_job_context_probe.py").write_text("# owned test fixture\n")
        (self.source / ".github/windows_gui_check.py").write_text("# owned test fixture\n")
        patch = mock.patch.object(ui, "ROOT", self.source)
        patch.start()
        self.addCleanup(patch.stop)

    def test_five_fixed_presets_change_only_two_ui_fields_and_never_mutate_baseline(self):
        original_policy = baseline()
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=original_policy))
        original_function = runtime.build_policy
        for variant in ui.VARIANTS[:5]:
            requests = []
            with ui.UIOverride(runtime, variant, requests):
                policy = runtime.build_policy("command", profile="private")
                self.assertEqual(policy["processContainer"]["ui"], {"isolation": variant[1], "ime": variant[2]})
                self.assertEqual(ui.non_variant_policy(policy), ui.non_variant_policy(original_policy))
                self.assertEqual(policy["ui"], {"disable": False, "clipboard": "all"})
                self.assertEqual(policy["network"], original_policy["network"])
                self.assertTrue(requests[0]["all_other_policy_fields_unchanged"])
                self.assertNotIn("do-not-print-this", json.dumps(requests))
                self.assertNotIn("owned-profile", json.dumps(requests))
            self.assertIs(runtime.build_policy, original_function)
        self.assertEqual(original_policy, baseline())
        self.assertEqual(len(ui.VARIANTS), 6)
        self.assertEqual({variant[1] for variant in ui.VARIANTS}, {"container", "handles", "desktop"})

    def test_zero_limit_request_is_source_only_diagnostic_and_preserves_network_fs_process(self):
        policy = baseline()
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=policy))
        requests = []
        variant = ui.VARIANTS[5]
        with ui.UIOverride(runtime, variant, requests):
            changed = runtime.build_policy()
        self.assertEqual(changed["ui"], {"disable": False, "clipboard": "all", "injection": True})
        self.assertEqual(changed["processContainer"]["ui"], {"isolation": "desktop", "ime": True,
                                                              "desktopSystemControl": True, "systemSettings": "all"})
        self.assertEqual(ui.non_variant_policy(changed, variant), ui.non_variant_policy(policy, variant))
        for key in ("network", "filesystem", "process", "fallback", "containment"):
            self.assertEqual(changed[key], policy[key])
        self.assertEqual(policy, baseline())
        self.assertEqual(requests[0]["ui"], changed["ui"])
        self.assertEqual(requests[0]["processContainer"]["ui"], changed["processContainer"]["ui"])
        self.assertNotIn("actual_job_ui_limits", requests[0])

    def test_wrapped_job_workload_preserves_the_real_original_edge_policy_and_launch_inputs(self):
        from ruleproxy import windows_runtime
        original_builder = windows_runtime.build_policy
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "browser"
            command = [r"C:\Edge\msedge.exe", "--headless=new", f"--user-data-dir={profile}",
                       "--proxy-server=http://127.0.0.1:34567", "--proxy-bypass-list=<-loopback>"]
            environment = {"HTTP_PROXY": "http://127.0.0.1:34567"}
            expected = original_builder(command, environment, profile, 34567)
            launched = []
            def launch(wrapped, env, actual_profile, host_port, runtime_path, **kwargs):
                self.assertIs(env, environment)
                self.assertEqual(actual_profile, profile.resolve())
                self.assertEqual((host_port, runtime_path, kwargs), (23456, "owned-runtime", {"guest_listener_port": 34567}))
                self.assertNotEqual(wrapped, command)
                self.assertEqual(wrapped[1:5], ["-I", "-S", "-X", "utf8"])
                config = json.loads(Path(wrapped[wrapped.index("--command") + 1]).read_text())
                self.assertEqual(config["command"], command)
                self.assertEqual(config["profile"], str(profile.resolve()))
                self.assertEqual(config["proxy_port"], 34567)
                self.assertEqual(len(config["nonce"]), 64)
                actual = windows_runtime.build_policy(wrapped, env, actual_profile, kwargs["guest_listener_port"])
                launched.append(actual)
                return "wrapper", "resources"
            requests = []
            with mock.patch.object(windows_runtime, "launch", side_effect=launch) as original_launch:
                with ui.UIOverride(windows_runtime, ui.VARIANTS[1], requests, observe_jobs=True):
                    value = windows_runtime.launch(command, environment, profile, 23456, "owned-runtime", guest_listener_port=34567)
                self.assertIs(windows_runtime.launch, original_launch)
            self.assertEqual(value, ("wrapper", "resources"))
            self.assertIs(windows_runtime.build_policy, original_builder)
            self.assertEqual(ui.non_variant_policy(launched[0]), ui.non_variant_policy(expected))
            self.assertEqual(launched[0]["filesystem"], expected["filesystem"])
            self.assertTrue(requests[0]["workload_wrapped_for_job_observation"])
            self.assertEqual(command[0], r"C:\Edge\msedge.exe")

    def test_real_job_api_report_is_scoped_to_test_wrapper_and_nonce_not_an_assumed_zero(self):
        nonce = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "job.json"
            value = {"schema_version": 1, "nonce": nonce, "scope": "actual_test_app_wrapper_innermost_job",
                     "pid": 123, "parent_pid": 100,
                     "job_context": {"status": "observed", "is_process_in_job": True,
                                     "is_process_in_job_error": None, "ui_restrictions": 4,
                                     "query_ui_restrictions_error": None, "query_return_length": 4}, "edge_launched": True,
                     "edge_exit_code": 3221225477, "edge_exit_code_hex": "0xC0000005", "edge_launch_error": None,
                     "acceptance_passed": False, "browser_sandbox_weakened": False}
            report.write_text(json.dumps(value))
            override = SimpleNamespace(jobs=[(report, nonce)])
            observed = {}
            ui.add_job_context(observed, override)
            self.assertTrue(observed["actual_job_ui_limits_verified"])
            self.assertFalse(observed["app_wrapper_zero_ui_limits_observed"])
            self.assertNotIn("nonce", observed["job_context"][0]["reported_context"])
            value["job_context"]["ui_restrictions"] = 0
            report.write_text(json.dumps(value))
            ui.add_job_context(observed, override)
            self.assertTrue(observed["app_wrapper_zero_ui_limits_observed"])
            value["nonce"] = "b" * 64
            report.write_text(json.dumps(value))
            with self.assertRaises(ui.DiagnosticError):
                ui.job_context_observations(override)
            value["nonce"] = nonce
            value["extra_private_path"] = "never serialize this"
            report.write_text(json.dumps(value))
            with self.assertRaises(ui.DiagnosticError):
                ui.job_context_observations(override)

    def test_incomplete_job_api_or_missing_report_cannot_prove_zero_limits(self):
        nonce = "a" * 64
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "job.json"
            override = SimpleNamespace(jobs=[(report, nonce)])
            observed = {}
            ui.add_job_context(observed, override)
            self.assertFalse(observed["actual_job_ui_limits_verified"])
            self.assertFalse(observed["app_wrapper_zero_ui_limits_observed"])
            value = {"schema_version": 1, "nonce": nonce, "scope": "actual_test_app_wrapper_innermost_job",
                     "pid": 123, "parent_pid": 100,
                     "job_context": {"status": "incomplete", "is_process_in_job": None,
                                     "is_process_in_job_error": 5, "ui_restrictions": None,
                                     "query_ui_restrictions_error": 5, "query_return_length": None}, "edge_launched": False,
                     "edge_exit_code": None, "edge_exit_code_hex": None, "edge_launch_error": None,
                     "acceptance_passed": False, "browser_sandbox_weakened": False}
            report.write_text(json.dumps(value))
            ui.add_job_context(observed, override)
            self.assertFalse(observed["actual_job_ui_limits_verified"])
            value["job_context"]["status"] = "observed"
            report.write_text(json.dumps(value))
            with self.assertRaises(ui.DiagnosticError):
                ui.job_context_observations(override)

    def test_exception_restores_builder_and_rejects_non_fixed_ui_requests(self):
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()))
        original = runtime.build_policy
        with self.assertRaisesRegex(RuntimeError, "crash"):
            with ui.UIOverride(runtime, ui.VARIANTS[1], []):
                runtime.build_policy()
                raise RuntimeError("crash")
        self.assertIs(runtime.build_policy, original)
        for variant in (("anything", "none", False), ("handles_ime", "handles", 1)):
            with self.assertRaises(ValueError):
                ui.UIOverride(runtime, variant, [])

    def test_different_production_clipboard_or_isolation_is_a_tool_error(self):
        for field in ("clipboard", "isolation"):
            policy = baseline()
            if field == "clipboard":
                policy["ui"][field] = "none"
            else:
                policy["processContainer"]["ui"][field] = "handles"
            runtime = SimpleNamespace(build_policy=mock.Mock(return_value=policy))
            original = runtime.build_policy
            with self.assertRaises(ui.DiagnosticError):
                with ui.UIOverride(runtime, ui.VARIANTS[0], []):
                    runtime.build_policy()
            self.assertIs(runtime.build_policy, original)

    def test_unexpected_builder_replacement_is_detected_and_original_restored(self):
        runtime = SimpleNamespace(build_policy=lambda: baseline())
        original = runtime.build_policy
        with self.assertRaises(ui.DiagnosticError):
            with ui.UIOverride(runtime, ui.VARIANTS[0], []):
                runtime.build_policy = lambda: {"bad": True}
        self.assertIs(runtime.build_policy, original)

    def test_insufficient_complete_budget_starts_no_fixture_or_process(self):
        browser = mock.Mock()
        entry = ui.run_variant(ui.VARIANTS[0], mock.Mock(), None, None, browser, time.monotonic() + 300)
        self.assertEqual(entry["status"], "budget_not_started")
        self.assertIs(entry["no_process_started"], True)
        self.assertIs(entry["cleanup_proven"], True)
        self.assertIs(entry["single_launch_fixture_passed"], False)
        browser.BrowserFixture.assert_not_called()

    def browser(self, runtime, *, fail=False, cleanup_fail=False, publish_context=True, exit_code=None):
        process = mock.Mock()
        process.poll.return_value = exit_code if exit_code is not None else 3221225477 if fail else 0
        class BrowserRun:
            def __init__(self, *arguments):
                self.wrapper = self.resources = None
                self.safe_close_count = 0
                self.profile = arguments[2] / "browser"

            def run(self, phase, timeout):
                self.wrapper = process
                self.resources = mock.Mock()
                runtime.launch([r"C:\Edge\msedge.exe", "--headless=new", "--proxy-server=http://127.0.0.1:34567"],
                               {"HTTP_PROXY": "http://127.0.0.1:34567"}, self.profile, 23456,
                               "owned-runtime", guest_listener_port=34567)
                if fail:
                    raise RuntimeError("real Edge/MXC workload exited with status 3221225477")
                self.close()
                return {"check": "real_edge_launch_1", "status": "passed", "natural_headless_exit": True,
                        "dom_nonce_via_page_ack": True, "cookie_request_verified": True, "private_profile_reused": False}

            def close(self):
                self.safe_close_count += 1
                if cleanup_fail:
                    raise RuntimeError("safe stop retained owned handles")
                self.wrapper = self.resources = None
        browser = SimpleNamespace(BrowserRun=BrowserRun, BrowserFixture=mock.Mock(return_value=mock.Mock()))
        def launch(command, env, profile, port, path, **kwargs):
            policy = runtime.build_policy(command, env, profile, kwargs["guest_listener_port"])
            if publish_context:
                config = json.loads(Path(command[command.index("--command") + 1]).read_text())
                raw = process.poll.return_value & 0xffffffff
                report = {"schema_version": 1, "nonce": config["nonce"], "scope": "actual_test_app_wrapper_innermost_job",
                    "pid": 123, "parent_pid": 100, "job_context": {"status": "observed", "is_process_in_job": True,
                    "is_process_in_job_error": None, "ui_restrictions": 4, "query_ui_restrictions_error": None,
                    "query_return_length": 4}, "edge_launched": True, "edge_exit_code": raw,
                    "edge_exit_code_hex": f"0x{raw:08X}", "edge_launch_error": None,
                    "acceptance_passed": False, "browser_sandbox_weakened": False}
                Path(command[command.index("--report") + 1]).write_text(json.dumps(report))
            return policy
        runtime.launch = mock.Mock(side_effect=launch)
        return browser, process

    def test_missing_context_after_actual_wrapper_exit_one_is_a_tool_failure_with_safe_cleanup(self):
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()))
        browser, process = self.browser(runtime, fail=True, publish_context=False, exit_code=1)
        entry = ui.run_variant(ui.VARIANTS[0], runtime, None, None, browser, time.monotonic() + 600)
        self.assertEqual(entry["status"], "failed")
        self.assertTrue(entry["tool_error"])
        self.assertEqual(entry["job_context_error"], "ObserverReportMissing")
        self.assertEqual(entry["edge_mxc_wrapper_exit_code"], 1)
        self.assertTrue(entry["cleanup_proven"])
        self.assertFalse(entry["actual_job_ui_limits_verified"])
        self.assertFalse(entry["app_wrapper_zero_ui_limits_observed"])
        process.kill.assert_not_called()

    def test_sdk_stdout_capture_is_exact_and_only_fixed_bounded_facts_leave_private_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "browser"
            facts = {"stage": "validate_profile_resolve", "errno": 13, "winerror": 5, "class": "PermissionError"}
            def create(arguments, *positional, **options):
                if len(arguments) == 3 and "--config" in arguments:
                    self.assertEqual(options["stderr"], ui.subprocess.STDOUT)
                    options["stdout"].write(b"PRIVATE_PATH PRIVATE_COMMAND PRIVATE_NONCE\n")
                    options["stdout"].write((json.dumps(facts) + "\n").encode())
                else:
                    self.assertEqual(options["stdout"], ui.subprocess.PIPE)
                    self.assertEqual(options["stderr"], ui.subprocess.PIPE)
                return mock.Mock()
            def launch(command, env, actual_profile, port, runtime_path, **kwargs):
                ui.subprocess.Popen([runtime_path, "--config", "owned-policy", "--probe"], shell=False,
                                    stdout=ui.subprocess.PIPE, stderr=ui.subprocess.PIPE)
                ui.subprocess.Popen([runtime_path, "--config", "owned-policy"], shell=False)
                return "wrapper", "resources"
            runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()), launch=launch)
            with mock.patch.object(ui.subprocess, "Popen", side_effect=create) as original_popen:
                with ui.UIOverride(runtime, ui.VARIANTS[0], [], observe_jobs=True) as override:
                    runtime.launch([r"C:\Edge\msedge.exe"], {}, profile, 1234, "owned-sdk", guest_listener_port=34567)
                self.assertIs(ui.subprocess.Popen, original_popen)
            with mock.patch("builtins.print"):
                observed = ui.job_stdout_facts(override)
            self.assertTrue(observed["captured"])
            self.assertEqual(observed["failure_facts"], [facts])
            self.assertFalse(observed["truncated"])
            for private in ("PRIVATE_PATH", "PRIVATE_COMMAND", "PRIVATE_NONCE", str(profile)):
                self.assertNotIn(private, json.dumps(observed))

    def test_precise_opened_name_failure_is_retained_by_the_fixed_stdout_schema(self):
        spec = importlib.util.spec_from_file_location("job_context_failure_contract", ROOT / ".github/windows_job_context_probe.py")
        probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(probe)
        self.assertEqual(ui.JOB_FAILURE_STAGES, probe.FAILURE_STAGES)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "private-stdout.log"
            facts = {"stage": "validate_profile_opened_name", "errno": 13, "winerror": 5, "class": "PermissionError"}
            path.write_text(json.dumps(facts) + "\n")
            with mock.patch("builtins.print"):
                value = ui.job_stdout_facts(SimpleNamespace(job_stdout=[path]))
            self.assertEqual(value["failure_facts"], [facts])

    def test_access_violation_is_observed_as_actual_exit_and_clean_case_can_continue(self):
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()))
        browser, process = self.browser(runtime, fail=True)
        original = runtime.build_policy
        entry = ui.run_variant(ui.VARIANTS[0], runtime, None, None, browser, time.monotonic() + 600)
        self.assertEqual(entry["status"], "observed")
        self.assertEqual(entry["edge_mxc_wrapper_exit_code"], 3221225477)
        self.assertEqual(entry["edge_mxc_wrapper_exit_hex"], "0xC0000005")
        self.assertFalse(entry["single_launch_fixture_passed"])
        self.assertTrue(entry["cleanup_proven"])
        self.assertIs(runtime.build_policy, original)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        process._handle.Close.assert_called_once()

    def test_single_phase_pass_does_not_claim_persistent_cookie_or_two_phase_browser(self):
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()))
        browser, process = self.browser(runtime)
        entry = ui.run_variant(ui.VARIANTS[1], runtime, None, None, browser, time.monotonic() + 600)
        self.assertTrue(entry["single_launch_fixture_passed"])
        self.assertFalse(entry["persistent_cookie_verified"])
        self.assertEqual(entry["edge_mxc_wrapper_exit_code"], 0)
        self.assertEqual(len(entry["checks"]), 1)
        self.assertFalse(entry["checks"][0]["private_profile_reused"])
        self.assertTrue(entry["cleanup_proven"])
        process._handle.Close.assert_called_once()

    def test_cleanup_failure_retains_actual_owner_fixture_and_profile(self):
        runtime = SimpleNamespace(build_policy=mock.Mock(return_value=baseline()))
        browser, process = self.browser(runtime, fail=True, cleanup_fail=True)
        retained_count = len(ui._RECOVERY_OWNERS)
        with tempfile.TemporaryDirectory() as temporary:
            profile = Path(temporary) / "retained"
            profile.mkdir()
            try:
                with mock.patch.object(ui.tempfile, "mkdtemp", return_value=str(profile)), \
                        mock.patch.object(ui.shutil, "rmtree") as remove:
                    entry = ui.run_variant(ui.VARIANTS[0], runtime, None, None, browser, time.monotonic() + 600)
                self.assertFalse(entry["cleanup_proven"])
                self.assertEqual(entry["recovery_directory"], str(profile))
                self.assertIs(ui._RECOVERY_OWNERS[-1][0].wrapper, process)
                self.assertEqual(ui._RECOVERY_OWNERS[-1][0].retained_processes, [process])
                remove.assert_not_called()
                process._handle.Close.assert_not_called()
                process.kill.assert_not_called()
            finally:
                del ui._RECOVERY_OWNERS[retained_count:]

    def test_optional_gui_never_starts_without_pass_or_complete_budget(self):
        facts = {"native_machine": 0x8664, "python_pe_machine": 0x8664}
        with mock.patch.object(ui, "source_module") as load:
            result = ui.optional_gui([], facts, None, None, None, None, None, time.monotonic() + 600)
            self.assertFalse(result["single_visible_gui_observed"])
            self.assertEqual(result["reason"], "no_single_launch_preset_passed")
            result = ui.optional_gui([{"id": "handles_ime", "single_launch_fixture_passed": True}],
                                     facts, None, None, None, None, None, time.monotonic() + 300)
            self.assertEqual(result["status"], "budget_not_started")
            load.assert_not_called()

    def main_fixture(self, root):
        browser = mock.Mock()
        helpers = browser.acceptance_helpers.return_value
        helpers.host_facts.return_value = {"windows_product_type": 1, "native_machine": 0x8664,
                                           "python_pe_machine": 0x8664}
        helpers.verify_runtime_manifest.return_value = {}
        helpers.executable_machine.return_value = 0x8664
        helpers.acceptance_scope.return_value = "native_x64"
        helpers.network_snapshot.return_value = {"unchanged": True}
        helpers.write_json.side_effect = lambda path, value: path.write_text(json.dumps(value))
        return browser, helpers

    def test_executor_selection_preserves_default_and_rejects_unpaired_inputs(self):
        root = Path("owned-package")
        with mock.patch.object(ui, "source_module") as load:
            self.assertEqual(ui.diagnostic_runtime(root, {}), (root / "bin/windows-amd64/wxc-exec.exe", None))
            for executor, manifest in ((Path("candidate.exe"), None), (None, Path("manifest.json"))):
                with self.assertRaises(ValueError):
                    ui.diagnostic_runtime(root, {}, executor, manifest)
            load.assert_not_called()

    def test_crash_reader_requires_one_published_nonce_bound_observed_generation(self):
        with mock.patch.object(ui, "source_module") as load:
            for values in ([], [{"published": False}], [{"published": True, "reported_context": {}}],
                    [{"published": True, "reported_context": {"edge_identity": {"status": "incomplete"}}}]):
                self.assertEqual(ui.collect_edge_crash_evidence(values)["reason"], "nonce_bound_edge_generation_unavailable")
            load.assert_not_called()
            identity = {"status": "observed"}
            with self.assertRaises(ui.DiagnosticError):
                ui.collect_edge_crash_evidence([{"published": True, "reported_context": {"edge_identity": identity}}] * 2)
            load.assert_not_called()

    def test_crash_reader_uses_exact_filetime_and_retains_unclosed_owned_reader(self):
        identity = {"status": "observed", "process_created": 134101234567890120, "pid": 123}
        values = [{"published": True, "reported_context": {"edge_identity": identity}}]
        collector = mock.Mock()
        evidence = {"status": "incomplete", "reader_cleanup_proven": False, "acceptance_passed": False}
        collector.collect_crash_events.return_value = evidence
        before = list(ui._RECOVERY_OWNERS)
        try:
            with mock.patch.object(ui, "source_module", return_value=collector):
                self.assertIs(ui.collect_edge_crash_evidence(values), evidence)
            collector.validate_identity.assert_called_once_with(identity)
            call = collector.collect_crash_events.call_args
            self.assertIs(call.args[0], identity)
            expected = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(microseconds=identity["process_created"] // 10)
            self.assertEqual(call.args[1], expected)
            self.assertEqual(call.args[2].tzinfo, dt.timezone.utc)
            self.assertIs(ui._RECOVERY_OWNERS[-1], collector)
        finally:
            ui._RECOVERY_OWNERS[:] = before

    def test_invalid_edge_identity_is_rejected_before_reading_events(self):
        values = [{"published": True, "reported_context": {"edge_identity": {"status": "observed", "process_created": 1}}}]
        collector = mock.Mock()
        collector.validate_identity.side_effect = ValueError("wrong generation")
        with mock.patch.object(ui, "source_module", return_value=collector), self.assertRaises(ValueError):
            ui.collect_edge_crash_evidence(values)
        collector.collect_crash_events.assert_not_called()

    def test_verified_candidate_reaches_only_diagnostic_variants_and_stays_separate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report, executor, manifest = (root / name for name in ("report.json", "candidate.exe", "manifest.json"))
            browser, helpers = self.main_fixture(root)
            original_digest = "a" * 64
            helpers.verify_runtime_manifest.return_value = {"wxc-exec.exe": original_digest}
            verifier = mock.Mock()
            metadata = {"source_only_executor_changed": True, "default_product_runtime_replaced": False,
                        "original_runtime_sha256": original_digest, "acceptance_passed": False}
            verifier.verify_test_executor.return_value = (executor, metadata)
            entries = [{"id": variant[0], "status": "observed", "cleanup_proven": True,
                        "single_launch_fixture_passed": False, "requests": [{}]} for variant in ui.VARIANTS]
            def source(name):
                return verifier if name == "windows_network_experiment" else browser
            with mock.patch.object(ui.sys, "platform", "win32"), \
                    mock.patch.object(ui, "source_module", side_effect=source), \
                    mock.patch.object(ui, "run_variant", side_effect=entries) as run, mock.patch("builtins.print"):
                self.assertEqual(ui.main(["--root", str(root), "--report", str(report),
                    "--test-psec-executor", str(executor), "--test-psec-manifest", str(manifest)]), 0)
            verifier.verify_test_executor.assert_called_once_with(root.resolve(), executor, manifest, original_digest)
            self.assertEqual(run.call_count, len(ui.VARIANTS))
            self.assertTrue(all(call.args[2] == executor for call in run.call_args_list))
            value = json.loads(report.read_text())
            self.assertTrue(value["source_only_executor_changed"])
            self.assertEqual(value["test_psec_executor"], metadata)
            for key in ("default_product_runtime_replaced", "production_policy_changed", "browser_fixture_passed",
                        "gui_fixture_passed", "acceptance_passed", "full_acceptance_passed", "real_node_passed"):
                self.assertIs(value[key], False)

    def test_rejected_candidate_cannot_launch_edge_or_get_a_success_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            browser, _ = self.main_fixture(root)
            verifier = mock.Mock()
            verifier.verify_test_executor.side_effect = ValueError("manifest rejected")
            with mock.patch.object(ui.sys, "platform", "win32"), \
                    mock.patch.object(ui, "source_module", side_effect=lambda name:
                        verifier if name == "windows_network_experiment" else browser), \
                    mock.patch.object(ui, "run_variant") as run, mock.patch("builtins.print"):
                self.assertEqual(ui.main(["--root", str(root), "--report", str(report),
                    "--test-psec-executor", str(root / "candidate.exe"),
                    "--test-psec-manifest", str(root / "manifest.json")]), 1)
            run.assert_not_called()
            browser.find_edge.assert_not_called()
            self.assertEqual(json.loads(report.read_text())["status"], "failed")

    def test_all_browser_failures_still_collect_and_never_promote_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "nested/report.json"
            browser, helpers = self.main_fixture(root)
            entries = [{"id": variant[0], "status": "observed", "cleanup_proven": True,
                        "single_launch_fixture_passed": False, "requests": [{"actual": True}]} for variant in ui.VARIANTS]
            with mock.patch.object(ui.sys, "platform", "win32"), \
                    mock.patch.object(ui, "source_module", return_value=browser), \
                    mock.patch.object(ui, "run_variant", side_effect=entries) as run, \
                    mock.patch("builtins.print"):
                self.assertEqual(ui.main(["--root", str(root), "--report", str(report)]), 0)
            result = json.loads(report.read_text())
            self.assertEqual(result["status"], "experiment_only")
            self.assertEqual(run.call_count, 6)
            self.assertTrue(result["cleanup_proven"])
            self.assertEqual(result["ui_variant_requests_collected"], 6)
            for key in ("browser_fixture_passed", "gui_fixture_passed", "acceptance_passed", "full_acceptance_passed",
                        "real_node_passed", "public_udp_proven", "system_dns_proven"):
                self.assertIs(result[key], False)

    def test_cleanup_failure_blocks_every_later_variant_and_gui(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = root / "report.json"
            browser, helpers = self.main_fixture(root)
            entry = {"id": ui.VARIANTS[0][0], "cleanup_proven": False, "cleanup_error": "alive",
                     "recovery_directory": "owned recovery"}
            with mock.patch.object(ui.sys, "platform", "win32"), \
                    mock.patch.object(ui, "source_module", return_value=browser), \
                    mock.patch.object(ui, "run_variant", return_value=entry) as run, \
                    mock.patch.object(ui, "optional_gui") as gui, mock.patch("builtins.print"):
                self.assertEqual(ui.main(["--root", str(root), "--report", str(report)]), 1)
            result = json.loads(report.read_text())
            self.assertFalse(result["cleanup_proven"])
            self.assertEqual(result["recovery_directory"], "owned recovery")
            self.assertEqual(run.call_count, 1)
            gui.assert_not_called()

    def test_collector_error_or_changed_host_snapshot_fails_without_fake_recovery(self):
        for failure in ("tool", "snapshot"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = root / "report.json"
                browser, helpers = self.main_fixture(root)
                entry = {"id": ui.VARIANTS[0][0], "cleanup_proven": True, "single_launch_fixture_passed": False}
                if failure == "tool":
                    entry["tool_error"] = True
                else:
                    helpers.network_snapshot.side_effect = [{"before": True}, {"after": True}]
                with mock.patch.object(ui.sys, "platform", "win32"), \
                        mock.patch.object(ui, "source_module", return_value=browser), \
                        mock.patch.object(ui, "run_variant", return_value=entry), mock.patch("builtins.print"):
                    self.assertEqual(ui.main(["--root", str(root), "--report", str(report)]), 1)
                result = json.loads(report.read_text())
                self.assertEqual(result["status"], "failed")
                self.assertTrue(result["cleanup_proven"])
                self.assertNotIn("recovery_directory", result)


if __name__ == "__main__":
    unittest.main()
