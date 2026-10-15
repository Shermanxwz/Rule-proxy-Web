"""Observe stock Edge with fixed test-only PSEC UI presets, without product changes.

Use package x64 Python: --root PACKAGE --report edge-ui.json [--allow-emulated-x64].
Each preset uses a fresh private profile and one existing BrowserRun phase 1.
The shared 600-second scheduling budget reserves the existing startup bounds,
45 seconds for natural headless exit, safe cleanup, and the final host snapshot.
Unstarted cases are explicit. A completed collection can contain only failures;
exit 0 and experiment_only never establish browser or full acceptance.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import secrets
import re
import shutil
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
VARIANTS = (
    ("container_ime", "container", True),
    ("handles_ime", "handles", True),
    ("desktop_ime", "desktop", True),
    ("container_no_ime", "container", False),
    ("handles_no_ime", "handles", False),
    ("ui_no_job_limits", "desktop", True),
)
LIMIT_SECONDS = 600
STARTUP_RESERVE = 110  # Existing probe20 + bridge45 + app20 + failure12 + controls.
BROWSER_TIMEOUT = 45
CLEANUP_RESERVE = 25  # Existing production stop15 plus local fixture/resource closure.
FINAL_RESERVE = 125  # Existing read-only network snapshot120 plus report publication.
_RECOVERY_OWNERS = []
JOB_FAILURE_STAGES = frozenset({"read_config", "validate_schema", "validate_profile_exists", "validate_profile_resolve",
    "validate_report_parent", "validate_report_identity", "validate_report_reparse", "validate_command",
    "validate_executable", "validate_user_data_dir", "validate_proxy_server", "validate_proxy_bypass",
    "validate_argument", "validate_required_arguments", "query_job", "publish_initial", "launch",
    "publish_started", "wait", "publish_result", "validate_directory_close"}) | frozenset(
    f"{role}_{operation}" for role in ("validate_profile", "validate_config_parent", "validate_report_parent",
                                      "validate_report_file", "validate_config_file", "validate_script_file",
                                      "validate_user_data_dir")
    for operation in ("open", "attributes", "identity", "opened_name"))


class DiagnosticError(RuntimeError):
    """A collector invariant failed, rather than an observed Edge outcome."""


def source_module(name):
    path = ROOT / ".github" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"ruleproxy_edge_ui_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def non_variant_policy(policy, variant=None):
    value = copy.deepcopy(policy)
    ui = value["processContainer"]["ui"]
    ui.pop("isolation", None)
    ui.pop("ime", None)
    if variant is not None and variant[0] == "ui_no_job_limits":
        value["ui"].pop("injection", None)
        ui.pop("desktopSystemControl", None)
        ui.pop("systemSettings", None)
    return value


def policy_digest(policy):
    return hashlib.sha256(json.dumps(policy, sort_keys=True, ensure_ascii=True,
                                     separators=(",", ":")).encode("ascii")).hexdigest()


class UIOverride:
    """Override only this diagnostic process's policy builder, then restore it."""

    def __init__(self, runtime_module, variant, requests, *, observe_jobs=False):
        if variant not in VARIANTS or type(variant[2]) is not bool:
            raise ValueError("only the fixed UI presets are allowed")
        self.runtime, self.variant, self.requests = runtime_module, variant, requests
        self.original = None
        self.observe_jobs = observe_jobs
        self.jobs = []
        self.job_stdout = []
        self.original_edge_command = self.wrapped_command = None
        self.job_source_sha256 = None

    def __enter__(self):
        self.original = self.runtime.build_policy
        self.original_launch = self.runtime.launch if self.observe_jobs else None
        def build(*args, **kwargs):
            if self.wrapped_command is not None:
                if not args or list(args[0]) != self.wrapped_command:
                    raise DiagnosticError("job observer policy command did not match the owned launch")
                # The helper policy commandLine is independent of app argv.
                # Only original Edge argv determines its readonly exe directory.
                args = (list(self.original_edge_command), *args[1:])
            original = self.original(*args, **kwargs)
            if original.get("ui") != {"disable": False, "clipboard": "all"} \
                    or original.get("processContainer", {}).get("ui") != {"isolation": "container", "ime": True}:
                raise DiagnosticError("production UI policy differs from the fixed diagnostic baseline")
            policy = copy.deepcopy(original)
            policy["processContainer"]["ui"]["isolation"] = self.variant[1]
            policy["processContainer"]["ui"]["ime"] = self.variant[2]
            if self.variant[0] == "ui_no_job_limits":
                policy["ui"]["injection"] = True
                policy["processContainer"]["ui"].update(desktopSystemControl=True, systemSettings="all")
            baseline = non_variant_policy(original, self.variant)
            if non_variant_policy(policy, self.variant) != baseline:
                raise DiagnosticError("a field outside the fixed UI preset changed")
            if len(self.requests) >= 4:
                raise DiagnosticError("unexpected repeated policy builds in one UI case")
            # Full policy hashes preserve equality evidence without exposing
            # inherited environment values, paths or the private profile.
            self.requests.append({"ui": copy.deepcopy(policy["ui"]),
                                  "processContainer": {"ui": copy.deepcopy(policy["processContainer"]["ui"])},
                                  "containment": policy.get("containment"),
                                  "version": policy.get("version"),
                                  "fallback": copy.deepcopy(policy.get("fallback")),
                                  "network": copy.deepcopy(policy.get("network")),
                                  "filesystem_readonly_count": len(policy["filesystem"]["readonlyPaths"]),
                                  "filesystem_readwrite_count": len(policy["filesystem"]["readwritePaths"]),
                                  "request_sha256": policy_digest(policy),
                                  "non_variant_policy_sha256": policy_digest(baseline),
                                  "workload_wrapped_for_job_observation": self.wrapped_command is not None,
                                  "job_observer_source_sha256": self.job_source_sha256,
                                  "all_other_policy_fields_unchanged": True})
            return policy
        self.replacement = build
        self.runtime.build_policy = build
        if self.observe_jobs:
            def launch(command, env, profile, proxy_port, runtime_path, **kwargs):
                if self.jobs or not command or ntpath.basename(command[0]).lower() != "msedge.exe":
                    raise DiagnosticError("job observer requires one exact prepared Edge launch")
                port = kwargs.get("guest_listener_port")
                if type(port) is not int or not 1 <= port <= 65535:
                    raise DiagnosticError("job observer requires the actual guest listener port")
                profile = Path(profile).resolve()
                profile.mkdir(parents=True, exist_ok=True)
                source = ROOT / ".github/windows_job_context_probe.py"
                script = profile / "ruleproxy-job-context-probe.py"
                config = profile / "ruleproxy-job-command.json"
                report = profile / "ruleproxy-job-context.json"
                nonce = secrets.token_hex(32)
                raw = source.read_bytes()
                self.job_source_sha256 = hashlib.sha256(raw).hexdigest()
                with script.open("xb") as stream:
                    stream.write(raw)
                with config.open("x", encoding="utf-8") as stream:
                    json.dump({"schema_version": 1, "nonce": nonce, "command": list(command),
                               "proxy_port": port, "profile": str(profile)}, stream, ensure_ascii=True)
                self.original_edge_command = list(command)
                self.wrapped_command = [sys.executable, "-I", "-S", "-X", "utf8", str(script),
                                        "--command", str(config), "--report", str(report)]
                self.jobs.append((report, nonce))
                # Only app argv changes. Environment, profile, ports, provider,
                # and all builder kwargs keep the original prepared values.
                # Capture only this source diagnostic's exact SDK launch.
                # Probe subprocesses keep their original stdio; raw SDK output
                # remains private and is discarded after bounded fact parsing.
                output_path = profile / "ruleproxy-job-stdout.log"
                self.job_stdout.append(output_path)
                original_popen = subprocess.Popen
                captured = False
                with output_path.open("xb") as output:
                    def popen(arguments, *positional, **options):
                        nonlocal captured
                        if isinstance(arguments, (list, tuple)) and len(arguments) == 3 \
                                and str(arguments[0]) == str(runtime_path) and arguments[1] == "--config":
                            if captured or "stdout" in options or "stderr" in options:
                                raise DiagnosticError("unexpected SDK stdio while observing the owned test wrapper")
                            captured = True
                            options.update(stdout=output, stderr=subprocess.STDOUT)
                        return original_popen(arguments, *positional, **options)
                    subprocess.Popen = popen
                    try:
                        return self.original_launch(self.wrapped_command, env, profile, proxy_port, runtime_path, **kwargs)
                    finally:
                        changed = subprocess.Popen is not popen
                        subprocess.Popen = original_popen
                        if changed:
                            raise DiagnosticError("diagnostic process launcher changed unexpectedly")
            self.launch_replacement = launch
            self.runtime.launch = launch
        return self

    def __exit__(self, exc_type, exc, traceback):
        changed = self.runtime.build_policy is not self.replacement
        self.runtime.build_policy = self.original
        if self.observe_jobs:
            changed = changed or self.runtime.launch is not self.launch_replacement
            self.runtime.launch = self.original_launch
        if changed:
            raise DiagnosticError("diagnostic policy builder changed unexpectedly before restoration")


def budget_available(deadline, browser_seconds=BROWSER_TIMEOUT):
    return deadline - time.monotonic() >= STARTUP_RESERVE + browser_seconds + CLEANUP_RESERVE + FINAL_RESERVE


def requested_ui(variant):
    value = {"ui": {"disable": False, "clipboard": "all"},
             "processContainer": {"ui": {"isolation": variant[1], "ime": variant[2]}}}
    if variant[0] == "ui_no_job_limits":
        value["ui"]["injection"] = True
        value["processContainer"]["ui"].update(desktopSystemControl=True, systemSettings="all")
    return value


def job_context_observations(override):
    values = []
    for path, nonce in override.jobs:
        try:
            with path.open("rb") as stream:
                raw = stream.read(64 * 1024 + 1)
            if not raw or len(raw) > 64 * 1024:
                raise DiagnosticError("job context report exceeds its fixed bound")
            def unique(pairs):
                value = {}
                for key, item in pairs:
                    if key in value:
                        raise DiagnosticError("job context report contains duplicate fields")
                    value[key] = item
                return value
            value = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
            fields = {"schema_version", "nonce", "scope", "pid", "parent_pid", "job_context", "edge_launched",
                      "edge_exit_code", "edge_exit_code_hex", "edge_launch_error", "acceptance_passed", "browser_sandbox_weakened"}
            if not isinstance(value, dict) or set(value) != fields or type(value["schema_version"]) is not int \
                    or value["schema_version"] != 1 or value["nonce"] != nonce \
                    or value["scope"] != "actual_test_app_wrapper_innermost_job" \
                    or any(type(value[key]) is not int or value[key] <= 0 for key in ("pid", "parent_pid")) \
                    or type(value["edge_launched"]) is not bool \
                    or value["acceptance_passed"] is not False or value["browser_sandbox_weakened"] is not False:
                raise DiagnosticError("job context report does not match the owned command nonce")
            context = value["job_context"]
            context_fields = {"status", "is_process_in_job", "is_process_in_job_error", "ui_restrictions",
                              "query_ui_restrictions_error", "query_return_length"}
            if not isinstance(context, dict) or set(context) not in (context_fields, context_fields | {"error"}) \
                    or context["status"] not in ("observed", "incomplete") \
                    or (context["is_process_in_job"] is not None and type(context["is_process_in_job"]) is not bool) \
                    or any(item is not None and (type(item) is not int or not 0 <= item <= 0xffffffff)
                           for item in (context["is_process_in_job_error"], context["ui_restrictions"],
                                        context["query_ui_restrictions_error"], context["query_return_length"])) \
                    or ("error" in context and (context["status"] != "incomplete" or not isinstance(context["error"], str)
                                                  or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", context["error"]))):
                raise DiagnosticError("job context API fields are invalid")
            if context["status"] == "observed" and (context["is_process_in_job"] is not True
                    or context["is_process_in_job_error"] is not None or context["query_ui_restrictions_error"] is not None
                    or type(context["ui_restrictions"]) is not int or context["query_return_length"] != 4):
                raise DiagnosticError("job context observation lacks completed API results")
            code = value["edge_exit_code"]
            if (code is not None and (type(code) is not int or not -0x80000000 <= code <= 0xffffffff)) \
                    or (code is None and value["edge_exit_code_hex"] is not None) \
                    or (code is not None and value["edge_exit_code_hex"] != f"0x{code & 0xffffffff:08X}") \
                    or (value["edge_launch_error"] is not None and (type(value["edge_launch_error"]) is not str
                                                                    or len(value["edge_launch_error"]) > 1000)):
                raise DiagnosticError("job context Edge exit fields are invalid")
            value = dict(value)
            value.pop("nonce")
            values.append({"published": True, "nonce_sha256": hashlib.sha256(bytes.fromhex(nonce)).hexdigest(),
                           "reported_context": value})
        except FileNotFoundError:
            values.append({"published": False, "reason": "contained_app_context_was_not_published"})
    return values


def job_stdout_facts(override):
    facts, truncated = [], False
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate fixed stdout fact")
            value[key] = item
        return value
    for path in getattr(override, "job_stdout", []):
        with path.open("rb") as stream:
            raw = stream.read(64 * 1024 + 1)
        truncated = truncated or len(raw) > 64 * 1024
        for line in raw[:64 * 1024].splitlines():
            if len(line) > 1024:
                continue
            try:
                value = json.loads(line, object_pairs_hook=unique)
            except (ValueError, UnicodeError):
                continue
            if (not isinstance(value, dict) or set(value) != {"stage", "errno", "winerror", "class"}
                    or not isinstance(value["stage"], str) or value["stage"] not in JOB_FAILURE_STAGES
                    or not isinstance(value["class"], str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", value["class"])
                    or any(value[key] is not None and (type(value[key]) is not int
                        or not -0x80000000 <= value[key] <= 0xffffffff) for key in ("errno", "winerror"))):
                continue
            if len(facts) < 8:
                facts.append(value)
                print(json.dumps(value, ensure_ascii=True, separators=(",", ":")), flush=True)
            else:
                truncated = True
    return {"captured": bool(getattr(override, "job_stdout", [])), "truncated": truncated, "failure_facts": facts}


def add_job_context(observation, override):
    observation["job_observer_stdout"] = job_stdout_facts(override)
    values = job_context_observations(override)
    observation["job_context"] = values
    completed = [entry["reported_context"]["job_context"] for entry in values if entry.get("published") is True
                 and entry["reported_context"]["job_context"]["status"] == "observed"]
    observation["actual_job_ui_limits_verified"] = bool(completed)
    observation["app_wrapper_zero_ui_limits_observed"] = any(entry["ui_restrictions"] == 0 for entry in completed)
    if observation.get("process_started") is True and values and any(entry.get("published") is not True for entry in values):
        observation.update(status="failed", tool_error=True, job_context_error="ObserverReportMissing",
                           single_launch_fixture_passed=False)


def skipped_variant(variant):
    return {"id": variant[0], "status": "budget_not_started", "requested": requested_ui(variant),
            "launch_attempted": False, "process_started": False, "no_process_started": True,
            "single_launch_fixture_passed": False, "persistent_cookie_verified": False,
            "cleanup_proven": True, "requests": [], "checks": [],
            "desired_zero_ui_limits": variant[0] == "ui_no_job_limits", "actual_job_ui_limits_verified": False,
            "app_wrapper_zero_ui_limits_observed": False}


def observed_browser_owner(browser_module, runtime, edge, profile, fixture, observation):
    class TracedRun(browser_module.BrowserRun):
        def __init__(self):
            super().__init__(runtime, edge, profile, fixture)
            self.retained_processes = []

        def close(self):
            process = self.wrapper
            if process is not None:
                if process not in self.retained_processes:
                    self.retained_processes.append(process)
                observation["process_started"] = True
                code = process.poll()
                if type(code) is int and "edge_mxc_wrapper_exit_code" not in observation:
                    observation["edge_mxc_wrapper_exit_code"] = code
                    observation["edge_mxc_wrapper_exit_hex"] = f"0x{code & 0xffffffff:08X}"
                if code is None:
                    observation["wrapper_alive_before_safe_cleanup"] = True
            # Production stop retains its guardian handles on failure. Never
            # kill/terminate the SDK wrapper or a process discovered by name.
            super().close()
            for retained in list(self.retained_processes):
                if retained.poll() is None:
                    raise RuntimeError("SDK wrapper remained alive after production close")
                observation["wrapper_exited_after_cleanup"] = True
                if hasattr(retained._handle, "Close"):
                    retained._handle.Close()
                self.retained_processes.remove(retained)
    return TracedRun()


def run_variant(variant, runtime_module, runtime, edge, browser_module, deadline):
    if not budget_available(deadline):
        return skipped_variant(variant)
    observation = {"id": variant[0], "status": "observed", "requested": requested_ui(variant),
                   "launch_attempted": True, "single_launch_fixture_passed": False,
                   "persistent_cookie_verified": False, "requests": [], "checks": [],
                   "cleanup_proven": False, "browser_timeout_seconds": BROWSER_TIMEOUT,
                   "startup_reserve_seconds": STARTUP_RESERVE,
                   "desired_zero_ui_limits": variant[0] == "ui_no_job_limits",
                   "actual_job_ui_limits_verified": False, "app_wrapper_zero_ui_limits_observed": False}
    directory = fixture = owner = None
    safe = True
    override = None
    started = time.monotonic()
    try:
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-edge-ui-"))
        fixture = browser_module.BrowserFixture()
        owner = observed_browser_owner(browser_module, runtime, edge, directory / "profiles", fixture, observation)
        override = UIOverride(runtime_module, variant, observation["requests"], observe_jobs=True)
        with override:
            observation["checks"].append(owner.run(1, BROWSER_TIMEOUT))
        if not observation["requests"]:
            raise DiagnosticError("no actual diagnostic policy request was built")
        observation["single_launch_fixture_passed"] = True
        observation["outcome"] = "single_launch_passed"
    except Exception as exc:
        observation.update(outcome="launch_failed", detail=f"{type(exc).__name__}: {str(exc)[:400]}")
        if isinstance(exc, (DiagnosticError, TypeError, KeyError, AttributeError, ImportError)) \
                or not observation["requests"]:
            observation.update(status="failed", tool_error=True)
    finally:
        for item in (owner, fixture):
            if item is not None:
                try:
                    item.close()
                except Exception as exc:
                    safe = False
                    observation.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
        if override is not None:
            try:
                add_job_context(observation, override)
            except Exception as exc:
                observation.update(status="failed", tool_error=True, job_context_error=type(exc).__name__)
        if directory is not None and safe:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                safe = False
                observation.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
        observation["cleanup_proven"] = safe
        observation["elapsed_seconds"] = round(time.monotonic() - started, 3)
        if not safe:
            observation.update(status="failed", single_launch_fixture_passed=False)
            _RECOVERY_OWNERS.append((owner, fixture, directory))
    return observation


def optional_gui(variants, facts, runtime_module, runtime, edge, browser_module, helpers, deadline):
    # The fixed headless observations take priority. Prefer a working handles
    # preset, then desktop, then diagnostic zero-limit, then container. One GUI launch is never two-phase
    # GUI/browser acceptance or evidence of cookie persistence.
    ranking = ("handles_ime", "handles_no_ime", "desktop_ime", "ui_no_job_limits", "container_ime", "container_no_ime")
    passed = {entry["id"] for entry in variants if entry.get("single_launch_fixture_passed") is True}
    chosen = next((variant for name in ranking for variant in VARIANTS if variant[0] == name and name in passed), None)
    result = {"status": "not_started", "single_visible_gui_observed": False,
              "persistent_cookie_verified": False, "cleanup_proven": True}
    if chosen is None:
        result["reason"] = "no_single_launch_preset_passed"
        return result
    if facts.get("native_machine") != 0x8664 or facts.get("python_pe_machine") != 0x8664:
        result["reason"] = "requires_native_x64_interactive_vm"
        return result
    if not (ROOT / ".github/windows_gui_check.py").is_file():
        result["reason"] = "gui_diagnostic_source_unavailable"
        return result
    if not budget_available(deadline, 90):
        result.update(status="budget_not_started", reason="complete_gui_and_cleanup_budget_unavailable")
        return result
    gui = source_module("windows_gui_check")
    interactive = gui.interactive_facts()
    if interactive.get("ordinary_interactive") is not True:
        result["reason"] = "requires_ordinary_interactive_default_desktop"
        return result
    result.update(status="observed", variant=chosen[0], requested=requested_ui(chosen),
                  requests=[], interactive=interactive, cleanup_proven=False)
    directory = fixture = owner = None
    safe = True
    override = None
    try:
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-edge-ui-gui-"))
        fixture = browser_module.BrowserFixture()
        owner = gui.GuiRun(runtime, edge, directory / "profiles", fixture, helpers, browser_module)
        override = UIOverride(runtime_module, chosen, result["requests"], observe_jobs=True)
        with override:
            result["check"] = owner.run(1)
        if not result["requests"]:
            raise DiagnosticError("no actual GUI diagnostic policy request was built")
        result["single_visible_gui_observed"] = True
    except Exception as exc:
        result["detail"] = f"{type(exc).__name__}: {str(exc)[:400]}"
        if isinstance(exc, (DiagnosticError, TypeError, KeyError, AttributeError, ImportError)):
            result.update(status="failed", tool_error=True)
    finally:
        for item in (owner, fixture):
            if item is not None:
                try:
                    item.close()
                except Exception as exc:
                    safe = False
                    result.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
        if override is not None:
            try:
                add_job_context(result, override)
            except Exception as exc:
                result.update(status="failed", tool_error=True, job_context_error=type(exc).__name__)
        if directory is not None and safe:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                safe = False
                result.update(cleanup_error=type(exc).__name__, recovery_directory=str(directory))
        result["cleanup_proven"] = safe
        if not safe:
            result.update(status="failed", single_visible_gui_observed=False)
            _RECOVERY_OWNERS.append((owner, fixture, directory))
    return result


def initial_result():
    return {"status": "failed", "browser_fixture_passed": False, "gui_fixture_passed": False,
            "acceptance_passed": False, "full_acceptance_passed": False, "real_node_passed": False,
            "public_udp_proven": False, "system_dns_proven": False, "variants": [], "checks": [],
            "test_only_ui_override": True, "production_policy_changed": False,
            "workload_wrapped_for_job_observation": True,
            "browser_sandbox_weakened": False, "budget_seconds": LIMIT_SECONDS,
            "limitations": ["Single-launch fixed HTTP fixture only; cookie persistence is not tested.",
                            "UI isolation/IME presets are diagnostic requests, not a product policy change.",
                            "Zero UI limits are a requested diagnostic configuration, not an observed job restriction mask.",
                            "Actual job observations belong to the test app wrapper before Edge launches, not Edge's own nested job.",
                            "The five narrower presets retain other UI limits and cannot rule out Chromium nested-job conflicts.",
                            "API startup/cleanup bounds are preserved; cases without a full remaining budget are not started."]}


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--report", type=Path, default=Path("windows-edge-ui.json"))
    parser.add_argument("--allow-emulated-x64", action="store_true")
    args = parser.parse_args(arguments)
    started = time.monotonic()
    deadline = started + LIMIT_SECONDS
    result = initial_result()
    browser_module = source_module("windows_browser_check")
    helpers = browser_module.acceptance_helpers()
    before = None
    code, phase = 1, "platform"
    try:
        facts = helpers.host_facts()
        result["host"] = facts
        if sys.platform != "win32" or facts.get("windows_product_type") != 1 \
                or facts.get("python_pe_machine") != 0x8664 or (facts.get("native_machine") != 0x8664
                and not (args.allow_emulated_x64 and facts.get("native_machine") == 0xAA64)):
            result.update(status="unsupported", detail="Requires Windows 11 x64 Python; ARM needs --allow-emulated-x64.")
            return 3
        phase = "runtime_integrity"
        root = args.root.resolve(strict=True)
        sys.path.insert(0, str(root))
        helpers.verify_project_origin(root)
        from ruleproxy import windows_runtime
        digests = helpers.verify_runtime_manifest(root)
        result["runtime_integrity"] = {"manifest_verified": True, "file_count": len(digests)}
        runtime = root / "bin/windows-amd64/wxc-exec.exe"
        edge = browser_module.find_edge(None)
        machine = helpers.executable_machine(edge)
        result["browser"] = {"launcher_pe_machine": machine,
                             "launcher_execution_scope": helpers.acceptance_scope(facts["native_machine"], machine)}
        phase = "host_network_snapshot"
        before = helpers.network_snapshot()
        for variant in VARIANTS:
            phase = variant[0]
            entry = run_variant(variant, windows_runtime, runtime, edge, browser_module, deadline)
            result["variants"].append(entry)
            if entry["cleanup_proven"] is not True:
                result.update(cleanup_error=entry.get("cleanup_error", "unproved"),
                              recovery_directory=entry.get("recovery_directory"))
                break
            if entry.get("tool_error") is True:
                result["detail"] = "A UI diagnostic collector invariant failed."
                break
        if len(result["variants"]) == len(VARIANTS) and all(entry["cleanup_proven"] is True
                and entry.get("tool_error") is not True for entry in result["variants"]):
            phase = "optional_visible_gui"
            result["optional_gui"] = optional_gui(result["variants"], facts, windows_runtime,
                                                   runtime, edge, browser_module, helpers, deadline)
            if result["optional_gui"]["cleanup_proven"] is True and result["optional_gui"].get("tool_error") is not True:
                result.update(status="experiment_only", collection_completed=True)
                code = 0
            elif result["optional_gui"]["cleanup_proven"] is not True:
                result.update(cleanup_error=result["optional_gui"].get("cleanup_error", "unproved"),
                              recovery_directory=result["optional_gui"].get("recovery_directory"))
            else:
                result["detail"] = "An optional GUI diagnostic collector invariant failed."
    except Exception as exc:
        result.update(status="failed", detail=f"UI experiment failed during {phase} ({type(exc).__name__}): {str(exc)[:400]}")
    finally:
        result["cleanup_proven"] = not bool(result.get("cleanup_error") or result.get("recovery_directory")) \
            and all(entry.get("cleanup_proven") is True for entry in result["variants"]) \
            and result.get("optional_gui", {}).get("cleanup_proven", True) is True
        if before is not None:
            try:
                unchanged = before == helpers.network_snapshot()
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                         "status": "passed" if unchanged else "failed"})
                if not unchanged:
                    result.update(status="failed", detail="Host network snapshot changed during the UI diagnostic.")
                    code = 1
            except Exception as exc:
                result.update(status="failed", host_snapshot_error=type(exc).__name__)
                code = 1
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["ui_variant_requests_collected"] = sum(bool(entry.get("requests")) for entry in result["variants"])
        if result["elapsed_seconds"] > LIMIT_SECONDS:
            result.update(status="failed", budget_overrun=True)
            code = 1
        args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
        helpers.write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
