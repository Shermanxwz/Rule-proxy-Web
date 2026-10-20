"""Disabled-by-default native PSEC identity proof, not product qualification.

Stage 0 only executes a native token reporter. No socket, firewall, proxy,
credential, account, or desktop changes. Windows PSEC creates temporary
security state, so execution requires an explicitly approved disposable host.
Stage 1 policy construction is offline only until the real proxy is implemented.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("identity_smoke_helpers", ROOT / ".github/windows_psec_compartment_smoke.py")
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
NONCE = re.compile(r"[0-9a-f]{32}\Z")
PROFILE = re.compile(r"RuleProxy\.IdentityProof\.[0-9a-f]{32}\Z")
SID = re.compile(r"S-1-15-2(?:-[0-9]{1,10}){7}\Z")
MAX_OUTPUT = 128 * 1024


def policy(inputs, profile, actor, nonce, *, proxy=None):
    if not isinstance(nonce, str) or not NONCE.fullmatch(nonce):
        raise ValueError("invalid case nonce")
    command = [str(actor), "actor", nonce, str(Path(profile) / "actor.json")]
    value = {
        "$schema": "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json",
        "version": "1.0.0", "containment": "processcontainer",
        "containerId": "ruleproxy-identity-proof-" + nonce,
        "fallback": {"allowDaclMutation": False},
        "process": {"commandLine": subprocess.list2cmdline(command), "cwd": str(profile),
                    "inheritDefaultEnv": False, "env": [], "timeout": 15000},
        "filesystem": {"readonlyPaths": [str(inputs)], "readwritePaths": [str(profile)]},
        "ui": {"disable": True, "clipboard": "none"},
        "network": {"egress": {"default": "deny"},
                    "ingress": {"default": "deny", "hostLoopback": "deny"}},
    }
    if proxy is not None:
        # Input is an observed identity record, not an arbitrary profile string.
        # This validation is NOT evidence: the Windows controller must obtain it
        # from the owned process handle and OS-derived profile SID at runtime.
        if (not isinstance(proxy, dict) or set(proxy) != {"profile", "derived_sid", "token_sid", "appcontainer", "port"}
                or not isinstance(proxy["profile"], str) or not PROFILE.fullmatch(proxy["profile"])
                or not isinstance(proxy["derived_sid"], str) or not SID.fullmatch(proxy["derived_sid"])
                or proxy["token_sid"] != proxy["derived_sid"] or proxy["appcontainer"] is not True
                or type(proxy["port"]) is not int or not 1025 <= proxy["port"] <= 65535):
            raise ValueError("a live verified proxy identity and bounded port are required")
        value["network"]["ingress"]["default"] = "allow"
        value["processContainer"] = {"network": {"allowedProxyPeer": proxy["profile"]}}
        value["runtimeConfig"] = {"networkProxy": f"http://127.0.0.1:{proxy['port']}"}
        command[1] = "actor-http"
        command.append(str(proxy["port"]))
        value["process"]["commandLine"] = subprocess.list2cmdline(command)
    return value


def actual_tiers(data):
    # Closed-value extraction from the pinned executor's diagnostics. An
    # absent, duplicate, ambiguous or contradictory tier never counts as proof.
    if not isinstance(data, bytes) or len(data) > MAX_OUTPUT:
        return []
    return re.findall(r"(?m)^selected isolation tier: ([a-z-]+)\s*$", data.decode("utf-8", "replace"))


def stage0_checks(report):
    actor = report.get("actor", {})
    return {
        "request_aware_base_container": smoke.base_container_selected(report.get("probe"), report.get("probe_exit_code")),
        "actual_base_container": report.get("actual_tiers") == ["base-container"],
        "fresh_actor": actor.get("nonce") == report.get("nonce") and isinstance(report.get("nonce"), str)
                       and NONCE.fullmatch(report["nonce"]) is not None,
        "native_identity": actor.get("schemaVersion") == 1 and actor.get("mode") == "actor"
                           and actor.get("queriesSucceeded") is True and actor.get("errors") == []
                           and actor.get("tokenIsAppContainer") is True
                           and isinstance(actor.get("tokenAppContainerSid"), str)
                           and SID.fullmatch(actor["tokenAppContainerSid"]) is not None
                           and actor.get("tokenElevated") is False and actor.get("isProcessInJob") is True
                           and actor.get("tokenCapabilities") == []
                           and type(actor.get("pid")) is int and actor["pid"] > 0,
        "normal_exit": report.get("executor_exit_code") == 0 and report.get("timed_out") is False,
        "no_harness_error": "error" not in report,
    }


def run_case(executor, value, profile, *, runner=subprocess.run):
    """No runtime fallback claim: recheck actual selected tier after execution."""
    target = Path(profile) / "policy.json"
    smoke.save(target, value)
    result = {"started": False}
    probe = runner([str(executor), "--probe", "--config", str(target)],
                   stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    result["probe_exit_code"] = probe.returncode
    result["probe_diagnostic"] = smoke.executor_diagnostic(probe.stderr)
    try:
        parsed = json.loads(probe.stdout) if len(probe.stdout) <= MAX_OUTPUT else None
    except (ValueError, TypeError):
        parsed = None
    result["probe"] = ({key: parsed.get(key) for key in ("tier", "needsDaclAugmentation", "probes", "error")}
                       if isinstance(parsed, dict) else None)
    if not smoke.base_container_selected(result["probe"], probe.returncode):
        result["status"] = "unsupported"
        return result
    # Keep raw diagnostics private and bounded when reading. They can contain
    # local paths; the published report contains only closed categories/hash.
    with (Path(profile) / "executor.stdout").open("xb") as out, (Path(profile) / "executor.stderr").open("xb") as err:
        result["started"] = True
        try:
            completed = runner([str(executor), "--config", str(target), "--debug"],
                               stdin=subprocess.DEVNULL, stdout=out, stderr=err, timeout=35)
            result.update(executor_exit_code=completed.returncode, timed_out=False)
        except subprocess.TimeoutExpired:
            result.update(executor_exit_code=None, timed_out=True)
    tiers = []
    for name in ("stdout", "stderr"):
        with (Path(profile) / ("executor." + name)).open("rb") as stream:
            data = stream.read(MAX_OUTPUT + 1)
        tiers.extend(actual_tiers(data))
        result[name + "_diagnostic"] = smoke.executor_diagnostic(data)
    result["actual_tiers"] = tiers
    actor = Path(profile) / "actor.json"
    if actor.is_file() and not actor.is_symlink():
        result["actor"] = smoke.read(actor)
    result["status"] = "observed"
    return result


def controller(args):
    if os.name != "nt" or not args.disposable_ci or not args.approved_security_test:
        raise PermissionError("requires an approved disposable Windows security test")
    identity = smoke.identity_snapshot()
    if identity["elevated"] or identity["appcontainer"] or identity["cid"] != 1:
        raise PermissionError("run from an ordinary non-AppContainer user in the default compartment")
    provenance = smoke.verify_executor(args.executor, args.manifest)
    actor = args.actor.resolve(strict=True)
    if actor.suffix.lower() != ".exe" or not 512 <= actor.stat().st_size <= 8 * 1024 * 1024:
        raise ValueError("expected bounded native actor executable")
    digest = hashlib.sha256(actor.read_bytes()).hexdigest()
    if digest != args.actor_sha256:
        raise ValueError("actor differs from explicitly supplied build digest")
    work = args.work.resolve()
    if args.report.resolve() != work / "report.json":
        raise ValueError("report must be new WORK/report.json")
    if work.exists():
        raise ValueError("a fresh disposable work directory is required")
    for name in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)"):
        if os.environ.get(name):
            protected = Path(os.environ[name]).resolve()
            if work == protected or protected in work.parents:
                raise ValueError("protected work directory")
    work.mkdir(parents=True)
    inputs, profile = work / "inputs", work / "profile"
    inputs.mkdir(); profile.mkdir()
    staged_actor, staged_executor = inputs / "actor.exe", inputs / "wxc-exec.exe"
    shutil.copyfile(actor, staged_actor)
    shutil.copyfile(args.executor, staged_executor)
    nonce = secrets.token_hex(16)
    report = {"schema_version": 1, "stage": 0, "nonce": nonce, "provenance": provenance,
              "actor_sha256": digest, "privacy_qualified": False, "product_acceptance": False,
              "network_tested": False, "controller_identity": identity}
    try:
        report.update(run_case(staged_executor, policy(inputs, profile, staged_actor, nonce), profile))
    except Exception as exc:
        report["error"] = smoke.failure(exc)
    report["checks"] = stage0_checks(report)
    report["stage0_passed"] = all(report["checks"].values())
    # Retain owned directory as diagnostic evidence; no blanket recursive delete.
    report["cleanup"] = {"work_directory_retained": True, "psec_cleanup_independently_verified": False}
    smoke.save(args.report, report)
    return 0 if report["stage0_passed"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disposable-ci", action="store_true")
    parser.add_argument("--approved-security-test", action="store_true")
    for name in ("executor", "manifest", "actor", "work", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--actor-sha256", required=True)
    args = parser.parse_args(argv)
    return controller(args)


if __name__ == "__main__":
    raise SystemExit(main())
