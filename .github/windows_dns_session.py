"""Bounded native resolver observations for one experimental policy only.

Controllers invoke collect_call directly so their held-HANDLE cleanup cannot
be cut short by an extra subprocess timeout. A deadline result is incomplete;
worker exit is never a claim that Windows' broker stopped or emitted no DNS.
"""
from __future__ import annotations

import importlib.util
import math
from pathlib import Path
import secrets
import shutil
import time

PREFERRED = "model1_internal_ingress_deny"
SOURCE_MAC = "52:54:00:12:34:56"
APIS = ("getaddrinfo", "dns_a", "dns_aaaa")
ROLES = ("outside_before", "parent", "child", "outside_after")
ROOT = Path(__file__).resolve().parent


def load_native(path):
    spec = importlib.util.spec_from_file_location("ruleproxy_session_native_dns", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def collect_calls(config, role, directory, deadline):
    """Never start a worker without its full startup/call/cleanup allowance."""
    if role not in ROLES or type(deadline) not in (int, float) or not math.isfinite(deadline):
        raise ValueError("native_dns_session_scope_invalid")
    native = load_native(config["script"])
    nonce = config["nonce"]
    native.qname(nonce, role, APIS[0])
    directory = Path(directory)
    result = {"status": "incomplete", "calls": [], "cleanup_proven": True,
              "acceptance_passed": False, "dns_blocked_proven": False}
    identity = None
    per_call = native.STARTUP_SECONDS + native.CALL_SECONDS + 2.25
    for api in APIS:
        if deadline - time.monotonic() < per_call:
            result["calls"].append({"api": api, "qname": native.qname(nonce, role, api), "requested_role": role,
                "outcome": "budget_incomplete", "api_returned": False, "native_completion_proven": False,
                "entry_lease_published": False, "no_process_started": True, "worker_cleanup_proven": True,
                "default_system_server_list": True, "server_list_override": False,
                "acceptance_passed": False, "dns_blocked_proven": False})
            continue
        try:
            if identity is None:
                identity = native.ProcessIdentity()
            directory.mkdir(parents=True, exist_ok=True)
            call = native.collect_call(nonce, role, api, directory / api, identity)
        except Exception as exc:
            # A controller exception does not prove its possible child exited.
            result.update(cleanup_proven=False, cleanup_error=type(exc).__name__,
                          recovery_directory=str(directory))
            break
        result["calls"].append(call)
        if call.get("worker_cleanup_proven") is not True or any(
                key in call for key in ("cleanup_error", "recovery_directory")):
            result.update(cleanup_proven=False, cleanup_error="NativeDnsWorkerCleanupUnproven",
                          recovery_directory=str(directory))
            break
    if len(result["calls"]) == 3 and all(call.get("outcome") == "returned"
            and call.get("api_returned") is True and call.get("native_completion_proven") is True
            for call in result["calls"]):
        result["status"] = "native_dns_observation_only"
    return result


class DnsSession:
    def __init__(self, directory, deadline):
        self.directory, self.deadline = Path(directory), deadline
        self.config = {"nonce": secrets.token_hex(16), "script": str(ROOT / "windows_native_dns_probe.py")}
        self.native = load_native(self.config["script"])
        self.execution, self.controls = [], []
        self.attested, self.safe = False, True
        self.recovery = None
        probes = []
        for api in APIS:
            for role in ROLES:
                group = PREFERRED + "." + api
                probe = {"id": group + "." + role, "group": group, "role": role, "api": api,
                         "qname": self.native.qname(self.config["nonce"], role, api)}
                if api != "getaddrinfo":
                    probe["query_type"] = 1 if api == "dns_a" else 28
                probes.append(probe)
        self.manifest = {"schema_version": 1, "source_mac": SOURCE_MAC, "probes": probes}

    def actor_config(self, profile):
        return {**self.config, "session_script": str(Path(__file__).resolve()),
                "directory": str(Path(profile) / "native-dns-actors")}

    def append(self, observation, role):
        for call in observation.get("calls", []):
            api = call.get("api")
            if api not in APIS or call.get("requested_role") != role:
                self.safe = False
                self.recovery = {"cleanup_error": "NativeDnsObservationScopeMismatch",
                                 "recovery_directory": str(self.directory), "cleanup_proven": False}
                break
            self.execution.append({**call, "id": PREFERRED + "." + api + "." + role, "role": role,
                                   "attempted": call.get("entry_lease_published") is True})
        if observation.get("cleanup_proven") is not True or any(
                key in observation for key in ("cleanup_error", "recovery_directory")):
            self.safe = False
            self.recovery = {"cleanup_error": observation.get("cleanup_error", "NativeDnsCleanupUnproven"),
                             "recovery_directory": observation.get("recovery_directory", str(self.directory)),
                             "cleanup_proven": False}

    def control(self, role, deadline=None):
        if role not in ("outside_before", "outside_after"):
            raise ValueError("native_dns_control_role_invalid")
        if not self.safe:
            return self.recovery
        # Reserve the existing actor/teardown budget before a new containment;
        # after controls leave room for the remaining source-only variants.
        bound = min(self.deadline, deadline if deadline is not None else self.deadline)
        observation = collect_calls(self.config, role, self.directory / role, bound)
        self.controls.append({"role": role, **observation})
        self.append(observation, role)
        return observation

    def actors(self, variant):
        if variant.get("name") != PREFERRED or variant.get("process_started") is not True:
            return
        self.attested = variant.get("actor_attestation", {}).get("attestation_passed") is True
        for actor in variant.get("actors", []):
            role = actor.get("scope")
            if role not in ("parent", "child"):
                self.attested = False
                continue
            self.append(actor.get("native_dns", {"calls": [], "cleanup_proven": True}), role)

    def finish_payload(self):
        return {"manifest": self.manifest, "execution": self.execution,
                "actor_execution_attested": self.attested}

    def close(self):
        if not self.safe:
            return self.recovery
        try:
            if self.directory.exists():
                shutil.rmtree(self.directory)
        except OSError as exc:
            self.safe = False
            self.recovery = {"cleanup_error": type(exc).__name__, "recovery_directory": str(self.directory),
                             "cleanup_proven": False}
        return self.recovery
