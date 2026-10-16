"""Fail-closed admission of a release-reviewed Windows runtime attestation.

This is not an online verifier or a way for a desktop client to self-qualify.
No accepted receipt ships today. A future release must review the complete
native matrix, then package this fixed file with the tested code/core/runtime.
The sole profile covers an explicitly started session, never early boot.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import sys

from .windows_proxy_policy import ProxyError

RECEIPT = "ruleproxy/windows-global-qualification.json"
PROFILE = "windows-global-runtime-v1"
MAX_RECEIPT = 64 * 1024
CRITICAL_FILES = frozenset({
    "ruleproxy/windows_global_qualification.py", "ruleproxy/windows_global_guard.py",
    "ruleproxy/windows_global_dns.py", "ruleproxy/windows_proxy_service.py",
    "ruleproxy/windows_proxy_policy.py", "ruleproxy/windows_global_runtime.py",
    "ruleproxy/global_runtime.py", "ruleproxy/config.py", "ruleproxy/windows_app_process.py",
    "ruleproxy/windows_proxy_client.py",
    "bin/windows-amd64/mihomo.exe", "python/python.exe", "python/python314.zip",
    "python/python314._pth", "python/python314.dll",
})
SCENARIOS = frozenset({
    "physical_dual_stack_positive_controls_and_lossless_blocking",
    "core_service_tun_failure_and_interface_recreation",
    "bfe_restart_and_guard_policy_loss_fail_closed",
    "established_tcp_udp_reauthorization_and_route_changes",
    "system_core_identity_and_ordinary_same_path_denial",
    "child_processes_and_competing_wfp_providers",
    "rdp_reply_continuity_without_new_outbound_exemption",
    "precise_stop_reinstall_and_foreign_policy_preservation",
    "default_system_and_dual_stack_udp_tcp_dns_selected_node_doh",
    "dns_fresh_negative_and_reenabled_controls_without_direct_fallback",
    "physical_dns_and_encrypted_dns_bypass_absent_during_failures",
})
_SHA = re.compile(r"[a-f0-9]{64}\Z")
_COMMIT = re.compile(r"[a-f0-9]{40}\Z")


def _closed(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate qualification key")
        result[key] = value
    return result


def _os_identity():
    if os.name != "nt":
        raise ValueError("native Windows required")
    import winreg
    version = sys.getwindowsversion()
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
        ubr, kind = winreg.QueryValueEx(key, "UBR")
    if kind != winreg.REG_DWORD or type(ubr) is not int or ubr < 0:
        raise ValueError("unknown Windows revision")
    return {"major": version.major, "minor": version.minor, "build": version.build,
            "ubr": ubr, "product_type": version.product_type, "architecture": platform.machine().upper()}


def _protected_file(root, relative):
    # Lazy import avoids loading service APIs on the missing-receipt fast path.
    from .windows_proxy_service import protected_path
    relative = PurePosixPath(relative)
    if relative.is_absolute() or ".." in relative.parts or any(char in str(relative) for char in ("\\", ":")):
        raise ValueError("invalid qualification path")
    path = root / relative
    for item in (root.parent, root, *reversed(path.relative_to(root).parents)):
        protected_path(item if item.is_absolute() else root / item)
    protected_path(path)
    if not path.is_file():
        raise ValueError("qualification file missing")
    return path


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_qualification(metadata):
    """Use only installed metadata; missing/unknown evidence never qualifies."""
    denied = {"native_qualified": False, "profile": PROFILE, "runtime_only": True,
              "boot_protection": False, "reason": "qualification_missing"}
    entries = metadata.get("files", {}) if isinstance(metadata, dict) else {}
    if not isinstance(entries, dict) or RECEIPT not in entries:
        return denied
    try:
        root = Path(metadata["root"]).absolute()
        expected = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RuleProxy-Web"
        if os.path.normcase(str(root)) != os.path.normcase(str(expected.absolute())):
            raise ValueError("untrusted qualification root")
        path = _protected_file(root, RECEIPT)
        if path.stat().st_size > MAX_RECEIPT or not _SHA.fullmatch(entries[RECEIPT]):
            raise ValueError("invalid qualification size or manifest")
        with path.open("rb") as stream:
            raw = stream.read(MAX_RECEIPT + 1)
        if len(raw) > MAX_RECEIPT or hashlib.sha256(raw).hexdigest() != entries[RECEIPT]:
            raise ValueError("qualification digest differs")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if (not _closed(value, {"schema_version", "profile", "runtime_only", "boot_protection",
                                "accepted", "os", "files", "scenarios", "source_commit"})
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["profile"] != PROFILE or value["accepted"] is not True
                or value["runtime_only"] is not True or value["boot_protection"] is not False
                or not isinstance(value["source_commit"], str) or not _COMMIT.fullmatch(value["source_commit"])):
            raise ValueError("unaccepted qualification profile")
        current = _os_identity()
        if (not _closed(value["os"], current) or value["os"] != current
                or any(type(value["os"][key]) is not type(item) for key, item in current.items())):
            raise ValueError("Windows qualification identity differs")
        # Bind all shipped interpreter/extensions/vendor code as well as the
        # mandatory core files; an omitted extension cannot reuse old evidence.
        required = CRITICAL_FILES | {name for name in entries if isinstance(name, str)
                                    and (name.startswith(("python/", "vendor/"))
                                         or name.startswith("ruleproxy/") and name.endswith(".py"))}
        if not _closed(value["files"], required) or not _closed(value["scenarios"], SCENARIOS):
            raise ValueError("incomplete qualification matrix")
        for name, digest in value["files"].items():
            if (not isinstance(digest, str) or not _SHA.fullmatch(digest) or entries.get(name) != digest
                    or _digest(_protected_file(root, name)) != digest):
                raise ValueError("qualified code or core differs")
        for scenario in value["scenarios"].values():
            if (not _closed(scenario, {"result", "mode", "artifact_sha256", "summary_sha256"})
                    or scenario["result"] != "passed" or scenario["mode"] != "native_global_runtime_qualification"
                    or any(not isinstance(scenario[key], str) or not _SHA.fullmatch(scenario[key])
                           for key in ("artifact_sha256", "summary_sha256"))):
                raise ValueError("native scenario evidence incomplete")
        return {**denied, "native_qualified": True, "reason": "accepted_runtime_attestation",
                "receipt_sha256": entries[RECEIPT]}
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, ProxyError):
        return {**denied, "reason": "qualification_invalid"}
