"""Build a source-only MXC 1.0.0 capability experiment; never install it.

The caller supplies a clean checkout at the exact Microsoft release commit.
Use --source CHECKOUT --output DIAGNOSTIC_DIR; Windows builds native x64 wxc.
--prepare-only works on other hosts and never produces a runnable manifest.
The diagnostic clears only automatically added internetClient for one exact
internal TCP shape with empty caller capabilities. Actual sockets/DNS remain
unverified until a real PSEC run. The product's bin and policy are untouched.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
UPSTREAM_COMMIT = "7bf210247986cb73b1b314df60c2f1109c479c0b"
TARGET_FILE = "src/mxc-sdk/src/backends/process_container/common/base_container_helpers.rs"
ORIGINAL_SHA256 = "a03b8889d8d92fe854f46d56c702360403c6889e79b48b42f8b2535b66189491"
LICENSE_SHA256 = "d9a1b1e30d633d5732ea18e3cba9538d293ebc53e1a9e4e96ab739e0c5c4f1cb"
MAX_DIAGNOSTIC_INPUT_BYTES = 2 * 1024 * 1024
MAX_COMPILER_ERRORS = 16
TOOLCHAIN = "1.93"
BUILD_TARGET = "x86_64-pc-windows-msvc"
ANCHOR = "    let mut capabilities = effective_capabilities(&request.policy);\n"
INSERTION = """    // RuleProxy diagnostic only: the native endpoint table remains unchanged.
    // Empty caller capabilities avoid removing an explicitly requested grant.
    let policy = &request.policy;
    let exact_internal_tcp_only = policy.capabilities.is_empty()
        && !policy.network_proxy.is_enabled()
        && policy.allowed_proxy_peer.is_none()
        && policy.network_ingress.as_ref().is_some_and(|ingress| {
            ingress.default == NetworkAction::Deny
                && ingress.host_loopback == NetworkAction::Deny
        })
        && policy.network_egress.as_ref().is_some_and(|egress| {
            egress.default == NetworkAction::Deny
                && egress.deny.is_empty()
                && egress.allow.len() == 1
                && egress.allow[0].to.len() == 1
                && egress.allow[0].to[0].except.is_empty()
                && egress.allow[0].to[0].cidr.address
                    == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                && egress.allow[0].to[0].cidr.prefix_length == 32
                && egress.allow[0].ports.len() == 1
                && egress.allow[0].ports[0].protocol == NetworkProtocol::Tcp
                && egress.allow[0].ports[0].port.is_some_and(|port| port > 0)
                && egress.allow[0].ports[0].end_port.is_none()
        });
    if exact_internal_tcp_only {
        capabilities.retain(|name| !name.eq_ignore_ascii_case("internetClient"));
    }
"""
PATCH_INFO = {"name": "exact_internal_tcp_without_automatic_internet_client", "capabilities_null": True,
              "network_table_unchanged": True, "exact_internal_tcp_only": True,
              "caller_capabilities_must_be_empty": True}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def compiler_failure_facts(stdout, stderr, cwd):
    """Keep only Rust error codes/categories and public relative source spans.

    Cargo JSON can include environment, absolute paths and source excerpts.
    None of those fields, rendered messages or arbitrary tool text is emitted.
    """
    facts = {"compiler_errors": [], "cargo_failure_categories": [], "input_tail_truncated": False}
    categories = (("no field ", "unknown_field"), ("mismatched types", "mismatched_types"),
                  ("failed to resolve", "resolution_failed"), ("unresolved import", "unresolved_import"),
                  ("cannot find ", "missing_item"), ("expected ", "syntax_or_type_error"),
                  ("the trait bound ", "trait_bound"), ("linking with ", "linker_error"))
    cargo_categories = (("error: failed to run custom build command", "custom_build_command_failed"),
                        ("error: failed to get ", "dependency_fetch_failed"),
                        ("error: failed to download", "dependency_download_failed"),
                        ("error: failed to parse manifest", "manifest_parse_failed"),
                        ("error: could not find", "required_build_input_missing"),
                        ("error: linking with", "linker_failed"))
    base = str(Path(cwd).resolve()).replace("\\", "/").rstrip("/") + "/"
    for raw in (stdout, stderr):
        if not raw:
            continue
        raw = raw.encode("utf-8", "replace") if isinstance(raw, str) else raw
        facts["input_tail_truncated"] |= len(raw) > MAX_DIAGNOSTIC_INPUT_BYTES
        for line in raw[-MAX_DIAGNOSTIC_INPUT_BYTES:].decode("utf-8", "replace").splitlines():
            if len(line) > 64 * 1024:
                continue
            stripped = line.strip()
            for prefix, category in cargo_categories:
                if stripped.startswith(prefix) and category not in facts["cargo_failure_categories"]:
                    facts["cargo_failure_categories"].append(category)
            if not stripped.startswith("{") or len(facts["compiler_errors"]) >= MAX_COMPILER_ERRORS:
                continue
            try:
                value = json.loads(stripped)
            except (ValueError, TypeError):
                continue
            if not isinstance(value, dict) or value.get("reason") != "compiler-message":
                continue
            message = value.get("message")
            if not isinstance(message, dict) or message.get("level") != "error":
                continue
            code = message.get("code")
            code = code.get("code") if isinstance(code, dict) else None
            item = {"code": code if isinstance(code, str) and re.fullmatch(r"E[0-9]{4}", code) else None,
                    "category": "compiler_error"}
            text = message.get("message")
            if isinstance(text, str):
                item["category"] = next((label for prefix, label in categories if text.startswith(prefix)), "compiler_error")
            spans = message.get("spans")
            for span in spans if isinstance(spans, list) else []:
                if not isinstance(span, dict) or span.get("is_primary") is not True:
                    continue
                name = span.get("file_name")
                if not isinstance(name, str):
                    continue
                name = name.replace("\\", "/")
                if name.casefold().startswith(base.casefold()):
                    name = name[len(base):]
                if (not re.fullmatch(r"[A-Za-z0-9_.\-/]{1,240}\.rs", name) or name.startswith("/")
                        or ".." in name.split("/") or re.search(r"[0-9a-fA-F]{32,}", name)
                        or any(type(span.get(key)) is not int or not 1 <= span[key] <= 10_000_000
                               for key in ("line_start", "column_start"))):
                    continue
                item.update(source=name, line=span["line_start"], column=span["column_start"])
                break
            facts["compiler_errors"].append(item)
    return facts


class BuildCommandError(RuntimeError):
    def __init__(self, arguments, cwd, *, returncode=None, timeout=None, stdout=None, stderr=None):
        command = Path(arguments[0]).name.lower()
        command = command if command in ("cargo", "rustc", "git", "cargo.exe", "rustc.exe", "git.exe") else "build_command"
        detail = f"{command} exceeded its {timeout}s budget" if timeout is not None else f"{command} exited with status {returncode}"
        super().__init__(detail)
        self.diagnostics = {"command": command, "exit_code": returncode, "timed_out": timeout is not None,
                            **compiler_failure_facts(stdout, stderr, cwd)}


def run(arguments, *, cwd, timeout=60):
    try:
        completed = subprocess.run(arguments, cwd=cwd, shell=False, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise BuildCommandError(arguments, cwd, timeout=timeout, stdout=exc.stdout, stderr=exc.stderr) from None
    if completed.returncode:
        raise BuildCommandError(arguments, cwd, returncode=completed.returncode,
                                stdout=completed.stdout, stderr=completed.stderr)
    return completed.stdout


def permitted_destination(path):
    path = Path(path).resolve()
    try:
        path.relative_to((ROOT / "bin").resolve())
    except ValueError:
        return path
    raise ValueError("a diagnostic cannot write into the product runtime directory")


def patch_bytes(raw):
    if sha256(raw) != ORIGINAL_SHA256:
        raise ValueError("the upstream helper file does not match the fixed release SHA256")
    text = raw.decode("utf-8")
    if text.count(ANCHOR) != 1 or text.count("pub(super) fn build_psec_v1_security_environment_spec(") != 1:
        raise ValueError("the fixed capabilities patch anchor is not unique")
    patched = text.replace(ANCHOR, ANCHOR + INSERTION, 1).encode("utf-8")
    diff = "".join(difflib.unified_diff(text.splitlines(keepends=True), patched.decode("utf-8").splitlines(keepends=True),
                                     fromfile="a/" + TARGET_FILE, tofile="b/" + TARGET_FILE)).encode("utf-8")
    return patched, sha256(diff)


def prepare_source(source):
    source = Path(source).resolve(strict=True)
    if run(["git", "rev-parse", "HEAD"], cwd=source).decode("ascii").strip() != UPSTREAM_COMMIT:
        raise ValueError("the source checkout is not the exact Microsoft MXC 1.0.0 commit")
    if run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=source).strip():
        raise ValueError("the source checkout must be clean before the single diagnostic patch")
    target = source / TARGET_FILE
    if target.is_symlink() or target.resolve(strict=True) != target:
        raise ValueError("the fixed source target cannot be a filesystem alias")
    raw = target.read_bytes()
    if run(["git", "show", "HEAD:" + TARGET_FILE], cwd=source) != raw:
        raise ValueError("the working helper file differs from the fixed git blob")
    toolchain = (source / "src/rust-toolchain.toml").read_text(encoding="utf-8")
    if not re.search(r'^channel\s*=\s*"1\.93"\s*$', toolchain, re.MULTILINE):
        raise ValueError("the upstream Rust 1.93 pin changed")
    patched, patch_digest = patch_bytes(raw)
    target.write_bytes(patched)
    if target.read_bytes() != patched:
        raise RuntimeError("the diagnostic patch was not written exactly")
    return source, {"schema_version": 1, "status": "prepared_only", "upstream_commit": UPSTREAM_COMMIT,
                    "executor_sha256": None, "patch": dict(PATCH_INFO), "original_file_sha256": ORIGINAL_SHA256,
                    "patch_sha256": patch_digest, "patched_file_sha256": sha256(patched),
                    "toolchain": TOOLCHAIN, "target": BUILD_TARGET}


def executable_digest(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or not 512 <= path.stat().st_size <= 256 * 1024 * 1024:
        raise ValueError("the built diagnostic executor is missing or outside its size bound")
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:2] != b"MZ":
            raise ValueError("the executor is not a Windows PE image")
        offset = struct.unpack_from("<I", header, 0x3c)[0]
        if not 64 <= offset <= path.stat().st_size - 6:
            raise ValueError("the executor PE header offset is invalid")
        stream.seek(offset)
        pe = stream.read(6)
        if pe[:4] != b"PE\0\0" or struct.unpack_from("<H", pe, 4)[0] != 0x8664:
            raise ValueError("the executor is not native x64")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(source, output, manifest):
    if os.name != "nt":
        raise OSError("native Windows MSVC build is required; other hosts may only prepare")
    version = run(["rustc", "+" + TOOLCHAIN, "--version"], cwd=source / "src").decode("ascii").strip()
    if not re.fullmatch(r"rustc 1\.93\.\d+ \([^\r\n]+\)", version):
        raise ValueError("the active build compiler is not the pinned Rust 1.93 toolchain")
    target_directory = permitted_destination(source / "src/target")
    run(["cargo", "+" + TOOLCHAIN, "build", "--locked", "--release", "--message-format=json", "--target", BUILD_TARGET,
         "--target-dir", str(target_directory), "-p", "wxc", "--no-default-features"],
        cwd=source / "src", timeout=1800)
    changed = run(["git", "diff", "--name-only"], cwd=source).decode("utf-8").splitlines()
    if changed != [TARGET_FILE] or sha256((source / TARGET_FILE).read_bytes()) != manifest["patched_file_sha256"]:
        raise ValueError("the source tree drifted outside the verified diagnostic patch during build")
    artifact = target_directory / BUILD_TARGET / "release/wxc-exec.exe"
    digest = executable_digest(artifact)
    license_path = source / "LICENSE.md"
    if license_path.is_symlink() or license_path.resolve(strict=True) != license_path:
        raise ValueError("the fixed upstream license cannot be a filesystem alias")
    license_bytes = license_path.read_bytes()
    if (sha256(license_bytes) != LICENSE_SHA256
            or run(["git", "show", "HEAD:LICENSE.md"], cwd=source) != license_bytes):
        raise ValueError("the upstream license does not match the fixed release SHA256 and git blob")
    destination = output / "wxc-exec.exe"
    shutil.copyfile(artifact, destination)
    if executable_digest(destination) != digest:
        raise RuntimeError("the staged diagnostic executor digest changed")
    (output / "MXC-LICENSE.md").write_bytes(license_bytes)
    manifest.update(status="built", executor_sha256=digest)


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--prepare-only", action="store_true")
    args = parser.parse_args(arguments)
    try:
        if not args.prepare_only and os.name != "nt":
            raise OSError("use --prepare-only outside native Windows builds")
        output = permitted_destination(args.output)
        output.mkdir(parents=True, exist_ok=True)
        if any((output / name).exists() for name in ("build-manifest.json", "wxc-exec.exe", "MXC-LICENSE.md")):
            raise ValueError("the diagnostic output must not contain stale artifacts")
        source, manifest = prepare_source(args.source)
        if not args.prepare_only:
            build(source, output, manifest)
        temporary = output / "build-manifest.json.tmp"
        temporary.write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
        os.replace(temporary, output / "build-manifest.json")
        print(json.dumps(manifest, ensure_ascii=True, indent=2), flush=True)
        return 0
    except Exception as exc:
        failure = {"status": "failed", "error": type(exc).__name__, "detail": str(exc)[:300],
                   "product_runtime_changed": False, "acceptance_passed": False}
        if isinstance(exc, BuildCommandError):
            failure["build_diagnostics"] = exc.diagnostics
        print(json.dumps(failure), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
