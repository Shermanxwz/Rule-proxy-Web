"""Read-only dumpbin collection with a closed, path-free diagnostic fixture.

Capture limits bound observation, not acceptance. The existing 64-DLL gate
is deliberately unchanged. Collect every target before applying any gate.
No actor, token, networking, or security-setting operation is performed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time

MAX_CAPTURE_BYTES = 1024 * 1024
MAX_CAPTURE_SECONDS = 15
MAX_LINES = 16384
MAX_STRUCTURE = 2048
MAX_NAMES = 1024
MAX_FIXTURE_BYTES = 2 * 1024 * 1024
ACCEPTED_DLL_LIMIT = 64
DLL = re.compile(r"[A-Za-z0-9_.-]{1,128}\.dll", re.I)
LEGACY_DLL = re.compile(r"^\s+([A-Za-z0-9_.-]+\.dll)\s*$", re.I)
LABELS = ("full", "identity_only", "system_winhttp")
MODES = ("dependents", "imports")
STATUSES = ("completed", "start_failed", "timeout", "output_limit", "read_failed", "cleanup_failed")
KINDS = (
    "blank", "file_banner", "tool_banner", "file_type", "dependency_header",
    "delay_dependency_header", "import_header", "delay_import_header",
    "summary_header", "summary_row", "dll", "import_detail", "other",
)
FAILURES = (
    "capture_failed", "fixture_incomplete", "dependency_count",
    "dependency_header", "invalid_dependency_name", "import_bound", "http_variant_distinction",
)
HEADERS = {
    "image has the following dependencies:": "dependency_header",
    "image has the following delay load dependencies:": "delay_dependency_header",
    "section contains the following imports:": "import_header",
    "section contains the following delay load imports:": "delay_import_header",
    "summary": "summary_header",
}


def capture(command):
    """Bound bytes and time; raw output is memory-only and never printed."""
    try:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    except OSError:
        return {"status": "start_failed", "exit_code": None, "data": b""}
    data = bytearray()
    exceeded = threading.Event()
    read_failed = threading.Event()

    def read_output():
        try:
            while len(data) <= MAX_CAPTURE_BYTES:
                block = process.stdout.read(min(4096, MAX_CAPTURE_BYTES + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > MAX_CAPTURE_BYTES:
                    exceeded.set()
                    break
        except (OSError, ValueError):
            read_failed.set()

    reader = threading.Thread(target=read_output, daemon=True)
    reader.start()
    deadline = time.monotonic() + MAX_CAPTURE_SECONDS
    status = "completed"
    while process.poll() is None:
        if exceeded.is_set():
            status = "output_limit"
            break
        if time.monotonic() >= deadline:
            status = "timeout"
            break
        time.sleep(0.02)
    if status != "completed":
        try:
            process.kill()
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            status = "cleanup_failed"
    reader.join(timeout=2)
    if reader.is_alive():
        status = "cleanup_failed"
    elif read_failed.is_set():
        status = "read_failed"
    elif exceeded.is_set() and status == "completed":
        status = "output_limit"
    if not reader.is_alive():
        process.stdout.close()
    return {"status": status, "exit_code": process.poll(), "data": bytes(data[:MAX_CAPTURE_BYTES])}


def classify(line):
    text = line.strip()
    lower = text.lower()
    if not text:
        return "blank", None
    if DLL.fullmatch(text):
        return "dll", text.upper()
    if lower in HEADERS:
        return HEADERS[lower], None
    if lower.startswith("dump of file "):
        return "file_banner", None
    if lower.startswith("microsoft (r)") or lower.startswith("copyright (c)"):
        return "tool_banner", None
    if lower.startswith("file type:"):
        return "file_type", None
    if re.fullmatch(r"[0-9a-fA-F]+\s+\.[A-Za-z0-9$_.-]+", text):
        return "summary_row", None
    if re.match(r"^[0-9a-fA-F]{1,16}\s+", text):
        return "import_detail", None
    return "other", None


def decoded_output(data):
    encoding = "utf8"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf16_bom"
        text = data.decode("utf-16", errors="replace")
    else:
        text = data.decode("utf-8-sig", errors="replace")
    return encoding, text


def retained_import_lines(data):
    _, text = decoded_output(data)
    return [line.strip() for line in text.splitlines()
            if line.strip() and not line.strip().lower().startswith("dump of file ")]


def parse_output(label, mode, result):
    data = result["data"]
    encoding, text = decoded_output(data)
    lines = text.splitlines()
    structure = []
    legacy_names = set()
    trimmed_names = set()
    legacy_matches = 0
    invalid_legacy_names = 0
    trimmed_matches = 0
    dll_like_other = 0
    header_count = 0
    truncated = len(lines) > MAX_LINES
    for line in lines[:MAX_LINES]:
        kind, name = classify(line)
        old_match = LEGACY_DLL.fullmatch(line)
        if old_match:
            legacy_matches += 1
            if not DLL.fullmatch(old_match[1]):
                invalid_legacy_names += 1
            elif old_match[1].upper() in legacy_names or len(legacy_names) < MAX_NAMES:
                legacy_names.add(old_match[1].upper())
            else:
                truncated = True
        if name is not None:
            trimmed_matches += 1
            if name in trimmed_names or len(trimmed_names) < MAX_NAMES:
                trimmed_names.add(name)
            else:
                truncated = True
        elif ".dll" in line.lower():
            dll_like_other += 1
        if kind == "dependency_header":
            header_count += 1
        indent = len(line) - len(line.lstrip())
        record = {"kind": kind, "count": 1, "indent_min": indent,
                  "indent_max": indent, "chars_min": len(line), "chars_max": len(line)}
        if name is not None:
            record["dll"] = name
        if structure and name is None and structure[-1]["kind"] == kind:
            previous = structure[-1]
            previous["count"] += 1
            for field, function in (("indent_min", min), ("indent_max", max),
                                    ("chars_min", min), ("chars_max", max)):
                previous[field] = function(previous[field], record[field])
        elif len(structure) < MAX_STRUCTURE:
            structure.append(record)
        else:
            truncated = True
    imports = retained_import_lines(data) if mode == "imports" else []
    return {
        "label": label, "mode": mode, "status": result["status"],
        "exit_code": result["exit_code"], "captured_bytes": len(data),
        "encoding": encoding, "replacement_characters": text.count("\ufffd"),
        "nul_bytes": data.count(b"\0"), "line_count": len(lines),
        "max_line_chars": max((len(line) for line in lines), default=0),
        "retained_import_line_count": len(imports),
        "retained_import_max_chars": max((len(line) for line in imports), default=0),
        "legacy_match_count": legacy_matches, "trimmed_match_count": trimmed_matches,
        "invalid_legacy_name_count": invalid_legacy_names,
        "legacy_names": sorted(legacy_names), "trimmed_names": sorted(trimmed_names),
        "dll_like_other_count": dll_like_other, "dependency_header_count": header_count,
        "fixture_truncated": truncated, "structure": structure,
    }


def collect(targets, dumpbin, *, runner=capture, system_version=""):
    records = []
    local_imports = {}
    for label, mode in (
            ("full", "dependents"), ("identity_only", "dependents"),
            ("system_winhttp", "dependents"), ("full", "imports"),
            ("identity_only", "imports")):
        # No acceptance decision until all five read-only observations exist.
        outcome = runner([str(dumpbin), "/nologo", "/" + mode, str(targets[label])])
        records.append(parse_output(label, mode, outcome))
        if mode == "imports":
            # Kept runner-local only. Existing publication emits their hashes,
            # never these strings. Preserve the original trimmed-table meaning.
            local_imports[label] = retained_import_lines(outcome["data"])
    failures = []
    for record in records:
        if record["status"] != "completed" or record["exit_code"] != 0:
            failures.append("capture_failed")
        if record["fixture_truncated"]:
            failures.append("fixture_incomplete")
        if record["invalid_legacy_name_count"]:
            failures.append("invalid_dependency_name")
        if record["mode"] == "dependents":
            if not 1 <= len(record["legacy_names"]) <= ACCEPTED_DLL_LIMIT:
                failures.append("dependency_count")
            if record["dependency_header_count"] != 1:
                failures.append("dependency_header")
        elif record["line_count"] > 2048 or record["retained_import_max_chars"] > 512:
            failures.append("import_bound")
    by_key = {(item["label"], item["mode"]): item for item in records}
    full = by_key["full", "dependents"]["legacy_names"]
    minimal = by_key["identity_only", "dependents"]["legacy_names"]
    if "WINHTTP.DLL" not in full or "WINHTTP.DLL" in minimal:
        failures.append("http_variant_distinction")
    fixture = {
        "schema_version": 1, "stage": "dumpbin-parser-diagnostic",
        "sanitized": True, "byte_exact": False, "runtime_performed": False,
        "accepted_dll_limit": ACCEPTED_DLL_LIMIT,
        "metadata_gate_passed": not failures, "failures": sorted(set(failures)),
        "observations": records,
    }
    validate_fixture(fixture)
    audit = None
    if not failures:
        audit = {"schema_version": 1, "full": full, "identity_only": minimal,
                 "system_winhttp": by_key["system_winhttp", "dependents"]["legacy_names"],
                 "system_winhttp_file_version": system_version}
        for label in ("full", "identity_only"):
            audit[label + "_import_table"] = local_imports[label]
    return fixture, audit


def validate_fixture(value):
    """Reject unknown fields and raw strings before any diagnostic is saved."""
    top = {"schema_version", "stage", "sanitized", "byte_exact", "runtime_performed",
           "accepted_dll_limit", "metadata_gate_passed", "failures", "observations"}
    fields = {
        "label", "mode", "status", "exit_code", "captured_bytes", "encoding",
        "replacement_characters", "nul_bytes", "line_count", "max_line_chars",
        "retained_import_line_count", "retained_import_max_chars",
        "legacy_match_count", "trimmed_match_count", "legacy_names", "trimmed_names",
        "invalid_legacy_name_count",
        "dll_like_other_count", "dependency_header_count", "fixture_truncated", "structure",
    }
    numeric = fields - {
        "label", "mode", "status", "exit_code", "encoding", "legacy_names",
        "trimmed_names", "fixture_truncated", "structure",
    }
    if not isinstance(value, dict) or set(value) != top:
        raise ValueError("closed diagnostic schema required")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["stage"] != "dumpbin-parser-diagnostic"
            or value["sanitized"] is not True or value["byte_exact"] is not False
            or value["runtime_performed"] is not False
            or value["accepted_dll_limit"] != ACCEPTED_DLL_LIMIT
            or type(value["metadata_gate_passed"]) is not bool
            or not isinstance(value["failures"], list)
            or any(item not in FAILURES for item in value["failures"])):
        raise ValueError("invalid diagnostic header")
    if value["metadata_gate_passed"] != (not value["failures"]):
        raise ValueError("diagnostic gate contradiction")
    records = value["observations"]
    if not isinstance(records, list) or len(records) != 5:
        raise ValueError("all fixed observations required")
    expected = [("full", "dependents"), ("identity_only", "dependents"),
                ("system_winhttp", "dependents"), ("full", "imports"),
                ("identity_only", "imports")]
    for item, pair in zip(records, expected):
        if not isinstance(item, dict) or set(item) != fields:
            raise ValueError("closed observation schema required")
        if ((item["label"], item["mode"]) != pair or item["status"] not in STATUSES
                or item["encoding"] not in ("utf8", "utf16_bom")
                or type(item["fixture_truncated"]) is not bool):
            raise ValueError("invalid observation category")
        if any(type(item[key]) is not int or not 0 <= item[key] <= MAX_CAPTURE_BYTES
               for key in numeric):
            raise ValueError("bounded diagnostic integers required")
        if item["exit_code"] is not None and (
                type(item["exit_code"]) is not int or
                not -(2**31) <= item["exit_code"] <= 0xffffffff):
            raise ValueError("invalid exit status")
        for key in ("legacy_names", "trimmed_names"):
            names = item[key]
            if (not isinstance(names, list) or len(names) > MAX_NAMES or
                    any(not isinstance(name, str) or not DLL.fullmatch(name) for name in names)):
                raise ValueError("DLL basenames only")
        rows = item["structure"]
        if not isinstance(rows, list) or len(rows) > MAX_STRUCTURE:
            raise ValueError("bounded structure required")
        for row in rows:
            required = {"kind", "count", "indent_min", "indent_max", "chars_min", "chars_max"}
            if not isinstance(row, dict) or set(row) not in (required, required | {"dll"}):
                raise ValueError("closed structure schema required")
            if row["kind"] not in KINDS:
                raise ValueError("fixed line category required")
            if any(type(row[key]) is not int or not 0 <= row[key] <= MAX_CAPTURE_BYTES
                   for key in required - {"kind"}):
                raise ValueError("bounded structure integers required")
            if ("dll" in row) != (row["kind"] == "dll"):
                raise ValueError("DLL category mismatch")
            if "dll" in row and (not isinstance(row["dll"], str) or not DLL.fullmatch(row["dll"])):
                raise ValueError("DLL basename only")


def write_new(path, value, limit):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > limit:
        raise ValueError("sanitized report exceeds byte limit")
    with Path(path).open("xb") as stream:
        stream.write(data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("dumpbin", "full", "identity", "system-winhttp", "audit", "fixture"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--system-version", default="")
    args = parser.parse_args(argv)
    if os.name != "nt":
        raise ValueError("installed Windows dumpbin required")
    if not re.fullmatch(r"[0-9A-Za-z ()._-]{0,128}", args.system_version):
        raise ValueError("bounded public file-version metadata required")
    fixture, audit = collect(
        {"full": args.full, "identity_only": args.identity, "system_winhttp": args.system_winhttp},
        args.dumpbin, system_version=args.system_version,
    )
    # The fixture is retained even when zero matches, >64 DLLs, or tool errors
    # fail the gate. Never create an audit that could enable runtime on failure.
    write_new(args.fixture, fixture, MAX_FIXTURE_BYTES)
    if audit is None:
        print("Dumpbin metadata gate failed; all sanitized parser observations retained.")
        return 1
    write_new(args.audit, audit, 128 * 1024)
    print("Dumpbin metadata gate passed; sanitized parser observations retained.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
