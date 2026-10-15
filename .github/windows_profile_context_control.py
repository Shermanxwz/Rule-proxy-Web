"""Read-only Windows LocalAppData/profile-layout control; never an acceptance check."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import ntpath


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
GITHUB_DIR = str(ROOT / ".github")
if GITHUB_DIR not in sys.path:
    sys.path.insert(0, GITHUB_DIR)

import windows_gui_context as context
from ruleproxy import windows_runtime


REPORT_LIMIT = 8192
CHILD_TIMEOUT_SECONDS = 30
CASES = ("inherited_environment", "relocated_flat_profile", "relocated_with_standard_appdata")


def _numeric_error(exc: BaseException) -> int:
    try:
        value = int(getattr(exc, "winerror", None) or getattr(exc, "errno", None) or 1)
    except (TypeError, ValueError):
        return 1
    return value & 0xFFFFFFFF


def _normalized(path: str) -> str:
    return ntpath.normcase(ntpath.normpath(path))


def _child(case: str, report_path: Path) -> int:
    facts: dict = {
        "schema": 1,
        "case": case,
        "windows": os.name == "nt",
        "acceptance_passed": False,
        "localappdata_known_folder_path_matches_userprofile_appdata_local": False,
        "dontverify_known_folder_path_matches_userprofile_appdata_local": False,
        "localappdata_known_folder_path_matches_localappdata_environment": False,
        "standard_appdata_local_exists": False,
        "standard_appdata_roaming_exists": False,
        "known_folder_location_query_success": False,
        "known_folder_location_error": 0,
    }
    try:
        api = context.WindowsApi()
        facts["context"] = context.query_context(api=api, environ=os.environ)
        user_profile = os.environ.get("USERPROFILE")
        if user_profile:
            expected_local = ntpath.join(user_profile, "AppData", "Local")
            expected_roaming = ntpath.join(user_profile, "AppData", "Roaming")
            facts["standard_appdata_local_exists"] = os.path.isdir(expected_local)
            facts["standard_appdata_roaming_exists"] = os.path.isdir(expected_roaming)
            dont_verify = api.get_known_folder_path_without_verify(expected_local, True)
            facts["dontverify_known_folder_path_matches_userprofile_appdata_local"] = bool(
                dont_verify.get("success") and
                dont_verify.get("path_matches_localappdata_environment") is True
            )
        else:
            expected_local = None
        try:
            # This repeats the API's ordinary flags=0 query solely to compare
            # paths in memory; the actual path is never serialized.
            known = api.known_folder_location()
            facts["known_folder_location_query_success"] = True
            local_appdata = os.environ.get("LOCALAPPDATA")
            if local_appdata:
                facts["localappdata_known_folder_path_matches_localappdata_environment"] = (
                    _normalized(str(known)) == _normalized(local_appdata)
                )
            if expected_local:
                facts["localappdata_known_folder_path_matches_userprofile_appdata_local"] = (
                    _normalized(str(known)) == _normalized(expected_local)
                )
        except Exception as exc:
            facts["known_folder_location_error"] = _numeric_error(exc)
    except Exception as exc:
        facts["probe_error"] = {"type": type(exc).__name__, "code": _numeric_error(exc)}
    try:
        context.write_report(report_path, facts)
    except Exception:
        return 2
    return 0


def _case_environment(case: str, parent: Path) -> dict[str, str]:
    environment = os.environ.copy()
    if case == "inherited_environment":
        return environment
    # Reuse the same absolute paths in both relocated cases. Only the
    # existence of the standard AppData children changes between processes.
    profile = parent / "relocated-profile"
    profile.mkdir(exist_ok=True)
    environment = windows_runtime._profile_environment(environment, profile)
    if case == "relocated_flat_profile":
        # Retain the legacy missing-directory negative control after the
        # production environment builder has been corrected. These are empty
        # directories in this harness's fresh, owned temporary profile.
        home = Path(environment["USERPROFILE"])
        for child in (home / "AppData" / "Local", home / "AppData" / "Roaming"):
            if child.exists():
                child.rmdir()
    if case == "relocated_with_standard_appdata":
        home = Path(environment["USERPROFILE"])
        (home / "AppData" / "Local").mkdir(parents=True, exist_ok=True)
        (home / "AppData" / "Roaming").mkdir(parents=True, exist_ok=True)
    return environment


def _run_case(case: str, temporary: Path) -> dict:
    report_path = temporary / f"{case}.json"
    environment = _case_environment(case, temporary)
    command = [sys.executable, "-I", "-S", str(Path(__file__).resolve()),
               "--child", case, "--child-report", str(report_path)]
    record = {"case": case, "acceptance_passed": False}
    try:
        completed = subprocess.run(command, cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=CHILD_TIMEOUT_SECONDS, check=False)
        record["child_exit_code"] = int(completed.returncode)
    except subprocess.TimeoutExpired:
        record.update(child_timeout=True, child_exit_code=-1)
    except Exception as exc:
        record.update(child_timeout=False, child_exit_code=-1,
                      launch_error={"type": type(exc).__name__, "code": _numeric_error(exc)})
    try:
        with report_path.open("rb") as stream:
            payload = stream.read(REPORT_LIMIT + 1)
        if len(payload) <= REPORT_LIMIT:
            loaded = json.loads(payload.decode("utf-8"))
            if isinstance(loaded, dict) and loaded.get("case") == case:
                record["facts"] = loaded
                record["report_available"] = True
            else:
                record["report_available"] = False
        else:
            record["report_available"] = False
    except Exception:
        record["report_available"] = False
    return record


def _parent(report_path: Path) -> int:
    result = {"schema": 1, "diagnostic_only": True, "acceptance_passed": False,
              "cases": [], "case_timeout_seconds": CHILD_TIMEOUT_SECONDS,
              "cleanup_proven": False, "collection_complete": False}
    if os.name == "nt":
        version = sys.getwindowsversion()
        result.update(host_windows_build=int(version.build),
                      host_windows_product_type=int(version.product_type))
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as key:
                result["host_windows_ubr"] = int(winreg.QueryValueEx(key, "UBR")[0])
        except OSError as exc:
            result["host_windows_ubr_query_error"] = _numeric_error(exc)
    try:
        with tempfile.TemporaryDirectory(prefix="ruleproxy-profile-context-") as temporary:
            parent = Path(temporary)
            for case in CASES:
                result["cases"].append(_run_case(case, parent))
        result["cleanup_proven"] = True
        result["collection_complete"] = len(result["cases"]) == len(CASES) and all(
            case.get("child_exit_code") == 0 and case.get("report_available") is True
            for case in result["cases"])
    except Exception as exc:
        result["harness_error"] = {"type": type(exc).__name__, "code": _numeric_error(exc)}
    try:
        context.write_report(report_path, result)
    except Exception:
        return 2
    return 0 if result["collection_complete"] and result["cleanup_proven"] else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, default=Path("windows-profile-context-control.json"))
    parser.add_argument("--child", choices=CASES)
    parser.add_argument("--child-report", type=Path)
    args = parser.parse_args(argv)
    if args.child is not None:
        if args.child_report is None or not args.child_report.is_absolute():
            parser.error("--child-report must be an absolute path")
        return _child(args.child, args.child_report)
    if args.child_report is not None:
        parser.error("--child-report is reserved for child invocations")
    return _parent(args.report)


if __name__ == "__main__":
    raise SystemExit(main())
