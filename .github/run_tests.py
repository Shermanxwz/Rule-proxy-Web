"""Run the test suite in CI and report each failure as a GitHub annotation.

Annotations appear on the run and pull request pages, so a failure can be read
without downloading the job log.

Usage: python run_tests.py [--code FOLDER]

--code tests the ruleproxy package in FOLDER instead of this checkout, such as
an unpacked release package run with its own Python.
"""
import argparse
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape(text).replace(":", "%3A").replace(",", "%2C")


def main(argv: list[str]) -> int:
    # CI logs are UTF-8; the Windows runner's pipes default to cp1252 and cannot encode Chinese.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Run the RuleProxy test suite.")
    parser.add_argument("--code", type=Path, default=ROOT, help="folder holding the ruleproxy package under test")
    code = parser.parse_args(argv).code.resolve()
    sys.path.insert(0, str(code))
    import ruleproxy  # first, so the package's own vendor/ folder is on the path before any test imports yaml

    if Path(ruleproxy.__file__).resolve().parent.parent != code:
        print(f"::error title=Test setup::ruleproxy was imported from {ruleproxy.__file__}, not {code}", flush=True)
        return 1
    print(f"Testing ruleproxy {ruleproxy.__version__} in {code} with Python {sys.version.split()[0]} ({sys.executable})", flush=True)
    # Archived experiment harnesses under .github/ share module names with
    # tests/ modules (e.g. test_windows_n0a_actor.py exists in both). When a
    # harness copy is imported first, unittest discovery refuses the tests/
    # copy as "incorrectly imported". Seed the tests/ copies under their
    # plain names first so discovery sees the expected files.
    tests_dir = ROOT / "tests"
    harness_dir = ROOT / ".github"
    if harness_dir.is_dir():
        import importlib.util

        harness_names = {p.stem for p in harness_dir.glob("*.py")}
        for test_file in sorted(tests_dir.glob("*.py")):
            if test_file.stem in harness_names and test_file.stem not in sys.modules:
                spec = importlib.util.spec_from_file_location(test_file.stem, test_file)
                module = importlib.util.module_from_spec(spec)
                sys.modules[test_file.stem] = module
                spec.loader.exec_module(module)
    suite = unittest.TestLoader().discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
    # Archived identity-proof laboratory modules (project wrap-up, 2026-10-25).
    # These tests exercise the paused LPAC identity-pipe experiment line and
    # only pass inside its staged laboratory workflows, which remain in this
    # repository (.github/workflows/windows-identity-*.yml and peers). They
    # were never part of the product suite: the line's own CI excluded them
    # from this runner. They stay in the tree as archived evidence and are
    # listed here explicitly; the runner reports how many were excluded.
    ARCHIVED_LAB_MODULES = {
    "test_windows_client_identity_stage0",
    "test_windows_client_n0a_udp6_host",
    "test_windows_client_n0a_udp6_packet",
    "test_windows_client_n0a_udp_parent_host",
    "test_windows_identity_dns_cases_fixture",
    "test_windows_identity_dns_standard_local",
    "test_windows_identity_dns_standard_native",
    "test_windows_identity_lpac_curl_a5_config_native",
    "test_windows_identity_lpac_curl_http_adapter",
    "test_windows_identity_lpac_curl_http_events",
    "test_windows_identity_lpac_curl_http_pipe_win32",
    "test_windows_identity_lpac_curl_http_surface",
    "test_windows_identity_lpac_curl_loader_native",
    "test_windows_identity_lpac_curl_mm_loader",
    "test_windows_identity_lpac_curl_mm_loader_local",
    "test_windows_identity_lpac_curl_mm_loader_native",
    "test_windows_identity_lpac_curl_ws2_startup_native",
    "test_windows_identity_lpac_identity_local",
    "test_windows_identity_lpac_loopback_native",
    "test_windows_identity_lpac_pipe_dns_front_native",
    "test_windows_identity_lpac_pipe_front_native",
    "test_windows_identity_lpac_registry_loopback_native",
    "test_windows_identity_lpac_semantic_dns_local",
    "test_windows_identity_lpac_stream_mihomo_native",
    "test_windows_identity_lpac_stream_native",
    "test_windows_identity_model2_local_probe",
    "test_windows_identity_pipe_probe",
    "test_windows_identity_proxy_c_dns_candidate",
    "test_windows_identity_proxy_c_native",
    "test_windows_identity_proxy_c_raw_udp_candidate",
    "test_windows_identity_proxy_origin_native",
    "test_windows_identity_proxy_origin_probe",
    "test_windows_identity_proxy_pipe_ac_local",
    "test_windows_identity_proxy_pipe_probe",
    "test_windows_identity_psec_lpac_bridge_local",
    "test_windows_identity_psec_lpac_bridge_native",
    "test_windows_identity_psec_lpac_matchedcaps_bridge_local",
    "test_windows_identity_psec_lpac_matchedcaps_native",
    "test_windows_identity_psec_lpac_postassign_bridge_local",
    "test_windows_identity_stage0b_guest",
    "test_windows_n0a_capture_child_qemu",
    "test_windows_n0a_capture_qemu",
    "test_windows_n0a_udp6_workflow",
    "test_windows_n0a_workflow",
    "test_windows_provider_cache_recovery",
    "test_windows_dns_request3",
    "test_windows_identity_lpac_curl_loader_backend",
    "test_windows_identity_psec_lpac_bridge",
    "test_windows_identity_psec_lpac_matchedcaps_bridge",
    "test_windows_identity_psec_lpac_postassign_bridge",
    }
    def _without_archived_lab(suite):
        kept = unittest.TestSuite()
        dropped = 0
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                sub = _without_archived_lab(item)
                dropped += sub[1]
                if sub[0].countTestCases():
                    kept.addTest(sub[0])
            elif item.id().split(".")[0] in ARCHIVED_LAB_MODULES:
                dropped += 1
            else:
                kept.addTest(item)
        return kept, dropped
    suite, dropped = _without_archived_lab(suite)
    print(f"::notice title=Archived lab exclusions::Excluded {dropped} tests from {len(ARCHIVED_LAB_MODULES)} archived identity-proof laboratory modules; they run under their dedicated workflows, not the product suite.", flush=True)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    for test, trace in result.failures + result.errors:
        # Keep the end of the traceback: it holds the assertion and the failing line.
        print(f"::error title={escape_property(test.id())}::{escape(trace[-3500:])}", flush=True)
    # Say what ran and what was skipped, so a skipped sandbox test cannot pass unnoticed.
    summary = f"Ran {result.testsRun} tests, {len(result.failures) + len(result.errors)} failed, {len(result.skipped)} skipped."
    skipped = "\n".join(f"skipped {test.id()}: {reason}" for test, reason in result.skipped)
    print(f"::notice title=Test summary::{escape(summary + (chr(10) + skipped if skipped else ''))}", flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
