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
    suite = unittest.TestLoader().discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
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
