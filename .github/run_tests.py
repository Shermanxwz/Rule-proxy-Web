"""Run the test suite in CI and report each failure as a GitHub annotation.

Annotations appear on the run and pull request pages, so a failure can be read
without downloading the job log.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def escape(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape(text).replace(":", "%3A").replace(",", "%2C")


def main() -> int:
    # CI logs are UTF-8; the Windows runner's pipes default to cp1252 and cannot encode Chinese.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    suite = unittest.TestLoader().discover(str(ROOT / "tests"), top_level_dir=str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    for test, trace in result.failures + result.errors:
        # Keep the end of the traceback: it holds the assertion and the failing line.
        print(f"::error title={escape_property(test.id())}::{escape(trace[-3500:])}", flush=True)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
