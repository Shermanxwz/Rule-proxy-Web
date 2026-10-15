"""Assemble the pinned G runtime asset from a verified build artifact directory.

This is a release/CI helper, not a compiler. The executor, provenance manifest
and MIT license must already be present and match install_runtime.py pins.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install_runtime  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_directory", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args(argv)
    try:
        digest = install_runtime.build_g_bundle(args.artifact_directory, args.output)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"Built pinned G runtime bundle SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
