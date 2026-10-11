"""RuleProxy local application manager."""

from pathlib import Path
import sys

vendor = Path(__file__).resolve().parent.parent / "vendor"
if vendor.is_dir():
    sys.path.insert(0, str(vendor))

__version__ = "0.2.0"
