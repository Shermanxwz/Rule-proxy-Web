"""Shared filesystem fixtures for the pure Windows identity tests only."""
from contextlib import contextmanager
from pathlib import Path
import tempfile


@contextmanager
def owned_temp_directory():
    """Yield the canonical spelling that production input validation supplies.

    Windows tempfile can return an 8.3 parent spelling. Tests that bypass the
    production validator must not pass that raw spelling into an owned-path
    containment check. This helper does not alter production alias/reparse gates.
    """
    with tempfile.TemporaryDirectory() as directory:
        yield Path(directory).resolve(strict=True)
