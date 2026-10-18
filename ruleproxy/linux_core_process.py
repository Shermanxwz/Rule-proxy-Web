"""Exec the ordinary Linux global core with a kernel parent-death signal.

This small, separate interpreter avoids preexec_fn in the threaded Web panel.
It changes no namespaces, routes, firewall rules, DNS or system settings.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path
import signal
import sys


def command_for_parent(command):
    return [sys.executable, '-B', str(Path(__file__).resolve()), str(os.getpid()), *command]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if sys.platform != 'linux' or len(args) < 2 or not args[0].isdigit() or int(args[0]) <= 1:
        raise ValueError('A live Linux parent and executable command are required')
    parent = int(args[0])
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        raise OSError(ctypes.get_errno(), 'Could not bind the core to its panel parent')
    # Covers the race where the original parent died before prctl completed.
    if os.getppid() != parent:
        return 1
    os.execv(args[1], args[1:])
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
