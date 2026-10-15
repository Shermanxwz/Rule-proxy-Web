"""Check visible stock Edge windows in the production PSEC against fixed HTTP bytes.

Run with native x64 package Python in an ordinary interactive Windows 11 VM:
  python .github/windows_gui_check.py --root PACKAGE --report gui.json

The existing production startup bounds remain unchanged. Each launch then has
90 seconds for a visible window, DOM/cookie acknowledgement and natural close.
This is an HTTP GUI fixture, never full, HTTPS, login, public UDP or DNS acceptance.
"""
from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
import hashlib
import importlib.util
import json
import ntpath
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
MAX_HANDLES = 64
GUI_BUDGET_SECONDS = 90
_RECOVERY_OWNERS = []  # Failed cleanup keeps the actual handles, not just PIDs.
_DIAGNOSTIC_STAGES = frozenset({
    "unknown", "platform", "runtime_integrity", "request_probe", "host_network_snapshot",
    "real_edge_gui_1", "real_edge_gui_2", "image_path_canonicalize", "process_api_bind",
    "tree_root_identity", "tree_held_pid_query", "tree_held_creation_query",
    "tree_snapshot_first", "tree_snapshot_second", "tree_child_open", "tree_child_pid_query",
    "tree_child_creation_query", "tree_child_alive_query", "tree_parent_alive_query",
    "tree_parent_exit_time_query", "tree_child_image_query", "tree_owner_alive_query",
    "tree_owner_image_query", "tree_exit_query", "tree_exit_wait", "tree_query_handle_close",
    "tree_construct", "tree_refresh", "tree_startup_helper_verify", "tree_close_exited",
    "window_api_bind", "window_enumeration", "window_pid_query", "window_visibility_query",
    "window_close_post", "interactive_context_query", "app_prepare", "fixture_begin",
    "fixture_ack", "fixture_close", "runtime_launch", "startup_evidence", "wrapper_poll",
    "runtime_safe_stop", "runtime_resources_close", "wrapper_handle_close",
    "owner_cleanup", "profile_remove", "host_snapshot_after",
    "failure_fixture_counts", "failure_owned_windows",
    "tree_diagnostic_query_open", "tree_diagnostic_pid_query", "tree_diagnostic_creation_query",
    "tree_diagnostic_image_query", "tree_diagnostic_snapshot_second", "tree_diagnostic_parent_identity",
    "tree_diagnostic_handle_close",
})


def error_facts(error, fallback_stage="unknown"):
    """Finite operation names and integer codes; never filenames or traceback text."""
    stage = getattr(error, "_gui_diagnostic_stage", fallback_stage)
    if type(stage) is not str or stage not in _DIAGNOSTIC_STAGES:
        stage = "unknown"
    name = type(error).__name__
    if name not in {"PermissionError", "FileNotFoundError", "OSError", "RuntimeError",
                    "TimeoutError", "ValueError", "TypeError", "AttributeError",
                    "NotImplementedError"}:
        name = "Exception"
    facts = {"stage": stage, "error_type": name}
    for key in ("errno", "winerror"):
        value = getattr(error, key, None)
        facts[key] = value if type(value) is int and 0 <= value <= 0xffffffff else None
    context = getattr(error, "_gui_process_open_context", None)
    if isinstance(context, dict) and context.get("operation") == "OpenProcess":
        facts["operation"] = "OpenProcess"
        for key, limit in (("candidate_pid", 2**32), ("parent_pid", 2**32),
                           ("parent_creation_filetime", 2**64), ("requested_access", 2**32)):
            value = context.get(key)
            if type(value) is int and 0 < value < limit:
                facts[key] = value
    diagnostic = getattr(error, "_gui_query_only_diagnostic", None)
    if isinstance(diagnostic, dict):
        # This is a fixed diagnostic record, not arbitrary exception contents.
        safe = {"requested_access": 0x1000}
        status = diagnostic.get("status")
        if type(status) is str and status in {"observed", "incomplete", "not_repeated", "limit_reached"}:
            safe["status"] = status
        for key in ("opened", "pid_matches", "older_than_parent", "second_parent_matches",
                    "parent_identity_verified", "image_matches_edge", "handle_closed"):
            value = diagnostic.get(key)
            if type(value) is bool or value is None:
                safe[key] = value
        created = diagnostic.get("process_created")
        if type(created) is int and 0 < created < 2**64:
            safe["process_created"] = created
        image_hash = diagnostic.get("image_key_sha256")
        if isinstance(image_hash, str) and len(image_hash) == 64 and all(c in "0123456789abcdef" for c in image_hash):
            safe["image_key_sha256"] = image_hash
        for key in ("failure", "close_failure"):
            value = diagnostic.get(key)
            if (isinstance(value, dict) and type(value.get("stage")) is str
                    and value["stage"] in _DIAGNOSTIC_STAGES):
                kind = value.get("error_type")
                allowed = {"PermissionError", "FileNotFoundError", "OSError", "RuntimeError", "TimeoutError",
                           "ValueError", "TypeError", "AttributeError", "NotImplementedError", "Exception"}
                safe[key] = {"stage": value["stage"],
                             "error_type": kind if type(kind) is str and kind in allowed else "Exception"}
                for name in ("errno", "winerror"):
                    number = value.get(name)
                    safe[key][name] = number if type(number) is int and 0 <= number <= 0xffffffff else None
        facts["query_only_diagnostic"] = safe
    return facts


def _diagnostic_call(stage, function, *args, **kwargs):
    if stage not in _DIAGNOSTIC_STAGES:
        raise ValueError("unregistered GUI diagnostic stage")
    try:
        return function(*args, **kwargs)
    except Exception as error:
        # Preserve the original exception, owner and pending handles. An inner
        # operation is more precise than the caller's broader phase label.
        previous_stage = getattr(error, "_gui_diagnostic_stage", None)
        if type(previous_stage) is not str or previous_stage not in _DIAGNOSTIC_STAGES:
            error._gui_diagnostic_stage = stage
        raise


def owner_facts(owner):
    """Report existing ownership bookkeeping without making new kernel queries."""
    wrapper, tree = getattr(owner, "wrapper", None), getattr(owner, "tree", None)
    entries, pending = getattr(tree, "entries", None), getattr(tree, "pending", None)
    diagnostic_owners = getattr(tree, "diagnostic_query_owners", None)
    pid, created = getattr(wrapper, "pid", None), getattr(tree, "root_created", None)
    return {"wrapper_handle_retained": wrapper is not None,
            "runtime_resources_retained": getattr(owner, "resources", None) is not None,
            "tree_initialized": tree is not None,
            "wrapper_pid": pid if type(pid) is int and 0 < pid <= 0xffffffff else None,
            "wrapper_creation_filetime": created if type(created) is int and 0 < created < 2**64 else None,
            "attested_descendant_query_handles": len(entries) if isinstance(entries, dict) else None,
            "pending_query_handles": len(pending) if isinstance(pending, list) else None,
            "diagnostic_query_handles": len(diagnostic_owners) if isinstance(diagnostic_owners, list) else None,
            "query_handle_limit": MAX_HANDLES,
            "query_handle_scope": "gui_query_handles_and_borrowed_wrapper_only"}


def browser_helpers():
    path = ROOT / ".github/windows_browser_check.py"
    spec = importlib.util.spec_from_file_location("ruleproxy_gui_browser_helpers", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def image_key(path):
    value = os.fspath(path)
    if not ntpath.isabs(value):
        raise RuntimeError("process image is not an absolute Windows path")
    if os.name == "nt":
        value = str(_diagnostic_call("image_path_canonicalize", Path(value).resolve, strict=True))
    return ntpath.normcase(ntpath.normpath(value))


class ProcessApi:
    """Read-only query/synchronize handles; no terminate capability here."""

    PROCESS_ACCESS = 0x1000 | 0x00100000

    def __init__(self):
        from ruleproxy import windows_runtime
        self.api = _diagnostic_call("process_api_bind", windows_runtime._WinProcessApi)
        self.kernel = self.api.kernel32
        self.filetime = windows_runtime._FileTime
        self.kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        self.kernel.GetProcessId.restype = wintypes.DWORD

    def open(self, pid):
        handle = self.kernel.OpenProcess(self.PROCESS_ACCESS, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)

    def open_query(self, pid):
        handle = self.kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            raise ctypes.WinError(ctypes.get_last_error())
        return int(handle)

    def pid(self, handle):
        value = int(self.kernel.GetProcessId(handle))
        if not value:
            raise ctypes.WinError(ctypes.get_last_error())
        return value

    def created(self, handle):
        return self.api.process_creation_time(handle)

    def exited_at(self, handle):
        values = [self.filetime() for _ in range(4)]
        if not self.kernel.GetProcessTimes(handle, *(ctypes.byref(value) for value in values)):
            raise ctypes.WinError(ctypes.get_last_error())
        return (int(values[1].dwHighDateTime) << 32) | int(values[1].dwLowDateTime)

    def alive(self, handle):
        return self.api.process_alive(handle)

    def wait(self, handle, milliseconds):
        return self.api.wait(handle, milliseconds)

    def image(self, handle):
        return self.api.process_image(handle)

    def snapshot(self):
        return self.api._snapshot_parent_ids()

    def close(self, handle):
        self.api.close(handle)


class _DiagnosticQueryOwner:
    """Own one read-only diagnostic handle; it grants no process-tree authority."""
    def __init__(self, api, handle, facts):
        self.api, self.handle, self.facts = api, handle, facts

    def close(self):
        if self.handle is not None:
            _diagnostic_call("tree_diagnostic_handle_close", self.api.close, self.handle)
            self.handle = None
            self.facts["handle_closed"] = True


class OwnedTree:
    """Attest a new wrapper subtree using held generations and two snapshots.

    The wrapper HANDLE is borrowed from Popen. Every descendant query HANDLE
    remains held through teardown, including helpers with other image paths.
    A foreign PID is never opened just because it owns a desktop window.
    """

    def __init__(self, api, wrapper, edge):
        self.api, self.wrapper = api, wrapper
        self.edge = image_key(edge)
        self.root_handle = int(wrapper._handle)
        if _diagnostic_call("tree_root_identity", api.pid, self.root_handle) != wrapper.pid \
                or not _diagnostic_call("tree_root_identity", api.alive, self.root_handle):
            raise RuntimeError("wrapper held identity is not live")
        self.root_created = _diagnostic_call("tree_root_identity", api.created, self.root_handle)
        self.root = {"pid": wrapper.pid, "created": self.root_created,
                     "handle": self.root_handle, "depth": 0}
        self.entries = {}
        self.pending = []
        self.diagnostic_query_owners = []
        self.diagnostic_attempts = set()
        self.peak_handles = 1
        self.closed = False

    def _identity(self, entry):
        if _diagnostic_call("tree_held_pid_query", self.api.pid, entry["handle"]) != entry["pid"] \
                or _diagnostic_call("tree_held_creation_query", self.api.created, entry["handle"]) != entry["created"]:
            raise RuntimeError("held process generation changed")

    def _query_failure_candidate(self, pid, ppid, parent):
        facts = {"status": "incomplete", "requested_access": 0x1000, "opened": False,
                 "pid_matches": None, "older_than_parent": None, "second_parent_matches": None,
                 "parent_identity_verified": False, "image_matches_edge": None, "handle_closed": True}
        key = (pid, ppid, parent["created"])
        if key in self.diagnostic_attempts:
            facts["status"] = "not_repeated"
            return facts
        if (len(self.diagnostic_attempts) >= MAX_HANDLES or
                1 + len(self.entries) + len(self.pending) + len(self.diagnostic_query_owners) >= MAX_HANDLES):
            facts["status"] = "limit_reached"
            return facts
        self.diagnostic_attempts.add(key)
        owner = None
        try:
            handle = _diagnostic_call("tree_diagnostic_query_open", self.api.open_query, pid)
            owner = _DiagnosticQueryOwner(self.api, handle, facts)
            self.diagnostic_query_owners.append(owner)
            self.peak_handles = max(self.peak_handles,
                1 + len(self.entries) + len(self.pending) + len(self.diagnostic_query_owners))
            facts.update(opened=True, handle_closed=False)
            facts["pid_matches"] = _diagnostic_call("tree_diagnostic_pid_query", self.api.pid, handle) == pid
            if not facts["pid_matches"]:
                raise RuntimeError("diagnostic query PID differed from the candidate")
            created = _diagnostic_call("tree_diagnostic_creation_query", self.api.created, handle)
            if type(created) is not int or not 0 < created < 2**64:
                raise RuntimeError("diagnostic creation time was unavailable")
            facts.update(process_created=created, older_than_parent=created < parent["created"])
            _diagnostic_call("tree_diagnostic_parent_identity", self._identity, parent)
            second = _diagnostic_call("tree_diagnostic_snapshot_second", self.api.snapshot)
            _diagnostic_call("tree_diagnostic_parent_identity", self._identity, parent)
            facts["parent_identity_verified"] = True
            facts["second_parent_matches"] = second.get(pid) == ppid
            if (not facts["second_parent_matches"] or
                    _diagnostic_call("tree_diagnostic_creation_query", self.api.created, handle) != created):
                raise RuntimeError("diagnostic candidate changed between snapshots")
            image = image_key(_diagnostic_call("tree_diagnostic_image_query", self.api.image, handle))
            facts.update(image_key_sha256=hashlib.sha256(image.encode("utf-8")).hexdigest(),
                         image_matches_edge=image == self.edge, status="observed")
        except Exception as error:
            value = error_facts(error, "tree_diagnostic_query_open")
            facts["failure"] = {name: value[name] for name in ("stage", "error_type", "errno", "winerror")}
        finally:
            if owner is not None:
                try:
                    owner.close()
                    self.diagnostic_query_owners.remove(owner)
                except Exception as error:
                    value = error_facts(error, "tree_diagnostic_handle_close")
                    facts["close_failure"] = {name: value[name] for name in ("stage", "error_type", "errno", "winerror")}
        return facts

    def close_diagnostic_queries(self):
        for owner in list(self.diagnostic_query_owners):
            owner.close()
            self.diagnostic_query_owners.remove(owner)

    def refresh(self):
        if self.closed:
            raise RuntimeError("owned tree has already released its handles")
        self._identity(self.root)
        # An Edge child can start another sandbox process while these snapshots
        # are read. Repeating by depth discovers it without any name-based scan.
        for _ in range(32):
            parents = {self.wrapper.pid: self.root, **self.entries}
            first = _diagnostic_call("tree_snapshot_first", self.api.snapshot)
            added = False
            for pid, ppid in first.items():
                if pid == self.wrapper.pid or ppid not in parents or pid in self.entries:
                    continue
                parent = parents[ppid]
                self._identity(parent)
                if 1 + len(self.entries) + len(self.pending) + len(self.diagnostic_query_owners) >= MAX_HANDLES:
                    raise RuntimeError("owned process query handle limit exceeded")
                try:
                    handle = _diagnostic_call("tree_child_open", self.api.open, pid)
                except Exception as error:
                    # Correlation facts only: this candidate has NOT acquired
                    # owned-process or owned-window authority.
                    error._gui_process_open_context = {"operation": "OpenProcess", "candidate_pid": pid,
                        "parent_pid": ppid, "parent_creation_filetime": parent["created"],
                        "requested_access": ProcessApi.PROCESS_ACCESS}
                    if getattr(error, "winerror", None) == 5:
                        error._gui_query_only_diagnostic = self._query_failure_candidate(pid, ppid, parent)
                    raise
                self.pending.append(handle)
                self.peak_handles = max(self.peak_handles, 1 + len(self.entries) + len(self.pending))
                if _diagnostic_call("tree_child_pid_query", self.api.pid, handle) != pid:
                    raise RuntimeError("opened child PID did not match the snapshot")
                created = _diagnostic_call("tree_child_creation_query", self.api.created, handle)
                if created < parent["created"]:
                    # This is an old process carrying a recycled parent PID;
                    # the read-only handle grants it no owned-window authority.
                    _diagnostic_call("tree_query_handle_close", self.api.close, handle)
                    self.pending.remove(handle)
                    continue
                second = _diagnostic_call("tree_snapshot_second", self.api.snapshot)
                self._identity(parent)
                if second.get(pid) != ppid \
                        or _diagnostic_call("tree_child_creation_query", self.api.created, handle) != created:
                    raise RuntimeError("child lineage changed between process snapshots")
                if not _diagnostic_call("tree_child_alive_query", self.api.alive, handle):
                    _diagnostic_call("tree_query_handle_close", self.api.close, handle)
                    self.pending.remove(handle)
                    continue
                if not _diagnostic_call("tree_parent_alive_query", self.api.alive, parent["handle"]):
                    exited = _diagnostic_call("tree_parent_exit_time_query", self.api.exited_at, parent["handle"])
                    if not exited or created > exited:
                        raise RuntimeError("new child cannot be attributed to the held parent generation")
                image = image_key(_diagnostic_call("tree_child_image_query", self.api.image, handle))
                self.entries[pid] = {"pid": pid, "ppid": ppid, "created": created,
                                     "handle": handle, "depth": parent["depth"] + 1,
                                     "image": image}
                self.pending.remove(handle)
                added = True
            if not added:
                return
        raise RuntimeError("owned process lineage depth exceeded")

    def edge_owner(self, pid):
        entry = self.entries.get(pid)
        if entry is None or entry["image"] != self.edge:
            return None
        self._identity(entry)
        if not _diagnostic_call("tree_owner_alive_query", self.api.alive, entry["handle"]) \
                or image_key(_diagnostic_call("tree_owner_image_query", self.api.image, entry["handle"])) != self.edge:
            return None
        return entry

    def verify_startup_helper(self, parent):
        entry = self.entries.get(parent.get("pid")) if isinstance(parent, dict) else None
        if entry is None or entry["ppid"] != self.wrapper.pid \
                or parent.get("parent_pid") != self.wrapper.pid \
                or parent.get("process_created") != entry["created"]:
            raise RuntimeError("startup helper was not in the held wrapper generation")
        self._identity(entry)
        if not _diagnostic_call("tree_owner_alive_query", self.api.alive, entry["handle"]):
            raise RuntimeError("startup helper exited before GUI attestation")

    def all_exited(self):
        return not _diagnostic_call("tree_exit_query", self.api.alive, self.root_handle) and all(
            not _diagnostic_call("tree_exit_query", self.api.alive, entry["handle"]) for entry in self.entries.values()
        ) and all(not _diagnostic_call("tree_exit_query", self.api.alive, handle) for handle in self.pending)

    def close_exited(self, timeout=5):
        if self.closed:
            return
        self.close_diagnostic_queries()
        if type(timeout) not in (int, float) or not 0 <= timeout <= 5:
            raise ValueError("owned tree exit wait exceeds its fixed cleanup budget")
        deadline = time.monotonic() + timeout
        handles = [self.root_handle, *(entry["handle"] for entry in self.entries.values()), *self.pending]
        for handle in handles:
            # SDK teardown/accounting may finish before every descendant's
            # kernel handle is signaled. Keep one total deadline for all of
            # them; timeout never authorizes close or resource release.
            remaining = int(max(0.0, deadline - time.monotonic()) * 1000)
            if not _diagnostic_call("tree_exit_wait", self.api.wait, handle, remaining):
                raise RuntimeError("owned query handles still include a live process")
        for pid, entry in list(self.entries.items()):
            _diagnostic_call("tree_query_handle_close", self.api.close, entry["handle"])
            del self.entries[pid]
        for handle in list(self.pending):
            _diagnostic_call("tree_query_handle_close", self.api.close, handle)
            self.pending.remove(handle)
        self.closed = True


class WindowApi:
    """Enumerate/query desktop windows and post only a specifically verified close."""

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows desktop APIs are required")
        self.user = ctypes.WinDLL("user32", use_last_error=True)
        self.dwm = ctypes.WinDLL("dwmapi", use_last_error=True)
        self.callback = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        u = self.user
        u.EnumWindows.argtypes = [self.callback, wintypes.LPARAM]
        u.EnumWindows.restype = wintypes.BOOL
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.GetWindowThreadProcessId.restype = wintypes.DWORD
        u.IsWindowVisible.argtypes = u.IsIconic.argtypes = [wintypes.HWND]
        u.IsWindowVisible.restype = u.IsIconic.restype = wintypes.BOOL
        u.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
        u.GetWindowRect.restype = wintypes.BOOL
        u.GetSystemMetrics.argtypes = [ctypes.c_int]
        u.GetSystemMetrics.restype = ctypes.c_int
        u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u.PostMessageW.restype = wintypes.BOOL
        self.dwm.DwmGetWindowAttribute.argtypes = [wintypes.HWND, wintypes.DWORD,
                                                  ctypes.c_void_p, wintypes.DWORD]
        self.dwm.DwmGetWindowAttribute.restype = ctypes.c_long

    def pid(self, hwnd):
        pid = wintypes.DWORD()
        if not self.user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid)):
            return None  # A window may disappear during read-only enumeration.
        return int(pid.value)

    def windows(self, allowed_pids=None):
        if allowed_pids is not None and (not isinstance(allowed_pids, frozenset)
                or any(type(pid) is not int or not 0 < pid <= 0xffffffff for pid in allowed_pids)):
            raise ValueError("window filter requires fixed held process identifiers")
        values, overflow, visited = [], [], []
        def visit(hwnd, parameter):
            if len(visited) >= 1024:
                overflow.append(True)
                return False
            visited.append(None)  # Bound callbacks without retaining foreign HWND/PID data.
            pid = self.pid(hwnd)
            if pid and (allowed_pids is None or pid in allowed_pids):
                values.append((int(hwnd), pid))
            return True
        callback = self.callback(visit)
        ctypes.set_last_error(0)
        if not self.user.EnumWindows(callback, 0):
            if overflow:
                raise RuntimeError("desktop window enumeration limit exceeded")
            raise ctypes.WinError(ctypes.get_last_error())
        return values

    def visible_rect(self, hwnd):
        if not self.user.IsWindowVisible(hwnd) or self.user.IsIconic(hwnd):
            return None
        rect, cloaked = wintypes.RECT(), wintypes.DWORD()
        if not self.user.GetWindowRect(hwnd, ctypes.byref(rect)):
            return None
        # DWMWA_CLOAKED = 14, from the official dwmapi.h enumeration.
        if self.dwm.DwmGetWindowAttribute(hwnd, 14, ctypes.byref(cloaked), ctypes.sizeof(cloaked)) != 0:
            raise RuntimeError("DWM window visibility query failed")
        left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
        x, y, width, height = (self.user.GetSystemMetrics(index) for index in (76, 77, 78, 79))
        if cloaked.value or right <= left or bottom <= top or width <= 0 or height <= 0 \
                or right <= x or bottom <= y or left >= x + width or top >= y + height:
            return None
        return [left, top, right, bottom]

    def post_close(self, hwnd):
        if not hwnd or hwnd == 0xffff:
            raise RuntimeError("a specific owned window is required")
        if not self.user.PostMessageW(hwnd, 0x0010, 0, 0):  # WM_CLOSE, never broadcast.
            raise ctypes.WinError(ctypes.get_last_error())


def owned_windows(tree, windows, *, allowed_pids=None):
    values = []
    pairs = (_diagnostic_call("window_enumeration", windows.windows) if allowed_pids is None else
             _diagnostic_call("window_enumeration", windows.windows, allowed_pids=allowed_pids))
    for hwnd, pid in pairs:
        if allowed_pids is not None and pid not in allowed_pids:
            raise RuntimeError("window enumeration exceeded the held process filter")
        entry = tree.edge_owner(pid)
        if entry is None:
            continue
        rect = _diagnostic_call("window_visibility_query", windows.visible_rect, hwnd)
        if rect is not None and _diagnostic_call("window_pid_query", windows.pid, hwnd) == pid \
                and tree.edge_owner(pid) is not None:
            values.append({"hwnd": hwnd, "pid": pid, "created": entry["created"], "rect": rect})
    if len(values) > 16:
        raise RuntimeError("owned visible window limit exceeded")
    return values


def failure_auxiliary(owner, *, windows=None):
    """Counts only; never repair tracking failure or open another process HANDLE."""
    result = {"scope": "already_held_gui_failure_observations", "diagnostic_only": True}
    try:
        fixture = owner.fixture
        if not fixture.lock.acquire(timeout=0.1):
            raise TimeoutError("fixture count lock was unavailable")
        try:
            phase = fixture.phase
            if type(phase) is not int or phase not in (1, 2):
                raise ValueError("fixture phase was unavailable")
            pages, acks = len(fixture.pages[phase]), len(fixture.acks[phase])
            result["fixture"] = {"status": "observed", "phase": phase,
                "page_request_count": min(pages, 65535), "dom_ack_count": min(acks, 65535),
                "counts_capped": pages > 65535 or acks > 65535}
        finally:
            fixture.lock.release()
    except Exception as error:
        result["fixture"] = {"status": "incomplete", "failure": error_facts(error, "failure_fixture_counts")}
    try:
        tree = owner.tree
        if tree is None or tree.closed or len(tree.entries) > MAX_HANDLES - 1:
            raise RuntimeError("held process generations were unavailable")
        # Identity/image queries use only the existing held handles. Only
        # their verified Edge PIDs enter EnumWindows' retention filter.
        allowed = frozenset(pid for pid in tree.entries if tree.edge_owner(pid) is not None)
        visible = []
        if allowed:
            windows = _diagnostic_call("window_api_bind", WindowApi) if windows is None else windows
            visible = owned_windows(tree, windows, allowed_pids=allowed)
        result["visible_owned_windows"] = {"status": "observed", "held_edge_generation_count": len(allowed),
            "visible_window_count": len(visible), "visible_window_observed": bool(visible)}
    except Exception as error:
        result["visible_owned_windows"] = {"status": "incomplete", "failure": error_facts(error, "failure_owned_windows")}
    return result


def close_owned_window(tree, windows, value):
    pid = _diagnostic_call("window_pid_query", windows.pid, value["hwnd"])
    entry = tree.edge_owner(pid)
    if pid != value["pid"] or entry is None or entry["created"] != value["created"] \
            or _diagnostic_call("window_visibility_query", windows.visible_rect, value["hwnd"]) is None:
        raise RuntimeError("owned window identity changed before WM_CLOSE")
    # Revalidate the HWND immediately after all process/image/rectangle queries.
    if _diagnostic_call("window_pid_query", windows.pid, value["hwnd"]) != pid \
            or tree.edge_owner(pid) is None:
        raise RuntimeError("owned window generation changed before WM_CLOSE")
    _diagnostic_call("window_close_post", windows.post_close, value["hwnd"])


def interactive_facts():
    if os.name != "nt":
        raise OSError("an interactive Windows desktop is required")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    user = ctypes.WinDLL("user32", use_last_error=True)
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    shell.IsUserAnAdmin.argtypes, shell.IsUserAnAdmin.restype = [], wintypes.BOOL
    kernel.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel.GetCurrentThreadId.argtypes, kernel.GetCurrentThreadId.restype = [], wintypes.DWORD
    user.GetProcessWindowStation.argtypes, user.GetProcessWindowStation.restype = [], wintypes.HANDLE
    user.GetThreadDesktop.argtypes, user.GetThreadDesktop.restype = [wintypes.DWORD], wintypes.HANDLE
    user.GetUserObjectInformationW.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                               wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    user.GetUserObjectInformationW.restype = wintypes.BOOL
    session = wintypes.DWORD()
    if not kernel.ProcessIdToSessionId(os.getpid(), ctypes.byref(session)):
        raise ctypes.WinError(ctypes.get_last_error())
    def name(handle):
        buffer, needed = ctypes.create_unicode_buffer(256), wintypes.DWORD()
        if not handle or not user.GetUserObjectInformationW(handle, 2, buffer, ctypes.sizeof(buffer),
                                                             ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value
    station = name(user.GetProcessWindowStation())
    desktop = name(user.GetThreadDesktop(kernel.GetCurrentThreadId()))
    facts = {"token_is_admin": bool(shell.IsUserAnAdmin()), "session_id": int(session.value),
             "interactive_window_station": station.casefold() == "winsta0",
             "default_desktop": desktop.casefold() == "default"}
    facts["ordinary_interactive"] = not facts["token_is_admin"] and session.value > 0 \
        and facts["interactive_window_station"] and facts["default_desktop"]
    return facts


class GuiRun:
    def __init__(self, runtime, edge, profile_root, fixture, helpers, browser_module):
        self.runtime, self.edge, self.profile_root = runtime, edge, profile_root
        self.fixture, self.helpers, self.browser_module = fixture, helpers, browser_module
        self.wrapper = self.resources = self.tree = None
        self.cleanup_proven = True

    def run(self, phase):
        from ruleproxy import launcher, windows_runtime
        _diagnostic_call("fixture_begin", self.fixture.begin, phase)
        guest_port = windows_runtime.choose_guest_port(self.fixture.port)
        app = {"id": "gui", "label": "Visible Edge HTTP fixture", "path": str(self.edge),
               "adapter": "chromium", "args": ["--new-window", "--no-default-browser-check",
                                                  f"http://{self.browser_module.HOST}/phase/{phase}"]}
        command, environment, _ = _diagnostic_call("app_prepare", launcher.prepare_app,
                                                  app, guest_port, self.profile_root)
        startup_started = time.monotonic()
        self.cleanup_proven = False
        try:
            self.wrapper, self.resources = _diagnostic_call("runtime_launch", windows_runtime.launch,
                command, environment, self.profile_root / "gui", self.fixture.port,
                str(self.runtime), guest_listener_port=guest_port)
        except BaseException as exc:
            self.wrapper = getattr(exc, "process", None)
            self.resources = getattr(exc, "resource", None)
            raise
        startup_seconds = time.monotonic() - startup_started
        startup = _diagnostic_call("startup_evidence", self.helpers.startup_evidence, self.resources)
        deadline = time.monotonic() + GUI_BUDGET_SECONDS
        self.tree = _diagnostic_call("tree_construct", OwnedTree, ProcessApi(), self.wrapper, self.edge)
        _diagnostic_call("tree_refresh", self.tree.refresh)
        _diagnostic_call("tree_startup_helper_verify", self.tree.verify_startup_helper,
                         startup.get("startup_diagnostics", {}).get("parent"))
        windows = _diagnostic_call("window_api_bind", WindowApi)
        selected = []
        while time.monotonic() < deadline:
            if _diagnostic_call("wrapper_poll", self.wrapper.poll) is not None:
                raise RuntimeError("Edge/MXC exited before a visible acknowledged GUI window")
            _diagnostic_call("tree_refresh", self.tree.refresh)
            selected = owned_windows(self.tree, windows)
            if selected:
                try:
                    _diagnostic_call("fixture_ack", self.fixture.check, phase)
                    break
                except RuntimeError:
                    pass
            time.sleep(0.1)
        else:
            raise TimeoutError("visible Edge window and DOM cookie acknowledgement did not complete")
        rects = [value["rect"] for value in selected]
        posted = set()
        while time.monotonic() < deadline:
            _diagnostic_call("tree_refresh", self.tree.refresh)
            for value in owned_windows(self.tree, windows):
                key = (value["hwnd"], value["pid"], value["created"])
                if key not in posted:
                    close_owned_window(self.tree, windows, value)
                    posted.add(key)
            code = _diagnostic_call("wrapper_poll", self.wrapper.poll)
            if code is not None and self.tree.all_exited():
                if code:
                    raise RuntimeError(f"Edge/MXC natural GUI close exited with status {code}")
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("owned GUI window did not naturally exit within its shared budget")
        if not posted:
            raise RuntimeError("no attested owned WM_CLOSE request was posted")
        _diagnostic_call("fixture_ack", self.fixture.check, phase)
        count, peak = len(self.tree.entries), self.tree.peak_handles
        self.close()
        return {"check": f"real_edge_gui_{phase}", "status": "passed",
                "visible_window_verified": True, "visible_window_rects": rects,
                "dom_nonce_via_page_ack": True, "cookie_request_verified": True,
                "private_profile_reused": phase == 2, "wm_close_requested": True,
                "wm_close_window_count": len(posted), "natural_helper_wrapper_exit": True,
                "held_handles_verified": True, "descendant_cleanup_proven": True,
                "resources_closed": True, "held_descendant_count": count, "peak_query_handles": peak,
                "query_handle_scope": "gui_query_handles_and_borrowed_wrapper_only",
                "startup_seconds": round(startup_seconds, 3), "gui_budget_seconds": GUI_BUDGET_SECONDS,
                **startup}

    def close(self):
        from ruleproxy import windows_runtime
        self.cleanup_proven = False
        diagnostic_error = None
        if self.tree is not None:
            try:
                self.tree.close_diagnostic_queries()
            except Exception as error:
                diagnostic_error = error
        if self.wrapper is not None:
            _diagnostic_call("runtime_safe_stop", windows_runtime.stop, self.wrapper)
        if diagnostic_error is not None:
            raise diagnostic_error
        if self.tree is not None and not self.tree.closed:
            _diagnostic_call("tree_refresh", self.tree.refresh)  # Include a last child born during graceful shutdown.
            _diagnostic_call("tree_close_exited", self.tree.close_exited)
        if self.resources is not None:
            _diagnostic_call("runtime_resources_close", self.resources.close)
        if self.wrapper is not None and hasattr(self.wrapper._handle, "Close"):
            _diagnostic_call("wrapper_handle_close", self.wrapper._handle.Close)
        self.wrapper = self.resources = self.tree = None
        self.cleanup_proven = True


def initial_result():
    return {"status": "failed", "gui_fixture_passed": False, "acceptance_passed": False,
            "full_acceptance_passed": False, "real_node_passed": False,
            "public_udp_proven": False, "system_dns_proven": False, "checks": [],
            "query_handle_scope": "gui_query_handles_and_borrowed_wrapper_only",
            "limitations": ["Fixed local HTTP fixture only; no HTTPS, login or downloads tested.",
                            "Visible means nonzero on-screen, non-minimized, non-cloaked owned window; occlusion is not measured.",
                            "Production startup bounds are separate from the 90-second GUI/close budget."]}


def main(arguments):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--browser", type=Path, help="actual Microsoft Edge msedge.exe")
    parser.add_argument("--report", type=Path, default=Path("windows-gui.json"))
    args = parser.parse_args(arguments)
    browser_module = browser_helpers()
    helpers = browser_module.acceptance_helpers()
    result = initial_result()
    directory = fixture = owner = before = None
    safe_cleanup, code, phase = True, 1, "platform"
    try:
        facts = helpers.host_facts()
        result["host"] = facts
        if sys.platform != "win32" or facts.get("windows_product_type") != 1 \
                or facts.get("native_machine") != 0x8664 or facts.get("python_pe_machine") != 0x8664:
            result.update(status="unsupported", detail="Requires native x64 Windows 11 workstation Python.")
            return 3
        result["interactive"] = _diagnostic_call("interactive_context_query", interactive_facts)
        if not result["interactive"]["ordinary_interactive"]:
            result.update(status="unsupported", detail="Requires an ordinary user on the interactive default desktop.")
            return 3
        phase = "runtime_integrity"
        root = args.root.resolve(strict=True)
        sys.path.insert(0, str(root))
        helpers.verify_project_origin(root)
        from ruleproxy import windows_runtime
        digests = helpers.verify_runtime_manifest(root)
        result["runtime_integrity"] = {"manifest_verified": True, "file_count": len(digests)}
        runtime = root / "bin/windows-amd64/wxc-exec.exe"
        phase = "request_probe"
        result["probe"] = windows_runtime.probe(str(runtime))
        if not result["probe"]["supported"]:
            result.update(status="unsupported", detail=result["probe"]["detail"])
            return 3
        edge = browser_module.find_edge(args.browser)
        result["browser"] = {"launcher_pe_machine": helpers.executable_machine(edge),
                             "launcher_execution_scope": "native_x64", "headless": False,
                             "sandbox_weakened": False}
        if result["browser"]["launcher_pe_machine"] != 0x8664:
            raise RuntimeError("GUI requires the native x64 stock Edge entry point")
        phase = "host_network_snapshot"
        before = helpers.network_snapshot()
        directory = Path(tempfile.mkdtemp(prefix="ruleproxy-gui-"))
        fixture = browser_module.BrowserFixture()
        owner = GuiRun(runtime, edge, directory / "profiles", fixture, helpers, browser_module)
        for number in (1, 2):
            phase = f"real_edge_gui_{number}"
            result["checks"].append(owner.run(number))
        result.update(status="gui_fixture_only", gui_fixture_passed=True)
        code = 0
    except Exception as exc:
        result.update(status="failed", detail=f"GUI check failed during {phase} ({type(exc).__name__}): {str(exc)[:400]}")
        result["failure"] = error_facts(exc, phase)
        if owner is not None:
            result["failure_owner_state"] = owner_facts(owner)
            if result["failure"]["stage"] == "tree_child_open":
                result["failure_auxiliary"] = failure_auxiliary(owner)
    finally:
        if owner is not None:
            try:
                owner.close()
            except Exception as exc:
                safe_cleanup = False
                _RECOVERY_OWNERS.append(owner)
                result.update(status="failed", gui_fixture_passed=False, cleanup_error=type(exc).__name__,
                              recovery_directory=str(directory))
                result["cleanup_failure"] = error_facts(exc, "owner_cleanup")
                result["cleanup_owner_state"] = owner_facts(owner)
                code = 1
        if fixture is not None:
            try:
                fixture.close()
            except Exception as exc:
                safe_cleanup = False
                result.update(status="failed", gui_fixture_passed=False, cleanup_error=type(exc).__name__,
                              recovery_directory=str(directory))
                result["fixture_cleanup_failure"] = error_facts(exc, "fixture_close")
                code = 1
        if before is not None:
            try:
                unchanged = before == _diagnostic_call("host_snapshot_after", helpers.network_snapshot)
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                         "status": "passed" if unchanged else "failed"})
                if not unchanged:
                    result.update(status="failed", gui_fixture_passed=False)
                    code = 1
            except Exception as exc:
                result.update(status="failed", gui_fixture_passed=False, host_snapshot_error=type(exc).__name__)
                result["host_snapshot_failure"] = error_facts(exc, "host_snapshot_after")
                code = 1
        result["cleanup_proven"] = safe_cleanup
        if directory is not None and safe_cleanup:
            try:
                _diagnostic_call("profile_remove", shutil.rmtree, directory)
            except OSError as exc:
                result.update(status="failed", gui_fixture_passed=False, cleanup_proven=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                result["profile_cleanup_failure"] = error_facts(exc, "profile_remove")
                code = 1
        args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
        helpers.write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
