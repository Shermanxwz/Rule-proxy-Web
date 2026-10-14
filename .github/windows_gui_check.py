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
        value = str(Path(value).resolve(strict=True))
    return ntpath.normcase(ntpath.normpath(value))


class ProcessApi:
    """Read-only query/synchronize handles; no terminate capability here."""

    def __init__(self):
        from ruleproxy import windows_runtime
        self.api = windows_runtime._WinProcessApi()
        self.kernel = self.api.kernel32
        self.filetime = windows_runtime._FileTime
        self.kernel.GetProcessId.argtypes = [wintypes.HANDLE]
        self.kernel.GetProcessId.restype = wintypes.DWORD

    def open(self, pid):
        handle = self.kernel.OpenProcess(0x1000 | 0x00100000, False, pid)
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

    def image(self, handle):
        return self.api.process_image(handle)

    def snapshot(self):
        return self.api._snapshot_parent_ids()

    def close(self, handle):
        self.api.close(handle)


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
        if api.pid(self.root_handle) != wrapper.pid or not api.alive(self.root_handle):
            raise RuntimeError("wrapper held identity is not live")
        self.root_created = api.created(self.root_handle)
        self.root = {"pid": wrapper.pid, "created": self.root_created,
                     "handle": self.root_handle, "depth": 0}
        self.entries = {}
        self.pending = []
        self.peak_handles = 1
        self.closed = False

    def _identity(self, entry):
        if self.api.pid(entry["handle"]) != entry["pid"] \
                or self.api.created(entry["handle"]) != entry["created"]:
            raise RuntimeError("held process generation changed")

    def refresh(self):
        if self.closed:
            raise RuntimeError("owned tree has already released its handles")
        self._identity(self.root)
        # An Edge child can start another sandbox process while these snapshots
        # are read. Repeating by depth discovers it without any name-based scan.
        for _ in range(32):
            parents = {self.wrapper.pid: self.root, **self.entries}
            first = self.api.snapshot()
            added = False
            for pid, ppid in first.items():
                if pid == self.wrapper.pid or ppid not in parents or pid in self.entries:
                    continue
                parent = parents[ppid]
                self._identity(parent)
                if 1 + len(self.entries) + len(self.pending) >= MAX_HANDLES:
                    raise RuntimeError("owned process query handle limit exceeded")
                handle = self.api.open(pid)
                self.pending.append(handle)
                self.peak_handles = max(self.peak_handles, 1 + len(self.entries) + len(self.pending))
                if self.api.pid(handle) != pid:
                    raise RuntimeError("opened child PID did not match the snapshot")
                created = self.api.created(handle)
                if created < parent["created"]:
                    # This is an old process carrying a recycled parent PID;
                    # the read-only handle grants it no owned-window authority.
                    self.api.close(handle)
                    self.pending.remove(handle)
                    continue
                second = self.api.snapshot()
                self._identity(parent)
                if second.get(pid) != ppid or self.api.created(handle) != created:
                    raise RuntimeError("child lineage changed between process snapshots")
                if not self.api.alive(handle):
                    self.api.close(handle)
                    self.pending.remove(handle)
                    continue
                if not self.api.alive(parent["handle"]):
                    exited = self.api.exited_at(parent["handle"])
                    if not exited or created > exited:
                        raise RuntimeError("new child cannot be attributed to the held parent generation")
                image = image_key(self.api.image(handle))
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
        if not self.api.alive(entry["handle"]) or image_key(self.api.image(entry["handle"])) != self.edge:
            return None
        return entry

    def verify_startup_helper(self, parent):
        entry = self.entries.get(parent.get("pid")) if isinstance(parent, dict) else None
        if entry is None or entry["ppid"] != self.wrapper.pid \
                or parent.get("parent_pid") != self.wrapper.pid \
                or parent.get("process_created") != entry["created"]:
            raise RuntimeError("startup helper was not in the held wrapper generation")
        self._identity(entry)
        if not self.api.alive(entry["handle"]):
            raise RuntimeError("startup helper exited before GUI attestation")

    def all_exited(self):
        return not self.api.alive(self.root_handle) and all(
            not self.api.alive(entry["handle"]) for entry in self.entries.values()
        ) and all(not self.api.alive(handle) for handle in self.pending)

    def close_exited(self):
        if self.closed:
            return
        if not self.all_exited():
            raise RuntimeError("owned query handles still include a live process")
        for pid, entry in list(self.entries.items()):
            self.api.close(entry["handle"])
            del self.entries[pid]
        for handle in list(self.pending):
            self.api.close(handle)
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

    def windows(self):
        values, overflow = [], []
        def visit(hwnd, parameter):
            if len(values) >= 1024:
                overflow.append(True)
                return False
            pid = self.pid(hwnd)
            if pid:
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


def owned_windows(tree, windows):
    values = []
    for hwnd, pid in windows.windows():
        entry = tree.edge_owner(pid)
        if entry is None:
            continue
        rect = windows.visible_rect(hwnd)
        if rect is not None and windows.pid(hwnd) == pid and tree.edge_owner(pid) is not None:
            values.append({"hwnd": hwnd, "pid": pid, "created": entry["created"], "rect": rect})
    if len(values) > 16:
        raise RuntimeError("owned visible window limit exceeded")
    return values


def close_owned_window(tree, windows, value):
    pid = windows.pid(value["hwnd"])
    entry = tree.edge_owner(pid)
    if pid != value["pid"] or entry is None or entry["created"] != value["created"] \
            or windows.visible_rect(value["hwnd"]) is None:
        raise RuntimeError("owned window identity changed before WM_CLOSE")
    # Revalidate the HWND immediately after all process/image/rectangle queries.
    if windows.pid(value["hwnd"]) != pid or tree.edge_owner(pid) is None:
        raise RuntimeError("owned window generation changed before WM_CLOSE")
    windows.post_close(value["hwnd"])


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
        self.fixture.begin(phase)
        guest_port = windows_runtime.choose_guest_port(self.fixture.port)
        app = {"id": "gui", "label": "Visible Edge HTTP fixture", "path": str(self.edge),
               "adapter": "chromium", "args": ["--new-window", "--no-default-browser-check",
                                                  f"http://{self.browser_module.HOST}/phase/{phase}"]}
        command, environment, _ = launcher.prepare_app(app, guest_port, self.profile_root)
        startup_started = time.monotonic()
        self.cleanup_proven = False
        try:
            self.wrapper, self.resources = windows_runtime.launch(
                command, environment, self.profile_root / "gui", self.fixture.port,
                str(self.runtime), guest_listener_port=guest_port)
        except BaseException as exc:
            self.wrapper = getattr(exc, "process", None)
            self.resources = getattr(exc, "resource", None)
            raise
        startup_seconds = time.monotonic() - startup_started
        startup = self.helpers.startup_evidence(self.resources)
        deadline = time.monotonic() + GUI_BUDGET_SECONDS
        self.tree = OwnedTree(ProcessApi(), self.wrapper, self.edge)
        self.tree.refresh()
        self.tree.verify_startup_helper(startup.get("startup_diagnostics", {}).get("parent"))
        windows = WindowApi()
        selected = []
        while time.monotonic() < deadline:
            if self.wrapper.poll() is not None:
                raise RuntimeError("Edge/MXC exited before a visible acknowledged GUI window")
            self.tree.refresh()
            selected = owned_windows(self.tree, windows)
            if selected:
                try:
                    self.fixture.check(phase)
                    break
                except RuntimeError:
                    pass
            time.sleep(0.1)
        else:
            raise TimeoutError("visible Edge window and DOM cookie acknowledgement did not complete")
        rects = [value["rect"] for value in selected]
        posted = set()
        while time.monotonic() < deadline:
            self.tree.refresh()
            for value in owned_windows(self.tree, windows):
                key = (value["hwnd"], value["pid"], value["created"])
                if key not in posted:
                    close_owned_window(self.tree, windows, value)
                    posted.add(key)
            code = self.wrapper.poll()
            if code is not None and self.tree.all_exited():
                if code:
                    raise RuntimeError(f"Edge/MXC natural GUI close exited with status {code}")
                break
            time.sleep(0.1)
        else:
            raise TimeoutError("owned GUI window did not naturally exit within its shared budget")
        if not posted:
            raise RuntimeError("no attested owned WM_CLOSE request was posted")
        self.fixture.check(phase)
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
        if self.wrapper is not None:
            windows_runtime.stop(self.wrapper)
        if self.tree is not None and not self.tree.closed:
            self.tree.refresh()  # Include a last child born during graceful shutdown.
            self.tree.close_exited()
        if self.resources is not None:
            self.resources.close()
        if self.wrapper is not None and hasattr(self.wrapper._handle, "Close"):
            self.wrapper._handle.Close()
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
        result["interactive"] = interactive_facts()
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
    finally:
        if owner is not None:
            try:
                owner.close()
            except Exception as exc:
                safe_cleanup = False
                _RECOVERY_OWNERS.append(owner)
                result.update(status="failed", gui_fixture_passed=False, cleanup_error=type(exc).__name__,
                              recovery_directory=str(directory))
                code = 1
        if fixture is not None:
            try:
                fixture.close()
            except Exception as exc:
                safe_cleanup = False
                result.update(status="failed", gui_fixture_passed=False, cleanup_error=type(exc).__name__,
                              recovery_directory=str(directory))
                code = 1
        if before is not None:
            try:
                unchanged = before == helpers.network_snapshot()
                result["checks"].append({"check": "host_proxy_dns_default_routes_unchanged",
                                         "status": "passed" if unchanged else "failed"})
                if not unchanged:
                    result.update(status="failed", gui_fixture_passed=False)
                    code = 1
            except Exception as exc:
                result.update(status="failed", gui_fixture_passed=False, host_snapshot_error=type(exc).__name__)
                code = 1
        result["cleanup_proven"] = safe_cleanup
        if directory is not None and safe_cleanup:
            try:
                shutil.rmtree(directory)
            except OSError as exc:
                result.update(status="failed", gui_fixture_passed=False, cleanup_proven=False,
                              cleanup_error=type(exc).__name__, recovery_directory=str(directory))
                code = 1
        args.report.resolve().parent.mkdir(parents=True, exist_ok=True)
        helpers.write_json(args.report.resolve(), result)
        print(json.dumps(result, ensure_ascii=True, indent=2), flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
