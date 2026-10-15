"""Source-only, read-only Windows known-folder and token context probe."""
from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import uuid


CSIDL_LOCAL_APPDATA = 0x001C
FOLDERID_LOCAL_APPDATA = "F1B32785-6FBA-4FCF-9D55-7B8E7F157091"
TOKEN_QUERY = 0x0008
OPEN_THREAD_TOKEN_AS_SELF = 1
TOKEN_TYPE_CLASS = 8
TOKEN_IS_APP_CONTAINER_CLASS = 29
MAX_REPORT_BYTES = 8192
REPORT_SCHEMA = 1
RELEASE_CONTENT = b"release\n"
RELEASE_TIMEOUT_SECONDS = 30.0
RELEASE_POLL_SECONDS = 0.02


class GUID(ctypes.Structure):
    _fields_ = [("Data1", ctypes.c_uint32), ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16), ("Data4", ctypes.c_ubyte * 8)]

    @classmethod
    def parse(cls, value: str) -> "GUID":
        parsed = uuid.UUID(value)
        fields = parsed.fields
        result = cls()
        result.Data1, result.Data2, result.Data3 = fields[:3]
        result.Data4[:] = parsed.bytes[8:]
        return result


class ReleaseHandshakeError(ValueError):
    """The parent process did not provide the required local release signal."""


def _validate_release_destination(report_path: Path, release_path: Path) -> None:
    if not release_path.is_absolute():
        raise ReleaseHandshakeError("release path must be absolute")
    try:
        if release_path.parent.resolve() != report_path.parent.resolve():
            raise ReleaseHandshakeError("release path must share the report directory")
        os.lstat(release_path)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ReleaseHandshakeError("release path could not be validated") from exc
    raise ReleaseHandshakeError("release path already exists")


def _read_release_signal(path: Path) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ReleaseHandshakeError("release file could not be inspected") from exc
    if not stat.S_ISREG(before.st_mode):
        raise ReleaseHandshakeError("release file must be a regular nonsymlink file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ReleaseHandshakeError("release file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or not os.path.samestat(before, opened):
            raise ReleaseHandshakeError("release file changed during validation")
        content = os.read(descriptor, len(RELEASE_CONTENT) + 1)
    finally:
        os.close(descriptor)
    return content


def wait_for_release(path: str | os.PathLike[str], *, timeout: float = RELEASE_TIMEOUT_SECONDS,
                     interval: float = RELEASE_POLL_SECONDS, clock=None, sleep=None) -> None:
    """Wait for one exact local release file; the caller retains process/job ownership."""
    if timeout <= 0 or interval <= 0 or timeout > RELEASE_TIMEOUT_SECONDS:
        raise ValueError("release wait bounds are invalid")
    release_path = Path(path)
    monotonic = time.monotonic if clock is None else clock
    sleeper = time.sleep if sleep is None else sleep
    deadline = monotonic() + timeout
    while True:
        if os.path.lexists(release_path):
            if release_path.is_symlink():
                raise ReleaseHandshakeError("release file must not be a symlink")
            content = _read_release_signal(release_path)
            if content != RELEASE_CONTENT:
                raise ReleaseHandshakeError("release file content is invalid")
            return
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise ReleaseHandshakeError("release wait timed out")
        sleeper(min(interval, remaining))


def _last_error() -> int:
    getter = getattr(ctypes, "get_last_error", None)
    if getter is None:
        return 0
    return int(getter()) & 0xFFFFFFFF


def _failure_code(exc: Exception) -> int:
    return int(getattr(exc, "winerror", None) or getattr(exc, "errno", None) or 1) & 0xFFFFFFFF


class WindowsApi:
    """Explicitly typed Windows ABI bindings; library injection supports ABI tests."""

    def __init__(self, libraries=None, last_error=None):
        if libraries is None:
            if os.name != "nt":
                raise OSError("Windows APIs are unavailable")
            libraries = (
                ctypes.WinDLL("kernel32", use_last_error=True),
                ctypes.WinDLL("advapi32", use_last_error=True),
                ctypes.WinDLL("shell32", use_last_error=True),
                ctypes.WinDLL("ole32", use_last_error=True),
            )
        self.kernel, self.advapi, self.shell, self.ole = libraries
        self._get_last_error = _last_error if last_error is None else last_error
        handle = ctypes.c_void_p
        dword = ctypes.c_uint32
        boolean = ctypes.c_int32
        self.kernel.GetCurrentProcess.argtypes = []
        self.kernel.GetCurrentProcess.restype = handle
        self.kernel.GetCurrentThread.argtypes = []
        self.kernel.GetCurrentThread.restype = handle
        self.kernel.CloseHandle.argtypes = [handle]
        self.kernel.CloseHandle.restype = boolean
        self.advapi.OpenProcessToken.argtypes = [handle, dword, ctypes.POINTER(handle)]
        self.advapi.OpenProcessToken.restype = boolean
        self.advapi.OpenThreadToken.argtypes = [handle, dword, boolean, ctypes.POINTER(handle)]
        self.advapi.OpenThreadToken.restype = boolean
        self.advapi.GetTokenInformation.argtypes = [handle, ctypes.c_int32, handle, dword,
                                                     ctypes.POINTER(dword)]
        self.advapi.GetTokenInformation.restype = boolean

        # HRESULT is a signed 32-bit type on both 32-bit and 64-bit Windows.
        self.shell.SHGetFolderPathW.argtypes = [handle, ctypes.c_int32, handle, dword,
                                                ctypes.POINTER(ctypes.c_wchar)]
        self.shell.SHGetFolderPathW.restype = ctypes.c_int32
        self.shell.SHGetKnownFolderPath.argtypes = [ctypes.POINTER(GUID), dword, handle,
                                                    ctypes.POINTER(ctypes.c_wchar_p)]
        self.shell.SHGetKnownFolderPath.restype = ctypes.c_int32
        self.ole.CoTaskMemFree.argtypes = [handle]
        self.ole.CoTaskMemFree.restype = None

    @staticmethod
    def _hresult_result(value: int) -> tuple[int, bool]:
        signed = ctypes.c_int32(value).value
        return signed & 0xFFFFFFFF, signed >= 0

    def get_folder_path(self) -> dict:
        buffer = ctypes.create_unicode_buffer(32768)
        try:
            result = self.shell.SHGetFolderPathW(None, CSIDL_LOCAL_APPDATA, None, 0, buffer)
            code, success = self._hresult_result(result)
            return {"hresult_u32": code, "success": success,
                    "path_present": bool(success and buffer.value)}
        except Exception as exc:
            return {"hresult_u32": _failure_code(exc), "success": False, "path_present": False}

    def get_known_folder_path(self) -> dict:
        folder = GUID.parse(FOLDERID_LOCAL_APPDATA)
        output = ctypes.c_wchar_p()
        code, success = 1, False
        path_present = False
        pointer = None
        free_success, free_error = False, 0
        try:
            result = self.shell.SHGetKnownFolderPath(ctypes.byref(folder), 0, None,
                                                      ctypes.byref(output))
            code, success = self._hresult_result(result)
            pointer = ctypes.cast(output, ctypes.c_void_p).value
            if pointer:
                path_present = bool(ctypes.wstring_at(pointer))
        except Exception as exc:
            code = _failure_code(exc)
            pointer = ctypes.cast(output, ctypes.c_void_p).value
        finally:
            # SHGetKnownFolderPath allocates with the task allocator; free the
            # returned pointer even when HRESULT reports failure.
            if pointer:
                try:
                    self.ole.CoTaskMemFree(ctypes.c_void_p(pointer))
                    free_success = True
                except Exception as exc:
                    free_error = _failure_code(exc)
        return {"hresult_u32": code, "success": success, "path_present": path_present,
                "free_attempted": bool(pointer), "free_success": free_success,
                "free_error": free_error}

    def known_folder_location(self) -> Path:
        """Return the LocalAppData path for internal policy construction only."""
        folder = GUID.parse(FOLDERID_LOCAL_APPDATA)
        output = ctypes.c_wchar_p()
        pointer = None
        path_value = None
        free_error = None
        try:
            result = self.shell.SHGetKnownFolderPath(ctypes.byref(folder), 0, None,
                                                      ctypes.byref(output))
            pointer = ctypes.cast(output, ctypes.c_void_p).value
            code, success = self._hresult_result(result)
            if not success or not pointer:
                raise OSError(code, "LocalAppData known-folder query failed")
            path_value = ctypes.wstring_at(pointer)
        finally:
            if pointer:
                try:
                    self.ole.CoTaskMemFree(ctypes.c_void_p(pointer))
                except Exception as exc:
                    free_error = exc
        if free_error is not None:
            raise OSError("LocalAppData known-folder memory could not be released") from free_error
        if not isinstance(path_value, str) or not path_value:
            raise OSError("LocalAppData known-folder path was empty")
        path = Path(path_value)
        if not path.is_absolute() or not path.is_dir():
            raise OSError("LocalAppData known-folder directory is unavailable")
        resolved = path.resolve(strict=True)
        if resolved == Path(resolved.anchor):
            raise OSError("LocalAppData resolved to a filesystem root")
        return resolved

    def _query_token_value(self, token, info_class: int) -> dict:
        value, returned = ctypes.c_uint32(), ctypes.c_uint32()
        try:
            success = bool(self.advapi.GetTokenInformation(
                token, info_class, ctypes.byref(value), ctypes.sizeof(value), ctypes.byref(returned)
            ))
            error = 0 if success else self._get_last_error()
            valid_size = returned.value == ctypes.sizeof(value)
            success = success and valid_size
            return {"success": success, "value": int(value.value) if success else 0,
                    "error": 0 if success else (error or 1)}
        except Exception as exc:
            return {"success": False, "value": 0, "error": _failure_code(exc)}

    def _token_snapshot(self, thread: bool) -> dict:
        output = ctypes.c_void_p()
        handle, opened = None, False
        error = 0
        token_type = {"success": False, "value": 0, "error": 0}
        app_container = {"success": False, "value": 0, "error": 0}
        close_attempted, close_success, close_error = False, False, 0
        try:
            if thread:
                opened = bool(self.advapi.OpenThreadToken(
                    self.kernel.GetCurrentThread(), TOKEN_QUERY, OPEN_THREAD_TOKEN_AS_SELF,
                    ctypes.byref(output)
                ))
            else:
                opened = bool(self.advapi.OpenProcessToken(
                    self.kernel.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(output)
                ))
            handle = output.value
            if not opened or not handle:
                error = self._get_last_error() or 1
            else:
                token_type = self._query_token_value(handle, TOKEN_TYPE_CLASS)
                app_container = self._query_token_value(handle, TOKEN_IS_APP_CONTAINER_CLASS)
        except Exception as exc:
            error = _failure_code(exc)
        finally:
            if opened and handle:
                close_attempted = True
                try:
                    close_success = bool(self.kernel.CloseHandle(handle))
                    if not close_success:
                        close_error = self._get_last_error() or 1
                except Exception as exc:
                    close_error = _failure_code(exc)
        if not opened or not handle:
            token_type["error"] = token_type["error"] or error
            app_container["error"] = app_container["error"] or error
        return {"open_success": bool(opened and handle), "open_error": 0 if opened and handle else error,
                "token_type_success": token_type["success"], "token_type": token_type["value"],
                "token_type_error": token_type["error"],
                "app_container_query_success": app_container["success"],
                "app_container": bool(app_container["value"]),
                "app_container_error": app_container["error"],
                "close_attempted": close_attempted, "close_success": close_success,
                "close_error": close_error}

    def process_token(self) -> dict:
        return self._token_snapshot(False)

    def thread_token(self) -> dict:
        return self._token_snapshot(True)


def resolve_local_appdata_path(api=None) -> Path:
    """Resolve a real LocalAppData directory without adding it to probe reports."""
    api = WindowsApi() if api is None else api
    method = getattr(api, "known_folder_location", None)
    if method is None:
        raise OSError("LocalAppData location query is unavailable")
    path = method()
    if not isinstance(path, Path) or not path.is_absolute() or not path.is_dir():
        raise OSError("LocalAppData location is not an existing absolute directory")
    if path.resolve(strict=True) == Path(path.anchor):
        raise OSError("LocalAppData location must not be a filesystem root")
    return path.resolve(strict=True)


def _safe_call(api, name: str, default: dict) -> dict:
    try:
        value = getattr(api, name)()
        if not isinstance(value, dict):
            return default
        result = {}
        for key, fallback in default.items():
            candidate = value.get(key, fallback)
            result[key] = candidate if type(candidate) is type(fallback) else fallback
        error = value.get("error")
        if type(error) is int and 0 <= error <= 0xFFFFFFFF:
            result["error"] = error
        return result
    except Exception as exc:
        # Keep only a bounded numeric code; never serialize exception text.
        return {key: (False if isinstance(value, bool) else 0) for key, value in default.items()} | {
            "error": _failure_code(exc)
        }


def query_context(api=None, environ=None) -> dict:
    """Return bounded facts only; no path, SID, token, or exception text is retained."""
    env = os.environ if environ is None else environ
    environment = {
        "localappdata_present": "LOCALAPPDATA" in env,
        "appdata_present": "APPDATA" in env,
        "userprofile_present": "USERPROFILE" in env,
    }
    if api is None:
        try:
            api = WindowsApi()
        except Exception as exc:
            code = _failure_code(exc)
            return {"schema": REPORT_SCHEMA, "windows": os.name == "nt", "environment": environment,
                    "shgetfolderpath": {"hresult_u32": code, "success": False, "path_present": False},
                    "shgetknownfolderpath": {"hresult_u32": code, "success": False,
                                             "path_present": False, "free_attempted": False,
                                             "free_success": False, "free_error": 0},
                    "process_token": _empty_token(code), "thread_token": _empty_token(code)}
    return {
        "schema": REPORT_SCHEMA,
        "windows": os.name == "nt",
        "environment": environment,
        "shgetfolderpath": _safe_call(api, "get_folder_path",
                                       {"hresult_u32": 0, "success": False, "path_present": False}),
        "shgetknownfolderpath": _safe_call(api, "get_known_folder_path",
                                            {"hresult_u32": 0, "success": False,
                                             "path_present": False, "free_attempted": False,
                                             "free_success": False, "free_error": 0}),
        "process_token": _safe_call(api, "process_token", _empty_token(0)),
        "thread_token": _safe_call(api, "thread_token", _empty_token(0)),
    }


def _empty_token(error: int) -> dict:
    return {"open_success": False, "open_error": error,
            "token_type_success": False, "token_type": 0, "token_type_error": error,
            "app_container_query_success": False, "app_container": False,
            "app_container_error": error, "close_attempted": False,
            "close_success": False, "close_error": 0}


def write_report(path: str | os.PathLike[str], report: dict) -> None:
    payload = json.dumps(report, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"
    if len(payload) > MAX_REPORT_BYTES:
        raise ValueError("context report exceeds its size limit")
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".partial",
                                          dir=destination.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", action="store_true", help="collect read-only Windows context facts")
    parser.add_argument("--report", type=Path, required=True, help="write the bounded JSON report here")
    parser.add_argument("--release-file", type=Path,
                        help="wait for the parent to create an exact release signal beside the report")
    args = parser.parse_args(argv)
    if not args.probe:
        parser.error("--probe is required")
    try:
        if args.release_file is not None:
            _validate_release_destination(args.report, args.release_file)
        write_report(args.report, query_context())
        if args.release_file is not None:
            wait_for_release(args.release_file)
    except (OSError, ValueError):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
