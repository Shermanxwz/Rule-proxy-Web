"""Exercise the real file transport; these tests do not emulate Windows isolation."""

import errno
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from ruleproxy import file_bridge


class FileBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def make_host(self):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(4)
        self.addCleanup(listener.close)
        finished = threading.Event()
        errors = []

        def echo():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(4)
                    while True:
                        data = connection.recv(32768)
                        if not data:
                            connection.sendall(b"EOF")
                            return
                        connection.sendall(data)
            except OSError as exc:
                errors.append(exc)
            finally:
                finished.set()

        worker = threading.Thread(target=echo, daemon=True)
        worker.start()
        self.addCleanup(worker.join, 4)
        bridge = file_bridge.FileProxyBridge(listener.getsockname()[1], self.root)
        self.addCleanup(bridge.close)
        return bridge, finished, errors

    @staticmethod
    def sharing_error(winerror=32):
        error = PermissionError(13, "sharing violation")
        error.winerror = winerror
        return error

    def test_control_read_retries_only_bounded_windows_sharing_errors(self):
        path = self.root / "guest-status.json"
        file_bridge._atomic_json(path, {"nonce": "a" * 64, "state": "GUEST_READY"})
        real_open = Path.open
        calls = []

        def open_once_with_conflict(candidate, *args, **kwargs):
            if candidate == path and not calls:
                calls.append("conflict")
                raise self.sharing_error(32)
            calls.append("open")
            return real_open(candidate, *args, **kwargs)

        with mock.patch.object(file_bridge.os, "name", "nt"), \
                mock.patch.object(file_bridge.time, "sleep"), \
                mock.patch.object(Path, "open", autospec=True, side_effect=open_once_with_conflict):
            value = file_bridge._read_json(path)
        self.assertEqual(value, {"nonce": "a" * 64, "state": "GUEST_READY"})
        self.assertEqual(calls, ["conflict", "open"])

    def test_atomic_control_replace_retries_windows_sharing_error(self):
        path = self.root / "guest-status.json"
        real_replace = os.replace
        calls = []

        def replace_once_with_conflict(source, destination):
            calls.append((source, destination))
            if len(calls) == 1:
                raise self.sharing_error(33)
            return real_replace(source, destination)

        with mock.patch.object(file_bridge.os, "name", "nt"), \
                mock.patch.object(file_bridge.time, "sleep"), \
                mock.patch.object(file_bridge.os, "replace", side_effect=replace_once_with_conflict):
            file_bridge._atomic_json(path, {"state": "GUEST_READY"})
        self.assertEqual(len(calls), 2)
        self.assertEqual(file_bridge._read_json(path), {"state": "GUEST_READY"})

    def test_control_read_retries_windows_crt_eacces_without_winerror(self):
        path = self.root / 'guest-status.json'
        expected = {'nonce': 'a' * 64, 'state': 'BRIDGE_READY'}
        file_bridge._atomic_json(path, expected)
        error = PermissionError(errno.EACCES, 'Permission denied', str(path))
        self.assertIsNone(getattr(error, 'winerror', None))
        real_open, attempts = Path.open, []

        def open_after_conflict(candidate, *args, **kwargs):
            attempts.append(candidate)
            if len(attempts) == 1:
                raise error
            return real_open(candidate, *args, **kwargs)

        with mock.patch.object(file_bridge.os, 'name', 'nt'), \
                mock.patch.object(file_bridge.time, 'sleep') as sleep, \
                mock.patch.object(Path, 'open', autospec=True, side_effect=open_after_conflict):
            self.assertEqual(file_bridge._read_json(path), expected)
        self.assertEqual(attempts, [path, path])
        sleep.assert_called_once_with(file_bridge._SHARING_RETRY_DELAYS[0])

    def test_persistent_crt_eacces_still_raises_original_error_after_bounded_retries(self):
        path = self.root / 'guest-status.json'
        file_bridge._atomic_json(path, {'state': 'BRIDGE_READY'})
        error = PermissionError(errno.EACCES, 'Permission denied', str(path))
        with mock.patch.object(file_bridge.os, 'name', 'nt'), \
                mock.patch.object(file_bridge.time, 'sleep') as sleep, \
                mock.patch.object(Path, 'open', side_effect=error) as opening:
            with self.assertRaises(PermissionError) as raised:
                file_bridge._read_json(path)
        self.assertIs(raised.exception, error)
        self.assertEqual(opening.call_count, len(file_bridge._SHARING_RETRY_DELAYS) + 1)
        self.assertEqual(sleep.call_count, len(file_bridge._SHARING_RETRY_DELAYS))
        self.assertEqual(file_bridge._read_json(path), {'state': 'BRIDGE_READY'})

    def test_crt_errno_fallback_does_not_apply_to_other_platforms_or_explicit_winerrors(self):
        for platform, code in (('posix', None), ('nt', 87)):
            error = PermissionError(errno.EACCES, 'Permission denied')
            if code is not None:
                error.winerror = code
            with self.subTest(platform=platform, code=code), \
                    mock.patch.object(file_bridge.os, 'name', platform), \
                    mock.patch.object(file_bridge.time, 'sleep') as sleep, \
                    mock.patch.object(Path, 'open', side_effect=error) as opening:
                with self.assertRaises(PermissionError) as raised:
                    file_bridge._read_json(self.root)
                self.assertIs(raised.exception, error)
                opening.assert_called_once()
                sleep.assert_not_called()

    @unittest.skipUnless(os.name == 'nt', 'requires a real Windows file sharing lock')
    def test_actual_windows_exclusive_handle_read_recovers_after_lock_release(self):
        import ctypes
        from ctypes import wintypes

        path = self.root / 'guest-status.json'
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.WriteFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
        kernel.WriteFile.restype = wintypes.BOOL
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel.CloseHandle.restype = wintypes.BOOL
        # Create and write under one exclusive handle, so no timing or worker
        # thread is needed to establish the same CRT sharing failure as CI.
        handle = kernel.CreateFileW(str(path), 0xC0000000, 0, None, 1, 0x80, None)
        self.assertNotEqual(handle, ctypes.c_void_p(-1).value, 'cannot create exclusive test file')

        def release(_delay=None):
            nonlocal handle
            if handle is not None:
                self.assertTrue(kernel.CloseHandle(handle))
                handle = None

        try:
            payload = b'{"state":"BRIDGE_READY"}'
            written = wintypes.DWORD()
            self.assertTrue(kernel.WriteFile(handle, payload, len(payload), ctypes.byref(written), None))
            self.assertEqual(written.value, len(payload))
            with self.assertRaises(PermissionError) as blocked:
                with path.open('rb'):
                    self.fail('the exclusive Windows handle must prevent this read')
            self.assertEqual(blocked.exception.errno, errno.EACCES)
            self.assertIsNone(getattr(blocked.exception, 'winerror', None))
            with mock.patch.object(file_bridge.time, 'sleep', side_effect=release) as sleep:
                self.assertEqual(file_bridge._read_json(path), {'state': 'BRIDGE_READY'})
            sleep.assert_called_once_with(file_bridge._SHARING_RETRY_DELAYS[0])
        finally:
            release()

    def test_persistent_windows_sharing_error_reraises_after_bounded_retries(self):
        path = self.root / "guest-status.json"
        error = self.sharing_error(5)
        calls = []

        def always_conflict(_path, *_args, **_kwargs):
            calls.append(True)
            raise error

        with mock.patch.object(file_bridge.os, "name", "nt"), \
                mock.patch.object(file_bridge.time, "sleep") as sleep, \
                mock.patch.object(Path, "open", autospec=True, side_effect=always_conflict):
            with self.assertRaises(PermissionError) as raised:
                file_bridge._read_json(path)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), len(file_bridge._SHARING_RETRY_DELAYS) + 1)
        self.assertEqual(sleep.call_count, len(file_bridge._SHARING_RETRY_DELAYS))

    def test_nonsharing_and_nonwindows_errors_are_not_retried(self):
        path = self.root / "guest-status.json"
        error = PermissionError(13, "access denied")
        error.winerror = 5
        calls = []

        def denied(*_args, **_kwargs):
            calls.append(True)
            raise error

        with mock.patch.object(file_bridge.os, "name", "posix"), \
                mock.patch.object(file_bridge.time, "sleep") as sleep, \
                mock.patch.object(Path, "open", autospec=True, side_effect=denied):
            with self.assertRaises(PermissionError) as raised:
                file_bridge._read_json(path)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_windows_nonsharing_error_is_not_retried(self):
        path = self.root / "guest-status.json"
        error = OSError(22, "invalid parameter")
        error.winerror = 87
        calls = []

        def invalid(*_args, **_kwargs):
            calls.append(True)
            raise error

        with mock.patch.object(file_bridge.os, "name", "nt"), \
                mock.patch.object(file_bridge.time, "sleep") as sleep, \
                mock.patch.object(Path, "open", autospec=True, side_effect=invalid):
            with self.assertRaises(OSError) as raised:
                file_bridge._read_json(path)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), 1)
        sleep.assert_not_called()

    def test_persistent_replace_conflict_keeps_old_status_and_removes_temp_file(self):
        path = self.root / "guest-status.json"
        old_value = {"state": "BRIDGE_READY", "nonce": "a" * 64}
        file_bridge._atomic_json(path, old_value)
        error = self.sharing_error(32)
        calls = []

        def always_conflict(source, destination):
            calls.append((source, destination))
            raise error

        with mock.patch.object(file_bridge.os, "name", "nt"), \
                mock.patch.object(file_bridge.time, "sleep"), \
                mock.patch.object(file_bridge.os, "replace", side_effect=always_conflict):
            with self.assertRaises(PermissionError) as raised:
                file_bridge._atomic_json(path, {"state": "GUEST_READY", "nonce": "b" * 64})
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), len(file_bridge._SHARING_RETRY_DELAYS) + 1)
        self.assertTrue(all(source.parent == self.root and destination == path
                            for source, destination in calls))
        self.assertEqual(file_bridge._read_json(path), old_value)
        self.assertEqual(list(self.root.glob(path.name + ".tmp-*")), [])

    def make_guest(self, bridge):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind(("127.0.0.1", 0))
            port = candidate.getsockname()[1]
        stop = threading.Event()
        errors = []

        def guest():
            try:
                file_bridge.run_guest_bridge(port, bridge.directory, bridge.nonce, stop)
            except Exception as exc:
                errors.append(exc)

        worker = threading.Thread(target=guest, daemon=True)
        worker.start()

        def cleanup():
            stop.set()
            worker.join(4)

        self.addCleanup(cleanup)
        # The listener marker precedes READY frame publication and the final
        # BRIDGE_READY status. Wait for both before simulating the self-check,
        # so the guest cannot overwrite our GUEST_READY with its initial state.
        deadline = time.monotonic() + 3
        while True:
            self.assertEqual(errors, [], "guest startup failed")
            self.assertTrue(worker.is_alive(), "guest exited before startup completed")
            status = file_bridge._read_json(bridge.directory / "guest-status.json")
            if status is not None:
                self.assertEqual(status.get("nonce"), bridge.nonce)
                self.assertEqual(status.get("state"), "BRIDGE_READY", "guest startup failed")
                self.assertTrue(file_bridge.wait_for_bridge_ready(bridge.directory, bridge.nonce, 0))
                break
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "guest startup did not complete within 3 seconds")
            stop.wait(min(0.01, remaining))
        return port, worker, errors

    def test_guest_fixture_waits_for_complete_startup_before_simulating_self_check(self):
        bridge = file_bridge.FileProxyBridge(10809, self.root)
        self.addCleanup(bridge.close)
        marker_published, finish_startup, completed = threading.Event(), threading.Event(), threading.Event()
        results, errors = [], []

        def delayed_guest(_port, directory, nonce, stop):
            file_bridge._atomic_json(directory / "bridge-ready.json", {"nonce": nonce, "ready": True})
            marker_published.set()
            if not finish_startup.wait(3):
                raise TimeoutError("test startup was not released")
            file_bridge._atomic_json(directory / "guest-status.json", {"nonce": nonce, "state": "BRIDGE_READY"})
            stop.wait(3)

        def start_fixture():
            try:
                results.append(self.make_guest(bridge))
            except Exception as exc:
                errors.append(exc)
            finally:
                completed.set()

        with mock.patch.object(file_bridge, "run_guest_bridge", side_effect=delayed_guest):
            worker = threading.Thread(target=start_fixture, daemon=True)
            worker.start()
            try:
                self.assertTrue(marker_published.wait(1))
                self.assertFalse(completed.wait(0.05), "a bound listener must not complete startup")
            finally:
                finish_startup.set()
                worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        file_bridge.signal_guest_ready(bridge.directory, bridge.nonce)
        bridge.approve()

    def receive(self, connection, size):
        response = bytearray()
        while len(response) < size:
            chunk = connection.recv(size - len(response))
            if not chunk:
                break
            response.extend(chunk)
        return bytes(response)

    def test_real_bridge_roundtrip_crosses_frames_and_preserves_half_close(self):
        bridge, finished, host_errors = self.make_host()
        port, guest, guest_errors = self.make_guest(bridge)
        self.assertFalse(bridge.wait_ready(0), "bound listener is insufficient for application approval")
        file_bridge.signal_guest_ready(bridge.directory, bridge.nonce)
        self.assertTrue(bridge.wait_ready(0))
        bridge.approve()
        self.assertEqual(file_bridge.wait_for_decision(bridge.directory, bridge.nonce, 0), "approved")
        with socket.create_connection(("127.0.0.1", port), timeout=4) as connection:
            connection.settimeout(4)
            payload = bytes(range(256)) * 300
            connection.sendall(payload)
            self.assertEqual(self.receive(connection, len(payload)), payload)
            connection.shutdown(socket.SHUT_WR)
            self.assertEqual(self.receive(connection, 3), b"EOF")
            self.assertEqual(connection.recv(1), b"")
        self.assertTrue(finished.wait(3))
        self.assertEqual(host_errors, [])
        self.assertEqual(guest_errors, [])
        self.assertTrue(guest.is_alive())
        bridge.reject("test completed")
        guest.join(3)
        self.assertFalse(guest.is_alive())
        self.assertEqual(guest_errors, [])

    def test_guest_goaway_closes_active_host_connections(self):
        bridge, finished, _ = self.make_host()
        port, _, _ = self.make_guest(bridge)
        with socket.create_connection(("127.0.0.1", port), timeout=4) as connection:
            connection.settimeout(4)
            connection.sendall(b"roundtrip")
            self.assertEqual(self.receive(connection, 9), b"roundtrip")
            bridge._to_host.put("GOAWAY", 0, b"", threading.Event())
            bridge._dispatcher.join(3)
            self.assertFalse(bridge._dispatcher.is_alive())
            self.assertTrue(finished.wait(3), "the upstream socket must close when dispatch ends")
            self.assertEqual(bridge._streams, {})

    def test_corrupt_ring_header_fails_closed_and_releases_mapping_and_fd(self):
        path = self.root / "ring"
        original = file_bridge._Ring(path, b"a" * 16, create=True)
        self.addCleanup(original.close)
        original.map[:8] = b"INVALID!"
        created_maps = []
        real_mmap = file_bridge.mmap.mmap
        real_close = os.close

        def make_map(*args, **kwargs):
            mapping = real_mmap(*args, **kwargs)
            created_maps.append(mapping)
            return mapping

        with mock.patch.object(file_bridge.mmap, "mmap", side_effect=make_map), mock.patch.object(
            file_bridge.os, "close", wraps=real_close
        ) as close:
            with self.assertRaisesRegex(file_bridge.BridgeError, "header validation"):
                file_bridge._Ring(path, b"a" * 16)
        self.assertTrue(created_maps[0].closed)
        failed_fd = close.call_args.args[0]
        with self.assertRaises(OSError):
            os.fstat(failed_fd)

    def test_mapping_failure_releases_opened_ring_fd(self):
        real_close = os.close
        with mock.patch.object(file_bridge.mmap, "mmap", side_effect=OSError("mapping unavailable")), mock.patch.object(
            file_bridge.os, "close", wraps=real_close
        ) as close:
            with self.assertRaisesRegex(OSError, "mapping unavailable"):
                file_bridge._Ring(self.root / "ring", b"a" * 16, create=True)
        with self.assertRaises(OSError):
            os.fstat(close.call_args.args[0])

    def test_host_initialization_failure_closes_first_ring_and_removes_partial_run(self):
        first = mock.Mock()
        with mock.patch.object(file_bridge, "_Ring", side_effect=[first, OSError("second ring unavailable")]):
            with self.assertRaisesRegex(OSError, "second ring unavailable"):
                file_bridge.FileProxyBridge(10809, self.root)
        first.close.assert_called_once()
        self.assertEqual(list(self.root.iterdir()), [])

    def test_guest_bind_failure_closes_both_opened_rings(self):
        bridge = file_bridge.FileProxyBridge(10809, self.root)
        self.addCleanup(bridge.close)
        rings = []
        real_ring = file_bridge._Ring

        def open_ring(*args, **kwargs):
            ring = real_ring(*args, **kwargs)
            rings.append(ring)
            return ring

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            with mock.patch.object(file_bridge, "_Ring", side_effect=open_ring):
                with self.assertRaises(OSError):
                    file_bridge.run_guest_bridge(
                        occupied.getsockname()[1], bridge.directory, bridge.nonce, threading.Event()
                    )
        self.assertEqual(len(rings), 2)
        self.assertTrue(all(ring.map.closed for ring in rings))
        for ring in rings:
            with self.assertRaises(OSError):
                os.fstat(ring.fd)

    def test_wrong_nonce_never_approves_guest(self):
        bridge = file_bridge.FileProxyBridge(10809, self.root)
        self.addCleanup(bridge.close)
        file_bridge._atomic_json(bridge.directory / "guest-status.json", {
            "nonce": "b" * 64, "state": "GUEST_READY",
        })
        self.assertFalse(bridge.wait_ready(0))
        with self.assertRaises(file_bridge.BridgeError):
            bridge.approve()
        self.assertFalse((bridge.directory / "host-control.json").exists())

    def test_valid_frame_survives_lock_contention_longer_than_the_queue_poll(self):
        path = self.root / "ring"
        writer = file_bridge._Ring(path, b"a" * 16, create=True)
        self.addCleanup(writer.close)
        reader = file_bridge._Ring(path, b"a" * 16)
        self.addCleanup(reader.close)
        writer.put("DATA", 1, b"valid queued frame", threading.Event())
        entered, finished = threading.Event(), threading.Event()
        result, errors = [], []

        def read():
            entered.set()
            try:
                result.append(reader.get(threading.Event(), timeout=0.02))
            except Exception as exc:
                errors.append(exc)
            finally:
                finished.set()

        writer._lock(time.monotonic() + 1)
        worker = threading.Thread(target=read, daemon=True)
        try:
            worker.start()
            self.assertTrue(entered.wait(1))
            self.assertFalse(finished.wait(0.1), "queue polling must not expire a valid file-lock wait")
        finally:
            writer._unlock()
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(result, [("DATA", 1, b"valid queued frame")])

    def test_stuck_file_lock_still_fails_closed_with_its_own_budget(self):
        path = self.root / "ring"
        writer = file_bridge._Ring(path, b"a" * 16, create=True)
        self.addCleanup(writer.close)
        reader = file_bridge._Ring(path, b"a" * 16)
        self.addCleanup(reader.close)
        finished, errors = threading.Event(), []

        def read():
            try:
                reader.get(threading.Event(), timeout=10)
            except Exception as exc:
                errors.append(exc)
            finally:
                finished.set()

        writer._lock(time.monotonic() + 1)
        worker = threading.Thread(target=read, daemon=True)
        try:
            with mock.patch.object(file_bridge, "_FILE_LOCK_SECONDS", 0.05):
                worker.start()
                self.assertTrue(finished.wait(1), "a stuck lock must not wait for the queue timeout")
        finally:
            writer._unlock()
            worker.join(3)
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], TimeoutError)

    def test_shared_ring_frames_cross_processes_and_wrap_without_per_frame_disk_flush(self):
        path = self.root / "ring"
        reader = file_bridge._Ring(path, b"a" * 16, create=True)
        self.addCleanup(reader.close)
        script = r'''
from pathlib import Path
import struct, sys, threading
sys.path.insert(0, sys.argv[1])
from ruleproxy.file_bridge import _Ring
writer = _Ring(Path(sys.argv[2]), b"a" * 16)
try:
    for index in range(256):
        writer.put("DATA", 1, struct.pack("!I", index) * 4096, threading.Event())
    writer.put("FIN", 1, b"", threading.Event())
finally:
    writer.close()
'''
        code_root = Path(file_bridge.__file__).resolve().parent.parent
        child = subprocess.Popen([sys.executable, "-I", "-S", "-c", script, str(code_root), str(path)],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for index in range(256):
                item = reader.get(threading.Event(), timeout=3)
                self.assertIsNotNone(item)
                self.assertEqual(item, ("DATA", 1, index.to_bytes(4, "big") * 4096))
            self.assertEqual(reader.get(threading.Event(), timeout=3), ("FIN", 1, b""))
            output, errors = child.communicate(timeout=10)
            self.assertEqual(child.returncode, 0, errors.decode("utf-8", "replace"))
            self.assertEqual(output, b"")
        finally:
            if child.poll() is None:
                child.kill()  # This test helper is an ordinary Python peer, never MXC.
                child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
