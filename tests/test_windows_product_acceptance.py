"""Guard evidence boundaries and final artifact verification before native CI."""
import hashlib
import copy
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import zipfile
import zlib


SCRIPT = Path(__file__).resolve().parents[1] / ".github/windows_proxifyre_product_acceptance.py"
SPEC = importlib.util.spec_from_file_location("windows_product_acceptance", SCRIPT)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class ProductArtifactTests(unittest.TestCase):
    def package(self, directory, members=None, manifest_path="ruleproxy/manager.py"):
        package = directory / "final.zip"
        payload = b"final product implementation\n"
        manifest = {"version": "0.3.0", "files": {manifest_path: hashlib.sha256(payload).hexdigest()}}
        with zipfile.ZipFile(package, "w") as archive:
            archive.writestr("RuleProxy-Web/package-manifest.json", json.dumps(manifest))
            archive.writestr("RuleProxy-Web/ruleproxy/manager.py", payload)
            for name, value in members or []:
                archive.writestr(name, value)
        (directory / "SHA256SUMS.txt").write_text(acceptance.digest(package) + "  final.zip\n")
        return package

    def test_final_package_verifies_manifest_and_exact_zip(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory)
            root, facts = acceptance.unpack_package(directory, directory / "unpacked")
            self.assertEqual((root / "ruleproxy/manager.py").read_bytes(), b"final product implementation\n")
            self.assertTrue(facts["manifest_verified"])
            self.assertEqual(facts["files_verified"], 1)

    def test_modified_zip_cannot_pass_checksum(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            package = self.package(directory)
            with package.open("ab") as stream:
                stream.write(b"changed")
            with self.assertRaisesRegex(ValueError, "digest"):
                acceptance.unpack_package(directory, directory / "unpacked")

    def test_zip_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, [("../outside.txt", "escape")])
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                acceptance.unpack_package(directory, directory / "unpacked")
            self.assertFalse((directory / "outside.txt").exists())

    def test_manifest_traversal_rejected(self):
        with tempfile.TemporaryDirectory() as value:
            directory = Path(value)
            self.package(directory, manifest_path="../outside.txt")
            with self.assertRaisesRegex(ValueError, "Unsafe manifest"):
                acceptance.unpack_package(directory, directory / "unpacked")


class AtomicReportTests(unittest.TestCase):
    def test_report_creation_and_replacement_publish_complete_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "actors/report.json"
            acceptance.write(path, {"status": "running"})
            self.assertEqual(json.loads(path.read_text()), {"status": "running"})
            final = {"status": "passed", "checks": {"ordinary": True}, "payload": "x" * 8192}
            acceptance.write(path, final)
            self.assertEqual(json.loads(path.read_text()), final)
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_unrelated_replace_error_is_not_retried_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "original"})
            original = path.read_bytes()
            error = OSError(errno.EIO, "unrelated storage error")
            with mock.patch.object(acceptance.os, "replace", side_effect=error) as replace, \
                    mock.patch.object(acceptance.time, "sleep") as sleep:
                with self.assertRaises(OSError) as caught:
                    acceptance.write(path, {"status": "new"})
                self.assertIs(caught.exception, error)
                replace.assert_called_once()
                sleep.assert_not_called()
            self.assertEqual(path.read_bytes(), original)

    @staticmethod
    def reader_without_delete_sharing(path):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                                      ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
        kernel.CreateFileW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        # READ|WRITE sharing intentionally omits FILE_SHARE_DELETE, matching
        # the relevant Windows reader/atomic-rename conflict without an ACL edit.
        handle = kernel.CreateFileW(str(path), 0x80000000, 3, None, 3, 0x80, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        return kernel, handle

    @unittest.skipUnless(os.name == "nt", "requires Windows file-sharing semantics")
    def test_windows_report_replace_retries_real_reader_conflict_until_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "old"})
            kernel, handle = self.reader_without_delete_sharing(path)
            conflict, errors = threading.Event(), []
            real_replace = os.replace
            final = {"status": "complete", "checks": {"ordinary": True}, "payload": "x" * 8192}
            def replace(*args):
                try:
                    return real_replace(*args)
                except OSError as exc:
                    if getattr(exc, "winerror", None) in {5, 32, 33}:
                        conflict.set()
                    raise
            def publish():
                try:
                    acceptance.write(path, final)
                except BaseException as exc:
                    errors.append(exc)
            worker = threading.Thread(target=publish, daemon=True)
            try:
                with mock.patch.object(acceptance.os, "replace", side_effect=replace) as observed:
                    worker.start()
                    self.assertTrue(conflict.wait(1), "held Windows read handle did not exercise replace conflict")
                    self.assertTrue(kernel.CloseHandle(handle))
                    handle = None
                    worker.join(3)
                    self.assertFalse(worker.is_alive(), "replacement exceeded its bounded retry")
                    self.assertFalse(errors, repr(errors))
                    self.assertGreaterEqual(observed.call_count, 2)
                self.assertEqual(json.loads(path.read_text()), final)
                self.assertFalse(path.with_suffix(".json.tmp").exists())
            finally:
                if handle is not None:
                    kernel.CloseHandle(handle)
                if worker.ident is not None:
                    worker.join(3)

    @unittest.skipUnless(os.name == "nt", "requires Windows file-sharing semantics")
    def test_windows_persistent_reader_lock_expires_without_changing_original(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "report.json"
            acceptance.write(path, {"status": "old"})
            original = path.read_bytes()
            kernel, handle = self.reader_without_delete_sharing(path)
            real_replace = os.replace
            try:
                started = time.monotonic()
                with mock.patch.object(acceptance.os, "replace", wraps=real_replace) as observed:
                    with self.assertRaises(OSError) as caught:
                        acceptance.write(path, {"status": "new"}, replace_timeout=.12)
                    self.assertIn(caught.exception.winerror, {5, 32, 33})
                    self.assertGreaterEqual(observed.call_count, 2)
                self.assertLess(time.monotonic() - started, 2)
                self.assertEqual(path.read_bytes(), original)
            finally:
                kernel.CloseHandle(handle)
            acceptance.write(path, {"status": "after release"})
            self.assertEqual(json.loads(path.read_text()), {"status": "after release"})


class BackgroundEntryTests(unittest.TestCase):
    def test_short_lived_launcher_returns_while_descendant_retains_output(self):
        with tempfile.TemporaryDirectory(prefix="ruleproxy-background-entry-") as temporary:
            root = Path(temporary)
            ready, release, finished = (root / name for name in ("ready", "release", "finished"))
            child = (
                "import os,sys,time; from pathlib import Path\n"
                f"ready,release,finished=map(Path,{[str(ready), str(release), str(finished)]!r})\n"
                "print('descendant holds output', flush=True)\n"
                "ready.write_text('ready')\n"
                "deadline=time.monotonic()+10\n"
                "while not release.exists() and time.monotonic()<deadline: time.sleep(.02)\n"
                "for fd in (1,2):\n"
                " try: os.close(fd)\n"
                " except OSError: pass\n"
                "finished.write_text('finished')\n"
                "os._exit(0)\n"
            )
            parent = (
                "import os,subprocess,sys,time; from pathlib import Path\n"
                f"subprocess.Popen([sys.executable,'-c',{child!r}],close_fds=False)\n"
                f"ready=Path({str(ready)!r})\n"
                "deadline=time.monotonic()+5\n"
                "while not ready.exists() and time.monotonic()<deadline: time.sleep(.02)\n"
                "print('launcher exiting',flush=True)\n"
                "os._exit(0 if ready.exists() else 2)\n"
            )
            log = root / "entry.log"
            try:
                result = acceptance.run_background_entry([sys.executable, "-c", parent],
                                                        cwd=root, log_path=log, timeout=3)
                self.assertEqual(result.returncode, 0)
                self.assertTrue(ready.exists())
                self.assertFalse(finished.exists(), "launcher waited for background output EOF")
                self.assertIn("descendant holds output", log.read_text())
                self.assertIn("launcher exiting", log.read_text())
            finally:
                release.write_text("release")
                deadline = time.monotonic() + 5
                while ready.exists() and not finished.exists() and time.monotonic() < deadline:
                    time.sleep(.02)


class ReceiverEvidenceTests(unittest.TestCase):
    def phase(self, node="A"):
        return {"label": "raw socket", "token": "unique-phase-token", "expected_node": node,
                "actor": {"rows": [{}, {}]}}

    def transaction(self, *, node="A", role="actor", protocol="tcp_http_response"):
        return {"node": node, "evidence_role": role, "protocol": protocol,
                "request_target": "/nonce/unique-phase-token-0"}

    def verified(self, phase, rows):
        return acceptance.receiver_evidence([phase], {"transactions": rows})[0]

    def test_two_independent_matching_responses_qualify(self):
        value = self.verified(self.phase(), [self.transaction(), self.transaction(protocol="udp_dns")])
        self.assertTrue(value["passed"])
        self.assertEqual(value["receiver_node_counts"], {"A": 2, "B": 0})

    def test_explicit_health_cannot_qualify_transparent_actor(self):
        value = self.verified(self.phase(), [self.transaction(role="health"), self.transaction(role="health")])
        self.assertFalse(value["passed"])

    def test_wrong_node_or_missing_response_cannot_qualify(self):
        self.assertFalse(self.verified(self.phase(), [self.transaction()])["passed"])
        rows = [self.transaction(), self.transaction(), self.transaction(node="B")]
        self.assertFalse(self.verified(self.phase(), rows)["passed"])

    def test_unselected_control_must_never_reach_fixture(self):
        self.assertTrue(self.verified(self.phase(None), [self.transaction(role="health")])["passed"])
        self.assertFalse(self.verified(self.phase(None), [self.transaction()])["passed"])

    def test_browser_single_navigation_requires_independent_selected_b_response(self):
        phase = {"label": "system_edge", "token": "browser-navigation-token", "expected_node": "B",
                 "actor": {"rows": [{"browser": "system_edge"}]}}
        transaction = {"node": "B", "evidence_role": "actor", "protocol": "tcp_http_response",
                       "request_target": "/nonce/browser-navigation-token"}
        value = self.verified(phase, [transaction])
        self.assertTrue(value["passed"])
        self.assertEqual(value["attempts"], 1)
        self.assertEqual(value["receiver_node_counts"], {"A": 0, "B": 1})
        for rows in ([], [{**transaction, "node": "A"}], [{**transaction, "evidence_role": "health"}],
                     [{**transaction, "request_target": "/unrelated-navigation"}]):
            with self.subTest(rows=rows):
                self.assertFalse(self.verified(phase, rows)["passed"])


class NativeProxyEnvironmentEvidenceTests(unittest.TestCase):
    owner = "S-1-5-21-101-202-303-1001"

    def receipt(self, root):
        launcher = str((root / "ruleproxy/windows_app_process.py").resolve())
        nonce = "a1" * 16
        targets = [f"http://{nonce}.invalid/{nonce}/{role}" for role in ("child", "grandchild")]
        environment = {"HTTP_PROXY": "http://127.0.0.1:18809", "HTTPS_PROXY": "http://127.0.0.1:18809",
                       "ALL_PROXY": "http://127.0.0.1:18809", "NO_PROXY": "localhost,127.0.0.1,::1",
                       "NODE_USE_ENV_PROXY": "1"}
        parent = {"sid": self.owner, "elevated": False, "pid": os.getpid()}
        child_pid, grandchild_pid = os.getpid() + 10000, os.getpid() + 10001
        def actor(pid, ppid, target):
            return {"sid": self.owner, "elevated": False, "pid": pid, "ppid": ppid,
                    "launcher_file": launcher, "proxy_environment": dict(environment),
                    "target": target, "response": "proxy-fixture:" + nonce}
        return {"parent_token": parent, "child": {**actor(child_pid, parent["pid"], targets[0]), "grandchild_exit_code": 0},
                "grandchild": actor(grandchild_pid, child_pid, targets[1]),
                "expected_targets": targets, "received_targets": list(targets), "exit_code": 0,
                "launcher_file": launcher, "launched_pid": child_pid, "proxy_port": 18809,
                "probe_scope": "windows-native-launcher-child-grandchild-loopback"}

    def test_matching_ordinary_tokens_and_both_receiver_markers_are_required(self):
        root = Path("installed-product").resolve()
        receipt = self.receipt(root)
        self.assertTrue(acceptance.native_proxy_receipt_valid(receipt, self.owner, root))
        for role in ("parent_token", "child", "grandchild"):
            for key, value in (("sid", "S-1-5-18"), ("elevated", True), ("elevated", 0), ("pid", True)):
                changed = copy.deepcopy(receipt)
                changed[role][key] = value
                with self.subTest(role=role, key=key, value=value):
                    self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for received in ([], receipt["received_targets"][:1], receipt["received_targets"] * 2,
                         list(reversed(receipt["received_targets"])), ["/not-an-explicit-proxy-target"] * 2):
            changed = copy.deepcopy(receipt)
            changed["received_targets"] = received
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))

    def test_checkout_launcher_changed_environment_and_unrelated_child_cannot_qualify(self):
        root = Path("installed-product").resolve()
        receipt = self.receipt(root)
        for role, field, value in (
                ("child", "launcher_file", str(root / "checkout/windows_app_process.py")),
                ("grandchild", "ppid", receipt["parent_token"]["pid"]),
                ("child", "response", "unrelated-success"), ("grandchild", "error", "failure"),
                ("child", "grandchild_exit_code", False)):
            changed = copy.deepcopy(receipt)
            changed[role][field] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for key, value in (("NO_PROXY", "*"), ("CUSTOM_PROXY", "http://127.0.0.1:18809"),
                           ("HTTPS_PROXY", "http://untrusted.invalid:9")):
            changed = copy.deepcopy(receipt)
            changed["child"]["proxy_environment"][key] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))
        for key, value in (("exit_code", False), ("proxy_port", True), ("launched_pid", True),
                           ("probe_scope", "transparent_proxy_qualified")):
            changed = copy.deepcopy(receipt)
            changed[key] = value
            self.assertFalse(acceptance.native_proxy_receipt_valid(changed, self.owner, root))

    def test_exact_helper_copy_is_checked_before_running_shared_probe(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "native-proxy-probe.py"
            helper.write_bytes(b"fixed checked fixture source")
            spec = {"owner_sid": self.owner, "native_proxy_fixture_sha256": acceptance.digest(helper)}
            receipt = self.receipt(root / "installed")
            probe = mock.Mock(return_value=receipt)
            with mock.patch.object(acceptance, "LAB", root), \
                    mock.patch.object(acceptance, "INSTALLED", root / "installed"), \
                    mock.patch.object(acceptance, "module", return_value=SimpleNamespace(native_launcher_proxy_probe=probe)) as load:
                facts = acceptance.native_proxy_environment_probe(spec)
                self.assertTrue(facts["passed"])
                self.assertEqual(facts["receipt"], receipt)
                self.assertEqual(facts["fixture_sha256"], spec["native_proxy_fixture_sha256"])
                probe.assert_called_once_with(root / "actors")
                helper.write_bytes(b"replaced fixture")
                load.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "source differs"):
                    acceptance.native_proxy_environment_probe(spec)
                load.assert_not_called()

    def test_shared_probe_parent_must_be_the_actual_ordinary_suite_process(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            helper = root / "native-proxy-probe.py"
            helper.write_bytes(b"fixed checked fixture source")
            receipt = self.receipt(root / "installed")
            receipt["parent_token"]["pid"] += 1
            receipt["child"]["ppid"] = receipt["parent_token"]["pid"]
            spec = {"owner_sid": self.owner, "native_proxy_fixture_sha256": acceptance.digest(helper)}
            with mock.patch.object(acceptance, "LAB", root), \
                    mock.patch.object(acceptance, "INSTALLED", root / "installed"), \
                    mock.patch.object(acceptance, "module", return_value=SimpleNamespace(native_launcher_proxy_probe=lambda _: receipt)):
                with self.assertRaisesRegex(RuntimeError, "ordinary token"):
                    acceptance.native_proxy_environment_probe(spec)


class PngDimensionsTests(unittest.TestCase):
    @staticmethod
    def png(width=1, height=1):
        def chunk(kind, data):
            return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
        # A complete valid 1x1 RGBA image; alternate dimensions exercise the
        # metadata boundary without allocating their decoded pixel buffers.
        return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header)
                + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff")) + chunk(b"IEND", b""))

    def dimensions(self, raw):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "browser-screenshot.png"
            path.write_bytes(raw)
            return acceptance.png_dimensions(path)

    def test_valid_one_pixel_and_maximum_header_dimensions(self):
        self.assertEqual(self.dimensions(self.png()), (1, 1))
        self.assertEqual(self.dimensions(self.png(16384, 16384)), (16384, 16384))

    def test_zero_or_oversized_dimensions_are_rejected(self):
        for width, height in ((0, 1), (1, 0), (0, 0), (16385, 1), (1, 16385), (0xFFFFFFFF, 1)):
            with self.subTest(width=width, height=height), self.assertRaises(ValueError):
                self.dimensions(self.png(width, height))

    def test_signature_and_truncated_headers_are_rejected(self):
        valid = self.png()
        for raw in (b"not a PNG" + valid[9:], valid[:0], valid[:8], valid[:24], valid[:32]):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.dimensions(raw)

    def test_only_the_33_byte_header_is_read(self):
        class HeaderStream(io.BytesIO):
            def __init__(self, raw):
                super().__init__(raw)
                self.read_sizes = []

            def read(self, size=-1):
                self.read_sizes.append(size)
                if size != 33 or len(self.read_sizes) != 1:
                    raise AssertionError("Screenshot inspection must read only its first 33 bytes")
                return super().read(size)

        stream = HeaderStream(self.png())
        with mock.patch.object(Path, "open", return_value=stream), \
                mock.patch.object(Path, "read_bytes", side_effect=AssertionError("Unbounded screenshot read")):
            self.assertEqual(acceptance.png_dimensions(Path("screenshot.png")), (1, 1))
        self.assertEqual(stream.read_sizes, [33])


if __name__ == "__main__":
    unittest.main()
