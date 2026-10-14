"""Acceptance tooling must identify emulation and verify portable runtimes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "windows-acceptance.py"
acceptance = None
if SCRIPT.is_file():
    spec = importlib.util.spec_from_file_location("ruleproxy_acceptance_checks", SCRIPT)
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)


@unittest.skipIf(acceptance is None, "standalone acceptance script is absent from this copy")
class WindowsAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def executable(self, machine):
        header = bytearray(64)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 64)
        path = self.root / "python.exe"
        path.write_bytes(header + b"PE\0\0" + struct.pack("<H", machine))
        return path

    def test_arm_host_with_unknown_wow64_machine_uses_python_pe_machine(self):
        executable = self.executable(0x8664)
        kernel = mock.Mock()

        def machine_info(_handle, process, native):
            process._obj.value, native._obj.value = 0, 0xAA64
            return True

        kernel.IsWow64Process2.side_effect = machine_info
        with mock.patch.object(sys, "platform", "win32"), \
                mock.patch.object(sys, "getwindowsversion", create=True,
                                  return_value=SimpleNamespace(build=26200, product_type=1)), \
                mock.patch.object(sys, "executable", str(executable)), \
                mock.patch("ctypes.WinDLL", create=True, return_value=kernel):
            facts = acceptance.host_facts()
        self.assertEqual(facts["process_machine"], 0)
        self.assertEqual(facts["python_pe_machine"], 0x8664)
        self.assertEqual(facts["acceptance_scope"], "x64_on_arm_emulation")

    def test_native_architectures_and_invalid_executable_headers(self):
        self.assertEqual(acceptance.acceptance_scope(0x8664, 0x8664), "native_x64")
        self.assertEqual(acceptance.acceptance_scope(0xAA64, 0xAA64), "native_arm64_probe")
        self.assertEqual(acceptance.executable_machine(self.executable(0xAA64)), 0xAA64)
        path = self.root / "python.exe"
        for data in (b"not PE", b"MZ" + bytes(62), b"MZ" + bytes(58) + struct.pack("<I", 0xFFFFFFFF)):
            with self.subTest(data=data[:8]):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    acceptance.executable_machine(path)

    def manifest(self):
        directory = self.root / "bin" / "windows-amd64"
        directory.mkdir(parents=True)
        files = {name: ("fixture " + name).encode() for name in acceptance.RUNTIME_REQUIRED_FILES}
        files["additional.dll"] = b"additional runtime dependency"
        for name, data in files.items():
            (directory / name).write_bytes(data)
        record = dict(acceptance.RUNTIME_VERSIONS)
        record["sha256"] = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
        manifest = directory / "runtime.json"
        manifest.write_text(json.dumps(record), encoding="utf-8")
        return directory, manifest, record

    def test_portable_manifest_needs_no_builder_and_checks_additional_dll(self):
        directory, _manifest, record = self.manifest()
        self.assertFalse((self.root / "install_runtime.py").exists())
        self.assertEqual(acceptance.verify_runtime_manifest(self.root), record["sha256"])
        (directory / "additional.dll").write_bytes(b"tampered dependency")
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)

    def test_missing_executable_unlisted_file_versions_and_path_traversal_fail(self):
        directory, manifest, original = self.manifest()
        (directory / "mihomo.exe").unlink()
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)
        (directory / "mihomo.exe").write_bytes(b"fixture mihomo.exe")
        (directory / "unknown.exe").write_bytes(b"unknown")
        with self.assertRaises(ValueError):
            acceptance.verify_runtime_manifest(self.root)
        (directory / "unknown.exe").unlink()
        for mutate in (lambda value: value.update(mxc="old"),
                       lambda value: value["sha256"].update({"../outside.dll": "a" * 64}),
                       lambda value: value["sha256"].update({"C:\\outside.dll": "a" * 64})):
            value = json.loads(json.dumps(original))
            mutate(value)
            manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.assertRaises(ValueError):
                acceptance.verify_runtime_manifest(self.root)

    def test_project_origin_accepts_loaded_product_and_rejects_other_root(self):
        import ruleproxy
        actual = Path(ruleproxy.__file__).resolve().parent.parent
        acceptance.verify_project_origin(actual)
        (self.root / "ruleproxy").mkdir()
        (self.root / "ruleproxy" / "__init__.py").write_text("", encoding="utf-8")
        with self.assertRaises(ValueError):
            acceptance.verify_project_origin(self.root)

    def test_fixture_negotiation_cross_frame_payload_and_both_fin_directions(self):
        fixture = acceptance.FixedTransportFixture()
        self.addCleanup(fixture.close)
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(connection.recv(2), b"\x05\0")
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{fixture.port}"}):
            result = acceptance.fixture_roundtrip(fixture.token)
        self.assertGreater(result["payload_bytes_each_direction"], 4 * 16384)
        self.assertTrue(result["bidirectional_fin"])
        self.assertFalse(result["real_node_passed"])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and fixture.roundtrips != 1:
            time.sleep(0.01)
        self.assertEqual(fixture.roundtrips, 1)
        self.assertEqual(fixture.errors, [])
        fixture.close()
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": f"http://127.0.0.1:{fixture.port}"}):
            with self.assertRaises(OSError):
                acceptance.fixture_roundtrip(fixture.token)


if __name__ == "__main__":
    unittest.main()
