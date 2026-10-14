"""Acceptance tooling must identify emulation and verify portable runtimes."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
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

    def executable(self, machine, path=None):
        header = bytearray(64)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 64)
        path = path or self.root / "python.exe"
        path.parent.mkdir(parents=True, exist_ok=True)
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

    def test_snapshot_prefers_native_system_powershell_on_arm(self):
        emulated = self.executable(0x8664, self.root / "Sysnative/WindowsPowerShell/v1.0/powershell.exe")
        native = self.executable(0xAA64, self.root / "System32/WindowsPowerShell/v1.0/powershell.exe")
        with mock.patch.dict(os.environ, {"SystemRoot": str(self.root)}):
            self.assertEqual(acceptance.select_powershell(0xAA64), (native, 0xAA64))
            native.unlink()
            self.assertEqual(acceptance.select_powershell(0xAA64), (emulated, 0x8664))
            emulated.unlink()
            with self.assertRaises(RuntimeError):
                acceptance.select_powershell(0xAA64)

    def test_snapshot_has_cold_cim_budget_and_never_logs_configuration(self):
        record = {"dns": [], "routes": [], "proxy": {"server": "private-proxy-password"}, "winhttp": "private-config"}
        powershell = self.root / "powershell.exe"
        with mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0xAA64}), \
                mock.patch.object(acceptance, "select_powershell", return_value=(powershell, 0xAA64)), \
                mock.patch.object(acceptance.subprocess, "run", return_value=SimpleNamespace(
                    stdout=json.dumps(record), stderr="RULEPROXY_SNAPSHOT_STAGE=serialize\n")) as run, \
                mock.patch.object(sys, "stderr", new_callable=io.StringIO) as logged:
            digest = acceptance.network_snapshot()
            self.assertEqual(len(digest), 64)
            self.assertEqual(run.call_args.kwargs["timeout"], 120)
            self.assertEqual(run.call_args.args[0][0], str(powershell))
            self.assertIn("snapshot completed", logged.getvalue())
            self.assertNotIn("private-proxy-password", logged.getvalue())
            self.assertNotIn("private-config", logged.getvalue())

    def test_snapshot_timeout_and_failure_keep_fixed_stage_without_raw_output(self):
        output = b"RULEPROXY_SNAPSHOT_STAGE=dns\nprivate password must not be echoed\n"
        errors = (
            subprocess.TimeoutExpired(["private command"], 120, stderr=output),
            subprocess.CalledProcessError(1, ["private command"], stderr=output),
        )
        for error in errors:
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0xAA64}), \
                    mock.patch.object(acceptance, "select_powershell", return_value=(Path("powershell.exe"), 0xAA64)), \
                    mock.patch.object(acceptance.subprocess, "run", side_effect=error), \
                    mock.patch.object(sys, "stderr", new_callable=io.StringIO):
                with self.assertRaises(RuntimeError) as raised:
                    acceptance.network_snapshot()
                self.assertIn("during dns", str(raised.exception))
                self.assertNotIn("private", str(raised.exception))

    def test_snapshot_rejects_an_empty_json_value_instead_of_claiming_a_hash(self):
        with mock.patch.object(acceptance, "host_facts", return_value={"native_machine": 0x8664}), \
                mock.patch.object(acceptance, "select_powershell", return_value=(Path("powershell.exe"), 0x8664)), \
                mock.patch.object(acceptance.subprocess, "run", return_value=SimpleNamespace(stdout="null", stderr="")), \
                mock.patch.object(sys, "stderr", new_callable=io.StringIO):
            with self.assertRaises(RuntimeError):
                acceptance.network_snapshot()

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

    def test_connect_response_accepts_mihomo_reason_phrase_but_requires_bounded_200(self):
        for response in (b"HTTP/1.1 200 Connection Established\r\n\r\n",
                         b"HTTP/1.1 200 Connection established\r\n\r\n",
                         b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"):
            acceptance.validate_connect_response(response)
        for response in (b"HTTP/1.1 502 Bad Gateway\r\n\r\n", b"HTTP/2 200 OK\r\n\r\n",
                         b"HTTP/1.1 200 OK\r\n", b"HTTP/1.1 200 OK\r\nX: " + b"x" * 4096 + b"\r\n\r\n"):
            with self.subTest(response=response[:32]):
                with self.assertRaises(RuntimeError):
                    acceptance.validate_connect_response(response)

    def test_manager_socks_fixture_accepts_only_fixed_destination_and_fin_payload(self):
        fixture = acceptance.FixedSocksFixture()
        self.addCleanup(fixture.close)
        payload = acceptance.fixture_payload(fixture.token)
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(fixture._read_exact(connection, 2), b"\x05\0")
            host = fixture.host.encode("ascii")
            connection.sendall(b"\x05\x01\0\x03" + bytes([len(host)]) + host + struct.pack("!H", 443))
            self.assertEqual(fixture._read_exact(connection, 10), b"\x05\0\0\x01\x7f\0\0\x01\0\0")
            connection.sendall(payload)
            connection.shutdown(socket.SHUT_WR)
            echoed = bytearray()
            while True:
                part = connection.recv(16384)
                if not part:
                    break
                echoed.extend(part)
            self.assertEqual(bytes(echoed), payload[::-1])
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and fixture.roundtrips != 1:
            time.sleep(0.01)
        self.assertEqual(fixture.roundtrips, 1)
        self.assertEqual(fixture.errors, [])
        with socket.create_connection(("127.0.0.1", fixture.port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(b"\x05\x01\0")
            self.assertEqual(fixture._read_exact(connection, 2), b"\x05\0")
            wrong = b"unrelated.example"
            connection.sendall(b"\x05\x01\0\x03" + bytes([len(wrong)]) + wrong + struct.pack("!H", 443))
            self.assertEqual(connection.recv(1), b"")
        self.assertEqual(fixture.roundtrips, 1)

    def test_manager_override_changes_only_owned_core_endpoint_and_preserves_import_guard(self):
        import yaml
        from ruleproxy.config import compile_config
        fixture = acceptance.FixedSocksFixture()
        self.addCleanup(fixture.close)
        source = acceptance.manager_fixture_source(fixture)
        compiled = compile_config(source, secret="test-controller-token")
        original = json.loads(json.dumps(compiled.config))
        manager = SimpleNamespace(core=mock.Mock(), compiled=compiled, _controller=mock.Mock())
        manager.core.poll.return_value = None
        metadata = acceptance.reload_manager_fixture(manager, fixture)
        self.assertTrue(metadata["test_only_endpoint_override"])
        self.assertEqual(manager.compiled.config, original)
        call = manager._controller.call_args
        self.assertEqual(call.args[:2], ("PUT", "/configs?force=true"))
        actual = yaml.safe_load(call.args[2]["payload"])
        self.assertEqual(actual["proxies"][0]["server"], "127.0.0.1")
        actual["proxies"][0]["server"] = "upstream.ruleproxy.invalid"
        self.assertEqual(actual, original)
        with self.assertRaises(ValueError):
            compile_config(source.replace("upstream.ruleproxy.invalid", "127.0.0.1"), secret="test-token")
        manager.core.poll.return_value = 1
        with self.assertRaises(RuntimeError):
            acceptance.reload_manager_fixture(manager, fixture)


if __name__ == "__main__":
    unittest.main()
