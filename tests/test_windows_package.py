"""Release archive bytes must not depend on the checkout host or build time."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import zipfile
from unittest.mock import patch

try:
    import install_runtime
except ImportError:  # The shipped package does not contain its build tools.
    install_runtime = None


@unittest.skipIf(install_runtime is None, "the package builder is not part of this copy")
class WindowsPackageTests(unittest.TestCase):
    @staticmethod
    def builder():
        builder_path = Path(__file__).resolve().parent.parent / ".github" / "build_windows_package.py"
        spec = importlib.util.spec_from_file_location("ruleproxy_package_builder", builder_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_identical_files_produce_the_same_zip_after_mtime_and_mode_changes(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory(prefix="ruleproxy-package-test-") as temporary:
            root = Path(temporary)
            source = root / "应用 测试"
            source.mkdir()
            (source / "Start-Windows.cmd").write_bytes(b"@echo off\r\n")
            (source / "bin").mkdir()
            (source / "bin" / "mihomo.exe").write_bytes(b"verified runtime")
            first, second = root / "first.zip", root / "second.zip"
            builder.write_zip(source, first)
            for path in source.rglob("*"):
                if path.is_file():
                    os.utime(path, (1700000000, 1700000000))
                    path.chmod(0o755)
            builder.write_zip(source, second)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), ["RuleProxy-Web/Start-Windows.cmd", "RuleProxy-Web/bin/mihomo.exe"])
                self.assertEqual(archive.read("RuleProxy-Web/bin/mihomo.exe"), b"verified runtime")
                for entry in archive.infolist():
                    self.assertEqual(entry.date_time, (1980, 1, 1, 0, 0, 0))
                    self.assertEqual(entry.create_system, 3)
                    self.assertEqual(entry.external_attr >> 16, 0o100644)

    def test_portable_package_tracks_the_shared_runtime_pins_module(self):
        builder = self.builder()
        self.assertIn("ruleproxy/windows_runtime_pins.py", builder.project_files())

    def test_bundled_licenses_are_pinned_and_tampering_stops_packaging_before_downloads(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in builder.BUNDLED_LICENSE_SOURCES:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((builder.ROOT / name).read_bytes())
            with patch.object(builder, 'ROOT', root), patch.object(builder, 'INCLUDE', ('ruleproxy/',)), \
                    patch.object(builder, 'download') as network:
                self.assertEqual(builder.project_files(), sorted(builder.BUNDLED_LICENSE_SOURCES))
                damaged = root / builder.BUNDLED_LICENSE_SOURCES[0]
                damaged.write_bytes(damaged.read_bytes() + b'changed')
                with self.assertRaisesRegex(ValueError, 'license failed its size/SHA-256'):
                    builder.stage(root / 'output')
                network.assert_not_called()

    def test_bundled_license_files_are_required_for_source_packages(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'ruleproxy').mkdir()
            with patch.object(builder, 'ROOT', root), patch.object(builder, 'INCLUDE', ('ruleproxy/',)), \
                    self.assertRaisesRegex(ValueError, 'Required bundled Windows license is missing'):
                builder.project_files()

    def test_release_notes_bind_qualification_to_matching_evidence(self):
        builder = self.builder()
        notes = builder.release_notes("personal.zip", "a" * 64)
        self.assertIn("SHA-256: " + "a" * 64, notes)
        self.assertIn("Server 2025, native Windows 11 and visible GUI qualification", notes)
        self.assertIn("same ZIP SHA-256", notes)
        self.assertIn("current-status.json", notes)
        self.assertIn("A successful build does not establish qualification", notes)
        self.assertNotIn("qualification passed", notes)
        self.assertNotIn("qualification remains pending", notes)
        self.assertIn("same installation account to open Start-Windows.lnk", notes)
        self.assertIn("3010, restart Windows and repeat setup", notes)
        self.assertIn("Import your own YAML through the Web panel", notes)
        self.assertIn("UDP 53 and system DNS can go direct", notes)
        self.assertIn("engine failure can restore direct access", notes)
        self.assertNotIn(".github/build_windows_package.py", builder.project_files())

    def test_product_package_rejects_mxc_diagnostic_options(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "MXC"):
                builder.stage(Path(directory), mxc_g_bundle=Path(directory) / "g.zip")

    def test_product_inputs_include_setup_broker_and_no_user_yaml(self):
        builder = self.builder()
        files = builder.project_files()
        self.assertIn("Setup-Windows.cmd", files)
        self.assertIn("scripts/windows-setup.ps1", files)
        self.assertIn("scripts/windows-uninstall.ps1", files)
        self.assertIn("ruleproxy/windows_proxy_pins.py", files)
        self.assertIn("ruleproxy/windows_proxy_service.py", files)
        self.assertIn("ruleproxy/windows_proxy_policy.py", files)
        self.assertIn("ruleproxy/windows_proxy_runtime.py", files)
        for name in ("manager", "launcher", "windows_gemini", "windows_antigravity",
                     "windows_antigravity_ipc", "windows_ipc_lease"):
            self.assertIn(f"ruleproxy/{name}.py", files)
        self.assertFalse(any(name.endswith((".yaml", ".yml")) for name in files))
        self.assertFalse(any(name.startswith(("verification/", ".github/", "data/")) for name in files))

    def test_setup_requires_all_antigravity_ipc_modules_before_dependencies(self):
        import re
        source = (Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1').read_text(encoding='utf-8')
        check = re.search(r"    foreach \(\$required in @\((.*?)\)\) \{\n.*?\n    \}", source, re.S)
        self.assertIsNotNone(check)
        required = re.findall(r"'([^']+)'", check.group(1))
        for module in ('windows_antigravity', 'windows_antigravity_ipc', 'windows_ipc_lease'):
            self.assertIn(f'ruleproxy\\{module}.py', required)
        self.assertIn("throw ('Required product file missing: ' + $required)", check.group())
        self.assertLess(check.end(), source.index("$setupPhase = 'dependencies'"))

    @unittest.skipUnless(os.name == 'nt', 'executes isolated Windows PowerShell file-check/hash fragments only')
    def test_setup_ipc_required_failure_and_deployment_hashes_with_fixture_files(self):
        import hashlib
        import json
        import re
        import shutil
        import subprocess
        shell = shutil.which('pwsh') or shutil.which('powershell')
        if not shell:
            self.skipTest('PowerShell is not installed')
        source = (Path(__file__).resolve().parent.parent / 'scripts/windows-setup.ps1').read_text(encoding='utf-8')
        check = re.search(r"    foreach \(\$required in @\((.*?)\)\) \{\n.*?\n    \}", source, re.S)
        self.assertIsNotNone(check)
        required = re.findall(r"'([^']+)'", check.group(1))
        hash_block = source[source.index('    $files = @{}'):source.index('    $pfFiles = @{}')]
        # Execute only file checks and the real staging hash loop, never setup,
        # dependency executables, services, shortcut creation, or native helpers.
        with tempfile.TemporaryDirectory(prefix='ruleproxy-ipc-package-contract-') as directory:
            root = Path(directory)
            stage = root / 'fixture stage'
            stage.mkdir()
            for name in required:
                path = stage / name.replace('\\', '/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'non-executable fixture')
            script = root / 'check.ps1'
            script.write_text("param([string]$stage)\n$ErrorActionPreference = 'Stop'\n" + check.group()
                              + '\n' + hash_block + '\n$files | ConvertTo-Json -Compress\n', encoding='utf-8')
            def run():
                return subprocess.run([shell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                       '-File', str(script), str(stage)],
                                      capture_output=True, text=True, timeout=30)
            result = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            hashes = json.loads(result.stdout)
            self.assertEqual(set(hashes), {name.replace('\\', '/') for name in required})
            for module in ('windows_antigravity', 'windows_antigravity_ipc', 'windows_ipc_lease'):
                name = f'ruleproxy/{module}.py'
                path = stage / name
                with self.subTest(module=module):
                    body = path.read_bytes()
                    self.assertEqual(hashes[name], hashlib.sha256(body).hexdigest())
                    path.unlink()
                    result = run()
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Required product file missing:', result.stderr)
                    self.assertIn(module + '.py', result.stderr)
                    self.assertEqual(result.stdout.strip(), '')
                    path.write_bytes(body)

    def test_staging_refuses_existing_user_configuration_without_reading_it(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            configuration = target / "private.yaml"
            configuration.write_text("user credential", encoding="utf-8")
            with patch.object(builder, "download") as network, self.assertRaisesRegex(ValueError, "empty directory"):
                builder.stage(target)
            network.assert_not_called()
            self.assertEqual(configuration.read_text(encoding="utf-8"), "user credential")

    def test_archive_extraction_rejects_traversal_and_duplicate_case_paths(self):
        import io
        builder = self.builder()
        for names in (("../outside",), ("Code.py", "code.py"), ("C:/escape",), ("a\\b",)):
            body = io.BytesIO()
            with zipfile.ZipFile(body, "w") as archive:
                for name in names:
                    # Windows ZipInfo normalizes backslashes in its constructor.
                    # Assign after construction so the on-disk member is truly
                    # malformed; the reader retains those bytes as orig_filename.
                    entry = zipfile.ZipInfo("placeholder")
                    entry.filename = entry.orig_filename = name
                    archive.writestr(entry, b"x")
            with zipfile.ZipFile(body) as archive:
                self.assertEqual(tuple(item.orig_filename for item in archive.infolist()), names)
            with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
                builder.safe_extract(body.getvalue(), Path(directory))

    def test_default_stage_has_offline_installers_and_complete_hash_manifest(self):
        import io, json, hashlib
        builder = self.builder()
        python = io.BytesIO()
        with zipfile.ZipFile(python, "w") as archive:
            for name in (builder.PYTHON_PTH, builder.PYTHON_STDLIB, "python.exe", "pythonw.exe", "LICENSE.txt"):
                archive.writestr(name, b"fixture")
        yaml = io.BytesIO()
        with zipfile.ZipFile(yaml, "w") as archive:
            archive.writestr("yaml/__init__.py", b"# fixture")
        original_download = builder.download
        def fake_download(url, _digest):
            if any(builder.pins.ASSETS[key]['url'] == url for key in builder.LICENSE_KEYS):
                return original_download(url, _digest)
            return python.getvalue() if url == builder.PYTHON_URL else yaml.getvalue() if url == builder.PYYAML_URL else b"fixed-asset"
        def runtime(target, **_kwargs):
            path = target / "bin/windows-amd64"
            path.mkdir(parents=True)
            (path / "mihomo.exe").write_bytes(b"mihomo")
        with tempfile.TemporaryDirectory() as directory, patch.object(builder, "download", side_effect=fake_download), \
                patch.object(builder.install_runtime, "install_windows_proxy", side_effect=runtime), \
                patch.object(builder.install_runtime, "installed_windows_proxy", return_value=True), \
                patch.object(builder.pins, "validate_burn_layout", return_value={"fixture": True}):
            target = Path(directory) / "package"
            builder.stage(target)
            manifest = json.loads((target / "package-manifest.json").read_text())
            self.assertEqual(manifest["backend"], "proxifyre")
            self.assertFalse(manifest["public_binary_release_eligible"])
            actual_files = {p.relative_to(target).as_posix() for p in target.rglob('*') if p.is_file()}
            self.assertEqual(set(manifest['files']), actual_files - {'package-manifest.json'})
            for module in ('windows_antigravity', 'windows_antigravity_ipc', 'windows_ipc_lease'):
                self.assertIn(f'ruleproxy/{module}.py', manifest['files'])
            for name, digest in manifest["files"].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), digest)
            for asset in builder.pins.ASSETS.values():
                if asset["name"].endswith((".msi", ".exe")):
                    self.assertTrue((target / "installers" / asset["name"]).is_file())
            for key in ('proxifyre_license', 'ndisapi_license'):
                asset = builder.pins.ASSETS[key]
                self.assertEqual(hashlib.sha256((target / 'licenses' / asset['name']).read_bytes()).hexdigest(),
                                 asset['sha256'])
            self.assertFalse(list(target.rglob("wxc-exec.exe")))
            self.assertFalse(list(target.rglob("*.yaml")))


if __name__ == "__main__":
    unittest.main()
