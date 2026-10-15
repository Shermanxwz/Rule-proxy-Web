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
        self.assertFalse(any(name.endswith((".yaml", ".yml")) for name in files))
        self.assertFalse(any(name.startswith(("verification/", ".github/", "data/")) for name in files))

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
        def fake_download(url, _digest):
            return python.getvalue() if url == builder.PYTHON_URL else yaml.getvalue() if url == builder.PYYAML_URL else b"fixed-asset"
        def runtime(target, **_kwargs):
            path = target / "bin/windows-amd64"
            path.mkdir(parents=True)
            (path / "mihomo.exe").write_bytes(b"mihomo")
        with tempfile.TemporaryDirectory() as directory, patch.object(builder, "download", side_effect=fake_download), \
                patch.object(builder.install_runtime, "install_windows_proxy", side_effect=runtime), \
                patch.object(builder.install_runtime, "installed_windows_proxy", return_value=True):
            target = Path(directory) / "package"
            builder.stage(target)
            manifest = json.loads((target / "package-manifest.json").read_text())
            self.assertEqual(manifest["backend"], "proxifyre")
            self.assertFalse(manifest["public_binary_release_eligible"])
            for name, digest in manifest["files"].items():
                self.assertEqual(hashlib.sha256((target / name).read_bytes()).hexdigest(), digest)
            for asset in builder.pins.ASSETS.values():
                if asset["name"].endswith((".msi", ".exe")):
                    self.assertTrue((target / "installers" / asset["name"]).is_file())
            self.assertFalse(list(target.rglob("wxc-exec.exe")))
            self.assertFalse(list(target.rglob("*.yaml")))


if __name__ == "__main__":
    unittest.main()
