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

    def test_g_package_option_passes_only_the_pinned_variant_selection_to_installer(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory(prefix="ruleproxy-stage-test-") as temporary:
            target = Path(temporary) / "package"
            def extract(_data, destination):
                destination.mkdir(parents=True, exist_ok=True)
                if destination.name == "python":
                    for name in (builder.PYTHON_PTH, builder.PYTHON_STDLIB, "python.exe", "pythonw.exe", "LICENSE.txt"):
                        (destination / name).write_bytes(b"fixture")
            with patch.object(builder, "project_files", return_value=[]), \
                    patch.object(builder, "download", return_value=b"pinned bytes"), \
                    patch.object(builder, "safe_extract", side_effect=extract), \
                    patch.object(builder.install_runtime, "install") as install, \
                    patch.object(builder.install_runtime, "installed", return_value=True):
                builder.stage(target, mxc_g_bundle=Path(temporary) / "fixed-g.zip")
            install.assert_called_once_with("windows-amd64", target, mxc_variant="g-patched",
                g_bundle_path=Path(temporary) / "fixed-g.zip", variant_explicit=True,
                allow_env_bundle_cache=False)

    def test_portable_package_defaults_to_fixed_g_bundle_without_external_cache(self):
        builder = self.builder()
        with tempfile.TemporaryDirectory(prefix="ruleproxy-stage-test-") as temporary:
            target = Path(temporary) / "package"
            def extract(_data, destination):
                destination.mkdir(parents=True, exist_ok=True)
                if destination.name == "python":
                    for name in (builder.PYTHON_PTH, builder.PYTHON_STDLIB, "python.exe", "pythonw.exe", "LICENSE.txt"):
                        (destination / name).write_bytes(b"fixture")
            with patch.object(builder, "project_files", return_value=[]), \
                    patch.object(builder, "download", return_value=b"pinned bytes"), \
                    patch.object(builder, "safe_extract", side_effect=extract), \
                    patch.object(builder.install_runtime, "install") as install, \
                    patch.object(builder.install_runtime, "installed", return_value=True):
                builder.stage(target)
            install.assert_called_once_with("windows-amd64", target, mxc_variant="g-patched",
                g_bundle_path=None, variant_explicit=True, allow_env_bundle_cache=False)


if __name__ == "__main__":
    unittest.main()
