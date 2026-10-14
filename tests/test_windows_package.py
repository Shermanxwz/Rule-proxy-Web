"""Release archive bytes must not depend on the checkout host or build time."""
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import zipfile

try:
    import install_runtime
except ImportError:  # The shipped package does not contain its build tools.
    install_runtime = None


@unittest.skipIf(install_runtime is None, "the package builder is not part of this copy")
class WindowsPackageTests(unittest.TestCase):
    def test_identical_files_produce_the_same_zip_after_mtime_and_mode_changes(self):
        builder_path = Path(__file__).resolve().parent.parent / ".github" / "build_windows_package.py"
        spec = importlib.util.spec_from_file_location("ruleproxy_package_builder", builder_path)
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
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


if __name__ == "__main__":
    unittest.main()
