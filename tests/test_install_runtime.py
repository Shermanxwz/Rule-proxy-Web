"""The runtime installer: when runtimes count as installed, and the modes the setup scripts use."""
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
import zipfile

try:
    import install_runtime
except ImportError:  # the Windows release package ships its runtimes, not the installer
    install_runtime = None


@unittest.skipIf(install_runtime is None, "the runtime installer is not part of this copy")
class InstallRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patcher = patch.object(install_runtime, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def place(self, platform, files, record):
        directory = self.root / "bin" / platform
        directory.mkdir(parents=True)
        for name in files:
            (directory / name).write_bytes(b"binary")
        if record is not None:
            (directory / install_runtime.MANIFEST).write_text(json.dumps(record), encoding="utf-8")
        return directory

    def run_main(self, *argv):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = install_runtime.main(list(argv))
        return code, output.getvalue(), errors.getvalue()

    def test_a_complete_install_is_recognised(self):
        self.place("linux-amd64", ["mihomo"], install_runtime.expected("linux-amd64"))
        self.assertTrue(install_runtime.installed("linux-amd64"))
        self.assertEqual(self.run_main("--check", "--platform", "linux-amd64")[0], 0)

    def test_windows_also_needs_the_mxc_executor(self):
        self.place("windows-amd64", ["mihomo.exe"], install_runtime.expected("windows-amd64"))
        self.assertFalse(install_runtime.installed("windows-amd64"))

    def test_an_older_or_unfinished_install_is_not_complete(self):
        directory = self.place("linux-amd64", ["mihomo"], {"mihomo": "v1.0.0"})
        self.assertFalse(install_runtime.installed("linux-amd64"))
        (directory / install_runtime.MANIFEST).unlink()
        self.assertFalse(install_runtime.installed("linux-amd64"))
        self.assertEqual(self.run_main("--check", "--platform", "linux-amd64")[0], 1)

    def test_check_and_if_needed_download_nothing_when_installed(self):
        self.place("linux-amd64", ["mihomo"], install_runtime.expected("linux-amd64"))
        with patch.object(install_runtime, "fetch") as fetch:
            self.assertEqual(self.run_main("--check", "--platform", "linux-amd64")[0], 0)
            code, output, _ = self.run_main("--if-needed", "--platform", "linux-amd64")
        self.assertEqual(code, 0)
        self.assertIn("已就绪", output)
        fetch.assert_not_called()

    def test_a_network_failure_is_one_clear_message(self):
        with patch.object(install_runtime, "fetch", side_effect=urllib.error.URLError("offline")):
            code, _, errors = self.run_main("--if-needed", "--platform", "linux-amd64")
        self.assertEqual(code, 1)
        self.assertIn("运行组件下载失败", errors)
        self.assertNotIn("Traceback", errors)

    def test_a_checksum_mismatch_refuses_and_leaves_the_install_incomplete(self):
        self.place("linux-amd64", ["mihomo"], install_runtime.expected("linux-amd64"))
        with patch.object(install_runtime, "fetch", return_value=b"tampered"):
            code, _, errors = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1)
        self.assertIn("校验值不符", errors)
        self.assertFalse(install_runtime.installed("linux-amd64"), "a failed reinstall must not keep the old manifest")

    def make_windows_archives(self, extra=None):
        mihomo = io.BytesIO()
        with zipfile.ZipFile(mihomo, "w") as archive:
            archive.writestr("mihomo-windows-amd64-compatible.exe", b"mihomo")
        mxc = io.BytesIO()
        binaries = {"wxc-exec.exe":b"exec", "winhttp-proxy-shim.exe":b"shim"}
        with zipfile.ZipFile(mxc, "w") as archive:
            for name,data in binaries.items(): archive.writestr(name,data)
            archive.writestr("MXC-LICENSE.md", b"license")
            archive.writestr("SOURCE.txt", install_runtime.MXC_SOURCE_REVISION)
            archive.writestr("SHA256SUMS.txt", "tested")
            if extra: archive.writestr(*extra)
        return mihomo.getvalue(), mxc.getvalue(), {n:hashlib.sha256(v).hexdigest() for n,v in binaries.items()}

    def install_windows_fixture(self, extra=None):
        mihomo, mxc, files = self.make_windows_archives(extra)
        def fetch(url):
            return mxc if url == install_runtime.MXC_URL else mihomo if url.endswith(".zip") else b"license"
        name=install_runtime.MIHOMO["windows-amd64"][0]
        with patch.dict(install_runtime.MIHOMO,{"windows-amd64":(name,hashlib.sha256(mihomo).hexdigest())}), \
                patch.object(install_runtime,"MXC_SHA256",hashlib.sha256(mxc).hexdigest()), \
                patch.object(install_runtime,"MXC_FILES",files), patch.object(install_runtime,"fetch",side_effect=fetch):
            result=self.run_main("--platform","windows-amd64")
            installed=install_runtime.installed("windows-amd64")
        return result, installed, files

    def test_windows_install_requires_qualified_files_and_removes_old_plm(self):
        directory=self.root/"bin"/"windows-amd64";directory.mkdir(parents=True)
        (directory/"plm.exe").write_bytes(b"legacy")
        (code,_,errors),installed,_ = self.install_windows_fixture()
        self.assertEqual(code,0,errors);self.assertTrue(installed)
        self.assertEqual(sorted(p.name for p in directory.iterdir()),
                         ["MIHOMO-LICENSE","MXC-LICENSE.md","MXC-SOURCE.txt","mihomo.exe","runtime.json","winhttp-proxy-shim.exe","wxc-exec.exe"])

    def test_an_unexpected_archive_member_refuses_before_installation(self):
        (code,_,errors),installed,_ = self.install_windows_fixture(("../escape.exe",b"unexpected"))
        self.assertEqual(code,1);self.assertFalse(installed)
        self.assertIn("压缩包内容",errors)
        self.assertFalse((self.root/"bin"/"windows-amd64"/"wxc-exec.exe").exists())

    def test_a_damaged_component_is_no_longer_considered_installed(self):
        result,installed,files = self.install_windows_fixture()
        self.assertTrue(installed)
        (self.root/"bin"/"windows-amd64"/"wxc-exec.exe").write_bytes(b"corrupted")
        with patch.object(install_runtime,"MXC_FILES",files):
            self.assertFalse(install_runtime.installed("windows-amd64"))


if __name__ == "__main__":
    unittest.main()
