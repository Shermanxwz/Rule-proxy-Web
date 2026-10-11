"""The runtime installer: when runtimes count as installed, and the modes the setup scripts use."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tarfile
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

    def test_windows_install_leaves_out_plm_and_removes_an_old_copy(self):
        mihomo = io.BytesIO()
        with zipfile.ZipFile(mihomo, "w") as archive:
            archive.writestr("mihomo-windows-amd64-compatible.exe", b"mihomo")
        mxc = io.BytesIO()
        with tarfile.open(fileobj=mxc, mode="w:gz") as archive:
            for name, data in (("package/bin/x64/wxc-exec.exe", b"exec"), ("package/bin/x64/mxc_ffi.dll", b"ffi"),
                               ("package/bin/x64/plm.exe", b"plm"), ("package/LICENSE.md", b"license")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        mihomo, mxc = mihomo.getvalue(), mxc.getvalue()
        directory = self.root / "bin" / "windows-amd64"
        directory.mkdir(parents=True)
        (directory / "plm.exe").write_bytes(b"left by an older setup")

        def fetch(url):
            return mxc if url == install_runtime.MXC_URL else mihomo if url.endswith(".zip") else b"license"

        name = install_runtime.MIHOMO["windows-amd64"][0]
        with patch.dict(install_runtime.MIHOMO, {"windows-amd64": (name, hashlib.sha256(mihomo).hexdigest())}), \
                patch.object(install_runtime, "MXC_SHA512", base64.b64encode(hashlib.sha512(mxc).digest()).decode()), \
                patch.object(install_runtime, "fetch", side_effect=fetch):
            code, _, errors = self.run_main("--platform", "windows-amd64")
        self.assertEqual(code, 0, errors)
        self.assertEqual(sorted(path.name for path in directory.iterdir()),
                         ["MIHOMO-LICENSE", "MXC-LICENSE.md", "mihomo.exe", "mxc_ffi.dll", "runtime.json", "wxc-exec.exe"])
        self.assertTrue(install_runtime.installed("windows-amd64"))


if __name__ == "__main__":
    unittest.main()
