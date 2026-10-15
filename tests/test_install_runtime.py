"""The runtime installer: when runtimes count as installed, and the modes the setup scripts use."""
import base64
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
import zipfile
from unittest.mock import patch
import urllib.error

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
            record = dict(record, sha256={name: hashlib.sha256(b"binary").hexdigest() for name in files})
            (directory / install_runtime.MANIFEST).write_text(json.dumps(record), encoding="utf-8")
        return directory

    def run_main(self, *argv):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            code = install_runtime.main(list(argv))
        return code, output.getvalue(), errors.getvalue()

    def g_bundle_fixture(self):
        from contextlib import ExitStack
        stack = ExitStack()
        executor = bytearray(512)
        executor[:2] = b"MZ"
        executor[0x3c:0x40] = (64).to_bytes(4, "little")
        executor[64:68] = b"PE\0\0"
        executor[68:70] = (0x8664).to_bytes(2, "little")
        executor = bytes(executor)
        license_bytes = b"fixed MIT license fixture"
        manifest = json.loads(json.dumps(install_runtime.MXC_G_BUILD_MANIFEST))
        executor_hash = hashlib.sha256(executor).hexdigest()
        license_hash = hashlib.sha256(license_bytes).hexdigest()
        manifest["executor_sha256"] = executor_hash
        names = ("build-manifest.json", "wxc-exec.exe", "MXC-LICENSE.md")
        members = {names[0]: (json.dumps(manifest, indent=2) + "\n").encode(),
                   names[1]: executor, names[2]: license_bytes}
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
            for name in names:
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o100644 << 16
                archive.writestr(info, members[name])
        bundle = output.getvalue()
        stack.enter_context(patch.object(install_runtime, "MXC_G_BUILD_MANIFEST", manifest))
        stack.enter_context(patch.object(install_runtime, "MXC_G_EXECUTOR_SHA256", executor_hash))
        stack.enter_context(patch.object(install_runtime, "MXC_G_LICENSE_SHA256", license_hash))
        stack.enter_context(patch.object(install_runtime, "MXC_G_BUNDLE_SHA256", hashlib.sha256(bundle).hexdigest()))
        source = self.root / "g-build"
        source.mkdir()
        for name, data in members.items():
            (source / name).write_bytes(data)
        bundle_path = self.root / "g-bundle.zip"
        return stack, source, bundle_path, bundle, executor, license_bytes

    def test_a_complete_install_is_recognised(self):
        self.place("linux-amd64", install_runtime._required_files("linux-amd64"), install_runtime.expected("linux-amd64"))
        self.assertTrue(install_runtime.installed("linux-amd64"))
        self.assertEqual(self.run_main("--check", "--platform", "linux-amd64")[0], 0)

    def test_windows_also_needs_the_mxc_executor(self):
        self.place("windows-amd64", ["mihomo.exe"], install_runtime.expected("windows-amd64"))
        self.assertFalse(install_runtime.installed("windows-amd64"))

    def test_windows_also_needs_the_mxc_library(self):
        files = [name for name in install_runtime._required_files("windows-amd64") if name != "mxc_ffi.dll"]
        self.place("windows-amd64", files, install_runtime.expected("windows-amd64"))
        self.assertFalse(install_runtime.installed("windows-amd64"))

    def test_deleted_or_changed_components_trigger_repair(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        (directory / "mihomo").write_bytes(b"changed binary")
        self.assertFalse(install_runtime.installed("linux-amd64"))
        (directory / "mihomo").write_bytes(b"")
        self.assertFalse(install_runtime.installed("linux-amd64"))
        (directory / "mihomo").unlink()
        self.assertFalse(install_runtime.installed("linux-amd64"))

    def test_the_old_manifest_without_file_digests_triggers_repair(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        (directory / install_runtime.MANIFEST).write_text(json.dumps(install_runtime.expected("linux-amd64")))
        self.assertFalse(install_runtime.installed("linux-amd64"))

    def test_manifest_paths_cannot_read_outside_the_runtime_folder(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        record = json.loads((directory / install_runtime.MANIFEST).read_text())
        record["sha256"]["../secret"] = hashlib.sha256(b"private").hexdigest()
        (directory / install_runtime.MANIFEST).write_text(json.dumps(record))
        with patch.object(install_runtime, "_file_digest", wraps=install_runtime._file_digest) as digest:
            self.assertFalse(install_runtime.installed("linux-amd64"))
        self.assertNotIn(directory / "../secret", [call.args[0] for call in digest.call_args_list])

    def test_an_older_or_unfinished_install_is_not_complete(self):
        directory = self.place("linux-amd64", ["mihomo"], {"mihomo": "v1.0.0"})
        self.assertFalse(install_runtime.installed("linux-amd64"))
        (directory / install_runtime.MANIFEST).unlink()
        self.assertFalse(install_runtime.installed("linux-amd64"))
        self.assertEqual(self.run_main("--check", "--platform", "linux-amd64")[0], 1)

    def test_check_and_if_needed_download_nothing_when_installed(self):
        self.place("linux-amd64", install_runtime._required_files("linux-amd64"), install_runtime.expected("linux-amd64"))
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

    def test_a_checksum_mismatch_preserves_a_working_install(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        with patch.object(install_runtime, "MIHOMO_LICENSE_SHA256", hashlib.sha256(b"license").hexdigest()), \
                patch.object(install_runtime, "fetch", side_effect=lambda url: b"tampered" if url.endswith(".gz") else b"license"):
            code, _, errors = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1)
        self.assertIn("校验值不符", errors)
        self.assertTrue(install_runtime.installed("linux-amd64"))
        self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})

    def test_a_download_failure_preserves_a_working_install(self):
        self.place("linux-amd64", install_runtime._required_files("linux-amd64"), install_runtime.expected("linux-amd64"))
        with patch.object(install_runtime, "fetch", side_effect=urllib.error.URLError("offline")):
            code, _, _ = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1)
        self.assertTrue(install_runtime.installed("linux-amd64"))

    def test_a_failed_directory_swap_restores_the_working_install(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        original_rename = Path.rename

        def rename(source, target):
            if source.name == "new":
                raise PermissionError("destination is locked")
            return original_rename(source, target)

        with patch.object(install_runtime, "_populate"), patch.object(Path, "rename", rename):
            code, _, errors = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1, errors)
        self.assertTrue(install_runtime.installed("linux-amd64"))
        self.assertEqual(list(directory.parent.iterdir()), [directory])

    def test_a_locked_old_directory_is_never_modified(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        original_rename = Path.rename

        def rename(source, target):
            if source == directory:
                raise PermissionError("old directory is locked")
            return original_rename(source, target)

        with patch.object(install_runtime, "_populate"), patch.object(Path, "rename", rename):
            code, _, errors = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1, errors)
        self.assertTrue(install_runtime.installed("linux-amd64"))
        self.assertEqual(list(directory.parent.iterdir()), [directory])

    def test_failed_rollback_keeps_the_recovery_copy(self):
        directory = self.place("linux-amd64", install_runtime._required_files("linux-amd64"),
                               install_runtime.expected("linux-amd64"))
        original_rename = Path.rename

        def rename(source, target):
            if source.name == "new" or source.name.endswith("-previous"):
                raise PermissionError("destination is locked")
            return original_rename(source, target)

        with patch.object(install_runtime, "_populate"), patch.object(Path, "rename", rename):
            code, _, errors = self.run_main("--platform", "linux-amd64")
        self.assertEqual(code, 1)
        self.assertIn("原文件保留在", errors)
        backups = list(directory.parent.glob(".*-previous"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "mihomo").read_bytes(), b"binary")
        self.assertTrue((backups[0] / install_runtime.MANIFEST).is_file())

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
                patch.object(install_runtime, "MIHOMO_LICENSE_SHA256", hashlib.sha256(b"license").hexdigest()), \
                patch.object(install_runtime, "MXC_SHA512", base64.b64encode(hashlib.sha512(mxc).digest()).decode()), \
                patch.object(install_runtime, "fetch", side_effect=fetch):
            code, _, errors = self.run_main("--platform", "windows-amd64", "--mxc-stock")
        self.assertEqual(code, 0, errors)
        self.assertEqual(sorted(path.name for path in directory.iterdir()),
                         ["MIHOMO-LICENSE", "MXC-LICENSE.md", "mihomo.exe", "mxc_ffi.dll", "runtime.json", "wxc-exec.exe"])
        self.assertTrue(install_runtime.installed("windows-amd64", mxc_variant="stock"))
        (directory / "mxc_ffi.dll").write_bytes(b"truncated")
        self.assertFalse(install_runtime.installed("windows-amd64"))

    def test_fixed_g_bundle_build_is_byte_reproducible_and_provenance_checked(self):
        stack, source, bundle_path, bundle, executor, license_bytes = self.g_bundle_fixture()
        with stack:
            digest = install_runtime.build_g_bundle(source, bundle_path)
            self.assertEqual(digest, hashlib.sha256(bundle).hexdigest())
            self.assertEqual(bundle_path.read_bytes(), bundle)
            extracted = self.root / "extracted"
            extracted.mkdir()
            install_runtime._extract_g_bundle(bundle, extracted)
            self.assertEqual((extracted / "wxc-exec.exe").read_bytes(), executor)
            self.assertEqual((extracted / "MXC-LICENSE.md").read_bytes(), license_bytes)
            (source / "wxc-exec.exe").write_bytes(executor + b"tampered")
            with self.assertRaisesRegex(ValueError, "provenance or digest"):
                install_runtime.build_g_bundle(source, bundle_path)

    def test_source_installer_fetches_only_the_fixed_g_asset_url(self):
        stack, source, bundle_path, bundle, _, _ = self.g_bundle_fixture()
        with stack:
            install_runtime.build_g_bundle(source, bundle_path)
            with patch.object(install_runtime, "fetch", return_value=bundle) as fetch:
                self.assertEqual(install_runtime._g_bundle_bytes(allow_env_cache=False), bundle)
            fetch.assert_called_once_with(install_runtime.MXC_G_BUNDLE_URL)
            with patch.object(install_runtime, "fetch", return_value=b"not the pinned artifact") as bad_fetch:
                with self.assertRaisesRegex(ValueError, "bundle digest"):
                    install_runtime._g_bundle_bytes(allow_env_cache=False)
            bad_fetch.assert_called_once_with(install_runtime.MXC_G_BUNDLE_URL)

    def test_release_bundle_fetch_accepts_only_fixed_fully_verified_asset(self):
        stack, _source, _bundle_path, bundle, executor, license_bytes = self.g_bundle_fixture()
        with stack:
            response = io.BytesIO(bundle)
            response.__enter__ = lambda: response
            response.__exit__ = lambda *_args: None
            opener = unittest.mock.Mock(return_value=response)
            self.assertEqual(install_runtime.fetch_g_bundle_release(opener=opener), bundle)
            request, = opener.call_args.args
            self.assertEqual(request.full_url, install_runtime.MXC_G_BUNDLE_URL)
            self.assertEqual(opener.call_args.kwargs, {"timeout": 30})

            bad_response = io.BytesIO(b"wrong asset bytes")
            bad_response.__enter__ = lambda: bad_response
            bad_response.__exit__ = lambda *_args: None
            with self.assertRaisesRegex(ValueError, "bundle digest"):
                install_runtime.fetch_g_bundle_release(opener=lambda *_a, **_k: bad_response)

            corrupt = b"not a zip"
            with patch.object(install_runtime, "MXC_G_BUNDLE_SHA256", hashlib.sha256(corrupt).hexdigest()):
                malformed_response = io.BytesIO(corrupt)
                malformed_response.__enter__ = lambda: malformed_response
                malformed_response.__exit__ = lambda *_args: None
                with self.assertRaisesRegex(ValueError, "invalid"):
                    install_runtime.fetch_g_bundle_release(
                        opener=lambda *_a, **_k: malformed_response)

    def test_release_bundle_fallback_signal_is_only_http_404(self):
        error_404 = urllib.error.HTTPError(install_runtime.MXC_G_BUNDLE_URL, 404, "not published", {}, None)
        with self.assertRaises(install_runtime.GBundleNotPublished):
            install_runtime.fetch_g_bundle_release(opener=lambda *_a, **_k: (_ for _ in ()).throw(error_404))
        for status in (403, 429, 500):
            error = urllib.error.HTTPError(install_runtime.MXC_G_BUNDLE_URL, status, "transient", {}, None)
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, f"HTTP {status}"):
                install_runtime.fetch_g_bundle_release(
                    opener=lambda *_a, _error=error, **_k: (_ for _ in ()).throw(_error))
        with self.assertRaises(urllib.error.URLError):
            install_runtime.fetch_g_bundle_release(
                opener=lambda *_a, **_k: (_ for _ in ()).throw(urllib.error.URLError("offline")))

    def test_release_bundle_fetch_enforces_size_bound_before_fallback_or_acceptance(self):
        with patch.object(install_runtime, "MAX_G_BUNDLE_DOWNLOAD", 4):
            response = io.BytesIO(b"12345")
            response.__enter__ = lambda: response
            response.__exit__ = lambda *_args: None
            with self.assertRaisesRegex(ValueError, "size limit"):
                install_runtime.fetch_g_bundle_release(opener=lambda *_a, **_k: response)

    def test_default_if_needed_upgrades_stock_and_never_replaces_g_with_stock(self):
        stack, source, bundle_path, bundle, executor, license_bytes = self.g_bundle_fixture()
        with stack:
            install_runtime.build_g_bundle(source, bundle_path)
            mihomo = io.BytesIO()
            with zipfile.ZipFile(mihomo, "w") as archive:
                archive.writestr("mihomo-windows-amd64-compatible.exe", b"mihomo")
            mxc = io.BytesIO()
            with tarfile.open(fileobj=mxc, mode="w:gz") as archive:
                for name, data in (("package/bin/x64/wxc-exec.exe", b"stock executor"),
                                   ("package/bin/x64/mxc_ffi.dll", b"ffi"),
                                   ("package/LICENSE.md", b"npm license")):
                    info = tarfile.TarInfo(name); info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
            mihomo, mxc = mihomo.getvalue(), mxc.getvalue()

            def fetch(url):
                if url == install_runtime.MXC_URL:
                    return mxc
                if url.endswith(".zip"):
                    return mihomo
                return b"mihomo license"

            name = install_runtime.MIHOMO["windows-amd64"][0]
            with patch.dict(install_runtime.MIHOMO,
                            {"windows-amd64": (name, hashlib.sha256(mihomo).hexdigest())}), \
                    patch.object(install_runtime, "MIHOMO_LICENSE_SHA256", hashlib.sha256(b"mihomo license").hexdigest()), \
                    patch.object(install_runtime, "MXC_SHA512", base64.b64encode(hashlib.sha512(mxc).digest()).decode()), \
                    patch.object(install_runtime, "fetch", side_effect=fetch):
                stock_directory = install_runtime.install("windows-amd64", self.root,
                    mxc_variant="stock", variant_explicit=True)
                self.assertTrue(install_runtime.installed("windows-amd64", self.root, "stock"))
                code, _, errors = self.run_main("--if-needed", "--platform", "windows-amd64",
                                                 "--mxc-g-bundle", str(bundle_path))
                self.assertEqual(code, 0, errors)
                directory = self.root / "bin" / "windows-amd64"
                self.assertTrue(install_runtime.installed("windows-amd64", self.root, "g-patched"))
                self.assertFalse(install_runtime.installed("windows-amd64", self.root, "stock"))
                self.assertEqual((directory / "wxc-exec.exe").read_bytes(), executor)
                self.assertEqual((directory / "mxc_ffi.dll").read_bytes(), b"ffi")
                self.assertEqual((directory / "MXC-LICENSE.md").read_bytes(), license_bytes)
                # The normal default does not replace G with stock.
                code, _, errors = self.run_main("--if-needed", "--platform", "windows-amd64", "--mxc-g")
                self.assertEqual(code, 0, errors)
                self.assertTrue(install_runtime.installed("windows-amd64", self.root, "g-patched"))

    def test_default_check_targets_g_and_stock_is_only_accepted_when_explicit(self):
        self.assertEqual(install_runtime.expected("windows-amd64")["mxc"]["executor_variant"], "g-patched")
        stock = self.place("windows-amd64", install_runtime._required_files("windows-amd64"),
                           install_runtime.expected("windows-amd64", "stock"))
        # A stock record is valid as stock but cannot satisfy the default G check.
        record = json.loads((stock / install_runtime.MANIFEST).read_text())
        self.assertTrue(install_runtime.installed("windows-amd64", self.root, "stock"))
        self.assertFalse(install_runtime.installed("windows-amd64", self.root))
        self.assertEqual(self.run_main("--check", "--platform", "windows-amd64")[0], 1)
        self.assertEqual(self.run_main("--check", "--platform", "windows-amd64", "--mxc-stock")[0], 0)

    def test_source_bundle_cache_is_digest_pinned_and_never_accepts_arbitrary_bytes(self):
        stack, _source, bundle_path, bundle, *_ = self.g_bundle_fixture()
        with stack:
            bundle_path.write_bytes(bundle)
            with patch.dict(os.environ, {"RULEPROXY_PINNED_G_BUNDLE": str(bundle_path)}), \
                    patch.object(install_runtime, "fetch") as fetch:
                self.assertEqual(install_runtime._g_bundle_bytes(), bundle)
            fetch.assert_not_called()
            bundle_path.write_bytes(b"untrusted bytes")
            with patch.dict(os.environ, {"RULEPROXY_PINNED_G_BUNDLE": str(bundle_path)}):
                with self.assertRaisesRegex(ValueError, "bundle digest"):
                    install_runtime._g_bundle_bytes()

    def test_changed_runtime_variant_manifest_is_not_accepted_as_either_variant(self):
        directory = self.place("windows-amd64", install_runtime._required_files("windows-amd64"),
                               install_runtime.expected("windows-amd64"))
        record = json.loads((directory / install_runtime.MANIFEST).read_text())
        record["mxc"] = {"version": install_runtime.MXC_VERSION, "executor_variant": "unknown"}
        (directory / install_runtime.MANIFEST).write_text(json.dumps(record))
        self.assertFalse(install_runtime.installed("windows-amd64", self.root, "stock"))
        self.assertFalse(install_runtime.installed("windows-amd64", self.root, "g-patched"))


if __name__ == "__main__":
    unittest.main()
