import hashlib
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("free_backend_assets", ROOT / ".github/windows_free_backend_assets.py")
assets = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assets)


class FreeBackendAssetsTests(unittest.TestCase):
    def test_cached_asset_cannot_repin_modified_bytes_or_accept_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "official.exe"
            raw = b"fixed official fixture bytes"
            path.write_bytes(raw)
            pin = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "max_bytes": 100}
            self.assertTrue(assets.verify_asset(path, pin))
            path.write_bytes(b"x" * len(raw))
            self.assertFalse(assets.verify_asset(path, pin))
            path.write_bytes(raw)
            link = path.with_name("link.exe")
            try:
                link.symlink_to(path)
            except OSError:
                pass
            else:
                self.assertFalse(assets.verify_asset(link, pin))

    def test_unsafe_archive_paths_and_duplicate_members_rejected_before_extraction(self):
        for names in (("../escape",), ("C:/escape",), ("folder\\escape",), ("/absolute",), ("same", "same")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "input.zip"
                with zipfile.ZipFile(archive, "w") as target:
                    for name in names:
                        target.writestr(name.replace("\\", "/"), b"content")
                # Windows normalizes backslashes passed to writestr. Patch the
                # equal-length local/central names so this case really carries
                # an unsafe raw ZIP member on every host.
                for name in names:
                    if "\\" in name:
                        raw = archive.read_bytes()
                        safe_name = name.replace("\\", "/").encode("ascii")
                        self.assertEqual(raw.count(safe_name), 2)
                        archive.write_bytes(raw.replace(safe_name, name.encode("ascii")))
                with zipfile.ZipFile(archive) as source:
                    self.assertEqual(source.namelist(), list(names))
                output = root / "output"
                with self.assertRaises(ValueError):
                    assets.extract(archive, output)
                self.assertFalse(output.exists())

    def test_manifest_includes_nested_application_manifests_and_binds_changed_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "chromium/chrome-win64/resources/manifest.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b'{"application":"fixture"}')
            (root / "manifest.json").write_text("old root manifest")
            first = assets.manifest_for(root, "sandboxie")
            self.assertEqual([x["path"] for x in first["files"]], [path.relative_to(root).as_posix()])
            self.assertFalse(first["release_eligible"])
            old = first["files"][0]["sha256"]
            path.write_bytes(b'{"application":"changed"}')
            self.assertNotEqual(old, assets.manifest_for(root, "sandboxie")["files"][0]["sha256"])


if __name__ == "__main__":
    unittest.main()
