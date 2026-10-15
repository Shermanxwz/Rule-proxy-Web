"""Validation for the pinned, optional Chrome for Testing control archive."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "ruleproxy_windows_chromium_control", ROOT / ".github/windows_chromium_control.py"
)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


def pe_image(machine: int = control.PE_MACHINE_AMD64) -> bytes:
    data = bytearray(88)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 64)
    data[64:68] = b"PE\0\0"
    struct.pack_into("<H", data, 68, machine)
    return bytes(data)


def assembly_manifest(version: str = control.VERSION) -> bytes:
    return (
        "<assembly xmlns='urn:schemas-microsoft-com:asm.v1' manifestVersion='1.0'>"
        f"<assemblyIdentity name='{version}' version='{version}' type='win32'/>"
        "<file name='chrome_elf.dll'/></assembly>"
    ).encode()


def make_archive(path: Path, *, exe: bytes | None = None, manifest: bytes | None = None,
                 extra: tuple[tuple[str, bytes], ...] = ()) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        if exe is not None:
            bundle.writestr(control.EXPECTED_EXE, exe)
        if manifest is not None:
            bundle.writestr(control.EXPECTED_MANIFEST, manifest)
        for name, data in extra:
            bundle.writestr(name, data)
    data = stream.getvalue()
    path.write_bytes(data)
    return data


def make_archive_with_raw_name(path: Path, raw_name: str) -> bytes:
    """Serialize a name after ZipInfo construction to bypass host path cleanup."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr(control.EXPECTED_EXE, pe_image())
        bundle.writestr(control.EXPECTED_MANIFEST, assembly_manifest())
        info = zipfile.ZipInfo("safe-placeholder")
        info.filename = raw_name
        bundle.writestr(info, b"unsafe name payload")
    data = stream.getvalue()
    path.write_bytes(data)
    with zipfile.ZipFile(path) as bundle:
        names = [member.orig_filename for member in bundle.infolist()]
    if raw_name not in names:
        raise AssertionError("test ZIP did not preserve the unsafe raw member name")
    return data


class Response:
    def __init__(self, data: bytes, *, url: str = control.ARCHIVE_URL, declared: int | None = None):
        self.stream = io.BytesIO(data)
        self.status = 200
        self.headers = {} if declared is None else {"Content-Length": str(declared)}
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.stream.close()

    def geturl(self):
        return self.url

    def read(self, amount=-1):
        return self.stream.read(amount)


class ChromiumControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def patch_archive_facts(self, payload: bytes):
        return mock.patch.multiple(
            control, ARCHIVE_SIZE=len(payload), ARCHIVE_SHA256=hashlib.sha256(payload).hexdigest()
        )

    def test_constants_pin_public_release_and_download_identity(self):
        self.assertEqual(control.VERSION, "154.0.8037.92")
        self.assertEqual(control.PLATFORM, "win64")
        self.assertEqual(control.ARCHIVE_URL,
                         "https://storage.googleapis.com/chrome-for-testing-public/"
                         "154.0.8037.92/win64/chrome-win64.zip")
        self.assertEqual(control.ARCHIVE_SIZE, 205_614_867)
        self.assertEqual(len(control.ARCHIVE_SHA256), 64)

    def test_fetch_streams_to_atomic_destination_and_returns_digest(self):
        payload = b"verified test archive"
        destination = self.root / "archive.zip"
        with self.patch_archive_facts(payload), mock.patch.object(
            control.urllib.request, "urlopen", return_value=Response(payload, declared=len(payload))
        ) as urlopen:
            digest = control.fetch_archive(destination)
        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
        self.assertEqual(destination.read_bytes(), payload)
        request = urlopen.call_args.args[0]
        self.assertEqual(request.full_url, control.ARCHIVE_URL)
        self.assertFalse(list(self.root.glob("*.partial")))

    def test_fetch_hash_mismatch_preserves_existing_destination_and_removes_partial(self):
        destination = self.root / "archive.zip"
        destination.write_bytes(b"old")
        payload = b"wrong archive"
        with mock.patch.multiple(control, ARCHIVE_SIZE=len(payload), ARCHIVE_SHA256="0" * 64), \
                mock.patch.object(control.urllib.request, "urlopen", return_value=Response(payload)):
            with self.assertRaisesRegex(control.ControlArchiveError, "SHA-256"):
                control.fetch_archive(destination)
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["archive.zip"])

    def test_fetch_rejects_partial_download_and_content_length_mismatch(self):
        payload = b"short"
        destination = self.root / "archive.zip"
        with self.patch_archive_facts(b"longer than short"), mock.patch.object(
            control.urllib.request, "urlopen", return_value=Response(payload)
        ):
            with self.assertRaisesRegex(control.ControlArchiveError, "incomplete"):
                control.fetch_archive(destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.iterdir()), [])

        with self.patch_archive_facts(payload), mock.patch.object(
            control.urllib.request, "urlopen", return_value=Response(payload, declared=len(payload) + 1)
        ):
            with self.assertRaisesRegex(control.ControlArchiveError, "Content-Length"):
                control.fetch_archive(destination)
        self.assertFalse(destination.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_fetch_rejects_redirect_to_unpinned_host(self):
        payload = b"x"
        with self.patch_archive_facts(payload), mock.patch.object(
            control.urllib.request, "urlopen",
            return_value=Response(payload, url="https://example.invalid/chrome.zip"),
        ):
            with self.assertRaisesRegex(control.ControlArchiveError, "redirected"):
                control.fetch_archive(self.root / "archive.zip")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_extracts_only_valid_amd64_release_and_writes_provenance_manifest(self):
        archive = self.root / "archive.zip"
        payload = make_archive(
            archive, exe=pe_image(), manifest=assembly_manifest(),
            extra=(("chrome-win64/chrome.dll", b"placeholder"),),
        )
        target = self.root / "staged"
        with self.patch_archive_facts(payload):
            executable = control.extract_archive(archive, target)
        self.assertEqual(executable, target / control.EXPECTED_EXE)
        self.assertEqual(executable.read_bytes(), pe_image())
        facts = json.loads((target / control.GENERATED_MANIFEST).read_text(encoding="utf-8"))
        self.assertEqual(facts["version"], control.VERSION)
        self.assertEqual(facts["platform"], "win64")
        self.assertEqual(facts["pe_machine"], "AMD64")
        self.assertEqual(facts["version_manifest"], {
            "name": control.VERSION, "version": control.VERSION,
            "type": "win32", "declared_file": "chrome_elf.dll",
        })

    def test_staged_identity_checks_executable_and_dll_content_against_pins(self):
        archive, target = self.root / "archive.zip", self.root / "staged"
        components = {"chrome.exe": pe_image(), "chrome.dll": b"real-control-dll",
                      "chrome_elf.dll": b"real-control-elf"}
        payload = make_archive(archive, exe=components["chrome.exe"], manifest=assembly_manifest(),
                              extra=tuple(("chrome-win64/" + n, b) for n, b in components.items() if n != "chrome.exe"))
        pins = {n: hashlib.sha256(b).hexdigest() for n, b in components.items()}
        with self.patch_archive_facts(payload), mock.patch.object(control, "CONTROL_FILE_SHA256", pins):
            control.extract_archive(archive, target)
            executable, facts = control.staged_browser(target)
            self.assertTrue(os.path.samefile(executable, target / control.EXPECTED_EXE))
            self.assertEqual(facts["verified_component_count"], 3)
            self.assertTrue(facts["source_diagnostic_only"])
            (target / "chrome-win64/chrome.dll").write_bytes(b"changed")
            with self.assertRaisesRegex(control.ControlArchiveError, "component"):
                control.staged_browser(target)

    def test_staged_identity_rejects_modified_provenance(self):
        archive, target = self.root / "archive.zip", self.root / "staged"
        payload = make_archive(archive, exe=pe_image(), manifest=assembly_manifest())
        with self.patch_archive_facts(payload):
            control.extract_archive(archive, target)
            path = target / control.GENERATED_MANIFEST
            value = json.loads(path.read_text())
            value["archive_sha256"] = "0" * 64
            path.write_text(json.dumps(value))
            with self.assertRaisesRegex(control.ControlArchiveError, "provenance"):
                control.staged_browser(target)

    def test_extract_rejects_path_escape_without_writing_outside_stage(self):
        archive = self.root / "archive.zip"
        payload = make_archive(archive, exe=pe_image(), manifest=assembly_manifest(),
                               extra=(("../escaped.txt", b"escape"),))
        target = self.root / "staged"
        with self.patch_archive_facts(payload), self.assertRaisesRegex(
            control.ControlArchiveError, "unsafe member path"
        ):
            control.extract_archive(archive, target)
        self.assertFalse((self.root / "escaped.txt").exists())
        self.assertFalse(target.exists())

    def test_extract_rejects_windows_path_escape_and_casefold_duplicates(self):
        archive = self.root / "archive.zip"
        for unsafe_name in ("chrome-win64\\escape.txt", "chrome-win64\\..\\escaped.txt", "chrome-win64/unsafe\x00.txt"):
            with self.subTest(unsafe_name=repr(unsafe_name)):
                payload = make_archive_with_raw_name(archive, unsafe_name)
                with self.patch_archive_facts(payload), self.assertRaises(control.ControlArchiveError):
                    control.extract_archive(archive, self.root / "staged")

        payload = make_archive(archive, exe=pe_image(), manifest=assembly_manifest(),
                               extra=(("chrome-win64/Chrome.exe", b"shadow"),))
        with self.patch_archive_facts(payload), self.assertRaisesRegex(
            control.ControlArchiveError, "duplicate or case-colliding"
        ):
            control.extract_archive(archive, self.root / "staged")

    def test_extract_rejects_symlink_members(self):
        archive = self.root / "archive.zip"
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as bundle:
            bundle.writestr(control.EXPECTED_EXE, pe_image())
            bundle.writestr(control.EXPECTED_MANIFEST, assembly_manifest())
            link = zipfile.ZipInfo("chrome-win64/link")
            link.create_system = 3
            link.external_attr = (stat.S_IFLNK | 0o777) << 16
            bundle.writestr(link, b"chrome.exe")
        payload = stream.getvalue()
        archive.write_bytes(payload)
        with self.patch_archive_facts(payload), self.assertRaisesRegex(
            control.ControlArchiveError, "link or special file"
        ):
            control.extract_archive(archive, self.root / "staged")

    def test_extract_rejects_non_amd64_wrong_version_and_missing_exe(self):
        archive = self.root / "archive.zip"
        target = self.root / "staged"
        for exe, manifest in (
            (pe_image(0x14C), assembly_manifest()),
            (pe_image(), assembly_manifest("154.0.8037.91")),
            (None, assembly_manifest()),
        ):
            payload = make_archive(archive, exe=exe, manifest=manifest)
            with self.patch_archive_facts(payload), self.assertRaises(control.ControlArchiveError):
                control.extract_archive(archive, target)
            self.assertFalse(target.exists())

    def test_extract_rejects_invalid_pe_and_preexisting_destination(self):
        archive = self.root / "archive.zip"
        payload = make_archive(archive, exe=b"not a PE", manifest=assembly_manifest())
        with self.patch_archive_facts(payload), self.assertRaisesRegex(
            control.ControlArchiveError, "valid PE"
        ):
            control.extract_archive(archive, self.root / "staged")
        target = self.root / "existing"
        target.mkdir()
        with self.patch_archive_facts(payload), self.assertRaisesRegex(
            control.ControlArchiveError, "already exists"
        ):
            control.extract_archive(archive, target)


if __name__ == "__main__":
    unittest.main()
