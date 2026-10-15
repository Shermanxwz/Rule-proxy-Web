"""Fetch and safely stage a pinned Chrome for Testing control for Windows CI.

This is an optional source-only diagnostic input. It does not select or replace
the product browser. The URL, release, archive size, and digest are fixed here;
callers cannot supply a URL or a different release.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
import xml.etree.ElementTree as ET


VERSION = "154.0.8037.92"
PLATFORM = "win64"
ARCHIVE_URL = (
    "https://storage.googleapis.com/chrome-for-testing-public/"
    f"{VERSION}/{PLATFORM}/chrome-{PLATFORM}.zip"
)
ARCHIVE_SIZE = 205_614_867
ARCHIVE_SHA256 = "b897ef3601c947ac0620c784556dec719ac602b0159ce105927acf645ee0f598"
ARCHIVE_MAX_SECONDS = 900
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_MEMBER_BYTES = 512 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024
EXPECTED_ROOT = "chrome-win64"
EXPECTED_EXE = "chrome-win64/chrome.exe"
EXPECTED_MANIFEST = f"chrome-win64/{VERSION}.manifest"
GENERATED_MANIFEST = "chrome-for-testing-control.json"
PE_MACHINE_AMD64 = 0x8664
CONTROL_FILE_SHA256 = {
    "chrome.exe": "f0b204ce7239e221f84c4030cd38e4b688ad05320acc8373da166f548bf57eb5",
    "chrome.dll": "76249ef0bfc397679308ccca2e8e663b00dd4698353c0930d38d7fbeb840d6ef",
    "chrome_elf.dll": "a2fffdae42224ffd308963c4071a8f6854ad27d2314f88491a7e9aaa38ef6366",
}


class ControlArchiveError(ValueError):
    """The pinned control archive or its contents did not pass validation."""


def _digest_file(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(DOWNLOAD_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _check_archive(path: Path) -> str:
    try:
        size, digest = _digest_file(path)
    except OSError as exc:
        raise ControlArchiveError("control archive is unavailable") from exc
    if size != ARCHIVE_SIZE:
        raise ControlArchiveError("control archive size mismatch")
    if digest != ARCHIVE_SHA256:
        raise ControlArchiveError("control archive SHA-256 mismatch")
    return digest


def fetch_archive(path: str | os.PathLike[str]) -> str:
    """Download the one pinned public archive atomically and return its SHA-256."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    request = urllib.request.Request(
        ARCHIVE_URL,
        headers={"User-Agent": "windows-chromium-control/1", "Accept-Encoding": "identity"},
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname != "storage.googleapis.com":
                raise ControlArchiveError("control archive redirected outside its pinned HTTPS host")
            status = getattr(response, "status", 200)
            if status != 200:
                raise ControlArchiveError("control archive server returned a non-success status")
            header_length = response.headers.get("Content-Length")
            if header_length is not None:
                try:
                    if int(header_length) != ARCHIVE_SIZE:
                        raise ControlArchiveError("control archive Content-Length mismatch")
                except ValueError as exc:
                    raise ControlArchiveError("invalid control archive Content-Length") from exc

            fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".partial",
                                        dir=destination.parent)
            temporary = Path(name)
            digest = hashlib.sha256()
            size = 0
            with os.fdopen(fd, "wb") as output:
                while True:
                    if time.monotonic() - started > ARCHIVE_MAX_SECONDS:
                        raise TimeoutError("control archive download exceeded its time limit")
                    chunk = response.read(DOWNLOAD_CHUNK_BYTES)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > ARCHIVE_SIZE:
                        raise ControlArchiveError("control archive exceeded its pinned size")
                    output.write(chunk)
                    digest.update(chunk)
                output.flush()
                os.fsync(output.fileno())
            if size != ARCHIVE_SIZE:
                raise ControlArchiveError("control archive download was incomplete")
            actual_digest = digest.hexdigest()
            if actual_digest != ARCHIVE_SHA256:
                raise ControlArchiveError("control archive SHA-256 mismatch")
            os.replace(temporary, destination)
            temporary = None
            return actual_digest
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _validate_name(info: zipfile.ZipInfo) -> tuple[str, bool]:
    name = info.filename
    if not name or "\x00" in name or "\\" in name or ":" in name:
        raise ControlArchiveError("archive contains an invalid member path")
    is_dir = name.endswith("/")
    raw = name[:-1] if is_dir else name
    if any(part in ("", ".", "..") for part in raw.split("/")):
        raise ControlArchiveError("archive contains an unsafe member path")
    path = PurePosixPath(raw)
    if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
        raise ControlArchiveError("archive contains an unsafe member path")
    if path.parts[0] != EXPECTED_ROOT:
        raise ControlArchiveError("archive member is outside the expected root")
    mode = info.external_attr >> 16
    kind = stat.S_IFMT(mode)
    if kind not in (0, stat.S_IFREG, stat.S_IFDIR):
        raise ControlArchiveError("archive contains a link or special file")
    if is_dir != (kind == stat.S_IFDIR) and kind != 0:
        raise ControlArchiveError("archive member type does not match its path")
    if info.flag_bits & 0x1:
        raise ControlArchiveError("encrypted archive members are not accepted")
    if info.file_size < 0 or info.file_size > MAX_MEMBER_BYTES:
        raise ControlArchiveError("archive member exceeds the per-file size limit")
    if is_dir and info.file_size != 0:
        raise ControlArchiveError("directory entry contains data")
    return raw, is_dir


def _parse_assembly_manifest(data: bytes) -> dict[str, str]:
    if len(data) > 16_384:
        raise ControlArchiveError("version manifest is too large")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ControlArchiveError("version manifest declarations are not accepted")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ControlArchiveError("version manifest is malformed") from exc
    if root.tag != "{urn:schemas-microsoft-com:asm.v1}assembly" or root.attrib != {"manifestVersion": "1.0"}:
        raise ControlArchiveError("version manifest has unexpected assembly metadata")
    identity = root.find("{urn:schemas-microsoft-com:asm.v1}assemblyIdentity")
    if identity is None or identity.attrib != {
        "name": VERSION, "version": VERSION, "type": "win32"
    }:
        raise ControlArchiveError("version manifest does not identify the pinned release")
    files = root.findall("{urn:schemas-microsoft-com:asm.v1}file")
    if len(files) != 1 or files[0].attrib != {"name": "chrome_elf.dll"}:
        raise ControlArchiveError("version manifest file facts are unexpected")
    if len(root) != 2:
        raise ControlArchiveError("version manifest has unexpected elements")
    return {"name": identity.attrib["name"], "version": identity.attrib["version"],
            "type": identity.attrib["type"], "declared_file": files[0].attrib["name"]}


def _pe_machine(data: bytes) -> int:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ControlArchiveError("chrome.exe is not a valid PE image")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > len(data) - 24 or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise ControlArchiveError("chrome.exe has an invalid PE header")
    return struct.unpack_from("<H", data, pe_offset + 4)[0]


def extract_archive(zip_path: str | os.PathLike[str], destination: str | os.PathLike[str]) -> Path:
    """Verify and safely extract the pinned archive; return its AMD64 chrome.exe path."""
    archive = Path(zip_path)
    target = Path(destination)
    digest = _check_archive(archive)
    if target.exists():
        raise ControlArchiveError("control extraction destination already exists")
    target.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{target.name}.", suffix=".staging", dir=target.parent))
    try:
        try:
            with zipfile.ZipFile(archive, "r") as bundle:
                infos = bundle.infolist()
                if not infos or len(infos) > MAX_ARCHIVE_MEMBERS:
                    raise ControlArchiveError("archive member count is invalid")
                total = 0
                seen: set[str] = set()
                validated: list[tuple[zipfile.ZipInfo, str, bool]] = []
                for info in infos:
                    name, is_dir = _validate_name(info)
                    folded = name.casefold()
                    if folded in seen:
                        raise ControlArchiveError("archive contains duplicate or case-colliding paths")
                    seen.add(folded)
                    total += info.file_size
                    if total > MAX_EXTRACTED_BYTES:
                        raise ControlArchiveError("archive exceeds the total extraction size limit")
                    validated.append((info, name, is_dir))
                if EXPECTED_MANIFEST not in {name for _, name, is_dir in validated if not is_dir}:
                    raise ControlArchiveError("pinned version manifest is missing")
                if EXPECTED_EXE not in {name for _, name, is_dir in validated if not is_dir}:
                    raise ControlArchiveError("expected chrome.exe is missing")

                for info, name, is_dir in validated:
                    output_path = stage.joinpath(*PurePosixPath(name).parts)
                    if is_dir:
                        output_path.mkdir(parents=True, exist_ok=True)
                        continue
                    output_path.parent.mkdir(parents=True, exist_ok=True)
                    written = 0
                    with bundle.open(info, "r") as source, output_path.open("xb") as output:
                        while True:
                            chunk = source.read(DOWNLOAD_CHUNK_BYTES)
                            if not chunk:
                                break
                            written += len(chunk)
                            if written > info.file_size or written > MAX_MEMBER_BYTES:
                                raise ControlArchiveError("archive member expanded beyond its declared size")
                            output.write(chunk)
                    if written != info.file_size:
                        raise ControlArchiveError("archive member was truncated")
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, OSError) as exc:
            if isinstance(exc, ControlArchiveError):
                raise
            raise ControlArchiveError("pinned control archive could not be safely extracted") from exc

        exe = stage / EXPECTED_EXE
        pe = _pe_machine(exe.read_bytes())
        if pe != PE_MACHINE_AMD64:
            raise ControlArchiveError("chrome.exe is not AMD64")
        version_facts = _parse_assembly_manifest((stage / EXPECTED_MANIFEST).read_bytes())
        manifest = {
            "archive_sha256": digest,
            "archive_size": ARCHIVE_SIZE,
            "archive_url": ARCHIVE_URL,
            "platform": PLATFORM,
            "version": VERSION,
            "version_manifest": version_facts,
            "chrome_exe": EXPECTED_EXE,
            "pe_machine": "AMD64",
            "pe_machine_value": PE_MACHINE_AMD64,
        }
        (stage / GENERATED_MANIFEST).write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
        )
        os.replace(stage, target)
        return target / EXPECTED_EXE
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def staged_browser(destination: str | os.PathLike[str]) -> tuple[Path, dict]:
    """Recheck the pinned control's identity before its diagnostic launch."""
    target = Path(destination).resolve(strict=True)
    raw = (target / GENERATED_MANIFEST).read_bytes()
    if len(raw) > 8192:
        raise ControlArchiveError("control provenance record exceeds its bound")
    value = json.loads(raw)
    facts = _parse_assembly_manifest((target / EXPECTED_MANIFEST).read_bytes())
    expected = {"archive_sha256": ARCHIVE_SHA256, "archive_size": ARCHIVE_SIZE,
        "archive_url": ARCHIVE_URL, "platform": PLATFORM, "version": VERSION,
        "version_manifest": facts, "chrome_exe": EXPECTED_EXE,
        "pe_machine": "AMD64", "pe_machine_value": PE_MACHINE_AMD64}
    if value != expected:
        raise ControlArchiveError("control provenance does not match the pinned archive")
    for name, digest in CONTROL_FILE_SHA256.items():
        path = target / EXPECTED_ROOT / name
        if path.resolve(strict=True).parent != target / EXPECTED_ROOT or _digest_file(path)[1] != digest:
            raise ControlArchiveError("control executable component differs from the pinned archive")
    executable = target / EXPECTED_EXE
    if _pe_machine(executable.read_bytes()) != PE_MACHINE_AMD64:
        raise ControlArchiveError("control executable is not AMD64")
    return executable, {"version": VERSION, "archive_sha256": ARCHIVE_SHA256,
        "entry_sha256": CONTROL_FILE_SHA256["chrome.exe"], "verified_component_count": len(CONTROL_FILE_SHA256),
        "source_diagnostic_only": True, "product_browser_replaced": False}
