"""Download pinned official runtimes into this project's bin/ directory only."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile

from ruleproxy import windows_runtime_pins as runtime_pins


ROOT = Path(__file__).resolve().parent
MIHOMO_VERSION = runtime_pins.MIHOMO_VERSION
MIHOMO_LICENSE_SHA256 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"
MIHOMO = {
    "linux-amd64": ("mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"),
    "windows-amd64": ("mihomo-windows-amd64-compatible-v1.19.32.zip", "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
}
MXC_VERSION = runtime_pins.MXC_VERSION
MXC_URL = "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.0.tgz"
MXC_SHA512 = "7aVR+GHVKveIknZmUtkAEFwUBp61qgEmhJRe1ZyKHJ274yWlKWB/ZfDP/u/whfmDyck0wRNKZN49atlF+SZt2Q=="
MXC_G_BUNDLE_URL = runtime_pins.MXC_G_BUNDLE_URL
MXC_G_BUNDLE_SHA256 = runtime_pins.MXC_G_BUNDLE_SHA256
MXC_G_EXECUTOR_SHA256 = runtime_pins.MXC_G_EXECUTOR_SHA256
MXC_G_LICENSE_SHA256 = runtime_pins.MXC_G_LICENSE_SHA256
MXC_G_BUILD_MANIFEST = runtime_pins.MXC_G_BUILD_MANIFEST
MXC_VARIANTS = runtime_pins.MXC_VARIANTS
DEFAULT_MXC_VARIANT = runtime_pins.DEFAULT_MXC_VARIANT
# MXC's plm.exe serves only its elevated denial-capture diagnostics, which RuleProxy never
# requests, and MXC 1.0.0 panics while vetting it when the first folder of its path starts
# with a non-ASCII character (C:\应用\…). It is not installed (see ruleproxy/windows_runtime.py).
SKIPPED_MXC_FILES = ("plm.exe",)
# Written last, so an interrupted download never looks complete.
MANIFEST = "runtime.json"
MAX_DOWNLOAD = 160 * 1024 * 1024


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "RuleProxyWeb/0.1"})
    with urllib.request.urlopen(req, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("下载内容超过大小上限。")
    return data


def expected(platform: str, mxc_variant: str | None = None) -> dict:
    """The versions a complete install of this platform records."""
    if mxc_variant is None:
        mxc_variant = DEFAULT_MXC_VARIANT if platform == "windows-amd64" else "stock"
    record = {"mihomo": MIHOMO_VERSION}
    if platform == "windows-amd64":
        if mxc_variant not in MXC_VARIANTS:
            raise ValueError("Unknown Windows MXC runtime variant")
        record["mxc"] = runtime_pins.expected_mxc_record(mxc_variant)
    elif mxc_variant != "stock":
        raise ValueError("The G-patched MXC runtime is Windows-only")
    return record


def _required_files(platform: str) -> tuple[str, ...]:
    if platform == "linux-amd64":
        return ("mihomo", "MIHOMO-LICENSE")
    return ("mihomo.exe", "wxc-exec.exe", "mxc_ffi.dll", "MIHOMO-LICENSE", "MXC-LICENSE.md")


def _file_digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _installed_variant(platform: str, root: Path | None, mxc_variant: str) -> bool:
    """True when this platform's pinned runtimes are already in place."""
    directory = (ROOT if root is None else root) / "bin" / platform
    try:
        record = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            return False
        digests = record.pop("sha256", None)
        if record != expected(platform, mxc_variant) or not isinstance(digests, dict) or not digests:
            return False
        if not all(name in digests for name in _required_files(platform)):
            return False
        if mxc_variant == "g-patched" and (
                digests.get("wxc-exec.exe") != MXC_G_EXECUTOR_SHA256
                or digests.get("MXC-LICENSE.md") != MXC_G_LICENSE_SHA256):
            return False
        for name, digest in digests.items():
            # The manifest describes only files alongside it, never other paths.
            if not isinstance(name, str) or Path(name).name != name or ":" in name or "\\" in name \
                    or name in (".", "..", MANIFEST) or not isinstance(digest, str):
                return False
            path = directory / name
            if not path.is_file() or not path.stat().st_size or _file_digest(path) != digest:
                return False
    except (OSError, ValueError):
        return False
    return True


def installed(platform: str, root: Path | None = None,
              mxc_variant: str | None = None) -> bool:
    if mxc_variant is None:
        mxc_variant = DEFAULT_MXC_VARIANT if platform == "windows-amd64" else "stock"
    return _installed_variant(platform, root, mxc_variant)


def installed_other_variant(platform: str, root: Path | None, selected: str) -> str | None:
    if platform != "windows-amd64":
        return None
    return next((variant for variant in MXC_VARIANTS if variant != selected
                 and _installed_variant(platform, root, variant)), None)


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate G bundle manifest field")
        result[key] = value
    return result


def _g_bundle_bytes(path: Path | None = None, *, allow_env_cache: bool = True) -> bytes:
    if path is None:
        cached = os.environ.get("RULEPROXY_PINNED_G_BUNDLE") if allow_env_cache else None
        if cached:
            path = Path(cached)
        else:
            data = fetch(MXC_G_BUNDLE_URL)
            if hashlib.sha256(data).hexdigest() != MXC_G_BUNDLE_SHA256:
                raise ValueError("Pinned G runtime bundle digest mismatch")
            return data
    if path is not None:
        path = Path(path)
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or path.stat().st_size > 32 * 1024 * 1024):
            raise ValueError("G runtime bundle must be an absolute ordinary file")
        data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != MXC_G_BUNDLE_SHA256:
        raise ValueError("Pinned G runtime bundle digest mismatch")
    return data


def _extract_g_bundle(data: bytes, directory: Path) -> None:
    if hashlib.sha256(data).hexdigest() != MXC_G_BUNDLE_SHA256:
        raise ValueError("Pinned G runtime bundle digest mismatch")
    expected_names = ("build-manifest.json", "wxc-exec.exe", "MXC-LICENSE.md")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if tuple(info.filename for info in infos) != expected_names:
                raise ValueError("G runtime bundle member list mismatch")
            if any(info.is_dir() or info.compress_type != zipfile.ZIP_STORED
                   or info.date_time != (1980, 1, 1, 0, 0, 0) for info in infos):
                raise ValueError("G runtime bundle layout mismatch")
            manifest_bytes, executor_bytes, license_bytes = (archive.read(info) for info in infos)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ValueError("G runtime bundle is invalid") from exc
    if (len(manifest_bytes) > 16 * 1024 or len(executor_bytes) > 32 * 1024 * 1024
            or len(license_bytes) > 64 * 1024):
        raise ValueError("G runtime bundle member exceeds its bound")
    manifest = json.loads(manifest_bytes, object_pairs_hook=_strict_json_object)
    if manifest != MXC_G_BUILD_MANIFEST:
        raise ValueError("G runtime build provenance mismatch")
    if hashlib.sha256(executor_bytes).hexdigest() != MXC_G_EXECUTOR_SHA256:
        raise ValueError("G runtime executor digest mismatch")
    if hashlib.sha256(license_bytes).hexdigest() != MXC_G_LICENSE_SHA256:
        raise ValueError("G runtime MIT license digest mismatch")
    if len(executor_bytes) < 512 or executor_bytes[:2] != b"MZ":
        raise ValueError("G runtime executor is not a PE image")
    offset = int.from_bytes(executor_bytes[0x3c:0x40], "little")
    if offset < 64 or offset + 6 > len(executor_bytes) or executor_bytes[offset:offset + 4] != b"PE\0\0" \
            or int.from_bytes(executor_bytes[offset + 4:offset + 6], "little") != 0x8664:
        raise ValueError("G runtime executor is not native x64")
    (directory / "wxc-exec.exe").write_bytes(executor_bytes)
    (directory / "MXC-LICENSE.md").write_bytes(license_bytes)


def build_g_bundle(source: Path, output: Path) -> str:
    """Assemble the exact fixed three-file asset from a verified build artifact."""
    source, output = Path(source).resolve(strict=True), Path(output).resolve()
    if not source.is_dir() or source.is_symlink():
        raise ValueError("G build artifact source must be an ordinary directory")
    names = ("build-manifest.json", "wxc-exec.exe", "MXC-LICENSE.md")
    files = {}
    for name in names:
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("G build artifact is missing a fixed bundle member")
        files[name] = path.read_bytes()
    manifest = json.loads(files["build-manifest.json"], object_pairs_hook=_strict_json_object)
    if (manifest != MXC_G_BUILD_MANIFEST
            or hashlib.sha256(files["wxc-exec.exe"]).hexdigest() != MXC_G_EXECUTOR_SHA256
            or hashlib.sha256(files["MXC-LICENSE.md"]).hexdigest() != MXC_G_LICENSE_SHA256):
        raise ValueError("G build artifact provenance or digest mismatch")
    pending = io.BytesIO()
    with zipfile.ZipFile(pending, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    data = pending.getvalue()
    digest = hashlib.sha256(data).hexdigest()
    if digest != MXC_G_BUNDLE_SHA256:
        raise ValueError("Deterministic G bundle bytes do not match the pinned release asset")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(data)
    return digest


def _populate(platform: str, directory: Path, *, mxc_variant: str = "stock", g_bundle: bytes | None = None) -> None:
    """Verify and extract downloads into a new, private staging directory."""
    license_data = fetch(f"https://raw.githubusercontent.com/MetaCubeX/mihomo/{MIHOMO_VERSION}/LICENSE")
    if hashlib.sha256(license_data).hexdigest() != MIHOMO_LICENSE_SHA256:
        raise ValueError("Mihomo 许可文件校验值不符，已拒绝安装。")
    (directory / "MIHOMO-LICENSE").write_bytes(license_data)
    name, digest = MIHOMO[platform]
    print(f"正在下载固定版本的 Mihomo {MIHOMO_VERSION}…", flush=True)
    data = fetch(f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/{name}")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Mihomo 校验值不符，已拒绝安装。")
    if platform == "linux-amd64":
        path = directory / "mihomo"
        path.write_bytes(gzip.decompress(data))
        path.chmod(0o755)
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [m for m in archive.infolist() if not m.is_dir() and m.filename.endswith(".exe")]
            if len(members) != 1:
                raise ValueError("Mihomo 压缩包内容与预期不符。")
            (directory / "mihomo.exe").write_bytes(archive.read(members[0]))
        print(f"正在下载固定版本的 Microsoft MXC {MXC_VERSION}…", flush=True)
        data = fetch(MXC_URL)
        actual = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        if actual != MXC_SHA512:
            raise ValueError("MXC 校验值不符，已拒绝安装。")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                item = Path(member.name)
                if item.parent.as_posix() == "package/bin/x64" and item.suffix in (".exe", ".dll") \
                        and item.name.lower() not in SKIPPED_MXC_FILES \
                        and not (mxc_variant == "g-patched" and item.name.lower() == "wxc-exec.exe"):
                    with archive.extractfile(member) as source:
                        (directory / item.name).write_bytes(source.read())
                elif member.name == "package/LICENSE.md":
                    with archive.extractfile(member) as source:
                        (directory / "MXC-LICENSE.md").write_bytes(source.read())
        if mxc_variant == "g-patched":
            if g_bundle is None:
                raise ValueError("The G-patched MXC variant requires its pinned bundle")
            _extract_g_bundle(g_bundle, directory)
        elif mxc_variant != "stock":
            raise ValueError("Unknown Windows MXC runtime variant")
    if not all((directory / name).is_file() and (directory / name).stat().st_size
               for name in _required_files(platform)):
        raise ValueError("校验通过的运行组件包里缺少必要文件。")
    record = expected(platform, mxc_variant)
    record["sha256"] = {path.name: _file_digest(path) for path in sorted(directory.iterdir(), key=lambda item: item.name) if path.is_file()}
    (directory / MANIFEST).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def install(platform: str, root: Path | None = None, *, mxc_variant: str | None = None,
            g_bundle_path: Path | None = None, variant_explicit: bool = False,
            allow_env_bundle_cache: bool = True) -> Path:
    if mxc_variant is None:
        mxc_variant = DEFAULT_MXC_VARIANT if platform == "windows-amd64" else "stock"
    if mxc_variant not in MXC_VARIANTS or (platform != "windows-amd64" and mxc_variant != "stock"):
        raise ValueError("Runtime variant is not available for this platform")
    other = installed_other_variant(platform, root, mxc_variant)
    # Default G selection deliberately upgrades a verified stock install. The
    # reverse transition is never implicit.
    if other is not None and not variant_explicit and not (mxc_variant == "g-patched" and other == "stock"):
        raise ValueError(f"A valid {other} MXC runtime is installed; select the variant explicitly to replace it")
    g_bundle = (_g_bundle_bytes(g_bundle_path, allow_env_cache=allow_env_bundle_cache)
                if mxc_variant == "g-patched" else None)
    directory = (ROOT if root is None else root) / "bin" / platform
    directory.parent.mkdir(parents=True, exist_ok=True)
    # Keep the existing runtimes usable until every new component is verified.
    # Sibling paths stay on the same filesystem, so directory renames are atomic.
    with tempfile.TemporaryDirectory(prefix=f".{platform}-", dir=directory.parent,
                                     ignore_cleanup_errors=True) as temporary:
        staged = Path(temporary) / "new"
        # Keep the rollback copy outside the auto-cleaned staging folder. If a
        # competing writer prevents restoration, the previous files survive.
        backup = directory.parent / f"{Path(temporary).name}-previous"
        staged.mkdir()
        _populate(platform, staged, mxc_variant=mxc_variant, g_bundle=g_bundle)
        if directory.exists():
            directory.rename(backup)
        try:
            staged.rename(directory)
        except OSError:
            if backup.exists():
                try:
                    backup.rename(directory)
                except OSError as exc:
                    raise OSError(f"无法恢复旧运行组件；原文件保留在 {backup}：{exc}") from exc
            raise
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
    print(f"运行组件已安装到 {directory}（只写入本项目目录）。", flush=True)
    return directory


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # a cp1252 pipe must not crash on Chinese text
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(MIHOMO), default="windows-amd64" if sys.platform == "win32" else "linux-amd64")
    variant = parser.add_mutually_exclusive_group()
    variant.add_argument("--mxc-g", action="store_true", help=argparse.SUPPRESS)
    variant.add_argument("--mxc-g-bundle", type=Path, help=argparse.SUPPRESS)
    variant.add_argument("--mxc-stock", action="store_true", help=argparse.SUPPRESS)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--if-needed", action="store_true", help="skip the download when the pinned runtimes are already installed")
    mode.add_argument("--check", action="store_true", help="download nothing; exit 0 only when the pinned runtimes are installed")
    args = parser.parse_args(argv)
    selected_variant = ("stock" if args.platform != "windows-amd64" or args.mxc_stock else
                        "g-patched" if args.mxc_g or args.mxc_g_bundle is not None else DEFAULT_MXC_VARIANT)
    variant_explicit = args.mxc_g or args.mxc_g_bundle is not None or args.mxc_stock
    if selected_variant != "stock" and args.platform != "windows-amd64":
        parser.error("The G-patched MXC variant is Windows-only")
    if args.check:
        return 0 if installed(args.platform, mxc_variant=selected_variant) else 1
    if args.if_needed and installed(args.platform, mxc_variant=selected_variant):
        print(f"固定版本的运行组件已就绪：{ROOT / 'bin' / args.platform}", flush=True)
        return 0
    other = installed_other_variant(args.platform, None, selected_variant)
    if other is not None and not variant_explicit and not (selected_variant == "g-patched" and other == "stock"):
        print(f"已安装 {other} MXC 运行组件；请明确选择运行组件版本。", file=sys.stderr, flush=True)
        return 1
    try:
        install(args.platform, mxc_variant=selected_variant,
                g_bundle_path=args.mxc_g_bundle, variant_explicit=variant_explicit)
    except (OSError, ValueError, EOFError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"运行组件下载失败：{exc}", file=sys.stderr, flush=True)
        print("没有更改本项目目录以外的任何内容。请检查网络后重新运行安装。", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
