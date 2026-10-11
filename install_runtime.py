"""Download pinned runtimes into this project's bin/ directory only."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent
MIHOMO_VERSION = "v1.19.32"
MIHOMO = {
    "linux-amd64": ("mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"),
    "windows-amd64": ("mihomo-windows-amd64-compatible-v1.19.32.zip", "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
}
MXC_VERSION = "1.0.0+c6f301d.ruleproxy.1"
MXC_SOURCE_REVISION = "c6f301d53a1430c4c921a05c57af838f7392348f"
MXC_URL = "https://raw.githubusercontent.com/Shermanxwz/Rule-proxy-Web/139653ceb36e0597050d9a166f9bca6249248f81/mxc-proxy-c6f301d-windows-x64.zip"
MXC_SHA256 = "84bcb10b1f7ffd62f8fc8356e94e4c0a42684ce68515b68dfdcce4bb6c0757ef"
MXC_FILES = {
    "wxc-exec.exe": "e7527dfda680608442ecbd06222bf6bccd88e9205d80436d547afb2ca074fab7",
    "winhttp-proxy-shim.exe": "a90c902de8a37782947a9034eca8b4f7b03f154a0381fb57a8f3dc70037340c1",
}
LEGACY_MXC_URL = "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.0.tgz"
LEGACY_MXC_SHA512 = "7aVR+GHVKveIknZmUtkAEFwUBp61qgEmhJRe1ZyKHJ274yWlKWB/ZfDP/u/whfmDyck0wRNKZN49atlF+SZt2Q=="
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


def expected(platform: str) -> dict:
    """The versions a complete install of this platform records."""
    record = {"mihomo": MIHOMO_VERSION}
    if platform == "windows-amd64":
        record["mxc"] = MXC_VERSION
    return record


def _required_files(platform: str) -> tuple[str, ...]:
    return ("mihomo",) if platform == "linux-amd64" else ("mihomo.exe", *MXC_FILES)


def installed(platform: str, root: Path | None = None) -> bool:
    """True when this platform's pinned runtimes are already in place."""
    directory = (ROOT if root is None else root) / "bin" / platform
    try:
        record = json.loads((directory / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if record != expected(platform) or not all((directory / name).is_file() for name in _required_files(platform)):
        return False
    if platform == "windows-amd64":
        try:
            return all(hashlib.sha256((directory / name).read_bytes()).hexdigest() == digest for name, digest in MXC_FILES.items())
        except OSError:
            return False
    return True


def install(platform: str, root: Path | None = None) -> Path:
    directory = (ROOT if root is None else root) / "bin" / platform
    directory.mkdir(parents=True, exist_ok=True)
    (directory / MANIFEST).unlink(missing_ok=True)
    (directory / "MIHOMO-LICENSE").write_bytes(fetch(f"https://raw.githubusercontent.com/MetaCubeX/mihomo/{MIHOMO_VERSION}/LICENSE"))
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
        if hashlib.sha256(data).hexdigest() != MXC_SHA256:
            raise ValueError("MXC 校验值不符，已拒绝安装。")
        # Exact member names and per-file hashes prevent partial or ambiguous
        # runtime layouts. The immutable Git archive preserves the qualified bytes.
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            allowed = {*MXC_FILES, "MXC-LICENSE.md", "SOURCE.txt", "SHA256SUMS.txt"}
            if len(names) != len(set(names)) or set(names) != allowed:
                raise ValueError("MXC 运行组件压缩包内容与固定版本不符。")
            binaries = {}
            for name, digest in MXC_FILES.items():
                if archive.getinfo(name).file_size > 32 * 1024 * 1024:
                    raise ValueError("MXC 运行组件大小超过上限。")
                binary = archive.read(name)
                if hashlib.sha256(binary).hexdigest() != digest:
                    raise ValueError(f"MXC 组件 {name} 校验值不符。")
                binaries[name] = binary
            source = archive.read("SOURCE.txt")
            if MXC_SOURCE_REVISION.encode("ascii") not in source:
                raise ValueError("MXC 源码修订记录不符。")
            for name, binary in binaries.items():
                (directory / name).write_bytes(binary)
            (directory / "MXC-LICENSE.md").write_bytes(archive.read("MXC-LICENSE.md"))
            (directory / "MXC-SOURCE.txt").write_bytes(source)
        for name in SKIPPED_MXC_FILES:
            (directory / name).unlink(missing_ok=True)
    (directory / MANIFEST).write_text(json.dumps(expected(platform), indent=2) + "\n", encoding="utf-8")
    print(f"运行组件已安装到 {directory}（只写入本项目目录）。", flush=True)
    return directory


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # a cp1252 pipe must not crash on Chinese text
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(MIHOMO), default="windows-amd64" if sys.platform == "win32" else "linux-amd64")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--if-needed", action="store_true", help="skip the download when the pinned runtimes are already installed")
    mode.add_argument("--check", action="store_true", help="download nothing; exit 0 only when the pinned runtimes are installed")
    args = parser.parse_args(argv)
    if args.check:
        return 0 if installed(args.platform) else 1
    if args.if_needed and installed(args.platform):
        print(f"固定版本的运行组件已就绪：{ROOT / 'bin' / args.platform}", flush=True)
        return 0
    try:
        install(args.platform)
    except (OSError, ValueError, EOFError, zipfile.BadZipFile) as exc:
        print(f"运行组件下载失败：{exc}", file=sys.stderr, flush=True)
        print("没有更改本项目目录以外的任何内容。请检查网络后重新运行安装。", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
