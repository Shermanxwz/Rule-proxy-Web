"""Download pinned official runtimes into this project's bin/ directory only."""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
from pathlib import Path
import sys
import tarfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent
MIHOMO_VERSION = "v1.19.32"
MIHOMO = {
    "linux-amd64": ("mihomo-linux-amd64-compatible-v1.19.32.gz", "ba3ce607747a07f948fc35780e108a4a7c7f552a38b9bd4d115f313ebcb89c20"),
    "windows-amd64": ("mihomo-windows-amd64-compatible-v1.19.32.zip", "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"),
}
MXC_URL = "https://registry.npmjs.org/@microsoft/mxc-sdk/-/mxc-sdk-1.0.0.tgz"
MXC_SHA512 = "7aVR+GHVKveIknZmUtkAEFwUBp61qgEmhJRe1ZyKHJ274yWlKWB/ZfDP/u/whfmDyck0wRNKZN49atlF+SZt2Q=="


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "RuleProxyWeb/0.1"})
    with urllib.request.urlopen(req, timeout=60) as response:
        data = response.read(160 * 1024 * 1024 + 1)
    if len(data) > 160 * 1024 * 1024:
        raise ValueError("Runtime download exceeded the size limit")
    return data


def install(platform: str):
    directory = ROOT / "bin" / platform
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "MIHOMO-LICENSE").write_bytes(fetch(f"https://raw.githubusercontent.com/MetaCubeX/mihomo/{MIHOMO_VERSION}/LICENSE"))
    name, digest = MIHOMO[platform]
    print("Downloading pinned Mihomo " + MIHOMO_VERSION, flush=True)
    data = fetch(f"https://github.com/MetaCubeX/mihomo/releases/download/{MIHOMO_VERSION}/{name}")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Mihomo checksum mismatch; refusing to install")
    if platform == "linux-amd64":
        path = directory / "mihomo"
        path.write_bytes(gzip.decompress(data))
        path.chmod(0o755)
    else:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [m for m in archive.infolist() if not m.is_dir() and m.filename.endswith(".exe")]
            if len(members) != 1:
                raise ValueError("Unexpected Mihomo archive contents")
            (directory / "mihomo.exe").write_bytes(archive.read(members[0]))
        print("Downloading pinned Microsoft MXC 1.0.0", flush=True)
        data = fetch(MXC_URL)
        actual = base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
        if actual != MXC_SHA512:
            raise ValueError("MXC checksum mismatch; refusing to install")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                item = Path(member.name)
                if item.parent.as_posix() == "package/bin/x64" and item.suffix in (".exe", ".dll"):
                    with archive.extractfile(member) as source:
                        (directory / item.name).write_bytes(source.read())
                elif member.name == "package/LICENSE.md":
                    with archive.extractfile(member) as source:
                        (directory / "MXC-LICENSE.md").write_bytes(source.read())
        if not (directory / "wxc-exec.exe").is_file():
            raise ValueError("MXC executor was missing from the verified archive")
    print("Installed only project-local files: " + str(directory), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=tuple(MIHOMO), default="windows-amd64" if sys.platform == "win32" else "linux-amd64")
    args = parser.parse_args()
    install(args.platform)
