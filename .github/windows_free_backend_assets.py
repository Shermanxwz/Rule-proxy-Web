"""Build a pinned, source-only payload for disposable free-backend comparisons.

The official installers are inputs, not product dependencies or installation
actions. This Linux-capable builder never executes a downloaded binary.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import stat
import tempfile
import urllib.request
import zipfile


ROOT = Path(__file__).resolve().parent.parent
ASSETS = {
    "python": {
        "name": "python-3.14.8-embed-amd64.zip", "release": "3.14.8",
        "url": "https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip",
        "sha256": "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310", "max_bytes": 64 * 1024**2},
    "mihomo": {
        "name": "mihomo-windows-amd64-compatible-v1.19.32.zip", "release": "v1.19.32",
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-windows-amd64-compatible-v1.19.32.zip",
        "sha256": "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0", "max_bytes": 160 * 1024**2},
    "chromium": {
        "name": "chrome-win64-154.0.8037.92.zip", "release": "154.0.8037.92",
        "url": "https://storage.googleapis.com/chrome-for-testing-public/154.0.8037.92/win64/chrome-win64.zip",
        "sha256": "b897ef3601c947ac0620c784556dec719ac602b0159ce105927acf645ee0f598", "size": 205614867,
        "max_bytes": 256 * 1024**2},
    "sandboxie": {
        "name": "Sandboxie-Plus-x64-v1.18.5.exe", "release": "v1.18.5",
        "url": "https://github.com/sandboxie-plus/Sandboxie/releases/download/v1.18.5/Sandboxie-Plus-x64-v1.18.5.exe",
        "sha256": "bd984db71900ecb9fc22e4bbffda4363a92cd755840a8792c2422d6d42fd6fa3", "size": 24856520,
        "max_bytes": 32 * 1024**2},
    "proxybridge": {
        "name": "ProxyBridge-Setup-4.1.1.exe", "release": "v4.1.1",
        "url": "https://github.com/InterceptSuite/ProxyBridge/releases/download/v4.1.1/ProxyBridge-Setup-4.1.1.exe",
        "sha256": "754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152", "size": 799792,
        "max_bytes": 4 * 1024**2},
}
SCRIPT_NAMES = ("windows_free_backend_fixture.py", "windows_native_dns_probe.py")


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def verify_asset(path, asset):
    return (path.is_file() and not path.is_symlink() and path.stat().st_size <= asset["max_bytes"]
            and ("size" not in asset or path.stat().st_size == asset["size"])
            and sha256(path) == asset["sha256"])


def fetch(asset, cache):
    destination = cache / asset["name"]
    if verify_asset(destination, asset):
        return destination
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "RuleProxy-free-backend-controls/1"})
    temporary = destination.with_suffix(destination.suffix + ".partial")
    try:
        with urllib.request.urlopen(request, timeout=120) as source, temporary.open("wb") as target:
            size = 0
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > asset["max_bytes"]:
                    raise ValueError("official asset exceeds fixed size bound")
                target.write(block)
        if not verify_asset(temporary, asset):
            raise ValueError("official asset size or SHA-256 mismatch")
        temporary.replace(destination)
        return destination
    finally:
        temporary.unlink(missing_ok=True)


def extract(source, target):
    total = 0
    with zipfile.ZipFile(source) as archive:
        seen = set()
        for member in archive.infolist():
            path = PurePosixPath(member.filename)
            mode = member.external_attr >> 16
            if (path.is_absolute() or ".." in path.parts or ":" in member.filename
                    or "\\" in member.filename or member.filename in seen or stat.S_ISLNK(mode)):
                raise ValueError("unsafe or duplicate archive member")
            seen.add(member.filename)
            total += member.file_size
            if member.file_size > 512 * 1024**2 or total > 1536 * 1024**2:
                raise ValueError("archive expanded size limit")
        archive.extractall(target)


def manifest_for(root, backend):
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file() and path != root / "manifest.json":
            relative = path.relative_to(root).as_posix()
            entry = {"path": relative, "size": path.stat().st_size, "sha256": sha256(path)}
            for key, prefix in (("python", "python/"), ("mihomo", "mihomo/"),
                                ("chromium", "chromium/"), (backend, "installers/")):
                if relative.startswith(prefix):
                    entry["source_url"] = ASSETS[key]["url"]
                    break
            files.append(entry)
    return {"schema_version": 1, "backend": backend, "release": ASSETS[backend]["release"],
            "source_diagnostic_only": True, "release_eligible": False, "files": files,
            "downloaded_archives": [{"component": key, **{name: value for name, value in ASSETS[key].items()
                                                         if name in ("url", "sha256", "release", "size")}}
                                    for key in ("python", "mihomo", "chromium", backend)]}


def build(backend, destination, cache, source_root=ROOT):
    if backend not in ("sandboxie", "proxybridge"):
        raise ValueError("unknown diagnostic backend")
    cache.mkdir(parents=True, exist_ok=True)
    inputs = {key: fetch(ASSETS[key], cache) for key in ("python", "mihomo", "chromium", backend)}
    with tempfile.TemporaryDirectory(prefix="ruleproxy-free-bundle-") as directory:
        root = Path(directory)
        extract(inputs["python"], root / "python")
        if not (root / "python/python.exe").is_file() or not (root / "python/python314._pth").is_file():
            raise ValueError("pinned embedded Python layout changed")
        extract(inputs["mihomo"], root / "mihomo")
        binaries = list((root / "mihomo").glob("*.exe"))
        if len(binaries) != 1:
            raise ValueError("pinned Mihomo archive layout changed")
        binary = binaries[0]
        if binary.name != "mihomo.exe":
            binary.rename(root / "mihomo/mihomo.exe")
        extract(inputs["chromium"], root / "chromium")
        if not (root / "chromium/chrome-win64/chrome.exe").is_file():
            raise ValueError("pinned browser archive layout changed")
        installers = root / "installers"
        installers.mkdir()
        shutil.copyfile(inputs[backend], installers / ASSETS[backend]["name"])
        scripts = root / "scripts"
        scripts.mkdir()
        for name in (*SCRIPT_NAMES, "windows_" + backend + "_control.py"):
            source = source_root / ".github" / name
            if not source.is_file():
                raise ValueError("required source-only script missing: " + name)
            shutil.copyfile(source, scripts / name)
        manifest = manifest_for(root, backend)
        (root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=True, indent=2) + "\n", encoding="ascii")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".partial")
        try:
            with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
                for path in sorted(root.rglob("*")):
                    if path.is_file():
                        entry = zipfile.ZipInfo(path.relative_to(root).as_posix(), (1980, 1, 1, 0, 0, 0))
                        entry.create_system = 3
                        entry.external_attr = 0o100644 << 16
                        archive.writestr(entry, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=6)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    return {"backend": backend, "release": ASSETS[backend]["release"], "payload_bytes": destination.stat().st_size,
            "payload_sha256": sha256(destination), "source_diagnostic_only": True, "release_eligible": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend", required=True, choices=("sandboxie", "proxybridge"))
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "ruleproxy-free-backend-cache")
    args = parser.parse_args(argv)
    print(json.dumps(build(args.backend, args.output, args.cache_dir), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
