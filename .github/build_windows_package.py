"""Build the Windows release package: the panel, its pinned runtimes, PyYAML and a private Python.

Usage: python build_windows_package.py OUTPUT_DIR

Every download is checked against a pinned hash before use (Mihomo and MXC
through install_runtime.py). The zip unpacks to a single RuleProxy-Web folder,
so a newer version unpacked over an older one keeps the desktop shortcuts
working. The output folder also receives SHA256SUMS.txt and release-notes.md.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import install_runtime  # noqa: E402
from ruleproxy import __version__  # noqa: E402

# python.org publishes this SHA-256 in its release file listing for 3.14.8.
PYTHON_VERSION = "3.14.8"
PYTHON_URL = f"https://www.python.org/ftp/python/{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-amd64.zip"
PYTHON_SHA256 = "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"
PYTHON_PTH = "python314._pth"
PYTHON_STDLIB = "python314.zip"
# The PyPI wheel for that Python. Its compiled speedup is optional; the panel uses the pure-Python safe loader.
PYYAML_VERSION = "6.0.3"
PYYAML_URL = ("https://files.pythonhosted.org/packages/23/20/bb6982b26a40bb43951265ba29d4c246ef0ff59c9fdcdf0ed04e0687de4d/"
              "pyyaml-6.0.3-cp314-cp314-win_amd64.whl")
PYYAML_SHA256 = "4a2e8cebe2ff6ab7d1050ecd59c25d4c8bd7e6f400f5f82b96557ac0abafd0ac"

FOLDER = "RuleProxy-Web"
# What the Windows panel needs. Linux scripts, tests and the source-checkout installer stay out.
INCLUDE = ("Run-RuleProxy.py", "Start-Windows.cmd", "README.md", "CHANGELOG.md", "LICENSE", "THIRD-PARTY.md", "WINDOWS-VALIDATION.md", "ruleproxy/", "web/", "examples/")
# The embedded Python reads only the paths listed here: its own library, its folder, and the package root.
PTH_TEXT = f"{PYTHON_STDLIB}\r\n.\r\n..\r\n# RuleProxy: the package root holds ruleproxy/ and Run-RuleProxy.py; site is not imported.\r\n"
MAX_DOWNLOAD = 64 * 1024 * 1024


def download(url: str, sha256: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": f"RuleProxyWeb/{__version__} package build"})
    with urllib.request.urlopen(request, timeout=120) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise SystemExit(f"{url} is larger than expected")
    actual = hashlib.sha256(data).hexdigest()
    if actual != sha256:
        raise SystemExit(f"Checksum mismatch for {url}: expected {sha256}, got {actual}")
    return data


def safe_extract(data: bytes, target: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for member in archive.infolist():
            name = PurePosixPath(member.filename)
            if name.is_absolute() or ".." in name.parts or ":" in member.filename or "\\" in member.filename:
                raise SystemExit(f"Refusing unsafe archive path {member.filename!r}")
        archive.extractall(target)


def project_files() -> list[str]:
    listed = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True).stdout.decode("utf-8")
    files = sorted(name for name in listed.split("\0") if name and any(
        name == item or (item.endswith("/") and name.startswith(item)) for item in INCLUDE))
    missing = [item for item in INCLUDE if not any(name == item or name.startswith(item) for name in files)]
    if missing:
        raise SystemExit(f"Package inputs missing from the checkout: {missing}")
    return files


def stage(target: Path) -> None:
    for name in project_files():
        data = (ROOT / name).read_bytes()
        if name.endswith(".cmd"):
            # cmd.exe needs CRLF to find GOTO labels reliably, whatever the checkout used.
            data = data.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    print(f"Python {PYTHON_VERSION} (embeddable, amd64)", flush=True)
    python = target / "python"
    safe_extract(download(PYTHON_URL, PYTHON_SHA256), python)
    if not all((python / name).is_file() for name in (PYTHON_PTH, PYTHON_STDLIB, "python.exe", "pythonw.exe", "LICENSE.txt")):
        raise SystemExit("The embeddable Python layout changed; review PYTHON_PTH before packaging")
    (python / PYTHON_PTH).write_text(PTH_TEXT, encoding="ascii", newline="")

    print(f"PyYAML {PYYAML_VERSION}", flush=True)
    safe_extract(download(PYYAML_URL, PYYAML_SHA256), target / "vendor")

    install_runtime.install("windows-amd64", target)
    if not install_runtime.installed("windows-amd64", target):
        raise SystemExit("The Windows runtimes are incomplete")


def write_zip(source: Path, path: Path) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file in sorted(item for item in source.rglob("*") if item.is_file()):
            archive.write(file, f"{FOLDER}/{file.relative_to(source).as_posix()}")


def changes() -> str:
    """This version's entries in CHANGELOG.md; a release without them is refused."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    heading = f"## {__version__}\n"
    if heading not in text:
        raise SystemExit(f"CHANGELOG.md has no section for {__version__}")
    section = text.split(heading, 1)[1].split("\n## ", 1)[0].strip()
    if not section:
        raise SystemExit(f"The CHANGELOG.md section for {__version__} is empty")
    return section


def release_notes(zip_name: str, digest: str) -> str:
    return f"""## 本版更新

{changes()}

## 安装

**Windows**（x64 Windows 11 24H2 / 25H2，装好最新更新；不需要另外安装 Python）

1. 下载 `{zip_name}`。
2. 右键 zip →“属性”→ 勾选“解除锁定”→“确定”，避免每次启动都弹出安全提示。
3. 解压到固定位置，双击 `{FOLDER}\\Start-Windows.cmd`。浏览器会打开面板，面板在后台运行，没有命令行窗口。
4. 想要每次登录后自动在后台运行，在面板底部打开“登录后在后台运行”。

升级时先在面板点“退出面板”，再把新版本解压到同一位置覆盖；设置、登录状态、快捷方式和登录启动项都会保留。

**Linux**（Ubuntu 22.04 / 24.04，x86-64）

```sh
sudo apt install -y git
git clone https://github.com/Shermanxwz/Rule-proxy-Web.git
cd Rule-proxy-Web
sh start-linux.sh
```

第一次运行会安装 bubblewrap 和 PyYAML、在需要时加载 AppArmor 策略（会请求 sudo 密码），并下载固定版本的 Mihomo，之后直接打开面板。请用登录桌面的普通用户运行。

## Windows 包内的组件

| 组件 | 版本 | 下载校验 |
|---|---|---|
| Python（嵌入式版） | {PYTHON_VERSION} | python.org 公布的 SHA-256 |
| PyYAML | {PYYAML_VERSION} | PyPI 公布的 SHA-256 |
| Mihomo | {install_runtime.MIHOMO_VERSION} | GitHub 发布文件的 SHA-256 |
| Microsoft MXC（本项目固定微软源码的构建） | {install_runtime.MXC_VERSION} | 归档及可执行文件的固定 SHA-256 |

`{zip_name}` 的 SHA-256：`{digest}`

Windows 隔离使用指定代理端口的原生策略。已验证系统、普通用户、浏览器和故障范围见包内 `WINDOWS-VALIDATION.md`。不支持 Windows 10，不保证任意软件兼容；不兼容时拒绝启动，不退回直连。
"""


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    output = Path(argv[0]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    zip_name = f"RuleProxy-Web-{__version__}-windows-x64.zip"
    with tempfile.TemporaryDirectory(prefix="ruleproxy-package-") as temp:
        staged = Path(temp) / FOLDER
        stage(staged)
        write_zip(staged, output / zip_name)
    digest = hashlib.sha256((output / zip_name).read_bytes()).hexdigest()
    (output / "SHA256SUMS.txt").write_text(f"{digest}  {zip_name}\n", encoding="utf-8")
    (output / "release-notes.md").write_text(release_notes(zip_name, digest), encoding="utf-8")
    print(f"Built {output / zip_name} ({(output / zip_name).stat().st_size // (1024 * 1024)} MB), SHA-256 {digest}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
