"""Build a deterministic Windows online-setup source ZIP without downloading assets."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location('ruleproxy_online_offline_builder', ROOT / '.github/build_windows_package.py')
offline = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(offline)

EXTRA_SOURCES = ('install_runtime.py', '.github/build_windows_package.py')
ALLOWED_SUFFIXES = {'.py', '.cmd', '.ps1', '.md', '.txt', '.html', '.css', '.js', '.xml'}


def project_files() -> list[str]:
    files = sorted(set(offline.project_files()) | set(EXTRA_SOURCES))
    if len({name.casefold() for name in files}) != len(files):
        raise ValueError('Online package source paths collide')
    for name in files:
        relative = PurePosixPath(name)
        if (relative.is_absolute() or '..' in relative.parts or '\\' in name or ':' in name
                or relative.name == 'package-manifest.json'
                or '__pycache__' in relative.parts
                or any(part.startswith('.') for part in relative.parts) and name != EXTRA_SOURCES[1]
                or relative.suffix.lower() not in ALLOWED_SUFFIXES
                and name not in ('LICENSE', *offline.BUNDLED_LICENSE_SOURCES)):
            raise ValueError('Ineligible online package source: ' + name)
        path = ROOT
        for part in relative.parts:
            path = path / part
            if path.is_symlink():
                raise ValueError('Online package source must not be a symlink: ' + name)
        if not path.is_file():
            raise ValueError('Required online package source is missing: ' + name)
    return files


def install_instructions() -> str:
    return (
        f'RuleProxy-Web {offline.__version__}：Windows 11 x64 联网安装（预发布）\n\n'
        '请先完整解压到可写目录，再用日常普通账户双击 Setup-Windows.cmd。\n'
        '首次安装需要联网，会下载并校验官方固定 SHA 的 Python、Mihomo、ProxiFyre 和安装依赖；'
        '无需预装全局 Python。本包仅含源码和引导脚本，不是离线安装包。\n'
        '依赖准备完成后会弹出 UAC 管理员授权。Web 面板和所选应用仍使用普通用户权限。\n'
        '如果提示返回码 3010，请重启 Windows，再运行 Setup-Windows.cmd 继续安装。\n'
        '安装后默认在后台运行。日常双击桌面 RuleProxy Web 快捷方式，或安装目录的 Start-Windows.lnk，'
        '无需命令行窗口，也不会自动打开浏览器。手动访问 http://127.0.0.1:8879，在 Web 面板中自行导入 YAML。'
        '登录自启动可在面板开启，同样静默运行；后台错误见 %LOCALAPPDATA%\\RuleProxyWebSafe\\panel.log。\n'
        '临时下载故障会有界重试；失败后保留 .windows-cache，从同一目录重新运行 Setup-Windows.cmd 可复用校验过的依赖。'
        '固定许可证原文已随包附带，安装不为许可证访问 raw.githubusercontent.com。'
        '本包不含用户配置、节点凭据或第三方二进制。\n\n'
        '原生 Windows 11 的完整验收尚未通过；已观察到的部分功能不能替代完整 GUI、启动和卸载重装验收。'
        '发布为预发布候选，不宣称 Linux 等价隔离。具体能力和限制请阅读随包 README.md。\n'
    )


def stage(target: Path) -> dict:
    target = Path(target)
    if target.exists() and (target.is_symlink() or not target.is_dir() or any(target.iterdir())):
        raise ValueError('Online package staging requires an empty directory')
    files = project_files()
    target.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name in files:
        data = (ROOT / name).read_bytes()
        if name.lower().endswith('.cmd'):
            data = data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    instructions = install_instructions().replace('\n', '\r\n').encode('utf-8')
    (target / 'INSTALL-WINDOWS.txt').write_bytes(instructions)
    metadata = {'schema_version': 1, 'version': offline.__version__, 'platform': 'windows-amd64',
                'kind': 'online-source-bootstrap', 'third_party_binaries_bundled': False,
                'offline_package_manifest_included': False,
                'hash_scope': 'Shipped source bytes; CMD line endings normalized to CRLF. Metadata excludes itself.',
                'files': hashes,
                'generated_files': {'INSTALL-WINDOWS.txt': hashlib.sha256(instructions).hexdigest()}}
    (target / 'release-source.json').write_bytes((json.dumps(metadata, sort_keys=True, indent=2) + '\n').encode('utf-8'))
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_dir', type=Path)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    name = f'RuleProxy-Web-{offline.__version__}-windows-x64-online-setup.zip'
    with tempfile.TemporaryDirectory(prefix='ruleproxy-online-') as directory:
        source = Path(directory) / offline.FOLDER
        stage(source)
        offline.write_zip(source, output / name)
    digest = offline.pins.digest(output / name)
    (output / 'SHA256SUMS.txt').write_bytes(f'{digest}  {name}\n'.encode('ascii'))
    print(f'Built {output / name}: SHA-256 {digest}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
