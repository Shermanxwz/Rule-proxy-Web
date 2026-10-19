"""Build the small, deterministic, standalone offline recovery download."""
from __future__ import annotations

import hashlib
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MEMBERS = {
    'Recover-Windows-Network.cmd': 'Recover-Windows-Network.cmd',
    'scripts/windows-network-recover.ps1': 'scripts/windows-network-recover.ps1',
    'README.md': 'docs/windows-network-recovery.md',
}


def package_bytes(root: Path = ROOT) -> bytes:
    files = {}
    for target, source in MEMBERS.items():
        path = root / source
        if path.is_symlink():
            raise ValueError('Recovery package source is a symlink')
        data = path.read_bytes().replace(b'\r\n', b'\n')
        if target.endswith('.cmd'):
            data = data.replace(b'\n', b'\r\n')
        files[target] = data
    files['SOURCE-SHA256SUMS.txt'] = ''.join(
        hashlib.sha256(data).hexdigest() + '  ' + name + '\n'
        for name, data in sorted(files.items())
    ).encode('ascii')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return output.getvalue()


def main() -> None:
    directory = ROOT / 'downloads'
    directory.mkdir(exist_ok=True)
    data = package_bytes()
    (directory / 'RuleProxy-Network-Recovery.zip').write_bytes(data)
    (directory / 'SHA256SUMS.txt').write_text(
        hashlib.sha256(data).hexdigest() + '  RuleProxy-Network-Recovery.zip\n', encoding='ascii')


if __name__ == '__main__':
    main()
