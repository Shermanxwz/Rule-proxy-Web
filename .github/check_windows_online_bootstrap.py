"""Exercise the published source-bootstrap path without elevation or installation."""
from __future__ import annotations

import hashlib
import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location('online_bootstrap_builder', ROOT / '.github/build_windows_online_package.py')
online = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(online)

# Install the guard before importing any shipped code. Redirected requests use
# the same opener, so a license URL cannot silently fall back to the raw host.
CHILD = '''import runpy, sys, urllib.parse, urllib.request
for stream in (sys.stdout, sys.stderr):
    stream.reconfigure(encoding="utf-8", errors="replace")
class RejectRaw(urllib.request.BaseHandler):
    handler_order = 0
    def default_open(self, request):
        if urllib.parse.urlsplit(request.full_url).hostname == "raw.githubusercontent.com":
            raise AssertionError("raw.githubusercontent.com is blocked by the bootstrap smoke test")
urllib.request.install_opener(urllib.request.build_opener(RejectRaw()))
try:
    urllib.request.urlopen("https://raw.githubusercontent.com/smoke-test-blocked")
except AssertionError:
    pass
else:
    raise AssertionError("Raw-host block did not take effect")
print("Embedded bootstrap interpreter:", sys.executable, sys.version.split()[0], flush=True)
sys.argv = sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''


def validate_payload(target: Path, cache: Path) -> int:
    pins = online.offline.pins
    manifest = json.loads((target / 'package-manifest.json').read_text(encoding='utf-8'))
    files = manifest['files']
    actual = {path.relative_to(target).as_posix() for path in target.rglob('*') if path.is_file()}
    if actual != set(files) | {'package-manifest.json'}:
        raise AssertionError('Staged payload differs from its complete manifest')
    for name, expected in files.items():
        if hashlib.sha256((target / name).read_bytes()).hexdigest() != expected:
            raise AssertionError('Staged payload hash differs: ' + name)
    for key, name in (('mihomo_license', 'bin/windows-amd64/MIHOMO-LICENSE'),
                      ('proxifyre_license', 'licenses/PROXIFYRE-LICENSE'),
                      ('ndisapi_license', 'licenses/NDISAPI-LICENSE')):
        if pins.digest(target / name) != pins.ASSETS[key]['sha256']:
            raise AssertionError('Copied license differs from its upstream pin: ' + name)
    binaries = {asset['name'] for key, asset in pins.ASSETS.items() if not key.endswith('_license')}
    if {path.name for path in cache.iterdir()} != binaries:
        raise AssertionError('Fresh download cache must contain exactly the pinned binary assets')
    return len(files)


def validate_silent_launcher(target: Path, root: Path) -> None:
    from ruleproxy import shortcuts

    destination, installed = root / 'Start-Windows.lnk', root / '最终安装 root'
    subprocess.run([str(target / 'python/python.exe'), '-I', '-S', '-B',
                    str(target / 'Run-RuleProxy.py'), '--create-panel-shortcut', str(destination),
                    '--shortcut-root', str(installed)], check=True, timeout=75)
    reader = '''
namespace RuleProxyLinksSmoke {
    public static class Reader {
        public static string[] Read(string path) {
            var link = (RuleProxyLinks.IShellLinkW)new RuleProxyLinks.ShellLink();
            try {
                ((System.Runtime.InteropServices.ComTypes.IPersistFile)link).Load(path, 0);
                var target = new System.Text.StringBuilder(32768);
                var arguments = new System.Text.StringBuilder(32768);
                var directory = new System.Text.StringBuilder(32768);
                link.GetPath(target, target.Capacity, System.IntPtr.Zero, 0);
                link.GetArguments(arguments, arguments.Capacity);
                link.GetWorkingDirectory(directory, directory.Capacity);
                return new string[] {target.ToString(), arguments.ToString(), directory.ToString()};
            } finally {System.Runtime.InteropServices.Marshal.ReleaseComObject(link);}
        }
    }
}
'''
    script = ("$ErrorActionPreference = 'Stop'; $env:PSModulePath = Join-Path $PSHOME 'Modules'; "
              "Add-Type -TypeDefinition $env:RULEPROXY_SMOKE_LINK_TYPES; "
              "foreach ($value in ([RuleProxyLinksSmoke.Reader]::Read($env:RULEPROXY_SMOKE_LINK))) "
              "{ Write-Output ([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($value))) }")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            env={**os.environ, 'RULEPROXY_SMOKE_LINK': str(destination),
                                 'RULEPROXY_SMOKE_LINK_TYPES': shortcuts._SHELL_LINK_TYPES + reader},
                            check=True, capture_output=True, text=True, timeout=60)
    values = [base64.b64decode(line, validate=True).decode('utf-8') for line in result.stdout.split()]
    expected = [str(installed / 'python/pythonw.exe'), subprocess.list2cmdline(
        ['-I', '-S', str(installed / 'Run-RuleProxy.py'), '--no-browser']), str(installed)]
    if len(values) != 3 or any(os.path.normcase(a) != os.path.normcase(b) for a, b in zip(values, expected)):
        raise AssertionError('Silent launcher target, arguments or working directory differ')
    if installed.exists():
        raise AssertionError('Creating the launcher must not create or launch the final installation')


def main() -> int:
    if os.name != 'nt' or sys.maxsize <= 2**32:
        raise SystemExit('This smoke requires native Windows x64; it does not install or qualify the product.')
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding='utf-8', errors='replace')
    with tempfile.TemporaryDirectory(prefix='ruleproxy-online-smoke-') as directory:
        root = Path(directory)
        archives = root / 'archives'
        online.main([str(archives)])
        archive = next(archives.glob('*.zip'))
        extracted = root / '应用 在线安装 测试'
        online.offline.safe_extract(archive.read_bytes(), extracted)
        source = extracted / online.offline.FOLDER
        if (source / 'package-manifest.json').exists():
            raise AssertionError('Online ZIP unexpectedly contains an offline manifest')
        cache = source / '.windows-cache/assets'
        cache.mkdir(parents=True)
        python_asset = online.offline.pins.ASSETS['python']
        bootstrap = source / '.windows-cache/bootstrap-python'
        online.offline.safe_extract(online.offline.pins.fetch_asset(python_asset, cache), bootstrap)
        wrapper = root / 'run_with_raw_blocked.py'
        wrapper.write_text(CHILD, encoding='ascii')
        target = source / '.windows-cache/offline-package'
        subprocess.run([str(bootstrap / 'python.exe'), '-I', '-S', '-B', str(wrapper),
                        str(source / '.github/build_windows_package.py'), str(target),
                        '--stage-only', '--asset-cache', str(cache)], check=True, timeout=480)
        count = validate_payload(target, cache)
        validate_silent_launcher(target, root)
        print(f'Online bootstrap passed: embedded Python, Unicode/spaces path, fresh official downloads, '
              f'raw host blocked, all 3 license pins, {count} payload hashes and silent launcher verified. '
              'No elevation or system installation was performed.', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
