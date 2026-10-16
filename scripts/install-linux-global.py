#!/usr/bin/python3
"""Install/remove the fixed, root-owned Linux global helper; never start capture."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
try:
    import fcntl
except ImportError:
    fcntl = None

DESTINATION = Path('/usr/local/libexec/ruleproxy-web-global')
POLICY = Path('/usr/share/polkit-1/actions/io.ruleproxy.global.policy')
RUN = Path('/run/ruleproxy-web-global')
CORE_SHA256 = '7a0d59da2e678d56c899a3db996a2ad8963286c4f3634b0451435db248f13fa1'
CORE_SIZE = 62054526
MODULES = ('__init__.py', 'config.py', 'linux_global_runtime.py')


def trusted_directory(path):
    for item in (path, *path.parents):
        value = item.lstat()
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022
                or not value.st_mode & 0o001):
            raise ValueError('Protected installation parent is replaceable: ' + str(item))


def copy_file(source, target, mode=0o644):
    if not stat.S_ISREG(source.lstat().st_mode):
        raise ValueError('Installation source must be a regular file: ' + str(source))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with source.open('rb') as reader, target.open('xb') as writer:
        shutil.copyfileobj(reader, writer)
    target.chmod(mode)


def active():
    # An extant journal can represent a crashed guard as well as a live helper.
    return RUN.exists() and any(RUN.glob('lease-*.json'))


@contextmanager
def installation_lock():
    if not RUN.exists():
        RUN.mkdir(mode=0o755);RUN.chmod(0o755)
    trusted_directory(RUN)
    with (RUN/'global.lock').open('a+b') as lock:
        (RUN/'global.lock').chmod(0o600)
        try:
            fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('Stop global capture before updating/removing its protected helper')
        yield


def _install(source, owner):
    if owner < 1 or owner > 2**31 - 1:
        raise ValueError('A non-root desktop owner UID is required')
    if active():
        raise ValueError('Stop global capture before installing/updating its protected helper')
    source = source.resolve(strict=True)
    core = source / 'bin/linux-amd64/mihomo'
    if core.stat().st_size != CORE_SIZE or hashlib.sha256(core.read_bytes()).hexdigest() != CORE_SHA256:
        raise ValueError('Pinned Linux Mihomo failed its size/SHA-256 check; run install_runtime.py first')
    # -I ignores the working directory and PYTHONPATH. Only the OS-installed
    # PyYAML or an explicitly inspected project's pure-Python vendor is copied.
    vendor = source / 'vendor/yaml'
    if not (vendor / '__init__.py').is_file():
        import yaml
        vendor = Path(yaml.__file__).parent
    if not DESTINATION.parent.exists():
        DESTINATION.parent.mkdir(parents=True, mode=0o755)
        DESTINATION.parent.chmod(0o755)
    POLICY.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    trusted_directory(DESTINATION.parent)
    trusted_directory(POLICY.parent)
    if DESTINATION.exists():
        trusted_directory(DESTINATION)
        if not (DESTINATION / 'owner.json').is_file():
            raise ValueError('Refusing to replace an unowned helper directory')
    stage = Path(tempfile.mkdtemp(prefix='.ruleproxy-global-', dir=DESTINATION.parent))
    backup = DESTINATION.with_name('.ruleproxy-global-previous')
    swapped = False
    try:
        stage.chmod(0o755)
        for name in MODULES:
            copy_file(source / 'ruleproxy' / name, stage / 'ruleproxy' / name)
        if not vendor.is_dir() or vendor.is_symlink():
            raise ValueError('PyYAML package directory is invalid')
        for item in sorted(vendor.iterdir()):
            if item.suffix == '.py':
                copy_file(item, stage / 'vendor/yaml' / item.name)
        if not (stage / 'vendor/yaml/__init__.py').is_file():
            raise ValueError('PyYAML pure-Python package is incomplete')
        copy_file(core, stage / 'mihomo', 0o755)
        entry = "import sys\nfrom pathlib import Path\nroot=Path(__file__).resolve().parent\nsys.path[:0]=[str(root),str(root/'vendor')]\nfrom ruleproxy.linux_global_runtime import helper_main\nhelper_main()\n"
        (stage / 'entry.py').write_text(entry, encoding='ascii')
        (stage / 'launch').write_text('#!/bin/sh\nexec /usr/bin/python3 -I -S /usr/local/libexec/ruleproxy-web-global/entry.py\n', encoding='ascii')
        (stage / 'launch').chmod(0o755)
        (stage / 'owner.json').write_text(json.dumps({'owner_uid': owner}) + '\n', encoding='ascii')
        (stage / 'manifest.json').write_text(json.dumps({
            'schema': 1, 'core_sha256': CORE_SHA256,
            'modules': {name: hashlib.sha256((stage / 'ruleproxy' / name).read_bytes()).hexdigest()
                        for name in MODULES}}, indent=2) + '\n', encoding='ascii')
        for item in stage.rglob('*'):
            if item.is_dir():
                item.chmod(0o755)
            elif item.is_file() and item.name not in ('mihomo', 'launch'):
                item.chmod(0o644)
        check = subprocess.run(['/usr/bin/python3', '-I', '-S', '-c',
            'import sys; sys.path[:0]=sys.argv[1:]; import ruleproxy.config, ruleproxy.linux_global_runtime, yaml',
            str(stage), str(stage / 'vendor')], cwd='/', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode:
            raise ValueError('Protected helper import validation failed')
        policy_text = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN" "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>RuleProxy Web</vendor>
  <action id="io.ruleproxy.global">
    <description>Control RuleProxy global traffic capture</description>
    <message>Authentication is required to start or recover RuleProxy global traffic capture</message>
    <defaults><allow_any>no</allow_any><allow_inactive>no</allow_inactive><allow_active>auth_admin</allow_active></defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/usr/local/libexec/ruleproxy-web-global/launch</annotate>
  </action>
</policyconfig>
'''
        if backup.exists():
            raise ValueError('Previous protected helper backup requires administrator review')
        if DESTINATION.exists():
            DESTINATION.rename(backup)
        try:
            stage.rename(DESTINATION)
            swapped = True
            temporary = POLICY.with_suffix('.new')
            with temporary.open('w', encoding='utf-8') as output:
                output.write(policy_text)
            temporary.chmod(0o644); temporary.replace(POLICY)
        except BaseException:
            if swapped:
                shutil.rmtree(DESTINATION)
            if backup.exists():
                backup.rename(DESTINATION)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print('Protected Linux global helper installed. Global capture remains stopped.')


def _remove():
    if active():
        raise ValueError('Stop/recover global capture before removing the protected helper')
    if DESTINATION.exists():
        trusted_directory(DESTINATION)
        if not (DESTINATION / 'owner.json').is_file():
            raise ValueError('Refusing to remove an unowned helper directory')
        shutil.rmtree(DESTINATION)
    if POLICY.exists():
        if POLICY.is_symlink() or POLICY.stat().st_uid != 0:
            raise ValueError('Protected policy ownership is invalid')
        POLICY.unlink()
    print('Protected Linux global helper removed. System networking was not changed.')


def install(source,owner):
    with installation_lock():
        return _install(source,owner)


def remove():
    with installation_lock():
        return _remove()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--owner', type=int)
    parser.add_argument('--remove', action='store_true')
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('Run only this installer with sudo; the panel must stay unprivileged')
    try:
        if args.remove:
            remove()
        elif args.owner is not None:
            install(args.source, args.owner)
        else:
            parser.error('--owner is required for installation')
    except (OSError, ValueError, ImportError) as error:
        print('RuleProxy global helper: ' + str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
