"""Opt-in disposable Windows 11 Stage0. No product/privacy qualification.

Only closed projections leave the guest. Media, credentials, guest disk,
raw reports, serial output and screenshots are never publication artifacts.
The existing pinned media helpers are reused, not the old experiment matrix.
"""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import zipfile

ROOT = Path(__file__).resolve().parents[1]
CHECKS = ('request_aware_base_container', 'actual_base_container', 'fresh_actor',
          'native_identity', 'normal_exit', 'no_harness_error')
BOOLS = ('ordinary_account', 'servicing_verified', 'stage0_passed', 'harness_completed')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
MAX_REPORT = 16384


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def project_stage0(raw):
    """No recursive pass-through: a malicious path/nonce/error cannot escape."""
    checks = raw.get('checks', {})
    result = {'schema_version': 1, 'stage': 'win11-genuine-ordinary-psec-stage0',
              'network_tested': False, 'product_acceptance': False, 'privacy_qualified': False,
              'psec_cleanup_independently_verified': False,
              'checks': {key: checks.get(key) is True for key in CHECKS},
              'request_supported': checks.get('request_aware_base_container') is True,
              'stage0_passed': raw.get('stage0_passed') is True and all(checks.get(k) is True for k in CHECKS)}
    for key in ('actor_sha256',):
        value = raw.get(key)
        if isinstance(value, str) and DIGEST.fullmatch(value):
            result[key] = value
    if type(raw.get('executor_exit_code')) is int and -0x80000000 <= raw['executor_exit_code'] <= 0xffffffff:
        result['executor_exit_code'] = raw['executor_exit_code']
    return result


def validate_guest(value, actor_digest):
    if not isinstance(value, dict) or len(json.dumps(value)) > MAX_REPORT:
        raise ValueError('bounded result required')
    result = project_stage0(value)
    result.update({key: value.get(key) is True for key in BOOLS})
    result['stage0_passed'] = (value.get('stage0_passed') is True
                               and all(result['checks'].values())
                               and all(result[k] for k in ('ordinary_account', 'servicing_verified', 'harness_completed')))
    result['os'] = {'build': 26200, 'ubr': 9711, 'product_type': 'WinNT', 'architecture': 'AMD64'}
    if value.get('os') != result['os'] or value.get('actor_sha256') != actor_digest:
        raise ValueError('guest provenance differs')
    return result


def guest(args):
    proof = load('identity_stage0_guest', ROOT / '.github/windows_identity_proof.py')
    output = args.output
    result = project_stage0({})
    try:
        config = json.loads((ROOT / 'stage0-input.json').read_text())
        work = ROOT / 'private-stage0'
        options = SimpleNamespace(disposable_ci=True, approved_security_test=True,
            executor=ROOT / 'g/wxc-exec.exe', manifest=ROOT / 'g/build-manifest.json',
            actor=ROOT / 'actor.exe', actor_sha256=config['actor_sha256'], work=work, report=work / 'report.json')
        code = proof.controller(options)
        raw = proof.smoke.read(options.report)
        result = project_stage0(raw)
        result['harness_completed'] = True
        # A successful controller validates its observed current ordinary token;
        # the PowerShell entrypoint separately verifies the real RuleProxyCI user.
        identity = raw.get('controller_identity', {})
        result['ordinary_account'] = (identity.get('elevated') is False and identity.get('appcontainer') is False
                                      and identity.get('cid') == 1)
    except Exception:
        code = 1
        result['harness_completed'] = False
    output.write_text(json.dumps(result, sort_keys=True), encoding='ascii')
    return code


def payload(package, actor, actor_digest, bundle, destination):
    if not DIGEST.fullmatch(actor_digest) or hashlib.sha256(actor.read_bytes()).hexdigest() != actor_digest:
        raise ValueError('actor pin mismatch')
    sys.path.insert(0, str(ROOT))
    import install_runtime
    data = install_runtime._g_bundle_bytes(bundle, allow_env_cache=False)
    # Validate the pinned archive before copying only its known members.
    with tempfile.TemporaryDirectory(prefix='identity-bundle-') as temporary:
        install_runtime._extract_g_bundle(data, Path(temporary))
        with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(package, 'runtime.zip')
            archive.write(actor, 'actor.exe')
            archive.writestr('stage0-input.json', json.dumps({'actor_sha256': actor_digest}))
            for name in ('wxc-exec.exe', 'build-manifest.json', 'MXC-LICENSE.md'):
                archive.write(Path(temporary) / name, 'g/' + name)
            for name in ('.github/windows_identity_win11_stage0.py', '.github/windows_identity_proof.py',
                         '.github/windows_psec_compartment_smoke.py', 'ruleproxy/windows_runtime_pins.py'):
                archive.write(ROOT / name, name)
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def ordinary_beacon(path):
    if not path.exists(): return False
    with path.open('rb') as stream:
        stream.seek(0, os.SEEK_END)
        stream.seek(max(0, stream.tell() - 65536))
        return b'RPBEACON identity-ordinary-ready' in stream.read(65536)


def interrupted(signum, frame):
    raise InterruptedError('owned lab cancelled')


def remaining_budget(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError('work budget exhausted; reserve cleanup')
    return min(maximum, remaining)


def run_bounded(command, deadline, maximum, **kwargs):
    return subprocess.run(command, timeout=remaining_budget(deadline, maximum), **kwargs)


def download_updates_bounded(media, directory, deadline):
    directory.mkdir()
    for item in media.UPDATE_PACKAGES:
        path = directory / item['filename']
        run_bounded(['curl', '--fail', '--location', '--silent', '--show-error', '--retry', '3',
                     '--proto', '=https', '--proto-redir', '=https', '--connect-timeout', '30',
                     '--max-time', str(max(1, int(remaining_budget(deadline, 1800)))),
                     '--output', str(path), item['url']], deadline, 1800, check=True)
        if path.stat().st_size != item['bytes'] or media.digest(path) != item['sha256']:
            raise ValueError('pinned MSU provenance failed')


def cleanup_owned(media, work, qemu=None, tpm=None, qmp=None, server=None, thread=None):
    cleanup_ok = True
    for action in ((lambda: qmp.close()) if qmp else None,
                   lambda: media.stop_owned(qemu), lambda: media.stop_owned(tpm),
                   (lambda: server.shutdown()) if server else None,
                   (lambda: server.server_close()) if server else None):
        if action:
            try: action()
            except Exception: cleanup_ok = False
    if thread: thread.join(timeout=5)
    live = any(p is not None and p.poll() is None for p in (qemu, tpm))
    live = live or (thread is not None and thread.is_alive())
    if not live:
        try: shutil.rmtree(work)
        except OSError: cleanup_ok = False
    return cleanup_ok and not live and not work.exists()


def host(args):
    if sys.platform != 'linux' or not args.approved_disposable_vm:
        raise PermissionError('explicit disposable VM approval required')
    media = load('identity_win11_media', ROOT / '.github/windows_vm_test.py')
    # Verify the established runtime package layout using the existing validator.
    native = load('identity_win11_package', ROOT / '.github/windows_proxifyre_vm.py')
    native.verify_package(args.package, args.package_sha256)
    if (media.UPDATE_BUILD, media.UPDATE_UBR) != (26200, 9711):
        raise ValueError('servicing baseline changed')
    args.output.mkdir(parents=True, exist_ok=False)
    public = {'schema_version': 1, 'stage': 'win11-genuine-ordinary-psec-stage0',
              'status': 'blocked', 'stage0_passed': False, 'product_acceptance': False,
              'privacy_qualified': False, 'network_tested': False, 'vm_destroyed': False}
    qemu = tpm = server = thread = qmp = None
    work = Path(tempfile.mkdtemp(prefix='identity-win11-private-')); work.chmod(0o700)
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGALRM)}
    deadline = time.monotonic() + args.timeout_seconds - 120
    # Also bound non-subprocess work (hashes/ZIPs/filesystem) and helper calls.
    signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds - 120)
    source = os.environ.get('GITHUB_SHA', '')
    if re.fullmatch(r'[0-9a-f]{40}', source): public['source_commit'] = source
    public['iso_sha256'] = media.ISO_SHA256
    public['actor_sha256'] = args.actor_sha256
    phase = 'preflight'
    try:
        media.require_kvm()
        if shutil.disk_usage(work).free < media.MIN_FREE_BYTES:
            raise RuntimeError('insufficient disposable storage; no host cleanup performed')
        for binary in ('qemu-system-x86_64', 'qemu-img', 'swtpm', 'xorriso', 'curl'):
            if not shutil.which(binary): raise RuntimeError('missing VM tool')
        extractor = shutil.which('7zz') or shutil.which('7z')
        if not extractor: raise RuntimeError('missing UDF extractor')
        phase = 'verified_media_download'
        updates = work / 'updates'; download_updates_bounded(media, updates, deadline)
        iso = work / 'official.iso'
        run_bounded(['curl', '--fail', '--location', '--retry', '3', '--proto', '=https',
            '--proto-redir', '=https', '--connect-timeout', '30', '--max-time', '1200',
            '--output', str(iso), media.ISO_URL], deadline, 1220, check=True)
        if iso.stat().st_size != media.ISO_BYTES or media.digest(iso) != media.ISO_SHA256:
            raise ValueError('ISO provenance failed')
        raw = work / 'private-reports'; raw.mkdir()
        package = work / 'payload.zip'
        package_digest = payload(args.package, args.actor, args.actor_sha256, args.bundle, package)
        server = media.GuestServer(package, raw, updates=updates)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        tree = work / 'iso-tree'; tree.mkdir()
        run_bounded([extractor, 'x', '-tudf', '-y', '-o' + str(tree), str(iso)], deadline, 900, check=True,
                       stdout=subprocess.DEVNULL)
        boot = media.validate_install_tree(tree)
        config = {'host_url': f'http://10.0.2.2:{server.server_address[1]}/{server.capability}',
                  'payload_sha256': package_digest, 'package_sha256': args.package_sha256,
                  'actor_sha256': args.actor_sha256, 'update_build': 26200, 'update_ubr': 9711}
        media.prepare_seed(tree, secrets.token_hex(16) + 'Ci!9', config, updates=updates)
        # Keep original setup as an explicit protected-ACL/update helper. Replace
        # only disposable seed entrypoints, never repository files or main.
        shutil.copyfile(tree / 'ruleproxy-vm-setup.ps1', tree / 'identity-base-setup.ps1')
        for role in ('setup', 'run'):
            shutil.copyfile(ROOT / f'.github/windows-identity-win11-stage0-{role}.ps1', tree / f'ruleproxy-vm-{role}.ps1')
        unattended = work / 'unattended.iso'
        run_bounded(['xorriso', '-as', 'mkisofs', '-iso-level', '3', '-J', '-joliet-long', '-R',
            '-V', 'RULEPROXY_CI', '-b', 'boot/etfsboot.com', '-no-emul-boot', '-boot-load-size', '8',
            '-boot-info-table', '-eltorito-alt-boot', '-e', boot, '-no-emul-boot', '-o', str(unattended), str(tree)],
            deadline, 300, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        shutil.rmtree(tree); iso.unlink()
        disk = work / 'windows.qcow2'; nvram = work / 'OVMF_VARS.fd'
        firmware = Path('/usr/share/OVMF'); code = firmware / 'OVMF_CODE_4M.ms.fd'
        shutil.copyfile(firmware / 'OVMF_VARS_4M.ms.fd', nvram)
        run_bounded(['qemu-img', 'create', '-f', 'qcow2', str(disk), '80G'], deadline, 30, check=True, stdout=subprocess.DEVNULL)
        state = work / 'tpm-state'; state.mkdir()
        tpm_socket, qmp_socket, serial = work / 'tpm.sock', work / 'qmp.sock', work / 'serial.log'
        phase = 'guest_installation_and_servicing'
        tpm = subprocess.Popen(['swtpm', 'socket', '--tpm2', '--tpmstate', f'dir={state}', '--ctrl', f'type=unixio,path={tpm_socket}'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = time.monotonic() + 20
        while not tpm_socket.exists():
            if tpm.poll() is not None or time.monotonic() > ready: raise RuntimeError('TPM failed')
            time.sleep(.1)
        qemu = subprocess.Popen(['qemu-system-x86_64', '-machine', 'q35,accel=kvm,smm=on', '-cpu',
            'host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on', '-m', '6144', '-smp', '4',
            '-global', 'driver=cfi.pflash01,property=secure,value=on',
            '-drive', f'if=pflash,format=raw,readonly=on,file={code}', '-drive', f'if=pflash,format=raw,file={nvram}',
            '-drive', f'if=none,id=system,file={disk},format=qcow2,discard=unmap', '-device', 'ide-hd,drive=system,bus=ide.0,bootindex=1',
            '-drive', f'if=none,id=install,file={unattended},media=cdrom,readonly=on', '-device', 'ide-cd,drive=install,bus=ide.1,bootindex=2',
            '-netdev', 'user,id=vmnet', '-device', f'e1000,netdev=vmnet,mac={media.VM_NIC_MAC}',
            '-chardev', f'socket,id=tpm,path={tpm_socket}', '-tpmdev', 'emulator,id=tpmdev,chardev=tpm', '-device', 'tpm-tis,tpmdev=tpmdev',
            '-device', 'qemu-xhci', '-device', 'usb-tablet', '-vga', 'std', '-display', 'none', '-monitor', 'none',
            '-serial', f'file:{serial}', '-qmp', f'unix:{qmp_socket},server=on,wait=off'],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = time.monotonic() + 20
        while qmp is None:
            if qemu.poll() is not None or time.monotonic() > ready: raise RuntimeError('QEMU failed')
            try: qmp = media.Qmp(qmp_socket)
            except OSError: time.sleep(.1)
        if qmp.execute('query-kvm').get('enabled') is not True: raise RuntimeError('KVM required')
        qmp.execute('set_link', {'name': 'vmnet', 'up': False})
        if boot.endswith('/efisys.bin'):
            for _ in range(8):
                qmp.execute('send-key', {'keys': [{'type': 'qcode', 'data': 'ret'}], 'hold-time': 100}); time.sleep(2)
        plugged = False
        while not server.received.wait(2):
            if qemu.poll() is not None or time.monotonic() > deadline: raise RuntimeError('guest deadline or exit')
            if not plugged and ordinary_beacon(serial):
                qmp.execute('set_link', {'name': 'vmnet', 'up': True}); plugged = True
        public.update(validate_guest(server.result, args.actor_sha256))
        public['status'] = 'passed' if public['stage0_passed'] else 'observed_failure'
        phase = 'stage0_completed'
    except (Exception, KeyboardInterrupt):
        public['status'] = 'blocked'
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        # A second cancellation must not interrupt owned-process cleanup.
        for sig in old_handlers: signal.signal(sig, signal.SIG_IGN)
        public['vm_destroyed'] = cleanup_owned(media, work, qemu, tpm, qmp, server, thread)
        if not public['vm_destroyed']: public['status'] = 'cleanup_unconfirmed'; public['stage0_passed'] = False
        public['last_phase'] = phase
        (args.output / 'public-report.json').write_text(json.dumps(public, indent=2) + '\n', encoding='ascii')
        for sig, handler in old_handlers.items(): signal.signal(sig, handler)
    return 0 if public['stage0_passed'] and public['vm_destroyed'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guest', action='store_true'); parser.add_argument('--approved-disposable-vm', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    for name in ('package', 'actor', 'bundle'): parser.add_argument('--' + name, type=Path)
    for name in ('package-sha256', 'actor-sha256'): parser.add_argument('--' + name)
    parser.add_argument('--timeout-seconds', type=int, default=6600)
    args = parser.parse_args(argv)
    if args.guest: return guest(args)
    if not all((args.package, args.actor, args.bundle, args.package_sha256, args.actor_sha256)) or args.timeout_seconds != 6600:
        parser.error('fixed host inputs and 6600-second budget required')
    return host(args)

if __name__ == '__main__': raise SystemExit(main())
