"""CI-only paused TCG optical-media regression; never boots a guest or uses KVM.

Imports production media helpers. Unit tests mock QMP and do not establish real
QEMU compatibility. Only --run-actual-qemu executes the bounded synthetic check.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
MEDIA_BYTES = 1024 * 1024
MAX_SECONDS = 45
PHASES = ('preflight', 'launch', 'connect', 'version', 'wrong_backend',
          'reclaim', 'attach', 'final_readback', 'completed')


def load_host():
    spec = importlib.util.spec_from_file_location('qmp_regression_host', ROOT / '.github/windows_identity_serviced_stage0.py')
    host = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(host)
    return host


def command(binary, work):
    return [binary, '-S', '-machine', 'q35', '-accel', 'tcg', '-m', '64',
            '-nodefaults', '-nic', 'none', '-display', 'none', '-monitor', 'none',
            '-serial', 'none', '-no-reboot',
            '-qmp', f'unix:{work / "qmp.sock"},server=on,wait=off',
            '-drive', f'if=none,id=install,file={work / "official.iso"},media=cdrom,readonly=on,format=raw',
            '-device', 'ide-cd,id=install-cd,drive=install,bus=ide.1',
            '-drive', 'if=none,id=updates,media=cdrom,readonly=on',
            '-device', 'ide-cd,id=update-cd,drive=updates,bus=ide.3']


def require_paused(qmp):
    value = qmp.execute('query-status')
    if value.get('running') is not False or value.get('status') not in ('prelaunch', 'paused'):
        raise ValueError('synthetic machine must never run')


def exercise(host, qmp, work, public, result):
    """Actual production calls; also executable with deterministic mocks."""
    require_paused(qmp)
    result['phase'] = 'version'
    version = qmp.execute('query-version').get('qemu', {})
    if any(type(version.get(key)) is not int or not 0 <= version[key] <= 65535 for key in ('major', 'minor', 'micro')):
        raise ValueError('bounded QEMU version required')
    result['qemu_version'] = {key: version[key] for key in ('major', 'minor', 'micro')}
    if version.get('major') != 8 or version.get('minor') != 2:
        raise ValueError('QEMU 8.2.x required')
    result['qemu_8_2_verified'] = True
    result['phase'] = 'wrong_backend'
    try:
        qmp.execute('blockdev-remove-medium', {'device': 'install'})
    except RuntimeError:
        diagnostic = public.get('qmp_diagnostic', {})
        kind = diagnostic.get('error_class')
        if (diagnostic.get('command') != 'blockdev-remove-medium' or
                diagnostic.get('completed') is not False or kind not in host.QMP_ERROR_CLASSES):
            raise ValueError('closed rejection not established') from None
        result['wrong_backend_error_class'] = kind
        result['wrong_backend_rejected'] = True
    else:
        raise ValueError('old backend command unexpectedly accepted')
    require_paused(qmp)
    result['phase'] = 'reclaim'
    original = work / 'official.iso'
    host.reclaim_installer(qmp, original, work, SimpleNamespace(ISO_BYTES=MEDIA_BYTES), public)
    if original.exists():
        raise ValueError('owned installer was not reclaimed')
    result['installer_reclaimed'] = True
    result['phase'] = 'attach'
    host.attach_update_medium(qmp, work / 'updates.iso', public)
    result['phase'] = 'final_readback'
    install_row = host.exact_frontend(qmp, 'install', 'install-cd')
    if install_row.get('inserted') or install_row.get('tray-open') is not True:
        raise ValueError('installer eject not established')
    update_row = host.exact_frontend(qmp, 'updates', 'update-cd')
    if update_row.get('tray-open') is not False:
        raise ValueError('update tray closure not established')
    result['installer_tray_open_verified'] = True
    result['update_tray_closed_verified'] = True
    inserted = update_row.get('inserted', {})
    if inserted.get('file') != str(work / 'updates.iso') or inserted.get('ro') is not True:
        raise ValueError('readonly update not established')
    for query in ('query-block', 'query-named-block-nodes'):
        if host.references(host.block_inventory(qmp, query), original):
            raise ValueError('installer reference remains')
    for key in ('installer_frontend_verified', 'installer_tray_opened', 'installer_medium_removed',
                'installer_backend_released', 'update_frontend_verified', 'update_medium_changed',
                'update_media_attached_readonly'):
        if public.get(key) is not True:
            raise ValueError('production media witness missing')
        result[key] = True
    require_paused(qmp)
    result['never_running_verified'] = True
    result['phase'] = 'completed'


def run_actual():
    result = {'schema': 1, 'test_kind': 'actual_paused_tcg_qmp', 'phase': 'preflight',
              'passed': False, 'runtime_acceptance': False, 'failure_class': 'none',
              'process_exited': False, 'qmp_closed': False, 'work_removed': False,
              'watchdog_expired': False, 'cleanup_error': False}
    work = None; process = None; qmp = None; watchdog = None; host = None
    public = {}
    expired = threading.Event()
    try:
        binary = shutil.which('qemu-system-x86_64')
        if os.name != 'posix' or not binary:
            raise RuntimeError('Linux system QEMU required')
        host = load_host()
        media = host.load('qmp_regression_media', ROOT / '.github/windows_vm_test.py')
        work = Path(tempfile.mkdtemp(prefix='ruleproxy-qmp-'))
        os.chmod(work, 0o700)
        for name in ('official.iso', 'updates.iso'):
            with (work / name).open('xb') as handle:
                handle.write(bytes(MEDIA_BYTES))
        result['phase'] = 'launch'
        process = subprocess.Popen(command(binary, work), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def timeout_owned():
            expired.set()
            try:
                if process.poll() is None:
                    process.kill()
            except ProcessLookupError:
                pass
        watchdog = threading.Timer(MAX_SECONDS, timeout_owned)
        watchdog.start()
        result['phase'] = 'connect'
        until = time.monotonic() + 10
        while not (work / 'qmp.sock').exists():
            if process.poll() is not None or time.monotonic() >= until:
                raise TimeoutError('QMP startup deadline')
            time.sleep(.05)
        qmp_type = host.scoped_qmp_class(media.Qmp, public)
        qmp = qmp_type.__new__(qmp_type)
        qmp.__init__(work / 'qmp.sock')
        exercise(host, qmp, work, public, result)
        result['passed'] = True
    except Exception as exc:
        kind = type(exc).__name__
        result['failure_class'] = kind if kind in ('ValueError', 'RuntimeError', 'TimeoutError', 'OSError', 'FileNotFoundError', 'BrokenPipeError', 'ConnectionResetError') else 'other'
    finally:
        diagnostic = public.get('qmp_diagnostic', {})
        commands = host.QMP_COMMANDS if host is not None else ()
        classes = host.QMP_ERROR_CLASSES if host is not None else ()
        result['qmp_diagnostic'] = {
            'command': diagnostic.get('command') if diagnostic.get('command') in commands else 'unclassified',
            'error_class': diagnostic.get('error_class') if diagnostic.get('error_class') in (*classes, 'none') else 'unclassified',
            'completed': diagnostic.get('completed') is True}
        # Independent cleanup facts. Never infer cleanup from test completion.
        if process is not None:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                result['process_exited'] = process.poll() is not None
            except Exception:
                pass
        else:
            result['process_exited'] = True
        if watchdog is not None:
            watchdog.cancel(); watchdog.join(timeout=1)
        result['watchdog_expired'] = expired.is_set()
        if qmp is not None:
            try:
                qmp.close()
            except Exception:
                result['cleanup_error'] = True
            # Base close may fail while flushing its file before socket.close.
            try:
                qmp.socket.close()
            except Exception:
                pass
            try:
                result['qmp_closed'] = qmp.socket.fileno() == -1 and (getattr(qmp, 'file', None) is None or qmp.file.closed)
            except Exception:
                pass
        else:
            result['qmp_closed'] = True  # No connection object was created.
        if work is not None and result['process_exited']:
            try:
                shutil.rmtree(work)
                result['work_removed'] = not work.exists()
            except Exception:
                pass
        elif work is None:
            result['work_removed'] = True
        result['passed'] = (result['passed'] and not result['watchdog_expired'] and not result['cleanup_error'] and
                            all(result[k] for k in ('process_exited', 'qmp_closed', 'work_removed')))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-actual-qemu', action='store_true', required=True)
    parser.parse_args()
    result = run_actual()
    print(json.dumps(result, sort_keys=True, separators=(',', ':')))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
