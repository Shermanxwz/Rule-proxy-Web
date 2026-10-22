"""Opt-in local AC IPC guard; default entry is read-only preflight.

This is a separate local contract, not CI/VM qualification or proxy acceptance.
The explicit runtime flag records caller intent; it does not grant permission.
Run only after the device owner approves the exact local plan. No automatic
retry, elevation, network policy changes, or uncertain-resource removal.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_PUBLIC = 4096
MAX_PRIVATE = 128 * 1024
MAX_STAGE = 128 * 1024 * 1024
JOB_LIST = 0x2000D  # PROC_THREAD_ATTRIBUTE_JOB_LIST, creation-time assignment.
# WinSDK WinBase.h: ProcThreadAttributeJobList=13, INPUT=0x00020000.
# https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
SOURCES = (
    '.github/windows_identity_proxy_pipe_ac_local.py',
    '.github/windows_identity_proxy_pipe_ac_guest.py',
    '.github/windows_identity_proxy_pipe_probe.py',
    '.github/windows_identity_ordinary_launcher.py',
    '.github/windows_identity_pipe_probe.py',
    '.github/windows_identity_proof.py',
    '.github/windows_psec_compartment_smoke.py',
    'ruleproxy/windows_app_process.py',
)
NATIVE_SOURCES = {
    'actorSourceSha256': '.github/native/windows_identity_proxy_pipe_actor.cpp',
    'identitySourceSha256': '.github/native/windows_identity_actor.cpp',
    'coreSha256': '.github/native/windows_identity_proxy_bridge_core.hpp',
}


def _load_guest():
    path = Path(__file__).with_name('windows_identity_proxy_pipe_ac_guest.py')
    spec = importlib.util.spec_from_file_location('local_ac_guest_helpers', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guest = _load_guest()
controller = guest.controller_module()
launcher = controller.launcher


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def bounded(path, limit):
    path = launcher.checked_path(path)
    return launcher.read_private_bytes(path, limit)


def source_snapshot(root=ROOT):
    root = launcher.checked_path(root, is_file=False)
    files = {}
    for name in SOURCES:
        path = launcher.checked_path(root / name, inside=root)
        raw = bounded(path, 256 * 1024)
        files[name] = raw
    hashes = {name: sha(raw) for name, raw in files.items()}
    return files, hashes, sha(encode(hashes))


class LocalNativeAPI(launcher.NativeAPI):
    """Reuse the owner lifecycle; only the guard's worker creation is special.

    The Job is passed in JOB_LIST at CreateProcessW, never HANDLE_LIST. The
    worker cannot keep the guard's last Job handle alive. No post-create
    assignment fallback exists: launch_owned's assign step verifies membership.
    """
    def __init__(self):
        super().__init__()
        self.worker_job = None
        self.worker_create_attempted = False
        self.atomic_job_requested = False
        self.worker_job_name = None
        self.worker_sid = None

    def create_job(self):
        if self.worker_job is not None:
            raise launcher.GateFailure('single_local_worker_only')
        if (self.worker_job_name is None or self.worker_sid is None
                or not self.worker_job_name.startswith('Local\\RuleProxy.LocalGuard.')
                or len(self.worker_job_name) != len('Local\\RuleProxy.LocalGuard.') + 32
                or not controller.nonce(self.worker_job_name.rsplit('.', 1)[-1])):
            raise launcher.GateFailure('exact_named_guard_job_required')
        pointer = self.private_descriptor(self.worker_sid, job=True)
        try:
            security = launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes), pointer, False)
            C.set_last_error(0)
            self.worker_job = self.k.CreateJobObjectW(C.byref(security), self.worker_job_name)
            code = C.get_last_error()
            self.check(self.worker_job, 'CreateJobObjectW(local_guard)')
            if code == 183:
                raise launcher.GateFailure('fresh_guard_job_required')
            limits = self.proc._JobExtendedLimitInfo()
            limits.BasicLimitInformation.LimitFlags = launcher.KILL_ON_JOB_CLOSE
            self.check(self.k.SetInformationJobObject(self.worker_job, 9, C.byref(limits), C.sizeof(limits)),
                       'SetInformationJobObject(local_guard)')
            actual = self.proc._JobExtendedLimitInfo()
            self.check(self.k.QueryInformationJobObject(self.worker_job, 9, C.byref(actual), C.sizeof(actual), None),
                       'QueryInformationJobObject(local_guard)')
            if actual.BasicLimitInformation.LimitFlags != launcher.KILL_ON_JOB_CLOSE:
                raise launcher.GateFailure('job_not_kill_on_close_non_breakaway')
            self.k.SetHandleInformation.argtypes = [C.c_void_p, C.c_uint32, C.c_uint32]
            self.k.SetHandleInformation.restype = C.c_int
            self.check(self.k.SetHandleInformation(self.worker_job, 1, 0), 'SetHandleInformation(job_noninherit)')
        except BaseException:
            owned, self.worker_job = self.worker_job, None
            if owned:
                self.close(owned)
            raise
        finally:
            if self.k.LocalFree(pointer):
                # No worker exists yet; retain the job rather than lose uncertain ownership.
                launcher._RETAINED_SCOPED_OWNERS.append((self, self.worker_job))
                raise launcher.GateFailure('job_descriptor_close_uncertain')
        return self.worker_job

    def create_suspended(self, info, command, work, stdio, token):
        if token is not None or self.worker_job is None or self.worker_create_attempted:
            raise launcher.GateFailure('atomic_current_worker_required')
        self.worker_create_attempted = True
        size = C.c_size_t()
        self.k.InitializeProcThreadAttributeList(None, 2, 0, C.byref(size))
        if not 1 <= size.value <= 65536:
            raise launcher.GateFailure('invalid_process_attribute_size')
        attrs = C.create_string_buffer(size.value)
        self.check(self.k.InitializeProcThreadAttributeList(attrs, 2, 0, C.byref(size)),
                   'InitializeProcThreadAttributeList')
        try:
            handles = (C.c_void_p * 3)(*stdio)
            jobs = (C.c_void_p * 1)(self.worker_job)
            for kind, values in ((0x20002, handles), (JOB_LIST, jobs)):
                self.check(self.k.UpdateProcThreadAttribute(attrs, 0, kind, values,
                           C.sizeof(values), None, None), 'UpdateProcThreadAttribute(local_worker)')
            startup = self.proc._StartupInfoEx()
            startup.StartupInfo.cb = C.sizeof(startup)
            startup.StartupInfo.dwFlags = 0x100
            startup.StartupInfo.hStdInput, startup.StartupInfo.hStdOutput, startup.StartupInfo.hStdError = stdio
            startup.lpAttributeList = C.cast(attrs, C.c_void_p)
            flags = (self.proc._CREATE_SUSPENDED | self.proc._CREATE_UNICODE_ENVIRONMENT
                     | self.proc._EXTENDED_STARTUPINFO_PRESENT | 0x08000000)
            self.atomic_job_requested = True
            self.check(self.k.CreateProcessW(command[0], C.create_unicode_buffer(subprocess.list2cmdline(command)),
                None, None, True, flags, C.create_unicode_buffer(self.environment(work)), str(work),
                C.byref(startup), C.byref(info)), 'CreateProcessW(atomic_job_worker)')
        finally:
            self.k.DeleteProcThreadAttributeList(attrs)

    def assign_job(self, job, process):
        if job != self.worker_job or not self.atomic_job_requested:
            raise launcher.GateFailure('creation_time_job_required')
        self.verify_job(job, process)

    def device_sha256(self):
        size = C.c_uint32(256)
        buffer = C.create_unicode_buffer(size.value)
        self.k.GetComputerNameW.argtypes = [C.c_wchar_p, C.POINTER(C.c_uint32)]
        self.k.GetComputerNameW.restype = C.c_int
        self.check(self.k.GetComputerNameW(buffer, C.byref(size)), 'GetComputerNameW')
        return sha(buffer.value.casefold().encode('utf-16-le'))

    def windows_x64(self):
        process_machine, native_machine = C.c_ushort(), C.c_ushort()
        self.k.IsWow64Process2.argtypes = [C.c_void_p, C.POINTER(C.c_ushort), C.POINTER(C.c_ushort)]
        self.k.IsWow64Process2.restype = C.c_int
        self.check(self.k.IsWow64Process2(self.k.GetCurrentProcess(), C.byref(process_machine), C.byref(native_machine)),
                   'IsWow64Process2')
        return C.sizeof(C.c_void_p) == 8 and process_machine.value == 0 and native_machine.value == 0x8664

    def private_descriptor(self, sid, *, job=False):
        if launcher.SID_PATTERN.fullmatch(sid) is None:
            raise launcher.GateFailure('private_directory_identity')
        pointer = C.c_void_p()
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [C.c_wchar_p, C.c_uint32,
            C.POINTER(C.c_void_p), C.POINTER(C.c_uint32)]
        self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = C.c_int
        self.k.LocalFree.argtypes = [C.c_void_p]
        self.k.LocalFree.restype = C.c_void_p
        sddl = ('D:P(A;;GA;;;SY)(A;;GA;;;' + sid + ')' if job else
                'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + sid + ')')
        self.check(self.a.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, C.byref(pointer), None),
            'ConvertStringSecurityDescriptorToSecurityDescriptorW')
        return pointer.value

    def private_directory(self, path, sid):
        """Create fresh directory with protected user/SYSTEM DACL atomically."""
        pointer = self.private_descriptor(sid)
        self.k.CreateDirectoryW.argtypes = [C.c_wchar_p, C.c_void_p]
        self.k.CreateDirectoryW.restype = C.c_int
        self.k.LocalFree.argtypes = [C.c_void_p]
        self.k.LocalFree.restype = C.c_void_p
        sddl = 'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + sid + ')'
        try:
            security = launcher.SecurityAttributes(C.sizeof(launcher.SecurityAttributes), pointer, False)
            self.check(self.k.CreateDirectoryW(str(path), C.byref(security)), 'CreateDirectoryW(private_local_root)')
            self.verify_private_directory(path, sddl)
        finally:
            owned, pointer = pointer, None
            if owned and self.k.LocalFree(owned):
                raise launcher.GateFailure('private_directory_descriptor_close_uncertain')

    def verify_private_directory(self, path, expected_sddl):
        self.a.GetFileSecurityW.argtypes = [C.c_wchar_p, C.c_uint32, C.c_void_p, C.c_uint32, C.POINTER(C.c_uint32)]
        self.a.GetFileSecurityW.restype = C.c_int
        size = C.c_uint32()
        C.set_last_error(0)
        if self.a.GetFileSecurityW(str(path), 4, None, 0, C.byref(size)) or C.get_last_error() != 122 or not 20 <= size.value <= 65536:
            raise launcher.GateFailure('private_directory_acl_size')
        raw = C.create_string_buffer(size.value)
        self.check(self.a.GetFileSecurityW(str(path), 4, raw, len(raw), C.byref(size)), 'GetFileSecurityW(private_local_root)')
        text = C.c_wchar_p()
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.argtypes = [C.c_void_p, C.c_uint32,
            C.c_uint32, C.POINTER(C.c_wchar_p), C.POINTER(C.c_uint32)]
        self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW.restype = C.c_int
        self.check(self.a.ConvertSecurityDescriptorToStringSecurityDescriptorW(raw, 1, 4, C.byref(text), None),
                   'ConvertSecurityDescriptorToStringSecurityDescriptorW')
        try:
            if text.value != expected_sddl:
                raise launcher.GateFailure('private_directory_acl_mismatch')
        finally:
            owned, text = C.cast(text, C.c_void_p).value, None
            if owned and self.k.LocalFree(owned):
                raise launcher.GateFailure('private_directory_acl_readback_close_uncertain')


def ordinary(api):
    token = api.current_token()
    try:
        parent = api.identity(token)
        compartment = api.compartment()
        if not launcher.token_is_ordinary(parent) or type(compartment) is not int or compartment != 1:
            raise launcher.GateFailure('current_ordinary_required')
        return parent
    finally:
        api.close(token)


def valid_plan(value, *, device, actor_hash, manifest_hash, source_hash):
    keys = {'schema_version', 'scope', 'device_sha256', 'actor_sha256', 'manifest_sha256',
            'source_sha256', 'recovery_reference', 'residue_review_acknowledged'}
    if (type(value) is not dict or set(value) != keys or type(value['schema_version']) is not int
            or value['schema_version'] != 1 or value['scope'] != 'one-local-zero-cap-pair-no-network-v1'
            or value['residue_review_acknowledged'] is not True):
        raise ValueError('recovery_plan')
    for key, expected in (('device_sha256', device), ('actor_sha256', actor_hash),
                          ('manifest_sha256', manifest_hash), ('source_sha256', source_hash)):
        if not controller.digest(value[key]) or value[key] != expected:
            raise ValueError('recovery_plan')
    reference = value['recovery_reference']
    if type(reference) is not str or not 1 <= len(reference) <= 512 or any(ord(x) < 32 for x in reference):
        raise ValueError('recovery_plan')
    # This is a device-bound human attestation, never snapshot verification or permission.
    return value


def admitted_inputs(actor, manifest, actor_hash, manifest_hash, work_parent, *, root=ROOT):
    files, hashes, source_hash = source_snapshot(root)
    actor, _ = controller.verify_ac_artifact(actor, manifest, manifest_hash, actor_hash)
    manifest = launcher.checked_path(manifest)
    value = guest.decode(bounded(manifest, 8192))
    for key, name in NATIVE_SOURCES.items():
        path = launcher.checked_path(root / name, inside=launcher.checked_path(root, is_file=False))
        if sha(bounded(path, 256 * 1024)) != value[key]:
            raise ValueError('native_source_binding')
    parent = launcher.checked_path(work_parent, is_file=False)
    if parent != root and root not in parent.parents:
        raise ValueError('work_parent_outside_checkout')
    # Two actor copies (staging + pair), fixed sources/reports and a fresh reserve.
    size = sum(len(raw) for raw in files.values()) + 2 * actor.stat().st_size + 8192 + 3 * MAX_PRIVATE + 1048576
    if size > MAX_STAGE or shutil.disk_usage(parent).free < size:
        raise ValueError('capacity')
    return files, hashes, source_hash, actor, manifest, parent


def blank(mode):
    return dict(schema_version=1, stage='local-proxy-pipe-ac', profile='local-guard-worker-zero-cap-pipe-v1',
        mode=mode, status='inconclusive', failure=None,
        checks={key: False for key in ('windows_x64', 'ordinary', 'sources', 'artifacts', 'capacity', 'recovery_attested')},
        source_sha256=None, device_bound=False, actor_sha256=None, manifest_sha256=None,
        run_nonce_sha256=None, case_nonce_sha256=None, recovery_plan_sha256=None,
        python_version=platform.python_version(),
        clock_contract=dict(total_seconds=120, worker_reserve_seconds=5, guard_work_reserve_seconds=3,
                            frequency='same-actual-qpc', renewal=False),
        cleanup=dict(guard_job_verified=False, worker_held_verified=False, worker_exit_verified=False,
                     outer_cleanup_verified=False, tree_retained=False, recovery_required=False),
        ipc=None, local_ipc_qualified=False, synthetic_http_only=True,
        network_tested=False, proxy_tested=False, product_acceptance=False)


def validate_public(value):
    template = blank(value.get('mode') if type(value) is dict else None)
    if type(value) is not dict or set(value) != set(template):
        raise ValueError('local_public')
    for key in ('schema_version', 'stage', 'profile', 'synthetic_http_only', 'network_tested', 'proxy_tested', 'product_acceptance'):
        if type(value[key]) is not type(template[key]) or value[key] != template[key]:
            raise ValueError('local_public')
    if encode(value['clock_contract']) != encode(template['clock_contract']):
        raise ValueError('local_public')
    if value['mode'] not in ('preflight', 'runtime') or value['status'] not in ('ready', 'inconclusive', 'passed'):
        raise ValueError('local_public')
    if value['failure'] not in (None, 'platform', 'identity', 'inputs', 'recovery_plan', 'deadline', 'staging', 'worker', 'report', 'cleanup'):
        raise ValueError('local_public')
    for name in ('checks', 'cleanup'):
        if (type(value[name]) is not dict or set(value[name]) != set(template[name])
                or any(type(v) is not bool for v in value[name].values())):
            raise ValueError('local_public')
    if type(value['device_bound']) is not bool:
        raise ValueError('local_public')
    for key in ('source_sha256', 'actor_sha256', 'manifest_sha256',
                'run_nonce_sha256', 'case_nonce_sha256', 'recovery_plan_sha256'):
        if value[key] is not None and not controller.digest(value[key]):
            raise ValueError('local_public')
    for check, commitments in (('sources', ('source_sha256',)),
            ('artifacts', ('actor_sha256', 'manifest_sha256')), ('recovery_attested', ('recovery_plan_sha256',))):
        if value['checks'][check] and any(value[k] is None for k in commitments):
            raise ValueError('local_public')
    if value['checks']['recovery_attested'] and not value['device_bound']:
        raise ValueError('local_public')
    if (type(value['python_version']) is not str or len(value['python_version']) > 32
            or any(x not in '0123456789.' for x in value['python_version'])
            or type(value['local_ipc_qualified']) is not bool):
        raise ValueError('local_public')
    if value['ipc'] is not None:
        if any(value[k] is None for k in ('run_nonce_sha256', 'case_nonce_sha256', 'actor_sha256', 'manifest_sha256')):
            raise ValueError('local_public')
        ipc = value['ipc']
        if type(ipc) is not dict or set(ipc) != {'config_commitments', 'result'}:
            raise ValueError('local_public')
        # Only closed public data is nested; raw config/nonces never leave private reports.
        result = ipc['result']
        commitments = {k: result[k] for k in ('run_nonce_sha256', 'case_nonce_sha256', 'actor_sha256', 'manifest_sha256')}
        if ipc['config_commitments'] != commitments:
            raise ValueError('local_public')
        if any(commitments[k] != value[k] for k in commitments):
            raise ValueError('local_public')
        # Revalidate its full closed public schema without revealing the private nonces.
        safe_config = dict(enabled=True, run_nonce='0'*32, case_nonce='0'*32,
                           actor_sha256=value['actor_sha256'], manifest_sha256=value['manifest_sha256'])
        adjusted = guest.decode(encode(result))
        adjusted.update(run_nonce_sha256=sha(b'0'*32), case_nonce_sha256=sha(b'0'*32))
        guest.validate_public(adjusted, safe_config)
    passed = (value['mode'] == 'runtime' and all(value['checks'].values()) and value['failure'] is None
        and all(value['cleanup'][k] for k in ('guard_job_verified', 'worker_held_verified', 'worker_exit_verified', 'outer_cleanup_verified'))
        and value['cleanup']['tree_retained']
        and not value['cleanup']['recovery_required'] and value['ipc'] is not None
        and value['ipc']['result']['ac_pipe_passed'] is True)
    if value['local_ipc_qualified'] != passed or (value['status'] == 'passed') != passed:
        raise ValueError('local_public')
    if value['status'] == 'ready' and (value['mode'] != 'preflight' or not all(value['checks'].values()) or value['failure'] is not None):
        raise ValueError('local_public')
    if len(encode(value)) > MAX_PUBLIC:
        raise ValueError('local_public_bound')
    return value


def preflight(actor=None, manifest=None, actor_hash=None, manifest_hash=None, work_parent=None, recovery_plan=None, *, api=None, root=ROOT):
    value = blank('preflight')
    phase = 'platform'
    try:
        if os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise ValueError('platform')
        api = LocalNativeAPI() if api is None else api
        if not api.windows_x64():
            raise ValueError('platform')
        value['checks']['windows_x64'] = True
        phase = 'identity'; ordinary(api)
        device = api.device_sha256()
        if not controller.digest(device):
            raise ValueError('device_observation')
        value['checks']['ordinary'] = True
        phase = 'inputs'
        _, _, source_hash = source_snapshot(root)
        value['source_sha256'] = source_hash; value['checks']['sources'] = True
        _, _, source_hash, _, _, _ = admitted_inputs(actor, manifest, actor_hash, manifest_hash, work_parent, root=root)
        if source_hash != value['source_sha256']:
            raise ValueError('sources_changed')
        value.update(actor_sha256=actor_hash, manifest_sha256=manifest_hash)
        value['checks'].update(artifacts=True, capacity=True)
        phase = 'recovery_plan'; raw = bounded(recovery_plan, 8192)
        valid_plan(guest.decode(raw), device=device, actor_hash=actor_hash, manifest_hash=manifest_hash, source_hash=source_hash)
        value['device_bound'] = True
        value['checks']['recovery_attested'] = True; value['recovery_plan_sha256'] = sha(raw)
        value['status'] = 'ready'
    except Exception:
        value['failure'] = phase
    return validate_public(value)


def fixed_worker_command(python, stage):
    return [str(python), '-I', '-S', '-B', str(stage / SOURCES[0]), '--owned-worker',
            '--worker-config', str(stage / 'worker-config.json')]


def worker_expected(config, parent, launch):
    return dict(schema_version=1, stage='local-proxy-pipe-ac-worker', worker_pid=launch['child_pid'],
        worker_sid=parent['sid'], worker_session=parent['session_id'],
        root_deadline_qpc=config['root_deadline_qpc'], worker_deadline_qpc=config['worker_deadline_qpc'],
        qpc_frequency=config['qpc_frequency'], config_sha256=sha(encode(config)))


def bind_worker(report, config, parent, launch):
    if (launch.get('started') is not True or launch.get('resumed') is not True
            or launch.get('native_identity_verified_before_resume') is not True
            or launch.get('cleanup', {}).get('process_exit_confirmed') is not True
            or type(launch.get('child_pid')) is not int or launch['child_pid'] <= 0):
        raise ValueError('worker_not_held')
    expected = worker_expected(config, parent, launch)
    if type(report) is not dict or set(report) != set(expected) | {'result'}:
        raise ValueError('worker_report')
    for key, item in expected.items():
        if type(report[key]) is not type(item) or report[key] != item:
            raise ValueError('worker_binding')
    return guest.validate_public(report['result'], config['pair'])


def run_local(actor, manifest, actor_hash, manifest_hash, work_parent, recovery_plan, *, approved=False, api=None, root=ROOT, ids=secrets.token_hex):
    value = blank('runtime'); phase = 'platform'; budget = None; stage = None; launched = False
    try:
        if not approved or os.name != 'nt' or C.sizeof(C.c_void_p) != 8:
            raise ValueError('platform')
        api = LocalNativeAPI() if api is None else api
        # Actual clock is sampled once before all preflight/staging/setup. No new epoch below.
        phase = 'deadline'
        frequency = api.qpc_frequency(); start = api.qpc()
        if type(frequency) is not int or not 1 <= frequency <= 1000000000 or type(start) is not int or start < 0:
            raise ValueError('deadline')
        deadline = start + 120 * frequency
        budget = launcher.QpcBudget(api, deadline, frequency)
        check = preflight(actor, manifest, actor_hash, manifest_hash, work_parent, recovery_plan, api=api, root=root)
        for key in ('checks', 'source_sha256', 'device_bound', 'actor_sha256', 'manifest_sha256', 'recovery_plan_sha256'):
            value[key] = check[key]
        if check['status'] != 'ready':
            phase = check['failure']; raise ValueError('preflight')
        phase = 'deadline'; budget.require_ms(budget.cutoff(45))
        phase = 'inputs'
        files, hashes, source_hash, actor, manifest, parentpath = admitted_inputs(actor, manifest, actor_hash, manifest_hash, work_parent, root=root)
        if source_hash != value['source_sha256']:
            raise ValueError('sources_changed')
        phase = 'identity'; parent = ordinary(api)
        device = api.device_sha256()
        run_nonce, case_nonce = ids(16), ids(16)
        config_pair = guest.valid_config(dict(enabled=True, run_nonce=run_nonce, case_nonce=case_nonce,
            actor_sha256=actor_hash, manifest_sha256=manifest_hash))
        api.worker_job_name = 'Local\\RuleProxy.LocalGuard.' + run_nonce
        api.worker_sid = parent['sid']
        value.update(run_nonce_sha256=sha(run_nonce.encode('ascii')), case_nonce_sha256=sha(case_nonce.encode('ascii')))
        stage = parentpath / ('local-ac-' + run_nonce)
        if stage.exists() or stage.is_symlink():
            raise ValueError('fresh_stage')
        phase = 'staging'; budget.require_ms(budget.cutoff(45))
        value['cleanup']['tree_retained'] = True
        api.private_directory(stage, parent['sid'])
        launcher.checked_path(stage, inside=parentpath, is_file=False)
        for name, raw in files.items():
            budget.require_ms(budget.cutoff(40))
            path = stage / name; path.parent.mkdir(parents=True, exist_ok=True)
            launcher.write_private_bytes(path, raw)
            if sha(bounded(path, 256 * 1024)) != hashes[name]:
                raise ValueError('staged_source')
        bridge = stage / 'bridge'; bridge.mkdir()
        launcher.write_private_bytes(bridge / actor.name, bounded(actor, guest.MAX_ACTOR))
        launcher.write_private_bytes(bridge / manifest.name, bounded(manifest, 8192))
        controller.verify_ac_artifact(bridge / actor.name, bridge / manifest.name, manifest_hash, actor_hash)
        config = dict(schema_version=1, stage='local-proxy-pipe-ac-worker-input', pair=config_pair,
            root_deadline_qpc=deadline, worker_deadline_qpc=deadline - 5 * frequency,
            qpc_frequency=frequency, source_hashes=hashes, source_sha256=source_hash,
            device_sha256=device, recovery_plan_sha256=value['recovery_plan_sha256'],
            guard_job_name=api.worker_job_name)
        launcher.write_private_bytes(stage / 'worker-config.json', encode(config))
        # Private ownership/config journals remain for exact recovery when cleanup is uncertain.
        plan_raw = bounded(recovery_plan, 8192)
        if sha(plan_raw) != value['recovery_plan_sha256']:
            raise ValueError('recovery_plan_changed')
        launcher.write_private_bytes(stage / 'recovery-plan.json', plan_raw)
        work = stage / 'guard'; work.mkdir(); (work / 'temp').mkdir()
        runtime = launcher.checked_path(sys.base_prefix, is_file=False)
        python = launcher.checked_path(sys.executable, inside=runtime)
        if python.name.casefold() != 'python.exe':
            raise ValueError('python')
        phase = 'deadline'; budget.require_ms(budget.cutoff(40))
        phase = 'worker'; launched = True
        launch = launcher.launch_owned(api, fixed_worker_command(python, stage), work, parent, parent,
            qpc_budget=budget, work_cutoff=budget.cutoff(3), cleanup_cutoff=deadline)
        cleanup = value['cleanup']
        cleanup['guard_job_verified'] = api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True
        cleanup['worker_held_verified'] = launch.get('native_identity_verified_before_resume') is True
        cleanup['worker_exit_verified'] = launch.get('cleanup', {}).get('process_exit_confirmed') is True
        cleanup['outer_cleanup_verified'] = guest.cleanup_verified(launch)
        phase = 'report'
        if not cleanup['worker_exit_verified'] or launch.get('started') is not True:
            raise ValueError('unknown_worker')
        report = guest.decode(bounded(stage / 'worker-report.json', MAX_PRIVATE))
        result = bind_worker(report, config, parent, launch)
        value['ipc'] = dict(config_commitments={k: result[k] for k in
            ('run_nonce_sha256', 'case_nonce_sha256', 'actor_sha256', 'manifest_sha256')}, result=result)
        clean = (all(cleanup[k] for k in ('guard_job_verified', 'worker_held_verified', 'worker_exit_verified', 'outer_cleanup_verified'))
                 and all(result['facts'][k] for k in ('acl_removed_verified', 'profile_deleted_verified', 'outer_cleanup_verified')))
        cleanup['recovery_required'] = not clean
        phase = 'worker'
        if ('error' in launch or launch.get('timed_out') is True or launch.get('exit_code') != 0 or not result['ac_pipe_passed']):
            raise ValueError('worker_failed')
        phase = 'cleanup'
        if not clean:
            raise ValueError('cleanup')
        phase = 'deadline'; budget.require_ms(deadline)
        value['local_ipc_qualified'] = True; value['status'] = 'passed'
    except BaseException:
        value['failure'] = phase
        if launched and value['ipc'] is None:
            value['cleanup']['recovery_required'] = True
        if phase == 'staging' and value['cleanup']['tree_retained']:
            value['cleanup']['recovery_required'] = True
    return validate_public(value)


def worker(config_path):
    """Internal child, admitted by guard's held token/image and atomic outer Job.

    Not an independently authorized runtime command. Require inherited Job
    membership and use only the exact fresh staged config and closed sources.
    """
    path = launcher.checked_path(config_path, inside=ROOT)
    if path != ROOT / 'worker-config.json':
        raise ValueError('worker_config')
    raw = bounded(path, MAX_PRIVATE); config = guest.decode(raw)
    keys = {'schema_version', 'stage', 'pair', 'root_deadline_qpc', 'worker_deadline_qpc',
            'qpc_frequency', 'source_hashes', 'source_sha256', 'device_sha256', 'recovery_plan_sha256', 'guard_job_name'}
    if (type(config) is not dict or set(config) != keys or type(config['schema_version']) is not int
            or config['schema_version'] != 1 or config['stage'] != 'local-proxy-pipe-ac-worker-input'):
        raise ValueError('worker_config')
    guest.valid_config(config['pair'])
    run_nonce = config['pair']['run_nonce']
    if ROOT.name != 'local-ac-' + run_nonce or config['guard_job_name'] != 'Local\\RuleProxy.LocalGuard.' + run_nonce:
        raise ValueError('fresh_local_stage_required')
    frequency = config['qpc_frequency']; deadline = config['root_deadline_qpc']; child_deadline = config['worker_deadline_qpc']
    if (type(frequency) is not int or type(deadline) is not int or type(child_deadline) is not int
            or child_deadline != deadline - 5 * frequency):
        raise ValueError('worker_clock')
    api = launcher.NativeAPI(); budget = launcher.QpcBudget(api, deadline, frequency)
    budget.require_ms(budget.cutoff(35))
    _, hashes, source_hash = source_snapshot()
    if config['source_hashes'] != hashes or config['source_sha256'] != source_hash:
        raise ValueError('worker_sources')
    parent = ordinary(api)
    device = LocalNativeAPI.device_sha256(api)
    if config['device_sha256'] != device:
        raise ValueError('worker_device')
    plan_raw = bounded(ROOT / 'recovery-plan.json', 8192)
    if sha(plan_raw) != config['recovery_plan_sha256']:
        raise ValueError('worker_recovery_plan')
    valid_plan(guest.decode(plan_raw), device=device, actor_hash=config['pair']['actor_sha256'],
               manifest_hash=config['pair']['manifest_sha256'], source_hash=source_hash)
    LocalNativeAPI.verify_private_directory(api, ROOT,
        'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + parent['sid'] + ')')
    verify_guard_job(api, config['guard_job_name'])
    budget.require_ms(budget.cutoff(35))
    result = guest.execute(config['pair'], child_deadline, frequency, root=ROOT, api=api)
    budget.require_ms(budget.cutoff(3))
    report = worker_expected(config, parent, {'child_pid': os.getpid()})
    report['result'] = result
    launcher.write_private_bytes(ROOT / 'worker-report.json', encode(report))
    budget.require_ms(budget.cutoff(3))
    return 0 if result['ac_pipe_passed'] else 1


def verify_guard_job(api, name):
    """Query the exact fresh guardian, closing its temporary handle before setup.

    This handle is opened QUERY-only and never inherited. If the guardian dies
    during this observation, closing our last handle triggers kill-on-close;
    no profile or AppContainer ACL has been created at this point.
    """
    api.k.OpenJobObjectW.argtypes = [C.c_uint32, C.c_int, C.c_wchar_p]
    api.k.OpenJobObjectW.restype = C.c_void_p
    job = api.k.OpenJobObjectW(4, False, name)
    api.check(job, 'OpenJobObjectW(exact_guard_query)')
    try:
        in_job = C.c_int()
        api.check(api.k.IsProcessInJob(api.k.GetCurrentProcess(), job, C.byref(in_job)), 'IsProcessInJob(exact_guard)')
        actual = api.proc._JobExtendedLimitInfo()
        api.check(api.k.QueryInformationJobObject(job, 9, C.byref(actual), C.sizeof(actual), None),
                  'QueryInformationJobObject(exact_guard)')
        if in_job.value != 1 or actual.BasicLimitInformation.LimitFlags != launcher.KILL_ON_JOB_CLOSE:
            raise ValueError('exact_guard_job_required')
    finally:
        api.close(job)  # One attempt; unknown close prevents all security setup.


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local-pair', action='store_true')
    parser.add_argument('--approved-local-security-test', action='store_true')
    parser.add_argument('--actor'); parser.add_argument('--manifest')
    parser.add_argument('--expected-actor-sha256'); parser.add_argument('--expected-manifest-sha256')
    parser.add_argument('--work-parent', default=str(ROOT))
    parser.add_argument('--recovery-plan')
    parser.add_argument('--owned-worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--worker-config', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.owned_worker:
        try:
            if args.run_local_pair or args.approved_local_security_test or args.actor or args.manifest or args.recovery_plan:
                raise ValueError('worker_arguments')
            return worker(args.worker_config)
        except Exception:
            return 1
    if args.worker_config:
        return 1
    inputs = (args.actor, args.manifest, args.expected_actor_sha256, args.expected_manifest_sha256,
              Path(args.work_parent), args.recovery_plan)
    value = run_local(*inputs, approved=args.approved_local_security_test) if args.run_local_pair else preflight(*inputs)
    sys.stdout.write(encode(value).decode('ascii'))
    return 0 if value['status'] in ('ready', 'passed') else 1


if __name__ == '__main__':
    raise SystemExit(main())
