"""One approved local JOB_LIST mechanism observation; no AC/native actor/network."""
from pathlib import Path
import ctypes as C
import hashlib
import importlib.util
import json
import secrets
import sys

BASE = Path(__file__).resolve().parent
REPO = BASE / 'Rule-proxy-Web'
SOURCE = REPO / '.github/windows_identity_proxy_pipe_ac_local.py'
spec = importlib.util.spec_from_file_location('reviewed_local_job_mechanism', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class ObservedAPI(m.LocalNativeAPI):
    def __init__(self):
        super().__init__()
        self.live = {}
        self.close_roles = []
        self.noninherit = False
        self.held_job = False
        self.held_image = False
        self.held_identity = False
        self.pre_resume_verified = False

    def create_job(self):
        job = super().create_job()
        self.live[job] = 'job'
        flags = C.c_uint32()
        self.k.GetHandleInformation.argtypes = [C.c_void_p, C.POINTER(C.c_uint32)]
        self.k.GetHandleInformation.restype = C.c_int
        self.check(self.k.GetHandleInformation(job, C.byref(flags)), 'GetHandleInformation(owned_job)')
        self.noninherit = not bool(flags.value & 1)
        if not self.noninherit:
            raise m.launcher.GateFailure('owned_job_inheritable')
        return job

    def open_stdio_file(self, path, *, read=False):
        handle = super().open_stdio_file(path, read=read)
        self.live[handle] = 'stdio_' + path.name.split('.')[1]
        return handle

    def create_suspended(self, info, command, work, stdio, token):
        try:
            return super().create_suspended(info, command, work, stdio, token)
        finally:
            if info.hProcess:
                self.live[info.hProcess] = 'process'
            if info.hThread:
                self.live[info.hThread] = 'thread'

    def verify_job(self, job, process):
        super().verify_job(job, process)
        self.held_job = True

    def verify_image(self, process, expected):
        super().verify_image(process, expected)
        self.held_image = True

    def child_identity(self, process):
        identity = super().child_identity(process)
        self.held_identity = (m.launcher.token_is_ordinary(identity)
            and m.launcher.same_identity(identity, self.parent_identity))
        return identity

    def resume(self, thread):
        self.pre_resume_verified = all((self.atomic_job_requested, self.noninherit,
            self.held_job, self.held_image, self.held_identity))
        if not self.pre_resume_verified:
            raise m.launcher.GateFailure('pre_resume_observation_missing')
        return super().resume(thread)

    def close(self, handle):
        role = self.live.pop(handle, None)
        if role is not None:
            self.close_roles.append(role)
        return super().close(handle)


def run():
    value = dict(schema_version=1, stage='local-job-list-mechanism', attempt_count=1,
        status='inconclusive', failure=None, source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        python_version=sys.version.split()[0], nonce_sha256=None,
        facts={key: False for key in ('native_x64', 'current_ordinary', 'private_root_verified',
            'creation_time_job_requested', 'job_handle_noninheritable', 'held_job_before_resume',
            'held_image_before_resume', 'held_identity_before_resume', 'pre_resume_all_verified',
            'worker_resumed', 'worker_exit_zero', 'job_empty', 'job_closed',
            'process_exit_confirmed', 'core_handles_closed_once', 'cleanup_verified', 'deadline_verified')},
        journal_retained=False, security_profile_created=False, appcontainer_tested=False,
        native_actor_tested=False, network_tested=False, proxy_tested=False, product_acceptance=False)
    phase = 'api'; stage = None; launch = None; api = None; budget = None; journal = None
    try:
        api = ObservedAPI()
        phase = 'qpc'
        frequency = api.qpc_frequency(); start = api.qpc(); deadline = start + 120 * frequency
        budget = m.launcher.QpcBudget(api, deadline, frequency)
        # The exclusive attempt marker prevents accidental retry of this script.
        marker = BASE / 'local-job-mechanism-attempted.json'
        with marker.open('x', encoding='ascii') as stream:
            json.dump({'schema_version': 1, 'attempt_count': 1, 'scope': 'job-list-python-exit-only'}, stream)
        phase = 'identity'
        value['facts']['native_x64'] = api.windows_x64()
        parent = m.ordinary(api)
        value['facts']['current_ordinary'] = True
        api.parent_identity = parent
        if not value['facts']['native_x64']:
            raise ValueError('native_x64_required')
        nonce = secrets.token_hex(16)
        value['nonce_sha256'] = hashlib.sha256(nonce.encode('ascii')).hexdigest()
        stage = BASE / ('job-mechanism-private-' + nonce)
        m.launcher.checked_path(BASE, is_file=False)
        phase = 'private_root'; budget.require_ms(budget.cutoff(30))
        api.private_directory(stage, parent['sid'])
        value['facts']['private_root_verified'] = True
        (stage / 'temp').mkdir()
        api.worker_job_name = 'Local\\RuleProxy.LocalGuard.' + nonce
        api.worker_sid = parent['sid']
        python = m.launcher.checked_path(sys.executable,
            inside=m.launcher.checked_path(sys.base_prefix, is_file=False))
        if python.name.casefold() != 'python.exe':
            raise ValueError('fixed_python_required')
        command = [str(python), '-I', '-S', '-B', '-c', 'raise SystemExit(0)']
        journal = dict(schema_version=1, scope='job-list-python-exit-only', nonce=nonce,
            start_qpc=start, deadline_qpc=deadline, qpc_frequency=frequency,
            parent_identity=parent, stage=str(stage), command=command)
        m.launcher.write_private_bytes(stage / 'private-start.json', m.encode(journal))
        phase = 'launch'; budget.require_ms(budget.cutoff(20))
        launch = m.launcher.launch_owned(api, command, stage, parent, parent,
            qpc_budget=budget, work_cutoff=budget.cutoff(10), cleanup_cutoff=deadline)
        cleanup = launch.get('cleanup', {})
        facts = value['facts']
        roles = {'job', 'process', 'thread', 'stdio_stdin', 'stdio_stdout', 'stdio_stderr'}
        facts.update(creation_time_job_requested=api.atomic_job_requested,
            job_handle_noninheritable=api.noninherit, held_job_before_resume=api.held_job,
            held_image_before_resume=api.held_image, held_identity_before_resume=api.held_identity,
            pre_resume_all_verified=api.pre_resume_verified, worker_resumed=launch.get('resumed') is True,
            worker_exit_zero=type(launch.get('exit_code')) is int and launch['exit_code'] == 0,
            job_empty=cleanup.get('job_empty') is True, job_closed=cleanup.get('job_closed') is True,
            process_exit_confirmed=cleanup.get('process_exit_confirmed') is True,
            core_handles_closed_once=set(api.close_roles) == roles and len(api.close_roles) == 6 and not api.live,
            cleanup_verified=m.guest.cleanup_verified(launch))
        phase = 'deadline'; budget.require_ms(deadline); facts['deadline_verified'] = True
        phase = 'result'
        if not (all(facts.values()) and 'error' not in launch and launch.get('timed_out') is False
                and launch.get('native_identity_verified_before_resume') is True):
            raise ValueError('mechanism_incomplete')
        value['status'] = 'passed'
    except BaseException:
        value['failure'] = phase
    finally:
        if stage is not None and stage.is_dir():
            try:
                private = dict(initial=journal, launch=launch,
                    close_roles=[] if api is None else api.close_roles,
                    retained_core_roles=[] if api is None else list(api.live.values()))
                m.launcher.write_private_bytes(stage / 'private-result.json', m.encode(private))
                value['journal_retained'] = True
            except BaseException:
                value['failure'] = value['failure'] or 'journal'
                value['status'] = 'inconclusive'
    raw = m.encode(value)
    if len(raw) > 4096:
        raise ValueError('public_bound')
    # Public result contains closed fields only; journals and raw owners stay private.
    m.launcher.write_private_bytes(BASE / 'local-job-mechanism-public.json', raw)
    sys.stdout.write(raw.decode('ascii'))
    return 0 if value['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(run())
