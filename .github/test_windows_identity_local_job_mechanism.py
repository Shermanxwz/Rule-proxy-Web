"""Opt-in local JOB_LIST observation using a fixed ordinary Python exit worker.

Default entry refuses execution. --run-local-job-mechanism records explicit
caller intent; run only within the device owner's approved scope. Requires an
existing repo/private (or child) parent, creates one fresh protected directory,
never changes ancestor ACLs, and retains a private ownership journal. No
AppContainer profile, native actor, or network operation is performed.
"""
from pathlib import Path
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / '.github/windows_identity_proxy_pipe_ac_local.py'
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


def run(*, work_parent=None):
    value = dict(schema_version=1, stage='local-job-list-mechanism', attempt_count=1,
        status='inconclusive', failure=None, source_sha256=hashlib.sha256(SOURCE.read_bytes()).hexdigest(),
        runner_kind='repository-wrapper', runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        python_version=sys.version.split()[0], nonce_sha256=None,
        facts={key: False for key in ('native_x64', 'current_ordinary', 'private_root_verified',
            'creation_time_job_requested', 'job_handle_noninheritable', 'held_job_before_resume',
            'held_image_before_resume', 'held_identity_before_resume', 'pre_resume_all_verified',
            'worker_resumed', 'worker_exit_zero', 'job_empty', 'job_closed',
            'process_exit_confirmed', 'core_handles_closed_once', 'cleanup_verified', 'deadline_verified')},
        journal_retained=False, security_profile_created=False, appcontainer_tested=False,
        native_actor_tested=False, network_tested=False, proxy_tested=False, product_acceptance=False)
    phase = 'work_parent'; stage = None; launch = None; api = None; budget = None; journal = None
    parent_dir = None; public_path = None; stage_owned = False
    try:
        parent_dir = admit_work_parent(work_parent)
        marker = parent_dir / 'local-job-mechanism-attempted.json'
        public_path = parent_dir / 'local-job-mechanism-public.json'
        if marker.exists() or public_path.exists():
            raise ValueError('prior_attempt_requires_review')
        phase = 'api'; api = ObservedAPI()
        phase = 'qpc'
        frequency = api.qpc_frequency(); start = api.qpc(); deadline = start + 120 * frequency
        budget = m.launcher.QpcBudget(api, deadline, frequency)
        # The exclusive attempt marker prevents accidental retry of this script.
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
        stage = parent_dir / ('job-mechanism-private-' + nonce)
        m.launcher.checked_path(parent_dir, is_file=False)
        phase = 'private_root'; budget.require_ms(budget.cutoff(30))
        if stage.exists() or stage.is_symlink():
            raise ValueError('fresh_private_root_required')
        api.private_directory(stage, parent['sid'])
        stage_owned = True
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
        if stage_owned and stage is not None and stage.is_dir():
            try:
                private = dict(initial=journal, launch=launch,
                    close_roles=[] if api is None else api.close_roles,
                    retained_core_roles=[] if api is None else list(api.live.values()))
                m.launcher.write_private_bytes(stage / 'private-result.json', m.encode(private))
                value['journal_retained'] = True
            except BaseException:
                value['failure'] = value['failure'] or 'journal'
                value['status'] = 'inconclusive'
    raw = m.encode(validate_public(value))
    # Public result contains closed fields only; journals and raw owners stay private.
    if public_path is not None and not public_path.exists():
        try:
            m.launcher.write_private_bytes(public_path, raw)
        except BaseException:
            value['failure'] = value['failure'] or 'public_output'
            value['status'] = 'inconclusive'
            raw = m.encode(validate_public(value))
    sys.stdout.write(raw.decode('ascii'))
    return 0 if value['status'] == 'passed' else 1


FACTS = ('native_x64', 'current_ordinary', 'private_root_verified',
    'creation_time_job_requested', 'job_handle_noninheritable', 'held_job_before_resume',
    'held_image_before_resume', 'held_identity_before_resume', 'pre_resume_all_verified',
    'worker_resumed', 'worker_exit_zero', 'job_empty', 'job_closed',
    'process_exit_confirmed', 'core_handles_closed_once', 'cleanup_verified', 'deadline_verified')


def admit_work_parent(path=None, *, root=ROOT):
    root = m.launcher.checked_path(root, is_file=False)
    base = m.launcher.checked_path(root / 'private', inside=root, is_file=False)
    parent = m.launcher.checked_path(base if path is None else path, inside=base, is_file=False)
    if parent != base and base not in parent.parents:
        raise ValueError('owned_private_parent_required')
    return parent


def validate_public(value):
    keys = {'schema_version', 'stage', 'attempt_count', 'status', 'failure', 'source_sha256',
        'runner_kind', 'runner_sha256', 'python_version', 'nonce_sha256', 'facts', 'journal_retained',
        'security_profile_created', 'appcontainer_tested', 'native_actor_tested', 'network_tested',
        'proxy_tested', 'product_acceptance'}
    if type(value) is not dict or set(value) != keys:
        raise ValueError('public_schema')
    if (type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['stage'] != 'local-job-list-mechanism' or type(value['attempt_count']) is not int
            or value['attempt_count'] != 1 or value['runner_kind'] != 'repository-wrapper'):
        raise ValueError('public_schema')
    if (value['status'] not in ('passed', 'inconclusive') or value['failure'] not in
            (None, 'work_parent', 'api', 'qpc', 'identity', 'private_root', 'launch', 'deadline',
             'result', 'journal', 'public_output')):
        raise ValueError('public_schema')
    if any(not m.controller.digest(value[k]) for k in ('source_sha256', 'runner_sha256')):
        raise ValueError('public_schema')
    if value['nonce_sha256'] is not None and not m.controller.digest(value['nonce_sha256']):
        raise ValueError('public_schema')
    if (type(value['python_version']) is not str or not 1 <= len(value['python_version']) <= 32
            or any(x not in '0123456789.' for x in value['python_version'])):
        raise ValueError('public_schema')
    facts = value['facts']
    if type(facts) is not dict or set(facts) != set(FACTS) or any(type(x) is not bool for x in facts.values()):
        raise ValueError('public_schema')
    if type(value['journal_retained']) is not bool or any(value[k] is not False for k in
            ('security_profile_created', 'appcontainer_tested', 'native_actor_tested', 'network_tested',
             'proxy_tested', 'product_acceptance')):
        raise ValueError('public_schema')
    passed = (all(facts.values()) and value['failure'] is None and value['journal_retained']
              and value['nonce_sha256'] is not None)
    if (value['status'] == 'passed') != passed or len(m.encode(value)) > 4096:
        raise ValueError('public_schema')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local-job-mechanism', action='store_true')
    parser.add_argument('--work-parent', type=Path,
                        help='Existing repo/private or descendant; ancestors are never modified.')
    args = parser.parse_args(argv)
    if not args.run_local_job_mechanism:
        sys.stdout.write(m.encode(dict(schema_version=1, stage='local-job-list-mechanism',
            status='not_requested', execution_requested=False, network_tested=False,
            proxy_tested=False, product_acceptance=False)).decode('ascii'))
        return 2
    return run(work_parent=args.work_parent)


if __name__ == '__main__':
    raise SystemExit(main())
