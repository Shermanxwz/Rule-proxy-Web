"""Internal C elevated bootstrap; no mutation before held owner admission.

The ordinary owner keeps the maintenance Job's sole persistent HANDLE. The
bootstrap's temporary self-attachment HANDLE is consumed before READY. Every
PowerShell operation is created suspended and checked before resume.
"""
from __future__ import annotations
import ctypes as C
import importlib.util
import os
from pathlib import Path
import subprocess
import sys

_spec = importlib.util.spec_from_file_location('maintenance_live', Path(__file__).with_name('windows_identity_model2_live.py'))
live = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(live)
launcher = live.launcher
helpers = live.helpers
ac = live.ac
ROOT = Path(__file__).resolve().parents[1]
MAX_COMMANDS = 16


def maintenance_identity(identity, parent):
    live.require(type(identity) is dict and set(identity) == ac.AC_IDENTITY_KEYS, 'maintenance_identity')
    live.require(identity['sid'] == parent['sid'] and identity['session_id'] == parent['session_id']
        and live.integer(identity['token_type'], 1, 1) and identity['elevated'] is True
        and identity['appcontainer'] is False and identity['appcontainer_sid'] is None
        and live.integer(identity['capability_count'], 0, 0) and identity['ui_access'] is False
        and live.integer(identity['integrity_rid'], 12288, 12288)
        and live.integer(identity['elevation_type'], 1, 2)
        and live.integer(identity['admin_attributes']) and identity['admin_attributes'] & 4
        and not identity['admin_attributes'] & 16, 'maintenance_identity')
    return True


def validate_plan(value):
    keys = {'schema_version', 'stage', 'run', 'maintenance_nonce', 'source_hashes', 'source_sha256',
        'parent_sid', 'parent_session', 'start_qpc', 'frequency', 'deadline_qpc', 'rules', 'actor_sha256'}
    live.require(type(value) is dict and set(value) == keys and live.integer(value['schema_version'], 1, 1)
        and value['stage'] == 'model2-maintenance-plan' and ac.nonce(value['run'])
        and ac.nonce(value['maintenance_nonce']) and value['maintenance_nonce'] != value['run'], 'maintenance_plan')
    live.clock_record(value['start_qpc'], value['frequency'], value['deadline_qpc'])
    live.require(type(value['parent_sid']) is str and launcher.SID_PATTERN.fullmatch(value['parent_sid'])
        and live.integer(value['parent_session']) and ac.digest(value['source_sha256'])
        and ac.digest(value['actor_sha256']), 'maintenance_plan')
    live.require(type(value['source_hashes']) is dict and set(value['source_hashes']) == set(live.SOURCES)
        and all(ac.digest(x) for x in value['source_hashes'].values())
        and live.sha(live.encode(value['source_hashes'])) == value['source_sha256'], 'maintenance_sources')
    live.require(type(value['rules']) is list and 1 <= len(value['rules']) <= 3, 'maintenance_rules')
    names = set()
    for row in value['rules']:
        live.require(type(row) is dict and type(row.get('name')) is str, 'maintenance_rule')
        suffix = row['name'].rsplit('.', 1)[-1]
        expected = live.firewall_rule(value['run'], suffix, row.get('package_sid'), row.get('program'), row.get('local_port'))
        live.validate_rule(row, expected)
        live.require(row['name'] not in names, 'maintenance_duplicate')
        names.add(row['name'])
    return value


def command(run, plan_hash, sequence, operation, rule_name=None):
    live.require(ac.nonce(run) and ac.digest(plan_hash) and live.integer(sequence, 1, MAX_COMMANDS)
        and operation in ('admit', 'read-persistent', 'read-active', 'create', 'remove', 'finish'), 'maintenance_command')
    if operation in ('admit', 'finish'):
        live.require(rule_name is None, 'maintenance_command')
    else:
        live.require(type(rule_name) is str and rule_name.startswith('RuleProxy.Model2.' + run + '.')
            and rule_name.rsplit('.', 1)[-1] in ('A-P', 'A-Q', 'B-P'), 'maintenance_command')
    live.require((sequence == 1) == (operation == 'admit'), 'maintenance_first_admit')
    return dict(schema_version=1, stage='model2-maintenance-command', run=run, plan_sha256=plan_hash,
        sequence=sequence, operation=operation, rule_name=rule_name)


def validate_command(value, *, run, plan_hash, sequence):
    live.require(type(value) is dict and set(value) == set(command(run, plan_hash, sequence,
        value.get('operation'), value.get('rule_name'))), 'maintenance_command_schema')
    expected = command(run, plan_hash, sequence, value['operation'], value['rule_name'])
    live.require(all(type(value[k]) is type(expected[k]) and value[k] == expected[k] for k in expected), 'maintenance_command_binding')
    return value


def join_maintenance_job(api, name):
    """No persistent member-owned Job HANDLE can keep kill-on-close alive."""
    api.k.OpenJobObjectW.argtypes = [C.c_uint32, C.c_int, C.c_wchar_p]
    api.k.OpenJobObjectW.restype = C.c_void_p
    job = api.k.OpenJobObjectW(4 | 1, False, name)  # QUERY + ASSIGN_PROCESS, never inherited.
    api.native.check(job, 'OpenJobObjectW(maintenance_self_attach)')
    try:
        limits = api.proc._JobExtendedLimitInfo()
        api.native.check(api.k.QueryInformationJobObject(job, 9, C.byref(limits), C.sizeof(limits), None), 'QueryInformationJobObject(maintenance)')
        live.require(limits.BasicLimitInformation.LimitFlags == launcher.KILL_ON_JOB_CLOSE, 'maintenance_job')
        api.native.check(api.k.AssignProcessToJobObject(job, api.k.GetCurrentProcess()), 'AssignProcessToJobObject(maintenance_self)')
        api.verify_job(job, api.k.GetCurrentProcess())
    finally:
        api.close(job)  # Single attempt; failure prevents READY and all mutation.


def verify_maintenance_job(api, name):
    live.local.verify_guard_job(api.native, name)


def system_powershell(api):
    block = api.native.environment(ROOT)
    values = dict(x.split('=', 1) for x in block.rstrip('\0').split('\0'))
    live.require(set(values) == {'SystemRoot', 'WINDIR', 'TEMP', 'TMP'}, 'system_environment')
    path = launcher.checked_path(Path(values['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    live.require(path.name.casefold() == 'powershell.exe', 'system_powershell')
    return path


def operation_command(image, script, input_file, output_file):
    # Process-only policy for this pinned, held operation child. It does not set
    # any persistent scope and does not override Group Policy precedence.
    return [str(image), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
        '-File', str(script), '-InputPlan', str(input_file), '-OutputReport', str(output_file)]


def run_operation(api, budget, *, plan, request, directory, parent, root=ROOT):
    """One exact operation child, with a distinct nested Job and held identity."""
    operation = request['operation']
    row = next((x for x in plan['rules'] if x['name'] == request['rule_name']), None)
    live.require(row is not None, 'maintenance_rule')
    script = launcher.checked_path(root / '.github/windows_identity_model2_firewall.ps1', inside=root)
    live.require(live.sha(live.local.bounded(script, 64 * 1024)) == plan['source_hashes']['.github/windows_identity_model2_firewall.ps1'], 'firewall_script')
    helpers.verify_copied_actor(launcher.checked_path(row['program'], inside=root), plan['actor_sha256'])
    directory.mkdir()
    (directory / 'temp').mkdir()
    input_file = directory / 'plan.json'
    output_file = directory / 'report.json'
    payload = dict(schema_version=1, stage='model2-firewall-input', run=plan['run'], operation=operation,
        frequency=budget.frequency, deadline_qpc=budget.cutoff(5), rule=row)
    raw = live.encode(payload)
    launcher.write_private_bytes(input_file, raw)
    owners = helpers.OneShotHandles(api.close)
    info = api.process_info()
    child = dict(info=info, attempted=False, assigned=False, exited=False, exit_code=None)
    job = None
    result = dict(schema_version=1, stage='model2-maintenance-operation', sequence=request['sequence'],
        operation=operation, rule_name=row['name'], held_identity_verified=False, image_verified=False,
        input_verified=False, process_exit_confirmed=False, child_exit_code=None,
        job_empty=False, handles_closed=False, operation_result=None, failure=None)
    try:
        budget.require_ms(budget.cutoff(15))
        verify_maintenance_job(api, 'Local\\RuleProxy.LocalGuard.' + plan['maintenance_nonce'])
        job = api.owned_job(owners)
        stdio = []
        for name in ('stdin', 'stdout', 'stderr'):
            handle = api.open_stdio_file(directory / name, read=name == 'stdin')
            owners.add(handle)
            stdio.append(handle)
        image = system_powershell(api)
        image_hash = live.sha(live.local.bounded(image, 8 * 1024 * 1024))
        argv = operation_command(image, script, input_file, output_file)
        child['attempted'] = True
        try:
            api.native.create_suspended(info, argv, directory, stdio, None)
        finally:
            if info.hProcess:
                owners.add(info.hProcess)
            if info.hThread:
                owners.add(info.hThread)
        api.assign_job(job, info.hProcess)
        child['assigned'] = True
        api.verify_job(job, info.hProcess)
        api.verify_image(info.hProcess, image)
        live.require(live.sha(live.local.bounded(image, 8 * 1024 * 1024)) == image_hash, 'operation_image')
        result['image_verified'] = True
        held = api.identity_owned(owners, info.hProcess)
        maintenance_identity(held, parent)
        result['held_identity_verified'] = True
        live.require(live.local.bounded(input_file, 8192) == raw, 'operation_input')
        result['input_verified'] = True
        budget.require_ms(budget.cutoff(10))
        api.resume(info.hThread)
        child['exited'] = api.wait(info.hProcess, budget.require_ms(budget.cutoff(5))) is True
        if child['exited']:
            child['exit_code'] = api.exit_code(info.hProcess)
        live.require(child['exited'], 'operation_deadline')
    except BaseException:
        result['failure'] = 'operation'
    finally:
        cutoff = live.CleanupView(budget, budget.cutoff(2))
        clean, empty, _ = ac._cleanup(api, cutoff, job, [child], owners)
        result.update(process_exit_confirmed=child['exited'], child_exit_code=child['exit_code'],
            job_empty=empty, handles_closed=owners.confirmed_closed)
        if not clean:
            result['failure'] = 'cleanup'
    if child['exited']:
        try:
            budget.require_ms(budget.cutoff(3))
            raw_result = live.local.bounded(output_file, 8192)
            observed = live.decode(raw_result)
            keys = {'schema_version', 'stage', 'operation', 'attempted', 'success', 'record', 'failure'}
            live.require(type(observed) is dict and set(observed) == keys
                and live.integer(observed['schema_version'], 1, 1)
                and observed['stage'] == 'model2-firewall-operation' and observed['operation'] == operation
                and type(observed['attempted']) is bool and type(observed['success']) is bool
                and observed['failure'] in (None, 'input', 'firewall_operation'), 'operation_report')
            if observed['record'] is not None:
                live.validate_rule(observed['record'], row)
            live.require(not observed['success'] or observed['failure'] is None and child['exit_code'] == 0,
                'operation_exit')
            live.require(not live.local.bounded(directory / 'stdout', 8192)
                and not live.local.bounded(directory / 'stderr', 8192), 'operation_console')
            result['operation_result'] = observed
        except BaseException:
            result['failure'] = result['failure'] or 'report'
    return result


def bootstrap(config_path, *, root=ROOT, api=None):
    path = launcher.checked_path(config_path, inside=root)
    live.require(path == root / 'maintenance-plan.json', 'maintenance_input')
    raw = live.local.bounded(path, live.MAX_PRIVATE)
    plan = validate_plan(live.decode(raw))
    live.require(root.name == 'local-model2-' + plan['run'], 'maintenance_stage')
    api = live.LiveNativeAPI() if api is None else api
    budget = launcher.QpcBudget(api, plan['deadline_qpc'], plan['frequency'])
    budget.require_ms(budget.cutoff(20))
    _, hashes, source_hash = live.source_snapshot(root)
    live.require(hashes == plan['source_hashes'] and source_hash == plan['source_sha256'], 'maintenance_sources')
    parent = dict(sid=plan['parent_sid'], session_id=plan['parent_session'])
    owners = helpers.OneShotHandles(api.close)
    identity = api.identity_owned(owners)
    maintenance_identity(identity, parent)
    live.local.LocalNativeAPI.verify_private_directory(api.native, root,
        'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;' + parent['sid'] + ')')
    job_name = 'Local\\RuleProxy.LocalGuard.' + plan['maintenance_nonce']
    join_maintenance_job(api, job_name)
    budget.require_ms(budget.cutoff(20))
    work = root / 'maintenance'
    ready = dict(schema_version=1, stage='model2-maintenance-ready', run=plan['run'], pid=os.getpid(),
        plan_sha256=live.sha(raw), identity=identity, job_name=job_name, joined=True,
        temporary_job_handle_closed=True, qpc=[plan['frequency'], plan['start_qpc'], plan['deadline_qpc'], budget.read()])
    launcher.write_private_bytes(work / 'ready.json', live.encode(ready))
    admitted = False
    finished = False
    sequence = 1
    try:
        while sequence <= MAX_COMMANDS:
            budget.require_ms(budget.cutoff(2))
            path = work / ('command-%04d.json' % sequence)
            if not path.exists():
                api.sleep_ms(budget.require_ms(budget.cutoff(2), 10))
                continue
            value = live.decode(live.local.bounded(path, 8192))
            validate_command(value, run=plan['run'], plan_hash=live.sha(raw), sequence=sequence)
            verify_maintenance_job(api, job_name)
            if not admitted:
                live.require(value['operation'] == 'admit', 'maintenance_no_admission')
                admitted = True
                result = dict(schema_version=1, stage='model2-maintenance-admitted', sequence=sequence,
                    run=plan['run'], plan_sha256=live.sha(raw), admitted=True)
            elif value['operation'] == 'finish':
                finished = True
                result = dict(schema_version=1, stage='model2-maintenance-finished', sequence=sequence,
                    run=plan['run'], plan_sha256=live.sha(raw), finished=True)
            else:
                live.require(value['operation'] != 'admit', 'maintenance_readmit')
                result = run_operation(api, budget, plan=plan, request=value,
                    directory=work / ('operation-%04d' % sequence), parent=parent, root=root)
            launcher.write_private_bytes(work / ('result-%04d.json' % sequence), live.encode(result))
            sequence += 1
            if finished:
                break
        live.require(finished, 'maintenance_not_finished')
    finally:
        for handle in tuple(owners.pending):
            owners.close(handle)
    return 0


class MaintenanceOwner:
    """Query/sync process HANDLE plus an owned Job supply stop authority at high IL."""
    def __init__(self, api, budget, root, plan, job, owners):
        self.api, self.budget, self.root = api, budget, root
        self.plan = validate_plan(plan)
        self.job, self.owners = job, owners
        self.plan_hash = live.sha(live.encode(plan))
        self.sequence = 0
        self.process = None
        self.created = None
        self.pid = None
        self.identity = None
        self.admitted = False
        self.attempted = False
        self.spawn_unknown = False
        self.exited = False
        self.exit_code = None

    def start(self):
        api = self.api
        budget = self.budget
        budget.require_ms(budget.cutoff(30))
        image = launcher.checked_path(sys.executable, inside=launcher.checked_path(sys.base_prefix, is_file=False))
        live.require(image.name.casefold() == 'python.exe', 'maintenance_python')
        image_hash = live.sha(live.local.bounded(image, 16 * 1024 * 1024))
        config_path = self.root / 'maintenance-plan.json'
        live.require(live.local.bounded(config_path, live.MAX_PRIVATE) == live.encode(self.plan), 'maintenance_plan_bytes')
        command_line = subprocess.list2cmdline(['-I', '-S', '-B', str(self.root / '.github/windows_identity_model2_maintenance.py'),
            '--owned-maintenance', str(config_path)])
        self.attempted = True
        self.spawn_unknown = True
        launcher.write_private_bytes(self.root / 'maintenance-launch-intent.json', live.encode(dict(
            schema_version=1, stage='maintenance-launch-intent', run=self.plan['run'],
            plan_sha256=self.plan_hash, spawn_unknown=True, deadline_qpc=self.plan['deadline_qpc'])))
        self.process = api.shell_elevated(image, command_line, self.root)
        self.owners.add(self.process)
        self.spawn_unknown = False
        budget.require_ms(budget.cutoff(25))
        self.created = api.creation_time(self.process)
        self.pid = api.process_id(self.process)
        api.verify_image(self.process, image)
        live.require(live.sha(live.local.bounded(image, 16 * 1024 * 1024)) == image_hash, 'maintenance_image')
        held = api.identity_owned(self.owners, self.process)
        parent = dict(sid=self.plan['parent_sid'], session_id=self.plan['parent_session'])
        maintenance_identity(held, parent)
        self.identity = held
        path = self.root / 'maintenance/ready.json'
        while not path.exists():
            budget.require_ms(budget.cutoff(25))
            live.require(not api.wait(self.process, 0), 'maintenance_exited_before_ready')
            api.sleep_ms(budget.require_ms(budget.cutoff(25), 10))
        ready = live.decode(live.local.bounded(path, 8192))
        keys = {'schema_version', 'stage', 'run', 'pid', 'plan_sha256', 'identity', 'job_name', 'joined',
            'temporary_job_handle_closed', 'qpc'}
        live.require(type(ready) is dict and set(ready) == keys and live.integer(ready['schema_version'], 1, 1)
            and ready['stage'] == 'model2-maintenance-ready' and ready['run'] == self.plan['run']
            and ready['pid'] == api.process_id(self.process) and type(ready['pid']) is int
            and ready['plan_sha256'] == self.plan_hash and ready['identity'] == held
            and ready['job_name'] == 'Local\\RuleProxy.LocalGuard.' + self.plan['maintenance_nonce']
            and ready['joined'] is True and ready['temporary_job_handle_closed'] is True, 'maintenance_ready')
        q = ready['qpc']
        live.require(type(q) is list and len(q) == 4 and all(live.integer(x, 0, live.MAX_SIGNED) for x in q)
            and q[:3] == [self.plan['frequency'], self.plan['start_qpc'], self.plan['deadline_qpc']]
            and q[1] <= q[3] < q[2], 'maintenance_clock')
        # The returned process HANDLE, not the report PID, is the authority.
        api.verify_job(self.job, self.process)
        live.require(not api.wait(self.process, 0) and api.creation_time(self.process) == self.created, 'maintenance_generation')
        result = self.operation('admit')
        live.require(result == dict(schema_version=1, stage='model2-maintenance-admitted', sequence=1,
            run=self.plan['run'], plan_sha256=self.plan_hash, admitted=True), 'maintenance_admission')
        self.admitted = True
        return held

    def operation(self, operation, rule_name=None):
        live.require(self.process is not None and (self.admitted or operation == 'admit'), 'maintenance_admission')
        self.budget.require_ms(self.budget.cutoff(3))
        live.require(not self.api.wait(self.process, 0) and self.api.creation_time(self.process) == self.created,
            'maintenance_generation')
        self.api.verify_job(self.job, self.process)
        self.sequence += 1
        request = command(self.plan['run'], self.plan_hash, self.sequence, operation, rule_name)
        work = self.root / 'maintenance'
        temporary = work / ('command-%04d.tmp' % self.sequence)
        path = work / ('command-%04d.json' % self.sequence)
        live.require(not path.exists() and not temporary.exists(), 'maintenance_sequence')
        launcher.write_private_bytes(temporary, live.encode(request))
        temporary.rename(path)
        output = work / ('result-%04d.json' % self.sequence)
        while not output.exists():
            self.budget.require_ms(self.budget.cutoff(2))
            if self.api.wait(self.process, 0):
                # Publication then normal exit can race the first exists check.
                live.require(output.exists(), 'maintenance_operation_exit')
                break
            self.api.sleep_ms(self.budget.require_ms(self.budget.cutoff(2), 10))
        result = live.decode(live.local.bounded(output, 16384))
        if operation not in ('admit', 'finish'):
            keys = {'schema_version', 'stage', 'sequence', 'operation', 'rule_name', 'held_identity_verified',
                'image_verified', 'input_verified', 'process_exit_confirmed', 'child_exit_code', 'job_empty',
                'handles_closed', 'operation_result', 'failure'}
            live.require(type(result) is dict and set(result) == keys and live.integer(result['schema_version'], 1, 1)
                and result['stage'] == 'model2-maintenance-operation' and result['sequence'] == self.sequence
                and result['operation'] == operation and result['rule_name'] == rule_name
                and all(result[k] is True for k in ('held_identity_verified', 'image_verified', 'input_verified',
                    'process_exit_confirmed', 'job_empty', 'handles_closed'))
                and result['child_exit_code'] == 0 and type(result['child_exit_code']) is int
                and result['failure'] is None, 'maintenance_operation_report')
            observed = result['operation_result']
            live.require(type(observed) is dict and set(observed) == {'schema_version', 'stage', 'operation',
                'attempted', 'success', 'record', 'failure'} and live.integer(observed['schema_version'], 1, 1)
                and observed['stage'] == 'model2-firewall-operation' and observed['operation'] == operation
                and observed['success'] is True and type(observed['attempted']) is bool and observed['failure'] is None,
                'maintenance_rule_report')
            row = next(x for x in self.plan['rules'] if x['name'] == rule_name)
            if observed['record'] is not None:
                live.validate_rule(observed['record'], row)
            return observed['record']
        return result

    def finish(self):
        live.require(self.admitted, 'maintenance_admission')
        expected = dict(schema_version=1, stage='model2-maintenance-finished', sequence=self.sequence + 1,
            run=self.plan['run'], plan_sha256=self.plan_hash, finished=True)
        live.require(self.operation('finish') == expected, 'maintenance_finish')
        self.exited = self.api.wait(self.process, self.budget.require_ms(self.budget.cutoff(1))) is True
        if self.exited:
            self.exit_code = self.api.exit_code(self.process)
        live.require(self.exited and self.exit_code == 0, 'maintenance_exit')


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    live.require(len(args) == 2 and args[0] == '--owned-maintenance', 'internal_entry')
    return bootstrap(Path(args[1]))


if __name__ == '__main__':
    raise SystemExit(main())
