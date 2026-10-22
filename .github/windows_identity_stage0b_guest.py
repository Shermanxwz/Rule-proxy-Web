"""Default-OFF Stage0b minimum guest adapter; never substitutes for PSEC Stage0."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ENABLED = True
MAX_PUBLIC = 4096
MAX_PRIVATE = 128 * 1024
REPORT_ALLOWANCE = 1024 * 1024  # planning only; not an OS file quota
MAX_ACTOR = 8 * 1024 * 1024
NONCE = re.compile(r'[0-9a-f]{32}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
BOOL_FIELDS = ('current_ordinary_verified', 'launcher_creation_observed',
               'probe_creation_observed', 'actor_creation_observed',
               'launcher_identity_verified', 'probe_identity_verified',
               'actor_identity_verified', 'fresh_actor_verified', 'pipe_echo_verified',
               'pipe_eof_verified', 'actor_exit_verified', 'nested_cleanup_verified',
               'launcher_exit_verified', 'adapter_cleanup_verified', 'stage0b_passed',
               'network_tested', 'proxy_tested', 'product_acceptance')
REQUIRED_FACTS = BOOL_FIELDS[:14]
FAILURES = frozenset(('disabled', 'configuration', 'capacity', 'identity', 'launcher',
                      'report', 'cleanup', 'deadline', 'internal'))
PUBLIC_KEYS = frozenset(('schema_version', 'stage', 'case_nonce_sha256', 'actor_sha256',
                         'status', 'failure', 'diagnostic', *BOOL_FIELDS))


READ_STATES = ('not_attempted','missing','read_error','overbound','utf8','json','duplicate','nonfinite','not_object','close_uncertain','parsed')
BINDING_STATES = ('not_attempted','unavailable','schema','nonce','hash','deadline','identity','image','pipe','eof','exit','cleanup','verified')
EXECUTION_SOURCES = ('none','owner','report','owned_stdout')


def default_diagnostic():
    return dict(v=1, held=dict(created=False,resumed=False,exit_observed=False,
                              exit_code=None,cleanup_confirmed=False),
                reads=['not_attempted']*3, bindings=['not_attempted']*3,
                stdout_reads=['not_attempted']*2, execution_sources=['none']*3,
                execution=[None]*3)


def validate_diagnostic(value):
    if type(value) is not dict or set(value) != set(default_diagnostic()) or type(value['v']) is not int or value['v'] != 1:
        raise ValueError('diagnostic')
    held = value['held']
    if type(held) is not dict or set(held) != set(default_diagnostic()['held']):
        raise ValueError('diagnostic')
    if any(type(held[k]) is not bool for k in ('created','resumed','exit_observed','cleanup_confirmed')):
        raise ValueError('diagnostic')
    code = held['exit_code']
    if code is not None and (type(code) is not int or not 0 <= code <= 0xffffffff):
        raise ValueError('diagnostic')
    if (held['resumed'] and not held['created'] or held['exit_observed'] and not held['created'] or code is not None and not (held['created'] and held['exit_observed'])
            or held['cleanup_confirmed'] and held['created'] and not held['exit_observed']):
        raise ValueError('diagnostic')
    for key, count, labels in (('reads',3,READ_STATES),('bindings',3,BINDING_STATES),
                               ('stdout_reads',2,READ_STATES),('execution_sources',3,EXECUTION_SOURCES)):
        if type(value[key]) is not list or len(value[key]) != count or any(type(x) is not str or x not in labels for x in value[key]):
            raise ValueError('diagnostic')
    if type(value['execution']) is not list or len(value['execution']) != 3:
        raise ValueError('diagnostic')
    for index, (source, execution) in enumerate(zip(value['execution_sources'],value['execution'])):
        if ((source == 'none') != (execution is None) or index == 0 and source not in ('none','owner')
                or index > 0 and source == 'owner'):
            raise ValueError('diagnostic')
        if source == 'report' and (value['reads'][index-1] != 'parsed' or value['bindings'][index-1] != 'verified'):
            raise ValueError('diagnostic')
        if source == 'owned_stdout' and (value['stdout_reads'][index-1] != 'parsed'
                or index == 1 and not (held['created'] and held['exit_observed'])
                or index == 2 and value['bindings'][0] != 'verified'):
            raise ValueError('diagnostic')
        if execution is not None:
            launcher_module().validate_execution(execution)
    return value


def read_diagnostic_file(launcher, path, limit):
    try:
        return launcher.read_private(path,limit), 'parsed'
    except FileNotFoundError:
        return None, 'missing'
    except launcher.GateFailure as exc:
        states = {'private_report_bound':'overbound','private_report_utf8':'utf8',
                  'private_report_json':'json','private_report_duplicate':'duplicate',
                  'private_report_nonfinite':'nonfinite','private_report_object':'not_object',
                  'private_report_close_uncertain':'close_uncertain'}
        return None, states.get(str(exc),'read_error')
    except Exception:
        return None, 'read_error'


def owned_stdout_execution(value, launch, config, deadline, frequency, launcher):
    """Owned stdio is an invocation observation, not report-bound identity."""
    if (type(launch) is not dict or launch.get('native_identity_verified_before_resume') is not True
            or launch.get('cleanup',{}).get('process_exit_confirmed') is not True
            or type(launch.get('child_pid')) is not int or launch['child_pid'] <= 0):
        return None
    if (type(value) is not dict or set(value) != {'schema_version','stage','actor_sha256','case_nonce_sha256','deadline_qpc','qpc_frequency','execution'}
            or type(value['schema_version']) is not int or value['schema_version'] != 1
            or value['stage'] != 'stage0b-diagnostic'
            or value['actor_sha256'] != config['actor_sha256']
            or value['case_nonce_sha256'] != hashlib.sha256(config['case_nonce'].encode('ascii')).hexdigest()
            or type(value['deadline_qpc']) is not int or value['deadline_qpc'] != deadline
            or type(value['qpc_frequency']) is not int or value['qpc_frequency'] != frequency):
        return None
    try:
        return launcher.validate_execution(value['execution'])
    except Exception:
        return None


def set_execution(diagnostic, index, value, source, launcher):
    try:
        diagnostic['execution'][index] = launcher.validate_execution(value)
        diagnostic['execution_sources'][index] = source
    except Exception:
        pass  # Invalid optional diagnostics never create or erase core facts.


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError('duplicate')
        out[key] = value
    return out


def decode(raw):
    try:
        text = raw.decode('utf-8', 'strict') if type(raw) is bytes else raw
        return json.loads(text, object_pairs_hook=unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('json') from None


def default_public(case_nonce, actor_sha256):
    if type(case_nonce) is not str or not NONCE.fullmatch(case_nonce):
        raise ValueError('nonce')
    if type(actor_sha256) is not str or not HASH.fullmatch(actor_sha256):
        raise ValueError('pin')
    return dict(schema_version=2, stage='stage0b-minimum',
                case_nonce_sha256=hashlib.sha256(case_nonce.encode('ascii')).hexdigest(),
                actor_sha256=actor_sha256, status='inconclusive', failure=None, diagnostic=default_diagnostic(),
                **{key: False for key in BOOL_FIELDS})


def validate_public(value, case_nonce, actor_sha256):
    expected = default_public(case_nonce, actor_sha256)
    if type(value) is not dict or set(value) != PUBLIC_KEYS:
        raise ValueError('shape')
    for key in ('schema_version', 'stage', 'case_nonce_sha256', 'actor_sha256'):
        if type(value[key]) is not type(expected[key]) or value[key] != expected[key]:
            raise ValueError('binding')
    if any(type(value[key]) is not bool for key in BOOL_FIELDS):
        raise ValueError('boolean')
    if any(value[key] is not False for key in ('network_tested', 'proxy_tested', 'product_acceptance')):
        raise ValueError('scope')
    if value['failure'] is not None and (type(value['failure']) is not str or value['failure'] not in FAILURES):
        raise ValueError('failure')
    validate_diagnostic(value['diagnostic'])
    dependencies = {
        'launcher_identity_verified': ('current_ordinary_verified', 'launcher_creation_observed'),
        'probe_identity_verified': ('launcher_identity_verified', 'probe_creation_observed'),
        'actor_identity_verified': ('probe_identity_verified', 'actor_creation_observed'),
        'fresh_actor_verified': ('actor_identity_verified',),
        'pipe_echo_verified': ('fresh_actor_verified',),
        'pipe_eof_verified': ('fresh_actor_verified',),
        'actor_exit_verified': ('fresh_actor_verified',),
        'nested_cleanup_verified': ('fresh_actor_verified',),
    }
    if any(value[key] and not all(value[dep] for dep in deps) for key, deps in dependencies.items()):
        raise ValueError('consistency')
    passed = all(value[key] for key in REQUIRED_FACTS) and value['failure'] is None
    if value['stage0b_passed'] != passed or value['status'] != ('passed' if passed else 'inconclusive'):
        raise ValueError('qualification')
    if len((json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode('ascii')) > MAX_PUBLIC:
        raise ValueError('bound')
    return dict(value)


_LAUNCHER = None


def launcher_module():
    global _LAUNCHER
    if _LAUNCHER is not None:
        return _LAUNCHER
    path = Path(__file__).with_name('windows_identity_ordinary_launcher.py')
    spec = importlib.util.spec_from_file_location('stage0b_guest_launcher', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _LAUNCHER = module
    return module


def bounded(path, limit, launcher):
    path = launcher.checked_path(path)
    data = launcher.read_private_bytes(path, limit)
    if len(data) > limit:
        raise ValueError('bound')
    return data


def configuration(path):
    if str(Path(path)) != r'C:\RuleProxyCI\ruleproxy-vm-config.json':
        raise ValueError('configuration')
    launcher = launcher_module()
    value = decode(bounded(Path(path), 16384, launcher))
    if type(value) is not dict:
        raise ValueError('configuration')
    if any(key in value for key in ('n0a', 'n0a_udp', 'n0a_udp_parent', 'n0a_udp6', 'capture')):
        raise ValueError('configuration')
    config = value.get('stage0b')
    if type(config) is not dict or set(config) != {'enabled', 'case_nonce', 'actor_sha256'} or config['enabled'] is not True:
        raise ValueError('configuration')
    default_public(config['case_nonce'], config['actor_sha256'])
    return config


def capacity_requirement(actor_bytes, source_bytes):
    if (type(actor_bytes) is not int or not 512 <= actor_bytes <= MAX_ACTOR
            or type(source_bytes) is not int or not 0 <= source_bytes <= 1024 * 1024):
        raise ValueError('capacity')
    return 2 * actor_bytes + source_bytes + REPORT_ALLOWANCE


def ensure_space(directory, required):
    if shutil.disk_usage(directory).free < required:
        raise ValueError('capacity')


def stage_actor(source, destination, expected, launcher):
    data = bounded(source, MAX_ACTOR, launcher)
    if len(data) < 512 or data[:2] != b'MZ' or hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('actor')
    launcher.write_private_bytes(destination, data)
    copied = bounded(destination, MAX_ACTOR, launcher)
    if len(copied) != len(data) or hashlib.sha256(copied).hexdigest() != expected:
        raise ValueError('actor')
    return len(data)


def fixed_launcher_command(python, launcher_path, actor, work, config, deadline, frequency):
    return [str(python), '-I', '-S', '-B', str(launcher_path), '--disposable-ci',
            '--approved-security-test', '--current-ordinary-only', '--actor', str(actor),
            '--actor-sha256', config['actor_sha256'], '--case-nonce', config['case_nonce'],
            '--work', str(work), '--report', str(work / 'report.json'),
            '--deadline-qpc', str(deadline), '--qpc-frequency', str(frequency)]


def cleanup_verified(launch):
    if type(launch) is not dict:
        return False
    cleanup = launch.get('cleanup')
    return (type(cleanup) is dict and cleanup.get('job_closed') is True
            and cleanup.get('job_empty') is True and cleanup.get('handles_closed') is True
            and cleanup.get('process_exit_confirmed') is True
            and cleanup.get('close_uncertain') is False and cleanup.get('errors') == [])


def launcher_binding_stage(report,launch,config,sid,deadline,frequency):
    checks = (
        ('schema',type(report.get('schema_version')) is int and report['schema_version']==2 and report.get('stage')=='current-ordinary-stage0b-launcher' and report.get('current_ordinary_only') is True),
        ('nonce',report.get('case_nonce')==config['case_nonce']),
        ('hash',report.get('actor_sha256')==config['actor_sha256']),
        ('deadline',type(report.get('deadline_qpc')) is int and report['deadline_qpc']==deadline and type(report.get('qpc_frequency')) is int and report['qpc_frequency']==frequency),
        ('identity',type(report.get('controller_pid')) is int and report['controller_pid']==launch.get('child_pid') and report.get('controller_sid')==sid and report.get('current_ordinary_verified') is True),
        ('image',launch.get('native_identity_verified_before_resume') is True))
    return next((label for label,ok in checks if not ok),'verified')


def probe_binding_stage(probe,config,pid,sid,deadline,frequency):
    if type(probe) is not dict:return 'unavailable'
    identity=probe.get('controller_identity')
    checks=(('schema',type(probe.get('schema_version')) is int and probe['schema_version']==1 and probe.get('stage')=='0b' and type(identity) is dict),
            ('nonce',probe.get('nonce')==config['case_nonce']),
            ('hash',probe.get('actor_sha256')==config['actor_sha256']),
            ('deadline',type(probe.get('deadline_qpc')) is int and probe['deadline_qpc']==deadline and type(probe.get('qpc_frequency')) is int and probe['qpc_frequency']==frequency))
    for label,ok in checks:
        if not ok:return label
    if not (type(identity.get('pid')) is int and identity['pid']==pid and identity.get('sid')==sid and identity.get('elevated') is False and identity.get('appcontainer') is False and type(identity.get('cid')) is int and identity['cid']==1):return 'identity'
    return 'verified'


def native_binding_stage(probe,native,facts):
    if type(native) is not dict or type(probe) is not dict:return 'unavailable'
    if not facts['probe_identity_verified']:return 'identity'
    if json.dumps(native,sort_keys=True,allow_nan=False)!=json.dumps(probe.get('actor'),sort_keys=True,allow_nan=False):return 'hash'
    if type(native.get('schemaVersion')) is not int or native['schemaVersion']!=1:return 'schema'
    if probe.get('copied_actor_sha256') != probe.get('actor_sha256'):return 'hash'
    if probe.get('image_verified_before_resume') is not True:return 'image'
    if not facts['actor_identity_verified']:return 'identity'
    if not facts['fresh_actor_verified']:return 'nonce'
    for field,label in (('pipe_echo_verified','pipe'),('pipe_eof_verified','eof'),('actor_exit_verified','exit'),('nested_cleanup_verified','cleanup')):
        if not facts[field]:return label
    return 'verified'


def project_private(public, launcher, launch, report, probe, config, parent_sid, deadline, frequency, *, native=None):
    """No trusted Boolean from the report replaces the held outer chain."""
    public['launcher_creation_observed'] = launch.get('started') is True
    public['launcher_exit_verified'] = (launch.get('cleanup', {}).get('process_exit_confirmed') is True
                                       and type(launch.get('exit_code')) is int and launch['exit_code'] == 0)
    public['adapter_cleanup_verified'] = cleanup_verified(launch)
    diagnostic = public['diagnostic']
    diagnostic['bindings'][0] = 'unavailable'
    if type(report) is not dict:
        return
    bound = (type(report.get('schema_version')) is int and report['schema_version'] == 2
             and report.get('stage') == 'current-ordinary-stage0b-launcher'
             and report.get('case_nonce') == config['case_nonce']
             and report.get('actor_sha256') == config['actor_sha256']
             and type(report.get('deadline_qpc')) is int and report['deadline_qpc'] == deadline
             and type(report.get('qpc_frequency')) is int and report['qpc_frequency'] == frequency
             and report.get('current_ordinary_only') is True
             and type(report.get('controller_pid')) is int
             and report['controller_pid'] == launch.get('child_pid')
             and report.get('controller_sid') == parent_sid
             and report.get('current_ordinary_verified') is True
             and launch.get('native_identity_verified_before_resume') is True)
    if not bound:
        diagnostic['bindings'][0] = launcher_binding_stage(report,launch,config,parent_sid,deadline,frequency)
        return
    diagnostic['bindings'][0] = 'verified'
    public['launcher_identity_verified'] = True
    set_execution(diagnostic,1,report.get('diagnostic_execution'),'report',launcher)
    diagnostic['bindings'][1] = 'unavailable'
    inner = report.get('launch')
    if type(inner) is not dict:
        return
    public['probe_creation_observed'] = inner.get('started') is True
    if (inner.get('native_identity_verified_before_resume') is not True
            or inner.get('cleanup', {}).get('process_exit_confirmed') is not True
            or type(inner.get('child_pid')) is not int or inner['child_pid'] <= 0):
        return
    facts = launcher.probe_facts(probe, config['case_nonce'], config['actor_sha256'],
                                 inner['child_pid'], parent_sid, deadline, frequency, native=native)
    public.update(facts)
    diagnostic['bindings'][1] = probe_binding_stage(probe,config,inner['child_pid'],parent_sid,deadline,frequency)
    if facts['probe_identity_verified']:
        set_execution(diagnostic,2,probe.get('diagnostic_execution'),'report',launcher)
    diagnostic['bindings'][2] = native_binding_stage(probe,native,facts)
    public['nested_cleanup_verified'] = (facts['nested_cleanup_verified'] and cleanup_verified(inner)
                                         and report.get('cleanup', {}).get('token_handles_closed') is True
                                         and report.get('cleanup', {}).get('errors') == []
                                         and type(inner.get('exit_code')) is int and inner['exit_code'] == 0
                                         and inner.get('resumed') is True and 'error' not in inner
                                         and 'error' not in report)


def execute(config, deadline, frequency, *, root=ROOT, api=None):
    """Explicitly inactive entry; injected API is only for approved pure tests."""
    public = default_public(config['case_nonce'], config['actor_sha256'])
    if not EXECUTION_ENABLED or os.name != 'nt':
        public['failure'] = 'disabled'
        return public
    launcher = launcher_module()
    api = launcher.NativeAPI() if api is None else api
    token = None
    work = root / 'private-stage0b'
    launch = None
    phase = 'deadline'
    parent = None
    budget = None
    try:
        budget = launcher.QpcBudget(api, deadline, frequency)
        budget.require_ms(budget.cutoff(30))
        phase = 'identity'
        token = api.current_token()
        parent = api.identity(token)
        compartment = api.compartment()
        if not launcher.token_is_ordinary(parent) or type(compartment) is not int or compartment != 1:
            raise ValueError('identity')
        public['current_ordinary_verified'] = True
        phase = 'configuration'
        launcher.checked_path(root, is_file=False)
        actor = launcher.checked_path(root / 'actor.exe', inside=root)
        runtime = launcher.checked_path(sys.base_prefix, is_file=False)
        python = launcher.checked_path(sys.executable, inside=runtime)
        if python.name.casefold() != 'python.exe':
            raise ValueError('runtime')
        source_names = ('.github/windows_identity_ordinary_launcher.py', '.github/windows_identity_pipe_probe.py',
                        'ruleproxy/windows_app_process.py', '.github/windows_identity_stage0b_guest.py')
        source_bytes = sum(launcher.checked_path(root / name, inside=root).stat().st_size for name in source_names)
        phase = 'capacity'
        required = capacity_requirement(actor.stat().st_size, source_bytes)
        ensure_space(root, required)
        budget.require_ms(budget.cutoff(30))
        work.mkdir(exist_ok=False); (work / 'temp').mkdir()
        inputs = work / 'inputs'; inputs.mkdir()
        staged = inputs / 'windows_identity_actor.exe'
        stage_actor(actor, staged, config['actor_sha256'], launcher)
        # The probe will create its own second copy; do not borrow capture reserve.
        ensure_space(work, actor.stat().st_size + REPORT_ALLOWANCE)
        budget.require_ms(budget.cutoff(30))
        phase = 'launcher'
        child_work = work / 'launcher'
        command = fixed_launcher_command(python, root / source_names[0], staged, child_work,
                                          config, deadline, frequency)
        launch = launcher.launch_owned(api, command, work, parent, parent, qpc_budget=budget,
                                        work_cutoff=budget.cutoff(5), cleanup_cutoff=budget.deadline)
        public['diagnostic']['held'] = dict(created=launch.get('started') is True,resumed=launch.get('resumed') is True,exit_observed=launch.get('started') is True and launch.get('cleanup',{}).get('process_exit_confirmed') is True,exit_code=launch.get('exit_code'),cleanup_confirmed=cleanup_verified(launch))
        set_execution(public['diagnostic'],0,launch.get('diagnostic_execution'),'owner',launcher)
        public['launcher_creation_observed'] = launch.get('started') is True
        public['adapter_cleanup_verified'] = cleanup_verified(launch)
        public['launcher_exit_verified'] = (launch.get('cleanup', {}).get('process_exit_confirmed') is True
                                           and type(launch.get('exit_code')) is int and launch['exit_code'] == 0)
        # Exited nonzero/cleanup-failed chains may still carry bound pipe positives.
        if launch.get('cleanup', {}).get('process_exit_confirmed') is True and launch.get('started') is True:
            phase = 'report'
            diagnostic = public['diagnostic']
            loaded = []
            for index,(path,limit) in enumerate(((child_work/'report.json',MAX_PRIVATE),(child_work/'probe/report.json',MAX_PRIVATE),(child_work/'probe/output/actor.json',8192))):
                value,state = read_diagnostic_file(launcher,path,limit)
                diagnostic['reads'][index] = state
                if state == 'close_uncertain': public['adapter_cleanup_verified'] = False
                loaded.append(value)
            report,probe,native = loaded
            read_close_uncertain = not public['adapter_cleanup_verified']
            project_private(public, launcher, launch, report, probe, config, parent['sid'], deadline, frequency, native=native)
            if read_close_uncertain: public['adapter_cleanup_verified'] = False
            # These are the already-owned redirected files, never caller paths.
            inner = report.get('launch') if public['launcher_identity_verified'] else None
            for index,(path,owner) in enumerate(((work/'controller.stdout',launch),(child_work/'controller.stdout',inner))):
                if type(owner) is not dict or owner.get('native_identity_verified_before_resume') is not True or owner.get('cleanup',{}).get('process_exit_confirmed') is not True:
                    continue
                value,state = read_diagnostic_file(launcher,path,1024)
                diagnostic['stdout_reads'][index] = state
                if state == 'close_uncertain': public['adapter_cleanup_verified'] = False
                execution = owned_stdout_execution(value,owner,config,deadline,frequency,launcher)
                if execution is not None:
                    set_execution(diagnostic,index+1,execution,'owned_stdout',launcher)
        if 'error' in launch or launch.get('resumed') is not True:
            public['failure'] = 'launcher'
        if not all(public[key] for key in REQUIRED_FACTS):
            public['failure'] = 'cleanup' if not public['adapter_cleanup_verified'] else phase
    except Exception as exc:
        public['failure'] = phase
        if isinstance(exc, launcher.GateFailure) and str(exc) == 'private_report_close_uncertain':
            public['adapter_cleanup_verified'] = False
    finally:
        if token:
            owned, token = token, None
            try:
                api.close(owned)
            except Exception:
                public['adapter_cleanup_verified'] = False
                public['failure'] = public['failure'] or 'cleanup'
    if budget is not None:
        try:
            budget.require_ms(budget.deadline)
        except Exception:
            public['failure'] = public['failure'] or 'deadline'
    # Leave private roots to the original outer guest cleanup. Unknown ownership
    # is never converted into successful deletion by this adapter.
    passed = all(public[key] for key in REQUIRED_FACTS) and public['failure'] is None
    public['stage0b_passed'] = passed
    public['status'] = 'passed' if passed else 'inconclusive'
    return validate_public(public, config['case_nonce'], config['actor_sha256'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--deadline-qpc', required=True, type=int)
    parser.add_argument('--qpc-frequency', required=True, type=int)
    args = parser.parse_args(argv)
    try:
        config = configuration(args.config)
        value = execute(config, args.deadline_qpc, args.qpc_frequency)
        data = (json.dumps(value, ensure_ascii=True, indent=2) + '\n').encode('ascii')
        if len(data) > MAX_PUBLIC:
            return 1
        ensure_space(ROOT, len(data))
        launcher_module().write_private_bytes(ROOT / 'public-stage0b.json', data)
        return 0 if value['stage0b_passed'] else 1
    except Exception:
        return 1  # No traceback/private path or identifier projection.


if __name__ == '__main__':
    raise SystemExit(main())
