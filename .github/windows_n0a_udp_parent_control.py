"""Descendant UDP chain validation. Controller attestations are not host token proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import time
from dataclasses import dataclass
EXECUTION_ENABLED=False
PHASES=('before','sample','contained','after')
def udp():
    name='parent_udp_flow_dependency'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('windows_n0a_udp_flow.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name].engine()
integer=lambda v,lo=0,hi=(1<<63)-1:type(v) is int and lo<=v<=hi
hex_value=lambda v,n:type(v) is str and re.fullmatch('[0-9a-f]{%d}'%n,v) is not None
@dataclass(frozen=True)
class ParentUDPBinding:
    nonce:str
    parent_sha256:str
    child_sha256:str
    executor_sha256:str
    agentic_sid:str
    runner_port:int
    controller_compartment:int
    controller_elevated:bool
    controller_appcontainer:bool
    build:int=26300
    ubr:int=9457
    def valid(self):
        return (hex_value(self.nonce,32) and all(hex_value(v,64) for v in (self.parent_sha256,self.child_sha256,self.executor_sha256))
          and type(self.agentic_sid) is str and re.fullmatch(r'S-1-15-3(?:-[0-9]{1,10}){1,12}',self.agentic_sid) is not None
          and integer(self.runner_port,1025,65535) and type(self.controller_compartment) is int and self.controller_compartment==1
          and self.controller_elevated is False and self.controller_appcontainer is False and type(self.build) is int and self.build==26300 and type(self.ubr) is int and self.ubr==9457)
def verify_binding(parent,parent_hash,child,child_hash,executor,manifest,nonce,port):
    observed=udp().tcp_helpers().verify_binding(parent,parent_hash,executor,manifest,nonce,(port,port))
    path=Path(child);state=path.lstat()
    if path.is_symlink() or getattr(state,'st_file_attributes',0)&0x400 or not path.is_file():raise ValueError('child file')
    with path.open('rb') as stream:raw=stream.read(8*1024*1024+1)
    if not 512<=len(raw)<=8*1024*1024 or hashlib.sha256(raw).hexdigest()!=child_hash:raise ValueError('child pin')
    return ParentUDPBinding(nonce,parent_hash,child_hash,observed.executor_sha256,observed.agentic_sid,port,
        observed.controller_compartment,observed.controller_elevated,observed.controller_appcontainer,observed.build,observed.ubr)
def identity(actor,binding,phase,parent=False):
    mode='actor-n0a-udp-parent' if parent else 'actor-n0a-udp'
    if not(type(actor) is dict and actor.get('mode')==mode and type(actor.get('schemaVersion')) is int and actor['schemaVersion']==1
        and actor.get('nonce')==binding.nonce and actor.get('queriesSucceeded') is True and actor.get('errors')==[]
        and actor.get('tokenElevated') is False and integer(actor.get('pid'),1,2**32-1)):return False
    if phase=='contained':
        caps=actor.get('tokenCapabilities')
        return (actor.get('tokenIsAppContainer') is True and actor.get('isProcessInJob') is True
          and type(actor.get('tokenAppContainerSid')) is str and re.fullmatch(r'S-1-15-2(?:-[0-9]{1,10}){7}',actor['tokenAppContainerSid']) is not None
          and caps==[{'sid':binding.agentic_sid,'attributes':4}] and type(caps[0]['attributes']) is int)
    return phase in PHASES and actor.get('tokenIsAppContainer') is False and actor.get('tokenAppContainerSid') is None and actor.get('tokenCapabilities')==[]
CHAIN_KEYS={'parent_profile','child_profile','parent_pid_bound','child_pid_bound','sid_equal','child_hash_bound','resume_verified','wait_verified','child_report_bound','deadline_verified'}
PARENT_BOOL={'testOnly','deadlineVerified','profileMatched','childHashVerified','childCreated','tokenQuerySucceeded','sidMatched','resumeAttempted','resumed','waitSignaled','timedOut','terminateAttempted','terminationSucceeded','cleanupConfirmed','childReportObserved'}
PARENT_KEYS=PARENT_BOOL|{'version','phase','childPid','parentAppContainer','childAppContainer','sidEqual','resumeCount','childExitCode','childReportBytes','childReportSha256','failure'}
def parent_shape(v,phase):
    return (type(v) is dict and set(v)==PARENT_KEYS and type(v['version']) is int and v['version']==1 and v['phase']==phase
      and all(type(v[k]) is bool for k in PARENT_BOOL) and v['testOnly'] is False
      and all(v[k] is None or type(v[k]) is bool for k in ('parentAppContainer','childAppContainer','sidEqual'))
      and all(v[k] is None or integer(v[k],0,2**32-1) for k in ('resumeCount','childExitCode'))
      and integer(v['childPid'],0,2**32-1) and integer(v['childReportBytes'],0,32768)
      and (v['childReportSha256'] is None or hex_value(v['childReportSha256'],64))
      and v['failure'] in ('none','profile_only','profile','child_hash','child_report_exists','deadline','create','token','sid','resume_fixture','resume','timeout','wait','exit','hash','internal'))
def chain(value,binding,phase):
    facts={k:False for k in CHAIN_KEYS}
    if not isinstance(binding,ParentUDPBinding) or not binding.valid() or type(value) is not dict:return facts
    expected=dict(nonce=binding.nonce,parent_sha256=binding.parent_sha256,child_sha256=binding.child_sha256,executor_sha256=binding.executor_sha256,build=binding.build,ubr=binding.ubr)
    if any(type(value.get(k)) is not type(v) or value.get(k)!=v for k,v in expected.items()):return facts
    parent=value.get('parent');child=value.get('child')
    facts['parent_profile']=identity(parent,binding,phase,True);facts['child_profile']=identity(child,binding,phase)
    if not(type(parent) is dict and type(child) is dict):return facts
    try:facts['child_profile'] &= udp().validate_network(child.get('udp'),binding.nonce,phase,binding.runner_port)['profileMatched'] is True
    except (ValueError,TypeError):facts['child_profile']=False
    native=parent.get('parent')
    if not parent_shape(native,phase):return {k:False for k in CHAIN_KEYS}
    facts['parent_profile'] &= native.get('profileMatched') is True
    if phase=='contained':
        facts['parent_pid_bound']=(value.get('pid_verified') is True and value.get('pid_binding')=='executor_audit'
            and integer(value.get('parent_exit_code'),-2**31,2**31-1) and type(value.get('probe_exit_code')) is int and value['probe_exit_code']==0
            and udp().tcp_helpers().proof_helpers().smoke.base_container_selected(value.get('probe'),0) and value.get('actual_tiers')==['base-container'])
    else:facts['parent_pid_bound']=value.get('pid_verified') is True and value.get('pid_binding')=='ordinary_handle' and integer(value.get('parent_exit_code'),-2**31,2**31-1)
    facts['child_pid_bound']=(native.get('childCreated') is True and integer(native.get('childPid'),1,2**32-1)
        and native['childPid']==child.get('pid') and native['childPid']!=parent.get('pid'))
    expected_ac=phase=='contained'
    facts['sid_equal']=(native.get('tokenQuerySucceeded') is True and native.get('sidMatched') is True
        and native.get('parentAppContainer') is expected_ac and native.get('childAppContainer') is expected_ac
        and parent.get('tokenAppContainerSid')==child.get('tokenAppContainerSid')
        and (native.get('sidEqual') is True if expected_ac else native.get('sidEqual') is None))
    facts['child_hash_bound']=native.get('childHashVerified') is True
    facts['resume_verified']=native.get('resumeAttempted') is True and type(native.get('resumeCount')) is int and native['resumeCount']==1 and native.get('resumed') is True
    facts['wait_verified']=native.get('waitSignaled') is True and integer(native.get('childExitCode'),0,2**32-1)
    snapshot=value.get('child_snapshot')
    facts['child_report_bound']=(type(snapshot) is dict and set(snapshot)=={'sha256','bytes'} and hex_value(snapshot['sha256'],64)
        and integer(snapshot['bytes'],1,32768) and native.get('childReportObserved') is True
        and type(native.get('childReportBytes')) is int and native['childReportBytes']==snapshot['bytes'] and native.get('childReportSha256')==snapshot['sha256'])
    facts['deadline_verified']=native.get('deadlineVerified') is True
    return facts
def attributed(value,binding,phase):return all(chain(value,binding,phase).values())
def evaluate(cases,binding):
    result=udp().controls({},'0'*32,1025)
    result.update(schema_version=1,experiment='N0a-UDP-Parent',chain_verified={p:False for p in PHASES},
        profile_verified={p:False for p in PHASES},provenance_verified={p:False for p in PHASES},descendant_cleanup_confirmed=False,stage0_passed=False,product_acceptance=False,privacy_qualified=False,psec_cleanup_independently_verified=False)
    networks={};complete=type(cases) is dict
    for phase in PHASES:
        value=cases.get(phase) if type(cases) is dict else None
        facts=chain(value,binding,phase);okay=all(facts.values());result['chain_verified'][phase]=okay
        result['profile_verified'][phase]=facts['parent_profile'] and facts['child_profile']
        result['provenance_verified'][phase]=all(v for k,v in facts.items() if k not in ('parent_profile','child_profile'))
        if not okay:complete=False;continue
        try:networks[phase]=udp().validate_network(value['child'].get('udp'),binding.nonce,phase,binding.runner_port)
        except (ValueError,TypeError):complete=False;continue
        native=value['parent']['parent']
        if (native.get('failure')!='none' or value.get('parent_exit_code')!=0 or native['childExitCode']!=0 or native.get('cleanupConfirmed') is not True
            or native.get('timedOut') is not False or value.get('timed_out') is not False or value.get('harness_error') is not False):complete=False
    if isinstance(binding,ParentUDPBinding):result.update(udp().controls(networks,binding.nonce,binding.runner_port))
    result['descendant_cleanup_confirmed']=complete and cases.get('driver_error') is False and cases.get('cleanup_confirmed') is True
    if not complete or cases.get('driver_error') is not False or cases.get('cleanup_confirmed') is not True:
        result['ordinary_controls_verified']=False;result['sockets_cleanup_confirmed']=False
    return result
def closed_result(value):
    template=evaluate({},None)
    if type(value) is not dict or set(value)!=set(template):raise ValueError('parent result')
    for k,v in template.items():
        x=value[k]
        if type(v) is bool:
            if type(x) is not bool or (k in ('runtime_acceptance','stage0_passed','product_acceptance','privacy_qualified','psec_cleanup_independently_verified') and x):raise ValueError('flag')
        elif type(v) is dict:
            if type(x) is not dict or set(x)!=set(PHASES) or any(type(y) is not bool for y in x.values()):raise ValueError('chain')
        elif k=='selected_send_accepted_count':
            if not integer(x,0,3):raise ValueError('count')
        elif type(x) is not type(v) or x!=v:raise ValueError('fixed')
    if (value['selected_send_accepted_count'] or value['selected_echo_observed'] or value['explicit_send_denial']) and not value['chain_verified']['contained']:raise ValueError('unattributed')
    return json.loads(json.dumps(value))
def command(parent,parent_report,child,child_report,binding,phase,deadline_qpc,frequency):
    if not isinstance(binding,ParentUDPBinding) or not binding.valid() or phase not in PHASES or not integer(deadline_qpc,1) or not integer(frequency,1):raise ValueError('command')
    return [str(parent),'n0a-udp-parent',binding.nonce,str(parent_report),str(child),binding.child_sha256,str(child_report),str(binding.runner_port),phase,str(deadline_qpc),str(frequency)]
def run_endpoint(execution,binding,deadline,*,approved=False,clock=time.monotonic,sleep=time.sleep):
    if not EXECUTION_ENABLED or not approved:raise PermissionError('parent UDP inactive')
    if not isinstance(binding,ParentUDPBinding) or not binding.valid():raise ValueError('binding')
    limit=lambda seconds:udp().tcp_helpers().clipped_timeout(deadline,seconds,clock=clock)
    result={'driver_error':False,'cleanup_confirmed':False};owned=None
    try:
        execution.probe('runner',binding.runner_port,timeout=limit(30))
        result['before']=execution.invoke('ordinary','before','runner',binding.runner_port,timeout=limit(5))
        owned=execution.start('ordinary','sample','runner',binding.runner_port);sleep(limit(1.5))
        result['contained']=execution.invoke('contained','contained','runner',binding.runner_port,timeout=limit(15))
        result['sample']=execution.wait(owned,timeout=limit(12))
        result['after']=execution.invoke('ordinary','after','runner',binding.runner_port,timeout=limit(5))
    except Exception:result['driver_error']=True
    finally:
        if owned is not None:
            try:result['cleanup_confirmed']=execution.close_owned(owned) is True
            except Exception:pass
    return result

parse=lambda raw:udp().parse(raw)
def default_host_parent_udp(reason='report_absent'):
    old=udp().default_host_udp(reason)
    return dict(schema_version=1,experiment='N0a-UDP-Parent',receipt_verified=False,reason=old['reason'],result=evaluate({},None),execution=old['execution'],launcher=old['launcher'])
def validate_host_parent_udp_envelope(value,expected):
    from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
    if type(value) is not dict or set(value)!={'schema_version','case_nonce','parent_sha256','child_sha256','report','launcher'}:raise ValueError('parent envelope')
    if len(json.dumps(value,ensure_ascii=True).encode('ascii'))>4096:raise ValueError('parent wire')
    if type(value['schema_version']) is not int or value['schema_version']!=1 or any(value[k]!=expected[k] for k in ('case_nonce','parent_sha256','child_sha256')):raise ValueError('parent binding')
    template=default_host_parent_udp();launcher=value['launcher'];old=udp().tcp_helpers()
    if (type(launcher) is not dict or set(launcher)!=set(template['launcher']) or launcher['phase'] not in old.LAUNCHER_PHASES or launcher['failure'] not in old.LAUNCHER_FAILURES
        or (launcher['python_exit_code'] is not None and not integer(launcher['python_exit_code'],-2**31,2**31-1))
        or (launcher['process_exit_confirmed'] is not None and type(launcher['process_exit_confirmed']) is not bool)
        or any(type(launcher[k]) is not bool for k in ('timed_out','budget_exhausted'))):raise ValueError('launcher')
    template['launcher']=dict(launcher);template['reason']=launcher['failure'];report=value['report']
    if report is None:return template
    binding=dict(case_nonce=expected['case_nonce'],parent_sha256=expected['parent_sha256'],child_sha256=expected['child_sha256'],executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457)
    if type(report) is not dict or set(report)!={'schema_version','binding','result','execution'} or type(report['schema_version']) is not int or report['schema_version']!=1 or report['binding']!=binding:raise ValueError('parent report')
    execution=report['execution']
    if type(execution) is not dict or set(execution)!={'phase','failed','cleanup_confirmed'} or execution['phase'] not in old.EXECUTION_PHASES or any(type(execution[k]) is not bool for k in ('failed','cleanup_confirmed')):raise ValueError('execution')
    template.update(receipt_verified=True,reason='none',result=closed_result(report['result']),execution=dict(execution))
    complete=(not execution['failed'] and execution['cleanup_confirmed'] and launcher['failure']=='none' and launcher['python_exit_code']==0 and launcher['process_exit_confirmed'] is True and not launcher['timed_out'] and not launcher['budget_exhausted'])
    if not complete:
        for key in ('ordinary_controls_verified','sockets_cleanup_confirmed','descendant_cleanup_confirmed'):template['result'][key]=False
    return template
