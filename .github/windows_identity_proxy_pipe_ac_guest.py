"""Default-OFF ordinary guest owner for one zero-capability AC pipe pair.

No network mechanism or isolation acceptance is provided. Private controller
reports are admitted only against the already-held controller observations.
"""
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

ROOT=Path(__file__).resolve().parents[1]
MAX_PRIVATE=128*1024
MAX_PUBLIC=4096
MAX_ACTOR=8*1024*1024
FACTS=('current_ordinary_verified','controller_identity_verified','frontend_held_identity_verified',
       'relay_held_identity_verified','fresh_frontend_profile_verified','images_verified',
       'child_environment_verified','owned_acl_scope_verified','acl_removed_verified',
       'profile_deleted_verified','controller_exit_verified','outer_cleanup_verified')


def controller_module():
    """One exact-path/source module identity; a same-process consistency check."""
    path=Path(__file__).with_name('windows_identity_proxy_pipe_probe.py').resolve()
    source=path.read_bytes();digest=hashlib.sha256(source).hexdigest()
    key='identity_proxy_pipe_controller'
    cached=sys.modules.get(key)
    if cached is not None:
        if (getattr(cached,'__file__',None)!=str(path) or getattr(cached,'_source_sha256',None)!=digest
                or getattr(getattr(cached,'__spec__',None),'origin',None)!=str(path)):
            raise ValueError('controller_module')
        return cached
    spec=importlib.util.spec_from_file_location(key,path)
    module=importlib.util.module_from_spec(spec);module._source_sha256=digest
    sys.modules[key]=module
    try:exec(compile(source,str(path),'exec'),module.__dict__)
    except BaseException:
        if sys.modules.get(key) is module:del sys.modules[key]
        raise
    return module


def unique(pairs):
    value={}
    for key,item in pairs:
        if key in value:raise ValueError('duplicate')
        value[key]=item
    return value


def decode(raw):
    if type(raw) is not bytes:raise ValueError('report')
    return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=unique,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError('report')))


def valid_config(config):
    if type(config) is not dict or set(config)!={'enabled','run_nonce','case_nonce','actor_sha256','manifest_sha256'} or config['enabled'] is not True:
        raise ValueError('configuration')
    for key,width in (('run_nonce',32),('case_nonce',32),('actor_sha256',64),('manifest_sha256',64)):
        if type(config[key]) is not str or re.fullmatch('[0-9a-f]{'+str(width)+'}',config[key]) is None:
            raise ValueError('configuration')
    return config


def default_public(config):
    valid_config(config)
    return dict(schema_version=1,stage='proxy-pipe-ac',profile='ordinary-win11-zero-cap-front-pipe-v1',
                run_nonce_sha256=hashlib.sha256(config['run_nonce'].encode('ascii')).hexdigest(),
                case_nonce_sha256=hashlib.sha256(config['case_nonce'].encode('ascii')).hexdigest(),
                actor_sha256=config['actor_sha256'],manifest_sha256=config['manifest_sha256'],
                status='not_requested',ac_failure=None,
                diagnostic=dict(phase='configuration',error_domain='none',error_code=None,controller_report='not_attempted'),
                facts={key:False for key in FACTS},pair=None,ac_pipe_passed=False,
                synthetic_http_only=True,network_tested=False,proxy_tested=False,product_acceptance=False)


def cleanup_verified(launch):
    if type(launch) is not dict or type(launch.get('cleanup')) is not dict:return False
    c=launch['cleanup']
    return (all(c.get(key) is True for key in ('job_closed','job_empty','handles_closed','process_exit_confirmed'))
            and c.get('close_uncertain') is False and c.get('errors')==[])


def pair_passed(pair):
    return (type(pair) is dict and pair.get('case')==0 and all(pair.get(k) is True for k in
            ('admitted','parent_data_closed','cleanup_confirmed','job_empty','expected_outcome'))
            and all(type(pair.get(k)) is int and pair[k]==3 for k in
                    ('created','resumed','exit_observed','identity_verified','reports_bound'))
            and pair.get('observations')==[177,78] and pair.get('core_failure')==[0,0]
            and pair.get('pipe_eof')==[True,True] and pair.get('native_close')==[True,True]
            and pair.get('watchdog_stop') is False and pair.get('failure') is None)


def diagnostic_passed(value):
    return (type(value) is dict and value.get('controller_report')=='bound'
            and value.get('error_domain')=='none' and value.get('error_code') is None)


def validate_public(value,config):
    template=default_public(config);controller=controller_module()
    if type(value) is not dict or set(value)!=set(template):raise ValueError('report')
    for key in ('schema_version','stage','profile','run_nonce_sha256','case_nonce_sha256',
                'actor_sha256','manifest_sha256','synthetic_http_only','network_tested','proxy_tested','product_acceptance'):
        if type(value[key]) is not type(template[key]) or value[key]!=template[key]:raise ValueError('report')
    if value['status'] not in ('not_requested','inconclusive','passed') or type(value['ac_pipe_passed']) is not bool:
        raise ValueError('report')
    if value['ac_failure'] is not None and value['ac_failure'] not in controller.AC_FAILURES:raise ValueError('report')
    facts=value['facts'];d=value['diagnostic']
    if type(facts) is not dict or set(facts)!=set(FACTS) or any(type(v) is not bool for v in facts.values()):raise ValueError('report')
    if (type(d) is not dict or set(d)!={'phase','error_domain','error_code','controller_report'}
            or d['phase'] not in controller.AC_PHASES or d['error_domain'] not in controller.AC_ERROR_DOMAINS
            or d['controller_report'] not in controller.AC_REPORT_STATES
            or d['error_code'] is not None and (type(d['error_code']) is not int or not 0<=d['error_code']<=0xffffffff)):
        raise ValueError('report')
    if d['error_domain'] in ('none','internal') and d['error_code'] is not None:raise ValueError('report')
    if value['pair'] is not None:controller.validate_pair(value['pair'])
    passed=all(facts.values()) and pair_passed(value['pair']) and value['ac_failure'] is None and diagnostic_passed(d)
    if value['ac_pipe_passed']!=passed or (value['status']=='passed')!=passed:raise ValueError('report')
    if value['status']=='not_requested' and (any(facts.values()) or value['pair'] is not None):raise ValueError('report')
    if len((json.dumps(value,indent=2)+'\n').encode('ascii'))>MAX_PUBLIC:raise ValueError('bound')
    return value


def configuration(path):
    if str(Path(path))!=r'C:\RuleProxyCI\ruleproxy-vm-config.json':raise ValueError('configuration')
    controller=controller_module();launcher=controller.launcher
    value=decode(launcher.read_private_bytes(launcher.checked_path(Path(path)),16384))
    if type(value) is not dict or any(k in value for k in ('stage0b','n0a','n0a_udp','n0a_udp_parent','n0a_udp6','capture')):
        raise ValueError('configuration')
    return valid_config(value.get('proxy_pipe_ac'))


def fixed_command(python,script,actor,manifest,work,config,deadline,frequency):
    return [str(python),'-I','-S','-B',str(script),'--run-ac-pair','--actor',str(actor),
            '--manifest',str(manifest),'--expected-manifest-sha256',config['manifest_sha256'],
            '--expected-actor-sha256',config['actor_sha256'],
            '--work',str(work),'--run-nonce',config['run_nonce'],'--case-nonce',config['case_nonce'],
            '--deadline-qpc',str(deadline),'--qpc-frequency',str(frequency)]


def bind_controller(report,launch,config,parent,deadline,frequency,controller):
    if (type(launch) is not dict or launch.get('started') is not True or launch.get('resumed') is not True
            or launch.get('native_identity_verified_before_resume') is not True
            or type(launch.get('child_pid')) is not int or launch['child_pid']<=0
            or launch.get('cleanup',{}).get('process_exit_confirmed') is not True):
        raise ValueError('report')
    expected={key:config[key] for key in ('run_nonce','case_nonce','actor_sha256','manifest_sha256')}
    expected.update(deadline_qpc=deadline,qpc_frequency=frequency,controller_pid=launch['child_pid'],
                    controller_sid=parent['sid'],controller_session=parent['session_id'])
    return controller.validate_private_report(report,expected)


def execute(config,deadline,frequency,*,root=ROOT,api=None):
    public=default_public(config)
    controller=controller_module()
    if controller.AC_EXECUTION_ENABLED is not True or os.name!='nt':return public
    launcher=controller.launcher
    token=None;launch=None;budget=None;phase='configuration'
    try:
        api=launcher.NativeAPI() if api is None else api
        phase='configuration';budget=launcher.QpcBudget(api,deadline,frequency)
        budget.require_ms(budget.cutoff(5))
        phase='ordinary';token=api.current_token();parent=api.identity(token)
        compartment=api.compartment()
        if not launcher.token_is_ordinary(parent) or type(compartment) is not int or compartment!=1:
            raise ValueError('identity')
        public['facts']['current_ordinary_verified']=True
        phase='configuration';launcher.checked_path(root,is_file=False)
        actor=launcher.checked_path(root/'bridge/windows_identity_proxy_pipe_actor.exe',inside=root)
        manifest=launcher.checked_path(root/'bridge/identity-proxy-pipe-manifest.json',inside=root)
        script=launcher.checked_path(root/'.github/windows_identity_proxy_pipe_probe.py',inside=root)
        runtime=launcher.checked_path(sys.base_prefix,is_file=False)
        python=launcher.checked_path(sys.executable,inside=runtime)
        if python.name.casefold()!='python.exe':raise ValueError('configuration')
        verified,actor_hash=controller.verify_ac_artifact(actor,manifest,config['manifest_sha256'],config['actor_sha256'])
        if verified!=actor or actor_hash!=config['actor_sha256']:raise ValueError('configuration')
        phase='configuration'
        if shutil.disk_usage(root).free<2*MAX_ACTOR+MAX_PRIVATE:raise ValueError('capacity')
        budget.require_ms(budget.cutoff(5))
        phase='configuration';work=root/'private-proxy-pipe-ac';work.mkdir(exist_ok=False)
        (work/'temp').mkdir(exist_ok=False)
        child=work/'controller'
        command=fixed_command(python,script,actor,manifest,child,config,deadline,frequency)
        phase='create'
        launch=launcher.launch_owned(api,command,work,parent,parent,qpc_budget=budget,
                                     work_cutoff=budget.cutoff(5),cleanup_cutoff=budget.deadline)
        public['facts']['controller_exit_verified']=(launch.get('cleanup',{}).get('process_exit_confirmed') is True
            and type(launch.get('exit_code')) is int and launch['exit_code']==0)
        public['facts']['outer_cleanup_verified']=cleanup_verified(launch)
        phase='report'
        # Never read a live/unknown controller's mutable report, nor take over its ACL/profile cleanup.
        if launch.get('cleanup',{}).get('process_exit_confirmed') is True and launch.get('started') is True:
            path=launcher.checked_path(child/'private-ac.json',inside=work)
            report=decode(launcher.read_private_bytes(path,MAX_PRIVATE))
            projection=bind_controller(report,launch,config,parent,deadline,frequency,controller)
            for key in ('diagnostic','pair','ac_failure'):public[key]=projection[key]
            for key in FACTS:
                if key not in ('current_ordinary_verified','controller_exit_verified','outer_cleanup_verified'):
                    public['facts'][key]=projection['facts'][key]
            public['diagnostic']['controller_report']='bound'
        else:public['ac_failure']='report'
        if ('error' in launch or launch.get('resumed') is not True or launch.get('timed_out') is True):
            public['ac_failure']=public['ac_failure'] or 'create'
    except Exception as exc:
        public['ac_failure']=public['ac_failure'] or ('identity' if phase=='ordinary' else phase)
        public['diagnostic']['phase']=phase
        public['diagnostic']['error_domain']='internal'
        if phase=='report':
            public['diagnostic']['controller_report']='read_error'
            if isinstance(exc,launcher.GateFailure) and str(exc)=='private_report_close_uncertain':
                public['facts']['outer_cleanup_verified']=False
                public['diagnostic']['controller_report']='close_uncertain'
    finally:
        if token is not None:
            owned,token=token,None
            try:api.close(owned)
            except Exception:
                public['facts']['outer_cleanup_verified']=False
                public['ac_failure']=public['ac_failure'] or 'cleanup'
    if budget is not None:
        try:budget.require_ms(budget.deadline)
        except Exception:public['ac_failure']=public['ac_failure'] or 'deadline'
    passed=(all(public['facts'].values()) and pair_passed(public['pair']) and public['ac_failure'] is None
            and diagnostic_passed(public['diagnostic']))
    public['ac_pipe_passed']=passed;public['status']='passed' if passed else 'inconclusive'
    return validate_public(public,config)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',required=True);parser.add_argument('--deadline-qpc',required=True,type=int)
    parser.add_argument('--qpc-frequency',required=True,type=int);args=parser.parse_args(argv)
    try:
        config=configuration(args.config);value=execute(config,args.deadline_qpc,args.qpc_frequency)
        raw=(json.dumps(value,indent=2)+'\n').encode('ascii')
        if len(raw)>MAX_PUBLIC:raise ValueError('report')
        controller_module().launcher.write_private_bytes(ROOT/'public-proxy-pipe-ac.json',raw)
        return 0 if value['ac_pipe_passed'] else 1
    except Exception:return 1


if __name__=='__main__':raise SystemExit(main())
