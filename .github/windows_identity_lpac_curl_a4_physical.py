"""Pure physical task/control and safe observation validation for A4.

The caller supplies the pinned core module. No native construction, clock,
process discovery, mutating operation or project import is performed here.
"""
from pathlib import Path
import re


def physical_record(m,record,path,root):
    m.require(type(record) is dict and set(record)=={'name','text','sha256'}
        and type(record['name']) is str and re.fullmatch(r'[0-9]{3}-[a-z0-9-]{1,64}\.json',record['name'])
        and record['name']==Path(path).name and type(record['text']) is str
        and len(record['text'])<=m.MAX_REPORT and m.base.ac.digest(record['sha256']),'a4_record_schema')
    path=m.launcher.checked_path(path,inside=root)
    raw=record['text'].encode('ascii')
    m.require(m.sha(raw)==record['sha256'] and m.local.bounded(path,m.MAX_REPORT)==raw,'a4_record_physical')
    return m.decode(raw)


def task_validate(m,t,c,parent,root,*,curl):
    require,live,launcher=m.require,m.live,m.launcher
    require(type(t) is dict and set(t)==m.mm.TASK_KEYS
        and all(type(t[k]) is bool for k in m.mm.TASK_BOOLS),'a4_task_schema')
    selected=t['name']=='selected'
    require(t['name'] in ('before','selected','after','grant-root','grant-package','grant-output','remove')
        and t['lpac_expected']==selected and t['lpac'] is None
        and (t['capabilities'] is None or t['capabilities']==[]),'a4_task_role')
    for k in ('pid','created','admission_qpc','resume_qpc','resume_intent_qpc','exit_observed_qpc','constructor_return_qpc'):
        require(t[k] is None or live.integer(t[k],1,0xffffffffffffffff),'a4_task_integer')
    require(t['exit_code'] is None or live.integer(t['exit_code'],0,0xffffffff),'a4_task_exit')
    require(not t['exited'] or t['process_returned'] and t['exit_code'] is not None,'a4_task_exit_binding')
    require(not t['natural_exit'] or t['exited'],'a4_natural_requires_exit')
    require(type(t['held_checks']) is list and len(t['held_checks'])<=24
        and type(t['inherited_handles']) is list,'a4_task_bounds')
    require(not t['admitted'] or t['assigned'] and t['attempted'] and t['process_returned']
        and t['identity'] is not None and t['created'] is not None and t['pid'] is not None
        and t['capabilities']==[] and t['admission_qpc'] is not None,'a4_task_admitted')
    require(not t['resumed'] or t['admitted'] and t['resume_qpc'] is not None,'a4_task_resumed')
    if not curl:
        require(not selected and not t['natural_exit'],'a4_tool_claim')
        if t['admitted']:
            require(launcher.token_is_ordinary(t['identity']) and launcher.same_identity(t['identity'],parent),'a4_tool_ordinary')
        return t
    require(t['image_sha256']==m.CURL_SHA256,'a4_task_image')
    record=t['receipt']
    if record is not None:
        value=physical_record(m,record,Path(root)/'returns'/record['name'],root)
        require(type(value) is dict and set(value)=={'schema_version','scope','run','config_sha256','intent_sha256','action','qpc','data'}
            and type(value['schema_version']) is int and value['schema_version']==1
            and m.base.ac.digest(value['intent_sha256'])
            and live.integer(value['qpc'],c['start_qpc'],c['deadline_qpc']-1),'a4_PI_envelope')
        data=value['data']
        require(value['scope']==m.SCOPE and value['run']==c['run']
            and value['config_sha256']==m.sha(m.encode(c)) and value['action']=='create-'+t['name'],'a4_PI_scope')
        require(type(data) is dict and set(data)<={'creation_attempted','creation_unknown','create_status','raw_return','raw_error','raw_pi','returned_qpc'},'a4_PI_data')
        pi=data.get('raw_pi',[0,0,0,0])
        require(type(pi) is list and len(pi)==4 and all(live.integer(x,0,0xffffffffffffffff) for x in pi),'a4_PI_extent')
        if t['process_returned']:
            require(data.get('create_status')=='returned_true' and type(data.get('raw_return')) is int and data['raw_return']!=0
                and data.get('creation_attempted') is True and data.get('creation_unknown') is False and data.get('raw_error') is None
                and all(pi) and all(0<h<0xffffffffffffffff for h in pi[:2]) and pi[0]!=pi[1]
                and t['pid']==pi[2] and pi[2]<=0xffffffff and pi[3]<=0xffffffff,'a4_PI_owned')
    else:
        require(not t['admitted'],'a4_PI_missing')
    if t['admitted']:
        ob=t['create_observation']
        require(type(ob) is dict and set(ob)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'}
            and ob['status']=='returned_true' and ob['winerror'] is None
            and ob['process_information']=='nonzero' and ob['exception_detail'] is None
            and live.integer(ob['work_cutoff'],c['start_qpc']+1,m.work_cutoff(c)),'a4_create_observation')
        require(data.get('returned_qpc')==ob['returned_qpc'] and type(data.get('returned_qpc')) is int
            and ob['returned_qpc']<=value['qpc']<=t['constructor_return_qpc'],'a4_PI_return_clock_binding')
        require(live.integer(ob['returned_qpc'],c['start_qpc'],ob['work_cutoff']-1)
            and ob['returned_qpc']<=t['constructor_return_qpc']<=t['admission_qpc']<ob['work_cutoff']<=m.work_cutoff(c),'a4_admission_clock')
        require(t['parent_copies_closed'] and len(t['inherited_handles'])==(4 if selected else 3)
            and len(set(t['inherited_handles']))==len(t['inherited_handles'])
            and all(live.integer(h,1,0xfffffffffffffffe) for h in t['inherited_handles']),'a4_handle_list')
        require(type(t['kernel_security']) is dict and set(t['kernel_security'])=={'process','thread'}
            and all(m.private_process_thread_sddl(v,parent['sid']) for v in t['kernel_security'].values()),'a4_private_process_thread')
        primary=t['expected_primary'];m.access.identity_shape(primary)
        if selected:
            m.zero.identity(primary,primary=True)
        else:
            require(not primary['appcontainer'] and primary['appcontainer_sid'] is None and primary['capabilities']==[]
                and primary['token_type']==1 and not primary['elevated'] and not primary['ui_access'],'a4_control_token')
            require(launcher.token_is_ordinary(t['identity']) and launcher.same_identity(t['identity'],parent)
                and primary['integrity_rid']==parent['integrity_rid'],'a4_control_ordinary_parent')
        require(primary['sid']==parent['sid'] and primary['session_id']==parent['session_id']
            and type(primary['token_id']) is int and type(primary['authentication_id']) is int,'a4_primary_binding')
        require(t['identity']['capability_count']==0 and all(t['identity'][k]==primary[k]
            for k in ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access')),'a4_identity_primary_match')
        require(t['held_checks'],'a4_held_missing')
        last_held=t['constructor_return_qpc']
        for held in t['held_checks']:
            require(type(held) is dict and set(held)=={'qpc','pid','created','image_sha256','primary','inner_job','outer_job','kernel_security'}
                and held['pid']==t['pid'] and held['created']==t['created'] and held['image_sha256']==m.CURL_SHA256
                and held['primary']==primary and held['inner_job'] is True and held['outer_job'] is True
                and held['kernel_security']==t['kernel_security']
                and live.integer(held['qpc'],c['start_qpc'],m.work_cutoff(c)-1),'a4_held_binding')
            require(last_held<=held['qpc'],'a4_held_monotonic_after_constructor');last_held=held['qpc']
        require(t['held_checks'][0]['qpc']<=t['admission_qpc'],'a4_held_before_admission')
        if t['resumed']:
            require(live.integer(t['resume_intent_qpc'],t['admission_qpc'],m.work_cutoff(c)-1)
                and t['resume_intent_qpc']<=t['resume_qpc']<ob['work_cutoff'],'a4_resume_causal')
            require(any(t['admission_qpc']<=held['qpc']<=t['resume_intent_qpc'] for held in t['held_checks']),'a4_held_before_resume')
        if t['natural_exit']:
            require(t['resumed'] and live.integer(t['exit_observed_qpc'],t['resume_qpc'],ob['work_cutoff']-1),'a4_exit_causal')
    return t


def validate_ordinary_control(m,value,c,*,role,parent,root):
    require=m.require
    require(role in ('before','after') and type(value) is dict
        and set(value)=={'schema_version','scope','run','config_sha256','parent_sha256','role','case','deadline_qpc','task','output','positive'},'a4_control_schema')
    require(type(value['schema_version']) is int and value['schema_version']==1 and value['scope']==m.SCOPE
        and value['run']==c['run'] and value['config_sha256']==m.sha(m.encode(c))
        and value['parent_sha256']==m.sha(m.encode(parent)) and value['role']==role and value['case']==c[role+'_case'],'a4_control_binding')
    task=task_validate(m,value['task'],c,parent,root,curl=True)
    require(task['name']==role and not task['lpac_expected'],'a4_control_role')
    directory=Path(root)/('ordinary-'+role)
    stdout=m.local.bounded(m.launcher.checked_path(directory/'stdout',inside=root),m.MAX_OUTPUT)
    stderr=m.local.bounded(m.launcher.checked_path(directory/'stderr',inside=root),m.MAX_OUTPUT)
    output=dict(stdout_bytes=len(stdout),stdout_sha256=m.sha(stdout),stderr_bytes=len(stderr),stderr_sha256=m.sha(stderr),
        exact_baseline=len(stdout)==m.BASELINE_BYTES and m.sha(stdout)==m.BASELINE_SHA256 and not stderr)
    require(type(value['output']) is dict and value['output']==output and type(value['positive']) is bool
        and type(value['deadline_qpc']) is int and value['deadline_qpc']==task['create_observation']['work_cutoff'],'a4_control_output')
    positive=task['natural_exit'] and task['exit_code']==0 and output['exact_baseline']
    require(value['positive']==positive,'a4_control_positive');return value


def ordinary_controls(m,root,c,parent):
    result=dict(before=False,after=False)
    for role in result:
        try:
            path=m.launcher.checked_path(Path(root)/('control-'+role+'.json'),inside=root)
            value=m.decode(m.local.bounded(path,m.MAX_REPORT))
            validate_ordinary_control(m,value,c,role=role,parent=parent,root=root)
            result[role]=value['positive']
        except (m.launcher.GateFailure,ValueError,TypeError,KeyError,OSError,OverflowError,UnicodeError):
            pass
    return result


def validate_observation(m,v):
    require=m.require
    require(type(v) is dict and set(v)==m.OBS_KEYS
        and all(type(v[k]) is bool for k in (*m.OBS_BOOLS,*m.FALSE_CLAIMS))
        and v['failure'] in (None,*m.FAILURES)
        and (v['selected_exit_code'] is None or m.live.integer(v['selected_exit_code'],0,0xffffffff))
        and (v['trace_call_count'] is None or m.live.integer(v['trace_call_count'],0,256)),'a4_observation_schema')
    require(not any(v[k] for k in m.FALSE_CLAIMS),'a4_false_claims')
    require(not v['selected_natural_exit'] or v['selected_resumed'],'a4_natural_resume')
    require(not v['selected_version_positive'] or v['selected_natural_exit'] and v['selected_exit_code']==0,'a4_version_requires_zero')
    require(not v['payload_readback_readonly_verified'] or v['payload_carrier_returned_nonnull'],'a4_payload_readback_requires_pointer')
    require(not v['trace_diagnostic_candidate_complete'] or v['trace_header_bound'] and v['trace_stable']
        and m.live.integer(v['trace_call_count'],1,256),'a4_trace_candidate')
    required=('ordinary_before_positive','ordinary_after_positive','lpac_identity_verified','private_memory_sequence_complete',
        'payload_carrier_returned_nonnull','payload_readback_readonly_verified','selected_resumed','trace_header_bound','trace_stable',
        'trace_diagnostic_candidate_complete','selected_natural_exit','selected_version_positive')
    require(not v['startup_diagnostic_observed'] or all(v[k] for k in required),'a4_startup_diagnostic')
    require(not v['observation_complete'] or v['failure'] is None and v['startup_diagnostic_observed']
        and all(v[k] for k in m.CLEAN_KEYS),'a4_complete')
    return v
