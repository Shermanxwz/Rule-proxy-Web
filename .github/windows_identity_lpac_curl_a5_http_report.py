"""Pure A5 HTTP physical review. No process, clock, loader or network API calls.

The owner supplies pinned modules and exact durable constructor/stream records.
The selected curl's bytes, the trace, and the ordinary proxy leg must agree.
Old full startup diagnostic and broad isolation claims remain false.
"""
from pathlib import Path

A5_OBS_ADDITIONS=('selected_HTTP_positive','trace_transport_candidate',
    'ordinary_HTTP_calibration_positive','proxy_transport_positive',
    'finite_HTTP_observed','HTTP_byte_sinks_verified')
FINITE_REQUIRED=('ordinary_before_positive','ordinary_after_positive','lpac_identity_verified',
    'private_memory_sequence_complete','payload_carrier_returned_nonnull',
    'payload_readback_readonly_verified','selected_resumed','trace_header_bound','trace_stable',
    'trace_transport_candidate','selected_natural_exit','selected_HTTP_positive',
    'proxy_transport_positive','HTTP_byte_sinks_verified')
PROXY_KEYS={'scope','run','case','selected_pid','selected_creation','request_bytes',
    'response_bytes','transport_positive','byte_sinks_verified','cleanup_verified'}


def HTTP_inputs(m,c,root):
    """Read this run's independent binary challenges, not calibration bodies."""
    paths=m.http_challenge_paths(root)
    m.require(type(paths) in (tuple,list) and len(paths)==2,'a5_HTTP_challenge_paths')
    request,response=[m.local.bounded(m.launcher.checked_path(p,inside=root),65536) for p in paths]
    port=c['proxy']['ports']['origin_port'];headers=m.config_codec.fixed_headers(c['case'],port)
    values={}
    for name,raw,is_response,header,total in (
            ('request',request,False,headers[0],8193),('response',response,True,headers[1],12289)):
        values[name]=m.proxy_protocol.http_challenge(raw,response=is_response,case=c['case'],origin_port=port)
        m.require(type(raw) is bytes and len(raw)==total and raw.startswith(header),'a5_HTTP_fixed_profile')
    m.require(values==c['proxy']['challenges'],'a5_HTTP_this_run_challenge_pins')
    body=m.local.bounded(m.launcher.checked_path(Path(root)/'package/request-body.bin',inside=root),8065)
    m.require(body==request[128:] and len(headers[0])==128 and len(headers[1])==113,'a5_HTTP_request_body')
    return request,response


def selected_output(m,c,root):
    """Current selected stdout is only the independent response body."""
    _,response=HTTP_inputs(m,c,root)
    directory=Path(root)/'selected-output'
    stdout=m.local.bounded(m.launcher.checked_path(directory/'stdout',inside=root),16384)
    stderr=m.local.bounded(m.launcher.checked_path(directory/'stderr',inside=root),16384)
    return dict(stdout_bytes=len(stdout),stdout_sha256=m.sha(stdout),stderr_bytes=len(stderr),
        stderr_sha256=m.sha(stderr),exact_HTTP_body=len(stdout)==12176 and stdout==response[113:] and not stderr)


def validate_selected_output(m,j,c,root,selected):
    if j['selected_output'] is None:return None
    m.require(selected is not None and selected['exited'],'a5_selected_output_exit')
    output=selected_output(m,c,root)
    m.require(type(j['selected_output']) is dict and j['selected_output']==output,'a5_selected_HTTP_output_physical')
    return output


def reader_review(m,raw,config,c,selected,*,parent,root):
    config_facts=m.trace_reader.validate_config(config,schema_metadata=m.trace_reader.SCHEMA_METADATA)
    observed=m.physical.observed_handles(m,selected,c,parent,root)
    binding=dict(scope=m.SCOPE,config_bytes_sha256=m.sha(config),source_sha256=c['source_sha256'],
        trace_sha256=m.sha(raw),run=c['run'],case_id=c['case'],target_pid=selected['pid'],
        target_creation=selected['created'],inherited_handles=list(selected['inherited_handles']),
        observed_inherited_handles=observed,window_start=config_facts['window_start'],
        window_end=config_facts['window_end'],endpoint=dict(family='IPv4',address='127.0.0.1',
        port=c['proxy']['ports']['origin_port'],protocol='TCP'))
    return m.trace_reader.review(raw,expected_config2048=config,
        schema_metadata=m.trace_reader.SCHEMA_METADATA,transport_binding=binding)


def validate_trace(m,j,c,root,selected,config,returns,*,parent):
    if j['trace_binary'] is None:
        m.require(j['trace_review'] is None,'a5_trace_review_without_binary');return None
    m.require(config is not None and selected is not None and selected['natural_exit'] and selected['resumed']
        and selected['exit_observed_qpc'] is not None,'a5_trace_requires_natural_exit')
    raw=m.read_binary(root,j['trace_binary'],m.TRACE_BYTES)
    m.require(j['trace_binary']['name']=='a5-trace.bin' and len(raw)==m.TRACE_BYTES,'a5_trace_file')
    descriptor=j['trace_review'];m.require(descriptor is not None and descriptor['sha256'] in returns,'a5_trace_return')
    value=returns[descriptor['sha256']];data=value['data'];window=j['window']
    m.require(value['action']=='trace-after-exit' and type(data) is dict
        and set(data)=={'before_qpc','after_qpc','trace_sha256','config_sha256','stable','review'}
        and data['stable'] is True and type(data['before_qpc']) is int and type(data['after_qpc']) is int
        and selected['exit_observed_qpc']<=data['before_qpc']<=data['after_qpc']<=value['qpc']<window['end']
        and data['trace_sha256']==m.sha(raw) and data['config_sha256']==m.sha(config),'a5_trace_causal')
    review=reader_review(m,raw,config,c,selected,parent=parent,root=root)
    m.require(data['review']==review,'a5_trace_independent_projection')
    m.require(review['diagnostic_candidate_complete'] is False,'a5_old_full_diagnostic_stays_false')
    return review


def proxy_review(m,j,c,root,selected,*,parent):
    if j['proxy'] is None:return None
    value=m.validate_proxy_result(j['proxy'],c,parent=parent,root=root,selected=selected)
    m.require(type(value) is dict and set(value)==PROXY_KEYS,'a5_proxy_projection_schema')
    m.require(value['scope']==m.SCOPE and value['run']==c['run'] and value['case']==c['case']
        and all(type(value[k]) is bool for k in ('transport_positive','byte_sinks_verified','cleanup_verified')),
        'a5_proxy_projection_binding')
    if value['transport_positive'] or value['byte_sinks_verified']:
        m.require(selected is not None and type(value['selected_pid']) is int and value['selected_pid']==selected['pid']
            and type(value['selected_creation']) is int and value['selected_creation']==selected['created']
            and type(value['request_bytes']) is int and value['request_bytes']==8193
            and type(value['response_bytes']) is int and value['response_bytes']==12289,
            'a5_proxy_selected_generation_and_bytes')
    return value


def validate_HTTP_calibration(m,c):
    """Optional frozen ordinary calibration fact; never a current-run gate."""
    false=m.trace_reader.review_HTTP_byte_controls(None)
    resolver=getattr(m,'http_calibration_root',None)
    if resolver is None:return false
    directory=resolver(c)
    if directory is None:return false
    directory=m.launcher.checked_path(directory,is_file=False)
    raw=m.local.bounded(m.launcher.checked_path(Path(directory)/'worker-report.json',inside=directory),16384)
    m.require(len(raw)==8812 and m.sha(raw)=='4511ad479dfef705eba47a772ef2406d5a253704e749cfada680d80ebcfa24b9',
        'a5_ordinary_calibration_frozen_report')
    report=m.decode(raw);records=[]
    for index,row in enumerate(report['cases']):
        folder=Path(directory)/('case'+str(index))
        def read(name,limit):return m.local.bounded(m.launcher.checked_path(folder/name,inside=directory),limit)
        request=read('received-request.bin',8193)
        m.require(read('request-body.bin',8065)==request[128:],'a5_calibration_request_body')
        m.require(row['launch']['timed_out'] is False and row['launch']['exit_code']==0,'a5_calibration_natural_zero')
        records.append(dict(case_id=bytes.fromhex(row['case']),origin_port=row['port'],request=request,
            stdout=read('controller.stdout',16384),stderr=read('controller.stderr',16384),
            stdin=read('controller.stdin',1),natural_exit_code=row['launch']['exit_code'],curl_sha256=m.CURL_SHA256))
    return m.trace_reader.review_HTTP_byte_controls(records)


def pipe_bytes_crossbind(m,trace,proxy,root):
    """Crossbind trace raw wire counters to the physically re-read relay report."""
    if trace is None or proxy is None:return False
    facts=trace.get('transport',{}).get('pipe_facts',{})
    record=proxy.get('reports',{}).get('relay')
    if not facts.get('complete') or type(record) is not dict:return False
    m.require(set(record)=={'text','sha256'} and type(record['text']) is str,'a5_pipe_relay_record')
    raw=record['text'].encode('ascii')
    m.require(len(raw)<=32768 and m.sha(raw)==record['sha256'] and m.local.bounded(
        m.launcher.checked_path(Path(root)/'relay-report/actor.json',inside=root),32768)==raw,
        'a5_pipe_relay_physical')
    relay=m.decode(raw);pipe=relay.get('pipe',{})
    return bool(all(type(v.get(key)) is int and v[key]>0 for v in (facts,pipe)
        for key in ('read_bytes','write_bytes')) and facts['read_bytes']==pipe['write_bytes']
        and facts['write_bytes']==pipe['read_bytes'])


def finite_HTTP(v,*,leases_complete,pipe_bytes_bound=False):
    return bool(leases_complete and pipe_bytes_bound is True and all(v.get(key) is True for key in FINITE_REQUIRED))

def validate_result(m,j,c,*,parent,root):
    require,live,launcher,base,local=m.require,m.live,m.launcher,m.base,m.local
    sha,encode,decode=m.sha,m.encode,m.decode
    physical,memory_physical,zero,mm=m.physical,m.memory_physical,m.zero,m.mm
    config_validate,work_cutoff=m.config_validate,m.work_cutoff
    task_validate,validate_api_records=m.task_validate,m.validate_api_records
    _journal_graph,_validate_leases=m._journal_graph,m._validate_leases
    RESULT_KEYS,RESULT_BOOLS,SCOPE,PROFILE=m.RESULT_KEYS,m.RESULT_BOOLS,m.SCOPE,m.PROFILE
    FALSE_CLAIMS,FAILURES,CLEAN_KEYS,MAX_REPORT=m.FALSE_CLAIMS,m.FAILURES,m.CLEAN_KEYS,m.MAX_REPORT
    ordinary_controls=m.ordinary_controls
    config_validate(c);require(launcher.token_is_ordinary(parent),'a5_result_parent');root=Path(root)
    require(type(j) is dict and set(j)==RESULT_KEYS and type(j['schema_version']) is int and j['schema_version']==1
        and j['stage']=='lpac-curl-a5-http-result' and j['scope']==SCOPE and j['profile']==PROFILE
        and j['config_sha256']==sha(encode(c)) and j['failure'] in (None,*FAILURES),'a5_result_schema')
    require(all(type(j[k]) is bool for k in RESULT_BOOLS) and not any(j[k] for k in (*FALSE_CLAIMS,'token_class46_queried','endpoint_created','dns_api_called')),'a5_result_boolean_scope')
    base.validate_failure_detail(j['failure_detail']);require(j['failure'] is not None or j['failure_detail'] is None,'a5_failure_detail')
    require(j['completed_qpc'] is None or live.integer(j['completed_qpc'],c['start_qpc'],(1<<63)-1),'a5_result_clock')
    require(j['completed_qpc'] is not None or j['failure'] is not None,'a5_missing_completed_clock')
    require(j['profile_name']=='ruleproxy-curl-a5-http-'+c['run'] and (j['profile_sid'] is None or base.ac.ac_profile_sid(j['profile_sid'])),'a5_profile_name')
    require(type(j['profile_state']) is dict and set(j['profile_state'])=={'attempted','returned','created','sid_pointer_returned'}
        and all(type(x) is bool for x in j['profile_state'].values()),'a5_profile_state')
    require(not j['profile_created'] or j['profile_state']['created'] and j['profile_sid'] is not None
        and launcher.child_environment_admitted(j['child_environment']),'a5_profile_created')
    require(not j['acl_attempted'] or j['profile_created'],'a5_ACL_scope')
    intents,returns=_journal_graph(j,c,root)
    require(type(j['tasks']) is list and len(j['tasks'])<=6 and type(j['cleanup_tasks']) is list and len(j['cleanup_tasks'])<=1,'a5_task_bounds')
    tasks={}
    for t in j['tasks']:
        task_validate(t,c,parent,root,curl=t['name'] in ('before','selected','after'))
        require(t['name'] not in tasks,'a5_task_duplicate');tasks[t['name']]=t
        if t['receipt'] is not None:require(t['receipt']['sha256'] in returns,'a5_task_return_graph')
        for key in ('constructor_return_qpc','admission_qpc','resume_qpc','exit_observed_qpc'):
            require(t[key] is None or j['completed_qpc'] is None or t[key]<=j['completed_qpc'],'a5_task_before_completion')
    for t in j['cleanup_tasks']:
        task_validate(t,c,parent,root,curl=False);require(t['name']=='remove','a5_cleanup_tool')
    selected=tasks.get('selected');window=j['window']
    if window is not None:
        require(type(window) is dict and set(window)=={'start','end'} and live.integer(window['start'],c['start_qpc'],work_cutoff(c)-1)
            and window['end']==min(window['start']+8*c['frequency'],work_cutoff(c)) and selected is not None
            and selected['admitted'] and selected['admission_qpc']<=window['start'],'a5_window')
    else:
        require(all(j[k] is None for k in ('base_provenance','memory_summary','payload','config_binary','trace_binary','trace_review')),'a5_no_window_partial')
    require(type(j['controls']) is dict and set(j['controls'])=={'before','after'},'a5_control_set')
    for role,d in j['controls'].items():
        if d is not None:
            require(type(d) is dict and set(d)=={'text','sha256'} and type(d['text']) is str and sha(d['text'].encode('ascii'))==d['sha256']
                and local.bounded(launcher.checked_path(root/('control-'+role+'.json'),inside=root),MAX_REPORT)==d['text'].encode('ascii'),'a5_control_physical')
            v=physical.validate_ordinary_control(m,decode(d['text'].encode('ascii')),c,role=role,parent=parent,root=root)
            require(role in tasks and v['task']==tasks[role],'a5_control_task_match')
    require(type(j['proofs']) is list and len(j['proofs'])<=2,'a5_proofs')
    for index,p in enumerate(j['proofs']):
        require(type(p) is dict and set(p)=={'label','intent_sha256','value'} and p['label']==('before-memory','before-resume')[index]
            and p['intent_sha256'] in intents and intents[p['intent_sha256']]['action']=='observe-'+p['label'] and selected is not None,'a5_proof_intent')
        deadline=work_cutoff(c) if index==0 else window['end']
        zero.validate_proof(p['value'],expected_primary_identity=selected['expected_primary'],expected_role='lpac',expected_pid=selected['pid'],
            expected_creation=selected['created'],frequency=c['frequency'],deadline=deadline)
        require(p['value']['start_qpc'] is None or p['value']['start_qpc']>=intents[p['intent_sha256']]['qpc'],'a5_proof_causal')
    count=sum(v['action'].startswith('observe-') for v in intents.values())
    require(not j['observer_resources_cleanup_verified'] or count==len(j['proofs']) and all(p['value']['resource_cleanup_verified'] for p in j['proofs']),'a5_observer_sticky_cleanup')
    if selected is not None and selected['admitted']:
        require(j['profile_created'] and j['acl_attempted'] and selected['expected_primary']['appcontainer_sid']==j['profile_sid'],'a5_selected_profile')
    api=validate_api_records(j,c,root,selected)
    if any(x['operation']=='a5_copy_config_v1' for x in j['api_raw_calls']) and j['payload'] is None:
        require(j['remote_memory_unknown'],'a5_partial_carrier_unknown_retained')
    mem=memory_physical.validate_memory_records(m,j,c,root,selected)
    require(type(mem) is dict and set(mem)=={'base','memory_complete','payload_pointer','payload_readonly','config'}
        and all(type(mem[k]) is bool for k in ('memory_complete','payload_pointer','payload_readonly')),'a5_memory_projection_schema')
    _validate_leases(j,c,returns,selected);trace=validate_trace(m,j,c,root,selected,mem['config'],returns,parent=parent)
    if selected is not None and selected['resumed']:
        require(mem['memory_complete'] and mem['payload_readonly'] and len(j['proofs'])==2
            and all(p['value']['qualified'] and p['value']['resource_cleanup_verified'] for p in j['proofs'])
            and j['proofs'][1]['value']['end_qpc']<=selected['resume_intent_qpc']<window['end'],'a5_resume_authorization')
        d=j['resume_observation'];require(d is not None and d['sha256'] in returns,'a5_resume_return')
        v=returns[d['sha256']];data=v['data'];require(v['action']=='resume-selected' and type(data) is dict
            and set(data)=={'entered','returned','count','error','returned_qpc','clock_error','exception'} and data['entered'] is True
            and data['returned'] is True and type(data['count']) is int and data['count']==1 and data['error'] is None
            and data['returned_qpc']==selected['resume_qpc'] and data['clock_error'] is False and data['exception'] is False
            and data['returned_qpc']<=v['qpc'],'a5_resume_physical')
        if j['payload'] is not None:require(returns[j['payload']['sha256']]['qpc']<=selected['resume_intent_qpc'],'a5_payload_before_resume')
    elif j['resume_observation'] is not None:
        require(j['resume_observation']['sha256'] in returns and returns[j['resume_observation']['sha256']]['action']=='resume-selected'
            and j['failure'] is not None,'a5_failed_resume_partial')
    validate_selected_output(m,j,c,root,selected)
    if j['workload_cleanup']:
        require(j['workload_job_empty'] and not j['creation_unknown'] and all(not t['attempted'] or t['exited'] or mm.known_no_child(t,c) for t in tasks.values()),'a5_workload_cleanup')
    require(not j['selected_exit_confirmed'] or selected is not None and selected['exited'],'a5_selected_exit_claim')
    require(type(j['labels']) is list and len(j['labels'])<=1,'a5_label_set')
    if j['labels']:
        label=j['labels'][0];require(type(label) is dict and set(label)=={'name','attempted','lowered','restored'} and label['name']=='selected-output'
            and label['attempted'] is True and all(type(label[k]) is bool for k in ('lowered','restored')),'a5_label_schema')
        require(not j['labels_restored'] or label['restored'] and any(v['action']=='label-restore' for v in intents.values()),'a5_label_restored')
    if selected is not None and selected['admitted']:
        require(len(j['labels'])==1 and j['labels'][0]['lowered'] and any(v['action']=='label-lower' for v in intents.values())
            and all(name in tasks and tasks[name]['admitted'] and tasks[name]['resumed'] and tasks[name]['exited'] and tasks[name]['exit_code']==0
                for name in ('grant-root','grant-package','grant-output')),'a5_selected_setup')
    proxy=proxy_review(m,j,c,root,selected,parent=parent)
    if j['profile_deleted'] and j['profile_state']['attempted']:
        require(j['profile_created'] and not j['controls_uncertain'] and j['acl_removed'] and j['cleanup_tools'] and j['labels_restored']
            and j['parent_pipe_handles_closed'] and not j['pipe_allocation_unknown']
            and (j['proxy'] is None or proxy is not None and proxy['cleanup_verified'])
            and all(j[k] for k in CLEAN_KEYS if k not in ('profile_deleted','sid_released')) and len(j['cleanup_tasks'])==1
            and all(j['cleanup_tasks'][0][k] for k in ('admitted','resumed','exited')) and j['cleanup_tasks'][0]['exit_code']==0
            and any(v['action']=='acl-remove' for v in intents.values()) and any(v['action']=='profile-delete' for v in intents.values()),'a5_profile_delete_gate')
    pipe_bound=bool(proxy is not None and proxy['transport_positive']
        and pipe_bytes_crossbind(m,trace,j['proxy'],root))
    if j['failure'] is None:
        require(not j['controls_uncertain'] and api['qualified'] and j['completed_qpc']<c['deadline_qpc'] and all(j[k] for k in CLEAN_KEYS) and selected is not None and selected['natural_exit']
            and j['parent_pipe_handles_closed'] and not j['pipe_allocation_unknown']
            and selected['exit_code']==0 and j['selected_output'] is not None and j['selected_output']['exact_HTTP_body']
            and all(ordinary_controls(root,c,parent).values()) and trace is not None and trace['transport']['transport_candidate']
            and proxy is not None and proxy['transport_positive'] and proxy['byte_sinks_verified'] and proxy['cleanup_verified']
            and pipe_bound
            and len(j['lease_checks'])==2 and len(j['proofs'])==2 and all(p['value']['qualified'] for p in j['proofs']),'a5_failure_free_complete')
    return j


def project(m,j,c,*,parent,root):
    validate_result(m,j,c,parent=parent,root=root)
    m.require(set(A5_OBS_ADDITIONS)<=set(m.OBS_BOOLS),'a5_HTTP_observation_fields')
    value=dict(failure=j['failure'],selected_exit_code=None,trace_call_count=None,
        **dict.fromkeys(m.OBS_BOOLS,False),**dict.fromkeys(m.FALSE_CLAIMS,False))
    value.update({key:j[key] for key in m.CLEAN_KEYS})
    controls=m.ordinary_controls(root,c,parent)
    value.update(ordinary_before_positive=controls['before'],ordinary_after_positive=controls['after'])
    selected=next((row for row in j['tasks'] if row['name']=='selected'),None)
    value['lpac_identity_verified']=len(j['proofs'])==2 and all(
        proof['value']['qualified'] and proof['value']['resource_cleanup_verified'] for proof in j['proofs'])
    memory=m.memory_physical.validate_memory_records(m,j,c,root,selected)
    value.update(private_memory_sequence_complete=memory['memory_complete'],
        payload_carrier_returned_nonnull=memory['payload_pointer'],payload_readback_readonly_verified=memory['payload_readonly'])
    if selected is not None:
        value.update(selected_exit_code=selected['exit_code'],selected_resumed=selected['resumed'],
            selected_natural_exit=selected['natural_exit'])
        value['selected_HTTP_positive']=bool(selected['natural_exit'] and selected['exit_code']==0
            and j['selected_output'] is not None and j['selected_output']['exact_HTTP_body'])
    if j['trace_review'] is not None:
        review=m.decode(j['trace_review']['text'].encode('ascii'))['data']['review']
        value.update(trace_header_bound=review['header_bound'],trace_stable=review['stable'],
            trace_call_count=review['row_count'],trace_transport_candidate=review['transport']['transport_candidate'])
    proxy=proxy_review(m,j,c,root,selected,parent=parent)
    if proxy is not None:
        value['proxy_transport_positive']=proxy['transport_positive']
        value['HTTP_byte_sinks_verified']=bool(proxy['byte_sinks_verified'] and value['selected_HTTP_positive'])
    value['ordinary_HTTP_calibration_positive']=validate_HTTP_calibration(m,c)['byte_controls_candidate']
    pipe_bound=bool(proxy is not None and proxy['transport_positive'] and j['trace_review'] is not None
        and pipe_bytes_crossbind(m,review,j['proxy'],root))
    value['finite_HTTP_observed']=finite_HTTP(value,leases_complete=len(j['lease_checks'])==2,pipe_bytes_bound=pipe_bound)
    value['observation_complete']=bool(j['failure'] is None and value['finite_HTTP_observed']
        and all(value[key] for key in m.CLEAN_KEYS) and proxy is not None and proxy['cleanup_verified'])
    # The four retained closed loader rejections make the A4 full diagnostic
    # false even when the new, strictly narrower finite HTTP facts are complete.
    value.update(selected_version_positive=False,startup_diagnostic_observed=False,
        trace_diagnostic_candidate_complete=False)
    return m.physical.validate_observation(m,value)

