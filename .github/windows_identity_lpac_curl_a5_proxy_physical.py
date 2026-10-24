"""A5 ordinary proxy physical validator; file reads and pure validation only.

Native A2 relay/origin reports keep their actual schemas. No invented selected
actor report, no native imports, and no worker boolean can authorize a positive.
"""
from pathlib import Path

ROLES=('ordinary-pipe-relay','ordinary-origin-fixture','mihomo-config-check','mihomo-core')
CORE_ROLES=ROLES[2:]
REPORT_PATHS={'ready':'origin-report/ready.json','relay':'relay-report/actor.json','origin':'origin-report/actor.json'}
BARRIER_PATHS={'arm':'origin-control/phase.bin','ack':'origin-report/request-held.json','release':'origin-control/response-go.bin'}
STDIO_KEYS={'role','kind','handle','confirmed','receipt','open_call_sha256','open_intent','open_receipt'}


def _record(m,descriptor,path,root,limit=32768):
    m.require(type(descriptor) is dict and set(descriptor)=={'text','sha256'}
        and type(descriptor['text']) is str and len(descriptor['text'])<=limit,'a5_proxy_raw_record')
    raw=descriptor['text'].encode('ascii')
    m.require(m.sha(raw)==descriptor['sha256'] and m.local.bounded(
        m.launcher.checked_path(Path(root)/path,inside=root),limit)==raw,'a5_proxy_physical_record')
    return m.decode(raw)


def _returned(m,descriptor,returns,action):
    m.require(type(descriptor) is dict and set(descriptor)=={'name','text','sha256'}
        and descriptor['sha256'] in returns,'a5_proxy_journal_return')
    value=returns[descriptor['sha256']]
    m.require(value['action']==action and m.decode(descriptor['text'].encode('ascii'))==value,
        'a5_proxy_return_action');return value


def _config_view(c):
    p=c['proxy'];value=dict(c)
    value.update(ports=p['ports'],challenges=p['challenges'],mihomo_config_sha256=p['mihomo_config_sha256'],
        mihomo_sha256=p['artifacts']['mihomo']['sha256'],network_actor_sha256=p['artifacts']['network_actor']['sha256'],
        network_manifest_sha256=p['artifacts']['network_manifest']['sha256'])
    return value


def _task(m,row,c,parent,root,epoch,intents,returns):
    require,integer=m.require,m.live.integer
    extra={'role','command','ends','resume_receipt'}
    require(type(row) is dict and set(row)==m.mm.TASK_KEYS|extra and row['role'] in ROLES
        and row['name']==row['role'] and all(type(row[k]) is bool for k in m.mm.TASK_BOOLS),'a5_proxy_task_shape')
    role=row['role'];relay=role==ROLES[0];core=role in CORE_ROLES
    end=epoch['start']+8*c['frequency'] if relay else m.work_cutoff(c)
    require(all(row[k] for k in ('attempted','assigned','process_returned','admitted','resumed','exited'))
        and row['lpac_expected'] is False and row['lpac'] is None and row['capabilities']==[],
        'a5_proxy_task_complete')
    require(integer(row['pid'],1,0xffffffff) and integer(row['created'],1,0xffffffffffffffff)
        and row['image_sha256']==c['proxy']['artifacts']['mihomo' if core else 'network_actor']['sha256'],
        'a5_proxy_task_generation')
    require(row['natural_exit'] is (role!='mihomo-core') and type(row['exit_code']) is int
        and row['exit_code']==(1 if role=='mihomo-core' else 0),'a5_proxy_exit_kind')
    require(m.launcher.token_is_ordinary(row['identity']) and m.launcher.same_identity(row['identity'],parent),
        'a5_proxy_ordinary_identity')
    primary=row['expected_primary'];m.access.identity_shape(primary)
    require(primary['sid']==parent['sid'] and primary['session_id']==parent['session_id']
        and primary['token_type']==1 and primary['capabilities']==[] and primary['appcontainer'] is False
        and primary['appcontainer_sid'] is None and primary['elevated'] is False and primary['ui_access'] is False
        and primary['integrity_rid']==parent['integrity_rid'],'a5_proxy_primary')
    require(row['identity']['capability_count']==0 and all(row['identity'][key]==primary[key]
        for key in ('sid','session_id','token_type','appcontainer','appcontainer_sid','integrity_rid','elevated','ui_access')),
        'a5_proxy_primary_identity_binding')
    security=row['kernel_security']
    require(type(security) is dict and set(security)=={'process','thread'}
        and all(m.private_process_thread_sddl(value,parent['sid']) for value in security.values()),'a5_proxy_kernel_security')
    ob=row['create_observation']
    require(type(ob) is dict and set(ob)=={'status','winerror','process_information','returned_qpc','work_cutoff','exception_detail'}
        and ob['status']=='returned_true' and ob['winerror'] is None and ob['process_information']=='nonzero'
        and ob['exception_detail'] is None and type(ob['work_cutoff']) is int and ob['work_cutoff']==end,
        'a5_proxy_create_observation')
    value=_returned(m,row['receipt'],returns,'create-'+role);data=value['data']
    require(type(data) is dict and set(data)=={'creation_attempted','creation_unknown','create_status','raw_return',
        'raw_error','raw_pi','returned_qpc','handle_list','stdio','handle_flags','inherit_handles'},'a5_proxy_PI_data')
    pi=data['raw_pi'];require(type(pi) is list and len(pi)==4
        and all(integer(x,1,0xfffffffffffffffe if i<2 else 0xffffffff) for i,x in enumerate(pi))
        and pi[0]!=pi[1] and pi[2]==row['pid'],'a5_proxy_PI_owned')
    require(data['creation_attempted'] is True and data['creation_unknown'] is False
        and data['create_status']=='returned_true' and type(data['raw_return']) is int and data['raw_return']!=0
        and data['raw_error'] is None and data['returned_qpc']==ob['returned_qpc'],'a5_proxy_raw_create_success')
    handles=data['handle_list'];count=2 if relay else 3 if core else 0
    require(type(handles) is list and len(handles)==count and len(set(handles))==count
        and all(integer(h,1,0xfffffffffffffffe) for h in handles) and handles==row['inherited_handles']
        and type(data['handle_flags']) is list and len(data['handle_flags'])==count
        and all(type(flag) is int and flag==1 for flag in data['handle_flags'])
        and data['inherit_handles'] is (count>0),'a5_proxy_actual_HANDLE_LIST')
    require(type(data['stdio']) is list and all(type(h) is int for h in data['stdio'])
        and data['stdio']==(handles if core else [0,0,0]) and row['ends']==handles
        and row['parent_copies_closed'],'a5_proxy_actual_stdio_and_ends')
    require(integer(ob['returned_qpc'],epoch['start'] if relay else c['start_qpc'],end-1)
        and ob['returned_qpc']<=value['qpc']<=row['constructor_return_qpc']<=row['admission_qpc']
        <=row['resume_intent_qpc']<=row['resume_qpc']<=row['exit_observed_qpc']<end,'a5_proxy_task_causal')
    held=row['held_checks'];require(type(held) is list and 1<=len(held)<=64,'a5_proxy_held_count')
    previous=row['constructor_return_qpc']
    for snapshot in held:
        require(type(snapshot) is dict and set(snapshot)=={'qpc','pid','created','image_sha256','primary','inner_job','outer_job','kernel_security'}
            and all(snapshot[key]==row[key] for key in ('pid','created','image_sha256','kernel_security'))
            and snapshot['primary']==primary and snapshot['inner_job'] is True and snapshot['outer_job'] is True
            and integer(snapshot['qpc'],previous,end-1),'a5_proxy_held_exact_child')
        previous=snapshot['qpc']
    require(held[0]['qpc']<=row['admission_qpc']
        and any(row['admission_qpc']<=item['qpc']<=row['resume_intent_qpc'] for item in held),'a5_proxy_held_before_resume')
    resume=_returned(m,row['resume_receipt'],returns,'resume-proxy-'+role)
    intent=intents[resume['intent_sha256']];raw=resume['data']
    require(intent['qpc']==row['resume_intent_qpc'] and type(raw) is dict
        and set(raw)=={'entered','returned','count','error','returned_qpc','clock_error','exception'}
        and raw['entered'] is True and raw['returned'] is True and type(raw['count']) is int and raw['count']==1
        and raw['error'] is None and raw['clock_error'] is False and raw['exception'] is False
        and raw['returned_qpc']==row['resume_qpc'] and raw['returned_qpc']<=resume['qpc']<end,'a5_proxy_resume_raw')
    # The pure argv helper is supplied by the source-pinned proxy module.
    pair=dict(start=epoch['start'],relay_end=epoch['end'],relay_ends=row['ends']) if relay else None
    require(row['command']==m.proxy_leg.expected_argv(role,root,c,parent,pair),'a5_proxy_fixed_argv')
    return row


def _native(m,p,c,parent,root,rows):
    a=m.proxy_protocol;view=dict(p,profile_sid=None);cv=_config_view(c);reports={}
    for key,path in REPORT_PATHS.items():
        reports[key]=_record(m,p['reports'][key],path,root)
        a.validate_native(key,reports[key],view,cv,parent)
        m.require(p['report_status'][key]=='valid','a5_proxy_native_status')
    relay,origin=reports['relay'],reports['origin']
    for value in (relay,origin):
        m.require(value['failure'] is None and value['win32_error'] is None and value['wsa_error'] is None,
            'a5_proxy_native_success')
        for kind,total in (('request',8193),('response',12289)):
            h=value['http'][kind]
            m.require(h['configured'] and h['header_verified'] and h['message_complete'] and h['failure'] is None
                and h['total_bytes']==total and h['content_length']==h['body_bytes']
                and h['header_bytes']+h['body_bytes']==total,'a5_proxy_exact_HTTP')
    m.require(a.stream.protocol_passed(relay,False,cv),'a5_proxy_relay_RPS1')
    for direction,frames,payload in (('write_bytes','tx_frames','tx_payload_bytes'),('read_bytes','rx_frames','rx_payload_bytes')):
        m.require(relay['pipe'][direction]==relay['stream'][frames]*64+relay['stream'][payload],'a5_proxy_relay_wire_count')
    socks=relay['socks']
    m.require(socks['handshake_complete'] and socks['method_noauth_verified'] and socks['reply_ipv4_loopback_listener_verified']
        and socks['origin_dial_proven'] is False and socks['failure'] is None
        and [socks[key] for key in ('greeting_bytes_sent','method_bytes_received','connect_bytes_sent',
        'reply_bytes_received','handshake_wire_sent','handshake_wire_received')]==[3,2,10,10,13,12],
        'a5_proxy_exact_SOCKS')
    ra,oa=relay['http']['adapter'],origin['http']['adapter']
    m.require(all(ra[k] for k in a.RELAY_ADAPTER-{'request_fin_is_tcp_fin'}) and ra['request_fin_is_tcp_fin'] is False
        and all(oa[k] for k in a.ORIGIN_ADAPTER-{'request_eof_observed'}) and oa['request_eof_observed'] is False,
        'a5_proxy_message_boundary')
    rn,on=relay['network'],origin['network'];ports=c['proxy']['ports']
    m.require(all(rn[k] for k in ('wsa_startup','wsa_cleanup','socket_created','connect_attempted','connect_completed',
        'peer_loopback','send_shutdown','receive_eof')) and rn['socket_close']=='confirmed'
        and rn['listener_close']=='not_attempted' and rn['bytes_sent']==8206 and rn['bytes_received']==12301
        and rn['peer_port']==ports['proxy_port'],'a5_proxy_relay_transport')
    m.require(all(on[k] for k in ('wsa_startup','wsa_cleanup','listener_created','exclusive','bind_loopback',
        'accepted','peer_loopback','send_shutdown')) and on['socket_close']==on['listener_close']=='confirmed'
        and on['bytes_sent']==12289 and on['bytes_received']==8193 and on['local_port']==on['port']==ports['origin_port'],
        'a5_proxy_origin_transport')
    for key,role in (('relay',ROLES[0]),('origin',ROLES[1])):
        row=rows[role];m.require(row['resume_qpc']<=reports[key]['qpc'][3]<=row['exit_observed_qpc']<p['pair']['end'],
            'a5_proxy_native_held_exit_causal')
    return reports


def _tcp_and_barrier(m,p,c,parent,root,rows,reports,intents,selected):
    a=m.proxy_protocol;cv=_config_view(c);require=m.require;pair=p['pair'];commands=p['barrier_commands']
    require(set(p['tcp'])=={'listeners','two_hop'} and set(commands)=={'arm','release'},'a5_proxy_TCP_barrier_complete')
    ack=_record(m,p['barrier_ack'],BARRIER_PATHS['ack'],root)
    a.validate_ack(ack,cv,pair,origin_pid=rows[ROLES[1]]['pid'],arm_issued=commands['arm']['issued_qpc'])
    for key,descriptor in p['tcp'].items():
        name='listeners.bin' if key=='listeners' else 'two-hop.bin'
        require(descriptor['name']==name,'a5_proxy_TCP_path')
        raw=m.local.bounded(m.launcher.checked_path(Path(root)/'tcp'/name,inside=root),1048576)
        args=dict(proxy_pid=rows['mihomo-core']['pid'],origin_pid=rows[ROLES[1]]['pid'],declared=cv['ports'])
        expected=a.exact_listeners(raw,**args) if key=='listeners' else a.exact_two_hop(raw,
            relay_pid=rows[ROLES[0]]['pid'],origin_peer_port=ack['peer_port'],**args)
        a.validate_tcp_record(descriptor,root=root,expected_rows=expected)
        require(m.live.integer(descriptor['before_qpc'],c['start_qpc'],m.work_cutoff(c)-1)
            and m.live.integer(descriptor['after_qpc'],descriptor['before_qpc'],m.work_cutoff(c)-1),'a5_proxy_TCP_clock')
        for role in (ROLES[1],'mihomo-core',ROLES[0]) if key=='two_hop' else (ROLES[1],'mihomo-core'):
            held=rows[role]['held_checks']
            require(any(h['qpc']<=descriptor['before_qpc'] for h in held)
                and any(h['qpc']>=descriptor['after_qpc'] for h in held),'a5_proxy_TCP_held_brackets')
    for key,value in commands.items():
        require(type(value) is dict and set(value)=={'path','hex','sha256','issued_qpc','intent_qpc','published_qpc'}
            and value['path']==BARRIER_PATHS[key] and type(value['hex']) is str and len(value['hex'])==256,'a5_proxy_barrier_record')
        raw=bytes.fromhex(value['hex']);expected=a.barrier_control(cv,pair,value['issued_qpc'],release=key=='release',ack=ack if key=='release' else None)
        require(raw==expected and m.sha(raw)==value['sha256'] and m.local.bounded(
            m.launcher.checked_path(Path(root)/value['path'],inside=root),128)==raw,'a5_proxy_barrier_physical')
        found=[entry for entry in intents.values() if entry['action']=='proxy-barrier-'+key]
        require(len(found)==1 and found[0]['qpc']==value['intent_qpc']
            and value['intent_qpc']<=value['issued_qpc']<=value['published_qpc']<pair['end'],'a5_proxy_barrier_intent')
    require(commands['arm']['published_qpc']<=min(selected['resume_intent_qpc'],rows[ROLES[0]]['resume_intent_qpc']),
        'a5_proxy_arm_before_both_resume')
    barrier=a.validate_barrier(reports['origin']['barrier'],cv,pair);tcp=p['tcp']['two_hop'];release=commands['release']
    require(all(barrier[k] for k in a.BARRIER_FLAGS) and barrier['failure'] is None and barrier['ack_qpc']==ack['qpc'][3]
        and barrier['phase_issued_qpc']==ack['phase_issued_qpc'] and barrier['response_bytes_before_release']==0
        and barrier['release_issued_qpc']==release['issued_qpc'],'a5_proxy_release_gate')
    require(ack['qpc'][3]<=tcp['before_qpc']<=tcp['after_qpc']<=release['intent_qpc']<=release['issued_qpc']
        <=barrier['release_admitted_qpc']<=barrier['response_started_qpc']<=reports['origin']['qpc'][3]<pair['end']
        and barrier['release_admitted_qpc']<ack['wait_deadline_qpc'],'a5_proxy_release_causal')
    capture=tcp['rows'];rn=reports['relay']['network'];on=reports['origin']['network']
    require(rn['local_port']==capture['relay']['local_port'] and rn['peer_port']==capture['relay']['remote_port']
        and on['peer_port']==capture['proxy_out']['local_port']==ack['peer_port']
        and on['local_port']==capture['origin']['local_port'],'a5_proxy_native_kernel_crossbind')


def _sinks(m,p,c,root,reports):
    paths=m.proxy_protocol.SINK_PATHS
    expected_keys={'relay_request','relay_response','origin_request','origin_response'}
    m.require(set(p['physical_sinks'])==expected_keys,'a5_proxy_four_actual_sinks')
    for key in expected_keys:
        descriptor=p['physical_sinks'][key];kind='request' if key.endswith('request') else 'response'
        m.require(type(descriptor) is dict and set(descriptor)=={'path','bytes','sha256'}
            and descriptor['path']==paths[key],'a5_proxy_sink_descriptor')
        raw=m.local.bounded(m.launcher.checked_path(Path(root)/descriptor['path'],inside=root),65536)
        m.require({'bytes':len(raw),'sha256':m.sha(raw)}==c['proxy']['challenges'][kind]
            =={k:descriptor[k] for k in ('bytes','sha256')},'a5_proxy_sink_physical_bytes')
    for role,slot,kind in (('relay','request_sink','request'),('relay','response_sink','response'),
            ('origin','source','response'),('origin','request_sink','request'),('origin','response_sink','response')):
        file=reports[role]['files'][slot]
        m.require(file['attempted'] and file['opened'] and file['close']=='confirmed'
            and file['bytes']==c['proxy']['challenges'][kind]['bytes'] and file['flushed']==(slot!='source'),
            'a5_proxy_native_files_closed')


def _api_calls(m,physical,c,root):
    """Read each raw call descriptor; the owner's API graph separately owns it."""
    require=m.require;intents={};calls={};prefix=[]
    require(all(type(physical[key]) is list and len(physical[key])<=384
        for key in ('api_intents','api_calls','api_raw_calls')),'a5_proxy_API_bounds')
    for index,d in enumerate(physical['api_intents']):
        require(d['name']=='%03d-intent.json'%index,'a5_proxy_API_intent_name')
        value=_record(m,{k:d[k] for k in ('text','sha256')},'api-calls/'+d['name'],root,m.MAX_REPORT)
        require(set(value)=={'schema_version','scope','run','config_sha256','index','operation','arguments','qpc'}
            and type(value['schema_version']) is int and value['schema_version']==1 and value['scope']==m.SCOPE
            and value['run']==c['run'] and value['config_sha256']==m.sha(m.encode(c))
            and type(value['index']) is int and value['index']==index,'a5_proxy_API_intent_scope')
        intents[d['sha256']]=value
    for index,d in enumerate(physical['api_calls']):
        require(d['name']=='%03d-return.json'%index,'a5_proxy_API_return_name')
        value=_record(m,{k:d[k] for k in ('text','sha256')},'api-calls/'+d['name'],root,m.MAX_REPORT)
        require(set(value)=={'schema_version','scope','run','config_sha256','index','call','output'}
            and type(value['schema_version']) is int and value['schema_version']==1 and value['scope']==m.SCOPE
            and value['run']==c['run'] and value['config_sha256']==m.sha(m.encode(c))
            and type(value['index']) is int and value['index']==index,'a5_proxy_API_return_scope')
        call=m._raw_api_shape(value['call'],c);out=m.read_binary(root,value['output'],4096)
        require(value['output']['name']=='api-%03d.bin'%index and len(out)==call['output_bytes']
            and m.sha(out)==call['output_sha256'],'a5_proxy_API_output_binding')
        if call['intent_sha256'] is not None:
            require(call['intent_sha256'] in intents,'a5_proxy_API_prior_intent')
            prior=intents[call['intent_sha256']]
            require(prior['operation']==call['operation'] and prior['arguments']==call['arguments']
                and (prior['qpc'] is None or call['entered_qpc'] is not None and prior['qpc']<=call['entered_qpc']),
                'a5_proxy_API_intent_causal')
        calls[d['sha256']]=call;prefix.append(call)
    require(physical['api_raw_calls']==prefix,'a5_proxy_all_API_committed')
    return calls


def _close(m,descriptor,returns,calls,action,handle,earliest,latest,used):
    value=_returned(m,descriptor,returns,action);data=value['data']
    m.require(type(data) is dict and set(data)=={'handle','confirmed','call_sha256'}
        and type(data['handle']) is int and data['handle']==handle and data['confirmed'] is True
        and data['call_sha256'] in calls and data['call_sha256'] not in used,'a5_proxy_close_receipt')
    call=calls[data['call_sha256']];used.add(data['call_sha256'])
    m.require(call['operation']=='CloseHandle(A5_external)' and call['arguments']=={'handle':handle}
        and call['admission_known'] and call['entered'] and call['returned'] and call['clock_known'] and call['timely']
        and type(call['raw_return']) is int and call['raw_return']!=0 and call['error_captured']
        and all(call[key] is None for key in ('native_exception','error_exception','output_error','clock_error'))
        and call['outputs']=={} and call['output_bytes']==0 and call['output_sha256']==m.sha(b'')
        and call['intent_sha256'] is not None and not call.get('adoption_failed',False)
        and earliest<=call['entered_qpc']<=call['post_call_qpc']<=value['qpc']<latest,'a5_proxy_close_raw_success')
    return value['qpc']


def _stdio_open(m,item,root,intents,returns,calls,used):
    require=m.require;require(type(item) is dict and set(item)==STDIO_KEYS
        and item['role'] in CORE_ROLES and item['kind'] in ('stdin','stdout','stderr')
        and m.live.integer(item['handle'],1,0xfffffffffffffffe),'a5_proxy_stdio_open_shape')
    value=_returned(m,item['open_receipt'],returns,'open-core-stdio');data=value['data']
    require(type(data) is dict and set(data)=={'role','kind','handle','call_sha256'}
        and all(data[key]==item[key] for key in ('role','kind','handle'))
        and data['call_sha256']==item['open_call_sha256'] and data['call_sha256'] in calls
        and data['call_sha256'] not in used,'a5_proxy_stdio_open_receipt')
    used.add(data['call_sha256']);call=calls[data['call_sha256']]
    intent=item['open_intent'];require(intent['sha256']==value['intent_sha256']
        and m.decode(intent['text'].encode('ascii'))==intents[value['intent_sha256']],
        'a5_proxy_stdio_open_intent')
    require(call['operation']=='CreateFileW(A5_stdio)' and call['arguments']=={
        'path':str(Path(root)/item['role']/item['kind']),'read':item['kind']=='stdin'}
        and call['entered'] is True and call['returned'] is True and type(call['raw_return']) is int
        and call['raw_return']==item['handle'] and call['native_exception'] is None
        and call['outputs']=={} and call['output_bytes']==0 and call['output_sha256']==m.sha(b'')
        and not call.get('adoption_failed',False),'a5_proxy_stdio_actual_open_authority')
    return value['qpc']


def _pipes_and_stdio(m,p,c,root,selected,rows,intents,returns,calls):
    require=m.require;physical=p['physical'];allocations=physical['pipe_allocations'];allocated=[];opened={};used=set()
    require(type(allocations) is list and len(allocations)==2,'a5_proxy_two_pipe_allocations')
    for index,item in enumerate(allocations):
        name=('response','request')[index]
        require(type(item) is dict and set(item)=={'name','intent','observation','receipt'} and item['name']==name,
            'a5_proxy_pipe_state')
        value=_returned(m,item['receipt'],returns,'allocate-pipe-'+name);ob=item['observation']
        require(type(ob) is dict and set(ob)=={'attempted','returned','api_success','error','raw_outputs','unknown',
            'adopted','readback','return_qpc','allocation_size'} and value['data']==ob
            and all(ob[k] is True for k in ('attempted','returned','api_success','adopted','readback'))
            and ob['unknown'] is False and ob['error'] in (None,0)
            and type(ob['allocation_size']) is int and ob['allocation_size']==65536,'a5_proxy_pipe_raw_success')
        descriptor=item['intent'];require(descriptor['sha256']==value['intent_sha256'] and descriptor['sha256'] in intents
            and m.decode(descriptor['text'].encode('ascii'))==intents[descriptor['sha256']],'a5_proxy_pipe_intent')
        ticks=intents[descriptor['sha256']]['qpc'];raw=ob['raw_outputs']
        require(type(raw) is list and len(raw)==2 and all(m.live.integer(h,1,0xfffffffffffffffe) for h in raw)
            and len(set((*allocated,*raw)))==len(allocated)+2
            and c['start_qpc']<=ticks<=ob['return_qpc']<=value['qpc']<=selected['constructor_return_qpc'],
            'a5_proxy_pipe_extent_clock')
        allocated.extend(raw);opened.update({handle:value['qpc'] for handle in raw})
    relay=rows[ROLES[0]]
    # The caller's physical task validator has already bound the six selected
    # construction inputs to its sealed receipt; re-read that descriptor here.
    selected_create=_returned(m,selected['receipt'],returns,'create-selected')
    observed=m.physical.constructor_handles(m,selected_create['data'],selected,selected=True)
    require(observed[1:3]==[allocated[0],allocated[3]] and relay['ends']==[allocated[2],allocated[1]],
        'a5_proxy_actual_pipe_direction')
    closes=physical['parent_pipe_closes'];require(type(closes) is list and len(closes)==4
        and {row['handle'] for row in closes}==set(allocated),'a5_proxy_four_parent_pipe_closes')
    latest=min(selected['resume_intent_qpc'],relay['resume_intent_qpc'])
    for row in closes:
        require(type(row) is dict and set(row)=={'handle','intent','receipt'},'a5_proxy_parent_close_shape')
        value=_returned(m,row['receipt'],returns,'close-parent-pipe')
        require(row['intent']['sha256']==value['intent_sha256']
            and m.decode(row['intent']['text'].encode('ascii'))==intents[value['intent_sha256']],
            'a5_proxy_parent_close_intent')
        _close(m,row['receipt'],returns,calls,'close-parent-pipe',row['handle'],opened[row['handle']],latest,used)
    stdio=p['core_stdio'];require(type(stdio) is list and len(stdio)==6,'a5_proxy_six_core_stdio_closes')
    for role in CORE_ROLES:
        row=rows[role];items=[item for item in stdio if item['role']==role]
        require(len(items)==3 and {item['kind'] for item in items}=={'stdin','stdout','stderr'}
            and {item['handle'] for item in items}==set(row['inherited_handles']),'a5_proxy_core_stdio_binding')
        for item in items:
            require(type(item) is dict and set(item)==STDIO_KEYS
                and item['confirmed'] is True,'a5_proxy_core_stdio_record')
            opened=_stdio_open(m,item,root,intents,returns,calls,used)
            require(item['handle']==row['inherited_handles'][('stdin','stdout','stderr').index(item['kind'])],
                'a5_proxy_stdio_slot_binding')
            _close(m,item['receipt'],returns,calls,'close-core-stdio',item['handle'],
                max(opened,row['create_observation']['returned_qpc']),row['admission_qpc']+1,used)


def _leases(m,p,c,rows,intents):
    a=m.proxy_protocol;require=m.require;lease=p['port_lease'];cv=_config_view(c)
    require(type(lease) is dict and set(lease)=={'calls','closes','unknown','started','cleanup_attempted','cleanup_confirmed'}
        and all(type(lease[k]) is bool for k in ('unknown','started','cleanup_attempted','cleanup_confirmed')),
        'a5_proxy_lease_shape')
    require(type(lease['calls']) is list and len(lease['calls'])==12 and type(lease['closes']) is list
        and len(lease['closes'])==2,'a5_proxy_lease_complete')
    for row in lease['calls']:
        require(type(row) is dict and set(row)=={'operation','returned','value','return_qpc','exception'}
            and type(row['returned']) is type(row['exception']) is bool
            and m.live.integer(row['return_qpc'],c['start_qpc'],m.work_cutoff(c)-1),'a5_proxy_lease_call')
    for row in lease['closes']:
        require(type(row) is dict and set(row)=={'port_key','attempted','confirmed','value','return_qpc','exception'}
            and row['port_key'] in c['proxy']['ports'] and row['attempted'] is True
            and type(row['confirmed']) is type(row['exception']) is bool,'a5_proxy_lease_close')
    known,successful,cleanup=a.lease_facts(lease,cv)
    require(known and successful and lease['started'] and len(cleanup)==1,'a5_proxy_raw_lease_success')
    entries=[v for v in intents.values() if v['action']=='proxy-port-leases']
    require(len(entries)==1 and entries[0]['qpc']<=lease['calls'][0]['return_qpc'],'a5_proxy_lease_intent')
    for row in lease['closes']:
        role=ROLES[1] if row['port_key']=='origin_port' else 'mihomo-core'
        require(m.live.integer(row['return_qpc'],c['start_qpc'],rows[role]['resume_intent_qpc']),
            'a5_proxy_lease_before_listener')
    require(cleanup[0]['return_qpc']<=rows['mihomo-core']['resume_intent_qpc'],'a5_proxy_WSACleanup_before_core')


def _core_stop(m,p,c,rows,intents,returns):
    require=m.require;stop=p['core_stop'];row=rows['mihomo-core']
    require(type(stop) is dict and set(stop)=={'role','pid','created','image_sha256','intent_qpc','receipt','observation',
        'observed_exit_qpc','exit_code'} and stop['role']=='mihomo-core'
        and all(stop[key]==row[key] for key in ('pid','created','image_sha256','exit_code')),'a5_proxy_stop_exact_child')
    value=_returned(m,stop['receipt'],returns,'proxy-core-stop');intent=intents[value['intent_sha256']]
    raw=stop['observation'];require(value['data']==raw and intent['qpc']==stop['intent_qpc']
        and p['completion_qpc']<=stop['intent_qpc'],'a5_proxy_stop_after_data')
    require(type(raw) is dict and set(raw)=={'attempted','returned','raw_return','error','returned_qpc','exception'}
        and raw['attempted'] is True and raw['returned'] is True and type(raw['raw_return']) is int and raw['raw_return']!=0
        and type(raw['error']) is int and raw['error']==0 and raw['exception'] is None
        and stop['intent_qpc']<=raw['returned_qpc']<=value['qpc']<=stop['observed_exit_qpc']<m.work_cutoff(c)
        and stop['observed_exit_qpc']==row['exit_observed_qpc'] and stop['exit_code']==1,'a5_proxy_stop_raw_success')
    require(any(stop['intent_qpc']<=h['qpc']<=raw['returned_qpc'] for h in row['held_checks']),
        'a5_proxy_stop_fresh_identity')


def _cleanup(m,p,c,root,intents,returns,calls):
    """Known ownership closure is independent of HTTP or natural exit success."""
    require=m.require;constructors={};rows={};used=set()
    for row in p['tasks']:
        require(type(row) is dict and set(row)==m.mm.TASK_KEYS|{'role','command','ends','resume_receipt'}
            and row['role'] in ROLES and row['name']==row['role'] and row['role'] not in rows
            and all(type(row[k]) is bool for k in m.mm.TASK_BOOLS),'a5_proxy_cleanup_task')
        rows[row['role']]=row
        if row['receipt'] is None:
            require(not any(row[k] for k in ('attempted','process_returned','resumed','admitted','exited')),
                'a5_proxy_cleanup_unreceipted_child');continue
        value=_returned(m,row['receipt'],returns,'create-'+row['role']);data=value['data'];constructors[row['role']]=data
        require(type(data) is dict and data.get('creation_unknown') is False,'a5_proxy_cleanup_creation_known')
        if data.get('creation_attempted') is False:
            require(data.get('create_status')=='not_entered' and not row['attempted']
                and not row['process_returned'] and not any(data.get('raw_pi',[0,0,0,0])),
                'a5_proxy_cleanup_create_not_entered');continue
        pi=data.get('raw_pi');require(type(pi) is list and len(pi)==4
            and all(type(value) is int for value in pi),'a5_proxy_cleanup_PI_shape')
        require(row['attempted'] and m.live.integer(data.get('returned_qpc'),c['start_qpc'],value['qpc']),
            'a5_proxy_cleanup_return_clock')
        if data.get('create_status')=='returned_false':
            require(type(data.get('raw_return')) is int and data['raw_return']==0
                and m.live.integer(data.get('raw_error'),1,0xffffffff) and pi==[0,0,0,0]
                and not any(row[k] for k in ('process_returned','admitted','resumed','exited')),
                'a5_proxy_cleanup_exact_no_child')
        else:
            require(data.get('create_status')=='returned_true' and type(data.get('raw_return')) is int
                and data['raw_return']!=0 and data.get('raw_error') is None and all(pi)
                and all(0<h<0xffffffffffffffff for h in pi[:2]) and pi[0]!=pi[1]
                and 0<pi[2]<=0xffffffff and 0<pi[3]<=0xffffffff and pi[2]==row['pid']
                and row['process_returned'] and row['exited'] and m.live.integer(row['exit_code'],0,0xffffffff),
                'a5_proxy_cleanup_owned_child_exited')
    lease=p['port_lease']
    if lease is not None:
        require(type(lease) is dict and set(lease)=={'calls','closes','unknown','started','cleanup_attempted','cleanup_confirmed'}
            and all(type(lease[k]) is bool for k in ('unknown','started','cleanup_attempted','cleanup_confirmed')),
            'a5_proxy_cleanup_lease_shape')
        known,_,_=m.proxy_protocol.lease_facts(lease,_config_view(c))
        require(known,'a5_proxy_cleanup_known_leases')
    physical=p['physical'];allocations=physical['pipe_allocations'];opened={}
    require(type(allocations) is list and len(allocations)<=2,'a5_proxy_cleanup_pipe_count')
    for index,item in enumerate(allocations):
        name=('response','request')[index]
        require(type(item) is dict and set(item)=={'name','intent','observation','receipt'} and item['name']==name,
            'a5_proxy_cleanup_pipe_shape')
        value=_returned(m,item['receipt'],returns,'allocate-pipe-'+name);ob=item['observation']
        require(value['data']==ob and ob['unknown'] is False and ob['attempted'] is True and ob['returned'] is True
            and ob['api_success'] is True and ob['adopted'] is True and ob['readback'] is True
            and type(ob['allocation_size']) is int and ob['allocation_size']==65536,'a5_proxy_cleanup_known_pipe')
        raw=ob['raw_outputs'];require(type(raw) is list and len(raw)==2
            and all(m.live.integer(h,1,0xfffffffffffffffe) for h in raw)
            and len(set((*opened,*raw)))==len(opened)+2,'a5_proxy_cleanup_pipe_outputs')
        opened.update({handle:value['qpc'] for handle in raw})
    closes=physical['parent_pipe_closes'];require(type(closes) is list and len(closes)==len(opened)
        and {r['handle'] for r in closes}==set(opened),'a5_proxy_cleanup_all_pipe_closes')
    for item in closes:
        require(type(item) is dict and set(item)=={'handle','intent','receipt'},'a5_proxy_cleanup_pipe_close')
        _close(m,item['receipt'],returns,calls,'close-parent-pipe',item['handle'],opened[item['handle']],c['deadline_qpc'],used)
    stdio=p['core_stdio'];require(type(stdio) is list and len(stdio)<=6,'a5_proxy_cleanup_stdio_bound')
    seen=set()
    for item in stdio:
        require(type(item) is dict and set(item)==STDIO_KEYS
            and item['role'] in CORE_ROLES and item['kind'] in ('stdin','stdout','stderr')
            and (item['role'],item['kind']) not in seen and item['confirmed'] is True,'a5_proxy_cleanup_stdio_shape')
        seen.add((item['role'],item['kind']));opened=_stdio_open(m,item,root,intents,returns,calls,used)
        _close(m,item['receipt'],returns,calls,'close-core-stdio',item['handle'],opened,c['deadline_qpc'],used)
    for role,data in constructors.items():
        if role in CORE_ROLES and data.get('handle_list'):
            require(all((role,kind) in seen for kind in ('stdin','stdout','stderr')),'a5_proxy_cleanup_all_stdio')
    return True


def validate_proxy_result(m,p,c,*,parent,root,selected):
    result=dict(scope=m.SCOPE,run=c['run'],case=c['case'],
        selected_pid=None if selected is None else selected['pid'],
        selected_creation=None if selected is None else selected['created'],request_bytes=0,response_bytes=0,
        transport_positive=False,byte_sinks_verified=False,cleanup_verified=False)
    if p is None:return result
    require=m.require
    require(type(p) is dict and p['ports']==c['proxy']['ports'] and type(p['tasks']) is list and len(p['tasks'])<=4,
        'a5_proxy_shape')
    physical=p['physical'];require(type(physical) is dict and set(physical)=={'intents','returns','pipe_allocations',
        'parent_pipe_closes','api_intents','api_calls','api_raw_calls'},'a5_proxy_physical_set')
    intents,returns=m._journal_graph(physical,c,root)
    calls=_api_calls(m,physical,c,root)
    try:result['cleanup_verified']=_cleanup(m,p,c,root,intents,returns,calls)
    except (ValueError,KeyError,TypeError,IndexError,OverflowError):pass
    # Missing transport evidence does not erase independently known cleanup.
    if (selected is None or not selected['resumed'] or p['pair'] is None or len(p['tasks'])!=4
            or any(p['reports'].get(key) is None for key in REPORT_PATHS) or p['core_stop'] is None):return result
    try:
        _transport_complete(m,p,c,parent,root,selected,intents,returns,calls)
    except (ValueError,KeyError,TypeError,IndexError,OverflowError,OSError):
        return result
    result.update(request_bytes=8193,response_bytes=12289,transport_positive=True,byte_sinks_verified=True)
    return result


def _transport_complete(m,p,c,parent,root,selected,intents,returns,calls):
    require=m.require
    pair=p['pair'];require(type(pair) is dict and set(pair)=={'start','end','frequency'} and pair['frequency']==c['frequency']
        and m.live.integer(pair['start'],selected['admission_qpc'],m.work_cutoff(c)-1)
        and pair['end']==pair['start']+10*c['frequency'] and pair['end']<=m.work_cutoff(c),
        'a5_proxy_relay_10F_selected_original_8F_epoch')
    rows={}
    for row in p['tasks']:
        _task(m,row,c,parent,root,pair,intents,returns)
        require(row['role'] not in rows,'a5_proxy_duplicate_role');rows[row['role']]=row
    require(set(rows)==set(ROLES),'a5_proxy_closed_roles')
    raw_config=m.local.bounded(m.launcher.checked_path(Path(root)/'core-home/config.json',inside=root),32768)
    require(raw_config==m.encode(m.proxy_protocol.mihomo_configuration(c['proxy']['ports']))
        and m.sha(raw_config)==c['proxy']['mihomo_config_sha256'],'a5_proxy_configuration_bytes')
    reports=_native(m,p,c,parent,root,rows)
    _tcp_and_barrier(m,p,c,parent,root,rows,reports,intents,selected)
    _sinks(m,p,c,root,reports)
    _pipes_and_stdio(m,p,c,root,selected,rows,intents,returns,calls)
    _leases(m,p,c,rows,intents)
    latest=max(reports['relay']['qpc'][3],reports['origin']['qpc'][3],
        rows[ROLES[0]]['exit_observed_qpc'],rows[ROLES[1]]['exit_observed_qpc'],
        p['barrier_commands']['release']['published_qpc'])
    require(m.live.integer(p['completion_qpc'],latest,pair['start']+8*c['frequency']-1),'a5_proxy_completion_clock')
    _core_stop(m,p,c,rows,intents,returns)
    return True
