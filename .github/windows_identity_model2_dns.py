"""Closed selected standard53 diagnostic contracts; importing performs no I/O.

The separately held readonly inventory precedes the only exclusive UDP53 bind.
API access errors are typed observations, never system resolver qualification.
The receiver's independent selected event remains authoritative through parsing
and cleanup failures. Nothing here proves cancellation of the Windows broker.
"""
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path

spec=importlib.util.spec_from_file_location('model2_dns_three_case_fixture',Path(__file__).with_name('windows_identity_dns_cases_fixture.py'))
fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
PROFILE='same-selected-standard53-dns-v1'
_raw_spec=importlib.util.spec_from_file_location('model2_dns_raw_contract',Path(__file__).with_name('windows_identity_model2_dns_raw.py'))
raw_udp=importlib.util.module_from_spec(_raw_spec);_raw_spec.loader.exec_module(raw_udp)
PROFILES=(PROFILE,raw_udp.PROFILE)
INVENTORY='.github/windows_identity_dns_standard_inventory.ps1'
NATIVE='.github/native/windows_identity_dns_standard_probe.hpp'
OPTIONS=0x000019e8  # WinSDK windns.h fixed BYPASS/NO_HOSTS/NO_LOCAL/NO_NETBT/WIRE/NO_MULTICAST/FQDN.
MAX_NATIVE=16384
API_BOOLS=('configured','called','completed','pending','answer_match','records_released','context_retained','within_deadline')
REQUIRED=('requested','inventory_verified','inventory_before_bind','inventory_before_each_query','fixture_ready',
    'ordinary_before_verified','selected_attempted','selected_completed','selected_access_denial_observed',
    'ordinary_after_verified','receiver_complete','fixture_cleanup','same_selected','observation_complete')

def require(value,reason='dns_contract'):
    if not value:raise ValueError(reason)
def integer(value,lo=0,hi=0xffffffff):return type(value) is int and lo<=value<=hi
def nonce(value):return type(value) is str and len(value)==32 and all(c in '0123456789abcdef' for c in value)
def digest(value):return type(value) is str and len(value)==64 and all(c in '0123456789abcdef' for c in value)
def encode(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode('ascii')
def sha(raw):return hashlib.sha256(raw).hexdigest()

def extension(value):
    keys={'profile','before_case','selected_case','after_case','inventory_run'}
    require(type(value) is dict and set(value)==keys and value['profile'] in PROFILES
        and all(nonce(value[k]) for k in keys-{'profile'}) and len({value[k] for k in keys-{'profile'}})==4,'dns_extension')
    return value

def blank(profile=PROFILE):
    require(profile in PROFILES,'dns_profile')
    value=dict.fromkeys((*REQUIRED,'selected_pending','selected_late','selected_wire_query_observed','completed',
        'broker_cancellation_proven','default_resolver_tested','dns_isolation_qualified'),False)|{'requested':True}
    if profile==raw_udp.PROFILE:
        for key in ('selected_attempted','selected_completed','selected_pending','selected_late','selected_access_denial_observed'):value.pop(key)
        value.update(transport=raw_udp.TRANSPORT,method=raw_udp.METHOD,selected_raw_udp=None)
    return value

def public_profile(value):
    require(type(value) is dict,'dns_public_profile')
    if 'transport' in value:
        require(value['transport']==raw_udp.TRANSPORT and value.get('method')==raw_udp.METHOD,'dns_public_transport');return raw_udp.PROFILE
    return PROFILE

def opcode(c):return 7 if c['dns_extension']['profile']==raw_udp.PROFILE else 6

def public_access_denial(value):
    return raw_udp.public_access(value) if public_profile(value)==raw_udp.PROFILE else value['selected_access_denial_observed']

def selected_fields(value):
    if 'raw_udp' in value:return dict(selected_raw_udp=raw_udp.project(value))
    api=value['dns']['result'];return dict(selected_attempted=api['called'],selected_completed=api['completed'],selected_pending=api['pending'],
        selected_late=not api['within_deadline'] or value['phase_qpc'][2]>=value['phase_qpc'][1],selected_access_denial_observed=access_denial(value))

def selected_empty(value):
    return value['selected_raw_udp'] is None if public_profile(value)==raw_udp.PROFILE else not any(value[k] for k in
        ('selected_attempted','selected_completed','selected_pending','selected_late','selected_access_denial_observed'))

def ready(value):
    if public_profile(value)==raw_udp.PROFILE:
        required=tuple(k for k in REQUIRED if k not in ('selected_attempted','selected_completed','selected_access_denial_observed'))
        return all(value[k] for k in required) and not value['selected_wire_query_observed'] and raw_udp.public_access(value)
    return (all(value[k] for k in REQUIRED) and not any(value[k] for k in
        ('selected_pending','selected_late','selected_wire_query_observed')))

def validate_public(value):
    profile=public_profile(value)
    if profile==raw_udp.PROFILE:
        require(set(value)==set(blank(profile)) and all(type(v) is bool for k,v in value.items() if k not in ('transport','method','selected_raw_udp'))
            and value['requested'] and not any(value[k] for k in ('broker_cancellation_proven','default_resolver_tested','dns_isolation_qualified')),'dns_raw_public_scope')
        raw_udp.validate_public(value['selected_raw_udp']);return value
    require(type(value) is dict and set(value)==set(blank()) and all(type(v) is bool for v in value.values()) and value['requested'],'dns_public')
    require(not any(value[k] for k in ('broker_cancellation_proven','default_resolver_tested','dns_isolation_qualified')),'dns_scope')
    require(not value['selected_access_denial_observed'] or value['selected_attempted'] and value['selected_completed']
        and not value['selected_pending'] and not value['selected_late'],'dns_access_observation')
    return value

def inventory(value,*,run,pid,frequency,start,deadline,now):
    keys={'schema_version','stage','run','pid','qpc_frequency','start_qpc','deadline_qpc','begin_qpc','end_qpc',
        'read_only','dns_servers','effective_nrpt_count','udp53_count','tcp53_count'}
    require(type(value) is dict and set(value)==keys and integer(value['schema_version'],1,1)
        and value['stage']=='dns-standard-readonly-inventory' and value['run']==run and nonce(run)
        and type(value['pid']) is int and value['pid']==pid and value['read_only'] is True,'dns_inventory_binding')
    for k,v in (('qpc_frequency',frequency),('start_qpc',start),('deadline_qpc',deadline)):
        require(type(value[k]) is int and value[k]==v,'dns_inventory_clock')
    require(integer(start,1,0x7fffffffffffffff) and integer(frequency,1,1000000000)
        and start<deadline<=start+120*frequency and integer(value['begin_qpc'],start,deadline-1)
        and integer(value['end_qpc'],value['begin_qpc'],deadline-1) and integer(now,value['end_qpc'],deadline-1)
        and now-value['end_qpc']<=5*frequency,'dns_inventory_freshness')
    require(type(value['dns_servers']) is list and len(value['dns_servers'])<=256,'dns_inventory_servers')
    for text in value['dns_servers']:
        require(type(text) is str and 1<=len(text)<=96 and text==text.strip(),'dns_inventory_address')
        address=ipaddress.ip_address(text)
        require(not(address.is_unspecified or address.is_multicast or address.is_loopback
            or isinstance(address,ipaddress.IPv6Address) and address.ipv4_mapped and address.ipv4_mapped.is_loopback),'dns_inventory_loopback')
    # Conservatively reject all effective NRPT entries; no namespace inference.
    for key in ('effective_nrpt_count','udp53_count','tcp53_count'):
        require(type(value[key]) is int and value[key]==0,'dns_inventory_occupied_or_nrpt')
    return value

def api_result(value):
    require(type(value) is dict and set(value)=={*API_BOOLS,'api_status','query_status','record_count','start_qpc','end_qpc'}
        and all(type(value[k]) is bool for k in API_BOOLS)
        and all(integer(value[k]) for k in ('api_status','query_status')) and integer(value['record_count'],0,16)
        and integer(value['start_qpc'],0,0x7fffffffffffffff) and integer(value['end_qpc'],0,0x7fffffffffffffff)
        and (not value['within_deadline'] or value['end_qpc']>=value['start_qpc']),'dns_api_schema')
    require(not value['completed'] or value['called'] and value['configured'] and not value['pending'],'dns_api_completed')
    require(not value['pending'] or value['called'] and value['configured'] and not value['completed'] and value['context_retained'],'dns_api_pending')
    require(not value['records_released'] or value['completed'],'dns_api_release')
    require(not value['answer_match'] or value['completed'] and value['called'] and value['api_status']==value['query_status']==0
        and value['record_count']==1,'dns_api_answer')
    return value

def phase(value,task,c,*,role,boot,admission,sequence,case,phase_deadline,identity_check):
    raw=c['dns_extension']['profile']==raw_udp.PROFILE
    observation='raw_udp' if raw else 'dns'
    keys={'schema_version','stage','role','run_id','boot_case_id','case_id','pid','sequence','operation','target_port',
        'admission_nonce','identity','root_qpc','phase_qpc','command_close_verified',observation,'failure','proxy_tested','product_acceptance'}
    require(type(value) is dict and set(value)==keys and integer(value['schema_version'],1,1)
        and value['stage']=='proxy-c-client-phase' and value['role']==role and value['run_id']==c['run']
        and value['boot_case_id']==boot and value['case_id']==case and type(value['pid']) is int and value['pid']==task['pid']
        and type(value['sequence']) is int and value['sequence']==sequence and value['operation']==('dns-raw-udp' if raw else 'dns-query')
        and type(value['target_port']) is int and value['target_port']==53 and value['admission_nonce']==admission
        and value['command_close_verified'] is True and value['failure'] in (None,'dns-config','dns-pending','qpc','deadline','report')
        and value['proxy_tested'] is False and value['product_acceptance'] is False,'dns_phase')
    require(role=='selected-client' and task['identity']['appcontainer'] is True and task['identity']['capability_count']==2
        or role=='health-client' and task['identity']['appcontainer'] is False and task['capabilities']==[],'dns_role_profile')
    identity_check(value['identity'],task,c['run'])
    require(value['root_qpc']==[c['frequency'],c['start_qpc'],c['deadline_qpc']]
        and all(type(v) is int for v in value['root_qpc']),'dns_phase_root')
    q=value['phase_qpc']
    require(type(q) is list and len(q)==3 and all(integer(v,0,0x7fffffffffffffff) for v in q)
        and c['start_qpc']<=q[0]<=q[2] and q[1]==phase_deadline<=c['deadline_qpc'],'dns_phase_clock')
    if raw:
        raw_udp.payload(value['raw_udp'],case);return value
    dns=value['dns'];expected=dict(server_constructor='official-v1-zero-port',server_address='127.0.0.1',server_port=53,
        query_name=case+'.n0a.invalid',query_type=1,query_options=OPTIONS)
    require(type(dns) is dict and set(dns)=={*expected,'result'} and all(type(dns[k]) is type(v) and dns[k]==v for k,v in expected.items()),'dns_phase_request')
    r=api_result(dns['result'])
    # Failed native clock reads can leave either result tick zero or reversed.
    # Preserve the closed observation; only the strict timely predicate can qualify it.
    require(not r['within_deadline'] or q[0]<=r['start_qpc']<=r['end_qpc']<=q[2]
        and r['end_qpc']<phase_deadline,'dns_result_clock')
    return value

def timely(value):
    if 'raw_udp' in value:return raw_udp.timely(value)
    r=value['dns']['result'];q=value['phase_qpc']
    return (value['failure'] is None and r['configured'] and r['called'] and r['completed'] and not r['pending']
        and r['records_released'] and not r['context_retained'] and r['within_deadline'] and r['end_qpc']<q[1] and q[2]<q[1])
def positive(value):
    if 'raw_udp' in value:return raw_udp.positive(value)
    r=value['dns']['result'];return timely(value) and r['answer_match'] and r['api_status']==r['query_status']==0 and r['record_count']==1
def access_denial(value):
    if 'raw_udp' in value:return raw_udp.access_denial(value)
    r=value['dns']['result'];return timely(value) and r['api_status']==5 and not r['answer_match'] and r['record_count']==0

def receiver(value,*,final=False):
    base={'ready','error','counts','cases','case_query_observed','selected_query_observed','byte_count_is_observed_lower_bound','broker_cancellation_proven'}
    extra={'socket_close_attempted','socket_close_uncertain','socket_closed','thread_stopped','cleanup_confirmed'}
    require(type(value) is dict and set(value)==base|(extra if final else set()),'dns_receiver_schema')
    for key in ('ready','selected_query_observed','byte_count_is_observed_lower_bound','broker_cancellation_proven'):
        require(type(value[key]) is bool,'dns_receiver_bool')
    require(value['byte_count_is_observed_lower_bound'] is True and value['broker_cancellation_proven'] is False
        and value['error'] in ('none','bound','deadline','receive','operation','send'),'dns_receiver_scope')
    events=value['case_query_observed'];require(type(events) is dict and set(events)==set(fixture.CASES) and all(type(v) is bool for v in events.values())
        and value['selected_query_observed']==events['selected'],'dns_receiver_event')
    counts,cases=value['counts'],value['cases']
    if counts is None:require(cases is None,'dns_receiver_unknown')
    else:
        require(type(counts) is dict and set(counts)==set(fixture.COUNT_KEYS) and all(integer(v,0,fixture.MAX_BYTES if k=='bytes' else fixture.MAX_DATAGRAMS) for k,v in counts.items())
            and type(cases) is dict and set(cases)==set(fixture.CASES),'dns_receiver_counts')
        for key,row in cases.items():
            require(type(row) is dict and set(row)==set(fixture.CASE_COUNT_KEYS) and all(integer(v,0,fixture.MAX_DATAGRAMS) for v in row.values())
                and events[key]==(row['matched_queries']>0) and row['answers_sent']<=row['matched_queries'],'dns_receiver_case')
        require(sum(row['matched_queries'] for row in cases.values())==counts['matched_queries']
            and sum(row['answers_sent'] for row in cases.values())==counts['answers_sent'],'dns_receiver_totals')
    if final:
        require(all(type(value[k]) is bool for k in extra) and (not value['cleanup_confirmed'] or value['socket_closed']
            and value['thread_stopped'] and not value['socket_close_uncertain']),'dns_receiver_cleanup')
    return value

def case_positive(value,key):
    return (value['counts'] is not None and value['error']=='none' and value['case_query_observed'][key]
        and value['cases'][key]['matched_queries']>0 and value['cases'][key]['answers_sent']>0
        and value['cases'][key]['rejected']==value['cases'][key]['send_failed']==0)

def blank_ledger(c):
    return dict(schema_version=1,stage='model2-selected-standard53-dns-ownership',run=c['run'],profile=c['dns_extension']['profile'],
        inventory=None,inventory_gates=[],fixture_attempted=False,fixture_ready=False,fixture_deadline_qpc=None,fixture_snapshots=[],
        fixture_final=None,phases=[],selected_wire_query_observed=False)
