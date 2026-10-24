"""Typed connected-UDP DNS facts; no socket/DNS calls or broker attribution.

The native method is connect -> send -> recvfrom, never unconnected sendto.
Successful connect/send are local facts. Only the independent fixture proves
delivery; its sticky selected event overrides errors, clocks and cleanup.
"""
PROFILE='same-selected-raw-standard53-dns-v1'
TRANSPORT='winsock-udp'
METHOD='connect-send-recvfrom'
NATIVE='.github/native/windows_identity_dns_raw_udp.hpp'
BOOLEANS=('within_deadline','wsa_startup','wsa_cleanup','socket_created','inheritance_cleared','nonblocking',
    'connect_attempted','connect_completed','peer_loopback','send_attempted','send_complete','receive_attempted',
    'datagram_received','source_loopback','response_exact')
FAILURES=(None,'configuration','startup','create','inheritance','nonblocking','connect','peer','select-write',
    'send','select-read','receive','response','deadline','qpc','close','wsa-cleanup')
KEYS={*BOOLEANS,'server_address','server_port','query_name','query_type','transaction_id','query_bytes',
    'local_port','peer_port','send_bytes','response_bytes','source_port','socket_close','failure','wsa_error','win32_error'}
PUBLIC_KEYS={*BOOLEANS,'send_bytes','response_bytes','socket_close','failure','wsa_error','win32_error','phase_timely'}
def require(value,reason='dns_raw_contract'):
    if not value:raise ValueError(reason)
def integer(value,lo=0,hi=0xffffffff):return type(value) is int and lo<=value<=hi
def payload(value,case):
    require(type(value) is dict and set(value)==KEYS and all(type(value[k]) is bool for k in BOOLEANS),'dns_raw_schema')
    expected=dict(server_address='127.0.0.1',server_port=53,query_name=case+'.n0a.invalid',query_type=1,
        transaction_id=int(case[:4],16),query_bytes=62)
    require(all(type(value[k]) is type(v) and value[k]==v for k,v in expected.items()),'dns_raw_request')
    require(all(value[k] is None or integer(value[k],1,65535) for k in ('local_port','peer_port','source_port'))
        and integer(value['send_bytes'],0,62) and integer(value['response_bytes'],0,1233)
        and value['socket_close'] in ('not_attempted','confirmed','uncertain') and value['failure'] in FAILURES
        and all(value[k] is None or integer(value[k]) for k in ('wsa_error','win32_error')),'dns_raw_values')
    require(not value['connect_completed'] or value['connect_attempted'] and value['socket_created'],'dns_raw_connect')
    require(not value['peer_loopback'] or value['connect_completed'] and value['peer_port']==53 and value['local_port'] is not None,'dns_raw_peer')
    require(not value['send_attempted'] or value['peer_loopback'] and value['connect_completed'],'dns_raw_send')
    require(not value['send_bytes'] or value['send_attempted'],'dns_raw_send_bytes')
    require(not value['send_complete'] or value['send_attempted'] and value['send_bytes']==62,'dns_raw_send_complete')
    require(not value['datagram_received'] or value['receive_attempted'],'dns_raw_receive')
    require(not value['receive_attempted'] or value['send_complete'],'dns_raw_receive_order')
    require(not value['response_bytes'] or value['datagram_received'],'dns_raw_response_bytes')
    require(not value['response_exact'] or value['datagram_received'] and value['source_loopback']
        and value['source_port']==53 and value['response_bytes']==78,'dns_raw_response')
    return value
def phase_timely(value):
    q=value['phase_qpc'];return value['failure'] is None and q[2]<q[1]
def timely(value):return phase_timely(value) and value['raw_udp']['within_deadline']
def positive(value):
    r=value['raw_udp']
    return timely(value) and r['socket_close']=='confirmed' and r['failure'] is None and r['wsa_error'] is None and r['win32_error'] is None and all(r[k] for k in BOOLEANS)
def access_payload(value):
    return (value['within_deadline'] and value['socket_close']=='confirmed' and value['wsa_cleanup']
        and value['wsa_startup'] and value['socket_created'] and value['inheritance_cleared'] and value['nonblocking']
        and value['wsa_error']==10013 and value['win32_error'] is None and value['connect_attempted']
        and (value['failure']=='connect' and not value['connect_completed'] and not value['send_attempted']
            or value['failure']=='send' and value['connect_completed'] and value['peer_loopback'] and value['send_attempted']
                and not value['send_complete'] and value['send_bytes']==0))
def access_denial(value):return timely(value) and access_payload(value['raw_udp'])
def collect_after_timeout(value):
    """A closed typed timeout may collect its already-declared ordinary control.

    This grants no new time or denial: the caller still applies the original
    root deadline, held-task liveness and the same inventory freshness gate.
    Unknown clock/close states stop; no background API context exists here.
    """
    r=value['raw_udp'];q=value['phase_qpc']
    return (value['failure'] is None and not timely(value) and r['failure']!='qpc'
        and (r['failure']=='deadline' or q[2]>=q[1]) and q[2]<value['root_qpc'][2]
        and r['wsa_startup'] and r['wsa_cleanup'] and r['socket_close']=='confirmed')
def project(value):
    result={k:v for k,v in value['raw_udp'].items() if k in PUBLIC_KEYS}
    result['phase_timely']=phase_timely(value);return result
def validate_public(value):
    require(value is None or type(value) is dict and set(value)==PUBLIC_KEYS,'dns_raw_public')
    if value is not None:
        require(all(type(value[k]) is bool for k in (*BOOLEANS,'phase_timely'))
            and integer(value['send_bytes'],0,62) and integer(value['response_bytes'],0,1233)
            and value['socket_close'] in ('not_attempted','confirmed','uncertain') and value['failure'] in FAILURES
            and all(value[k] is None or integer(value[k]) for k in ('wsa_error','win32_error')),'dns_raw_public_types')
        require(not value['connect_completed'] or value['connect_attempted'] and value['socket_created'],'dns_raw_public_connect')
        require(not value['send_attempted'] or value['connect_completed'] and value['peer_loopback'],'dns_raw_public_send')
        require(not value['send_bytes'] or value['send_attempted'],'dns_raw_public_send_bytes')
        require(not value['send_complete'] or value['send_attempted'] and value['send_bytes']==62,'dns_raw_public_send_complete')
        require(not value['receive_attempted'] or value['send_complete'],'dns_raw_public_receive')
        require(not value['datagram_received'] or value['receive_attempted'],'dns_raw_public_datagram')
        require(not value['response_bytes'] or value['datagram_received'],'dns_raw_public_response_bytes')
        require(not value['response_exact'] or value['datagram_received'] and value['source_loopback'] and value['response_bytes']==78,'dns_raw_public_response')
    return value
def public_access(value):
    r=value['selected_raw_udp'];return r is not None and r['phase_timely'] and access_payload(r)
