"""Private capture bundle. Controller attestation, not independent actor authentication.
No transport, capture, token changes or QPC-to-PCAP time mapping.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

MAX_BUNDLE=65536
ROLES=('before','sample','contained','after')
BINDING_KEYS={'run_nonce','case_nonce','actor_sha256','executor_sha256','actor_source_sha256','identity_source_sha256','source_commit','build','ubr'}
ENDPOINT_KEYS={'vm_mac','destination_ipv4','destination_port'}
COMMIT_KEYS={'sha256','bytes','contained_report_sha256','ordinary_report_sha256'}

def engine():
    name='n0a_private_flow_engine'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('windows_n0a_control.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]

def object_keys(value,keys):return type(value) is dict and set(value)==keys

def hex_value(value,length):return type(value) is str and re.fullmatch('[0-9a-f]{%d}'%length,value) is not None

def encode(value):return json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')

def parse(raw,maximum):
    if type(raw) is not bytes or not 0<len(raw)<=maximum:raise ValueError('private bound')
    return json.loads(raw.decode('ascii'),object_pairs_hook=engine().unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('private number')))

def read_snapshot(path):
    # Same bounded buffer is parsed and hashed; no reserialization or second read.
    path=Path(path);attributes=getattr(path.lstat(),'st_file_attributes',0)
    if path.is_symlink() or attributes&0x400:raise ValueError('report link rejected')
    with path.open('rb') as stream:raw=stream.read(engine().MAX_REPORT+1)
    value=parse(raw,engine().MAX_REPORT)
    if type(value) is not dict:raise ValueError('report object')
    return value,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

def ordinary_digest(reports):
    digest=hashlib.sha256(b'N0A-ordinary-reports-v1\0')
    for role in ('before','sample','after'):
        row=reports[role]
        if not hex_value(row.get('sha256'),64) or not engine().integer(row.get('bytes'),1,32768):raise ValueError('source digest')
        digest.update(role.encode('ascii')+b'\0'+struct.pack('>Q',row['bytes'])+bytes.fromhex(row['sha256']))
    return digest.hexdigest()

def validate_network(network,port,role,pattern):
    e=engine();integer=e.integer;NETWORK_KEYS=e.NETWORK_KEYS;ATTEMPT_KEYS=e.ATTEMPT_KEYS;FAILURES=e.FAILURES
    endpoint='runner'
    if type(network) is not dict or set(network) != NETWORK_KEYS: return None
    if (type(network['version']) is not int or network['version'] != 1
            or not integer(network['startupError'],0,0xffffffff)
            or not integer(network['port'],1025,65535)
            or network['port'] != port
            or network['endpoint'] != endpoint or network['role'] != role or network['pattern'] != pattern
            or type(network['profileMatched']) is not bool
            or not integer(network['qpcFrequency'],1)
            or not integer(network['windowStartQpc'],1) or not integer(network['windowEndQpc'],1)
            or network['windowEndQpc'] < network['windowStartQpc']): return None
    duration = network['windowEndQpc'] - network['windowStartQpc']
    if duration > (10 if pattern == 'sample' else 3) * network['qpcFrequency']: return None
    rows = network['attempts']
    limit = 3 if role == 'contained' else (40 if pattern == 'sample' else 1)
    if type(rows) is not list or not 0 <= len(rows) <= limit: return None
    prior = network['windowStartQpc']
    for index,row in enumerate(rows):
        if type(row) is not dict or set(row) != ATTEMPT_KEYS or not integer(row['index'],0,39) or row['index'] != index: return None
        if any(type(row[k]) is not bool for k in ('attempted','bindSucceeded','connectSucceeded','nonceMatched','closed')): return None
        if (not integer(row['localPort'],0,65535) or not integer(row['localIpv4'],0,0xffffffff)
                or not integer(row['win32Error'],0,0xffffffff) or row['failure'] not in FAILURES): return None
        if any(not integer(row[k]) for k in ('connectStartQpc','connectEndQpc','exchangeEndQpc')): return None
        if row['attempted']:
            if not (network['windowStartQpc'] <= prior <= row['connectStartQpc'] <= row['connectEndQpc']
                    <= row['exchangeEndQpc'] <= network['windowEndQpc']): return None
            if row['connectEndQpc'] - row['connectStartQpc'] > network['qpcFrequency']: return None
            prior = row['exchangeEndQpc']
        elif row['connectSucceeded'] or row['nonceMatched']: return None
        if row['nonceMatched'] and not row['connectSucceeded']: return None
    return network

def bundle(raw):
    value=parse(raw,MAX_BUNDLE)
    if not object_keys(value,{'schema_version','binding','endpoint','reports'}) or type(value['schema_version']) is not int or value['schema_version']!=1:raise ValueError('bundle')
    binding=value['binding'];endpoint=value['endpoint'];reports=value['reports']
    if not object_keys(binding,BINDING_KEYS) or not object_keys(endpoint,ENDPOINT_KEYS) or not object_keys(reports,set(ROLES)):raise ValueError('bundle keys')
    for key in BINDING_KEYS-{'build','ubr'}:
        if not hex_value(binding[key],32 if key.endswith('nonce') else 40 if key=='source_commit' else 64):raise ValueError('binding')
    if type(binding['build']) is not int or binding['build']!=26300 or type(binding['ubr']) is not int or binding['ubr']!=9457:raise ValueError('build')
    if not hex_value(endpoint['vm_mac'],12) or endpoint['vm_mac']=='0'*12 or int(endpoint['vm_mac'][:2],16)&1 or endpoint['destination_ipv4']!='10.0.2.2' or not engine().integer(endpoint['destination_port'],1025,65535):raise ValueError('endpoint')
    for role,row in reports.items():
        if not object_keys(row,{'sha256','bytes','n0a'}) or not hex_value(row['sha256'],64) or not engine().integer(row['bytes'],1,32768):raise ValueError('source')
        if validate_network(row['n0a'],endpoint['destination_port'],'contained' if role=='contained' else 'ordinary','sample' if role=='sample' else 'single') is None:raise ValueError('network')
    return value

def commitment(raw):
    value=bundle(raw)
    return {'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'contained_report_sha256':value['reports']['contained']['sha256'],'ordinary_report_sha256':ordinary_digest(value['reports'])}

def build_bundle(config,binding,case,snapshots):
    reports={};e=engine()
    for role in ROLES:
        envelope=case['during' if role=='sample' else role]
        actor=e.bound_actor(envelope,binding)
        network=(e.observation(envelope,binding,'runner','contained','single') if role=='contained' and e.contained_binding_verified(envelope,binding) else
                 e.invocation_valid(envelope,binding,'runner','ordinary','sample' if role=='sample' else 'single') if role!='contained' else None)
        if actor is None or network is None:raise ValueError('observed source binding')
        snapshot=snapshots[id(actor)]
        reports[role]={'sha256':snapshot['sha256'],'bytes':snapshot['bytes'],'n0a':network}
    capture=config['capture'];pins=config['n0a']
    value={'schema_version':1,'binding':{'run_nonce':capture['run_nonce'],'case_nonce':binding.nonce,'actor_sha256':binding.actor_sha256,'executor_sha256':binding.executor_sha256,'actor_source_sha256':pins['actor_source_sha256'],'identity_source_sha256':pins['identity_source_sha256'],'source_commit':capture['source_commit'],'build':binding.build,'ubr':binding.ubr},'endpoint':{'vm_mac':capture['vm_mac'],'destination_ipv4':'10.0.2.2','destination_port':binding.ports[1]},'reports':reports}
    raw=encode(value);bundle(raw);return raw

def network_controls(reports):
    networks={role:row['n0a'] for role,row in reports.items()};c=networks['contained'];rows=c['attempts'];f=c['qpcFrequency'];start=c['windowStartQpc'];end=c['windowEndQpc']
    if any(not v['profileMatched'] or v['startupError']!=0 for v in networks.values()):return False
    if len(rows)!=3 or not 0<end-start<=3*f or start!=rows[0]['connectStartQpc'] or end!=rows[-1]['exchangeEndQpc']:return False
    if not all(r['attempted'] and r['bindSucceeded'] and r['localPort']>0 and not r['connectSucceeded'] and not r['nonceMatched'] and r['closed'] and r['win32Error']==10013 and r['failure'] in ('connect','completion') for r in rows):return False
    controls=[networks[k] for k in ('before','sample','after')]
    if any(v['qpcFrequency']!=f or not v['attempts'] or not all(engine().successful(r) for r in v['attempts']) for v in controls):return False
    before,sample,after=[v['attempts'] for v in controls]
    return (len(before)==len(after)==1 and before[0]['exchangeEndQpc']<start and after[0]['connectStartQpc']>end and any(r['exchangeEndQpc']<start for r in sample) and any(start<=r['connectStartQpc']<=r['exchangeEndQpc']<=end for r in sample) and any(r['connectStartQpc']>end for r in sample))

def normalize(raw,expected):
    if not object_keys(expected,{'binding','endpoint','flow_commitment','controller_result'}):raise ValueError('expected context')
    value=bundle(raw)
    if value['binding']!=expected['binding'] or value['endpoint']!=expected['endpoint'] or commitment(raw)!=expected['flow_commitment']:raise ValueError('committed context')
    observed=expected['controller_result']
    # Input is the already validated controller receipt, not a bundle boolean.
    controls=False
    if type(observed) is dict and observed.get('receipt_verified') is True:
        result=engine().closed_result(observed.get('result'))
        controls=result['endpoints']['runner']['status']=='observed_connect_denial' and network_controls(value['reports'])
    binding=dict(value['binding'],actor_report_sha256=value['reports']['contained']['sha256'],ordinary_report_sha256=ordinary_digest(value['reports']))
    ordinary=[]
    for role in ('before','sample','after'):
        for row in value['reports'][role]['n0a']['attempts']:
            ordinary.append({'phase':role,'index':len(ordinary),'source_port':row['localPort'],'connect_succeeded':row['connectSucceeded'],'nonce_verified':row['nonceMatched']})
    manifest={'schema_version':1,'binding':binding,'endpoint':value['endpoint'],'selected':[{'index':r['index'],'source_port':r['localPort']} for r in value['reports']['contained']['n0a']['attempts']],'ordinary':ordinary}
    data=encode(manifest)
    return {'manifest_bytes':data,'expected':{'binding':binding,'endpoint':value['endpoint'],'manifest_sha256':hashlib.sha256(data).hexdigest(),'connect_controls_verified':bool(controls)},'controls_verified':bool(controls)}
