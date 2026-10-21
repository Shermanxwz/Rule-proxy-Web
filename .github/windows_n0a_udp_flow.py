"""UDP-only private source bundle; hashes are controller attestations, not identity proof.
Same-buffer parse/hash, no transport or execution, and no TCP acceptance reuse.
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
    name='udp_private_flow_engine'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('windows_n0a_udp.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]

def exact(value,keys):return type(value) is dict and set(value)==keys

def hex_value(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{%d}'%size,value) is not None

def encode(value):return json.dumps(value,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')

def parse(raw,maximum):
    if type(raw) is not bytes or not 0<len(raw)<=maximum:raise ValueError('bound')
    try:return json.loads(raw.decode('ascii'),object_pairs_hook=engine().unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('number')))
    except (UnicodeError,RecursionError,json.JSONDecodeError):raise ValueError('json') from None

def read_snapshot(path):
    path=Path(path);state=path.lstat()
    if path.is_symlink() or getattr(state,'st_file_attributes',0)&0x400 or not path.is_file():raise ValueError('report path')
    with path.open('rb') as stream:raw=stream.read(engine().MAX_REPORT+1)
    value=engine().parse(raw)
    return value,{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}

def ordinary_digest(reports):
    digest=hashlib.sha256(b'N0AU-ordinary-reports-v1\0')
    for role in ('before','sample','after'):
        row=reports[role]
        if not hex_value(row.get('sha256'),64) or not engine().integer(row.get('bytes'),1,32768):raise ValueError('source')
        digest.update(role.encode('ascii')+b'\0'+struct.pack('>Q',row['bytes'])+bytes.fromhex(row['sha256']))
    return digest.hexdigest()

def bundle(raw):
    value=parse(raw,MAX_BUNDLE)
    if not exact(value,{'schema_version','protocol','binding','endpoint','reports'}) or type(value['schema_version']) is not int or value['schema_version']!=1 or value['protocol']!='udp':raise ValueError('bundle')
    b=value['binding'];ep=value['endpoint'];reports=value['reports']
    if not exact(b,BINDING_KEYS) or not exact(ep,ENDPOINT_KEYS) or not exact(reports,set(ROLES)):raise ValueError('keys')
    for k in BINDING_KEYS-{'build','ubr'}:
        if not hex_value(b[k],32 if k.endswith('nonce') else 40 if k=='source_commit' else 64):raise ValueError('binding')
    if type(b['build']) is not int or b['build']!=26300 or type(b['ubr']) is not int or b['ubr']!=9457:raise ValueError('build')
    if not hex_value(ep['vm_mac'],12) or ep['vm_mac']=='0'*12 or int(ep['vm_mac'][:2],16)&1 or ep['destination_ipv4']!='10.0.2.2' or not engine().integer(ep['destination_port'],1025,65535):raise ValueError('endpoint')
    for role,row in reports.items():
        if not exact(row,{'sha256','bytes','udp'}) or not hex_value(row['sha256'],64) or not engine().integer(row['bytes'],1,32768):raise ValueError('source')
        engine().validate_network(row['udp'],b['case_nonce'],role,ep['destination_port'])
    return value

def commitment(raw):
    v=bundle(raw)
    return dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),contained_report_sha256=v['reports']['contained']['sha256'],ordinary_report_sha256=ordinary_digest(v['reports']))

def build_bundle(config,binding,cases,snapshots):
    e=engine();reports={}
    for role in ROLES:
        envelope=cases[role];actor=e.bound_actor(envelope,binding)
        if actor is None or not e.provenance_verified(envelope,binding,role) or not e.native_identity(actor,binding.nonce,role,binding.agentic_sid):raise ValueError('source binding')
        network=e.validate_network(actor.get('udp'),binding.nonce,role,binding.runner_port)
        if network['profileMatched'] is not True:raise ValueError('profile')
        source=snapshots[id(actor)]
        reports[role]={'sha256':source['sha256'],'bytes':source['bytes'],'udp':network}
    capture=config['capture'];pins=config['n0a_udp']
    value=dict(schema_version=1,protocol='udp',binding=dict(run_nonce=capture['run_nonce'],case_nonce=binding.nonce,
        actor_sha256=binding.actor_sha256,executor_sha256=binding.executor_sha256,
        actor_source_sha256=pins['actor_source_sha256'],identity_source_sha256=pins['identity_source_sha256'],
        source_commit=capture['source_commit'],build=binding.build,ubr=binding.ubr),
        endpoint=dict(vm_mac=capture['vm_mac'],destination_ipv4='10.0.2.2',destination_port=binding.runner_port),reports=reports)
    raw=encode(value);bundle(raw);return raw

def normalize(raw,expected):
    if not exact(expected,{'binding','endpoint','flow_commitment','controller_result','cleanup_verified'}) or type(expected['cleanup_verified']) is not bool:raise ValueError('context')
    if not exact(expected['binding'],BINDING_KEYS) or not exact(expected['endpoint'],ENDPOINT_KEYS) or not exact(expected['flow_commitment'],COMMIT_KEYS):raise ValueError('context fields')
    v=bundle(raw)
    if (v['binding']!=expected['binding'] or v['endpoint']!=expected['endpoint']
            or any(type(v['binding'][k]) is not type(expected['binding'].get(k)) for k in BINDING_KEYS)
            or any(type(v['endpoint'][k]) is not type(expected['endpoint'].get(k)) for k in ENDPOINT_KEYS)
            or commitment(raw)!=expected['flow_commitment']):raise ValueError('commitment')
    networks={role:r['udp'] for role,r in v['reports'].items()}
    facts=engine().controls(networks,v['binding']['case_nonce'],v['endpoint']['destination_port'])
    observed=expected['controller_result'];trusted=False
    if type(observed) is dict and observed.get('receipt_verified') is True:
        try:
            result=engine().closed_result(observed.get('result'))
            trusted=(all(result[k][role] is True for k in ('profile_verified','provenance_verified') for role in ROLES)
                     and result['ordinary_controls_verified'] is True and result['all_selected_sendto_invoked'] is True)
        except (ValueError,TypeError,KeyError):pass
    controls=trusted and facts['ordinary_controls_verified'] and facts['all_selected_sendto_invoked'] and facts['profile_flags_verified']
    binding=dict(v['binding'],actor_report_sha256=v['reports']['contained']['sha256'],ordinary_report_sha256=ordinary_digest(v['reports']))
    def source_port(row):
        if row['localPort']==0 and row['attempted'] is False:return None
        return row['localPort']
    selected=[dict(index=r['index'],source_port=source_port(r),send_invoked=r['attempted']) for r in networks['contained']['attempts']]
    ordinary=[dict(phase=role,index=r['index'],source_port=source_port(r),send_invoked=r['attempted'],nonce_verified=r['nonceMatched'])
              for role in ('before','sample','after') for r in networks[role]['attempts']]
    data=encode(dict(schema_version=1,binding=binding,endpoint=v['endpoint'],selected=selected,ordinary=ordinary))
    return dict(manifest_bytes=data,expected=dict(binding=binding,endpoint=v['endpoint'],manifest_sha256=hashlib.sha256(data).hexdigest(),
                controls_verified=bool(controls),cleanup_verified=expected['cleanup_verified'] and facts['sockets_cleanup_confirmed']),
                controls_verified=bool(controls))
