"""Private descendant network bundle. Source/chain facts are controller attestations."""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys
MAX_BUNDLE=65536
ROLES=('before','sample','contained','after')
BINDING_KEYS={'run_nonce','case_nonce','parent_sha256','child_sha256','parent_manifest_sha256','child_manifest_sha256','executor_sha256','parent_source_sha256','child_source_sha256','identity_source_sha256','source_commit','build','ubr'}
ENDPOINT_KEYS={'vm_mac','destination_ipv4','destination_port'}
COMMIT_KEYS={'sha256','bytes','contained_report_sha256','ordinary_report_sha256'}
def engine():
    name='canonical_udp_parent_control';path=Path(__file__).with_name('windows_n0a_udp_parent_control.py').resolve()
    raw=path.read_bytes();digest=hashlib.sha256(raw).hexdigest()
    if name in sys.modules:
        module=sys.modules[name];spec=getattr(module,'__spec__',None)
        if (getattr(module,'__file__',None)!=str(path) or getattr(spec,'origin',None)!=str(path) or getattr(spec,'name',None)!=name
            or getattr(module,'_source_sha256',None)!=digest or getattr(getattr(module,'ParentUDPBinding',None),'__module__',None)!=name):raise ValueError('parent engine cache')
        return module
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    try:exec(compile(raw,str(path),'exec'),module.__dict__);module._source_sha256=digest
    except BaseException:sys.modules.pop(name,None);raise
    return module
exact=lambda x,keys:type(x) is dict and set(x)==keys
encode=lambda x:json.dumps(x,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode('ascii')
hex_value=lambda x,n:engine().hex_value(x,n)
def read_snapshot(path,maximum=32768):
    path=Path(path);state=path.lstat()
    if maximum not in (8192,32768) or path.is_symlink() or getattr(state,'st_file_attributes',0)&0x400 or not path.is_file():raise ValueError('snapshot path')
    with path.open('rb') as stream:raw=stream.read(maximum+1)
    if not 0<len(raw)<=maximum:raise ValueError('snapshot bound')
    return engine().parse(raw),dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
def source(row,maximum):
    return exact(row,{'sha256','bytes'}) and hex_value(row['sha256'],64) and engine().integer(row['bytes'],1,maximum)
def pair_bytes(row):
    out=b''
    for key,maximum in (('parent_source',8192),('child_source',32768)):
        r=row[key]
        if not source(r,maximum):raise ValueError('source')
        out+=struct.pack('>Q',r['bytes'])+bytes.fromhex(r['sha256'])
    return out
def source_digests(reports):
    contained=hashlib.sha256(b'N0AUP-contained-v1\0'+pair_bytes(reports['contained'])).hexdigest()
    ordinary=hashlib.sha256(b'N0AUP-ordinary-v1\0'+b''.join(role.encode()+b'\0'+pair_bytes(reports[role]) for role in ('before','sample','after'))).hexdigest()
    return contained,ordinary
def bundle(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_BUNDLE:raise ValueError('bundle bound')
    v=json.loads(raw.decode('ascii'),object_pairs_hook=engine().udp().unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('number')))
    if not exact(v,{'schema_version','protocol','binding','endpoint','reports'}) or type(v['schema_version']) is not int or v['schema_version']!=1 or v['protocol']!='udp-parent':raise ValueError('bundle')
    b=v['binding'];ep=v['endpoint']
    if not exact(b,BINDING_KEYS) or not exact(ep,ENDPOINT_KEYS) or not exact(v['reports'],set(ROLES)):raise ValueError('keys')
    for key in BINDING_KEYS-{'build','ubr'}:
        if not hex_value(b[key],32 if key.endswith('nonce') else 40 if key=='source_commit' else 64):raise ValueError('binding')
    if type(b['build']) is not int or b['build']!=26300 or type(b['ubr']) is not int or b['ubr']!=9457:raise ValueError('build')
    if not hex_value(ep['vm_mac'],12) or ep['vm_mac']=='0'*12 or int(ep['vm_mac'][:2],16)&1 or ep['destination_ipv4']!='10.0.2.2' or not engine().integer(ep['destination_port'],1025,65535):raise ValueError('endpoint')
    for phase,row in v['reports'].items():
        if not exact(row,{'parent_source','child_source','udp','chain'}) or not exact(row['chain'],engine().CHAIN_KEYS) or any(type(x) is not bool for x in row['chain'].values()):raise ValueError('row')
        pair_bytes(row);engine().udp().validate_network(row['udp'],b['case_nonce'],phase,ep['destination_port'])
    return v
def commitment(raw):
    v=bundle(raw);contained,ordinary=source_digests(v['reports'])
    return dict(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw),contained_report_sha256=contained,ordinary_report_sha256=ordinary)
def build_bundle(config,binding,cases,snapshots):
    e=engine();reports={}
    for phase in ROLES:
        envelope=cases[phase];facts=e.chain(envelope,binding,phase)
        if not all(facts.values()):raise ValueError('chain')
        parent=envelope['parent'];child=envelope['child']
        reports[phase]=dict(parent_source=snapshots[id(parent)],child_source=snapshots[id(child)],udp=e.udp().validate_network(child['udp'],binding.nonce,phase,binding.runner_port),chain=facts)
    capture=config['capture'];pins=config['n0a_udp_parent']
    b={key:pins[key] for key in BINDING_KEYS if key in pins}
    b.update(run_nonce=capture['run_nonce'],case_nonce=binding.nonce,source_commit=capture['source_commit'],build=binding.build,ubr=binding.ubr,executor_sha256=binding.executor_sha256)
    raw=encode(dict(schema_version=1,protocol='udp-parent',binding=b,endpoint=dict(vm_mac=capture['vm_mac'],destination_ipv4='10.0.2.2',destination_port=binding.runner_port),reports=reports))
    bundle(raw);return raw
def normalize(raw,expected):
    if not exact(expected,{'binding','endpoint','flow_commitment','controller_result','cleanup_verified'}) or type(expected['cleanup_verified']) is not bool:raise ValueError('expected')
    v=bundle(raw)
    if (not exact(expected['binding'],BINDING_KEYS) or not exact(expected['endpoint'],ENDPOINT_KEYS) or not exact(expected['flow_commitment'],COMMIT_KEYS)
        or expected['binding']!=v['binding'] or expected['endpoint']!=v['endpoint'] or commitment(raw)!=expected['flow_commitment']
        or any(type(expected['binding'][k]) is not type(x) for k,x in v['binding'].items()) or any(type(expected['endpoint'][k]) is not type(x) for k,x in v['endpoint'].items())):raise ValueError('binding')
    e=engine();observed=expected['controller_result'];result=e.closed_result(observed.get('result'))
    trusted=observed.get('receipt_verified') is True
    networks={p:r['udp'] for p,r in v['reports'].items()}
    facts=e.udp().controls(networks,v['binding']['case_nonce'],v['endpoint']['destination_port'])
    chain_ok=trusted and all(result['chain_verified'][p] and all(v['reports'][p]['chain'].values()) for p in ROLES)
    # No available positive is erased by failed ordinary controls/cleanup. But
    # selected attribution still needs the selected validated chain contract.
    selected_ok=trusted and result['chain_verified']['contained'] and all(v['reports']['contained']['chain'].values())
    if not selected_ok:raise ValueError('selected chain')
    child_hash=v['reports']['contained']['child_source']['sha256'];_,ordinary=source_digests(v['reports'])
    b=v['binding'];packet_binding=dict(run_nonce=b['run_nonce'],case_nonce=b['case_nonce'],actor_sha256=b['child_sha256'],executor_sha256=b['executor_sha256'],actor_source_sha256=b['child_source_sha256'],identity_source_sha256=b['identity_source_sha256'],source_commit=b['source_commit'],build=b['build'],ubr=b['ubr'],actor_report_sha256=child_hash,ordinary_report_sha256=ordinary)
    def port(r):return None if r['localPort']==0 and r['attempted'] is False else r['localPort']
    manifest=encode(dict(schema_version=1,binding=packet_binding,endpoint=v['endpoint'],selected=[dict(index=r['index'],source_port=port(r),send_invoked=r['attempted']) for r in networks['contained']['attempts']],ordinary=[dict(phase=p,index=r['index'],source_port=port(r),send_invoked=r['attempted'],nonce_verified=r['nonceMatched']) for p in ('before','sample','after') for r in networks[p]['attempts']]))
    controls=chain_ok and facts['ordinary_controls_verified'] and facts['all_selected_sendto_invoked'] and result['ordinary_controls_verified']
    return dict(manifest_bytes=manifest,expected=dict(binding=packet_binding,endpoint=v['endpoint'],manifest_sha256=hashlib.sha256(manifest).hexdigest(),controls_verified=bool(controls),cleanup_verified=expected['cleanup_verified'] and facts['sockets_cleanup_confirmed'] and result['descendant_cleanup_confirmed']),controls_verified=bool(controls))
