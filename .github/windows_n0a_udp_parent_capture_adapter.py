"""Runtime-disabled descendant UDP chain host adapter; no direct-actor provenance alias."""
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys

ROOT=Path(__file__).resolve().parents[1]
MAX_FLOW=65536
MAX_RESULT=4096

def helper(name):
    key='udp_parent_adapter_'+name
    if key not in sys.modules:
        filenames={'control':'windows_n0a_udp_parent_control.py','flow':'windows_n0a_udp_parent_flow.py','udp':'windows_n0a_udp_capture_adapter.py','packet':'windows_n0a_udp_packet.py','lifecycle':'windows_n0a_capture_adapter.py'}
        spec=importlib.util.spec_from_file_location(key,ROOT/'.github'/filenames[name])
        module=importlib.util.module_from_spec(spec);sys.modules[key]=module;spec.loader.exec_module(module)
    return sys.modules[key]

def make_configuration(config,source_commit,mac):return helper('lifecycle').make_configuration(config,source_commit,mac)
def admit(payload_bytes,free_bytes,baseline_launch_free):return helper('lifecycle').admit(payload_bytes,free_bytes,baseline_launch_free)
def new_owner(root,outer_deadline):return helper('lifecycle').new_owner(root,outer_deadline)
def valid_commitment(value):return helper('lifecycle').valid_commitment(value)
def accept_private_body(raw,commitment):return helper('lifecycle').accept_private_body(raw,commitment)

def runtime_executor_pin():
    # Pre-media script entry has .github, not the repository package root, on
    # sys.path. Load only this checkout's trusted pin source; no ambient package
    # or sys.modules fallback and no mutation of import search paths.
    spec=importlib.util.spec_from_file_location('parent_host_runtime_pins',ROOT/'ruleproxy/windows_runtime_pins.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    value=module.MXC_G_EXECUTOR_SHA256
    if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError('executor pin')
    return value


def verify_inputs(parent,parent_manifest,child,child_manifest):
    child_inputs=helper('udp').verify_inputs(child,child_manifest)
    parent=Path(parent);parent_manifest=Path(parent_manifest)
    if parent.name!='windows_n0a_udp_parent.exe' or parent_manifest.name!='N0A-UDP-PARENT-manifest.json':raise ValueError('parent production artifact')
    def bounded(path,maximum):
        path=Path(path)
        if path.is_symlink() or not path.is_file():raise ValueError('parent input')
        with path.open('rb') as stream:raw=stream.read(maximum+1)
        if not 0<len(raw)<=maximum:raise ValueError('parent bound')
        return raw
    raw=bounded(parent,16*1024*1024);manifest_raw=bounded(parent_manifest,4096)
    if len(raw)<512:raise ValueError('parent executable')
    value=helper('control').parse(manifest_raw)
    pins=dict(parentSourceSha256=hashlib.sha256(bounded(ROOT/'.github/native/windows_n0a_udp_parent.cpp',128*1024)).hexdigest(),
              identitySourceSha256=child_inputs['config']['identity_source_sha256'],
              childActorSourceSha256=child_inputs['config']['actor_source_sha256'],executableSha256=hashlib.sha256(raw).hexdigest())
    fixed=dict(schemaVersion=1,testOnly=False,deployable=True,compileOnly=True)
    if type(value) is not dict or set(value)!=set(pins)|set(fixed) or any(type(value[k]) is not type(v) or value[k]!=v for k,v in {**pins,**fixed}.items()):raise ValueError('parent production pins')
    executor_pin=runtime_executor_pin()
    config=dict(enabled=True,case_nonce=secrets.token_hex(16),runner_port=None,
        parent_sha256=pins['executableSha256'],parent_manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
        parent_source_sha256=pins['parentSourceSha256'],child_sha256=child_inputs['config']['actor_sha256'],
        child_manifest_sha256=child_inputs['config']['manifest_sha256'],child_source_sha256=pins['childActorSourceSha256'],
        identity_source_sha256=pins['identitySourceSha256'],executor_sha256=executor_pin)
    return dict(parent=parent,parent_manifest=parent_manifest,child=Path(child),child_manifest=Path(child_manifest),config=config)

def flow_context(capture,config,server,cleanup_verified):
    keys=('parent_sha256','child_sha256','parent_manifest_sha256','child_manifest_sha256',
          'parent_source_sha256','child_source_sha256','identity_source_sha256','executor_sha256')
    binding={key:config[key] for key in keys}
    binding.update(run_nonce=capture['run_nonce'],case_nonce=config['case_nonce'],source_commit=capture['source_commit'],build=26300,ubr=9457)
    return dict(binding=binding,endpoint=dict(vm_mac=capture['vm_mac'],destination_ipv4='10.0.2.2',destination_port=config['runner_port']),
                flow_commitment=server.capture_commitment,controller_result=server.n0a_result,cleanup_verified=cleanup_verified)

def validate_capture_envelope(value,expected):
    if type(value) is not dict or set(value)!={'schema_version','parent_udp','flow_commitment'} or type(value['schema_version']) is not int or value['schema_version']!=4:raise ValueError('UDP capture envelope')
    if len(json.dumps(value,ensure_ascii=True).encode('ascii'))>MAX_RESULT:raise ValueError('UDP wire bound')
    receipt=helper('control').validate_host_parent_udp_envelope(value['parent_udp'],expected)
    commitment=value['flow_commitment'];valid=valid_commitment(commitment)
    return dict(legacy=receipt,commitment=dict(commitment) if valid else None,commitment_error=commitment is not None and not valid)

def flow_body_state(raw,commitment):
    """Closed admission state only, not source authenticity or normalization.

    Missing data does not distinguish producer failure from transport failure.
    No raw body, digest, path, or exception content is projected.
    """
    if commitment is None:return 'commitment_missing'
    if not valid_commitment(commitment):return 'commitment_invalid'
    if raw is None:return 'body_missing'
    if type(raw) is not bytes:return 'body_type'
    if len(raw)!=commitment['bytes']:return 'body_size'
    if hashlib.sha256(raw).hexdigest()!=commitment['sha256']:return 'body_digest'
    return 'body_verified'

def unavailable(reason='unavailable'):
    if reason not in ('unavailable','flow_context','commitment_missing','commitment_invalid','body_missing','body_type','body_size','body_digest','normalization','capture_file','parse'):reason='unavailable'
    return dict(schema_version=1,scope='runner_ipv4_udp_payload',status='inconclusive',packet_egress_tested=False,
                packet=None,reason=reason,capture_read_cleanup_confirmed=True,selected_payload_observed=None,
                actor_attribution_established=False,isolation_acceptance=False)

def parse_before_cleanup(path,capture_facts,raw_flow,flow_expected,*,header_before_link,terminal_before_shutdown,capacity_abort=False):
    if type(flow_expected) is not dict:return unavailable('flow_context')
    state=flow_body_state(raw_flow,flow_expected.get('flow_commitment'))
    if state!='body_verified':return unavailable(state)
    try:normalized=helper('flow').normalize(raw_flow,flow_expected)
    except Exception:return unavailable('normalization')
    if type(capture_facts) is not dict or capture_facts.get('qemu_exit_observed') is not True or capture_facts.get('child_exit_observed') is not True:return unavailable('capture_file')
    lifecycle=helper('lifecycle')
    try:data=lifecycle.read_capture(path)
    except lifecycle.CaptureReadCloseError:
        result=unavailable('capture_file');result['capture_read_cleanup_confirmed']=False;return result
    except Exception:return unavailable('capture_file')
    try:
        contract=lifecycle.capture_contract(data,capture_facts,header_before_link=header_before_link,terminal_before_shutdown=terminal_before_shutdown,capacity_abort=capacity_abort)
        packet=helper('packet').evaluate(data,normalized['manifest_bytes'],normalized['expected'],contract)
    except Exception:return unavailable('parse')
    result=unavailable();result.update(status=packet['status'],packet=packet,reason='none',packet_egress_tested=True,selected_payload_observed=packet['selected_payload_observed'])
    return result

def receiver(nonce,deadline):
    return helper('udp').receiver(nonce,deadline)

def compose(server,public,wait_state):
    source=getattr(server,'n0a_result',None) if server is not None else None
    value=json.loads(json.dumps(source if source is not None else helper('control').default_host_parent_udp()))
    # The handler retains invalid-vs-missing commitment even though it drops
    # invalid metadata from the trusted commitment slot. Report only that fact.
    transport='not_observed'
    if source is not None:
        transport=('commitment_invalid' if getattr(server,'capture_commitment_error',False) is True else
                   flow_body_state(getattr(server,'capture_private_body',None),getattr(server,'capture_commitment',None)))
    value['flow_transport_state']=transport
    value.update(original_stage0_receipt_verified=public.get('guest_result_provenance_verified') is True,
                 host_receiver=public.get('n0a_receiver_cleanup'),vm_destroyed=public.get('vm_destroyed') is True,host_wait_state=wait_state)
    return value

def receiver_complete(receiver):
    if type(receiver) is not dict or receiver.get('contained_observed') is not False:return False
    counts=receiver.get('counts');seen=receiver.get('verified_indices')
    keys={'datagrams','observed_bytes','verified','echoed','rejected','oversized','send_errors'}
    if type(counts) is not dict or set(counts)!=keys or any(type(v) is not int or not 0<=v<=(128*129 if k=='observed_bytes' else 128) for k,v in counts.items()):return False
    if not counts['echoed']<=counts['verified']<=counts['datagrams'] or counts['verified']+counts['rejected']+counts['oversized']>counts['datagrams']:return False
    if counts['observed_bytes']>counts['datagrams']*129 or counts['send_errors']>counts['verified']:return False
    if type(seen) is not dict or set(seen)!=set(helper('control').PHASES):return False
    for phase,indices in seen.items():
        limit=40 if phase=='sample' else 3 if phase=='contained' else 1
        if type(indices) is not list or len(indices)>limit or any(type(i) is not int or not 0<=i<limit for i in indices) or indices!=sorted(set(indices)):return False
    return (counts['verified']>=sum(len(v) for v in seen.values()) and counts['echoed']>=5
            and counts['rejected']==counts['oversized']==counts['send_errors']==0
            and seen['before']==[0] and seen['after']==[0] and len(seen['sample'])>=3 and seen['contained']==[])

def qualify(tentative,original_public,udp_public):
    if type(tentative) is not dict or tentative.get('scope')!='runner_ipv4_udp_payload':tentative=unavailable()
    result=json.loads(json.dumps(tentative))
    receiver=udp_public.get('host_receiver') or {};receiver_ok=receiver_complete(receiver)
    observations=udp_public.get('result',{})
    ready=(original_public.get('guest_result_provenance_verified') is True and original_public.get('vm_destroyed') is True
           and udp_public.get('receipt_verified') is True and udp_public.get('vm_destroyed') is True
           and receiver.get('cleanup_confirmed') is True and receiver.get('error') is False and receiver_ok
           and observations.get('ordinary_controls_verified') is True and observations.get('all_selected_sendto_invoked') is True
           and observations.get('sockets_cleanup_confirmed') is True and observations.get('descendant_cleanup_confirmed') is True
           and all(observations.get(k,{}).get(p) is True for k in ('profile_verified','provenance_verified','chain_verified') for p in helper('control').PHASES))
    result['host_prerequisites_verified']=ready
    result['receiver_selected_observed']=receiver.get('contained_observed') if type(receiver.get('contained_observed')) is bool else None
    if type(result.get('packet')) is dict and result['packet'].get('bounded_no_selected_udp_datagram') and not ready:
        result['packet']['bounded_no_selected_udp_datagram']=False;result['packet']['status']='inconclusive'
        result['packet']['reasons']=sorted(set(result['packet']['reasons'])|{'host_prerequisites'})
        result['status']='inconclusive'
    result['isolation_acceptance']=False
    return result
