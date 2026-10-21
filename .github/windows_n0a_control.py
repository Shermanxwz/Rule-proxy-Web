"""Inactive N0a-connect experiment. No packet/no-egress or isolation acceptance.

Private native reports are evaluated independently of original Stage0. Ordinary
controls make fresh connections; QPC proves window overlap, not syscall overlap.
No existing proof policy, native identity gate, or direct harness is changed.
"""
from __future__ import annotations
import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXECUTION_ENABLED = False
MAX_REPORT = 32768
MAX_QPC = (1 << 63) - 1
NONCE = re.compile(r'[0-9a-f]{32}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
PACKAGE_SID = re.compile(r'S-1-15-2(?:-[0-9]{1,10}){7}\Z')
CAPABILITY_SID = re.compile(r'S-1-15-3(?:-[0-9]{1,10}){1,12}\Z')
ENDPOINTS = {'guest': '127.0.0.1', 'runner': '10.0.2.2'}
FAILURES = ('none','profile','socket','nonblocking','bind','getsockname','connect',
            'select','completion','getsockopt_error','send','recv','echo','close','deadline')
ATTEMPT_KEYS = {'index','attempted','bindSucceeded','localPort','localIpv4',
                'connectStartQpc','connectEndQpc','connectSucceeded','nonceMatched',
                'exchangeEndQpc','win32Error','failure','closed'}
NETWORK_KEYS = {'version','port','startupError','endpoint','role','pattern','windowStartQpc','windowEndQpc',
                'qpcFrequency','profileMatched','attempts'}


def integer(value, low=0, high=MAX_QPC):
    return type(value) is int and low <= value <= high


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate report key')
        result[key] = value
    return result


def read_report(path):
    path = Path(path)
    attributes = getattr(path.lstat(), 'st_file_attributes', 0)
    if path.is_symlink() or attributes & 0x400: raise ValueError('report link rejected')
    with path.open('rb') as stream: data = stream.read(MAX_REPORT + 1)
    if not 0 < len(data) <= MAX_REPORT: raise ValueError('report bound')
    value = json.loads(data.decode('ascii'), object_pairs_hook=unique_object)
    if type(value) is not dict: raise ValueError('report object required')
    return value


@dataclass(frozen=True)
class Binding:
    # Construct only after current-guest build/native catalog and pinned input
    # checks. These are controller observations, not fields trusted from actor.
    nonce: str
    actor_sha256: str
    executor_sha256: str
    agentic_sid: str
    ports: tuple
    controller_compartment: int
    controller_elevated: bool
    controller_appcontainer: bool
    build: int = 26300
    ubr: int = 9457

    def valid(self):
        return (type(self.nonce) is str and NONCE.fullmatch(self.nonce) is not None
                and all(type(v) is str and HASH.fullmatch(v) for v in
                        (self.actor_sha256,self.executor_sha256))
                and type(self.agentic_sid) is str and CAPABILITY_SID.fullmatch(self.agentic_sid) is not None
                and type(self.ports) is tuple and len(self.ports) == 2
                and all(integer(port,1025,65535) for port in self.ports)
                and type(self.controller_compartment) is int and self.controller_compartment == 1
                and self.controller_elevated is False and self.controller_appcontainer is False
                and type(self.build) is int and self.build == 26300
                and type(self.ubr) is int and self.ubr == 9457)


def proof_helpers():
    spec = importlib.util.spec_from_file_location('n0a_original_proof', ROOT/'.github/windows_identity_proof.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def native_amd64():
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    query=kernel.GetNativeSystemInfo
    query.argtypes=[ctypes.c_void_p]; query.restype=None
    # SYSTEM_INFO begins with the architecture WORD; oversized aligned buffer
    # safely accommodates the documented x64 structure, no pointers exported.
    buffer=(ctypes.c_uint64*8)(); query(ctypes.byref(buffer))
    return ctypes.sizeof(ctypes.c_void_p)==8 and ctypes.cast(buffer,ctypes.POINTER(ctypes.c_uint16))[0]==9


def verify_binding(actor, expected_actor_sha256, executor, manifest, nonce, ports):
    """Read-only current-guest/pinned-input binding, never a supplied profile.

    Kept separate from evaluation so unit fixtures cannot be mistaken for OS
    observations. No CLI/integration currently calls this inactive experiment.
    """
    if os.name != 'nt': raise PermissionError('Windows guest observation required')
    import winreg
    proof = proof_helpers()
    identity = proof.smoke.identity_snapshot()
    provenance = proof.smoke.verify_executor(executor,manifest)
    actor = Path(actor)
    attributes = getattr(actor.lstat(),'st_file_attributes',0)
    if (actor.is_symlink() or attributes & 0x400 or actor.suffix.lower() != '.exe'
            or not 512 <= actor.stat().st_size <= 8*1024*1024): raise ValueError('bounded actor required')
    with actor.open('rb') as stream: data=stream.read(8*1024*1024+1)
    if len(data)>8*1024*1024 or hashlib.sha256(data).hexdigest()!=expected_actor_sha256:
        raise ValueError('actor pin differs')
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SYSTEM\CurrentControlSet\Control\ProductOptions') as key:
        product=winreg.QueryValueEx(key,'ProductType')[0]
    if product != 'WinNT': raise ValueError('client Windows required')
    if not native_amd64(): raise ValueError('native AMD64 required')
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,r'SOFTWARE\Microsoft\Windows NT\CurrentVersion') as key:
        build=winreg.QueryValueEx(key,'CurrentBuildNumber')[0]
        ubr=winreg.QueryValueEx(key,'UBR')[0]
    if build != '26300' or type(ubr) is not int or ubr != 9457: raise ValueError('exact exploratory build required')
    observer = proof.WindowsCapabilityObserver(); catalog=observer.catalog()
    if observer.source() != []: raise ValueError('observed empty controller capabilities required')
    binding=Binding(nonce,expected_actor_sha256,provenance['executor_sha256'],catalog['AgenticAppContainer'],
                    ports,identity['cid'],identity['elevated'],identity['appcontainer'],26300,9457)
    if not binding.valid(): raise ValueError('ordinary bound context required')
    return binding


def command(actor, report, binding, endpoint, port, role, pattern):
    if (not binding.valid() or endpoint not in ENDPOINTS or not integer(port,1025,65535)
            or role not in ('ordinary','contained') or pattern not in ('single','sample')
            or (role == 'contained' and pattern != 'single')
            or port != binding.ports[tuple(ENDPOINTS).index(endpoint)]):
        raise ValueError('fixed N0a command required')
    return [str(actor),'n0a-tcp',binding.nonce,str(report),endpoint,str(port),role,pattern]


def contained_policy(inputs, profile, actor, binding, endpoint, port, required_environment):
    proof = proof_helpers()
    value = proof.policy(inputs,profile,actor,binding.nonce,required_environment=required_environment)
    value['process']['commandLine'] = subprocess.list2cmdline(command(
        actor,Path(profile)/'actor.json',binding,endpoint,port,'contained','single'))
    return value


def native_identity(actor, binding, role):
    # Explicit new-mode conjunction. Never adapt/modify original stage0_checks.
    if not (type(actor) is dict and actor.get('schemaVersion') == 1
            and type(actor.get('schemaVersion')) is int and actor.get('mode') == 'actor-n0a'
            and actor.get('nonce') == binding.nonce and actor.get('queriesSucceeded') is True
            and actor.get('errors') == [] and actor.get('tokenElevated') is False
            and integer(actor.get('pid'),1)):
        return False
    if role == 'contained':
        return (actor.get('tokenIsAppContainer') is True and actor.get('isProcessInJob') is True
                and type(actor.get('tokenAppContainerSid')) is str
                and PACKAGE_SID.fullmatch(actor['tokenAppContainerSid']) is not None
                and actor.get('tokenCapabilities') == [{'sid':binding.agentic_sid,'attributes':4}]
                and type(actor['tokenCapabilities'][0].get('attributes')) is int)
    return (role == 'ordinary' and actor.get('tokenIsAppContainer') is False
            and actor.get('tokenAppContainerSid') is None and actor.get('tokenCapabilities') == [])


def bound_actor(value, binding):
    """Bind private observations before considering outcomes or acceptance."""
    if type(value) is not dict or not binding.valid(): return None
    if (value.get('nonce') != binding.nonce or value.get('actor_sha256') != binding.actor_sha256
            or value.get('executor_sha256') != binding.executor_sha256
            or value.get('build') != binding.build or value.get('ubr') != binding.ubr): return None
    actor = value.get('actor')
    if type(actor) is not dict or actor.get('nonce') != binding.nonce or actor.get('mode') != 'actor-n0a': return None
    try:
        if len(json.dumps(actor,ensure_ascii=True).encode('ascii')) > MAX_REPORT: return None
    except (ValueError,TypeError,RecursionError): return None
    return actor


def observation(value, binding, endpoint, role, pattern):
    actor = bound_actor(value,binding)
    if actor is None: return None
    network = actor.get('n0a')
    if type(network) is not dict or set(network) != NETWORK_KEYS: return None
    if (type(network['version']) is not int or network['version'] != 1
            or not integer(network['startupError'],0,0xffffffff)
            or not integer(network['port'],1025,65535)
            or network['port'] != binding.ports[tuple(ENDPOINTS).index(endpoint)]
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


def contained_binding_verified(value, binding):
    actor = bound_actor(value,binding)
    if actor is None or not native_identity(actor,binding,'contained'): return False
    network = actor.get('n0a')
    if (type(network) is not dict or network.get('profileMatched') is not True
            or value.get('pid_verified') is not True or value.get('pid_binding')!='executor_audit'
            or not integer(value.get('child_exit_code'),-0x80000000,0x7fffffff)): return False
    proof = proof_helpers()
    return (type(value.get('probe_exit_code')) is int and value['probe_exit_code'] == 0
            and proof.smoke.base_container_selected(value.get('probe'),value['probe_exit_code'])
            and value.get('actual_tiers') == ['base-container'])


def invocation_valid(value, binding, endpoint, role, pattern):
    network = observation(value,binding,endpoint,role,pattern)
    if network is None: return None
    if (type(value.get('exit_code')) is not int or value['exit_code'] != 0
            or value.get('timed_out') is not False or value.get('harness_error') is not False
            or not native_identity(value['actor'],binding,role) or not network['profileMatched'] or network['startupError'] != 0): return None
    if role == 'contained':
        if not contained_binding_verified(value,binding) or value['child_exit_code']!=0: return None
    elif value.get('pid_verified') is not True or value.get('pid_binding')!='ordinary_handle': return None
    return network


def successful(row):
    return (row['attempted'] and row['bindSucceeded'] and row['localPort'] > 0
            and row['connectSucceeded'] and row['nonceMatched'] and row['closed']
            and row['win32Error'] == 0 and row['failure'] == 'none')


def endpoint_result(case, binding, endpoint):
    result = {'status':'inconclusive','profile_verified':False,'controls_verified':False,
              'window_overlap_verified':False,'explicit_denials':0,'connect_success_observed':False}
    if type(case) is not dict: return result
    # First retain raw connection observation. Only established contained
    # profile/tier provenance makes it a boundary failure; afterwards bad
    # echo, timing, exit, control, or cleanup cannot rescue that failure.
    actor = bound_actor(case.get('contained'),binding)
    raw = actor.get('n0a') if actor is not None else None
    if (type(raw) is dict and raw.get('endpoint') == endpoint and raw.get('role') == 'contained'
            and raw.get('port') == binding.ports[tuple(ENDPOINTS).index(endpoint)]
            and type(raw.get('attempts')) is list and len(raw['attempts']) <= 40
            and any(type(row) is dict and row.get('attempted') is True
                    and row.get('connectSucceeded') is True for row in raw['attempts'])):
        result['connect_success_observed'] = True
        if contained_binding_verified(case.get('contained'),binding):
            result.update(status='connect_succeeded',profile_verified=True)
        return result
    if case.get('cleanup_confirmed') is not True or case.get('driver_error') is not False: return result
    contained = invocation_valid(case.get('contained'),binding,endpoint,'contained','single')
    if contained is None: return result
    result['profile_verified'] = True
    rows = contained['attempts']; frequency = contained['qpcFrequency']
    duration = contained['windowEndQpc']-contained['windowStartQpc']
    if (len(rows) != 3 or not 0 < duration <= 3*frequency
            or contained['windowStartQpc'] != rows[0]['connectStartQpc']
            or contained['windowEndQpc'] != rows[-1]['exchangeEndQpc']): return result
    explicit = [row['attempted'] and row['bindSucceeded'] and row['localPort'] > 0
                and not row['connectSucceeded'] and not row['nonceMatched'] and row['closed']
                and row['win32Error'] == 10013 and row['failure'] in ('connect','completion') for row in rows]
    result['explicit_denials'] = sum(explicit)
    controls = [invocation_valid(case.get(key),binding,endpoint,'ordinary',pattern)
                for key,pattern in (('before','single'),('during','sample'),('after','single'))]
    if any(control is None or control['qpcFrequency'] != frequency or not control['attempts']
           or not all(successful(row) for row in control['attempts']) for control in controls): return result
    before,during,after = controls
    start,end = contained['windowStartQpc'],contained['windowEndQpc']
    if not (len(before['attempts']) == len(after['attempts']) == 1
            and before['attempts'][0]['exchangeEndQpc'] < start
            and after['attempts'][0]['connectStartQpc'] > end): return result
    result['controls_verified'] = True
    # Fresh successful TCP exchange wholly inside the matching endpoint's
    # attempt window, plus fresh successful sampler connections on both sides.
    sample = during['attempts']
    overlap = (any(row['exchangeEndQpc'] < start for row in sample)
               and any(start <= row['connectStartQpc'] <= row['exchangeEndQpc'] <= end for row in sample)
               and any(row['connectStartQpc'] > end for row in sample))
    result['window_overlap_verified'] = overlap
    if all(explicit) and overlap: result['status'] = 'observed_connect_denial'
    return result


def evaluate(cases, binding):
    endpoints = {name:endpoint_result(cases.get(name) if type(cases) is dict else None,binding,name)
                 for name in ENDPOINTS}
    statuses = [value['status'] for value in endpoints.values()]
    status = ('connect_succeeded' if 'connect_succeeded' in statuses else
              'observed_connect_denial' if statuses == ['observed_connect_denial']*2 else 'inconclusive')
    return {'schema_version':1,'experiment':'N0a-connect','status':status,'endpoints':endpoints,
            'packet_egress_tested':False,'stage0_passed':False,'product_acceptance':False,
            'privacy_qualified':False,'psec_cleanup_independently_verified':False,
            'exploratory_below_support_floor':True,'continuous_token_identity_proven':False}


def clipped_timeout(deadline, limit, *, clock=time.monotonic, reserve=2):
    remaining = deadline-clock()-reserve
    if remaining <= 0: raise TimeoutError('N0a absolute budget exhausted')
    return min(limit,remaining)


def run_endpoint(execution, binding, endpoint, port, deadline, *, approved=False, clock=time.monotonic, sleep=time.sleep):
    """Inactive driver seam. Execution adapter owns OS handles/provenance/pins.

    Integration must supply verified bounded invoke/probe/start/wait methods;
    this module neither enables VM execution nor silently uses original proof
    run_case's independent timeout. Every wait clips to the existing deadline.
    """
    if not EXECUTION_ENABLED or not approved: raise PermissionError('N0a execution inactive')
    if (not binding.valid() or endpoint not in ENDPOINTS or not integer(port,1025,65535)
            or port != binding.ports[tuple(ENDPOINTS).index(endpoint)]): raise ValueError('N0a scope')
    result = {'driver_error':False,'cleanup_confirmed':False}; owned = None
    try:
        execution.probe(endpoint,port,timeout=clipped_timeout(deadline,30,clock=clock))
        result['before'] = execution.invoke('ordinary','single',endpoint,port,timeout=clipped_timeout(deadline,5,clock=clock))
        owned = execution.start('ordinary','sample',endpoint,port)
        sleep(clipped_timeout(deadline,1.5,clock=clock))  # Scheduling only, never overlap evidence.
        result['contained'] = execution.invoke('contained','single',endpoint,port,timeout=clipped_timeout(deadline,15,clock=clock))
        result['during'] = execution.wait(owned,timeout=clipped_timeout(deadline,12,clock=clock))
        result['after'] = execution.invoke('ordinary','single',endpoint,port,timeout=clipped_timeout(deadline,5,clock=clock))
    except Exception:
        result['driver_error'] = True  # No raw path, identity, or error export.
    finally:
        if owned is not None:
            try: result['cleanup_confirmed'] = execution.close_owned(owned) is True
            except Exception: result['cleanup_confirmed'] = False
    return result


def nonce_frame(nonce, endpoint, role):
    if type(nonce) is not str or NONCE.fullmatch(nonce) is None or endpoint not in ENDPOINTS or role not in ('ordinary','contained'):
        raise ValueError('fixed nonce frame required')
    return f'N0A1 {nonce} {endpoint} {role}\n'.encode('ascii')


class NonceEndpoint:
    """Owned loopback-only raw TCP echo endpoint; no HTTP/DNS/proxy behavior.

    Both runner and guest bind only127.0.0.1. Runner exposure to10.0.2.2 uses
    existing QEMU user networking, not a new public listener. This remains
    unintegrated; endpoint traffic is not isolation acceptance.
    """
    def __init__(self, nonce, endpoint, deadline):
        self.frames = {nonce_frame(nonce,endpoint,role):role for role in ('ordinary','contained')}
        self.deadline=deadline; self.stop=threading.Event(); self.listener=None; self.thread=None
        self.connection=None; self.closed=False; self.error=False
        self.counts={'accepted':0,'ordinary_verified_frames':0,'contained_verified_frames':0,
                     'rejected':0,'timed_out':0}

    def start(self):
        try:
            self.listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.listener.bind(('127.0.0.1',0)); self.listener.listen(4); self.listener.settimeout(.1)
            self.port=self.listener.getsockname()[1]
            self.thread=threading.Thread(target=self.serve,daemon=True); self.thread.start()
            return self.port
        except Exception:
            self.finish(); raise

    def serve(self):
        accepted = 0
        try:
            while not self.stop.is_set() and time.monotonic() < self.deadline:
                if accepted >= 128:
                    self.error=True; break
                try: connection,_=self.listener.accept()
                except socket.timeout: continue  # Idle polls do not consume accept quota.
                accepted += 1; self.counts['accepted']=accepted; self.connection=connection
                connection_deadline=min(self.deadline,time.monotonic()+.5)
                try:
                    data=bytearray()
                    while len(data)<96 and not data.endswith(b'\n'):
                        remaining=connection_deadline-time.monotonic()
                        if remaining <= 0: raise TimeoutError('nonce frame deadline')
                        connection.settimeout(remaining)
                        chunk=connection.recv(1)
                        if not chunk: break
                        data.extend(chunk)
                    if bytes(data) in self.frames:
                        self.counts[self.frames[bytes(data)]+'_verified_frames'] += 1
                        remaining=connection_deadline-time.monotonic()
                        if remaining <= 0: raise TimeoutError('nonce response deadline')
                        connection.settimeout(remaining); connection.sendall(bytes(data))
                    else: self.counts['rejected'] += 1
                except TimeoutError: self.counts['timed_out'] += 1
                except OSError: self.counts['rejected'] += 1
                finally:
                    connection.close(); self.connection=None
        except OSError:
            if not self.stop.is_set(): self.error=True

    def finish(self):
        self.stop.set(); okay=True
        for value in (self.connection,self.listener):
            if value is not None:
                try: value.close()
                except OSError: okay=False
        if self.thread is not None:
            try: self.thread.join(1)
            except RuntimeError: okay=False
            okay = okay and not self.thread.is_alive()
        self.closed=okay
        stopped=self.thread is None or not self.thread.is_alive()
        return {'socket_cleanup_confirmed':okay,'endpoint_error':self.error,
                'receiver_counts':dict(self.counts) if stopped else None}

# Dedicated pinned-G audit stream, never merged actor stdout.
MAX_AUDIT = 128*1024
MAX_N0A_REPORT = 4096
AUDIT_FIELDS = {'event','backend','identity','tier','pid','exit_code'}
LAUNCHER_PHASES = ('not_started','configuration','budget','python_start','python_wait','report_read','report_parse','completed','transport')
LAUNCHER_FAILURES = ('none','original_unavailable','original_transport','configuration','budget','spawn','timeout','process_exit','report_absent','report_bound','report_parse','operation_failed','work_budget_exhausted')
EXECUTION_PHASES = ('not_started','disabled','configuration','binding','endpoint','guest','runner','cleanup','completed')


def audit_exit(data, actor_pid, executor_pid):
    if (type(data) is not bytes or len(data)>MAX_AUDIT or not integer(actor_pid,1,0xffffffff)
            or not integer(executor_pid,1,0xffffffff) or actor_pid==executor_pid): return None
    try: text=data.decode('utf-8','strict')
    except UnicodeError: return None
    candidates=[]
    for line in text.split('\n'):
        match=re.fullmatch(r'\[([0-9]{1,20})\] (\{.*\})',line)
        if match is None:
            if 'mxc.ProcessExited' in line:return None
            continue
        try: event=json.loads(match[2],object_pairs_hook=unique_object)
        except (ValueError,TypeError,RecursionError):
            if 'ProcessExited' in line:return None
            continue
        if type(event) is not dict or event.get('event')!='mxc.ProcessExited':continue
        if (int(match[1])>0xffffffffffffffff or set(event)!=AUDIT_FIELDS
                or event['backend']!='processcontainer' or event['identity']!='redacted' or event['tier']!='base-container'
                or not integer(event['pid'],1,0xffffffff)
                or not integer(event['exit_code'],-0x80000000,0x7fffffff)): return None
        candidates.append(event)
    if len(candidates)!=1 or candidates[0]['pid']!=actor_pid: return None
    return {'pid_verified':True,'pid_binding':'executor_audit','child_exit_code':candidates[0]['exit_code']}


def safe_argument(value):
    value=str(value)
    if any(character in value for character in '\r\n\0'): raise ValueError('unsafe diagnostic argument')
    return value


def closed_result(value):
    template=evaluate({},None)
    if type(value) is not dict or set(value)!=set(template): raise ValueError('N0a result shape')
    for key,expected in template.items():
        if key in ('status','endpoints'): continue
        if type(value[key]) is not type(expected) or value[key]!=expected: raise ValueError('N0a scope differs')
    if type(value['endpoints']) is not dict or set(value['endpoints'])!=set(ENDPOINTS): raise ValueError('N0a endpoints')
    endpoints={}
    for name in ENDPOINTS:
        row=value['endpoints'][name]; base=template['endpoints'][name]
        if type(row) is not dict or set(row)!=set(base): raise ValueError('N0a endpoint shape')
        if row['status'] not in ('inconclusive','connect_succeeded','observed_connect_denial'): raise ValueError('N0a status')
        if any(type(row[key]) is not bool for key in ('profile_verified','controls_verified','window_overlap_verified','connect_success_observed')):
            raise ValueError('N0a endpoint flags')
        if not integer(row['explicit_denials'],0,3): raise ValueError('N0a count')
        if row['status']=='connect_succeeded' and not (row['profile_verified'] and row['connect_success_observed']): raise ValueError('N0a failure attribution')
        if row['status']=='observed_connect_denial' and not (row['profile_verified'] and row['controls_verified'] and row['window_overlap_verified']
                and row['explicit_denials']==3 and not row['connect_success_observed']): raise ValueError('N0a denial prerequisites')
        endpoints[name]=dict(row)
    statuses=[row['status'] for row in endpoints.values()]
    status='connect_succeeded' if 'connect_succeeded' in statuses else ('observed_connect_denial' if statuses==['observed_connect_denial']*2 else 'inconclusive')
    if value['status']!=status: raise ValueError('N0a aggregate differs')
    template.update(status=status,endpoints=endpoints)
    return template


def closed_receiver(value):
    if type(value) is not dict or set(value)!={'socket_cleanup_confirmed','endpoint_error','receiver_counts'}: raise ValueError('receiver shape')
    if any(type(value[key]) is not bool for key in ('socket_cleanup_confirmed','endpoint_error')): raise ValueError('receiver flags')
    counts=value['receiver_counts']; keys={'accepted','ordinary_verified_frames','contained_verified_frames','rejected','timed_out'}
    if counts is not None:
        if type(counts) is not dict or set(counts)!=keys or any(not integer(v,0,128) for v in counts.values()): raise ValueError('receiver counters')
        if counts['ordinary_verified_frames']+counts['contained_verified_frames']>counts['accepted']: raise ValueError('receiver count consistency')
        if counts['rejected']>counts['accepted'] or counts['timed_out']>counts['accepted']: raise ValueError('receiver count consistency')
    return {'socket_cleanup_confirmed':value['socket_cleanup_confirmed'],'endpoint_error':value['endpoint_error'],
            'receiver_counts':None if counts is None else dict(counts)}


def default_host_n0a(reason='report_absent'):
    return {'schema_version':1,'experiment':'N0a-connect','receipt_verified':False,
            'reason':reason if reason in LAUNCHER_FAILURES else 'operation_failed',
            'result':evaluate({},None),'execution':{'phase':'not_started','failed':True,'cleanup_confirmed':False},
            'receiver':{'socket_cleanup_confirmed':False,'endpoint_error':False,'receiver_counts':None},
            'launcher':{'phase':'not_started','failure':'report_absent','python_exit_code':None,
                        'process_exit_confirmed':None,'timed_out':False,'budget_exhausted':False}}


def validate_host_n0a_envelope(value, expected):
    from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
    if type(value) is not dict or set(value)!={'schema_version','case_nonce','actor_sha256','report','launcher'}: raise ValueError('N0a envelope')
    if len(json.dumps(value,ensure_ascii=True).encode('ascii'))>MAX_N0A_REPORT: raise ValueError('N0a wire bound')
    if (type(value['schema_version']) is not int or value['schema_version']!=1
            or value['case_nonce']!=expected['case_nonce'] or value['actor_sha256']!=expected['actor_sha256']): raise ValueError('N0a outer provenance')
    launcher=value['launcher']; keys=set(default_host_n0a()['launcher'])
    if (type(launcher) is not dict or set(launcher)!=keys or launcher['phase'] not in LAUNCHER_PHASES
            or launcher['failure'] not in LAUNCHER_FAILURES
            or (launcher['python_exit_code'] is not None and not integer(launcher['python_exit_code'],-0x80000000,0x7fffffff))
            or (launcher['process_exit_confirmed'] is not None and type(launcher['process_exit_confirmed']) is not bool)
            or any(type(launcher[k]) is not bool for k in ('timed_out','budget_exhausted'))): raise ValueError('N0a launcher')
    result=default_host_n0a(launcher['failure']);result['launcher']=dict(launcher)
    report=value['report']
    if report is None: return result
    if type(report) is not dict or set(report)!={'schema_version','binding','result','execution','receiver'}: raise ValueError('N0a inner report')
    binding={'case_nonce':expected['case_nonce'],'actor_sha256':expected['actor_sha256'],
             'executor_sha256':MXC_G_EXECUTOR_SHA256,'build':26300,'ubr':9457}
    if type(report['schema_version']) is not int or report['schema_version']!=1 or report['binding']!=binding: raise ValueError('N0a observed binding')
    execution=report['execution']
    if (type(execution) is not dict or set(execution)!={'phase','failed','cleanup_confirmed'}
            or execution['phase'] not in EXECUTION_PHASES or type(execution['failed']) is not bool
            or type(execution['cleanup_confirmed']) is not bool): raise ValueError('N0a execution')
    result.update(receipt_verified=True,reason='none',result=closed_result(report['result']),
                  execution=dict(execution),receiver=closed_receiver(report['receiver']))
    if result['result']['status']!='connect_succeeded' and (execution['failed'] or not execution['cleanup_confirmed']
            or not result['receiver']['socket_cleanup_confirmed'] or result['receiver']['endpoint_error']
            or result['receiver']['receiver_counts'] is None
            or result['receiver']['receiver_counts']['ordinary_verified_frames']<5
            or result['receiver']['receiver_counts']['contained_verified_frames']!=0
            or launcher['failure']!='none' or launcher['python_exit_code']!=0 or launcher['process_exit_confirmed'] is not True
            or launcher['timed_out'] or launcher['budget_exhausted']):
        result['result']['status']='inconclusive'
        for row in result['result']['endpoints'].values():
            if row['status']=='observed_connect_denial':row['status']='inconclusive'
    return result
