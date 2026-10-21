"""Standalone IPv6 UDP observations. No DNS, broker, or isolation acceptance.

Pure validation cannot authenticate a caller's identity/provenance context.
Production integration requires a separate explicit opt-in; TEST_ONLY is never production.
"""
import json
import re
import socket
import threading
import time

MAX_REPORT=32768
MAX_FRAME=128
PHASES=('before','sample','contained','after')
FAILURES=('none','v6only_set','v6only_get','v6only_length','v6only_zero','socket','exclusive','nonblocking','bind','getsockname','deadline','sendto','short_send','recv_select','recvfrom','echo_peer','echo_payload')
NETWORK_KEYS={'version','endpoint','phase','port','profileMatched','startupError','qpcFrequency','windowStartQpc','windowEndQpc','attempts','testOnly','socketsCleanupConfirmed'}
ATTEMPT_KEYS={'index','attempted','socketCreated','bindSucceeded','localPort','localIpv6','localScopeId','v6OnlySet','v6OnlyVerified','v6OnlyGetReturn','v6OnlyGetError','v6OnlyGetLength','v6OnlyGetValue','v6OnlyGetStage','sendStartQpc','sendEndQpc','sendAccepted','sendBytes','nonceMatched','exchangeEndQpc','win32Error','failure','closed','closeError','closeQpc'}


def integer(value,lo=0,hi=(1<<63)-1):return type(value) is int and lo<=value<=hi

def frame(nonce,phase,index):
    if type(nonce) is not str or re.fullmatch('[0-9a-f]{32}',nonce) is None or phase not in PHASES or not integer(index,0,39 if phase=='sample' else 2 if phase=='contained' else 0):raise ValueError('frame')
    return f'N0AU6 {nonce} {phase} {index}\n'.encode('ascii')

def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate')
        result[key]=value
    return result

def parse(raw):
    if type(raw) is not bytes or not 0<len(raw)<=MAX_REPORT:raise ValueError('report_bound')
    try:
        value=json.loads(raw.decode('ascii'),object_pairs_hook=unique,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('number')))
        if type(value) is not dict:raise ValueError('report')
        return value
    except (UnicodeError,RecursionError,json.JSONDecodeError):raise ValueError('report') from None

def validate_v6only(row):
    stage=row['v6OnlyGetStage'];returned=row['v6OnlyGetReturn'];error=row['v6OnlyGetError']
    length=row['v6OnlyGetLength'];value=row['v6OnlyGetValue']
    if stage not in ('not_attempted','api_error','length_mismatch','zero','nonzero'):raise ValueError('v6only_stage')
    if row['v6OnlyVerified'] is not (stage=='nonzero'):raise ValueError('v6only_verified')
    if stage!='nonzero' and (row['bindSucceeded'] or row['attempted']):raise ValueError('v6only_order')
    if stage=='not_attempted':
        if any(v is not None for v in (returned,error,length,value)) or row['v6OnlySet']:raise ValueError('v6only_unattempted')
        return
    if not row['socketCreated'] or not row['v6OnlySet'] or not integer(returned,-2**31,2**31-1) or not integer(length,-2**31,2**31-1):raise ValueError('v6only_type')
    if stage=='api_error':
        if returned!=-1 or not integer(error,0,2**32-1) or value is not None or row['failure']!='v6only_get' or row['win32Error']!=error:raise ValueError('v6only_api')
    else:
        if returned!=0 or error is not None:raise ValueError('v6only_return')
        if stage=='length_mismatch':
            if length in (1,4) or value is not None or row['failure']!='v6only_length' or row['win32Error']!=0:raise ValueError('v6only_length')
        elif length not in (1,4) or not integer(value,0,255 if length==1 else 2**32-1) or ((value==0)!=(stage=='zero')):raise ValueError('v6only_value')
        elif stage=='zero' and (row['failure']!='v6only_zero' or row['win32Error']!=0):raise ValueError('v6only_zero')
    if stage!='nonzero' and (row['bindSucceeded'] or row['attempted']):raise ValueError('v6only_order')

def validate_network(value,nonce,phase,port,endpoint='runner-v6',test_only=False):
    if phase not in PHASES or endpoint not in ('runner-v6','fixture-loopback-v6') or type(test_only) is not bool or not integer(port,1025,65535):raise ValueError('context')
    frame(nonce,phase,0)
    if type(value) is not dict or set(value)!=NETWORK_KEYS:raise ValueError('network')
    fixed={'version':1,'endpoint':endpoint,'phase':phase,'port':port,'testOnly':test_only}
    if any(type(value[k]) is not type(v) or value[k]!=v for k,v in fixed.items()):raise ValueError('binding')
    if any(type(value[k]) is not bool for k in ('profileMatched','socketsCleanupConfirmed')) or not integer(value['startupError'],0,2**32-1):raise ValueError('type')
    frequency=value['qpcFrequency'];start=value['windowStartQpc'];end=value['windowEndQpc']
    if not integer(frequency,1,10**9) or not integer(start,1) or not integer(end,start) or end-start>(10 if phase=='sample' else 3)*frequency:raise ValueError('clock')
    rows=value['attempts'];limit=40 if phase=='sample' else 3 if phase=='contained' else 1
    if type(rows) is not list or len(rows)>limit:raise ValueError('attempts')
    prior=start
    for index,row in enumerate(rows):
        if type(row) is not dict or set(row)!=ATTEMPT_KEYS or not integer(row['index'],0,39) or row['index']!=index:raise ValueError('attempt')
        if any(type(row[k]) is not bool for k in ('attempted','socketCreated','bindSucceeded','sendAccepted','nonceMatched','closed','v6OnlySet','v6OnlyVerified')):raise ValueError('type')
        if not integer(row['localPort'],0,65535) or type(row['localIpv6']) is not str or re.fullmatch('[0-9a-f]{32}',row['localIpv6']) is None or not integer(row['localScopeId'],0,2**32-1) or not integer(row['sendBytes'],-1,128) or any(not integer(row[k],0,2**32-1) for k in ('win32Error','closeError')) or row['failure'] not in FAILURES:raise ValueError('row')
        validate_v6only(row)
        if any(not integer(row[k]) for k in ('sendStartQpc','sendEndQpc','exchangeEndQpc','closeQpc')):raise ValueError('clock')
        if row['attempted']:
            if not row['v6OnlySet'] or not row['v6OnlyVerified'] or row['localScopeId']!=0 or row['localIpv6'].startswith('00000000000000000000ffff') or not row['socketCreated'] or not row['bindSucceeded'] or not row['localPort'] or not start<=prior<=row['sendStartQpc']<=row['sendEndQpc']<=row['exchangeEndQpc']<=end:raise ValueError('attempt_clock')
            prior=row['exchangeEndQpc']
        elif row['sendAccepted'] or row['nonceMatched']:raise ValueError('unattempted')
        if row['sendAccepted'] and (row['sendBytes']!=len(frame(nonce,phase,index)) or not row['attempted']):raise ValueError('send')
        if row['nonceMatched'] and not row['sendAccepted']:raise ValueError('echo')
        if row['closed'] and (not row['socketCreated'] or row['closeError']!=0 or row['closeQpc']<end):raise ValueError('close')
    return value

def native_identity(actor,nonce,phase,agentic_sid):
    if not(type(actor) is dict and type(actor.get('schemaVersion')) is int and actor['schemaVersion']==1 and actor.get('mode')=='actor-n0a-udp6' and actor.get('nonce')==nonce and actor.get('queriesSucceeded') is True and actor.get('errors')==[] and actor.get('tokenElevated') is False and integer(actor.get('pid'),1,2**32-1)):return False
    if phase=='contained':
        caps=actor.get('tokenCapabilities')
        return (actor.get('tokenIsAppContainer') is True and actor.get('isProcessInJob') is True and type(actor.get('tokenAppContainerSid')) is str and re.fullmatch(r'S-1-15-2(?:-[0-9]{1,10}){7}',actor['tokenAppContainerSid']) is not None and type(agentic_sid) is str and re.fullmatch(r'S-1-15-3(?:-[0-9]{1,10}){1,12}',agentic_sid) is not None and caps==[{'sid':agentic_sid,'attributes':4}] and type(caps[0]['attributes']) is int)
    return phase in ('before','sample','after') and actor.get('tokenIsAppContainer') is False and actor.get('tokenAppContainerSid') is None and actor.get('tokenCapabilities')==[]

def echo_success(row):
    return row['attempted'] and row['socketCreated'] and row['bindSucceeded'] and row['sendAccepted'] and row['nonceMatched'] and row['closed'] and row['win32Error']==0 and row['failure']=='none' and row['closeError']==0

def controls(reports,nonce,port,*,production=True):
    result=dict(all_selected_sendto_invoked=False,ordinary_controls_verified=False,explicit_send_denial=False,
                selected_send_accepted_count=0,selected_echo_observed=False,sockets_cleanup_confirmed=False,
                profile_flags_verified=False,runtime_acceptance=False)
    try:
        if type(reports) is not dict or 'contained' not in reports:return result
        selected=validate_network(reports['contained'],nonce,'contained',port,'runner-v6' if production else 'fixture-loopback-v6',not production)
        rows=selected['attempts'];frequency=selected['qpcFrequency'];start=selected['windowStartQpc'];end=selected['windowEndQpc']
        result['selected_send_accepted_count']=sum(r['sendAccepted'] for r in rows)
        result['selected_echo_observed']=any(r['nonceMatched'] for r in rows)
        ready=selected['startupError']==0 and (not production or selected['profileMatched'])
        result['all_selected_sendto_invoked']=ready and len(rows)==3 and all(r['attempted'] and r['bindSucceeded'] and r['socketCreated'] and r['localPort']>0 for r in rows) and rows[0]['sendStartQpc']==start and rows[-1]['exchangeEndQpc']==end and end>start
        result['explicit_send_denial']=result['all_selected_sendto_invoked'] and all(not r['sendAccepted'] and r['sendBytes']==-1 and r['failure']=='sendto' and r['win32Error']==10013 for r in rows)
        if set(reports)!=set(PHASES):return result
        networks={phase:validate_network(reports[phase],nonce,phase,port,'runner-v6' if production else 'fixture-loopback-v6',not production) for phase in PHASES}
        result['sockets_cleanup_confirmed']=all(n['socketsCleanupConfirmed'] and all(r['closed'] and r['closeError']==0 for r in n['attempts']) for n in networks.values())
        result['profile_flags_verified']=all(n['profileMatched'] for n in networks.values()) if production else False
        ready=ready and all(n['startupError']==0 for n in networks.values()) and (not production or result['profile_flags_verified'])
        ordinary=[networks[p] for p in ('before','sample','after')]
        valid=ready and all(n['qpcFrequency']==frequency and n['attempts'] and all(echo_success(r) for r in n['attempts']) for n in ordinary)
        before,sample,after=[n['attempts'] for n in ordinary]
        if valid:
            result['ordinary_controls_verified']=(len(before)==len(after)==1 and before[0]['exchangeEndQpc']<start and after[0]['sendStartQpc']>end and any(r['exchangeEndQpc']<start for r in sample) and any(start<=r['sendStartQpc']<=r['exchangeEndQpc']<=end for r in sample) and any(r['sendStartQpc']>end for r in sample))
    except (ValueError,TypeError,KeyError):pass
    return result


class Udp6Endpoint:
    """Owned localhost high-port echo; at most128 datagrams; at most129 bytes observed per read.

    Oversized frames are counted/rejected, never prefix-parsed. Raw peers/frames
    remain private. observed_bytes counts only returned bytes, not original wire
    lengths; Windows WSAEMSGSIZE returns no payload and contributes zero bytes.
    Same nonce/phase/index is calibration, not sender identity.
    """
    def __init__(self,nonce,deadline):
        frame(nonce,'before',0)
        self.frames={frame(nonce,p,i):(p,i) for p in PHASES for i in range(40 if p=='sample' else 3 if p=='contained' else 1)}
        self.deadline=deadline;self.socket=None;self.thread=None;self.stop=threading.Event();self.ready=threading.Event()
        self.observed=threading.Event();self.contained_observed=threading.Event();self.closed_uncertain=False;self.close_attempted=False;self.error=False
        self.counts=dict(datagrams=0,observed_bytes=0,verified=0,echoed=0,rejected=0,oversized=0,send_errors=0)
        self.seen=set();self.wrong_echo=False
    @classmethod
    def for_test_wrong_echo(cls,nonce,deadline):
        result=cls(nonce,deadline);result.wrong_echo=True;return result
    def start(self):
        if self.socket is not None or time.monotonic()>=self.deadline:raise ValueError('endpoint_start')
        self.socket=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        if self.socket.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY)==0:raise ValueError('v6only')
        if hasattr(socket,'SO_EXCLUSIVEADDRUSE'):self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
        self.socket.bind(('::1',0,0,0));self.socket.settimeout(.1)
        bound=self.socket.getsockname()
        if type(bound) is not tuple or len(bound)!=4 or bound[0]!='::1' or any(type(v) is not int or v!=0 for v in bound[2:]):raise ValueError('endpoint_address')
        port=bound[1]
        if not integer(port,1025,65535):raise ValueError('endpoint_port')
        self.thread=threading.Thread(target=self.serve,daemon=True);self.thread.start()
        if not self.ready.wait(max(0,min(1,self.deadline-time.monotonic()))):raise TimeoutError('endpoint_ready')
        return port
    def serve(self):
        self.ready.set()
        try:
            while not self.stop.is_set() and time.monotonic()<self.deadline:
                if self.counts['datagrams']>=128:self.error=True;return
                try:data,peer=self.socket.recvfrom(MAX_FRAME+1)
                except socket.timeout:continue
                except OSError as exc:
                    if self.stop.is_set():return
                    if getattr(exc,'winerror',None)==10040:
                        self.counts['datagrams']+=1;self.counts['oversized']+=1;continue
                    self.error=True;return
                self.counts['datagrams']+=1;self.counts['observed_bytes']+=len(data)
                if len(data)>MAX_FRAME:self.counts['oversized']+=1;continue
                if (type(peer) is not tuple or len(peer)!=4 or peer[0]!='::1' or not integer(peer[1],1,65535) or any(type(v) is not int or v!=0 for v in peer[2:])) or data not in self.frames:self.counts['rejected']+=1;continue
                self.counts['verified']+=1;self.seen.add(self.frames[data]);self.observed.set()
                if self.frames[data][0]=='contained':self.contained_observed.set()
                if time.monotonic()>=self.deadline:self.error=True;return
                try:
                    self.socket.settimeout(min(.1,max(0,self.deadline-time.monotonic())))
                    response=(b'X'+data[1:]) if self.wrong_echo else data
                    if self.socket.sendto(response,peer)!=len(response):raise OSError('short')
                    self.counts['echoed']+=1
                except OSError:self.counts['send_errors']+=1;self.error=True;return
            if not self.stop.is_set():self.error=True
        except Exception:self.error=True
    def finish(self,deadline):
        self.stop.set();okay=not self.closed_uncertain
        if self.socket is not None and not self.close_attempted:
            self.close_attempted=True
            try:self.socket.close()
            except Exception:okay=False;self.closed_uncertain=True
        stopped=self.thread is None
        if self.thread is not None:
            try:self.thread.join(max(0,min(deadline,self.deadline)-time.monotonic()))
            except RuntimeError:pass
            stopped=not self.thread.is_alive()
        if self.socket is not None:
            try:okay=okay and self.socket.fileno()==-1
            except Exception:okay=False
        return dict(cleanup_confirmed=okay and stopped,thread_stopped=stopped,socket_closed=okay,
                    error=self.error,datagram_observed=self.observed.is_set(),contained_observed=self.contained_observed.is_set(),counts=dict(self.counts) if stopped else None,
                    verified_indices={p:sorted(i for phase,i in self.seen if phase==p) for p in PHASES} if stopped else None)


# Optional integration has its own explicit gate. No TCP globals are changed.
EXECUTION_ENABLED=True

def tcp_helpers():
    import importlib.util
    import sys
    from pathlib import Path
    name='udp6_pinned_tcp_helpers'
    if name not in sys.modules:
        spec=importlib.util.spec_from_file_location(name,Path(__file__).with_name('windows_n0a_control.py'))
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module)
    return sys.modules[name]

from dataclasses import dataclass

@dataclass(frozen=True)
class UDP6Binding:
    nonce: str
    actor_sha256: str
    executor_sha256: str
    agentic_sid: str
    runner_port: int
    controller_compartment: int
    controller_elevated: bool
    controller_appcontainer: bool
    build: int = 26300
    ubr: int = 9457
    def valid(self):
        return (type(self.nonce) is str and re.fullmatch('[0-9a-f]{32}',self.nonce) is not None
                and all(type(x) is str and re.fullmatch('[0-9a-f]{64}',x) for x in (self.actor_sha256,self.executor_sha256))
                and type(self.agentic_sid) is str and re.fullmatch(r'S-1-15-3(?:-[0-9]{1,10}){1,12}',self.agentic_sid) is not None
                and integer(self.runner_port,1025,65535) and type(self.controller_compartment) is int and self.controller_compartment==1
                and self.controller_elevated is False and self.controller_appcontainer is False
                and type(self.build) is int and self.build==26300 and type(self.ubr) is int and self.ubr==9457)

def verify_binding(actor,expected_actor_sha256,executor,manifest,nonce,runner_port):
    if not integer(runner_port,1025,65535):raise ValueError('port')
    # Reuse only the read-only OS/source-token/pinned-G observation, not its
    # two-endpoint model or TCP actor identity acceptance.
    observed=tcp_helpers().verify_binding(actor,expected_actor_sha256,executor,manifest,nonce,(runner_port,runner_port))
    return UDP6Binding(observed.nonce,observed.actor_sha256,observed.executor_sha256,observed.agentic_sid,runner_port,
                      observed.controller_compartment,observed.controller_elevated,observed.controller_appcontainer,observed.build,observed.ubr)

def command(actor,report,binding,phase):
    if not isinstance(binding,UDP6Binding) or not binding.valid() or phase not in PHASES:raise ValueError('command')
    return [str(actor),'n0a-udp6',binding.nonce,str(report),str(binding.runner_port),phase]

def contained_policy(inputs,profile,actor,binding,required_environment):
    import subprocess
    from pathlib import Path
    value=tcp_helpers().proof_helpers().policy(inputs,profile,actor,binding.nonce,required_environment=required_environment)
    value['process']['commandLine']=subprocess.list2cmdline(command(actor,Path(profile)/'actor.json',binding,'contained'))
    return value

def bound_actor(value,binding):
    if not isinstance(binding,UDP6Binding) or not binding.valid() or type(value) is not dict:return None
    fixed={'nonce':binding.nonce,'actor_sha256':binding.actor_sha256,'executor_sha256':binding.executor_sha256,'build':binding.build,'ubr':binding.ubr}
    if any(type(value.get(k)) is not type(v) or value.get(k)!=v for k,v in fixed.items()):return None
    actor=value.get('actor')
    return actor if type(actor) is dict and actor.get('nonce')==binding.nonce and actor.get('mode')=='actor-n0a-udp6' else None

def provenance_verified(value,binding,phase):
    actor=bound_actor(value,binding)
    if actor is None or value.get('pid_verified') is not True:return False
    if phase=='contained':
        return (value.get('pid_binding')=='executor_audit' and integer(value.get('child_exit_code'),-2**31,2**31-1)
                and type(value.get('probe_exit_code')) is int and value['probe_exit_code']==0
                and tcp_helpers().proof_helpers().smoke.base_container_selected(value.get('probe'),0)
                and value.get('actual_tiers')==['base-container'])
    return phase in PHASES and value.get('pid_binding')=='ordinary_handle' and integer(value.get('child_exit_code'),-2**31,2**31-1)

def invocation_valid(value,binding,phase):
    actor=bound_actor(value,binding)
    if actor is None or not native_identity(actor,binding.nonce,phase,binding.agentic_sid) or not provenance_verified(value,binding,phase):return None
    try:network=validate_network(actor.get('udp6'),binding.nonce,phase,binding.runner_port)
    except (ValueError,TypeError):return None
    if (network['profileMatched'] is not True or network['startupError']!=0 or value.get('timed_out') is not False
            or value.get('harness_error') is not False or type(value.get('exit_code')) is not int or value['exit_code']!=0
            or value.get('child_exit_code')!=0):return None
    return network

def evaluate(cases,binding):
    result=controls({},'0'*32,1025)
    result.update(schema_version=1,experiment='N0a-UDP6',profile_verified={p:False for p in PHASES},
                  provenance_verified={p:False for p in PHASES},stage0_passed=False,product_acceptance=False,
                  privacy_qualified=False,psec_cleanup_independently_verified=False)
    networks={};valid=True
    if type(cases) is not dict:return result
    for phase in PHASES:
        value=cases.get(phase);actor=bound_actor(value,binding)
        if actor is None:valid=False;continue
        result['profile_verified'][phase]=native_identity(actor,binding.nonce,phase,binding.agentic_sid)
        result['provenance_verified'][phase]=provenance_verified(value,binding,phase)
        try:network=validate_network(actor.get('udp6'),binding.nonce,phase,binding.runner_port)
        except (ValueError,TypeError):valid=False;continue
        result['profile_verified'][phase]=result['profile_verified'][phase] and network['profileMatched']
        if result['profile_verified'][phase] and result['provenance_verified'][phase]:networks[phase]=network
        if invocation_valid(value,binding,phase) is None:valid=False
    if isinstance(binding,UDP6Binding):result.update(controls(networks,binding.nonce,binding.runner_port))
    if not valid or cases.get('driver_error') is not False or cases.get('cleanup_confirmed') is not True:
        # All-three sendto10013 is an independent bound API observation,
        # not a control/cleanup or isolation outcome. Do not erase it here.
        result['ordinary_controls_verified']=False;result['sockets_cleanup_confirmed']=False
    return result

def run_endpoint(execution,binding,deadline,*,approved=False,clock=time.monotonic,sleep=time.sleep):
    if not EXECUTION_ENABLED or not approved:raise PermissionError('UDP inactive')
    if not isinstance(binding,UDP6Binding) or not binding.valid():raise ValueError('binding')
    limit=lambda seconds:tcp_helpers().clipped_timeout(deadline,seconds,clock=clock)
    result={'driver_error':False,'cleanup_confirmed':False};owned=None
    try:
        execution.probe('runner-v6',binding.runner_port,timeout=limit(30))
        result['before']=execution.invoke('ordinary','before','runner-v6',binding.runner_port,timeout=limit(5))
        before=invocation_valid(result['before'],binding,'before')
        if before is None or before['socketsCleanupConfirmed'] is not True or len(before['attempts'])!=1 or not echo_success(before['attempts'][0]):
            raise ValueError('ordinary IPv6 admission failed')
        owned=execution.start('ordinary','sample','runner-v6',binding.runner_port)
        sleep(limit(1.5))
        result['contained']=execution.invoke('contained','contained','runner-v6',binding.runner_port,timeout=limit(15))
        result['sample']=execution.wait(owned,timeout=limit(12))
        result['after']=execution.invoke('ordinary','after','runner-v6',binding.runner_port,timeout=limit(5))
    except Exception:result['driver_error']=True
    finally:
        if owned is not None:
            try:result['cleanup_confirmed']=execution.close_owned(owned) is True
            except Exception:pass
    return result

def closed_result(value):
    template=evaluate({},None)
    if type(value) is not dict or set(value)!=set(template):raise ValueError('UDP result')
    for key,default in template.items():
        current=value[key]
        if type(default) is bool:
            if type(current) is not bool:raise ValueError('UDP flag')
            if key in ('runtime_acceptance','stage0_passed','product_acceptance','privacy_qualified','psec_cleanup_independently_verified') and current:raise ValueError('UDP acceptance')
        elif type(default) is dict:
            if type(current) is not dict or set(current)!=set(PHASES) or any(type(x) is not bool for x in current.values()):raise ValueError('UDP phases')
        elif key=='selected_send_accepted_count':
            if not integer(current,0,3):raise ValueError('UDP count')
        elif type(current) is not type(default) or current!=default:raise ValueError('UDP fixed')
    if value['explicit_send_denial'] and (not value['all_selected_sendto_invoked'] or value['selected_send_accepted_count'] or not value['profile_verified']['contained'] or not value['provenance_verified']['contained']):raise ValueError('UDP denial')
    return json.loads(json.dumps(value))

def default_host_udp6(reason='report_absent'):
    old=tcp_helpers().default_host_n0a(reason)
    return dict(schema_version=1,experiment='N0a-UDP6',receipt_verified=False,reason=old['reason'],result=evaluate({},None),execution=old['execution'],launcher=old['launcher'])

def validate_host_udp6_envelope(value,expected):
    from ruleproxy.windows_runtime_pins import MXC_G_EXECUTOR_SHA256
    if type(value) is not dict or set(value)!={'schema_version','case_nonce','actor_sha256','report','launcher'}:raise ValueError('UDP envelope')
    if len(json.dumps(value,ensure_ascii=True).encode('ascii'))>4096:raise ValueError('UDP bound')
    if type(value['schema_version']) is not int or value['schema_version']!=1 or value['case_nonce']!=expected['case_nonce'] or value['actor_sha256']!=expected['actor_sha256']:raise ValueError('UDP binding')
    launcher=value['launcher'];old=tcp_helpers();template=default_host_udp6()
    if (type(launcher) is not dict or set(launcher)!=set(template['launcher']) or launcher['phase'] not in old.LAUNCHER_PHASES or launcher['failure'] not in old.LAUNCHER_FAILURES
        or (launcher['python_exit_code'] is not None and not integer(launcher['python_exit_code'],-2**31,2**31-1))
        or (launcher['process_exit_confirmed'] is not None and type(launcher['process_exit_confirmed']) is not bool)
        or any(type(launcher[k]) is not bool for k in ('timed_out','budget_exhausted'))):raise ValueError('UDP launcher')
    template['launcher']=dict(launcher);template['reason']=launcher['failure']
    report=value['report']
    if report is None:return template
    binding=dict(case_nonce=expected['case_nonce'],actor_sha256=expected['actor_sha256'],executor_sha256=MXC_G_EXECUTOR_SHA256,build=26300,ubr=9457)
    if type(report) is not dict or set(report)!={'schema_version','binding','result','execution'} or type(report['schema_version']) is not int or report['schema_version']!=1 or report['binding']!=binding:raise ValueError('UDP report')
    execution=report['execution']
    if type(execution) is not dict or set(execution)!={'phase','failed','cleanup_confirmed'} or execution['phase'] not in old.EXECUTION_PHASES or any(type(execution[k]) is not bool for k in ('failed','cleanup_confirmed')):raise ValueError('UDP execution')
    template.update(receipt_verified=True,reason='none',result=closed_result(report['result']),execution=dict(execution))
    complete=(not execution['failed'] and execution['cleanup_confirmed'] and launcher['failure']=='none' and launcher['python_exit_code']==0 and launcher['process_exit_confirmed'] is True and not launcher['timed_out'] and not launcher['budget_exhausted'])
    if not complete:
        template['result']['ordinary_controls_verified']=False;template['result']['sockets_cleanup_confirmed']=False
    return template
