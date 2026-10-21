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
FAILURES=('none','v6only_set','v6only_get','socket','exclusive','nonblocking','bind','getsockname','deadline','sendto','short_send','recv_select','recvfrom','echo_peer','echo_payload')
NETWORK_KEYS={'version','endpoint','phase','port','profileMatched','startupError','qpcFrequency','windowStartQpc','windowEndQpc','attempts','testOnly','socketsCleanupConfirmed'}
ATTEMPT_KEYS={'index','attempted','socketCreated','bindSucceeded','localPort','localIpv6','localScopeId','v6OnlySet','v6OnlyVerified','sendStartQpc','sendEndQpc','sendAccepted','sendBytes','nonceMatched','exchangeEndQpc','win32Error','failure','closed','closeError','closeQpc'}


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
        if self.socket.getsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY)!=1:raise ValueError('v6only')
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

