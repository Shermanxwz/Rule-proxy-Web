"""Fixed public synthetic corpus for the inactive native bridge core.

No test starts the native executable. Export creates only one fresh generated
header; it accepts no input corpus, endpoint, or private runtime data.
"""
import importlib.util
import hashlib
import os
import stat
import subprocess
import threading
import time
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
MAX_CASES = 1024
MAX_EVENTS = 256
MAX_TOTAL_EVENTS = 32768
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_NATIVE_OUTPUT = 65536


def _oracle():
    path = ROOT / '.github/windows_identity_proxy_bridge_model.py'
    spec = importlib.util.spec_from_file_location('_bridge_native_fixed_oracle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


m = _oracle()
c = m._codec()


def config():
    return c.BridgeConfig(bytes(range(16)), bytes(range(16, 32)), 51001, 51002, 11000)


def request():
    return (b'GET http://ruleproxy-identity-proof.invalid/' + config().case_id.hex().encode() +
            b' HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('output')
        result[key] = value
    return result


def validate_native_output(raw, expected):
    """Validate a supplied captured result, never launch a process to obtain it."""
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_NATIVE_OUTPUT:
        raise ValueError('output')
    if not raw.endswith(b'\n'):
        raise ValueError('output')
    body=raw[:-2] if raw.endswith(b'\r\n') else raw[:-1]
    if b'\n' in body or b'\r' in body or b'\0' in body:
        raise ValueError('output')
    try:
        value = json.loads(body.decode('ascii'), object_pairs_hook=_unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError('output')))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError('output') from None
    if (type(value) is not dict or set(value) !=
            {'schema_version', 'model_only', 'runtime_acceptance', 'cases'} or
            type(value['schema_version']) is not int or value['schema_version'] != 1 or
            value['model_only'] is not True or value['runtime_acceptance'] is not False):
        raise ValueError('output')
    rows = value['cases']
    if type(rows) is not list or len(rows) != len(expected):
        raise ValueError('output')
    for row, wanted in zip(rows, expected):
        if type(row) is not list or len(row) != 7 or any(type(x) is not int for x in row):
            raise ValueError('output')
        if (not 0 <= row[0] < MAX_CASES or row[1] not in FAILURES or row[2] not in FAILURES or
                not 0 <= row[3] <= 255 or any(not 0 <= n <= 63 for n in row[4:]) or
                row[5] & row[6] or (row[5] | row[6]) & ~row[4]):
            raise ValueError('output')
        if row != wanted:
            raise ValueError('conformance')
    return value

# Frozen descriptor mechanics: role0 frontend/1 relay; kind0 tick,1 frame,
# 2 HTTP bytes,3 HTTP finish,4 write,5 pipe EOF,6 close,7 I/O error,8 relay error.
# Output failure labels and resource bits are independent local-model goldens.
FAILURES = tuple(range(12))
RESOURCE_MASK = 63


def event(role, kind, selector=0, tick=1000, data=b'', value=0):
    return (role, kind, selector, tick, data, value)


def _parts(data, split):
    return (data,) if split is None or not 0 < split < len(data) else (data[:split], data[split:])


def coupled_success(split=None, request_split=None, response_split=None):
    """FIFO bytes actually written are delivered; barriers satisfy old oracle.

    The Python model is NOT used as an oracle for independent local receive events.
    Those traces below have separately authored expectations.
    """
    model = m.BridgeModel(config(), start=1000)
    events = []
    def transfer(role, kind):
        channel = 'relay_to_front' if role == 1 else 'front_to_relay'
        data = model.pending_output(channel)
        assert data == c.encode_frame(config(), kind)
        for chunk in _parts(data, split):
            events.append(event(role, 4, data=chunk, value=len(chunk)))
            model.write_progress(channel, len(chunk), now=1000)
        for chunk in _parts(data, split):
            events.append(event(1-role, 1, data=chunk))
            model.receive_frame(channel, chunk, now=1000)
    def write_http(role, data):
        channel = 'client_http' if role == 0 else 'relay_http'
        assert model.pending_output(channel) == data
        for chunk in _parts(data, split):
            events.append(event(role, 4, selector=1, data=chunk, value=len(chunk)))
            model.write_progress(channel, len(chunk), now=1000)
    def close(role, index):
        names = ('front_reader','front_writer','client_stream','relay_reader','relay_writer','relay_stream')
        events.append(event(role, 6, selector=index, value=1))
        model.close_result(names[index], True, now=1000)
    transfer(1, 1); transfer(0, 2)
    for chunk in _parts(request(), request_split):
        events.append(event(0, 2, data=chunk)); model.client_request_bytes(chunk, now=1000)
    events.append(event(0, 3)); model.finish_client_request(now=1000)
    transfer(0, 3); write_http(1, c.relay_request(config()))
    for chunk in _parts(c.expected_response(config()), response_split):
        events.append(event(1, 2, data=chunk)); model.relay_response_bytes(chunk, now=1000)
    events.append(event(1, 3)); model.relay_response_eof(now=1000)
    close(1, 5); transfer(1, 4); close(1, 4)
    events.append(event(0, 5)); model.pipe_eof('relay_to_front', now=1000)
    close(0, 0); write_http(0, c.expected_response(config())); close(0, 2)
    transfer(0, 5); close(0, 1)
    events.append(event(1, 5)); model.pipe_eof('front_to_relay', now=1000)
    close(1, 3)
    assert model.snapshot()['model_complete'] is True
    return events


def _front_ready():
    return [event(0,1,data=c.encode_frame(config(),1)),event(0,4,data=c.encode_frame(config(),2),value=48)]


def fixed_corpus():
    """Only these public deterministic cases may be exported."""
    cases = []
    def add(name, events, result, start=1000, deadline=11000):
        identifier = len(cases)
        cases.append({'id':identifier,'name':name,'events':tuple(events),
                      'start':start,'deadline':deadline,'expected':[identifier]+list(result)})
    add('coupled_complete',coupled_success(),(0,0,255,63,63,0))
    for split in range(1,48):
        add('frame_write_split_'+str(split),coupled_success(split=split),(0,0,255,63,63,0))
    for split in range(1,len(request())):
        add('request_split_'+str(split),coupled_success(request_split=split),(0,0,255,63,63,0))
    for split in range(1,len(c.expected_response(config()))):
        add('response_split_'+str(split),coupled_success(response_split=split),(0,0,255,63,63,0))
    for split in range(48,max(len(c.relay_request(config())),len(c.expected_response(config())))):
        add('http_write_split_'+str(split),coupled_success(split=split),(0,0,255,63,63,0))
    # Local observations do not require the other endpoint's hidden send ledger.
    add('local_init_without_remote_send',[event(0,1,data=c.encode_frame(config(),1))],(0,0,1,0,0,0))
    add('local_ready_without_remote_send',[event(1,4,data=c.encode_frame(config(),1),value=48),event(1,1,data=c.encode_frame(config(),2))],(0,0,2,0,0,0))
    add('local_request_before_remote_ready',_front_ready()+[event(0,2,data=request()),event(0,3)],(0,0,1,0,0,0))
    for offset in (0,4,5,6,7,8,24,40,41,42,43,44,45,46,47):
        wire=bytearray(c.encode_frame(config(),1));wire[offset]^=128
        add('frame_corrupt_'+str(offset),[event(0,1,data=bytes(wire))],(2,0,0,7,0,0))
    add('replay_init',[event(0,1,data=c.encode_frame(config(),1)),event(0,1,data=c.encode_frame(config(),1))],(3,0,1,7,0,0))
    add('frame_surplus',[event(0,1,data=c.encode_frame(config(),1)+b'x')],(11,0,0,7,0,0))
    for count in range(1,48):
        add('partial_frame_eof_'+str(count),[event(0,1,data=c.encode_frame(config(),1)[:count]),event(0,5)],(7,0,0,7,0,0))
    add('eof_before_response',[event(0,5)],(7,0,0,7,0,0))
    add('write_zero',[event(1,4,value=0)],(0,6,0,56,0,0))
    add('write_over',[event(1,4,value=49)],(0,6,0,56,0,0))
    add('deadline_equality',[event(0,0,tick=11000)],(9,0,0,7,0,0))
    add('deadline_before',[event(0,0,tick=10999)],(0,0,0,0,0,0))
    add('clock_backwards',[event(0,0,tick=999)],(8,0,0,7,0,0))
    add('close_wrong_owner',[event(0,6,selector=5,value=1)],(10,0,0,7,0,0))
    add('close_unrequested',[event(0,6,selector=0,value=1)],(10,0,0,7,0,0))
    add('close_uncertain',[event(0,0,tick=11000),event(0,6,selector=0,tick=11000,value=0)],(9,0,0,7,0,1))
    add('close_uncertain_retry',[event(0,0,tick=11000),event(0,6,selector=0,tick=11000,value=0),event(0,6,selector=0,tick=11000,value=1)],(9,0,0,7,0,1))
    for index, bad in enumerate((request()+b'x',request().replace(b'GET ',b'CONNECT '),
            request().replace(b'Host:',b'Host :'),request().replace(b'\r\n\r\n',b'\r\nHost: x\r\n\r\n'),
            request().replace(b'\r\n\r\n',b'\r\nTransfer-Encoding: chunked\r\n\r\n'),
            request().replace(b'\r\n\r\n',b'\r\nContent-Length: 1\r\n\r\n'),
            request().replace(b'\r\n\r\n',b'\r\nAuthorization: x\r\n\r\n'),
            request().replace(b'\r\n\r\n',b'\r\nX: '+b'x'*1024+b'\r\n\r\n'),
            request().replace(b'\r\n\r\n',b'\r\n'+b'X: y\r\n'*32+b'\r\n'))):
        add('http_rejected_'+str(index),_front_ready()+[event(0,2,data=bad),event(0,3)],(11 if index in (7,8) else 4,0,1,7,0,0))
    add('request_8193',_front_ready()+[event(0,2,data=b'x'*8193)],(11,0,1,7,0,0))
    # Independently allowed HTTP grammar, not merely the canonical request.
    positives=[request().replace(b'.invalid/',b'.invalid:80/'),
               request().replace(b'Host: ruleproxy-identity-proof.invalid',b'hOsT: ruleproxy-identity-proof.invalid:80'),
               request().replace(b'Host: ',b'Host:\t ').replace(b'.invalid\r\n',b'.invalid \t\r\n'),
               request()[:-2]+b'Content-Length: 0\r\n\r\n',
               request()[:-2]+b'X: '+b'x'*1019+b'\r\n\r\n',
               request()[:-2]+b'X: y\r\n'*31+b'\r\n']
    # Exactly8192 total,32 headers, each line<=1024 inclCRLF.
    base=request()[:-2]; lines=[b'X: '+b'\r\n' for _ in range(31)]
    remaining=8192-len(base)-2-sum(map(len,lines))
    for i in range(31):
        take=min(1019,remaining);lines[i]=b'X: '+b'x'*take+b'\r\n';remaining-=take
    assert remaining==0
    positives.append(base+b''.join(lines)+b'\r\n')
    for index,data in enumerate(positives):
        assert c.parse_proxy_request(config(),data)==c.relay_request(config())
        add('http_allowed_'+str(index),_front_ready()+[event(0,2,data=data),event(0,3),
            event(0,4,data=c.encode_frame(config(),3),value=48)],(0,0,1,0,0,0))
    for index,header in enumerate((b'Cookie: x',b'Set-Cookie: x',b'Upgrade: x',b'Proxy-Authorization: x',
                                  b'Content-Length: 0\r\nContent-Length: 0')):
        add('http_forbidden_'+str(index),_front_ready()+[event(0,2,data=request()[:-2]+header+b'\r\n\r\n'),event(0,3)],(4,0,1,7,0,0))
    add('request_exact_bound_plus1',_front_ready()+[event(0,2,data=positives[-1]+b'x')],(11,0,1,7,0,0))
    relay_requested=[event(1,4,data=c.encode_frame(config(),1),value=48),event(1,1,data=c.encode_frame(config(),2)),
                     event(1,1,data=c.encode_frame(config(),3))]
    relay_http_sent=relay_requested+[event(1,4,selector=1,data=c.relay_request(config()),value=len(c.relay_request(config())))]
    add('done_without_own_writer_close',relay_http_sent+[event(1,2,data=c.expected_response(config())),event(1,3),event(1,4,data=c.encode_frame(config(),4),value=48),event(1,1,data=c.encode_frame(config(),5))],(0,3,14,56,0,0))
    add('response_257',relay_http_sent+[event(1,2,data=b'x'*257)],(0,11,6,56,0,0))
    add('response_missing_eof',relay_http_sent+[event(1,2,data=c.expected_response(config()))],(0,0,6,0,0,0))
    add('response_wrong',relay_http_sent+[event(1,2,data=b'wrong'),event(1,3)],(0,5,6,56,0,0))
    front_request_sent=_front_ready()+[event(0,2,data=request()),event(0,3),event(0,4,data=c.encode_frame(config(),3),value=48)]
    # Complete local response frame + independently observed EOF permits success
    # bytes, without consulting a remote write/close ledger.
    local_response=front_request_sent+[event(0,1,data=c.encode_frame(config(),4)),event(0,5)]
    add('local_response_no_remote_ledger',local_response,(0,0,17,1,0,0))
    add('sticky_response_deadline',local_response+[event(0,0,tick=11000)],(9,0,17,7,0,0))
    add('sticky_response_late_cleanup',local_response+[event(0,6,selector=0,value=0)],(10,0,17,7,0,1))
    for status in range(1,5):
        add('relay_error_drain_'+str(status),relay_requested+[event(1,8,value=status),event(1,4,data=c.encode_frame(config(),4,status),value=48)],(0,5,6,56,0,0))
        add('front_error_'+str(status),front_request_sent+[event(0,1,data=c.encode_frame(config(),4,status))],(5,0,1,7,0,0))
    add('config_deadline',[],(1,1,0,63,0,0),deadline=11001)
    add('config_overflow',[],(1,1,0,63,0,0),start=2**64-1,deadline=9999)
    return cases


def validate_corpus(cases):
    if not 1 <= len(cases) <= MAX_CASES or [x['id'] for x in cases] != list(range(len(cases))):
        raise ValueError('corpus')
    total = size = 0
    for case in cases:
        if not 0 <= len(case['events']) <= MAX_EVENTS:
            raise ValueError('corpus')
        total += len(case['events'])
        for role,kind,selector,tick,data,value in case['events']:
            if (any(type(n) is not int for n in (role,kind,selector,tick,value)) or
                    type(data) is not bytes or role not in (0,1) or not 0<=kind<=8 or
                    not 0<=selector<=5 or not 0<=tick<2**64 or not 0<=value<2**32):
                raise ValueError('corpus')
            if ((kind not in (1,2,4) and data) or (kind==4 and (selector>1 or data and len(data)!=value)) or
                    (kind not in (4,6) and selector) or (kind==6 and value>1) or
                    (kind==8 and value not in (1,2,3,4)) or
                    (kind not in (4,6,8) and value)):
                raise ValueError('corpus')
            size += len(data)
    if total > MAX_TOTAL_EVENTS or size > MAX_INPUT_BYTES:
        raise ValueError('corpus')
    return total,size


def export_corpus(path):
    cases=fixed_corpus();validate_corpus(cases)
    lines=['// Fixed public synthetic corpus. Generated, not a runtime input.', '#pragma once',
           'namespace rpb_fixture {']
    empty='{nullptr,0}'
    for case in cases:
        for index,e in enumerate(case['events']):
            if e[4]:
                lines.append('constexpr uint8_t b_%d_%d[]={%s};'%(case['id'],index,','.join(map(str,e[4]))))
        lines.append('constexpr rpb::Event e_%d[]={'%case['id'])
        if not case['events']: lines.append('{0,0,0,0ULL,{nullptr,0},0U},')
        for index,(role,kind,selector,tick,data,value) in enumerate(case['events']):
            view=('{b_%d_%d,sizeof(b_%d_%d)}'%(case['id'],index,case['id'],index)) if data else empty
            lines.append('{%d,%d,%d,%dULL,%s,%dU},'%(role,kind,selector,tick,view,value))
        lines.append('};')
    lines.append('constexpr rpb::Case Cases[]={')
    ids=','.join(map(str,config().run_id)); casesid=','.join(map(str,config().case_id))
    for case in cases:
        lines.append('{%d,{{{%s}},{{%s}},51001,51002,%dULL,%dULL},e_%d,%d},'%
                     (case['id'],ids,casesid,case['start'],case['deadline'],case['id'],len(case['events'])))
    lines.extend(['};','constexpr size_t CaseCount=sizeof(Cases)/sizeof(Cases[0]);','}'])
    raw=('\n'.join(lines)+'\n').encode('ascii')
    if len(raw)>16*1024*1024:raise ValueError('header')
    with Path(path).open('xb') as stream:stream.write(raw)
    return len(cases)


RETAINED_OWNERS=[]
RUN_FAILURES=('verification','spawn','deadline','reader','overflow','exit','output','cleanup','internal')
MANIFEST_KEYS={'schemaVersion','modelOnly','runtimeAcceptance','compileOnly','executed',
               'coreSha256','conformanceSha256','fixtureSha256','codecSha256','modelSha256',
               'generatedHeaderSha256','executableSha256'}
SOURCE_FILES={
    'coreSha256':'.github/native/windows_identity_proxy_bridge_core.hpp',
    'conformanceSha256':'.github/native/windows_identity_proxy_bridge_conformance.cpp',
    'fixtureSha256':'tests/test_windows_identity_proxy_bridge_native.py',
    'codecSha256':'.github/windows_identity_proxy_bridge_codec.py',
    'modelSha256':'.github/windows_identity_proxy_bridge_model.py',
}


def _digest(value):
    return type(value) is str and len(value)==64 and all(x in '0123456789abcdef' for x in value)


def _regular_bytes(path,limit,deadline,clock):
    """Bounded bytes with one-shot FD closure; synchronous I/O is not cancellable."""
    if clock()>=deadline:raise ValueError('verification')
    before=os.stat(path,follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_size>limit or
            getattr(before,'st_file_attributes',0)&0x400):raise ValueError('verification')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NOFOLLOW',0))
    try:
        opened=os.fstat(fd)
        if (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):raise ValueError('verification')
        data=bytearray()
        while len(data)<=limit:
            if clock()>=deadline:raise ValueError('verification')
            chunk=os.read(fd,min(65536,limit+1-len(data)))
            if not chunk:break
            data.extend(chunk)
        after=os.fstat(fd); current=os.stat(path,follow_symlinks=False)
        # Windows path-stat and FD-stat may expose different ctime domains.
        # Compare each source with itself; cross-source identity excludes ctime.
        common=lambda x:(x.st_dev,x.st_ino,x.st_size,x.st_mtime_ns)
        signature=lambda x:common(x)+(x.st_ctime_ns,)
        if (len(data)>limit or signature(before)!=signature(current) or
                signature(opened)!=signature(after) or common(before)!=common(opened) or
                common(current)!=common(after)):
            raise ValueError('verification')
        if clock()>=deadline:raise ValueError('verification')
        return bytes(data)
    finally:
        held=fd;fd=None
        try:os.close(held)
        except BaseException:
            RETAINED_OWNERS.append(('file_close_uncertain',held))
            raise ValueError('cleanup') from None


def verify_build(executable,manifest,expected_digest,deadline,clock=time.monotonic):
    executable=Path(executable);manifest=Path(manifest)
    if (not _digest(expected_digest) or executable.name!='windows_identity_proxy_bridge_conformance.exe' or
            manifest.name!='BRIDGE-CORE-model-manifest.json' or executable.parent!=manifest.parent):
        raise ValueError('verification')
    # Reject alias/reparse directories, not just the final files.
    for path in (executable.parent,):
        if not path.is_absolute() or path.resolve(strict=True)!=path:raise ValueError('verification')
        for part in (path,)+tuple(path.parents):
            info=os.stat(part,follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0)&0x400:
                raise ValueError('verification')
    raw=_regular_bytes(manifest,8192,deadline,clock)
    if hashlib.sha256(raw).hexdigest()!=expected_digest:raise ValueError('verification')
    value=json.loads(raw.decode('utf-8'),object_pairs_hook=_unique,
                     parse_constant=lambda _:(_ for _ in ()).throw(ValueError('verification')))
    if (type(value) is not dict or set(value)!=MANIFEST_KEYS or
            type(value['schemaVersion']) is not int or value['schemaVersion']!=1 or
            value['modelOnly'] is not True or value['runtimeAcceptance'] is not False or
            value['compileOnly'] is not True or value['executed'] is not False):raise ValueError('verification')
    paths={key:ROOT/name for key,name in SOURCE_FILES.items()}
    paths['generatedHeaderSha256']=executable.parent/'windows_identity_proxy_bridge_cases.h'
    paths['executableSha256']=executable
    identities={}
    for key,path in paths.items():
        if not _digest(value[key]):raise ValueError('verification')
        if hashlib.sha256(_regular_bytes(path,16*1024*1024,deadline,clock)).hexdigest()!=value[key]:
            raise ValueError('verification')
        info=os.stat(path,follow_symlinks=False)
        identities[key]=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    info=os.stat(manifest,follow_symlinks=False)
    identities['manifest']=(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    return {'manifest':value,'identities':identities}


def _drain(pipe,state):
    try:
        while len(state['data'])<MAX_NATIVE_OUTPUT+1:
            part=os.read(pipe.fileno(),min(4096,MAX_NATIVE_OUTPUT+1-len(state['data'])))
            if not part:state['eof']=True;return
            state['data'].extend(part)
        state['overflow']=True
    except BaseException:state['error']=True
    finally:state['stopped']=True


def _cleanup_process(process,thread,reader,cutoff,clock):
    """Independent exact-owned stop/observation attempts; never name-based kills."""
    exited=False; code=None; uncertain=False; closed=True
    try:
        code=process.poll();exited=code is not None
    except BaseException:uncertain=True
    if not exited:
        try:process.kill()
        except BaseException:uncertain=True
    try:
        result=process.wait(timeout=max(0,cutoff-clock()))
        if type(result) is int:code=result;exited=True
    except BaseException:uncertain=True
    try:
        result=process.poll()
        if type(result) is int:code=result;exited=True
    except BaseException:uncertain=True
    stopped=thread is None
    if thread is not None:
        try:thread.join(timeout=max(0,cutoff-clock()))
        except BaseException:uncertain=True
        try:stopped=not thread.is_alive() and reader['stopped']
        except BaseException:uncertain=True;stopped=False
    if stopped:
        try:
            if process.stdout is not None:process.stdout.close()
        except BaseException:closed=False;uncertain=True
    else:closed=False
    handle=getattr(process,'_handle',None)
    if handle is not None:
        if exited:
            try:handle.Close()
            except BaseException:closed=False;uncertain=True
        else:closed=False
    if not exited:closed=False
    if clock()>cutoff:uncertain=True
    cleanup=exited and stopped and closed and not uncertain
    if not cleanup:RETAINED_OWNERS.append((process,thread,reader))
    return exited,code,stopped,closed,cleanup


def run_conformance(executable,manifest,expected_digest,*,clock=time.monotonic,
                    process_factory=subprocess.Popen,thread_factory=threading.Thread,
                    verifier=verify_build,drainer=_drain,sleeper=time.sleep):
    start=clock();deadline=start+10.0;retained_before=len(RETAINED_OWNERS)
    receipt={'schema_version':1,'model_only':True,'runtime_acceptance':False,
             'conformance_verified':False,'exit_observed':False,'reader_stopped':False,
             'handles_closed':False,'cleanup_confirmed':False,'cases':None,'failure':None}
    reader={'data':bytearray(),'eof':False,'overflow':False,'error':False,'stopped':False}
    process=None;thread=None;spawn_attempted=False;rows_verified=False;code=None
    def fail(label):
        if receipt['failure'] is None:receipt['failure']=label
    try:
        before=verifier(executable,manifest,expected_digest,deadline,clock)
        if clock()>=deadline:raise ValueError('deadline')
        spawn_attempted=True
        process=process_factory([str(executable)],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,close_fds=True)
        thread=thread_factory(target=drainer,args=(process.stdout,reader),daemon=True)
        thread.start()
        while True:
            if clock()>=deadline:fail('deadline');break
            code=process.poll()
            if reader['overflow']:fail('overflow');break
            if reader['error']:fail('reader');break
            if code is not None and reader['stopped']:break
            sleeper(min(.005,max(0,deadline-clock())))
        if receipt['failure'] is None:
            if type(code) is not int or code!=0:fail('exit')
            elif not reader['eof']:fail('reader')
            else:
                try:
                    cases=fixed_corpus()
                    validate_native_output(bytes(reader['data']),[x['expected'] for x in cases])
                    after=verifier(executable,manifest,expected_digest,deadline,clock)
                    if before!=after:raise ValueError('verification')
                    if clock()>=deadline:fail('deadline')
                    else:rows_verified=True;receipt['cases']=len(cases)
                except BaseException:fail('output')
    except BaseException as exc:
        label=str(exc) if type(exc) is ValueError and str(exc) in RUN_FAILURES else (
            'spawn' if spawn_attempted and process is None else 'internal')
        fail(label)
    finally:
        cutoff=clock()+1.0
        if process is not None:
            try:
                exited,code,stopped,closed,cleanup=_cleanup_process(process,thread,reader,cutoff,clock)
                receipt.update(exit_observed=exited,reader_stopped=stopped,handles_closed=closed,cleanup_confirmed=cleanup)
            except BaseException:
                RETAINED_OWNERS.append((process,thread,reader));fail('cleanup')
        elif spawn_attempted:
            RETAINED_OWNERS.append(('spawn_uncertain',))
        else:
            receipt.update(reader_stopped=True,handles_closed=True,cleanup_confirmed=True)
        if len(RETAINED_OWNERS)>retained_before:
            receipt['cleanup_confirmed']=False;receipt['handles_closed']=False
        if not receipt['cleanup_confirmed']:fail('cleanup')
    receipt['conformance_verified']=rows_verified and code==0 and receipt['cleanup_confirmed'] and receipt['failure'] is None
    return receipt


class NativeCorpusTests(unittest.TestCase):
    def test_coupled_oracle_and_fixed_caps(self):
        cases=fixed_corpus(); events,size=validate_corpus(cases)
        self.assertLessEqual(events,32768);self.assertLessEqual(size,2097152)
        self.assertTrue(any(len(e[4])==8193 for x in cases for e in x['events']))
        self.assertTrue(any(len(e[4])==257 for x in cases for e in x['events']))
        self.assertTrue(all(len(x['expected'])==7 for x in cases))

    def test_generated_header_is_fresh_deterministic_public_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/'a.h';b=Path(tmp)/'b.h'
            self.assertEqual(export_corpus(a),export_corpus(b))
            self.assertEqual(a.read_bytes(),b.read_bytes())
            with self.assertRaises(FileExistsError):export_corpus(a)
            self.assertNotIn(b'callback',a.read_bytes())
            self.assertIn(b'namespace rpb_fixture',a.read_bytes())

    def test_byte_offsets_endian_and_local_refinement_goldens(self):
        frame=c.encode_frame(config(),4,3)
        self.assertEqual(frame[:8],b'RPB1\x04\0\0\0')
        self.assertEqual(frame[40:],b'\x03\0\0\0\x03\0\0\0')
        cases={x['name']:x for x in fixed_corpus()}
        self.assertEqual(cases['local_init_without_remote_send']['expected'][1:], [0,0,1,0,0,0])
        self.assertEqual(cases['local_response_no_remote_ledger']['expected'][1:], [0,0,17,1,0,0])
        self.assertEqual(cases['sticky_response_late_cleanup']['expected'][1:], [10,0,17,7,0,1])
        # Demonstrate why arbitrary local events cannot use omniscient Python oracle.
        x=m.BridgeModel(config(),start=1000)
        x.receive_frame('relay_to_front',c.encode_frame(config(),1),now=1000)
        self.assertEqual(x.failure,'order')

    def test_output_strict_one_line_closed_schema(self):
        rows=[x['expected'] for x in fixed_corpus()]
        value={'schema_version':1,'model_only':True,'runtime_acceptance':False,'cases':rows}
        raw=json.dumps(value,separators=(',',':')).encode()+b'\n'
        self.assertLessEqual(len(raw),65536)
        self.assertEqual(validate_native_output(raw,rows),value)
        self.assertEqual(validate_native_output(raw[:-1]+b'\r\n',rows),value)
        bad=[raw+b'\n',raw[:-1],raw[:-1]+b'\r\r\n',b'\0'+raw,b'\r'+raw,b'x'*65537,
             b'{"schema_version":1,"schema_version":1}\n',b'{"x":NaN}\n']
        for field,replacement in [('schema_version',True),('model_only',1),('runtime_acceptance',0),('cases',rows[:-1])]:
            changed=dict(value);changed[field]=replacement;bad.append(json.dumps(changed).encode()+b'\n')
        for item in bad:
            with self.assertRaises(ValueError):validate_native_output(item,rows)
        mutated=json.loads(raw);mutated['cases'][0][0]=True
        with self.assertRaises(ValueError):validate_native_output(json.dumps(mutated).encode()+b'\n',rows)

    def test_negative_corpus_is_not_truncated_or_vacuous(self):
        for case in fixed_corpus():
            if case['name'].startswith('http_rejected_'):
                data=next(e[4] for e in case['events'] if e[1]==2)
                with self.assertRaises(c.BridgeProtocolError):c.parse_proxy_request(config(),data)
            if case['name'].startswith('frame_corrupt_'):
                with self.assertRaises(c.BridgeProtocolError):c.decode_frame(config(),case['events'][0][4])
        cases=fixed_corpus()
        with self.assertRaises(ValueError):validate_corpus(cases*3)
        one=dict(cases[0]);one['events']=(event(0,0),)*257
        with self.assertRaises(ValueError):validate_corpus([one])
        one['events']=(event(0,2,data=b'x'*(MAX_INPUT_BYTES+1)),)
        with self.assertRaises(ValueError):validate_corpus([one])

    def test_strict_enum_masks_even_if_expected_is_malicious(self):
        for row in ([0,12,0,0,0,0,0],[0,0,0,256,0,0,0],
                    [0,0,0,0,64,0,0],[0,0,0,0,1,1,1],[0,0,0,0,0,1,0],
                    [0,0,0,0,0,0,True]):
            raw=json.dumps({'schema_version':1,'model_only':True,'runtime_acceptance':False,'cases':[row]}).encode()+b'\n'
            with self.assertRaises(ValueError):validate_native_output(raw,[row])

    def test_native_driver_has_no_runtime_input_and_fixed_bounds(self):
        core=(ROOT/'.github/native/windows_identity_proxy_bridge_core.hpp').read_text()
        driver=(ROOT/'.github/native/windows_identity_proxy_bridge_conformance.cpp').read_text()
        self.assertLess(driver.index('if(argc!=1)'),driver.index('if(!corpus_valid())'))
        for token in ('MaxCases=1024','MaxEventsPerCase=256','MaxEvents=32768','MaxBytes=2*1024*1024','Buffer<65536>'):
            self.assertIn(token,driver)
        for forbidden in ('#include <windows.h>','#include <winsock','CreateProcess','getenv(',
                          'std::cin','fopen(', 'socket(', 'system(', 'std::function', '#pragma pack'):
            self.assertNotIn(forbidden,core+driver)
        self.assertIn('std::fwrite',driver)

    def test_compile_helper_never_executes_binary(self):
        source=(ROOT/'.github/build_windows_identity_proxy_bridge_core.ps1').read_text()
        for word in ('/W4','/WX','/std:c++17','/MT','--export-corpus','Source changed during compilation.',
                     'Generated header changed during compilation.','compileOnly=$true','executed=$false'):
            self.assertIn(word,source)
        self.assertNotIn('& $exe',source)
        self.assertNotIn('Start-Process',source)


class RunnerTests(unittest.TestCase):
    class Clock:
        def __init__(self):self.now=0.0
        def __call__(self):return self.now
        def sleep(self,amount):self.now+=amount
    class Pipe:
        def __init__(self,close_error=False):self.closes=0;self.close_error=close_error
        def close(self):
            self.closes+=1
            if self.close_error:raise OSError('PRIVATE PATH')
    class Process:
        def __init__(self,mode='ok'):
            self.mode=mode;self.calls=[];self.stdout=RunnerTests.Pipe(mode=='close_error');self.killed=False
        def poll(self):
            self.calls.append('poll')
            if self.mode=='poll_error':raise OSError('PRIVATE PID')
            if self.mode in ('timeout','kill_error','wait_error','unknown') and not self.killed:return None
            return 7 if self.mode=='badexit' else 0
        def kill(self):
            self.calls.append('kill')
            if self.mode=='kill_error':raise OSError('PRIVATE')
            if self.mode!='unknown':self.killed=True
        def wait(self,timeout):
            self.calls.append('wait')
            if self.mode in ('wait_error','unknown'):raise subprocess.TimeoutExpired('PRIVATE',timeout)
            self.killed=True;return 7 if self.mode=='badexit' else 0
    class Thread:
        def __init__(self,*,target,args,daemon):self.target=target;self.args=args;self.alive=False
        def start(self):self.target(*self.args)
        def join(self,timeout):pass
        def is_alive(self):return self.alive

    def exercise(self,mode='ok',data=None,reader_error=False,overflow=False,eof=True,verifier=None):
        clock=self.Clock();process=self.Process(mode)
        if data is None:
            data=json.dumps({'schema_version':1,'model_only':True,'runtime_acceptance':False,
                             'cases':[x['expected'] for x in fixed_corpus()]},separators=(',',':')).encode()+b'\n'
        def drain(pipe,state):state.update(data=bytearray(data),eof=eof,stopped=True,error=reader_error,overflow=overflow)
        kwargs=[]
        def spawn(*args,**kw):kwargs.append(kw);return process
        result=run_conformance('/fixed/windows_identity_proxy_bridge_conformance.exe','/fixed/BRIDGE-CORE-model-manifest.json','a'*64,
             clock=clock,process_factory=spawn,thread_factory=self.Thread,
             verifier=verifier or (lambda *args:{}),drainer=drain,sleeper=clock.sleep)
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual(kwargs[0]['stdin'],subprocess.DEVNULL)
        self.assertEqual(kwargs[0]['stderr'],subprocess.DEVNULL)
        return result,process,clock

    def test_explicit_runner_success_only_mocked_no_native_process(self):
        result,process,clock=self.exercise()
        self.assertTrue(result['conformance_verified']);self.assertTrue(result['cleanup_confirmed'])
        self.assertEqual(process.stdout.closes,1);self.assertFalse(result['runtime_acceptance'])

    def test_faults_are_closed_and_cleanup_independent(self):
        for mode,options in [('timeout',{}),('poll_error',{}),('kill_error',{}),('wait_error',{}),
                             ('unknown',{}),('close_error',{}),('badexit',{}),
                             ('ok',{'reader_error':True}),('ok',{'overflow':True}),
                             ('ok',{'data':b'{'}),('ok',{'eof':False})]:
            with self.subTest(mode=mode,options=tuple(options)):
                result,process,clock=self.exercise(mode,**options)
                self.assertFalse(result['conformance_verified']);self.assertIn(result['failure'],RUN_FAILURES)
                self.assertIn('wait',process.calls)
                self.assertLessEqual(clock.now,11.01)
                if mode in ('poll_error','kill_error','wait_error','unknown','close_error'):
                    self.assertFalse(result['cleanup_confirmed']);self.assertIn(process,[x[0] for x in RETAINED_OWNERS if isinstance(x,tuple)])
                self.assertLessEqual(process.stdout.closes,1)

    def test_spawn_unknown_and_expired_before_spawn(self):
        clock=self.Clock()
        def spawn(*a,**k):raise OSError('PRIVATE PATH')
        result=run_conformance('x','y','a'*64,clock=clock,process_factory=spawn,verifier=lambda *a:{})
        self.assertEqual(result['failure'],'spawn');self.assertFalse(result['cleanup_confirmed'])
        called=[]
        def expired(*a):clock.now=10.0
        result=run_conformance('x','y','a'*64,clock=clock,process_factory=lambda *a,**k:called.append(1),verifier=lambda *a:(_ for _ in ()).throw(ValueError('deadline')))
        self.assertFalse(called);self.assertEqual(result['failure'],'deadline')
        clock.now=0
        result=run_conformance('x','y','a'*64,clock=clock,process_factory=lambda *a,**k:called.append(1),verifier=expired)
        self.assertFalse(called);self.assertEqual(result['failure'],'deadline')
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_late_post_verification_and_mutation_cannot_pass(self):
        calls=[]
        def changed(*args):
            calls.append(1)
            if len(calls)==2:raise ValueError('verification')
        result,_,_=self.exercise(verifier=changed)
        self.assertFalse(result['conformance_verified']);self.assertEqual(len(calls),2)
        def late(*args):
            if len(calls)==3:args[-1].now=args[-2]
            calls.append(1)
        result,_,_=self.exercise(verifier=late)
        self.assertFalse(result['conformance_verified'])

    def test_reader_cap_and_failure_never_exports_bytes(self):
        state={'data':bytearray(),'eof':False,'overflow':False,'error':False,'stopped':False}
        pipe=mock.Mock();pipe.fileno.return_value=3
        with mock.patch.object(os,'read',side_effect=lambda fd,n:b'x'*n):_drain(pipe,state)
        self.assertEqual(len(state['data']),65537);self.assertTrue(state['overflow']);self.assertTrue(state['stopped'])
        state={'data':bytearray(),'eof':False,'overflow':False,'error':False,'stopped':False}
        with mock.patch.object(os,'read',side_effect=OSError('PRIVATE')):_drain(pipe,state)
        self.assertTrue(state['error']);self.assertTrue(state['stopped'])

    def test_manifest_exact_files_hashes_and_mutation(self):
        clock=self.Clock()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp).resolve();exe=root/'windows_identity_proxy_bridge_conformance.exe'
            header=root/'windows_identity_proxy_bridge_cases.h';manifest=root/'BRIDGE-CORE-model-manifest.json'
            exe.write_bytes(b'synthetic NOT executable');header.write_bytes(b'fixed synthetic header')
            value={'schemaVersion':1,'modelOnly':True,'runtimeAcceptance':False,'compileOnly':True,'executed':False}
            value.update({key:hashlib.sha256((ROOT/path).read_bytes()).hexdigest() for key,path in SOURCE_FILES.items()})
            value['generatedHeaderSha256']=hashlib.sha256(header.read_bytes()).hexdigest()
            value['executableSha256']=hashlib.sha256(exe.read_bytes()).hexdigest()
            raw=json.dumps(value).encode();manifest.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
            self.assertEqual(verify_build(exe,manifest,digest,10,clock)['manifest'],value)
            from types import SimpleNamespace
            actual_fstat=os.fstat
            def windows_fd(fd):
                x=actual_fstat(fd)
                return SimpleNamespace(st_dev=x.st_dev,st_ino=x.st_ino,st_size=x.st_size,
                    st_mtime_ns=x.st_mtime_ns,st_ctime_ns=x.st_ctime_ns+100000,st_mode=x.st_mode)
            with mock.patch.object(os,'fstat',side_effect=windows_fd):
                self.assertEqual(verify_build(exe,manifest,digest,10,clock)['manifest'],value)
            exe.write_bytes(b'changed')
            with self.assertRaises(ValueError):verify_build(exe,manifest,digest,10,clock)
            with self.assertRaises(ValueError):verify_build(exe,manifest,'0'*64,10,clock)
            for bad in (raw+b' {}',b'{"x":NaN}',b'{"x":1,"x":2}',raw.decode().encode('utf-16')):
                manifest.write_bytes(bad)
                with self.assertRaises((ValueError,UnicodeError)):
                    verify_build(exe,manifest,hashlib.sha256(bad).hexdigest(),10,clock)
            with self.assertRaises(ValueError):verify_build(Path('relative')/exe.name,Path('relative')/manifest.name,digest,10,clock)
            value['schemaVersion']=True;manifest.write_text(json.dumps(value))
            with self.assertRaises(ValueError):verify_build(exe,manifest,hashlib.sha256(manifest.read_bytes()).hexdigest(),10,clock)

    def test_windows_path_fd_ctime_domains_remain_independently_bracketed(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixed';path.write_bytes(b'fixed')
            original_stat=os.stat;original_fstat=os.fstat
            def altered(value,ctime):
                return SimpleNamespace(st_mode=value.st_mode,st_size=value.st_size,
                    st_dev=value.st_dev,st_ino=value.st_ino,st_mtime_ns=value.st_mtime_ns,
                    st_ctime_ns=ctime,st_file_attributes=0)
            def path_stat(*a,**k):return altered(original_stat(*a,**k),100)
            def fd_stat(*a,**k):return altered(original_fstat(*a,**k),200)
            with mock.patch.object(os,'stat',side_effect=path_stat),mock.patch.object(os,'fstat',side_effect=fd_stat):
                self.assertEqual(_regular_bytes(path,10,10,self.Clock()),b'fixed')
            calls=[]
            def changing_fd(*a,**k):
                calls.append(1);return altered(original_fstat(*a,**k),200+len(calls))
            with mock.patch.object(os,'stat',side_effect=path_stat),mock.patch.object(os,'fstat',side_effect=changing_fd):
                with self.assertRaisesRegex(ValueError,'^verification$'):_regular_bytes(path,10,10,self.Clock())
            calls=[]
            def changing_path(*a,**k):
                calls.append(1);return altered(original_stat(*a,**k),100+len(calls))
            with mock.patch.object(os,'stat',side_effect=changing_path),mock.patch.object(os,'fstat',side_effect=fd_stat):
                with self.assertRaisesRegex(ValueError,'^verification$'):_regular_bytes(path,10,10,self.Clock())

    def test_file_close_uncertainty_is_retained(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'fixed';path.write_bytes(b'x')
            original=os.close;fds=[]
            def failed(fd):fds.append(fd);raise OSError('PRIVATE')
            try:
                with mock.patch.object(os,'close',side_effect=failed):
                    with self.assertRaisesRegex(ValueError,'^cleanup$'):_regular_bytes(path,2,10,self.Clock())
            finally:
                for fd in fds:original(fd) # fixture releases its deliberately still-open mock FD
            self.assertEqual(len(fds),1)


class WorkflowTests(unittest.TestCase):
    def test_dedicated_gate_is_exclusive_and_pure(self):
        text=(ROOT/'.github/workflows/windows-identity-proxy-core-gates.yml').read_text()
        self.assertEqual(text.count('    if: ${{'),2)
        self.assertIn('timeout-minutes: 5',text);self.assertIn('timeout-minutes: 8',text)
        self.assertEqual(text.count("github.event_name == 'push'"),2)
        self.assertEqual(text.count("github.ref == 'refs/heads/dot/windows-isolation-proof'"),2)
        markers=('identity-direct-stage0','identity-pipe','identity-restricted-r0','identity-serviced-stage0',
                 'identity-stage0b','identity-startup-paired','identity-stock-stage0','identity-win11-stage0',
                 'n0a-capture','n0a-connect','n0a-udp-parent','n0a-udp','n0a-udp6')
        for marker in markers:
            self.assertEqual(text.count("!contains(github.event.head_commit.message, '["+marker+"-runtime]')"),2)
        self.assertEqual(text.count("m.count('[identity-proxy-core-gates]')==1"),2)
        self.assertEqual(text.count('--run-conformance --executable'),2)
        self.assertEqual(text.count('--expected-manifest-sha256'),2)
        self.assertEqual(text.count('sum(counts[:2])==44'),2)
        self.assertEqual(text.count('result.wasSuccessful() and not result.skipped'),2)
        for name in ('codec','model','native'):
            self.assertGreaterEqual(text.count('test_windows_identity_proxy_bridge_'+name+'.py'),3)
        for forbidden in ('upload-artifact','download-artifact','workflow_dispatch:','schedule:',
                          'continue-on-error','qemu-system','windows_identity_direct_stage0.py','pip install'):
            self.assertNotIn(forbidden,text)
        self.assertEqual(text.count('persist-credentials: false'),2)
        self.assertEqual(text.count('ref: ${{ github.sha }}'),2)

    def test_cleanup_reader_thread_and_handle_faults(self):
        clock=RunnerTests.Clock();process=RunnerTests.Process()
        class LiveThread:
            def join(self,timeout):raise RuntimeError('PRIVATE')
            def is_alive(self):return True
        result=_cleanup_process(process,LiveThread(),{'stopped':False},1,clock)
        self.assertTrue(result[0]);self.assertFalse(result[-1]);self.assertEqual(process.stdout.closes,0)
        class Handle:
            def __init__(self):self.calls=0
            def Close(self):self.calls+=1;raise OSError('PRIVATE')
        process=RunnerTests.Process();process._handle=Handle()
        result=_cleanup_process(process,None,{},1,clock)
        self.assertFalse(result[-1]);self.assertEqual(process._handle.calls,1)
        process=RunnerTests.Process()
        def late_wait(timeout):clock.now=2;return 0
        process.wait=late_wait
        self.assertFalse(_cleanup_process(process,None,{},1,clock)[-1])

    def test_thread_start_error_retains_owner_and_still_waits(self):
        clock=RunnerTests.Clock();process=RunnerTests.Process()
        class BadThread(RunnerTests.Thread):
            def start(self):raise RuntimeError('PRIVATE')
            def join(self,timeout):raise RuntimeError('PRIVATE')
        result=run_conformance('x','y','a'*64,clock=clock,process_factory=lambda *a,**k:process,
                               thread_factory=BadThread,verifier=lambda *a:{})
        self.assertFalse(result['cleanup_confirmed']);self.assertIn('wait',process.calls)
        self.assertEqual(process.stdout.closes,0);self.assertNotIn('PRIVATE',json.dumps(result))


if __name__=='__main__':
    if len(sys.argv)==3 and sys.argv[1]=='--export-corpus':
        try:
            count=export_corpus(sys.argv[2])
        except (OSError,ValueError,AssertionError):
            raise SystemExit('fixed corpus export failed') from None
        print(json.dumps({'schema_version':1,'model_only':True,'cases':count},separators=(',',':')))
    elif len(sys.argv)==8 and sys.argv[1]=='--run-conformance' and sys.argv[2]=='--executable' and sys.argv[4]=='--manifest' and sys.argv[6]=='--expected-manifest-sha256':
        result=run_conformance(sys.argv[3],sys.argv[5],sys.argv[7])
        print(json.dumps(result,separators=(',',':')))
        raise SystemExit(0 if result['conformance_verified'] else 1)
    elif len(sys.argv)==1:
        unittest.main()
    else:
        raise SystemExit('arguments')
