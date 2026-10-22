"""B: generated zero-capability frontend and a held ordinary loopback origin.

Default entry only performs read-only preflight. The opt-in local owner uses the
existing atomic Job guard and absolute QPC lifecycle. This is a relay/origin
network mechanism; a real selected application and proxy isolation are untested.
"""
from __future__ import annotations
import argparse
import ctypes as C
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import sys

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('origin_local_guard',Path(__file__).with_name('windows_identity_proxy_pipe_ac_local.py'))
local=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(local)
a=local.controller;launcher=a.launcher;helpers=a.pipe_helpers;guest=local.guest
MAX_PRIVATE=128*1024;MAX_NATIVE=8192;MAX_READY=4096;MAX_PUBLIC=4096
ACTOR='windows_identity_proxy_origin_actor.exe'
MANIFEST='identity-proxy-origin-manifest.json'
BOUNDARY='generated-front-and-sink-native-relay-origin'
SCOPE='one-local-zero-cap-pair-owned-loopback-origin-v1'
SOURCES=(*local.SOURCES,'.github/windows_identity_proxy_origin_probe.py')
NATIVE_SOURCES={**local.NATIVE_SOURCES,
    'actorSourceSha256':'.github/native/windows_identity_proxy_origin_actor.cpp',
    'pipeHelperSha256':'.github/native/windows_identity_proxy_pipe_actor.cpp',
    'originTransportSha256':'.github/native/windows_identity_proxy_origin_transport.hpp'}
RELAY_BOOLS=('wsa_startup','wsa_cleanup','inheritance_cleared','socket_created','connect_attempted',
    'connect_completed','peer_loopback','request_complete','send_shutdown','response_exact','response_eof')
FIXTURE_BOOLS=('wsa_startup','wsa_cleanup','listener_created','inheritance_cleared','exclusive',
    'bind_loopback','accepted','peer_loopback','request_exact','request_eof','response_complete','send_shutdown')
ORIGIN_FACTS=('held_identity_verified','image_verified','ready_bound','report_bound','request_exact',
    'request_eof','response_complete','response_eof','relay_close_verified','fixture_close_verified',
    'peer_tuple_bound','cleanup_verified','connect_attempted_observed','accepted_observed')


def encode(value):return local.encode(value)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def decode(raw):return guest.decode(raw)
def require(value):
    if not value:raise ValueError('origin_report')


def payloads(case,port):
    require(a.nonce(case) and a.integer(port,49153,65535))
    request=('GET /p1/'+case+' HTTP/1.1\r\nHost: 127.0.0.1:'+str(port)+'\r\nConnection: close\r\n\r\n').encode('ascii')
    response=('HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\n'+case).encode('ascii')
    return request,response


def verify_artifact(actor,manifest,manifest_hash,actor_hash,*,source_root=None):
    actor=launcher.checked_path(actor);manifest=launcher.checked_path(manifest)
    require(actor.name==ACTOR and manifest.name==MANIFEST and actor.parent==manifest.parent)
    require(a.digest(actor_hash) and a.digest(manifest_hash))
    value,raw=a.bounded_json(manifest,8192,inside=actor.parent)
    require(set(value)=={'schemaVersion','compileOnly','runtimeAcceptance','executableSha256',*NATIVE_SOURCES})
    require(a.integer(value['schemaVersion'],1,1) and value['compileOnly'] is True and value['runtimeAcceptance'] is False)
    require(all(a.digest(value[k]) for k in (*NATIVE_SOURCES,'executableSha256')))
    require(sha(raw)==manifest_hash and value['executableSha256']==actor_hash)
    helpers.verify_copied_actor(actor,actor_hash)
    if source_root is not None:
        root=launcher.checked_path(source_root,is_file=False)
        for key,path in NATIVE_SOURCES.items():
            require(sha(local.bounded(launcher.checked_path(root/path,inside=root),256*1024))==value[key])
    return actor,actor_hash


def validate_identity(value,held,run,pid):
    keys={'schemaVersion','mode','nonce','pid','tokenUserSid','tokenIsAppContainer','tokenAppContainerSid',
        'tokenElevated','isProcessInJob','tokenCapabilities','queriesSucceeded','errors'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schemaVersion'],1,1))
    require(value['mode']=='actor' and value['nonce']==run and a.integer(value['pid'],1) and value['pid']==pid)
    require(value['tokenUserSid']==held['sid'] and value['tokenIsAppContainer'] is False
        and value['tokenAppContainerSid'] is None and value['tokenElevated'] is False
        and value['isProcessInJob'] is True and value['tokenCapabilities']==[]
        and value['queriesSucceeded'] is True and value['errors']==[])


def validate_ready(value,*,run,case,pid,frequency,deadline):
    keys={'schema_version','stage','run_id','case_id','pid','port','qpc_frequency','deadline_qpc','loopback_ipv4'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schema_version'],1,1))
    require(value['stage']=='bridge-origin-ready' and value['run_id']==run and value['case_id']==case)
    require(a.integer(value['pid'],1) and value['pid']==pid and a.integer(value['port'],49153,65535))
    require(a.integer(value['qpc_frequency'],1,1000000000) and value['qpc_frequency']==frequency
        and a.integer(value['deadline_qpc'],1,0x7fffffffffffffff) and value['deadline_qpc']==deadline
        and value['loopback_ipv4'] is True)
    return value


def validate_relay(value,port,case):
    keys={*RELAY_BOOLS,'port','local_port','peer_port','request_bytes','response_bytes','socket_close','failure','wsa_error'}
    require(type(value) is dict and set(value)==keys and value['port']==port and a.integer(value['port'],49153,65535))
    require(all(type(value[k]) is bool for k in RELAY_BOOLS))
    for k in ('local_port','peer_port'):
        require(value[k] is None or a.integer(value[k],1,65535))
    request,response=payloads(case,port)
    require(a.integer(value['request_bytes'],0,len(request)) and a.integer(value['response_bytes'],0,257))
    require(value['socket_close'] in ('not_attempted','confirmed','uncertain'))
    require(value['failure'] in (None,'setup','connect','io','response','deadline','close'))
    require(value['wsa_error'] is None or a.integer(value['wsa_error']))
    require(not value['connect_completed'] or value['connect_attempted'] and value['socket_created'])
    require(not value['peer_loopback'] or value['connect_completed'] and value['peer_port']==port)
    require(not value['request_complete'] or value['request_bytes']==len(request) and value['connect_completed'])
    require(not value['response_exact'] or value['response_bytes']==len(response))
    return value


def relay_passed(value,case):
    if value is None:return False
    request,response=payloads(case,value['port'])
    return (all(value[k] for k in RELAY_BOOLS) and value['socket_close']=='confirmed'
        and value['failure'] is None and value['wsa_error'] is None
        and value['request_bytes']==len(request) and value['response_bytes']==len(response)
        and value['peer_port']==value['port'] and a.integer(value['local_port'],1,65535))


def validate_native(value,*,port,**expected):
    keys={'schema_version','stage','role','run_id','case_id','pid','ipc_mechanics','origin','http_boundary',
        'network_tested','proxy_tested','product_acceptance'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schema_version'],1,1))
    require(value['stage']=='bridge-origin-pipe-test' and value['http_boundary']==BOUNDARY)
    require(value['role']==expected['role'] and value['run_id']==expected['run_id'] and value['case_id']==expected['case_id']
        and a.integer(value['pid'],1) and value['pid']==expected['pid'])
    require(value['proxy_tested'] is False and value['product_acceptance'] is False and type(value['network_tested']) is bool)
    a.validate_ac_native(value['ipc_mechanics'],**expected)
    if expected['role']=='pipe-front':require(value['origin'] is None and value['network_tested'] is False)
    else:
        validate_relay(value['origin'],port,expected['case_id'])
        require(value['network_tested']==value['origin']['connect_attempted'])
    return value


def validate_fixture(value,*,run,case,pid,held,frequency,deadline,start_min,port):
    keys={'schema_version','stage','run_id','case_id','pid','identity','qpc','socket','ready_published',
        'failure','wsa_error','network_scope','network_tested','proxy_tested','product_acceptance'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schema_version'],1,1))
    require(value['stage']=='bridge-origin-fixture' and value['run_id']==run and value['case_id']==case
        and a.integer(value['pid'],1) and value['pid']==pid)
    require(launcher.token_is_ordinary(held));validate_identity(value['identity'],held,run,pid)
    q=value['qpc'];require(type(q) is list and len(q)==4 and all(a.integer(x,0,0x7fffffffffffffff) for x in q))
    require(q[0]==frequency and start_min<=q[1]<deadline and q[2]==deadline and q[3]>=q[1])
    require(type(value['ready_published']) is bool and value['failure'] in (None,'configuration','identity','qpc',
        'socket','bind','listen','accept','request','send','shutdown','close','report','deadline'))
    require(value['wsa_error'] is None or a.integer(value['wsa_error']))
    require(value['network_scope']=='ordinary-loopback-origin' and value['proxy_tested'] is False and value['product_acceptance'] is False)
    s=value['socket'];keys={*FIXTURE_BOOLS,'port','peer_port','request_bytes','response_bytes','listener_close','connection_close'}
    require(type(s) is dict and set(s)==keys and all(type(s[k]) is bool for k in FIXTURE_BOOLS))
    require(a.integer(s['port'],0,65535) and s['port']==port and (s['peer_port'] is None or a.integer(s['peer_port'],1,65535)))
    request,response=payloads(case,port)
    require(a.integer(s['request_bytes'],0,257) and a.integer(s['response_bytes'],0,len(response)))
    require(all(s[k] in ('not_attempted','confirmed','uncertain') for k in ('listener_close','connection_close')))
    require(type(value['network_tested']) is bool and value['network_tested']==s['accepted'])
    require(not s['request_exact'] or s['request_bytes']==len(request))
    require(not s['response_complete'] or s['response_bytes']==len(response))
    return value


def fixture_passed(value,case):
    if value is None:return False
    s=value['socket'];request,response=payloads(case,s['port'])
    return (all(s[k] for k in FIXTURE_BOOLS) and value['ready_published'] is True and value['failure'] is None
        and value['wsa_error'] is None and value['qpc'][3]<value['qpc'][2]
        and all(s[k]=='confirmed' for k in ('listener_close','connection_close'))
        and s['request_bytes']==len(request) and s['response_bytes']==len(response))


def raw_record(raw):
    require(type(raw) is bytes and len(raw)<=MAX_NATIVE)
    return dict(raw=raw.decode('ascii','strict'),sha256=sha(raw),bytes=len(raw))


def read_record(value,limit):
    require(type(value) is dict and set(value)=={'raw','sha256','bytes'} and type(value['raw']) is str)
    raw=value['raw'].encode('ascii','strict')
    require(a.integer(value['bytes'],1,limit) and len(raw)==value['bytes'] and a.digest(value['sha256']) and sha(raw)==value['sha256'])
    return decode(raw)


class CombinedLedgers:
    """Only a ledger view; the existing _cleanup remains the single lifecycle."""
    def __init__(self,*ledgers):self.ledgers=ledgers
    @property
    def pending(self):
        values=[h for ledger in self.ledgers for h in ledger.pending]
        require(len(values)==len(set(values)));return set(values)
    def close(self,handle):
        owners=[ledger for ledger in self.ledgers if handle in ledger.pending]
        require(len(owners)==1);owners[0].close(handle)
    @property
    def confirmed_closed(self):return all(ledger.confirmed_closed for ledger in self.ledgers)


class OriginAPI(a.ACWindowsAPI):
    def verify_acl_scope(self,work,inputs,output,sid,budget):
        for path in helpers.owned_paths(work):
            budget.require_ms(budget.cutoff(30))
            expected=[(16,0x1200a9)] if path.parent==inputs and path.name==ACTOR else a.ac_scope_expected(work,inputs,output,path)
            if self.acl_read(path,sid)!=expected:return False
        budget.require_ms(budget.cutoff(30));return True


class OriginExtension:
    actor_name=ACTOR;profile_prefix='RuleProxy.ProxyOrigin.'
    def __init__(self,api):
        self.origin_owners=helpers.OneShotHandles(api.close);self.ledgers=(self.origin_owners,)
        self.child={'info':api.process_info(),'attempted':False,'assigned':False,'exited':False,'exit_code':None}
        self.children=[self.child];self.native_records=[None,None]
        self.fixture=dict(pid=None,identity=None,attempted=False,image_verified=False,assigned=False,resumed=False,
            start_min=None,deadline=None,ready=None,report=None,exit_observed=False,exit_code=None,handles_closed=False)
        self.port=None;self.out=None
    def cleanup_ledger(self,base):return CombinedLedgers(base,self.origin_owners)
    def setup(self,api,budget,work,exe,job,parent,run,case,actor_hash):
        self.out=work/'origin-output';self.out.mkdir();(self.out/'temp').mkdir()
        info=self.child['info'];state=self.fixture
        state['deadline']=budget.cutoff(30);state['start_min']=budget.read()
        stdio=[]
        for name in ('origin.stdin','origin.stdout','origin.stderr'):
            budget.require_ms(budget.cutoff(40));handle=api.open_stdio_file(self.out/name,read=name.endswith('stdin'))
            self.origin_owners.add(handle);stdio.append(handle)
        command=[str(exe),'origin-fixture',run,case,str(self.out/'actor.json'),str(self.out/'ready.json'),
            str(budget.frequency),str(state['deadline']),parent['sid']]
        budget.require_ms(budget.cutoff(40));self.child['attempted']=True;state['attempted']=True
        try:api.create_suspended(info,command,self.out,stdio,None)
        finally:
            if info.hProcess:self.origin_owners.add(info.hProcess);state['pid']=int(info.dwProcessId)
            if info.hThread:self.origin_owners.add(info.hThread)
        api.assign_job(job,info.hProcess);self.child['assigned']=True;state['assigned']=True
        api.verify_job(job,info.hProcess);api.verify_image(info.hProcess,exe);helpers.verify_copied_actor(exe,actor_hash)
        state['image_verified']=True;state['identity']=api.identity_owned(self.origin_owners,info.hProcess)
        require(launcher.token_is_ordinary(state['identity']) and launcher.same_identity(state['identity'],parent))
        budget.require_ms(budget.cutoff(40));api.resume(info.hThread);state['resumed']=True
        ready_end=min(budget.read()+5*budget.frequency,budget.cutoff(40))
        while budget.remaining_ms(ready_end,10)>0:
            if (self.out/'ready.json').exists():
                try:value,raw=a.bounded_json(self.out/'ready.json',MAX_READY,inside=work)
                except OSError as exc:
                    # CREATE_NEW/share-zero becomes readable only after the
                    # held fixture closes its publication handle. No other
                    # read/close uncertainty is retried.
                    if getattr(exc,'winerror',None)!=32:raise
                    api.sleep_ms(budget.require_ms(ready_end,10));continue
                validate_ready(value,run=run,case=case,pid=state['pid'],frequency=budget.frequency,deadline=state['deadline'])
                self.port=value['port'];state['ready']=raw_record(raw);return
            if api.wait(info.hProcess,0):raise ValueError('origin_exited_before_ready')
            api.sleep_ms(budget.require_ms(ready_end,10))
        raise ValueError('origin_ready_deadline')
    def arguments(self):
        require(a.integer(self.port,49153,65535));return [str(self.port)]
    def await_completion(self,api,budget,end):
        # The same pair Tb/end bounds report publication and normal fixture
        # exit. The shared cleanup is a fallback, not a normal-exit race.
        info=self.child['info'];require(self.child['attempted'] and info.hProcess and self.fixture['resumed'])
        self.child['exited']=api.wait(info.hProcess,budget.require_ms(end)) is True
        if self.child['exited']:self.child['exit_code']=api.exit_code(info.hProcess)
        require(budget.read()<end and self.child['exited'] and self.child['exit_code']==0)
    def project_native(self,value,raw,**expected):
        validate_native(value,port=self.port,**expected)
        self.native_records[0 if expected['role']=='pipe-front' else 1]=raw_record(raw)
        projection=value['ipc_mechanics']
        return projection,encode(projection)
    def finish(self,budget,work,run,case):
        self.fixture.update(exit_observed=self.child['exited'],exit_code=self.child['exit_code'],handles_closed=self.origin_owners.confirmed_closed)
        if self.out is not None and self.child['exited'] and self.fixture['identity'] is not None and self.port is not None:
            try:
                budget.require_ms(budget.cutoff(5));value,raw=a.bounded_json(self.out/'actor.json',MAX_NATIVE,inside=work)
                validate_fixture(value,run=run,case=case,pid=self.fixture['pid'],held=self.fixture['identity'],
                    frequency=budget.frequency,deadline=self.fixture['deadline'],start_min=self.fixture['start_min'],port=self.port)
                self.fixture['report']=raw_record(raw)
            except BaseException:return False
        return self.fixture['report'] is not None


def run_controller(config,*,root=ROOT,api=None):
    pair=guest.valid_config(config['pair']);deadline=config['deadline_qpc'];frequency=config['qpc_frequency']
    api=OriginAPI() if api is None else api;budget=launcher.QpcBudget(api,deadline,frequency)
    extension=OriginExtension(api);work=root/'controller'
    mechanics=None;failure=None
    try:
        mechanics=a.run_ac_pair(api,root/'bridge'/ACTOR,root/'bridge'/MANIFEST,pair['actor_sha256'],pair['manifest_sha256'],
            work,pair['run_nonce'],pair['case_nonce'],deadline,frequency,artifact_verifier=verify_artifact,extension=extension)
    except BaseException:failure='controller'
    if not extension.finish(budget,work,pair['run_nonce'],pair['case_nonce']):failure=failure or 'origin_report'
    value=dict(schema_version=1,stage='proxy-origin-controller',controller_pid=os.getpid(),
        run_nonce=pair['run_nonce'],case_nonce=pair['case_nonce'],actor_sha256=pair['actor_sha256'],
        manifest_sha256=pair['manifest_sha256'],deadline_qpc=deadline,qpc_frequency=frequency,
        mechanics_projection_report_kind='canonical-ipc-view-not-raw-native',mechanics_projection=mechanics,
        pair_native=extension.native_records,origin_fixture=extension.fixture,failure=failure)
    budget.require_ms(budget.cutoff(5));raw=encode(value);require(len(raw)<=MAX_PRIVATE)
    launcher.write_private_bytes(root/'private-origin.json',raw);budget.require_ms(budget.cutoff(5))
    return value


def validate_private(value,expected):
    keys={'schema_version','stage','controller_pid','run_nonce','case_nonce','actor_sha256','manifest_sha256',
        'deadline_qpc','qpc_frequency','mechanics_projection_report_kind','mechanics_projection','pair_native','origin_fixture','failure'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schema_version'],1,1))
    require(value['stage']=='proxy-origin-controller' and value['mechanics_projection_report_kind']=='canonical-ipc-view-not-raw-native')
    for k in ('controller_pid','run_nonce','case_nonce','actor_sha256','manifest_sha256','deadline_qpc','qpc_frequency'):
        require(type(value[k]) is type(expected[k]) and value[k]==expected[k])
    require(value['failure'] in (None,'controller','origin_report'))
    mechanics=value['mechanics_projection'];projection=None
    if mechanics is not None:projection=a.validate_private_report(mechanics,expected)
    origin=value['origin_fixture']
    origin_keys={'pid','identity','attempted','image_verified','assigned','resumed','start_min','deadline','ready','report',
        'exit_observed','exit_code','handles_closed'}
    require(type(origin) is dict and set(origin)==origin_keys)
    for k in ('attempted','image_verified','assigned','resumed','exit_observed','handles_closed'):require(type(origin[k]) is bool)
    require(origin['pid'] is None or a.integer(origin['pid'],1))
    for k in ('start_min','deadline'):require(origin[k] is None or a.integer(origin[k],0,0x7fffffffffffffff))
    require(origin['exit_code'] is None or a.integer(origin['exit_code']) and origin['exit_observed'])
    require(not origin['assigned'] or origin['attempted'] and origin['pid'] is not None)
    require(not origin['image_verified'] or origin['assigned'])
    require(not origin['exit_observed'] or origin['attempted'] and origin['pid'] is not None)
    require(origin['deadline'] is None or origin['deadline']==expected['deadline_qpc']-30*expected['qpc_frequency'])
    held=origin['identity'];held_good=False
    if held is not None:
        require(type(held) is dict and set(held)==a.AC_IDENTITY_KEYS)
        held_good=launcher.token_is_ordinary(held) and held['sid']==expected['controller_sid'] and held['session_id']==expected['controller_session']
        require(held_good and origin['pid'] is not None and origin['image_verified'] and origin['assigned'])
    require(not origin['resumed'] or held_good)
    if mechanics is not None and mechanics['cleanup']['profile_deleted']:
        require(origin['handles_closed'] and (not origin['attempted'] or origin['pid'] is not None and origin['exit_observed']))
    ready=None;fixture=None;port=None
    if origin['ready'] is not None:
        require(held_good and origin['resumed'] and origin['deadline']==expected['deadline_qpc']-30*expected['qpc_frequency'])
        ready=validate_ready(read_record(origin['ready'],MAX_READY),run=expected['run_nonce'],case=expected['case_nonce'],pid=origin['pid'],
            frequency=expected['qpc_frequency'],deadline=origin['deadline']);port=ready['port']
    if origin['report'] is not None:
        require(ready is not None and origin['exit_observed'])
        fixture=validate_fixture(read_record(origin['report'],MAX_NATIVE),run=expected['run_nonce'],case=expected['case_nonce'],
            pid=origin['pid'],held=held,frequency=expected['qpc_frequency'],deadline=origin['deadline'],start_min=origin['start_min'],port=port)
    records=value['pair_native'];require(type(records) is list and len(records)==2)
    native=[None,None]
    for i,record in enumerate(records):
        if record is None:continue
        require(mechanics is not None and ready is not None)
        row=mechanics['children'][i];qpc=mechanics['pair_qpc']
        native[i]=validate_native(read_record(record,MAX_NATIVE),port=port,role=('pipe-front','pipe-relay')[i],
            run_id=expected['run_nonce'],case_id=expected['case_nonce'],pid=row['pid'],identity=row['identity'],
            frequency=expected['qpc_frequency'],start=qpc[0],end=qpc[1],expected_ac_sid=mechanics['derived_sid'] if i==0 else None)
        ipc=native[i]['ipc_mechanics'];require(row['native']==ipc and row['native_sha256']==sha(encode(ipc)) and row['native_bytes']==len(encode(ipc)))
    relay=None if native[1] is None else native[1]['origin']
    facts={k:False for k in ORIGIN_FACTS}
    facts.update(held_identity_verified=held_good,image_verified=origin['image_verified'],ready_bound=ready is not None,
        report_bound=fixture is not None,cleanup_verified=origin['exit_observed'] and origin['handles_closed'])
    if fixture is not None:
        s=fixture['socket'];facts.update(request_exact=s['request_exact'],request_eof=s['request_eof'],
            response_complete=s['response_complete'],accepted_observed=s['accepted'],
            fixture_close_verified=all(s[k]=='confirmed' for k in ('listener_close','connection_close')))
    if relay is not None:
        facts.update(response_eof=relay['response_eof'],relay_close_verified=relay['socket_close']=='confirmed',
            connect_attempted_observed=relay['connect_attempted'])
        if fixture is not None:
            facts['peer_tuple_bound']=(relay['peer_port']==port and relay['local_port']==fixture['socket']['peer_port'])
    network_tested=facts['connect_attempted_observed'] or facts['accepted_observed']
    origin_passed=(all(facts.values()) and fixture_passed(fixture,expected['case_nonce']) and relay_passed(relay,expected['case_nonce'])
        and origin['exit_code']==0 and value['failure'] is None)
    return dict(mechanics=projection,origin=facts,network_tested=bool(network_tested),origin_roundtrip_verified=origin_passed,
        counts=dict(request_bytes=0 if relay is None else relay['request_bytes'],response_bytes=0 if relay is None else relay['response_bytes']))


def source_snapshot(root=ROOT):
    root=launcher.checked_path(root,is_file=False);files={}
    for name in SOURCES:files[name]=local.bounded(launcher.checked_path(root/name,inside=root),256*1024)
    hashes={name:sha(raw) for name,raw in files.items()}
    return files,hashes,sha(encode(hashes))


def valid_plan(value,*,device,actor_hash,manifest_hash,source_hash):
    keys={'schema_version','scope','device_sha256','actor_sha256','manifest_sha256','source_sha256',
        'recovery_reference','residue_review_acknowledged'}
    require(type(value) is dict and set(value)==keys and a.integer(value['schema_version'],1,1)
        and value['scope']==SCOPE and value['residue_review_acknowledged'] is True)
    for key,expected in (('device_sha256',device),('actor_sha256',actor_hash),('manifest_sha256',manifest_hash),('source_sha256',source_hash)):
        require(a.digest(value[key]) and value[key]==expected)
    require(type(value['recovery_reference']) is str and 1<=len(value['recovery_reference'])<=512
        and not any(ord(x)<32 for x in value['recovery_reference']))
    return value


def admitted_inputs(actor,manifest,actor_hash,manifest_hash,work_parent,root=ROOT):
    root=launcher.checked_path(root,is_file=False)
    files,hashes,source_hash=source_snapshot(root)
    actor,_=verify_artifact(actor,manifest,manifest_hash,actor_hash,source_root=root)
    manifest=launcher.checked_path(manifest)
    private=launcher.checked_path(root/'private',inside=root,is_file=False)
    parent=launcher.checked_path(private if work_parent is None else work_parent,inside=private,is_file=False)
    required=sum(map(len,files.values()))+2*actor.stat().st_size+8192+4*MAX_PRIVATE+1048576
    require(required<=local.MAX_STAGE and shutil.disk_usage(parent).free>=required)
    return files,hashes,source_hash,actor,manifest,parent


def blank(mode):
    return dict(schema_version=1,stage='local-proxy-origin',profile='zero-cap-front-ordinary-relay-owned-origin-v1',
        mode=mode,status='inconclusive',failure=None,http_boundary=BOUNDARY,network_scope='relay-to-owned-ipv4-loopback-origin',
        source_sha256=None,actor_sha256=None,manifest_sha256=None,recovery_plan_sha256=None,
        run_nonce_sha256=None,case_nonce_sha256=None,device_bound=False,python_version=platform.python_version(),
        checks={k:False for k in ('windows_x64','ordinary','sources','artifacts','capacity','recovery_attested')},
        facts={k:False for k in guest.FACTS},origin={k:False for k in ORIGIN_FACTS},
        cleanup=dict(guard_job_verified=False,controller_held_verified=False,controller_exit_verified=False,
            outer_cleanup_verified=False,tree_retained=False,recovery_required=False),
        pair=None,counts=dict(request_bytes=0,response_bytes=0),ipc_mechanics_passed=False,
        origin_roundtrip_verified=False,local_origin_qualified=False,generated_front_and_sink=True,
        selected_application_tested=False,network_tested=False,proxy_tested=False,product_acceptance=False)


def validate_public(value):
    template=blank(value.get('mode') if type(value) is dict else None)
    require(type(value) is dict and set(value)==set(template))
    for k in ('schema_version','stage','profile','http_boundary','network_scope','generated_front_and_sink',
            'selected_application_tested','proxy_tested','product_acceptance'):
        require(type(value[k]) is type(template[k]) and value[k]==template[k])
    require(value['mode'] in ('preflight','runtime') and value['status'] in ('ready','inconclusive','passed'))
    require(value['failure'] in (None,'platform','identity','inputs','recovery_plan','deadline','staging','controller','report','cleanup'))
    for key in ('checks','facts','origin','cleanup'):
        require(type(value[key]) is dict and set(value[key])==set(template[key]) and all(type(x) is bool for x in value[key].values()))
    for key in ('device_bound','ipc_mechanics_passed','origin_roundtrip_verified','local_origin_qualified','network_tested'):
        require(type(value[key]) is bool)
    for key in ('source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','run_nonce_sha256','case_nonce_sha256'):
        require(value[key] is None or a.digest(value[key]))
    for check,fields in (('sources',('source_sha256',)),('artifacts',('actor_sha256','manifest_sha256')),
            ('recovery_attested',('recovery_plan_sha256',))):
        require(not value['checks'][check] or all(value[k] is not None for k in fields))
    require(not value['checks']['recovery_attested'] or value['device_bound'])
    require(type(value['python_version']) is str and 1<=len(value['python_version'])<=32
        and all(x in '0123456789.' for x in value['python_version']))
    require(type(value['counts']) is dict and set(value['counts'])=={'request_bytes','response_bytes'}
        and all(a.integer(x,0,8192) for x in value['counts'].values()))
    if value['pair'] is not None:
        a.validate_pair(value['pair']);require(value['run_nonce_sha256'] is not None and value['case_nonce_sha256'] is not None)
    if value['mode']=='preflight':
        require(not any(value['facts'].values()) and not any(value['origin'].values()) and not any(value['cleanup'].values())
            and value['pair'] is None and value['run_nonce_sha256'] is None and value['case_nonce_sha256'] is None
            and not value['network_tested'] and not value['origin_roundtrip_verified'] and not any(value['counts'].values()))
    ipc=all(value['facts'].values()) and guest.pair_passed(value['pair'])
    require(value['ipc_mechanics_passed']==ipc)
    require(not value['origin_roundtrip_verified'] or all(value['origin'].values()) and value['network_tested'])
    require(value['network_tested']==(value['origin']['connect_attempted_observed'] or value['origin']['accepted_observed']))
    if value['origin_roundtrip_verified']:
        request,response=payloads('0'*32,50000)
        require(value['counts']==dict(request_bytes=len(request),response_bytes=len(response)))
    passed=(value['mode']=='runtime' and all(value['checks'].values()) and value['failure'] is None and ipc
        and value['origin_roundtrip_verified'] and all(value['cleanup'][k] for k in
            ('guard_job_verified','controller_held_verified','controller_exit_verified','outer_cleanup_verified','tree_retained'))
        and not value['cleanup']['recovery_required'])
    require(value['local_origin_qualified']==passed and (value['status']=='passed')==passed)
    require(value['status']!='ready' or value['mode']=='preflight' and all(value['checks'].values()) and value['failure'] is None)
    require(len(encode(value))<=MAX_PUBLIC)
    return value


def preflight(actor=None,manifest=None,actor_hash=None,manifest_hash=None,work_parent=None,recovery_plan=None,*,api=None,root=ROOT):
    value=blank('preflight');phase='platform'
    try:
        require(os.name=='nt' and C.sizeof(C.c_void_p)==8)
        api=local.LocalNativeAPI() if api is None else api;require(api.windows_x64());value['checks']['windows_x64']=True
        phase='identity';local.ordinary(api);device=api.device_sha256();require(a.digest(device));value['checks']['ordinary']=True
        phase='inputs';_,_,source_hash=source_snapshot(root);value['source_sha256']=source_hash;value['checks']['sources']=True
        _,_,again,_,_,_=admitted_inputs(actor,manifest,actor_hash,manifest_hash,work_parent,root)
        require(again==source_hash);value.update(actor_sha256=actor_hash,manifest_sha256=manifest_hash)
        value['checks'].update(artifacts=True,capacity=True)
        phase='recovery_plan';raw=local.bounded(recovery_plan,8192)
        valid_plan(decode(raw),device=device,actor_hash=actor_hash,manifest_hash=manifest_hash,source_hash=source_hash)
        value.update(device_bound=True,recovery_plan_sha256=sha(raw));value['checks']['recovery_attested']=True;value['status']='ready'
    except BaseException:value['failure']=phase
    return validate_public(value)


def fixed_command(python,stage):
    return [str(python),'-I','-S','-B',str(stage/'.github/windows_identity_proxy_origin_probe.py'),
        '--owned-origin-controller','--controller-config',str(stage/'origin-config.json')]


def run_local(actor,manifest,actor_hash,manifest_hash,work_parent,recovery_plan,*,approved=False,api=None,root=ROOT,ids=secrets.token_hex):
    value=blank('runtime');phase='platform';launched=False;budget=None;clean=False
    try:
        require(approved and os.name=='nt')
        api=local.LocalNativeAPI() if api is None else api
        phase='deadline';frequency=api.qpc_frequency();start=api.qpc();deadline=start+120*frequency
        budget=launcher.QpcBudget(api,deadline,frequency)
        check=preflight(actor,manifest,actor_hash,manifest_hash,work_parent,recovery_plan,api=api,root=root)
        for key in ('checks','source_sha256','actor_sha256','manifest_sha256','recovery_plan_sha256','device_bound'):value[key]=check[key]
        if check['status']!='ready':phase=check['failure'];raise ValueError('preflight')
        phase='inputs';files,hashes,source_hash,actor,manifest,parentpath=admitted_inputs(actor,manifest,actor_hash,manifest_hash,work_parent,root)
        require(source_hash==value['source_sha256']);plan_raw=local.bounded(recovery_plan,8192);require(sha(plan_raw)==value['recovery_plan_sha256'])
        phase='identity';parent=local.ordinary(api);device=api.device_sha256()
        valid_plan(decode(plan_raw),device=device,actor_hash=actor_hash,manifest_hash=manifest_hash,source_hash=source_hash)
        run,case=ids(16),ids(16);pair=guest.valid_config(dict(enabled=True,run_nonce=run,case_nonce=case,actor_sha256=actor_hash,manifest_sha256=manifest_hash))
        value.update(run_nonce_sha256=sha(run.encode('ascii')),case_nonce_sha256=sha(case.encode('ascii')))
        stage=parentpath/('local-origin-'+run);require(not stage.exists() and not stage.is_symlink())
        phase='staging';budget.require_ms(budget.cutoff(50));value['cleanup']['tree_retained']=True
        api.private_directory(stage,parent['sid']);launcher.checked_path(stage,inside=parentpath,is_file=False)
        for name,raw in files.items():
            budget.require_ms(budget.cutoff(45));path=stage/name;path.parent.mkdir(parents=True,exist_ok=True)
            launcher.write_private_bytes(path,raw);require(sha(local.bounded(path,256*1024))==hashes[name])
        bridge=stage/'bridge';bridge.mkdir()
        launcher.write_private_bytes(bridge/ACTOR,local.bounded(actor,a.MAX_ACTOR));launcher.write_private_bytes(bridge/MANIFEST,local.bounded(manifest,8192))
        verify_artifact(bridge/ACTOR,bridge/MANIFEST,manifest_hash,actor_hash)
        api.worker_job_name='Local\\RuleProxy.LocalGuard.'+run;api.worker_sid=parent['sid']
        config=dict(schema_version=1,stage='proxy-origin-owned-input',pair=pair,deadline_qpc=deadline,qpc_frequency=frequency,
            source_hashes=hashes,source_sha256=source_hash,device_sha256=device,recovery_plan_sha256=sha(plan_raw),guard_job_name=api.worker_job_name)
        launcher.write_private_bytes(stage/'origin-config.json',encode(config));launcher.write_private_bytes(stage/'recovery-plan.json',plan_raw)
        work=stage/'guard';work.mkdir();(work/'temp').mkdir()
        python=launcher.checked_path(sys.executable,inside=launcher.checked_path(sys.base_prefix,is_file=False));require(python.name.casefold()=='python.exe')
        phase='deadline';budget.require_ms(budget.cutoff(45));phase='controller';launched=True
        launch=launcher.launch_owned(api,fixed_command(python,stage),work,parent,parent,qpc_budget=budget,
            work_cutoff=budget.cutoff(3),cleanup_cutoff=deadline)
        c=value['cleanup'];c.update(guard_job_verified=api.atomic_job_requested and launch.get('native_identity_verified_before_resume') is True,
            controller_held_verified=launch.get('native_identity_verified_before_resume') is True,
            controller_exit_verified=launch.get('cleanup',{}).get('process_exit_confirmed') is True and launch.get('exit_code')==0,
            outer_cleanup_verified=guest.cleanup_verified(launch))
        value['facts']['current_ordinary_verified']=True
        value['facts']['controller_exit_verified']=c['controller_exit_verified'];value['facts']['outer_cleanup_verified']=c['outer_cleanup_verified']
        phase='report';require(launch.get('started') is True and launch.get('resumed') is True
            and launch.get('native_identity_verified_before_resume') is True
            and launch.get('cleanup',{}).get('process_exit_confirmed') is True)
        report=decode(local.bounded(stage/'private-origin.json',MAX_PRIVATE))
        expected={k:pair[k] for k in ('run_nonce','case_nonce','actor_sha256','manifest_sha256')}
        expected.update(deadline_qpc=deadline,qpc_frequency=frequency,controller_pid=launch['child_pid'],
            controller_sid=parent['sid'],controller_session=parent['session_id'])
        projection=validate_private(report,expected)
        if projection['mechanics'] is not None:
            for k,v in projection['mechanics']['facts'].items():
                if k not in ('current_ordinary_verified','controller_exit_verified','outer_cleanup_verified'):value['facts'][k]=v
            value['pair']=projection['mechanics']['pair']
        value.update(origin=projection['origin'],network_tested=projection['network_tested'],counts=projection['counts'],
            origin_roundtrip_verified=projection['origin_roundtrip_verified'])
        value['ipc_mechanics_passed']=all(value['facts'].values()) and guest.pair_passed(value['pair'])
        clean=c['outer_cleanup_verified'] and projection['origin']['cleanup_verified'] and all(value['facts'][k] for k in ('acl_removed_verified','profile_deleted_verified'))
        c['recovery_required']=not clean
        phase='controller';require('error' not in launch and launch.get('timed_out') is False and c['controller_exit_verified'])
        require(projection['mechanics'] is not None and projection['mechanics']['ac_failure'] is None)
        require(value['ipc_mechanics_passed'] and value['origin_roundtrip_verified'])
        phase='cleanup';require(clean);phase='deadline';budget.require_ms(deadline)
        value.update(status='passed',local_origin_qualified=True)
    except BaseException:
        value['failure']=phase
        if launched:value['cleanup']['recovery_required']=not clean
        if phase=='staging' and value['cleanup']['tree_retained']:value['cleanup']['recovery_required']=True
    return validate_public(value)


def owned_controller(path):
    path=launcher.checked_path(path,inside=ROOT);require(path==ROOT/'origin-config.json')
    config=decode(local.bounded(path,MAX_PRIVATE))
    keys={'schema_version','stage','pair','deadline_qpc','qpc_frequency','source_hashes','source_sha256',
        'device_sha256','recovery_plan_sha256','guard_job_name'}
    require(type(config) is dict and set(config)==keys and a.integer(config['schema_version'],1,1) and config['stage']=='proxy-origin-owned-input')
    pair=guest.valid_config(config['pair']);require(ROOT.name=='local-origin-'+pair['run_nonce']
        and config['guard_job_name']=='Local\\RuleProxy.LocalGuard.'+pair['run_nonce'])
    api=OriginAPI();budget=launcher.QpcBudget(api,config['deadline_qpc'],config['qpc_frequency']);budget.require_ms(budget.cutoff(45))
    _,hashes,source_hash=source_snapshot();require(config['source_hashes']==hashes and config['source_sha256']==source_hash)
    parent=local.ordinary(api);device=local.LocalNativeAPI.device_sha256(api);require(config['device_sha256']==device)
    plan_raw=local.bounded(ROOT/'recovery-plan.json',8192);require(sha(plan_raw)==config['recovery_plan_sha256'])
    valid_plan(decode(plan_raw),device=device,actor_hash=pair['actor_sha256'],manifest_hash=pair['manifest_sha256'],source_hash=source_hash)
    local.LocalNativeAPI.verify_private_directory(api,ROOT,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    local.verify_guard_job(api,config['guard_job_name']);budget.require_ms(budget.cutoff(45))
    report=run_controller(config,api=api)
    expected={k:pair[k] for k in ('run_nonce','case_nonce','actor_sha256','manifest_sha256')}
    expected.update(deadline_qpc=config['deadline_qpc'],qpc_frequency=config['qpc_frequency'],controller_pid=os.getpid(),
        controller_sid=parent['sid'],controller_session=parent['session_id'])
    projection=validate_private(report,expected)
    return 0 if (projection['mechanics'] is not None and projection['mechanics']['ac_failure'] is None
        and guest.pair_passed(projection['mechanics']['pair']) and projection['origin_roundtrip_verified']) else 1


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-local-origin-pair',action='store_true');parser.add_argument('--approved-local-security-test',action='store_true')
    for name in ('actor','manifest','expected-actor-sha256','expected-manifest-sha256','work-parent','recovery-plan'):parser.add_argument('--'+name)
    parser.add_argument('--owned-origin-controller',action='store_true',help=argparse.SUPPRESS)
    parser.add_argument('--controller-config',help=argparse.SUPPRESS);args=parser.parse_args(argv)
    if args.owned_origin_controller:
        try:
            require(not any((args.run_local_origin_pair,args.approved_local_security_test,args.actor,args.manifest,args.recovery_plan)))
            return owned_controller(args.controller_config)
        except BaseException:return 1
    if args.controller_config:return 1
    inputs=(args.actor,args.manifest,args.expected_actor_sha256,args.expected_manifest_sha256,args.work_parent,args.recovery_plan)
    value=run_local(*inputs,approved=args.approved_local_security_test) if args.run_local_origin_pair else preflight(*inputs)
    sys.stdout.write(encode(value).decode('ascii'));return 0 if value['status'] in ('ready','passed') else 1


if __name__=='__main__':raise SystemExit(main())
