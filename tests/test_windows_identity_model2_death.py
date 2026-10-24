"""Pure death ABI, stop authority and journal fixtures; no actor/network/API."""
import copy
import importlib.util
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('death_native_fixtures', Path(__file__).with_name('test_windows_identity_model2_native_schemas.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
m, l = f.m, f.m.live
spec2 = importlib.util.spec_from_file_location('death_outer', f.ROOT/'.github/windows_identity_model2_local.py')
outer = importlib.util.module_from_spec(spec2); spec2.loader.exec_module(outer)
H = 'a'*64; DEATH = 'a'*32; AFTER = 'b'*32; START = 40000; END = 50000
PORTS = dict(proxy=f.P, wrong_port=f.Q, origin=f.O)

def config():
    hashes = dict.fromkeys(l.SOURCES, H)
    return dict(schema_version=1, stage='model2-first-owned-input', run=f.RUN, boot_case=f.BOOT,
        positive_case=f.CASE, direct_case='6'*32, admission_nonce=f.ADMISSION, maintenance_nonce='5'*32,
        health_cases=['7'*32, '8'*32, '9'*32], capability_profile='agentic-pncs', frequency=f.F, start_qpc=f.T0,
        root_deadline_qpc=f.T0+120*f.F, deadline_qpc=f.D, source_hashes=hashes, source_sha256=l.sha(l.encode(hashes)),
        actor_sha256=H, manifest_sha256=H, device_sha256=H, recovery_plan_sha256=H,
        guard_job_name='Local\\RuleProxy.LocalGuard.'+f.RUN, execution_mode='profiles-off-diagnostic',
        selected_admission=dict(profile='actor-plus-system-conhost-v1', conhost_sha256=H),
        death_extension=dict(profile='same-selected-live-proxy-death-v1', death_case=DEATH, after_direct_case=AFTER))

def held(profile, pid, *, code=0):
    row = f.task(profile, pid)
    return dict(row, resumed=True, image_verified=True, exited=True, exit_code=code, created=1000+pid,
        image_sha256=H, admission_qpc=START+1, resume_qpc=START+2)

def ack(released=False):
    c = config(); row = dict(f.prefix('proxy-c-origin-released' if released else 'proxy-c-origin-withheld', held('ordinary',104),
        'health-origin-withhold', c['health_cases'][0]), case_id=DEATH, root_qpc=[f.F, f.T0, f.D],
        flow_qpc=[41000,42000,45001,45002] if released else [41000,42000], port=f.O, peer_port=54000,
        request_bytes=95, request_exact=True, request_eof=True, response_bytes=0, response_withheld=True,
        socket_held=not released, failure=None, proxy_tested=False, product_acceptance=False)
    if released: row.update(release_sequence=1, release_verified=True, release_command_close_verified=True, connection_close='confirmed')
    else: row['command_close_verified'] = True
    return row

def front():
    row = f.front_report(held('pncs',107)); row.update(case_id=DEATH, failure='pipe_read')
    row['client'].update(response_bytes=0, response_complete=False, send_shutdown=False)
    ipc = row['ipc_mechanics']; ipc.update(case_id=DEATH, qpc=[f.F, START, END,43500], failure='pipe_read', win32_error=109)
    ipc['pipe'].update(read_bytes=48, write_bytes=96, read_frames=1, write_frames=2, eof_observed=False)
    ipc['core'] = dict(failure=0, observations=1, requested=0, confirmed=0, uncertain=0)
    ipc['synthetic_http'] = dict(request_checked=True, response_checked=False, client_sink_checked=False)
    return row

def phase(after=False):
    row = f.phase(held('agentic-pncs',101), 'direct-tcp' if after else 'proxy-after-death', f.O if after else f.P)
    row.update(case_id=AFTER if after else DEATH, sequence=4 if after else 3,
        phase_qpc=[46000,49000,47000] if after else [40010,END,44000])
    if after:
        row['network'] = dict.fromkeys(l.origin.RELAY_BOOLS, False)
        row['network'].update(wsa_startup=True, wsa_cleanup=True, socket_created=True, inheritance_cleared=True, connect_attempted=True,
            port=f.O, local_port=None, peer_port=None, request_bytes=0, response_bytes=0, socket_close='confirmed', failure='connect', wsa_error=10013)
    else: row['network'].update(response_bytes=0, response_exact=False, failure='response')
    return row

def evidence():
    c = config(); ledger = m.blank_death_ledger(c); descriptors = []
    tasks = {role:held(profile,pid,code=code) for role,profile,pid,code in (
        ('origin','ordinary',104,0), ('selected','agentic-pncs',101,0), ('death-relay','ordinary',106,1), ('death-front','pncs',107,5))}
    go = []
    def command(role, seq, op, case, end, path):
        raw = l.fixture_release(run=c['run'], death_case=case, frequency=f.F, deadline=f.D) if op==254 else l.go_record(
            run=c['run'], case=case, sequence=seq, opcode=op, frequency=f.F, deadline=f.D, fixed_ports=PORTS,
            admission=c['admission_nonce'], phase_deadline=end)
        item = dict(role=role, sequence=seq, opcode=op, case=case, phase_deadline=end, path=path, sha256=l.sha(raw)); go.append(item)
        return item
    def record(path, value):
        raw = l.encode(value); item=dict(path=path, bytes=len(raw), sha256=l.sha(raw), text=raw.decode('ascii'))
        descriptors.append(dict(path=path, bytes=len(raw), sha256=l.sha(raw), state='read')); return item
    death_go = command('selected-client',3,5,DEATH,END,'selected-control/phase-0003.bin')
    release_go = command('health-origin-release',1,254,DEATH,f.D,'origin-control/release.bin')
    command('selected-client',4,2,AFTER,49000,'selected-control/phase-0004.bin')
    flow = dict(pid=106,state=7,local_address='127.0.0.1',remote_address='127.0.0.1',local_port=54000,remote_port=f.O)
    ledger.update(pair_start=START,pair_deadline=END,ticket=dict(record=death_go,issued_qpc=40001),
        held_ack=record('origin/death-held.json',ack()),relay_binding=dict(pid=106,created=1106,before_qpc=42500,after_qpc=42600,flow=flow,
            origin_alive=True,relay_alive=True,exact_workload_job=True,exact_outer_job=True,query_handles_closed=True),
        stop_persisted_qpc=42800,terminate_requested=True,terminate_returned=True,exit_code=1,exit_qpc=43000,
        front_report=record('front/death/final.json',front()),client_report=record('selected/phase-0003.json',phase()),
        release_go=dict(record=release_go,issued_qpc=45000),release_ack=record('origin/death-release.json',ack(True)),
        after_direct_report=record('selected/phase-0004.json',phase(True)))
    intent=dict(schema_version=1,stage='model2-death-stop-intent',run=c['run'],case=DEATH,pid=106,created=1106,
        actor_sha256=H,frequency=f.F,deadline_qpc=f.D,issued_qpc=42700,held_ack_sha256=ledger['held_ack']['sha256'],
        go_sha256=death_go['sha256'],relay_flow_sha256=l.sha(l.encode(flow)))
    ledger['stop_intent']=record('death-stop-intent.json',intent)
    cases=[c['health_cases'][0],c['positive_case'],c['health_cases'][1],DEATH,c['health_cases'][2]]
    for index,case in enumerate(cases,1):
        item=f.receipt(tasks['origin']);item.update(case_id=case,index=index,boot_case_id=c['health_cases'][0])
        if case==DEATH:item.update(response_bytes=0,response_complete=False,send_shutdown=False,qpc=[f.F,41000,f.D,45002])
        if index==5:item['qpc']=[f.F,60000,f.D,61000]
        ledger['origin_receipts'].append(record('origin/receipt-%04d.json'%index,item))
    public=l.blank('profiles-off-diagnostic',death_extension=True)
    for key in ('sources','artifacts','ordinary','live_probe','selected_held','declared_caps','positive','origin_healthy','same_selected','cleanup'):
        public['checks'][key]=True
    public['observations']=dict.fromkeys(public['observations'],True)
    public['diagnostic'].update(requested=True,profiles_off_verified=True,exact_rule_scope_verified=True,positive_verified=True,direct_attempted=True,observation_complete=True)
    for key in l.DEATH_REQUIRED:public['death_extension'][key]=True
    # Inner journal never claims the outer guard, hence completed remains false.
    l.finalize_public(public)
    return ledger,c,tasks,go,descriptors,PORTS,public

class DeathTests(unittest.TestCase):
    def runtime(self, fault=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
        for path in ('front','origin','selected','selected-control','origin-control'):(root/path).mkdir()
        c=config();events=[]
        class API:
            def __init__(self):self.now=START;self.next=1000
            def qpc(self):return self.now
            def qpc_frequency(self):return f.F
            def close(self,handle):events.append(('close',handle))
            def owned_pipe(self,owners):
                self.next+=2;return owners.add(self.next),owners.add(self.next+1)
            def process_id(self,handle):return handle
            def verify_job(self,job,handle):events.append(('job',handle))
            def owned_halfclosed_tcp_flow(self,pid,lp,rp,budget,cutoff):
                events.append(('tcp',pid));self.now=42600
                if fault=='tuple':raise ValueError('fake_tuple_unknown')
                return dict(pid=pid,state=7,local_address='127.0.0.1',remote_address='127.0.0.1',local_port=lp,remote_port=rp)
            def terminate_process(self,handle):
                events.append(('terminate',handle))
                if fault=='terminate':raise ValueError('fake_stop_unknown')
            def terminate_job(self,*args):raise AssertionError('death stop cannot terminate a Job')
        api=API();owner=m.FirstController(c,root,api);owner.parent=held('ordinary',104)['identity'];owner.profile['sid']=f.AC;owner.job=7
        for key in ('positive','direct_deny','same_selected'):owner.value['checks'][key]=True
        owner.value['observations']=dict.fromkeys(owner.value['observations'],True)
        def taskrow(profile,pid,code=0):
            row=held(profile,pid,code=code);row.update(info=SimpleNamespace(hProcess=pid,hThread=pid+1000),
                attempted=True,assigned=True,command=[str(root/'fixed.exe')],image_path=str(root/'fixed.exe'),cleanup_role=False,
                externally_held_before_first_resume=profile!='agentic-pncs',externally_held_before_network_go=True)
            if profile=='agentic-pncs':row['resume_qpc']=None
            return row
        selected=taskrow('agentic-pncs',101);origin=taskrow('ordinary',104)
        selected.update(exited=False,exit_code=None);origin.update(exited=False,exit_code=None)
        owner.tasks=dict(front=taskrow('pncs',102),relay=taskrow('ordinary',103),selected=selected,origin=origin)
        owner.fixed_ports=PORTS
        for role,seq,op,case in (('health-client',1,2,c['health_cases'][0]),('selected-client',1,1,c['positive_case']),
                ('health-client',2,2,c['health_cases'][1]),('selected-client',2,2,c['direct_case'])):
            raw=l.go_record(run=c['run'],case=case,sequence=seq,opcode=op,frequency=f.F,deadline=f.D,fixed_ports=PORTS,
                admission=c['admission_nonce'] if role=='selected-client' else c['maintenance_nonce'],phase_deadline=39000)
            owner.go_records.append(dict(role=role,sequence=seq,opcode=op,case=case,phase_deadline=39000,
                path=('selected-control' if role=='selected-client' else 'health-control')+'/phase-%04d.bin'%seq,sha256=l.sha(raw)))
        def task(name,argv,work,**kwargs):
            profile,pid=('pncs',107) if name=='death-front' else ('ordinary',106)
            row=taskrow(profile,pid);row.update(exited=False,exit_code=None);owner.tasks[name]=row;owner.children.append(row)
            if name=='death-front':
                value=front()
                if fault=='front':value['ipc_mechanics']['win32_error']=5
                (work/'final.json').write_bytes(l.encode(value))
            return row
        owner.task=task
        owner.resume=lambda row:events.append(('resume',row['pid']))
        owner.selected_family_alive=lambda *args:events.append(('selected-family',101))
        def alive(row):
            events.append(('alive',row['pid']))
            if fault=='generation' and row['pid']==106:raise ValueError('fake_generation')
        owner.alive=alive;owner.refresh_profiles=lambda:events.append(('profiles',))
        def publish(task,**fields):
            events.append(('publish',fields['sequence']));api.now=40020
            raw=l.go_record(run=c['run'],case=DEATH,sequence=3,opcode=5,frequency=f.F,deadline=f.D,fixed_ports=PORTS,admission=c['admission_nonce'],phase_deadline=END)
            row=dict(role='selected-client',sequence=3,opcode=5,case=DEATH,phase_deadline=END,path='selected-control/phase-0003.bin',sha256=l.sha(raw))
            owner.go_records.append(row)
            return dict(task=task,role='selected-client',boot=c['boot_case'],admission=c['admission_nonce'],sequence=3,
                case=DEATH,opcode=5,reports=root/'selected',fixed_ports=PORTS,end=END,record=row,issued_qpc=40020)
        owner.publish_phase=publish
        client=phase()
        if fault=='client':client['network']['failure']='deadline'
        (root/'selected/phase-0003.json').write_bytes(l.encode(client))
        def collect(ticket):events.append(('collect',ticket['sequence']));api.now=44000;return client
        owner.collect_phase=collect
        def after(task,**fields):
            events.append(('after-direct',fields['sequence']));api.now=47000;row=phase(True);row['phase_qpc'][1]=fields['end']
            raw=l.go_record(run=c['run'],case=AFTER,sequence=4,opcode=2,frequency=f.F,deadline=f.D,fixed_ports=PORTS,
                admission=c['admission_nonce'],phase_deadline=fields['end'])
            owner.go_records.append(dict(role='selected-client',sequence=4,opcode=2,case=AFTER,phase_deadline=fields['end'],
                path='selected-control/phase-0004.bin',sha256=l.sha(raw)))
            if fault=='leak':row['network']=f.transport(case=AFTER,port=f.O,operation='direct-tcp')
            (root/'selected/phase-0004.json').write_bytes(l.encode(row));return row
        owner.native_phase=after
        def wait(row,end,*,code=0):
            events.append(('wait',row['pid'],code));row.update(exited=True,exit_code=code);api.now=43000 if row['pid']==106 else 43500
        owner.wait=wait
        def read(api,budget,path,process,cutoff):
            if path.name=='ready.json':
                api.now=40010;value=f.ready_listener(taskrow('pncs',107),'pipe-live-front','pncs',f.P,START,END);value['boot_case_id']=DEATH
            elif path.name=='death-held.json':
                events.append(('held-ack',));api.now=42001;value=ack()
                if fault=='ack':value['pid']=999
            else:
                events.append(('release-ack',));api.now=45003;value=ack(True)
                if fault=='release':value['release_sequence']=2
            path.write_bytes(l.encode(value));return value,None
        real_write=m.write_death_stop_intent;real_release=l.publish_fixture_release
        def intent(path,raw):
            events.append(('intent',))
            if fault=='intent':raise OSError('fake_fsync')
            return real_write(path,raw)
        def release(*args,**kwargs):events.append(('release',));return real_release(*args,**kwargs)
        def outer_job(api,handle,name,*,owners):
            events.append(('outer',handle));owners.add(900);owners.close(900)
        caught=None
        with patch.object(m,'read_when_closed',side_effect=read),patch.object(m,'write_death_stop_intent',side_effect=intent), \
             patch.object(l,'verify_exact_guard_member',side_effect=outer_job),patch.object(l,'publish_fixture_release',side_effect=release):
            try:owner.death_run(selected,PORTS,root/'fixed.exe','fixed-environment')
            except (ValueError,OSError) as exc:caught=exc
        return owner,events,caught

    def test_scope_plan_config_nonces_and_mutual_exclusion(self):
        c=config();m.validate_config(c);outer.validate_config(c)
        for key in ('wrong_port_extension','wrong_peer_extension'):
            changed=copy.deepcopy(c);changed[key]={}
            with self.assertRaises(ValueError):m.validate_config(changed)
        for kwargs in (dict(execution_mode='strict',death_extension=True),dict(execution_mode='profiles-off-diagnostic',death_extension=True,wrong_peer_extension=True)):
            with self.assertRaises(ValueError):l.blank(**kwargs)
        changed=copy.deepcopy(c);changed['death_extension']['death_case']=c['positive_case']
        with self.assertRaises(ValueError):outer.validate_config(changed)
        p=dict(schema_version=1,scope=outer.DEATH_SCOPE,device_sha256=H,source_sha256=c['source_sha256'],actor_sha256=H,
            manifest_sha256=H,residue_review_acknowledged=True,recovery_reference='pure fixture',execution_mode='profiles-off-diagnostic',
            selected_admission=c['selected_admission'],death_extension=c['death_extension'])
        options=dict(device=H,source=c['source_sha256'],actor=H,manifest=H,execution_mode='profiles-off-diagnostic',selected_admission=c['selected_admission'])
        outer.plan(p,**options,death_extension=True)
        with self.assertRaises(ValueError):outer.plan(p,**options)

    def test_release_exact_128_bytes_distinct_from_go_and_finish(self):
        raw=l.fixture_release(run=f.RUN,death_case=DEATH,frequency=f.F,deadline=f.D)
        self.assertEqual(len(raw),128);self.assertEqual(raw[:6],b'RPC1\x01\xfe')
        self.assertEqual(raw[64:72],bytes(8));self.assertEqual(raw[32:48],raw[72:88])
        self.assertEqual(struct.unpack_from('<I',raw,8)[0],1);self.assertEqual(struct.unpack_from('<Q',raw,88)[0],f.D)
        self.assertNotEqual(raw,l.fixture_finish(run=f.RUN,boot_case=DEATH,frequency=f.F,deadline=f.D))
        with self.assertRaises(ValueError):l.go_record(run=f.RUN,case=DEATH,sequence=1,opcode=254,frequency=f.F,deadline=f.D,
            fixed_ports=PORTS,admission=DEATH,phase_deadline=f.D)

    def test_ack_and_release_held_identity_clock_tuple_close_binding(self):
        c=config();origin=held('ordinary',104)
        m.origin_death_ack(ack(),origin,c,lower=40001,upper=42500)
        m.origin_death_ack(ack(True),origin,c,released=True,held=ack(),lower=45000,upper=45003)
        for key,value in (('pid',999),('case_id','c'*32),('response_bytes',1),('socket_held',False),('request_eof',False),('extra',True)):
            item=ack();item[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.origin_death_ack(item,origin,c,lower=40001,upper=42500)
        for key,value in (('release_sequence',2),('release_verified',False),('connection_close','uncertain'),('peer_port',54001)):
            item=ack(True);item[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):m.origin_death_ack(item,origin,c,released=True,held=ack(),lower=45000,upper=45003)

    def test_negative_front_golden_is_distinct_from_positive_and_no_fake_eof(self):
        value=front();m.validate_death_front(value,held('pncs',107),config(),f.P,f.O,START,END)
        self.assertFalse(value['ipc_mechanics']['pipe']['eof_observed'])
        for mutate in (lambda v:v['ipc_mechanics'].update(win32_error=5),lambda v:v['ipc_mechanics']['core'].update(confirmed=7),
                lambda v:v['client'].update(response_bytes=1),lambda v:v['ipc_mechanics']['pipe'].update(reader_close='uncertain'),lambda v:v.update(wsa_cleanup=False)):
            changed=copy.deepcopy(value);mutate(changed)
            with self.assertRaises(ValueError):m.validate_death_front(changed,held('pncs',107),config(),f.P,f.O,START,END)
        with self.assertRaises(ValueError):m.validate_front(value,held('pncs',107),config(),f.P,f.O,START,END)

    def test_selected_response_failure_requires_real_connect_request_eof_and_no_deadline(self):
        value=phase();self.assertTrue(m.death_client_failed_closed(value))
        for key,bad in (('response_bytes',1),('response_eof',False),('failure','deadline'),('connect_completed',False),('socket_close','uncertain')):
            changed=copy.deepcopy(value);changed['network'][key]=bad;self.assertFalse(m.death_client_failed_closed(changed))
        value['phase_qpc'][2]=END;self.assertFalse(m.death_client_failed_closed(value))

    def test_tcp_table_network_order_halfclose_exact_owner_and_unique_tuple(self):
        addr=int.from_bytes(b'\x7f\0\0\1','little')
        def table(state=7,pid=106,lp=54000,rp=f.O,count=1):
            item=struct.pack('<6I',state,addr,int.from_bytes(lp.to_bytes(2,'big'),'little'),addr,int.from_bytes(rp.to_bytes(2,'big'),'little'),pid)
            return struct.pack('<I',count)+item*count
        for state in (6,7):self.assertEqual(l.exact_halfclosed_tcp_flow(table(state),106,54000,f.O)['state'],state)
        for raw in (table(5),table(pid=107),table(lp=54001),table(rp=f.O+1),table(count=2),b'\1\0\0\0'):
            with self.assertRaises(ValueError):l.exact_halfclosed_tcp_flow(raw,106,54000,f.O)

    def test_death_receipt_only_special_case_and_no_success_response_claim(self):
        ledger,c,tasks,go,reports,ports,public=evidence()
        row=l.decode(ledger['origin_receipts'][3]['text'].encode('ascii'))
        self.assertTrue(m.death_receipt_passed(row));self.assertFalse(m.receipt_passed(row))
        row['response_complete']=True;self.assertFalse(m.death_receipt_passed(row))

    def test_complete_and_partial_closed_death_journal(self):
        args=evidence();m.validate_death_ledger(*args)
        c=config();public=l.blank('profiles-off-diagnostic',death_extension=True)
        m.validate_death_ledger(m.blank_death_ledger(c),c,{},[],[],None,public)
        public['death_extension']['relay_stop_confirmed']=True
        with self.assertRaises(ValueError):m.validate_death_ledger(m.blank_death_ledger(c),c,{},[],[],None,public)

    def test_stop_intent_raw_hash_generation_order_and_ack_binding_recomputed(self):
        for mutate in (lambda v:v.update(stop_intent=None,stop_persisted_qpc=None),lambda v:v.update(terminate_requested=False),
                lambda v:v['relay_binding'].update(created=999),lambda v:v['relay_binding']['flow'].update(state=5),
                lambda v:v.update(stop_persisted_qpc=40000),lambda v:v['stop_intent'].update(sha256='0'*64),
                lambda v:v['release_go'].update(issued_qpc=42000),lambda v:v['ticket']['record'].update(sequence=2)):
            args=list(evidence());mutate(args[0])
            with self.assertRaises(ValueError):m.validate_death_ledger(*args)

    def test_postdeath_leak_sticky_prevents_diagnostic_completion(self):
        args=evidence();v=args[-1];v['checks']['guard_held']=True;l.finalize_public(v)
        self.assertTrue(v['diagnostic_completed']);self.assertFalse(v['checks']['proxy_death']);self.assertFalse(v['local_c_qualified'])
        v['death_extension'].update(after_direct_connected=True,after_direct_denied_by_access=False)
        v['violations']['fallback_after_death']=True;l.finalize_public(v)
        self.assertFalse(v['diagnostic_completed']);self.assertEqual(v['status'],'failed')
        self.assertTrue(v['death_extension']['after_direct_connected']);self.assertTrue(v['violations']['fallback_after_death'])

    def test_default_and_readiness_keep_death_absent_or_all_runtime_false(self):
        self.assertNotIn('death_extension',l.blank())
        value=l.blank('profiles-off-diagnostic',death_extension=True)
        value.update(status='ready',source_sha256=H,actor_sha256=H,manifest_sha256=H)
        value['checks'].update(sources=True,artifacts=True);l.validate_public(value)
        value['death_extension']['request_published']=True
        with self.assertRaises(ValueError):l.validate_public(value)

    def test_fsync_stop_intent_single_fresh_file_before_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/'death-stop-intent.json'
            with patch.object(m.os,'fsync') as flush:
                m.write_death_stop_intent(path,b'fixture');flush.assert_called_once()
            self.assertEqual(path.read_bytes(),b'fixture')
            with self.assertRaises(ValueError):m.write_death_stop_intent(path,b'replacement')

    def test_runtime_waits_for_ack_and_attribution_before_single_held_stop_and_release(self):
        owner,events,error=self.runtime();self.assertIsNone(error)
        kinds=[item[0] for item in events]
        expected=['publish','held-ack','tcp','intent','terminate','wait','wait','collect','release','release-ack','after-direct']
        at=-1
        for kind in expected:at=kinds.index(kind,at+1)
        self.assertEqual([item for item in events if item[0]=='terminate'],[('terminate',106)])
        self.assertEqual([item for item in events if item[0]=='wait'],[('wait',106,1),('wait',107,5)])
        self.assertEqual([item for item in events if item[0]=='outer'],[('outer',104),('outer',106),('outer',104),('outer',106)])
        self.assertTrue(owner.value['death_extension']['same_selected']);self.assertTrue(owner.death_after_denied)
        self.assertEqual(owner.death_ledger['pair_deadline']-owner.death_ledger['pair_start'],10*f.F)
        self.assertEqual(owner.budget.deadline,f.D);self.assertTrue(all(scope.confirmed_closed for scope in owner.scoped_owners))

    def test_missing_ack_wrong_tuple_generation_or_intent_never_stops_or_releases(self):
        for fault in ('ack','tuple','generation','intent'):
            with self.subTest(fault=fault):
                owner,events,error=self.runtime(fault);self.assertIsNotNone(error)
                self.assertFalse(any(item[0] in ('terminate','release','after-direct') for item in events))
                self.assertFalse(owner.value['death_extension']['relay_stop_confirmed'])

    def test_unknown_stop_front_client_or_release_cannot_publish_after_direct(self):
        for fault in ('terminate','front','client','release'):
            with self.subTest(fault=fault):
                owner,events,error=self.runtime(fault);self.assertIsNotNone(error)
                self.assertFalse(any(item[0]=='after-direct' for item in events))
                if fault!='release':self.assertFalse(any(item[0]=='release' for item in events))
                self.assertFalse(owner.value['death_extension']['observation_complete'])

    def test_runtime_after_direct_connection_is_sticky_and_never_denied(self):
        owner,events,error=self.runtime('leak');self.assertIsNone(error)
        self.assertTrue(owner.value['death_extension']['after_direct_connected'])
        self.assertTrue(owner.value['violations']['fallback_after_death']);self.assertFalse(owner.death_after_denied)
        owner.value['failure']='death';l.finalize_public(owner.value)
        self.assertFalse(owner.value['diagnostic_completed']);self.assertTrue(owner.value['violations']['fallback_after_death'])

    def test_runtime_partial_failures_write_and_validate_whole_closed_ownership_journal(self):
        for fault in ('ack','intent','terminate','release'):
            with self.subTest(fault=fault):
                owner,events,error=self.runtime(fault);self.assertIsNotNone(error)
                owner.value['failure']='death';l.finalize_public(owner.value)
                journal=owner.ownership_journal()
                m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])
                self.assertEqual(journal['death'],owner.death_ledger)
                self.assertEqual(journal['public_sha256'],l.sha(l.encode(owner.value)))

    def test_complete_whole_ownership_journal_allows_only_bound_death_exit_exceptions(self):
        ledger,c,tasks,death_go,reports,ports,public=evidence()
        root=Path('fixture');rows={}
        required=('origin','health','front','relay','g-probe','g-live','selected','acl-root','acl-inputs','acl-front','acl-remove','system-conhost','death-front','death-relay')
        for i,role in enumerate(required,1):
            profile='agentic-pncs' if role=='selected' else 'pncs' if role in ('front','death-front') else 'ordinary'
            row=copy.deepcopy(tasks.get(role,held(profile,200+i)))
            row.update(role=role,attempted=True,assigned=True,command=['fixture/fixed.exe'],image_path='fixture/fixed.exe',cleanup_role=role.startswith('acl-'),
                externally_held_before_first_resume=role not in ('selected','system-conhost'),externally_held_before_network_go=True)
            if role in ('g-probe','g-live'):row['image_sha256']=l.probe.pins.MXC_G_EXECUTOR_SHA256
            if role in ('selected','system-conhost'):row['resume_qpc']=None
            if role=='g-live':row['created']=1000
            if role=='system-conhost':row.update(command=None,image_path='fixture/conhost.exe',natural_exit_observed=True,stop_requested=False,finish_order_verified=True)
            rows[role]=row
        def command(role,seq,op,case):
            if role=='health-origin':raw=l.fixture_finish(run=c['run'],boot_case=case,frequency=f.F,deadline=f.D);path='origin-control/finish.bin'
            else:
                raw=l.go_record(run=c['run'],case=case,sequence=seq,opcode=op,frequency=f.F,deadline=f.D,fixed_ports=ports,
                    admission=c['admission_nonce'] if role=='selected-client' else c['maintenance_nonce'],phase_deadline=f.D)
                path=('selected-control' if role=='selected-client' else 'health-control')+'/phase-%04d.bin'%seq
            return dict(role=role,sequence=seq,opcode=op,case=case,phase_deadline=f.D,path=path,sha256=l.sha(raw))
        prefix=[command(*args) for args in (('health-client',1,2,c['health_cases'][0]),('selected-client',1,1,c['positive_case']),
            ('health-client',2,2,c['health_cases'][1]),('selected-client',2,2,c['direct_case']))]
        suffix=[command(*args) for args in (('selected-client',5,255,c['boot_case']),('health-client',3,2,c['health_cases'][2]),
            ('health-client',4,255,c['admission_nonce']),('health-origin',1,255,c['health_cases'][0]))]
        selected,helper,parent=(rows[k] for k in ('selected','system-conhost','g-live'))
        discovery=dict(parent_pid=parent['pid'],parent_created=parent['created'],first_children=sorted([selected['pid'],helper['pid']]),
            second_children=sorted([selected['pid'],helper['pid']]),query_created=selected['created'],held_created=selected['created'],
            workload_job_verified=True,outer_job_verified=True,outer_query_handle_closed=True,
            auxiliary=dict(pid=helper['pid'],created=helper['created'],query_created=helper['created'],held_created=helper['created'],
                workload_job_verified=True,outer_job_verified=True,outer_query_handle_closed=True))
        journal=dict(schema_version=1,stage='model2-first-ownership',controller_pid=123,public_sha256=l.sha(l.encode(public)),
            tasks=list(rows.values()),selected_discovery=discovery,public=public,fixed_ports=ports,go=prefix+death_go+suffix,native_reports=reports,
            maintenance=dict(attempted=True,spawn_unknown=False,pid=888,created=999,identity=held('ordinary',888)['identity'],admitted=True,exited=True,exit_code=0,plan_sha256=H),
            rules=dict(rule=l.firewall_rule(c['run'],'A-P',f.AC,'fixture/fixed.exe',f.P),intent=True,attempted=True,present_verified=True,absent_verified=True,uncertain=False),
            cleanup=dict.fromkeys(('workload_cleanup_confirmed','workload_job_empty','all_workloads_exited','maintenance_cleanup_confirmed',
                'maintenance_handles_closed','acl_removed','profile_deleted','sid_released','cleanup'),True),death=ledger,
            **{k:c[k] for k in ('run','frequency','start_qpc','deadline_qpc','source_sha256','actor_sha256','manifest_sha256')})
        m.validate_ownership_journal(journal,c,controller_pid=123)
        for role,code in (('relay',1),('front',5),('death-front',0),('death-relay',0)):
            changed=copy.deepcopy(journal);next(r for r in changed['tasks'] if r['role']==role)['exit_code']=code
            with self.subTest(role=role),self.assertRaises(ValueError):m.validate_ownership_journal(changed,c,controller_pid=123)

if __name__=='__main__':unittest.main()
