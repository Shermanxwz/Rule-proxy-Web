"""Pure selected DNS contracts and owner seams; no process, socket or DNS API."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch

spec=importlib.util.spec_from_file_location('dns_death_fixtures',Path(__file__).with_name('test_windows_identity_model2_death.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
m,l,outer=f.m,f.l,f.outer;d=l.dns;F=f.f.F;T0=f.f.T0;D=f.f.D;H=f.H;PORTS=f.PORTS

def config():
    c=f.config();c.pop('death_extension');c['dns_extension']=dict(profile=d.PROFILE,before_case='a'*32,selected_case='b'*32,
        after_case='c'*32,inventory_run='d'*32);return c

def inventory(c,pid=300):
    return dict(schema_version=1,stage='dns-standard-readonly-inventory',run=c['dns_extension']['inventory_run'],pid=pid,
        qpc_frequency=F,start_qpc=T0,deadline_qpc=D,begin_qpc=40000,end_qpc=40001,read_only=True,
        dns_servers=['192.0.2.1'],effective_nrpt_count=0,udp53_count=0,tcp53_count=0)

def phase(c,label='selected',status=5):
    selected=label=='selected';task=f.held('agentic-pncs' if selected else 'ordinary',101 if selected else 102)
    row=f.f.phase(task,'proxy-get',f.f.P);row.pop('network')
    row.update(role='selected-client' if selected else 'health-client',boot_case_id=c['boot_case'] if selected else c['admission_nonce'],
        admission_nonce=c['admission_nonce'] if selected else c['maintenance_nonce'],case_id=c['dns_extension'][label+'_case'],
        sequence=3 if label!='after' else 4,operation='dns-query',target_port=53,phase_qpc=[40100,42000,40130])
    result=dict(configured=True,called=True,completed=True,pending=False,answer_match=status==0,records_released=True,
        context_retained=False,within_deadline=True,api_status=status,query_status=0,record_count=1 if status==0 else 0,start_qpc=40110,end_qpc=40120)
    row['dns']=dict(server_constructor='official-v1-zero-port',server_address='127.0.0.1',server_port=53,
        query_name=row['case_id']+'.n0a.invalid',query_type=1,query_options=0x19e8,result=result)
    return row,task

def receiver(before=1,selected=0,after=1,*,final=False):
    cases={key:dict(matched_queries=count,answers_sent=count,rejected=0,send_failed=0) for key,count in
        (('before',before),('selected',selected),('after',after))}
    count=before+selected+after
    value=dict(ready=True,error='none',counts=dict(datagrams=count,bytes=count*64,matched_queries=count,answers_sent=count,rejected=0,oversized=0,send_failed=0),
        cases=cases,case_query_observed={key:row['matched_queries']>0 for key,row in cases.items()},selected_query_observed=selected>0,
        byte_count_is_observed_lower_bound=True,broker_cancellation_proven=False)
    if final:value.update(socket_close_attempted=True,socket_close_uncertain=False,socket_closed=True,thread_stopped=True,cleanup_confirmed=True)
    return value

class DnsTests(unittest.TestCase):
    def check_phase(self,value,task,c):
        return d.phase(value,task,c,role=value['role'],boot=value['boot_case_id'],admission=value['admission_nonce'],
            sequence=value['sequence'],case=value['case_id'],phase_deadline=value['phase_qpc'][1],identity_check=m.native_identity)

    def runtime(self,fault=None,status=5,*,profile=None,phase_builder=None):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name).resolve()
        for name in ('tools','selected','health','selected-control','health-control'):(root/name).mkdir()
        c=config()
        if profile is not None:c['dns_extension']['profile']=profile
        script=root/d.INVENTORY;script.parent.mkdir(parents=True);script.write_bytes(b'fixed readonly script')
        c['source_hashes'][d.INVENTORY]=l.sha(script.read_bytes());c['source_sha256']=l.sha(l.encode(c['source_hashes']))
        powershell=root/'System32/WindowsPowerShell/v1.0/powershell.exe';powershell.parent.mkdir(parents=True);powershell.write_bytes(b'fixed system image')
        events=[]
        class API:
            def __init__(self):self.now=40000;self.native=SimpleNamespace(environment=lambda work:'SystemRoot='+str(root)+'\0WINDIR='+str(root)+'\0TEMP='+str(work/'temp')+'\0TMP='+str(work/'temp')+'\0\0')
            def qpc(self):return self.now
            def qpc_frequency(self):return F
            def close(self,h):events.append(('close',h))
        api=API();owner=m.FirstController(c,root,api)
        def row(profile,pid):
            r=f.held(profile,pid);r.update(info=SimpleNamespace(hProcess=pid,hThread=pid+1000),attempted=True,assigned=True,
                exited=False,exit_code=None,command=[str(root/'inputs'/l.ACTOR)],image_path=str(root/'inputs'/l.ACTOR),cleanup_role=False,
                externally_held_before_first_resume=profile!='agentic-pncs',externally_held_before_network_go=True)
            if profile=='agentic-pncs':r['resume_qpc']=None
            return r
        selected,health=row('agentic-pncs',101),row('ordinary',102);owner.tasks=dict(selected=selected,health=health)
        owner.fixed_ports=PORTS
        owner.value.update(source_sha256=c['source_sha256'],actor_sha256=H,manifest_sha256=H,run_sha256=l.sha(c['run'].encode()))
        for key in ('sources','artifacts','positive','direct_deny','same_selected'):owner.value['checks'][key]=True
        owner.value['observations']=dict.fromkeys(owner.value['observations'],True)
        for role,seq,op,case in (('health-client',1,2,c['health_cases'][0]),('selected-client',1,1,c['positive_case']),
                ('health-client',2,2,c['health_cases'][1]),('selected-client',2,2,c['direct_case'])):
            raw=l.go_record(run=c['run'],case=case,sequence=seq,opcode=op,frequency=F,deadline=D,fixed_ports=PORTS,
                admission=c['admission_nonce'] if role=='selected-client' else c['maintenance_nonce'],phase_deadline=39000)
            owner.go_records.append(dict(role=role,sequence=seq,opcode=op,case=case,phase_deadline=39000,
                path=('selected-control' if role=='selected-client' else 'health-control')+'/phase-%04d.bin'%seq,sha256=l.sha(raw)))
        owner.alive=lambda r:events.append(('alive',r['pid']));owner.selected_family_alive=lambda *args:events.append(('same-selected',))
        owner.refresh_profiles=lambda:events.append(('profiles',));owner.maintenance=SimpleNamespace(last_observation={},attempted=False,
            spawn_unknown=False,pid=None,created=None,identity=None,admitted=False,exited=False,exit_code=None,plan_hash=None)
        def task(name,command,work,**kw):
            r=row('ordinary',300);r.update(command=command,image_path=command[0],image_sha256=kw['image_hash']);owner.tasks[name]=r
            return r
        owner.task=task;owner.resume=lambda r:events.append(('resume-inventory',))
        def wait(r,end,**kw):
            r.update(exited=True,exit_code=0);api.now=40002
            value=inventory(c)
            if fault=='inventory':value['udp53_count']=1
            (root/'tools/dns-inventory/stdout').write_bytes(l.encode(value));(root/'tools/dns-inventory/stderr').write_bytes(b'')
        owner.wait=wait
        class Fixture:
            bind_address='127.0.0.1';bind_port=53;allowed_peers=('127.0.0.1',)
            def __init__(self):self.query_observed=threading.Event();self.current=receiver(0,0,0)
            def start(self):events.append(('bind',));return 53
            def snapshot(self,**kw):return copy.deepcopy(self.current)
            def finish(self,**kw):
                events.append(('fixture-finish',))
                if fault=='cleanup':
                    self.query_observed.set();raise OSError('fake_cleanup_unknown')
                out=copy.deepcopy(self.current);out.update(socket_close_attempted=True,socket_close_uncertain=False,socket_closed=True,thread_stopped=True,cleanup_confirmed=True);return out
        fixture=Fixture()
        def read(api,budget,path,process,cutoff):
            if fault=='parse' and path.parent.name=='selected' and path.name=='phase-0003.json':
                fixture.query_observed.set();fixture.current=receiver(1,1,0);path.write_bytes(b'{malformed JSON')
                raise ValueError('malformed_json')
            return l.decode(path.read_bytes()),None
        real_publish=owner.publish_phase
        def publish(task,**fields):
            label=next(key for key in ('before','selected','after') if c['dns_extension'][key+'_case']==fields['case'])
            events.append(('query',label));api.now+=100
            if fault=='stale' and label=='selected':api.now=46000
            ticket=real_publish(task,**fields)
            value,_=(phase_builder or phase)(c,label,status if label=='selected' else 0)
            value['phase_qpc']=[api.now,fields['end'],api.now+30]
            if 'dns' in value:value['dns']['result'].update(start_qpc=api.now+10,end_qpc=api.now+20)
            fixture.current=receiver(1,1 if fault=='wire' else 0,1 if label=='after' else 0)
            if fault=='wire' and label=='selected':fixture.query_observed.set()
            if fault=='pending' and label=='selected':
                value.update(failure='dns-pending');value['dns']['result'].update(completed=False,pending=True,records_released=False,context_retained=True,answer_match=False)
            if fault=='late' and label=='selected':
                value['phase_qpc'][2]=fields['end']
                if 'dns' in value:value['dns']['result'].update(end_qpc=fields['end'],within_deadline=False)
                else:value['raw_udp']['within_deadline']=False
            (fields['reports']/('phase-%04d.json'%fields['sequence'])).write_bytes(l.encode(value));return ticket
        owner.publish_phase=publish
        error=None
        with patch.object(d.fixture,'DnsCasesFixture',return_value=fixture),patch.object(m,'read_when_closed',side_effect=read), \
                patch.object(m.maintenance,'validate_profiles_observation'):
            try:owner.dns_run(selected,health,PORTS)
            except (ValueError,OSError) as exc:error=exc
            try:owner.finish_dns_fixture()
            except (ValueError,OSError) as exc:error=error or exc
        owner.value['failure']='dns' if error else None
        if not d.public_access_denial(owner.value['dns_extension']):owner.value['failure']='dns'
        l.finalize_public(owner.value)
        return owner,events,error

    def test_exact_scope_plan_impact_ack_13_nonces_and_mutual_exclusion(self):
        c=config();m.validate_config(c);outer.validate_config(c)
        value=dict(schema_version=1,scope=outer.DNS_SCOPE,device_sha256=H,source_sha256=c['source_sha256'],actor_sha256=H,manifest_sha256=H,
            residue_review_acknowledged=True,recovery_reference='pure fixture',execution_mode='profiles-off-diagnostic',
            selected_admission=c['selected_admission'],dns_extension=c['dns_extension'],standard53_impact_acknowledged=True)
        options=dict(device=H,source=c['source_sha256'],actor=H,manifest=H,execution_mode='profiles-off-diagnostic',selected_admission=c['selected_admission'])
        outer.plan(value,**options,dns_extension=True)
        for change in ({'standard53_impact_acknowledged':False},{'scope':outer.DEATH_SCOPE}):
            with self.assertRaises(ValueError):outer.plan(dict(value,**change),**options,dns_extension=True)
        with self.assertRaises(ValueError):outer.plan(value,**options)
        for key in ('death_extension','wrong_peer_extension','wrong_port_extension'):
            changed=copy.deepcopy(c);changed[key]={}
            with self.assertRaises(ValueError):m.validate_config(changed)
        changed=copy.deepcopy(c);changed['dns_extension']['before_case']=c['direct_case']
        with self.assertRaises(ValueError):outer.validate_config(changed)
        with self.assertRaises(ValueError):l.blank('strict',dns_extension=True)

    def test_inventory_fresh_closed_known_dns_nrpt_and_both_port_gates(self):
        c=config();value=inventory(c)
        d.inventory(value,run=c['dns_extension']['inventory_run'],pid=300,frequency=F,start=T0,deadline=D,now=40002)
        for key,bad in (('dns_servers',['127.0.0.1']),('dns_servers',['::ffff:127.0.0.1']),('effective_nrpt_count',1),
                ('udp53_count',1),('tcp53_count',1),('pid',301),('extra',True)):
            changed=copy.deepcopy(value);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):d.inventory(changed,run=c['dns_extension']['inventory_run'],pid=300,frequency=F,start=T0,deadline=D,now=40002)
        with self.assertRaises(ValueError):d.inventory(value,run=c['dns_extension']['inventory_run'],pid=300,frequency=F,start=T0,deadline=D,now=45002)

    def test_same_api_success_api5_observation_and_api87_query0_not_success(self):
        c=config()
        for status in (0,5,87):
            value,task=phase(c,status=status);self.check_phase(value,task,c)
            self.assertEqual(d.positive(value),status==0);self.assertEqual(d.access_denial(value),status==5)
        value,task=phase(c,label='before',status=0);self.check_phase(value,task,c)
        task['identity']['appcontainer']=True
        with self.assertRaises(ValueError):self.check_phase(value,task,c)
        with self.assertRaises(ValueError):m.transport_payload(c['dns_extension']['selected_case'],53,'dns-query')

    def test_pending_late_and_unknown_qpc_preserved_but_never_access_denial(self):
        c=config()
        for fault in ('pending','phase-late','root-late','uncalled-zero','completed-end-zero','qpc','deadline'):
            value,task=phase(c);r=value['dns']['result']
            if fault=='pending':value.update(failure='dns-pending');r.update(completed=False,pending=True,context_retained=True,records_released=False)
            elif fault in ('phase-late','root-late'):
                value['phase_qpc'][2]=42000 if fault=='phase-late' else D+1;r.update(within_deadline=False,end_qpc=value['phase_qpc'][2])
            elif fault=='uncalled-zero':value.update(failure='dns-config');r.update(configured=False,called=False,completed=False,records_released=False,within_deadline=False,start_qpc=0,end_qpc=0)
            elif fault=='completed-end-zero':r.update(within_deadline=False,end_qpc=0)
            else:value['failure']=fault
            with self.subTest(fault=fault):self.check_phase(value,task,c);self.assertFalse(d.timely(value));self.assertFalse(d.access_denial(value))

    def test_receiver_unknown_counts_keep_sticky_wire_and_cleanup_independent(self):
        value=receiver(selected=1,final=True);d.receiver(value,final=True)
        value.update(counts=None,cases=None,socket_closed=False,cleanup_confirmed=False,socket_close_uncertain=True)
        d.receiver(value,final=True);self.assertTrue(value['selected_query_observed'])
        changed=copy.deepcopy(value);changed['case_query_observed']['selected']=False
        with self.assertRaises(ValueError):d.receiver(changed,final=True)

    def test_owner_inventory_precedes_only_bind_then_exact_three_queries(self):
        owner,events,error=self.runtime();self.assertIsNone(error)
        self.assertLess(events.index(('resume-inventory',)),events.index(('bind',)))
        self.assertEqual([e for e in events if e[0]=='query'],[('query','before'),('query','selected'),('query','after')])
        self.assertEqual([r['label'] for r in owner.dns_ledger['inventory_gates']],['bind','before','selected','after'])
        self.assertTrue(d.ready(owner.value['dns_extension']));self.assertFalse(owner.value['system_dns_tested'])
        journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_unsafe_or_stale_inventory_never_publishes_selected_dns(self):
        for fault in ('inventory','stale'):
            owner,events,error=self.runtime(fault);self.assertIsNotNone(error)
            selected=[g for g in owner.go_records if g['role']=='selected-client' and g['opcode']==6]
            self.assertEqual(selected,[])
            if fault=='inventory':self.assertNotIn(('bind',),events)
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_wire_is_failed_before_parse_and_through_cleanup_failure_and_outer_binding(self):
        for fault in ('wire','parse','cleanup'):
            owner,events,error=self.runtime(fault,status=87 if fault=='wire' else 5)
            with self.subTest(fault=fault):
                self.assertTrue(owner.value['violations']['selected_dns_query_observed']);self.assertEqual(owner.value['status'],'failed')
                self.assertFalse(owner.value['diagnostic_completed']);self.assertFalse(owner.value['product_acceptance'])
                journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])
                raw=l.encode(journal)
                report=dict(schema_version=1,stage='model2-first-controller',controller_pid=123,public=owner.value,
                    ownership_journal_sha256=l.sha(raw),ownership_journal_bytes=len(raw),
                    **{k:owner.config[k] for k in ('run','frequency','start_qpc','deadline_qpc','source_sha256','actor_sha256','manifest_sha256')})
                self.assertTrue(outer.bind_controller(report,owner.config,dict(child_pid=123))['violations']['selected_dns_query_observed'])

    def test_pending_late_or_api87_runtime_cannot_complete(self):
        for fault,status in (('pending',5),('late',5),(None,87)):
            owner,events,error=self.runtime(fault,status)
            self.assertFalse(d.ready(owner.value['dns_extension']));self.assertFalse(owner.value['diagnostic_completed'])
            self.assertFalse(owner.value['violations']['selected_dns_query_observed'])
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_go_exact_selected_object_and_no_other_case_is_admitted(self):
        owner,_,_=self.runtime();before=len(owner.go_records)
        changed=copy.deepcopy(owner.tasks['selected'])
        with patch.object(m.maintenance,'validate_profiles_observation'),self.assertRaises(ValueError):
            owner.publish_phase(changed,role='selected-client',boot=owner.config['boot_case'],admission=owner.config['admission_nonce'],sequence=3,
                case=owner.config['dns_extension']['selected_case'],opcode=6,control=owner.root/'selected-control',reports=owner.root/'selected',fixed_ports=PORTS,end=50000)
        self.assertEqual(len(owner.go_records),before)

    def test_complete_11_go_journal_and_independent_digests_gates_and_role_bindings(self):
        owner,_,error=self.runtime();self.assertIsNone(error);c=owner.config
        for key in ('ordinary','live_probe','selected_held','declared_caps','origin_healthy','cleanup'):owner.value['checks'][key]=True
        owner.value['diagnostic'].update(profiles_off_verified=True,exact_rule_scope_verified=True,positive_verified=True,direct_attempted=True,observation_complete=True)
        l.finalize_public(owner.value)
        base=copy.deepcopy(owner.tasks['health'])
        for index,role in enumerate(('origin','front','relay','g-probe','g-live','acl-root','acl-inputs','acl-front','acl-remove','system-conhost'),1):
            row=copy.deepcopy(base);row.update(pid=500+index,created=1500+index,exited=True,exit_code=0)
            if role in ('g-probe','g-live'):row['image_sha256']=l.probe.pins.MXC_G_EXECUTOR_SHA256
            if role=='g-live':row['created']=1000
            if role=='front':row.update(identity=f.held('pncs',row['pid'])['identity'],capabilities=f.held('pncs',row['pid'])['capabilities'])
            if role=='system-conhost':row.update(command=None,image_path='fixture/conhost.exe',image_sha256=H,
                externally_held_before_first_resume=False,resume_qpc=None,natural_exit_observed=True,stop_requested=False,finish_order_verified=True)
            owner.tasks[role]=row
        for row in owner.tasks.values():row.update(exited=True,exit_code=0)
        selected,parent,helper=(owner.tasks[k] for k in ('selected','g-live','system-conhost'))
        owner.selected_discovery=dict(parent_pid=parent['pid'],parent_created=parent['created'],
            first_children=sorted([selected['pid'],helper['pid']]),second_children=sorted([selected['pid'],helper['pid']]),
            query_created=selected['created'],held_created=selected['created'],workload_job_verified=True,outer_job_verified=True,outer_query_handle_closed=True,
            auxiliary=dict(pid=helper['pid'],created=helper['created'],query_created=helper['created'],held_created=helper['created'],
                workload_job_verified=True,outer_job_verified=True,outer_query_handle_closed=True))
        owner.maintenance=SimpleNamespace(attempted=True,spawn_unknown=False,pid=888,created=999,identity=base['identity'],admitted=True,exited=True,exit_code=0,plan_hash=H)
        owner.rule_owner=SimpleNamespace(rule=l.firewall_rule(c['run'],'A-P',f.f.AC,str(owner.root/'inputs'/l.ACTOR),f.f.P),
            intent=True,attempted=True,present_verified=True,absent_verified=True,uncertain=False)
        owner.cleanup_ledger=dict.fromkeys(owner.cleanup_ledger,True)
        for role,seq,op,case in (('selected-client',4,255,c['boot_case']),('health-client',5,2,c['health_cases'][2]),
                ('health-client',6,255,c['admission_nonce']),('health-origin',1,255,c['health_cases'][0])):
            raw=l.fixture_finish(run=c['run'],boot_case=case,frequency=F,deadline=D) if role=='health-origin' else l.go_record(
                run=c['run'],case=case,sequence=seq,opcode=op,frequency=F,deadline=D,fixed_ports=PORTS,
                admission=c['admission_nonce'] if role=='selected-client' else c['maintenance_nonce'],phase_deadline=D)
            path='origin-control/finish.bin' if role=='health-origin' else ('selected-control' if role=='selected-client' else 'health-control')+'/phase-%04d.bin'%seq
            owner.go_records.append(dict(role=role,sequence=seq,opcode=op,case=case,phase_deadline=D,path=path,sha256=l.sha(raw)))
        journal=owner.ownership_journal();self.assertEqual(len(journal['go']),11)
        m.validate_ownership_journal(journal,c,controller_pid=journal['controller_pid'])
        for mutate in (lambda j:j['dns']['inventory'].update(sha256='0'*64),
                lambda j:j['dns']['inventory_gates'][2].update(qpc=46000),
                lambda j:next(t for t in j['tasks'] if t['role']=='dns-inventory')['command'].__setitem__(8,'e'*32),
                lambda j:j['go'][5].update(case='e'*32),
                lambda j:j['dns'].update(fixture_final=None)):
            changed=copy.deepcopy(journal);mutate(changed)
            with self.assertRaises(ValueError):m.validate_ownership_journal(changed,c,controller_pid=journal['controller_pid'])

    def test_default_and_preflight_cannot_claim_dns_runtime_facts(self):
        self.assertNotIn('dns_extension',l.blank())
        value=l.blank('profiles-off-diagnostic',dns_extension=True)
        value.update(status='ready',source_sha256=H,actor_sha256=H,manifest_sha256=H)
        value['checks'].update(sources=True,artifacts=True);l.validate_public(value)
        value['dns_extension']['selected_attempted']=True
        with self.assertRaises(ValueError):l.validate_public(value)

if __name__=='__main__':unittest.main()
