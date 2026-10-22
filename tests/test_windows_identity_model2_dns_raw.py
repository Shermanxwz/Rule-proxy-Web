"""Pure connected-UDP DNS contracts and held-owner seams; no sockets or actors."""
import copy
import importlib.util
import io
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('raw_dns_api6_fixtures',Path(__file__).with_name('test_windows_identity_model2_dns.py'))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
m,l,outer,d=f.m,f.l,f.outer,f.d;r=d.raw_udp;F,T0,D,H,PORTS=f.F,f.T0,f.D,f.H,f.PORTS

def config():
    c=f.config();c['dns_extension']['profile']=r.PROFILE;return c

def phase(c,label='selected',status=5):
    value,task=f.phase(c,label,status);value.pop('dns');value['operation']='dns-raw-udp'
    raw=dict.fromkeys(r.BOOLEANS,False)
    raw.update(server_address='127.0.0.1',server_port=53,query_name=value['case_id']+'.n0a.invalid',query_type=1,
        transaction_id=int(value['case_id'][:4],16),query_bytes=62,within_deadline=True,wsa_startup=True,wsa_cleanup=True,
        socket_created=True,inheritance_cleared=True,nonblocking=True,connect_attempted=True,local_port=None,peer_port=None,
        send_bytes=0,response_bytes=0,source_port=None,socket_close='confirmed',failure='connect',wsa_error=10013,win32_error=None)
    if status==0:
        raw.update(dict.fromkeys(r.BOOLEANS,True));raw.update(local_port=52001,peer_port=53,source_port=53,
            send_bytes=62,response_bytes=78,failure=None,wsa_error=None)
    elif status==6:
        raw.update(connect_completed=True,peer_loopback=True,local_port=52001,peer_port=53,send_attempted=True,failure='send')
    elif status!=5:
        raw.update(failure='create',socket_created=False,inheritance_cleared=False,nonblocking=False,
            connect_attempted=False,socket_close='not_attempted',wsa_error=status)
    value['raw_udp']=raw;return value,task

def complete_owner(owner):
    """Close the same existing fake owner, with original roles/11-GO authority."""
    c=owner.config
    for key in ('ordinary','live_probe','selected_held','declared_caps','origin_healthy','cleanup'):owner.value['checks'][key]=True
    owner.value['diagnostic'].update(profiles_off_verified=True,exact_rule_scope_verified=True,positive_verified=True,
        direct_attempted=True,observation_complete=True)
    l.finalize_public(owner.value)
    base=copy.deepcopy(owner.tasks['health'])
    for index,role in enumerate(('origin','front','relay','g-probe','g-live','acl-root','acl-inputs','acl-front','acl-remove','system-conhost'),1):
        row=copy.deepcopy(base);row.update(pid=500+index,created=1500+index,exited=True,exit_code=0)
        if role in ('g-probe','g-live'):row['image_sha256']=l.probe.pins.MXC_G_EXECUTOR_SHA256
        if role=='g-live':row['created']=1000
        if role=='front':row.update(identity=f.f.held('pncs',row['pid'])['identity'],capabilities=f.f.held('pncs',row['pid'])['capabilities'])
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
    owner.maintenance=SimpleNamespace(attempted=True,spawn_unknown=False,pid=888,created=999,identity=base['identity'],admitted=True,
        exited=True,exit_code=0,plan_hash=H)
    owner.rule_owner=SimpleNamespace(rule=l.firewall_rule(c['run'],'A-P',f.f.f.AC,str(owner.root/'inputs'/l.ACTOR),f.f.f.P),
        intent=True,attempted=True,present_verified=True,absent_verified=True,uncertain=False)
    owner.cleanup_ledger=dict.fromkeys(owner.cleanup_ledger,True)
    for role,seq,op,case in (('selected-client',4,255,c['boot_case']),('health-client',5,2,c['health_cases'][2]),
            ('health-client',6,255,c['admission_nonce']),('health-origin',1,255,c['health_cases'][0])):
        raw=l.fixture_finish(run=c['run'],boot_case=case,frequency=F,deadline=D) if role=='health-origin' else l.go_record(
            run=c['run'],case=case,sequence=seq,opcode=op,frequency=F,deadline=D,fixed_ports=PORTS,
            admission=c['admission_nonce'] if role=='selected-client' else c['maintenance_nonce'],phase_deadline=D)
        path='origin-control/finish.bin' if role=='health-origin' else ('selected-control' if role=='selected-client' else 'health-control')+'/phase-%04d.bin'%seq
        owner.go_records.append(dict(role=role,sequence=seq,opcode=op,case=case,phase_deadline=D,path=path,sha256=l.sha(raw)))
    return owner.ownership_journal()

class RawDnsTests(unittest.TestCase):
    def check_phase(self,value,task,c):return f.DnsTests.check_phase(self,value,task,c)
    def runtime(self,fault=None,status=5,phase_builder=phase):return f.DnsTests.runtime(self,fault,status,profile=r.PROFILE,phase_builder=phase_builder)

    def test_original_api6_public_shape_and_distinct_raw_method_without_api_facts(self):
        original=d.blank();raw=d.blank(r.PROFILE)
        self.assertNotIn('transport',original);self.assertNotIn('selected_raw_udp',original)
        self.assertEqual(raw['transport'],'winsock-udp');self.assertEqual(raw['method'],'connect-send-recvfrom')
        for key in ('selected_attempted','selected_completed','selected_pending','selected_late','selected_access_denial_observed',
                'selected_api_status','query_status','record_count'):
            self.assertNotIn(key,raw)
        d.validate_public(original);d.validate_public(raw);self.assertFalse(d.ready(raw))
        self.assertIsNone(raw['selected_raw_udp'])

    def test_raw_selector_requires_test_flag_exact_scope_plan_and_profile(self):
        c=config();m.validate_config(c);outer.validate_config(c)
        value=dict(schema_version=1,scope=outer.RAW_DNS_SCOPE,device_sha256=H,source_sha256=c['source_sha256'],actor_sha256=H,manifest_sha256=H,
            residue_review_acknowledged=True,recovery_reference='pure fixture',execution_mode='profiles-off-diagnostic',
            selected_admission=c['selected_admission'],dns_extension=c['dns_extension'],standard53_impact_acknowledged=True)
        options=dict(device=H,source=c['source_sha256'],actor=H,manifest=H,execution_mode='profiles-off-diagnostic',selected_admission=c['selected_admission'])
        outer.plan(value,**options,dns_extension=True,dns_profile=r.PROFILE)
        for kw in ({},{'dns_profile':r.PROFILE},{'dns_extension':True},{'dns_extension':True,'dns_profile':'unknown'}):
            with self.subTest(options=kw),self.assertRaises(ValueError):outer.plan(value,**options,**kw)
        for key,bad in (('scope',outer.DNS_SCOPE),('standard53_impact_acknowledged',False)):
            with self.subTest(key=key),self.assertRaises(ValueError):outer.plan(dict(value,**{key:bad}),**options,dns_extension=True,dns_profile=r.PROFILE)
        changed=copy.deepcopy(value);changed['dns_extension']['profile']=d.PROFILE
        with self.assertRaises(ValueError):outer.plan(changed,**options,dns_extension=True,dns_profile=r.PROFILE)
        for builder in (lambda:l.blank(dns_profile=r.PROFILE),lambda:outer.blank('preflight',dns_profile=r.PROFILE)):
            with self.assertRaises(ValueError):builder()
        c['dns_extension']['before_case']=c['direct_case']
        with self.assertRaises(ValueError):m.validate_config(c)

    def test_cli_raw_needs_test_dns_and_passes_explicit_profile_without_runtime(self):
        with patch.object(outer,'preflight') as preflight,patch.object(outer,'run_local') as runtime,patch('sys.stderr',new=io.StringIO()):
            with self.assertRaises(SystemExit):outer.main(['--dns-profile',r.PROFILE])
            preflight.assert_not_called();runtime.assert_not_called()
        result=outer.blank('preflight','profiles-off-diagnostic',dns_extension=True,dns_profile=r.PROFILE)
        with patch.object(outer,'preflight',return_value=result) as preflight,patch.object(outer,'run_local') as runtime,patch('sys.stdout',new=io.StringIO()):
            outer.main(['--profiles-off-diagnostic','--test-dns','--dns-profile',r.PROFILE])
            self.assertEqual(preflight.call_args.kwargs,dict(execution_mode='profiles-off-diagnostic',test_dns=True,dns_profile=r.PROFILE))
            runtime.assert_not_called()

    def test_raw_phase_exact_shape_packet_identity_and_no_api6_substitution(self):
        c=config();value,task=phase(c,status=0);self.check_phase(value,task,c);self.assertTrue(d.positive(value))
        for key,bad in (('transaction_id',0),('query_name','e'*32+'.n0a.invalid'),('query_bytes',61),('server_port',5353),
                ('response_bytes',77),('source_port',54),('source_loopback',False),('extra',True)):
            changed=copy.deepcopy(value);changed['raw_udp'][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.check_phase(changed,task,c)
        changed=copy.deepcopy(value);changed['dns']=changed.pop('raw_udp')
        with self.assertRaises(ValueError):self.check_phase(changed,task,c)
        changed=copy.deepcopy(value);changed['operation']='dns-query'
        with self.assertRaises(ValueError):self.check_phase(changed,task,c)
        ordinary=copy.deepcopy(task);ordinary['identity']['appcontainer']=False
        with self.assertRaises(ValueError):self.check_phase(value,ordinary,c)

    def test_connect_and_send_10013_are_distinct_typed_observations(self):
        c=config()
        for status,stage in ((5,'connect'),(6,'send')):
            value,task=phase(c,status=status);self.check_phase(value,task,c)
            self.assertTrue(d.access_denial(value));self.assertFalse(d.positive(value))
            public=d.selected_fields(value)['selected_raw_udp'];r.validate_public(public)
            self.assertEqual(public['failure'],stage);self.assertEqual(public['wsa_error'],10013)
            self.assertEqual(public['send_attempted'],stage=='send');self.assertFalse(public['send_complete'])
            self.assertNotIn('local_port',public);self.assertNotIn('peer_port',public);self.assertNotIn('source_port',public)

    def test_create_setup_select_receive_or_unknown_error_cannot_be_53_denial(self):
        c=config()
        for stage in ('create','inheritance','nonblocking','peer','select-write','select-read','receive','response','close','wsa-cleanup'):
            value,task=phase(c,status=0);raw=value['raw_udp'];raw.update(failure=stage,wsa_error=10013,response_exact=False)
            if stage=='inheritance':raw.update(wsa_error=None,win32_error=10013)
            self.check_phase(value,task,c);self.assertFalse(d.access_denial(value),stage)
        value,task=phase(c,status=10013);self.check_phase(value,task,c);self.assertFalse(d.access_denial(value))
        value,task=phase(c);value['raw_udp']['wsa_error']=None;self.check_phase(value,task,c);self.assertFalse(d.access_denial(value))

    def test_zero_datagram_and_late_positive_keep_facts_but_never_become_deny(self):
        c=config();value,task=phase(c,status=0);raw=value['raw_udp']
        raw.update(response_exact=False,response_bytes=0,failure='response');self.check_phase(value,task,c)
        self.assertTrue(raw['datagram_received']);self.assertFalse(d.positive(value));self.assertFalse(d.access_denial(value))
        for stage in ('qpc','deadline'):
            value,task=phase(c,status=0);value['raw_udp'].update(within_deadline=False,failure=stage)
            self.check_phase(value,task,c);self.assertTrue(value['raw_udp']['response_exact']);self.assertFalse(d.timely(value))
            self.assertFalse(d.access_denial(value))

    def test_postcall_clock_does_not_erase_first_10013_or_qualify_late_denial(self):
        c=config()
        for fault in ('within','phase','root','qpc','deadline','close'):
            value,task=phase(c);raw=value['raw_udp']
            if fault=='within':raw['within_deadline']=False
            elif fault in ('phase','root'):value['phase_qpc'][2]=value['phase_qpc'][1] if fault=='phase' else D+1
            elif fault=='close':raw['socket_close']='uncertain'
            else:value['failure']=fault;raw['within_deadline']=False
            self.check_phase(value,task,c);self.assertEqual(raw['wsa_error'],10013);self.assertEqual(raw['failure'],'connect')
            self.assertFalse(d.access_denial(value),fault)

    def test_no_wire_claim_from_connect_or_local_send_and_unknown_receiver_never_ready(self):
        raw=d.blank(r.PROFILE);c=config();value,task=phase(c,status=0)
        value['raw_udp'].update(datagram_received=False,response_bytes=0,source_loopback=False,source_port=None,response_exact=False,failure='deadline',within_deadline=False)
        self.check_phase(value,task,c);raw.update(d.selected_fields(value));d.validate_public(raw)
        self.assertTrue(raw['selected_raw_udp']['connect_completed']);self.assertTrue(raw['selected_raw_udp']['send_complete'])
        self.assertFalse(raw['selected_wire_query_observed']);self.assertFalse(d.ready(raw))
        receiver=f.receiver(selected=1,final=True);receiver.update(counts=None,cases=None,cleanup_confirmed=False,socket_closed=False,socket_close_uncertain=True)
        d.receiver(receiver,final=True);self.assertTrue(receiver['selected_query_observed'])

    def test_owner_inventory_precedes_bind_and_same_api_controls_use_op7_only(self):
        for status,stage in ((5,'connect'),(6,'send')):
            owner,events,error=self.runtime(status=status);self.assertIsNone(error)
            self.assertLess(events.index(('resume-inventory',)),events.index(('bind',)))
            self.assertEqual([e for e in events if e[0]=='query'],[('query','before'),('query','selected'),('query','after')])
            self.assertEqual([g['opcode'] for g in owner.go_records[4:]], [7,7,7])
            self.assertEqual([g['label'] for g in owner.dns_ledger['inventory_gates']],['bind','before','selected','after'])
            self.assertTrue(d.ready(owner.value['dns_extension']));self.assertFalse(owner.value['system_dns_tested'])
            self.assertEqual(owner.value['dns_extension']['selected_raw_udp']['failure'],stage)
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_publisher_refuses_other_transport_opcode_and_copied_selected_before_go(self):
        owner,_,_=self.runtime();before=len(owner.go_records)
        for task,op in ((owner.tasks['selected'],6),(copy.deepcopy(owner.tasks['selected']),7)):
            with patch.object(m.maintenance,'validate_profiles_observation'),self.assertRaises(ValueError):
                owner.publish_phase(task,role='selected-client',boot=owner.config['boot_case'],admission=owner.config['admission_nonce'],sequence=3,
                    case=owner.config['dns_extension']['selected_case'],opcode=op,control=owner.root/'selected-control',reports=owner.root/'selected',fixed_ports=PORTS,end=50000)
            self.assertEqual(len(owner.go_records),before)

    def test_stale_inventory_and_late_raw_report_never_complete(self):
        for fault in ('inventory','stale','late'):
            owner,events,error=self.runtime(fault)
            if fault=='late':self.assertIsNone(error);self.assertIn(('query','after'),events)
            else:self.assertIsNotNone(error)
            self.assertFalse(d.ready(owner.value['dns_extension']));self.assertFalse(owner.value['diagnostic_completed'])
            self.assertFalse(owner.value['violations']['selected_dns_query_observed'])
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_only_closed_typed_timeout_collects_declared_after_without_becoming_denial(self):
        for failure,closed,expected in (('deadline','confirmed',True),('qpc','confirmed',False),('deadline','uncertain',False)):
            def builder(c,label,status):
                value,task=phase(c,label,status)
                if label=='selected':value['raw_udp'].update(failure=failure,within_deadline=False,socket_close=closed,wsa_error=None)
                return value,task
            owner,events,error=self.runtime(phase_builder=builder)
            self.assertEqual(('query','after') in events,expected)
            self.assertFalse(d.ready(owner.value['dns_extension']));self.assertFalse(owner.value['diagnostic_completed'])
            if expected:self.assertIsNone(error)
            else:self.assertIsNotNone(error)
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])

    def test_receiver_hit_survives_raw_parse_and_cleanup_errors_through_outer(self):
        for fault,status in (('wire',0),('parse',5),('cleanup',5)):
            owner,_,_=self.runtime(fault,status)
            self.assertTrue(owner.value['violations']['selected_dns_query_observed']);self.assertEqual(owner.value['status'],'failed')
            self.assertFalse(owner.value['diagnostic_completed']);self.assertFalse(owner.value['product_acceptance'])
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,owner.config,controller_pid=journal['controller_pid'])
            raw=l.encode(journal)
            report=dict(schema_version=1,stage='model2-first-controller',controller_pid=123,public=owner.value,
                ownership_journal_sha256=l.sha(raw),ownership_journal_bytes=len(raw),
                **{k:owner.config[k] for k in ('run','frequency','start_qpc','deadline_qpc','source_sha256','actor_sha256','manifest_sha256')})
            bound=outer.bind_controller(report,owner.config,dict(child_pid=123));self.assertTrue(bound['violations']['selected_dns_query_observed'])

    def test_full_11_go_13_nonce_journal_is_profile_bound_and_preserves_false_scope(self):
        owner,_,error=self.runtime();self.assertIsNone(error);journal=complete_owner(owner);c=owner.config
        self.assertEqual(len(journal['go']),11);self.assertEqual([g['opcode'] for g in journal['go'][4:7]],[7,7,7])
        m.validate_ownership_journal(journal,c,controller_pid=journal['controller_pid'])
        self.assertFalse(owner.value['system_dns_tested']);self.assertFalse(owner.value['local_c_qualified']);self.assertFalse(owner.value['product_acceptance'])
        self.assertFalse(owner.value['dns_extension']['default_resolver_tested']);self.assertFalse(owner.value['dns_extension']['dns_isolation_qualified'])
        for mutate in (lambda j:j['dns'].update(profile=d.PROFILE),lambda j:j['dns']['inventory_gates'][2].update(qpc=46000),
                lambda j:j['dns']['phases'][1]['record'].update(sha256='0'*64),lambda j:j['go'][5].update(opcode=6),
                lambda j:j['dns'].update(fixture_final=None)):
            changed=copy.deepcopy(journal);mutate(changed)
            with self.assertRaises(ValueError):m.validate_ownership_journal(changed,c,controller_pid=journal['controller_pid'])

    def test_ready_preflight_cannot_claim_raw_stage_and_public_rejects_api_fields(self):
        value=l.blank('profiles-off-diagnostic',dns_extension=True,dns_profile=r.PROFILE)
        value.update(status='ready',source_sha256=H,actor_sha256=H,manifest_sha256=H);value['checks'].update(sources=True,artifacts=True)
        l.validate_public(value);value['dns_extension'].update(d.selected_fields(phase(config())[0]))
        with self.assertRaises(ValueError):l.validate_public(value)
        for change in ({'selected_api_status':0},{'transport':'DnsQueryEx'},{'method':'sendto-recvfrom'}):
            public=d.blank(r.PROFILE);public.update(change)
            with self.assertRaises(ValueError):d.validate_public(public)

if __name__=='__main__':unittest.main()
