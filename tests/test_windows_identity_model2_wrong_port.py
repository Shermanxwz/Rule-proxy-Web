"""Same-peer wrong-port controls are inert fakes; no Windows/network calls."""
import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
def module(name):
    s=importlib.util.spec_from_file_location('wrong_port_'+name,Path(__file__).with_name(name+'.py'))
    v=importlib.util.module_from_spec(s);s.loader.exec_module(v);return v
f=module('test_windows_identity_model2_native_schemas');d=module('test_windows_identity_model2_diagnostic')
m=f.m;l=m.live


def extension():
    return dict(profile='same-peer-wrong-port-v1',**{k:format(i,'032x') for i,k in enumerate(
        ('listener_boot','control_boot','control_admission','before_case','wrong_case','after_case'),20)})


class WrongPortTests(unittest.TestCase):
    def test_extension_requires_both_controls_without_changing_original_qualification(self):
        value=d.completed();value['wrong_port_extension']=l.blank_wrong_port()
        self.assertFalse(l.diagnostic_ready(value))
        value['wrong_port_extension'].update(healthy_before=True,healthy_after=True,attempted=True,observation_complete=True)
        value=l.finalize_public(value)
        self.assertTrue(value['wrong_port_extension']['completed'])
        self.assertFalse(value['checks']['wrong_port']);self.assertFalse(value['local_c_qualified'])
        self.assertFalse(value['first_chain_verified']);self.assertFalse(value['product_acceptance'])
        bad=copy.deepcopy(value);bad['wrong_port_extension']['healthy_after']=False
        self.assertFalse(l.finalize_public(bad)['wrong_port_extension']['completed'])

    def test_role_override_keeps_default_origin_gate_and_absolute_receipt_contract(self):
        held=f.task('pncs',105);row=f.receipt(held);row.update(role='health-listener',port=f.Q)
        row['request_bytes']=len(m.transport_payload(f.CASE,f.Q,'wrong-port')[0])
        with self.assertRaises(ValueError):m.receipt(row,held,f.CONFIG,boot=f.BOOT,port=f.Q,index=2)
        m.receipt(row,held,f.CONFIG,boot=f.BOOT,port=f.Q,index=2,role='health-listener')
        self.assertTrue(m.receipt_passed(row,'wrong-port'));self.assertFalse(m.receipt_passed(row))

    def test_healthy_controls_and_access_deny_complete_independent_wrong_port_observation(self):
        owner,calls=self.exercise()
        self.assertEqual([row['opcode'] for row in calls],[3,3,3])
        self.assertEqual([row['sequence'] for row in calls],[1,3,2])
        self.assertTrue(owner.value['wrong_port_extension']['denied_by_access'])
        self.assertTrue(owner.value['wrong_port_extension']['observation_complete'])
        self.assertFalse(owner.value['checks']['wrong_port'])

    def test_unhealthy_ordinary_control_stops_before_selected_wrong_port_go(self):
        owner,calls=self.exercise(unhealthy=True)
        self.assertEqual(len(calls),1)
        self.assertFalse(owner.value['wrong_port_extension']['attempted'])
        self.assertFalse(owner.value['wrong_port_extension']['observation_complete'])

    def test_psec_controls_use_swapped_ports_and_op1_without_changing_main_wrong_op3(self):
        owner,calls=self.exercise(psec=True)
        self.assertEqual([row['opcode'] for row in calls],[1,3,1])
        for row in (calls[0],calls[2]):
            self.assertEqual(row['fixed_ports'],dict(proxy=f.Q,wrong_port=f.P,origin=f.O))
        self.assertEqual(calls[1]['fixed_ports'],dict(proxy=f.P,wrong_port=f.Q,origin=f.O))
        self.assertTrue(owner.value['wrong_port_extension']['observation_complete'])

    def test_wrong_peer_changes_receiver_identity_at_same_port_and_uses_op4(self):
        owner,calls=self.exercise(psec=True,peer=True)
        self.assertEqual([row['opcode'] for row in calls],[1,4,1])
        self.assertTrue(all(row['fixed_ports']==dict(proxy=f.P,wrong_port=f.Q,origin=f.O) for row in calls))
        self.assertTrue(owner.value['wrong_peer_extension']['denied_by_access'])
        self.assertTrue(owner.value['wrong_peer_extension']['observation_complete'])
        self.assertFalse(owner.value['checks']['wrong_peer'])

    def test_typed_peer_timeout_collects_after_controls_but_never_becomes_denial_or_completed(self):
        owner,calls=self.exercise(psec=True,peer=True,peer_timeout=True)
        self.assertEqual([row['opcode'] for row in calls],[1,4,1])
        peer=owner.value['wrong_peer_extension']
        self.assertTrue(peer['timed_out']);self.assertTrue(peer['healthy_after']);self.assertTrue(peer['observation_complete'])
        self.assertFalse(peer['denied_by_access'])
        value=d.completed();value['wrong_peer_extension']=copy.deepcopy(peer)
        m.finish_peer_observation(value);value=l.finalize_public(value)
        self.assertEqual(value['failure'],'wrong-peer');self.assertEqual(value['status'],'inconclusive')
        self.assertFalse(value['diagnostic_completed']);self.assertFalse(value['wrong_peer_extension']['completed'])
        self.assertFalse(value['first_chain_verified']);self.assertFalse(value['local_c_qualified'])
        value['wrong_peer_extension'].update(connected=True,forbidden_nonce_received=True)
        value['violations']['wrong_peer_connected']=True
        value=l.finalize_public(value)
        self.assertEqual(value['status'],'failed');self.assertTrue(value['wrong_peer_extension']['timed_out'])

    def test_peer_timeout_predicate_rejects_unbounded_or_setup_or_error_substitutes(self):
        row=f.phase(operation='wrong-peer',port=f.P)
        row['phase_qpc']=[21000,24000,24001]
        row['network'].update(connect_completed=False,peer_loopback=False,request_complete=False,send_shutdown=False,
            response_exact=False,response_eof=False,local_port=None,peer_port=None,request_bytes=0,response_bytes=0,
            failure='deadline',wsa_error=None)
        self.assertTrue(m.bounded_connect_timeout(row,f.F,f.D))
        for mutate in (lambda x:x['phase_qpc'].__setitem__(2,25000),lambda x:x['phase_qpc'].__setitem__(2,23999),
                       lambda x:x['network'].update(wsa_error=10013),lambda x:x['network'].update(socket_created=False),
                       lambda x:x['network'].update(connect_completed=True),lambda x:x['network'].update(socket_close='uncertain'),
                       lambda x:x.update(failure='deadline')):
            changed=copy.deepcopy(row);mutate(changed)
            self.assertFalse(m.bounded_connect_timeout(changed,f.F,f.D))

    def test_main_actual_tier_cannot_substitute_for_missing_q_actual_tier(self):
        owner,calls=self.exercise(psec=True,bad_q_tier=True)
        self.assertEqual(len(calls),3)
        self.assertTrue(owner.value['wrong_port_extension']['healthy_before'])
        self.assertTrue(owner.value['wrong_port_extension']['attempted'])
        self.assertFalse(owner.value['wrong_port_extension']['observation_complete'])

    def test_q_go_digest_with_main_ports_is_rejected_by_independent_journal(self):
        o=module('test_windows_identity_model2_ownership');c=o.config();x=extension()
        x['profile']='same-peer-wrong-port-psec-control-v1'
        c.update(execution_mode='profiles-off-diagnostic',wrong_port_extension=x,
            selected_admission=dict(profile='actor-plus-system-conhost-v1',conhost_sha256='f'*64))
        with tempfile.TemporaryDirectory() as temporary:
            owner=m.FirstController(c,Path(temporary),o.Clock());owner.fixed_ports=dict(proxy=f.P,wrong_port=f.Q,origin=f.O)
            entries=[('health-client',1,2,c['health_cases'][0]),('selected-client',1,1,c['positive_case']),
                ('health-client',2,2,c['health_cases'][1]),('selected-client',2,2,c['direct_case']),('q-health',1,1,x['before_case'])]
            for role,sequence,opcode,case in entries:
                admission=c['admission_nonce'] if role=='selected-client' else x['control_admission'] if role=='q-health' else c['maintenance_nonce']
                ports=dict(proxy=f.Q,wrong_port=f.P,origin=f.O) if role=='q-health' else owner.fixed_ports
                raw=l.go_record(run=c['run'],case=case,sequence=sequence,opcode=opcode,frequency=c['frequency'],
                    deadline=c['deadline_qpc'],fixed_ports=ports,admission=admission,phase_deadline=20000)
                path=('selected-control' if role=='selected-client' else 'q-health-control' if role=='q-health' else 'health-control')+'/phase-%04d.bin'%sequence
                owner.go_records.append(dict(role=role,sequence=sequence,opcode=opcode,case=case,phase_deadline=20000,path=path,sha256=l.sha(raw)))
            journal=owner.ownership_journal();m.validate_ownership_journal(journal,c,controller_pid=journal['controller_pid'])
            journal['go'][-1]['sha256']=l.sha(l.go_record(run=c['run'],case=x['before_case'],sequence=1,opcode=1,
                frequency=c['frequency'],deadline=c['deadline_qpc'],fixed_ports=owner.fixed_ports,
                admission=x['control_admission'],phase_deadline=20000))
            with self.assertRaisesRegex(ValueError,'journal_go_digest'):
                m.validate_ownership_journal(journal,c,controller_pid=journal['controller_pid'])

    def exercise(self,unhealthy=False,psec=False,bad_q_tier=False,peer=False,peer_timeout=False):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup);root=Path(temporary.name)
        prefix='b' if peer else 'q';key='wrong_peer_extension' if peer else 'wrong_port_extension'
        listener_dir=root/('b-front' if peer else 'front');listener_dir.mkdir()
        x=extension();c=dict(f.CONFIG,admission_nonce=f.ADMISSION);c[key]=x
        if psec:x['profile']='wrong-peer-psec-control-v1' if peer else 'same-peer-wrong-port-psec-control-v1'
        target=f.P if peer else f.Q
        c['direct_case']='e'*32
        listener=dict(f.task('pncs',105),info=SimpleNamespace(hProcess=105),exited=False)
        control=dict(f.task('ordinary',106),info=SimpleNamespace(hProcess=106),exited=False)
        owner=object.__new__(m.FirstController);owner.config=c;owner.root=root;owner.go_records=[]
        owner.value=l.blank('profiles-off-diagnostic',wrong_port_extension=not peer,wrong_peer_extension=peer)
        owner.tasks={prefix+'-listener':listener,prefix+'-health':control}
        if psec:
            work=root/(prefix+'-g-live');(work/'dacl-state').mkdir(parents=True)
            (work/'stdout').write_bytes(b'' if bad_q_tier else b'selected isolation tier: base-container\n')
            (work/'stderr').write_bytes(b'')
            (root/'main-tier-control').write_bytes(b'selected isolation tier: base-container\n')
            owner.tasks[prefix+'-g-live']=dict(work=work,exited=False,exit_code=None)
        owner.finish_auxiliary=lambda role:None
        owner.phase='health';owner.wrong_port_deadline=None;owner.wrong_port_denied=False
        owner.budget=SimpleNamespace(read=lambda:21000,cutoff=lambda n:90000,require_ms=lambda end:100)
        owner.api=SimpleNamespace();owner.selected_family_alive=lambda:None;owner.alive=lambda task:None
        owner.refresh_profiles=lambda:None;owner.finish_client=lambda *a,**kw:None
        owner.wait=lambda task,end:task.update(exited=True,exit_code=0)
        calls=[]
        def phase(task,**kw):
            calls.append(kw);row=f.phase(operation='wrong-peer' if peer else 'wrong-port',port=target);row['case_id']=kw['case']
            row['phase_qpc']=[21000,kw['end'],22000]
            if task is not control or unhealthy:
                row['network'].update(connect_completed=False,peer_loopback=False,request_complete=False,send_shutdown=False,
                    response_exact=False,response_eof=False,local_port=None,peer_port=None,request_bytes=0,response_bytes=0,
                    failure='connect',wsa_error=10013)
                if peer_timeout and task is not control:
                    row['network'].update(failure='deadline',wsa_error=None)
                    row['phase_qpc'][2]=kw['end']+1
            return row
        owner.native_phase=phase
        def receipt(index,case):
            row=f.receipt(listener);row.update(role='health-listener',boot_case_id=x['listener_boot'],port=target,
                index=index,case_id=case,peer_port=55000,request_bytes=len(m.transport_payload(case,target,'wrong-port')[0]))
            return row
        before=receipt(1,x['before_case']);after=receipt(2,x['after_case'])
        for index,row in enumerate((before,after),1):
            (listener_dir/('receipt-%04d.json'%index)).write_bytes(l.encode(row))
        final=f.listener_final(listener);final.update(role='health-listener',boot_case_id=x['listener_boot'],
            capability_profile='pncs',port=target,accepted_count=2,receipt_count=2)
        (listener_dir/('final.json' if peer else 'q-final.json')).write_bytes(l.encode(final))
        with mock.patch.object(m,'read_when_closed',return_value=(before,b'')),mock.patch.object(l,'publish_fixture_finish',return_value='a'*64):
            if unhealthy:
                with self.assertRaisesRegex(ValueError,'wrong_port_before_health'):
                    owner.wrong_port_run({'selected':True},dict(proxy=f.P,wrong_port=f.Q,origin=f.O),peer=peer)
            elif bad_q_tier:
                with self.assertRaisesRegex(ValueError,'q_actual_tier'):
                    owner.wrong_port_run({'selected':True},dict(proxy=f.P,wrong_port=f.Q,origin=f.O),peer=peer)
            else:owner.wrong_port_run({'selected':True},dict(proxy=f.P,wrong_port=f.Q,origin=f.O),peer=peer)
        return owner,calls


if __name__=='__main__':unittest.main()
