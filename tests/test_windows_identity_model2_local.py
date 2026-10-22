"""Pure outer-owner fakes: no real process, profile, ACL, firewall or network."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('model2_outer_pure',ROOT/'.github/windows_identity_model2_local.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def ordinary():
    return dict(sid='S-1-5-21-1-2-3-1001',session_id=1,token_type=1,elevation_type=1,
        elevated=False,integrity_rid=8192,admin_attributes=None,appcontainer=False,
        appcontainer_sid=None,capability_count=0,ui_access=False)


class ClockAPI:
    def __init__(self):
        self.now=10000;self.created=[];self.closed=[];self.atomic_job_requested=False
    def qpc_frequency(self):return 1000
    def qpc(self):return self.now
    def current_token(self):return 41
    def identity(self,token):return ordinary()
    def compartment(self):return 1
    def close(self,handle):self.closed.append(handle)
    def windows_x64(self):return True
    def device_sha256(self):return '1'*64
    def private_directory(self,path,sid):
        self.created.append(path);path.mkdir() # A temporary test directory, never an ACL API.


def source_fixture():
    files={name:('# fixed inert fixture '+name+'\n').encode('ascii') for name in m.live.SOURCES}
    hashes={name:m.live.sha(raw) for name,raw in files.items()}
    return files,hashes,m.live.sha(m.live.encode(hashes))


def config_fixture():
    _,hashes,closure=source_fixture()
    names=('run','boot_case','positive_case','direct_case','admission_nonce','maintenance_nonce')
    value={name:format(index,'032x') for index,name in enumerate(names,1)}
    value.update(schema_version=1,stage='model2-first-owned-input',health_cases=[format(index,'032x') for index in (7,8,9)],
        capability_profile='agentic-pncs',frequency=1000,start_qpc=10000,root_deadline_qpc=130000,deadline_qpc=125000,
        source_hashes=hashes,source_sha256=closure,actor_sha256='3'*64,manifest_sha256='4'*64,
        device_sha256='1'*64,recovery_plan_sha256='6'*64)
    value['guard_job_name']='Local\\RuleProxy.LocalGuard.'+value['run']
    return value


def recovery_plan(closure):
    return dict(schema_version=1,scope=m.SCOPE,device_sha256='1'*64,source_sha256=closure,
        actor_sha256='3'*64,manifest_sha256='4'*64,residue_review_acknowledged=True,
        recovery_reference='pure-test recovery attestation; no snapshot fact asserted')


def controller_public(config,*,violation=False,inner_cleanup=True):
    value=m.live.blank()
    for key in ('source_sha256','actor_sha256','manifest_sha256'):value[key]=config[key]
    value['run_sha256']=m.live.sha(config['run'].encode('ascii'))
    for key in ('sources','artifacts','ordinary','live_probe','selected_held','declared_caps','firewall_exact',
                'positive','origin_healthy','direct_deny','same_selected'):
        value['checks'][key]=True
    value['checks']['cleanup']=inner_cleanup
    value['observations']={key:True for key in value['observations']}
    if violation:
        value['violations']['direct_connected']=True;value['status']='failed'
    # A controller never claims its external guard. Promotion happens in outer.
    return m.live.finalize_public(value)


def controller_report(config,launch,**options):
    public=controller_public(config,**options)
    journal=m.live.encode({'schema_version':1,'stage':'inert-journal-validator-fixture',
        'public_sha256':m.live.sha(m.live.encode(public))})
    return dict(schema_version=1,stage='model2-first-controller',run=config['run'],
        controller_pid=launch['child_pid'],frequency=config['frequency'],start_qpc=config['start_qpc'],
        deadline_qpc=config['deadline_qpc'],source_sha256=config['source_sha256'],
        actor_sha256=config['actor_sha256'],manifest_sha256=config['manifest_sha256'],
        ownership_journal_sha256=m.live.sha(journal),ownership_journal_bytes=len(journal),
        public=public)


class LocalModel2Tests(unittest.TestCase):
    def exercise(self,*,setup_ticks=0,launch_changes=None,cleanup_changes=None,report_mutation=None,
                 violation=False,inner_cleanup=True,late=False,missing=False,changed_plan=False,interrupt=False,journal_mode=None):
        api=ClockAPI();calls={};files,hashes,closure=source_fixture()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);actor=root/m.live.ACTOR;actor.write_bytes(b'MZ inert fixture')
            manifest=root/m.live.MANIFEST;manifest.write_bytes(b'{}\n')
            bundle=root/'fixture.zip';bundle.write_bytes(b'inert bundle')
            runtime=root/'fixture-runtime';runtime.mkdir()
            for name in m.probe.MEMBERS:(runtime/name).write_bytes(b'inert member')
            plan_path=root/'plan.json';plan_path.write_bytes(m.live.encode(recovery_plan(closure)))
            python_root=root/'python-root';python_root.mkdir();python=python_root/'python.exe';python.write_bytes(b'not executable')
            input_count=0
            def inputs(*args,**kwargs):
                nonlocal input_count
                input_count+=1
                if input_count==2:
                    api.now+=setup_ticks
                    if changed_plan:plan_path.write_bytes(m.live.encode(dict(recovery_plan(closure),recovery_reference='changed during setup')))
                return files,hashes,closure,actor,manifest,bundle,runtime,root
            def launch(unused_api,command,work,parent,expected,**kwargs):
                calls.update(command=command,kwargs=kwargs,parent=parent,expected=expected)
                api.atomic_job_requested=True
                stage=work.parent;config=m.live.decode((stage/'model2-config.json').read_bytes());calls['config']=config
                calls['source_copy_bound']=all((stage/name).read_bytes()==raw for name,raw in files.items())
                calls['plan_copy_bound']=(stage/'recovery-plan.json').read_bytes()==plan_path.read_bytes()
                record=dict(started=True,resumed=True,timed_out=False,native_identity_verified_before_resume=True,
                    child_pid=123,exit_code=0,cleanup=dict(job_closed=True,job_empty=True,handles_closed=True,
                    process_exit_confirmed=True,close_uncertain=False,errors=[]))
                if launch_changes:record.update(launch_changes)
                if cleanup_changes:record['cleanup'].update(cleanup_changes)
                report=controller_report(config,record,violation=violation,inner_cleanup=inner_cleanup)
                journal=m.live.encode({'schema_version':1,'stage':'inert-journal-validator-fixture',
                    'public_sha256':m.live.sha(m.live.encode(report['public']))})
                if journal_mode=='wrong_hash':report['ownership_journal_sha256']='e'*64
                if journal_mode=='wrong_length':report['ownership_journal_bytes']+=1
                if journal_mode=='oversize':journal=b' '*(m.live.MAX_PRIVATE+1)
                if journal_mode=='malformed':
                    journal=b'not json';report['ownership_journal_sha256']=m.live.sha(journal);report['ownership_journal_bytes']=len(journal)
                if journal_mode=='wrong_public_sha':
                    changed=m.live.decode(journal);changed['public_sha256']='e'*64;journal=m.live.encode(changed)
                    report['ownership_journal_sha256']=m.live.sha(journal);report['ownership_journal_bytes']=len(journal)
                if journal_mode!='missing':(stage/'model2-ownership-private.json').write_bytes(journal)
                if report_mutation:report_mutation(report)
                if not missing:(stage/'model2-controller-report.json').write_bytes(m.live.encode(report))
                if late:api.now=config['root_deadline_qpc']+1
                if interrupt:raise KeyboardInterrupt()
                return record
            ids=iter(format(i,'032x') for i in range(1,10))
            # Journal internals have their own independent suite. This fake keeps
            # the real outer byte/length/hash/decode checks and held PID binding.
            journal_validator=mock.Mock(return_value=None)
            controller=types.SimpleNamespace(validate_ownership_journal=journal_validator)
            with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
                 mock.patch.object(m,'inputs',side_effect=inputs), \
                 mock.patch.object(m.live,'source_snapshot',return_value=(files,hashes,closure)), \
                 mock.patch.object(m.live,'verify_actor',side_effect=lambda actor,*args,**kwargs:actor), \
                 mock.patch.object(m.probe,'verify_artifacts',return_value=runtime/'wxc-exec.exe'), \
                 mock.patch.object(m,'load',return_value=controller), \
                 mock.patch.object(m.launcher,'launch_owned',side_effect=launch), \
                 mock.patch.object(m,'sys',types.SimpleNamespace(executable=str(python),base_prefix=str(python_root))):
                result=m.run_local(actor,manifest,'3'*64,'4'*64,bundle,runtime,root,plan_path,
                    approved=True,api=api,root=root,ids=lambda size:next(ids))
            calls['journal_validation_calls']=journal_validator.call_args_list
            calls['created']=list(api.created)
            calls['retained_count']=len(list(root.glob('local-model2-*')))
            return result,api,calls

    def test_default_cli_only_calls_preflight(self):
        value=m.blank('preflight');value['failure']='inputs'
        with mock.patch.object(m,'preflight',return_value=value) as pre, \
             mock.patch.object(m,'run_local') as run,mock.patch.object(m.sys,'stdout'):
            self.assertEqual(m.main([]),1)
        pre.assert_called_once();run.assert_not_called()

    def test_diagnostic_cli_is_explicit_and_never_implies_runtime(self):
        value=m.blank('preflight','profiles-off-diagnostic');value['failure']='inputs'
        with mock.patch.object(m,'preflight',return_value=value) as pre, \
             mock.patch.object(m,'run_local') as run,mock.patch.object(m.sys,'stdout'):
            self.assertEqual(m.main(['--profiles-off-diagnostic']),1)
        self.assertEqual(pre.call_args.kwargs,{'execution_mode':'profiles-off-diagnostic'})
        run.assert_not_called()

    def test_diagnostic_plan_config_and_controller_mode_cannot_cross_bind(self):
        config=config_fixture();_,_,closure=source_fixture();p=recovery_plan(closure)
        kw=dict(device='1'*64,source=closure,actor='3'*64,manifest='4'*64)
        with self.assertRaises(ValueError):m.plan(p,**kw,execution_mode='profiles-off-diagnostic')
        p.update(scope=m.DIAGNOSTIC_SCOPE,execution_mode='profiles-off-diagnostic')
        self.assertIs(m.plan(p,**kw,execution_mode='profiles-off-diagnostic'),p)
        with self.assertRaises(ValueError):m.plan(p,**kw)
        config['execution_mode']='profiles-off-diagnostic'
        self.assertIs(m.validate_config(config),config)
        changed=copy.deepcopy(config);changed['execution_mode']='strict'
        with self.assertRaises(ValueError):m.validate_config(changed)
        report=controller_report(config,{'child_pid':123})
        with self.assertRaises(ValueError):m.bind_controller(report,config,{'child_pid':123})

    def test_diagnostic_preflight_retains_requested_mode_without_runtime_claims(self):
        api=ClockAPI();_,_,closure=source_fixture();p=recovery_plan(closure)
        p.update(scope=m.DIAGNOSTIC_SCOPE,execution_mode='profiles-off-diagnostic')
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
             mock.patch.object(m,'inputs',return_value=({}, {},closure,None,None,None,None,None)), \
             mock.patch.object(m.local,'bounded',return_value=m.live.encode(p)), \
             mock.patch.object(m.launcher,'launch_owned') as launch:
            value=m.preflight(*([None,None,'3'*64,'4'*64]+[None]*4),api=api,execution_mode='profiles-off-diagnostic')
        self.assertEqual(value['status'],'ready');launch.assert_not_called()
        self.assertEqual(value['result']['execution_mode'],'profiles-off-diagnostic')
        self.assertTrue(value['result']['diagnostic']['requested'])
        self.assertFalse(value['result']['diagnostic_completed'])
        self.assertFalse(value['result']['checks']['firewall_exact'])
        self.assertFalse(value['result']['first_chain_verified'])

    def test_helper_plan_config_need_separate_scope_explicit_mode_and_pinned_image(self):
        _,_,closure=source_fixture()
        admission=dict(profile='actor-plus-system-conhost-v1',conhost_sha256='7'*64)
        p=recovery_plan(closure);p.update(scope=m.HELPER_DIAGNOSTIC_SCOPE,execution_mode='profiles-off-diagnostic',selected_admission=admission)
        kw=dict(device='1'*64,source=closure,actor='3'*64,manifest='4'*64)
        self.assertIs(m.plan(p,**kw,execution_mode='profiles-off-diagnostic',selected_admission=admission),p)
        with self.assertRaises(ValueError):m.plan(p,**kw,execution_mode='profiles-off-diagnostic')
        with self.assertRaises(ValueError):m.plan(p,**kw,selected_admission=admission)
        with self.assertRaises(ValueError):m.plan(p,**kw,execution_mode='profiles-off-diagnostic',selected_admission=dict(admission,conhost_sha256='8'*64))
        c=config_fixture();c.update(execution_mode='profiles-off-diagnostic',selected_admission=admission)
        self.assertIs(m.validate_config(c),c)
        for bad in (dict(admission,profile='observed'),dict(admission,conhost_sha256=None),dict(admission,extra=True)):
            changed=copy.deepcopy(c);changed['selected_admission']=bad
            with self.subTest(admission=bad),self.assertRaises(ValueError):m.validate_config(changed)

    def test_helper_preflight_is_read_only_and_rechecks_system_image_against_plan(self):
        api=ClockAPI();_,_,closure=source_fixture()
        admission=dict(profile='actor-plus-system-conhost-v1',conhost_sha256='7'*64)
        p=recovery_plan(closure);p.update(scope=m.HELPER_DIAGNOSTIC_SCOPE,execution_mode='profiles-off-diagnostic',selected_admission=admission)
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
             mock.patch.object(m,'inputs',return_value=({}, {},closure,None,None,None,None,None)), \
             mock.patch.object(m.local,'bounded',return_value=m.live.encode(p)), \
             mock.patch.object(m.live,'system_conhost_record',return_value=admission) as image, \
             mock.patch.object(m.launcher,'launch_owned') as launch:
            value=m.preflight(*([None,None,'3'*64,'4'*64]+[None]*4),api=api,execution_mode='profiles-off-diagnostic',allow_held_system_conhost=True)
            self.assertEqual(value['status'],'ready');image.assert_called_once_with(api);launch.assert_not_called()
            image.return_value=dict(admission,conhost_sha256='8'*64)
            changed=m.preflight(*([None,None,'3'*64,'4'*64]+[None]*4),api=api,execution_mode='profiles-off-diagnostic',allow_held_system_conhost=True)
            self.assertEqual(changed['failure'],'plan');self.assertEqual(api.created,[])

    def test_opt_in_missing_never_constructs_native_api(self):
        with mock.patch.object(m.local,'LocalNativeAPI') as native:
            value=m.run_local(*([None]*8))
        native.assert_not_called();self.assertEqual(value['failure'],'platform')
        self.assertFalse(value['result']['first_chain_verified']);self.assertFalse(value['result']['local_c_qualified'])

    def test_preflight_reads_only_and_has_no_runtime_observations_or_cleanup(self):
        api=ClockAPI();_,_,closure=source_fixture()
        with mock.patch.object(m,'os',types.SimpleNamespace(name='nt')), \
             mock.patch.object(m,'inputs',return_value=({}, {},closure,None,None,None,None,None)), \
             mock.patch.object(m.local,'bounded',return_value=m.live.encode(recovery_plan(closure))), \
             mock.patch.object(m.launcher,'launch_owned') as launch:
            value=m.preflight(*([None,None,'3'*64,'4'*64]+[None]*4),api=api)
        self.assertEqual(value['status'],'ready');launch.assert_not_called();self.assertEqual(api.created,[])
        self.assertFalse(any(value['cleanup'].values()));r=value['result']
        self.assertIsNone(r['run_sha256']);self.assertFalse(r['checks']['ordinary'])
        self.assertFalse(any(r['observations'].values()));self.assertFalse(any(r['violations'].values()))
        self.assertFalse(r['first_chain_verified']);self.assertFalse(r['local_c_qualified'])
        contaminated=copy.deepcopy(value);contaminated['result']['observations']['selected_network_attempted']=True
        with self.assertRaises(ValueError):m.validate(contaminated)

    def test_config_requires_original_120_seconds_worker_reserve_and_nine_unique_nonces(self):
        value=config_fixture();self.assertIs(m.validate_config(value),value)
        self.assertEqual(value['root_deadline_qpc']-value['start_qpc'],120*value['frequency'])
        self.assertEqual(value['deadline_qpc'],value['root_deadline_qpc']-5*value['frequency'])
        mutations=[lambda c:c.update(extra=True),lambda c:c.update(schema_version=True),
            lambda c:c.update(capability_profile='agentic-only'),lambda c:c.update(root_deadline_qpc=130001),
            lambda c:c.update(deadline_qpc=130000),lambda c:c.update(start_qpc=11000),
            lambda c:c.update(guard_job_name='Local\\Other'),lambda c:c.update(boot_case=c['run']),
            lambda c:c['health_cases'].__setitem__(2,c['maintenance_nonce']),lambda c:c.update(health_cases=['a'*32]*3),
            lambda c:c.update(health_cases=c['health_cases'][:2]),lambda c:c['source_hashes'].update(extra='a'*64),
            lambda c:c.update(source_sha256='e'*64)]
        for mutate in mutations:
            changed=copy.deepcopy(value);mutate(changed)
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):m.validate_config(changed)

    def test_controller_report_binds_held_pid_run_source_artifacts_frequency_and_deadline(self):
        config=config_fixture();launch={'child_pid':123};report=controller_report(config,launch)
        self.assertIs(m.bind_controller(report,config,launch),report['public'])
        for key,bad in (('controller_pid',999),('run','f'*32),('frequency',1001),('start_qpc',10001),
                        ('deadline_qpc',130000),('source_sha256','d'*64),('actor_sha256','d'*64),('manifest_sha256','d'*64)):
            changed=copy.deepcopy(report);changed[key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):m.bind_controller(changed,config,launch)
        for mutate in (lambda r:r.update(extra=True),lambda r:r['public'].update(run_sha256='d'*64),
                       lambda r:r['public'].update(actor_sha256='d'*64),lambda r:r['public']['checks'].update(guard_held=True)):
            changed=copy.deepcopy(report);mutate(changed)
            with self.assertRaises(ValueError):m.bind_controller(changed,config,launch)
        for key,bad in (('ownership_journal_sha256',None),('ownership_journal_sha256','private-path'),
                        ('ownership_journal_bytes',True),('ownership_journal_bytes',0),
                        ('ownership_journal_bytes',m.live.MAX_PRIVATE+1)):
            changed=copy.deepcopy(report);changed[key]=bad
            with self.subTest(journal_key=key,bad=bad),self.assertRaises(ValueError):m.bind_controller(changed,config,launch)

    def test_controller_cannot_claim_future_wrong_peer_port_death_or_full_qualification(self):
        config=config_fixture();launch={'child_pid':123}
        for key in ('wrong_peer','wrong_port','proxy_death'):
            report=controller_report(config,launch);report['public']['checks'][key]=True
            # guard remains false, so this is still a self-consistent live schema.
            m.live.validate_public(report['public'])
            with self.subTest(key=key),self.assertRaises(ValueError):m.bind_controller(report,config,launch)
        report=controller_report(config,launch);report['public']['local_c_qualified']=True
        with self.assertRaises(ValueError):m.bind_controller(report,config,launch)

    def test_bound_early_failure_may_omit_unverified_commitments_but_never_substitute_them(self):
        config=config_fixture();launch={'child_pid':123};report=controller_report(config,launch)
        report['public']=m.live.blank();report['public']['failure']='inputs'
        self.assertIs(m.bind_controller(report,config,launch),report['public'])
        for key in ('source_sha256','actor_sha256','manifest_sha256','run_sha256'):
            changed=copy.deepcopy(report);changed['public'][key]='e'*64
            with self.subTest(key=key),self.assertRaises(ValueError):m.bind_controller(changed,config,launch)

    def test_preflight_cannot_carry_any_nested_runtime_check(self):
        _,_,closure=source_fixture();value=m.blank('preflight')
        value.update(status='ready',source_sha256=closure,actor_sha256='3'*64,manifest_sha256='4'*64,
            recovery_plan_sha256='6'*64,device_bound=True)
        value['checks']={key:True for key in m.CHECKS}
        value['result'].update(source_sha256=closure,actor_sha256='3'*64,manifest_sha256='4'*64,status='ready')
        value['result']['checks'].update(sources=True,artifacts=True)
        m.validate(value)
        for key in value['result']['checks']:
            if key in ('sources','artifacts'):continue
            changed=copy.deepcopy(value);changed['result']['status']='inconclusive';changed['result']['checks'][key]=True
            if key=='positive':changed['result']['observations']={name:True for name in changed['result']['observations']}
            changed['result']=m.live.finalize_public(changed['result'])
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate(changed)

    def test_positive_requires_normal_outer_exit_and_cleanup_and_keeps_original_deadlines(self):
        value,api,calls=self.exercise(setup_ticks=7000)
        self.assertEqual(value['status'],'observed');self.assertTrue(value['result']['first_chain_verified'])
        self.assertFalse(value['result']['local_c_qualified']);self.assertFalse(value['result']['product_acceptance'])
        config=calls['config'];self.assertEqual((config['start_qpc'],config['root_deadline_qpc'],config['deadline_qpc']),(10000,130000,125000))
        self.assertEqual(calls['kwargs']['work_cutoff'],127000);self.assertEqual(calls['kwargs']['cleanup_cutoff'],130000)
        nonces=[config[k] for k in ('run','boot_case','positive_case','direct_case','admission_nonce','maintenance_nonce')]+config['health_cases']
        self.assertEqual(len(set(nonces)),9);self.assertTrue(calls['source_copy_bound']);self.assertTrue(calls['plan_copy_bound'])
        self.assertTrue(all(value['cleanup'][k] for k in m.CLEANUP if k!='recovery_required'))
        self.assertFalse(value['cleanup']['recovery_required']);self.assertEqual(calls['retained_count'],1)
        self.assertEqual(calls['parent'],calls['expected']);self.assertIn('--owned-worker',calls['command'])
        self.assertEqual(len(calls['journal_validation_calls']),1)
        self.assertEqual(calls['journal_validation_calls'][0].kwargs,{'controller_pid':123})

    def test_setup_time_consumes_budget_and_cannot_renew_deadline(self):
        value,_,calls=self.exercise(setup_ticks=90000)
        self.assertEqual(value['failure'],'deadline');self.assertEqual(value['status'],'inconclusive')
        self.assertNotIn('command',calls);self.assertEqual(calls['created'],[])
        self.assertFalse(value['cleanup']['recovery_required'])

    def test_timeout_nonzero_or_launch_error_never_promote_partial_positive(self):
        for changes in ({'timed_out':True},{'exit_code':1},{'started':False},{'resumed':False},{'error':'fake-owner-error'}):
            value,_,_=self.exercise(launch_changes=changes)
            with self.subTest(changes=changes):
                self.assertEqual(value['status'],'inconclusive');self.assertEqual(value['failure'],'worker')
                self.assertFalse(value['result']['first_chain_verified']);self.assertFalse(value['result']['local_c_qualified'])
                self.assertTrue(all(value['result']['observations'].values()))
                self.assertEqual(value['result']['failure'],'worker')

    def test_outer_or_inner_cleanup_unknown_blocks_positive_and_retains_recovery(self):
        for options in ({'cleanup_changes':{'job_empty':False}}, {'cleanup_changes':{'close_uncertain':True}}, {'inner_cleanup':False}):
            value,_,_=self.exercise(**options)
            with self.subTest(options=options):
                self.assertEqual(value['failure'],'cleanup');self.assertFalse(value['result']['first_chain_verified'])
                self.assertTrue(value['cleanup']['recovery_required']);self.assertTrue(value['cleanup']['tree_retained'])
                self.assertTrue(all(value['result']['observations'].values()))

    def test_violations_remain_failed_after_timeout_and_late_deadline(self):
        for options in ({'launch_changes':{'timed_out':True}}, {'launch_changes':{'exit_code':1}}, {'late':True}):
            value,_,_=self.exercise(violation=True,**options)
            with self.subTest(options=options):
                self.assertEqual(value['status'],'failed');self.assertTrue(value['result']['violations']['direct_connected'])
                self.assertTrue(all(value['result']['observations'].values()));self.assertFalse(value['result']['first_chain_verified'])

    def test_late_deadline_demotes_observed_and_preserves_native_observations(self):
        value,_,_=self.exercise(late=True)
        self.assertEqual(value['status'],'inconclusive');self.assertEqual(value['failure'],'deadline')
        self.assertEqual(value['result']['status'],'inconclusive');self.assertEqual(value['result']['failure'],'deadline')
        self.assertFalse(value['result']['first_chain_verified']);self.assertFalse(value['result']['local_c_qualified'])
        self.assertTrue(all(value['result']['observations'].values()))

    def test_unknown_exit_missing_report_or_bad_binding_retains_tree_without_promotion(self):
        for options in ({'cleanup_changes':{'process_exit_confirmed':False}}, {'missing':True},
                        {'report_mutation':lambda r:r.update(controller_pid=999)}):
            value,_,calls=self.exercise(**options)
            with self.subTest(options=options):
                self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['result']['first_chain_verified'])
                self.assertTrue(value['cleanup']['recovery_required']);self.assertEqual(calls['retained_count'],1)

    def test_changed_plan_stops_before_any_owned_worker(self):
        value,_,calls=self.exercise(changed_plan=True)
        self.assertEqual(value['failure'],'staging');self.assertNotIn('command',calls)
        self.assertTrue(value['cleanup']['tree_retained'])

    def test_interrupt_after_owned_launch_is_inconclusive_and_requires_recovery(self):
        value,_,_=self.exercise(interrupt=True)
        self.assertEqual(value['status'],'inconclusive');self.assertEqual(value['failure'],'worker')
        self.assertTrue(value['cleanup']['recovery_required'])

    def test_private_journal_wrong_hash_length_oversize_or_unknown_file_blocks_promotion_and_keeps_facts(self):
        for mode in ('wrong_hash','wrong_length','oversize','missing','malformed','wrong_public_sha'):
            for violation in (False,True):
                value,_,calls=self.exercise(journal_mode=mode,violation=violation)
                with self.subTest(mode=mode,violation=violation):
                    self.assertEqual(value['failure'],'report')
                    self.assertEqual(value['status'],'failed' if violation else 'inconclusive')
                    self.assertTrue(all(value['result']['observations'].values()))
                    self.assertEqual(value['result']['violations']['direct_connected'],violation)
                    self.assertFalse(value['result']['first_chain_verified']);self.assertFalse(value['result']['local_c_qualified'])
                    self.assertTrue(value['cleanup']['tree_retained']);self.assertTrue(value['cleanup']['recovery_required'])
                    self.assertEqual(len(calls['journal_validation_calls']),1 if mode=='wrong_public_sha' else 0)


if __name__=='__main__':unittest.main()
