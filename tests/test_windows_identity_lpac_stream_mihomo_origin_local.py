"""Inert outer guard contracts and physical worker binding, never Windows APIs."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace as NS

ROOT=Path(__file__).resolve().parents[1]
def load(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
m=load('a2_guard_test',ROOT/'.github/windows_identity_lpac_stream_mihomo_origin_local.py')
f=load('a2_guard_inert_owner_fixture',Path(__file__).with_name('test_windows_identity_lpac_stream_mihomo_origin.py'))

class GuardTests(unittest.TestCase):
    def prepared(self):
        fixture=f.ComposedOwnerTests('test_real_new_coordinator_composes_5_roles_barrier_rawTCP_and_explicit_core_stop');self.addCleanup(fixture.doCleanups)
        o,api,j,observation=fixture.owner();launch=dict(started=True,resumed=True,native_identity_verified_before_resume=True,
            child_pid=4711,child_identity=m.launcher.safe_identity(f.prior.b.PARENT,f.prior.b.PARENT),cleanup={'process_exit_confirmed':True})
        raw=m.encode(launch);(o.root/'outer-launch-report.json').write_bytes(raw)
        report=dict(schema_version=1,stage='lpac-stream-mihomo-origin-worker',config=o.c,worker_pid=4711,worker_identity=f.prior.b.PARENT,result=j)
        result=m.blank('runtime');result['outer_launch_report_sha256']=m.sha(raw);result['checks'].update(guard=True,worker_exit=True,outer_cleanup=True)
        return o,report,launch,result
    def test_public_fixed_boundaries_and_default_inert_result(self):
        value=m.blank('preflight');m.validate_public(value)
        self.assertIs(type(m.core.ACTUAL_READY),bool);self.assertFalse(value['observation_complete']);self.assertFalse(any(value[k] for k in m.core.FALSE_CLAIMS))
        for key in m.core.FALSE_CLAIMS:
            wrong=copy.deepcopy(value);wrong[key]=True
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_public(wrong)
    def test_false_ready_explicit_run_never_constructs_native_API(self):
        with patch.object(m.core,'ACTUAL_READY',False),patch.object(m.local,'LocalNativeAPI',side_effect=AssertionError('native API forbidden')):
            value=m.run_local(*(None,)*13,approved=True)
        self.assertEqual(value['status'],'inconclusive');self.assertFalse(value['tree_retained']);self.assertFalse(value['bundle_retained']);self.assertFalse(value['recovery_required'])
    def test_hidden_worker_false_ready_checks_sources_before_API(self):
        o,_,_,_=self.prepared();path=o.root/'worker-config.json';path.write_bytes(m.encode(o.c))
        with patch.object(m,'ROOT',o.root),patch.object(m,'snapshot',return_value=({},o.c['source_hashes'],o.c['source_sha256'])),patch.object(m.core,'ACTUAL_READY',False),patch.object(m.core,'API',side_effect=AssertionError('native API forbidden')):
            with self.assertRaisesRegex(ValueError,'stream_worker_source_ready'):m.worker(path)
    def test_source_closure_is_actual_unique_map_with_native02_and_unchanged_selected(self):
        files,hashes,closure=m.snapshot();self.assertEqual(set(files),set(m.SOURCES));self.assertEqual(len(files),len(set(m.SOURCES)));self.assertEqual(closure,m.sha(m.encode(hashes)))
        self.assertIn('.github/native/windows_identity_lpac_stream_mihomo_http.hpp',files)
        self.assertIn('.github/native/windows_identity_lpac_stream_mihomo_network_actor.cpp',files)
        for key,path in m.core.NATIVE_SOURCES.items():self.assertEqual(hashes[path],m.sha(files[path]))
    def test_physical_outer_worker_and_complete_new_observation_bind(self):
        o,report,launch,result=self.prepared();m.bind_report(report,o.c,f.prior.b.PARENT,launch,result,root=o.root)
        self.assertTrue(result['checks']['worker_bound']);self.assertTrue(result['checks']['mechanism']);self.assertFalse(result['recovery_required'])
        m.validate_observation(result['observation']);self.assertTrue(result['observation']['finite_core_integration_observed']);self.assertFalse(result['observation']['mihomo_listener_exclusivity_verified'])
    def test_modified_outer_ledger_or_core_stop_cannot_bind_complete(self):
        o,report,launch,result=self.prepared();(o.root/'outer-launch-report.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError,'stream_outer_physical'):m.bind_report(report,o.c,f.prior.b.PARENT,launch,result,root=o.root)
        (o.root/'outer-launch-report.json').write_bytes(m.encode(launch));bad=copy.deepcopy(report);bad['result']['core_stop']['observation']['raw_return']=0
        with self.assertRaises(ValueError):m.bind_report(bad,o.c,f.prior.b.PARENT,launch,result,root=o.root)
    def test_public_positive_requires_controlled_stop_and_kernel_binding(self):
        o,report,launch,result=self.prepared();m.bind_report(report,o.c,f.prior.b.PARENT,launch,result,root=o.root)
        for key in ('core_controlled_stop_confirmed','kernel_tcp_snapshot_observed','finite_core_integration_observed','core_config_check_completed','port_leases_closed','core_stdio_closed'):
            bad=copy.deepcopy(result['observation']);bad[key]=False
            with self.subTest(key=key),self.assertRaises(ValueError):m.validate_observation(bad)

    def run_guard(self,fault=None):
        td=tempfile.TemporaryDirectory();self.addCleanup(td.cleanup);root=Path(td.name).resolve();(root/'private').mkdir();H='1'*64
        inputs=[root/name for name in (m.core.ACTOR,m.core.MANIFEST,m.core.NETWORK_ACTOR,m.core.NETWORK_MANIFEST)]
        for path,raw in zip(inputs,(b'x'*512,b'{}',b'b'*512,b'{"compile":true}')):path.write_bytes(raw)
        mihomo=root/'mihomo.exe';mihomo.write_bytes(b'inert-not-a-release-binary');request=root/'request.bin';response=root/'response.bin'
        for path,is_response in ((request,False),(response,True)):path.write_bytes(f.independent_message(is_response)[0])
        challenges={name:dict(bytes=len(path.read_bytes()),sha256=m.sha(path.read_bytes())) for name,path in (('request',request),('response',response))}
        files=dict.fromkeys(m.SOURCES,b'# inert source-copy transport fixture\n');hashes={k:m.sha(v) for k,v in files.items()};source=m.sha(m.encode(hashes));digests=[m.sha(p.read_bytes()) for p in inputs]
        declared=dict(origin_port=f.O,proxy_port=f.M);configuration=m.encode(m.core.mihomo_configuration(declared))
        plan=dict(schema_version=1,scope=m.SCOPE,profile=m.core.PROFILE,run='1'*32,case=f.CASE,device_sha256=H,source_sha256=source,
            actor_sha256=digests[0],manifest_sha256=digests[1],network_actor_sha256=digests[2],network_manifest_sha256=digests[3],challenges=challenges,ports=declared,
            mihomo_sha256=m.core.MIHOMO_SHA256,mihomo_bytes=m.core.MIHOMO_BYTES,mihomo_bundle=m.core.bundle_name('1'*32),mihomo_config_sha256=m.sha(configuration),
            recovery_reference='test-only original deadline and two exact fresh directories',**dict.fromkeys(m.core.ACKS,True))
        path=root/'plan.json';path.write_bytes(m.encode(plan));calls=[];made=[];cap={}
        class GuardAPI:
            atomic_job_requested=True
            def windows_x64(self):return True
            def qpc_frequency(self):return f.prior.F
            def qpc(self):return f.prior.T
            def device_sha256(self):return H
            def private_directory(self,path,sid):
                path.mkdir();made.append(path)
                if fault=='partial-bundle' and path.name.startswith('mihomo-a2-private-bundle-'):raise OSError('created but readback unknown')
        api=GuardAPI();pre=m.blank('preflight');pre.update(status='ready',source_sha256=source,actor_sha256=digests[0],manifest_sha256=digests[1],network_actor_sha256=digests[2],network_manifest_sha256=digests[3],
            mihomo_sha256=m.core.MIHOMO_SHA256,mihomo_config_sha256=m.sha(configuration),ports_sha256=m.sha(m.encode(declared)),recovery_plan_sha256=m.sha(path.read_bytes()),challenges=challenges)
        pre['checks'].update(dict.fromkeys(m.CHECKS[:4],True))
        def launch(native,argv,cwd,parent,child,**kwargs):
            calls.append(argv);stage=cwd.parent;c=m.decode((stage/'worker-config.json').read_bytes());m.core.config_validate(c)
            self.assertEqual((c['start_qpc'],c['root_deadline_qpc'],c['deadline_qpc'],kwargs['cleanup_cutoff']),(f.prior.T,f.prior.T+120*f.prior.F,f.prior.D,f.prior.T+120*f.prior.F))
            self.assertTrue((stage.parent/c['mihomo_bundle']/'mihomo.exe').is_file());self.assertFalse((stage/'inputs/mihomo.exe').exists())
            tool=stage/'win/System32/icacls.exe';tool.parent.mkdir(parents=True);tool.write_bytes(b'tool');fake=f.ComposedAPI(stage)
            owner=m.core.Owner(stage,c,parent,fake,m.launcher.QpcBudget(fake,c['deadline_qpc'],c['frequency']));fake.owner=owner;private=owner.execute()
            m.core.validate_result(private,c,parent=parent,root=stage);report=dict(schema_version=1,stage='lpac-stream-mihomo-origin-worker',config=c,worker_pid=77,worker_identity=parent,result=private)
            (stage/'worker-report.json').write_bytes(m.encode(report));cap.update(stage=stage,c=c,report=report)
            return dict(started=True,resumed=True,child_pid=77,child_identity=m.launcher.safe_identity(parent,parent),native_identity_verified_before_resume=True,
                timed_out=False,exit_code=0,cleanup=dict(process_exit_confirmed=True,job_empty_confirmed=True,handles_closed=True))
        with patch.object(m.core,'ACTUAL_READY',True),patch.object(m,'os',NS(name='nt')),patch.object(m.local,'LocalNativeAPI',return_value=api),patch.object(m.local,'ordinary',return_value=f.prior.b.PARENT),\
                patch.object(m,'snapshot',return_value=(files,hashes,source)),patch.object(m,'preflight',return_value=pre),patch.object(m.core,'verify_artifacts'),\
                patch.object(m.core,'verify_mihomo',side_effect=lambda path,digest:Path(path)),patch.object(m.local.guest,'cleanup_verified',return_value=True),\
                patch.object(m.launcher,'launch_owned',side_effect=launch),patch.object(m.sys,'executable',str(root/'python.exe')),patch.object(m.sys,'base_prefix',str(root)):
            (root/'python.exe').write_bytes(b'inert');value=m.run_local(inputs[0],inputs[1],digests[0],digests[1],inputs[2],inputs[3],digests[2],digests[3],mihomo,request,response,root/'private',path,approved=True,root=root)
        return value,calls,made,cap

    def test_full_guard_stages_private_large_role_separately_and_retains_partial_bundle(self):
        value,calls,made,cap=self.run_guard();self.assertEqual(value['status'],'observed');self.assertEqual(len(calls),1);self.assertEqual(len(made),2)
        self.assertFalse(value['recovery_required']);self.assertTrue(value['bundle_retained']);self.assertTrue(value['observation']['core_controlled_stop_confirmed'])
        value,calls,made,cap=self.run_guard('partial-bundle');self.assertEqual(value['status'],'inconclusive');self.assertFalse(calls);self.assertEqual(len(made),2)
        self.assertTrue(value['tree_retained']);self.assertTrue(value['bundle_retained']);self.assertTrue(value['recovery_required'])

if __name__=='__main__':unittest.main()
