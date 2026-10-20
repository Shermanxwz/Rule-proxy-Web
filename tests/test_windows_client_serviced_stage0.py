import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('serviced_host_test', ROOT / '.github/windows_identity_serviced_stage0.py')
host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)


class BudgetTests(unittest.TestCase):
    def calculate(self, free, allocated, size=None, **kwargs):
        disk = Mock(); disk.lstat.return_value = types.SimpleNamespace(st_mode=0o100600,
            st_size=allocated if size is None else size, st_blocks=allocated//512)
        with patch.object(host.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=free)):
            return host.service_capacity(Path('/owned'), disk, **kwargs)

    def test_observed_reclaimed_stock_can_admit_bounded_media(self):
        result = self.calculate(11302961152+7092807680,16159727616,
            size=16185294848, temporary=host.UPDATE_BYTES+host.UPDATE_ISO_CAP, final_addition=host.UPDATE_ISO_CAP)
        self.assertGreaterEqual(result['projected_floor_bytes'], 5*host.GIB)

    def test_unreclaimed_stock_cannot_admit(self):
        with self.assertRaises(RuntimeError):
            self.calculate(11302961152,16159727616,temporary=host.UPDATE_BYTES+host.UPDATE_ISO_CAP,final_addition=host.UPDATE_ISO_CAP)

    def test_full_remaining_allocation_not_just_logical_gap(self):
        result = self.calculate(30*host.GIB, 10*host.GIB, size=15*host.GIB)
        self.assertEqual(result['remaining_qcow_allocation_bound'],12*host.GIB)

    def test_exact_projected_floor_allowed_below_rejected(self):
        for delta in (0,-1):
            if delta == 0:
                self.calculate(17*host.GIB+delta,10*host.GIB)
            else:
                with self.assertRaises(RuntimeError): self.calculate(17*host.GIB+delta,10*host.GIB)

    def test_hard_cap_never_unlimited(self):
        self.assertEqual(host.DISK_FILE_CAP,22*host.GIB)
        self.assertEqual(host.STOP_FREE,4*host.GIB)
        self.assertEqual(host.SERVICE_FLOOR,5*host.GIB)
        self.assertIn('--fsize=23622320128:23622320128',host.limited_command(['qemu'],host.DISK_FILE_CAP))
        self.assertIs(type(host.EXECUTION_ENABLED), bool)

    def test_disabled_runtime_flag_refuses_before_inputs_or_mutation(self):
        with patch.object(host, 'EXECUTION_ENABLED', False):
            with self.assertRaises(PermissionError): host.host(None)

    def test_oversize_or_nonregular_disk_rejected(self):
        with self.assertRaises(ValueError): self.calculate(40*host.GIB,host.DISK_FILE_CAP)


@unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
class OwnershipTests(unittest.TestCase):
    def test_owned_unlink_checks_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); p=root/'official.iso';p.write_bytes(b'old')
            before=host.owned_regular(p,root)
            p.write_bytes(b'longer')
            with self.assertRaises(ValueError): host.unlink_same(p,root,before)
            self.assertTrue(p.exists())

    def test_symlink_and_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); source=root/'source'; source.write_bytes(b'x'); p=root/'official.iso'
            p.symlink_to(source)
            with self.assertRaises(ValueError):host.owned_regular(p,root)
            p.unlink();os.link(source,p)
            with self.assertRaises(ValueError):host.owned_regular(p,root)

    def test_wrong_target_and_world_writable_root_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'not_owned';p.write_bytes(b'x')
            with self.assertRaises(ValueError):host.owned_regular(p,root)
            p=root/'official.iso';p.write_bytes(b'x');root.chmod(0o777)
            with self.assertRaises(ValueError):host.owned_regular(p,root)
            root.chmod(0o700)


class QmpTests(unittest.TestCase):
    def fake(self, path, lingering=False, wrong=False):
        state={'removed':False};qmp=Mock()
        def execute(command,args=None):
            if command=='query-block':
                inserted={} if state['removed'] else {'inserted':{'file':str(path) if not wrong else '/other','ro':True}}
                return [{'device':'install',**inserted}]
            if command=='query-named-block-nodes':return [{'file':str(path)}] if lingering else []
            if command=='blockdev-remove-medium':state['removed']=True
            return {}
        qmp.execute.side_effect=execute
        return qmp

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_detach_both_queries_before_owned_delete(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'official.iso';p.write_bytes(b'iso')
            qmp=self.fake(p);host.reclaim_installer(qmp,p,root,types.SimpleNamespace(ISO_BYTES=3))
            self.assertFalse(p.exists())
            self.assertIn('query-named-block-nodes',[c.args[0] for c in qmp.execute.call_args_list])

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_lingering_named_node_prevents_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'official.iso';p.write_bytes(b'iso')
            with self.assertRaises(ValueError):host.reclaim_installer(self.fake(p,lingering=True),p,root,types.SimpleNamespace(ISO_BYTES=3))
            self.assertTrue(p.exists())

    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_wrong_readonly_binding_never_ejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);p=root/'official.iso';p.write_bytes(b'iso');qmp=self.fake(p,wrong=True)
            with self.assertRaises(ValueError):host.reclaim_installer(qmp,p,root,types.SimpleNamespace(ISO_BYTES=3))
            self.assertEqual(qmp.execute.call_count,1);self.assertTrue(p.exists())

    def test_duplicate_device_fails(self):
        qmp=Mock();qmp.execute.return_value=[{'device':'install'},{'device':'install'}]
        with self.assertRaises(ValueError):host.exact_block(qmp,'install')

    def test_pause_requires_status_readback(self):
        qmp=Mock();qmp.execute.side_effect=[{'running':True},{},{'running':False,'status':'paused'}]
        host.pause_installed(qmp)
        qmp=Mock();qmp.execute.side_effect=[{'running':True},{},{'running':True,'status':'running'}]
        with self.assertRaises(ValueError):host.pause_installed(qmp)


class PinsAndProtocolTests(unittest.TestCase):
    def media(self):
        return types.SimpleNamespace(UPDATE_BUILD=26200,UPDATE_UBR=9711,UPDATE_PACKAGES=[
            dict(seed_filename=n,bytes=b,sha256=h,url='https://catalog.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/x')
            for n,b,h in host.UPDATE_PINS])

    def test_exact_packages_only(self):
        media=self.media();self.assertEqual(sum(p['bytes'] for p in host.update_packages(media)),host.UPDATE_BYTES)
        media.UPDATE_PACKAGES[0]['bytes']+=1
        with self.assertRaises(ValueError):host.update_packages(media)

    def test_untrusted_origin_or_target_rejected(self):
        media=self.media();media.UPDATE_PACKAGES[0]['url']='https://other.example/x'
        with self.assertRaises(ValueError):host.update_packages(media)
        media=self.media();media.UPDATE_UBR+=1
        with self.assertRaises(ValueError):host.update_packages(media)

    def test_receipt_closed_and_false_not_truthy(self):
        result=host.closed_servicing({'phase':'PRIVATE','completed':'true','packages_verified':True,'secret':'PRIVATE'})
        self.assertEqual(result['phase'],'not_observed');self.assertFalse(result['completed'])
        self.assertNotIn('PRIVATE',json.dumps(result))

    def test_new_path_not_stock_relabel(self):
        self.assertIn('serviced26200.9711',host.project_stage0({})['stage'])
        self.assertEqual(host.GUEST_SOURCES[0],'.github/windows_identity_serviced_stage0.py')
        source=(ROOT/'.github/windows_identity_serviced_stage0.py').read_text()
        self.assertIn("'identity-stock-installed-ready'",source.replace('RPBEACON ',''))
        self.assertIn("'-iso-level', '3'",source)
        self.assertIn("'read-only-mode': 'read-only'",source)
        self.assertNotIn("'--fsize=0",source)


class WireReceiptTests(unittest.TestCase):
    def receipt(self):
        return dict(stage0_passed=True, checks={k:True for k in host.CHECKS}, ordinary_account=True,
            servicing_verified=True,harness_completed=True,actor_sha256='a'*64,
            os={'build':26200,'ubr':9711,'product_type':'WinNT','architecture':'AMD64'},
            servicing_diagnostic={'phase':'completed','failure':'none','dism_exit_code':3010,
                'packages_verified':True,'reboot_observed':True,'task_unregistered':True,'completed':True},
            launcher_diagnostic={'phase':'serviced_build','failure_category':'none','failed':False})

    def test_exact_guest_receipt_passes_gate(self):
        result=host.validate_guest(self.receipt(),'a'*64)
        self.assertTrue(result['stage0_passed'])
        self.assertEqual(result['servicing_diagnostic']['dism_exit_code'],3010)
        self.assertEqual(result['launcher_diagnostic']['phase'],'serviced_build')

    def test_missing_or_truthy_service_observations_fail(self):
        for field in ('completed','packages_verified','reboot_observed','task_unregistered'):
            for value in (None,'true',1,False):
                raw=self.receipt();raw['servicing_diagnostic'][field]=value
                self.assertFalse(host.validate_guest(raw,'a'*64)['stage0_passed'])

    def test_failure_kept_before_wrong_build_provenance_rejection(self):
        raw=self.receipt();raw['os']['ubr']=6584
        raw['servicing_diagnostic'].update(phase='installing_official_cu',failure='dism_failed',dism_exit_code=87)
        raw['launcher_diagnostic'].update(phase='servicing_wait',failure_category='servicing_failed')
        projected=host.project_stage0(raw)
        self.assertEqual(projected['servicing_diagnostic']['failure'],'dism_failed')
        self.assertEqual(projected['servicing_diagnostic']['dism_exit_code'],87)
        self.assertEqual(projected['launcher_diagnostic']['failure_category'],'servicing_failed')
        with self.assertRaises(ValueError):host.validate_guest(raw,'a'*64)

    def test_unknown_fields_do_not_escape(self):
        raw=self.receipt();raw['servicing_diagnostic']['private_boot_ticks']='SECRET'
        raw['servicing_diagnostic']['failure']='SECRET'
        raw['launcher_diagnostic']['private']='SECRET'
        self.assertNotIn('SECRET',json.dumps(host.project_stage0(raw)))


class PrepareProtocolTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_sources_deleted_before_readonly_attach(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);disk=root/'windows.qcow2';disk.write_bytes(b'disk');iso=root/'official.iso';iso.write_bytes(b'iso')
            pkgs=[dict(seed_filename=n,bytes=1,sha256=h,url='https://test') for n,_,h in host.UPDATE_PINS]
            calls=[];qmp=Mock();attached={'value':False}
            def command(cmd,args=None):
                calls.append(cmd)
                if cmd=='query-block':
                    return [{'device':'updates',**({'inserted':{'file':str(root/'updates.iso'),'ro':True}} if attached['value'] else {})}]
                if cmd=='blockdev-change-medium':
                    self.assertTrue(all(not (root/p['seed_filename']).exists() for p in pkgs))
                    self.assertEqual(args['read-only-mode'],'read-only');attached['value']=True
                if cmd=='query-status':return {'running':True}
                return {}
            qmp.execute.side_effect=command
            def process(argv,*args,**kwargs):
                if argv[0]=='curl':Path(argv[argv.index('--output')+1]).write_bytes(b'x')
                if argv[0]=='xorriso':(root/'updates.iso').write_bytes(b'xx')
            media=Mock();media.digest.side_effect=lambda p:next((x['sha256'] for x in pkgs if x['seed_filename']==p.name),'b'*64)
            with patch.object(host,'update_packages',return_value=pkgs),patch.object(host,'pause_installed'),\
                 patch.object(host,'reclaim_installer',side_effect=lambda *a:iso.unlink()),\
                 patch.object(host,'service_capacity',return_value={'projected_floor_bytes':host.SERVICE_FLOOR}),\
                 patch.object(host,'record_breadcrumb'),patch.object(host,'service_process',side_effect=process),\
                 patch.object(host.shutil,'which',return_value='/usr/bin/7z'),patch.object(host,'UPDATE_BYTES',2),patch.object(host,'UPDATE_ISO_CAP',20):
                public={};host.prepare_servicing(media,qmp,root,iso,disk,host.time.monotonic()+4000,Mock(),public)
            self.assertTrue(public['update_media_members_verified']);self.assertTrue(public['update_source_files_removed'])
            self.assertTrue(public['installed_guest_resumed']);self.assertLess(calls.index('blockdev-change-medium'),calls.index('cont'))

    def test_time_gate_before_pause_or_mutation(self):
        qmp=Mock()
        with patch.object(host,'update_packages',return_value=[]):
            with self.assertRaises(host.VMWorkBudgetInsufficient):
                host.prepare_servicing(Mock(),qmp,Path('/x'),Path('/x/official.iso'),Path('/x/disk'),host.time.monotonic()+10,Mock(),{})
        qmp.execute.assert_not_called()

class InventoryFailureTests(unittest.TestCase):
    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership and permission semantics required')
    def test_unknown_named_inventory_prevents_delete(self):
        for invalid in (None,3,{},[None],[{}],[{'file':3}], [{'file':'x'}]*65):
            with self.subTest(invalid=invalid),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);p=root/'official.iso';p.write_bytes(b'iso');state={'removed':False}
                qmp=Mock()
                def execute(cmd,args=None):
                    if cmd=='query-block':return [{'device':'install',**({} if state['removed'] else {'inserted':{'file':str(p),'ro':True}})}]
                    if cmd=='blockdev-remove-medium':state['removed']=True
                    if cmd=='query-named-block-nodes':return invalid
                    return {}
                qmp.execute.side_effect=execute
                with self.assertRaises(ValueError):host.reclaim_installer(qmp,p,root,types.SimpleNamespace(ISO_BYTES=3))
                self.assertTrue(p.exists())

    def test_nested_file_reference_detected(self):
        path=Path('/owned/official.iso')
        self.assertTrue(host.references([{'image':{'filename':'prefix:'+str(path)+':suffix'}}],path))

    def test_malformed_block_inventory_rejected(self):
        for rows in (None,{},[{}],[None],[{'device':3}]):
            qmp=Mock();qmp.execute.return_value=rows
            with self.assertRaises(ValueError):host.exact_block(qmp,'install')

class AcceptanceFailureTests(WireReceiptTests):
    def test_contradictory_receipts_fail(self):
        for key,value in [('phase','reboot_pending'),('failure','dism_failed'),('dism_exit_code',87),('dism_exit_code',None)]:
            raw=self.receipt();raw['servicing_diagnostic'][key]=value
            self.assertFalse(host.validate_guest(raw,'a'*64)['stage0_passed'])

    def test_valid_guest_missing_host_stage_never_leaves_true(self):
        fields=('installer_detach_verified','update_media_members_verified','update_source_files_removed','update_media_attached_readonly','installed_guest_resumed')
        for missing in fields:
            public={k:True for k in fields};public[missing]=False;public['stage0_passed']=True
            with self.assertRaises(ValueError):host.merge_serviced_result(public,self.receipt(),'a'*64,True)
            self.assertFalse(public['stage0_passed']);self.assertFalse(public['guest_result_provenance_verified'])
            self.assertEqual(public['servicing_diagnostic']['phase'],'completed')

    def test_valid_complete_host_and_guest_pass(self):
        public={k:True for k in ('installer_detach_verified','update_media_members_verified','update_source_files_removed','update_media_attached_readonly','installed_guest_resumed')}
        host.merge_serviced_result(public,self.receipt(),'a'*64,True)
        self.assertTrue(public['stage0_passed']);self.assertTrue(public['guest_result_provenance_verified'])

class HelperCleanupTests(unittest.TestCase):
    def test_unconfirmed_helper_retains_work_and_revokes_pass(self):
        helper=Mock();helper.poll.return_value=None;helper.kill.side_effect=OSError('cannot confirm')
        helper.wait.side_effect=host.subprocess.TimeoutExpired('helper',5)
        watch=Mock();watch.processes=[helper];watch.thread.is_alive.return_value=False;watch.minimum_free=10*host.GIB;watch.reason=None
        public={'stage0_passed':True,'status':'passed'}
        with patch.object(host,'cleanup_owned',return_value=False) as cleanup:
            host.finalize_owned(public,Mock(),Path('/owned'),watch=watch)
        self.assertTrue(cleanup.call_args.kwargs['retain_work'])
        self.assertFalse(public['vm_destroyed']);self.assertFalse(public['stage0_passed'])

    def test_registered_finished_helper_does_not_block_cleanup(self):
        helper=Mock();helper.poll.return_value=0
        watch=Mock();watch.processes=[helper];watch.thread.is_alive.return_value=False;watch.minimum_free=10*host.GIB;watch.reason=None
        public={'stage0_passed':False,'status':'observed_failure'}
        with patch.object(host,'cleanup_owned',return_value=True) as cleanup:
            host.finalize_owned(public,Mock(),Path('/owned'),watch=watch)
        self.assertFalse(cleanup.call_args.kwargs['retain_work']);self.assertTrue(public['vm_destroyed'])

@unittest.skipUnless(host.sys.platform=='linux' and host.shutil.which('prlimit'), 'Linux process limiter required')
class ActualBoundedHelperTests(unittest.TestCase):
    def watch(self):
        watch=types.SimpleNamespace(reason=None,processes=[])
        watch.register=watch.processes.append
        return watch

    def run_helper(self, code, digest, maximum=2):
        watch=self.watch()
        try:
            host.service_process([host.sys.executable,'-c',code],host.time.monotonic()+10,watch,
                ceiling=1024**2,maximum=maximum,stream_digest=digest)
        finally:
            self.assertTrue(all(p.poll() is not None for p in watch.processes))

    def test_stream_hash_without_disk_copy(self):
        self.run_helper("import sys;sys.stdout.buffer.write(b'abc')",(3,host.hashlib.sha256(b'abc').hexdigest()))

    def test_stream_overrun_and_wrong_hash_rejected(self):
        with self.assertRaises(ValueError):self.run_helper("print('abcd',end='')",(3,host.hashlib.sha256(b'abc').hexdigest()))
        with self.assertRaises(ValueError):self.run_helper("print('abd',end='')",(3,host.hashlib.sha256(b'abc').hexdigest()))

    def test_timeout_kills_owned_helper(self):
        with self.assertRaises(TimeoutError):self.run_helper('import time;time.sleep(5)',(3,'a'*64),maximum=.05)


if __name__ == "__main__":
    unittest.main()
