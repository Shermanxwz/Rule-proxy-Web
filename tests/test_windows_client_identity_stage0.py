"""Pure wiring/projection tests. No VM, account, token or Windows execution."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch, Mock
import tempfile
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('client_stage0', ROOT / '.github/windows_identity_win11_stage0.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)

PREFLIGHT_SPEC=importlib.util.spec_from_file_location('lab_preflight', ROOT/'.github/windows_identity_lab_preflight.py')
pref=importlib.util.module_from_spec(PREFLIGHT_SPEC); PREFLIGHT_SPEC.loader.exec_module(pref)

class LabPreflightTests(unittest.TestCase):
    def test_all_fixed_locations_and_kvm_observed_before_storage_failure(self):
        calls=[]
        def storage(path):
            calls.append(path)
            return {'exists':True,'directory':True,'writable':True,'total_bytes':100,
                    'free_bytes':1,'minimum_met':False,'error_errno':None}, 4711
        def kvm():
            calls.append('KVM_READ_ONLY')
            return {'opened_read_write':True,'api_supported':True,'handle_closed':True}
        out=pref.collect(storage_reader=storage,kvm_reader=kvm,runner_temp='/private/temp',workspace='/private/work')
        self.assertEqual(calls,['/private/work','/tmp','/private/temp','/mnt','KVM_READ_ONLY'])
        self.assertFalse(out['existing_tmp_ready'])
        self.assertEqual(out['eligible_storage_labels'],[])
        text=json.dumps(out)
        for secret in ('/private','/tmp','/mnt','4711'): self.assertNotIn(secret,text)
        self.assertEqual({x['filesystem_group'] for x in out['storage'].values()},{'filesystem_1'})
        self.assertTrue(all(out['same_filesystem'].values()))

    def test_alternate_is_proposed_not_selected_or_provisioned(self):
        def storage(path):
            eligible=path=='/mnt'
            return {'exists':True,'directory':True,'writable':True,'total_bytes':99*1024**3,
                    'free_bytes':56*1024**3 if eligible else 1,'minimum_met':eligible,'error_errno':None}, 2 if eligible else 1
        out=pref.collect(storage_reader=storage,kvm_reader=lambda:{'opened_read_write':False},runner_temp='/tmp',workspace='/tmp')
        self.assertEqual(out['proposed_storage_label'],'mnt')
        self.assertTrue(out['alternate_storage_available'])
        self.assertFalse(out['same_filesystem']['tmp__mnt'])
        self.assertFalse(out['existing_tmp_ready']); self.assertFalse(out['vm_created']); self.assertFalse(out['host_changes'])
        self.assertEqual(out['minimum_free_bytes'],55*1024**3)

    def test_kvm_open_failure_is_closed_errno_without_path(self):
        with patch.object(pref.os.path,'exists',return_value=True), patch.object(pref.os,'open',side_effect=PermissionError(13,'private-path')):
            out=pref.inspect_kvm()
        self.assertEqual(out['error_errno'],13)
        self.assertFalse(out['opened_read_write'])
        self.assertNotIn('private-path',json.dumps(out))

class ClientStage0Tests(unittest.TestCase):
    def sample(self):
        return dict(checks={k: True for k in m.CHECKS}, stage0_passed=True,
                    ordinary_account=True, servicing_verified=True, harness_completed=True,
                    actor_sha256='a'*64, os={'build':26200,'ubr':9711,'product_type':'WinNT','architecture':'AMD64'})

    def test_closed_projection_removes_sensitive_arbitrary_values(self):
        value=self.sample()
        value.update(nonce='secret nonce', sid='S-1-5-21-private', error={'detail':'C:/private/password'},
                     controller_identity={'sid':'private'}, checks={**value['checks'],'password':'secret'})
        out=m.validate_guest(value,'a'*64)
        text=json.dumps(out)
        for secret in ('secret','private','nonce','password','controller_identity'):
            self.assertNotIn(secret,text)
        self.assertTrue(out['stage0_passed'])
        self.assertFalse(out['psec_cleanup_independently_verified'])
        self.assertFalse(out['network_tested'])
        self.assertFalse(out['privacy_qualified'])

    def test_each_required_gate_is_fail_closed(self):
        for key in m.CHECKS:
            value=self.sample(); value['checks'][key]=False
            self.assertFalse(m.validate_guest(value,'a'*64)['stage0_passed'])
        for key in ('ordinary_account','servicing_verified','harness_completed'):
            value=self.sample(); value[key]=False
            self.assertFalse(m.validate_guest(value,'a'*64)['stage0_passed'])

    def test_bool_not_truthy(self):
        value=self.sample(); value['ordinary_account']='true'
        self.assertFalse(m.validate_guest(value,'a'*64)['stage0_passed'])
        value=self.sample(); value['checks']['native_identity']=1
        self.assertFalse(m.validate_guest(value,'a'*64)['stage0_passed'])

    def test_exact_build_and_actor_required(self):
        for key,bad in (('build',26300),('ubr',9712),('product_type','ServerNT'),('architecture','ARM64')):
            value=self.sample(); value['os'][key]=bad
            with self.assertRaises(ValueError): m.validate_guest(value,'a'*64)
        with self.assertRaises(ValueError): m.validate_guest(self.sample(),'b'*64)

    def test_unsupported_contract_stays_separate(self):
        value=self.sample(); value['checks']['request_aware_base_container']=False
        out=m.validate_guest(value,'a'*64)
        self.assertFalse(out['request_supported']); self.assertFalse(out['stage0_passed'])
        self.assertNotIn('R0',json.dumps(out))

    def test_bounded_input(self):
        value=self.sample(); value['junk']='x'*m.MAX_REPORT
        with self.assertRaises(ValueError): m.validate_guest(value,'a'*64)

    def test_workflow_single_opt_in_and_public_only(self):
        text=(ROOT/'.github/workflows/windows-identity-win11-stage0.yml').read_text()
        self.assertIn("branches: ['dot/windows-isolation-proof']",text)
        self.assertIn('[identity-win11-stage0-runtime]',text)
        self.assertIn('artifact-ids: 11938733475',text)
        self.assertIn('timeout-minutes: 120',text)
        self.assertNotIn('rm -rf',text); self.assertNotIn('docker system prune',text)
        self.assertNotIn('matrix:',text); self.assertNotIn('secrets.',text)
        native=text[text.index('  native:'):]
        self.assertLess(native.index('--require-existing-tmp'),native.index('sudo apt-get update'))
        self.assertLess(native.index('--require-existing-tmp'),native.index('uses: actions/download-artifact'))
        self.assertIn('[identity-win11-preflight]',text)
        preflight=text[text.index('  preflight:'):text.index('  compile:')]
        self.assertNotIn('apt-get',preflight)
        self.assertNotIn('download-artifact',preflight)
        self.assertIn('if: always()',preflight)
        self.assertIn('path: client-stage0-public/public-report.json',text)
        self.assertNotIn('test_windows_identity*.py',text)
        self.assertNotIn('build-manifest.json\n',text.split('path: |')[1].split('retention-days:')[0])

    def test_guest_not_system_or_second_account(self):
        run=(ROOT/'.github/windows-identity-win11-stage0-run.ps1').read_text()
        setup=(ROOT/'.github/windows-identity-win11-stage0-setup.ps1').read_text()
        self.assertIn("RULEPROXY-VM\\RuleProxyCI",run)
        self.assertIn('WindowsBuiltInRole]::Administrator',run)
        self.assertIn('SessionId -le 0',run)
        self.assertIn('identity-base-setup.ps1',setup)
        self.assertIn('ServiceUpdate',setup)
        self.assertIn('/v BypassNRO /t REG_DWORD /d 1 /f',setup)
        self.assertIn('/v NoAutoUpdate /t REG_DWORD /d 1 /f',setup)
        self.assertEqual(setup.count('reg.exe add'),2)
        self.assertIn('3e90bb1f129a7d08b85fb816c7c70ba4f346ee66',setup)
        for forbidden in ('New-LocalUser','NetUserAdd','LogonUserW','CreateRestrictedToken','CreateProcessWithTokenW','rpps'):
            self.assertNotIn(forbidden,run+setup)
        self.assertNotIn('windows_psec_compartment_smoke.py',run)

    def test_every_blocking_subprocess_has_remaining_work_budget(self):
        with patch.object(m.time, 'monotonic', return_value=90):
            self.assertEqual(m.remaining_budget(100, 30), 10)
            self.assertEqual(m.remaining_budget(100, 5), 5)
            with patch.object(m.subprocess, 'run') as run:
                m.run_bounded(['tool'], 100, 30, check=True)
                run.assert_called_once_with(['tool'], timeout=10, check=True)
        with patch.object(m.time, 'monotonic', return_value=100):
            with self.assertRaises(TimeoutError): m.remaining_budget(100, 30)
        source=(ROOT/'.github/windows_identity_win11_stage0.py').read_text()
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, args.timeout_seconds - 120)',source)
        self.assertIn('signal.setitimer(signal.ITIMER_REAL, 0)',source)
        self.assertEqual(source.count('subprocess.run('),1)

    def test_cleanup_keeps_private_material_until_owned_processes_stop(self):
        for live in (True, False):
            with tempfile.TemporaryDirectory() as parent:
                work=Path(parent)/'private'; work.mkdir(); (work/'secret').write_text('test fixture')
                process=Mock(); process.poll.return_value=None if live else 0
                media=SimpleNamespace(stop_owned=Mock())
                result=m.cleanup_owned(media,work,qemu=process)
                self.assertEqual(result,not live)
                self.assertEqual(work.exists(),live)
                media.stop_owned.assert_any_call(process)
        with tempfile.TemporaryDirectory() as parent:
            work=Path(parent)/'private'; work.mkdir()
            thread=Mock(); thread.is_alive.return_value=True
            self.assertFalse(m.cleanup_owned(SimpleNamespace(stop_owned=Mock()),work,thread=thread))
            self.assertTrue(work.exists())

    def test_host_owns_cleanup_no_artifact_raw_files(self):
        source=(ROOT/'.github/windows_identity_win11_stage0.py').read_text()
        self.assertIn("'-netdev', 'user,id=vmnet'",source)
        self.assertIn('media.stop_owned(qemu)',source)
        self.assertIn('media.stop_owned(tpm)',source)
        self.assertIn('if not live:',source)
        self.assertIn('work.chmod(0o700)',source)
        self.assertNotIn('screenshot(',source)
        self.assertNotIn('iptables',source)
        self.assertNotIn('native.run(',source)

if __name__=='__main__': unittest.main()
