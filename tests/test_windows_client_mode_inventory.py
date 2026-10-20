import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('modes',ROOT/'.github/windows_identity_mode_inventory.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class ModeInventoryTests(unittest.TestCase):
    def test_unknown_image_before_filesystem(self):
        with patch.dict(os.environ,{'ImageOS':'ubuntu24','ImageVersion':'unreviewed'}), patch.object(m,'mount_points',side_effect=AssertionError('must not inspect')):
            r=m.collect()
        self.assertEqual(r['status'],'unknown_image_blocked');self.assertEqual(r['targets'],{})
    def test_exact_two_image_map(self):
        self.assertEqual(set(m.REVIEWED_IMAGES),{'20261012.334.1','20261018.339.1'})
        for v,(_,commit) in m.REVIEWED_IMAGES.items():
            with patch.dict(os.environ,{'ImageOS':'ubuntu24','ImageVersion':v}),patch.object(m,'mount_points',return_value=set()),patch.object(m,'preparation_context',return_value={}),patch.object(m,'inspect_target',return_value={}):
                r=m.collect()
            self.assertEqual(r['image_provenance']['definition_commit'],commit)
    def test_mode_projection(self):
        for bits in (0o755,0o777,0o1777,0o4755):
            r=m.mode_fact(SimpleNamespace(st_mode=stat.S_IFDIR|bits,st_uid=0,st_gid=0))
            self.assertEqual(r,{'type':'directory','mode':format(bits,'04o'),'owner_root':True,'group_root':True})
    @unittest.skipUnless(os.name=='posix','descriptor-relative Linux fixture')
    def test_modes_no_symlink_target_traversal(self):
        real_stat,real_fstat=os.stat,os.fstat
        def root_owned(info):
            values={key:getattr(info,key) for key in dir(info) if key.startswith('st_')}
            values.update(st_uid=0,st_gid=0);return SimpleNamespace(**values)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'owned';root.mkdir();root.chmod(0o777)
            f=root/'file';f.write_bytes(b'x');f.chmod(0o664)
            outside=Path(directory)/'outside';outside.mkdir();(outside/'excluded').write_bytes(b'secret')
            (root/'link').symlink_to(outside)
            os.link(f,root/'hard')
            def opener(path,result):
                fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
                result['target_root_mode']=m.mode_fact(root_owned(real_fstat(fd)))
                return fd
            with patch.object(m,'open_root',side_effect=opener),patch.object(m,'mount_id',return_value=1),patch.object(m.os,'stat',side_effect=lambda *a,**k:root_owned(real_stat(*a,**k))),patch.object(m.os,'fstat',side_effect=lambda fd:root_owned(real_fstat(fd))):
                r=m.inspect_target(str(root),set(),time.monotonic()+30)
            self.assertTrue(r['complete']);self.assertEqual(r['entries'],4)
            self.assertEqual(r['mode_counts']['directory'],{'0777':1})
            self.assertEqual(r['mode_counts']['regular'],{'0664':2})
            self.assertEqual(r['symlink_count'],1);self.assertEqual(r['multiply_linked_file_count'],1)
            self.assertEqual(r['first_writable_role'],'root')
            self.assertNotIn('excluded',str(r));self.assertNotIn(str(outside),str(r))
    def test_mount_block_role(self):
        r=m.inspect_target('/fixed',{'/fixed/child'},time.monotonic()+30)
        self.assertEqual(r['first_failure_role'],'descendant');self.assertFalse(r['complete'])
    def test_package_estimates_only_selected_versions(self):
        outputs=['Inst example (2 repo [amd64])\n', 'Package: example\nVersion: 2\nSize: 100\nInstalled-Size: 20\n', 'example\tinstall ok installed\t10\n']
        with patch.object(m,'command_metadata',side_effect=outputs) as command:
            result=m.package_plan(False)
        self.assertTrue(result['available']);self.assertEqual(result['download_bytes_upper_bound'],100)
        self.assertEqual(result['positive_installed_growth_bytes'],10240)
        self.assertEqual(command.call_args_list[-1].args[0][-1],'example')
        self.assertFalse(result['peak_disk_bound'])
    def test_missing_package_metadata_not_guessed(self):
        with patch.object(m,'command_metadata',side_effect=['Inst example (2 repo [amd64])\n','', '']):
            result=m.package_plan(True)
        self.assertFalse(result['available']);self.assertIsNone(result['positive_installed_growth_bytes'])
    def test_no_package_changes_is_zero(self):
        with patch.object(m,'command_metadata',return_value='0 upgraded, 0 newly installed'):
            result=m.package_plan(False)
        self.assertTrue(result['available']);self.assertEqual(result['download_bytes_upper_bound'],0)
    def test_exact_preserved_environment(self):
        import re
        text=(ROOT/'.github/workflows/windows-identity-mode-inventory.yml').read_text()
        self.assertEqual(re.findall(r'sudo --preserve-env=([^ ]+)',text),
                         ['ImageOS,ImageVersion,RUNNER_TEMP,GITHUB_WORKSPACE'])
    def test_embedding_matches(self):
        text=(ROOT/'.github/workflows/windows-identity-mode-inventory.yml').read_text()
        body=text.split("<<'MODE_INSPECTOR'\n",1)[1].split('          MODE_INSPECTOR',1)[0]
        self.assertEqual('\n'.join(x[10:] for x in body.splitlines())+'\n',(ROOT/'.github/windows_identity_mode_inventory.py').read_text())
        self.assertNotIn('actions/checkout',text);self.assertIn('timeout-minutes: 5',text)
        self.assertNotIn('execute-reviewed-recovery',text)
if __name__=='__main__':unittest.main()
