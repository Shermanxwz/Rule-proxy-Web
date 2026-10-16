"""Exercise the ordinary-user YAML staging used when only conda has PyYAML."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT=Path(__file__).resolve().parent.parent


class GlobalSetupYamlTests(unittest.TestCase):
    def run_stage(self,directory,package):
        script=(ROOT/'setup-linux.sh').read_text(encoding='utf-8')
        snippet=script.split("python3 - <<'GLOBAL_VENDOR_YAML'\n",1)[1].split('\nGLOBAL_VENDOR_YAML',1)[0]
        # Simulate a selected conda interpreter whose PyYAML is unavailable to
        # /usr/bin/python3. No sudo, package manager, or network command runs.
        preamble='import sys,types\nsys.modules["ruleproxy"]=types.ModuleType("ruleproxy")\n'
        preamble+='yaml=types.ModuleType("yaml");yaml.__file__='+repr(str(package/'__init__.py'))+'\nsys.modules["yaml"]=yaml\n'
        return subprocess.run([sys.executable,'-I','-X','utf8','-'],cwd=directory,input=preamble+snippet,
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',timeout=10)

    def test_selected_python_parser_is_staged_without_foreign_c_extension(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);project=root/'project';project.mkdir()
            package=root/'conda-package/yaml';package.mkdir(parents=True)
            (package/'__init__.py').write_text('# selected parser\n',encoding='utf-8')
            (package/'loader.py').write_text('# pure loader\n',encoding='utf-8')
            (package/'_yaml.cpython-314-x86_64-linux-gnu.so').write_bytes(b'foreign ABI')
            result=self.run_stage(project,package)
            self.assertEqual(result.returncode,0,result.stderr)
            copied=project/'vendor/yaml'
            self.assertEqual({item.name for item in copied.iterdir()},{'__init__.py','loader.py'})
            self.assertEqual((copied/'loader.py').read_text(encoding='utf-8'),'# pure loader\n')
            self.assertTrue((package/'_yaml.cpython-314-x86_64-linux-gnu.so').exists())

    def test_existing_selected_vendor_parser_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);package=root/'vendor/yaml';package.mkdir(parents=True)
            source=package/'__init__.py';source.write_text('# existing selected parser\n',encoding='utf-8')
            result=self.run_stage(root,package)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(source.read_text(encoding='utf-8'),'# existing selected parser\n')

    @unittest.skipIf(sys.platform=='win32','Windows symlink creation requires an optional privilege')
    def test_vendor_link_cannot_redirect_staging_outside_project(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);project=root/'project';project.mkdir();outside=root/'outside';outside.mkdir()
            package=root/'conda-package/yaml';package.mkdir(parents=True)
            (package/'__init__.py').write_text('# selected parser\n',encoding='utf-8')
            (project/'vendor').symlink_to(outside,target_is_directory=True)
            result=self.run_stage(project,package)
            self.assertNotEqual(result.returncode,0)
            self.assertFalse(any(outside.iterdir()))


if __name__=='__main__':unittest.main()
