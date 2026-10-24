"""Portable production-header fakes, not a Windows DLL or actor build.

The two checked-in C++ sources are exact frozen08 copies. They include only the
portable production core/finder/reference headers. WORK and Git-history files
are not runtime fixtures. This harness source was prepared without execution.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT=Path(__file__).resolve().parents[1]


class ProductionPureTests(unittest.TestCase):
    def compile_run(self,filename,stem,expected):
        source=ROOT/'tests'/filename
        self.assertTrue(source.is_file())
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td).resolve()
            if os.name=='nt':
                compiler=shutil.which('cl.exe')
                self.assertIsNotNone(compiler,'MSVC x64 developer shell required for portable pure harness')
                executable=directory/(stem+'.exe')
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/O2',
                    str(source),'/Fe:'+str(executable),'/Fo:'+str(directory/(stem+'.obj'))]
            else:
                compiler=shutil.which('c++')
                self.assertIsNotNone(compiler,'C++17 compiler required for portable pure harness')
                executable=directory/stem
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2',
                    str(source),'-o',str(executable)]
            compiled=subprocess.run(command,cwd=directory,capture_output=True,timeout=60)
            self.assertEqual(compiled.returncode,0,repr(compiled.stdout)+repr(compiled.stderr))
            result=subprocess.run([str(executable)],cwd=directory,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,repr(result.stdout)+repr(result.stderr))
            self.assertEqual(result.stdout.replace(b'\r\n',b'\n'),expected)
            self.assertEqual(result.stderr,b'')

    def test_startup_capture_and_module_policy_production_headers(self):
        self.compile_run('lpac_curl_ws2_startup_fake.cpp','a4_startup_fake',
            b'A4_STARTUP_PURE_ASSERTIONS 168\n')

    def test_payload_finder_and_reference_ledger_production_headers(self):
        self.compile_run('lpac_curl_ws2_startup_bootstrap_fake.cpp','a4_bootstrap_fake',
            b'A4_BOOTSTRAP_PRODUCTION_ASSERTIONS 23\n')


if __name__=='__main__':unittest.main()
