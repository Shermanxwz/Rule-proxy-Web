"""Portable production-header fakes; contains no Win32/native-DLL backend.

Source was prepared without compilation. Only a separately authorized caller
may execute this test. The harness is checked in beside this file; WORK and
Git-history files are not runtime fixtures.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


class ProductionPureTests(unittest.TestCase):
    def test_observer_marker_and_ownership_use_production_headers(self):
        source=ROOT/'tests/lpac_curl_mm_loader_fake.cpp'
        self.assertTrue(source.is_file())
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td).resolve()
            if os.name=='nt':
                compiler=shutil.which('cl.exe')
                self.assertIsNotNone(compiler,'MSVC developer shell required for portable pure harness')
                executable=directory/'cmm_fake.exe'
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/O2',
                         str(source),'/Fe:'+str(executable),'/Fo:'+str(directory/'cmm_fake.obj')]
            else:
                compiler=shutil.which('c++')
                self.assertIsNotNone(compiler,'C++17 compiler required for portable pure harness')
                executable=directory/'cmm_fake'
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(executable)]
            compiled=subprocess.run(command,cwd=directory,capture_output=True,timeout=60)
            self.assertEqual(compiled.returncode,0,repr(compiled.stdout)+repr(compiled.stderr))
            result=subprocess.run([str(executable)],cwd=directory,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,repr(result.stdout)+repr(result.stderr))
            output=result.stdout.decode('ascii')
            self.assertRegex(output,r'^CMM_PURE_ASSERTIONS [1-9][0-9]*\r?\n$')
            self.assertEqual(result.stderr,b'')


if __name__=='__main__':
    unittest.main()
