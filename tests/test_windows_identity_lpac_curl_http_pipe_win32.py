"""Future portable production-header harness only; author did not execute it.

No Windows DLL/actor/compiler has been run during source preparation. The test
command below builds a fake scheduler, never a shim or any real curl process.
"""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.name=='nt','Windows SDK types for fake pipe calls')
class PurePipeWin32Tests(unittest.TestCase):
    def test_pipe_bounds_adoption_once_close_and_late_raw_facts(self):
        source=ROOT/'tests/lpac_curl_http_pipe_win32_fake.cpp'
        with tempfile.TemporaryDirectory() as td:
            directory=Path(td).resolve()
            if os.name=='nt':
                compiler=shutil.which('cl.exe')
                self.assertIsNotNone(compiler,'MSVC x64 developer shell required')
                executable=directory/'curl_http_pipe_fake.exe'
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/O2',
                    str(source),'/Fe:'+str(executable),'/Fo:'+str(directory/'fake.obj')]
            else:
                compiler=shutil.which('c++')
                self.assertIsNotNone(compiler,'C++17 compiler required')
                executable=directory/'curl_http_pipe_fake'
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(executable)]
            built=subprocess.run(command,cwd=directory,capture_output=True,timeout=60)
            self.assertEqual(built.returncode,0,repr(built.stdout)+repr(built.stderr))
            result=subprocess.run([str(executable)],cwd=directory,capture_output=True,timeout=20)
            self.assertEqual(result.returncode,0,repr(result.stdout)+repr(result.stderr))
            found=re.fullmatch(rb'pipe fake assertions: ([0-9]+)\r?\n',result.stdout)
            self.assertIsNotNone(found,repr(result.stdout))
            self.assertEqual(int(found.group(1)),41)
            self.assertEqual(result.stderr,b'')


if __name__=='__main__':
    unittest.main()
