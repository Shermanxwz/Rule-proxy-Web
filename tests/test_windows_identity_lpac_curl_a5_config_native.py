"""One Python production encoder -> native production Config parser test.

Source preparation only. The author did not import/run this test or compiler.
The future harness runs only file/struct code, never a Windows DLL or target.
All fixtures and includes are repo-relative; no private WORK/history inputs.
"""
import ctypes
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]


class A5ConfigNativeInteropTests(unittest.TestCase):
    def test_Python_pack_config_matches_actual_native_config_shape(self):
        path=ROOT/'.github/windows_identity_lpac_curl_a5_config.py'
        with mock.patch.object(ctypes,'WinDLL',side_effect=AssertionError('no native API'),create=True):
            spec=importlib.util.spec_from_file_location('a5_cross_abi_pure_encoder',path)
            codec=importlib.util.module_from_spec(spec);spec.loader.exec_module(codec)
            values=dict(run='11'*16,case='22'*16,trace_nonce='33'*16,
                source_sha256='44'*32,config_sha256='55'*32,target_sha256='66'*32,shim_sha256='77'*32,
                frequency=1000000,root_start=1000,root_deadline=120001000,work_deadline=85001000,
                window_start=2000,window_end=8002000,target_pid=123,target_creation=456,
                private_path='C:\\owned\\package\\'+codec.SHIM_BASENAME,
                system_ws2_path='C:\\Windows\\System32\\WS2_32.dll',
                inherited_handles=[100,104,108,112,116,120],port=51001,virtual_local_port=51002)
            raw=codec.pack_config(values)
        self.assertEqual(len(raw),2048)
        with tempfile.TemporaryDirectory() as temporary:
            directory=Path(temporary).resolve();config=directory/'config.bin'
            with config.open('xb') as stream:self.assertEqual(stream.write(raw),2048)
            source=ROOT/'tests/lpac_curl_a5_config_native_fake.cpp'
            if os.name=='nt':
                compiler=shutil.which('cl.exe');self.assertIsNotNone(compiler,'MSVC x64 developer shell required')
                executable=directory/'a5_config_native_fake.exe'
                command=[compiler,'/nologo','/std:c++17','/EHsc','/W4','/WX','/O2',str(source),
                    '/Fe:'+str(executable),'/Fo:'+str(directory/'fake.obj')]
            else:
                compiler=shutil.which('c++');self.assertIsNotNone(compiler,'C++17 compiler required')
                executable=directory/'a5_config_native_fake'
                command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2',str(source),'-o',str(executable)]
            built=subprocess.run(command,cwd=directory,capture_output=True,timeout=60)
            self.assertEqual(built.returncode,0,repr(built.stdout)+repr(built.stderr))
            result=subprocess.run([str(executable),str(config)],cwd=directory,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,repr(result.stdout)+repr(result.stderr))
            match=re.fullmatch(rb'a5-cross-abi assertions: ([0-9]+)\r?\n',result.stdout)
            self.assertIsNotNone(match,repr(result.stdout));self.assertEqual(int(match.group(1)),16)
            self.assertEqual(result.stderr,b'')


if __name__=='__main__':unittest.main()
