"""Pure Windows-path/real-adapter fakes for the constructor02 narrow fix.

The already frozen backend fixture supplies Python callbacks and ctypes buffers.
No existing backend tests, DLL, Windows API, compiler, or target are executed.
"""
import importlib.util
from pathlib import Path, PureWindowsPath
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('loader_constructor02_backend_fixture',
    Path(__file__).with_name('test_windows_identity_lpac_curl_loader_backend.py'))
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
m=b.m


class ConstructorPathTests(unittest.TestCase):
    def setUp(self):
        self.no_init=mock.patch.object(m.NativeAPI,'__init__',side_effect=AssertionError('real backend forbidden')).start()
        self.no_dll=mock.patch.object(b.C,'WinDLL',side_effect=AssertionError('DLL loading forbidden'),create=True).start()
        self.addCleanup(mock.patch.stopall)

    def call(self,f,command,*,selected=True):
        handles=f.selected_handles if selected else f.selected_handles[-3:]
        for h in handles:f.flags.setdefault(h,1)
        with mock.patch.object(b.C,'get_last_error',lambda:f.error,create=True),\
             mock.patch.object(m.local.LocalNativeAPI,'private_descriptor',return_value=f.sd):
            return f.api.create_curl(f.info,command,Path('C:/Owned/package'),f.environment,f.job,f.owners,f.state,
                handles=handles,stdio=handles[-3:],profile_pointer=f.sid if selected else None,
                parent_sid='S-1-5-21-1',budget=f.budget,end=1900,on_return=f.returned,other_owned=())

    def test_pure_windows_path_semantics_accept_both_case_directions(self):
        for requested,system in (
            (r'C:\Windows\System32\curl.exe',r'C:\WINDOWS\system32\curl.exe'),
            (r'C:\WINDOWS\system32\curl.exe',r'C:\Windows\System32\curl.exe'),
            (r'C:\Windows\.\System32\curl.exe',r'C:\Windows\System32\curl.exe'),
            ('c:/windows/SYSTEM32/CURL.EXE',r'C:\Windows\System32\curl.exe')):
            with self.subTest(requested=requested,system=system):
                self.assertNotEqual(requested,system)
                self.assertTrue(m.curl_command_matches_system([requested,'--disable','--version'],PureWindowsPath(system)))
        self.assertTrue(m.curl_command_matches_system([r'C:\Windows\System32\curl.exe','--disable','--version'],r'C:\Windows\System32\curl.exe'))

    def test_only_fixed_typed_argv_and_same_absolute_system_target_can_match(self):
        system=PureWindowsPath(r'C:\Windows\System32\curl.exe')
        commands=[None,(str(system),'--disable','--version'),[system,'--disable','--version'],
            [str(system),'--version','--disable'],[str(system),'--disable'],[str(system),'--disable','--version','https://invalid/'],
            [str(system),'--DISABLE','--version'],['curl.exe','--disable','--version'],
            [r'\Windows\System32\curl.exe','--disable','--version'],[r'D:\Windows\System32\curl.exe','--disable','--version'],
            [r'C:\Other\System32\curl.exe','--disable','--version'],[r'C:\Windows\System32\other.exe','--disable','--version'],
            [r'C:\Windows\System32\..\System32\curl.exe','--disable','--version']]
        for command in commands:
            with self.subTest(command=command):self.assertFalse(m.curl_command_matches_system(command,system))
        for path in (r'\\server\share\Windows\System32\curl.exe',r'\\?\C:\Windows\System32\curl.exe',
                     r'\\.\C:\Windows\System32\curl.exe',r'C:\Windows\System32\..\System32\curl.exe'):
            with self.subTest(both_same_disallowed_path=path):
                self.assertFalse(m.curl_command_matches_system([path,'--disable','--version'],PureWindowsPath(path)))

    def test_selected_and_ordinary_adapter_preserve_requested_argv_with_case_variant(self):
        requested=r'C:\Windows\System32\curl.exe'
        for selected in (False,True):
            with self.subTest(selected=selected):
                f=b.Fixture();f.api.system_curl=lambda:PureWindowsPath(r'C:\WINDOWS\system32\curl.exe')
                command=m.argv({'curl_path':requested});self.assertEqual(command,[requested,'--disable','--version'])
                self.call(f,command,selected=selected)
                self.assertEqual(f.created[0]['application'],requested)
                self.assertEqual(f.created[0]['command'],requested+' --disable --version')
                self.assertEqual(f.receipts[0]['create_status'],'returned_true');self.assertFalse(f.state['creation_unknown'])
                attributes={kind:value for kind,size,value in f.attrs}
                self.assertEqual(attributes[m.base.JOB_LIST],[f.job])
                self.assertEqual(attributes[0x20002],f.selected_handles if selected else f.selected_handles[-3:])
                if selected:
                    self.assertEqual(attributes[m.base.SECURITY_CAPABILITIES],[f.sid,None,0,0])
                    self.assertEqual(attributes[m.base.ALL_APPLICATION_PACKAGES_POLICY],1)
                else:self.assertEqual(set(attributes),{m.base.JOB_LIST,0x20002})
                self.no_init.assert_not_called();self.no_dll.assert_not_called()

    def test_adapter_other_target_or_option_stops_before_constructor_or_allocation(self):
        for command in ([r'C:\Windows\SysWOW64\curl.exe','--disable','--version'],
                        [r'C:\Windows\System32\curl.exe','--version','--disable']):
            with self.subTest(command=command):
                f=b.Fixture();f.api.system_curl=lambda:PureWindowsPath(r'C:\WINDOWS\system32\curl.exe')
                with self.assertRaisesRegex(ValueError,'loader_constructor_inputs'):self.call(f,command,selected=False)
                self.assertEqual(f.created,[]);self.assertEqual(f.init_counts,[]);self.assertEqual(f.attrs,[])
                self.assertEqual(f.receipts,[]);self.assertFalse(f.owners.pending)

    def test_case_fix_does_not_bypass_original_deadline_or_erase_known_true_cleanup(self):
        f=b.Fixture();f.api.system_curl=lambda:PureWindowsPath(r'C:\WINDOWS\system32\curl.exe');f.after_create_tick=1900
        with self.assertRaisesRegex(ValueError,'fake_original_deadline'):
            self.call(f,[r'C:\Windows\System32\curl.exe','--disable','--version'],selected=False)
        self.assertEqual(f.receipts[0]['create_status'],'returned_true');self.assertFalse(f.state['creation_unknown'])
        self.assertEqual(f.owners.pending,set(f.raw_pi[:2]));self.assertEqual(f.receipts[0]['returned_qpc'],1900)


if __name__=='__main__':unittest.main()
