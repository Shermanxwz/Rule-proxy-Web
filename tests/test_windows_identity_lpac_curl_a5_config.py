"""Pure encoding fixtures only; source prepared without executing this module."""
import importlib.util
from pathlib import Path
import struct
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('a5_config', ROOT/'.github/windows_identity_lpac_curl_a5_config.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def fixture():
    return dict(run='11'*16, case='22'*16, trace_nonce='33'*16,
                source_sha256='44'*32, config_sha256='55'*32,
                target_sha256='66'*32, shim_sha256='77'*32,
                frequency=1000000, root_start=1000,
                root_deadline=120001000, work_deadline=85001000,
                window_start=2000, window_end=8002000,
                target_pid=123, target_creation=456,
                private_path='C:\\owned\\package\\'+m.SHIM_BASENAME,
                system_ws2_path='C:\\Windows\\System32\\WS2_32.dll',
                inherited_handles=[100, 104, 108, 112, 116, 120], port=51001,virtual_local_port=51002)


class PureConfigTests(unittest.TestCase):
    def test_exact_offsets_fixed_HTTP_profile_and_zero_reserved(self):
        v=fixture(); raw=m.pack_config(v)
        self.assertEqual(len(raw),2048)
        self.assertEqual(raw[:8],b'A5P1\x01\x00\x00\x08')
        self.assertEqual(struct.unpack_from('<Q',raw,216)[0],100)
        self.assertEqual(struct.unpack_from('<QQ',raw,1800),(104,108))
        self.assertEqual(raw[1816:1832],bytes.fromhex(v['case']))
        self.assertEqual(struct.unpack_from('<HHIIHHII',raw,1832),(51001,1,8193,12289,128,113,8065,12176))
        self.assertEqual(struct.unpack_from('<HH',raw,1856),(51002,0))
        self.assertEqual(raw[1860:],bytes(188))
        req,res=m.fixed_headers(v['case'],v['port'])
        self.assertEqual((len(req),len(res)),(128,113))
        self.assertIn(b'Host: 127.0.0.1:51001\r\n',req)
        self.assertEqual(m.PAYLOAD_GUID_BYTES,bytes.fromhex('723b19a5d35a4b4fae3a706564727073'))

    def test_child_six_handle_alias_zero_invalid_and_bool_are_rejected(self):
        for h in (0,m.INVALID_HANDLE,True,-1):
            with self.subTest(bad=h):
                v=fixture();v['inherited_handles'][1]=h
                with self.assertRaises(ValueError):m.pack_config(v)
        for index in range(1,6):
            with self.subTest(alias=index):
                v=fixture();v['inherited_handles'][index]=v['inherited_handles'][0]
                with self.assertRaises(ValueError):m.pack_config(v)

    def test_original_epoch_cases_paths_and_closed_keys_cannot_be_relaxed(self):
        for field,value in [('root_deadline',120001001),('work_deadline',85001001),
                            ('window_end',8002001),('port',80),('virtual_local_port',51001),
                            ('virtual_local_port',0),('virtual_local_port',True),('target_pid',True),
                            ('case','11'*16),('trace_nonce','22'*16),
                            ('private_path','C:\\owned\\..\\'+m.SHIM_BASENAME),
                            ('system_ws2_path','C:\\Windows\\System32\\ws2_32.dll')]:
            with self.subTest(field=field):
                v=fixture();v[field]=value
                with self.assertRaises(ValueError):m.pack_config(v)
        v=fixture();v['optional_unknown']=False
        with self.assertRaises(ValueError):m.pack_config(v)


if __name__ == '__main__':
    unittest.main()
