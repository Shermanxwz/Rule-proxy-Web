"""Pure codec negatives. No native library or Windows API is loaded."""
import importlib.util
from pathlib import Path
import struct
import unittest
ROOT=Path(__file__).resolve().parents[1]
s=importlib.util.spec_from_file_location('pure_psec_spec',ROOT/'.github/windows_identity_psec_spec.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
INPUTS=r'C:\Private\local-psec-lpac-identity-00000000000000000000000000000001\inputs'
class SpecTests(unittest.TestCase):
    def test_canonical_roundtrip_exact_path_no_proxy_peer_or_writable_tree(self):
        raw=m.build(INPUTS);v=m.verify(raw,INPUTS)
        self.assertEqual(v['variant'],m.VARIANT);self.assertEqual(v['schema_version'],[1,1])
        self.assertEqual(v['capabilities'],'privateNetworkClientServer');self.assertFalse(v['peer_present']);self.assertFalse(v['proxy_present'])
        self.assertEqual(raw,m.build(INPUTS));self.assertEqual(v['ingress'],'deny')
    def test_every_single_bit_corruption_rejected_including_padding(self):
        raw=m.build(INPUTS)
        for index in range(len(raw)*8):
            b=bytearray(raw);b[index//8]^=1<<(index%8)
            with self.subTest(bit=index),self.assertRaises((ValueError,UnicodeError,struct.error)):m.verify(bytes(b),INPUTS)
    def test_truncation_growth_wrong_path_and_untrusted_paths_rejected(self):
        raw=m.build(INPUTS)
        for b in (raw[:-1],raw+b'\0',b'PSEC',raw+raw):
            with self.assertRaises((ValueError,UnicodeError,struct.error)):m.verify(b,INPUTS)
        with self.assertRaises(ValueError):m.verify(raw,INPUTS+'x')
        for p in ('relative',r'\\host\share\inputs',r'C:\Private\..\inputs','C:\\Private\\inputs\\',r'C:/Private/inputs',r'C:\bad.\inputs'):
            with self.subTest(path=p),self.assertRaises(ValueError):m.build(p)
    def test_unknown_slot_and_allow_or_nonzero_ui_mutations_rejected(self):
        raw=m.build(INPUTS);r=m.Reader(raw);root=r.offset(0);fields=r.table(root,9)
        for at,value,fmt in ((fields[2],0,'<B'),(fields[3],0,'<Q'),(root-struct.unpack_from('<i',raw,root)[0],24,'<H')):
            b=bytearray(raw);struct.pack_into(fmt,b,at,value)
            with self.assertRaises(ValueError):m.verify(bytes(b),INPUTS)
if __name__=='__main__':unittest.main()
