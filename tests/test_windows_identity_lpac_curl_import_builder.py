"""Offline production builder tests; the fixed executable is read, never run.

No replacement binary or hash override is used. An unavailable/different fixed
fixture is explicitly skipped, not accepted as a different application. This
author run records its actual zero-skip result separately from future CI.
"""
import builtins
from dataclasses import FrozenInstanceError, fields
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
WORK=ROOT/'tests'/'fixtures'/'lpac-curl-a4'
spec=importlib.util.spec_from_file_location('curl_import_offline_test',ROOT/'.github/windows_identity_lpac_curl_import_builder.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
BASE=0x180000000
PRIVATE=r'C:\Owned Package\package\windows_identity_lpac_curl_ws2_shim.dll'


class OfflineImportBuilderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture=Path('C:/Windows/System32/curl.exe')
        if not fixture.is_file():raise unittest.SkipTest('fixed System32 curl PE fixture absent; no substitution')
        cls.image=fixture.read_bytes()
        if len(cls.image)!=m.CURL_BYTES or hashlib.sha256(cls.image).hexdigest()!=m.CURL_SHA256:
            raise unittest.SkipTest('installed curl differs from the declared fixed PE; no substitution')
        cls.transcript=json.loads((WORK/'lpac-curl-A4-fixed-PE-import-transcript-03.json').read_bytes())
        cls.manifest=json.loads((WORK/'lpac-curl-A4-export-manifest-proposal-03.json').read_bytes())
        cls.pe=m.verify_fixed_pe(cls.image)

    def reject(self,image,code=None):
        with self.assertRaises(m.BuilderError) as cm:m.verify_fixed_pe(image)
        if code is not None:self.assertIs(cm.exception.code,code)

    def mutate(self,offset,fmt,value):
        raw=bytearray(self.image);struct.pack_into(fmt,raw,offset,value);return bytes(raw)

    def sample(self):
        p=m.build_import_patch(self.image,BASE,PRIVATE)
        return p,dict(header=p.expected_header,arena=p.arena,old_descriptors=p.original_tables.descriptors,
            old_lookup_tables=p.original_tables.lookup_tables,old_IAT_tables=p.original_tables.IAT_tables)

    def test_fixed_raw_geometry_and_every_original_table_match_independent_transcript(self):
        self.assertEqual((self.pe.image_bytes,self.pe.image_sha256,self.pe.descriptor_count),(818512,m.CURL_SHA256,42))
        self.assertEqual(self.pe.preferred_image_base,0x140000000)
        self.assertEqual(self.pe.import_count,sum(len(r['imports']) for r in self.transcript['descriptors']))
        for index,row in enumerate(self.transcript['descriptors']):
            with self.subTest(module=row['name']):
                table=self.pe.original_tables.lookup_tables[index]
                self.assertEqual(table,self.pe.original_tables.IAT_tables[index])
                self.assertEqual(hashlib.sha256(table).hexdigest(),row['lookup_sha256'])
                self.assertEqual(len(table),(len(row['imports'])+1)*8)
                self.assertEqual(table[-8:],bytes(8))
        self.assertEqual(hashlib.sha256(self.pe.original_tables.descriptors).hexdigest(),self.transcript['descriptor_array_sha256'])

    def test_arena_has_exact_two_name_fields_and_original_iat_is_not_rebuilt(self):
        p=m.build_import_patch(self.image,BASE,PRIVATE);old=self.pe.original_tables.descriptors
        self.assertEqual(len(p.arena),4096);self.assertEqual(p.metadata.arena_address,BASE+0xD0000)
        self.assertEqual((p.metadata.replaced_indices,p.metadata.descriptor_count),((0,10),42))
        changed=set()
        for i in range(42):
            actual=p.arena[i*20:(i+1)*20]
            if i in (0,10):
                expected=bytearray(old[i*20:(i+1)*20]);struct.pack_into('<I',expected,12,0xD0000+864)
                self.assertEqual(actual,bytes(expected));changed.add(i)
            else:self.assertEqual(actual,old[i*20:(i+1)*20])
        self.assertEqual(changed,{0,10});self.assertEqual(p.arena[840:864],bytes(24))
        encoded=PRIVATE.encode('ascii');self.assertEqual(p.arena[864:864+len(encoded)+1],encoded+b'\0')
        self.assertEqual(p.arena[864+len(encoded)+1:],bytes(4096-864-len(encoded)-1))
        self.assertEqual(p.original_tables,self.pe.original_tables)

    def test_only_four_byte_import_rva_header_range_can_change(self):
        p=m.build_import_patch(self.image,BASE,PRIVATE);header=self.image[:1024]
        changed={i for i,(a,b) in enumerate(zip(header,p.expected_header)) if a!=b}
        self.assertTrue(changed);self.assertLessEqual(changed,set(range(400,404)))
        self.assertEqual(p.header_patch,struct.pack('<I',0xD0000));self.assertEqual(p.expected_header[404:408],struct.pack('<I',860))
        self.assertEqual(p.expected_header[:400]+p.expected_header[404:],header[:400]+header[404:])
        self.assertEqual(hashlib.sha256(self.image).hexdigest(),m.CURL_SHA256)

    def test_aslr_base_is_input_not_preferred_base_and_uint64_bounds_are_strict(self):
        for actual in (0x10000,0x140000000,0x7FF600000000):
            with self.subTest(actual=actual):self.assertEqual(m.build_import_patch(self.image,actual,PRIVATE).metadata.arena_address,actual+0xD0000)
        for bad in (None,True,False,1.0,'65536',0,-65536,1,65535,65537,1<<64,m.MAX_U64&~65535):
            with self.subTest(bad=bad),self.assertRaises(m.BuilderError) as cm:m.build_import_patch(self.image,bad,PRIVATE)
            self.assertIs(cm.exception.code,m.RejectCode.BASE)
        last=((m.MAX_U64-m.ARENA_RVA-m.ARENA_BYTES)//65536)*65536
        self.assertLessEqual(m.build_import_patch(self.image,last,PRIVATE).metadata.arena_address+4096,m.MAX_U64)

    def test_private_ascii_path_is_canonical_literal_and_length_bound(self):
        for path in (PRIVATE,'c:\\'+m.PRIVATE_BASENAME):
            self.assertEqual(m.build_import_patch(self.image,BASE,path).metadata.private_path_bytes,len(path))
        path='C:\\'+('a'*(1023-4-len(m.PRIVATE_BASENAME)))+'\\'+m.PRIVATE_BASENAME
        result=m.build_import_patch(self.image,BASE,path);self.assertEqual(len(path),1023);self.assertEqual(result.metadata.arena_used,1888)
        bad=[None,PRIVATE.encode(),True,'',PRIVATE+'x','C:\\'+m.PRIVATE_BASENAME.upper(),
            '\\\\server\\share\\'+m.PRIVATE_BASENAME,'\\\\?\\C:\\'+m.PRIVATE_BASENAME,'\\\\.\\C:\\'+m.PRIVATE_BASENAME,
            'C:'+m.PRIVATE_BASENAME,'C:/package/'+m.PRIVATE_BASENAME,'C:\\..\\'+m.PRIVATE_BASENAME,
            'C:\\.\\'+m.PRIVATE_BASENAME,'C:\\x\\\\'+m.PRIVATE_BASENAME,'C:\\NUL\\'+m.PRIVATE_BASENAME,
            'C:\\x.\\'+m.PRIVATE_BASENAME,'C:\\x \\'+m.PRIVATE_BASENAME,'C:\\x:stream\\'+m.PRIVATE_BASENAME,
            'C:\\中文\\'+m.PRIVATE_BASENAME,'C:\\x\0\\'+m.PRIVATE_BASENAME,path+'x']
        for value in bad:
            with self.subTest(value=value),self.assertRaises(m.BuilderError) as cm:m.build_import_patch(self.image,BASE,value)
            self.assertIs(cm.exception.code,m.RejectCode.PATH)

    def test_wrong_image_type_length_and_non_structural_hash_tamper_reject(self):
        for image in (None,bytearray(self.image),memoryview(self.image),self.image.decode('latin1')):
            with self.subTest(kind=type(image).__name__):self.reject(image,m.RejectCode.TYPE)
        self.reject(self.image[:-1],m.RejectCode.LENGTH);self.reject(self.image+b'\0',m.RejectCode.LENGTH)
        raw=bytearray(self.image);raw[-1]^=1;self.reject(bytes(raw),m.RejectCode.HASH)

    def test_header_sections_directories_and_nonzero_bound_delay_are_not_repaired(self):
        cases=[(60,'<I',0xffffffff,m.RejectCode.DOS),(260,'<H',0x14c,m.RejectCode.COFF),
            (262,'<H',8,m.RejectCode.COFF),(276,'<H',224,m.RejectCode.COFF),(280,'<H',0x10b,m.RejectCode.OPTIONAL),
            (304,'<Q',0x180000000,m.RejectCode.OPTIONAL),(336,'<I',827393,m.RejectCode.OPTIONAL),
            (340,'<I',1025,m.RejectCode.OPTIONAL),(388,'<I',17,m.RejectCode.OPTIONAL),
            (400,'<I',777209,m.RejectCode.DIRECTORY),(404,'<I',880,m.RejectCode.DIRECTORY),
            (480,'<I',1,m.RejectCode.DIRECTORY),(484,'<I',1,m.RejectCode.DIRECTORY),
            (488,'<I',593928,m.RejectCode.DIRECTORY),(492,'<I',2240,m.RejectCode.DIRECTORY),
            (496,'<I',1,m.RejectCode.DIRECTORY),(500,'<I',1,m.RejectCode.DIRECTORY)]
        for offset,fmt,value,code in cases:
            with self.subTest(offset=offset):self.reject(self.mutate(offset,fmt,value),code)
        for i in range(len(self.transcript['sections'])):
            with self.subTest(section=i):self.reject(self.mutate(520+i*40+20,'<I',0xffffffff),m.RejectCode.SECTION)

    def test_every_descriptor_and_module_name_is_checked_before_acceptance(self):
        for row in self.transcript['descriptors']:
            at=m._rva_offset(row['descriptor_rva'],20)
            with self.subTest(module=row['name'],part='descriptor'):self.reject(self.mutate(at+12,'<I',row['name_rva']+1),m.RejectCode.DESCRIPTOR)
            name_at=m._rva_offset(row['name_rva'],1);raw=bytearray(self.image);raw[name_at]^=1
            with self.subTest(module=row['name'],part='name'):self.reject(bytes(raw),m.RejectCode.STRING)
        end=m._rva_offset(m.IMPORT_RVA,m.IMPORT_BYTES)+840
        self.reject(self.mutate(end,'<I',1),m.RejectCode.DESCRIPTOR)

    def test_every_old_lookup_iat_entry_and_terminator_is_bound(self):
        for row in self.transcript['descriptors']:
            for field,code in (('original_first_thunk',m.RejectCode.LOOKUP),('first_thunk',m.RejectCode.IAT)):
                at=m._rva_offset(row[field],row['lookup_bytes'])
                for slot in (0,len(row['imports'])):
                    raw=bytearray(self.image);raw[at+slot*8]^=1
                    with self.subTest(module=row['name'],field=field,slot=slot):self.reject(bytes(raw),code)
        row=self.transcript['descriptors'][0];symbol=next(x for x in row['imports'] if 'name' in x)
        self.reject(self.mutate(m._rva_offset(symbol['original_thunk'],2),'<H',symbol['hint']+1),m.RejectCode.LOOKUP)
        raw=bytearray(self.image);raw[m._rva_offset(symbol['original_thunk']+2,1)]^=1;self.reject(bytes(raw),m.RejectCode.STRING)

    def test_readback_model_verifies_bytes_but_never_claims_process_observation(self):
        p,s=self.sample();view=m.verify_readback_model(self.image,BASE,PRIVATE,**s)
        self.assertTrue(view.readback_bytes_match);self.assertFalse(view.actual_process_observed or view.remote_mutation_performed or view.loader_accepted)
        mutations=[('header',bytes(1024)),('arena',p.arena[:-1]+b'X'),('old_descriptors',bytes(860)),
            ('old_lookup_tables',list(s['old_lookup_tables'])),('old_IAT_tables',()),('old_lookup_tables',(b'',)*42)]
        for key,value in mutations:
            changed=dict(s);changed[key]=value
            with self.subTest(key=key),self.assertRaises(m.BuilderError) as cm:m.verify_readback_model(self.image,BASE,PRIVATE,**changed)
            self.assertIs(cm.exception.code,m.RejectCode.READBACK)
        arena=bytearray(p.arena);arena[12]^=1;changed=dict(s,arena=bytes(arena))
        with self.assertRaises(m.BuilderError):m.verify_readback_model(self.image,BASE,PRIVATE,**changed)

    def test_output_is_deeply_immutable_and_closed_typed_metadata(self):
        p=m.build_import_patch(self.image,BASE,PRIVATE)
        self.assertEqual({x.name for x in fields(p)},{'arena','header_patch','expected_header','original_tables','metadata'})
        self.assertIs(type(p.arena),bytes);self.assertIs(type(p.original_tables.lookup_tables),tuple)
        with self.assertRaises(FrozenInstanceError):p.metadata.actual_ready=True
        with self.assertRaises(FrozenInstanceError):p.arena=b''
        with self.assertRaises(TypeError):p.arena[0]=0
        self.assertFalse(p.metadata.actual_ready or p.metadata.remote_mutation_performed or p.metadata.actual_process_observed
            or p.metadata.owned_private_path_verified or p.metadata.loader_accepted)
        self.assertTrue(m.OFFLINE_IMPLEMENTATION_AUTHORIZED);self.assertFalse(m.ACTUAL_READY)

    def test_production_functions_do_not_open_files_or_query_external_state(self):
        with (patch.object(builtins,'open',side_effect=AssertionError('production file IO forbidden')) as a,
              patch.object(io,'open',side_effect=AssertionError('production file IO forbidden')) as b):
            p=m.build_import_patch(self.image,BASE,PRIVATE)
            m.verify_readback_model(self.image,BASE,PRIVATE,header=p.expected_header,arena=p.arena,
                old_descriptors=p.original_tables.descriptors,old_lookup_tables=p.original_tables.lookup_tables,old_IAT_tables=p.original_tables.IAT_tables)
        a.assert_not_called();b.assert_not_called()

    def test_exact_40_export_source_manifest_is_data_not_a_built_shim(self):
        actual=tuple((x['name'],x['ordinal'],x['kind'],x['forward_to'],x['dynamic_ordinal_accepted'])
            for x in sorted(self.manifest['exports'],key=lambda x:x['ordinal']))
        self.assertEqual(m.EXPECTED_EXPORTS,actual);self.assertEqual(len(actual),40)
        self.assertEqual(len({x[0] for x in actual}),40);self.assertEqual(len({x[1] for x in actual}),40)
        self.assertEqual([x[0] for x in actual if x[3] is not None],['GetModuleFileNameA'])
        self.assertEqual(sum(x[2]=='private-gateway' for x in actual),4)
        self.assertTrue(all(not x['implemented'] for x in self.manifest['exports']))


if __name__=='__main__':unittest.main()
