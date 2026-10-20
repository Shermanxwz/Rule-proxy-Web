import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
P=Path(__file__).resolve().parents[1]/'.github/windows_identity_publication.py'
S=importlib.util.spec_from_file_location('publication_test',P);m=importlib.util.module_from_spec(S);S.loader.exec_module(m)
H='a'*64
class PublicationTests(unittest.TestCase):
    def test_private_and_unknown_fields_never_export(self):
        secret='PRIVATE_SENTINEL_123'
        v={'stage':'R0-restricted-caller-native-identity','sid':secret,'hostname':secret,'nonce':secret,'parent_identity':{'privileges':[secret]},'launch':{'child_pid':22,'child_identity':secret,'exit_code':3221225794,'resumed':True},'error':{'operation':secret,'reason':secret,'winerror':5},'cleanup':{'handles_closed':True,'errors':[]},'unrecognized':secret}
        out=m.project(v,H);text=json.dumps(out)
        self.assertNotIn(secret,text);self.assertNotIn('child_pid',text);self.assertTrue(out['sanitized']);self.assertFalse(out['byte_exact']);self.assertEqual(out['launch']['exit_code'],3221225794)
    def test_field_values_are_omitted_but_abi_sizes_preserved(self):
        v={'current':{'sid':{'ok':True,'value':'S-1-5-21-PRIVATE'},'has_restrictions':{'ok':True,'value':False,'native_query':{'operation':'GetTokenInformation(TokenHasRestrictions)','expected_size':1,'returned_size':1,'native_success':True}},'PRIVATE':{'ok':True}}}
        out=m.project(v,H);self.assertNotIn('PRIVATE',json.dumps(out));self.assertEqual(out['observed_field_count'],2);self.assertEqual(out['fields']['has_restrictions']['native_query']['returned_size'],1)
    def test_build_projection_has_no_paths_arguments_or_time(self):
        v={'sourceSha256':H,'executableSha256':'b'*64,'sourcePath':'PRIVATE','compilerPath':'PRIVATE','compilerArguments':['PRIVATE'],'builtAtUtc':'PRIVATE','httpCompiled':False,'staticCrt':True,'compileOnly':True,'targetArchitecture':'x64'}
        out=m.project(v,H,build=True);self.assertNotIn('PRIVATE',json.dumps(out));self.assertFalse(out['httpCompiled'])
    def test_build_requires_real_digest_shape(self):
        with self.assertRaises(ValueError):m.project({'sourceSha256':'private'},H,build=True)
    def test_untrusted_boolean_and_error_text_not_exported(self):
        out=m.project({'stage':'PRIVATE','stage0b_passed':'PRIVATE','error':{'operation':'PRIVATE','winerror':'PRIVATE'}},H)
        self.assertNotIn('PRIVATE',json.dumps(out));self.assertNotIn('stage0b_passed',out)
    def test_import_projection_excludes_raw_lines_and_machine_version(self):
        v={'full':['KERNEL32.dll','WINHTTP.dll'],'identity_only':['KERNEL32.dll'],'system_winhttp':['USER32.dll'],'full_import_table':['PRIVATE_PATH'],'identity_only_import_table':['PRIVATE_PATH'],'system_winhttp_file_version':'PRIVATE_VERSION'}
        out=m.project_imports(v,H);self.assertNotIn('PRIVATE',json.dumps(out));self.assertEqual(out['system_winhttp'],['USER32.dll'])
        v['full']=['C:\\PRIVATE.dll']
        with self.assertRaises(ValueError):m.project_imports(v,H)
if __name__=='__main__':unittest.main()
