"""Closed publication projections; raw native evidence remains runner-local."""
from __future__ import annotations
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('identity_publication_paths',Path(__file__).with_name('windows_identity_ordinary_launcher.py'))
ordinary=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(ordinary)
DIGEST=re.compile(r'[0-9a-f]{64}\Z')
STAGES={'ordinary-token-preflight','ordinary-user-stage0b-launcher','R0-restricted-source-token-preflight','R0-restricted-caller-native-identity'}
BOOLS=('preflight_only','process_created','profile_created','appcontainer_created','derived_token_created','acl_changed','network_tested','observations_complete','parent_token_unchanged','restricted_caller_r0_passed','stage0b_passed','launcher_passed','ordinary_user_acceptance','product_acceptance','psec_acceptance','privacy_qualified','actor_matches_native_parent_observation','nested_resource_cleanup_incomplete')
CLEANUP=('token_handles_closed','source_token_closed','derived_token_closed','job_closed','job_empty','handles_closed','process_exit_confirmed','owned_aces_removed','profile_deleted')
FIELDS={'sid','session_id','token_type','elevation_type','elevated','integrity_rid','groups','appcontainer','appcontainer_sid','capabilities','ui_access','privileges','authentication_luid','has_restrictions','sandbox_inert','restricted_sids','logon_sids','user_attributes'}
QUERIES={'TokenUser','TokenSessionId','TokenType','TokenElevationType','TokenElevation','TokenIntegrityLevel','TokenGroups','TokenIsAppContainer','TokenAppContainerSid','TokenCapabilities','TokenUIAccess','TokenPrivileges','TokenStatistics','TokenHasRestrictions','TokenSandBoxInert','TokenRestrictedSids','TokenLogonSid','TokenLinkedToken'}
OPERATIONS={'GetTokenInformation('+x+')' for x in QUERIES}|{'CreateRestrictedToken','CreateProcessAsUserW','CreateProcessW','OpenProcessToken','OpenProcessToken(restricted_source)','SetTokenInformation(new_token_medium_integrity)','CloseHandle','ResumeThread','TerminateJobObject','TerminateProcess','QueryInformationJobObject','AssignProcessToJobObject','QueryFullProcessImageNameW','LookupPrivilegeNameW','invariant','launcher','native_abi'}

def booleans(value,names):
    return {k:value[k] for k in names if type(value.get(k)) is bool}

def error_projection(value):
    if not isinstance(value,dict):return {'operation':'unclassified_error'}
    result={'operation':value.get('operation') if value.get('operation') in OPERATIONS else 'unclassified_error'}
    for key in ('winerror','token_information_class','capacity','expected_size','returned_size'):
        item=value.get(key)
        if type(item) is int and 0<=item<=0xffffffff:result[key]=item
    return result

def cleanup_projection(value):
    if not isinstance(value,dict):return {}
    result=booleans(value,CLEANUP)
    errors=value.get('errors',[])
    if isinstance(errors,list):
        result['error_count']=len(errors)
        result['errors']=[error_projection(x) for x in errors[:16]]
    return result

def project(value,source_sha256,*,build=False):
    if not isinstance(value,dict) or not DIGEST.fullmatch(source_sha256):raise ValueError('invalid projection input')
    result={'schema_version':1,'sanitized':True,'byte_exact':False,'source_report_sha256':source_sha256}
    if build:
        result['stage']='native-build-public-metadata'
        for key in ('sourceSha256','executableSha256'):
            item=value.get(key)
            if isinstance(item,str) and DIGEST.fullmatch(item):result[key]=item
            else:raise ValueError('missing build digest')
        result.update(booleans(value,('httpCompiled','staticCrt','compileOnly')))
        if value.get('targetArchitecture') in ('x64','x86','arm64'):result['targetArchitecture']=value['targetArchitecture']
        return result
    result['stage']=value.get('stage') if value.get('stage') in STAGES else 'unclassified-native-experiment'
    result.update(booleans(value,BOOLS))
    for key in ('actor_sha256',):
        item=value.get(key)
        if isinstance(item,str) and DIGEST.fullmatch(item):result[key]=item
    if 'error' in value:result['error']=error_projection(value['error'])
    result['cleanup']=cleanup_projection(value.get('cleanup',{}))
    current=value.get('current')
    if isinstance(current,dict):
        known={k:v for k,v in current.items() if k in FIELDS and isinstance(v,dict)}
        result['observed_field_count']=len(known)
        result['successful_field_count']=sum(v.get('ok') is True for v in known.values())
        result['fields']={}
        for name,entry in known.items():
            item=booleans(entry,('ok',))
            if 'error' in entry:item['error']=error_projection(entry['error'])
            query=entry.get('native_query')
            if isinstance(query,dict):
                item['native_query']=error_projection(query)
                item['native_query'].update(booleans(query,('native_success',)))
            result['fields'][name]=item
    launch=value.get('launch')
    if isinstance(launch,dict):
        result['launch']=booleans(launch,('started','resumed','timed_out','native_verified_before_resume','native_identity_verified_before_resume','job_created','assigned_to_owned_job'))
        if type(launch.get('exit_code')) is int and 0<=launch['exit_code']<=0xffffffff:result['launch']['exit_code']=launch['exit_code']
        if 'error' in launch:result['launch']['error']=error_projection(launch['error'])
        result['launch']['cleanup']=cleanup_projection(launch.get('cleanup',{}))
    return result

def project_imports(value,source_sha256):
    if not isinstance(value,dict) or not DIGEST.fullmatch(source_sha256):raise ValueError('invalid import projection input')
    result={'schema_version':1,'stage':'native-import-public-metadata','sanitized':True,'byte_exact':False,'source_report_sha256':source_sha256}
    for name in ('full','identity_only','system_winhttp'):
        entries=value.get(name)
        if not isinstance(entries,list) or not 1<=len(entries)<=64:raise ValueError('bounded DLL list required')
        if not all(isinstance(x,str) and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}\.dll',x,re.I) for x in entries):raise ValueError('DLL basenames only')
        result[name]=entries
    for name in ('full_import_table','identity_only_import_table'):
        entries=value.get(name)
        if not isinstance(entries,list) or len(entries)>2048 or not all(isinstance(x,str) and len(x)<=512 for x in entries):raise ValueError('bounded import table required')
        result[name+'_sha256']=hashlib.sha256(json.dumps(entries,ensure_ascii=True).encode('ascii')).hexdigest()
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--build',action='store_true')
    parser.add_argument('--imports',action='store_true')
    args=parser.parse_args(argv)
    root=ordinary.checked_path(ROOT,is_file=False)
    source=ordinary.checked_path(args.input,inside=root)
    output=args.output.absolute();parent=ordinary.checked_path(output.parent,inside=root,is_file=False);output=parent/output.name
    if output.exists() or output.is_symlink():raise ValueError('fresh publication path required')
    with source.open('rb') as stream:data=stream.read(ordinary.MAX_REPORT+1)
    if len(data)>ordinary.MAX_REPORT:raise ValueError('bounded publication input required')
    if args.build and args.imports:raise ValueError('one projection mode only')
    digest=hashlib.sha256(data).hexdigest()
    result=(project_imports(json.loads(data),digest) if args.imports else project(json.loads(data),digest,build=args.build))
    ordinary.save_report(output,result)
    return 0

if __name__=='__main__':raise SystemExit(main())
