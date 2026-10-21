"""Opt-in hosted Windows REQUEST3 mechanism gate; never isolation acceptance.

One 60-second absolute budget bounds caller waits, not broker cancellation or
uninterruptible OS operations. Unknown owned cleanup retains private work.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent
MAX_REPORT = 4096
BUDGET = 60
NRPT_SCRIPT = "$ErrorActionPreference='Stop'; try { $p=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Select-Object -First 1); if($p.Count -eq 0){[Console]::Write('NRPT_EMPTY')}else{[Console]::Write('NRPT_PRESENT')} } catch { exit 2 }"


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise ValueError('duplicate')
        result[key] = value
    return result


def decode(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REPORT: raise ValueError('bound')
    try: return json.loads(raw.decode('ascii'), object_pairs_hook=unique)
    except (UnicodeError, RecursionError, json.JSONDecodeError) as exc: raise ValueError('json') from exc


def integer(value, lo, hi):
    return type(value) is int and lo <= value <= hi


def native_report(raw):
    value = decode(raw)
    fixed = dict(schema=1, test_only=True, request_version=3, custom_server_count=1,
                 custom_udp=True, custom_flags_zero=True, legacy_server_list_null=True,
                 callback_null=True, runtime_acceptance=False)
    booleans = ('api_called','pending','answer_match','records_freed','context_retained')
    if type(value) is not dict or set(value) != set(fixed) | set(booleans) | {'api_status','result_status','record_count'}:
        raise ValueError('schema')
    for key, expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key] != expected: raise ValueError('fixed')
    if any(type(value[key]) is not bool for key in booleans): raise ValueError('type')
    if not integer(value['api_status'],0,2**32-1): raise ValueError('status')
    for key, maximum in [('result_status',2**32-1),('record_count',17)]:
        if value[key] is not None and not integer(value[key],0,maximum): raise ValueError('type')
    if value['pending']:
        if value['api_status'] != 9506 or value['result_status'] is not None or value['record_count'] is not None or not value['context_retained'] or value['records_freed'] or value['answer_match']:
            raise ValueError('pending')
    elif value['result_status'] is None or value['record_count'] is None or value['context_retained']:
        raise ValueError('completed')
    return value


def verify(actor, manifest):
    if actor.name != 'windows_n0a_DNS_TEST_ONLY_fixture.exe' or manifest.name != 'DNS-TEST-ONLY-manifest.json': raise ValueError('artifact')
    value = decode(read_bounded(manifest))
    fixed = dict(schemaVersion=1,testOnly=True,deployable=False,compileOnly=True,requestVersion=3,customServerType='UDP')
    if type(value) is not dict or set(value) != set(fixed)|{'installedSdkVersion','sourceSha256','sdkHeaders','executableSha256'}: raise ValueError('manifest')
    for key, expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key] != expected: raise ValueError('manifest')
    if type(value['installedSdkVersion']) is not str or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+',value['installedSdkVersion']): raise ValueError('sdk')
    headers = value['sdkHeaders']
    if type(headers) is not list or len(headers)!=3: raise ValueError('headers')
    if {item.get('name') for item in headers if type(item) is dict} != {'windns.h','windnsdef.h','ws2ipdef.h'}: raise ValueError('headers')
    for item in headers:
        if type(item) is not dict or set(item)!={'name','sha256'} or type(item['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',item['sha256']): raise ValueError('headers')
    for key,path in [('sourceSha256',ROOT/'native/windows_n0a_dns_fixture.cpp'),('executableSha256',actor)]:
        if type(value[key]) is not str or not re.fullmatch('[0-9a-f]{64}',value[key]) or not path.is_file() or path.is_symlink() or path.stat().st_size>16*1024*1024 or hashlib.sha256(path.read_bytes()).hexdigest()!=value[key]: raise ValueError('pin')
    return True


def read_bounded(path):
    with path.open('rb') as stream: raw=stream.read(MAX_REPORT+1)
    if len(raw)>MAX_REPORT: raise ValueError('output_bound')
    return raw


class Child:
    def __init__(self, root, name):
        self.path=root/(name+'.out'); self.stream=None; self.process=None; self.closed=False
    def start(self, argv):
        self.stream=self.path.open('xb')
        self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=self.stream,stderr=subprocess.DEVNULL,close_fds=True)
    def wait(self, deadline, *, pending=False):
        while time.monotonic()<deadline:
            if self.path.stat().st_size>MAX_REPORT: raise ValueError('output_bound')
            if self.process.poll() is not None: return True
            if pending:
                raw=read_bounded(self.path)
                if raw.endswith(b'\n'):
                    value=native_report(raw)
                    if value['pending'] and not value['api_called']: return False
            time.sleep(min(.02,max(0,deadline-time.monotonic())))
        return False
    def finish(self, deadline):
        exited=self.process is None; killed=False; observation_ok=True
        if self.process is not None:
            try: exited=self.process.poll() is not None
            except Exception: exited=False; observation_ok=False
            if not exited:
                killed=True
                try: self.process.kill()
                except Exception: observation_ok=False
                try: self.process.wait(timeout=max(0,deadline-time.monotonic()))
                except Exception: observation_ok=False
                try: exited=self.process.poll() is not None
                except Exception: exited=False; observation_ok=False
        close_ok=True
        if self.stream is not None:
            try:self.stream.close()
            except Exception:close_ok=False
        if exited and self.process is not None and hasattr(self.process,'_handle'):
            try:self.process._handle.Close()
            except Exception:close_ok=False
        self.closed=exited and close_ok and observation_ok
        return dict(exited=exited,killed=killed,handles_closed=close_ok and exited,cleanup_confirmed=self.closed)


def run(actor, manifest):
    deadline=time.monotonic()+BUDGET
    result=dict(schema=1,mechanism_positive=False,injected_pending_control=False,
                nrpt_empty=False,query_observed=False,api_report=None,fixture=None,
                cleanup_confirmed=False,work_removed=False,failure='none',
                runtime_acceptance=False,isolation_tested=False,broker_cancellation_proven=False)
    root=None; fixture=None; children=[]; cleanup=[]
    try:
        if os.name!='nt': raise ValueError('platform')
        verify(actor,manifest)
        root=Path(tempfile.mkdtemp(prefix='dns-request3-'))
        nrpt=Child(root,'nrpt');children.append(nrpt)
        nrpt.start(['powershell.exe','-NoProfile','-NonInteractive','-Command',NRPT_SCRIPT])
        if not nrpt.wait(min(deadline-10,time.monotonic()+5)) or nrpt.process.returncode!=0 or read_bounded(nrpt.path)!=b'NRPT_EMPTY': raise ValueError('nrpt')
        result['nrpt_empty']=True
        spec=importlib.util.spec_from_file_location('owned_dns_fixture',ROOT/'windows_dns_fixture.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        nonce=secrets.token_hex(16);fixture=module.DnsFixture(nonce,deadline=deadline)
        port=fixture.start()
        child=Child(root,'query');children.append(child)
        child.start([str(actor),'--query',nonce,str(port)])
        ended=child.wait(min(deadline-10,time.monotonic()+30))
        report=native_report(read_bounded(child.path));result['api_report']=report
        positive=ended and child.process.returncode==0 and report['api_called'] and not report['pending'] and report['api_status']==0 and report['result_status']==0 and report['record_count']==1 and report['answer_match'] and report['records_freed']
        if not ended: raise ValueError('query_timeout')
        pending=Child(root,'pending');children.append(pending)
        pending.start([str(actor),'--test-pending'])
        pending.wait(min(deadline-10,time.monotonic()+3),pending=True)
        pending_report=native_report(read_bounded(pending.path))
        result['injected_pending_control']=pending.process.poll() is None and pending_report['pending'] and not pending_report['api_called'] and pending_report['context_retained']
        result['mechanism_positive']=positive
    except Exception as exc:
        allowed={'platform','nrpt','query_timeout','output_bound','artifact','manifest','pin','sdk','headers'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        for child in reversed(children):
            try: cleanup.append(child.finish(deadline))
            except Exception: cleanup.append(dict(exited=False,killed=False,handles_closed=False,cleanup_confirmed=False))
        result['children_cleanup']=cleanup
        if fixture is not None:
            try: result['fixture']=fixture.finish(deadline=deadline)
            except Exception: result['fixture']=dict(cleanup_confirmed=False,counts=None,error='operation')
            result['query_observed']=fixture.query_observed.is_set()
        clean=all(item['cleanup_confirmed'] for item in cleanup) and (fixture is None or result['fixture']['cleanup_confirmed'])
        result['cleanup_confirmed']=clean
        if root is not None and clean:
            try:shutil.rmtree(root);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        counts=(result['fixture'] or {}).get('counts')
        clean_fixture=counts is not None and counts['matched_queries']>0 and counts['answers_sent']>0 and all(counts[key]==0 for key in ('rejected','oversized','send_failed')) and result['fixture']['error']=='none'
        result['mechanism_positive']=result['mechanism_positive'] and clean_fixture and result['injected_pending_control'] and result['cleanup_confirmed'] and result['work_removed']
        result['injected_pending_control']=result['injected_pending_control'] and result['cleanup_confirmed']
    return result


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--run-actual-windows',action='store_true')
    parser.add_argument('--actor',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if not args.run_actual_windows:parser.error('explicit opt-in required')
    try:
        result=run(args.actor.resolve(),args.manifest.resolve())
        raw=json.dumps(result,sort_keys=True,separators=(',',':'))
        args.output.write_text(raw+'\n',encoding='ascii');print(raw)
        return 0 if result['mechanism_positive'] else 1
    except Exception:
        print('{"schema":1,"failure":"output","mechanism_positive":false,"runtime_acceptance":false}')
        return 1

if __name__=='__main__':raise SystemExit(main())
