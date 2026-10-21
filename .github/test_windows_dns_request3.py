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
import sys
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
    booleans = ('api_called','pending','answer_match','records_freed','context_retained','cancellation_handle_null','custom_port53')
    if type(value) is not dict or set(value) != set(fixed) | set(booleans) | {'api_status','result_status','record_count','endpoint_kind'}:
        raise ValueError('schema')
    for key, expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key] != expected: raise ValueError('fixed')
    if any(type(value[key]) is not bool for key in booleans): raise ValueError('type')
    if type(value['endpoint_kind']) is not str or value['endpoint_kind'] not in ('high_port','standard_port','none') or value['custom_port53'] is not (value['endpoint_kind']=='standard_port'):raise ValueError('endpoint')
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
    if type(headers) is not list or len(headers)!=4: raise ValueError('headers')
    if {item.get('name') for item in headers if type(item) is dict} != {'windns.h','windnsdef.h','ws2ipdef.h','ws2tcpip.h'}: raise ValueError('headers')
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
                nrpt_empty=False,query_observed=False,cases={},os_version=None,
                receiver_attribution='temporal_deltas_shared_nonce_not_broker_identity',
                cleanup_confirmed=False,work_removed=False,failure='none',
                runtime_acceptance=False,isolation_tested=False,broker_cancellation_proven=False)
    root=None; children=[]; fixtures=[]; cleanup=[]; finished=set(); fixture=None
    def stop_child(child):
        if id(child) in finished:return
        finished.add(id(child))
        try:cleanup.append(child.finish(deadline))
        except Exception:cleanup.append(dict(exited=False,killed=False,handles_closed=False,cleanup_confirmed=False))
    def stop_fixture(fixture):
        try:return fixture.finish(deadline=deadline)
        except Exception:return dict(cleanup_confirmed=False,counts=None,error='operation')
    try:
        if os.name!='nt':raise ValueError('platform')
        if hasattr(sys,'getwindowsversion'):
            version=sys.getwindowsversion()
            result['os_version']={key:int(getattr(version,key)) for key in ('major','minor','build')}
        verify(actor,manifest)
        root=Path(tempfile.mkdtemp(prefix='dns-request3-'))
        nrpt=Child(root,'nrpt');children.append(nrpt)
        nrpt.start(['powershell.exe','-NoProfile','-NonInteractive','-Command',NRPT_SCRIPT])
        if not nrpt.wait(min(deadline-10,time.monotonic()+5)) or nrpt.process.returncode!=0 or read_bounded(nrpt.path)!=b'NRPT_EMPTY':raise ValueError('nrpt')
        result['nrpt_empty']=True;stop_child(nrpt)
        spec=importlib.util.spec_from_file_location('owned_dns_fixture',ROOT/'windows_dns_fixture.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        nonce=secrets.token_hex(16);fixture=module.DnsFixture(nonce,deadline=deadline)
        fixtures.append(fixture);port=fixture.start()
        for name,flag,is_null in [('baseline','--query',False),('null_cancel','--query-null-cancel',True)]:
            case=dict(api_report=None,query_observed=False,positive=False,failure='none')
            result['cases'][name]=case;child=None;cleanup_start=len(cleanup)
            before=fixture.snapshot(deadline=deadline-10);case['receiver_before']=before;completed=False
            try:
                if time.monotonic()>=deadline-10:raise ValueError('query_timeout')
                child=Child(root,name);children.append(child)
                child.start([str(actor),flag,nonce,str(port)])
                ended=child.wait(min(deadline-10,time.monotonic()+15))
                report=native_report(read_bounded(child.path));case['api_report']=report
                if report['cancellation_handle_null'] is not is_null:raise ValueError('case_binding')
                case['positive']=ended and child.process.returncode==0 and report['api_called'] and not report['pending'] and report['api_status']==0 and report['result_status']==0 and report['record_count']==1 and report['answer_match'] and report['records_freed']
                if not ended:raise ValueError('query_timeout')
                completed=child.process.returncode==0 and not report['pending']
            except Exception as exc:
                case['failure']=str(exc) if type(exc) is ValueError and str(exc) in ('query_timeout','output_bound','case_binding') else 'operation'
            finally:
                if child is not None:stop_child(child)
                after=fixture.snapshot(deadline=deadline-10);case['receiver_after']=after
                counts={key:after[key]-before[key] for key in before}
                case['receiver_delta']=counts;case['query_observed']=counts['matched_queries']>0
                case['child_cleanup']=cleanup[cleanup_start:]
                clean_counts=counts['matched_queries']>0 and counts['answers_sent']>0 and all(counts[key]==0 for key in ('rejected','oversized','send_failed')) and fixture.error=='none'
                case['positive']=case['positive'] and clean_counts and all(item['cleanup_confirmed'] for item in case['child_cleanup'])
            if not completed or not all(item['cleanup_confirmed'] for item in case['child_cleanup']):
                raise ValueError('pair_incomplete')
        if time.monotonic()>=deadline-10:raise ValueError('query_timeout')
        pending=Child(root,'pending');children.append(pending)
        pending.start([str(actor),'--test-pending'])
        pending.wait(min(deadline-10,time.monotonic()+3),pending=True)
        pending_report=native_report(read_bounded(pending.path))
        result['injected_pending_control']=pending.process.poll() is None and pending_report['pending'] and not pending_report['api_called'] and pending_report['context_retained'] and not pending_report['cancellation_handle_null']
    except Exception as exc:
        allowed={'platform','nrpt','query_timeout','output_bound','artifact','manifest','pin','sdk','headers','pair_incomplete'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        for child in reversed(children):stop_child(child)
        result['children_cleanup']=cleanup
        result['fixture']=stop_fixture(fixture) if fixture is not None else None
        result['query_observed']=any(fixture.query_observed.is_set() for fixture in fixtures)
        clean=all(item['cleanup_confirmed'] for item in cleanup) and (fixture is None or result['fixture']['cleanup_confirmed'])
        result['cleanup_confirmed']=clean
        if root is not None and clean:
            try:shutil.rmtree(root);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        result['mechanism_positive']=any(case['positive'] for case in result['cases'].values()) and (result['fixture'] or {}).get('error')=='none' and result['injected_pending_control'] and result['cleanup_confirmed'] and result['work_removed']
        result['injected_pending_control']=result['injected_pending_control'] and result['cleanup_confirmed']
    return result


def ownership_script(after_bind, pid):
    if type(after_bind) is not bool or not integer(pid,1,2**32-1):raise ValueError('owner')
    prefix="$ErrorActionPreference='Stop'; try { $p=@(Get-NetUDPEndpoint -ErrorAction Stop | Where-Object {$_.LocalPort -eq 53} | Select-Object -First 2); "
    check=("$p.Count -eq 1 -and $p[0].LocalAddress -ceq '127.0.0.1' -and $p[0].OwningProcess -eq "+str(pid)) if after_bind else '$p.Count -eq 0'
    token='UDP53_OWNED' if after_bind else 'UDP53_EMPTY'
    return prefix+"if("+check+"){[Console]::Write('"+token+"')}else{[Console]::Write('UDP53_UNCONFIRMED')} } catch { exit 2 }"


def run_port_pair(actor,manifest):
    deadline=time.monotonic()+BUDGET
    result=dict(schema=1,mode='port_pair',mechanism_positive=False,pair_complete=False,cases={},fixtures={},
                nrpt_empty=False,port53_empty=False,port53_owned=False,query_observed=False,
                cleanup_confirmed=False,work_removed=False,failure='none',runtime_acceptance=False,
                broker_cancellation_proven=False,receiver_attribution='temporal_shared_nonce_cross_endpoint_observed')
    root=None;children=[];fixtures={};cleanup=[];finished={}
    def stop(child):
        if id(child) in finished:return finished[id(child)]
        try:fact=child.finish(deadline)
        except Exception:fact=dict(exited=False,killed=False,handles_closed=False,cleanup_confirmed=False)
        finished[id(child)]=fact;cleanup.append(fact);return fact
    def control(name,script,expected):
        if time.monotonic()>=deadline-10:raise ValueError('budget')
        child=Child(root,name);children.append(child)
        child.start(['powershell.exe','-NoProfile','-NonInteractive','-Command',script])
        ended=child.wait(min(deadline-10,time.monotonic()+5))
        valid=ended and child.process.returncode==0 and read_bounded(child.path)==expected
        fact=stop(child)
        if not valid or not fact['cleanup_confirmed']:raise ValueError(name)
    try:
        if os.name!='nt':raise ValueError('platform')
        verify(actor,manifest);root=Path(tempfile.mkdtemp(prefix='dns-port-pair-'))
        control('nrpt',NRPT_SCRIPT,b'NRPT_EMPTY');result['nrpt_empty']=True
        pid=os.getpid()
        control('preflight',ownership_script(False,pid),b'UDP53_EMPTY');result['port53_empty']=True
        spec=importlib.util.spec_from_file_location('owned_dns_fixture',ROOT/'windows_dns_fixture.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        nonce=secrets.token_hex(16)
        fixtures['high_port']=module.DnsFixture(nonce,deadline=deadline);highport=fixtures['high_port'].start()
        fixtures['standard_port']=module.DnsFixture.for_port53(nonce,deadline=deadline);fixtures['standard_port'].start()
        control('ownership',ownership_script(True,pid),b'UDP53_OWNED');result['port53_owned']=True
        for endpoint in ('high_port','standard_port'):
            if time.monotonic()>=deadline-10:raise ValueError('budget')
            before={name:fixture.snapshot(deadline=deadline-10) for name,fixture in fixtures.items()}
            case=dict(api_report=None,receiver_before=before,positive=False,failure='none');result['cases'][endpoint]=case
            child=Child(root,endpoint);children.append(child);ended=False;completed=False
            try:
                argv=[str(actor),'--query',nonce,str(highport)] if endpoint=='high_port' else [str(actor),'--query-port53',nonce]
                child.start(argv);ended=child.wait(min(deadline-10,time.monotonic()+15))
                report=native_report(read_bounded(child.path));case['api_report']=report
                if report['endpoint_kind']!=endpoint or report['custom_port53'] is not (endpoint=='standard_port') or report['cancellation_handle_null']:raise ValueError('case_binding')
                completed=ended and child.process.returncode==0 and not report['pending']
                case['positive']=completed and report['api_called'] and report['api_status']==0 and report['result_status']==0 and report['record_count']==1 and report['answer_match'] and report['records_freed']
            except Exception:case['failure']='observation'
            finally:case['child_cleanup']=stop(child)
            case['completed']=completed
            after={name:fixture.snapshot(deadline=deadline-10) for name,fixture in fixtures.items()}
            delta={name:{key:after[name][key]-before[name][key] for key in before[name]} for name in fixtures}
            case['receiver_after']=after;case['receiver_delta']=delta
            other='standard_port' if endpoint=='high_port' else 'high_port'
            case['other_endpoint_observed']=any(delta[other].values())
            selected=delta[endpoint]
            case['positive']=case['positive'] and selected['matched_queries']>0 and selected['answers_sent']>0 and all(selected[key]==0 for key in ('rejected','oversized','send_failed')) and not case['other_endpoint_observed'] and case['child_cleanup']['cleanup_confirmed']
            if not completed or not case['child_cleanup']['cleanup_confirmed']:raise ValueError('pair_incomplete')
    except Exception as exc:
        allowed={'platform','budget','nrpt','preflight','ownership','pair_incomplete','artifact','manifest','pin','sdk','headers'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        for child in reversed(children):stop(child)
        result['children_cleanup']=cleanup
        for name,fixture in fixtures.items():
            try:result['fixtures'][name]=fixture.finish(deadline=deadline)
            except Exception:result['fixtures'][name]=dict(cleanup_confirmed=False,error='operation',counts=None)
        result['query_observed']=any(f.query_observed.is_set() for f in fixtures.values())
        clean=all(item['cleanup_confirmed'] for item in cleanup) and all(item['cleanup_confirmed'] for item in result['fixtures'].values())
        result['cleanup_confirmed']=clean
        if root is not None and clean:
            try:shutil.rmtree(root);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        result['pair_complete']=set(result['cases'])=={'high_port','standard_port'} and all(case.get('completed') and case['child_cleanup']['cleanup_confirmed'] for case in result['cases'].values())
        result['mechanism_positive']=result['pair_complete'] and not any(case.get('other_endpoint_observed',True) for case in result['cases'].values()) and any(case['positive'] for case in result['cases'].values()) and result['cleanup_confirmed'] and result['work_removed'] and all(item['error']=='none' for item in result['fixtures'].values())
    return result


DESCRIBE_LAYOUT={'sizes':3,'alignments':3,'request_offsets':12,'result_offsets':5,'custom_offsets':4}
DESCRIBE_INITIALIZED=('request_version','result_version','reserved_zero','result_zero','custom_singleton','legacy_null','callback_null','custom_udp','flags_zero','template_null','ipv4','loopback','port_roundtrip','query_name_bound','query_type_a','interface_zero','context_null','options_exact')


def describe_report(raw):
    value=decode(raw)
    fixed=dict(schema=1,test_only=True,mode='describe',api_called=False,runtime_acceptance=False)
    flags=('module_existing','system_path_verified','version_available')
    if type(value) is not dict or set(value)!=set(fixed)|set(flags)|{'layout','initialized','dnsapi_file_version'}:raise ValueError('describe_schema')
    for key,expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key]!=expected:raise ValueError('describe_fixed')
    if any(type(value[key]) is not bool for key in flags):raise ValueError('describe_type')
    layout=value['layout']
    if type(layout) is not dict or set(layout)!=set(DESCRIBE_LAYOUT):raise ValueError('describe_layout')
    for key,count in DESCRIBE_LAYOUT.items():
        if type(layout[key]) is not list or len(layout[key])!=count or any(not integer(item,0,65536) for item in layout[key]):raise ValueError('describe_layout')
    initialized=value['initialized']
    if type(initialized) is not dict or set(initialized)!=set(DESCRIBE_INITIALIZED) or any(type(item) is not bool for item in initialized.values()):raise ValueError('describe_initialized')
    version=value['dnsapi_file_version']
    if version is not None and (type(version) is not list or len(version)!=4 or any(not integer(item,0,65535) for item in version)):raise ValueError('describe_version')
    if value['version_available'] is not (version is not None):raise ValueError('describe_version')
    if value['version_available'] and not (value['module_existing'] and value['system_path_verified']):raise ValueError('describe_version')
    return value


def run_describe(actor, manifest):
    """No-query diagnostic lifecycle. No receiver, NRPT, or DNS query dispatch."""
    deadline=time.monotonic()+BUDGET
    result=dict(schema=1,mode='describe',diagnostics_complete=False,descriptor=None,
                os_version=None,cleanup_confirmed=False,work_removed=False,
                failure='none',api_called=False,runtime_acceptance=False)
    root=None;child=None
    try:
        if os.name!='nt':raise ValueError('platform')
        if hasattr(sys,'getwindowsversion'):
            version=sys.getwindowsversion()
            result['os_version']={key:int(getattr(version,key)) for key in ('major','minor','build')}
        verify(actor,manifest)
        root=Path(tempfile.mkdtemp(prefix='dns-describe-'))
        child=Child(root,'describe')
        child.start([str(actor),'--describe'])
        ended=child.wait(min(deadline-10,time.monotonic()+10))
        result['descriptor']=describe_report(read_bounded(child.path))
        result['diagnostics_complete']=ended and child.process.returncode==0
        if not ended:result['failure']='timeout'
    except Exception as exc:
        allowed={'platform','output_bound','artifact','manifest','pin','sdk','headers'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        if child is not None:
            try:result['child_cleanup']=child.finish(deadline)
            except Exception:result['child_cleanup']=dict(exited=False,killed=False,handles_closed=False,cleanup_confirmed=False)
            result['cleanup_confirmed']=result['child_cleanup']['cleanup_confirmed']
        else:result['cleanup_confirmed']=True
        if root is not None and result['cleanup_confirmed']:
            try:shutil.rmtree(root);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        result['diagnostics_complete']=result['diagnostics_complete'] and result['cleanup_confirmed'] and result['work_removed']
    return result


def main():
    parser=argparse.ArgumentParser();modes=parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--run-actual-windows',action='store_true')
    modes.add_argument('--run-no-query-diagnostics',action='store_true')
    modes.add_argument('--run-port-pair',action='store_true')
    parser.add_argument('--actor',type=Path,required=True);parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    try:
        result=(run_describe if args.run_no_query_diagnostics else run_port_pair if args.run_port_pair else run)(args.actor.resolve(),args.manifest.resolve())
        raw=json.dumps(result,sort_keys=True,separators=(',',':'))
        args.output.write_text(raw+'\n',encoding='ascii');print(raw)
        return 0 if result['diagnostics_complete' if args.run_no_query_diagnostics else 'mechanism_positive'] else 1
    except Exception:
        print('{"schema":1,"failure":"output","mechanism_positive":false,"runtime_acceptance":false}')
        return 1

if __name__=='__main__':raise SystemExit(main())
