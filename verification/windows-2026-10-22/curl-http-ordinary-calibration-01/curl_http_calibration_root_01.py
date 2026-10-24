"""Ordinary-only, guarded loopback byte calibration; no isolation qualification.

Preview is inert. Actual uses the existing atomic JOB_LIST ordinary launcher
for both a Python worker and two real System32 curl controls. No shim, LPAC,
firewall, system proxy, DNS, route, external host, or package installation.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import secrets
import stat
import sys

SCRIPT=Path(os.path.abspath(__file__))
W=SCRIPT.parent
R=W/'Rule-proxy-Web'
READY=W/'lpac-curl-A4-ready-source-freeze-03.json'
READY_SHA='c90fbbdbf75f3495c1c492d8a386a1bb4766d73da370cf1aa9cd0de13e9e96cf'
CURL=Path(r'C:\Windows\System32\curl.exe')
CURL_SHA='73d24149ff289afc49ec41f08918ef9faa727d39ad993e929757dc2ddafab805'
STAGE=R/'private/curl-http-ordinary-calibration-01'

def need(value,why):
    if not value:raise ValueError(why)

def digest(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode('ascii')

def checked_path(path,*,inside=None,is_file=True):
    """Stdlib-only physical-path check before importing any native adapter."""
    path=Path(os.path.abspath(path))
    for component in (path,*path.parents):
        info=component.lstat()
        need(not stat.S_ISLNK(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,
            'reparse or symlink path')
    resolved=path.resolve(strict=True)
    if inside is not None:
        owner=Path(os.path.abspath(inside)).resolve(strict=True)
        need(resolved==owner or owner in resolved.parents,'path outside exact owner')
    info=resolved.lstat()
    need(stat.S_ISREG(info.st_mode) if is_file else stat.S_ISDIR(info.st_mode),'physical path kind')
    return resolved

def fresh_path(path,*,inside):
    path=Path(os.path.abspath(path))
    checked_path(path.parent,inside=inside,is_file=False)
    try:path.lstat()
    except FileNotFoundError:return path
    raise ValueError('fresh physical leaf required')

def pin(path):
    raw=checked_path(path).read_bytes();return dict(bytes=len(raw),sha256=digest(raw))

def put(path,raw):
    fresh_path(path,inside=W)
    with path.open('xb') as stream:
        need(stream.write(raw)==len(raw),'full file write');stream.flush();os.fsync(stream.fileno())

def verified_sources():
    checked_path(SCRIPT,inside=W);checked_path(R,inside=W,is_file=False)
    raw=checked_path(READY,inside=W).read_bytes()
    need(digest(raw)==READY_SHA,'frozen dependency source list')
    value=json.loads(raw)
    need(type(value['source_hashes']) is dict and len(value['source_hashes'])==90,'exact source90 closure')
    for name,expected in value['source_hashes'].items():
        relative=Path(name)
        need(not relative.is_absolute() and not relative.drive and '..' not in relative.parts and ':' not in name,'source relative path')
        path=checked_path(R/relative,inside=R)
        need(pin(path)['sha256']==expected,'dependency source '+name)
    need(pin(CURL)==dict(bytes=818512,sha256=CURL_SHA),'fixed system curl')
    return value['source_sha256']

def module():
    path=checked_path(R/'.github/windows_identity_proxy_pipe_ac_local.py',inside=R)
    spec=importlib.util.spec_from_file_location('ordinary_http_local_owner',path)
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result

def good_launch(value):
    return (value.get('started') is True and value.get('resumed') is True
        and value.get('native_identity_verified_before_resume') is True
        and value.get('exit_code')==0 and not value.get('timed_out') and 'error' not in value
        and all(value.get('cleanup',{}).get(k) is True for k in ('process_exit_confirmed','job_empty','job_closed','handles_closed'))
        and not value.get('cleanup',{}).get('errors'))

def header(case,port,total,response=False):
    body=total
    for _ in range(8):
        text=(f'HTTP/1.1 200 OK\r\nContent-Length: {body}\r\nConnection: close\r\nX-RuleProxy-Case: {case}\r\n\r\n' if response else
              f'POST /ruleproxy-a2/{case} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: {body}\r\nConnection: close\r\n\r\n').encode('ascii')
        rest=total-len(text)
        if rest==body:return text
        body=rest
    raise ValueError('header fixed point')

def argv(body,case,port,count):
    return [str(CURL),'--disable','--silent','--show-error','--http1.1','--ipv4',
        '--proxy','','--noproxy','*','--max-time','6','--connect-timeout','2','--retry','0',
        '--header','User-Agent:','--header','Accept:','--header','Content-Type:',
        '--header',f'Content-Length: {count}','--header','Connection: close',
        '--data-binary','@'+str(body),f'http://127.0.0.1:{port}/ruleproxy-a2/{case}']

def worker(config):
    # All source and fixed-image checks precede native constructors or sockets.
    checked_path(STAGE,inside=R,is_file=False)
    config=checked_path(config,inside=STAGE)
    need(config==checked_path(STAGE/'config.json',inside=STAGE),'exact physical worker config')
    c=json.loads(config.read_bytes());source=verified_sources()
    need(type(c) is dict and set(c)=={'schema_version','source_sha256','script','parent','frequency','start','deadline','guard_job_name','stage_path'},'closed worker config')
    need(type(c['schema_version']) is int and c['schema_version']==1 and c['stage_path']==str(STAGE),'worker stage binding')
    need(all(type(c[k]) is int and c[k]>0 for k in ('frequency','start','deadline'))
        and c['deadline']==c['start']+45*c['frequency'],'original 45-second epoch')
    need(c['source_sha256']==source and c['script']==pin(SCRIPT),'worker frozen inputs')
    local=module();api=local.LocalNativeAPI();parent=local.ordinary(api)
    need(parent==c['parent'] and api.qpc_frequency()==c['frequency'],'worker ordinary parent and QPC')
    budget=local.launcher.QpcBudget(api,c['deadline'],c['frequency'])
    local.verify_guard_job(api,c['guard_job_name'])
    local.LocalNativeAPI.verify_private_directory(api,STAGE,'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;'+parent['sid']+')')
    import socket
    import threading
    result=dict(schema_version=1,scope='ordinary-fixed-curl-owned-loopback-HTTP-calibration-v1',
        source_sha256=source,worker_pid=os.getpid(),worker_identity=parent,cases=[],passed=False,
        LPAC_tested=False,DNS_tested=False,proxy_tested=False,Linux_equivalence=False)
    try:
        for index in range(2):
            budget.require_ms(budget.cutoff(15))
            case=secrets.token_hex(16);root=STAGE/('case'+str(index));root.mkdir();(root/'temp').mkdir()
            row=dict(case=case,request_match=False,response_match=False,receiver_closed=False,
                receiver_finished=False,launch=None,receiver_error=None,extra_bytes=None,raw_saved=False,raw_error=None,
                work_completed_qpc=None,cleanup_join_qpc=None,cleanup_clock_errors=[],socket_closes={},
                listener_owner='main',thread_start_returned=False,outer_job_verified_before_resume=False)
            result['cases'].append(row)
            listener=None;thread=None;ownership_lock=threading.Lock();ownership={'thread':False}
            cleanup_end=budget.cutoff(3)
            def sample_cleanup(label):
                try:return api.qpc()
                except BaseException as exc:
                    row['cleanup_clock_errors'].append(label+':'+type(exc).__name__);return None
            def close_socket(sock,label):
                receipt=dict(attempted=True,closed=False,error=None,before_qpc=sample_cleanup(label+'-before'),after_qpc=None)
                row['socket_closes'][label]=receipt
                try:
                    sock.close();receipt['closed']=sock.fileno()==-1
                    need(receipt['closed'],'socket close readback')
                except BaseException as exc:receipt['error']=type(exc).__name__+':'+str(exc)[:256]
                finally:receipt['after_qpc']=sample_cleanup(label+'-after')
            def cleanup_remaining():return max(0,(cleanup_end-api.qpc())/c['frequency'])
            try:
                listener=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
                need(listener.getsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE)==1,'exclusive listener readback')
                listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
                need(49153<=port<=65535,'ephemeral high port')
                listener.listen(1)
                end=min(api.qpc()+8*c['frequency'],budget.cutoff(12))
                def timeout(sock):
                    remaining=(end-api.qpc())/c['frequency'];need(remaining>0,'original receive deadline')
                    sock.settimeout(remaining)
                request_header=header(case,port,8193);response_header=header(case,port,12289,True)
                body=bytes((i*73+17)%256 for i in range(8193-len(request_header)))
                response_body=bytes((i*29+211)%256 for i in range(12289-len(response_header)))
                expected=request_header+body;response=response_header+response_body
                put(root/'request-body.bin',body)
                row.update(port=port,request_header=request_header.decode('ascii'),response_header=response_header.decode('ascii'),
                    expected_request=dict(bytes=len(expected),sha256=digest(expected)),expected_body=dict(bytes=len(response_body),sha256=digest(response_body)),
                    deadline_qpc=end,cleanup_deadline_qpc=cleanup_end,request_input_mode='data-binary-file')
                def receive(server):
                    # The thread may run before start() returns. No socket use
                    # or close is authorized until the main owner hands it off.
                    with ownership_lock:authorized=ownership['thread']
                    if not authorized:
                        row['receiver_finished']=True;return
                    peer=None;data=bytearray()
                    try:
                        timeout(server);peer,address=server.accept()
                        need(address[0]=='127.0.0.1','loopback peer')
                        row['accepted_tuple']=[list(peer.getsockname()),list(peer.getpeername())]
                        while len(data)<8193:
                            timeout(peer);chunk=peer.recv(8194-len(data))
                            need(chunk,'early request EOF');data.extend(chunk)
                            need(len(data)<=8193,'request overflow')
                        row['request_match']=bytes(data)==expected
                        need(row['request_match'],'actual curl request differs from frozen A2 canonical')
                        timeout(peer);peer.sendall(response);peer.shutdown(socket.SHUT_WR)
                        timeout(peer);extra=peer.recv(1);row['extra_bytes']=len(extra)
                        need(extra==b'','request EOF without extra bytes')
                        row['work_completed_qpc']=api.qpc()
                        need(row['work_completed_qpc']<end,'receiver work returned after original deadline')
                    except BaseException as exc:row['receiver_error']=type(exc).__name__+':'+str(exc)[:256]
                    finally:
                        # Close the network resources before disk persistence;
                        # close and raw-write errors are independently retained.
                        if peer is not None:
                            owned,peer=peer,None;close_socket(owned,'peer')
                        close_socket(server,'listener')
                        row['receiver_closed']=all(r['closed'] and r['error'] is None for r in row['socket_closes'].values())
                        try:
                            put(root/'received-request.bin',bytes(data));row['raw_saved']=True
                        except BaseException as exc:row['raw_error']=type(exc).__name__+':'+str(exc)[:256]
                        finally:row['receiver_finished']=True
                thread=threading.Thread(target=receive,args=(listener,),name='owned-http-calibration-receiver',daemon=False)
                with ownership_lock:
                    thread.start();row['thread_start_returned']=True
                    budget.require_ms(end)
                    ownership['thread']=True;row['listener_owner']='thread';listener=None
                child_api=local.LocalNativeAPI();child_api.worker_job_name='Local\\RuleProxy.LocalGuard.'+secrets.token_hex(16)
                child_api.worker_sid=parent['sid']
                child_api.k.OpenJobObjectW.argtypes=[local.C.c_uint32,local.C.c_int,local.C.c_wchar_p]
                child_api.k.OpenJobObjectW.restype=local.C.c_void_p
                verify_inner=child_api.verify_job
                def verify_both(job,process):
                    verify_inner(job,process)
                    budget.require_ms(end)
                    outer=child_api.k.OpenJobObjectW(4,False,c['guard_job_name'])
                    child_api.check(outer,'OpenJobObjectW(calibration_outer_query)')
                    try:verify_inner(outer,process);budget.require_ms(end)
                    finally:child_api.close(outer)
                    row['outer_job_verified_before_resume']=True
                child_api.verify_job=verify_both
                command=argv(root/'request-body.bin',case,port,len(body));row['command']=command
                row['launch']=local.launcher.launch_owned(child_api,command,root,parent,parent,qpc_budget=budget,
                    work_cutoff=end,cleanup_cutoff=budget.cutoff(5))
            finally:
                # Before successful start, main retains the sole close right.
                # Afterwards only receive() closes; main never races that close.
                if listener is not None and not ownership['thread']:
                    owned,listener=listener,None;close_socket(owned,'listener')
                if thread is not None and (row['thread_start_returned'] or thread.ident is not None):
                    thread.join(cleanup_remaining())
                    need(not thread.is_alive(),'receiver thread stopped within original cleanup reserve')
                row['cleanup_join_qpc']=sample_cleanup('join')
            observed=checked_path(root/'controller.stdout',inside=STAGE).read_bytes()
            error=checked_path(root/'controller.stderr',inside=STAGE).read_bytes()
            row['stdout']=dict(bytes=len(observed),sha256=digest(observed));row['stderr']=dict(bytes=len(error),sha256=digest(error))
            row['response_match']=observed==response_body and not error
            row['passed']=(good_launch(row['launch']) and row['outer_job_verified_before_resume'] and row['request_match'] and row['response_match']
                and row['receiver_closed'] and row['receiver_finished'] and row['receiver_error'] is None and row['extra_bytes']==0
                and row['raw_saved'] and row['raw_error'] is None and row['work_completed_qpc'] is not None and row['work_completed_qpc']<end
                and not row['cleanup_clock_errors'] and row['cleanup_join_qpc'] is not None and row['cleanup_join_qpc']<cleanup_end
                and set(row['socket_closes'])=={'listener','peer'}
                and all(r['after_qpc'] is not None and r['after_qpc']<cleanup_end for r in row['socket_closes'].values()))
            need(row['passed'],'ordinary real curl exact HTTP calibration')
        result['passed']=len(result['cases'])==2 and all(x['passed'] for x in result['cases'])
    except BaseException as exc:result['error']=type(exc).__name__+':'+str(exc)[:256]
    finally:
        try:result['sources_unchanged']=verified_sources()==source and c['script']==pin(SCRIPT)
        except BaseException as exc:
            result['sources_unchanged']=False;result['source_error']=type(exc).__name__+':'+str(exc)[:256]
        put(STAGE/'worker-report.json',encoded(result))
    return 0 if result['passed'] and result['sources_unchanged'] else 1

def actual():
    source=verified_sources();local=module();api=local.LocalNativeAPI();parent=local.ordinary(api)
    need(api.windows_x64(),'ordinary x64');fresh_path(STAGE,inside=R)
    frequency=api.qpc_frequency();start=api.qpc();deadline=start+45*frequency
    budget=local.launcher.QpcBudget(api,deadline,frequency);budget.require_ms(budget.cutoff(4))
    # Only this new private directory receives an explicit user/SYSTEM DACL.
    api.private_directory(STAGE,parent['sid']);(STAGE/'guard').mkdir();(STAGE/'guard/temp').mkdir()
    api.worker_job_name='Local\\RuleProxy.LocalGuard.'+secrets.token_hex(16);api.worker_sid=parent['sid']
    c=dict(schema_version=1,source_sha256=source,script=pin(SCRIPT),parent=parent,
        frequency=frequency,start=start,deadline=deadline,guard_job_name=api.worker_job_name,stage_path=str(STAGE))
    put(STAGE/'config.json',encoded(c))
    command=[str(checked_path(sys.executable)),'-I','-S','-B',str(SCRIPT),'--worker',str(STAGE/'config.json')]
    launch=local.launcher.launch_owned(api,command,STAGE/'guard',parent,parent,qpc_budget=budget,
        work_cutoff=budget.cutoff(4),cleanup_cutoff=deadline)
    put(STAGE/'outer-launch.json',encoded(launch))
    report=json.loads(checked_path(STAGE/'worker-report.json',inside=STAGE).read_bytes()) if (STAGE/'worker-report.json').exists() else None
    passed=bool(good_launch(launch) and report and report['passed'] and report['sources_unchanged']
        and report['worker_pid']==launch['child_pid'] and report['worker_identity']==parent)
    public=dict(schema_version=1,scope='ordinary-fixed-curl-owned-loopback-HTTP-calibration-v1',passed=passed,
        source_sha256=source,script=pin(SCRIPT),cases=0 if report is None else len(report['cases']),
        outer_known_cleanup=all(launch.get('cleanup',{}).get(k) is True for k in ('process_exit_confirmed','job_empty','job_closed','handles_closed')),
        selected_LPAC_tested=False,DNS_tested=False,proxy_tested=False,Linux_equivalence=False,
        worker_report=None if report is None else pin(STAGE/'worker-report.json'))
    put(W/'curl-http-ordinary-calibration-01-result.json',encoded(public));print(json.dumps(public,sort_keys=True))
    return 0 if passed else 1

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--actual',action='store_true');parser.add_argument('--worker',type=Path);args=parser.parse_args()
    if args.worker:
        need(not args.actual and args.worker==STAGE/'config.json','exact worker config')
        raise SystemExit(worker(args.worker))
    if args.actual:raise SystemExit(actual())
    print(json.dumps(dict(preview=True,network=False,processes=False,mutations=False)))
