"""Standalone TEST_ONLY socket-free parent/UDP child mechanics.

No VM, PSEC execution, production network command, or isolation acceptance.
Unknown parent exit never establishes descendant cleanup.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('udp_parent_existing_mechanics',ROOT/'test_windows_n0a_udp.py')
mechanics=importlib.util.module_from_spec(spec);spec.loader.exec_module(mechanics)
u=mechanics.u
BUDGET=60
MAX_PARENT_REPORT=32768

class OwnedParent:
    """One exact held parent process. It does not own a child HANDLE itself."""
    def __init__(self,report):
        self.report=Path(report);self.process=None;self.uncertain=False;self.handle_closed=False
    def start(self,argv):
        if self.process is not None or self.report.exists():raise ValueError('fresh_parent')
        self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    def wait(self,deadline):
        while time.monotonic()<deadline:
            if self.report.exists() and self.report.stat().st_size>MAX_PARENT_REPORT:raise ValueError('parent_report_bound')
            if self.process.poll() is not None:return True
            time.sleep(min(.02,max(0,deadline-time.monotonic())))
        return False
    def finish(self,deadline):
        exited=self.process is None;killed=False
        if self.process is not None:
            try:exited=type(self.process.poll()) is int
            except Exception:self.uncertain=True;exited=False
            if not exited:
                killed=True
                try:self.process.kill()
                except Exception:self.uncertain=True
                try:self.process.wait(timeout=max(0,deadline-time.monotonic()))
                except Exception:self.uncertain=True
                try:exited=type(self.process.poll()) is int
                except Exception:self.uncertain=True;exited=False
            if exited and not self.handle_closed:
                # Mark one attempt before closing; never retry a detached handle.
                self.handle_closed=True
                try:
                    handle=getattr(self.process,'_handle',None)
                    if handle is not None:handle.Close()
                except Exception:self.uncertain=True
        return dict(parent_exit_observed=exited,parent_killed=killed,
                    parent_handles_closed=exited and not self.uncertain,
                    parent_cleanup_confirmed=exited and not self.uncertain)

def read_report(path):
    return u.parse(mechanics.read(Path(path),MAX_PARENT_REPORT))

def bounded_deadline(deadline,limit,reserve=10):
    remaining=deadline-time.monotonic()-reserve
    if remaining<=0:raise ValueError('budget')
    return min(deadline-reserve,time.monotonic()+min(limit,remaining))

def qpc_clock():
    import ctypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    counter=ctypes.c_longlong();frequency=ctypes.c_longlong()
    for name,value in (('QueryPerformanceFrequency',frequency),('QueryPerformanceCounter',counter)):
        method=getattr(kernel,name);method.argtypes=[ctypes.POINTER(ctypes.c_longlong)];method.restype=ctypes.c_int
        if not method(ctypes.byref(value)):raise ValueError('qpc')
    if not 1<=frequency.value<=10**9 or not 0<counter.value<2**63:raise ValueError('qpc')
    return counter.value,frequency.value

def absolute_qpc(deadline,maximum,clock=qpc_clock):
    # Remaining time sampled after QPC is conservative: sampling delay is consumed.
    counter,frequency=clock()
    duration=min(maximum,deadline-time.monotonic())
    if duration<=2:raise ValueError('budget')
    target=counter+int(duration*frequency)
    if not 0<target<2**63:raise ValueError('qpc')
    return target,frequency

PARENT_KEYS={'version','testOnly','phase','deadlineVerified','profileMatched','childHashVerified','childCreated','childPid','tokenQuerySucceeded',
             'parentAppContainer','childAppContainer','sidEqual','sidMatched','resumeAttempted','resumeCount','resumed','waitSignaled',
             'childExitCode','timedOut','terminateAttempted','terminationSucceeded','cleanupConfirmed','childReportObserved',
             'childReportBytes','childReportSha256','failure'}
BOOL_KEYS={'deadlineVerified','testOnly','profileMatched','childHashVerified','childCreated','tokenQuerySucceeded','sidMatched','resumeAttempted',
           'resumed','waitSignaled','timedOut','terminateAttempted','terminationSucceeded','cleanupConfirmed','childReportObserved'}

def parent_report(owned,nonce,phase,failures):
    value=read_report(owned.report)
    if (type(value.get('schemaVersion')) is not int or value['schemaVersion']!=1 or value.get('mode')!='actor-n0a-udp-parent'
            or value.get('nonce')!=nonce or type(value.get('pid')) is not int or value['pid']!=owned.process.pid
            or value.get('queriesSucceeded') is not True or value.get('errors')!=[]):raise ValueError('parent_binding')
    row=value.get('parent')
    if type(row) is not dict or set(row)!=PARENT_KEYS:raise ValueError('parent_schema')
    if type(row['version']) is not int or row['version']!=1 or row['testOnly'] is not True or row['phase']!=phase:raise ValueError('parent_binding')
    if any(type(row[k]) is not bool for k in BOOL_KEYS):raise ValueError('parent_type')
    for key in ('parentAppContainer','childAppContainer','sidEqual'):
        if row[key] is not None and type(row[key]) is not bool:raise ValueError('parent_type')
    if not u.integer(row['childPid'],0,2**32-1) or not u.integer(row['childReportBytes'],0,32768):raise ValueError('parent_type')
    for key in ('resumeCount','childExitCode'):
        if row[key] is not None and not u.integer(row[key],0,2**32-1):raise ValueError('parent_type')
    digest=row['childReportSha256']
    if digest is not None and (type(digest) is not str or len(digest)!=64 or any(c not in '0123456789abcdef' for c in digest)):raise ValueError('parent_digest')
    if type(row['failure']) is not str or row['failure'] not in failures:raise ValueError('parent_failure')
    if row['childCreated'] and (not row['childPid'] or row['childPid']==owned.process.pid):raise ValueError('child_pid')
    if not row['childCreated'] and row['childPid']!=0:raise ValueError('child_pid')
    return value,row

def verified_child(path,nonce,phase,port,row):
    if not(row['deadlineVerified'] and row['childHashVerified'] and row['childCreated'] and row['waitSignaled'] and row['childReportObserved'] and row['childReportBytes']>0 and row['childReportSha256'] is not None):raise ValueError('child_observation')
    raw=mechanics.read(Path(path),u.MAX_REPORT)
    if len(raw)!=row['childReportBytes'] or hashlib.sha256(raw).hexdigest()!=row['childReportSha256']:raise ValueError('child_snapshot')
    value=u.parse(raw)
    if (type(value.get('schemaVersion')) is not int or value['schemaVersion']!=1 or value.get('mode')!='actor-n0a-udp'
            or value.get('nonce')!=nonce or type(value.get('pid')) is not int or value['pid']!=row['childPid']
            or value.get('queriesSucceeded') is not True or value.get('errors')!=[]):raise ValueError('child_binding')
    u.validate_network(value.get('udp'),nonce,phase,port,'fixture-loopback',True)
    return value

def projected_parent(row):
    # Never project process/token identifiers, report hashes, names or paths.
    return dict(child_created=row['childCreated'],token_query_succeeded=row['tokenQuerySucceeded'],
                sid_matched=row['sidMatched'],child_resumed=row['resumed'],held_wait_observed=row['waitSignaled'],
                child_report_observed=row['childReportObserved'],timed_out=row['timedOut'],
                terminate_attempted=row['terminateAttempted'],termination_succeeded=row['terminationSucceeded'],
                descendant_cleanup_confirmed=row['cleanupConfirmed'] and (not row['childCreated'] or (row['waitSignaled'] and row['childExitCode'] is not None)),failure=row['failure'])

FAILURES=('none','profile_only','profile','child_hash','child_report_exists','deadline','create','token','sid','resume_fixture','resume','timeout','wait','exit','hash','internal')

def verify_parent(actor,manifest,fixture):
    actor=Path(actor);manifest=Path(manifest)
    expected_names=('windows_n0a_UDP_PARENT_TEST_ONLY_fixture.exe','PARENT-TEST-ONLY-manifest.json') if fixture else ('windows_n0a_udp_parent.exe','N0A-UDP-PARENT-manifest.json')
    if (actor.name,manifest.name)!=expected_names:raise ValueError('parent_artifact')
    data=mechanics.read(actor,16*1024*1024)
    if len(data)<512:raise ValueError('parent_artifact')
    value=u.parse(mechanics.read(manifest,4096))
    fixed=dict(schemaVersion=1,testOnly=fixture,deployable=not fixture,compileOnly=True)
    pins=dict(parentSourceSha256=ROOT/'native/windows_n0a_udp_parent.cpp',identitySourceSha256=ROOT/'native/windows_identity_actor.cpp',childActorSourceSha256=ROOT/'native/windows_n0a_udp_actor.cpp',executableSha256=actor)
    if fixture:pins['fixtureSourceSha256']=ROOT/'native/windows_n0a_udp_parent_fixture.cpp'
    if set(value)!=set(fixed)|set(pins):raise ValueError('parent_manifest')
    for key,expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key]!=expected:raise ValueError('parent_manifest')
    for key,path in pins.items():
        if value[key]!=hashlib.sha256(mechanics.read(path,16*1024*1024)).hexdigest():raise ValueError('parent_pin')
    return data

def complete_parent(row):
    return (row['deadlineVerified'] and row['childHashVerified'] and row['childCreated'] and row['tokenQuerySucceeded'] and row['sidMatched']
            and row['parentAppContainer'] is False and row['childAppContainer'] is False and row['sidEqual'] is None
            and row['resumeAttempted'] and row['resumeCount']==1 and row['resumed'] and row['waitSignaled']
            and row['childExitCode']==0 and not row['timedOut'] and not row['terminateAttempted']
            and row['cleanupConfirmed'] and row['childReportObserved'] and row['failure']=='none')

def run(production_parent,production_manifest,fixture_parent,fixture_manifest,child_actor,child_manifest):
    deadline=time.monotonic()+BUDGET
    result=dict(schema=1,experiment='UDP-parent-hosted-mechanics',mechanics_complete=False,
        fixture_echo_controls=False,fixture_send_accepted_count=0,fixture_echo_count=0,profile_only_verified=False,production_invalid_cli_rejected=False,
        production_network_guard_executed=False,appcontainer_inheritance_tested=False,
        cleanup_confirmed=False,descendant_cleanup_confirmed=False,work_removed=False,failure='none',
        runtime_acceptance=False,packet_egress_tested=False,dns_tested=False,cases={})
    work=None;owned=[];endpoints=[];rows={};cleanup=[];receivers=[]
    def endpoint(nonce):
        bounded_deadline(deadline,1)
        value=u.UdpEndpoint(nonce,deadline);endpoints.append(value);return value.start()
    def launch(nonce,phase,port,name,mode='n0a-udp-parent',budget_limit=None,qpc_override=None,prelaunch_delay=0):
        maximum=budget_limit if budget_limit is not None else (5000 if phase in ('before','after') else 15000)
        latest=bounded_deadline(deadline,maximum/1000)
        target,frequency=absolute_qpc(latest,maximum/1000) if qpc_override is None else qpc_override
        folder=work/name;folder.mkdir()
        child_report=folder/'child.json';parent=OwnedParent(folder/'parent.json');owned.append((name,parent))
        argv=[str(staged_parent),mode,nonce,str(parent.report),str(staged_child),child_digest,str(child_report),str(port),phase,str(target),str(frequency)]
        if prelaunch_delay:
            before,observed_frequency=qpc_clock()
            initial=observed_frequency==frequency and target-before>2*frequency
            if not initial:raise ValueError('qpc')
            time.sleep(min(prelaunch_delay,max(0,latest-time.monotonic())))
            after,observed_frequency=qpc_clock()
            exhausted=observed_frequency==frequency and 0<target-after<=2*frequency
            parent.prelaunch_checks=(initial,exhausted)
            if not exhausted:raise ValueError('qpc')
        parent.start(argv)
        return parent,child_report,latest
    def observe(name,entry,nonce,phase,port,positive):
        parent,child_report,limit=entry
        if not parent.wait(limit):raise ValueError('parent_timeout')
        private,row=parent_report(parent,nonce,phase,FAILURES);rows[name]=row
        result['cases'][name]=projected_parent(row)
        if hasattr(parent,'prelaunch_checks'):
            result['cases'][name].update(initial_reserve_admissible=parent.prelaunch_checks[0],delayed_reserve_exhausted=parent.prelaunch_checks[1])
        if positive:
            child=verified_child(child_report,nonce,phase,port,row)
            result['cases'][name]['send_accepted_count']=sum(r['sendAccepted'] is True for r in child['udp']['attempts'])
            result['cases'][name]['echo_count']=sum(u.echo_success(r) for r in child['udp']['attempts'])
            if phase=='contained':
                result['fixture_send_accepted_count']=result['cases'][name]['send_accepted_count']
                result['fixture_echo_count']=result['cases'][name]['echo_count']
            if parent.process.returncode!=0 or not complete_parent(row):raise ValueError('parent_observation')
            return child['udp']
        return row
    try:
        if os.name!='nt':raise ValueError('platform')
        verify_parent(production_parent,production_manifest,False)
        fixture_bytes=verify_parent(fixture_parent,fixture_manifest,True)
        mechanics.verify(Path(child_actor),Path(child_manifest),True)
        child_bytes=mechanics.read(Path(child_actor),8*1024*1024);child_digest=hashlib.sha256(child_bytes).hexdigest()
        work=Path(tempfile.mkdtemp(prefix='udp-parent-mechanics-'));inputs=work/'inputs';inputs.mkdir()
        staged_parent=inputs/Path(fixture_parent).name;staged_child=inputs/Path(child_actor).name
        with staged_parent.open('xb') as stream:stream.write(fixture_bytes)
        with staged_child.open('xb') as stream:stream.write(child_bytes)
        profile_nonce=secrets.token_hex(16);profile=OwnedParent(work/'profile.json');owned.append(('profile',profile))
        profile.start([str(staged_parent),'--profile-only',profile_nonce,str(profile.report)])
        if not profile.wait(bounded_deadline(deadline,3)):raise ValueError('parent_timeout')
        private,row=parent_report(profile,profile_nonce,'profile',FAILURES);rows['profile']=row
        result['cases']['profile']=projected_parent(row)
        result['profile_only_verified']=(profile.process.returncode==0 and private.get('tokenElevated') is True and row['profileMatched'] is False
            and row['failure']=='profile_only' and not row['deadlineVerified'] and not row['childHashVerified'] and not row['childCreated'] and not row['tokenQuerySucceeded']
            and not row['resumeAttempted'] and not row['resumed'] and not row['childReportObserved'] and row['cleanupConfirmed'])
        if not result['profile_only_verified']:raise ValueError('negative_control')
        nonce=secrets.token_hex(16);port=endpoint(nonce);networks={} 
        networks['before']=observe('before',launch(nonce,'before',port,'before'),nonce,'before',port,True)
        sampler=launch(nonce,'sample',port,'sample')
        bounded_deadline(deadline,2);time.sleep(1.5) # Scheduling only; QPC establishes overlap.
        networks['contained']=observe('contained',launch(nonce,'contained',port,'contained'),nonce,'contained',port,True)
        networks['sample']=observe('sample',sampler,nonce,'sample',port,True)
        networks['after']=observe('after',launch(nonce,'after',port,'after'),nonce,'after',port,True)
        facts=u.controls(networks,nonce,port,production=False)
        result['fixture_echo_controls']=facts['ordinary_controls_verified'] and facts['all_selected_sendto_invoked'] and facts['sockets_cleanup_confirmed'] and all(u.echo_success(r) for r in networks['contained']['attempts'])
        result['fixture_send_accepted_count']=facts['selected_send_accepted_count']
        for name,mode,failure in (('token_failure','--test-token-failure','token'),('sid_mismatch','--test-sid-mismatch','sid'),('resume_failure','--test-resume-failure','resume_fixture')):
            case_nonce=secrets.token_hex(16);case_port=endpoint(case_nonce)
            entry=launch(case_nonce,'before',case_port,name,mode)
            row=observe(name,entry,case_nonce,'before',case_port,False)
            okay=(entry[0].process.returncode==5 and row['failure']==failure and row['childCreated'] and not row['resumed'] and not row['resumeAttempted']
                  and row['resumeCount'] is None and row['waitSignaled'] and row['childExitCode'] is not None
                  and row['terminateAttempted'] and row['terminationSucceeded'] and row['cleanupConfirmed']
                  and not row['childReportObserved'] and row['childReportBytes']==0 and row['childReportSha256'] is None)
            result['cases'][name]['expected_refusal']=okay
            if not okay:raise ValueError('negative_control')
        timeout_nonce=secrets.token_hex(16);timeout_port=endpoint(timeout_nonce)
        timeout_entry=launch(timeout_nonce,'sample',timeout_port,'timeout',budget_limit=3000)
        row=observe('timeout',timeout_entry,timeout_nonce,'sample',timeout_port,False)
        result['cases']['timeout']['expected_refusal']=(timeout_entry[0].process.returncode==5 and row['failure']=='timeout' and row['timedOut'] and row['childCreated']
            and row['resumed'] and row['resumeCount']==1 and row['terminateAttempted'] and row['terminationSucceeded']
            and row['waitSignaled'] and row['childExitCode'] is not None and row['cleanupConfirmed'])
        if row['childReportObserved']:
            child=verified_child(timeout_entry[1],timeout_nonce,'sample',timeout_port,row)
            result['cases']['timeout']['send_accepted_count']=sum(r['sendAccepted'] is True for r in child['udp']['attempts'])
        if not result['cases']['timeout']['expected_refusal']:raise ValueError('negative_control')
        for name in ('expired','wrong_frequency','prelaunch_delay'):
            counter,frequency=qpc_clock();target=counter-1;supplied_frequency=frequency;delay=0
            if name=='wrong_frequency':target=counter+5*frequency;supplied_frequency=frequency+1 if frequency<10**9 else frequency-1
            if name=='prelaunch_delay':target=counter+2*frequency+max(1,frequency//5);delay=.3
            case_nonce=secrets.token_hex(16)
            entry=launch(case_nonce,'before',port,name,qpc_override=(target,supplied_frequency),prelaunch_delay=delay)
            row=observe(name,entry,case_nonce,'before',port,False)
            result['cases'][name]['expected_refusal']=(entry[0].process.returncode==5 and row['failure']=='deadline'
                and not row['deadlineVerified'] and not row['childCreated'] and not row['childHashVerified']
                and not row['resumed'] and not row['childReportObserved'] and row['cleanupConfirmed'])
            if not result['cases'][name]['expected_refusal']:raise ValueError('negative_control')
        overflow_nonce=secrets.token_hex(16)
        overflow_entry=launch(overflow_nonce,'before',port,'overflow',qpc_override=(2**63,1))
        overflow=overflow_entry[0]
        result['cases']['overflow']=dict(expected_refusal=overflow.wait(overflow_entry[2]) and overflow.process.returncode==2 and not overflow.report.exists())
        if not result['cases']['overflow']['expected_refusal']:raise ValueError('negative_control')
        bounded_deadline(deadline,1)
        invalid=OwnedParent(work/'invalid.json');owned.append(('invalid',invalid))
        invalid.start([str(production_parent),'--invalid-mechanics-control'])
        result['production_invalid_cli_rejected']=invalid.wait(bounded_deadline(deadline,3)) and invalid.process.returncode==2 and not invalid.report.exists()
    except Exception as exc:
        allowed={'platform','budget','parent_timeout','parent_observation','negative_control','parent_artifact','parent_manifest','parent_pin','parent_binding','parent_schema','parent_type','parent_digest','parent_failure','child_pid','child_binding','child_observation','child_snapshot'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        descendants=True
        for name,parent in reversed(owned):
            try:facts=parent.finish(deadline)
            except Exception:facts=dict(parent_exit_observed=False,parent_killed=False,parent_handles_closed=False,parent_cleanup_confirmed=False)
            cleanup.append(facts)
            if name not in ('invalid','overflow'):
                row=rows.get(name)
                known=(row is not None and row['cleanupConfirmed'] and (not row['childCreated'] or (row['waitSignaled'] and row['childExitCode'] is not None))
                       and facts['parent_exit_observed'] and not facts['parent_killed'])
                descendants=descendants and known
        for endpoint_value in endpoints:
            try:receivers.append(endpoint_value.finish(deadline))
            except Exception:receivers.append(dict(cleanup_confirmed=False,error=True,counts=None))
        result['parents_cleanup']=cleanup;result['receivers']=receivers
        result['descendant_cleanup_confirmed']=descendants
        clean=descendants and all(v['parent_cleanup_confirmed'] for v in cleanup) and all(v['cleanup_confirmed'] for v in receivers)
        result['cleanup_confirmed']=clean
        if work is not None and clean:
            try:shutil.rmtree(work);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        receiver_ok=(len(receivers)==5 and all(not r['error'] and r['counts'] is not None for r in receivers)
                     and receivers[0]['verified_indices']['contained']==[0,1,2]
                     and all(r['counts']['datagrams']==0 for r in receivers[1:4])
                     and all(r['counts'][key]==0 for r in receivers for key in ('rejected','oversized','send_errors')))
        result['mechanics_complete']=(result['fixture_echo_controls'] and result['profile_only_verified'] and result['production_invalid_cli_rejected']
            and all(result['cases'].get(name,{}).get('expected_refusal') is True for name in ('token_failure','sid_mismatch','resume_failure','timeout','expired','wrong_frequency','prelaunch_delay','overflow'))
            and receiver_ok and result['cleanup_confirmed'] and result['work_removed'] and result['failure']=='none')
    return result

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-actual-windows',action='store_true')
    for name in ('production-parent','production-manifest','fixture-parent','fixture-manifest','child-actor','child-manifest','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args(argv)
    if not args.run_actual_windows:parser.error('explicit opt-in required')
    try:
        result=run(args.production_parent.resolve(),args.production_manifest.resolve(),args.fixture_parent.resolve(),args.fixture_manifest.resolve(),args.child_actor.resolve(),args.child_manifest.resolve())
        data=json.dumps(result,ensure_ascii=True,sort_keys=True,separators=(',',':'));args.output.write_text(data+'\n',encoding='ascii');print(data)
        return 0 if result['mechanics_complete'] else 1
    except Exception:
        print('{"schema":1,"failure":"output","runtime_acceptance":false}');return 1
if __name__=='__main__':raise SystemExit(main())
