"""Standalone hosted mechanics only. No VM, DNS, capture, or isolation verdict."""
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

ROOT=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('udp6_mechanics',ROOT/'windows_n0a_udp6.py')
u=importlib.util.module_from_spec(spec);spec.loader.exec_module(u)
BUDGET=60
MAX_PUBLIC_REPORT=32768
DIAGNOSTIC_CASES=('before','sample','contained','after','wrong_echo')
# At most seven owned child processes and two endpoints in the one-shot harness.
_UNCERTAIN_OWNERS=[]

def read(path,limit):
    if path.is_symlink() or not path.is_file():raise ValueError('file')
    with path.open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('bound')
    return data

def verify(actor,manifest,fixture):
    names=('windows_n0a_UDP6_TEST_ONLY_fixture.exe','UDP6-TEST-ONLY-manifest.json') if fixture else ('windows_n0a_udp6_actor.exe','N0A-UDP6-manifest.json')
    if (actor.name,manifest.name)!=names:raise ValueError('artifact')
    value=u.parse(read(manifest,4096))
    fixed=dict(schemaVersion=1,testOnly=fixture,deployable=not fixture,compileOnly=True)
    pins={'actorSourceSha256':ROOT/'native/windows_n0a_udp6_actor.cpp','identitySourceSha256':ROOT/'native/windows_identity_actor.cpp','executableSha256':actor}
    if fixture:pins['fixtureSourceSha256']=ROOT/'native/windows_n0a_udp6_fixture.cpp'
    if set(value)!=set(fixed)|set(pins):raise ValueError('manifest')
    for key,expected in fixed.items():
        if type(value[key]) is not type(expected) or value[key]!=expected:raise ValueError('manifest')
    for key,path in pins.items():
        if type(value[key]) is not str or re.fullmatch('[0-9a-f]{64}',value[key]) is None or hashlib.sha256(read(path,16*1024*1024)).hexdigest()!=value[key]:raise ValueError('pin')
    return True

def network_diagnostic(value,nonce,phase,port):
    """Only closed facts from the actual validated TEST_ONLY network object."""
    network=u.validate_network(value,nonce,phase,port,'fixture-loopback-v6',True)
    names={'failure':'failure','win32_error':'win32Error','socket_created':'socketCreated',
           'v6only_set':'v6OnlySet','v6only_verified':'v6OnlyVerified','bound':'bindSucceeded',
           'send_invoked':'attempted','send_accepted':'sendAccepted','echo_verified':'nonceMatched',
           'closed':'closed','close_error':'closeError',
           'v6only_get_return':'v6OnlyGetReturn','v6only_get_error':'v6OnlyGetError',
           'v6only_get_length':'v6OnlyGetLength','v6only_get_value':'v6OnlyGetValue','v6only_get_stage':'v6OnlyGetStage'}
    return dict(startup_error=network['startupError'],profile_matched=network['profileMatched'],
                sockets_cleanup_confirmed=network['socketsCleanupConfirmed'],
                attempt_count=len(network['attempts']),
                attempts=[{public:row[private] for public,private in names.items()} for row in network['attempts']])

class Owned:
    def __init__(self,path):self.path=path;self.process=None;self.spawn_attempted=False;self.close_attempted=False;self.close_uncertain=False
    def start(self,actor,nonce,port,phase):
        if self.path.exists():raise ValueError('report_exists')
        self.spawn_attempted=True
        self.process=subprocess.Popen([str(actor),'n0a-udp6',nonce,str(self.path),str(port),phase],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    def start_arguments(self,argv):
        if self.path.exists():raise ValueError('report_exists')
        self.spawn_attempted=True
        self.process=subprocess.Popen(argv,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
    def wait(self,deadline):
        while time.monotonic()<deadline:
            if self.path.exists() and self.path.stat().st_size>u.MAX_REPORT:raise ValueError('report_bound')
            if self.process.poll() is not None:return True
            time.sleep(min(.02,max(0,deadline-time.monotonic())))
        return False
    def report(self,nonce,phase,port,fixture):
        value=u.parse(read(self.path,u.MAX_REPORT))
        if value.get('mode')!='actor-n0a-udp6' or value.get('nonce')!=nonce or type(value.get('pid')) is not int or value['pid']!=self.process.pid or value.get('queriesSucceeded') is not True or value.get('errors')!=[]:raise ValueError('native_binding')
        u.validate_network(value.get('udp6'),nonce,phase,port,'fixture-loopback-v6' if fixture else 'runner-v6',fixture)
        return value
    def finish(self,deadline):
        exited=self.process is None and not self.spawn_attempted;okay=not self.close_uncertain;killed=False
        if self.process is not None:
            try:exited=self.process.poll() is not None
            except Exception:okay=False;exited=False
            if not exited:
                killed=True
                try:self.process.kill()
                except Exception:okay=False
                try:self.process.wait(timeout=max(0,deadline-time.monotonic()))
                except Exception:okay=False
                try:exited=self.process.poll() is not None
                except Exception:okay=False;exited=False
            if exited and hasattr(self.process,'_handle') and not self.close_attempted:
                self.close_attempted=True
                try:self.process._handle.Close()
                except Exception:okay=False;self.close_uncertain=True
        return dict(process_exited=exited,killed=killed,handles_closed=exited and okay,cleanup_confirmed=exited and okay)

def run(production_actor,production_manifest,fixture_actor,fixture_manifest):
    deadline=time.monotonic()+BUDGET
    result=dict(schema=1,protocol='udp6',hosted_mechanics_complete=False,fixture_echo_controls=False,fixture_send_accepted_count=0,fixture_selected_echo_observed=False,
                wrong_echo_send_accepted=False,wrong_echo_rejected=False,actual_admin_profile_rejected=False,v6only_contract_verified=False,echo_peer_contract_verified=False,
                production_invalid_cli_rejected=False,production_network_guard_executed=False,ordinary_nonadmin_tested=False,
                cleanup_confirmed=False,work_removed=False,failure='none',runtime_acceptance=False,packet_egress_tested=False,dns_tested=False)
    result['network_diagnostics']={key:None for key in DIAGNOSTIC_CASES}
    root=None;children=[];endpoints=[];cleanup=[];receivers=[]
    def endpoint(nonce,wrong=False):
        value=u.Udp6Endpoint.for_test_wrong_echo(nonce,deadline) if wrong else u.Udp6Endpoint(nonce,deadline)
        endpoints.append(value)
        try:return value.start()
        except Exception:raise ValueError('endpoint_setup') from None
    def start(actor,nonce,phase,port,name):
        if time.monotonic()>=deadline-10:raise ValueError('budget')
        child=Owned(root/(name+'.json'));children.append(child);child.start(actor,nonce,port,phase);return child
    def done(child,nonce,phase,port,fixture,limit):
        if not child.wait(min(deadline-10,time.monotonic()+limit)):raise ValueError('timeout')
        value=child.report(nonce,phase,port,fixture)
        key='wrong_echo' if child.path.stem=='wrong-echo' else phase
        result['network_diagnostics'][key]=network_diagnostic(value['udp6'],nonce,phase,port)
        if phase=='contained':
            result['fixture_send_accepted_count']=sum(row['sendAccepted'] for row in value['udp6']['attempts'])
            result['fixture_selected_echo_observed']=any(row['nonceMatched'] for row in value['udp6']['attempts'])
        if child.process.returncode!=0:raise ValueError('native_exit')
        return value
    try:
        if os.name!='nt':raise ValueError('platform')
        verify(production_actor,production_manifest,False);verify(fixture_actor,fixture_manifest,True)
        root=Path(tempfile.mkdtemp(prefix='udp-mechanics-'))
        nonce=secrets.token_hex(16);port=endpoint(nonce);reports={}
        child=start(fixture_actor,nonce,'before',port,'before');reports['before']=done(child,nonce,'before',port,True,5)['udp6']
        sampler=start(fixture_actor,nonce,'sample',port,'sample')
        remaining=deadline-10-time.monotonic()
        if remaining<1.5:raise ValueError('budget')
        time.sleep(1.5)
        child=start(fixture_actor,nonce,'contained',port,'contained');reports['contained']=done(child,nonce,'contained',port,True,5)['udp6']
        result['fixture_send_accepted_count']=sum(row['sendAccepted'] for row in reports['contained']['attempts'])
        result['fixture_selected_echo_observed']=any(row['nonceMatched'] for row in reports['contained']['attempts'])
        reports['sample']=done(sampler,nonce,'sample',port,True,12)['udp6']
        child=start(fixture_actor,nonce,'after',port,'after');reports['after']=done(child,nonce,'after',port,True,5)['udp6']
        observed=u.controls(reports,nonce,port,production=False)
        result['fixture_echo_controls']=observed['ordinary_controls_verified'] and observed['all_selected_sendto_invoked'] and all(u.echo_success(row) for row in reports['contained']['attempts']) and observed['sockets_cleanup_confirmed']
        result['fixture_send_accepted_count']=observed['selected_send_accepted_count']
        negative_nonce=secrets.token_hex(16);negative_port=endpoint(negative_nonce,True)
        child=start(fixture_actor,negative_nonce,'before',negative_port,'wrong-echo');negative=done(child,negative_nonce,'before',negative_port,True,3)['udp6']
        rows=negative['attempts']
        result['wrong_echo_send_accepted']=len(rows)==1 and rows[0]['sendAccepted']
        result['wrong_echo_rejected']=len(rows)==1 and not rows[0]['nonceMatched'] and rows[0]['failure']=='echo_payload' and rows[0]['closed'] and negative['socketsCleanupConfirmed']
        profile_nonce=secrets.token_hex(16)
        profile_child=Owned(root/'profile.json');children.append(profile_child)
        if time.monotonic()>=deadline-10:raise ValueError('budget')
        profile_child.start_arguments([str(fixture_actor),'--profile-only',profile_nonce,str(profile_child.path)])
        if not profile_child.wait(min(deadline-10,time.monotonic()+5)):raise ValueError('timeout')
        profile=u.parse(read(profile_child.path,u.MAX_REPORT))
        facts=profile.get('profile')
        if not (profile.get('mode')=='actor-n0a-udp6-profile' and profile.get('nonce')==profile_nonce and type(profile.get('pid')) is int and profile['pid']==profile_child.process.pid and profile.get('queriesSucceeded') is True and profile.get('errors')==[] and type(facts) is dict and set(facts)=={'testOnly','ordinaryMatched','containedMatched','networkApiCalled','v6OnlyContractVerified','echoPeerContractVerified'} and all(type(v) is bool for v in facts.values()) and facts['testOnly'] and not facts['networkApiCalled']):raise ValueError('profile_binding')
        # Synthetic shared-helper cases only, not a new socket/API observation.
        result['echo_peer_contract_verified']=profile_child.process.returncode==0 and facts['echoPeerContractVerified'] is True
        result['v6only_contract_verified']=profile_child.process.returncode==0 and facts['v6OnlyContractVerified'] is True
        result['actual_admin_profile_rejected']=profile_child.process.returncode==0 and profile.get('tokenElevated') is True and facts['ordinaryMatched'] is False and facts['containedMatched'] is False
        invalid=Owned(root/'invalid.json');children.append(invalid)
        if time.monotonic()>=deadline-10:raise ValueError('budget')
        invalid.start_arguments([str(production_actor),'--invalid-mechanics-control'])
        ended=invalid.wait(min(deadline-10,time.monotonic()+5))
        result['production_invalid_cli_rejected']=ended and invalid.process.returncode==2 and not invalid.path.exists()
    except Exception as exc:
        allowed={'platform','budget','timeout','native_exit','artifact','manifest','pin','bound','report_bound','endpoint_setup'}
        result['failure']=str(exc) if type(exc) is ValueError and str(exc) in allowed else 'operation'
    finally:
        for child in reversed(children):
            try:cleanup.append(child.finish(deadline))
            except Exception:cleanup.append(dict(process_exited=False,killed=False,handles_closed=False,cleanup_confirmed=False))
        for value in endpoints:
            try:receivers.append(value.finish(deadline))
            except Exception:receivers.append(dict(cleanup_confirmed=False,error=True,counts=None))
        for owner,facts in zip(reversed(children),cleanup):
            if not facts['cleanup_confirmed']:_UNCERTAIN_OWNERS.append(owner)
        for owner,facts in zip(endpoints,receivers):
            if not facts['cleanup_confirmed']:_UNCERTAIN_OWNERS.append(owner)
        result['children_cleanup']=cleanup;result['receivers']=receivers
        clean=all(item['cleanup_confirmed'] for item in cleanup+receivers)
        result['cleanup_confirmed']=clean
        if root is not None and clean:
            try:shutil.rmtree(root);result['work_removed']=True
            except Exception:result['cleanup_confirmed']=False
        receiver_ok=len(receivers)==2 and all(not r['error'] and r['counts'] is not None and all(r['counts'][key]==0 for key in ('rejected','oversized','send_errors')) for r in receivers)
        if receiver_ok:
            receiver_ok=(receivers[0]['counts']['verified']>=8 and receivers[0]['verified_indices']['contained']==[0,1,2] and receivers[1]['counts']['verified']==1)
        result['hosted_mechanics_complete']=result['fixture_echo_controls'] and result['wrong_echo_send_accepted'] and result['wrong_echo_rejected'] and result['actual_admin_profile_rejected'] and result['v6only_contract_verified'] and result['echo_peer_contract_verified'] and result['production_invalid_cli_rejected'] and receiver_ok and result['cleanup_confirmed'] and result['work_removed']
    return result

def public_json(result):
    data=json.dumps(result,sort_keys=True,separators=(',',':'))+'\n'
    if len(data.encode('ascii'))>MAX_PUBLIC_REPORT:raise ValueError('public_bound')
    return data

def main():
    p=argparse.ArgumentParser();p.add_argument('--run-actual-windows',action='store_true')
    for name in ('production-actor','production-manifest','fixture-actor','fixture-manifest','output'):p.add_argument('--'+name,type=Path,required=True)
    args=p.parse_args()
    if not args.run_actual_windows:p.error('explicit opt-in required')
    try:
        result=run(args.production_actor.resolve(),args.production_manifest.resolve(),args.fixture_actor.resolve(),args.fixture_manifest.resolve())
        data=public_json(result);args.output.write_text(data,encoding='ascii');print(data,end='')
        return 0 if result['hosted_mechanics_complete'] else 1
    except Exception:
        print('{"schema":1,"failure":"output","runtime_acceptance":false}');return 1
if __name__=='__main__':raise SystemExit(main())
