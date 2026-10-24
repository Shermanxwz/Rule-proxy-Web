"""A5 ordinary proxy leg. Owns no independent Job or duplicated cleanup ledger.

The host is the one A5 owner. All new children/known handles join its live
ownership view; native A2 reports retain their genuine original schema.
"""
from pathlib import Path

ROLES=('ordinary-pipe-relay','ordinary-origin-fixture','mihomo-config-check','mihomo-core')
CORE_ROLES=('mihomo-config-check','mihomo-core')
REPORT_PATHS={'ready':'origin-report/ready.json','relay':'relay-report/actor.json','origin':'origin-report/actor.json'}
BARRIER_PATHS={'arm':'origin-control/phase.bin','ack':'origin-report/request-held.json','release':'origin-control/response-go.bin'}


def bundle(root,run):return Path(root).parent/('mihomo-a5-private-bundle-'+run)


def config_view(c):
    p=c['proxy'];v=dict(c)
    v.update(ports=p['ports'],challenges=p['challenges'],mihomo_config_sha256=p['mihomo_config_sha256'],
             mihomo_sha256=p['artifacts']['mihomo']['sha256'],network_actor_sha256=p['artifacts']['network_actor']['sha256'],
             network_manifest_sha256=p['artifacts']['network_manifest']['sha256'])
    return v


def expected_argv(role,root,c,parent,pair=None):
    p=Path(root);ports=c['proxy']['ports'];network=p/'inputs/windows_identity_lpac_stream_mihomo_network_actor.exe'
    if role in CORE_ROLES:
        value=[str(bundle(root,c['run'])/'mihomo.exe'),'-d',str(p/'core-home'),'-f',str(p/'core-home/config.json')]
        return value+['-t'] if role==CORE_ROLES[0] else value
    if role=='ordinary-origin-fixture':
        return [str(network),'stream-a2-origin',c['run'],c['case'],str(p/REPORT_PATHS['origin']),str(p/REPORT_PATHS['ready']),
            str(c['start_qpc']),str(c['frequency']),str(c['root_deadline_qpc']-35*c['frequency']),parent['sid'],'8193','12289',
            str(ports['origin_port']),str(ports['proxy_port']),str(p/BARRIER_PATHS['arm']),str(p/BARRIER_PATHS['ack']),str(p/BARRIER_PATHS['release'])]
    if role=='ordinary-pipe-relay' and pair is not None:
        return [str(network),'stream-a2-relay',c['run'],c['case'],str(p/REPORT_PATHS['relay']),
            *(str(h) for h in pair['relay_ends']),str(pair['start']),str(c['frequency']),str(pair['relay_end']),parent['sid'],
            'none','8193','12289',str(ports['origin_port']),str(ports['proxy_port'])]
    raise ValueError('a5_proxy_closed_role')


class ProxyLeg:
    def __init__(self,host,m):
        self.h,self.m,self.a=host,m,m.proxy_protocol
        self.root,self.c,self.parent,self.api,self.budget=host.root,host.c,host.parent,host.api,host.budget
        self.rows={};self.leases=None;self.epoch=None;self.stdio=[];self.allocations=[];self.parent_closes=[]
        self.j=dict(ports=self.c['proxy']['ports'],pair=None,tasks=[],reports=dict.fromkeys(REPORT_PATHS),
            report_status=dict.fromkeys(REPORT_PATHS,'unavailable'),tcp={},barrier_commands={},barrier_ack=None,
            barrier_released=False,kernel_tcp_snapshot_observed=False,core_check_completed=False,core_stop=None,
            core_stdio=[],core_stdio_closed=True,port_lease=None,port_leases_closed=True,completion_qpc=None,
            natural_exits=False,workload_stop=False,physical_sinks={},physical={},failure=None)
        host.j['proxy']=self.j

    def sync(self):
        self.j['tasks']=[dict(self.m.task_projection(r),role=r['role'],command=r['command'],ends=r['ends'],resume_receipt=r.get('resume_receipt')) for r in self.rows.values()]
        # A sealed copy, never a reference back to the mutable proxy result.
        self.j['physical']=self.m.decode(self.m.encode(dict(intents=self.h.j['intents'],returns=self.h.j['returns'],
            api_intents=self.h.j['api_intents'],api_calls=self.h.j['api_calls'],api_raw_calls=self.h.j['api_raw_calls'],
            pipe_allocations=self.allocations,parent_pipe_closes=self.parent_closes)))
        if self.leases is not None:
            self.j['port_lease']=dict(calls=self.leases.calls,closes=self.leases.closed,unknown=self.leases.unknown,
                started=self.leases.started,cleanup_attempted=self.leases.cleanup_attempted,cleanup_confirmed=self.leases.cleanup_confirmed)
            self.j['port_leases_closed']=self.leases.confirmed_closed
        self.j['core_stdio_closed']=all(r['confirmed'] for r in self.j['core_stdio'])

    def verify_configuration(self):
        raw=self.m.local.bounded(self.m.launcher.checked_path(self.root/'core-home/config.json',inside=self.root),32768)
        self.m.require(raw==self.m.encode(self.a.mihomo_configuration(self.c['proxy']['ports']))
            and self.m.sha(raw)==self.c['proxy']['mihomo_config_sha256'],'a5_config_repin')
        return raw

    def spawn(self,role,end,ends=()):
        self.m.require(role in ROLES and role not in self.rows,'a5_proxy_spawn_once')
        argv=expected_argv(role,self.root,self.c,self.parent,self.epoch)
        row=self.h.spawn_proxy(role,argv,end,ends=ends,session=self)
        self.rows[role]=row;self.sync();return row

    def resume(self,row,end):
        self.h.held(row,end);self.m.require(row['admitted'] and not row['resumed'],'a5_proxy_resume_once')
        if row['role'] in CORE_ROLES:self.verify_configuration()
        if row['role']=='ordinary-pipe-relay':
            self.m.require(self.h.j['parent_pipe_handles_closed'] and self.h.pipe_owners.confirmed_closed
                and not self.h.pipe_allocation_unknown and len(self.h.j['proofs'])==2
                and all(p['value']['qualified'] and p['value']['resource_cleanup_verified'] for p in self.h.j['proofs'])
                and 'arm' in self.j['barrier_commands'],'a5_relay_resume_gate')
        intent=self.h.journal('resume-proxy-'+row['role']);row['resume_intent_qpc']=self.m.decode(intent['text'].encode('ascii'))['qpc']
        raw=dict(entered=True,returned=False,count=None,error=None,returned_qpc=None,clock_error=False,exception=False)
        try:
            count,error=self.api.resume_raw(row['info'].hThread);raw.update(returned=True,count=count,error=error)
            if count==1 and error is None:row['resumed']=True
            try:raw['returned_qpc']=self.budget.read();row['resume_qpc']=raw['returned_qpc']
            except BaseException:raw['clock_error']=True;self.api.controls_uncertain=True;raise
            self.m.require(type(count) is int and count==1 and error is None and row['resume_intent_qpc']<=raw['returned_qpc']<end,'a5_proxy_resume_raw')
        except BaseException:
            if not raw['returned']:raw['exception']=True;self.api.controls_uncertain=True
            raise
        finally:
            row['resume_receipt']=self.h.returned('resume-proxy-'+row['role'],intent,raw);self.sync()

    def wait(self,row,end,*,expected=0,natural=True):
        self.budget.require_ms(end)
        self.m.require(self.api.wait(row['info'].hProcess,self.budget.require_ms(end)) is True,'a5_proxy_wait')
        row['exited']=True;row['exit_code']=self.api.exit_code(row['info'].hProcess)
        row['exit_observed_qpc']=self.budget.read();self.budget.require_ms(end)
        row['natural_exit']=bool(natural)
        self.m.require(row['exit_code']==expected,'a5_proxy_exit_code')
        if row['role'] in CORE_ROLES:self.verify_configuration()
        self.sync()

    def read_closed(self,path,row,end):
        while not path.exists():
            self.budget.require_ms(end);self.m.require(not self.api.wait(row['info'].hProcess,0),'a5_proxy_exit_before_report')
            self.api.sleep_ms(self.budget.require_ms(end,5))
        while True:
            try:
                raw=self.m.local.bounded(self.m.launcher.checked_path(path,inside=self.root),32768)
                self.budget.require_ms(end);return raw
            except OSError as e:
                if getattr(e,'winerror',None)!=32:raise
                self.api.sleep_ms(self.budget.require_ms(end,5))

    def native_view(self):
        self.sync();return dict(self.j,profile_sid=self.h.profile['sid'],pair=dict(start=self.epoch['start'],end=self.epoch['relay_end'],frequency=self.c['frequency']))

    def held_family(self,end):
        for role in ('ordinary-pipe-relay','ordinary-origin-fixture','mihomo-core'):
            self.h.held(self.rows[role],end)

    def prepare(self):
        end=self.m.work_cutoff(self.c);self.verify_configuration()
        self.h.journal('proxy-port-leases')
        self.leases=self.a.PortLeases(self.api.lease_backend(),self.budget,end,self.c['proxy']['ports'])
        try:self.leases.acquire()
        finally:self.sync()
        check=self.spawn('mihomo-config-check',end);self.resume(check,end);self.wait(check,end)
        self.j['core_check_completed']=True
        self.leases.release('origin_port');self.sync()
        origin=self.spawn('ordinary-origin-fixture',end);self.resume(origin,end)
        raw=self.read_closed(self.root/REPORT_PATHS['ready'],origin,end)
        self.j['reports']['ready']=dict(text=raw.decode('ascii'),sha256=self.m.sha(raw));self.j['report_status']['ready']='invalid'
        # Ready validation does not consume pair_qpc, which is not issued yet.
        view=dict(self.j,tasks=[dict(self.m.task_projection(origin),role=origin['role'])])
        self.a.validate_native('ready',self.m.decode(raw),view,config_view(self.c),self.parent)
        self.j['report_status']['ready']='valid'
        self.leases.release('proxy_port');self.leases.close_all();self.sync()
        self.m.require(self.leases.confirmed_closed,'a5_port_leases_closed_before_core')
        core=self.spawn('mihomo-core',end);self.resume(core,end)
        while True:
            for row in (origin,core):self.h.held(row,end)
            before=self.budget.read();table=self.api.tcp_snapshot(self.budget,end);after=self.budget.read()
            try:rows=self.a.exact_listeners(table,proxy_pid=core['pid'],origin_pid=origin['pid'],declared=self.c['proxy']['ports'])
            except ValueError:self.api.sleep_ms(self.budget.require_ms(end,10));continue
            for row in (origin,core):self.h.held(row,end)
            self.m.base.durable_private(self.root/'tcp/listeners.bin',table)
            self.j['tcp']['listeners']=self.a.tcp_record(table,rows,name='listeners.bin',before_qpc=before,after_qpc=after)
            self.budget.require_ms(end);break

    def start_pair(self,epoch,relay_ends):
        self.epoch=dict(epoch,relay_ends=list(relay_ends));self.j['pair']=dict(start=epoch['start'],end=epoch['relay_end'],frequency=self.c['frequency'])
        return self.spawn('ordinary-pipe-relay',epoch['app_end'],ends=relay_ends)

    def publish(self,*,release=False,ack=None):
        key='release' if release else 'arm';end=self.epoch['app_end']
        if release:end=self.m.barrier_cutoff(self.epoch,ack['wait_deadline_qpc'])
        intent=self.h.journal('proxy-barrier-'+key);self.budget.require_ms(end);issued=self.budget.read()
        raw=self.a.barrier_control(config_view(self.c),self.j['pair'],issued,release=release,ack=ack)
        record=dict(path=BARRIER_PATHS[key],hex=raw.hex(),sha256=self.m.sha(raw),issued_qpc=issued,
            intent_qpc=self.m.decode(intent['text'].encode('ascii'))['qpc'],published_qpc=None)
        self.j['barrier_commands'][key]=record
        self.m.zero.atomic_publish(self.root/BARRIER_PATHS[key],raw,self.budget,end)
        record['published_qpc']=self.budget.read();self.budget.require_ms(end)

    def barrier(self):
        end=self.epoch['app_end'];row=self.rows['ordinary-origin-fixture']
        raw=self.read_closed(self.root/BARRIER_PATHS['ack'],row,end)
        self.j['barrier_ack']=dict(text=raw.decode('ascii'),sha256=self.m.sha(raw))
        ack=self.a.validate_ack(self.m.decode(raw),config_view(self.c),self.j['pair'],origin_pid=row['pid'],arm_issued=self.j['barrier_commands']['arm']['issued_qpc'])
        end=self.m.barrier_cutoff(self.epoch,ack['wait_deadline_qpc']);self.budget.require_ms(end);self.held_family(end)
        before=self.budget.read();table=self.api.tcp_snapshot(self.budget,end);after=self.budget.read()
        rows=self.a.exact_two_hop(table,relay_pid=self.rows['ordinary-pipe-relay']['pid'],proxy_pid=self.rows['mihomo-core']['pid'],
            origin_pid=row['pid'],declared=self.c['proxy']['ports'],origin_peer_port=ack['peer_port'])
        self.held_family(end);self.m.base.durable_private(self.root/'tcp/two-hop.bin',table)
        self.j['tcp']['two_hop']=self.a.tcp_record(table,rows,name='two-hop.bin',before_qpc=before,after_qpc=after)
        self.j['kernel_tcp_snapshot_observed']=True;self.publish(release=True,ack=ack);self.j['barrier_released']=True

    def finish(self):
        end=self.epoch['app_end']
        for role in ('ordinary-pipe-relay','ordinary-origin-fixture'):self.wait(self.rows[role],end)
        for key in ('relay','origin'):
            raw=self.m.local.bounded(self.m.launcher.checked_path(self.root/REPORT_PATHS[key],inside=self.root),32768)
            self.j['reports'][key]=dict(text=raw.decode('ascii'),sha256=self.m.sha(raw));self.j['report_status'][key]='invalid'
            self.a.validate_native(key,self.m.decode(raw),self.native_view(),config_view(self.c),self.parent)
            self.j['report_status'][key]='valid';self.budget.require_ms(end)
        for key in ('relay_request','relay_response','origin_request','origin_response'):
            name=self.a.SINK_PATHS[key]
            raw=self.m.local.bounded(self.m.launcher.checked_path(self.root/name,inside=self.root),65536)
            self.j['physical_sinks'][key]=dict(path=name,bytes=len(raw),sha256=self.m.sha(raw))
        self.j['natural_exits']=True;self.j['completion_qpc']=self.budget.read();self.budget.require_ms(end);self.sync()

    def stop_core(self):
        self.m.require(self.j['core_stop'] is None,'a5_core_stop_once')
        row=self.rows['mihomo-core'];end=self.m.work_cutoff(self.c)
        record=dict(role='mihomo-core',pid=row['pid'],created=row['created'],image_sha256=row['image_sha256'],
            intent_qpc=None,receipt=None,observation=None,observed_exit_qpc=None,exit_code=None)
        self.j['core_stop']=record
        intent=self.h.journal('proxy-core-stop');record['intent_qpc']=self.m.decode(intent['text'].encode('ascii'))['qpc'];self.h.held(row,end)
        def returned(value):
            record['observation']=value;record['receipt']=self.h.returned('proxy-core-stop',intent,value)
        self.api.terminate_core(row['info'].hProcess,self.budget,end,returned)
        self.wait(row,end,expected=1,natural=False)
        record.update(observed_exit_qpc=row['exit_observed_qpc'],exit_code=row['exit_code']);self.sync()

    def cleanup_known(self):
        if self.leases is not None:
            try:self.leases.close_all()
            except BaseException:self.api.controls_uncertain=True
        self.sync()
        if not self.j['port_leases_closed'] or not self.j['core_stdio_closed']:self.api.controls_uncertain=True
