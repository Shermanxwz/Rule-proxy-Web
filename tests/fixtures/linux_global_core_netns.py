"""Real fixed-core/production Lease acceptance, confined to disposable netns.

The SOCKS node and all targets use virtual public IPs on a private veth. The
node refuses every non-fixture destination (including its recorded DoH probe).
This tests Lease/core/guard/routing; interactive polkit UI is deliberately not
exercised by a headless root CI job.
"""
from pathlib import Path
import ipaddress
import json
import os
import pwd
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(Path(__file__).parent))
from ruleproxy import linux_global_runtime as runtime
from linux_global_guard_netns import run,echo_server

NODE4='93.184.216.35';APP4='93.184.216.34';TARGET4='93.184.216.36';DNS4='93.184.216.37'
NODE6='2606:4700:93::35';APP6='2606:4700:93::34';TARGET6='2606:4700:93::36'


def isolated():
    if os.geteuid()!=0 or os.stat('/proc/self/ns/net').st_ino==int(os.environ['RULEPROXY_PARENT_NETNS']):
        raise RuntimeError('Refusing privileged networking outside a new disposable namespace')


def read_exact(peer,size):
    result=bytearray()
    while len(result)<size:
        part=peer.recv(size-len(result))
        if not part:raise OSError('SOCKS fixture closed')
        result.extend(part)
    return bytes(result)


def address_from_stream(peer,kind):
    if kind==1:return socket.inet_ntop(socket.AF_INET,read_exact(peer,4))
    if kind==4:return socket.inet_ntop(socket.AF_INET6,read_exact(peer,16))
    if kind==3:return read_exact(peer,read_exact(peer,1)[0]).decode('ascii')
    raise OSError('invalid fixture destination')


def udp_address(raw):
    if len(raw)<4 or raw[:3]!=b'\x00\x00\x00':raise OSError('invalid SOCKS datagram')
    kind=raw[3]
    size=4 if kind==1 else 16 if kind==4 else 0
    if not size or len(raw)<6+size:raise OSError('unexpected datagram address')
    family=socket.AF_INET if kind==1 else socket.AF_INET6
    return socket.inet_ntop(family,raw[4:4+size]),struct.unpack('!H',raw[4+size:6+size])[0],raw[6+size:],raw[:6+size]


class SocksNode:
    def __init__(self):
        self.counts={'tcp4':0,'tcp6':0,'udp4':0,'udp6':0,'dns_doh_rejected':0}
        self.lock=threading.Lock()
        self.listener=socket.socket();self.listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.listener.bind((NODE4,19080));self.listener.listen(16)
        threading.Thread(target=self.accept,daemon=True).start()

    def bump(self,key):
        with self.lock:self.counts[key]+=1

    def accept(self):
        while True:
            try:peer,_=self.listener.accept()
            except OSError:return
            threading.Thread(target=self.serve,args=(peer,),daemon=True).start()

    def serve(self,peer):
        with peer:
            peer.settimeout(15)
            try:
                version,methods=read_exact(peer,2);assert version==5
                read_exact(peer,methods);peer.sendall(b'\x05\x00')
                version,command,_,kind=read_exact(peer,4);assert version==5
                address=address_from_stream(peer,kind);port=struct.unpack('!H',read_exact(peer,2))[0]
                if command==3:
                    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind((NODE4,0));udp.settimeout(.3)
                    active=threading.Event();active.set()
                    def relay():
                        with udp:
                            while active.is_set():
                                try:raw,origin=udp.recvfrom(65535)
                                except socket.timeout:continue
                                except OSError:return
                                try:
                                    target,destination,data,header=udp_address(raw)
                                    if target not in (TARGET4,TARGET6) or destination!=18880:continue
                                    family=socket.AF_INET6 if ':' in target else socket.AF_INET
                                    with socket.socket(family,socket.SOCK_DGRAM) as forward:
                                        forward.settimeout(1);forward.sendto(data,(target,destination));answer,_=forward.recvfrom(65535)
                                    self.bump('udp6' if family==socket.AF_INET6 else 'udp4')
                                    udp.sendto(header+answer,origin)
                                except OSError:continue
                    threading.Thread(target=relay,daemon=True).start()
                    peer.sendall(b'\x05\x00\x00\x01'+socket.inet_aton(NODE4)+struct.pack('!H',udp.getsockname()[1]))
                    try:
                        while peer.recv(4096):pass
                    finally:active.clear()
                elif command==1 and address in (TARGET4,TARGET6) and port==18878:
                    with socket.create_connection((address,port),timeout=2) as target:
                        self.bump('tcp6' if ':' in address else 'tcp4')
                        peer.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
                        peer.settimeout(None);target.settimeout(None)
                        while True:
                            ready,_,_=select.select([peer,target],[],[],10)
                            if not ready:return
                            for source in ready:
                                chunk=source.recv(65535)
                                if not chunk:return
                                (target if source is peer else peer).sendall(chunk)
                else:
                    if address=='1.1.1.1' and port==443:self.bump('dns_doh_rejected')
                    # Every non-fixture request fails here; never try the Internet.
                    peer.sendall(b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00')
            except (OSError,AssertionError,ValueError):return


def helper():
    isolated()
    runtime.CORE=Path(os.environ['RULEPROXY_FIXTURE_CORE'])
    runtime.RUN_ROOT=Path(os.environ['RULEPROXY_FIXTURE_RUN'])
    runtime._root_directory(runtime.RUN_ROOT)
    class FixtureSystem(runtime.System):
        def run(self,name,arguments,data=None,check=True):
            result=super().run(name,arguments,data=data,check=False)
            if check and result.returncode:
                # Only fixed public fixture addresses are present in this job;
                # show bounded native diagnostics without printing config text.
                raise runtime.GlobalRuntimeError('fixture_command_failed',name+' '+repr(arguments)+': '+result.stderr[-2000:].decode('utf-8','replace'))
            return result
    uid=int(os.environ['RULEPROXY_FIXTURE_UID']);lease=runtime.Lease(uid,FixtureSystem())
    app=None
    print(json.dumps({'pid':os.getpid(),'namespace':os.stat('/proc/self/ns/net').st_ino}),flush=True)
    def application(operation,**fields):
        app.stdin.write(json.dumps({'operation':operation,**fields})+'\n');app.stdin.flush()
        if not select.select([app.stdout],[],[],5)[0]:raise RuntimeError('ordinary-user probe timed out')
        return json.loads(app.stdout.readline())['result']
    def core_log_tail():
        log=lease.directory/'core.log'
        if not log.exists():return ''
        tail=log.read_bytes()[-3500:].decode('utf-8','replace')
        if lease.controller_secret:tail=tail.replace(lease.controller_secret,'[redacted]')
        return tail
    def network_fact(arguments):
        result=lease.system.run('ip',arguments,check=False)
        raw=result.stdout[:3000].decode('utf-8','replace')
        try:value=json.loads(raw)
        except ValueError:value=raw
        return {'exit_code':result.returncode,'value':value,
                'stderr':result.stderr[:500].decode('utf-8','replace')}
    try:
        for line in sys.stdin:
            request=json.loads(line);operation=request['operation']
            try:
                if operation=='app_start':
                    def ordinary_user():
                        os.setgroups([]);os.setgid(pwd.getpwuid(uid).pw_gid);os.setuid(uid)
                    app=subprocess.Popen([sys.executable,str(Path(__file__).with_name('linux_global_guard_netns.py')),'--client'],
                                         stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                         text=True,cwd='/',preexec_fn=ordinary_user)
                    hello=json.loads(app.stdout.readline());assert hello['uid']==uid
                    result=hello
                elif operation=='app':result=application(**request['request'])
                elif operation=='start':
                    identity=runtime._identity(app.pid)
                    source='proxies:\n- name: fixture-node\n  type: socks5\n  server: '+NODE4+'\n  port: 19080\n  udp: true\nrules: ["MATCH,fixture-node"]\n'
                    result=lease.start({'operation':'start','source':source,'secret':'public-fixture-not-root-secret',
                                        'mixed_port':10809,'controller_port':19097,'selected_node':'fixture-node',
                                        'owner_pid':app.pid,'owner_start':identity['start']})
                elif operation=='kill_core':
                    lease.core.kill();lease.core.wait(timeout=5);lease.watch();result=lease.snapshot()
                elif operation=='status':result=lease.snapshot()
                elif operation=='diagnostics':
                    links=lease.system.json('ip',['-j','address','show'])
                    rules=lease.system.json('ip',['-j','-6','rule','show'])
                    result={'lease':lease.snapshot(),'app_error':application('diagnostics'),
                            'interfaces':[{'name':row.get('ifname'),'flags':row.get('flags'),
                                           'addresses':[{key:item.get(key) for key in ('family','local','prefixlen')}
                                                        for item in row.get('addr_info',[])]} for row in links],
                            'owned_v6_rules':[row for row in rules if runtime.RULE_PRIORITY<=int(row.get('priority',-1))
                                              <=runtime.RULE_PRIORITY+runtime.RULE_SPAN],
                            'v6_route_get':network_fact(['-j','-6','route','get',TARGET6]),
                            'v6_route_get_original_source':network_fact(['-j','-6','route','get',TARGET6,'from',APP6]),
                            'v6_owned_routes':network_fact(['-j','-6','route','show','table',str(runtime.ROUTE_TABLE)]),
                            'core_log_tail':core_log_tail()}
                elif operation=='stop_capture':result=lease.stop()
                elif operation=='quit':break
                else:raise RuntimeError('unknown fixture operation')
                print(json.dumps({'ok':True,'result':result}),flush=True)
            except Exception as error:
                print(json.dumps({'ok':False,'type':type(error).__name__,
                                  'detail':str(error) if isinstance(error,runtime.GlobalRuntimeError) else 'fixture operation failed',
                                  'core_log_tail':core_log_tail()}),flush=True)
    finally:
        if lease.guard or lease.journal.exists():lease.stop()
        if app and app.poll() is None:
            try:application('stop');app.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):app.kill();app.wait(timeout=3)


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--helper':helper();return
    isolated()
    original=int(os.environ['RULEPROXY_PARENT_NETNS']);current=os.stat('/proc/self/ns/net').st_ino
    uid=ROOT.stat().st_uid or 65534
    directory=Path('/run')/('ruleproxy-global-core-ci-'+str(os.getpid()))
    directory.mkdir(mode=0o755);directory.chmod(0o755)
    core=directory/'mihomo';child=None;incoming=[]
    try:
        shutil.copyfile(ROOT/'bin/linux-amd64/mihomo',core);core.chmod(0o755)
        run(['ip','link','set','lo','up'])
        environment=dict(os.environ,RULEPROXY_FIXTURE_CORE=str(core),RULEPROXY_FIXTURE_RUN=str(directory/'lease'),
                         RULEPROXY_FIXTURE_UID=str(uid))
        child=subprocess.Popen(['unshare','--net','--fork','--kill-child=KILL','--',sys.executable,__file__,'--helper'],
                               stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=environment)
        if not select.select([child.stdout],[],[],10)[0]:raise RuntimeError('helper namespace did not start')
        hello=json.loads(child.stdout.readline());pid=hello['pid'];assert hello['namespace'] not in (original,current)
        def inside(arguments):return run(['nsenter','--target',str(pid),'--net','--',*arguments])
        def rpc(operation,**fields):
            child.stdin.write(json.dumps({'operation':operation,**fields})+'\n');child.stdin.flush()
            if not select.select([child.stdout],[],[],45)[0]:raise RuntimeError('real helper probe timed out')
            result=json.loads(child.stdout.readline());assert result.get('ok'),result
            return result.get('result')
        def app(operation,**fields):return rpc('app',request={'operation':operation,**fields})
        run(['ip','link','add','rpgw','type','veth','peer','name','rpclient']);run(['ip','link','set','rpclient','netns',str(pid)])
        for address in (NODE4+'/24',TARGET4+'/32',DNS4+'/32'):run(['ip','address','add',address,'dev','rpgw'])
        for address in (NODE6+'/64',TARGET6+'/128'):run(['ip','-6','address','add',address,'dev','rpgw','nodad'])
        run(['ip','link','set','rpgw','up'])
        inside(['ip','link','set','lo','up']);inside(['ip','link','set','rpclient','up'])
        inside(['ip','address','add',APP4+'/24','dev','rpclient'])
        inside(['ip','-6','address','add',APP6+'/64','dev','rpclient','nodad'])
        inside(['ip','route','add','default','via',NODE4]);inside(['ip','-6','route','add','default','via',NODE6])
        servers=[echo_server(family,kind,udp_target if kind==socket.SOCK_DGRAM else wildcard,port)
                 for family,wildcard,udp_target in ((socket.AF_INET,'0.0.0.0',TARGET4),
                                                    (socket.AF_INET6,'::',TARGET6))
                 for kind,port in ((socket.SOCK_STREAM,18878),(socket.SOCK_DGRAM,18880))]
        dns_count=[0];dns_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns_socket.bind((DNS4,53))
        def dns_sink():
            while True:
                try:data,peer=dns_socket.recvfrom(4096);dns_count[0]+=1;dns_socket.sendto(data,peer)
                except OSError:return
        threading.Thread(target=dns_sink,daemon=True).start()
        node=SocksNode();rpc('app_start')
        for version,address in ((4,TARGET4),(6,TARGET6)):
            for operation in ('tcp','udp'):assert app(operation,version=version,address=address),('baseline',operation,version)
        assert app('dns',version=4,address=DNS4,port=53);baseline_dns=dns_count[0]
        assert app('listen')
        incoming=[socket.create_connection((address,18879),timeout=2) for address in (APP4,APP6)]
        for peer in incoming:peer.sendall(b'alive');assert peer.recv(5)==b'alive'
        status=rpc('start');assert status['running'] and status['strict_isolation'],status
        private_path=str(directory/'lease'/('state-'+str(uid))/'config.yaml')
        assert not app('read_private',path=private_path),'ordinary user could read privileged controller credentials'
        for version,address in ((4,TARGET4),(6,TARGET6)):
            for operation in ('tcp','udp'):
                if not app(operation,version=version,address=address):
                    diagnostics=rpc('diagnostics')
                    with node.lock:diagnostics['node_counts']=dict(node.counts)
                    raise AssertionError(json.dumps({'phase':'captured','operation':operation,'version':version,
                                                     'diagnostics':diagnostics},sort_keys=True))
        assert app('loopback')
        for peer in incoming:peer.sendall(b'alive');assert peer.recv(5)==b'alive','pre-existing inbound reply lost'
        before=node.counts['dns_doh_rejected'];app('dns',version=4,address=DNS4,port=53)
        deadline=time.monotonic()+3
        while node.counts['dns_doh_rejected']==before and time.monotonic()<deadline:time.sleep(.05)
        assert dns_count[0]==baseline_dns,'DNS escaped to physical DNS sink'
        assert node.counts['dns_doh_rejected']>before,'DNS was neither observed through the node nor independently proven intercepted'
        for protocol in ('tcp4','tcp6','udp4','udp6'):assert node.counts[protocol]>0,(protocol,node.counts)
        fault=rpc('kill_core');assert not fault['running'] and fault['protection_active'] and fault['strict_isolation'],fault
        for version,address in ((4,TARGET4),(6,TARGET6)):
            for operation in ('tcp','udp'):assert not app(operation,version=version,address=address),('core crash escaped',operation,version)
        app('dns',version=4,address=DNS4,port=53);assert dns_count[0]==baseline_dns,'DNS escaped after core crash'
        assert app('loopback')
        for peer in incoming:peer.sendall(b'alive');assert peer.recv(5)==b'alive','inbound management lost on core crash'
        stopped=rpc('stop_capture');assert stopped['state']=='idle' and not stopped['protection_active'],stopped
        for version,address in ((4,TARGET4),(6,TARGET6)):
            for operation in ('tcp','udp'):assert app(operation,version=version,address=address),('explicit stop',operation,version)
        assert app('dns',version=4,address=DNS4,port=53);assert dns_count[0]>baseline_dns
        print(json.dumps({'real_core_probe':'passed','actual_fixed_mihomo':True,'production_lease':True,
                          'ordinary_user_app':True,'families':[4,6],'tcp_udp_via_fixture_socks':True,
                          'dns_observed_via_node_and_blocked':True,'core_crash_keeps_independent_guard':True,
                          'preexisting_inbound_preserved':True,'private_controller_not_readable':True,
                          'explicit_stop_restores':True,'polkit_dialog_exercised':False}))
    finally:
        for peer in incoming:peer.close()
        if child and child.poll() is None:
            try:child.stdin.write('{"operation":"quit"}\n');child.stdin.flush();child.wait(timeout=15)
            except (OSError,subprocess.TimeoutExpired):child.kill();child.wait(timeout=5)
        shutil.rmtree(directory)


if __name__=='__main__':main()
