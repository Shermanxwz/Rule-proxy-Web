"""Opt-in kernel probe. The parent must first put this process in a new netns.

All addresses are synthetic and confined to two nested namespaces. No real
proxy account, external network, login, host route, or host firewall is used.
"""
from pathlib import Path
import json
import os
import select
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from ruleproxy.linux_global_runtime import DEVICE, ROUTE_TABLE, ROUTING_MARK, ROUTING_PROTOCOL, nft_guard, rule_plan


def run(arguments, data=None, check=True):
    return subprocess.run(arguments, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=check, timeout=10)


def echo_peer(peer):
    with peer:
        peer.settimeout(10)
        try:
            while True:
                data=peer.recv(4096)
                if not data:return
                peer.sendall(data)
        except OSError:pass


def echo_server(family, kind, address, port):
    peer=socket.socket(family,kind)
    if family==socket.AF_INET6:peer.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    peer.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);peer.bind((address,port))
    if kind==socket.SOCK_STREAM:
        peer.listen(8)
        def serve():
            while True:
                try:connection,_=peer.accept()
                except OSError:return
                threading.Thread(target=echo_peer,args=(connection,),daemon=True).start()
    else:
        def serve():
            while True:
                try:data,remote=peer.recvfrom(4096);peer.sendto(data,remote)
                except OSError:return
    threading.Thread(target=serve,daemon=True).start()
    return peer


def client():
    if os.stat('/proc/self/ns/net').st_ino==int(os.environ['RULEPROXY_PARENT_NETNS']):
        raise RuntimeError('Refusing socket probes in the parent network namespace')
    print(json.dumps({'pid':os.getpid(),'uid':os.geteuid(),'namespace':os.stat('/proc/self/ns/net').st_ino}),flush=True)
    servers=[];cached=None
    for line in sys.stdin:
        request=json.loads(line);operation=request['operation'];answer=False
        try:
            if operation=='stop':return
            if operation=='listen':
                servers.extend([echo_server(socket.AF_INET,socket.SOCK_STREAM,'0.0.0.0',18879),
                                echo_server(socket.AF_INET6,socket.SOCK_STREAM,'::',18879)])
                answer=True
            elif operation=='peers':
                from ruleproxy.linux_global_runtime import inbound_peers
                answer=inbound_peers()
            elif operation=='close':
                if cached:cached.close();cached=None
                answer=True
            elif operation=='read_private':
                with open(request['path'],'rb') as reader:reader.read(1)
                answer=True
            elif operation=='loopback':
                server=echo_server(socket.AF_INET,socket.SOCK_STREAM,'127.0.0.1',0);servers.append(server)
                with socket.create_connection(('127.0.0.1',server.getsockname()[1]),timeout=.4) as peer:
                    peer.sendall(b'local');answer=peer.recv(5)==b'local'
            elif operation=='reuse':
                cached.sendall(b'reuse');answer=cached.recv(5)==b'reuse'
            else:
                family=socket.AF_INET6 if request['version']==6 else socket.AF_INET
                kind=socket.SOCK_DGRAM if operation in ('udp','dns') else socket.SOCK_STREAM
                address=request.get('address') or ('2001:4860:1::1' if family==socket.AF_INET6 else '8.8.4.4')
                peer=socket.socket(family,kind);peer.settimeout(.4)
                try:
                    if request.get('marked'):peer.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,ROUTING_MARK)
                    peer.connect((address,request.get('port',18880 if kind==socket.SOCK_DGRAM else 18878)))
                    payload=(b'\x72\x70\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                             if operation=='dns' else b'probe')
                    peer.sendall(payload);received=peer.recv(4096)
                    answer=(received[:2]==payload[:2]) if operation=='dns' else received==payload
                    if operation=='open':cached=peer;peer=None
                finally:
                    if peer:peer.close()
        except OSError:answer=False
        print(json.dumps({'result':answer}),flush=True)


def main():
    if len(sys.argv)>1 and sys.argv[1]=='--client':client();return
    original=int(os.environ['RULEPROXY_PARENT_NETNS'])
    current=os.stat('/proc/self/ns/net').st_ino
    if os.geteuid()!=0 or original==current:
        raise RuntimeError('Refusing all network operations outside the requested isolated namespace')
    run(['ip','link','set','lo','up'])
    child=subprocess.Popen(['unshare','--net','--fork','--kill-child=KILL','--',sys.executable,__file__,'--client'],
                           stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        if not select.select([child.stdout],[],[],10)[0]:raise RuntimeError('nested namespace did not start')
        hello=json.loads(child.stdout.readline());pid=hello['pid']
        assert hello['namespace'] not in (original,current)
        def inside(arguments,data=None,check=True):
            return run(['nsenter','--target',str(pid),'--net','--',*arguments],data,check)
        def rpc(operation,**fields):
            child.stdin.write(json.dumps({'operation':operation,**fields})+'\n');child.stdin.flush()
            if not select.select([child.stdout],[],[],5)[0]:raise RuntimeError('client probe timed out')
            return json.loads(child.stdout.readline())['result']
        run(['ip','link','add','rpgw','type','veth','peer','name','rpclient'])
        run(['ip','link','set','rpclient','netns',str(pid)])
        run(['ip','address','add','8.8.8.8/24','dev','rpgw'])
        run(['ip','address','add','8.8.4.4/32','dev','rpgw'])
        run(['ip','-6','address','add','2001:4860::1/64','dev','rpgw','nodad'])
        run(['ip','-6','address','add','2001:4860:1::1/128','dev','rpgw','nodad'])
        run(['ip','link','set','rpgw','up'])
        inside(['ip','link','set','lo','up']);inside(['ip','link','set','rpclient','up'])
        inside(['ip','address','add','8.8.8.9/24','dev','rpclient'])
        inside(['ip','-6','address','add','2001:4860::2/64','dev','rpclient','nodad'])
        inside(['ip','route','add','default','via','8.8.8.8'])
        inside(['ip','-6','route','add','default','via','2001:4860::1'])
        servers=[echo_server(family,kind,address,port)
                 for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::'))
                 for kind,port in ((socket.SOCK_STREAM,18878),(socket.SOCK_DGRAM,18880))]
        for version in (4,6):
            for operation in ('tcp','udp'):assert rpc(operation,version=version),(operation,version,'baseline')
        assert rpc('open',version=4,address='8.8.8.8')
        assert rpc('listen')
        incoming4=socket.create_connection(('8.8.8.9',18879),timeout=2)
        incoming6=socket.create_connection(('2001:4860::2',18879),timeout=2)
        for peer in (incoming4,incoming6):peer.sendall(b'input');assert peer.recv(5)==b'input'
        peers=rpc('peers');assert '8.8.8.8/32' in peers and '2001:4860::1/128' in peers,peers
        inside(['nft','--file','-'],b'table inet fixture_unrelated { comment "preserve me"; }\n')
        text=nft_guard(1000,'a'*32,peers).encode()
        inside(['nft','--check','--file','-'],text);inside(['nft','--file','-'],text)
        assert rpc('loopback')
        assert not rpc('reuse'),'existing outbound connection escaped guard'
        rpc('close')
        inside(['ip','link','add',DEVICE,'type','dummy']);inside(['ip','link','set',DEVICE,'up'])
        commands=[['-'+str(version),'route','add','table',str(ROUTE_TABLE),'default','dev',DEVICE,'metric','8879','proto',str(ROUTING_PROTOCOL)] for version in (4,6)]
        commands+=rule_plan(peers)
        for command in commands:inside(['ip',*command])
        for peer in (incoming4,incoming6):peer.sendall(b'alive');assert peer.recv(5)==b'alive','existing inbound session lost'
        for version in (4,6):
            for operation in ('tcp','udp'):
                assert not rpc(operation,version=version),(operation,version,'unmarked escaped')
                assert rpc(operation,version=version,marked=True),(operation,version,'marked core carrier failed')
        # A vanished core/TUN removes its connected defaults. Persistent nft
        # must block fallback via the physical route in both address families.
        inside(['ip','link','delete',DEVICE])
        for version in (4,6):
            for operation in ('tcp','udp'):
                assert not rpc(operation,version=version),(operation,version,'core failure restored direct')
        assert rpc('loopback')
        for peer in (incoming4,incoming6):peer.sendall(b'alive');assert peer.recv(5)==b'alive'
        for command in reversed(commands):
            if command[1]=='route':continue  # kernel removed routes with the dummy interface
            deletion=list(command);deletion[2]='del';inside(['ip',*deletion])
        inside(['nft','delete','table','inet','ruleproxy_global_1000'])
        inside(['nft','list','table','inet','fixture_unrelated'])
        for version in (4,6):
            for operation in ('tcp','udp'):assert rpc(operation,version=version),(operation,version,'explicit stop failed')
        incoming4.close();incoming6.close()
        print(json.dumps({'guard_probe':'passed','families':[4,6],'protocols':['TCP','UDP'],
                          'existing_outbound_blocked':True,'existing_inbound_preserved':True,
                          'loopback_preserved':True,'core_mark_bypass_verified':True,
                          'tun_disappearance_keeps_block':True,'explicit_stop_restores':True,
                          'unrelated_table_preserved':True}))
    finally:
        if child.poll() is None:
            try:child.stdin.write('{"operation":"stop"}\n');child.stdin.flush();child.wait(timeout=3)
            except (OSError,subprocess.TimeoutExpired):child.kill();child.wait(timeout=3)


if __name__=='__main__':main()
