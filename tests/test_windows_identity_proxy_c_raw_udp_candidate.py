"""Work-only portable fake UDP driver. No native actor, socket or DNS execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'
REPO=ROOT
HARNESS=r'''
#include "windows_identity_dns_raw_udp.hpp"
#include <cstdio>
#include <cstring>
#include <vector>
namespace d=rp_dns_udp;
using d::Code;using d::Io;
enum class Mode {Success,Startup,StartupVersion,Create,Inheritance,Nonblocking,ConnectDeny,ConnectPending,
    ConnectPendingDeny,Peer,SendDeny,SendWouldBlock,ShortSend,ReadError,Zero,WrongSource,WrongPort,
    WrongTx,WrongQuestion,WrongFlags,WrongAnswer,Extra,Truncated,Close,Cleanup,SelectWrite,SelectRead,
    Timeout,LateSend,LateReceive,LateConnectDeny,LateReceiveError,Oversize};
struct Time {
    unsigned calls=0,limit=1000;bool qpc=false;
    bool sample(){return ++calls<limit;}
    unsigned remaining_ms()const{return 10;}
    bool qpc_failed()const{return qpc;}
};
struct Fake {
    Mode mode=Mode::Success;Time& time;bool active=false,allocated=false;
    unsigned starts=0,opens=0,connects=0,sends=0,receives=0,closes=0,cleanups=0,polls=0;
    std::uint16_t local_port=54321,peer_port=53;
    d::Packet bytes;bool valid_query=true;int delta_offset=-1;unsigned delta_bit=0;
    explicit Fake(Time& t,Mode m=Mode::Success):mode(m),time(t){d::packet(std::string(32,'a'),bytes);}
    Io ok(unsigned n=0){return {Code::Progress,n,0};}Io error(unsigned n=10013){return {Code::Error,0,n};}
    bool started()const{return active;}bool created()const{return allocated;}
    Io start(){++starts;active=mode!=Mode::Startup;
        return mode==Mode::Startup?error(10093):mode==Mode::StartupVersion?error(10092):ok();}
    Io cleanup(){++cleanups;return mode==Mode::Cleanup?error(10093):ok();}
    Io open(){++opens;allocated=mode!=Mode::Create;return allocated?ok():error();}
    Io clear_inheritance(){return mode==Mode::Inheritance?error(5):ok();}
    Io set_nonblocking(){return mode==Mode::Nonblocking?error(10022):ok();}
    Io connect(){++connects;
        if(mode==Mode::LateConnectDeny){time.limit=time.calls+1;return error();}
        if(mode==Mode::ConnectDeny)return error();
        return mode==Mode::ConnectPending||mode==Mode::ConnectPendingDeny?Io{Code::WouldBlock,0,10035}:ok();}
    Io connect_result(){return mode==Mode::ConnectPendingDeny?error():ok();}
    Io peer_check(){return mode==Mode::Peer?error(0):ok();}
    Io wait_write(unsigned ms){++polls;if(!ms||ms>100)return error(0);
        return mode==Mode::SelectWrite?error(10022):ok();}
    Io wait_read(unsigned ms){++polls;if(!ms||ms>100)return error(0);
        if(mode==Mode::Timeout)return {Code::WouldBlock,0,0};
        return mode==Mode::SelectRead?error(10022):ok();}
    Io send(rpb::ByteView sent){++sends;
        valid_query=sent.size==bytes.query.size()&&rpb::equal(sent,{bytes.query.data(),bytes.query.size()});
        if(mode==Mode::SendDeny)return error();
        if(mode==Mode::SendWouldBlock)return {Code::WouldBlock,0,10035};
        if(mode==Mode::LateSend)time.limit=time.calls+1;
        return ok(mode==Mode::ShortSend?61u:62u);}
    d::Datagram receive(std::uint8_t* target,std::size_t capacity){++receives;
        if(capacity!=1233)return {error(0),false,0};
        if(mode==Mode::LateReceive||mode==Mode::LateReceiveError)time.limit=time.calls+1;
        if(mode==Mode::ReadError||mode==Mode::LateReceiveError)return {error(10054),false,0};
        std::vector<std::uint8_t> copy(bytes.response.begin(),bytes.response.end());
        if(delta_offset>=0)copy[static_cast<std::size_t>(delta_offset)]^=static_cast<std::uint8_t>(1u<<delta_bit);
        if(mode==Mode::WrongTx)copy[0]^=1;
        if(mode==Mode::WrongQuestion)copy[13]^=1;
        if(mode==Mode::WrongFlags)copy[2]^=1;
        if(mode==Mode::WrongAnswer)copy.back()^=1;
        if(mode==Mode::Extra)copy.push_back(0);
        if(mode==Mode::Truncated)copy.pop_back();
        if(mode==Mode::Zero)copy.clear();
        if(mode==Mode::Oversize)copy.resize(1233);
        if(!copy.empty())std::memcpy(target,copy.data(),copy.size());
        return {ok(static_cast<unsigned>(copy.size())),mode!=Mode::WrongSource,
            static_cast<std::uint16_t>(mode==Mode::WrongPort?54:53)};}
    Io close(){++closes;return mode==Mode::Close?error(10038):ok();}
};
unsigned cases=0;
bool require(bool ok,const char* name){++cases;if(!ok)std::printf("FAIL %s\n",name);return ok;}
int main(){bool good=true;d::Packet p;
    good=require(d::packet("0123456789abcdef0123456789abcdef",p)&&p.transaction_id==0x0123
        &&p.query.size()==62&&p.response.size()==78,"packet-fixed-length-and-big-endian-tx")&&good;
    for(unsigned i=0;i<256;++i){std::string item(32,'a');item[0]=static_cast<char>(i);d::Packet q;
        good=require(d::packet(item,q)==((i>='0'&&i<='9')||(i>='a'&&i<='f')),"closed-lowercase-hex")&&good;}
    for(unsigned n=0;n<66;++n){d::Packet q;good=require(d::packet(std::string(n,'a'),q)==(n==32),"exact-case-length")&&good;}
    for(unsigned m=0;m<=static_cast<unsigned>(Mode::Oversize);++m){const auto mode=static_cast<Mode>(m);
        Time time;if(mode==Mode::Timeout)time.limit=50;Fake api(time,mode);d::Facts f;
        const bool passed=d::exchange(api,time,std::string(32,'a'),f);
        const bool expected=mode==Mode::Success||mode==Mode::ConnectPending;
        good=require(passed==expected,"only-exact-complete-exchange-passes")&&good;
        good=require(api.starts==1&&api.opens<=1&&api.connects<=1&&api.sends<=1&&api.receives<=1
            &&api.closes==(api.allocated?1u:0u)&&api.cleanups==(api.active?1u:0u)&&api.valid_query,
            "single-attempt-and-one-consumed-close-cleanup")&&good;
        good=require(f.socket_created==api.allocated&&f.wsa_startup==api.active,"created-and-started-truthful")&&good;
        if(expected)good=require(f.send_complete&&f.send_bytes==62&&f.datagram_received&&f.response_bytes==78
            &&f.source_loopback&&f.source_port==53&&f.response_exact&&f.peer_loopback&&f.wsa_cleanup
            &&f.socket_close==d::Close::Confirmed&&f.within_deadline,"exact-positive-facts")&&good;
        if(mode==Mode::Create)good=require(f.failure==d::Failure::Create&&f.wsa_error==10013
            &&!f.connect_attempted&&!f.send_attempted,"socket-10013-not-send-denial")&&good;
        if(mode==Mode::ConnectDeny||mode==Mode::ConnectPendingDeny)good=require(f.failure==d::Failure::Connect
            &&f.wsa_error==10013&&f.connect_attempted&&!f.connect_completed&&!f.send_attempted,"connect-error-has-no-send")&&good;
        if(mode==Mode::SendDeny)good=require(f.failure==d::Failure::Send&&f.wsa_error==10013
            &&f.connect_completed&&f.send_attempted&&!f.send_complete&&!f.datagram_received,"send-denial-narrow-stage")&&good;
        if(mode==Mode::Inheritance)good=require(f.failure==d::Failure::Inheritance&&f.win32_error==5
            &&f.wsa_error==0&&!f.send_attempted,"win32-error-never-invented-wsa-error")&&good;
        if(mode==Mode::Zero)good=require(f.datagram_received&&f.response_bytes==0&&!f.response_exact
            &&f.failure==d::Failure::Response,"zero-datagram-is-not-eof")&&good;
        if(mode==Mode::LateReceive)good=require(f.response_exact&&f.datagram_received&&f.send_complete
            &&!f.within_deadline&&f.failure==d::Failure::Deadline,"late-real-response-sticky-not-pass")&&good;
        if(mode==Mode::LateSend)good=require(f.send_complete&&!f.within_deadline&&!f.receive_attempted
            &&f.failure==d::Failure::Deadline,"late-send-sticky-no-new-io")&&good;
        if(mode==Mode::LateConnectDeny)good=require(f.failure==d::Failure::Connect&&f.wsa_error==10013
            &&!f.within_deadline&&!f.send_attempted,"late-10013-error-retained-but-not-timely-deny")&&good;
        if(mode==Mode::LateReceiveError)good=require(f.failure==d::Failure::Receive&&f.wsa_error==10054
            &&!f.within_deadline&&f.receive_attempted,"late-real-error-stage-retained")&&good;
        if(mode==Mode::Timeout)good=require(f.failure==d::Failure::Deadline&&f.wsa_error==0
            &&f.send_complete&&!f.receive_attempted&&!f.datagram_received&&!f.within_deadline,"timeout-not-access-deny")&&good;
        if(mode==Mode::Close)good=require(f.response_exact&&f.socket_close==d::Close::Uncertain
            &&f.failure==d::Failure::Close&&f.wsa_cleanup,"close-uncertain-never-laundered")&&good;
        if(mode==Mode::Cleanup)good=require(f.response_exact&&!f.wsa_cleanup
            &&f.failure==d::Failure::WsaCleanup,"wsa-cleanup-failure-retains-positive")&&good;
    }
    for(bool qpc:{false,true}){Time t;t.limit=1;t.qpc=qpc;Fake api(t);d::Facts f;
        good=require(!d::exchange(api,t,std::string(32,'a'),f)&&api.starts==0&&api.opens==0
            &&!f.within_deadline&&f.failure==(qpc?d::Failure::Qpc:d::Failure::Deadline),"invalid-clock-never-initializes-wsa")&&good;}
    {Time t;Fake api(t);d::Facts f;good=require(!d::exchange(api,t,std::string(32,'A'),f)
        &&api.starts==0&&f.failure==d::Failure::Configuration,"invalid-case-no-wsa")&&good;}
    for(unsigned offset=0;offset<78;++offset)for(unsigned bit=0;bit<8;++bit){Time t;Fake api(t);
        api.delta_offset=static_cast<int>(offset);api.delta_bit=bit;d::Facts f;
        good=require(!d::exchange(api,t,std::string(32,'a'),f)&&f.datagram_received&&!f.response_exact
            &&f.failure==d::Failure::Response&&api.receives==1&&api.closes==1&&api.cleanups==1,
            "every-response-bit-rejected-by-exchange")&&good;}
    std::printf("RAW_UDP_FAKE_SCENARIOS %u\n",cases);return good?0:1;
}
'''

def compile_fake(text):
    compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++')
    if not compiler:raise AssertionError('developer compiler required')
    with tempfile.TemporaryDirectory() as directory:
        work=Path(directory).resolve();source=work/'raw-udp-fake.cpp';source.write_text(text,encoding='utf-8')
        exe=work/('raw-udp-fake.exe' if os.name=='nt' else 'raw-udp-fake')
        if os.name=='nt':command=[compiler,'/nologo','/W4','/WX','/std:c++17','/EHsc','/MT','/O2',
            '/I'+str(NATIVE),'/Fo'+str(work/'raw-udp-fake.obj'),'/Fe'+str(exe),str(source)]
        else:command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(source),'-o',str(exe)]
        built=subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=60)
        if built.returncode:raise AssertionError(built.stdout+built.stderr)
        ran=subprocess.run([str(exe)],cwd=work,capture_output=True,text=True,timeout=15)
        if ran.returncode:raise AssertionError(ran.stdout+ran.stderr)
        return ran.stdout

class RawUdpCandidateTests(unittest.TestCase):
    def test_portable_single_datagram_errors_deadline_sticky_and_once_cleanup(self):
        self.assertIn('RAW_UDP_FAKE_SCENARIOS',compile_fake(HARNESS))

    def test_whole_packet_matches_existing_fixture_and_every_response_bit_is_bound(self):
        nonce='0123456789abcdef0123456789abcdef'
        source=r'''
#include "windows_identity_dns_raw_udp.hpp"
#include <cstdio>
int main(){rp_dns_udp::Packet p;if(!rp_dns_udp::packet("0123456789abcdef0123456789abcdef",p))return 1;
    for(auto b:p.query)std::printf("%02x",b);std::puts("");
    for(auto b:p.response)std::printf("%02x",b);std::puts("");return 0;}
'''
        lines=compile_fake(source).splitlines();self.assertEqual(len(lines),2)
        query,response=map(bytes.fromhex,lines)
        spec=importlib.util.spec_from_file_location('fixture_raw07_readonly',REPO/'.github/windows_dns_fixture.py')
        fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
        result=fixture.answer_query(query,fixture.query_name(nonce))
        self.assertIsNotNone(result)
        expected=result[0] if isinstance(result,tuple) else result
        self.assertEqual(response,expected)
        self.assertEqual((len(query),len(response)),(62,78))
        self.assertEqual(struct.unpack('!6H',query[:12]),(0x0123,256,1,0,0,0))

    def test_serializer_closed_abi_and_late_facts(self):
        actor=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        serializer=actor[actor.index('std::string raw_udp_report('):actor.index('// RAW_UDP_PHASE_END')]
        source='#include "windows_identity_dns_raw_udp.hpp"\n#include <cstdio>\nconst char* boolean(bool b){return b?"true":"false";}\n'
        source+='std::string quoted(const char* p){return p?"\\\""+std::string(p)+"\\\"":"null";}\n'+serializer
        # Pure serializer supports all observed negatives without Windows headers/APIs.
        source+=r'''
int main(){rp_dns_udp::Facts f;f.send_attempted=true;f.send_complete=true;f.send_bytes=62;
    f.datagram_received=true;f.response_bytes=78;f.response_exact=true;f.within_deadline=false;
    f.failure=rp_dns_udp::Failure::Deadline;std::puts(raw_udp_report(std::string(32,'a'),f).c_str());return 0;}
'''
        row=json.loads(compile_fake(source))
        self.assertEqual(set(row),set(['server_address', 'server_port', 'query_name', 'query_type', 'transaction_id', 'query_bytes', 'within_deadline', 'wsa_startup', 'wsa_cleanup', 'socket_created', 'inheritance_cleared', 'nonblocking', 'connect_attempted', 'connect_completed', 'peer_loopback', 'local_port', 'peer_port', 'send_attempted', 'send_bytes', 'send_complete', 'receive_attempted', 'datagram_received', 'response_bytes', 'source_loopback', 'source_port', 'response_exact', 'socket_close', 'failure', 'wsa_error', 'win32_error']))
        self.assertEqual((row['query_bytes'],row['transaction_id']),(62,0xaaaa))
        self.assertTrue(row['response_exact'] and row['send_complete'] and row['datagram_received'])
        self.assertFalse(row['within_deadline']);self.assertEqual(row['failure'],'deadline')

    def test_original_non_client_lifecycle_op6_and_frozen_dependencies_remain_exact(self):
        candidate=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        self.assertEqual(hashlib.sha256(candidate[candidate.index('struct ListenerFacts'):].encode()).hexdigest(),
                         '7983eb65784f77ddf1cf81d2bf92a36136dfe72a984abd8c51a4b5f460b38cea')
        for marker in ('// DNS_PHASE_REPORT_BEGIN:','// DNS_PHASE_REPORT_END'):
            self.assertIn(marker,candidate)
        candidate_dns=candidate.split('// DNS_PHASE_REPORT_BEGIN:',1)[1].split('// DNS_PHASE_REPORT_END',1)[0]
        self.assertEqual(hashlib.sha256(candidate_dns.encode()).hexdigest(),'b222d3972f067097a3be0404e7418b9769aa364b64811297528ea7ff6c607b7e')
        expected={'windows_identity_proxy_origin_actor.cpp': '3d079e77e387ba77545c27f5b5c260f591657ef3a44384426cd2039fa8c04010', 'windows_identity_actor.cpp': '530482aae4c94707ae4da25c1c3e84d8da929a021fc23b09e59fec17fe28d553', 'windows_identity_proxy_bridge_core.hpp': 'f03e45166265f02a65abc12930efd73634a332596d22aa78cadc1267a80b6356', 'windows_identity_proxy_pipe_actor.cpp': '26636a6b9979e91452cf6e7d2049d6fbbfa43639a35708ee18d4a71e67fb8dd0', 'windows_identity_proxy_origin_transport.hpp': 'bed113e5e20064722cbb2c6d3e71b4d3ca6c4769ebd694c86997abec0af661c4', 'windows_identity_dns_standard_probe.hpp': 'bce69ff57a173525a9cff2731f4d05fe34b5144daeaa465b0d8bb5181432d28c'}
        for name,digest in expected.items():
            self.assertEqual(hashlib.sha256((NATIVE/name).read_bytes()).hexdigest(),digest)
        before=candidate[candidate.index('int client('):candidate.index('const auto state=command_file(')]
        self.assertNotIn('RawUdpAPI ',before)
        body=candidate[candidate.index('int client('):candidate.index('struct ListenerFacts')]
        self.assertLess(body.index('if(!fresh)'),body.index('command.operation==7'))
        self.assertLess(body.index('if(profile=="agentic-only")'),body.index('command.operation==7'))

    def test_new_header_has_no_socket_calls_or_ambient_targets_and_build_is_compile_only(self):
        header=(NATIVE/'windows_identity_dns_raw_udp.hpp').read_text(encoding='utf-8')
        for forbidden in ('WSAStartup(', 'socket(', 'DnsQuery', 'sendto(', 'recvfrom(', 'shutdown(', 'Sleep(', 'getaddrinfo'):
            self.assertNotIn(forbidden,header)
        source=(NATIVE/'windows_identity_proxy_c_actor.cpp').read_text(encoding='utf-8')
        adapter=source.split('// RAW_UDP_PHASE_BEGIN:',1)[1].split('struct RawUdpObserver',1)[0]
        self.assertIn('SOCK_DGRAM,IPPROTO_UDP',adapter);self.assertIn('htons(53)',adapter)
        for forbidden in ('shutdown(', 'getaddrinfo(', 'INADDR_ANY', 'SO_BROADCAST', 'SO_REUSEADDR'):
            self.assertNotIn(forbidden,adapter)
        helper=(ROOT/'.github/build_windows_identity_proxy_c_actor.ps1').read_text(encoding='utf-8')
        self.assertIn('ExpectedDnsRawUdpSha256',helper);self.assertIn('dnsRawUdpSha256=$hashes[8]',helper)
        self.assertIn('compileOnly=$true;runtimeAcceptance=$false',helper);self.assertNotIn('& $exe',helper)

if __name__=='__main__':unittest.main()
