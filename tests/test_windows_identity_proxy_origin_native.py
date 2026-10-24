"""Compiled fake I/O/QPC only; the executable contains no Win32/Winsock calls."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
NATIVE=ROOT/'.github/native'

HARNESS=r'''
#include "windows_identity_proxy_origin_transport.hpp"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
using rp_origin::Code;using rp_origin::Io;using rp_origin::Failure;using rp_origin::Close;
rpb::Config config(bool local=true){
    rpb::Config c{{},{},49152,54321,0,10000};c.case_id.fill(0x22);
    if(local)c.origin_authority=rpb::OriginAuthority::LocalLoopback;return c;
}
struct Observer {
    std::uint64_t tick=0;unsigned feed=0,ends=0;bool after_eof_expire=false;
    rpb::Relay core;
    Observer():core(config()){
        core.apply({0,4,0,0,{nullptr,0},48});
        const auto ready=rpb::encode_frame(config(),2),request=rpb::encode_frame(config(),3);
        core.apply({0,1,0,0,ready.view(),0});core.apply({0,1,0,0,request.view(),0});
    }
    bool sample(){++tick;if(tick>=10000)return false;core.apply({0,0,0,tick,{nullptr,0},0});return core.snapshot().failure==rpb::Failure::None;}
    std::uint32_t remaining_ms(){return tick<10000?static_cast<std::uint32_t>((std::min)(10000-tick,std::uint64_t(100))):0;}
    bool write_progress(std::uint32_t count){core.apply({0,4,1,tick,{nullptr,0},count});return core.snapshot().failure==rpb::Failure::None;}
    bool response_bytes(rpb::ByteView bytes){++feed;core.apply({0,2,0,tick,bytes,0});return core.snapshot().failure==rpb::Failure::None;}
    bool response_eof(){++ends;core.apply({0,3,0,tick,{nullptr,0},0});return core.snapshot().failure==rpb::Failure::None;}
};
struct API {
    Observer& observer;bool made=false,open_error=false,configure_error=false,connect_error=false;
    bool connect_pending=false,finish_error=false,wrong_peer=false,send_zero=false,send_over=false,close_error=false;
    bool shutdown_error=false,no_eof=false,expire_on_eof=false,expire_on_connect=false,expire_on_send=false;
    bool block_send=false,blocked=false,block_receive=false,receive_blocked=false;
    std::size_t send_chunk=256,receive_chunk=256,offset=0;unsigned closes=0,write_waits=0,read_waits=0;
    std::vector<std::uint8_t> response;std::vector<std::uint8_t> sent;
    explicit API(Observer& o):observer(o){const auto expected=rpb::expected_response(config());response.assign(expected.data.begin(),expected.data.begin()+expected.size);}
    bool created()const{return made;}
    Io open(){if(open_error)return {Code::Error,0,10001};made=true;return configure_error?Io{Code::Error,0,10002}:Io{Code::Progress,0,0};}
    Io connect(std::uint16_t port){if(port!=54321)return {Code::Error,0,10003};if(expire_on_connect)observer.tick=10000;
        return connect_error?Io{Code::Error,0,10061}:connect_pending?Io{Code::WouldBlock,0,10035}:Io{Code::Progress,0,0};}
    Io connect_result(){return finish_error?Io{Code::Error,0,10061}:Io{Code::Progress,0,0};}
    bool peer_check(std::uint16_t port){return port==54321&&!wrong_peer;}
    Io wait_write(std::uint32_t ms){++write_waits;observer.tick+=ms;return {Code::Progress,0,0};}
    Io wait_read(std::uint32_t ms){++read_waits;observer.tick+=ms;return {no_eof?Code::WouldBlock:Code::Progress,0,0};}
    Io send(rpb::ByteView bytes){
        if(block_send&&!blocked){blocked=true;return {Code::WouldBlock,0,10035};}
        if(send_zero)return {Code::Progress,0,0};
        if(send_over)return {Code::Progress,static_cast<std::uint32_t>(bytes.size+1),0};
        const auto count=(std::min)(bytes.size,send_chunk);sent.insert(sent.end(),bytes.data,bytes.data+count);
        if(expire_on_send)observer.tick=10000;
        return {Code::Progress,static_cast<std::uint32_t>(count),0};
    }
    Io shutdown_send(){return shutdown_error?Io{Code::Error,0,10004}:Io{Code::Progress,0,0};}
    Io receive(std::uint8_t* bytes,std::size_t capacity){
        if(block_receive&&!receive_blocked){receive_blocked=true;return {Code::WouldBlock,0,10035};}
        if(offset==response.size()){
            if(no_eof)return {Code::WouldBlock,0,10035};
            if(expire_on_eof)observer.tick=10000;
            return {Code::Eof,0,0};
        }
        const auto count=(std::min)((std::min)(response.size()-offset,capacity),receive_chunk);
        std::memcpy(bytes,response.data()+offset,count);offset+=count;
        return {Code::Progress,static_cast<std::uint32_t>(count),0};
    }
    Io close(){++closes;return close_error?Io{Code::Error,0,10005}:Io{Code::Progress,0,0};}
};
unsigned scenarios=0;
bool require(bool value,const char* name){++scenarios;if(!value)std::printf("FAIL %s\n",name);return value;}
bool run(API& api,Observer& observer,rp_origin::Facts& facts,std::uint16_t port=54321){
    const auto request=rpb::relay_request(config()),expected=rpb::expected_response(config());
    return rp_origin::roundtrip(api,observer,port,request.view(),expected.view(),facts);
}
int main(){
    bool good=true;
    const auto request=rpb::relay_request(config()),response=rpb::expected_response(config());
    for(std::size_t chunk=1;chunk<=request.size;++chunk){
        Observer observer;API api(observer);api.send_chunk=chunk;api.connect_pending=true;api.block_send=true;api.block_receive=true;
        rp_origin::Facts facts;const bool result=run(api,observer,facts);
        good=require(result&&facts.request_bytes==request.size&&facts.response_bytes==response.size&&facts.response_exact
            &&facts.response_eof&&facts.send_shutdown&&facts.socket_close==Close::Confirmed&&api.closes==1
            &&api.sent.size()==request.size&&std::memcmp(api.sent.data(),request.data.data(),request.size)==0
            &&observer.feed==1&&observer.ends==1&&(observer.core.snapshot().observations&8u)!=0,"partial-send")&&good;
    }
    for(std::size_t chunk=1;chunk<=response.size;++chunk){
        Observer observer;API api(observer);api.receive_chunk=chunk;rp_origin::Facts facts;
        good=require(run(api,observer,facts)&&facts.response_exact&&facts.response_eof&&api.closes==1,"partial-receive")&&good;
    }
    for(std::size_t prefix=0;prefix<response.size;++prefix){
        Observer observer;API api(observer);api.response.resize(prefix);rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.failure==Failure::Response&&facts.response_eof
            &&!facts.response_exact&&api.closes==1&&observer.ends==0,"truncated-response-eof")&&good;
    }
    for(std::size_t i=0;i<response.size;++i){
        Observer observer;API api(observer);api.response[i]^=1;rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.failure==Failure::Response&&!facts.response_exact&&api.closes==1,"wrong-byte")&&good;
    }
    {
        Observer observer;API api(observer);api.response.push_back('x');rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.failure==Failure::Response&&api.closes==1,"surplus-after-exact-prefix")&&good;
    }
    {
        Observer observer;API api(observer);api.response.assign(257,'x');rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.failure==Failure::Response&&facts.response_bytes==257&&api.closes==1,"bounded-257")&&good;
    }
    for(unsigned kind=0;kind<10;++kind){
        Observer observer;API api(observer);rp_origin::Facts facts;
        switch(kind){case 0:api.open_error=true;break;case 1:api.configure_error=true;break;
        case 2:api.connect_error=true;break;case 3:api.connect_pending=true;api.finish_error=true;break;
        case 4:api.wrong_peer=true;break;case 5:api.send_zero=true;break;case 6:api.send_over=true;break;
        case 7:api.shutdown_error=true;break;case 8:api.no_eof=true;break;case 9:api.close_error=true;break;}
        const bool result=run(api,observer,facts);
        good=require(!result&&facts.failure!=Failure::None&&api.closes==(kind==0?0u:1u),"failure-once-cleanup")&&good;
        if(kind==9)good=require(facts.response_exact&&facts.response_eof&&facts.socket_close==Close::Uncertain,"sticky-response-after-close-failure")&&good;
        if(kind==8)good=require(facts.failure==Failure::Deadline&&!facts.response_eof&&observer.ends==0,"explicit-eof-required")&&good;
    }
    {
        Observer observer;API api(observer);api.expire_on_eof=true;rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.response_eof&&facts.response_exact&&facts.failure==Failure::Deadline
            &&observer.ends==0&&api.closes==1,"late-eof-sticky-no-protocol-success")&&good;
    }
    {
        Observer observer;API api(observer);api.expire_on_connect=true;rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.connect_completed&&facts.failure==Failure::Deadline&&api.closes==1,
            "late-connect-sticky")&&good;
    }
    {
        Observer observer;API api(observer);api.expire_on_send=true;rp_origin::Facts facts;
        good=require(!run(api,observer,facts)&&facts.request_complete&&facts.request_bytes==request.size
            &&facts.failure==Failure::Deadline&&api.closes==1,"late-full-send-sticky")&&good;
    }
    {
        Observer observer;API api(observer);rp_origin::Facts facts;
        good=require(!run(api,observer,facts,49152)&&!facts.socket_created&&api.closes==0,"bad-port-no-open")&&good;
    }
    auto legacy=config(false),local=config();
    const auto old_request=rpb::relay_request(legacy),new_request=rpb::relay_request(local);
    const std::string old_text(reinterpret_cast<const char*>(old_request.data.data()),old_request.size);
    const std::string new_text(reinterpret_cast<const char*>(new_request.data.data()),new_request.size);
    good=require(old_text.find("Host: 10.0.2.2:54321")!=std::string::npos
        &&new_text.find("Host: 127.0.0.1:54321")!=std::string::npos,"authority-profiles")&&good;
    for(std::uint8_t kind=1;kind<=5;++kind){
        const auto a=rpb::encode_frame(legacy,kind),b=rpb::encode_frame(local,kind);
        good=require(a.size==48&&rpb::equal(a.view(),b.view()),"unchanged-frame-wire")&&good;
    }
    local.origin_authority=static_cast<rpb::OriginAuthority>(2);
    good=require(!rpb::valid_config(local),"closed-authority")&&good;
    std::printf("ORIGIN_FAKE_SCENARIOS %u\n",scenarios);
    return good?0:1;
}
'''


class NativeOriginTests(unittest.TestCase):
    def test_compiled_fake_partial_io_eof_deadline_cleanup_and_legacy_wire(self):
        compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++')
        self.assertIsNotNone(compiler,'run inside the installed x64 compiler developer shell')
        with tempfile.TemporaryDirectory() as directory:
            work=Path(directory);source=work/'origin-fake.cpp';source.write_text(HARNESS,encoding='utf-8')
            exe=work/('origin-fake.exe' if os.name=='nt' else 'origin-fake')
            if os.name=='nt':
                command=[compiler,'/nologo','/W4','/WX','/std:c++17','/EHsc','/MT','/O2',
                         '/I'+str(NATIVE),'/Fo'+str(work/'origin-fake.obj'),'/Fe'+str(exe),str(source)]
            else:command=[compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(source),'-o',str(exe)]
            built=subprocess.run(command,cwd=work,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(exe)],cwd=work,capture_output=True,text=True,timeout=15)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertRegex(ran.stdout,r'ORIGIN_FAKE_SCENARIOS [2-9][0-9]{2}')

    def test_a_default_entry_and_constructor_are_preserved(self):
        source=(NATIVE/'windows_identity_proxy_pipe_actor.cpp').read_text(encoding='utf-8')
        self.assertIn('#ifndef RULEPROXY_PROXY_PIPE_LIBRARY\nint wmain',source)
        self.assertIn('std::uint16_t relay_port=49153',source)
        self.assertIn('authority=rpb::OriginAuthority::GuestFixture',source)
        self.assertIn('if(argc!=13)return 2;',source)
        self.assertIn('rpb::ByteView pending_http()const',source)

    def test_b_is_fixed_loopback_no_name_resolution_or_client_listener(self):
        source=(NATIVE/'windows_identity_proxy_origin_actor.cpp').read_text(encoding='utf-8')
        self.assertIn('htonl(INADDR_LOOPBACK)',source)
        self.assertIn('SO_EXCLUSIVEADDRUSE',source)
        self.assertIn('WSA_FLAG_NO_HANDLE_INHERIT',source)
        for forbidden in ('getaddrinfo(', 'GetAddrInfo', 'WinHttp', 'SO_REUSEADDR', 'AF_INET6'):
            self.assertNotIn(forbidden,source)
        self.assertIn('if(argc!=14)return 2;',source)
        self.assertIn('if(argc!=9)return 2;',source)

    def test_manifest_helper_pins_all_five_sources_and_never_executes_actor(self):
        source=(ROOT/'.github/build_windows_identity_proxy_origin_actor.ps1').read_text(encoding='utf-8')
        for name in ('windows_identity_proxy_origin_actor.cpp','windows_identity_actor.cpp',
                     'windows_identity_proxy_bridge_core.hpp','windows_identity_proxy_pipe_actor.cpp',
                     'windows_identity_proxy_origin_transport.hpp'):
            self.assertIn(name,source);self.assertEqual(len(hashlib.sha256((NATIVE/name).read_bytes()).hexdigest()),64)
        for flag in ('/W4','/WX','/MT','/O2','/guard:cf'):
            self.assertIn(flag,source)
        self.assertIn('compileOnly=$true;runtimeAcceptance=$false',source)
        self.assertNotIn('& $exe',source)


if __name__=='__main__':unittest.main()
