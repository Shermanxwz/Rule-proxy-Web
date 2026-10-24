"""Compile only portable production codec/pump with finite fake I/O; never an actor."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

NATIVE = Path(__file__).resolve().parents[1]/'.github/native'
HARNESS = r'''
#include "windows_identity_lpac_stream_contract.hpp"
#include <deque>
#include <cstdio>
#include <cstdlib>
using namespace lpac_stream;
unsigned checks=0;void check(bool b){++checks;if(!b){std::fprintf(stderr,"check %u failed\n",checks);std::exit(1);}}
std::vector<std::uint8_t> body(std::size_t n,unsigned seed){std::vector<std::uint8_t> b(n);for(std::size_t i=0;i<n;++i)b[i]=static_cast<std::uint8_t>((i*73+seed)^(i>>7));return b;}
struct Wire{std::deque<std::uint8_t> data;bool closed=false;};
struct Fake {
 Wire& input;Wire& output;std::vector<std::uint8_t> source,sink;std::size_t at=0,cap=0;unsigned turn=0,closes=0,finishes=0;bool saw_eof=false;
 bool block=false,failed=false;unsigned budget=1000000;
 bool sample(){return budget--!=0;}
 IO pipe_read(std::uint8_t* p,std::size_t n){if(saw_eof)return {};if(input.data.empty()){if(input.closed){saw_eof=true;return {IOState::eof,0};}return {};}
  const auto k=std::min({n,input.data.size(),cap});for(std::size_t i=0;i<k;++i){p[i]=input.data.front();input.data.pop_front();}return {IOState::progress,k};}
 IO pipe_write(const std::uint8_t* p,std::size_t n){if(failed)return {IOState::error,0};if(output.closed||output.data.size()>=4096)return {};const auto k=std::min({n,cap,4096-output.data.size()});output.data.insert(output.data.end(),p,p+k);return {IOState::progress,k};}
 IOState connect(){return IOState::progress;}
 IO consume(const std::uint8_t* p,std::size_t n){if(block&&turn++%5!=0)return {};const auto k=std::min(n,cap+3);sink.insert(sink.end(),p,p+k);return {IOState::progress,k};}
 IOState finish_inbound(){++finishes;return IOState::progress;}
 IO produce(std::uint8_t* p,std::size_t n){if(at==source.size())return {IOState::eof,0};const auto k=std::min({n,source.size()-at,cap+137});std::memcpy(p,source.data()+at,k);at+=k;return {IOState::progress,k};}
 bool close_writer(){check(!output.closed);output.closed=true;++closes;return true;}
};
Config cfg(bool front,unsigned a=8193,unsigned b=12289){Config c;c.front=front;c.run.fill(0x12);c.case_id.fill(0x34);c.send=front?a:b;c.receive=front?b:a;return c;}
void pair(unsigned cap,bool blocked){Wire a,b;Node front(cfg(true)),relay(cfg(false));auto request=body(8193,7),response=body(12289,211);
 Fake f{b,a,request,{},0,cap},r{a,b,response,{},0,cap+4};f.block=blocked;r.block=blocked;
 for(unsigned i=0;i<300000&&!(front.complete()&&relay.complete());++i){step(front,f);step(relay,r);if(front.failure()||relay.failure())std::fprintf(stderr,"cap%u iteration%u front%s relay%s\n",cap,i,front.json().c_str(),relay.json().c_str());check(!front.failure()&&!relay.failure());}
 check(front.complete()&&relay.complete());check(f.sink==response&&r.sink==request);check(f.closes==1&&r.closes==1&&f.finishes==1&&r.finishes==1);
 check(a.data.empty()&&b.data.empty());check(front.json().find("\"tx_credit_received\":8193")!=std::string::npos);
 check(relay.json().find("\"rx_credit_sent\":8193")!=std::string::npos);
}
std::vector<std::uint8_t> open(){Node n(cfg(true));const auto* p=n.output();return {p,p+n.output_size()};}
std::vector<std::uint8_t> frame(Kind kind,unsigned seq,unsigned length=0,unsigned credit=0){auto p=open();p[5]=static_cast<std::uint8_t>(kind);put32(p.data()+40,seq);put32(p.data()+44,length);put32(p.data()+52,credit);p.resize(Header+length,0x79);return p;}
void handshake(Node& front,Node& relay){const auto* p=front.output();std::vector<std::uint8_t> a(p,p+front.output_size());front.written(a.size());check(relay.feed(a.data(),a.size())&&relay.needs_connect());relay.connected();p=relay.output();std::vector<std::uint8_t> b(p,p+relay.output_size());relay.written(b.size());check(front.feed(b.data(),b.size())&&front.opened()&&relay.opened());}
void adversarial(){
 for(unsigned credit:{0u,1u,4097u}){Node f(cfg(true)),r(cfg(false));handshake(f,r);auto p=frame(Kind::credit,2,0,credit);check(!f.feed(p.data(),p.size())&&f.failure()!=nullptr);}
 for(bool duplicate:{false,true}){Node f(cfg(true,1,1)),r(cfg(false,1,1));handshake(f,r);auto p=frame(Kind::data,2,1);check(r.feed(p.data(),p.size()));p=frame(Kind::fin,3);check(r.feed(p.data(),p.size()));p=frame(duplicate?Kind::fin:Kind::data,4,duplicate?0:1);check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true,1,1)),r(cfg(false,1,1));handshake(f,r);auto p=frame(Kind::data,2,2);check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);for(unsigned seq=2;seq<6;++seq){auto p=frame(Kind::data,seq,1024);check(r.feed(p.data(),p.size()));}auto p=frame(Kind::data,6,1);check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true,65536,65536)),r(cfg(false,65536,65536));handshake(f,r);for(unsigned seq=2;seq<=256;++seq){auto p=frame(Kind::data,seq,1);check(r.feed(p.data(),p.size()));}auto p=frame(Kind::data,257,1);check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);auto p=frame(Kind::reset,2);check(!r.feed(p.data(),p.size())&&std::string(r.failure())=="peer_reset");}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);auto p=frame(Kind::data,2,1);check(r.feed(p.data(),p.size()));check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);auto p=frame(Kind::data,2,1025);check(!r.feed(p.data(),p.size()));}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);auto p=frame(Kind::fin,2);check(!r.feed(p.data(),p.size()));}
 {auto c=cfg(true);c.send=65537;Node n(c);check(n.failure()!=nullptr);c=cfg(false);c.receive=65537;Node m(c);check(m.failure()!=nullptr);}
 {Node f(cfg(true,1,1)),r(cfg(false,1,1));handshake(f,r);const std::uint8_t x[2]={1,2};check(!f.source(x,2));}
 {Node f(cfg(true)),r(cfg(false));handshake(f,r);f.source_eof();check(f.failure()!=nullptr);}
}
int main(){
 for(unsigned cap:{1u,3u,13u,64u,511u,1024u}){pair(cap,false);pair(cap,true);}
 const auto original=open();check(original.size()==64);
 for(std::size_t at=0;at<64;++at)for(unsigned bit=0;bit<8;++bit){auto changed=original;changed[at]^=static_cast<std::uint8_t>(1u<<bit);Node n(cfg(false));check(!n.feed(changed.data(),changed.size())&&n.failure()!=nullptr&&!n.needs_connect());}
 for(std::size_t split=1;split<64;++split){Node n(cfg(false));check(n.feed(original.data(),split));check(n.feed(original.data()+split,64-split));check(n.needs_connect());}
 {Node n(cfg(false));n.feed(original.data(),23);n.peer_eof();check(n.failure()!=nullptr);}
 {Node n(cfg(true));n.peer_eof();check(n.failure()!=nullptr);}
 {Node n(cfg(false));n.feed(original.data(),64);n.feed(original.data(),64);check(n.failure()!=nullptr);}
 {auto c=cfg(true);c.send=0;Node n(c);check(n.failure()!=nullptr);}
 {Wire a,b;Node n(cfg(true));Fake f{b,a,body(8193,1),{},0,13};f.budget=0;step(n,f);check(n.failure()!=nullptr&&a.data.empty()&&f.closes==0);}
 {Wire a,b;Node n(cfg(true));Fake f{b,a,body(8193,1),{},0,13};f.failed=true;step(n,f);check(n.failure()!=nullptr&&f.closes==0);}
 adversarial();std::printf("RPS1_PRODUCTION_ASSERTIONS %u\n",checks);return 0;
}
'''


class StreamNativeTests(unittest.TestCase):
    def test_production_partial_io_credit_fin_eof_and_header_mutations(self):
        compiler=shutil.which('cl.exe') if os.name=='nt' else shutil.which('c++')
        self.assertIsNotNone(compiler, 'installed developer compiler required')
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);src=root/'fake.cpp';src.write_bytes(HARNESS.encode())
            exe=root/('fake.exe' if os.name=='nt' else 'fake')
            args=([compiler,'/nologo','/std:c++17','/W4','/WX','/EHsc','/MT','/O2','/I'+str(NATIVE),'/Fo'+str(root/'fake.obj'),'/Fe'+str(exe),str(src)] if os.name=='nt' else
                  [compiler,'-std=c++17','-Wall','-Wextra','-Werror','-O2','-I',str(NATIVE),str(src),'-o',str(exe)])
            built=subprocess.run(args,cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(built.returncode,0,built.stdout+built.stderr)
            ran=subprocess.run([str(exe)],cwd=root,capture_output=True,text=True,timeout=30)
            self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
            self.assertRegex(ran.stdout,r'RPS1_PRODUCTION_ASSERTIONS [0-9]+')
            print(ran.stdout.strip())

if __name__=='__main__':unittest.main()
