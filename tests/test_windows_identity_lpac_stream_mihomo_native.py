"""Portable production A2 codec/adapters only. No actor, sockets, or Mihomo."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

NATIVE = Path(__file__).resolve().parents[1] / '.github/native'
HARNESS = r'''
#define RULEPROXY_LPAC_STREAM_MIHOMO_PORTABLE 1
#include "windows_identity_lpac_stream_mihomo_network_actor.cpp"
#include <deque>
#include <cstdio>
#include <cstdlib>
using namespace lpac_stream_mihomo;
using lpac_stream::Node;using lpac_stream::Config;using lpac_stream::step;
using Bytes=std::vector<std::uint8_t>;
unsigned checks=0;
void check(bool b){++checks;if(!b){std::fprintf(stderr,"A2 check %u failed\n",checks);std::exit(1);}}
const std::string case_id(32,'b');
constexpr std::uint16_t O=56123,M=56124;
Bytes message(bool response){const auto h=canonical(response,case_id,O,response?12289:8193);check(!h.empty());Bytes b(h.begin(),h.end());
 const auto total=response?12289u:8193u;while(b.size()<total)b.push_back(static_cast<std::uint8_t>((b.size()*73+(response?59:11))^(b.size()>>7)));
 const std::string marker="RPS1";std::copy(marker.begin(),marker.end(),b.begin()+static_cast<std::ptrdiff_t>(h.size()+19));return b;}
IO readq(std::deque<std::uint8_t>& q,std::uint8_t* p,std::size_t n,std::size_t cap){if(q.empty())return {};const auto k=std::min({q.size(),n,cap});
 for(std::size_t i=0;i<k;++i){p[i]=q.front();q.pop_front();}return {IOState::progress,k};}
struct SocksFake {
 Bytes sent;std::deque<std::uint8_t> input;std::size_t cap=1;bool receive_eof=false,error=false,idle_once=false,oversized=false;
 explicit SocksFake(std::size_t c):cap(c){const Bytes r={5,0,5,0,0,1,127,0,0,1,static_cast<std::uint8_t>(M>>8),static_cast<std::uint8_t>(M)};input.insert(input.end(),r.begin(),r.end());}
 IO send(const std::uint8_t* p,std::size_t n){if(error)return {IOState::error,0};if(oversized)return {IOState::progress,n+1};const auto k=std::min(n,cap);sent.insert(sent.end(),p,p+k);return {IOState::progress,k};}
 IO receive(std::uint8_t* p,std::size_t n){if(error)return {IOState::error,0};if(idle_once){idle_once=false;return {};}if(receive_eof)return {IOState::eof,0};return readq(input,p,n,cap);}
};
void protocol(){
 auto a=message(false),b=message(true);
 for(std::size_t cap:{1u,2u,3u,7u,64u,1024u})for(bool response:{false,true}){HTTP p(response,case_id,O,response?12289:8193);const auto& v=response?b:a;
  for(std::size_t at=0;at<v.size();at+=cap)check(p.feed(v.data()+at,std::min(cap,v.size()-at)));
  check(p.complete()&&!p.eof_seen());check(p.eof()&&p.eof_seen());check(!p.feed(v.data(),1));}
 for(bool response:{false,true}){const auto good=response?b:a;const auto h=canonical(response,case_id,O,static_cast<std::uint32_t>(good.size()));
  for(std::size_t i=0;i<h.size();++i)for(unsigned bit=0;bit<8;++bit){auto bad=good;bad[i]^=static_cast<std::uint8_t>(1u<<bit);HTTP p(response,case_id,O,static_cast<std::uint32_t>(good.size()));check(!p.feed(bad.data(),bad.size()));check(!p.complete());}
  {HTTP p(response,case_id,O,static_cast<std::uint32_t>(good.size()));check(p.feed(good.data(),good.size()-1));check(!p.eof());check(std::string(p.failure())=="early_eof");}
  {HTTP p(response,case_id,O,static_cast<std::uint32_t>(good.size()));auto bad=good;bad.push_back(0);check(!p.feed(bad.data(),bad.size()));check(std::string(p.failure())=="overflow");}
  {HTTP p(response,case_id,O,static_cast<std::uint32_t>(good.size()));check(p.feed(good.data(),good.size()));check(!p.feed(good.data(),1));}}
 // Production exact-header matcher rejects Host/CL/TE/duplicate/pipeline alternatives.
 for(const auto& text:{std::string("Host: localhost:"),std::string("Transfer-Encoding: chunked\r\n"),std::string("Content-Length: 1\r\nContent-Length: 2\r\n"),std::string("HTTP/1.1 100 Continue\r\n")}){
  auto v=a;std::copy(text.begin(),text.end(),v.begin());HTTP p(false,case_id,O,8193);check(!p.feed(v.data(),v.size()));}
 check(canonical(false,case_id,49152,8193).empty());check(canonical(false,"bad",O,8193).empty());
 for(std::size_t cap=1;cap<=13;++cap){SocksFake f(cap);f.idle_once=true;SOCKS s(O,M);for(unsigned k=0;k<100&&!s.complete()&&!s.failure();++k)s.pump(f);
  check(s.complete());check(f.sent==Bytes({5,1,0,5,1,0,1,127,0,0,1,static_cast<std::uint8_t>(O>>8),static_cast<std::uint8_t>(O)}));check(f.input.empty());
  check(s.json().find("\"handshake_wire_sent\":13")!=std::string::npos);check(s.json().find("\"handshake_wire_received\":12")!=std::string::npos);}
 for(std::size_t at=0;at<12;++at)for(unsigned bit=0;bit<8;++bit){SocksFake f(1);f.input[at]^=static_cast<std::uint8_t>(1u<<bit);SOCKS s(O,M);
  for(unsigned k=0;k<100&&!s.complete()&&!s.failure();++k)s.pump(f);check(s.failure()!=nullptr&&!s.complete());}
 for(unsigned n=0;n<12;++n){SocksFake f(1);while(f.input.size()>n)f.input.pop_back();SOCKS s(O,M);
  for(unsigned k=0;k<100&&!s.failure()&&!s.complete();++k){if(f.input.empty())f.receive_eof=true;s.pump(f);}check(s.failure()!=nullptr&&!s.complete());}
 {SocksFake f(1);f.error=true;SOCKS s(O,M);check(s.pump(f)==IOState::error&&!s.complete());}
 {SocksFake f(1);f.oversized=true;SOCKS s(O,M);check(s.pump(f)==IOState::error&&!s.complete());check(f.sent.empty());}
 {SOCKS s(O,O);check(s.failure()!=nullptr);}
}
struct Wire {std::deque<std::uint8_t> data;bool closed=false;};
struct Tcp {std::deque<std::uint8_t> request,response;bool origin_eof=false,client_shutdown=false;};
struct OriginFake {
 Tcp& tcp;Bytes response_source,request_sink,response_sink;std::size_t at=0,cap=1;unsigned shutdowns=0,source_reads=0;bool allow=true,flush_ok=true,overreport=false;
 OriginFake(Tcp& t,Bytes response,std::size_t c):tcp(t),response_source(std::move(response)),cap(c){}
 bool sample(){return allow;}
 IO receive(std::uint8_t* p,std::size_t n){if(overreport)return {IOState::progress,n+1};auto v=readq(tcp.request,p,n,cap);if(v.state==IOState::idle&&tcp.client_shutdown)return {IOState::eof,0};return v;}
 IOState before_response(const HTTP&){return IOState::progress;}
 IO source(std::uint8_t* p,std::size_t n){++source_reads;if(at==response_source.size())return {IOState::eof,0};const auto k=std::min({n,cap+3,response_source.size()-at});std::memcpy(p,response_source.data()+at,k);at+=k;return {IOState::progress,k};}
 IO send(const std::uint8_t* p,std::size_t n){const auto k=std::min(n,cap+5);tcp.response.insert(tcp.response.end(),p,p+k);return {IOState::progress,k};}
 bool record_request(const std::uint8_t* p,std::size_t n){request_sink.insert(request_sink.end(),p,p+n);return true;}
 bool record_response(const std::uint8_t* p,std::size_t n){response_sink.insert(response_sink.end(),p,p+n);return true;}
 bool flush_request(){return flush_ok;}bool flush_response(){return flush_ok;}
 bool shutdown_send(){++shutdowns;tcp.origin_eof=true;return true;}
};
struct RelayFake {
 Tcp& tcp;Bytes request_sink,response_sink,handshake;std::deque<std::uint8_t> socks_reply;std::size_t cap=1;bool connected=false,handshake_done=false,allow_eof=true,allow=true,flush_ok=true,shutdown_ok=true,close_ok=true;
 unsigned shutdowns=0,request_flushes=0,writer_closes=0;std::uint64_t sent=0,received=0;
 explicit RelayFake(Tcp& t,std::size_t c):tcp(t),cap(c){}
 bool sample(){return allow;}IOState connect(){connected=true;return IOState::progress;}
 IO send(const std::uint8_t* p,std::size_t n){const auto k=std::min(n,cap);sent+=k;
  if(!handshake_done){handshake.insert(handshake.end(),p,p+k);if(handshake.size()==3){check(handshake==Bytes({5,1,0}));socks_reply.push_back(5);socks_reply.push_back(0);}
   if(handshake.size()==13){check(handshake==Bytes({5,1,0,5,1,0,1,127,0,0,1,static_cast<std::uint8_t>(O>>8),static_cast<std::uint8_t>(O)}));
    const Bytes r={5,0,0,1,127,0,0,1,static_cast<std::uint8_t>(M>>8),static_cast<std::uint8_t>(M)};socks_reply.insert(socks_reply.end(),r.begin(),r.end());handshake_done=true;}}
  else tcp.request.insert(tcp.request.end(),p,p+k);return {IOState::progress,k};}
 IO receive(std::uint8_t* p,std::size_t n){auto v=readq(socks_reply,p,n,cap);if(v.state==IOState::progress){received+=v.bytes;return v;}
  v=readq(tcp.response,p,n,cap+7);received+=v.bytes;if(v.state==IOState::idle&&tcp.origin_eof&&allow_eof)return {IOState::eof,0};return v;}
 bool record_request(const std::uint8_t* p,std::size_t n){request_sink.insert(request_sink.end(),p,p+n);return true;}
 bool record_response(const std::uint8_t* p,std::size_t n){response_sink.insert(response_sink.end(),p,p+n);return true;}
 bool flush_request(){++request_flushes;return flush_ok;}
 bool shutdown_send(){check(tcp.origin_eof&&tcp.response.empty());++shutdowns;if(shutdown_ok)tcp.client_shutdown=true;return shutdown_ok;}
 bool close_writer(){++writer_closes;return close_ok;}
};
struct FrontFake {
 Wire& input;Wire& output;Bytes source,sink;std::size_t at=0,cap=1;bool saw_eof=false;unsigned finishes=0,closes=0;
 bool sample(){return true;}
 IO pipe_read(std::uint8_t* p,std::size_t n){auto v=readq(input.data,p,n,cap);if(v.state==IOState::idle&&!saw_eof&&input.closed){saw_eof=true;return {IOState::eof,0};}return v;}
 IO pipe_write(const std::uint8_t* p,std::size_t n){if(output.data.size()>=4096)return {};const auto k=std::min({cap,n,4096-output.data.size()});output.data.insert(output.data.end(),p,p+k);return {IOState::progress,k};}
 IOState connect(){return IOState::progress;}
 IO consume(const std::uint8_t* p,std::size_t n){const auto k=std::min(n,cap+9);sink.insert(sink.end(),p,p+k);return {IOState::progress,k};}
 IOState finish_inbound(){++finishes;return IOState::progress;}
 IO produce(std::uint8_t* p,std::size_t n){if(at==source.size())return {IOState::eof,0};const auto k=std::min({n,cap+3,source.size()-at});std::memcpy(p,source.data()+at,k);at+=k;return {IOState::progress,k};}
 bool close_writer(){check(!output.closed);++closes;output.closed=true;return true;}
};
struct RelayPipeFake {
 Wire& input;Wire& output;RelayFake& net;Relay<RelayFake>& flow;std::size_t cap=1;bool saw_eof=false;
 bool sample(){return net.sample();}
 IO pipe_read(std::uint8_t* p,std::size_t n){auto v=readq(input.data,p,n,cap);if(v.state==IOState::idle&&!saw_eof&&input.closed){saw_eof=true;return {IOState::eof,0};}return v;}
 IO pipe_write(const std::uint8_t* p,std::size_t n){if(output.data.size()>=4096)return {};const auto k=std::min({n,cap+3,4096-output.data.size()});output.data.insert(output.data.end(),p,p+k);return {IOState::progress,k};}
 IOState connect(){return flow.connect();}IO consume(const std::uint8_t* p,std::size_t n){return flow.consume(p,n);}IO produce(std::uint8_t* p,std::size_t n){return flow.produce(p,n);}
 IOState finish_inbound(){return flow.finish_inbound();}bool close_writer(){if(!flow.close_writer())return false;output.closed=true;return true;}
};
Config cfg(bool front){Config c;c.front=front;c.run.fill(0xaa);c.case_id.fill(0xbb);c.send=front?8193:12289;c.receive=front?12289:8193;return c;}
void integration(){
 for(std::size_t cap:{1u,3u,13u,64u,511u}){Wire a,b;Tcp tcp;auto request=message(false),response=message(true);Node front(cfg(true)),relay(cfg(false));
  FrontFake selected{b,a,request,{},0,cap};RelayFake net(tcp,cap+2);Relay<RelayFake> flow(net,case_id,O,M);RelayPipeFake driver{a,b,net,flow,cap+4};OriginFake origin_io(tcp,response,cap+6);Origin<OriginFake> origin(origin_io,case_id,O);
  for(unsigned i=0;i<300000&&!(front.complete()&&relay.complete()&&origin.complete());++i){step(front,selected);step(relay,driver);origin.step();check(!front.failure()&&!relay.failure()&&!flow.failure()&&!origin.failure());}
  check(front.complete()&&relay.complete()&&origin.complete());check(selected.sink==response&&net.request_sink==request&&net.response_sink==response&&origin_io.request_sink==request&&origin_io.response_sink==response);
  check(net.sent==8193+13&&net.received==12289+12);check(net.shutdowns==1&&origin_io.shutdowns==1&&net.writer_closes==1&&selected.closes==1);check(tcp.client_shutdown&&tcp.origin_eof);
  check(origin.adapter_json().find("\"response_started_without_waiting_for_request_eof\":true")!=std::string::npos);check(flow.adapter_json().find("\"send_shutdown_after_response_eof\":true")!=std::string::npos);}
 // A complete CL request causes the actual Origin state machine to respond while receive would still be idle.
 {Tcp tcp;const auto request=message(false),response=message(true);tcp.request.insert(tcp.request.end(),request.begin(),request.end());OriginFake io(tcp,response,17);Origin<OriginFake> origin(io,case_id,O);
  for(unsigned i=0;i<50000&&!origin.complete()&&!origin.failure();++i)origin.step();check(origin.complete()&&!tcp.client_shutdown&&io.request_sink==request&&io.response_sink==response);check(io.shutdowns==1);}
 // No proxy EOF => no TCP SD_SEND, even if all response bytes and RPS1 FIN are present.
 {Tcp tcp;RelayFake io(tcp,128);Relay<RelayFake> flow(io,case_id,O,M);for(unsigned i=0;i<100&&!flow.socks.complete();++i)flow.connect();auto req=message(false),res=message(true);
  std::size_t at=0;while(at<req.size()){auto v=flow.consume(req.data()+at,req.size()-at);check(v.state==IOState::progress);at+=v.bytes;}check(flow.finish_inbound()==IOState::progress&&io.shutdowns==0);
  tcp.response.insert(tcp.response.end(),res.begin(),res.end());tcp.origin_eof=true;io.allow_eof=false;std::array<std::uint8_t,1024> out{};
  for(unsigned i=0;i<5000;++i){auto v=flow.produce(out.data(),out.size());check(v.state!=IOState::error&&v.state!=IOState::eof);}check(flow.response.complete()&&io.shutdowns==0);
  io.allow_eof=true;check(flow.produce(out.data(),out.size()).state==IOState::eof&&io.shutdowns==1);check(flow.produce(out.data(),out.size()).state==IOState::eof&&io.shutdowns==1);}
 {Tcp tcp;RelayFake io(tcp,128);Relay<RelayFake> flow(io,case_id,O,M);for(unsigned i=0;i<100&&!flow.socks.complete();++i)flow.connect();auto req=message(false);std::size_t at=0;
  while(at<req.size()){auto v=flow.consume(req.data()+at,req.size()-at);at+=v.bytes;}check(flow.finish_inbound()==IOState::progress);tcp.origin_eof=true;std::uint8_t p[1];check(flow.produce(p,1).state==IOState::error&&io.shutdowns==0);}
 {Tcp tcp;OriginFake io(tcp,message(true),17);auto request=message(false);request.pop_back();tcp.request.insert(tcp.request.end(),request.begin(),request.end());tcp.client_shutdown=true;Origin<OriginFake> flow(io,case_id,O);
  for(unsigned i=0;i<5000&&!flow.failure();++i)flow.step();check(flow.failure()!=nullptr&&io.source_reads==0&&io.shutdowns==0&&flow.request.eof_seen());}
 {Tcp tcp;OriginFake io(tcp,message(true),17);io.allow=false;Origin<OriginFake> flow(io,case_id,O);check(!flow.step()&&flow.failure()!=nullptr&&io.source_reads==0);}
 {Tcp tcp;RelayFake io(tcp,17);io.allow=false;Relay<RelayFake> flow(io,case_id,O,M);check(flow.connect()==IOState::error&&!io.connected);}
 for(bool fail_shutdown:{false,true}){Tcp tcp;RelayFake io(tcp,1024);Relay<RelayFake> flow(io,case_id,O,M);for(unsigned i=0;i<100&&!flow.socks.complete();++i)flow.connect();
  auto req=message(false),res=message(true);std::size_t at=0;while(at<req.size()){auto v=flow.consume(req.data()+at,req.size()-at);at+=v.bytes;}check(flow.finish_inbound()==IOState::progress);
  tcp.response.insert(tcp.response.end(),res.begin(),res.end());tcp.origin_eof=true;io.shutdown_ok=!fail_shutdown;io.close_ok=false;std::array<std::uint8_t,1024> out{};
  IO v;for(unsigned i=0;i<100&&v.state!=IOState::eof&&v.state!=IOState::error;++i)v=flow.produce(out.data(),out.size());
  check(io.shutdowns==1);if(fail_shutdown){check(v.state==IOState::error&&!flow.close_writer()&&io.writer_closes==0);}else{check(v.state==IOState::eof&&!flow.close_writer()&&io.writer_closes==1);}}
}
std::vector<std::wstring> args(bool relay){return relay?std::vector<std::wstring>{L"a.exe",L"stream-a2-relay",std::wstring(32,L'a'),std::wstring(32,L'b'),L"C:\\x\\relay-report\\actor.json",L"100",L"104",L"1000",L"100",L"2000",L"S-1-5-21-1",L"none",L"8193",L"12289",L"56123",L"56124"}:
 std::vector<std::wstring>{L"a.exe",L"stream-a2-origin",std::wstring(32,L'a'),std::wstring(32,L'b'),L"C:\\x\\origin-report\\actor.json",L"C:\\x\\origin-report\\ready.json",L"1000",L"100",L"9500",L"S-1-5-21-1",L"8193",L"12289",L"56123",L"56124",L"C:\\x\\origin-control\\phase.bin",L"C:\\x\\origin-report\\request-held.json",L"C:\\x\\origin-control\\response-go.bin"};}
void serialization(){
 for(bool relay:{false,true}){auto a=args(relay);CLI c;check(cli(a,c));check(c.origin==O&&c.proxy==M&&c.legacy.size()==(relay?15u:12u));
  for(unsigned index:{relay?14u:12u,relay?15u:13u}){auto bad=a;bad[index]=L"49152";CLI p;check(!cli(bad,p));}
  {auto bad=a;bad[relay?15:13]=bad[relay?14:12];CLI p;check(!cli(bad,p));}{auto bad=a;bad[relay?9:8]=L"99999";CLI p;check(!cli(bad,p));}
  {auto bad=a;bad[relay?12:10]=L"8194";CLI p;check(!cli(bad,p));}{auto bad=a;bad[3]=bad[2];CLI p;check(!cli(bad,p));}
  Report r;r.relay=relay;r.run=std::string(32,'a');r.case_id=case_id;r.pid=1;r.frequency=100;r.start=1000;r.end=relay?2000:9500;r.last=1500;r.origin=O;r.proxy=M;
  HTTP req(false,case_id,O,8193),res(true,case_id,O,12289);r.http=std::string("{\"request\":")+req.json()+",\"response\":"+res.json()+",\"adapter\":null}";r.socks=relay?SOCKS(O,M).json():"null";
  std::printf("REPORT %s",report(r).c_str());if(!relay)std::printf("READY %s",ready(r).c_str());}
 std::vector<std::wstring> out;check(arguments(L"a.exe stream-a2-relay a b c d e f g h i j k l m n",out)&&out.size()==16);
 std::vector<std::wstring> invalid;check(!arguments(L"a.exe \"unterminated",invalid));
}
BarrierPlan binding(){BarrierPlan b;b.run.fill(0xaa);b.case_id.fill(0xbb);b.frequency=100;b.start=1000;b.end=9500;b.origin=O;b.proxy=M;return b;}
Command phase(){Command c;c.operation=1;c.pair_start=1100;c.pair_end=2100;c.issued=1150;return c;}
Command release(){auto c=phase();c.operation=2;c.issued=1300;c.ack=1250;c.pid=77;c.peer=51234;return c;}
HeldRequest facts(){HeldRequest h;h.pid=77;h.local=O;h.peer=51234;h.accepted=true;h.loopback=true;h.socket_held=true;h.request_complete=true;h.request_bytes=8193;return h;}
struct BarrierFake {
 std::uint64_t tick=1200,cutoff=9500;Bytes phase_raw,release_raw;bool phase_close=true,release_close=true,publish_ok=true,force_badclock=false;unsigned phase_reads=0,release_reads=0;std::string ack;
 bool sample(){return !force_badclock&&tick<cutoff;}std::uint64_t now()const{return tick;}void clamp(std::uint64_t end){cutoff=std::min(cutoff,end);}
 CommandRead read_command(bool rel,std::uint8_t* p,std::size_t n){if(rel)++release_reads;else ++phase_reads;const auto& b=rel?release_raw:phase_raw;if(b.empty())return {};
  std::memcpy(p,b.data(),std::min(n,b.size()));return {IOState::progress,b.size(),rel?release_close:phase_close};}
 bool publish_ack(const std::string& raw){ack=raw;return publish_ok;}
};
void arm_fake(BarrierFake& f){const auto p=encode_command(binding(),phase());f.phase_raw.assign(p.begin(),p.end());}
void release_fake(BarrierFake& f,Command c=release()){const auto p=encode_command(binding(),c);f.release_raw.assign(p.begin(),p.end());}
struct GatedOriginFake:OriginFake {
 Barrier<BarrierFake>& gate;BarrierFake& control;bool fail_post_send_qpc=false;
 GatedOriginFake(Tcp& t,Bytes r,Barrier<BarrierFake>& g,BarrierFake& c):OriginFake(t,std::move(r),111),gate(g),control(c){}
 bool sample(){return control.sample();}
 IOState before_response(const HTTP& p){check(p.complete());return gate.hold(facts());}
 IO send(const std::uint8_t* p,std::size_t n){auto v=OriginFake::send(p,n);if(fail_post_send_qpc&&v.bytes){control.force_badclock=true;v.state=IOState::error;}observe_socket_send(gate,v,!control.force_badclock);return v;}
};
void barriers(){
 const auto b=binding();const auto good=encode_command(b,phase());Command parsed;
 check(command(good.data(),good.size(),b,1200,parsed));
 for(std::size_t at=0;at<128;++at)if(at<88||at>=96)for(unsigned bit=0;bit<8;++bit){auto v=good;v[at]^=static_cast<std::uint8_t>(1u<<bit);check(!command(v.data(),v.size(),b,1200,parsed));}
 for(std::size_t n:{0u,127u,129u})check(!command(good.data(),n,b,1200,parsed));
 check(!command(good.data(),128,b,1149,parsed));check(!command(good.data(),128,b,2100,parsed));
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress&&io.cutoff==2100);io.tick=1250;check(gate.hold(facts())==IOState::idle&&io.ack.size()>0&&!gate.released());
  std::printf("ACK %s",io.ack.c_str());std::printf("BARRIER %s\n",gate.json().c_str());release_fake(io);io.tick=1350;check(gate.hold(facts())==IOState::progress&&gate.released());gate.note_send(1);check(gate.json().find("\"response_started_qpc\":1350")!=std::string::npos);}
 for(bool closed:{false,true}){BarrierFake io;arm_fake(io);io.phase_close=closed;Barrier<BarrierFake> gate(io,b);check((gate.arm()==IOState::progress)==closed);}
 for(unsigned mutation=0;mutation<8;++mutation){BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;check(gate.hold(facts())==IOState::idle);
  auto c=release();if(mutation==0)++c.pid;if(mutation==1)++c.peer;if(mutation==2)--c.ack;if(mutation==3)c.issued=1249;if(mutation==4)c.operation=1;release_fake(io,c);
  if(mutation==5)io.release_close=false;if(mutation==6)io.release_raw.pop_back();if(mutation==7)io.release_raw.push_back(0);io.tick=1350;check(gate.hold(facts())==IOState::error&&!gate.released());}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;check(gate.hold(facts())==IOState::idle);release_fake(io);io.tick=1450;check(gate.hold(facts())==IOState::error&&std::string(gate.failure())=="deadline");}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;check(gate.hold(facts())==IOState::idle);release_fake(io);io.tick=1449;check(gate.hold(facts())==IOState::progress);io.tick=2100;check(gate.hold(facts())==IOState::error);}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=2050;check(gate.hold(facts())==IOState::idle);check(gate.json().find("\"wait_deadline_qpc\":2100")!=std::string::npos);io.tick=2100;check(gate.hold(facts())==IOState::error);}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);auto h=facts();h.response_bytes=3;check(gate.hold(h)==IOState::error&&!gate.released());check(gate.json().find("\"response_bytes_before_release\":3")!=std::string::npos);}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);gate.note_send(1);check(std::string(gate.failure())=="release"&&gate.json().find("\"response_started_qpc\":1200")!=std::string::npos);}
 // Actual production Origin pump stays at zero source reads/sends until the typed release closes.
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;Tcp tcp;auto req=message(false);tcp.request.insert(tcp.request.end(),req.begin(),req.end());GatedOriginFake api(tcp,message(true),gate,io);Origin<GatedOriginFake> origin(api,case_id,O);
  for(unsigned i=0;i<300;++i)origin.step();check(origin.request.complete()&&api.source_reads==0&&api.response_sink.empty()&&!origin.complete()&&!gate.released());
  release_fake(io);io.tick=1350;for(unsigned i=0;i<2000&&!origin.complete()&&!origin.failure();++i)origin.step();check(origin.complete()&&gate.released()&&api.response_sink==message(true));}
 for(bool close_ok:{false,true}){BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;Tcp tcp;auto req=message(false);tcp.request.insert(tcp.request.end(),req.begin(),req.end());GatedOriginFake api(tcp,message(true),gate,io);Origin<GatedOriginFake> origin(api,case_id,O);
  for(unsigned i=0;i<300;++i)origin.step();check(api.source_reads==0);release_fake(io);io.release_close=close_ok;io.tick=close_ok?1450:1350;
  for(unsigned i=0;i<10&&!origin.failure();++i)origin.step();check(origin.failure()!=nullptr&&api.source_reads==0&&api.response_sink.empty());}
 {BarrierFake io;arm_fake(io);Barrier<BarrierFake> gate(io,b);check(gate.arm()==IOState::progress);io.tick=1250;Tcp tcp;auto req=message(false);tcp.request.insert(tcp.request.end(),req.begin(),req.end());GatedOriginFake api(tcp,message(true),gate,io);api.fail_post_send_qpc=true;Origin<GatedOriginFake> origin(api,case_id,O);
  for(unsigned i=0;i<300;++i)origin.step();release_fake(io);io.tick=1350;for(unsigned i=0;i<50&&!origin.failure();++i)origin.step();check(origin.failure()!=nullptr&&!origin.complete()&&!tcp.response.empty());check(gate.json().find("\"response_started_qpc\":null")!=std::string::npos);}
 // A real API-shaped overreport1025 lies within remaining8193, but outside asked1024.
 {Tcp tcp;OriginFake io(tcp,message(true),17);io.overreport=true;Origin<OriginFake> origin(io,case_id,O);check(!origin.step()&&origin.failure()!=nullptr);check(io.request_sink.empty()&&origin.request.seen()==0&&io.source_reads==0);}
}
int main(int argc,char** argv){if(argc!=2)return 2;const std::string mode=argv[1];if(mode=="protocol")protocol();else if(mode=="integration")integration();else if(mode=="serialization")serialization();else if(mode=="barrier")barriers();else return 2;
 std::printf("A2_PRODUCTION_ASSERTIONS %u\n",checks);return 0;}
'''


class MihomoNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.folder = tempfile.TemporaryDirectory()
        cls.root = Path(cls.folder.name).resolve()
        src = cls.root / 'fake.cpp'
        src.write_bytes(HARNESS.encode('ascii'))
        cls.exe = cls.root / ('fake.exe' if os.name == 'nt' else 'fake')
        compiler = shutil.which('cl.exe') if os.name == 'nt' else shutil.which('c++')
        if compiler is None:
            raise AssertionError('installed developer compiler required')
        cmd = ([compiler, '/nologo', '/std:c++17', '/W4', '/WX', '/EHsc', '/MT', '/O2', '/I'+str(NATIVE), '/Fo'+str(cls.root/'fake.obj'), '/Fe'+str(cls.exe), str(src)]
               if os.name == 'nt' else [compiler, '-std=c++17', '-Wall', '-Wextra', '-Werror', '-O2', '-I', str(NATIVE), str(src), '-o', str(cls.exe)])
        built = subprocess.run(cmd, cwd=cls.root, capture_output=True, text=True, timeout=60)
        if built.returncode:
            cls.folder.cleanup()
            raise AssertionError(built.stdout+built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.folder.cleanup()

    def run_mode(self, mode):
        result = subprocess.run([str(self.exe), mode], cwd=self.root, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertRegex(result.stdout, r'A2_PRODUCTION_ASSERTIONS [0-9]+')
        print(result.stdout.strip().splitlines()[-1])
        return result.stdout

    def test_production_http_and_socks_fragmented_negative_contracts(self):
        self.run_mode('protocol')

    def test_production_rps1_adapters_actual_partial_io_and_deferred_shutdown(self):
        self.run_mode('integration')

    def test_production_origin_barrier_original_clock_close_and_asked_bounds(self):
        raw = self.run_mode('barrier')
        ack = json.loads(next(s[4:] for s in raw.splitlines() if s.startswith('ACK ')))
        self.assertEqual(set(ack), {'schema_version','stage','role','run_id','case_id','pid','qpc','pair_qpc','ports','accepted_count','local_port','peer_port','peer_loopback','request_bytes','request_message_complete','request_eof_observed','response_bytes_sent','socket_held','phase_command_close_verified','phase_issued_qpc','wait_deadline_qpc','failure'})
        self.assertEqual(ack['response_bytes_sent'], 0)
        self.assertEqual(ack['wait_deadline_qpc'], 1450)
        barrier = json.loads(next(s[8:] for s in raw.splitlines() if s.startswith('BARRIER ')))
        self.assertEqual(set(barrier), {'phase_admitted','phase_command_closed','phase_issued_qpc','pair_start_qpc','pair_deadline_qpc','request_held_ack_published','ack_qpc','wait_deadline_qpc','response_bytes_before_release','socket_held_at_ack','release_attempted','release_admitted','release_command_closed','release_issued_qpc','release_admitted_qpc','response_started_qpc','failure'})
        self.assertIs(barrier['release_admitted'], False)

    def test_production_cli_and_report_renderers(self):
        raw = self.run_mode('serialization')
        reports = [json.loads(s[7:]) for s in raw.splitlines() if s.startswith('REPORT ')]
        self.assertEqual(len(reports), 2)
        common = {'schema_version','stage','role','run_id','case_id','pid','identity','qpc','limits','files','stream','pipe','network','admitted_qpc','read_handle_inherit_cleared','write_handle_inherit_cleared','failure','win32_error','wsa_error','selected_socket_api_tested','network_tested','proxy_tested','product_acceptance','ports','socks','http','message_boundary','network_scope','barrier'}
        parser_keys = {'configured','header_verified','header_bytes','body_bytes','total_bytes','expected_total_bytes','content_length','message_complete','eof_observed','failure'}
        for report in reports:
            self.assertEqual(set(report), common)
            self.assertEqual(report['stage'], 'lpac-stream-mihomo-http-actor')
            self.assertEqual(report['ports'], {'origin_port':56123,'proxy_port':56124})
            for key in ('proxy_tested','product_acceptance','selected_socket_api_tested'):
                self.assertIs(report[key], False)
            for key in ('request','response'):
                self.assertEqual(set(report['http'][key]), parser_keys)
        self.assertEqual({r['role'] for r in reports}, {'stream-a2-origin','stream-a2-relay'})
        ready = json.loads(next(s[6:] for s in raw.splitlines() if s.startswith('READY ')))
        self.assertEqual(set(ready), {'schema_version','stage','run_id','case_id','pid','port','proxy_port','qpc_frequency','start_qpc','deadline_qpc','loopback_ipv4','exclusive'})
        self.assertEqual(ready['stage'], 'lpac-stream-mihomo-origin-ready')


if __name__ == '__main__':
    unittest.main()
