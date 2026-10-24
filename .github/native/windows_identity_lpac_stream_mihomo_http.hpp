// A2 fixed SOCKS5/HTTP-message adaptation. Portable production state machines.
#pragma once
#include "windows_identity_lpac_stream_contract.hpp"
#include <optional>
#include <limits>
#include <utility>
namespace lpac_stream_mihomo {
using lpac_stream::IO;using lpac_stream::IOState;
inline const char* boolean(bool x){return x?"true":"false";}
inline std::string quoted(const char* x){return x?"\""+std::string(x)+"\"":"null";}
inline bool id(const std::string& x){if(x.size()!=32)return false;for(char c:x){if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;}return true;}
inline bool high(std::uint64_t n){return n>=49153&&n<=65535;}
inline bool decimal(const std::wstring& x,std::uint64_t max,std::uint64_t& value){
    if(x.empty()||x.size()>20||x[0]==L'0')return false;
    value=0;for(wchar_t c:x){if(c<L'0'||c>L'9')return false;const auto d=static_cast<unsigned>(c-L'0');if(value>(max-d)/10)return false;value=value*10+d;}return true;
}
inline bool narrow_id(const std::wstring& w,std::string& s){s.clear();for(wchar_t c:w){if(c>127||c<32)return false;s+=static_cast<char>(c);}return id(s);}
struct CLI {bool relay=false;std::uint16_t origin=0,proxy=0;std::string run,case_id;std::vector<std::wstring> legacy;std::wstring phase_path,ack_path,release_path;};
inline bool arguments(const wchar_t* p,std::vector<std::wstring>& out){
    if(!p)return false;
    std::size_t total=0;while(*p){while(*p==L' '||*p==L'\t')++p;if(!*p)break;std::wstring v;const bool q=*p==L'"';if(q)++p;
        while(*p&&!(q?*p==L'"':(*p==L' '||*p==L'\t'))){if(*p<32||(!q&&*p==L'"'))return false;v+=*p++;if(++total>16000||v.size()>4096)return false;}
        if(q){if(*p!=L'"')return false;++p;if(*p&&*p!=L' '&&*p!=L'\t')return false;}if(v.empty()||out.size()>=17)return false;out.push_back(std::move(v));
    }return out.size()==16||out.size()==17;
}
inline bool cli(const std::vector<std::wstring>& a,CLI& out){
    const bool relay=a.size()==16&&a[1]==L"stream-a2-relay",origin=a.size()==17&&a[1]==L"stream-a2-origin";
    if(!relay&&!origin)return false;
    std::uint64_t o=0,m=0,s=0,f=0,e=0,r=0,w=0;
    if(!narrow_id(a[2],out.run)||!narrow_id(a[3],out.case_id)||out.run==out.case_id
       ||!decimal(a[relay?14:12],65535,o)||!decimal(a[relay?15:13],65535,m)||!high(o)||!high(m)||o==m
       ||a[relay?12:10]!=L"8193"||a[relay?13:11]!=L"12289"
       ||!decimal(a[relay?7:6],0x7fffffffffffffffULL,s)||!decimal(a[relay?8:7],1000000000ULL,f)
       ||!decimal(a[relay?9:8],0x7fffffffffffffffULL,e))return false;
    const auto seconds=relay?10u:85u;
    if(f>(0x7fffffffffffffffULL-s)/seconds||e!=s+seconds*f)return false;
    if(relay&&(!decimal(a[5],0x7fffffffffffffffULL,r)||!decimal(a[6],0x7fffffffffffffffULL,w)||r==w||a[11]!=L"none"))return false;
    if(origin){if(a[14].empty()||a[15].empty()||a[16].empty()||a[14]==a[15]||a[14]==a[16]||a[15]==a[16])return false;out.phase_path=a[14];out.ack_path=a[15];out.release_path=a[16];}
    out.relay=relay;out.origin=static_cast<std::uint16_t>(o);out.proxy=static_cast<std::uint16_t>(m);out.legacy=a;out.legacy.resize(relay?15u:12u);out.legacy[1]=relay?L"stream-relay":L"stream-origin";return true;
}
inline std::string canonical(bool response,const std::string& case_id,std::uint16_t port,std::uint32_t total){
    if(!id(case_id)||!high(port)||!total||total>65536)return {};
    std::uint32_t body=total;
    for(unsigned n=0;n<8;++n){std::string h=response?std::string("HTTP/1.1 200 OK\r\nContent-Length: ")+std::to_string(body)+"\r\nConnection: close\r\nX-RuleProxy-Case: "+case_id+"\r\n\r\n":
        std::string("POST /ruleproxy-a2/")+case_id+" HTTP/1.1\r\nHost: 127.0.0.1:"+std::to_string(port)+"\r\nContent-Length: "+std::to_string(body)+"\r\nConnection: close\r\n\r\n";
        if(h.size()>512||h.size()>=total)return {};
        const auto next=total-static_cast<std::uint32_t>(h.size());if(next==body)return h;body=next;
    }return {};
}
class HTTP {
    std::string header_;std::uint32_t expected_=0,observed_=0;bool eof_=false;const char* failure_=nullptr;
public:
    HTTP(bool response,const std::string& case_id,std::uint16_t port,std::uint32_t total):header_(canonical(response,case_id,port,total)),expected_(total){if(header_.empty())failure_="configuration";}
    void fail(const char* why){if(!failure_)failure_=why;}
    const char* failure()const{return failure_;}
    bool feed(const std::uint8_t* p,std::size_t n){
        if(failure_)return false;
        if(eof_||!p||!n){fail("order");return false;}
        const auto old=observed_;if(n>65537u-observed_){fail("overflow");return false;}observed_+=static_cast<std::uint32_t>(n);
        if(observed_>expected_){fail("overflow");return false;}
        for(std::size_t i=0;i<n&&old+i<header_.size();++i){if(p[i]!=static_cast<std::uint8_t>(header_[old+i])){fail("header");return false;}}
        return true;
    }
    bool eof(){if(eof_){fail("order");return false;}eof_=true;if(!complete()){fail("early_eof");return false;}return true;}
    bool complete()const{return !failure_&&observed_==expected_;}
    bool eof_seen()const{return eof_;}
    std::uint32_t seen()const{return observed_;}std::uint32_t expected()const{return expected_;}
    std::size_t remaining()const{return observed_<=expected_?expected_-observed_:0;}
    bool header_verified()const{return !failure_&&observed_>=header_.size();}
    std::string json()const{
        const auto head=(std::min)(static_cast<std::size_t>(observed_),header_.size());
        return std::string("{\"configured\":")+boolean(!header_.empty())+",\"header_verified\":"+boolean(header_verified())+",\"header_bytes\":"+std::to_string(head)
         +",\"body_bytes\":"+std::to_string(observed_-head)+",\"total_bytes\":"+std::to_string(observed_)+",\"expected_total_bytes\":"+std::to_string(expected_)
         +",\"content_length\":"+(header_verified()?std::to_string(expected_-header_.size()):"null")+",\"message_complete\":"+boolean(complete())+",\"eof_observed\":"+boolean(eof_)+",\"failure\":"+quoted(failure_)+"}";
    }
};
// Separate ordinary-only M2B1 commands. These do not change RPS1 or the LPAC.
inline std::uint16_t read16(const std::uint8_t* p){return static_cast<std::uint16_t>(p[0]|(std::uint16_t(p[1])<<8));}
inline std::uint64_t read64(const std::uint8_t* p){std::uint64_t n=0;for(unsigned i=0;i<8;++i)n|=std::uint64_t(p[i])<<(8*i);return n;}
inline void write16(std::uint8_t* p,std::uint16_t n){p[0]=static_cast<std::uint8_t>(n);p[1]=static_cast<std::uint8_t>(n>>8);}
inline void write64(std::uint8_t* p,std::uint64_t n){for(unsigned i=0;i<8;++i)p[i]=static_cast<std::uint8_t>(n>>(8*i));}
template<class T>inline std::string nullable(const std::optional<T>& n){return n?std::to_string(*n):"null";}
struct BarrierPlan {std::array<std::uint8_t,16> run{},case_id{};std::uint64_t frequency=0,start=0,end=0;std::uint16_t origin=0,proxy=0;};
struct Command {std::uint8_t operation=0;std::uint64_t pair_start=0,pair_end=0,issued=0,ack=0;std::uint32_t pid=0;std::uint16_t peer=0;};
inline bool command(const std::uint8_t* p,std::size_t n,const BarrierPlan& b,std::uint64_t now,Command& c){
    constexpr auto maximum=0x7fffffffffffffffULL;
    if(!p||n!=128||std::memcmp(p,"M2B1",4)||read16(p+4)!=1||(p[6]!=1&&p[6]!=2)||p[7])return false;
    for(unsigned i=110;i<128;++i)if(p[i])return false;
    if(!b.frequency||!b.start||b.run==b.case_id||!high(b.origin)||!high(b.proxy)||b.origin==b.proxy||b.start>maximum||b.frequency>(maximum-b.start)/85
       ||b.end!=b.start+85*b.frequency||read64(p+40)!=b.frequency||read64(p+48)!=b.start||read64(p+56)!=b.end
       ||std::memcmp(p+8,b.run.data(),16)||std::memcmp(p+24,b.case_id.data(),16)||read16(p+80)!=b.origin||read16(p+82)!=b.proxy||read16(p+84)!=8193||read16(p+86)!=12289)return false;
    c.operation=p[6];c.pair_start=read64(p+64);c.pair_end=read64(p+72);c.issued=read64(p+88);c.ack=read64(p+96);c.pid=lpac_stream::get32(p+104);c.peer=read16(p+108);
    if(c.pair_start<b.start||c.pair_start>maximum||b.frequency>(maximum-c.pair_start)/10||c.pair_end!=c.pair_start+10*b.frequency||c.pair_end>b.end
       ||c.issued<c.pair_start||c.issued>=c.pair_end||now<c.issued||now>=c.pair_end||now>maximum)return false;
    return c.operation==1?c.ack==0&&c.pid==0&&c.peer==0:c.ack>=c.pair_start&&c.ack<=c.issued&&c.pid!=0&&c.peer!=0;
}
inline std::array<std::uint8_t,128> encode_command(const BarrierPlan& b,const Command& c){
    std::array<std::uint8_t,128> p{};std::memcpy(p.data(),"M2B1",4);write16(p.data()+4,1);p[6]=c.operation;
    std::memcpy(p.data()+8,b.run.data(),16);std::memcpy(p.data()+24,b.case_id.data(),16);write64(p.data()+40,b.frequency);write64(p.data()+48,b.start);write64(p.data()+56,b.end);
    write64(p.data()+64,c.pair_start);write64(p.data()+72,c.pair_end);write16(p.data()+80,b.origin);write16(p.data()+82,b.proxy);write16(p.data()+84,8193);write16(p.data()+86,12289);
    write64(p.data()+88,c.issued);write64(p.data()+96,c.ack);lpac_stream::put32(p.data()+104,c.pid);write16(p.data()+108,c.peer);return p;
}
struct CommandRead {IOState state=IOState::idle;std::size_t bytes=0;bool closed=false;};
struct HeldRequest {std::uint32_t pid=0;std::uint16_t local=0,peer=0;bool accepted=false,loopback=false,socket_held=false,request_complete=false,request_eof=false;std::uint32_t request_bytes=0,response_bytes=0;};
template<class API>class Barrier {
    API& api_;BarrierPlan b_;Command phase_{};HeldRequest held_{};const char* failure_=nullptr;
    bool phase_ok_=false,phase_closed_=false,ack_published_=false,release_attempted_=false,release_ok_=false,release_closed_=false;
    std::optional<std::uint64_t> ack_,wait_end_,release_issued_,release_admitted_,response_started_;std::optional<std::uint32_t> response_before_;
    void fail(const char* x){if(!failure_)failure_=x;}
    bool clock(){if(!api_.sample()){const auto end=phase_.pair_end?(std::min)(phase_.pair_end,b_.end):b_.end;fail(api_.now()>=end?"deadline":"qpc");return false;}if(wait_end_&&api_.now()>=*wait_end_&&!release_ok_){fail("deadline");return false;}return true;}
public:
    Barrier(API& api,BarrierPlan b):api_(api),b_(b){}
    const char* failure()const{return failure_;}bool armed()const{return phase_ok_;}bool released()const{return release_ok_;}
    IOState arm(){
        if(failure_)return IOState::error;if(phase_ok_)return IOState::progress;if(!clock())return IOState::error;
        std::array<std::uint8_t,129> bytes{};const auto read=api_.read_command(false,bytes.data(),bytes.size());
        if(read.state==IOState::idle)return IOState::idle;
        phase_closed_=read.closed;if(read.state!=IOState::progress||read.bytes!=128||!read.closed){fail(read.closed?"phase":"close");return IOState::error;}
        if(!clock()||!command(bytes.data(),read.bytes,b_,api_.now(),phase_)||phase_.operation!=1){fail("phase");return IOState::error;}
        api_.clamp(phase_.pair_end);if(!clock()){fail("deadline");return IOState::error;}phase_ok_=true;return IOState::progress;
    }
    std::string ack_json()const{
        auto hex=[](const std::array<std::uint8_t,16>& b){const char* d="0123456789abcdef";std::string s;for(auto x:b){s+=d[x>>4];s+=d[x&15];}return s;};
        return std::string("{\"schema_version\":1,\"stage\":\"lpac-stream-mihomo-origin-request-held\",\"role\":\"stream-a2-origin\",\"run_id\":\"")+hex(b_.run)+"\",\"case_id\":\""+hex(b_.case_id)+"\",\"pid\":"+std::to_string(held_.pid)
          +",\"qpc\":["+std::to_string(b_.frequency)+","+std::to_string(b_.start)+","+std::to_string(b_.end)+","+nullable(ack_)+"],\"pair_qpc\":["+std::to_string(phase_.pair_start)+","+std::to_string(phase_.pair_end)+"]"
          +",\"ports\":{\"origin_port\":"+std::to_string(b_.origin)+",\"proxy_port\":"+std::to_string(b_.proxy)+"},\"accepted_count\":"+(held_.accepted?"1":"0")+",\"local_port\":"+std::to_string(held_.local)+",\"peer_port\":"+std::to_string(held_.peer)
          +",\"peer_loopback\":"+boolean(held_.loopback)+",\"request_bytes\":"+std::to_string(held_.request_bytes)+",\"request_message_complete\":"+boolean(held_.request_complete)+",\"request_eof_observed\":"+boolean(held_.request_eof)
          +",\"response_bytes_sent\":"+std::to_string(held_.response_bytes)+",\"socket_held\":"+boolean(held_.socket_held)+",\"phase_command_close_verified\":"+boolean(phase_closed_)+",\"phase_issued_qpc\":"+std::to_string(phase_.issued)+",\"wait_deadline_qpc\":"+nullable(wait_end_)+",\"failure\":"+quoted(failure_)+"}\n";
    }
    IOState hold(const HeldRequest& facts){
        if(failure_||!phase_ok_){fail("phase");return IOState::error;}if(release_ok_)return clock()?IOState::progress:IOState::error;
        if(!clock())return IOState::error;
        if(!ack_published_){held_=facts;response_before_=facts.response_bytes;
            if(!facts.pid||!facts.peer||facts.local!=b_.origin||!facts.accepted||!facts.loopback||!facts.socket_held||!facts.request_complete||facts.request_bytes!=8193||facts.response_bytes){fail("ack");return IOState::error;}
            ack_=api_.now();const auto remaining=phase_.pair_end-*ack_;wait_end_=*ack_+(std::min)(remaining,2*b_.frequency);
            ack_published_=api_.publish_ack(ack_json());if(!ack_published_){fail("ack");return IOState::error;}if(!clock())return IOState::error;
        }
        release_attempted_=true;std::array<std::uint8_t,129> bytes{};const auto read=api_.read_command(true,bytes.data(),bytes.size());
        if(read.state==IOState::idle)return clock()?IOState::idle:IOState::error;
        release_closed_=read.closed;if(read.state!=IOState::progress||read.bytes!=128||!read.closed){fail(read.closed?"release":"close");return IOState::error;}
        Command c;if(!clock()||!command(bytes.data(),read.bytes,b_,api_.now(),c)||c.operation!=2||c.pair_start!=phase_.pair_start||c.pair_end!=phase_.pair_end||c.ack!=*ack_||c.pid!=held_.pid||c.peer!=held_.peer){fail("release");return IOState::error;}
        release_issued_=c.issued;release_admitted_=api_.now();release_ok_=true;return IOState::progress;
    }
    void note_send(std::size_t bytes){if(bytes&&!response_started_){response_started_=api_.now();if(!release_ok_)fail("release");}}
    std::string json()const{return std::string("{\"phase_admitted\":")+boolean(phase_ok_)+",\"phase_command_closed\":"+boolean(phase_closed_)+",\"phase_issued_qpc\":"+(phase_ok_?std::to_string(phase_.issued):"null")
      +",\"pair_start_qpc\":"+(phase_ok_?std::to_string(phase_.pair_start):"null")+",\"pair_deadline_qpc\":"+(phase_ok_?std::to_string(phase_.pair_end):"null")+",\"request_held_ack_published\":"+boolean(ack_published_)+",\"ack_qpc\":"+nullable(ack_)+",\"wait_deadline_qpc\":"+nullable(wait_end_)
      +",\"response_bytes_before_release\":"+nullable(response_before_)+",\"socket_held_at_ack\":"+boolean(ack_published_&&held_.socket_held)+",\"release_attempted\":"+boolean(release_attempted_)+",\"release_admitted\":"+boolean(release_ok_)+",\"release_command_closed\":"+boolean(release_closed_)
      +",\"release_issued_qpc\":"+nullable(release_issued_)+",\"release_admitted_qpc\":"+nullable(release_admitted_)+",\"response_started_qpc\":"+nullable(response_started_)+",\"failure\":"+quoted(failure_)+"}";}
};
// A positive send remains a byte fact even if its post-call clock read failed.
// In that case no old pre-call tick may become a response-start observation.
template<class B>inline void observe_socket_send(B& barrier,const IO& result,bool postcall_qpc_verified){if(postcall_qpc_verified)barrier.note_send(result.bytes);}
class SOCKS {
    std::uint16_t origin_=0,proxy_=0;unsigned stage_=0;std::size_t at_=0;std::array<std::uint8_t,10> connect_{},reply_{};
    std::uint32_t greeting_sent_=0,method_read_=0,connect_sent_=0,reply_read_=0;const char* failure_=nullptr;
    void fail(const char* x){if(!failure_)failure_=x;}
public:
    SOCKS(std::uint16_t origin,std::uint16_t proxy):origin_(origin),proxy_(proxy){
        if(!high(origin)||!high(proxy)||origin==proxy)fail("configuration");
        connect_={5,1,0,1,127,0,0,1,static_cast<std::uint8_t>(origin>>8),static_cast<std::uint8_t>(origin)};
        reply_={5,0,0,1,127,0,0,1,static_cast<std::uint8_t>(proxy>>8),static_cast<std::uint8_t>(proxy)};
    }
    const char* failure()const{return failure_;}bool complete()const{return stage_==4&&!failure_;}
    template<class API>IOState pump(API& api){
        if(failure_)return IOState::error;
        if(complete())return IOState::progress;
        constexpr std::array<std::uint8_t,3> greet={5,1,0};constexpr std::array<std::uint8_t,2> method={5,0};
        const bool send=stage_==0||stage_==2;const auto size=stage_==0?3u:stage_==1?2u:10u;std::array<std::uint8_t,10> input{};
        const auto* bytes=stage_==0?greet.data():connect_.data();auto value=send?api.send(bytes+at_,size-at_):api.receive(input.data(),size-at_);
        if(value.bytes>size-at_){fail("io");return IOState::error;}
        if(send){if(stage_==0)greeting_sent_+=static_cast<std::uint32_t>(value.bytes);else connect_sent_+=static_cast<std::uint32_t>(value.bytes);}
        else{if(stage_==1)method_read_+=static_cast<std::uint32_t>(value.bytes);else reply_read_+=static_cast<std::uint32_t>(value.bytes);}
        if(!send&&value.bytes){for(std::size_t i=0;i<value.bytes;++i){const auto want=stage_==1?method[at_+i]:reply_[at_+i];if(input[i]!=want){fail(stage_==1?"method":at_+i<4?"reply":"bound");return IOState::error;}}}
        at_+=value.bytes;if(value.state==IOState::eof){fail("eof");return IOState::error;}
        if(value.state==IOState::error||(value.state==IOState::progress&&!value.bytes)||(value.state==IOState::idle&&value.bytes)){fail("io");return IOState::error;}
        if(at_==size){++stage_;at_=0;}return complete()?IOState::progress:IOState::idle;
    }
    std::string json()const{return std::string("{\"greeting_bytes_sent\":")+std::to_string(greeting_sent_)+",\"method_bytes_received\":"+std::to_string(method_read_)
        +",\"connect_bytes_sent\":"+std::to_string(connect_sent_)+",\"reply_bytes_received\":"+std::to_string(reply_read_)+",\"method_noauth_verified\":"+boolean(stage_>=2)
        +",\"reply_ipv4_loopback_listener_verified\":"+boolean(complete())+",\"handshake_complete\":"+boolean(complete())+",\"handshake_wire_sent\":"+std::to_string(greeting_sent_+connect_sent_)
        +",\"handshake_wire_received\":"+std::to_string(method_read_+reply_read_)+",\"origin_dial_proven\":false,\"failure\":"+quoted(failure_)+"}";}
};
// API calls below are shared verbatim by the real actor and portable partial-I/O fake.
template<class API>class Relay {
    API& api_;bool tcp_=false,request_fin_=false,request_flushed_=false,eof_=false,shutdown_attempted_=false,shutdown_=false;const char* failure_=nullptr;
    void fail(const char* x){if(!failure_)failure_=x;}
public:
    SOCKS socks;HTTP request,response;
    Relay(API& api,const std::string& id_,std::uint16_t o,std::uint16_t m):api_(api),socks(o,m),request(false,id_,o,8193),response(true,id_,o,12289){}
    const char* failure()const{return failure_?failure_:socks.failure()?"socks":request.failure()?"http":response.failure()?"http":nullptr;}
    IOState connect(){
        if(!api_.sample()){fail("io");return IOState::error;}if(failure())return IOState::error;
        if(!tcp_){const auto r=api_.connect();if(r==IOState::error){fail("io");return r;}if(r!=IOState::progress)return IOState::idle;tcp_=true;}
        return socks.pump(api_);
    }
    IO consume(const std::uint8_t* p,std::size_t n){
        if(failure()||!socks.complete()||request_fin_){fail("order");return {IOState::error,0};}
        auto preview=request;if(!preview.feed(p,n)){request.fail(preview.failure());return {IOState::error,0};}
        auto v=api_.send(p,n);if(v.bytes){if(v.bytes>n||!request.feed(p,v.bytes)||!api_.record_request(p,v.bytes)){fail("io");return {IOState::error,v.bytes};}}
        if(v.state==IOState::error||v.state==IOState::eof||(v.state==IOState::idle&&v.bytes)||(v.state==IOState::progress&&!v.bytes))fail("io");
        if(failure())v.state=IOState::error;
        return v;
    }
    IOState finish_inbound(){
        if(failure()||request_fin_||!request.complete()){fail("order");return IOState::error;}request_fin_=true;
        request_flushed_=api_.flush_request();if(!request_flushed_){fail("io");return IOState::error;}return IOState::progress;
    }
    IO produce(std::uint8_t* p,std::size_t n){
        if(failure()||!socks.complete())return {IOState::error,0};
        if(!request.complete())return {};
        if(!eof_){const auto room=response.remaining();const auto wanted=(std::min)(n,room?room:std::size_t(1));auto v=api_.receive(p,wanted);
            if(v.bytes){if(v.bytes>wanted||!api_.record_response(p,v.bytes)||!response.feed(p,v.bytes)){fail("http");return {IOState::error,v.bytes};}}
            if(v.state==IOState::error||(v.state==IOState::idle&&v.bytes)||(v.state==IOState::progress&&!v.bytes)||(v.state==IOState::eof&&v.bytes)){fail("io");return {IOState::error,v.bytes};}
            if(v.state==IOState::eof){eof_=true;if(!response.eof()){fail("http");return {IOState::error,0};}}
            else return v;
        }
        if(!request_fin_)return {};
        if(!shutdown_attempted_){shutdown_attempted_=true;shutdown_=api_.shutdown_send();if(!shutdown_){fail("io");return {IOState::error,0};}}
        return {shutdown_?IOState::eof:IOState::error,0};
    }
    bool close_writer(){return !failure()&&shutdown_&&api_.close_writer();}
    std::string adapter_json()const{return std::string("{\"request_fin_received\":")+boolean(request_fin_)+",\"request_message_complete\":"+boolean(request.complete())+",\"request_sink_flushed\":"+boolean(request_flushed_)
      +",\"tcp_send_shutdown_deferred\":"+boolean(request_fin_)+",\"response_message_complete\":"+boolean(response.complete())+",\"proxy_eof_observed\":"+boolean(eof_)
      +",\"send_shutdown_attempted\":"+boolean(shutdown_attempted_)+",\"send_shutdown_confirmed\":"+boolean(shutdown_)+",\"send_shutdown_after_response_eof\":"+boolean(shutdown_&&eof_&&response.complete())+",\"request_fin_is_tcp_fin\":false}";}
    std::string http_json()const{return std::string("{\"request\":")+request.json()+",\"response\":"+response.json()+",\"adapter\":"+adapter_json()+"}";}
};
template<class API>class Origin {
    API& api_;std::array<std::uint8_t,1024> data_{};std::size_t size_=0,at_=0;std::uint32_t sent_=0;
    bool response_admitted_=false,started_=false,source_eof_=false,shutdown_attempted_=false,shutdown_=false,done_=false;const char* failure_=nullptr;
    void fail(const char* x){if(!failure_)failure_=x;}
    bool once(){
        if(!request.complete()){
            const auto asked=(std::min)(data_.size(),request.remaining());auto v=api_.receive(data_.data(),asked);
            if(v.bytes>asked){fail("io");return false;}
            if(v.bytes){if(!api_.record_request(data_.data(),v.bytes)||!request.feed(data_.data(),v.bytes)){fail("http");return false;}}
            if(v.state==IOState::error||(v.state==IOState::idle&&v.bytes)||(v.state==IOState::progress&&!v.bytes)||(v.state==IOState::eof&&v.bytes)){fail("io");return false;}
            if(v.state==IOState::eof){request.eof();fail("http");return false;}return v.state==IOState::progress;
        }
        if(!response_admitted_){const auto gate=api_.before_response(request);if(gate==IOState::error){fail("order");return false;}if(gate!=IOState::progress)return false;response_admitted_=true;}
        if(size_>at_){auto v=api_.send(data_.data()+at_,size_-at_);if(v.bytes){if(v.bytes>size_-at_||!api_.record_response(data_.data()+at_,v.bytes)){fail("io");return false;}started_=true;at_+=v.bytes;sent_+=static_cast<std::uint32_t>(v.bytes);}
            if(v.state==IOState::error||v.state==IOState::eof||(v.state==IOState::idle&&v.bytes)||(v.state==IOState::progress&&!v.bytes)){fail("io");return false;}return v.state==IOState::progress;}
        auto v=api_.source(data_.data(),data_.size());if(v.bytes){if(v.bytes>data_.size()||!response.feed(data_.data(),v.bytes)){fail("http");return false;}size_=v.bytes;at_=0;}
        if(v.state==IOState::error||(v.state==IOState::idle&&v.bytes)||(v.state==IOState::progress&&!v.bytes)||(v.state==IOState::eof&&v.bytes)){fail("io");return false;}
        if(v.state!=IOState::eof)return v.state==IOState::progress;
        source_eof_=true;if(!response.complete()||sent_!=response.expected()||!api_.flush_request()||!api_.flush_response()){fail("http");return false;}
        shutdown_attempted_=true;shutdown_=api_.shutdown_send();if(!shutdown_){fail("io");return false;}done_=true;return true;
    }
public:
    HTTP request,response;
    Origin(API& api,const std::string& id_,std::uint16_t o):api_(api),request(false,id_,o,8193),response(true,id_,o,12289){}
    const char* failure()const{return failure_?failure_:request.failure()?"http":response.failure()?"http":nullptr;}
    bool complete()const{return done_&&!failure();}
    bool step(){if(failure()||done_)return false;if(!api_.sample()){fail("io");return false;}const bool progress=once();if(!api_.sample())fail("io");return progress;}
    std::string adapter_json()const{return std::string("{\"request_message_complete\":")+boolean(request.complete())+",\"request_eof_observed\":"+boolean(request.eof_seen())+",\"response_started_after_request_message\":"+boolean(started_&&request.complete())
      +",\"response_started_without_waiting_for_request_eof\":"+boolean(started_&&!request.eof_seen())+",\"response_message_complete\":"+boolean(response.complete())+",\"source_eof_verified\":"+boolean(source_eof_)
      +",\"send_shutdown_attempted\":"+boolean(shutdown_attempted_)+",\"send_shutdown_confirmed\":"+boolean(shutdown_)+",\"response_sent_complete\":"+boolean(sent_==response.expected()&&source_eof_&&response.complete())+"}";}
    std::string http_json()const{return std::string("{\"request\":")+request.json()+",\"response\":"+response.json()+",\"adapter\":"+adapter_json()+"}";}
};
struct Report {
    bool relay=false,read_inherit=false,write_inherit=false,network_tested=false;std::string run,case_id,identity="null",limits="null",files="null",stream="null",pipe="null",network="null",socks="null",http="null",barrier="null";
    std::uint32_t pid=0;std::uint64_t frequency=0,start=0,end=0,last=0,admitted=0;std::uint16_t origin=0,proxy=0;const char* failure=nullptr;std::optional<std::uint32_t> error,wsa_error;
};
inline std::string optional_number(const std::optional<std::uint32_t>& v){return v?std::to_string(*v):"null";}
inline std::string report(const Report& r){
    return std::string("{\"schema_version\":1,\"stage\":\"lpac-stream-mihomo-http-actor\",\"role\":\"")+(r.relay?"stream-a2-relay":"stream-a2-origin")+"\",\"run_id\":\""+r.run+"\",\"case_id\":\""+r.case_id+"\",\"pid\":"+std::to_string(r.pid)
      +",\"identity\":"+r.identity+",\"qpc\":["+std::to_string(r.frequency)+","+std::to_string(r.start)+","+std::to_string(r.end)+","+std::to_string(r.last)+"],\"limits\":"+r.limits+",\"files\":"+r.files+",\"stream\":"+r.stream+",\"pipe\":"+r.pipe+",\"network\":"+r.network
      +",\"admitted_qpc\":"+(r.admitted?std::to_string(r.admitted):"null")+",\"read_handle_inherit_cleared\":"+boolean(r.read_inherit)+",\"write_handle_inherit_cleared\":"+boolean(r.write_inherit)
      +",\"failure\":"+quoted(r.failure)+",\"win32_error\":"+optional_number(r.error)+",\"wsa_error\":"+optional_number(r.wsa_error)+",\"selected_socket_api_tested\":false,\"network_tested\":"+boolean(r.network_tested)
      +",\"proxy_tested\":false,\"product_acceptance\":false,\"ports\":{\"origin_port\":"+std::to_string(r.origin)+",\"proxy_port\":"+std::to_string(r.proxy)+"},\"socks\":"+r.socks+",\"http\":"+r.http
      +",\"message_boundary\":\"deferred-shutdown-after-http-message-and-response-eof\",\"network_scope\":\"ordinary-relay-to-held-mihomo-to-owned-origin-only\",\"barrier\":"+r.barrier+"}\n";
}
inline std::string ready(const Report& r){return std::string("{\"schema_version\":1,\"stage\":\"lpac-stream-mihomo-origin-ready\",\"run_id\":\"")+r.run+"\",\"case_id\":\""+r.case_id+"\",\"pid\":"+std::to_string(r.pid)+",\"port\":"+std::to_string(r.origin)+",\"proxy_port\":"+std::to_string(r.proxy)+",\"qpc_frequency\":"+std::to_string(r.frequency)+",\"start_qpc\":"+std::to_string(r.start)+",\"deadline_qpc\":"+std::to_string(r.end)+",\"loopback_ipv4\":true,\"exclusive\":true}\n";}
} // namespace lpac_stream_mihomo
