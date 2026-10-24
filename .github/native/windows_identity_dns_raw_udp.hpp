// Portable fixed standard-port UDP DNS driver. No system, DNS or socket calls.
// One query datagram, one response datagram, injected clock/API, no fallback.
// Connected UDP only: connect -> send -> recvfrom; no unconnected sendto claim.
#pragma once
#include "windows_identity_proxy_origin_transport.hpp"
#include <string>
namespace rp_dns_udp {
using rp_origin::Code;using rp_origin::Io;using rp_origin::Close;
constexpr std::size_t QuerySize=62,ResponseSize=78,ReceiveCapacity=1233;
enum class Failure : std::uint8_t {None,Configuration,Startup,Create,Inheritance,Nonblocking,
    Connect,Peer,SelectWrite,Send,SelectRead,Receive,Response,Deadline,Qpc,Close,WsaCleanup};
inline const char* failure_name(Failure value){switch(value){
    case Failure::None:return nullptr;case Failure::Configuration:return "configuration";
    case Failure::Startup:return "startup";case Failure::Create:return "create";
    case Failure::Inheritance:return "inheritance";case Failure::Nonblocking:return "nonblocking";
    case Failure::Connect:return "connect";case Failure::Peer:return "peer";
    case Failure::SelectWrite:return "select-write";case Failure::Send:return "send";
    case Failure::SelectRead:return "select-read";case Failure::Receive:return "receive";
    case Failure::Response:return "response";case Failure::Deadline:return "deadline";
    case Failure::Qpc:return "qpc";case Failure::Close:return "close";
    case Failure::WsaCleanup:return "wsa-cleanup";}return "configuration";
}
struct Packet {
    std::array<std::uint8_t,QuerySize> query{};
    std::array<std::uint8_t,ResponseSize> response{};
    std::uint16_t transaction_id=0;
};
inline int hex_digit(char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
inline bool packet(const std::string& item,Packet& out){
    if(item.size()!=32)return false;
    for(char c:item)if(hex_digit(c)<0)return false;
    out=Packet{};
    out.transaction_id=static_cast<std::uint16_t>((hex_digit(item[0])<<12)|(hex_digit(item[1])<<8)
        |(hex_digit(item[2])<<4)|hex_digit(item[3]));
    auto& q=out.query;q[0]=static_cast<std::uint8_t>(out.transaction_id>>8);q[1]=static_cast<std::uint8_t>(out.transaction_id);
    q[2]=1;q[5]=1; // RD=1, exactly one question, no EDNS or other records.
    std::size_t n=12;q[n++]=32;for(char c:item)q[n++]=static_cast<std::uint8_t>(c);
    q[n++]=3;for(char c:std::string("n0a"))q[n++]=static_cast<std::uint8_t>(c);
    q[n++]=7;for(char c:std::string("invalid"))q[n++]=static_cast<std::uint8_t>(c);
    q[n++]=0;q[n++]=0;q[n++]=1;q[n++]=0;q[n++]=1;
    if(n!=q.size())return false;
    auto& r=out.response;r[0]=q[0];r[1]=q[1];r[2]=0x85;r[5]=1;r[7]=1;
    for(std::size_t i=12;i<q.size();++i)r[i]=q[i];
    constexpr std::array<std::uint8_t,16> answer{0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,192,0,2,123};
    for(std::size_t i=0;i<answer.size();++i)r[QuerySize+i]=answer[i];
    return true;
}
struct Datagram {Io io{Code::Error,0,0};bool source_loopback=false;std::uint16_t source_port=0;};
struct Facts {
    Failure failure=Failure::None;std::uint32_t wsa_error=0,win32_error=0;
    bool within_deadline=true,wsa_startup=false,wsa_cleanup=false;
    bool socket_created=false,inheritance_cleared=false,nonblocking=false;
    bool connect_attempted=false,connect_completed=false,peer_loopback=false;
    std::uint16_t local_port=0,peer_port=0;
    bool send_attempted=false,send_complete=false;std::uint32_t send_bytes=0;
    bool receive_attempted=false,datagram_received=false,source_loopback=false,response_exact=false;
    std::uint16_t source_port=0;std::uint32_t response_bytes=0;
    Close socket_close=Close::NotAttempted;
};
inline void fail(Facts& facts,Failure failure,std::uint32_t error=0,bool win32=false){
    if(facts.failure==Failure::None){facts.failure=failure;
        if(win32)facts.win32_error=error;else facts.wsa_error=error;}
}
template<class API,class Observer>bool exchange(API& api,Observer& observer,const std::string& item,Facts& facts){
    Packet bytes;
    auto alive=[&](){if(observer.sample())return true;facts.within_deadline=false;
        fail(facts,observer.qpc_failed()?Failure::Qpc:Failure::Deadline);return false;};
    auto wait=[&](bool write){for(;;){
        if(!alive())return false;const auto milliseconds=observer.remaining_ms();
        if(!milliseconds||milliseconds>100){facts.within_deadline=false;fail(facts,Failure::Deadline);return false;}
        const auto result=write?api.wait_write(milliseconds):api.wait_read(milliseconds);
        if(result.code!=Code::Progress&&result.code!=Code::WouldBlock)
            fail(facts,write?Failure::SelectWrite:Failure::SelectRead,result.error);
        if(!alive())return false;
        if(result.code==Code::Progress)return true;
        if(result.code!=Code::WouldBlock)return false;
    }};
    const bool protocol=[&](){
        if(!packet(item,bytes)){fail(facts,Failure::Configuration);return false;}
        if(!alive())return false;
        const auto started=api.start();facts.wsa_startup=api.started();
        if(started.code!=Code::Progress||!facts.wsa_startup)fail(facts,Failure::Startup,started.error);
        if(!alive()||facts.failure!=Failure::None)return false;
        const auto created=api.open();facts.socket_created=api.created();
        if(created.code!=Code::Progress||!facts.socket_created)fail(facts,Failure::Create,created.error);
        if(!alive()||facts.failure!=Failure::None)return false;
        const auto inheritance=api.clear_inheritance();facts.inheritance_cleared=inheritance.code==Code::Progress;
        if(!facts.inheritance_cleared)fail(facts,Failure::Inheritance,inheritance.error,true);
        if(!alive()||facts.failure!=Failure::None)return false;
        const auto blocking=api.set_nonblocking();facts.nonblocking=blocking.code==Code::Progress;
        if(!facts.nonblocking)fail(facts,Failure::Nonblocking,blocking.error);
        if(!alive()||facts.failure!=Failure::None)return false;
        facts.connect_attempted=true;auto connected=api.connect();
        facts.connect_completed=connected.code==Code::Progress;
        if(connected.code!=Code::Progress&&connected.code!=Code::WouldBlock)fail(facts,Failure::Connect,connected.error);
        if(!alive()||facts.failure!=Failure::None)return false;
        if(connected.code==Code::WouldBlock){
            if(!wait(true))return false;connected=api.connect_result();facts.connect_completed=connected.code==Code::Progress;
            if(!facts.connect_completed)fail(facts,Failure::Connect,connected.error);
            if(!alive()||facts.failure!=Failure::None)return false;
        }
        const auto peer=api.peer_check();facts.peer_loopback=peer.code==Code::Progress;
        facts.local_port=api.local_port;facts.peer_port=api.peer_port;
        if(!facts.peer_loopback)fail(facts,Failure::Peer,peer.error);
        if(!alive()||facts.failure!=Failure::None||!wait(true))return false;
        facts.send_attempted=true;const auto sent=api.send({bytes.query.data(),bytes.query.size()});
        if(sent.code==Code::Progress){facts.send_bytes=sent.count;facts.send_complete=sent.count==bytes.query.size();}
        if(!facts.send_complete)fail(facts,Failure::Send,sent.error);
        // Preserve actual local acceptance before checking whether the call ran late.
        if(!alive()||facts.failure!=Failure::None||!wait(false))return false;
        std::array<std::uint8_t,ReceiveCapacity> received{};facts.receive_attempted=true;
        const auto datagram=api.receive(received.data(),received.size());
        if(datagram.io.code==Code::Progress){
            facts.datagram_received=true;facts.response_bytes=datagram.io.count;
            facts.source_loopback=datagram.source_loopback;facts.source_port=datagram.source_port;
            facts.response_exact=facts.source_loopback&&facts.source_port==53&&facts.response_bytes==bytes.response.size()
                &&rpb::equal({received.data(),facts.response_bytes},{bytes.response.data(),bytes.response.size()});
            if(!facts.response_exact)fail(facts,Failure::Response);
        }else fail(facts,Failure::Receive,datagram.io.error);
        // A zero-length UDP datagram is data, never TCP EOF. Invalid/late packets stay observed.
        if(!alive()||facts.failure!=Failure::None)return false;
        return true;
    }();
    if(facts.socket_created){const auto closed=api.close();
        facts.socket_close=closed.code==Code::Progress?Close::Confirmed:Close::Uncertain;
        if(facts.socket_close==Close::Uncertain)fail(facts,Failure::Close,closed.error);}
    if(facts.wsa_startup){const auto cleaned=api.cleanup();facts.wsa_cleanup=cleaned.code==Code::Progress;
        if(!facts.wsa_cleanup)fail(facts,Failure::WsaCleanup,cleaned.error);}
    (void)alive();return protocol&&facts.failure==Failure::None&&facts.within_deadline;
}
} // namespace rp_dns_udp
