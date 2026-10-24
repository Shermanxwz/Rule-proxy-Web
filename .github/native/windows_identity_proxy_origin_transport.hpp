#ifndef WINDOWS_IDENTITY_PROXY_ORIGIN_TRANSPORT_HPP
#define WINDOWS_IDENTITY_PROXY_ORIGIN_TRANSPORT_HPP
// Portable bounded transport driver. API/observer are injected; no system calls.
#include "windows_identity_proxy_bridge_core.hpp"

namespace rp_origin {
enum class Code : std::uint8_t { Progress,WouldBlock,Eof,Error };
enum class Failure : std::uint8_t { None,Setup,Connect,Io,Response,Deadline,Close };
enum class Close : std::uint8_t { NotAttempted,Confirmed,Uncertain };
struct Io { Code code;std::uint32_t count=0,error=0; };
struct Facts {
    Failure failure=Failure::None;std::uint32_t error=0;
    bool socket_created=false,connect_attempted=false,connect_completed=false,peer_loopback=false;
    std::uint32_t request_bytes=0,response_bytes=0;
    bool request_complete=false,send_shutdown=false,response_exact=false,response_eof=false;
    Close socket_close=Close::NotAttempted;
};
inline void fail(Facts& facts,Failure reason,std::uint32_t error=0) {
    if(facts.failure==Failure::None){facts.failure=reason;facts.error=error;}
}
inline const char* failure_name(Failure reason) {
    switch(reason){case Failure::None:return nullptr;case Failure::Setup:return "setup";
    case Failure::Connect:return "connect";case Failure::Io:return "io";
    case Failure::Response:return "response";case Failure::Deadline:return "deadline";
    case Failure::Close:return "close";}return "setup";
}
inline const char* close_name(Close state) {
    return state==Close::Confirmed?"confirmed":state==Close::Uncertain?"uncertain":"not_attempted";
}
inline std::uint32_t status(Failure reason) {
    return reason==Failure::Connect||reason==Failure::Setup?1u:reason==Failure::Response?3u:
           reason==Failure::Deadline?4u:2u;
}
template<class API,class Observer> bool roundtrip(API& api,Observer& observer,std::uint16_t port,
        rpb::ByteView request,rpb::ByteView expected,Facts& facts) {
    auto alive=[&](){if(observer.sample())return true;fail(facts,Failure::Deadline);return false;};
    auto wait=[&](bool write){
        for(;;){
            if(!alive())return false;
            const auto timeout=observer.remaining_ms();
            if(!timeout){fail(facts,Failure::Deadline);return false;}
            const auto result=write?api.wait_write(timeout):api.wait_read(timeout);
            if(!alive())return false;
            if(result.code==Code::Progress)return true;
            if(result.code!=Code::WouldBlock){fail(facts,Failure::Io,result.error);return false;}
        }
    };
    const bool protocol=[&](){
        if(port<49153||!request.size||request.size>256||!request.data||!expected.size||expected.size>256||!expected.data){
            fail(facts,Failure::Setup);return false;}
        if(!alive())return false;
        const auto opened=api.open();facts.socket_created=api.created();
        if(opened.code!=Code::Progress||!facts.socket_created){fail(facts,Failure::Setup,opened.error);return false;}
        if(!alive())return false;
        facts.connect_attempted=true;auto connected=api.connect(port);
        if(connected.code==Code::Progress)facts.connect_completed=true;
        if(!alive())return false;
        if(connected.code==Code::WouldBlock){
            if(!wait(true))return false;
            connected=api.connect_result();
            if(connected.code==Code::Progress)facts.connect_completed=true;
            if(!alive())return false;
        }
        if(connected.code!=Code::Progress){fail(facts,Failure::Connect,connected.error);return false;}
        facts.connect_completed=true;facts.peer_loopback=api.peer_check(port);
        if(!facts.peer_loopback){fail(facts,Failure::Connect);return false;}
        if(!alive())return false;
        while(facts.request_bytes<request.size){
            if(!alive())return false;
            const auto offset=static_cast<std::size_t>(facts.request_bytes);
            const auto sent=api.send({request.data+offset,request.size-offset});
            if(sent.code==Code::Progress){
                if(!sent.count||sent.count>request.size-offset){fail(facts,Failure::Io,sent.error);return false;}
                facts.request_bytes+=sent.count;
                facts.request_complete=facts.request_bytes==request.size;
                if(!alive()||!observer.write_progress(sent.count))return false;
            }else if(sent.code==Code::WouldBlock){if(!wait(true))return false;}
            else{fail(facts,Failure::Io,sent.error);return false;}
        }
        facts.request_complete=true;
        const auto shut=api.shutdown_send();facts.send_shutdown=shut.code==Code::Progress;
        if(!facts.send_shutdown){fail(facts,Failure::Io,shut.error);return false;}
        if(!alive())return false;
        std::array<std::uint8_t,257> bytes{};
        for(;;){
            if(!alive())return false;
            const auto available=bytes.size()-facts.response_bytes;
            const auto received=api.receive(bytes.data()+facts.response_bytes,available);
            if(received.code==Code::Progress){
                if(!received.count||received.count>available){fail(facts,Failure::Io,received.error);return false;}
                facts.response_bytes+=received.count;
                if(facts.response_bytes>256){fail(facts,Failure::Response);return false;}
                if(!alive())return false;
            }else if(received.code==Code::Eof){
                facts.response_eof=true;
                const rpb::ByteView response{bytes.data(),facts.response_bytes};
                facts.response_exact=rpb::equal(response,expected);
                if(!alive())return false;
                if(!facts.response_exact){fail(facts,Failure::Response);return false;}
                return observer.response_bytes(response)&&observer.response_eof();
            }else if(received.code==Code::WouldBlock){if(!wait(false))return false;}
            else{fail(facts,Failure::Io,received.error);return false;}
        }
    }();
    if(facts.socket_created){
        const auto closed=api.close();
        facts.socket_close=closed.code==Code::Progress?Close::Confirmed:Close::Uncertain;
        if(facts.socket_close==Close::Uncertain)fail(facts,Failure::Close,closed.error);
    }
    if(!observer.sample())fail(facts,Failure::Deadline);
    return protocol&&facts.failure==Failure::None;
}
} // namespace rp_origin
#endif
