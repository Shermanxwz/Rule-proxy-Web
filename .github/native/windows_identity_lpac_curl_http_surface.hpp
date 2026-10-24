// Finite Windows-AMD64 Winsock DTO semantics over the production RPS1 core.
// Pure source only: no Win32 include, SDK call, host socket, DNS or clock query.
// A future guarded-copy shim owns TLS last-error, physical IO and outer gates.
#pragma once
#include "windows_identity_lpac_curl_http_adapter.hpp"
#include <cstddef>

namespace lpac_curl_http_surface {
using lpac_curl_http::Config;
using lpac_curl_http::Endpoint;
using lpac_curl_http::SocketCore;
using lpac_curl_http::State;
using lpac_curl_http::VirtualSocket;
constexpr bool ImplementationAuthorized=true, ActualReady=false, ActualCurlQualified=false;
constexpr int AfInet=2, SockStream=1, IpProtoTcp=6, SolSocket=0xffff;
constexpr int SoError=0x1007, SoType=0x1008, SoKeepAlive=8;
constexpr int TcpNoDelay=1, TcpKeepIdle=3, TcpKeepCount=16, TcpKeepInterval=17;
constexpr std::uint32_t Fionbio=0x8004667eU;
constexpr int Invalid=10022, WouldBlock=10035, Unsupported=10045, NotConnected=10057, TimedOut=10060;

// These are boundary DTOs, not aliases to platform C structs. The shim must
// guarded-copy target memory into owned DTOs and commit outputs independently.
struct SockaddrIn16 {std::uint16_t family=0,port=0;std::uint32_t address=0;std::uint8_t zero[8]{};};
struct FdSet520 {std::uint32_t count=0,padding=0;std::uint64_t sockets[64]{};};
struct Timeval8 {std::int32_t seconds=0,microseconds=0;};
static_assert(sizeof(SockaddrIn16)==16&&offsetof(SockaddrIn16,address)==4,"sockaddr_in x64 DTO");
static_assert(sizeof(FdSet520)==520&&offsetof(FdSet520,sockets)==8,"fd_set x64 DTO");
static_assert(sizeof(Timeval8)==8,"timeval Windows LONG32 DTO");

inline std::uint16_t htons(std::uint16_t v){return static_cast<std::uint16_t>((v<<8)|(v>>8));}
inline std::uint16_t ntohs(std::uint16_t v){return htons(v);}
inline std::uint32_t htonl(std::uint32_t v){return (v<<24)|((v&0xff00U)<<8)|((v>>8)&0xff00U)|(v>>24);}
inline std::uint32_t ntohl(std::uint32_t v){return htonl(v);}
inline SockaddrIn16 address(Endpoint e){
    SockaddrIn16 a;a.family=AfInet;a.port=htons(e.port);
    // On the fixed Windows AMD64 ABI these integer bytes are network-order.
    a.address=static_cast<std::uint32_t>(e.address[0])|(static_cast<std::uint32_t>(e.address[1])<<8)
        |(static_cast<std::uint32_t>(e.address[2])<<16)|(static_cast<std::uint32_t>(e.address[3])<<24);
    return a;
}
inline bool equal_address(const SockaddrIn16& a,const Endpoint& e){
    const auto b=address(e);return a.family==b.family&&a.port==b.port&&a.address==b.address;
}

enum class Completion {returned,pending,failed};
struct Call {
    Completion completion=Completion::failed;
    std::int64_t value=-1;int error=Invalid;
    // TRUE means a failed API has an error to put in the shim's existing TLS.
    // Successful APIs do not implicitly clear that TLS last-error value.
    bool error_valid=true;
    std::vector<std::uint8_t> bytes;
};
struct SelectRequest {
    bool read=false,write=false,except=false;
    FdSet520 reads{},writes{},excepts{};
    Timeval8 timeout{}; // NULL/infinite timeout deliberately not represented.
};
struct Selection {
    Call call;std::uint64_t ticket=0;
    FdSet520 reads{},writes{},excepts{};
};
struct Options {
    int no_delay=0,keepalive=0,keep_idle=7200,keep_interval=75,keep_count=10;
};

class Surface {
    Config config_;SocketCore core_;Endpoint local_;
    Options options_{};
    std::uint64_t last_=0,next_ticket_=1,select_ticket_=0,select_end_=0;
    SelectRequest select_{};
    bool created_=false,connecting_=false,connected_=false,nonblocking_=false;
    bool closing_=false,closed_=false,failed_=false;
    int socket_error_=0,terminal_error_=0;const char* reason_=nullptr;
    static Call okay(std::int64_t value=0){Call c;c.completion=Completion::returned;c.value=value;c.error=0;c.error_valid=false;return c;}
    static Call pending(){Call c;c.completion=Completion::pending;c.error=0;c.error_valid=false;return c;}
    static Call returned_error(int e){Call c;c.completion=Completion::failed;c.value=-1;c.error=e;c.error_valid=true;return c;}
    Call fail(const char* why,int e,std::uint64_t now){
        if(!failed_){failed_=true;reason_=why;socket_error_=e;terminal_error_=e;core_.unsupported(0,now);}
        return returned_error(e);
    }
    bool tick(std::uint64_t now){
        if(failed_)return false;
        if(now<last_||now<config_.start||now>=config_.end){fail("original_deadline",TimedOut,now);return false;}
        last_=now;
        if(core_.failure()){fail("transport_failed",10054,now);return false;}
        return true;
    }
    bool socket(std::uint64_t s,std::uint64_t now,bool allow_closing=false){
        if(!tick(now))return false;
        if(!created_||closed_||s!=VirtualSocket||(!allow_closing&&closing_)){fail("socket_identity",Invalid,now);return false;}
        return true;
    }
    lpac_curl_http::Ready refresh(std::uint64_t now){
        auto r=core_.readiness(now);
        if(r.exceptional||core_.failure()){fail("transport_failed",10054,now);return r;}
        if(connecting_&&r.connected){connecting_=false;connected_=true;socket_error_=0;}
        return r;
    }
    Call io_result(const lpac_curl_http::Result& r){
        if(r.state==State::okay)return okay(static_cast<std::int64_t>(r.bytes));
        if(r.state==State::eof)return okay(0);
        if(r.state==State::pending)return nonblocking_?returned_error(WouldBlock):pending();
        failed_=true;reason_="transport_call";socket_error_=static_cast<int>(r.error);terminal_error_=socket_error_;
        return returned_error(terminal_error_?terminal_error_:socket_error_);
    }
    bool set_shape(bool present,const FdSet520& s)const{
        // fd_set padding/unused elements are not promised zero by the SDK.
        return !present||s.count==0||(s.count==1&&s.sockets[0]==VirtualSocket);
    }
    Selection select_now(std::uint64_t now){
        Selection s;s.ticket=select_ticket_;const auto ready=refresh(now);
        if(failed_){s.call=returned_error(terminal_error_?terminal_error_:socket_error_);return s;}
        std::int64_t total=0;
        if(select_.read&&select_.reads.count&&ready.readable){s.reads.count=1;s.reads.sockets[0]=VirtualSocket;++total;}
        if(select_.write&&select_.writes.count&&ready.writable){s.writes.count=1;s.writes.sockets[0]=VirtualSocket;++total;}
        if(select_.except&&select_.excepts.count&&ready.exceptional){s.excepts.count=1;s.excepts.sockets[0]=VirtualSocket;++total;}
        if(total||now>=select_end_){s.call=okay(total);select_ticket_=0;return s;}
        s.call=pending();return s;
    }
public:
    // local is an explicitly virtual name, not an allocated kernel TCP tuple.
    // Both it and the remote endpoint are predeclared by the future new scope.
    Surface(Config c,Endpoint local):config_(std::move(c)),core_(config_),local_(local),last_(config_.start){
        if(core_.failure()||local_.address!=std::array<std::uint8_t,4>{127,0,0,1}
            ||local_.port<49153||local_.port==config_.target.port){failed_=true;reason_="surface_configuration";socket_error_=Invalid;terminal_error_=Invalid;}
    }
    SocketCore& core(){return core_;}
    const SocketCore& core()const{return core_;}
    const char* failure()const{return reason_?reason_:core_.failure();}
    bool qualification_failed()const{return failed_||core_.failure()!=nullptr;}
    bool nonblocking()const{return nonblocking_;}
    const Options& options()const{return options_;}
    std::uint64_t deadline()const{return config_.end;}
    bool complete()const{return closed_&&!qualification_failed()&&core_.transport_complete();}
    Call create(int family,int type,int protocol,std::uint64_t now){
        if(!tick(now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(created_)return fail("second_socket",Unsupported,now);
        // For AF_INET/SOCK_STREAM, protocol zero has the explicitly chosen TCP
        // meaning. There is no family/type/provider search or host fallback.
        const auto r=core_.create(family,type,protocol==0?IpProtoTcp:protocol,now);
        if(r.state!=State::okay)return io_result(r);
        created_=true;return okay(static_cast<std::int64_t>(VirtualSocket));
    }
    Call ioctl(std::uint64_t s,std::uint32_t command,std::uint32_t value,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(command!=Fionbio)return fail("ioctl_unsupported",Unsupported,now);
        nonblocking_=value!=0;return okay();
    }
    Call connect(std::uint64_t s,const SockaddrIn16& a,int length,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(connecting_||connected_||length!=16||!equal_address(a,config_.target))return fail("fixed_connect",Unsupported,now);
        const auto r=core_.begin_connect(s,config_.target,now);
        if(r.state==State::failed)return io_result(r);
        connecting_=true;
        return nonblocking_?returned_error(WouldBlock):pending();
    }
    // poll_connect continues this one invocation. It never calls begin_connect
    // twice and never changes the original absolute deadline.
    Call poll_connect(std::uint64_t s,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(!connecting_&&!connected_)return fail("connect_not_entered",Invalid,now);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        return connected_?okay():pending();
    }
    Call set_option(std::uint64_t s,int level,int name,int value,int length,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(length!=4)return fail("option_length",Invalid,now);
        int* destination=nullptr;
        if(level==SolSocket&&name==SoKeepAlive){if(value!=0&&value!=1)return fail("keepalive_boolean",Invalid,now);destination=&options_.keepalive;}
        else if(level==IpProtoTcp&&name==TcpNoDelay){if(value!=0&&value!=1)return fail("nodelay_boolean",Invalid,now);destination=&options_.no_delay;}
        else if(level==IpProtoTcp&&(name==TcpKeepIdle||name==TcpKeepInterval)){
            // No timer can fire within this <=8-second scope. These are only
            // virtual hints; ordinary relay socket options are not claimed.
            if(value<8||value>7200)return fail("keepalive_interval",Unsupported,now);
            destination=name==TcpKeepIdle?&options_.keep_idle:&options_.keep_interval;
        }else if(level==IpProtoTcp&&name==TcpKeepCount){
            if(value<1||value>255)return fail("keepalive_count",Invalid,now);destination=&options_.keep_count;
        }else return fail("option_unsupported",Unsupported,now);
        *destination=value;return okay();
    }
    Call get_option(std::uint64_t s,int level,int name,int capacity,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(capacity<4)return fail("option_capacity",Invalid,now);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        std::int32_t value=0;
        // Any transport failure already stopped this scope. SO_ERROR is only
        // the known healthy virtual provider state, never a way to clear a
        // sticky qualification failure or infer an unobserved SDK outcome.
        if(level==SolSocket&&name==SoError){value=socket_error_;socket_error_=0;}
        else if(level==SolSocket&&name==SoType)value=SockStream;
        else if(level==SolSocket&&name==SoKeepAlive)value=options_.keepalive;
        else if(level==IpProtoTcp&&name==TcpNoDelay)value=options_.no_delay;
        else if(level==IpProtoTcp&&name==TcpKeepIdle)value=options_.keep_idle;
        else if(level==IpProtoTcp&&name==TcpKeepInterval)value=options_.keep_interval;
        else if(level==IpProtoTcp&&name==TcpKeepCount)value=options_.keep_count;
        else return fail("option_unsupported",Unsupported,now);
        auto out=okay();out.bytes.resize(4);std::memcpy(out.bytes.data(),&value,4);return out;
    }
    Call name(std::uint64_t s,bool peer,int capacity,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(!connected_||capacity<16)return fail("name_before_connect_or_short",NotConnected,now);
        const auto a=address(peer?config_.target:local_);auto out=okay();out.bytes.resize(16);std::memcpy(out.bytes.data(),&a,16);return out;
    }
    Call send(std::uint64_t s,const std::uint8_t* bytes,std::size_t count,int flags,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(!connected_)return fail("send_not_connected",NotConnected,now);
        if(!count&&flags==0)return okay(0);
        return io_result(core_.send(s,bytes,count,flags,now));
    }
    Call recv(std::uint64_t s,std::size_t capacity,int flags,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(!connected_||!capacity||capacity>1024U*1024U)return fail("recv_signature",Invalid,now);
        const auto bounded=std::min(capacity,static_cast<std::size_t>(lpac_stream::Window));
        std::vector<std::uint8_t> bytes(bounded);const auto r=core_.recv(s,bytes.data(),bounded,flags,now);
        auto out=io_result(r);if(r.state==State::okay){bytes.resize(r.bytes);out.bytes=std::move(bytes);}return out;
    }
    Call close(std::uint64_t s,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(select_ticket_)return fail("close_with_pending_select",Invalid,now);
        const auto r=core_.close_request(s,now);closing_=true;
        if(r.state==State::failed)return io_result(r);
        if(core_.close_ready()){closed_=true;return okay();}return pending();
    }
    Call poll_close(std::uint64_t s,std::uint64_t now){
        if(!socket(s,now,true))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(!closing_)return fail("close_not_entered",Invalid,now);
        refresh(now);if(failed_)return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(core_.close_ready()){closed_=true;return okay();}return pending();
    }
    Selection select_begin(const SelectRequest& request,std::uint64_t now){
        Selection out;
        if(!socket(VirtualSocket,now)){out.call=returned_error(terminal_error_?terminal_error_:socket_error_);return out;}
        if(select_ticket_||(!request.read&&!request.write&&!request.except)
            ||!set_shape(request.read,request.reads)||!set_shape(request.write,request.writes)||!set_shape(request.except,request.excepts)
            ||((request.read?request.reads.count:0U)+(request.write?request.writes.count:0U)+(request.except?request.excepts.count:0U)==0)
            ||request.timeout.seconds<0||request.timeout.seconds>8||request.timeout.microseconds<0||request.timeout.microseconds>999999){
            out.call=fail("select_shape",Invalid,now);return out;
        }
        const auto micros=static_cast<std::uint64_t>(request.timeout.seconds)*1000000U+static_cast<std::uint32_t>(request.timeout.microseconds);
        // ceil conversion, overflow bounded by constructor F<=INT64_MAX/8.
        const auto whole=micros/1000000U,part=micros%1000000U;
        const auto fraction=(config_.frequency/1000000U)*part+((config_.frequency%1000000U)*part+999999U)/1000000U;
        const auto duration=whole*config_.frequency+fraction;
        select_end_=now+std::min(duration,config_.end-now);select_=request;
        select_ticket_=next_ticket_++;if(!select_ticket_){out.call=fail("select_ticket_overflow",Invalid,now);return out;}
        return select_now(now);
    }
    Selection select_poll(std::uint64_t ticket,std::uint64_t now){
        Selection out;
        if(!socket(VirtualSocket,now)){out.call=returned_error(terminal_error_?terminal_error_:socket_error_);return out;}
        if(!select_ticket_||ticket!=select_ticket_){out.call=fail("select_ticket",Invalid,now);return out;}
        return select_now(now);
    }
    Call fd_is_set(std::uint64_t s,const FdSet520& set,std::uint64_t now){
        if(!socket(s,now))return returned_error(terminal_error_?terminal_error_:socket_error_);
        if(set.count>64)return fail("fdset_count",Invalid,now);
        for(std::uint32_t i=0;i<set.count;++i)if(set.sockets[i]!=VirtualSocket)return fail("fdset_foreign_socket",Unsupported,now);
        return okay(set.count?1:0);
    }
    Call unsupported_api(std::uint32_t operation,std::uint64_t now){
        (void)operation;return fail("surface_API_unsupported",Unsupported,now);
    }
    // WSA event objects, WSAPoll, DNS/resolvers, bind/listen/accept, datagrams,
    // linger, shutdown and additional sockets are deliberately not provided.
    // The future wrapper must emit an unsupported receipt and call the method
    // above, not pass them through to WS2_32 or invent success.
};
} // namespace lpac_curl_http_surface
