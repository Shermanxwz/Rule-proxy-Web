// Ordinary-owned real TCP stream relay/origin. No payload synthesized from nonce.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain lpac_stream_unused_identity_entry
#include "windows_identity_actor.cpp"
#undef wmain
#define RULEPROXY_LPAC_STREAM_WINDOWS_HELPERS 1
#include "windows_identity_lpac_stream_contract.hpp"
#pragma comment(lib,"ws2_32.lib")

namespace lpac_stream {
struct Socket {
    SOCKET value=INVALID_SOCKET;const char* closed="not_attempted";
    bool valid()const{return value!=INVALID_SOCKET;}
    bool close(Clock& clock){if(!valid())return std::string(closed)!="uncertain";const auto owned=value;value=INVALID_SOCKET;closed="uncertain";
        const int result=closesocket(owned);const int error=result?WSAGetLastError():0;if(!result)closed="confirmed";else clock.wfail("close",error);clock.sample();return result==0;}
};
struct Network {
    Clock& clock;Socket socket,listener;bool started=false,was_started=false,cleaned=false,created=false,connecting=false,connected=false;
    bool peer_loopback=false,shutdown_sent=false,received_eof=false,listener_created=false,exclusive=false,bound=false,accepted=false;
    std::uint16_t port=0;std::optional<DWORD> local_port,peer_port;std::uint64_t sent=0,received=0;
    explicit Network(Clock& c):clock(c){}
    bool boot(){if(!clock.sample())return false;WSADATA data{};const int e=WSAStartup(MAKEWORD(2,2),&data);if(!e){started=true;was_started=true;}const bool time=clock.sample();if(e)clock.wfail("socket_setup",e);
        if(!time||e)return false;if(data.wVersion!=MAKEWORD(2,2)){clock.fail("socket_setup");return false;}return true;}
    bool setup(Socket& slot,bool listening){
        if(!clock.sample())return false;slot.value=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
        const int error=slot.valid()?0:WSAGetLastError();if(slot.valid()){if(listening)listener_created=true;else created=true;}const bool time=clock.sample();
        if(!slot.valid()){clock.wfail("socket_setup",error);return false;}if(!time)return false;
        DWORD flags=0;const BOOL got=GetHandleInformation(reinterpret_cast<HANDLE>(slot.value),&flags);const DWORD ge=got?0:GetLastError();
        if(!clock.sample()||!got||(flags&HANDLE_FLAG_INHERIT)){clock.fail("socket_setup",ge);return false;}
        u_long nonblocking=1;const int changed=ioctlsocket(slot.value,FIONBIO,&nonblocking);const int ce=changed?WSAGetLastError():0;
        const bool timely=clock.sample();if(changed)clock.wfail("socket_setup",ce);return !changed&&timely;
    }
    bool tuple(){
        if(!clock.sample())return false;sockaddr_in local{},peer{};int n=static_cast<int>(sizeof(local));
        const int a=getsockname(socket.value,reinterpret_cast<sockaddr*>(&local),&n);const int ae=a?WSAGetLastError():0;
        if(!clock.sample()||a||n!=static_cast<int>(sizeof(local))){clock.wfail("peer",ae);return false;}local_port=ntohs(local.sin_port);
        n=static_cast<int>(sizeof(peer));const int b=getpeername(socket.value,reinterpret_cast<sockaddr*>(&peer),&n);const int be=b?WSAGetLastError():0;
        if(!clock.sample()||b||n!=static_cast<int>(sizeof(peer))){clock.wfail("peer",be);return false;}peer_port=ntohs(peer.sin_port);
        peer_loopback=local.sin_family==AF_INET&&peer.sin_family==AF_INET&&local.sin_addr.s_addr==htonl(INADDR_LOOPBACK)&&peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK);
        if(!peer_loopback){clock.fail("peer");return false;}return true;
    }
    IOState connect_once(){
        if(!clock.sample())return IOState::error;
        if(!connecting){sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);connecting=true;
            const int result=::connect(socket.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address));const int e=result?WSAGetLastError():0;
            if(result==0)connected=true;const bool time=clock.sample();if(!time)return IOState::error;
            if(result&&e!=WSAEWOULDBLOCK&&e!=WSAEINPROGRESS&&e!=WSAEALREADY){clock.wfail("connect",e);return IOState::error;}
        }
        if(!connected){fd_set writable,errors;FD_ZERO(&writable);FD_ZERO(&errors);FD_SET(socket.value,&writable);FD_SET(socket.value,&errors);timeval wait{};
            const int selected=select(0,nullptr,&writable,&errors,&wait);const int se=selected==SOCKET_ERROR?WSAGetLastError():0;
            if(!clock.sample())return IOState::error;if(selected==SOCKET_ERROR){clock.wfail("connect",se);return IOState::error;}if(!selected)return IOState::idle;
            int value=0;int length=static_cast<int>(sizeof(value));const int got=getsockopt(socket.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&value),&length);const int ge=got?WSAGetLastError():0;
            if(!clock.sample())return IOState::error;if(got||length!=static_cast<int>(sizeof(value))){clock.wfail("connect",ge);return IOState::error;}if(value){clock.wfail("connect",value);return IOState::error;}connected=true;
        }
        if(!tuple()||peer_port!=std::optional<DWORD>(port)){clock.fail("peer");return IOState::error;}return IOState::progress;
    }
    IO send_bytes(const std::uint8_t* p,std::size_t n){
        if(!clock.sample())return {IOState::error,0};const int result=send(socket.value,reinterpret_cast<const char*>(p),static_cast<int>(n),0);const int e=result==SOCKET_ERROR?WSAGetLastError():0;
        if(result>0)sent+=static_cast<unsigned>(result);const bool time=clock.sample();if(!time)return {IOState::error,result>0?static_cast<std::size_t>(result):0};
        if(result==SOCKET_ERROR){if(e==WSAEWOULDBLOCK)return {};clock.wfail("send",e);return {IOState::error,0};}if(result<=0||static_cast<std::size_t>(result)>n){clock.fail("send");return {IOState::error,0};}
        return {IOState::progress,static_cast<std::size_t>(result)};
    }
    IO receive_bytes(std::uint8_t* p,std::size_t n){
        if(!clock.sample())return {IOState::error,0};const int result=recv(socket.value,reinterpret_cast<char*>(p),static_cast<int>(n),0);const int e=result==SOCKET_ERROR?WSAGetLastError():0;
        if(result>0)received+=static_cast<unsigned>(result);if(result==0)received_eof=true;const bool time=clock.sample();if(!time)return {IOState::error,result>0?static_cast<std::size_t>(result):0};
        if(result==SOCKET_ERROR){if(e==WSAEWOULDBLOCK)return {};clock.wfail("receive",e);return {IOState::error,0};}return {result?IOState::progress:IOState::eof,static_cast<std::size_t>(result)};
    }
    bool half_close(){if(shutdown_sent)return true;if(!clock.sample())return false;const int result=shutdown(socket.value,SD_SEND);const int e=result?WSAGetLastError():0;
        if(!result)shutdown_sent=true;const bool time=clock.sample();if(result)clock.wfail("shutdown",e);return !result&&time;}
    void cleanup(){socket.close(clock);listener.close(clock);if(started){started=false;const int result=WSACleanup();const int e=result?WSAGetLastError():0;cleaned=result==0;if(result)clock.wfail("close",e);clock.sample();}}
    std::string json()const{return "{\"wsa_startup\":"+boolean(was_started)+",\"wsa_cleanup\":"+boolean(cleaned)+",\"socket_created\":"+boolean(created)
      +",\"connect_attempted\":"+boolean(connecting)+",\"connect_completed\":"+boolean(connected)+",\"peer_loopback\":"+boolean(peer_loopback)+",\"port\":"+std::to_string(port)
      +",\"local_port\":"+number(local_port)+",\"peer_port\":"+number(peer_port)+",\"bytes_sent\":"+std::to_string(sent)+",\"bytes_received\":"+std::to_string(received)
      +",\"send_shutdown\":"+boolean(shutdown_sent)+",\"receive_eof\":"+boolean(received_eof)+",\"socket_close\":"+quoted(socket.closed)+",\"listener_created\":"+boolean(listener_created)
      +",\"exclusive\":"+boolean(exclusive)+",\"bind_loopback\":"+boolean(bound)+",\"accepted\":"+boolean(accepted)+",\"listener_close\":"+quoted(listener.closed)+"}";}
};
inline bool write_all(File& file,Clock& clock,const std::uint8_t* p,std::size_t n){
    std::size_t at=0;while(at<n){const auto part=file.write(clock,p+at,n-at);at+=part.bytes;if(part.state!=IOState::progress)return false;}return true;
}
struct RelayAPI {
    Clock& clock;Pipes& pipes;Network& net;File& request;File& response;
    bool sample(){return clock.sample();}
    IO pipe_read(std::uint8_t* p,std::size_t n){return pipes.read(clock,p,std::min<std::size_t>(n,239));}
    IO pipe_write(const std::uint8_t* p,std::size_t n){return pipes.write(clock,p,std::min<std::size_t>(n,173));}
    IOState connect(){return net.connect_once();}
    IO consume(const std::uint8_t* p,std::size_t n){auto v=net.send_bytes(p,std::min<std::size_t>(n,511));if(v.bytes&&!write_all(request,clock,p,v.bytes))v.state=IOState::error;return v;}
    IOState finish_inbound(){return net.half_close()&&request.flush(clock)?IOState::progress:IOState::error;}
    IO produce(std::uint8_t* p,std::size_t n){auto v=net.receive_bytes(p,std::min<std::size_t>(n,617));if(v.bytes&&!write_all(response,clock,p,v.bytes))v.state=IOState::error;return v;}
    bool close_writer(){return response.flush(clock)&&pipes.writer.close(clock);}
};
int relay(const Plan& p){
    Clock clock(p);Pipes pipes(p);Network net(clock);net.port=p.port;File request,response;Node node(p.config);Observations identity;Slot output;
    output.value=CreateFileW(p.report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;pipes.cleanup(clock);return 3;}
    try{if(clock.sample()){
        identity=ObserveNativeIdentity();const bool time=clock.sample();if(!admitted(identity,p))clock.fail("identity");
        if(time&&!clock.failure&&pipes.prepare(clock)&&request.open(clock,p.root/L"relay-report"/L"request-sent.raw",true)
           &&response.open(clock,p.root/L"relay-report"/L"response-received.raw",true)&&net.boot()&&net.setup(net.socket,false)){
            RelayAPI api{clock,pipes,net,request,response};while(!clock.failure&&!node.failure()&&!node.complete()){const bool progress=step(node,api);if(!progress&&!clock.failure&&!node.failure())Sleep(1);}
            if(node.failure()&&!clock.failure)clock.fail("protocol");if(!node.complete()&&!clock.failure)clock.fail("protocol");
        }
    }}catch(...){clock.fail("configuration");node.fail("external");}
    request.cleanup(clock);response.cleanup(clock);pipes.cleanup(clock);net.cleanup();
    const auto body=report(p,clock,identity,&node,&pipes,nullptr,&request,&response,net.json(),net.connecting);
    if(!write_report(output,clock,body))return 3;return clock.failure?5:0;
}
bool listen(Network& net){
    auto& clock=net.clock;if(!net.boot()||!net.setup(net.listener,true))return false;const BOOL yes=TRUE;
    const int option=setsockopt(net.listener.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&yes),sizeof(yes));const int oe=option?WSAGetLastError():0;net.exclusive=option==0;
    if(!clock.sample()||option){clock.wfail("socket_setup",oe);return false;}
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    const int bound=bind(net.listener.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address));const int be=bound?WSAGetLastError():0;net.bound=bound==0;
    if(!clock.sample()||bound){clock.wfail("socket_setup",be);return false;}
    int n=static_cast<int>(sizeof(address));const int got=getsockname(net.listener.value,reinterpret_cast<sockaddr*>(&address),&n);const int ge=got?WSAGetLastError():0;
    if(!clock.sample()||got||n!=static_cast<int>(sizeof(address))||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)){clock.wfail("peer",ge);return false;}
    net.port=ntohs(address.sin_port);if(net.port<49153){clock.fail("socket_setup");return false;}
    const int listening=::listen(net.listener.value,1);const int le=listening?WSAGetLastError():0;if(!clock.sample()||listening){clock.wfail("socket_setup",le);return false;}return true;
}
bool accept_one(Network& net){
    auto& clock=net.clock;while(clock.sample()){
        net.socket.value=accept(net.listener.value,nullptr,nullptr);const int e=net.socket.valid()?0:WSAGetLastError();if(net.socket.valid()){net.created=true;net.accepted=true;}
        const bool time=clock.sample();if(!time)return false;if(net.socket.valid()){
            if(!net.tuple()||net.local_port!=std::optional<DWORD>(net.port))return false;
            const BOOL changed=SetHandleInformation(reinterpret_cast<HANDLE>(net.socket.value),HANDLE_FLAG_INHERIT,0);const DWORD ce=changed?0:GetLastError();if(!clock.sample()||!changed){clock.fail("inheritance",ce);return false;}
            DWORD flags=0;const BOOL got=GetHandleInformation(reinterpret_cast<HANDLE>(net.socket.value),&flags);const DWORD ge=got?0:GetLastError();if(!clock.sample()||!got||(flags&HANDLE_FLAG_INHERIT)){clock.fail("inheritance",ge);return false;}
            u_long nonblocking=1;const int nb=ioctlsocket(net.socket.value,FIONBIO,&nonblocking);const int ne=nb?WSAGetLastError():0;if(!clock.sample()||nb){clock.wfail("socket_setup",ne);return false;}return true;
        }
        if(e!=WSAEWOULDBLOCK){clock.wfail("receive",e);return false;}Sleep(1);
    }return false;
}
int origin(const Plan& p){
    Clock clock(p);Network net(clock);Observations identity;File source,request,response;Slot output;
    output.value=CreateFileW(p.report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;return 3;}
    try{if(clock.sample()){
        identity=ObserveNativeIdentity();const bool time=clock.sample();if(!admitted(identity,p))clock.fail("identity");
        if(time&&!clock.failure&&source.open(clock,p.root/L"ordinary-inputs"/L"response.bin",false,p.response)
           &&request.open(clock,p.root/L"origin-report"/L"request.raw",true)&&response.open(clock,p.root/L"origin-report"/L"response-sent.raw",true)&&listen(net)){
            Slot ready;ready.value=CreateFileW(p.ready.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(ready.value==INVALID_HANDLE_VALUE){ready.value=nullptr;clock.fail("report",GetLastError());}
            else{
                const std::string body="{\"schema_version\":1,\"stage\":\"lpac-stream-origin-ready\",\"run_id\":\""+p.run+"\",\"case_id\":\""+p.case_id+"\",\"pid\":"+std::to_string(identity.pid)+",\"port\":"+std::to_string(net.port)
                  +",\"qpc_frequency\":"+std::to_string(clock.frequency)+",\"start_qpc\":"+std::to_string(p.start)+",\"deadline_qpc\":"+std::to_string(p.end)+",\"loopback_ipv4\":true}\n";
                if(!write_report(ready,clock,body))clock.fail("report");
            }
            if(!clock.failure&&accept_one(net)){
                std::array<std::uint8_t,Payload> buf{};
                while(!clock.failure&&!net.received_eof){const auto remaining=p.request>=net.received?static_cast<std::size_t>(p.request-net.received+1):1;
                    auto v=net.receive_bytes(buf.data(),std::min(buf.size(),remaining));if(v.bytes&&!write_all(request,clock,buf.data(),v.bytes))break;
                    if(net.received>p.request){clock.fail("protocol");break;}if(v.state==IOState::error)break;if(v.state==IOState::idle)Sleep(1);}
                if(!clock.failure&&(net.received!=p.request||!net.received_eof))clock.fail("protocol");
                bool eof=false;
                while(!clock.failure&&!eof){auto v=source.read(clock,buf.data(),std::min<std::size_t>(buf.size(),509));
                    if(v.state==IOState::eof){eof=true;break;}if(v.state!=IOState::progress)break;
                    if(source.bytes>p.response){clock.fail("protocol");break;}std::size_t at=0;
                    while(!clock.failure&&at<v.bytes){const auto part=net.send_bytes(buf.data()+at,v.bytes-at);if(part.bytes&&!write_all(response,clock,buf.data()+at,part.bytes))break;at+=part.bytes;
                        if(part.state==IOState::error)break;if(part.state==IOState::idle)Sleep(1);}
                }
                if(!clock.failure&&(!eof||source.bytes!=p.response||net.sent!=p.response))clock.fail("protocol");if(!clock.failure)net.half_close();
            }
        }
    }}catch(...){clock.fail("configuration");}
    source.cleanup(clock);request.cleanup(clock);response.cleanup(clock);net.cleanup();
    const auto body=report(p,clock,identity,nullptr,nullptr,&source,&request,&response,net.json(),net.accepted);
    if(!write_report(output,clock,body))return 3;return clock.failure?5:0;
}
} // namespace lpac_stream
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    try{std::vector<std::wstring> args;lpac_stream::Plan p;if(!lpac_stream::arguments(GetCommandLineW(),args)||!lpac_stream::parse_plan(args,p))return 2;
        if(p.role==L"stream-relay")return lpac_stream::relay(p);if(p.role==L"stream-origin")return lpac_stream::origin(p);return 2;}catch(...){return 6;}
}
