// Mixed-boundary B probe: generated frontend/sink, real fixed loopback origin.
// No selected proxy/WFP/transparent socket or OS enforcement claim is made.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#define RULEPROXY_PROXY_PIPE_LIBRARY 1
#include "windows_identity_proxy_pipe_actor.cpp"
#include "windows_identity_proxy_origin_transport.hpp"
#pragma comment(lib,"ws2_32.lib")

namespace bridge_origin {
using rp_origin::Code;using rp_origin::Io;using rp_origin::Close;
constexpr auto Invalid=INVALID_SOCKET;
Io ok(std::uint32_t count=0){return {Code::Progress,count,0};}
Io socket_error(){const auto error=static_cast<std::uint32_t>(WSAGetLastError());
    return {error==WSAEWOULDBLOCK?Code::WouldBlock:Code::Error,0,error};}
const char* boolean(bool value){return bridge_pipe::boolean(value);}
struct SocketSlot {
    SOCKET value=Invalid;Close receipt=Close::NotAttempted;
    SocketSlot()=default;SocketSlot(const SocketSlot&)=delete;SocketSlot& operator=(const SocketSlot&)=delete;
    Io close(){
        if(value==Invalid)return {Code::Error,0,0};
        const auto owned=value;value=Invalid; // Consume once before closesocket, no destructor retry.
        const auto result=closesocket(owned);
        receipt=result==0?Close::Confirmed:Close::Uncertain;
        return result==0?ok():socket_error();
    }
};
bool noninherit(SOCKET socket){
    const auto handle=reinterpret_cast<HANDLE>(socket);DWORD flags=0;
    return SetHandleInformation(handle,HANDLE_FLAG_INHERIT,0)&&GetHandleInformation(handle,&flags)
        &&(flags&HANDLE_FLAG_INHERIT)==0;
}
Io nonblocking(SOCKET socket){u_long mode=1;return ioctlsocket(socket,FIONBIO,&mode)==0?ok():socket_error();}
Io poll(SOCKET socket,bool write,std::uint32_t milliseconds){
    if(!milliseconds||milliseconds>100)return {Code::Error,0,0};
    fd_set ready{},errors{};FD_ZERO(&ready);FD_ZERO(&errors);FD_SET(socket,&ready);FD_SET(socket,&errors);
    timeval time{};time.tv_sec=0;time.tv_usec=static_cast<long>(milliseconds*1000u);
    const int result=select(0,write?nullptr:&ready,write?&ready:nullptr,&errors,&time);
    if(result==SOCKET_ERROR)return socket_error();
    if(result==0)return {Code::WouldBlock,0,0};
    // A connect error appears in exceptfds: inspect SO_ERROR in connect_result.
    return ok();
}
Io send_bytes(SOCKET socket,rpb::ByteView bytes){
    if(!bytes.data||!bytes.size||bytes.size>257)return {Code::Error,0,0};
    const int count=send(socket,reinterpret_cast<const char*>(bytes.data),static_cast<int>(bytes.size),0);
    return count==SOCKET_ERROR?socket_error():ok(static_cast<std::uint32_t>(count));
}
Io receive_bytes(SOCKET socket,std::uint8_t* bytes,std::size_t capacity){
    if(!bytes||!capacity||capacity>257)return {Code::Error,0,0};
    const int count=recv(socket,reinterpret_cast<char*>(bytes),static_cast<int>(capacity),0);
    return count==SOCKET_ERROR?socket_error():count==0?Io{Code::Eof,0,0}:ok(static_cast<std::uint32_t>(count));
}
struct Session {
    bool started=false,cleaned=false,cleanup_attempted=false;std::uint32_t error=0;
    bool start(){WSADATA data{};const int result=WSAStartup(MAKEWORD(2,2),&data);
        if(result){error=static_cast<std::uint32_t>(result);return false;}
        started=true;if(data.wVersion!=MAKEWORD(2,2)){error=WSAVERNOTSUPPORTED;return false;}return true;}
    bool cleanup(){if(!started)return true;if(cleanup_attempted)return cleaned;cleanup_attempted=true;
        const int result=WSACleanup();cleaned=result==0;
        if(result&&!error)error=static_cast<std::uint32_t>(WSAGetLastError());return cleaned;}
};
struct SocketAPI {
    SocketSlot socket;bool allocated=false,inheritance=false;std::uint16_t local_port=0,peer_port=0;
    std::uint32_t startup_error=0;
    explicit SocketAPI(std::uint32_t error):startup_error(error){}
    bool created()const{return allocated;}
    Io open(){
        if(startup_error)return {Code::Error,0,startup_error};
        socket.value=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
        if(socket.value==Invalid)return socket_error();allocated=true;
        inheritance=noninherit(socket.value);if(!inheritance)return {Code::Error,0,0};
        return nonblocking(socket.value);
    }
    Io connect(std::uint16_t port){
        sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
        return ::connect(socket.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address))==0?ok():socket_error();
    }
    Io connect_result(){int error=0;int size=sizeof(error);
        if(getsockopt(socket.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&error),&size)==SOCKET_ERROR)return socket_error();
        if(size!=sizeof(error))return {Code::Error,0,0};
        return error?Io{Code::Error,0,static_cast<std::uint32_t>(error)}:ok();}
    bool peer_check(std::uint16_t port){
        sockaddr_in peer{},local{};int ps=sizeof(peer),ls=sizeof(local);
        if(getpeername(socket.value,reinterpret_cast<sockaddr*>(&peer),&ps)||getsockname(socket.value,reinterpret_cast<sockaddr*>(&local),&ls))return false;
        local_port=ntohs(local.sin_port);peer_port=ntohs(peer.sin_port);
        return ps==sizeof(peer)&&ls==sizeof(local)&&peer.sin_family==AF_INET&&local.sin_family==AF_INET
            &&peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK)&&local.sin_addr.s_addr==htonl(INADDR_LOOPBACK)
            &&peer_port==port&&local_port!=0;
    }
    Io wait_write(std::uint32_t ms){return poll(socket.value,true,ms);}
    Io wait_read(std::uint32_t ms){return poll(socket.value,false,ms);}
    Io send(rpb::ByteView bytes){return send_bytes(socket.value,bytes);}
    Io shutdown_send(){return shutdown(socket.value,SD_SEND)==0?ok():socket_error();}
    Io receive(std::uint8_t* bytes,std::size_t capacity){return receive_bytes(socket.value,bytes,capacity);}
    Io close(){return socket.close();}
};
struct PipeObserver {
    bridge_pipe::Probe& probe;
    bool sample(){return probe.sample();}
    std::uint32_t remaining_ms()const{
        const auto& f=probe.facts;if(!f.frequency||f.last>=f.end)return 0;
        const auto ms=(f.end-f.last)*1000/f.frequency;return static_cast<std::uint32_t>((std::min)(ms,100ULL));
    }
    bool write_progress(std::uint32_t bytes){return probe.event(4,1,{nullptr,0},bytes);}
    bool response_bytes(rpb::ByteView bytes){return probe.event(2,0,bytes);}
    bool response_eof(){return probe.event(3);}
};
std::string transport_report(const rp_origin::Facts& f,const SocketAPI& api,const Session& session,std::uint16_t port){
    std::string out="{\"port\":"+std::to_string(port)+",\"wsa_startup\":"+boolean(session.started)+",\"wsa_cleanup\":"+boolean(session.cleaned);
    out+=",\"inheritance_cleared\":"+std::string(boolean(api.inheritance))+",\"socket_created\":"+boolean(f.socket_created);
    out+=",\"connect_attempted\":"+std::string(boolean(f.connect_attempted))+",\"connect_completed\":"+boolean(f.connect_completed)+",\"peer_loopback\":"+boolean(f.peer_loopback);
    out+=",\"local_port\":"+(api.local_port?std::to_string(api.local_port):"null")+",\"peer_port\":"+(api.peer_port?std::to_string(api.peer_port):"null");
    out+=",\"request_bytes\":"+std::to_string(f.request_bytes)+",\"request_complete\":"+boolean(f.request_complete)+",\"send_shutdown\":"+boolean(f.send_shutdown);
    out+=",\"response_bytes\":"+std::to_string(f.response_bytes)+",\"response_exact\":"+boolean(f.response_exact)+",\"response_eof\":"+boolean(f.response_eof);
    out+=",\"socket_close\":\""+std::string(rp_origin::close_name(f.socket_close))+"\",\"failure\":";
    const auto failure=rp_origin::failure_name(f.failure);out+=failure?"\""+std::string(failure)+"\"":"null";
    const auto error=f.error?f.error:session.error;out+=",\"wsa_error\":"+(error?std::to_string(error):"null")+"}";return out;
}
void relay(bridge_pipe::Probe& probe,const rpb::Config& config,SocketAPI& api,Session& session,rp_origin::Facts& facts){
    if(!probe.write_frame()||!probe.read_frame()||!probe.read_frame())return;
    const auto request=rpb::relay_request(config),expected=rpb::expected_response(config);
    probe.facts.request_checked=rpb::equal(probe.pending_http(),request.view());
    if(!probe.facts.request_checked){probe.fail("core");return;}
    PipeObserver observer{probe};const bool success=rp_origin::roundtrip(api,observer,config.relay_port,request.view(),expected.view(),facts);
    probe.facts.response_checked=facts.response_exact;
    if(!session.cleanup())rp_origin::fail(facts,rp_origin::Failure::Close,session.error);
    if(!success||facts.failure!=rp_origin::Failure::None){
        if(facts.failure==rp_origin::Failure::None)rp_origin::fail(facts,rp_origin::Failure::Io);
        // Bounded nonzero error frame only. Never wait for DONE on this path.
        if(probe.event(8,0,{nullptr,0},rp_origin::status(facts.failure))){
            (void)probe.event(6,5,{nullptr,0},facts.socket_close==Close::Uncertain?0u:1u);
            (void)probe.write_frame();
        }
        probe.fail("core");return;
    }
    if(!probe.event(6,5,{nullptr,0},1)||!probe.write_frame()||!probe.close_pipe(true)
        ||!probe.read_frame()||!probe.read_eof()||!probe.close_pipe(false))return;
}
int pair(int argc,wchar_t** argv){
    if(argc!=14)return 2;const bool front=std::wstring(argv[1])==L"pipe-front";
    if(!front&&std::wstring(argv[1])!=L"pipe-relay")return 2;
    std::string run,case_id,user,ac;std::wstring path;std::uint64_t read=0,write=0,start=0,frequency=0,end=0,port=0;
    if(!ReadNonce(argv[2],run)||!ReadNonce(argv[3],case_id)||!ReadReportPath(argv[4],path)
       ||!bridge_pipe::decimal(argv[5],static_cast<std::uint64_t>((std::numeric_limits<std::intptr_t>::max)()),read)
       ||!bridge_pipe::decimal(argv[6],static_cast<std::uint64_t>((std::numeric_limits<std::intptr_t>::max)()),write)||read==write
       ||!bridge_pipe::decimal(argv[7],bridge_pipe::MaxSigned,start)||!bridge_pipe::decimal(argv[8],1000000000ULL,frequency)
       ||!bridge_pipe::decimal(argv[9],bridge_pipe::MaxSigned,end)||!bridge_pipe::sid_text(argv[10],user)
       ||!bridge_pipe::decimal(argv[13],65535,port)||port<49153)return 2;
    if(std::wstring(argv[11])==L"none")ac="none";else if(!bridge_pipe::sid_text(argv[11],ac))return 2;
    if(std::wstring(argv[12])!=L"0")return 2;
    const auto native_port=static_cast<std::uint16_t>(port);
    bridge_pipe::Probe probe(front,run,case_id,reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(read)),
        reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(write)),start,frequency,end,native_port,rpb::OriginAuthority::LocalLoopback);
    bridge_pipe::Slot output;output.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;probe.cleanup();return 3;}
    Observations identity;Session session;SocketAPI api(0);rp_origin::Facts facts;
    try{
        identity=ObserveNativeIdentity();
        if(probe.admitted(identity,user,ac,false)){
            if(front)probe.run();
            else{if(!session.start())api.startup_error=session.error;
                const rpb::Config config{bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(case_id),49152,native_port,0,10000,rpb::OriginAuthority::LocalLoopback};
                relay(probe,config,api,session,facts);}
        }
    }catch(...){probe.fail("configuration");}
    if(api.socket.value!=Invalid){const auto closed=api.close();facts.socket_close=api.socket.receipt;
        if(closed.code!=Code::Progress)rp_origin::fail(facts,rp_origin::Failure::Close,closed.error);}
    if(session.started&&!session.cleanup_attempted&&!session.cleanup())rp_origin::fail(facts,rp_origin::Failure::Close,session.error);
    probe.cleanup();bool written=false;
    try{
        auto mechanics=bridge_pipe::report(probe,identity,front,run,case_id);
        while(!mechanics.empty()&&(mechanics.back()=='\n'||mechanics.back()=='\r'))mechanics.pop_back();
        std::string out="{\"schema_version\":1,\"stage\":\"bridge-origin-pipe-test\",\"role\":\"";
        out+=front?"pipe-front":"pipe-relay";out+="\",\"run_id\":\""+run+"\",\"case_id\":\""+case_id+"\",\"pid\":"+std::to_string(identity.pid);
        out+=",\"ipc_mechanics\":"+mechanics+",\"origin\":"+(front?"null":transport_report(facts,api,session,native_port));
        out+=",\"http_boundary\":\"generated-front-and-sink-native-relay-origin\",\"network_tested\":"+std::string(boolean(!front&&facts.connect_attempted));
        out+=",\"proxy_tested\":false,\"product_acceptance\":false}\n";written=WriteReport(output.value,out);
    }catch(...){written=false;}
    DWORD error=0;const bool closed=output.close(error);if(!written||!closed)return 3;
    return probe.facts.failure||facts.failure!=rp_origin::Failure::None?5:0;
}

struct FixtureClock {
    std::uint64_t frequency=0,start=0,deadline=0,last=0;const char* failure=nullptr;
    bool sample(){LARGE_INTEGER now{};if(!QueryPerformanceCounter(&now)||now.QuadPart<0){failure="qpc";return false;}
        const auto tick=static_cast<std::uint64_t>(now.QuadPart);if(tick<start||(last&&tick<last)){failure="qpc";return false;}
        last=tick;if(tick>=deadline){failure="deadline";return false;}return true;}
    std::uint32_t remaining(){if(!sample()||!frequency)return 0;const auto ms=(deadline-last)*1000/frequency;
        return static_cast<std::uint32_t>((std::min)(ms,100ULL));}
    bool admit(){LARGE_INTEGER observed{};
        if(!frequency||frequency>1000000000ULL||!QueryPerformanceFrequency(&observed)||observed.QuadPart<=0
            ||static_cast<std::uint64_t>(observed.QuadPart)!=frequency)return false;
        LARGE_INTEGER now{};if(!QueryPerformanceCounter(&now)||now.QuadPart<0)return false;
        start=static_cast<std::uint64_t>(now.QuadPart);last=start;
        return deadline>start&&deadline-start<=120*frequency;
    }
};
struct FixtureFacts {
    bool listener_created=false,inheritance=false,exclusive=false,bound=false,accepted=false,peer_loopback=false;
    std::uint16_t port=0,peer_port=0;std::uint32_t request_bytes=0,response_bytes=0;
    bool request_exact=false,request_eof=false,response_complete=false,send_shutdown=false,ready=false;
    const char* failure=nullptr;std::uint32_t error=0;
    void fail(const char* name,std::uint32_t code=0){if(!failure){failure=name;error=code;}}
};
bool wait_fixture(FixtureClock& clock,SOCKET socket,bool write,FixtureFacts& facts){
    for(;;){const auto ms=clock.remaining();if(!ms){facts.fail(clock.failure?clock.failure:"deadline");return false;}
        const auto result=poll(socket,write,ms);if(!clock.sample()){facts.fail(clock.failure);return false;}
        if(result.code==Code::Progress)return true;if(result.code!=Code::WouldBlock){facts.fail(write?"send":"request",result.error);return false;}}
}
bool ordinary_identity(const Observations& identity,const std::string& user){
    return identity.errors.empty()&&identity.tokenUserSid==std::optional<std::string>(user)
        &&identity.tokenElevated==std::optional<bool>(false)&&identity.tokenIsAppContainer==std::optional<bool>(false)
        &&!identity.tokenAppContainerSid.has_value()&&identity.tokenCapabilities.empty()
        &&identity.isProcessInJob==std::optional<bool>(true);
}
bool publish_ready(const std::wstring& path,const std::string& run,const std::string& case_id,const Observations& identity,
                   const FixtureClock& clock,std::uint16_t port){
    bridge_pipe::Slot file;file.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file.value==INVALID_HANDLE_VALUE){file.value=nullptr;return false;}
    bool written=false;try{
        const std::string out="{\"schema_version\":1,\"stage\":\"bridge-origin-ready\",\"run_id\":\""+run+"\",\"case_id\":\""+case_id
            +"\",\"pid\":"+std::to_string(identity.pid)+",\"port\":"+std::to_string(port)
            +",\"qpc_frequency\":"+std::to_string(clock.frequency)+",\"deadline_qpc\":"+std::to_string(clock.deadline)+",\"loopback_ipv4\":true}\n";
        written=WriteReport(file.value,out);
    }catch(...){written=false;}
    DWORD error=0;const bool closed=file.close(error);return written&&closed;
}
void serve(FixtureClock& clock,Session& session,SocketSlot& listener,SocketSlot& connection,FixtureFacts& facts,
           const std::string& run,const std::string& case_id,const std::wstring& ready,const Observations& identity){
    if(!session.start()){facts.fail("socket",session.error);return;}
    if(!clock.sample()){facts.fail(clock.failure);return;}
    listener.value=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
    if(listener.value==Invalid){facts.fail("socket",static_cast<std::uint32_t>(WSAGetLastError()));return;}
    facts.listener_created=true;facts.inheritance=noninherit(listener.value);
    if(!facts.inheritance){facts.fail("socket");return;}
    const BOOL exclusive=TRUE;
    facts.exclusive=setsockopt(listener.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))==0;
    if(!facts.exclusive){facts.fail("socket",static_cast<std::uint32_t>(WSAGetLastError()));return;}
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=0;
    if(bind(listener.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address))){facts.fail("bind",static_cast<std::uint32_t>(WSAGetLastError()));return;}
    int length=sizeof(address);
    if(getsockname(listener.value,reinterpret_cast<sockaddr*>(&address),&length)||length!=sizeof(address)
        ||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)){facts.fail("bind");return;}
    facts.port=ntohs(address.sin_port);facts.bound=true;
    if(facts.port<49153){facts.fail("bind");return;}
    if(nonblocking(listener.value).code!=Code::Progress||listen(listener.value,1)){facts.fail("listen",static_cast<std::uint32_t>(WSAGetLastError()));return;}
    if(!clock.sample()){facts.fail(clock.failure);return;}
    facts.ready=publish_ready(ready,run,case_id,identity,clock,facts.port);if(!facts.ready){facts.fail("report");return;}
    for(;;){
        if(!clock.sample()){facts.fail(clock.failure);return;}
        sockaddr_in peer{};int peer_size=sizeof(peer);
        connection.value=accept(listener.value,reinterpret_cast<sockaddr*>(&peer),&peer_size);
        if(connection.value!=Invalid){
            facts.accepted=true;facts.peer_port=ntohs(peer.sin_port);
            facts.peer_loopback=peer_size==sizeof(peer)&&peer.sin_family==AF_INET&&peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK)&&facts.peer_port!=0;
            const bool inherited_clear=noninherit(connection.value);facts.inheritance=facts.inheritance&&inherited_clear;
            if(!facts.peer_loopback||!inherited_clear){facts.fail("accept");return;}
            const auto nonblock=nonblocking(connection.value);
            if(nonblock.code!=Code::Progress){facts.fail("accept",nonblock.error);return;}
            break;
        }
        const auto error=static_cast<std::uint32_t>(WSAGetLastError());if(error!=WSAEWOULDBLOCK){facts.fail("accept",error);return;}
        if(!wait_fixture(clock,listener.value,false,facts))return;
    }
    const auto listener_closed=listener.close();if(listener_closed.code!=Code::Progress){facts.fail("close",listener_closed.error);return;}
    const rpb::Config config{bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(case_id),49152,facts.port,0,10000,rpb::OriginAuthority::LocalLoopback};
    const auto request=rpb::relay_request(config),response=rpb::expected_response(config);
    std::array<std::uint8_t,257> bytes{};
    for(;;){
        if(!clock.sample()){facts.fail(clock.failure);return;}
        const auto received=receive_bytes(connection.value,bytes.data()+facts.request_bytes,bytes.size()-facts.request_bytes);
        if(received.code==Code::Progress){
            if(!received.count||received.count>bytes.size()-facts.request_bytes){facts.fail("request");return;}
            facts.request_bytes+=received.count;if(facts.request_bytes>256){facts.fail("request");return;}
        }else if(received.code==Code::Eof){facts.request_eof=true;facts.request_exact=rpb::equal({bytes.data(),facts.request_bytes},request.view());break;}
        else if(received.code==Code::WouldBlock){if(!wait_fixture(clock,connection.value,false,facts))return;}
        else{facts.fail("request",received.error);return;}
    }
    if(!facts.request_exact){facts.fail("request");return;}
    while(facts.response_bytes<response.size){
        if(!clock.sample()){facts.fail(clock.failure);return;}
        const auto sent=send_bytes(connection.value,{response.data.data()+facts.response_bytes,response.size-facts.response_bytes});
        if(sent.code==Code::Progress){
            if(!sent.count||sent.count>response.size-facts.response_bytes){facts.fail("send");return;}
            facts.response_bytes+=sent.count;
        }else if(sent.code==Code::WouldBlock){if(!wait_fixture(clock,connection.value,true,facts))return;}
        else{facts.fail("send",sent.error);return;}
    }
    facts.response_complete=true;
    if(!clock.sample()){facts.fail(clock.failure);return;}
    facts.send_shutdown=shutdown(connection.value,SD_SEND)==0;
    if(!facts.send_shutdown){facts.fail("shutdown",static_cast<std::uint32_t>(WSAGetLastError()));return;}
    if(!clock.sample())facts.fail(clock.failure);
}
std::string fixture_report(const std::string& run,const std::string& case_id,const Observations& identity,const FixtureClock& clock,
    const Session& session,const SocketSlot& listener,const SocketSlot& connection,const FixtureFacts& f){
    auto native=MakeReport("actor",run,identity,std::nullopt,std::nullopt);
    while(!native.empty()&&(native.back()=='\n'||native.back()=='\r'))native.pop_back();
    std::string out="{\"schema_version\":1,\"stage\":\"bridge-origin-fixture\",\"run_id\":\""+run+"\",\"case_id\":\""+case_id
        +"\",\"pid\":"+std::to_string(identity.pid)+",\"identity\":"+native;
    out+=",\"qpc\":["+std::to_string(clock.frequency)+","+std::to_string(clock.start)+","+std::to_string(clock.deadline)+","+std::to_string(clock.last)+"]";
    out+=",\"socket\":{\"wsa_startup\":"+std::string(boolean(session.started))+",\"wsa_cleanup\":"+boolean(session.cleaned);
    out+=",\"listener_created\":"+std::string(boolean(f.listener_created))+",\"inheritance_cleared\":"+boolean(f.inheritance)+",\"exclusive\":"+boolean(f.exclusive)+",\"bind_loopback\":"+boolean(f.bound);
    out+=",\"port\":"+(f.port?std::to_string(f.port):"null")+",\"accepted\":"+boolean(f.accepted)+",\"peer_loopback\":"+boolean(f.peer_loopback)+",\"peer_port\":"+(f.peer_port?std::to_string(f.peer_port):"null");
    out+=",\"request_bytes\":"+std::to_string(f.request_bytes)+",\"request_exact\":"+boolean(f.request_exact)+",\"request_eof\":"+boolean(f.request_eof);
    out+=",\"response_bytes\":"+std::to_string(f.response_bytes)+",\"response_complete\":"+boolean(f.response_complete)+",\"send_shutdown\":"+boolean(f.send_shutdown);
    out+=",\"listener_close\":\""+std::string(rp_origin::close_name(listener.receipt))+"\",\"connection_close\":\""+rp_origin::close_name(connection.receipt)+"\"}";
    out+=",\"ready_published\":"+std::string(boolean(f.ready))+",\"failure\":"+(f.failure?"\""+std::string(f.failure)+"\"":"null");
    const auto error=f.error?f.error:session.error;out+=",\"wsa_error\":"+(error?std::to_string(error):"null");
    out+=",\"network_scope\":\"ordinary-loopback-origin\",\"network_tested\":"+std::string(boolean(f.accepted))+",\"proxy_tested\":false,\"product_acceptance\":false}\n";
    return out;
}
int fixture(int argc,wchar_t** argv){
    if(argc!=9)return 2;std::string run,case_id,user;std::wstring report,ready;FixtureClock clock;
    if(!ReadNonce(argv[2],run)||!ReadNonce(argv[3],case_id)||!ReadReportPath(argv[4],report)||!ReadReportPath(argv[5],ready)||report==ready
        ||!bridge_pipe::decimal(argv[6],1000000000ULL,clock.frequency)||!bridge_pipe::decimal(argv[7],bridge_pipe::MaxSigned,clock.deadline)
        ||!bridge_pipe::sid_text(argv[8],user))return 2;
    bridge_pipe::Slot output;output.value=CreateFileW(report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;return 3;}
    Observations identity;Session session;SocketSlot listener,connection;FixtureFacts facts;
    try{
        identity=ObserveNativeIdentity();if(!ordinary_identity(identity,user))facts.fail("identity");
        else if(!clock.admit())facts.fail("qpc");else serve(clock,session,listener,connection,facts,run,case_id,ready,identity);
    }catch(...){facts.fail("configuration");}
    for(SocketSlot* socket:std::array<SocketSlot*,2>{&connection,&listener})if(socket->value!=Invalid){
        const auto closed=socket->close();if(closed.code!=Code::Progress)facts.fail("close",closed.error);}
    if(!session.cleanup())facts.fail("close",session.error);
    if(clock.start&&!clock.sample())facts.fail(clock.failure);
    bool written=false;try{written=WriteReport(output.value,fixture_report(run,case_id,identity,clock,session,listener,connection,facts));}catch(...){written=false;}
    DWORD error=0;const bool closed=output.close(error);if(!written||!closed)return 3;return facts.failure?5:0;
}
} // namespace bridge_origin
int wmain(int argc,wchar_t* argv[]){try{
    return argc>1&&std::wstring(argv[1])==L"origin-fixture"?bridge_origin::fixture(argc,argv):bridge_origin::pair(argc,argv);
}catch(...){return 6;}}
