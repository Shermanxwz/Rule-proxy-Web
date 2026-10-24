// Ordinary-only A2 adapter. The LPAC selected actor and its RPS1 codec are immutable.
// A message FIN is deliberately not TCP FIN; this is finite HTTP adaptation.
#ifndef RULEPROXY_LPAC_STREAM_MIHOMO_PORTABLE
#define wWinMain lpac_a2_unused_amin_network_entry
#include "windows_identity_lpac_stream_network_actor.cpp"
#undef wWinMain
#endif
#include "windows_identity_lpac_stream_mihomo_http.hpp"

#ifndef RULEPROXY_LPAC_STREAM_MIHOMO_PORTABLE
namespace lpac_stream_mihomo {
using lpac_stream::Clock;using lpac_stream::Network;using lpac_stream::File;
using lpac_stream::Pipes;using lpac_stream::Plan;using lpac_stream::Slot;
struct RelayIO {
    Clock& clock;Pipes& pipes;Network& net;File& request;File& response;
    bool sample(){return clock.sample();}
    IOState connect(){return net.connect_once();}
    IO send(const std::uint8_t* p,std::size_t n){return net.send_bytes(p,(std::min)(n,std::size_t(511)));}
    IO receive(std::uint8_t* p,std::size_t n){return net.receive_bytes(p,(std::min)(n,std::size_t(617)));}
    bool record_request(const std::uint8_t* p,std::size_t n){return lpac_stream::write_all(request,clock,p,n);}
    bool record_response(const std::uint8_t* p,std::size_t n){return lpac_stream::write_all(response,clock,p,n);}
    bool flush_request(){return request.flush(clock);}
    bool shutdown_send(){return net.half_close();}
    bool close_writer(){return response.flush(clock)&&pipes.writer.close(clock);}
};
struct RelayDriver {
    RelayIO& io;Relay<RelayIO>& flow;
    bool sample(){return io.sample();}
    IO pipe_read(std::uint8_t* p,std::size_t n){return io.pipes.read(io.clock,p,(std::min)(n,std::size_t(239)));}
    IO pipe_write(const std::uint8_t* p,std::size_t n){return io.pipes.write(io.clock,p,(std::min)(n,std::size_t(173)));}
    IOState connect(){return flow.connect();}
    IO consume(const std::uint8_t* p,std::size_t n){return flow.consume(p,n);}
    IOState finish_inbound(){return flow.finish_inbound();}
    IO produce(std::uint8_t* p,std::size_t n){return flow.produce(p,n);}
    bool close_writer(){return flow.close_writer();}
};
struct CommandAPI {
    Clock& clock;const CLI& c;
    bool sample(){return clock.sample();}std::uint64_t now()const{return clock.last;}
    void clamp(std::uint64_t end){clock.end=(std::min)(clock.end,end);}
    CommandRead read_command(bool release,std::uint8_t* bytes,std::size_t cap){
        if(!clock.sample())return {IOState::error,0,false};Slot file;
        file.value=CreateFileW((release?c.release_path:c.phase_path).c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        const DWORD opened=file.value==INVALID_HANDLE_VALUE?GetLastError():0;
        if(file.value==INVALID_HANDLE_VALUE)file.value=nullptr;
        const bool timely=clock.sample();
        if(!file.valid()){if(!timely)return {IOState::error,0,false};if(opened==ERROR_FILE_NOT_FOUND||opened==ERROR_SHARING_VIOLATION)return {};clock.fail(release?"release":"phase",opened);return {IOState::error,0,false};}
        bool valid=timely;DWORD n=0;
        if(valid){FILE_ATTRIBUTE_TAG_INFO tag{};const BOOL ok=GetFileInformationByHandleEx(file.value,FileAttributeTagInfo,&tag,sizeof(tag));const DWORD e=ok?0:GetLastError();
            valid=clock.sample()&&ok&&(tag.FileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))==0;if(!valid)clock.fail(release?"release":"phase",e);}
        if(valid){LARGE_INTEGER size{};const BOOL ok=GetFileSizeEx(file.value,&size);const DWORD e=ok?0:GetLastError();valid=clock.sample()&&ok&&size.QuadPart==128;if(!valid)clock.fail(release?"release":"phase",e);}
        if(valid){const BOOL ok=ReadFile(file.value,bytes,static_cast<DWORD>(cap),&n,nullptr);const DWORD e=ok?0:GetLastError();valid=clock.sample()&&ok&&n==128&&n<=cap;if(!valid)clock.fail(release?"release":"phase",e);}
        const bool closed=file.close(clock);return {valid&&closed?IOState::progress:IOState::error,n,closed};
    }
    bool publish_ack(const std::string& raw){
        if(!clock.sample())return false;Slot file;file.value=CreateFileW(c.ack_path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        const DWORD e=file.value==INVALID_HANDLE_VALUE?GetLastError():0;if(file.value==INVALID_HANDLE_VALUE)file.value=nullptr;
        const bool timely=clock.sample();if(!file.valid()){clock.fail("ack",e);return false;}
        bool wrote=false;if(timely){try{wrote=WriteReport(file.value,raw);}catch(...){clock.fail("ack");}if(!wrote)clock.fail("ack");}
        if(wrote){const BOOL ok=FlushFileBuffers(file.value);const DWORD error=ok?0:GetLastError();const bool time=clock.sample();if(!ok)clock.fail("ack",error);wrote=ok&&time;}
        const bool closed=file.close(clock);return wrote&&closed;
    }
};
struct OriginIO {
    Clock& clock;Network& net;File& source_file;File& request;File& response;Barrier<CommandAPI>& barrier;Observations& identity;
    bool sample(){return clock.sample();}
    IO receive(std::uint8_t* p,std::size_t n){return net.receive_bytes(p,(std::min)(n,std::size_t(617)));}
    IO send(const std::uint8_t* p,std::size_t n){auto result=net.send_bytes(p,(std::min)(n,std::size_t(511)));observe_socket_send(barrier,result,!clock.failure||std::strcmp(clock.failure,"qpc")!=0);return result;}
    IO source(std::uint8_t* p,std::size_t n){return source_file.read(clock,p,(std::min)(n,std::size_t(509)));}
    bool record_request(const std::uint8_t* p,std::size_t n){return lpac_stream::write_all(request,clock,p,n);}
    bool record_response(const std::uint8_t* p,std::size_t n){return lpac_stream::write_all(response,clock,p,n);}
    bool flush_request(){return request.flush(clock);}
    bool flush_response(){return response.flush(clock);}
    bool shutdown_send(){return net.half_close();}
    IOState before_response(const HTTP& http){
        if(!request.flush(clock))return IOState::error;HeldRequest h;h.pid=identity.pid;h.accepted=net.accepted;h.loopback=net.peer_loopback;h.socket_held=net.socket.valid();
        h.local=net.local_port?static_cast<std::uint16_t>(*net.local_port):0;h.peer=net.peer_port?static_cast<std::uint16_t>(*net.peer_port):0;
        h.request_complete=http.complete();h.request_eof=http.eof_seen();h.request_bytes=http.seen();h.response_bytes=static_cast<std::uint32_t>(net.sent);return barrier.hold(h);
    }
};
// A2 binds exactly the predeclared O. No bind(0), address resolution, or retry.
bool fixed_listen(Network& net,std::uint16_t port){
    auto& clock=net.clock;net.port=port;
    if(!high(port)||!net.boot()||!net.setup(net.listener,true))return false;
    const BOOL yes=TRUE;
    const int option=setsockopt(net.listener.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&yes),sizeof(yes));
    const int oe=option?WSAGetLastError():0;net.exclusive=option==0;
    if(!clock.sample()||option){clock.wfail("socket_setup",oe);return false;}
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
    const int bound=bind(net.listener.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address));
    const int be=bound?WSAGetLastError():0;net.bound=bound==0;
    if(!clock.sample()||bound){clock.wfail("socket_setup",be);return false;}
    int n=static_cast<int>(sizeof(address));const int got=getsockname(net.listener.value,reinterpret_cast<sockaddr*>(&address),&n);
    const int ge=got?WSAGetLastError():0;
    if(!clock.sample()||got||n!=static_cast<int>(sizeof(address))||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)||ntohs(address.sin_port)!=port){clock.wfail("peer",ge);return false;}
    const int listening=::listen(net.listener.value,1);const int le=listening?WSAGetLastError():0;
    if(!clock.sample()||listening){clock.wfail("socket_setup",le);return false;}return true;
}
Report make_report(const CLI& c,const Plan& p,const Clock& clock,const Observations& identity,const lpac_stream::Node* node,const Pipes* pipes,const File* source,const File* request,const File* response,const Network& net,const std::string& socks,const std::string& http){
    Report r;r.relay=c.relay;r.run=p.run;r.case_id=p.case_id;r.pid=identity.pid;
    r.frequency=clock.frequency;r.start=p.start;r.end=p.end;r.last=clock.last;r.origin=c.origin;r.proxy=c.proxy;r.failure=clock.failure;
    if(clock.error)r.error=static_cast<std::uint32_t>(*clock.error);if(clock.wsa_error)r.wsa_error=static_cast<std::uint32_t>(*clock.wsa_error);
    r.identity=MakeReport("actor",p.run,identity,std::nullopt,std::nullopt);
    while(!r.identity.empty()&&(r.identity.back()=='\r'||r.identity.back()=='\n'))r.identity.pop_back();
    r.limits=std::string("{\"payload_max\":1024,\"window\":4096,\"total_max\":65536,\"frames_max\":256,\"request_bytes\":")+std::to_string(p.request)+",\"response_bytes\":"+std::to_string(p.response)+"}";
    r.files=std::string("{\"source\":")+(source?source->json():"null")+",\"request_sink\":"+(request?request->json():"null")+",\"response_sink\":"+(response?response->json():"null")+"}";
    if(node)r.stream=node->json();if(pipes){r.pipe=pipes->json();r.admitted=pipes->admitted;r.read_inherit=pipes->inherited_read;r.write_inherit=pipes->inherited_write;}
    r.network=net.json();r.network_tested=c.relay?net.connecting:net.accepted;r.socks=socks;r.http=http;return r;
}
int relay(const CLI& c,const Plan& p){
    Clock clock(p);Pipes pipes(p);Network net(clock);net.port=c.proxy;File request,response;lpac_stream::Node node(p.config);Observations identity;Slot output;
    RelayIO io{clock,pipes,net,request,response};Relay<RelayIO> flow(io,p.case_id,c.origin,c.proxy);RelayDriver driver{io,flow};
    output.value=CreateFileW(p.report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;pipes.cleanup(clock);return 3;}
    try{if(clock.sample()){
        identity=ObserveNativeIdentity();const bool timely=clock.sample();if(!lpac_stream::admitted(identity,p))clock.fail("identity");
        if(timely&&!clock.failure&&pipes.prepare(clock)&&request.open(clock,p.root/L"relay-report"/L"request-sent.raw",true)
           &&response.open(clock,p.root/L"relay-report"/L"response-received.raw",true)&&net.boot()&&net.setup(net.socket,false)){
            while(!clock.failure&&!node.failure()&&!flow.failure()&&!node.complete()){const bool progress=lpac_stream::step(node,driver);if(!progress&&!clock.failure&&!node.failure()&&!flow.failure())Sleep(1);}
            if(flow.failure()&&!clock.failure)clock.fail(flow.socks.failure()?"socks":flow.request.failure()||flow.response.failure()?"http":"protocol");
            if((!node.complete()||node.failure())&&!clock.failure)clock.fail("protocol");
        }
    }}catch(...){clock.fail("configuration");node.fail("external");}
    request.cleanup(clock);response.cleanup(clock);pipes.cleanup(clock);net.cleanup();
    const auto body=report(make_report(c,p,clock,identity,&node,&pipes,nullptr,&request,&response,net,flow.socks.json(),flow.http_json()));
    if(!lpac_stream::write_report(output,clock,body))return 3;return clock.failure?5:0;
}
int origin(const CLI& c,const Plan& p){
    Clock clock(p);Network net(clock);Observations identity;File source,request,response;Slot output;
    CommandAPI commands{clock,c};BarrierPlan binding;binding.run=p.config.run;binding.case_id=p.config.case_id;binding.frequency=p.frequency;binding.start=p.start;binding.end=p.end;binding.origin=c.origin;binding.proxy=c.proxy;
    Barrier<CommandAPI> barrier(commands,binding);OriginIO io{clock,net,source,request,response,barrier,identity};Origin<OriginIO> flow(io,p.case_id,c.origin);
    output.value=CreateFileW(p.report.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;return 3;}
    try{if(clock.sample()){
        identity=ObserveNativeIdentity();const bool timely=clock.sample();if(!lpac_stream::admitted(identity,p))clock.fail("identity");
        if(timely&&!clock.failure&&source.open(clock,p.root/L"ordinary-inputs"/L"response.bin",false,p.response)
           &&request.open(clock,p.root/L"origin-report"/L"request.raw",true)&&response.open(clock,p.root/L"origin-report"/L"response-sent.raw",true)&&fixed_listen(net,c.origin)){
            Slot published;published.value=CreateFileW(p.ready.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
            if(published.value==INVALID_HANDLE_VALUE){published.value=nullptr;clock.fail("report",GetLastError());}
            else{const auto r=make_report(c,p,clock,identity,nullptr,nullptr,&source,&request,&response,net,"null",flow.http_json());if(!lpac_stream::write_report(published,clock,ready(r)))clock.fail("report");}
            while(!clock.failure&&!barrier.failure()&&!barrier.armed()){const auto state=barrier.arm();if(state==IOState::idle)Sleep(1);}
            if(barrier.failure()&&!clock.failure)clock.fail(barrier.failure());
            if(!clock.failure&&barrier.armed()&&lpac_stream::accept_one(net)){
                while(!clock.failure&&!flow.failure()&&!flow.complete()){const bool progress=flow.step();if(!progress&&!clock.failure&&!flow.failure())Sleep(1);}
                if(barrier.failure()&&!clock.failure)clock.fail(barrier.failure());if(flow.failure()&&!clock.failure)clock.fail("http");if(!flow.complete()&&!clock.failure)clock.fail("http");
            }
        }
    }}catch(...){clock.fail("configuration");}
    source.cleanup(clock);request.cleanup(clock);response.cleanup(clock);net.cleanup();
    auto facts=make_report(c,p,clock,identity,nullptr,nullptr,&source,&request,&response,net,"null",flow.http_json());facts.barrier=barrier.json();const auto body=report(facts);
    if(!lpac_stream::write_report(output,clock,body))return 3;return clock.failure?5:0;
}
} // namespace lpac_stream_mihomo
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    try{std::vector<std::wstring> args;lpac_stream_mihomo::CLI c;lpac_stream::Plan p;
        if(!lpac_stream_mihomo::arguments(GetCommandLineW(),args)||!lpac_stream_mihomo::cli(args,c)||!lpac_stream::parse_plan(c.legacy,p))return 2;
        if(!c.relay){std::wstring phase,ack,release;if(!ReadReportPath(c.phase_path.c_str(),phase)||!ReadReportPath(c.ack_path.c_str(),ack)||!ReadReportPath(c.release_path.c_str(),release)
            ||std::filesystem::path(phase)!=p.root/L"origin-control"/L"phase.bin"||std::filesystem::path(ack)!=p.root/L"origin-report"/L"request-held.json"||std::filesystem::path(release)!=p.root/L"origin-control"/L"response-go.bin")return 2;
            c.phase_path=phase;c.ack_path=ack;c.release_path=release;}
        return c.relay?lpac_stream_mihomo::relay(c,p):lpac_stream_mihomo::origin(c,p);
    }catch(...){return 6;}
}
#endif
