// C: real raw TCP proxy request/sink and identity-first selected client.
// GUI subsystem supplies a separate entry point without editing frozen B sources.
// No window, UIAccess, WinHTTP, firewall, exemption or security mutation.
// The separate op6 performs one explicit-server DNS observation only after GO.
#include "windows_identity_proxy_origin_actor.cpp"
#include "windows_identity_proxy_c_contract.hpp"
#include "windows_identity_dns_standard_probe.hpp"
#include <cstdlib>
namespace bridge_c {
using bridge_origin::SocketSlot;using bridge_origin::SocketAPI;using bridge_origin::Session;
using bridge_origin::Code;using bridge_origin::Close;using bridge_origin::Io;
using bridge_origin::boolean;
std::string quoted(const char* value){return value?"\""+std::string(value)+"\"":"null";}
std::string identity_json(const std::string& run,const Observations& identity){
    auto out=MakeReport("actor",run,identity,std::nullopt,std::nullopt);
    while(!out.empty()&&(out.back()=='\n'||out.back()=='\r'))out.pop_back();return out;
}
bool publish(const std::wstring& path,const std::string& out){
    bridge_pipe::Slot file;file.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(file.value==INVALID_HANDLE_VALUE){file.value=nullptr;return false;}
    bool written=false;try{written=WriteReport(file.value,out+"\n");}catch(...){written=false;}
    DWORD error=0;const bool closed=file.close(error);return written&&closed;
}
std::wstring numbered(const std::wstring& root,const wchar_t* prefix,unsigned index,const wchar_t* suffix){
    std::wstring number=std::to_wstring(index);while(number.size()<4)number=L"0"+number;
    return root+L"\\"+prefix+number+suffix;
}
std::wstring parent(const std::wstring& path){const auto pos=path.find_last_of(L"\\/");return path.substr(0,pos);}
struct Clock {
    std::uint64_t frequency=0,start=0,deadline=0,last=0;const char* failure=nullptr;
    bool sample(){LARGE_INTEGER now{};if(!QueryPerformanceCounter(&now)||now.QuadPart<0){failure="qpc";return false;}
        const auto tick=static_cast<std::uint64_t>(now.QuadPart);
        if(tick<start||(last&&tick<last)){failure="qpc";return false;}last=tick;
        if(tick>=deadline){failure="deadline";return false;}return true;}
    bool admit(){LARGE_INTEGER f{};return frequency&&frequency<=1000000000ULL&&start&&deadline>start
        &&deadline-start<=120*frequency&&QueryPerformanceFrequency(&f)&&f.QuadPart>0
        &&static_cast<std::uint64_t>(f.QuadPart)==frequency&&sample();}
    std::uint32_t remaining_ms()const{if(!frequency||last>=deadline)return 0;
        return static_cast<std::uint32_t>((std::min)((deadline-last)*1000/frequency,100ULL));}
    std::string json()const{return "["+std::to_string(frequency)+","+std::to_string(start)+","+std::to_string(deadline)+","+std::to_string(last)+"]";}
};
struct Qualification {bool verified=false,cleaned=true;};
bool local_free(void* memory){return !memory||LocalFree(static_cast<HLOCAL>(memory))==nullptr;}
// Fixed catalog lookup is read-only and is completed/consumed before any GO.
Qualification capabilities(const Observations& identity,const std::string& profile){
    Qualification result;
    if(profile=="ordinary"){result.verified=identity.tokenCapabilities.empty();return result;}
    const bool pncs=profile=="pncs"||profile=="agentic-pncs",agentic=profile=="agentic-only"||profile=="agentic-pncs";
    if((!pncs&&!agentic)||identity.tokenCapabilities.size()!=static_cast<std::size_t>(pncs)+static_cast<std::size_t>(agentic))return result;
    using Derive=BOOL(WINAPI*)(PCWSTR,PSID**,DWORD*,PSID**,DWORD*);
    Derive derive=nullptr;const auto base=GetModuleHandleW(L"kernelbase.dll");
    const auto address=base?GetProcAddress(base,"DeriveCapabilitySidsFromName"):nullptr;
    static_assert(sizeof(derive)==sizeof(address),"function pointer ABI");std::memcpy(&derive,&address,sizeof(derive));
    if(!derive)return result;
    bool all=true;std::vector<std::string> matched;
    for(const auto* name:std::array<const wchar_t*,2>{L"privateNetworkClientServer",L"AgenticAppContainer"}){
        const bool is_pncs=name[0]==L'p';if((is_pncs&&!pncs)||(!is_pncs&&!agentic))continue;
        PSID* groups=nullptr;PSID* caps=nullptr;DWORD ng=0,nc=0;
        const bool derived=derive(name,&groups,&ng,&caps,&nc)!=FALSE;
        bool valid=derived&&nc==1&&ng<=16&&caps&&IsValidSid(caps[0]);
        if(valid&&is_pncs){std::array<std::uint8_t,SECURITY_MAX_SID_SIZE> known{};DWORD length=static_cast<DWORD>(known.size());
            valid=CreateWellKnownSid(static_cast<WELL_KNOWN_SID_TYPE>(87),nullptr,known.data(),&length)&&EqualSid(known.data(),caps[0]);}
        unsigned found=0;
        if(valid)for(const auto& capability:identity.tokenCapabilities){
            const std::wstring text(capability.sid.begin(),capability.sid.end());PSID observed=nullptr;
            const bool converted=ConvertStringSidToSidW(text.c_str(),&observed)!=FALSE;
            if(converted&&IsValidSid(observed)&&EqualSid(observed,caps[0])&&capability.attributes==4){++found;matched.push_back(capability.sid);}
            result.cleaned=local_free(observed)&&result.cleaned;
        }
        all=all&&valid&&found==1;
        // The API contract bounds this fixed-name result. Refuse unexpected counts;
        // consume known entries once and do not turn unknown cleanup into success.
        if(ng>16||nc>16){all=false;result.cleaned=false;}
        if(groups&&ng<=16)for(DWORD i=0;i<ng;++i)result.cleaned=local_free(groups[i])&&result.cleaned;
        if(caps&&nc<=16)for(DWORD i=0;i<nc;++i)result.cleaned=local_free(caps[i])&&result.cleaned;
        result.cleaned=local_free(groups)&&result.cleaned;result.cleaned=local_free(caps)&&result.cleaned;
    }
    if(matched.size()==2&&matched[0]==matched[1])all=false;
    result.verified=all&&result.cleaned;return result;
}
bool basic_identity(const Observations& identity,const std::string& user,bool container,const std::string& ac="none"){
    return identity.errors.empty()&&identity.tokenUserSid==std::optional<std::string>(user)
        &&identity.tokenElevated==std::optional<bool>(false)&&identity.isProcessInJob==std::optional<bool>(true)
        &&identity.tokenIsAppContainer==std::optional<bool>(container)
        &&(container?identity.tokenAppContainerSid.has_value()&&(ac=="none"||identity.tokenAppContainerSid==std::optional<std::string>(ac))
                     :!identity.tokenAppContainerSid.has_value());
}
std::string prefix(const char* stage,const std::string& role,const std::string& run,const std::string& boot,const Observations& id){
    return "{\"schema_version\":1,\"stage\":\""+std::string(stage)+"\",\"role\":\""+role+"\",\"run_id\":\""+run
        +"\",\"boot_case_id\":\""+boot+"\",\"pid\":"+std::to_string(id.pid)+",\"identity\":"+identity_json(run,id);
}
std::string qualification_json(const std::string& profile,const Qualification& q){
    return ",\"capability_profile\":\""+profile+"\",\"capability_profile_verified\":"+boolean(q.verified)
        +",\"catalog_cleanup_verified\":"+boolean(q.cleaned);
}
enum class FileState {Missing,Valid,Invalid};
FileState command_file(const std::wstring& path,const rpc::Binding& binding,std::uint32_t sequence,Clock& clock,
                       rpc::Command& command,bool& close_verified,bool fixture=false,bool release=false){
    if(!clock.sample())return FileState::Invalid;
    bridge_pipe::Slot input;input.value=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    const DWORD open_error=input.value==INVALID_HANDLE_VALUE?GetLastError():0;
    if(input.value==INVALID_HANDLE_VALUE){input.value=nullptr;
        if(!clock.sample())return FileState::Invalid;return open_error==ERROR_FILE_NOT_FOUND?FileState::Missing:FileState::Invalid;}
    std::array<std::uint8_t,129> bytes{};DWORD total=0;bool read_ok=clock.sample();
    while(read_ok&&total<bytes.size()){
        if(!clock.sample()){read_ok=false;break;}DWORD count=0;
        const BOOL read=ReadFile(input.value,bytes.data()+total,static_cast<DWORD>(bytes.size()-total),&count,nullptr);
        if(count>bytes.size()-total){read_ok=false;break;}total+=count;
        const bool in_time=clock.sample();if(!read||!in_time){read_ok=false;break;}if(!count)break;
    }
    DWORD error=0;const bool closed=input.close(error);close_verified=close_verified&&closed;
    const bool in_time=clock.sample();
    return read_ok&&closed&&in_time&&(release?rpc::decode_release(bytes.data(),total,binding,clock.last,command)
        :rpc::decode(bytes.data(),total,binding,sequence,clock.last,command,fixture))?FileState::Valid:FileState::Invalid;
}
struct Observer {
    Clock& clock;bool sample(){return clock.sample();}std::uint32_t remaining_ms()const{return clock.remaining_ms();}
    bool write_progress(std::uint32_t){return true;}bool response_bytes(rpb::ByteView){return true;}bool response_eof(){return true;}
};
rpb::Config config(const std::string& run,const std::string& item,std::uint16_t port){
    return {bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(item),49152,port,0,10000,rpb::OriginAuthority::LocalLoopback};
}
rpb::Buffer<256> proxy_request(const std::string& item){rpb::Buffer<256> out;
    rpb::append_literal(out,"GET http://ruleproxy-identity-proof.invalid/");rpb::append_hex(out,bridge_pipe::id_bytes(item));
    rpb::append_literal(out," HTTP/1.1\r\nHost: ruleproxy-identity-proof.invalid\r\n\r\n");return out;
}
// DNS_PHASE_REPORT_BEGIN: pure serialization, no DNS or networking initialization.
std::string dns_report(const std::string& item,const ruleproxy_dns_standard::Result& result){
    constexpr auto options=DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE|DNS_QUERY_NO_LOCAL_NAME|
        DNS_QUERY_NO_NETBT|DNS_QUERY_WIRE_ONLY|DNS_QUERY_NO_MULTICAST|DNS_QUERY_TREAT_AS_FQDN;
    return "{\"server_constructor\":\""+std::string(ruleproxy_dns_standard::ServerConstructor)
        +"\",\"server_address\":\"127.0.0.1\",\"server_port\":53,\"query_name\":\""+item+".n0a.invalid\",\"query_type\":1,\"query_options\":"+std::to_string(options)
        +",\"result\":{\"configured\":"+boolean(result.configured)+",\"called\":"+boolean(result.called)
        +",\"completed\":"+boolean(result.completed)+",\"pending\":"+boolean(result.pending)
        +",\"answer_match\":"+boolean(result.answer_match)+",\"records_released\":"+boolean(result.records_released)
        +",\"context_retained\":"+boolean(result.context_retained)+",\"within_deadline\":"+boolean(result.within_deadline)
        +",\"api_status\":"+std::to_string(result.api_status)+",\"query_status\":"+std::to_string(result.query_status)
        +",\"record_count\":"+std::to_string(result.record_count)+",\"start_qpc\":"+std::to_string(result.start_qpc)
        +",\"end_qpc\":"+std::to_string(result.end_qpc)+"}}";
}
// DNS_PHASE_REPORT_END
int client(int argc,wchar_t** argv){
    if(argc!=16)return 2;std::string run,boot,user,admission;std::wstring ready,results,control;
    Clock clock;std::uint64_t p=0,q=0,o=0;
    const std::string role=std::wstring(argv[1])==L"selected-client"?"selected-client":"health-client";
    const std::wstring profile_text(argv[14]);
    const std::string profile=profile_text==L"agentic-only"?"agentic-only":profile_text==L"agentic-pncs"?"agentic-pncs":profile_text==L"ordinary"?"ordinary":"invalid";
    if(!ReadNonce(argv[2],run)||!ReadNonce(argv[3],boot)||!ReadReportPath(argv[4],ready)||!ReadReportPath(argv[5],results)
       ||!ReadReportPath(argv[6],control)||!bridge_pipe::decimal(argv[7],1000000000ULL,clock.frequency)
       ||!bridge_pipe::decimal(argv[8],bridge_pipe::MaxSigned,clock.start)||!bridge_pipe::decimal(argv[9],bridge_pipe::MaxSigned,clock.deadline)
       ||!bridge_pipe::decimal(argv[10],65535,p)||!bridge_pipe::decimal(argv[11],65535,q)||!bridge_pipe::decimal(argv[12],65535,o)
       ||!bridge_pipe::sid_text(argv[13],user)||!ReadNonce(argv[15],admission)
       ||(profile!="agentic-only"&&profile!="agentic-pncs"&&!(role=="health-client"&&profile=="ordinary")))return 2;
    const rpc::Binding binding{bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(admission),clock.frequency,clock.deadline,
        static_cast<std::uint16_t>(p),static_cast<std::uint16_t>(q),static_cast<std::uint16_t>(o)};
    if(!rpc::valid_binding(binding))return 2;
    Observations identity;Qualification qualification;const char* failure=nullptr;
    bool finished=false,network=false,commands_closed=true;unsigned phases=0;std::vector<std::string> phase_cases;
    try{
        identity=ObserveNativeIdentity();qualification=capabilities(identity,profile);
        if(!basic_identity(identity,user,profile!="ordinary"))failure="identity";
        else if(!qualification.verified||!qualification.cleaned)failure="capability";
        else if(!clock.admit())failure="qpc";
        const auto ready_json=prefix("proxy-c-client-ready",role,run,boot,identity)+qualification_json(profile,qualification)
            +",\"qpc\":"+clock.json()+",\"admission_nonce\":\""+admission+"\",\"ready\":"+boolean(!failure)
            +",\"network_initialized\":false,\"failure\":"+quoted(failure)+"}";
        if(!publish(ready,ready_json))failure="report";
        // No Session/SocketAPI or WSA call exists above this held-admission barrier.
        for(unsigned sequence=1;!failure&&sequence<=16;){
            rpc::Command command;const auto state=command_file(numbered(control,L"phase-",sequence,L".bin"),binding,sequence,clock,command,commands_closed);
            if(state==FileState::Missing){Sleep(10);continue;}
            if(state!=FileState::Valid){failure=clock.failure?clock.failure:"command";break;}
            if(command.operation==255){finished=true;break;}
            const auto item=rpc::hex(command.item);const auto port=rpc::target(binding,command.operation);
            if(profile=="agentic-only"){failure="capability";break;} // Identity-only probe, never a network admission.
            bool fresh=item!=boot;for(const auto& previous:phase_cases)if(previous==item)fresh=false;
            if(!fresh){failure="command";break;}phase_cases.push_back(item);
            Clock phase=clock;phase.deadline=command.phase_deadline;const auto observed_start=clock.last;
            std::string observation;
            if(command.operation==6){
                // A synchronous API can outlive phaseD. Preserve its actual
                // result; only the existing outer Job/rootD bounds a stuck call.
                const auto dns=ruleproxy_dns_standard::query(item,clock.frequency,command.phase_deadline);
                network=network||dns.called;
                if(dns.pending)failure="dns-pending";else if(!dns.called)failure="dns-config";
                (void)phase.sample();observation=",\"dns\":"+dns_report(item,dns);
            }else{
                Session session;SocketAPI api(0);rp_origin::Facts facts;
                if(!session.start())api.startup_error=session.error;network=network||session.started;
                Observer observer{phase};const auto c=config(run,item,port);
                const auto request=command.operation==2?rpb::relay_request(c):proxy_request(item);
                const auto response=rpb::expected_response(c);
                (void)rp_origin::roundtrip(api,observer,port,request.view(),response.view(),facts);
                if(!session.cleanup())rp_origin::fail(facts,rp_origin::Failure::Close,session.error);
                observation=",\"network\":"+bridge_origin::transport_report(facts,api,session,port);
            }
            clock.last=phase.last;if(!clock.sample()&&!failure)failure=clock.failure;
            const auto report=prefix("proxy-c-client-phase",role,run,boot,identity)+",\"case_id\":\""+item
                +"\",\"sequence\":"+std::to_string(sequence)+",\"operation\":\""+rpc::operation_name(command.operation)
                +"\",\"target_port\":"+std::to_string(port)+",\"admission_nonce\":\""+admission
                +"\",\"root_qpc\":["+std::to_string(clock.frequency)+","+std::to_string(clock.start)+","+std::to_string(clock.deadline)
                +"],\"phase_qpc\":["+std::to_string(observed_start)+","+std::to_string(command.phase_deadline)+","+std::to_string(phase.last)
                +"],\"command_close_verified\":"+boolean(commands_closed)+observation
                +",\"failure\":"+quoted(failure)+",\"proxy_tested\":false,\"product_acceptance\":false}";
            if(!publish(numbered(results,L"phase-",sequence,L".json"),report)){failure="report";break;}
            ++phases;++sequence;
        }
        if(!failure&&!finished)failure="command";
    }catch(...){failure="configuration";}
    const auto out=prefix("proxy-c-client-final",role,run,boot,identity)+qualification_json(profile,qualification)
        +",\"qpc\":"+clock.json()+",\"phase_count\":"+std::to_string(phases)+",\"finished\":"+boolean(finished)
        +",\"network_initialized_before_go\":false,\"network_initialized\":"+boolean(network)
        +",\"command_close_verified\":"+boolean(commands_closed)+",\"failure\":"+quoted(failure)
        +",\"proxy_tested\":false,\"product_acceptance\":false}";
    if(!publish(results+L"\\final.json",out))return 3;return failure?5:0;
}
struct ListenerFacts {
    bool created=false,inheritance=false,exclusive=false,bound=false,listening=false,accepted=false,peer_loopback=false;
    std::uint16_t port=0,peer_port=0;const char* failure=nullptr;std::uint32_t error=0;
    void fail(const char* why,std::uint32_t code=0){if(!failure){failure=why;error=code;}}
};
template<class Time>bool open_listener(Time& clock,Session& session,SocketSlot& listener,ListenerFacts& facts,std::uint16_t port){
    if(!clock.sample()){facts.fail("deadline");return false;}
    if(!session.start()){facts.fail("socket",session.error);return false;}
    if(!clock.sample()){facts.fail("deadline");return false;}
    listener.value=WSASocketW(AF_INET,SOCK_STREAM,IPPROTO_TCP,nullptr,0,WSA_FLAG_NO_HANDLE_INHERIT);
    facts.created=listener.value!=bridge_origin::Invalid;
    if(!clock.sample()||!facts.created){facts.fail("socket",static_cast<std::uint32_t>(WSAGetLastError()));return false;}
    facts.inheritance=bridge_origin::noninherit(listener.value);const BOOL exclusive=TRUE;
    if(!clock.sample()){facts.fail("deadline");return false;}
    facts.exclusive=setsockopt(listener.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))==0;
    if(!clock.sample()||!facts.inheritance||!facts.exclusive){facts.fail("socket");return false;}
    sockaddr_in address{};address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(port);
    const int bound=bind(listener.value,reinterpret_cast<const sockaddr*>(&address),sizeof(address));
    const auto bind_error=bound?static_cast<std::uint32_t>(WSAGetLastError()):0;
    if(!clock.sample()||bound){facts.fail("bind",bind_error);return false;}
    int length=sizeof(address);const int named=getsockname(listener.value,reinterpret_cast<sockaddr*>(&address),&length);
    if(!clock.sample()||named||length!=sizeof(address)||address.sin_family!=AF_INET||address.sin_addr.s_addr!=htonl(INADDR_LOOPBACK)){
        facts.fail("bind");return false;}
    facts.port=ntohs(address.sin_port);facts.bound=true;
    if(!rpc::high(facts.port)){facts.fail("bind");return false;}
    const auto nonblock=bridge_origin::nonblocking(listener.value);if(!clock.sample()||nonblock.code!=Code::Progress){facts.fail("socket",nonblock.error);return false;}
    const int listened=listen(listener.value,1);if(!clock.sample()||listened){facts.fail("listen",static_cast<std::uint32_t>(WSAGetLastError()));return false;}
    facts.listening=true;return true;
}
template<class Time>bool wait_socket(Time& clock,SOCKET socket,bool write,ListenerFacts& facts){
    if(!clock.sample()){facts.fail("deadline");return false;}
    const auto result=bridge_origin::poll(socket,write,50);
    if(!clock.sample()){facts.fail("deadline");return false;}
    if(result.code==Code::Error){facts.fail(write?"send":"request",result.error);return false;}return true;
}
template<class Time>bool accept_one(Time& clock,SocketSlot& listener,SocketSlot& connection,ListenerFacts& facts,bool& pending){
    pending=false;if(!clock.sample()){facts.fail("deadline");return false;}
    sockaddr_in peer{};int length=sizeof(peer);connection.value=accept(listener.value,reinterpret_cast<sockaddr*>(&peer),&length);
    const auto error=connection.value==bridge_origin::Invalid?static_cast<std::uint32_t>(WSAGetLastError()):0;
    const bool in_time=clock.sample();
    if(connection.value==bridge_origin::Invalid){if(error==WSAEWOULDBLOCK&&in_time){pending=true;return true;}facts.fail("accept",error);return false;}
    facts.accepted=true;facts.peer_port=ntohs(peer.sin_port);facts.peer_loopback=length==sizeof(peer)&&peer.sin_family==AF_INET
        &&peer.sin_addr.s_addr==htonl(INADDR_LOOPBACK)&&facts.peer_port!=0;
    if(!in_time||!facts.peer_loopback){facts.fail("accept");return false;}
    const bool inherit=bridge_origin::noninherit(connection.value);if(!clock.sample()||!inherit){facts.fail("socket");return false;}
    const auto nonblock=bridge_origin::nonblocking(connection.value);if(!clock.sample()||nonblock.code!=Code::Progress){facts.fail("socket",nonblock.error);return false;}
    return true;
}
struct TransferFacts {std::uint32_t received=0,sent=0;bool request_exact=false,eof=false,response_complete=false,shutdown=false;};
template<class Time,class Feed>bool receive_request(Time& clock,SocketSlot& connection,ListenerFacts& facts,TransferFacts& transfer,
                                                   std::vector<std::uint8_t>& bytes,Feed feed){
    for(;;){if(!clock.sample()){facts.fail("deadline");return false;}
        std::array<std::uint8_t,257> chunk{};const auto got=bridge_origin::receive_bytes(connection.value,chunk.data(),chunk.size());
        const bool in_time=clock.sample();
        if(got.code==Code::Progress){if(!got.count||got.count>chunk.size()){facts.fail("request");return false;}
            transfer.received+=got.count;bytes.insert(bytes.end(),chunk.begin(),chunk.begin()+got.count);
            if(bytes.size()>8192){facts.fail("request");return false;}
            if(!in_time||!feed({chunk.data(),got.count})){facts.fail("request");return false;}}
        else if(got.code==Code::Eof){transfer.eof=true;if(!in_time){facts.fail("deadline");return false;}return true;}
        else if(got.code==Code::WouldBlock){if(!in_time||!wait_socket(clock,connection.value,false,facts))return false;}
        else{facts.fail("request",got.error);return false;}}
}
template<class Time,class Feed>bool send_response(Time& clock,SocketSlot& connection,ListenerFacts& facts,TransferFacts& transfer,rpb::ByteView bytes,Feed feed){
    while(transfer.sent<bytes.size){if(!clock.sample()){facts.fail("deadline");return false;}
        const auto count=(std::min)(std::size_t(257),bytes.size-transfer.sent);
        const auto sent=bridge_origin::send_bytes(connection.value,{bytes.data+transfer.sent,count});const bool in_time=clock.sample();
        if(sent.code==Code::Progress){if(!sent.count||sent.count>count){facts.fail("send");return false;}
            transfer.sent+=sent.count;if(!in_time||!feed(sent.count)){facts.fail("send");return false;}}
        else if(sent.code==Code::WouldBlock){if(!in_time||!wait_socket(clock,connection.value,true,facts))return false;}
        else{facts.fail("send",sent.error);return false;}}
    transfer.response_complete=true;if(!clock.sample()){facts.fail("deadline");return false;}
    transfer.shutdown=shutdown(connection.value,SD_SEND)==0;const auto error=transfer.shutdown?0:static_cast<std::uint32_t>(WSAGetLastError());
    if(!clock.sample()||!transfer.shutdown){facts.fail("shutdown",error);return false;}return true;
}
std::string listener_ready(const std::string& role,const std::string& run,const std::string& boot,const Observations& identity,
                           const std::string& profile,const Qualification& qualification,const std::string& qpc,const ListenerFacts& facts,bool network){
    return prefix("proxy-c-listener-ready",role,run,boot,identity)+qualification_json(profile,qualification)+",\"qpc\":"+qpc
        +",\"port\":"+(facts.port?std::to_string(facts.port):"null")+",\"ready\":"+boolean(!facts.failure&&facts.listening)
        +",\"network_initialized\":"+boolean(network)+",\"failure\":"+quoted(facts.failure)+"}";
}
std::string transfer_json(const TransferFacts& t,const SocketSlot& connection){return "{\"request_bytes\":"+std::to_string(t.received)
    +",\"request_exact\":"+boolean(t.request_exact)+",\"request_eof\":"+boolean(t.eof)+",\"response_bytes\":"+std::to_string(t.sent)
    +",\"response_complete\":"+boolean(t.response_complete)+",\"send_shutdown\":"+boolean(t.shutdown)
    +",\"connection_close\":\""+rp_origin::close_name(connection.receipt)+"\"}";}
bool close_socket(SocketSlot& socket,ListenerFacts& facts){if(socket.value==bridge_origin::Invalid)return true;
    const auto result=socket.close();if(result.code!=Code::Progress)facts.fail("close",result.error);return result.code==Code::Progress;}
// Probe's zero-capability admission is intentionally not called for this PNCS role.
bool admit_front(bridge_pipe::Probe& probe,const Observations& identity,const std::string& user,const std::string& ac,const Qualification& q){
    if(!basic_identity(identity,user,true,ac)||!q.verified||!q.cleaned){probe.fail("identity");return false;}
    LARGE_INTEGER f{};if(!QueryPerformanceFrequency(&f)||f.QuadPart<=0||static_cast<std::uint64_t>(f.QuadPart)!=probe.facts.frequency||!probe.sample()){
        probe.fail("qpc");return false;}
    for(const auto handle:std::array<HANDLE,2>{probe.reader.value,probe.writer.value}){
        if(GetFileType(handle)!=FILE_TYPE_PIPE||!probe.sample()){probe.fail("pipe_type");return false;}
        DWORD flags=0;if(!SetHandleInformation(handle,HANDLE_FLAG_INHERIT,0)||!GetHandleInformation(handle,&flags)
            ||(flags&HANDLE_FLAG_INHERIT)||!probe.sample()){probe.fail("inheritance");return false;}}
    probe.facts.inheritance=true;return true;
}
int front(int argc,wchar_t** argv){
    if(argc!=17)return 2;std::string run,item,user,ac;std::wstring report,ready,control;
    std::uint64_t read=0,write=0,start=0,f=0,end=0,o=0,p=0;
    if(!ReadNonce(argv[2],run)||!ReadNonce(argv[3],item)||!ReadReportPath(argv[4],report)
       ||!bridge_pipe::decimal(argv[5],bridge_pipe::MaxSigned,read)||!bridge_pipe::decimal(argv[6],bridge_pipe::MaxSigned,write)||read==write
       ||!bridge_pipe::decimal(argv[7],bridge_pipe::MaxSigned,start)||!bridge_pipe::decimal(argv[8],1000000000ULL,f)
       ||!bridge_pipe::decimal(argv[9],bridge_pipe::MaxSigned,end)||!bridge_pipe::sid_text(argv[10],user)
       ||!bridge_pipe::sid_text(argv[11],ac)||std::wstring(argv[12])!=L"0"||!bridge_pipe::decimal(argv[13],65535,o)
       ||!bridge_pipe::decimal(argv[14],65535,p)||o<49153||p<49153||o==p||!ReadReportPath(argv[15],ready)||!ReadReportPath(argv[16],control))return 2;
    bridge_pipe::Probe probe(true,run,item,reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(read)),
        reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(write)),start,f,end,static_cast<std::uint16_t>(o),rpb::OriginAuthority::LocalLoopback);
    Observations identity;Qualification q;Session session;SocketSlot listener,connection;ListenerFacts facts;TransferFacts t;
    try{
        identity=ObserveNativeIdentity();q=capabilities(identity,"pncs");
        if(admit_front(probe,identity,user,ac,q)&&open_listener(probe,session,listener,facts,static_cast<std::uint16_t>(p))
           &&probe.read_frame()&&probe.write_frame()){
            const auto qpc="["+std::to_string(f)+","+std::to_string(start)+","+std::to_string(end)+","+std::to_string(probe.facts.last)+"]";
            if(!publish(ready,listener_ready("pipe-live-front",run,item,identity,"pncs",q,qpc,facts,session.started)))facts.fail("report");
            bool pending=true;
            while(!facts.failure&&pending){if(!accept_one(probe,listener,connection,facts,pending))break;
                if(pending&&!wait_socket(probe,listener.value,false,facts))break;}
            if(!facts.failure&&connection.value!=bridge_origin::Invalid){std::vector<std::uint8_t> bytes;
                const auto c=config(run,item,static_cast<std::uint16_t>(o));
                if(receive_request(probe,connection,facts,t,bytes,[&](rpb::ByteView b){return probe.event(2,0,b);})){
                    t.request_exact=rpb::parse_request(c,{bytes.data(),bytes.size()})==rpb::Failure::None;probe.facts.request_checked=t.request_exact;
                    if(t.request_exact&&probe.event(3)&&probe.write_frame()&&probe.read_frame()&&probe.read_eof()&&probe.close_pipe(false)){
                        const auto expected=rpb::expected_response(c);probe.facts.response_checked=rpb::equal(probe.pending_http(),expected.view());
                        if(probe.facts.response_checked&&send_response(probe,connection,facts,t,expected.view(),[&](std::uint32_t n){return probe.event(4,1,{nullptr,0},n);})){
                            const bool closed=close_socket(connection,facts);probe.facts.client_checked=closed&&t.response_complete&&t.shutdown;
                            if(probe.event(6,2,{nullptr,0},closed?1u:0u)&&closed){(void)probe.write_frame();(void)probe.close_pipe(true);}
                        }
                    }else if(!t.request_exact)facts.fail("request");
                }
            }
        }
    }catch(...){facts.fail("configuration");}
    (void)close_socket(connection,facts);(void)close_socket(listener,facts);
    if(!session.cleanup())facts.fail("close",session.error);probe.cleanup();
    (void)probe.sample();
    if(probe.facts.failure&&!facts.failure)facts.fail(probe.facts.failure);
    auto mechanics=bridge_pipe::report(probe,identity,true,run,item);while(!mechanics.empty()&&(mechanics.back()=='\n'||mechanics.back()=='\r'))mechanics.pop_back();
    std::string out="{\"schema_version\":1,\"stage\":\"proxy-c-live-front\",\"role\":\"pipe-live-front\",\"run_id\":\""+run
        +"\",\"case_id\":\""+item+"\",\"pid\":"+std::to_string(identity.pid)+",\"identity\":"+identity_json(run,identity)+qualification_json("pncs",q)
        +",\"ipc_mechanics\":"+mechanics+",\"listener\":{\"port\":"+(facts.port?std::to_string(facts.port):"null")
        +",\"listener_created\":"+boolean(facts.created)+",\"inheritance_cleared\":"+boolean(facts.inheritance)+",\"exclusive\":"+boolean(facts.exclusive)
        +",\"bind_loopback\":"+boolean(facts.bound)+",\"accepted\":"+boolean(facts.accepted)+",\"peer_loopback\":"+boolean(facts.peer_loopback)
        +",\"peer_port\":"+(facts.peer_port?std::to_string(facts.peer_port):"null")+",\"listener_close\":\""+rp_origin::close_name(listener.receipt)+"\"}"
        +",\"client\":"+transfer_json(t,connection)+",\"wsa_startup\":"+boolean(session.started)+",\"wsa_cleanup\":"+boolean(session.cleaned)
        +",\"failure\":"+quoted(facts.failure)+",\"wsa_error\":"+(facts.error?std::to_string(facts.error):"null")
        +",\"http_boundary\":\"real-client-request-and-response-socket\",\"network_tested\":"+boolean(facts.accepted)
        +",\"proxy_tested\":false,\"product_acceptance\":false}";
    if(!publish(report,out))return 3;return facts.failure?5:0;
}
bool withhold_origin(Clock& clock,SocketSlot& connection,ListenerFacts& facts,const TransferFacts& transfer,
                     const Observations& identity,const std::string& run,const std::string& boot,const std::string& item,
                     const std::wstring& report_directory,const std::wstring& control,std::uint64_t accepted_tick,bool& commands_closed){
    const rpc::Binding binding{bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(item),clock.frequency,clock.deadline,0,0,0};
    rpc::WithholdGate gate;
    if(!clock.sample()||connection.value==bridge_origin::Invalid||connection.receipt!=Close::NotAttempted
       ||transfer.response_complete||transfer.shutdown||!gate.begin(binding,bridge_pipe::id_bytes(item),
           transfer.request_exact,transfer.eof,transfer.sent,clock.last)){facts.fail(clock.failure?clock.failure:"configuration");return false;}
    const auto held_tick=clock.last;
    const auto root_qpc="["+std::to_string(clock.frequency)+","+std::to_string(clock.start)+","+std::to_string(clock.deadline)+"]";
    const auto common=",\"case_id\":\""+item+"\",\"root_qpc\":"+root_qpc+",\"port\":"+std::to_string(facts.port)
        +",\"peer_port\":"+std::to_string(facts.peer_port)+",\"request_bytes\":"+std::to_string(transfer.received)
        +",\"request_exact\":"+boolean(transfer.request_exact)+",\"request_eof\":"+boolean(transfer.eof)
        +",\"response_bytes\":"+std::to_string(transfer.sent)+",\"response_withheld\":true";
    const auto held=prefix("proxy-c-origin-withheld","health-origin-withhold",run,boot,identity)+common
        +",\"flow_qpc\":["+std::to_string(accepted_tick)+","+std::to_string(held_tick)+"],\"socket_held\":true"
        +",\"command_close_verified\":"+boolean(commands_closed)+",\"failure\":null,\"proxy_tested\":false,\"product_acceptance\":false}";
    if(!publish(report_directory+L"\\death-held.json",held)){facts.fail("report");return false;}
    rpc::Command command;std::uint64_t release_tick=0;
    while(!facts.failure){
        // Finish never substitutes for release. No response/send/recv/accept is
        // performed while this owned socket is held; only the original clock
        // and the single predeclared release file are observed.
        const auto state=command_file(control+L"\\release.bin",binding,1,clock,command,commands_closed,false,true);
        if(state==FileState::Invalid){facts.fail(clock.failure?clock.failure:"command");break;}
        if(state==FileState::Valid){
            release_tick=clock.last;
            if(!gate.release(binding,command,clock.last))facts.fail("command");
            break;
        }
        if(!clock.sample()){facts.fail("deadline");break;}
        Sleep(clock.remaining_ms());
    }
    const bool closed=close_socket(connection,facts);
    if(gate.released&&!gate.consume_close(closed))facts.fail("close");
    if(!clock.sample())facts.fail("deadline");
    const auto released=prefix("proxy-c-origin-released","health-origin-withhold",run,boot,identity)+common
        +",\"flow_qpc\":["+std::to_string(accepted_tick)+","+std::to_string(held_tick)+","+std::to_string(release_tick)+","+std::to_string(clock.last)+"]"
        +",\"socket_held\":"+boolean(connection.value!=bridge_origin::Invalid)+",\"release_sequence\":"+std::to_string(gate.released?command.sequence:0)
        +",\"release_verified\":"+boolean(gate.released)+",\"release_command_close_verified\":"+boolean(commands_closed)
        +",\"connection_close\":\""+rp_origin::close_name(connection.receipt)+"\",\"failure\":"+quoted(facts.failure)
        +",\"proxy_tested\":false,\"product_acceptance\":false}";
    if(!publish(report_directory+L"\\death-release.json",released))facts.fail("report");
    return !facts.failure&&gate.released&&gate.closed;
}
int health_listener(int argc,wchar_t** argv){
    const bool withholding=std::wstring(argv[1])==L"health-origin-withhold";
    if(argc!=(withholding?15:14))return 2;
    const std::string role=withholding||std::wstring(argv[1])==L"health-origin"?"health-origin":"health-listener";
    const std::string profile=role=="health-origin"?"ordinary":"pncs";
    std::string run,boot,user,ac,death;std::wstring report,ready,control;Clock clock;std::uint64_t port=0,maximum=0;
    if(!ReadNonce(argv[2],run)||!ReadNonce(argv[3],boot)||!ReadReportPath(argv[4],report)||!ReadReportPath(argv[5],ready)
       ||!ReadReportPath(argv[6],control)||!bridge_pipe::decimal(argv[7],1000000000ULL,clock.frequency)
       ||!bridge_pipe::decimal(argv[8],bridge_pipe::MaxSigned,clock.start)||!bridge_pipe::decimal(argv[9],bridge_pipe::MaxSigned,clock.deadline)
       ||(std::wstring(argv[10])!=L"0"&&!bridge_pipe::decimal(argv[10],65535,port))||(port&&port<49153)
       ||!bridge_pipe::sid_text(argv[11],user)||!bridge_pipe::decimal(argv[13],8,maximum))return 2;
    if(std::wstring(argv[12])==L"none")ac="none";else if(!bridge_pipe::sid_text(argv[12],ac))return 2;
    if((profile=="ordinary")!=(ac=="none"))return 2;
    if(withholding&&(!ReadNonce(argv[14],death)||death==run||death==boot))return 2;
    Observations identity;Qualification q;Session session;SocketSlot listener;ListenerFacts facts;
    bool finished=false,commands_closed=true;unsigned accepted=0,receipts=0;std::vector<std::string> seen;
    const rpc::Binding finish_binding{bridge_pipe::id_bytes(run),bridge_pipe::id_bytes(boot),clock.frequency,clock.deadline,0,0,0};
    try{
        identity=ObserveNativeIdentity();q=capabilities(identity,profile);
        if(!basic_identity(identity,user,profile!="ordinary",ac))facts.fail("identity");
        else if(!q.verified||!q.cleaned)facts.fail("capability");else if(!clock.admit())facts.fail("qpc");
        else (void)open_listener(clock,session,listener,facts,static_cast<std::uint16_t>(port));
        if(!publish(ready,listener_ready(role,run,boot,identity,profile,q,clock.json(),facts,session.started)))facts.fail("report");
        while(!facts.failure&&!finished){
            rpc::Command finish;const auto state=command_file(control+L"\\finish.bin",finish_binding,1,clock,finish,commands_closed,true);
            if(state==FileState::Invalid){facts.fail(clock.failure?clock.failure:"command");break;}
            if(state==FileState::Valid){finished=true;break;}
            if(accepted>=maximum){facts.fail("accept-limit");break;}
            SocketSlot connection;ListenerFacts item_facts;item_facts.port=facts.port;TransferFacts t;bool pending=false;
            if(!accept_one(clock,listener,connection,item_facts,pending)){facts.fail(item_facts.failure,item_facts.error);(void)close_socket(connection,facts);break;}
            if(pending){if(!wait_socket(clock,listener.value,false,facts))break;continue;}
            ++accepted;const auto accept_tick=clock.last;std::vector<std::uint8_t> bytes;std::string item;
            if(receive_request(clock,connection,item_facts,t,bytes,[](rpb::ByteView){return true;})){
                const std::string request(bytes.begin(),bytes.end());
                const std::string marker=profile=="ordinary"?"GET /p1/":"GET http://ruleproxy-identity-proof.invalid/";
                if(request.compare(0,marker.size(),marker)==0&&request.size()>=marker.size()+32){
                    const auto candidate=request.substr(marker.size(),32);const std::wstring wide(candidate.begin(),candidate.end());
                    if(ReadNonce(wide.c_str(),item)){
                        const auto c=config(run,item,facts.port);const auto expected=profile=="ordinary"?rpb::relay_request(c):proxy_request(item);
                        t.request_exact=rpb::equal({bytes.data(),bytes.size()},expected.view());
                        for(const auto& previous:seen)if(previous==item)t.request_exact=false;
                        if(t.request_exact){seen.push_back(item);
                            if(withholding&&item==death){
                                (void)withhold_origin(clock,connection,item_facts,t,identity,run,boot,item,parent(report),control,accept_tick,commands_closed);
                            }else{const auto response=rpb::expected_response(c);
                                (void)send_response(clock,connection,item_facts,t,response.view(),[](std::uint32_t){return true;});}}
                    }
                }
                if(!t.request_exact)item_facts.fail("request");
            }
            (void)clock.sample();(void)close_socket(connection,item_facts);if(!clock.sample())item_facts.fail(clock.failure);
            std::string receipt="{\"schema_version\":1,\"stage\":\"proxy-c-listener-receipt\",\"role\":\""+role+"\",\"run_id\":\""+run
                +"\",\"boot_case_id\":\""+boot+"\",\"case_id\":"+(item.empty()?"null":"\""+item+"\"")+",\"pid\":"+std::to_string(identity.pid)
                +",\"index\":"+std::to_string(accepted)+",\"port\":"+std::to_string(facts.port)+",\"peer_port\":"+std::to_string(item_facts.peer_port)
                +",\"qpc\":["+std::to_string(clock.frequency)+","+std::to_string(accept_tick)+","+std::to_string(clock.deadline)+","+std::to_string(clock.last)
                +"],\"request_bytes\":"+std::to_string(t.received)+",\"request_exact\":"+boolean(t.request_exact)+",\"request_eof\":"+boolean(t.eof)
                +",\"response_bytes\":"+std::to_string(t.sent)+",\"response_complete\":"+boolean(t.response_complete)+",\"send_shutdown\":"+boolean(t.shutdown)
                +",\"connection_close\":\""+rp_origin::close_name(connection.receipt)+"\",\"failure\":"+quoted(item_facts.failure)
                +",\"wsa_error\":"+(item_facts.error?std::to_string(item_facts.error):"null")+"}";
            if(!publish(numbered(parent(report),L"receipt-",accepted,L".json"),receipt)){facts.fail("report");break;}++receipts;
            if(item_facts.failure){facts.fail(item_facts.failure,item_facts.error);break;}
        }
    }catch(...){facts.fail("configuration");}
    (void)close_socket(listener,facts);if(!session.cleanup())facts.fail("close",session.error);
    if(!clock.sample()&&!facts.failure)facts.fail(clock.failure);
    const auto out=prefix("proxy-c-listener-final",role,run,boot,identity)+qualification_json(profile,q)+",\"qpc\":"+clock.json()
        +",\"port\":"+(facts.port?std::to_string(facts.port):"null")+",\"accepted_count\":"+std::to_string(accepted)
        +",\"receipt_count\":"+std::to_string(receipts)+",\"finished\":"+boolean(finished)+",\"listener_close\":\""+rp_origin::close_name(listener.receipt)
        +"\",\"wsa_startup\":"+boolean(session.started)+",\"wsa_cleanup\":"+boolean(session.cleaned)
        +",\"command_close_verified\":"+boolean(commands_closed)+",\"failure\":"+quoted(facts.failure)
        +",\"wsa_error\":"+(facts.error?std::to_string(facts.error):"null")+"}";
    if(!publish(report,out))return 3;return facts.failure?5:0;
}
int dispatch(int argc,wchar_t** argv){
    if(argc<2)return 2;const std::wstring role(argv[1]);
    if(role==L"selected-client"||role==L"health-client")return client(argc,argv);
    if(role==L"pipe-live-front")return front(argc,argv);
    if(role==L"health-origin"||role==L"health-listener"||role==L"health-origin-withhold")return health_listener(argc,argv);
    if(role==L"pipe-relay")return bridge_origin::pair(argc,argv);
    if(role==L"origin-fixture")return bridge_origin::fixture(argc,argv);
    return 2;
}
} // namespace bridge_c
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    // The wide GUI CRT startup configures __wargv before calling wWinMain.
    // Avoid Shell32 and its UI DLL initialization under the Win32k restriction.
    const int count=__argc;auto raw=__wargv;if(!raw)return 2;
    std::vector<std::wstring> arguments;bool valid=count>=2&&count<=32;
    try{if(valid)for(int i=0;i<count;++i){const std::wstring text(raw[i]);if(text.size()>4096){valid=false;break;}arguments.push_back(text);}}
    catch(...){valid=false;}
    if(!valid)return 2;std::vector<wchar_t*> pointers;for(auto& argument:arguments)pointers.push_back(&argument[0]);
    try{return bridge_c::dispatch(count,pointers.data());}catch(...){return 6;}
}
