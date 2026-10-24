// New same-process finite diagnostic. No old actor/protocol is modified.
// DNS uses the frozen synchronous VERSION1 helper; no socket is transferred.
#include "windows_identity_lpac_pipe_dns_contract.hpp"
#ifndef RULEPROXY_LPAC_PIPE_DNS_PORTABLE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include "windows_identity_dns_standard_probe.hpp"
#define RULEPROXY_PROXY_PIPE_LIBRARY 1
#include "windows_identity_proxy_pipe_actor.cpp"
#include <utility>
namespace lpac_pipe_dns {
std::uint64_t qpc(){LARGE_INTEGER v{};return QueryPerformanceCounter(&v)&&v.QuadPart>0?static_cast<std::uint64_t>(v.QuadPart):0;}
std::string trim(std::string v){while(!v.empty()&&(v.back()=='\n'||v.back()=='\r'))v.pop_back();return v;}
std::string clock(const Plan& p){return "["+std::to_string(p.frequency)+","+std::to_string(p.start)+","+std::to_string(p.end)+"]";}
std::string prefix(const Plan& p,const char* stage,DWORD pid){return "{\"schema_version\":1,\"stage\":\""+std::string(stage)+"\",\"role\":\"lpac-pipe-front\",\"run_id\":\""+p.run+"\",\"http_case_id\":\""+p.http+"\",\"dns_case_id\":\""+p.dns+"\",\"pid\":"+std::to_string(pid);}
bool write(const std::wstring& path,const std::string& bytes){
    bridge_pipe::Slot slot;slot.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(slot.value==INVALID_HANDLE_VALUE){slot.value=nullptr;return false;}bool ok=false;
    try{ok=WriteReport(slot.value,bytes);}catch(...){ok=false;}DWORD error=0;const bool closed=slot.close(error);return ok&&closed;
}
bool command(const std::wstring& path,const Plan& p,std::uint32_t next,Command& out,bool& close_verified,std::uint64_t& observed){
    close_verified=false;observed=0;
    for(;;){const auto now=qpc();if(!now||now>=p.end)return false;
        bridge_pipe::Slot slot;slot.value=CreateFileW(path.c_str(),GENERIC_READ,0,nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(slot.value==INVALID_HANDLE_VALUE){slot.value=nullptr;const auto error=GetLastError();if(error==ERROR_FILE_NOT_FOUND){Sleep(10);continue;}return false;}
        std::array<std::uint8_t,128> bytes{};std::uint8_t extra=0;DWORD size=0,tail=0;LARGE_INTEGER length{};
        const bool read_ok=GetFileSizeEx(slot.value,&length)&&length.QuadPart==128&&ReadFile(slot.value,bytes.data(),128,&size,nullptr)&&size==128
            &&ReadFile(slot.value,&extra,1,&tail,nullptr)&&tail==0;
        DWORD error=0;close_verified=slot.close(error);observed=qpc();
        return read_ok&&close_verified&&observed&&decode(bytes.data(),bytes.size(),p.binding,next,observed,out);
    }
}
bool self(const Observations& i,const Plan& p){return i.errors.empty()&&i.tokenUserSid==std::optional<std::string>(p.user)
    &&i.tokenIsAppContainer==std::optional<bool>(true)&&i.tokenAppContainerSid==std::optional<std::string>(p.package)
    &&i.tokenElevated==std::optional<bool>(false)&&i.isProcessInJob==std::optional<bool>(true)&&i.tokenCapabilities.empty();}
std::string result_json(const ruleproxy_dns_standard::Result& r){
    return std::string("{\"configured\":")+bridge_pipe::boolean(r.configured)+",\"called\":"+bridge_pipe::boolean(r.called)+",\"completed\":"+bridge_pipe::boolean(r.completed)
      +",\"pending\":"+bridge_pipe::boolean(r.pending)+",\"answer_match\":"+bridge_pipe::boolean(r.answer_match)+",\"records_released\":"+bridge_pipe::boolean(r.records_released)
      +",\"context_retained\":"+bridge_pipe::boolean(r.context_retained)+",\"within_deadline\":"+bridge_pipe::boolean(r.within_deadline)
      +",\"api_status\":"+std::to_string(r.api_status)+",\"query_status\":"+std::to_string(r.query_status)+",\"record_count\":"+std::to_string(r.record_count)
      +",\"start_qpc\":"+std::to_string(r.start_qpc)+",\"end_qpc\":"+std::to_string(r.end_qpc)+"}";
}
int run(const std::vector<std::wstring>& a){
    Plan p;if(!plan(a,p))return 2;std::array<std::wstring,5> paths{};
    for(std::size_t i=0;i<5;++i)if(!ReadReportPath(a[i?14+i:4].c_str(),paths[i]))return 2;
    bridge_pipe::Probe probe(true,p.run,p.http,reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.reader)),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.writer)),p.start,p.frequency,p.end,p.port,rpb::OriginAuthority::LocalLoopback);
    Observations identity;bool rd=false,wr=false;std::uint64_t admitted=0;
    try{identity=ObserveNativeIdentity();if(probe.admitted(identity,p.user,p.package,false)){
        DWORD rf=0,wf=0;rd=GetHandleInformation(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.reader)),&rf)&&(rf&HANDLE_FLAG_INHERIT)==0;
        wr=GetHandleInformation(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.writer)),&wf)&&(wf&HANDLE_FLAG_INHERIT)==0;
        if(probe.sample()&&rd&&wr){admitted=probe.facts.last;probe.run();}else probe.fail("inheritance");}}
    catch(...){probe.fail("configuration");}probe.cleanup();
    const auto ipc="{\"schema_version\":1,\"stage\":\"lpac-pipe-dns-ipc-complete\",\"role\":\"lpac-pipe-front\",\"run_id\":\""+p.run+"\",\"case_id\":\""+p.http+"\",\"dns_case_id\":\""+p.dns+"\",\"pid\":"+std::to_string(identity.pid)+",\"ipc_mechanics\":"+trim(bridge_pipe::report(probe,identity,true,p.run,p.http))
       +",\"admitted_qpc\":"+(admitted?std::to_string(admitted):"null")+",\"read_handle_inherit_cleared\":"+bridge_pipe::boolean(rd)+",\"write_handle_inherit_cleared\":"+bridge_pipe::boolean(wr)
       +",\"identity_basis\":\"external-held-four-descriptor-required\",\"network_tested\":false,\"proxy_tested\":false,\"product_acceptance\":false}\n";
    if(!write(paths[0],ipc))return 3;if(probe.facts.failure)return 5;
    Command go;bool go_closed=false;std::uint64_t begin=0;if(!command(paths[1],p,1,go,go_closed,begin))return 5;
    ruleproxy_dns_standard::Result result;const char* failure=nullptr;Observations dns_identity;
    try{dns_identity=ObserveNativeIdentity();if(!self(dns_identity,p))failure="identity";else result=ruleproxy_dns_standard::query(p.dns,p.frequency,go.deadline);}
    catch(...){failure="dns-config";}
    const auto last=qpc();if(!failure){if(!last||!result.end_qpc)failure="qpc";else if(last>=go.deadline||!result.within_deadline)failure="deadline";
    else if(result.pending)failure="dns-pending";else if(!result.configured||!result.called||!result.completed)failure="dns-config";}
    constexpr auto options=DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE|DNS_QUERY_NO_LOCAL_NAME|DNS_QUERY_NO_NETBT|DNS_QUERY_WIRE_ONLY|DNS_QUERY_NO_MULTICAST|DNS_QUERY_TREAT_AS_FQDN;
    const auto dns=prefix(p,"lpac-pipe-dns-dns-result",identity.pid)+",\"sequence\":1,\"pair_qpc\":"+clock(p)+",\"phase_qpc\":["+std::to_string(begin)+","+std::to_string(go.deadline)+","+std::to_string(last)+"],\"command_close_verified\":"+bridge_pipe::boolean(go_closed)
       +",\"identity\":"+trim(MakeReport("actor",p.run,dns_identity,std::nullopt,std::nullopt))+",\"dns\":{\"server_constructor\":\"official-v1-zero-port\",\"server_address\":\"127.0.0.1\",\"server_port\":53,\"query_name\":\""+p.dns+".n0a.invalid\",\"query_type\":1,\"query_options\":"+std::to_string(options)+",\"result\":"+result_json(result)+"},\"failure\":"+(failure?"\""+std::string(failure)+"\"":"null")+",\"selected_socket_api_tested\":false,\"proxy_tested\":false,\"product_acceptance\":false}\n";
    if(!write(paths[2],dns))return 3;Command finish;bool finish_closed=false;std::uint64_t finish_qpc=0;
    const bool finished=command(paths[3],p,2,finish,finish_closed,finish_qpc);const auto final_qpc=qpc();
    const auto final=prefix(p,"lpac-pipe-dns-final",identity.pid)+",\"pair_qpc\":"+clock(p)+",\"last_qpc\":"+std::to_string(final_qpc)
       +",\"ipc_report_sha256\":\""+sha256(ipc)+"\",\"dns_report_sha256\":\""+sha256(dns)+"\",\"dns_called\":"+bridge_pipe::boolean(result.called)+",\"dns_pending\":"+bridge_pipe::boolean(result.pending)
       +",\"finish_admitted\":"+bridge_pipe::boolean(finished)+",\"command_close_verified\":"+bridge_pipe::boolean(finish_closed)+",\"failure\":"+(!finished?"\"control\"":failure?"\""+std::string(failure)+"\"":"null")
       +",\"selected_socket_api_tested\":false,\"proxy_tested\":false,\"product_acceptance\":false}\n";
    if(!write(paths[4],final))return 3;
    return finished&&final_qpc&&final_qpc<p.end&&!failure?0:5;
}
} // namespace lpac_pipe_dns
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){try{std::vector<std::wstring> a;if(!lpac_pipe_dns::arguments(GetCommandLineW(),a))return 2;return lpac_pipe_dns::run(a);}catch(...){return 6;}}
#endif
