// Cooperative LPAC-generated request/sink over two inherited pipes only.
// All real sockets remain in the separately built ordinary B relay/origin.
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include "windows_identity_proxy_bridge_core.hpp"

namespace lpac_pipe {
constexpr std::uint64_t MaxSigned=0x7fffffffffffffffULL;
struct Plan {
    std::string run,case_id,user,package;
    std::uint64_t reader=0,writer=0,start=0,frequency=0,end=0;
    std::uint16_t port=0;
};
inline bool decimal(const std::wstring& text,std::uint64_t max,std::uint64_t& out) {
    if(text.empty()||text.size()>20||text[0]==L'0')return false;
    std::uint64_t value=0;
    for(auto c:text){if(c<L'0'||c>L'9')return false;const auto digit=static_cast<std::uint64_t>(c-L'0');
        if(value>(max-digit)/10){return false;}value=value*10+digit;}
    out=value;return true;
}
inline bool nonce(const std::wstring& text,std::string& out) {
    if(text.size()!=32){return false;}out.clear();
    for(auto c:text){if(!((c>=L'0'&&c<=L'9')||(c>=L'a'&&c<=L'f')))return false;out+=static_cast<char>(c);}return true;
}
inline bool sid(const std::wstring& text,std::string& out) {
    if(text.size()<5||text.size()>255||text[0]!=L'S'||text[1]!=L'-'){return false;}out.clear();
    for(std::size_t i=0;i<text.size();++i){auto c=text[i];if(i>0&&c!=L'-'&&(c<L'0'||c>L'9'))return false;out+=static_cast<char>(c);}return true;
}
inline bool arguments(const wchar_t* p,std::vector<std::wstring>& out) {
    if(!p){return false;}std::size_t total=0;
    while(*p){while(*p==L' '||*p==L'\t')++p;if(!*p)break;
        std::wstring value;const bool quoted=*p==L'"';if(quoted)++p;
        while(*p&&!(quoted?*p==L'"':(*p==L' '||*p==L'\t'))){
            if(*p<32||(!quoted&&*p==L'"')){return false;}value+=*p++;
            if(++total>12000||value.size()>4096)return false;}
        if(quoted){if(*p!=L'"')return false;++p;if(*p&&*p!=L' '&&*p!=L'\t')return false;}
        if(value.empty()||out.size()>=14){return false;}out.push_back(std::move(value));
    }return out.size()==14;
}
inline bool plan(const std::vector<std::wstring>& args,Plan& out) {
    if(args.size()!=14||args[1]!=L"pipe-front"||args[12]!=L"0")return false;
    std::uint64_t port=0;
    if(!nonce(args[2],out.run)||!nonce(args[3],out.case_id)||!sid(args[10],out.user)||!sid(args[11],out.package)
       ||out.package=="none"||!decimal(args[5],MaxSigned,out.reader)||!decimal(args[6],MaxSigned,out.writer)
       ||out.reader==out.writer||!decimal(args[7],MaxSigned,out.start)||!decimal(args[8],1000000000ULL,out.frequency)
       ||!decimal(args[9],MaxSigned,out.end)||out.frequency>(MaxSigned-out.start)/10
       ||out.end!=out.start+10*out.frequency||!decimal(args[13],65535,port)||port<49153)return false;
    out.port=static_cast<std::uint16_t>(port);return true;
}
struct Readback {bool reader=false,writer=false,admitted=false;std::uint64_t admitted_qpc=0;};
template<class API,class Probe> inline bool inheritance_readback(API& api,Probe& probe,std::uintptr_t read,std::uintptr_t write,Readback& result) {
    if(!probe.sample())return false;
    std::uint32_t flags=0,error=0;const bool read_ok=api.flags(read,flags,error);
    result.reader=read_ok&&(flags&1u)==0;const bool read_time=probe.sample();
    if(!result.reader){if(error)probe.fail("inheritance",error);else probe.fail("inheritance");}
    if(!read_time||!result.reader)return false;
    flags=0;error=0;const bool write_ok=api.flags(write,flags,error);
    result.writer=write_ok&&(flags&1u)==0;const bool write_time=probe.sample();
    if(!result.writer){if(error)probe.fail("inheritance",error);else probe.fail("inheritance");}
    if(!write_time||!result.writer)return false;
    // First sampled native QPC after BOTH successful readbacks, before I/O.
    result.admitted_qpc=probe.facts.last;result.admitted=true;return true;
}
} // namespace lpac_pipe

#ifndef RULEPROXY_LPAC_PIPE_FRONT_PORTABLE
#define RULEPROXY_PROXY_PIPE_LIBRARY 1
#include "windows_identity_proxy_pipe_actor.cpp"

namespace lpac_pipe {
struct NativeFlags {
    bool flags(std::uintptr_t handle,std::uint32_t& observed_flags,std::uint32_t& error) {
        DWORD value=0;const BOOL ok=GetHandleInformation(reinterpret_cast<HANDLE>(handle),&value);
        error=ok?0:GetLastError();if(ok)observed_flags=value;return ok!=FALSE;
    }
};
std::string report(bridge_pipe::Probe& probe,const Observations& identity,const Plan& p,const Readback& inherited) {
    auto mechanics=bridge_pipe::report(probe,identity,true,p.run,p.case_id);
    while(!mechanics.empty()&&(mechanics.back()=='\n'||mechanics.back()=='\r'))mechanics.pop_back();
    return "{\"schema_version\":1,\"stage\":\"lpac-ipc-origin-selected\",\"role\":\"lpac-pipe-front\",\"run_id\":\""+p.run+
      "\",\"case_id\":\""+p.case_id+"\",\"pid\":"+std::to_string(identity.pid)+",\"ipc_mechanics\":"+mechanics+
      ",\"admitted_qpc\":"+(inherited.admitted?std::to_string(inherited.admitted_qpc):"null")+
      ",\"read_handle_inherit_cleared\":"+bridge_pipe::boolean(inherited.reader)+
      ",\"write_handle_inherit_cleared\":"+bridge_pipe::boolean(inherited.writer)+
      ",\"identity_basis\":\"external-held-four-descriptor-required\",\"network_tested\":false,\"proxy_tested\":false,\"product_acceptance\":false}\n";
}
int run(const std::vector<std::wstring>& args) {
    Plan p;if(!plan(args,p))return 2;std::wstring path;
    if(!ReadReportPath(args[4].c_str(),path))return 2;
    bridge_pipe::Probe probe(true,p.run,p.case_id,reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.reader)),
       reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(p.writer)),p.start,p.frequency,p.end,p.port,rpb::OriginAuthority::LocalLoopback);
    bridge_pipe::Slot output;output.value=CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(output.value==INVALID_HANDLE_VALUE){output.value=nullptr;probe.cleanup();return 3;}
    Observations identity;Readback inherited;
    try {
        identity=ObserveNativeIdentity();
        if(probe.admitted(identity,p.user,p.package,false)){
            NativeFlags api;
            if(inheritance_readback(api,probe,static_cast<std::uintptr_t>(p.reader),static_cast<std::uintptr_t>(p.writer),inherited))probe.run();
        }
    }catch(...){probe.fail("configuration");}
    probe.cleanup();bool written=false;
    try{written=WriteReport(output.value,report(probe,identity,p,inherited));}catch(...){written=false;}
    DWORD error=0;const bool closed=output.close(error);if(!written||!closed)return 3;
    return probe.facts.failure?5:0;
}
} // namespace lpac_pipe
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int) {
    try{std::vector<std::wstring> args;if(!lpac_pipe::arguments(GetCommandLineW(),args))return 2;return lpac_pipe::run(args);}
    catch(...){return 6;}
}
#endif
