// Independent ordinary-only standard53 mechanism. The owner MUST first hold
// image/token/Job and establish an owned 127.0.0.1:53 same-API receiver control.
// No default resolver settings, REQUEST3, callback or high-port fallback.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedDnsStandardIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include "windows_identity_dns_standard_probe.hpp"
#include <cstdio>
namespace {
bool StandardDecimal(const wchar_t* value,std::uint64_t& out){
    if(!value||!*value||*value==L'0')return false;out=0;unsigned count=0;
    for(;*value;++value){if(++count>19||*value<L'0'||*value>L'9')return false;
        const auto digit=static_cast<std::uint64_t>(*value-L'0');if(out>(0x7fffffffffffffffULL-digit)/10)return false;
        out=out*10+digit;}return out!=0;
}
const char* StandardBool(bool value){return value?"true":"false";}
int StandardMain(int argc,wchar_t** argv){
    if(argc!=4)return 2;std::string id;std::uint64_t frequency=0,deadline=0;
    if(!ReadNonce(argv[1],id)||!StandardDecimal(argv[2],frequency)||!StandardDecimal(argv[3],deadline))return 2;
    const auto identity=ObserveNativeIdentity();
    if(!identity.errors.empty()||identity.tokenElevated!=std::optional<bool>(false)
       ||identity.tokenIsAppContainer!=std::optional<bool>(false)||identity.tokenAppContainerSid.has_value()
       ||identity.isProcessInJob!=std::optional<bool>(true)||!identity.tokenCapabilities.empty())return 4;
    const auto result=ruleproxy_dns_standard::query(id,frequency,deadline);
    const auto native=MakeReport("actor",id,identity,std::nullopt,std::nullopt);
    const std::string output="{\"schema_version\":1,\"stage\":\"dns-standard-native\",\"identity\":"+native
        +",\"server_constructor\":\""+ruleproxy_dns_standard::ServerConstructor+"\",\"qpc_frequency\":"+std::to_string(frequency)
        +",\"deadline_qpc\":"+std::to_string(deadline)+",\"result\":{\"configured\":"+StandardBool(result.configured)
        +",\"called\":"+StandardBool(result.called)+",\"completed\":"+StandardBool(result.completed)
        +",\"pending\":"+StandardBool(result.pending)+",\"answer_match\":"+StandardBool(result.answer_match)
        +",\"records_released\":"+StandardBool(result.records_released)+",\"context_retained\":"+StandardBool(result.context_retained)
        +",\"within_deadline\":"+StandardBool(result.within_deadline)+",\"api_status\":"+std::to_string(result.api_status)
        +",\"query_status\":"+std::to_string(result.query_status)+",\"record_count\":"+std::to_string(result.record_count)
        +",\"start_qpc\":"+std::to_string(result.start_qpc)+",\"end_qpc\":"+std::to_string(result.end_qpc)+"}}";
    if(output.size()>8192||std::fwrite(output.data(),1,output.size(),stdout)!=output.size()||std::fflush(stdout)!=0)return 3;
    // Completed errors are mechanism observations, never wire/deny qualification.
    return result.called&&result.completed&&!result.pending?0:5;
}
}
int wmain(int argc,wchar_t** argv){try{return StandardMain(argc,argv);}catch(...){return 6;}}
