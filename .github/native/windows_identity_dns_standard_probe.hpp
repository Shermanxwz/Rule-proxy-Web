// Independent standard DNS server constructor. No request is made by inclusion.
// Official sample: microsoft/Windows-classic-samples, DNSAsyncQuery/cpp/DnsQueryEx.cpp,
// CreateDnsServerList: zero array, MaxCount=AddrCount=1, copy bare IP sockaddr.
// Family remains zero here deliberately; the sockaddr itself is AF_INET/port 0.
// DnsQueryEx is synchronous (null callback/cancel), so only an outer absolute
// Job watchdog can bound a blocked call. This does not change resolver settings.
#pragma once
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windns.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#pragma comment(lib,"dnsapi.lib")

namespace ruleproxy_dns_standard {
constexpr const char* ServerConstructor="official-v1-zero-port";
struct Result {
    bool configured=false,called=false,completed=false,pending=false,answer_match=false;
    bool records_released=false,context_retained=false,within_deadline=false;
    DWORD api_status=ERROR_SUCCESS,query_status=ERROR_SUCCESS;
    unsigned record_count=0;std::uint64_t start_qpc=0,end_qpc=0;
};
struct Context {
    std::wstring name;
    DNS_ADDR_ARRAY servers{};
    DNS_QUERY_REQUEST request{};
    DNS_QUERY_RESULT response{};
};
inline bool nonce(const std::string& value){
    if(value.size()!=32)return false;
    for(const auto c:value)if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return false;return true;
}
inline bool configure(Context& context,const std::string& id){
    if(!nonce(id))return false;
    context.name.assign(id.begin(),id.end());context.name+=L".n0a.invalid";
    // Explicit zeroing includes every reserved/padding byte. There is no port
    // argument, no high-port mode, and no automatic fallback to standard DNS.
    std::memset(&context.servers,0,sizeof(context.servers));
    std::memset(&context.request,0,sizeof(context.request));
    std::memset(&context.response,0,sizeof(context.response));
    context.servers.MaxCount=1;context.servers.AddrCount=1;
    sockaddr_in address{};address.sin_family=AF_INET; // sin_port stays zero.
    constexpr unsigned char loopback[4]={127,0,0,1};
    static_assert(sizeof(address.sin_addr)==sizeof(loopback),"IPv4 width");
    std::memcpy(&address.sin_addr,loopback,sizeof(loopback));
    static_assert(sizeof(address)<=sizeof(context.servers.AddrArray[0].MaxSa),"official DNS_ADDR storage");
    std::memcpy(context.servers.AddrArray[0].MaxSa,&address,sizeof(address));
    context.request.Version=DNS_QUERY_REQUEST_VERSION1;
    context.request.QueryName=context.name.c_str();context.request.QueryType=DNS_TYPE_A;
    context.request.QueryOptions=DNS_QUERY_BYPASS_CACHE|DNS_QUERY_NO_HOSTS_FILE|DNS_QUERY_NO_LOCAL_NAME|
        DNS_QUERY_NO_NETBT|DNS_QUERY_WIRE_ONLY|DNS_QUERY_NO_MULTICAST|DNS_QUERY_TREAT_AS_FQDN;
    context.request.pDnsServerList=&context.servers;
    // pQueryCompletionCallback/pQueryContext/InterfaceIndex and reserved stay 0.
    context.response.Version=DNS_QUERY_RESULTS_VERSION1;return true;
}
struct NativeAPI {
    bool frequency(std::uint64_t& out){LARGE_INTEGER value{};if(!QueryPerformanceFrequency(&value)||value.QuadPart<=0)return false;
        out=static_cast<std::uint64_t>(value.QuadPart);return true;}
    bool qpc(std::uint64_t& out){LARGE_INTEGER value{};if(!QueryPerformanceCounter(&value)||value.QuadPart<=0)return false;
        out=static_cast<std::uint64_t>(value.QuadPart);return true;}
    DNS_STATUS call(DNS_QUERY_REQUEST& request,DNS_QUERY_RESULT& response){return DnsQueryEx(&request,&response,nullptr);}
    void free_records(PDNS_RECORD records)noexcept{DnsRecordListFree(records,DnsFreeRecordList);}
    bool equal_name(PCWSTR a,PCWSTR b){return CompareStringOrdinal(a,-1,b,-1,TRUE)==CSTR_EQUAL;}
};
template<class API>struct ContextDeleter {
    API* api;
    void operator()(Context* context)const noexcept{
        if(context->response.pQueryRecords){api->free_records(context->response.pQueryRecords);context->response.pQueryRecords=nullptr;}
        delete context;
    }
};
// API injection exists solely for pure no-DNS-call lifetime/configuration tests.
// Every actual pointer target is in one stable heap Context, including QueryName.
template<class API>Result query_with_api(API& api,const std::string& id,std::uint64_t frequency,std::uint64_t deadline){
    Result result;
    if(!nonce(id)||!frequency||frequency>1000000000ULL||deadline>0x7fffffffffffffffULL)return result;
    std::uint64_t actual=0;
    if(!api.frequency(actual)||actual!=frequency||!api.qpc(result.start_qpc)||result.start_qpc>=deadline
       ||deadline-result.start_qpc>120*frequency)return result;
    const auto admitted_start=result.start_qpc;
    std::unique_ptr<Context,ContextDeleter<API>> context(new Context,{&api});
    if(!configure(*context,id))return result;result.configured=true;
    if(!api.qpc(result.start_qpc)||result.start_qpc<admitted_start||result.start_qpc>=deadline)return result;
    result.called=true;const auto status=api.call(context->request,context->response);
    result.api_status=static_cast<DWORD>(status);
    result.within_deadline=api.qpc(result.end_qpc)&&result.end_qpc>=result.start_qpc&&result.end_qpc<deadline;
    if(status==DNS_REQUEST_PENDING){
        result.pending=true;context.release(); // No free/cancel/retry: retain ALL pointers until process death.
        result.context_retained=true;return result;
    }
    result.completed=true;result.query_status=static_cast<DWORD>(context->response.QueryStatus);
    bool exact=true;auto* record=context->response.pQueryRecords;
    constexpr unsigned char expected[4]={192,0,2,123};
    while(record&&result.record_count<16){
        ++result.record_count;
        exact=exact&&record->wType==DNS_TYPE_A&&record->wDataLength==sizeof(DNS_A_DATA)&&record->pName
            &&api.equal_name(record->pName,context->name.c_str())
            &&std::memcmp(&record->Data.A.IpAddress,expected,sizeof(expected))==0;
        record=record->pNext;
    }
    result.answer_match=status==ERROR_SUCCESS&&context->response.QueryStatus==ERROR_SUCCESS&&exact
        &&result.record_count==1&&!record;
    if(context->response.pQueryRecords){api.free_records(context->response.pQueryRecords);context->response.pQueryRecords=nullptr;}
    result.records_released=true;return result;
}
inline Result query(const std::string& id,std::uint64_t frequency,std::uint64_t deadline){
    NativeAPI api;return query_with_api(api,id,frequency,deadline);
}
} // namespace ruleproxy_dns_standard
