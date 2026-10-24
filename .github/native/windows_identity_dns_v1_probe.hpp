// Opt-in DNS_QUERY_REQUEST_VERSION1 mechanism. No request is made by inclusion.
// Call only behind held admission and an outer absolute Job watchdog. This
// synchronous API cannot be canceled by the QPC checks around it. REQUEST3 and
// ambient/default resolver settings are not touched by this mechanism.
#pragma once
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
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace ruleproxy_dns_v1 {
struct Result {
    bool configured = false;
    bool called = false;
    bool completed = false;
    bool pending = false;
    bool answer_match = false;
    bool records_released = false;
    bool context_retained = false;
    bool within_deadline = false;
    DWORD api_status = ERROR_SUCCESS;
    DWORD query_status = ERROR_SUCCESS;
    unsigned record_count = 0;
    std::uint64_t start_qpc = 0;
    std::uint64_t end_qpc = 0;
};

struct Context {
    std::wstring name;
    DNS_ADDR_ARRAY servers{};
    DNS_QUERY_REQUEST request{};
    DNS_QUERY_RESULT response{};
    ~Context() {
        if (response.pQueryRecords != nullptr) {
            DnsRecordListFree(response.pQueryRecords, DnsFreeRecordList);
            response.pQueryRecords = nullptr;
        }
    }
};

inline bool nonce(const std::string& value) {
    if (value.size() != 32) return false;
    for (const char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

inline bool qpc(std::uint64_t& value) {
    LARGE_INTEGER q{};
    if (!QueryPerformanceCounter(&q) || q.QuadPart <= 0) return false;
    value = static_cast<std::uint64_t>(q.QuadPart);
    return true;
}

// One exact numeric loopback DNS server and one fresh synthetic A question.
// A same-API ordinary control and the independent receiver must establish the
// actual endpoint behavior before any denial can be interpreted as isolation.
// Unknown pending retains ALL pointer targets until process death; caller must
// stop further phases, retain ownership and terminate via the held outer Job.
inline Result query(const std::string& id, unsigned short port,
                    std::uint64_t frequency, std::uint64_t deadline) {
    Result result;
    if (!nonce(id) || !(port == 53 || port >= 49153) || frequency == 0 ||
        frequency > 1000000000 || deadline > 0x7fffffffffffffffULL) return result;
    LARGE_INTEGER actual{};
    if (!QueryPerformanceFrequency(&actual) || actual.QuadPart <= 0 ||
        static_cast<std::uint64_t>(actual.QuadPart) != frequency ||
        !qpc(result.start_qpc) || result.start_qpc >= deadline ||
        deadline - result.start_qpc > 120 * frequency) return result;
    auto context = std::make_unique<Context>();
    context->name.assign(id.begin(), id.end());
    context->name += L".n0a.invalid";
    context->servers.MaxCount = 1;
    context->servers.AddrCount = 1;
    context->servers.Family = AF_INET;
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    static_assert(sizeof(address) <= sizeof(context->servers.AddrArray[0].MaxSa),
                  "official DNS_ADDR storage too small");
    std::memcpy(context->servers.AddrArray[0].MaxSa, &address, sizeof(address));
    auto& request = context->request;
    request.Version = DNS_QUERY_REQUEST_VERSION1;
    request.QueryName = context->name.c_str();
    request.QueryType = DNS_TYPE_A;
    request.QueryOptions = DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE |
        DNS_QUERY_NO_LOCAL_NAME | DNS_QUERY_NO_NETBT | DNS_QUERY_WIRE_ONLY |
        DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN;
    request.pDnsServerList = &context->servers;
    // callback/context/interface and all reserved fields stay zero.
    context->response.Version = DNS_QUERY_RESULTS_VERSION1;
    result.configured = true;
    // No timer reset: all setup and this potentially blocking call are charged
    // against the original epoch. Job supervision is a required caller contract.
    if (!qpc(result.start_qpc) || result.start_qpc >= deadline) return result;
    result.called = true;
    const DNS_STATUS status = DnsQueryEx(&request, &context->response, nullptr);
    result.api_status = static_cast<DWORD>(status);
    result.end_qpc = 0;
    result.within_deadline = qpc(result.end_qpc) && result.end_qpc < deadline;
    if (status == DNS_REQUEST_PENDING) {
        result.pending = true;
        // Intentionally no destructor: OS may still hold these pointers.
        context.release();
        result.context_retained = true;
        return result;
    }
    result.completed = true;
    result.query_status = static_cast<DWORD>(context->response.QueryStatus);
    bool exact = true;
    auto* record = context->response.pQueryRecords;
    while (record != nullptr && result.record_count < 16) {
        ++result.record_count;
        // Only the one exact synthetic answer emitted by the owned responder.
        // Traversal is bounded; extra, aliased or CNAME answers do not qualify.
        exact = exact && record->wType == DNS_TYPE_A &&
            record->wDataLength == sizeof(DNS_A_DATA) && record->pName != nullptr &&
            CompareStringOrdinal(record->pName, -1, context->name.c_str(), -1,
                                 TRUE) == CSTR_EQUAL &&
            record->Data.A.IpAddress == htonl(0xc000027bUL);
        record = record->pNext;
    }
    result.answer_match = status == ERROR_SUCCESS &&
        context->response.QueryStatus == ERROR_SUCCESS && exact &&
        result.record_count == 1 && record == nullptr;
    if (context->response.pQueryRecords != nullptr) {
        DnsRecordListFree(context->response.pQueryRecords, DnsFreeRecordList);
        context->response.pQueryRecords = nullptr;
    }
    result.records_released = true;
    return result;
}
} // namespace ruleproxy_dns_v1
