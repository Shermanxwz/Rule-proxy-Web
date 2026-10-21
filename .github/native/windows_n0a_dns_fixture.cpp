// TEST ONLY. Installed Windows SDK REQUEST3 mechanism fixture, never deployable.
// The parent owns the process deadline. No callback/cancellation or isolation claim.
#if !defined(N0A_DNS_TEST_ONLY) || N0A_DNS_TEST_ONLY != 1
#error This source is only a non-deployable DNS mechanism fixture.
#endif
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
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <winsock2.h>
#include <ws2ipdef.h> // Official DNS_CUSTOM_SERVER::ServerAddr declaration.
#include <windows.h>
#include <windns.h>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <string>
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ws2_32.lib")

static_assert(DNS_QUERY_REQUEST_VERSION3 == 3, "Official REQUEST3 SDK required");
static_assert(DNS_CUSTOM_SERVER_TYPE_UDP == 1, "Official custom UDP SDK required");

namespace {
struct Context {
    std::wstring name;
    DNS_CUSTOM_SERVER server{};
    DNS_QUERY_REQUEST3 request{};
    DNS_QUERY_RESULT result{};
    DNS_QUERY_CANCEL cancel{};
    ~Context() {
        if (result.pQueryRecords != nullptr) {
            DnsRecordListFree(result.pQueryRecords, DnsFreeRecordList);
            result.pQueryRecords = nullptr;
        }
    }
};
// Unexpected PENDING retains all pointed-to storage until process termination.
// This is not a cancellation mechanism and does not assert broker completion.
Context* retainedPendingContext = nullptr;

bool Nonce(const wchar_t* value) {
    if (value == nullptr || wcslen(value) != 32) return false;
    for (size_t i = 0; i < 32; ++i) {
        if (!((value[i] >= L'0' && value[i] <= L'9') || (value[i] >= L'a' && value[i] <= L'f'))) return false;
    }
    return true;
}
bool Port(const wchar_t* value, unsigned short& port) {
    if (value == nullptr || *value == L'\0') return false;
    unsigned long number = 0;
    for (size_t i = 0; value[i] != L'\0'; ++i) {
        if (i >= 5 || value[i] < L'0' || value[i] > L'9') return false;
        number = number * 10 + static_cast<unsigned long>(value[i] - L'0');
    }
    if (number < 1025 || number > 65535) return false;
    port = static_cast<unsigned short>(number); return true;
}
const char* Bool(bool value) { return value ? "true" : "false"; }
void Emit(DNS_STATUS apiStatus, const Context* context, bool apiCalled, bool pending,
          unsigned count, bool answerMatch, bool freed) {
    const std::string status = pending ? "null" : std::to_string(static_cast<DWORD>(context->result.QueryStatus));
    const std::string records = pending ? "null" : std::to_string(count);
    std::printf("{\"schema\":1,\"test_only\":true,\"request_version\":3,"
                "\"custom_server_count\":1,\"custom_udp\":true,\"custom_flags_zero\":true,"
                "\"legacy_server_list_null\":true,\"callback_null\":true,"
                "\"api_called\":%s,\"pending\":%s,\"api_status\":%lu,\"result_status\":%s,"
                "\"record_count\":%s,\"answer_match\":%s,\"records_freed\":%s,"
                "\"context_retained\":%s,\"runtime_acceptance\":false}\n",
                Bool(apiCalled), Bool(pending), static_cast<unsigned long>(static_cast<DWORD>(apiStatus)),
                status.c_str(), records.c_str(), Bool(answerMatch), Bool(freed),
                Bool(pending && retainedPendingContext != nullptr));
    std::fflush(stdout);
}
[[noreturn]] void RetainPending(std::unique_ptr<Context> context, bool apiCalled) {
    retainedPendingContext = context.release();
    Emit(DNS_REQUEST_PENDING, retainedPendingContext, apiCalled, true, 0, false, false);
    // Parent's exact-owned process timeout is the bound. Do not unwind/free any
    // request/result/custom-server/name/cancel storage as if completion occurred.
    for (;;) Sleep(INFINITE);
}
int Run(int argc, wchar_t** argv) {
    const bool injectedPending = argc == 2 && wcscmp(argv[1], L"--test-pending") == 0;
    unsigned short port = 0;
    if (!injectedPending && (argc != 4 || wcscmp(argv[1], L"--query") != 0 || !Nonce(argv[2]) || !Port(argv[3], port))) return 2;
    auto context = std::make_unique<Context>();
    context->name = injectedPending ? L"00000000000000000000000000000000.n0a.invalid." : std::wstring(argv[2]) + L".n0a.invalid.";
    context->server.dwServerType = DNS_CUSTOM_SERVER_TYPE_UDP;
    context->server.ullFlags = 0;
    context->server.pwszTemplate = nullptr;
    context->server.ServerAddr.Ipv4.sin_family = AF_INET;
    context->server.ServerAddr.Ipv4.sin_port = htons(port);
    context->server.ServerAddr.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    context->request.Version = DNS_QUERY_REQUEST_VERSION3;
    context->request.QueryName = context->name.c_str();
    context->request.QueryType = DNS_TYPE_A;
    context->request.QueryOptions = DNS_QUERY_WIRE_ONLY | DNS_QUERY_BYPASS_CACHE |
        DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN;
    context->request.pDnsServerList = nullptr;
    context->request.InterfaceIndex = 0;
    context->request.pQueryCompletionCallback = nullptr;
    context->request.pQueryContext = nullptr;
    context->request.IsNetworkQueryRequired = FALSE; // Reserved: never used to force routing.
    context->request.RequiredNetworkIndex = 0;       // Reserved.
    context->request.cCustomServers = 1;
    context->request.pCustomServers = &context->server;
    context->result.Version = DNS_QUERY_RESULTS_VERSION1;
    if (injectedPending) RetainPending(std::move(context), false);
    const DNS_STATUS status = DnsQueryEx(reinterpret_cast<PDNS_QUERY_REQUEST>(&context->request), &context->result, &context->cancel);
    if (status == DNS_REQUEST_PENDING) RetainPending(std::move(context), true);
    unsigned count = 0;
    bool answer = false;
    for (PDNS_RECORD record = context->result.pQueryRecords; record != nullptr; record = record->pNext) {
        if (++count > 16) { answer = false; break; }
        const bool nameMatches = record->pName != nullptr &&
            (_wcsicmp(record->pName, context->name.c_str()) == 0 ||
             _wcsicmp(record->pName, context->name.substr(0, context->name.size() - 1).c_str()) == 0);
        const bool exact = record->wType == DNS_TYPE_A && record->wDataLength == sizeof(DNS_A_DATA) &&
            record->Flags.S.Section == DnsSectionAnswer && record->dwTtl == 0 && nameMatches &&
            record->Data.A.IpAddress == htonl(0xc000027bUL);
        answer = count == 1 && exact;
    }
    answer = answer && count == 1 && status == ERROR_SUCCESS && context->result.QueryStatus == ERROR_SUCCESS;
    const bool freed = context->result.pQueryRecords != nullptr;
    if (freed) {
        DnsRecordListFree(context->result.pQueryRecords, DnsFreeRecordList);
        context->result.pQueryRecords = nullptr;
    }
    Emit(status, context.get(), true, false, count, answer, freed);
    return 0; // Completed observation, never a network/isolation acceptance verdict.
}
}
int wmain(int argc, wchar_t** argv) {
    try {
        const int status = Run(argc, argv);
        if (status == 2) std::puts("{\"schema\":1,\"test_only\":true,\"failure\":\"arguments\",\"runtime_acceptance\":false}");
        return status;
    } catch (...) {
        std::puts("{\"schema\":1,\"test_only\":true,\"failure\":\"internal\",\"runtime_acceptance\":false}");
        return 3;
    }
}
