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
#include <ws2ipdef.h>
#include <ws2tcpip.h> // Official header enables DNS_CUSTOM_SERVER::ServerAddr.
#include <windows.h>
#include <windns.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <string>
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "version.lib")
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
          unsigned count, bool answerMatch, bool freed, bool cancelNull) {
    const std::string status = pending ? "null" : std::to_string(static_cast<DWORD>(context->result.QueryStatus));
    const std::string records = pending ? "null" : std::to_string(count);
    const unsigned short observedPort = ntohs(context->server.ServerAddr.Ipv4.sin_port);
    const ULONG observedAddress = ntohl(context->server.ServerAddr.Ipv4.sin_addr.s_addr);
    const char* addressKind = observedAddress == INADDR_LOOPBACK ? "loopback1" : (observedAddress == 0x7f000002UL ? "loopback2" : "other");
    const char* endpointKind = observedPort == 53 ? "standard_port" : (observedPort >= 1025 ? "high_port" : "none");
    std::printf("{\"schema\":1,\"test_only\":true,\"request_version\":3,"
                "\"custom_server_count\":1,\"custom_udp\":true,\"custom_flags_zero\":true,"
                "\"legacy_server_list_null\":true,\"callback_null\":true,"
                "\"endpoint_address_kind\":\"%s\",\"endpoint_kind\":\"%s\",\"custom_port53\":%s,\"cancellation_handle_null\":%s,\"api_called\":%s,\"pending\":%s,\"api_status\":%lu,\"result_status\":%s,"
                "\"record_count\":%s,\"answer_match\":%s,\"records_freed\":%s,"
                "\"context_retained\":%s,\"runtime_acceptance\":false}\n",
                addressKind, endpointKind, Bool(observedPort == 53), Bool(cancelNull), Bool(apiCalled), Bool(pending), static_cast<unsigned long>(static_cast<DWORD>(apiStatus)),
                status.c_str(), records.c_str(), Bool(answerMatch), Bool(freed),
                Bool(pending && retainedPendingContext != nullptr));
    std::fflush(stdout);
}
[[noreturn]] void RetainPending(std::unique_ptr<Context> context, bool apiCalled, bool cancelNull) {
    retainedPendingContext = context.release();
    Emit(DNS_REQUEST_PENDING, retainedPendingContext, apiCalled, true, 0, false, false, cancelNull);
    // Parent's exact-owned process timeout is the bound. Do not unwind/free any
    // request/result/custom-server/name/cancel storage as if completion occurred.
    for (;;) Sleep(INFINITE);
}
void Describe(const Context& context, unsigned short port) {
    const HMODULE module = GetModuleHandleW(L"dnsapi.dll");
    bool systemPath = false;
    bool versionAvailable = false;
    DWORD version[4]{};
    std::vector<wchar_t> modulePath(32768), systemDirectory(32768);
    if (module != nullptr) {
        const DWORD moduleLength = GetModuleFileNameW(module, modulePath.data(), static_cast<DWORD>(modulePath.size()));
        const UINT directoryLength = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        if (moduleLength > 0 && moduleLength < modulePath.size() && directoryLength > 0 && directoryLength < systemDirectory.size()) {
            const std::wstring expected = std::wstring(systemDirectory.data(), directoryLength) + L"\\dnsapi.dll";
            systemPath = CompareStringOrdinal(modulePath.data(), static_cast<int>(moduleLength), expected.c_str(), static_cast<int>(expected.size()), TRUE) == CSTR_EQUAL;
            if (systemPath) {
                DWORD ignored = 0;
                const DWORD bytes = GetFileVersionInfoSizeW(modulePath.data(), &ignored);
                if (bytes > 0 && bytes <= 65536) {
                    std::vector<BYTE> info(bytes);
                    if (GetFileVersionInfoW(modulePath.data(), 0, bytes, info.data())) {
                        void* value = nullptr;
                        UINT length = 0;
                        if (VerQueryValueW(info.data(), L"\\", &value, &length) && value != nullptr && length >= sizeof(VS_FIXEDFILEINFO)) {
                            const auto* fixed = static_cast<const VS_FIXEDFILEINFO*>(value);
                            if (fixed->dwSignature == 0xfeef04bdUL) {
                                version[0] = HIWORD(fixed->dwFileVersionMS); version[1] = LOWORD(fixed->dwFileVersionMS);
                                version[2] = HIWORD(fixed->dwFileVersionLS); version[3] = LOWORD(fixed->dwFileVersionLS);
                                versionAvailable = true;
                            }
                        }
                    }
                }
            }
        }
    }
    std::printf("{\"schema\":1,\"test_only\":true,\"mode\":\"describe\",\"api_called\":false,\"runtime_acceptance\":false,"
                "\"layout\":{\"sizes\":[%zu,%zu,%zu],\"alignments\":[%zu,%zu,%zu],"
                "\"request_offsets\":[%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu],"
                "\"result_offsets\":[%zu,%zu,%zu,%zu,%zu],\"custom_offsets\":[%zu,%zu,%zu,%zu]},",
                sizeof(DNS_QUERY_REQUEST3), sizeof(DNS_QUERY_RESULT), sizeof(DNS_CUSTOM_SERVER),
                alignof(DNS_QUERY_REQUEST3), alignof(DNS_QUERY_RESULT), alignof(DNS_CUSTOM_SERVER),
                offsetof(DNS_QUERY_REQUEST3, Version), offsetof(DNS_QUERY_REQUEST3, QueryName),
                offsetof(DNS_QUERY_REQUEST3, QueryType), offsetof(DNS_QUERY_REQUEST3, QueryOptions),
                offsetof(DNS_QUERY_REQUEST3, pDnsServerList), offsetof(DNS_QUERY_REQUEST3, InterfaceIndex),
                offsetof(DNS_QUERY_REQUEST3, pQueryCompletionCallback), offsetof(DNS_QUERY_REQUEST3, pQueryContext),
                offsetof(DNS_QUERY_REQUEST3, IsNetworkQueryRequired), offsetof(DNS_QUERY_REQUEST3, RequiredNetworkIndex),
                offsetof(DNS_QUERY_REQUEST3, cCustomServers), offsetof(DNS_QUERY_REQUEST3, pCustomServers),
                offsetof(DNS_QUERY_RESULT, Version), offsetof(DNS_QUERY_RESULT, QueryStatus),
                offsetof(DNS_QUERY_RESULT, QueryOptions), offsetof(DNS_QUERY_RESULT, pQueryRecords), offsetof(DNS_QUERY_RESULT, Reserved),
                offsetof(DNS_CUSTOM_SERVER, dwServerType), offsetof(DNS_CUSTOM_SERVER, ullFlags),
                offsetof(DNS_CUSTOM_SERVER, pwszTemplate), offsetof(DNS_CUSTOM_SERVER, ServerAddr));
    std::printf("\"initialized\":{\"request_version\":%s,\"result_version\":%s,\"reserved_zero\":%s,\"result_zero\":%s,"
                "\"query_name_bound\":%s,\"query_type_a\":%s,\"interface_zero\":%s,\"context_null\":%s,\"options_exact\":%s,"
                "\"custom_singleton\":%s,\"legacy_null\":%s,\"callback_null\":%s,\"custom_udp\":%s,\"flags_zero\":%s,"
                "\"template_null\":%s,\"ipv4\":%s,\"loopback\":%s,\"port_roundtrip\":%s},"
                "\"module_existing\":%s,\"system_path_verified\":%s,\"version_available\":%s,\"dnsapi_file_version\":",
                Bool(context.request.Version == DNS_QUERY_REQUEST_VERSION3), Bool(context.result.Version == DNS_QUERY_RESULTS_VERSION1),
                Bool(context.request.IsNetworkQueryRequired == FALSE && context.request.RequiredNetworkIndex == 0),
                Bool(context.result.QueryStatus == 0 && context.result.QueryOptions == 0 && context.result.pQueryRecords == nullptr && context.result.Reserved == nullptr),
                Bool(context.request.QueryName == context.name.c_str() && !context.name.empty()),
                Bool(context.request.QueryType == DNS_TYPE_A), Bool(context.request.InterfaceIndex == 0), Bool(context.request.pQueryContext == nullptr),
                Bool(context.request.QueryOptions == (DNS_QUERY_WIRE_ONLY | DNS_QUERY_BYPASS_CACHE | DNS_QUERY_NO_HOSTS_FILE | DNS_QUERY_NO_NETBT | DNS_QUERY_NO_MULTICAST | DNS_QUERY_TREAT_AS_FQDN)),
                Bool(context.request.cCustomServers == 1 && context.request.pCustomServers == &context.server),
                Bool(context.request.pDnsServerList == nullptr), Bool(context.request.pQueryCompletionCallback == nullptr),
                Bool(context.server.dwServerType == DNS_CUSTOM_SERVER_TYPE_UDP), Bool(context.server.ullFlags == 0),
                Bool(context.server.pwszTemplate == nullptr), Bool(context.server.ServerAddr.Ipv4.sin_family == AF_INET),
                Bool(ntohl(context.server.ServerAddr.Ipv4.sin_addr.s_addr) == INADDR_LOOPBACK),
                Bool(ntohs(context.server.ServerAddr.Ipv4.sin_port) == port),
                Bool(module != nullptr), Bool(systemPath), Bool(versionAvailable));
    if (versionAvailable) std::printf("[%lu,%lu,%lu,%lu]", version[0], version[1], version[2], version[3]);
    else std::printf("null");
    std::printf("}\n");
    std::fflush(stdout);
}
int Run(int argc, wchar_t** argv) {
    const bool describe = argc == 2 && wcscmp(argv[1], L"--describe") == 0;
    const bool alternateHigh = argc == 4 && wcscmp(argv[1], L"--query-loopback2") == 0;
    const bool alternate53 = argc == 3 && wcscmp(argv[1], L"--query-loopback2-port53") == 0;
    const bool alternateAddress = alternateHigh || alternate53;
    const bool standardPort = alternate53 || (argc == 3 && wcscmp(argv[1], L"--query-port53") == 0);
    const bool injectedPending = argc == 2 && wcscmp(argv[1], L"--test-pending") == 0;
    const bool cancelNull = argc == 4 && wcscmp(argv[1], L"--query-null-cancel") == 0;
    unsigned short port = 0;
    if (standardPort && !Nonce(argv[2])) return 2;
    if (!describe && !injectedPending && !standardPort && (argc != 4 || (wcscmp(argv[1], L"--query") != 0 && !cancelNull && !alternateHigh) || !Nonce(argv[2]) || !Port(argv[3], port))) return 2;
    if (standardPort) port = 53; // Explicit TEST_ONLY mode; never a fallback.
    if (describe) port = 40000; // Private fixed initialization probe, never used for I/O.
    auto context = std::make_unique<Context>();
    context->name = (injectedPending || describe) ? L"00000000000000000000000000000000.n0a.invalid." : std::wstring(argv[2]) + L".n0a.invalid.";
    context->server.dwServerType = DNS_CUSTOM_SERVER_TYPE_UDP;
    context->server.ullFlags = 0;
    context->server.pwszTemplate = nullptr;
    context->server.ServerAddr.Ipv4.sin_family = AF_INET;
    context->server.ServerAddr.Ipv4.sin_port = htons(port);
    context->server.ServerAddr.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (alternateAddress) context->server.ServerAddr.Ipv4.sin_addr.s_addr = htonl(0x7f000002UL); // Fixed TEST_ONLY pair, no address argument.
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
    if (describe) { Describe(*context, port); return 0; }
    if (injectedPending) RetainPending(std::move(context), false, false);
    const DNS_STATUS status = DnsQueryEx(reinterpret_cast<PDNS_QUERY_REQUEST>(&context->request), &context->result, cancelNull ? nullptr : &context->cancel);
    if (status == DNS_REQUEST_PENDING) RetainPending(std::move(context), true, cancelNull);
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
    Emit(status, context.get(), true, false, count, answer, freed, cancelNull);
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
