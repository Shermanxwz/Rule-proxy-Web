// Disposable native WFP experiment. Never included in a product runtime.
// Persistent, app-ID-scoped terminating callouts remain BLOCK when no kernel
// callout is registered. This demonstrates denial only, not redirection,
// descendant identity, boot protection, or a working ProxyBridge backend.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <rpc.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>

struct Failure { DWORD code; const char* stage; };
static void checked(DWORD code, const char* stage) {
    if (code != ERROR_SUCCESS) throw Failure{code, stage};
}
static void require(bool ok, const char* stage) {
    if (!ok) throw Failure{ERROR_INVALID_DATA, stage};
}
static bool same(const GUID& a, const GUID& b) { return !!IsEqualGUID(a, b); }

struct Engine {
    HANDLE handle = nullptr;
    bool transaction = false;
    Engine() {
        // Non-dynamic session: committed filters survive this handle/process.
        checked(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &handle), "engine-open");
    }
    ~Engine() {
        if (transaction) FwpmTransactionAbort0(handle);
        if (handle) FwpmEngineClose0(handle);
    }
    void begin() { checked(FwpmTransactionBegin0(handle, 0), "transaction-begin"); transaction = true; }
    void commit() { checked(FwpmTransactionCommit0(handle), "transaction-commit"); transaction = false; }
};
template<class T> struct WfpMemory {
    T* value = nullptr;
    ~WfpMemory() { if (value) FwpmFreeMemory0(reinterpret_cast<void**>(&value)); }
};

static std::wstring full_path(const wchar_t* path) {
    wchar_t buffer[32768];
    DWORD size = GetFullPathNameW(path, 32768, buffer, nullptr);
    require(size != 0 && size < 32768, "absolute-path");
    return std::wstring(buffer, size);
}
static void lab_scope(const wchar_t* program) {
    wchar_t actions[16], temp[32768];
    require(GetEnvironmentVariableW(L"GITHUB_ACTIONS", actions, 16) == 4 &&
            std::wcscmp(actions, L"true") == 0, "disposable-github-runner-required");
    DWORD size = GetEnvironmentVariableW(L"RUNNER_TEMP", temp, 32768);
    require(size && size < 32768, "runner-temp-required");
    auto root = full_path(temp);
    if (root.back() != L'\\') root += L'\\';
    auto path = full_path(program);
    require(path.size() > root.size() &&
            _wcsnicmp(path.c_str(), root.c_str(), root.size()) == 0,
            "only-runner-temp-executable-may-be-filtered");
    auto filename = path.substr(path.find_last_of(L"\\/") + 1);
    require(filename == L"RuleProxyNativeProbe.exe", "only-synthetic-probe-may-be-filtered");
    DWORD attributes = GetFileAttributesW(path.c_str());
    require(attributes != INVALID_FILE_ATTRIBUTES &&
            !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)), "probe-is-ordinary-file");
}

struct Policy {
    GUID seed{}, sublayer{}, callout[2]{}, filter[2]{};
    unsigned char owner[64]{};
    FWP_BYTE_BLOB ownership{};
    WfpMemory<FWP_BYTE_BLOB> app;
    Policy(const wchar_t* text, const wchar_t* program) {
        checked(UuidFromStringW(reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(text)), &seed), "policy-guid");
        const GUID zero{};
        require(!same(seed, zero), "nonzero-policy-guid");
        sublayer = seed; sublayer.Data4[7] ^= 0x11;
        callout[0] = seed; callout[0].Data4[7] ^= 0x21;
        callout[1] = seed; callout[1].Data4[7] ^= 0x22;
        filter[0] = seed; filter[0].Data4[7] ^= 0x31;
        filter[1] = seed; filter[1].Data4[7] ^= 0x32;
        const char mark[] = "RuleProxy-disposable-WFP-lab-v1";
        std::memcpy(owner, mark, sizeof(mark));
        std::memcpy(owner + sizeof(mark), &seed, sizeof(seed));
        ownership = {static_cast<UINT32>(sizeof(mark) + sizeof(seed)), owner};
        auto path = full_path(program);
        checked(FwpmGetAppIdFromFileName0(path.c_str(), &app.value), "app-id");
    }
    bool owned(const FWP_BYTE_BLOB& data) const {
        return data.size == ownership.size && data.data &&
               std::memcmp(data.data, ownership.data, data.size) == 0;
    }
};
static const GUID* layers[2] = {&FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V6};

static void add_policy(Engine& e, Policy& p) {
    FWPM_SUBLAYER0 sub{};
    sub.subLayerKey = p.sublayer;
    sub.displayData.name = const_cast<wchar_t*>(L"RuleProxy disposable native denial lab");
    sub.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    sub.weight = 0xF000;
    sub.providerData = p.ownership;
    // No service-associated provider: a non-autostart provider can have its
    // filters disabled by BFE at restart. Reboot/boot-time behavior is untested.
    checked(FwpmSubLayerAdd0(e.handle, &sub, nullptr), "sublayer-add");
    for (int i = 0; i < 2; ++i) {
        FWPM_CALLOUT0 call{};
        call.calloutKey = p.callout[i];
        call.displayData.name = sub.displayData.name;
        call.flags = FWPM_CALLOUT_FLAG_PERSISTENT;
        call.providerData = p.ownership;
        call.applicableLayer = *layers[i];
        checked(FwpmCalloutAdd0(e.handle, &call, nullptr, nullptr), "callout-add");
        FWPM_FILTER_CONDITION0 condition{};
        condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        condition.matchType = FWP_MATCH_EQUAL;
        condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        condition.conditionValue.byteBlob = p.app.value;
        FWPM_FILTER0 rule{};
        rule.filterKey = p.filter[i];
        rule.displayData.name = sub.displayData.name;
        rule.flags = FWPM_FILTER_FLAG_PERSISTENT;
        rule.providerData = p.ownership;
        rule.layerKey = *layers[i];
        rule.subLayerKey = p.sublayer;
        rule.weight.type = FWP_EMPTY;
        rule.numFilterConditions = 1;
        rule.filterCondition = &condition;
        rule.action.type = FWP_ACTION_CALLOUT_TERMINATING;
        rule.action.calloutKey = p.callout[i];
        // PERMIT_IF_CALLOUT_UNREGISTERED must never be set.
        checked(FwpmFilterAdd0(e.handle, &rule, nullptr, nullptr), "filter-add");
    }
}

// Validate every existing object before any deletion. A GUID receipt alone
// does not prove enforcement or ownership; read the objects back from BFE.
static unsigned inspect_policy(Engine& e, Policy& p, bool output) {
    unsigned count = 0;
    UINT64 ids[2]{};
    WfpMemory<FWPM_SUBLAYER0> sub;
    DWORD result = FwpmSubLayerGetByKey0(e.handle, &p.sublayer, &sub.value);
    if (result != FWP_E_SUBLAYER_NOT_FOUND) {
        checked(result, "sublayer-get");
        require(p.owned(sub.value->providerData) && !sub.value->providerKey &&
                (sub.value->flags & FWPM_SUBLAYER_FLAG_PERSISTENT), "sublayer-ownership");
        ++count;
    }
    for (int i = 0; i < 2; ++i) {
        WfpMemory<FWPM_CALLOUT0> call;
        result = FwpmCalloutGetByKey0(e.handle, &p.callout[i], &call.value);
        if (result != FWP_E_CALLOUT_NOT_FOUND) {
            checked(result, "callout-get");
            require(p.owned(call.value->providerData) && !call.value->providerKey &&
                    same(call.value->applicableLayer, *layers[i]) &&
                    (call.value->flags & FWPM_CALLOUT_FLAG_PERSISTENT) &&
                    !(call.value->flags & FWPM_CALLOUT_FLAG_REGISTERED), "callout-ownership-and-unregistered-state");
            ++count;
        }
        WfpMemory<FWPM_FILTER0> rule;
        result = FwpmFilterGetByKey0(e.handle, &p.filter[i], &rule.value);
        if (result != FWP_E_FILTER_NOT_FOUND) {
            checked(result, "filter-get");
            auto& f = *rule.value;
            require(p.owned(f.providerData) && !f.providerKey &&
                    same(f.layerKey, *layers[i]) && same(f.subLayerKey, p.sublayer) &&
                    f.action.type == FWP_ACTION_CALLOUT_TERMINATING && same(f.action.calloutKey, p.callout[i]) &&
                    (f.flags & FWPM_FILTER_FLAG_PERSISTENT) &&
                    !(f.flags & (FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED | FWPM_FILTER_FLAG_DISABLED)) &&
                    f.numFilterConditions == 1 && f.filterCondition, "filter-enforcement-properties");
            auto& c = f.filterCondition[0];
            require(same(c.fieldKey, FWPM_CONDITION_ALE_APP_ID) && c.matchType == FWP_MATCH_EQUAL &&
                    c.conditionValue.type == FWP_BYTE_BLOB_TYPE && c.conditionValue.byteBlob &&
                    c.conditionValue.byteBlob->size == p.app.value->size &&
                    std::memcmp(c.conditionValue.byteBlob->data, p.app.value->data, p.app.value->size) == 0,
                    "filter-exact-app-id");
            ids[i] = f.filterId;
            ++count;
        }
    }
    if (output) {
        std::printf("{\"object_count\":%u,\"absent\":%s,\"verified\":%s,\"filter_ids\":[%llu,%llu],"
                    "\"scope\":\"executable-path-only\",\"callout_registered\":false}\n",
                    count, count == 0 ? "true" : "false", count == 5 ? "true" : "false",
                    static_cast<unsigned long long>(ids[0]), static_cast<unsigned long long>(ids[1]));
        std::fflush(stdout);
    }
    return count;
}
static void delete_result(DWORD code, DWORD absent, const char* stage) {
    if (code != absent) checked(code, stage);
}
static void remove_policy(Engine& e, Policy& p) {
    e.begin();
    inspect_policy(e, p, false);
    for (int i = 0; i < 2; ++i)
        delete_result(FwpmFilterDeleteByKey0(e.handle, &p.filter[i]), static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND), "filter-delete");
    for (int i = 0; i < 2; ++i)
        delete_result(FwpmCalloutDeleteByKey0(e.handle, &p.callout[i]), static_cast<DWORD>(FWP_E_CALLOUT_NOT_FOUND), "callout-delete");
    delete_result(FwpmSubLayerDeleteByKey0(e.handle, &p.sublayer), static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND), "sublayer-delete");
    e.commit();
    require(inspect_policy(e, p, true) == 0, "cleanup-not-verified");
}

static int probe(const wchar_t* host, const wchar_t* port, const wchar_t* protocol) {
    bool udp = std::wcscmp(protocol, L"udp") == 0;
    require(udp || std::wcscmp(protocol, L"tcp") == 0, "probe-protocol");
    WSADATA data{};
    checked(static_cast<DWORD>(WSAStartup(MAKEWORD(2, 2), &data)), "winsock-startup");
    ADDRINFOW hints{}, *address = nullptr;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
    int status = GetAddrInfoW(host, port, &hints, &address);
    if (status) { WSACleanup(); throw Failure{static_cast<DWORD>(status), "numeric-probe-address"}; }
    SOCKET socket = WSASocketW(address->ai_family, hints.ai_socktype, hints.ai_protocol, nullptr, 0, 0);
    DWORD error = socket == INVALID_SOCKET ? static_cast<DWORD>(WSAGetLastError()) : 0;
    if (!error) {
        DWORD timeout = 3000;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
        if (connect(socket, address->ai_addr, static_cast<int>(address->ai_addrlen)) == SOCKET_ERROR)
            error = static_cast<DWORD>(WSAGetLastError());
        else if (send(socket, "WFP-LAB", 7, 0) != 7) error = static_cast<DWORD>(WSAGetLastError());
        else {
            char reply[7]{};
            int received = recv(socket, reply, sizeof(reply), udp ? 0 : MSG_WAITALL);
            if (received != 7 || std::memcmp(reply, "WFP-LAB", 7) != 0)
                error = received == SOCKET_ERROR ? static_cast<DWORD>(WSAGetLastError()) : ERROR_INVALID_DATA;
        }
    }
    if (socket != INVALID_SOCKET) closesocket(socket);
    FreeAddrInfoW(address);
    WSACleanup();
    std::printf("{\"connected\":%s,\"wsa_error\":%lu}\n", error ? "false" : "true", error);
    return error ? 2 : 0;
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 5 && std::wcscmp(argv[1], L"probe") == 0) return probe(argv[2], argv[3], argv[4]);
        require(argc == 4, "usage-command-guid-synthetic-exe");
        std::wstring command = argv[1];
        require(command == L"install" || command == L"hold" || command == L"abort-hold" ||
                command == L"inspect" || command == L"remove", "known-command");
        lab_scope(argv[3]);
        Policy p(argv[2], argv[3]);
        Engine e;
        if (command == L"inspect") { inspect_policy(e, p, true); return 0; }
        if (command == L"remove") { remove_policy(e, p); return 0; }
        require(inspect_policy(e, p, false) == 0, "new-policy-must-be-absent");
        e.begin();
        add_policy(e, p);
        if (command == L"abort-hold") {
            std::puts("{\"transaction_pending\":true}"); std::fflush(stdout);
            Sleep(INFINITE); // The test kills this process before commit.
        }
        e.commit();
        require(inspect_policy(e, p, true) == 5, "installed-policy-not-verified");
        if (command == L"hold") Sleep(INFINITE); // The test kills this process after commit.
        return 0;
    } catch (const Failure& error) {
        std::printf("{\"error_code\":%lu,\"stage\":\"%s\"}\n", error.code, error.stage);
        return 1;
    }
}
