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
#include <vector>

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

struct NativeHandle {
    HANDLE value = nullptr;
    NativeHandle() = default;
    NativeHandle(const NativeHandle&) = delete;
    NativeHandle& operator=(const NativeHandle&) = delete;
    ~NativeHandle() { if (value) CloseHandle(value); }
};

static std::vector<BYTE> token_information(HANDLE token, TOKEN_INFORMATION_CLASS kind) {
    DWORD size = 0;
    GetTokenInformation(token, kind, nullptr, 0, &size);
    require(GetLastError() == ERROR_INSUFFICIENT_BUFFER && size != 0, "token-information-size");
    std::vector<BYTE> data(size);
    if (!GetTokenInformation(token, kind, data.data(), size, &size))
        throw Failure{GetLastError(), "token-information-read"};
    return data;
}

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

// New credentials are synthetic, never authenticated or used for network I/O.
// Query the real suspended child's token, then kill it without resuming it.
// A new LSA logon session is not assumed to give a distinct WFP-matchable SID.
static int token_identity(const wchar_t* program) {
    lab_scope(program);
    NativeHandle current;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &current.value))
        throw Failure{GetLastError(), "current-token-open"};
    auto original_user = token_information(current.value, TokenUser);
    auto original_logon = token_information(current.value, TokenLogonSid);
    auto original_statistics = token_information(current.value, TokenStatistics);
    auto original_groups = reinterpret_cast<const TOKEN_GROUPS*>(original_logon.data());
    require(original_groups->GroupCount == 1, "current-logon-sid-count");

    const auto application = full_path(program);
    std::wstring line = L"\"" + application + L"\" identity-idle";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    // LOGON_NETCREDENTIALS_ONLY creates a new LSA session without account
    // provisioning or validating these deliberately fictitious credentials.
    if (!CreateProcessWithLogonW(L"RuleProxyLabSynthetic", L".", L"RuleProxyLab-NotAnAccount-42!",
                                LOGON_NETCREDENTIALS_ONLY, application.c_str(), line.data(),
                                CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process))
        throw Failure{GetLastError(), "netonly-suspended-process-create"};
    NativeHandle child, thread, child_token;
    child.value = process.hProcess;
    thread.value = process.hThread;
    try {
        if (!OpenProcessToken(child.value, TOKEN_QUERY, &child_token.value))
            throw Failure{GetLastError(), "child-token-open"};
        auto user = token_information(child_token.value, TokenUser);
        auto logon = token_information(child_token.value, TokenLogonSid);
        auto statistics = token_information(child_token.value, TokenStatistics);
        const auto groups = reinterpret_cast<const TOKEN_GROUPS*>(logon.data());
        require(groups->GroupCount == 1, "child-logon-sid-count");
        bool user_same = !!EqualSid(reinterpret_cast<const TOKEN_USER*>(original_user.data())->User.Sid,
                                   reinterpret_cast<const TOKEN_USER*>(user.data())->User.Sid);
        bool logon_distinct = !EqualSid(original_groups->Groups[0].Sid, groups->Groups[0].Sid);
        const auto old_id = reinterpret_cast<const TOKEN_STATISTICS*>(original_statistics.data())->AuthenticationId;
        const auto new_id = reinterpret_cast<const TOKEN_STATISTICS*>(statistics.data())->AuthenticationId;
        bool authentication_distinct = old_id.LowPart != new_id.LowPart || old_id.HighPart != new_id.HighPart;
        if (!TerminateProcess(child.value, 0)) throw Failure{GetLastError(), "suspended-child-terminate"};
        require(WaitForSingleObject(child.value, 5000) == WAIT_OBJECT_0, "suspended-child-exit-verified");
        std::printf("{\"identity_measured\":true,\"local_user_sid_unchanged\":%s,"
                    "\"logon_sid_distinct\":%s,\"authentication_luid_distinct\":%s,"
                    "\"child_never_resumed\":true,\"child_exited\":true,"
                    "\"process_id\":%lu,\"network_credentials_used\":false}\n",
                    user_same ? "true" : "false", logon_distinct ? "true" : "false",
                    authentication_distinct ? "true" : "false", process.dwProcessId);
        return 0;
    } catch (...) {
        TerminateProcess(child.value, 1);
        WaitForSingleObject(child.value, 5000);
        throw;
    }
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

static DWORD ready(SOCKET sock, bool write) {
    fd_set selected{}, failed{};
    FD_ZERO(&selected); FD_SET(sock, &selected);
    FD_ZERO(&failed); FD_SET(sock, &failed);
    timeval limit{3, 0};
    int result = select(0, write ? nullptr : &selected, write ? &selected : nullptr, &failed, &limit);
    if (result == SOCKET_ERROR) return static_cast<DWORD>(WSAGetLastError());
    if (!result) return WSAETIMEDOUT;
    if (FD_ISSET(sock, &failed)) {
        int error = 0, length = sizeof(error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) == SOCKET_ERROR)
            return static_cast<DWORD>(WSAGetLastError());
        return error ? static_cast<DWORD>(error) : WSAECONNABORTED;
    }
    return 0;
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
    SOCKET sock = WSASocketW(address->ai_family, hints.ai_socktype, hints.ai_protocol, nullptr, 0, WSA_FLAG_OVERLAPPED);
    DWORD error = sock == INVALID_SOCKET ? static_cast<DWORD>(WSAGetLastError()) : 0;
    int sent = 0;
    const char* stage = "socket";
    if (!error) {
        // Explicit nonblocking deadlines apply even if an unavailable callout
        // silently discards UDP. Blocking WSASocket I/O is not a test timeout.
        u_long nonblocking = 1;
        if (ioctlsocket(sock, FIONBIO, &nonblocking) == SOCKET_ERROR) error = static_cast<DWORD>(WSAGetLastError());
        stage = "connect";
        if (!error && connect(sock, address->ai_addr, static_cast<int>(address->ai_addrlen)) == SOCKET_ERROR) {
            error = static_cast<DWORD>(WSAGetLastError());
            if (error == WSAEWOULDBLOCK) error = ready(sock, true);
        }
        if (!error) {
            int connect_error = 0, length = sizeof(connect_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&connect_error), &length) == SOCKET_ERROR)
                error = static_cast<DWORD>(WSAGetLastError());
            else error = static_cast<DWORD>(connect_error);
        }
        stage = error ? stage : "send";
        if (!error) {
            sent = send(sock, "WFP-LAB", 7, 0);
            if (sent != 7) error = sent == SOCKET_ERROR ? static_cast<DWORD>(WSAGetLastError()) : ERROR_INVALID_DATA;
        }
        stage = error ? stage : "receive";
        if (!error) {
            char reply[7]{};
            int total = 0;
            for (int attempt = 0; attempt < 7 && total < 7 && !error; ++attempt) {
                error = ready(sock, false);
                if (error) break;
                int received = recv(sock, reply + total, 7 - total, 0);
                if (received <= 0) error = received == SOCKET_ERROR ? static_cast<DWORD>(WSAGetLastError()) : ERROR_INVALID_DATA;
                else total += received;
                if (udp) break;
            }
            if (!error && (total != 7 || std::memcmp(reply, "WFP-LAB", 7) != 0)) error = ERROR_INVALID_DATA;
        }
    }
    if (sock != INVALID_SOCKET) closesocket(sock);
    FreeAddrInfoW(address);
    WSACleanup();
    std::printf("{\"connected\":%s,\"wsa_error\":%lu,\"stage\":\"%s\",\"sent_bytes\":%d,\"process_id\":%lu}\n",
                error ? "false" : "true", error, stage, sent, GetCurrentProcessId());
    return error ? 2 : 0;
}

static int spawn_probe(wchar_t** argv) {
    lab_scope(argv[2]);
    require(std::wcslen(argv[3]) < 64 && std::wcslen(argv[4]) <= 5,
            "bounded-numeric-child-destination");
    require(std::wcsspn(argv[3], L"0123456789abcdefABCDEF:.") == std::wcslen(argv[3]) &&
            std::wcsspn(argv[4], L"0123456789") == std::wcslen(argv[4]) &&
            (std::wcscmp(argv[5], L"tcp") == 0 || std::wcscmp(argv[5], L"udp") == 0),
            "numeric-child-destination-and-protocol");
    auto child = full_path(argv[2]);
    std::wstring line = L"\"" + child + L"\" probe " + argv[3] + L" " + argv[4] + L" " + argv[5];
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(child.c_str(), line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &startup, &process)) throw Failure{GetLastError(), "child-create"};
    CloseHandle(process.hThread);
    DWORD wait = WaitForSingleObject(process.hProcess, 10000), code = 1;
    if (wait != WAIT_OBJECT_0) {
        TerminateProcess(process.hProcess, 1);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        throw Failure{ERROR_TIMEOUT, "child-probe-timeout"};
    }
    BOOL ok = GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess);
    require(!!ok, "child-exit-code");
    return static_cast<int>(code);
}

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wcscmp(argv[1], L"token-identity") == 0) return token_identity(argv[2]);
        if (argc == 2 && std::wcscmp(argv[1], L"identity-idle") == 0) { Sleep(INFINITE); return 0; }
        if (argc == 5 && std::wcscmp(argv[1], L"probe") == 0) return probe(argv[2], argv[3], argv[4]);
        if (argc == 6 && std::wcscmp(argv[1], L"spawn") == 0) return spawn_probe(argv);
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
