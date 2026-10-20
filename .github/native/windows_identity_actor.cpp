// Windows SDK only. Build with cl /W4 /WX /std:c++17 /EHsc /MT.
// No token, job, firewall, ACL, or other host security state is changed.
//
// Usage:
//   windows_identity_actor.exe actor <32-hex-nonce> <absolute-report-path>
//   windows_identity_actor.exe actor-http <nonce> <report> <proxy-port>
//   windows_identity_actor.exe actor-pipe <nonce> <report> <read-handle> <write-handle>
//
// Exit codes: 0 = complete successful report, 2 = invalid arguments,
// 3 = report I/O failure, 4 = native observation failure,
// 5 = transport failure, 6 = internal failure.
// A report is valid only with the expected nonce, strict schema, and exit 0.
// HTTP is opt-in and forces a named proxy at 127.0.0.1:1025..65535.
// Anonymous-pipe I/O is synchronous: the controller MUST impose an outer
// timeout and terminate the containing job. There is no native pipe timeout.

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
#define _WIN32_WINNT 0x0602
#endif

#include <windows.h>
#include <sddl.h>
#include <winhttp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "winhttp.lib")

namespace {

constexpr std::size_t kNonceLength = 32;
constexpr std::size_t kMaxReportPath = 4096;
constexpr DWORD kMaxTokenBytes = 65536;
constexpr std::size_t kMaxReportBytes = 8192;
constexpr std::size_t kMaxSidText = 256;
constexpr DWORD kMaxCapabilities = 16;

class UniqueHandle final {
public:
    explicit UniqueHandle(HANDLE handle = nullptr) noexcept : handle_(handle) {}
    ~UniqueHandle() noexcept {
        if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE) {
            CloseHandle(handle_);
        }
    }
    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;
    HANDLE get() const noexcept { return handle_; }

private:
    HANDLE handle_;
};

class LocalSidText final {
public:
    LocalSidText() noexcept = default;
    ~LocalSidText() noexcept {
        if (text_ != nullptr) {
            LocalFree(text_);
        }
    }
    LocalSidText(const LocalSidText&) = delete;
    LocalSidText& operator=(const LocalSidText&) = delete;
    LPWSTR* address() noexcept { return &text_; }
    const wchar_t* get() const noexcept { return text_; }

private:
    LPWSTR text_ = nullptr;
};

class UniqueInternetHandle final {
public:
    explicit UniqueInternetHandle(HINTERNET handle = nullptr) noexcept
        : handle_(handle) {}
    ~UniqueInternetHandle() noexcept {
        if (handle_ != nullptr) {
            WinHttpCloseHandle(handle_);
        }
    }
    UniqueInternetHandle(const UniqueInternetHandle&) = delete;
    UniqueInternetHandle& operator=(const UniqueInternetHandle&) = delete;
    HINTERNET get() const noexcept { return handle_; }

private:
    HINTERNET handle_;
};

struct QueryError {
    const char* query;
    DWORD win32Error;
};

struct Capability {
    std::string sid;
    DWORD attributes;
};

struct Observations {
    DWORD pid = 0;
    std::optional<std::string> tokenUserSid;
    std::optional<bool> tokenIsAppContainer;
    std::optional<std::string> tokenAppContainerSid;
    std::optional<bool> tokenElevated;
    std::optional<bool> isProcessInJob;
    std::vector<Capability> tokenCapabilities;
    std::vector<QueryError> errors;
};

struct HttpResult {
    bool attempted = false;
    bool succeeded = false;
    unsigned int proxyPort = 0;
    std::optional<DWORD> statusCode;
    DWORD bytesRead = 0;
    bool nonceMatched = false;
    DWORD win32Error = ERROR_SUCCESS;
    const char* failure = nullptr;
};

struct PipeResult {
    bool attempted = false;
    bool succeeded = false;
    bool inheritanceCleared = false;
    DWORD bytesRead = 0;
    DWORD bytesWritten = 0;
    bool nonceMatched = false;
    DWORD win32Error = ERROR_SUCCESS;
    const char* failure = nullptr;
};

bool IsHex(wchar_t value) noexcept {
    return (value >= L'0' && value <= L'9') ||
           (value >= L'a' && value <= L'f') ||
           (value >= L'A' && value <= L'F');
}

bool ReadNonce(const wchar_t* argument, std::string& result) {
    result.clear();
    for (std::size_t index = 0; index < kNonceLength; ++index) {
        if (!IsHex(argument[index])) {
            return false;
        }
        result.push_back(static_cast<char>(argument[index]));
    }
    return argument[kNonceLength] == L'\0';
}

bool ReadPort(const wchar_t* argument, unsigned int& result) noexcept {
    unsigned int port = 0;
    std::size_t digits = 0;
    while (argument[digits] != L'\0') {
        const wchar_t value = argument[digits];
        if (digits >= 5 || value < L'0' || value > L'9') {
            return false;
        }
        port = port * 10 + static_cast<unsigned int>(value - L'0');
        ++digits;
    }
    if (port < 1025 || port > 65535) {
        return false;
    }
    result = port;
    return true;
}

bool ReadPipeHandle(const wchar_t* argument, HANDLE& result) noexcept {
    std::uintptr_t value = 0;
    std::size_t digits = 0;
    constexpr std::uintptr_t maximum =
        std::numeric_limits<std::uintptr_t>::max();
    while (argument[digits] != L'\0') {
        const wchar_t character = argument[digits];
        if (digits >= 20 || character < L'0' || character > L'9') {
            return false;
        }
        const auto digit = static_cast<std::uintptr_t>(character - L'0');
        if (value > (maximum - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
        ++digits;
    }
    if (digits == 0 || value == 0 || value == maximum) {
        return false;
    }
    result = reinterpret_cast<HANDLE>(value);
    return true;
}

// Only an absolute drive-letter file path is accepted. Reject UNC, device
// paths, alternate streams, traversal, and Win32 normalization ambiguities.
// The extended prefix prevents reserved DOS basenames from opening devices.
bool ReadReportPath(const wchar_t* argument, std::wstring& result) {
    std::size_t length = 0;
    while (length <= kMaxReportPath && argument[length] != L'\0') {
        ++length;
    }
    if (length < 4 || length > kMaxReportPath) {
        return false;
    }
    if (!((argument[0] >= L'A' && argument[0] <= L'Z') ||
          (argument[0] >= L'a' && argument[0] <= L'z')) ||
        argument[1] != L':' || argument[2] != L'\\') {
        return false;
    }
    std::size_t componentStart = 3;
    for (std::size_t index = 3; index <= length; ++index) {
        const wchar_t value = argument[index];
        if (value == L'\\' || value == L'\0') {
            if (index == componentStart ||
                argument[index - 1] == L'.' || argument[index - 1] == L' ') {
                return false;
            }
            componentStart = index + 1;
        } else if (value < L' ' || value == L':' || value == L'/' ||
                   value == L'"' || value == L'<' || value == L'>' ||
                   value == L'|' || value == L'?' || value == L'*') {
            return false;
        }
    }
    result.assign(L"\\\\?\\");
    result.append(argument, length);
    return true;
}

void AddError(Observations& observations, const char* query, DWORD error) {
    observations.errors.push_back(
        QueryError{query, error == ERROR_SUCCESS ? ERROR_INVALID_DATA : error});
}

bool QueryFixed(HANDLE token, TOKEN_INFORMATION_CLASS infoClass, void* output,
                DWORD outputBytes, const char* name, Observations& observations) {
    DWORD returnedBytes = 0;
    if (!GetTokenInformation(token, infoClass, output, outputBytes,
                             &returnedBytes)) {
        AddError(observations, name, GetLastError());
        return false;
    }
    if (returnedBytes != outputBytes) {
        AddError(observations, name, ERROR_INVALID_DATA);
        return false;
    }
    return true;
}

bool QueryVariable(HANDLE token, TOKEN_INFORMATION_CLASS infoClass,
                   std::size_t minimumBytes, const char* name,
                   std::vector<BYTE>& buffer, Observations& observations) {
    DWORD neededBytes = 0;
    const BOOL initialResult =
        GetTokenInformation(token, infoClass, nullptr, 0, &neededBytes);
    const DWORD initialError = initialResult ? ERROR_SUCCESS : GetLastError();
    if (initialResult || initialError != ERROR_INSUFFICIENT_BUFFER ||
        neededBytes < minimumBytes || neededBytes > kMaxTokenBytes) {
        AddError(observations, name,
                 initialError == ERROR_INSUFFICIENT_BUFFER ?
                     ERROR_INVALID_DATA : initialError);
        return false;
    }
    buffer.resize(neededBytes);
    DWORD returnedBytes = 0;
    if (!GetTokenInformation(token, infoClass, buffer.data(), neededBytes,
                             &returnedBytes)) {
        AddError(observations, name, GetLastError());
        return false;
    }
    if (returnedBytes < minimumBytes || returnedBytes > neededBytes) {
        AddError(observations, name, ERROR_INVALID_DATA);
        return false;
    }
    buffer.resize(returnedBytes);
    return true;
}

bool SidToString(PSID sid, const std::vector<BYTE>& buffer, const char* name,
                 std::optional<std::string>& output,
                 Observations& observations) {
    // Validate containment before calling APIs that dereference the SID.
    const std::uintptr_t begin =
        reinterpret_cast<std::uintptr_t>(buffer.data());
    const std::uintptr_t address = reinterpret_cast<std::uintptr_t>(sid);
    constexpr std::size_t kSidHeaderBytes = 8;
    if (sid == nullptr || address < begin ||
        address - begin > buffer.size() ||
        buffer.size() - (address - begin) < kSidHeaderBytes) {
        AddError(observations, name, ERROR_INVALID_SID);
        return false;
    }
    const BYTE* bytes = static_cast<const BYTE*>(sid);
    const std::size_t sidBytes =
        kSidHeaderBytes + static_cast<std::size_t>(bytes[1]) * sizeof(DWORD);
    if (sidBytes > buffer.size() - (address - begin) || !IsValidSid(sid)) {
        AddError(observations, name, ERROR_INVALID_SID);
        return false;
    }
    LocalSidText text;
    if (!ConvertSidToStringSidW(sid, text.address())) {
        AddError(observations, name, GetLastError());
        return false;
    }
    std::string converted;
    for (std::size_t index = 0; index < kMaxSidText; ++index) {
        const wchar_t value = text.get()[index];
        if (value == L'\0') {
            if (converted.size() < 5 || converted[0] != 'S' ||
                converted[1] != '-') {
                break;
            }
            output = std::move(converted);
            return true;
        }
        if (value != L'S' && value != L'-' &&
            !(value >= L'0' && value <= L'9')) {
            break;
        }
        converted.push_back(static_cast<char>(value));
    }
    AddError(observations, name, ERROR_INVALID_SID);
    return false;
}

void ObserveCapabilities(HANDLE token, Observations& observations) {
    std::vector<BYTE> buffer;
    if (!QueryVariable(token, TokenCapabilities, sizeof(DWORD),
                       "TokenCapabilities", buffer, observations)) {
        return;
    }
    DWORD groupCount = 0;
    std::memcpy(&groupCount, buffer.data(), sizeof(groupCount));
    if (groupCount > kMaxCapabilities) {
        // Never silently truncate an identity-relevant observation.
        AddError(observations, "TokenCapabilities", ERROR_BUFFER_OVERFLOW);
        return;
    }
    if (groupCount == 0) {
        return;
    }
    const std::size_t groupsBytes = offsetof(TOKEN_GROUPS, Groups) +
        static_cast<std::size_t>(groupCount) * sizeof(SID_AND_ATTRIBUTES);
    if (buffer.size() < groupsBytes) {
        AddError(observations, "TokenCapabilities", ERROR_INVALID_DATA);
        return;
    }
    const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
    std::vector<Capability> capabilities;
    capabilities.reserve(groupCount);
    for (DWORD index = 0; index < groupCount; ++index) {
        std::optional<std::string> sid;
        if (!SidToString(groups->Groups[index].Sid, buffer, "TokenCapabilities",
                         sid, observations)) {
            return;
        }
        capabilities.push_back(
            Capability{sid.value(), groups->Groups[index].Attributes});
    }
    observations.tokenCapabilities = std::move(capabilities);
}

Observations ObserveNativeIdentity() {
    Observations observations;
    observations.errors.reserve(8);
    observations.pid = GetCurrentProcessId();
    if (observations.pid == 0) {
        AddError(observations, "GetCurrentProcessId", ERROR_INVALID_DATA);
    }

    BOOL inJob = FALSE;
    if (IsProcessInJob(GetCurrentProcess(), nullptr, &inJob)) {
        observations.isProcessInJob = inJob != FALSE;
    } else {
        AddError(observations, "IsProcessInJob", GetLastError());
    }

    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) {
        AddError(observations, "OpenProcessToken", GetLastError());
        return observations;
    }
    UniqueHandle token(rawToken);
    std::vector<BYTE> buffer;
    if (QueryVariable(token.get(), TokenUser, sizeof(TOKEN_USER), "TokenUser",
                      buffer, observations)) {
        const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        SidToString(user->User.Sid, buffer, "TokenUser",
                    observations.tokenUserSid, observations);
    }

    DWORD isAppContainer = 0;
    if (QueryFixed(token.get(), TokenIsAppContainer, &isAppContainer,
                   static_cast<DWORD>(sizeof(isAppContainer)),
                   "TokenIsAppContainer", observations)) {
        observations.tokenIsAppContainer = isAppContainer != 0;
    }

    if (QueryVariable(token.get(), TokenAppContainerSid,
                      sizeof(TOKEN_APPCONTAINER_INFORMATION),
                      "TokenAppContainerSid", buffer, observations)) {
        const auto* appContainer =
            reinterpret_cast<const TOKEN_APPCONTAINER_INFORMATION*>(
                buffer.data());
        if (appContainer->TokenAppContainer != nullptr) {
            SidToString(appContainer->TokenAppContainer, buffer,
                        "TokenAppContainerSid",
                        observations.tokenAppContainerSid, observations);
        }
    }

    TOKEN_ELEVATION elevation{};
    if (QueryFixed(token.get(), TokenElevation, &elevation,
                   static_cast<DWORD>(sizeof(elevation)),
                   "TokenElevation", observations)) {
        observations.tokenElevated = elevation.TokenIsElevated != 0;
    }
    ObserveCapabilities(token.get(), observations);
    return observations;
}

HttpResult ProbeHttp(const std::string& nonce, unsigned int proxyPort,
                     bool nativeQueriesSucceeded) {
    HttpResult result;
    result.proxyPort = proxyPort;
    if (!nativeQueriesSucceeded) {
        result.failure = "native-observation-failed";
        return result;
    }
    result.attempted = true;
    const std::wstring proxy = L"127.0.0.1:" + std::to_wstring(proxyPort);
    UniqueInternetHandle session(
        WinHttpOpen(L"RuleProxyIdentityProof/1.0",
                    WINHTTP_ACCESS_TYPE_NAMED_PROXY, proxy.c_str(),
                    WINHTTP_NO_PROXY_BYPASS, 0));
    if (session.get() == nullptr) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpOpen";
        return result;
    }
    if (!WinHttpSetTimeouts(session.get(), 2000, 2000, 2000, 2000)) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpSetTimeouts";
        return result;
    }
    UniqueInternetHandle connection(
        WinHttpConnect(session.get(), L"ruleproxy-identity-proof.invalid",
                       INTERNET_DEFAULT_HTTP_PORT, 0));
    if (connection.get() == nullptr) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpConnect";
        return result;
    }
    std::wstring resource = L"/";
    resource.append(nonce.begin(), nonce.end());
    UniqueInternetHandle request(
        WinHttpOpenRequest(connection.get(), L"GET", resource.c_str(), nullptr,
                           WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0));
    if (request.get() == nullptr) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpOpenRequest";
        return result;
    }

    // Reassert the same named proxy on the request. There is no PAC,
    // autodetection, system-default proxy, bypass list, or direct retry path.
    WINHTTP_PROXY_INFO proxyInfo{};
    proxyInfo.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    proxyInfo.lpszProxy = const_cast<wchar_t*>(proxy.c_str());
    proxyInfo.lpszProxyBypass = WINHTTP_NO_PROXY_BYPASS;
    DWORD disabledFeatures = WINHTTP_DISABLE_COOKIES |
        WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION |
        WINHTTP_DISABLE_KEEP_ALIVE;
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    DWORD autologonPolicy = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    DWORD maxHeaderBytes = 16384;
    if (!WinHttpSetOption(request.get(), WINHTTP_OPTION_PROXY, &proxyInfo,
                          static_cast<DWORD>(sizeof(proxyInfo))) ||
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_DISABLE_FEATURE,
                          &disabledFeatures,
                          static_cast<DWORD>(sizeof(disabledFeatures))) ||
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_REDIRECT_POLICY,
                          &redirectPolicy,
                          static_cast<DWORD>(sizeof(redirectPolicy))) ||
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_AUTOLOGON_POLICY,
                          &autologonPolicy,
                          static_cast<DWORD>(sizeof(autologonPolicy))) ||
        !WinHttpSetOption(request.get(), WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
                          &maxHeaderBytes,
                          static_cast<DWORD>(sizeof(maxHeaderBytes)))) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpSetOption";
        return result;
    }
    if (!WinHttpSendRequest(request.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpSendRequest";
        return result;
    }
    if (!WinHttpReceiveResponse(request.get(), nullptr)) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpReceiveResponse";
        return result;
    }
    DWORD statusCode = 0;
    DWORD statusBytes = static_cast<DWORD>(sizeof(statusCode));
    if (!WinHttpQueryHeaders(request.get(),
                             WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             WINHTTP_HEADER_NAME_BY_INDEX, &statusCode,
                             &statusBytes, WINHTTP_NO_HEADER_INDEX)) {
        result.win32Error = GetLastError();
        result.failure = "WinHttpQueryHeaders";
        return result;
    }
    result.statusCode = statusCode;
    if (statusBytes != sizeof(statusCode) || statusCode != 200) {
        result.failure = "unexpected-http-status";
        return result;
    }
    std::array<char, kNonceLength + 1> body{};
    std::size_t totalBytes = 0;
    while (totalBytes < body.size()) {
        DWORD receivedBytes = 0;
        const DWORD requestedBytes =
            static_cast<DWORD>(body.size() - totalBytes);
        if (!WinHttpReadData(request.get(), body.data() + totalBytes,
                             requestedBytes, &receivedBytes)) {
            result.win32Error = GetLastError();
            result.failure = "WinHttpReadData";
            return result;
        }
        if (receivedBytes > requestedBytes) {
            result.failure = "invalid-response-length";
            return result;
        }
        if (receivedBytes == 0) {
            break;
        }
        totalBytes += receivedBytes;
        result.bytesRead = static_cast<DWORD>(totalBytes);
    }
    result.nonceMatched = totalBytes == kNonceLength &&
        std::memcmp(body.data(), nonce.data(), kNonceLength) == 0;
    if (!result.nonceMatched) {
        result.failure = "response-nonce-mismatch";
        return result;
    }
    result.succeeded = true;
    return result;
}

PipeResult ProbePipes(const std::string& nonce, HANDLE readHandle,
                      HANDLE writeHandle, bool nativeQueriesSucceeded) {
    PipeResult result;
    // Adopt handles only after verifying their types. All adopted handles
    // close on every return, before the report is written.
    SetLastError(ERROR_SUCCESS);
    if (GetFileType(readHandle) != FILE_TYPE_PIPE) {
        result.win32Error = GetLastError();
        result.failure = "read-handle-is-not-pipe";
        return result;
    }
    UniqueHandle reader(readHandle);
    SetLastError(ERROR_SUCCESS);
    if (GetFileType(writeHandle) != FILE_TYPE_PIPE) {
        result.win32Error = GetLastError();
        result.failure = "write-handle-is-not-pipe";
        return result;
    }
    UniqueHandle writer(writeHandle);
    if (!SetHandleInformation(reader.get(), HANDLE_FLAG_INHERIT, 0) ||
        !SetHandleInformation(writer.get(), HANDLE_FLAG_INHERIT, 0)) {
        result.win32Error = GetLastError();
        result.failure = "SetHandleInformation";
        return result;
    }
    result.inheritanceCleared = true;
    if (!nativeQueriesSucceeded) {
        result.failure = "native-observation-failed";
        return result;
    }
    result.attempted = true;
    std::array<char, kNonceLength> body{};
    while (result.bytesRead < body.size()) {
        DWORD receivedBytes = 0;
        const DWORD requestedBytes =
            static_cast<DWORD>(body.size() - result.bytesRead);
        if (!ReadFile(reader.get(), body.data() + result.bytesRead,
                       requestedBytes, &receivedBytes, nullptr)) {
            result.win32Error = GetLastError();
            result.failure = "ReadFile-pipe";
            return result;
        }
        if (receivedBytes == 0 || receivedBytes > requestedBytes) {
            result.failure = "incomplete-pipe-nonce";
            return result;
        }
        result.bytesRead += receivedBytes;
    }
    result.nonceMatched =
        std::memcmp(body.data(), nonce.data(), kNonceLength) == 0;
    if (!result.nonceMatched) {
        result.failure = "pipe-nonce-mismatch";
        return result;
    }
    while (result.bytesWritten < body.size()) {
        DWORD writtenBytes = 0;
        const DWORD requestedBytes =
            static_cast<DWORD>(body.size() - result.bytesWritten);
        if (!WriteFile(writer.get(), body.data() + result.bytesWritten,
                        requestedBytes, &writtenBytes, nullptr)) {
            result.win32Error = GetLastError();
            result.failure = "WriteFile-pipe";
            return result;
        }
        if (writtenBytes == 0 || writtenBytes > requestedBytes) {
            result.failure = "incomplete-pipe-echo";
            return result;
        }
        result.bytesWritten += writtenBytes;
    }
    // Do not FlushFileBuffers on an anonymous pipe: it can wait for the peer
    // to consume data. Closing this write end gives the controller EOF.
    result.succeeded = true;
    return result;
}

std::string JsonBoolean(const std::optional<bool>& value) {
    if (!value.has_value()) {
        return "null";
    }
    return value.value() ? "true" : "false";
}

std::string JsonSid(const std::optional<std::string>& value) {
    // SID strings are accepted only from the restricted alphabet above.
    return value.has_value() ? "\"" + value.value() + "\"" : "null";
}

std::string MakeReport(const char* mode, const std::string& nonce,
                       const Observations& observations,
                       const std::optional<HttpResult>& http,
                       const std::optional<PipeResult>& pipe) {
    std::string report;
    report.reserve(2048);
    report += "{\"schemaVersion\":1,\"mode\":\"";
    report += mode;
    report += "\",\"nonce\":\"";
    report += nonce;
    report += "\",\"pid\":" + std::to_string(observations.pid);
    report += ",\"tokenUserSid\":" + JsonSid(observations.tokenUserSid);
    report += ",\"tokenIsAppContainer\":" +
              JsonBoolean(observations.tokenIsAppContainer);
    report += ",\"tokenAppContainerSid\":" +
              JsonSid(observations.tokenAppContainerSid);
    report += ",\"tokenElevated\":" + JsonBoolean(observations.tokenElevated);
    report += ",\"isProcessInJob\":" +
              JsonBoolean(observations.isProcessInJob);
    report += ",\"tokenCapabilities\":[";
    bool firstCapability = true;
    for (const Capability& capability : observations.tokenCapabilities) {
        if (!firstCapability) {
            report += ',';
        }
        firstCapability = false;
        report += "{\"sid\":\"" + capability.sid + "\",\"attributes\":" +
                  std::to_string(capability.attributes) + "}";
    }
    report += ']';
    report += ",\"queriesSucceeded\":";
    report += observations.errors.empty() ? "true" : "false";
    report += ",\"errors\":[";
    bool first = true;
    for (const QueryError& error : observations.errors) {
        if (!first) {
            report += ',';
        }
        first = false;
        report += "{\"query\":\"";
        report += error.query;
        report += "\",\"win32Error\":" + std::to_string(error.win32Error) + "}";
    }
    report += ']';
    if (http.has_value()) {
        const HttpResult& value = http.value();
        report += ",\"httpSucceeded\":";
        report += value.succeeded ? "true" : "false";
        report += ",\"http\":{\"attempted\":";
        report += value.attempted ? "true" : "false";
        report += ",\"proxyPort\":" + std::to_string(value.proxyPort);
        report += ",\"statusCode\":";
        report += value.statusCode.has_value() ?
            std::to_string(value.statusCode.value()) : "null";
        report += ",\"bytesRead\":" + std::to_string(value.bytesRead);
        report += ",\"nonceMatched\":";
        report += value.nonceMatched ? "true" : "false";
        report += ",\"win32Error\":" + std::to_string(value.win32Error);
        report += ",\"failure\":";
        report += value.failure == nullptr ?
            "null" : "\"" + std::string(value.failure) + "\"";
        report += '}';
    }
    if (pipe.has_value()) {
        const PipeResult& value = pipe.value();
        report += ",\"pipeSucceeded\":";
        report += value.succeeded ? "true" : "false";
        report += ",\"pipe\":{\"attempted\":";
        report += value.attempted ? "true" : "false";
        report += ",\"inheritanceCleared\":";
        report += value.inheritanceCleared ? "true" : "false";
        report += ",\"bytesRead\":" + std::to_string(value.bytesRead);
        report += ",\"bytesWritten\":" + std::to_string(value.bytesWritten);
        report += ",\"nonceMatched\":";
        report += value.nonceMatched ? "true" : "false";
        report += ",\"requiresControllerTimeout\":true,\"win32Error\":" +
                  std::to_string(value.win32Error);
        report += ",\"failure\":";
        report += value.failure == nullptr ?
            "null" : "\"" + std::string(value.failure) + "\"";
        report += '}';
    }
    report += "}\n";
    return report;
}

bool WriteReport(HANDLE file, const std::string& report) noexcept {
    if (report.empty() || report.size() > kMaxReportBytes) {
        return false;
    }
    std::size_t offset = 0;
    while (offset < report.size()) {
        DWORD writtenBytes = 0;
        const DWORD requestedBytes =
            static_cast<DWORD>(report.size() - offset);
        if (!WriteFile(file, report.data() + offset, requestedBytes,
                       &writtenBytes, nullptr) ||
            writtenBytes == 0 || writtenBytes > requestedBytes) {
            return false;
        }
        offset += writtenBytes;
    }
    return FlushFileBuffers(file) != FALSE;
}

int Run(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        return 2;
    }
    const std::wstring role(argv[1]);
    const char* mode = nullptr;
    unsigned int proxyPort = 0;
    HANDLE readHandle = nullptr;
    HANDLE writeHandle = nullptr;
    if (role == L"actor" && argc == 4) {
        mode = "actor";
    } else if (role == L"actor-http" && argc == 5 &&
               ReadPort(argv[4], proxyPort)) {
        mode = "actor-http";
    } else if (role == L"actor-pipe" && argc == 6 &&
               ReadPipeHandle(argv[4], readHandle) &&
               ReadPipeHandle(argv[5], writeHandle) &&
               readHandle != writeHandle) {
        mode = "actor-pipe";
    } else {
        return 2;
    }
    std::string nonce;
    std::wstring reportPath;
    if (!ReadNonce(argv[2], nonce) || !ReadReportPath(argv[3], reportPath)) {
        return 2;
    }
    // Never replace or append to an existing report; do not create parents.
    UniqueHandle file(CreateFileW(reportPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                  CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (file.get() == INVALID_HANDLE_VALUE) {
        return 3;
    }
    const Observations observations = ObserveNativeIdentity();
    std::optional<HttpResult> http;
    std::optional<PipeResult> pipe;
    if (role == L"actor-http") {
        http = ProbeHttp(nonce, proxyPort, observations.errors.empty());
    } else if (role == L"actor-pipe") {
        pipe = ProbePipes(nonce, readHandle, writeHandle,
                          observations.errors.empty());
    }
    const std::string report = MakeReport(mode, nonce, observations, http, pipe);
    if (!WriteReport(file.get(), report)) {
        return 3;
    }
    if (!observations.errors.empty()) {
        return 4;
    }
    if ((http.has_value() && !http.value().succeeded) ||
        (pipe.has_value() && !pipe.value().succeeded)) {
        return 5;
    }
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    try {
        return Run(argc, argv);
    } catch (...) {
        // No unbounded or non-JSON diagnostic output, and never a false pass.
        return 6;
    }
}
