// Opt-in, experimental N0a raw IPv4 TCP actor. No DNS, proxy, rules or token changes.
// The original identity actor is a separately pinned, unchanged dependency.
// Private report contains identity/tuple observations: NEVER upload it verbatim.
// CLI: n0a-tcp nonce report guest|runner port ordinary|contained single|sample
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include <algorithm>
#include <stdexcept>
#pragma comment(lib, "ws2_32.lib")

namespace n0a {
constexpr std::size_t MaxReport = 32768;
constexpr ULONGLONG ContainedBudget = 3000;
constexpr ULONGLONG SampleBudget = 10000;
constexpr std::size_t MaxSamples = 40;

struct Socket final {
    SOCKET value = INVALID_SOCKET;
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket() = default;
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    bool close() {
        if (value == INVALID_SOCKET) return false;
        const SOCKET owned = value;
        value = INVALID_SOCKET;
        return closesocket(owned) == 0;
    }
};
struct Wsa final {
    bool active = false;
    ~Wsa() { if (active) WSACleanup(); }
};
struct SidArrays final {
    PSID* groups = nullptr;
    DWORD groupCount = 0;
    PSID* capabilities = nullptr;
    DWORD capabilityCount = 0;
    ~SidArrays() {
        if (groups) { for (DWORD i=0; i<groupCount; ++i) LocalFree(groups[i]); LocalFree(groups); }
        if (capabilities) { for (DWORD i=0; i<capabilityCount; ++i) LocalFree(capabilities[i]); LocalFree(capabilities); }
    }
};
LONGLONG Tick() {
    LARGE_INTEGER value{};
    if (!QueryPerformanceCounter(&value) || value.QuadPart <= 0) throw std::runtime_error("qpc");
    return value.QuadPart;
}
LONGLONG Frequency() {
    LARGE_INTEGER value{};
    if (!QueryPerformanceFrequency(&value) || value.QuadPart <= 0) throw std::runtime_error("qpc");
    return value.QuadPart;
}
bool Port(const wchar_t* text, unsigned int& port) {
    const std::wstring value(text);
    if (value.empty() || value.size()>5 || value[0]==L'0') return false;
    unsigned int result=0;
    for (wchar_t digit:value) { if (digit<L'0'||digit>L'9') return false; result=result*10+static_cast<unsigned int>(digit-L'0'); }
    if (result<1025 || result>65535) return false;
    port=result; return true;
}
bool PackageSid(const std::optional<std::string>& sid) {
    if (!sid || sid->compare(0,8,"S-1-15-2")!=0) return false;
    std::size_t position=8;
    for (int part=0;part<7;++part) {
        if (position>=sid->size() || (*sid)[position++]!='-') return false;
        const std::size_t start=position;
        while (position<sid->size() && (*sid)[position]>='0' && (*sid)[position]<='9') ++position;
        if (position==start || position-start>10) return false;
    }
    return position==sid->size();
}
bool Agentic(const Capability& capability) {
    if (capability.attributes != SE_GROUP_ENABLED) return false;
    const HMODULE module=GetModuleHandleW(L"kernelbase.dll");
    if (!module) return false;
    using Derive=BOOL(WINAPI*)(LPCWSTR,PSID**,DWORD*,PSID**,DWORD*);
    const FARPROC address=GetProcAddress(module,"DeriveCapabilitySidsFromName");
    Derive derive=nullptr; static_assert(sizeof(derive)==sizeof(address),"function pointer size");
    std::memcpy(&derive,&address,sizeof(derive));
    if (!derive) return false;
    SidArrays ids;
    if (!derive(L"AgenticAppContainer",&ids.groups,&ids.groupCount,&ids.capabilities,&ids.capabilityCount)
        || ids.capabilityCount!=1 || !ids.capabilities || !IsValidSid(ids.capabilities[0])) return false;
    PSID actual=nullptr;
    if (!ConvertStringSidToSidA(capability.sid.c_str(),&actual)) return false;
    const bool equal=IsValidSid(actual) && EqualSid(actual,ids.capabilities[0]);
    LocalFree(actual);
    return equal;
}
bool Profile(const Observations& identity, bool contained) {
    if (!identity.errors.empty() || identity.pid==0 || identity.tokenElevated!=false
        || !identity.tokenIsAppContainer.has_value() || !identity.isProcessInJob.has_value()) return false;
    if (!contained) return identity.tokenIsAppContainer==false && !identity.tokenAppContainerSid
        && identity.tokenCapabilities.empty();
    return identity.tokenIsAppContainer==true && identity.isProcessInJob==true
        && PackageSid(identity.tokenAppContainerSid) && identity.tokenCapabilities.size()==1
        && Agentic(identity.tokenCapabilities.front());
}
struct Attempt {
    unsigned int index=0;
    bool attempted=false,bindSucceeded=false,connectSucceeded=false,nonceMatched=false,closed=false;
    unsigned int localPort=0;
    unsigned long localIpv4=0;
    LONGLONG connectStartQpc=0,connectEndQpc=0,exchangeEndQpc=0;
    int win32Error=0;
    const char* failure="none";
};
void Error(Attempt& result, const char* phase, int error) {
    result.failure=phase; result.win32Error=error;
}
bool Wait(SOCKET socket, bool writing, bool connecting, ULONGLONG deadline, Attempt& result, const char* phase) {
    const ULONGLONG now=GetTickCount64();
    if (now>=deadline) { Error(result,phase,WSAETIMEDOUT); return false; }
    const ULONGLONG remaining=deadline-now;
    timeval timeout{};
    timeout.tv_sec=static_cast<long>(remaining/1000);
    timeout.tv_usec=static_cast<long>((remaining%1000)*1000);
    fd_set ready{},errors{}; FD_ZERO(&ready); FD_ZERO(&errors); FD_SET(socket,&ready); FD_SET(socket,&errors);
    const int status=select(0,writing?nullptr:&ready,writing?&ready:nullptr,connecting?&errors:nullptr,&timeout);
    if (status==SOCKET_ERROR) { Error(result,phase,WSAGetLastError()); return false; }
    if (status==0) { Error(result,phase,WSAETIMEDOUT); return false; }
    return true;
}
bool Echo(SOCKET socket, const std::string& frame, ULONGLONG deadline, Attempt& result) {
    std::size_t sent=0;
    while (sent<frame.size()) {
        if (!Wait(socket,true,false,deadline,result,"send")) return false;
        const int count=send(socket,frame.data()+sent,static_cast<int>(frame.size()-sent),0);
        if (count==SOCKET_ERROR) { const int error=WSAGetLastError(); if (error==WSAEWOULDBLOCK) continue; Error(result,"send",error); return false; }
        if (count<=0) { Error(result,"send",WSAECONNRESET); return false; }
        sent+=static_cast<std::size_t>(count);
    }
    std::array<char,96> buffer{};
    std::size_t received=0;
    while (received<frame.size()) {
        if (!Wait(socket,false,false,deadline,result,"recv")) return false;
        const int count=recv(socket,buffer.data()+received,static_cast<int>(frame.size()-received),0);
        if (count==SOCKET_ERROR) { const int error=WSAGetLastError(); if (error==WSAEWOULDBLOCK) continue; Error(result,"recv",error); return false; }
        if (count<=0) { Error(result,"recv",WSAECONNRESET); return false; }
        received+=static_cast<std::size_t>(count);
    }
    if (std::memcmp(buffer.data(),frame.data(),frame.size())!=0) { Error(result,"echo",WSAEINVAL); return false; }
    result.nonceMatched=true; return true;
}
Attempt Probe(unsigned int index, bool runner, unsigned int port, const std::string& frame, ULONGLONG deadline) {
    Attempt result; result.index=index;
    Socket owned;
    owned.value=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if (owned.value==INVALID_SOCKET) { Error(result,"socket",WSAGetLastError()); result.exchangeEndQpc=Tick(); return result; }
    // Closing is explicit so uncertainty is part of the private report; RAII is the exception backstop.
    do {
        u_long nonblocking=1;
        if (ioctlsocket(owned.value,FIONBIO,&nonblocking)!=0) { Error(result,"nonblocking",WSAGetLastError()); break; }
        sockaddr_in local{}; local.sin_family=AF_INET; local.sin_addr.s_addr=htonl(INADDR_ANY); local.sin_port=0;
        if (bind(owned.value,reinterpret_cast<const sockaddr*>(&local),sizeof(local))!=0) { Error(result,"bind",WSAGetLastError()); break; }
        result.bindSucceeded=true;
        int length=sizeof(local);
        if (getsockname(owned.value,reinterpret_cast<sockaddr*>(&local),&length)!=0 || length!=static_cast<int>(sizeof(local))) { Error(result,"getsockname",WSAGetLastError()); break; }
        result.localPort=ntohs(local.sin_port); result.localIpv4=ntohl(local.sin_addr.s_addr);
        sockaddr_in remote{}; remote.sin_family=AF_INET; remote.sin_port=htons(static_cast<u_short>(port));
        remote.sin_addr.s_addr=htonl(runner?0x0a000202UL:0x7f000001UL);
        if (GetTickCount64()>=deadline) { Error(result,"deadline",WSAETIMEDOUT); break; }
        result.connectStartQpc=Tick(); result.attempted=true;
        const int connected=connect(owned.value,reinterpret_cast<const sockaddr*>(&remote),sizeof(remote));
        if (connected==0) result.connectSucceeded=true;
        else {
            const int error=WSAGetLastError();
            if (error!=WSAEWOULDBLOCK) { Error(result,"connect",error); result.connectEndQpc=Tick(); break; }
            if (!Wait(owned.value,true,true,deadline,result,"select")) { result.connectEndQpc=Tick(); break; }
            int socketError=0; int optionLength=sizeof(socketError);
            if (getsockopt(owned.value,SOL_SOCKET,SO_ERROR,reinterpret_cast<char*>(&socketError),&optionLength)!=0 || optionLength!=static_cast<int>(sizeof(socketError))) {
                Error(result,"getsockopt_error",WSAGetLastError()); result.connectEndQpc=Tick(); break;
            }
            if (socketError!=0) { Error(result,"completion",socketError); result.connectEndQpc=Tick(); break; }
            result.connectSucceeded=true;
        }
        result.connectEndQpc=Tick();
        length=sizeof(local);
        if (getsockname(owned.value,reinterpret_cast<sockaddr*>(&local),&length)!=0 || length!=static_cast<int>(sizeof(local))) { Error(result,"getsockname",WSAGetLastError()); break; }
        result.localPort=ntohs(local.sin_port); result.localIpv4=ntohl(local.sin_addr.s_addr);
        Echo(owned.value,frame,deadline,result);
    } while (false);
    result.closed=owned.close();
    if (!result.closed && std::strcmp(result.failure,"none")==0) Error(result,"close",WSAGetLastError());
    result.exchangeEndQpc=Tick();
    return result;
}
std::string Bool(bool value) { return value?"true":"false"; }
std::string Serialize(const Attempt& a) {
    return "{\"index\":"+std::to_string(a.index)+",\"attempted\":"+Bool(a.attempted)+
        ",\"bindSucceeded\":"+Bool(a.bindSucceeded)+",\"localPort\":"+std::to_string(a.localPort)+
        ",\"localIpv4\":"+std::to_string(a.localIpv4)+",\"connectStartQpc\":"+std::to_string(a.connectStartQpc)+
        ",\"connectEndQpc\":"+std::to_string(a.connectEndQpc)+",\"connectSucceeded\":"+Bool(a.connectSucceeded)+
        ",\"nonceMatched\":"+Bool(a.nonceMatched)+",\"exchangeEndQpc\":"+std::to_string(a.exchangeEndQpc)+
        ",\"win32Error\":"+std::to_string(a.win32Error)+",\"failure\":\""+a.failure+"\",\"closed\":"+Bool(a.closed)+"}";
}
bool Report(HANDLE file,const std::string& report) {
    if (report.empty() || report.size()>MaxReport) return false;
    DWORD written=0;
    return WriteFile(file,report.data(),static_cast<DWORD>(report.size()),&written,nullptr)
        && written==report.size() && FlushFileBuffers(file);
}
std::string MakeN0aReport(const Observations& identity, const std::string& nonce,
    bool runner, bool contained, bool sample, unsigned int port, bool profile,
    int startupError, LONGLONG frequency, LONGLONG windowStart, LONGLONG endQpc,
    const std::vector<Attempt>& attempts) {
    std::string value=MakeReport("actor-n0a",nonce,identity,std::nullopt,std::nullopt);
    value.resize(value.size()-2); // Replace only the known final }\n from unchanged producer.
    value+=",\"n0a\":{\"version\":1,\"endpoint\":\""+std::string(runner?"runner":"guest")+
        "\",\"role\":\""+(contained?"contained":"ordinary")+"\",\"pattern\":\""+(sample?"sample":"single")+
        "\",\"port\":"+std::to_string(port)+",\"profileMatched\":"+Bool(profile)+
        ",\"startupError\":"+std::to_string(startupError)+
        ",\"qpcFrequency\":"+std::to_string(frequency)+",\"windowStartQpc\":"+std::to_string(windowStart)+
        ",\"windowEndQpc\":"+std::to_string(endQpc)+",\"attempts\":[";
    for (std::size_t index=0;index<attempts.size();++index) { if (index) value+=','; value+=Serialize(attempts[index]); }
    value+="]}}\n";
    return value;
}
int Run(int argc,wchar_t* argv[]) {
    if (argc!=8 || std::wstring(argv[1])!=L"n0a-tcp") return 2;
    std::string nonce; std::wstring path; unsigned int port=0;
    const std::wstring endpoint(argv[4]),role(argv[6]),pattern(argv[7]);
    if (!ReadNonce(argv[2],nonce) || !ReadReportPath(argv[3],path) || !Port(argv[5],port)
        || (endpoint!=L"guest" && endpoint!=L"runner") || (role!=L"ordinary" && role!=L"contained")
        || (pattern!=L"single" && pattern!=L"sample") || (role==L"contained" && pattern!=L"single")) return 2;
    UniqueHandle report(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if (report.get()==INVALID_HANDLE_VALUE) return 3;
    const Observations identity=ObserveNativeIdentity();
    const bool contained=role==L"contained",sample=pattern==L"sample",runner=endpoint==L"runner";
    const bool profile=Profile(identity,contained);
    const LONGLONG frequency=Frequency();
    const LONGLONG startQpc=Tick();
    const ULONGLONG start=GetTickCount64();
    const ULONGLONG deadline=start+(sample?SampleBudget:ContainedBudget);
    std::vector<Attempt> attempts;
    Wsa wsa; int startupError=0;
    if (profile) {
        WSADATA data{}; startupError=WSAStartup(MAKEWORD(2,2),&data); wsa.active=startupError==0;
        if (wsa.active) {
            const std::string frame="N0A1 "+nonce+(runner?" runner ":" guest ")+(contained?"contained\n":"ordinary\n");
            const std::size_t maximum=sample?MaxSamples:(contained?3:1);
            for (std::size_t index=0;index<maximum;++index) {
                const ULONGLONG scheduled=start+static_cast<ULONGLONG>(index)*(sample?250:500);
                ULONGLONG now=GetTickCount64();
                if (now<scheduled) Sleep(static_cast<DWORD>(std::min(scheduled,deadline)-now));
                now=GetTickCount64(); if (now>=deadline) break;
                const ULONGLONG attemptDeadline=std::min(deadline,now+(sample?500:1000));
                attempts.push_back(Probe(static_cast<unsigned int>(index),runner,port,frame,attemptDeadline));
            }
        }
    }
    const LONGLONG endQpc=attempts.empty()?Tick():attempts.back().exchangeEndQpc;
    const LONGLONG windowStart=attempts.empty() || attempts.front().connectStartQpc==0?startQpc:attempts.front().connectStartQpc;
    const std::string value=MakeN0aReport(identity,nonce,runner,contained,sample,port,profile,startupError,frequency,windowStart,endQpc,attempts);
    if (!Report(report.get(),value)) return 3;
    return identity.errors.empty()?0:4;
}
}
#ifndef RULEPROXY_N0A_FIXTURE
int wmain(int argc,wchar_t* argv[]) { try { return n0a::Run(argc,argv); } catch (...) { return 6; } }
#endif
