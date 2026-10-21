// Opt-in direct IPv6 UDP actor. This is NOT DNS API, DNS isolation, or broker evidence.
// The original identity actor is a separately pinned, unchanged dependency.
// Private report contains identity/tuple observations: NEVER upload it verbatim.
// CLI: n0a-udp6 nonce report port before|sample|contained|after
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
#include <mswsock.h>
#include <iphlpapi.h>
#include <mstcpip.h>
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include <algorithm>
#include <cstddef>
#include <stdexcept>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace n0a_udp6 {
constexpr std::size_t MaxReport = 32768;
#ifdef N0A_UDP6_TEST_ONLY
static_assert(N0A_UDP6_TEST_ONLY == 1, "Fixture marker must be exact");
constexpr bool TestOnly = true;
constexpr std::array<unsigned char,16> Destination = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
#else
constexpr bool TestOnly = false;
constexpr std::array<unsigned char,16> Destination = {0xfe,0xc0,0,0,0,0,0,0,0,0,0,0,0,0,0,2};
#endif
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
        value = INVALID_SOCKET; // One attempt only; uncertainty is sticky, never retry a bare handle.
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
    unsigned int contextObserved=0,contextPassed=0;
    bool socketCreated=false,v6OnlySet=false,v6OnlyVerified=false,attempted=false,bindSucceeded=false,sendAccepted=false,nonceMatched=false,closed=false;
    unsigned int localPort=0;
    std::array<unsigned char,16> localIpv6{};
    unsigned long localScopeId=0;
    std::optional<int> v6OnlyGetReturn,v6OnlyGetLength;
    std::optional<DWORD> v6OnlyGetError,v6OnlyGetValue;
    const char* v6OnlyGetStage="not_attempted";
    std::optional<bool> echoPeerLengthMatched,echoPeerFamilyMatched,echoPeerPortMatched,echoPeerScopeZero,echoPeerNotV4Mapped,echoPeerAddressMatched;
    LONGLONG sendStartQpc=0,sendEndQpc=0,exchangeEndQpc=0,closeQpc=0;
    int sendBytes=-1,win32Error=0,closeError=0;
    const char* failure="none";
};
void Error(Attempt& result,const char* phase,int error) { result.failure=phase; result.win32Error=error; }
bool ValidateV6Only(int returned,int apiError,int length,const std::array<unsigned char,sizeof(DWORD)>& storage,Attempt& result) {
    result.v6OnlyGetReturn=returned; result.v6OnlyGetLength=length;
    if (returned!=0) {
        result.v6OnlyGetError=static_cast<DWORD>(apiError); result.v6OnlyGetStage="api_error";
        Error(result,"v6only_get",apiError); return false;
    }
    if (length!=1 && length!=static_cast<int>(sizeof(DWORD))) {
        result.v6OnlyGetStage="length_mismatch"; Error(result,"v6only_length",0); return false;
    }
    DWORD value=0;
    if (length==1) value=storage[0];
    else std::memcpy(&value,storage.data(),sizeof(value));
    result.v6OnlyGetValue=value;
    if (value==0) { result.v6OnlyGetStage="zero"; Error(result,"v6only_zero",0); return false; }
    result.v6OnlyGetStage="nonzero"; result.v6OnlyVerified=true; return true;
}
void ObserveEchoPeer(int count,int length,const sockaddr_in6& sender,const sockaddr_in6& remote,Attempt& result) {
    if (count<0) return;
    result.echoPeerLengthMatched=length==static_cast<int>(sizeof(sender));
    if (length<0 || length>static_cast<int>(sizeof(sender))) return;
    const std::size_t available=static_cast<std::size_t>(length);
    if (available>=offsetof(sockaddr_in6,sin6_family)+sizeof(sender.sin6_family))
        result.echoPeerFamilyMatched=sender.sin6_family==AF_INET6;
    if (available>=offsetof(sockaddr_in6,sin6_port)+sizeof(sender.sin6_port))
        result.echoPeerPortMatched=sender.sin6_port==remote.sin6_port;
    if (available>=offsetof(sockaddr_in6,sin6_scope_id)+sizeof(sender.sin6_scope_id))
        result.echoPeerScopeZero=sender.sin6_scope_id==0;
    if (available>=offsetof(sockaddr_in6,sin6_addr)+sizeof(sender.sin6_addr)) {
        result.echoPeerNotV4Mapped=!IN6_IS_ADDR_V4MAPPED(&sender.sin6_addr);
        result.echoPeerAddressMatched=std::memcmp(&sender.sin6_addr,Destination.data(),Destination.size())==0;
    }
}
// v2 pc bits: option, extension, pre-interface, receive, ancillary, arrival,
// local-destination sanity, stable post-interface, peer scope, combined context.
bool ContextCheck(Attempt& result,unsigned int bit,bool passed) {
    result.contextObserved|=1u<<bit;
    if (passed) result.contextPassed|=1u<<bit;
    return passed;
}
struct InterfaceContext {
    NET_IFINDEX index=0;
    NET_LUID luid{};
    ULONG siteZone=0;
};
constexpr std::array<unsigned char,6> ExpectedMac={0x52,0x54,0x00,0x12,0x34,0x56};
bool InterfaceRows(NET_IFINDEX index,const MIB_IPINTERFACE_ROW& ip,const MIB_IF_ROW2& nic,InterfaceContext& result,bool fixture) {
    if (index==0 || ip.Family!=AF_INET6 || ip.InterfaceIndex!=index || nic.InterfaceIndex!=index
        || ip.InterfaceLuid.Value==0 || ip.InterfaceLuid.Value!=nic.InterfaceLuid.Value
        || !ip.Connected || nic.OperStatus!=IfOperStatusUp) return false;
    if (fixture) {
        if (nic.Type!=IF_TYPE_SOFTWARE_LOOPBACK) return false;
    } else {
        if (nic.Type==IF_TYPE_SOFTWARE_LOOPBACK || nic.PhysicalAddressLength!=ExpectedMac.size()
            || std::memcmp(nic.PhysicalAddress,ExpectedMac.data(),ExpectedMac.size())!=0
            || ip.ZoneIndices[ScopeLevelSite]==0 || ip.ZoneIndices[ScopeLevelSite]>0x0fffffffUL) return false;
    }
    result.index=index;result.luid=ip.InterfaceLuid;result.siteZone=ip.ZoneIndices[ScopeLevelSite];
    return true;
}
bool ReadInterface(const sockaddr_in6& remote,ULONGLONG deadline,InterfaceContext& result,int& error) {
    error=0;
    if (GetTickCount64()>=deadline) return false;
    DWORD index=0;
    sockaddr_in6 destination=remote;
    DWORD status=GetBestInterfaceEx(reinterpret_cast<sockaddr*>(&destination),&index);
    if (status!=NO_ERROR) { error=static_cast<int>(status); return false; }
    if (GetTickCount64()>=deadline) return false;
    MIB_IPINTERFACE_ROW ip{};ip.Family=AF_INET6;ip.InterfaceIndex=index;
    status=GetIpInterfaceEntry(&ip);
    if (status!=NO_ERROR) { error=static_cast<int>(status); return false; }
    if (GetTickCount64()>=deadline) return false;
    MIB_IF_ROW2 nic{};nic.InterfaceIndex=index;
    status=GetIfEntry2(&nic);
    if (status!=NO_ERROR) { error=static_cast<int>(status); return false; }
    return GetTickCount64()<deadline && InterfaceRows(index,ip,nic,result,TestOnly);
}
bool StableInterface(const InterfaceContext& before,const InterfaceContext& after) {
    return before.index==after.index && before.luid.Value==after.luid.Value && before.siteZone==after.siteZone;
}
bool PeerScope(const IN6_ADDR& address,ULONG raw,ULONG expectedZone,bool fixture) {
    if (fixture) return raw==0 && IN6_IS_ADDR_LOOPBACK(&address);
    SCOPE_ID scope{};scope.Value=raw;
    if (expectedZone==0 || expectedZone>0x0fffffffUL
        || (scope.Level!=0 && scope.Level!=static_cast<ULONG>(ScopeLevelSite))) return false;
    IN6_UNCANONICALIZE_SCOPE_ID(&address,&scope);
    return scope.Value==expectedZone;
}

bool PacketDestination(const IN6_ADDR& address,bool fixture) {
    if (fixture) return IN6_IS_ADDR_LOOPBACK(&address)!=0;
    // Sanity only, NOT an independent local-address-table ownership check.
    return !IN6_IS_ADDR_UNSPECIFIED(&address) && !IN6_IS_ADDR_V4MAPPED(&address)
        && !IN6_IS_ADDR_MULTICAST(&address) && !IN6_IS_ADDR_LOOPBACK(&address);
}
constexpr std::size_t ControlSize=WSA_CMSG_SPACE(sizeof(IN6_PKTINFO));
struct ControlStorage { alignas(WSACMSGHDR) std::array<unsigned char,ControlSize> bytes{}; };
bool PacketInfo(const WSAMSG& message,const ControlStorage& storage,IN6_PKTINFO& packet) {
    const std::size_t length=message.Control.len;
    if (message.dwFlags!=0 || message.Control.buf!=reinterpret_cast<const char*>(storage.bytes.data())
        || length<WSA_CMSG_LEN(sizeof(IN6_PKTINFO)) || length>storage.bytes.size()) return false;
    WSACMSGHDR header{};std::memcpy(&header,storage.bytes.data(),sizeof(header));
    if (header.cmsg_len!=WSA_CMSG_LEN(sizeof(IN6_PKTINFO))
        || header.cmsg_level!=IPPROTO_IPV6 || header.cmsg_type!=IPV6_PKTINFO) return false;
    // Only trailing alignment padding is permitted; a second record cannot fit.
    constexpr std::size_t offset=WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR));
    static_assert(offset+sizeof(IN6_PKTINFO)==WSA_CMSG_LEN(sizeof(IN6_PKTINFO)),"SDK control layout");
    std::memcpy(&packet,storage.bytes.data()+offset,sizeof(packet));
    return true;
}
bool ObservePayload(int count,const char* bytes,const std::string& frame,DWORD flags,Attempt& result) {
    const bool matched=flags==0 && count==static_cast<int>(frame.size()) && std::memcmp(bytes,frame.data(),frame.size())==0;
    if (matched) result.nonceMatched=true;
    return matched;
}
bool Receive(SOCKET socket,LPFN_WSARECVMSG receiveMessage,const InterfaceContext& before,const sockaddr_in6& remote,const std::string& frame,ULONGLONG deadline,Attempt& result) {
    const ULONGLONG now=GetTickCount64();
    if (now>=deadline) { Error(result,"recv_select",WSAETIMEDOUT); return false; }
    const ULONGLONG remaining=deadline-now;
    timeval timeout{}; timeout.tv_sec=static_cast<long>(remaining/1000); timeout.tv_usec=static_cast<long>((remaining%1000)*1000);
    fd_set ready{}; FD_ZERO(&ready); FD_SET(socket,&ready);
    const int selected=select(0,&ready,nullptr,nullptr,&timeout);
    if (selected==SOCKET_ERROR) { Error(result,"recv_select",WSAGetLastError()); return false; }
    if (selected==0 || !FD_ISSET(socket,&ready)) { Error(result,"recv_select",WSAETIMEDOUT); return false; }
    std::array<char,129> buffer{};
    sockaddr_in6 sender{};
    WSABUF data{};data.buf=buffer.data();data.len=static_cast<ULONG>(buffer.size());
    ControlStorage storage;
    WSAMSG message{};message.name=reinterpret_cast<sockaddr*>(&sender);message.namelen=sizeof(sender);
    message.lpBuffers=&data;message.dwBufferCount=1;message.Control.buf=reinterpret_cast<char*>(storage.bytes.data());
    message.Control.len=static_cast<ULONG>(storage.bytes.size());
    DWORD received=0;
    const int returned=receiveMessage(socket,&message,&received,nullptr,nullptr);
    const int receiveError=returned!=0?WSAGetLastError():0;
    if (!ContextCheck(result,3,returned==0 && message.dwFlags==0 && received<=buffer.size())) { Error(result,"recvmsg",receiveError); return false; }
    const int senderLength=message.namelen;
    const int count=received<=buffer.size()?static_cast<int>(received):-1;
    const bool payloadMatched=ObservePayload(count,buffer.data(),frame,message.dwFlags,result);
    ObserveEchoPeer(count,senderLength,sender,remote,result);
    if (senderLength!=static_cast<int>(sizeof(sender)) || sender.sin6_family!=AF_INET6
        || sender.sin6_port!=remote.sin6_port || IN6_IS_ADDR_V4MAPPED(&sender.sin6_addr)
        || std::memcmp(&sender.sin6_addr,Destination.data(),Destination.size())!=0) {
        Error(result,"echo_peer",0); return false;
    }
    IN6_PKTINFO packet{};
    if (!ContextCheck(result,4,PacketInfo(message,storage,packet))) { Error(result,"ancillary",0); return false; }
    if (!ContextCheck(result,5,packet.ipi6_ifindex==before.index)) { Error(result,"arrival_interface",0); return false; }
    if (!ContextCheck(result,6,PacketDestination(packet.ipi6_addr,TestOnly))) { Error(result,"packet_destination",0); return false; }
    if (!ContextCheck(result,8,PeerScope(sender.sin6_addr,sender.sin6_scope_id,before.siteZone,TestOnly))) { Error(result,"peer_scope",0); return false; }
    // Preserve observed payload even if subsequent context/interface checks fail.
    InterfaceContext after;int interfaceError=0;
    const bool post=ReadInterface(remote,deadline,after,interfaceError) && StableInterface(before,after);
    if (!ContextCheck(result,7,post)) { Error(result,"interface_post",interfaceError); return false; }
    const bool context=ContextCheck(result,9,result.contextObserved==511u && result.contextPassed==511u);
    if (!payloadMatched) { Error(result,"echo_payload",0); return false; }
    return context;
}
Attempt Probe(unsigned int index,unsigned int port,const std::string& frame,ULONGLONG deadline,Socket& owned) {
    Attempt result; result.index=index;
    owned.value=socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP);
    if (owned.value==INVALID_SOCKET) { Error(result,"socket",WSAGetLastError()); result.exchangeEndQpc=Tick(); return result; }
    result.socketCreated=true;
    do {
        const DWORD v6Only=1;
        if (setsockopt(owned.value,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<const char*>(&v6Only),sizeof(v6Only))!=0) { Error(result,"v6only_set",WSAGetLastError()); break; }
        result.v6OnlySet=true;
        std::array<unsigned char,sizeof(DWORD)> observedV6Only{}; int optionLength=static_cast<int>(observedV6Only.size());
        const int optionReturn=getsockopt(owned.value,IPPROTO_IPV6,IPV6_V6ONLY,reinterpret_cast<char*>(observedV6Only.data()),&optionLength);
        const int optionError=optionReturn!=0?WSAGetLastError():0;
        if (!ValidateV6Only(optionReturn,optionError,optionLength,observedV6Only,result)) break;
        const DWORD packetInfo=1;
        const int packetReturn=setsockopt(owned.value,IPPROTO_IPV6,IPV6_PKTINFO,reinterpret_cast<const char*>(&packetInfo),sizeof(packetInfo));
        const int packetError=packetReturn!=0?WSAGetLastError():0;
        if (!ContextCheck(result,0,packetReturn==0)) { Error(result,"pktinfo_set",packetError); break; }
        GUID receiveGuid=WSAID_WSARECVMSG;LPFN_WSARECVMSG receiveMessage=nullptr;DWORD extensionBytes=0;
        const int extensionReturn=WSAIoctl(owned.value,SIO_GET_EXTENSION_FUNCTION_POINTER,&receiveGuid,sizeof(receiveGuid),
            &receiveMessage,sizeof(receiveMessage),&extensionBytes,nullptr,nullptr);
        const int extensionError=extensionReturn!=0?WSAGetLastError():0;
        if (!ContextCheck(result,1,extensionReturn==0 && extensionBytes==sizeof(receiveMessage) && receiveMessage!=nullptr)) {
            Error(result,"recvmsg_extension",extensionError); break;
        }
        const BOOL exclusive=TRUE;
        if (setsockopt(owned.value,SOL_SOCKET,SO_EXCLUSIVEADDRUSE,reinterpret_cast<const char*>(&exclusive),sizeof(exclusive))!=0) { Error(result,"exclusive",WSAGetLastError()); break; }
        u_long nonblocking=1;
        if (ioctlsocket(owned.value,FIONBIO,&nonblocking)!=0) { Error(result,"nonblocking",WSAGetLastError()); break; }
        sockaddr_in6 local{}; local.sin6_family=AF_INET6; local.sin6_port=0; // Unspecified ::; never substitute a routed source address.
        if (bind(owned.value,reinterpret_cast<const sockaddr*>(&local),sizeof(local))!=0) { Error(result,"bind",WSAGetLastError()); break; }
        result.bindSucceeded=true;
        int length=sizeof(local);
        if (getsockname(owned.value,reinterpret_cast<sockaddr*>(&local),&length)!=0) { Error(result,"getsockname",WSAGetLastError()); break; }
        if (length!=static_cast<int>(sizeof(local)) || local.sin6_family!=AF_INET6 || local.sin6_port==0 || local.sin6_scope_id!=0 || IN6_IS_ADDR_V4MAPPED(&local.sin6_addr)) { Error(result,"getsockname",WSAEINVAL); break; }
        result.localPort=ntohs(local.sin6_port); std::memcpy(result.localIpv6.data(),&local.sin6_addr,result.localIpv6.size()); result.localScopeId=local.sin6_scope_id; // Actual wildcard observation is retained.
        sockaddr_in6 remote{}; remote.sin6_family=AF_INET6; remote.sin6_port=htons(static_cast<u_short>(port));
        std::memcpy(&remote.sin6_addr,Destination.data(),Destination.size()); // Fixed address, zero flowinfo/scope, no resolver.
        if (frame.empty() || frame.size()>128 || GetTickCount64()>=deadline) { Error(result,"deadline",WSAETIMEDOUT); break; }
        InterfaceContext before;int interfaceError=0;
        if (!ContextCheck(result,2,ReadInterface(remote,deadline,before,interfaceError))) { Error(result,"interface_pre",interfaceError); break; }
        if (GetTickCount64()>=deadline) { Error(result,"deadline",WSAETIMEDOUT); break; }
        result.sendStartQpc=Tick(); result.attempted=true;
        const int sent=sendto(owned.value,frame.data(),static_cast<int>(frame.size()),0,reinterpret_cast<const sockaddr*>(&remote),sizeof(remote));
        const int sendError=sent==SOCKET_ERROR?WSAGetLastError():0;
        result.sendEndQpc=Tick(); result.sendBytes=sent;
        if (sent==SOCKET_ERROR) { Error(result,"sendto",sendError); break; }
        if (sent!=static_cast<int>(frame.size())) { Error(result,"short_send",0); break; }
        result.sendAccepted=true; // Local API acceptance only, NOT delivery.
        Receive(owned.value,receiveMessage,before,remote,frame,deadline,result);
    } while (false);
    result.exchangeEndQpc=Tick(); // Socket remains owned and bound through the probe window.
    return result;
}
std::string Bool(bool value) { return value?"true":"false"; }
std::string OptionalBool(const std::optional<bool>& value) { return value.has_value()?Bool(*value):"null"; }
std::string AddressHex(const std::array<unsigned char,16>& value) {
    const char* digits="0123456789abcdef"; std::string result; result.reserve(32);
    for(unsigned char byte:value) { result+=digits[byte>>4]; result+=digits[byte&15]; } return result;
}
template<class T> std::string OptionalNumber(const std::optional<T>& value) { return value?std::to_string(*value):"null"; }
std::string Serialize(const Attempt& a) {
    return "{\"index\":"+std::to_string(a.index)+",\"socketCreated\":"+Bool(a.socketCreated)+
        ",\"v6OnlySet\":"+Bool(a.v6OnlySet)+",\"v6OnlyVerified\":"+Bool(a.v6OnlyVerified)+",\"attempted\":"+Bool(a.attempted)+
        ",\"v6OnlyGetReturn\":"+OptionalNumber(a.v6OnlyGetReturn)+",\"v6OnlyGetError\":"+OptionalNumber(a.v6OnlyGetError)+
        ",\"v6OnlyGetLength\":"+OptionalNumber(a.v6OnlyGetLength)+",\"v6OnlyGetValue\":"+OptionalNumber(a.v6OnlyGetValue)+",\"v6OnlyGetStage\":\""+a.v6OnlyGetStage+"\""+
        ",\"bindSucceeded\":"+Bool(a.bindSucceeded)+",\"localPort\":"+std::to_string(a.localPort)+",\"localIpv6\":\""+AddressHex(a.localIpv6)+"\",\"localScopeId\":"+std::to_string(a.localScopeId)+
        ",\"sendStartQpc\":"+std::to_string(a.sendStartQpc)+",\"sendEndQpc\":"+std::to_string(a.sendEndQpc)+",\"sendBytes\":"+std::to_string(a.sendBytes)+
        ",\"sendAccepted\":"+Bool(a.sendAccepted)+",\"nonceMatched\":"+Bool(a.nonceMatched)+",\"exchangeEndQpc\":"+std::to_string(a.exchangeEndQpc)+
        ",\"pc\":[1,"+std::to_string(a.contextObserved)+","+std::to_string(a.contextPassed)+"]"+
        ",\"echoPeerLengthMatched\":"+OptionalBool(a.echoPeerLengthMatched)+
        ",\"echoPeerFamilyMatched\":"+OptionalBool(a.echoPeerFamilyMatched)+
        ",\"echoPeerPortMatched\":"+OptionalBool(a.echoPeerPortMatched)+
        ",\"echoPeerScopeZero\":"+OptionalBool(a.echoPeerScopeZero)+
        ",\"echoPeerNotV4Mapped\":"+OptionalBool(a.echoPeerNotV4Mapped)+
        ",\"echoPeerAddressMatched\":"+OptionalBool(a.echoPeerAddressMatched)+
        ",\"win32Error\":"+std::to_string(a.win32Error)+",\"failure\":\""+a.failure+"\",\"closed\":"+Bool(a.closed)+
        ",\"closeError\":"+std::to_string(a.closeError)+",\"closeQpc\":"+std::to_string(a.closeQpc)+"}";
}
bool Report(HANDLE file,const std::string& report) {
    if (report.empty() || report.size()>MaxReport) return false;
    DWORD written=0;
    return WriteFile(file,report.data(),static_cast<DWORD>(report.size()),&written,nullptr) && written==report.size() && FlushFileBuffers(file);
}
int Run(int argc,wchar_t* argv[]) {
    if (argc!=6 || std::wstring(argv[1])!=L"n0a-udp6") return 2;
    std::string nonce; std::wstring path; unsigned int port=0;
    const std::wstring phaseWide(argv[5]);
    if (!ReadNonce(argv[2],nonce) || !ReadReportPath(argv[3],path) || !Port(argv[4],port)
        || (phaseWide!=L"before" && phaseWide!=L"sample" && phaseWide!=L"contained" && phaseWide!=L"after")) return 2;
    const bool contained=phaseWide==L"contained",sample=phaseWide==L"sample";
    const std::string phase=contained?"contained":(sample?"sample":(phaseWide==L"before"?"before":"after"));
    UniqueHandle report(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr));
    if (report.get()==INVALID_HANDLE_VALUE) return 3;
    const Observations identity=ObserveNativeIdentity();
    const bool profile=Profile(identity,contained);
    const LONGLONG frequency=Frequency(),startQpc=Tick();
    const ULONGLONG start=GetTickCount64(),deadline=start+(sample?SampleBudget:ContainedBudget);
    std::vector<Attempt> attempts; attempts.reserve(MaxSamples);
    Wsa wsa; int startupError=0;
    std::array<Socket,MaxSamples> sockets;
    if (profile || TestOnly) {
        WSADATA data{}; startupError=WSAStartup(MAKEWORD(2,2),&data); wsa.active=startupError==0;
        if (wsa.active) {
            const std::size_t maximum=sample?MaxSamples:(contained?3:1);
            for (std::size_t index=0;index<maximum;++index) {
                const ULONGLONG scheduled=start+static_cast<ULONGLONG>(index)*(sample?250:500);
                ULONGLONG now=GetTickCount64();
                if (now<scheduled) Sleep(static_cast<DWORD>(std::min(scheduled,deadline)-now));
                now=GetTickCount64(); if (now>=deadline) break;
                const std::string frame="N0AU6 "+nonce+" "+phase+" "+std::to_string(index)+"\n";
                attempts.push_back(Probe(static_cast<unsigned int>(index),port,frame,std::min(deadline,now+(sample?200:800)),sockets[index]));
            }
        }
    }
    const LONGLONG endQpc=attempts.empty()?Tick():attempts.back().exchangeEndQpc;
    const LONGLONG windowStart=attempts.empty() || attempts.front().sendStartQpc==0?startQpc:attempts.front().sendStartQpc;
    bool cleanup=true;
    for (std::size_t index=0;index<attempts.size();++index) {
        Attempt& attempt=attempts[index];
        if (attempt.socketCreated) {
            attempt.closed=sockets[index].close();
            attempt.closeError=attempt.closed?0:WSAGetLastError();
            attempt.closeQpc=Tick(); cleanup=cleanup&&attempt.closed;
        }
    }
    std::string value=MakeReport("actor-n0a-udp6",nonce,identity,std::nullopt,std::nullopt);
    value.resize(value.size()-2);
    value+=",\"udp6\":{\"version\":2,\"testOnly\":"+Bool(TestOnly)+",\"endpoint\":\""+std::string(TestOnly?"fixture-loopback-v6":"runner-v6")+
        "\",\"phase\":\""+phase+"\",\"port\":"+std::to_string(port)+",\"profileMatched\":"+Bool(profile)+
        ",\"startupError\":"+std::to_string(startupError)+",\"qpcFrequency\":"+std::to_string(frequency)+
        ",\"windowStartQpc\":"+std::to_string(windowStart)+",\"windowEndQpc\":"+std::to_string(endQpc)+
        ",\"socketsCleanupConfirmed\":"+Bool(cleanup)+",\"attempts\":[";
    for (std::size_t index=0;index<attempts.size();++index) { if (index) value+=','; value+=Serialize(attempts[index]); }
    value+="]}}\n";
    if (!Report(report.get(),value)) return 3;
    return identity.errors.empty()?0:4;
}
}
#ifndef N0A_UDP6_FIXTURE_ENTRY
int wmain(int argc,wchar_t* argv[]) { try { return n0a_udp6::Run(argc,argv); } catch (...) { return 6; } }
#endif
