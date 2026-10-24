#pragma once
// A5 startup-only interface proposal. Declarations only; no API is executed.
// External exports are controlled solely by the exact40 .def (no dllexport).
// No real WS2 import library or provider forwarder is permitted in this scope.
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstddef>
#include <type_traits>
#if !defined(_WIN64) || !defined(_M_X64)
#error Fixed AMD64 scope only
#endif
static_assert(sizeof(SOCKET)==8 && sizeof(WSADATA)==408,"AMD64 Winsock SDK ABI");
static_assert(offsetof(WSADATA,wVersion)==0 && offsetof(WSADATA,wHighVersion)==2,"versions");
static_assert(offsetof(WSADATA,lpVendorInfo)==8 && offsetof(WSADATA,szDescription)==16 && offsetof(WSADATA,szSystemStatus)==273,"WSADATA fields");
extern "C" {
SOCKET WSAAPI a5_accept(SOCKET, sockaddr*, int*);
int WSAAPI a5_bind(SOCKET, const sockaddr*, int);
int WSAAPI a5_closesocket(SOCKET);
int WSAAPI a5_connect(SOCKET, const sockaddr*, int);
int WSAAPI a5_getpeername(SOCKET, sockaddr*, int*);
int WSAAPI a5_getsockname(SOCKET, sockaddr*, int*);
int WSAAPI a5_getsockopt(SOCKET, int, int, char*, int*);
u_long WSAAPI a5_htonl(u_long);
u_short WSAAPI a5_htons(u_short);
int WSAAPI a5_ioctlsocket(SOCKET, long, u_long*);
int WSAAPI a5_listen(SOCKET, int);
u_short WSAAPI a5_ntohs(u_short);
int WSAAPI a5_recv(SOCKET, char*, int, int);
int WSAAPI a5_recvfrom(SOCKET, char*, int, int, sockaddr*, int*);
int WSAAPI a5_select(int, fd_set*, fd_set*, fd_set*, const timeval*);
int WSAAPI a5_send(SOCKET, const char*, int, int);
int WSAAPI a5_sendto(SOCKET, const char*, int, int, const sockaddr*, int);
int WSAAPI a5_setsockopt(SOCKET, int, int, const char*, int);
int WSAAPI a5_shutdown(SOCKET, int);
SOCKET WSAAPI a5_socket(int, int, int);
BOOL WSAAPI a5_WSACloseEvent(WSAEVENT);
WSAEVENT WSAAPI a5_WSACreateEvent(void);
int WSAAPI a5_gethostname(char*, int);
int WSAAPI a5_WSAEnumNetworkEvents(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
int WSAAPI a5_WSAEventSelect(SOCKET, WSAEVENT, long);
int WSAAPI a5_WSAIoctl(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
BOOL WSAAPI a5_WSAResetEvent(WSAEVENT);
int WSAAPI a5_WSAGetLastError(void);
void WSAAPI a5_WSASetLastError(int);
int WSAAPI a5_WSAStartup(WORD, LPWSADATA);
int WSAAPI a5_WSACleanup(void);
DWORD WSAAPI a5_WSAWaitForMultipleEvents(DWORD, const WSAEVENT*, BOOL, DWORD, BOOL);
int WSAAPI a5___WSAFDIsSet(SOCKET, fd_set*);
void WSAAPI a5_freeaddrinfo(PADDRINFOA);
INT WSAAPI a5_getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
FARPROC WINAPI a5_GetProcAddress(HMODULE, LPCSTR);
HMODULE WINAPI a5_GetModuleHandleW(LPCWSTR);
HMODULE WINAPI a5_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
BOOL WINAPI a5_FreeLibrary(HMODULE);
}
// Future compile-only signature checks; this file has not been compiled.
static_assert(std::is_same<decltype(&::accept),decltype(&a5_accept)>::value,"SDK accept");
static_assert(std::is_same<decltype(&::bind),decltype(&a5_bind)>::value,"SDK bind");
static_assert(std::is_same<decltype(&::closesocket),decltype(&a5_closesocket)>::value,"SDK closesocket");
static_assert(std::is_same<decltype(&::connect),decltype(&a5_connect)>::value,"SDK connect");
static_assert(std::is_same<decltype(&::getpeername),decltype(&a5_getpeername)>::value,"SDK getpeername");
static_assert(std::is_same<decltype(&::getsockname),decltype(&a5_getsockname)>::value,"SDK getsockname");
static_assert(std::is_same<decltype(&::getsockopt),decltype(&a5_getsockopt)>::value,"SDK getsockopt");
static_assert(std::is_same<decltype(&::htonl),decltype(&a5_htonl)>::value,"SDK htonl");
static_assert(std::is_same<decltype(&::htons),decltype(&a5_htons)>::value,"SDK htons");
static_assert(std::is_same<decltype(&::ioctlsocket),decltype(&a5_ioctlsocket)>::value,"SDK ioctlsocket");
static_assert(std::is_same<decltype(&::listen),decltype(&a5_listen)>::value,"SDK listen");
static_assert(std::is_same<decltype(&::ntohs),decltype(&a5_ntohs)>::value,"SDK ntohs");
static_assert(std::is_same<decltype(&::recv),decltype(&a5_recv)>::value,"SDK recv");
static_assert(std::is_same<decltype(&::recvfrom),decltype(&a5_recvfrom)>::value,"SDK recvfrom");
static_assert(std::is_same<decltype(&::select),decltype(&a5_select)>::value,"SDK select");
static_assert(std::is_same<decltype(&::send),decltype(&a5_send)>::value,"SDK send");
static_assert(std::is_same<decltype(&::sendto),decltype(&a5_sendto)>::value,"SDK sendto");
static_assert(std::is_same<decltype(&::setsockopt),decltype(&a5_setsockopt)>::value,"SDK setsockopt");
static_assert(std::is_same<decltype(&::shutdown),decltype(&a5_shutdown)>::value,"SDK shutdown");
static_assert(std::is_same<decltype(&::socket),decltype(&a5_socket)>::value,"SDK socket");
static_assert(std::is_same<decltype(&::WSACloseEvent),decltype(&a5_WSACloseEvent)>::value,"SDK WSACloseEvent");
static_assert(std::is_same<decltype(&::WSACreateEvent),decltype(&a5_WSACreateEvent)>::value,"SDK WSACreateEvent");
static_assert(std::is_same<decltype(&::gethostname),decltype(&a5_gethostname)>::value,"SDK gethostname");
static_assert(std::is_same<decltype(&::WSAEnumNetworkEvents),decltype(&a5_WSAEnumNetworkEvents)>::value,"SDK WSAEnumNetworkEvents");
static_assert(std::is_same<decltype(&::WSAEventSelect),decltype(&a5_WSAEventSelect)>::value,"SDK WSAEventSelect");
static_assert(std::is_same<decltype(&::WSAIoctl),decltype(&a5_WSAIoctl)>::value,"SDK WSAIoctl");
static_assert(std::is_same<decltype(&::WSAResetEvent),decltype(&a5_WSAResetEvent)>::value,"SDK WSAResetEvent");
static_assert(std::is_same<decltype(&::WSAGetLastError),decltype(&a5_WSAGetLastError)>::value,"SDK WSAGetLastError");
static_assert(std::is_same<decltype(&::WSASetLastError),decltype(&a5_WSASetLastError)>::value,"SDK WSASetLastError");
static_assert(std::is_same<decltype(&::WSAStartup),decltype(&a5_WSAStartup)>::value,"SDK WSAStartup");
static_assert(std::is_same<decltype(&::WSACleanup),decltype(&a5_WSACleanup)>::value,"SDK WSACleanup");
static_assert(std::is_same<decltype(&::WSAWaitForMultipleEvents),decltype(&a5_WSAWaitForMultipleEvents)>::value,"SDK WSAWaitForMultipleEvents");
static_assert(std::is_same<decltype(&::__WSAFDIsSet),decltype(&a5___WSAFDIsSet)>::value,"SDK __WSAFDIsSet");
static_assert(std::is_same<decltype(&::freeaddrinfo),decltype(&a5_freeaddrinfo)>::value,"SDK freeaddrinfo");
static_assert(std::is_same<decltype(&::getaddrinfo),decltype(&a5_getaddrinfo)>::value,"SDK getaddrinfo");
static_assert(std::is_same<decltype(&::GetProcAddress),decltype(&a5_GetProcAddress)>::value,"SDK GetProcAddress");
static_assert(std::is_same<decltype(&::GetModuleHandleW),decltype(&a5_GetModuleHandleW)>::value,"SDK GetModuleHandleW");
static_assert(std::is_same<decltype(&::LoadLibraryExW),decltype(&a5_LoadLibraryExW)>::value,"SDK LoadLibraryExW");
static_assert(std::is_same<decltype(&::FreeLibrary),decltype(&a5_FreeLibrary)>::value,"SDK FreeLibrary");
