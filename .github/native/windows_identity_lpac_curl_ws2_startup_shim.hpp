#pragma once
// A4 startup-only interface proposal. Declarations only; no API is executed.
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
SOCKET WSAAPI a4_accept(SOCKET, sockaddr*, int*);
int WSAAPI a4_bind(SOCKET, const sockaddr*, int);
int WSAAPI a4_closesocket(SOCKET);
int WSAAPI a4_connect(SOCKET, const sockaddr*, int);
int WSAAPI a4_getpeername(SOCKET, sockaddr*, int*);
int WSAAPI a4_getsockname(SOCKET, sockaddr*, int*);
int WSAAPI a4_getsockopt(SOCKET, int, int, char*, int*);
u_long WSAAPI a4_htonl(u_long);
u_short WSAAPI a4_htons(u_short);
int WSAAPI a4_ioctlsocket(SOCKET, long, u_long*);
int WSAAPI a4_listen(SOCKET, int);
u_short WSAAPI a4_ntohs(u_short);
int WSAAPI a4_recv(SOCKET, char*, int, int);
int WSAAPI a4_recvfrom(SOCKET, char*, int, int, sockaddr*, int*);
int WSAAPI a4_select(int, fd_set*, fd_set*, fd_set*, const timeval*);
int WSAAPI a4_send(SOCKET, const char*, int, int);
int WSAAPI a4_sendto(SOCKET, const char*, int, int, const sockaddr*, int);
int WSAAPI a4_setsockopt(SOCKET, int, int, const char*, int);
int WSAAPI a4_shutdown(SOCKET, int);
SOCKET WSAAPI a4_socket(int, int, int);
BOOL WSAAPI a4_WSACloseEvent(WSAEVENT);
WSAEVENT WSAAPI a4_WSACreateEvent(void);
int WSAAPI a4_gethostname(char*, int);
int WSAAPI a4_WSAEnumNetworkEvents(SOCKET, WSAEVENT, LPWSANETWORKEVENTS);
int WSAAPI a4_WSAEventSelect(SOCKET, WSAEVENT, long);
int WSAAPI a4_WSAIoctl(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
BOOL WSAAPI a4_WSAResetEvent(WSAEVENT);
int WSAAPI a4_WSAGetLastError(void);
void WSAAPI a4_WSASetLastError(int);
int WSAAPI a4_WSAStartup(WORD, LPWSADATA);
int WSAAPI a4_WSACleanup(void);
DWORD WSAAPI a4_WSAWaitForMultipleEvents(DWORD, const WSAEVENT*, BOOL, DWORD, BOOL);
int WSAAPI a4___WSAFDIsSet(SOCKET, fd_set*);
void WSAAPI a4_freeaddrinfo(PADDRINFOA);
INT WSAAPI a4_getaddrinfo(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
FARPROC WINAPI a4_GetProcAddress(HMODULE, LPCSTR);
HMODULE WINAPI a4_GetModuleHandleW(LPCWSTR);
HMODULE WINAPI a4_LoadLibraryExW(LPCWSTR, HANDLE, DWORD);
BOOL WINAPI a4_FreeLibrary(HMODULE);
}
// Future compile-only signature checks; this file has not been compiled.
static_assert(std::is_same<decltype(&::accept),decltype(&a4_accept)>::value,"SDK accept");
static_assert(std::is_same<decltype(&::bind),decltype(&a4_bind)>::value,"SDK bind");
static_assert(std::is_same<decltype(&::closesocket),decltype(&a4_closesocket)>::value,"SDK closesocket");
static_assert(std::is_same<decltype(&::connect),decltype(&a4_connect)>::value,"SDK connect");
static_assert(std::is_same<decltype(&::getpeername),decltype(&a4_getpeername)>::value,"SDK getpeername");
static_assert(std::is_same<decltype(&::getsockname),decltype(&a4_getsockname)>::value,"SDK getsockname");
static_assert(std::is_same<decltype(&::getsockopt),decltype(&a4_getsockopt)>::value,"SDK getsockopt");
static_assert(std::is_same<decltype(&::htonl),decltype(&a4_htonl)>::value,"SDK htonl");
static_assert(std::is_same<decltype(&::htons),decltype(&a4_htons)>::value,"SDK htons");
static_assert(std::is_same<decltype(&::ioctlsocket),decltype(&a4_ioctlsocket)>::value,"SDK ioctlsocket");
static_assert(std::is_same<decltype(&::listen),decltype(&a4_listen)>::value,"SDK listen");
static_assert(std::is_same<decltype(&::ntohs),decltype(&a4_ntohs)>::value,"SDK ntohs");
static_assert(std::is_same<decltype(&::recv),decltype(&a4_recv)>::value,"SDK recv");
static_assert(std::is_same<decltype(&::recvfrom),decltype(&a4_recvfrom)>::value,"SDK recvfrom");
static_assert(std::is_same<decltype(&::select),decltype(&a4_select)>::value,"SDK select");
static_assert(std::is_same<decltype(&::send),decltype(&a4_send)>::value,"SDK send");
static_assert(std::is_same<decltype(&::sendto),decltype(&a4_sendto)>::value,"SDK sendto");
static_assert(std::is_same<decltype(&::setsockopt),decltype(&a4_setsockopt)>::value,"SDK setsockopt");
static_assert(std::is_same<decltype(&::shutdown),decltype(&a4_shutdown)>::value,"SDK shutdown");
static_assert(std::is_same<decltype(&::socket),decltype(&a4_socket)>::value,"SDK socket");
static_assert(std::is_same<decltype(&::WSACloseEvent),decltype(&a4_WSACloseEvent)>::value,"SDK WSACloseEvent");
static_assert(std::is_same<decltype(&::WSACreateEvent),decltype(&a4_WSACreateEvent)>::value,"SDK WSACreateEvent");
static_assert(std::is_same<decltype(&::gethostname),decltype(&a4_gethostname)>::value,"SDK gethostname");
static_assert(std::is_same<decltype(&::WSAEnumNetworkEvents),decltype(&a4_WSAEnumNetworkEvents)>::value,"SDK WSAEnumNetworkEvents");
static_assert(std::is_same<decltype(&::WSAEventSelect),decltype(&a4_WSAEventSelect)>::value,"SDK WSAEventSelect");
static_assert(std::is_same<decltype(&::WSAIoctl),decltype(&a4_WSAIoctl)>::value,"SDK WSAIoctl");
static_assert(std::is_same<decltype(&::WSAResetEvent),decltype(&a4_WSAResetEvent)>::value,"SDK WSAResetEvent");
static_assert(std::is_same<decltype(&::WSAGetLastError),decltype(&a4_WSAGetLastError)>::value,"SDK WSAGetLastError");
static_assert(std::is_same<decltype(&::WSASetLastError),decltype(&a4_WSASetLastError)>::value,"SDK WSASetLastError");
static_assert(std::is_same<decltype(&::WSAStartup),decltype(&a4_WSAStartup)>::value,"SDK WSAStartup");
static_assert(std::is_same<decltype(&::WSACleanup),decltype(&a4_WSACleanup)>::value,"SDK WSACleanup");
static_assert(std::is_same<decltype(&::WSAWaitForMultipleEvents),decltype(&a4_WSAWaitForMultipleEvents)>::value,"SDK WSAWaitForMultipleEvents");
static_assert(std::is_same<decltype(&::__WSAFDIsSet),decltype(&a4___WSAFDIsSet)>::value,"SDK __WSAFDIsSet");
static_assert(std::is_same<decltype(&::freeaddrinfo),decltype(&a4_freeaddrinfo)>::value,"SDK freeaddrinfo");
static_assert(std::is_same<decltype(&::getaddrinfo),decltype(&a4_getaddrinfo)>::value,"SDK getaddrinfo");
static_assert(std::is_same<decltype(&::GetProcAddress),decltype(&a4_GetProcAddress)>::value,"SDK GetProcAddress");
static_assert(std::is_same<decltype(&::GetModuleHandleW),decltype(&a4_GetModuleHandleW)>::value,"SDK GetModuleHandleW");
static_assert(std::is_same<decltype(&::LoadLibraryExW),decltype(&a4_LoadLibraryExW)>::value,"SDK LoadLibraryExW");
static_assert(std::is_same<decltype(&::FreeLibrary),decltype(&a4_FreeLibrary)>::value,"SDK FreeLibrary");
