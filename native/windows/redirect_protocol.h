// Versioned ABI between the ALE redirector and its local relay. No pointers,
// TCHARs or compiler-sized fields cross this boundary. Windows x64/ARM64 only.
#pragma once

#define RP_REDIRECT_ABI 1u
#define RP_REDIRECT_MAGIC 0x52505244u
#define RP_AF_INET 2u
#define RP_AF_INET6 23u
#define RP_CONTEXT_BYTES 64u
#define RP_CONFIG_BYTES 40u
#define RP_DEVICE_TYPE 0x8337u
#define RP_IOCTL_CONFIGURE CTL_CODE(RP_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)
#define RP_IOCTL_CLEAR CTL_CODE(RP_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)

// Ports are host order here; destination address bytes are network order.
// Session is the exact rawContext of the SID-scoped redirect filter. Generation
// pins the relay instance. It is an identifier, not a bearer credential.
typedef struct _RP_REDIRECT_CONTEXT {
    UINT32 magic;
    UINT32 version;
    UINT32 size;
    UINT16 family;
    UINT16 destinationPort;
    UINT64 session;
    UINT64 originalProcessId;
    UINT8 generation[16];
    UINT8 destinationAddress[16];
} RP_REDIRECT_CONTEXT;

typedef struct _RP_RELAY_CONFIG {
    UINT32 version;
    UINT32 size;
    UINT64 processId;
    UINT16 ipv4Port;
    UINT16 ipv6Port;
    UINT32 reserved;
    UINT8 generation[16];
} RP_RELAY_CONFIG;

// The management policy references precisely these callout keys. The driver
// only registers callouts; it never installs/removes independent guard filters.
DEFINE_GUID(RP_REDIRECT_V4, 0x4ac38f01, 0x8473, 0x4bd0, 0xb6, 0x02, 0xd1, 0x89, 0x2e, 0x9c, 0x15, 0x01);
DEFINE_GUID(RP_REDIRECT_V6, 0x4ac38f01, 0x8473, 0x4bd0, 0xb6, 0x02, 0xd1, 0x89, 0x2e, 0x9c, 0x15, 0x02);
DEFINE_GUID(RP_DEVICE_CLASS, 0x4ac38f01, 0x8473, 0x4bd0, 0xb6, 0x02, 0xd1, 0x89, 0x2e, 0x9c, 0x15, 0x03);

