#pragma once
// Source-only A5 draft. No Windows headers, API calls or hidden allocation.
#include <cstddef>
#include <cstdint>
#include <type_traits>
namespace a5startup {
using u16=std::uint16_t;using u32=std::uint32_t;using u64=std::uint64_t;
// GUID a5193b72-5ad3-4f4b-ae3a-706564727073, Windows GUID bytes_le.
constexpr std::uint8_t payload_guid[16]={0x72,0x3b,0x19,0xa5,0xd3,0x5a,0x4b,0x4f,0xae,0x3a,0x70,0x65,0x64,0x72,0x70,0x73};
constexpr u32 trace_capacity=256;
constexpr u32 trace_bytes=557312;
#pragma pack(push,8)
struct Config2048 {
 char magic[4];u16 version,size;
 std::uint8_t run[16],source_sha256[32],config_sha256[32],target_sha256[32],shim_sha256[32];
 u64 frequency,root_start,root_deadline,work_deadline,window_start,window_end;
 u32 target_pid,reserved0;u64 target_creation,trace_handle;
 u32 trace_bytes,capacity,private_path_bytes,system_ws2_chars;
 std::uint8_t trace_nonce[16];char private_path[1024];u16 system_ws2_path[260];
 u64 pipe_read,pipe_write;std::uint8_t case_id[16];u16 origin_port,http_profile;
 u32 request_total,response_total;u16 request_header_bytes,response_header_bytes;
 u32 request_body,response_body;u16 virtual_local_port,reserved1;std::uint8_t reserved[188];
};
struct TraceHeader256 {
 char magic[4];u16 version,header_bytes;u32 total_bytes,capacity,row_bytes,claimed,overflow,input_fault;
 std::uint8_t run[16],config_sha256[32],source_sha256[32],shim_sha256[32];
 u32 target_pid,reserved0;u64 target_creation,frequency,root_start,root_deadline,work_deadline,window_start,window_end;
 u64 sequence,unsupported_mask;u32 startup_refs,state_flags;std::uint8_t trace_nonce[16],reserved[8];
};
struct TraceCall64 {
 u32 size,export_ordinal;u64 sequence,entered_qpc,returned_qpc;std::int64_t raw_return;
 std::int32_t error;u32 flags;u64 arg0,arg1;
};
struct SdkReceipt32 {std::int64_t raw_return;std::int32_t error;u32 flags;u64 entered_qpc,returned_qpc;};
struct TraceCall2176 {
 TraceCall64 raw;
 u32 input_kind,captured_bytes,module_kind,resolution_kind,resolved_ordinal,thread_id;u64 arg2;
 std::uint8_t name_or_WSADATA[2048];SdkReceipt32 sdk;
};
struct Trace557312 {TraceHeader256 header;TraceCall2176 calls[trace_capacity];};
#pragma pack(pop)
static_assert(sizeof(Config2048)==2048&&alignof(Config2048)==8,"A5 config");
static_assert(offsetof(Config2048,run)==8&&offsetof(Config2048,frequency)==152&&offsetof(Config2048,target_pid)==200,"config binding");
static_assert(offsetof(Config2048,trace_handle)==216&&offsetof(Config2048,trace_nonce)==240&&offsetof(Config2048,private_path)==256,"config inputs");
static_assert(offsetof(Config2048,system_ws2_path)==1280&&offsetof(Config2048,pipe_read)==1800,"config paths");
static_assert(offsetof(Config2048,pipe_write)==1808&&offsetof(Config2048,case_id)==1816,"A5 inherited stream");
static_assert(offsetof(Config2048,origin_port)==1832&&offsetof(Config2048,http_profile)==1834&&offsetof(Config2048,request_total)==1836,"A5 profile");
static_assert(offsetof(Config2048,response_total)==1840&&offsetof(Config2048,request_header_bytes)==1844&&offsetof(Config2048,response_header_bytes)==1846,"A5 totals");
static_assert(offsetof(Config2048,request_body)==1848&&offsetof(Config2048,response_body)==1852&&offsetof(Config2048,virtual_local_port)==1856,"A5 message");
static_assert(offsetof(Config2048,reserved1)==1858&&offsetof(Config2048,reserved)==1860,"A5 zero reserved");
static_assert(sizeof(TraceHeader256)==256&&alignof(TraceHeader256)==8,"A5 header");
static_assert(offsetof(TraceHeader256,run)==32&&offsetof(TraceHeader256,target_pid)==144&&offsetof(TraceHeader256,sequence)==208,"header bindings");
static_assert(offsetof(TraceHeader256,trace_nonce)==232&&offsetof(TraceHeader256,reserved)==248,"trace nonce");
static_assert(offsetof(TraceCall2176,input_kind)==64&&offsetof(TraceCall2176,arg2)==88&&offsetof(TraceCall2176,name_or_WSADATA)==96&&offsetof(TraceCall2176,sdk)==2144,"owned capture");
static_assert(sizeof(SdkReceipt32)==32&&offsetof(SdkReceipt32,entered_qpc)==16&&offsetof(SdkReceipt32,returned_qpc)==24,"SDK raw first");
static_assert(sizeof(TraceCall64)==64&&alignof(TraceCall64)==8&&sizeof(TraceCall2176)==2176&&sizeof(Trace557312)==557312,"A5 output");
static_assert(std::is_trivial<Config2048>::value&&std::is_trivial<Trace557312>::value,"POD only");
// Config magic A5P1/version1, trace magic A5T1/version1. The child trace HANDLE
// belongs to its own inherited HANDLE table, never compared with caller-table
// numbers. Child FILE_MAP_WRITE view is read/write, not hardware write-only.
// Config is separate and copied from the new fixed-GUID payload only once.
// ABI03: delivery in raw, original SDK return in sdk. Exactly one primary SDK
// invocation per export row; additional SDK operations have closed internal IDs.
enum class InternalOp:u32 {frequency=300,scan_summary=301,payload_framing=302,configuration=303,
 process_id=304,process_times=305,trace_flags_before=306,trace_clear_inherit=307,
 trace_flags_after=308,map_trace=309,close_trace_handle=310,self_module_name=311,
 kernel32_handle=312,kernel32_module_name=313,kernelbase_handle=314,kernelbase_module_name=315,
 ntdll_handle=316,ntdll_module_name=317,resolve_system_filename=318,resolve_ntdll_version=319,
 module_name_after_acquire=320,main_module_handle=321,system_directory=322};
enum TraceFlags:u32 {entered=1,returned=2,error_valid=4,unsupported_delivery=8,input_fault=16,
 diagnostic_failure=32,ordinal_input=64,null_input=128,capture_complete=256,
 clock_unknown=512,late=1024,internal=2048};
enum SdkFlags:u32 {sdk_entered=1,sdk_returned=2,sdk_error_captured=4,sdk_exception=8,
 sdk_clock_unknown=16,sdk_late=32};
enum HeaderState:u32 {bootstrap_failure=1,clock_failure=2,unsupported_seen=4,
 capture_failure=8,reference_uncertain=16,trace_failure=32,concurrent_bootstrap=64};
// Header.claimed is bounded0..256: overflow sets sticky overflow and does not
// advance it. Slot i odd sequence=2*i+1 while pending; complete=2*i+2 after
// release barrier. Header.sequence=2*number of completely committed rows;
// completion order need not equal claim order. Parent reads after known exit.
}
