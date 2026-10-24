#pragma once
#include <cstdint>
#include <cstddef>
// Source-only parent helper. It does not admit a process, own a HANDLE,
// enforce an epoch, authorize Resume, or establish cleanup. The future owner
// must bind the retained process/current token/SD/both Jobs and original
// deadline before and after this synchronous, non-interruptible helper.
namespace a4payload {
constexpr std::uint32_t config_bytes=2048;
enum Flag:std::uint32_t {entered=1,returned=2,error_valid=4,input_fault=8,exception=16};
struct Result32 {
 std::uint32_t size,version,flags,error;
 std::uint64_t raw_pointer;
 std::uint32_t seh_code,reserved;
};
static_assert(sizeof(Result32)==32&&alignof(Result32)==8&&offsetof(Result32,raw_pointer)==16,"payload receipt");
}
