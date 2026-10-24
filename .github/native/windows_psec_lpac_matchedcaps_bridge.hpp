#pragma once
// ABI-3 matched-capabilities CPSE identity bridge. No process is ever resumed by this module.
#include <cstddef>
#include <cstdint>
#if defined(_WIN32)
#define PB_CALL __stdcall
#if defined(PB3_BUILD_DLL)
#define PB_EXPORT extern "C" __declspec(dllexport)
#else
#define PB_EXPORT extern "C"
#endif
#else
#define PB_CALL
#define PB_EXPORT extern "C"
#endif

struct alignas(16) PB_CONTEXT_V1 { unsigned char storage[512]; };
struct PB_PLAN_V1 {
    std::uint32_t size, version;
    std::uint64_t frequency, start_qpc, root_deadline_qpc;
    std::uint64_t worker_deadline_qpc, work_cutoff_qpc;
};
struct PB_CHILD_V1 {
    std::uint32_t size, version, policy, reserved;
    std::uint64_t job;
    const std::uint16_t* image;
    std::uint32_t image_units;
    const std::uint16_t* inputs_directory;
    std::uint32_t inputs_units;
    const std::uint16_t* system_root;
    std::uint32_t system_root_units;
    const std::uint16_t* local_appdata;
    std::uint32_t local_appdata_units;
};
// Caller supplies these borrowed buffers; native copies validated SID bytes into
// its context before constructing attributes. No caller SID pointer survives a call.
// Agentic and PNCS positions are fixed; count is exactly two, attributes exactly 4.
struct PB_SC_INPUT_V3 {
    std::uint32_t size, version, capability_count, reserved;
    const std::uint8_t* package_sid;
    std::uint32_t package_bytes, reserved2;
    const std::uint8_t* agentic_sid;
    std::uint32_t agentic_bytes, agentic_attributes;
    const std::uint8_t* pncs_sid;
    std::uint32_t pncs_bytes, pncs_attributes;
};
struct PB_PI_V1 {
    std::uint64_t process, thread;
    std::uint32_t process_id, thread_id;
};
struct PB_RESULT_V1 {
    std::uint32_t size, version, operation, wrapper_status;
    std::uint32_t api_entered, api_returned, hresult_valid;
    std::int32_t hresult;
    std::uint32_t win32_error, within_deadline;
    std::uint64_t before_qpc, after_qpc;
    std::uint32_t environment_state, opaque_outcome_unknown;
    std::uint32_t close_invoked_once, close_returned_normally;
    std::uint32_t module_close_attempted, module_close_confirmed;
    std::uint64_t support_flags;
    std::uint32_t schema_major_available, schema_minor;
};
static_assert(sizeof(void*) == 8, "Only the x64 ABI is supported");
static_assert(sizeof(PB_CONTEXT_V1) == 512 && alignof(PB_CONTEXT_V1) == 16);
static_assert(sizeof(PB_PLAN_V1) == 48 && offsetof(PB_PLAN_V1, frequency) == 8);
static_assert(sizeof(PB_CHILD_V1) == 88 && offsetof(PB_CHILD_V1, job) == 16);
static_assert(offsetof(PB_CHILD_V1, image) == 24 && offsetof(PB_CHILD_V1, local_appdata_units) == 80);
static_assert(sizeof(PB_SC_INPUT_V3) == 64 && alignof(PB_SC_INPUT_V3) == 8);
static_assert(offsetof(PB_SC_INPUT_V3, package_sid) == 16 && offsetof(PB_SC_INPUT_V3, package_bytes) == 24);
static_assert(offsetof(PB_SC_INPUT_V3, agentic_sid) == 32 && offsetof(PB_SC_INPUT_V3, agentic_attributes) == 44);
static_assert(offsetof(PB_SC_INPUT_V3, pncs_sid) == 48 && offsetof(PB_SC_INPUT_V3, pncs_attributes) == 60);
static_assert(sizeof(PB_PI_V1) == 24 && offsetof(PB_PI_V1, process_id) == 16);
static_assert(sizeof(PB_RESULT_V1) == 96 && offsetof(PB_RESULT_V1, before_qpc) == 40);

PB_EXPORT std::uint32_t PB_CALL pb_abi_version() noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_build_spec(const std::uint16_t*, std::uint32_t,
    std::uint8_t*, std::uint32_t, std::uint32_t*) noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_verify_spec(const std::uint8_t*, std::uint32_t,
    const std::uint16_t*, std::uint32_t) noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_bind(PB_CONTEXT_V1*, const PB_PLAN_V1*, PB_RESULT_V1*) noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_create_environment(PB_CONTEXT_V1*, const std::uint8_t*,
    std::uint32_t, const std::uint16_t*, std::uint32_t, PB_RESULT_V1*) noexcept;
// role 0=bootstrap: policy 0, SC null. role 1=measured AC: policy 0, SC required.
// role 2=measured LPAC: policy 1, byte-identical SC required. Order is once-only.
// External owner must independently admit suspended bootstrap/arms; this DLL
// neither grants admission nor assigns a Job or resumes any process.
PB_EXPORT std::uint32_t PB_CALL pb_create_matched_child(PB_CONTEXT_V1*, const PB_CHILD_V1*,
    std::uint32_t role, const PB_SC_INPUT_V3*, PB_PI_V1*, PB_RESULT_V1*) noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_close_environment(PB_CONTEXT_V1*, PB_RESULT_V1*) noexcept;
PB_EXPORT std::uint32_t PB_CALL pb_unbind(PB_CONTEXT_V1*, PB_RESULT_V1*) noexcept;
