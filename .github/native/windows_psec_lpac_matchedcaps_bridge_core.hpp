#pragma once
#include "windows_psec_lpac_matchedcaps_bridge.hpp"
#include <limits>
#include <array>
#include <algorithm>
#include <cstring>

namespace pb {
enum Status : std::uint32_t {
    ok=0, bad_argument=1, bad_state=2, unsupported=3, clock=4,
    deadline=5, api_failed=6, readback_failed=7, cleanup_unknown=8, exception=9,
    precreate_failed=10
};
enum Operation : std::uint32_t { bind=1, create_environment=2, create_arm=3, close_environment=4, unbind=5 };
enum Environment : std::uint32_t { none=0, create_consumed=1, owned=2, close_consumed=3 };

inline bool valid_plan(const PB_PLAN_V1& p) noexcept {
    constexpr auto max=std::numeric_limits<std::uint64_t>::max();
    if (p.size!=sizeof p || p.version!=1 || !p.frequency || p.frequency>max/120) return false;
    const auto f=p.frequency;
    return p.start_qpc<=max-120*f && p.root_deadline_qpc>p.start_qpc+35*f
        && p.root_deadline_qpc<=p.start_qpc+120*f
        && p.worker_deadline_qpc==p.root_deadline_qpc-5*f
        && p.work_cutoff_qpc==p.root_deadline_qpc-35*f;
}
inline Status timely(const PB_PLAN_V1& p, std::uint64_t actual_f,
    std::uint64_t tick, bool cleanup=false) noexcept {
    if (actual_f!=p.frequency || tick<p.start_qpc) return clock;
    return tick<(cleanup?p.worker_deadline_qpc:p.work_cutoff_qpc)?ok:deadline;
}
inline bool complete_pi(const PB_PI_V1& p) noexcept {
    return p.process && p.thread && p.process!=p.thread && p.process_id && p.thread_id;
}
inline bool empty_pi(const PB_PI_V1& p) noexcept {
    return !p.process && !p.thread && !p.process_id && !p.thread_id;
}

enum Role : std::uint32_t { bootstrap=0, measured_ac=1, measured_lpac=2 };

// Fixed-name capability SID bytes, NOT user/package identity. Agentic's bytes
// are the historical OS DeriveCapabilitySidsFromName(AgenticAppContainer)
// observation pinned in ABI-3's receipt; the Python outer must independently
// derive the same fixed-name catalog on the current host before any runtime.
// PNCS is the documented well-known S-1-15-3-3 capability.
constexpr std::array<std::uint8_t,48> agentic_sid_bytes{{
    0x01,0x0a,0x00,0x00,0x00,0x00,0x00,0x0f,0x03,0x00,0x00,0x00,
    0x00,0x04,0x00,0x00,0xaf,0x2e,0xa0,0x1f,0xa2,0xd1,0xe1,0xb9,
    0xc9,0x13,0x49,0x0d,0x22,0x00,0xf0,0x62,0xd5,0xfd,0x08,0x20,
    0x6a,0xbf,0xee,0x07,0x9a,0x49,0x43,0x51,0x19,0x27,0x70,0xf4}};
constexpr std::array<std::uint8_t,16> pncs_sid_bytes{{
    0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x0f,0x03,0x00,0x00,0x00,
    0x03,0x00,0x00,0x00}};
constexpr std::size_t maximum_sid_bytes=68;
struct SecuritySnapshot {
    std::array<std::uint8_t,maximum_sid_bytes> package{},agentic{},pncs{};
    std::uint32_t package_bytes=0,agentic_bytes=0,pncs_bytes=0;
};
inline bool sid_shape(const std::uint8_t* p, std::uint32_t n,
    std::uint32_t first_subauthority) noexcept {
    if (!p || n<12 || n>maximum_sid_bytes || p[0]!=1 || !p[1] || p[1]>15
        || n!=8u+4u*p[1] || p[2] || p[3] || p[4] || p[5] || p[6] || p[7]!=15)
        return false;
    const auto first=std::uint32_t(p[8]) | std::uint32_t(p[9])<<8
        | std::uint32_t(p[10])<<16 | std::uint32_t(p[11])<<24;
    return first==first_subauthority;
}
inline bool security_input(const PB_SC_INPUT_V3& input, SecuritySnapshot& output) noexcept {
    if (input.size!=sizeof input || input.version!=3 || input.capability_count!=2
        || input.reserved || input.reserved2 || input.agentic_attributes!=4 || input.pncs_attributes!=4
        || input.package_bytes<20 || input.package_bytes>maximum_sid_bytes
        || input.agentic_bytes!=agentic_sid_bytes.size() || input.pncs_bytes!=pncs_sid_bytes.size()
        || !input.package_sid || !input.agentic_sid || !input.pncs_sid
        || !sid_shape(input.package_sid,input.package_bytes,2)
        || !sid_shape(input.agentic_sid,input.agentic_bytes,3)
        || !sid_shape(input.pncs_sid,input.pncs_bytes,3)) return false;
    SecuritySnapshot copy{};
    copy.package_bytes=input.package_bytes;
    copy.agentic_bytes=input.agentic_bytes;
    copy.pncs_bytes=input.pncs_bytes;
    // Copy first: later attribute construction never observes caller buffers.
    std::memcpy(copy.package.data(),input.package_sid,copy.package_bytes);
    std::memcpy(copy.agentic.data(),input.agentic_sid,copy.agentic_bytes);
    std::memcpy(copy.pncs.data(),input.pncs_sid,copy.pncs_bytes);
    if (!sid_shape(copy.package.data(),copy.package_bytes,2)
        || !sid_shape(copy.agentic.data(),copy.agentic_bytes,3)
        || !sid_shape(copy.pncs.data(),copy.pncs_bytes,3)
        || !std::equal(agentic_sid_bytes.begin(),agentic_sid_bytes.end(),copy.agentic.begin())
        || !std::equal(pncs_sid_bytes.begin(),pncs_sid_bytes.end(),copy.pncs.begin())) return false;
    output=copy;
    return true;
}
inline bool same_security(const SecuritySnapshot& a, const SecuritySnapshot& b) noexcept {
    return a.package_bytes==b.package_bytes && a.agentic_bytes==b.agentic_bytes && a.pncs_bytes==b.pncs_bytes
        && a.package==b.package && a.agentic==b.agentic && a.pncs==b.pncs;
}

// Production and fake tests share this once-only authority state machine.
// It does not infer server absence, cancellation, or ownership from failure.
struct Machine {
    PB_PLAN_V1 plan{};
    Environment environment=none;
    bool initialized=false, bound=false, bind_verified=false, opaque_unknown=false;
    bool environment_returned=false, close_invoked=false, close_returned=false;
    bool module_close_attempted=false, module_close_confirmed=false;
    unsigned arm_attempts=0, arm_returns=0;
    bool arm_failure=false;

    Status initialize(const PB_PLAN_V1& p) noexcept {
        if (initialized) return bad_state;
        if (!valid_plan(p)) return bad_argument;
        plan=p; initialized=true; return ok;
    }
    Status begin_environment() noexcept {
        if (!bound || !bind_verified || environment!=none || opaque_unknown) return bad_state;
        environment=create_consumed; return ok;
    }
    Status environment_result(std::int32_t hr, bool nonnull) noexcept {
        if (environment!=create_consumed || environment_returned) return bad_state;
        environment_returned=true;
        if (hr==0 && nonnull) { environment=owned; return ok; }
        if (hr>=0 || nonnull) opaque_unknown=true;
        return hr<0?api_failed:readback_failed;
    }
    Status begin_arm(unsigned role, unsigned policy, bool same_inputs, bool has_security) noexcept {
        if (!bound || environment!=owned || opaque_unknown || arm_failure
            || arm_attempts!=arm_returns || arm_attempts>=3 || role!=arm_attempts
            || policy!=(role==2?1u:0u) || has_security!=(role!=0) || !same_inputs)
            return bad_state;
        ++arm_attempts; return ok;
    }
    Status arm_result(bool returned_true, const PB_PI_V1& pi) noexcept {
        if (!arm_attempts || arm_returns+1!=arm_attempts) return bad_state;
        ++arm_returns;
        if (returned_true && complete_pi(pi)) return ok;
        arm_failure=true;
        // Kernel outputs, including partial ones, remain the caller's cleanup responsibility.
        return returned_true?readback_failed:api_failed;
    }
    // Used only at the two proven attribute-setup failure sites before Create.
    // No API-return fact is manufactured; a nonzero PI can never enter this case.
    Status precreate_result(const PB_PI_V1& pi) noexcept {
        if (!empty_pi(pi)) return bad_state;
        return arm_result(false,pi)==api_failed?precreate_failed:bad_state;
    }
    Status begin_close(bool owned_job_empty) noexcept {
        if (environment!=owned || opaque_unknown || close_invoked
            || arm_attempts!=arm_returns || !owned_job_empty) return bad_state;
        environment=close_consumed; close_invoked=true; return ok;
    }
    void end_close() noexcept { close_returned=true; }
    bool can_unbind() const noexcept {
        return bound && !opaque_unknown && environment_returned== (environment!=none)
            && (environment==none || (environment==create_consumed && environment_returned)
                || (environment==close_consumed && close_returned))
            && !module_close_attempted;
    }
};
}
