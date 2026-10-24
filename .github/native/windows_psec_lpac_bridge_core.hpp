#pragma once
#include "windows_psec_lpac_bridge.hpp"
#include <limits>

namespace pb {
enum Status : std::uint32_t {
    ok=0, bad_argument=1, bad_state=2, unsupported=3, clock=4,
    deadline=5, api_failed=6, readback_failed=7, cleanup_unknown=8, exception=9
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
    Status begin_arm(unsigned policy, bool same_inputs) noexcept {
        if (!bound || environment!=owned || opaque_unknown || arm_failure
            || arm_attempts!=arm_returns || arm_attempts>=2 || policy!=arm_attempts || !same_inputs)
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
