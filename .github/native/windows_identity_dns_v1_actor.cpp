// Ordinary same-API DNS mechanism only. Must be launched by the supervised
// owner. This actor changes no DNS settings and does not use REQUEST3.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#define RULEPROXY_IDENTITY_ONLY 1
#define wmain UnusedDnsIdentityEntry
#include "windows_identity_actor.cpp"
#undef wmain
#include "windows_identity_dns_v1_probe.hpp"
#include <cstdio>

namespace {
bool DnsDecimal(const wchar_t* value, std::uint64_t& number) {
    if (!value || !*value || *value == L'0') return false;
    number = 0;
    unsigned count = 0;
    for (; *value; ++value) {
        if (++count > 19 || *value < L'0' || *value > L'9') return false;
        const auto digit = static_cast<std::uint64_t>(*value - L'0');
        if (number > (0x7fffffffffffffffULL - digit) / 10) return false;
        number = number * 10 + digit;
    }
    return number != 0;
}
const char* DnsBool(bool value) { return value ? "true" : "false"; }
int DnsMain(int argc, wchar_t** argv) {
    if (argc != 5) return 2;
    std::string id;
    std::uint64_t frequency = 0, deadline = 0, port = 0;
    if (!ReadNonce(argv[1], id) || !DnsDecimal(argv[2], frequency) ||
        !DnsDecimal(argv[3], deadline) || !DnsDecimal(argv[4], port) ||
        port < 49153 || port > 65535) return 2;
    const auto identity = ObserveNativeIdentity();
    if (!identity.errors.empty() || !identity.tokenElevated.has_value() ||
        identity.tokenElevated.value() || !identity.tokenIsAppContainer.has_value() ||
        identity.tokenIsAppContainer.value() || !identity.isProcessInJob.has_value() ||
        !identity.isProcessInJob.value() || !identity.tokenCapabilities.empty()) return 4;
    const auto result = ruleproxy_dns_v1::query(id, static_cast<unsigned short>(port),
                                               frequency, deadline);
    const auto native = MakeReport("actor", id, identity, std::nullopt, std::nullopt);
    const std::string output = "{\"schema_version\":1,\"stage\":\"dns-v1-native\",\"identity\":" +
        native + ",\"qpc_frequency\":" + std::to_string(frequency) +
        ",\"deadline_qpc\":" + std::to_string(deadline) +
        ",\"result\":{\"configured\":" + DnsBool(result.configured) +
        ",\"called\":" + DnsBool(result.called) +
        ",\"completed\":" + DnsBool(result.completed) +
        ",\"pending\":" + DnsBool(result.pending) +
        ",\"answer_match\":" + DnsBool(result.answer_match) +
        ",\"records_released\":" + DnsBool(result.records_released) +
        ",\"context_retained\":" + DnsBool(result.context_retained) +
        ",\"within_deadline\":" + DnsBool(result.within_deadline) +
        ",\"api_status\":" + std::to_string(result.api_status) +
        ",\"query_status\":" + std::to_string(result.query_status) +
        ",\"record_count\":" + std::to_string(result.record_count) +
        ",\"start_qpc\":" + std::to_string(result.start_qpc) +
        ",\"end_qpc\":" + std::to_string(result.end_qpc) + "}}";
    if (output.size() > 8192 || std::fwrite(output.data(), 1, output.size(), stdout) != output.size() ||
        std::fflush(stdout) != 0) return 3;
    // A completed API failure is valid mechanism evidence, not process failure
    // or denial/isolation qualification. The owner independently grades it.
    return result.called && result.completed && !result.pending ? 0 : 5;
}
}
int wmain(int argc, wchar_t** argv) {
    try { return DnsMain(argc, argv); } catch (...) { return 6; }
}
