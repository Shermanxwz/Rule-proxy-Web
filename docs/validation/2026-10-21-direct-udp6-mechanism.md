# Standalone IPv6 UDP mechanism and pure packet contracts

This first slice adds separate UDP6 files only. It does not modify the existing
IPv4 TCP/UDP actors, identity observer, policy, descendant experiment, capture
lifecycle, guest transport, or runtime workflows. It is not a VM experiment.

## Native and hosted boundary

The production actor has a fixed numeric `fec0::2` destination and high port.
The compile-time TEST_ONLY fixture instead targets owned `::1` only. Both use
`AF_INET6` datagrams, set `IPV6_V6ONLY=1` and verify a nonzero Boolean readback, request exclusive binding,
and use fresh nonblocking sockets. There is no IPv4, DNS, address-search, or
default-route fallback. Production identity/profile checks precede Winsock and
socket use. The unchanged identity source supplies those observations.

The private frame is `N0AU6 <nonce> <phase> <index>\n`, at most 128 bytes. Three
selected attempts use the bounded three-second window; ordinary before, sample,
and after phases retain their separately bounded schedules. Send acceptance is
only local API acceptance, not delivery. Exact echoed payload and receiver
observations are separate. A successful API call does not establish isolation.

Hosted Windows executes production only with an invalid CLI. A separate fixture
profile-only entry observes the actual hosted token without networking. All
actual network mechanics use the TEST_ONLY binary and an exclusively owned
IPv6-only loopback responder. A fixture phase named contained is not PSEC.
Unsupported IPv6 or a setup failure is a failed/inconclusive mechanism, not a
reason to fall back. No raw identities, private endpoint data or packet files
are uploaded. The new marker-only workflow uses standard five/eight-minute jobs.

## Pure manifest and decoder

The separate versioned UDP6 manifest binds the fixed runner IPv6 destination,
high port, scope zero, VM MAC, source pins and nonce/payload indices. Pure functions
cannot authenticate those caller-supplied facts. Uninvoked unavailable ports and
typed failed ordinary observations must not erase another bound positive; they
prevent qualifying absence.

The parser checks Ethernet, IPv6 and UDP lengths, with at most eight extension
headers and 256 extension bytes. It does not reassemble fragments. Relevant
fragment, opaque, unsupported or malformed chains prevent an absence conclusion.
It does not authenticate AH, validate checksums, or map guest QPC to PCAP time.
Fully observed selected payloads remain separate from later control, capture or
cleanup failures. Ambiguous/reused ports cannot establish actor attribution.

Future bounded absence requires complete capture through owned QEMU exit,
ordinary guest-to-runner UDP6 payload calibration including a terminal witness,
fresh trusted binding, all selected invocations, and confirmed cleanup. The
existing IPv4 decoder's absence result is never reused for IPv6.

## Unproven guest alias and next boundary

Pinned QEMU defaults and upstream libslirp source suggest the existing user-mode
network may map guest `fec0::2` to runner `::1`; this is feasibility evidence only.
The actually linked libslirp provenance and ordinary guest reachability have not
been observed. Hosted `::1` mechanics do not establish either. Any later guest
integration needs those admissions without changing QEMU arguments, routes,
addresses, firewall, DNS or policy. No descendant, proxy, DNS/broker, universal
egress, Linux-equivalence or product-acceptance claim follows from this slice.

## First hosted result and diagnostic boundary

Run 39661648491 compiled both binaries and passed all 527 required tests on each
platform, but the hosted IPv6 mechanism failed: neither receiver observed a
datagram and no selected send was accepted. All seven child owners, both
receivers and owned work reported successful cleanup. All five network reports
passed their binding/schema checks with process exit zero; this does not make
their network operations successful. The first public projection omitted native
startup and per-attempt failure fields, so the failed stage remains unknown.
This is an inadmissible positive-control mechanism, not evidence of isolation.

The diagnostic follow-up projects only fixed stage/error/setup/send/close fields
from those same validated reports, with a 32 KiB total output bound. It changes
no native parameter, profile guard, endpoint, attempt, deadline or acceptance
condition. Private identities, nonces, addresses, ports, paths and QPC values
remain excluded. A later diagnostic result cannot reconstruct the deleted first
run's private reports or retroactively establish its precise cause.

Run 39663356528 passed both 531-test suites and native builds, then exposed the
readback seam: all 46 attempt rows set IPV6_V6ONLY successfully but failed its
readback check before bind or send. The old report combined a real getsockopt
error with a synthetic returned-length/value rejection under v6only_get/10022;
the diagnostic therefore does not distinguish those causes. Cleanup was
confirmed, but ordinary IPv6 mechanics remained inadmissible.

Microsoft documents IPV6_V6ONLY as a DWORD Boolean: any nonzero value means
IPv6-only. The first correction kept setsockopt's argument 1, the same single
getsockopt call, and an exact DWORD-sized successful read before admitting a
nonzero result. Zero, API error and wrong length remain fail-closed before bind.
Closed return/error/length/value observations distinguish API failure from
validation failure; no IPv4 fallback is introduced. The existing TEST_ONLY
profile-only process checks the shared pure helper against fixed synthetic
cases without sockets. That helper check is not actual Windows API evidence.

Primary contract: [IPPROTO_IPV6 socket options](https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-ipv6-socket-options)
and [getsockopt](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-getsockopt).
The documented semantic correction is not proof that a noncanonical nonzero
value caused either previous failure; that requires actual closed readback data.

Run 39665095939 passed both 538-test suites and native builds. All 46 actual
getsockopt calls succeeded with returned length 1. The full-DWORD gate rejected
that length before bind/send, so the returned Boolean value remained unobserved.
All owned cleanup succeeded. This identifies that job's size-check mismatch,
not either previous job's exact cause, and still supplies no isolation result.

The bounded compatibility correction accepts only successful returned lengths
1 and 4. The same four-byte zeroed storage and single call are retained. Length
1 is decoded from only its returned unsigned byte; length 4 is decoded as a
complete native DWORD via memcpy. All other lengths, API errors and zero values
remain inadmissible. Poisoned unreturned-byte tests ensure length-1 zero cannot
be promoted by upper storage bytes. No socket-option argument, fallback,
additional probe or pre-verification bind/send is introduced.

Microsoft's actual-returned-size and Boolean contracts are corroborated by
[CPython 3.13 socketmodule.c](https://github.com/python/cpython/blob/v3.13.0/Modules/socketmodule.c)
and [.NET 8 Windows SocketPal](https://github.com/dotnet/runtime/blob/v8.0.0/src/libraries/System.Net.Sockets/src/System/Net/Sockets/SocketPal.Windows.cs),
which use zero-initialized integer storage without requiring returned length 4.
Our explicit 1-or-4 rule is narrower than accepting arbitrary returned lengths.
Successful ordinary echo and actual nonzero readback remain required empirical
gates; source compatibility alone does not establish either.
