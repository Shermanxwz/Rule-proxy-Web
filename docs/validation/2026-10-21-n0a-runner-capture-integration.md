# Runner-only capture integration candidate

This code-only, default-disabled extension does not change the actor, policy,
attempt count, ordinary control connections or original Stage0 acceptance. The
legacy route and cleanup behavior remain unchanged when capture is not selected.
No Windows packet result is established by the implementation or its short gates.

## Private evidence, not new native authority

The pinned guest controller hashes the same bounded native report buffer that it
parses. One private bundle contains the four existing runner network records
(before, sampler, contained, after), their original-byte lengths/digests and fixed
binding fields. Token SIDs, PIDs, paths and executor logs are excluded. Every
sampler port is retained. The existing after connection is the terminal witness;
there is no new connection.

A separate versioned capture-result route receives the connect result first,
committing the optional bundle's exact length/digest. The private bundle follows
only within the remainder of the same ten-second reporting allowance. Failed
preparation, missing upload or exhausted time cannot erase the connect result.
The original Stage0 POST remains independent. Legacy schemas are not relaxed.
Duplicate, conflicting, oversized, truncated and late submissions fail closed.

The host supplies run/case nonces, binary/source/build pins, VM MAC and runner
endpoint. It verifies the separately received commitment, rechecks the network
records and QPC controls, and constructs the canonical flow manifest itself.
Report hashes and native token/PID provenance remain pinned-controller
attestations, not independent host observations of raw native reports. Neither
an incoming controls Boolean nor a manifest self-hash establishes authority.

## Lifetime and resources

Capture uses an opt-in filter-dump argument in the original QEMU command, not new
object-add/object-del commands. The owned child is ready before QEMU starts; an
actual PCAP header is required before existing intentional NIC link-up. Capture
continues through owned QEMU exit, including background/payload traffic.

The retained cap is 64 MiB. Admission adds 65 MiB of reserve inside the existing
resource policy and requires `2 * actual_payload_bytes + 16 MiB <= 64 MiB`.
This is planning headroom, not a guarantee against retransmissions/background
traffic. Overflow continues drain/discard and makes capture incomplete. No disk,
live-space, job, work or cleanup budget is relaxed.

One admission-captured monotonic deadline defines work and the original reserved
120-second cleanup interval. Construction, uploads and finalization do not renew
it. The private-upload wait is clipped to both the existing N0a work wait and
capture-result arrival plus ten seconds, never the cleanup reserve. Reads have
an absolute deadline; blocking I/O is not performed under the receiver state lock.

One authoritative stop path handles the same held QEMU process: TERM and bounded
wait, then exact-owned kill fallback. Forced or unconfirmed exit cannot support
absence. The sink stays outside generic helper-first termination, drains FIFO and
stderr to EOF, fsyncs/closes, sends final status and exits before private parsing.
Parsing is tentative until remaining receiver/server/process/socket/work cleanup
is independently confirmed. Unknown cleanup makes absence inconclusive and
retains work that a live resource might access. It does not erase an observed
tuple packet. All shutdown attempts use the original deadline; bounded caller
waits do not guarantee OS calls or process/thread termination.

## Narrow claims

Selected and ordinary ports must be unambiguous across the runner endpoint
lifetime. All ordinary SYN witnesses, including the terminal control, are needed.
Guest QPC is never mapped to PCAP timestamps. Loopback is not seen by this NIC
capture. A selected tuple packet is a byte observation, not automatically an
authenticated actor leak. No selected tuple in a complete capture is not general
no-egress, DNS/IPv6/UDP/proxy/child isolation, supported-build acceptance or Linux
equivalence.

The helper provides same-UID lifecycle/failure separation, not an OS privilege
sandbox or anti-host-root boundary. PCAP and private bundles are not logged or
uploaded. Runtime stays disabled pending exact review, short gates and a separate
activation decision.
