# Isolated capture worker and pure packet contract (code-only candidate)

This second mechanism slice does not integrate with the Windows guest or direct
host transport. The previously measured owner-thread primitive remains unchanged.
A separate owned worker process isolates blocking capture operations from its
controller's lifecycle handling; this is not reduced-privilege sandboxing.

## Ownership and IPC

The parent alone owns QEMU and sink-worker `Popen` handles. The sink worker does
not receive QEMU control handles or a process-signalling interface. Before spawning,
the parent registers all resource slots, prepares the private root/FIFO, stderr
pipe and local `SOCK_SEQPACKET` socket pair. Descriptor inheritance is explicit:
only the owned root descriptor, stderr reader and child status endpoint go to the
worker. Parent-created socket peer credentials are not asserted to authenticate
the subsequently executed worker PID. Per-message `SO_PASSCRED` / `SCM_CREDENTIALS` instead binds the
exact owned sender PID and its UID/GID. It also distinguishes a credential-bearing
empty record (invalid protocol data) from a credential-free EOF; a first empty
read alone is not proof that no trailing record exists. Both payload and ancillary
truncation, missing/duplicate/unexpected credentials and mismatched senders fail
closed. This is same-UID IPC sender binding, not resistance to a privileged host
attacker or a Windows application isolation result.

Startup order is reader-open notification, parent-only dummy writer, arm command,
ready notification, QEMU start, actual PCAP header, then dummy-writer closure.
Dummy and unrelated control descriptors must not leak into either child. The
parent closes its duplicate pipe/socket ends as soon as ownership transfers.

IPC is a bounded closed-schema protocol, not logs: at most 64 status frames,
2048 bytes each, with duplicate JSON keys, truncation/oversize and non-increasing
sequence numbers rejected. Coalescing permits sequence gaps but cannot erase
cumulative ready/header/error/overflow/EOF facts. No heartbeat loop is needed.
A received final state does not substitute for observing the exact owned worker's
exit. Missing, malformed, stale or incomplete status forbids completeness.

## Shutdown and fault observations

The original absolute cleanup deadline is never renewed. The parent authorizes
normal closure before signalling QEMU, waits at most 15 seconds (shortened to
leave worker cleanup time), then kills only its owned QEMU if needed. The worker
keeps draining through QEMU exit, FIFO/stderr EOF and output fsync/close. A stuck
worker receives bounded termination/kill/reap attempts using the remaining
cleanup budget. This is not a hard bound on OS calls or guaranteed termination;
unknown exit or forced producer closure makes capture incomplete. Confirmed
cleanup may remove owned work even after forced closure; unconfirmed cleanup
requires retaining it.

A fixture-only reader-close command is rejected in ordinary worker mode. In the
actual QEMU fault case, the gate first receives the valid header, closes the sole
FIFO reader while retaining stderr observation, and injects the first packet.
The actual QEMU dump-write error and still-responsive paused QMP are required.
This demonstrates that a broken dump does not itself establish blocked forwarding.
It does not execute a Windows guest or prove guest egress.

## Pure packet/manifest contract

A separate pure module validates bounded private manifests and complete Ethernet
PCAP framing. It receives expected binding and lifecycle/digest evidence as
separate caller inputs; it cannot authenticate their origin. No transport is added
by this slice. Fixed VM MAC, runner destination and source ports define the narrow
tuple scope. Port collision/reuse, missing ordinary SYN witnesses, malformed or
relevant unsupported traffic and incomplete capture make absence inconclusive.
The private flow sequence is the existing before/sample*/after sequence (at most
42 ordinary flows); the existing after connection is the terminal witness. It
does not add a terminal connection or label all sampler traffic as concurrent.
A separately supplied exact-Boolean connect-controls prerequisite is mandatory
for a negative conclusion. Guest QPC is never converted to PCAP time. Positive tuple observations survive
later parsing/completeness failures but are not automatically actor-attributed
leaks. Normal out-of-scope traffic is not silently reclassified as TCP evidence. IPv4
and TCP header-length bounds are checked; option contents and checksums are not
validated, and tuple-byte observations do not establish valid packet delivery.

All candidate results remain separate from original Stage0 and N0a-connect
acceptance. Production integration, full Windows capture, independent PSEC
cleanup, DNS/IPv6/UDP/proxy/child isolation and Linux equivalence are not proved.

The Linux [unix(7) manual](https://man7.org/linux/man-pages/man7/unix.7.html)
documents per-message credentials, the different cached `SO_PEERCRED` semantics,
and credential validation/privileged exceptions. Actual Linux child/socketpair
fixtures are required in addition to that source contract.
