# N0a capture mechanism: standalone validation first

This candidate adds only a private bounded capture sink and synthetic producer/QEMU
lifecycle gates. It is not integrated into the direct Windows runtime and does not
change the actor, policy, existing connect verdict, or strict Stage0 result.
No packet-egress conclusion follows from these gates.

The closed output identifies `execution_model=owner_threads`.
The first primitive runs FIFO and stderr drainers as two owner-process threads,
not a separate sink subprocess. Its completion report distinguishes their stopped
state from the owned QEMU process exit. Future production isolation/teardown
integration is not supplied or proven by this standalone thread-based gate.
Before production integration, the agreed owned-child isolation, bounded status
transfer, child kill and observed exit contract must be implemented and separately
reviewed. The short CI timeout is not a Windows-VM helper runtime boundary.

## Proposed production boundary

A future explicitly reviewed capture adapter would add `filter-dump` to the
original QEMU argv, bound to `vmnet`, `queue=all`, `status=on`, and `maxlen=262144`.
There is no object-add/object-del protocol. An owned FIFO reader must be ready
before QEMU starts; the complete PCAP header must be observed before intentional
link-up. Capture includes boot/background traffic and payload transfer and stays
attached through confirmed owned QEMU exit.

The retained private file cap is 64 MiB. This is not a bound on total traffic.
Overflow is permanent evidence of incompleteness: keep draining and discarding
while the owner stops its own QEMU. Never stop reading at the cap and thereby
manufacture blocked networking through FIFO backpressure. QEMU's `maxlen` is a
per-packet snap length, not a total cap. Truncated records or packets cannot support
an absence conclusion.

QEMU can close a failed dump while continuing networking. Therefore FIFO EOF alone
is insufficient: a bounded stderr observer must also reach EOF without a dump-write
failure. Raw stderr and PCAP stay private. Reader, writer, flush/fsync, process,
thread, descriptor and owned-work cleanup outcomes are separate facts. Unknown
cleanup retains owned work and cannot become successful capture completion.

Only a future capture opt-in may use SIGTERM followed by at most 15 seconds of
observed exit waiting, clipped to the existing cleanup deadline. Kill fallback is
mandatory but makes capture incomplete. Legacy direct teardown remains unchanged.
The sink must outlive QEMU, drain EOF, flush/fsync, close and exit before private
work deletion; generic helper-first termination must not kill it prematurely.

## Capacity and later attribution (not implemented by this slice)

The proposed admission checks actual built payload P with `2*P + 16 MiB <= 64 MiB`
and separately reserves the complete capture cap plus bounded metadata inside
existing free-space constraints. The formula is planning headroom, not a guarantee
against retransmission/background traffic. Larger payloads decline capture
admission; no existing payload, disk, job or financial limit is widened.

Later tuple attribution requires a private bounded flow manifest, fixed VM MAC and
runner destination, and observed uniqueness/disjointness of contained and all
ordinary source ports. It must not map guest QPC to PCAP timestamps. Reuse or
ambiguity is inconclusive. Ordinary SYN witnesses, including a terminal control,
are necessary; an empty or broken trace never establishes denial. A matching tuple
packet is preserved as an observation even if later completeness fails, but is not
automatically attributed to the actor. Guest loopback is not observable here.

## Gate claim limits

Fake producers test exact cap, continued draining after overflow, malformed data,
I/O faults and owned cleanup. The tiny QEMU gate must verify actual version 8.2.2,
FIFO/header and termination/EOF behavior. Synthetic socket-backend ingress is only
ingress evidence; it is not proof of the Windows guest's egress filter path.
No Windows image, account, KVM, external endpoint, deployable artifact upload or
full guest runtime is part of this mechanism gate. Native/runtime integration and
packet attribution require a separate review after these gates.

## Pinned implementation references

- [QEMU 8.2.2 dump implementation](https://github.com/qemu/qemu/blob/v8.2.2/net/dump.c):
  per-packet snap length, PCAP writes and disabling dump after write failure.
- [QEMU 8.2.2 signal handling](https://github.com/qemu/qemu/blob/v8.2.2/os-posix.c)
  and [run-state cleanup](https://github.com/qemu/qemu/blob/v8.2.2/system/runstate.c):
  SIGTERM requests shutdown; actual exit/EOF remains a gate observation, not an
  assumption derived from source alone.

Selector polling, process waits and joins use finite waits. Process creation,
filesystem writes/fsync and OS close operations are not claimed to have a hard
per-call execution-time guarantee. The existing bounded CI job is the ultimate
containment for this standalone mechanism test; no Windows VM deadline is changed.
