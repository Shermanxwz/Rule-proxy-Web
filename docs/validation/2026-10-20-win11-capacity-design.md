# Windows client capacity investigation and disabled stock trial

Status: code/review only. Neither cache removal, stock VM execution, Compact OS,
nor a lower serviced-lab threshold is authorized by this document. Existing
serviced 26200.9711 flow and its 55 GiB gate are unchanged. Stock draft host,
workflow job and provider recovery helper are independently disabled.

## Measured capacity

Preflight run 39373913151 measured total 76,887,154,688 bytes and free
14,078,107,648 bytes across the four fixed labels on the same filesystem.
KVM API 12 was available. Inventory run 39374582044 observed allocated bytes:
Android 11,838,296,064; .NET 6,167,728,128; Swift 3,710,971,904.
Their sum is 21,716,996,096. Adding that optimistic sum to the earlier free
measurement gives 35,795,103,744 bytes (33.34 GiB), not guaranteed reclaim or
contemporaneous available space. No subset meets the existing 55 GiB gate.
No deletion has been performed by this implementation worker.

Inventory image was ubuntu24 / 20261018.339.1. Publisher resolved official image
tag ubuntu24/20261018.339 to b4067e48bd9bd803e958bfe1503ea0a06a3a127f and verified
that the three installer scripts are byte-identical to previously reviewed
7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe. This does not prove current tree contents
or reclaimability. Old reports are not rewritten. Example provenance:
https://github.com/actions/runner-images/blob/b4067e48bd9bd803e958bfe1503ea0a06a3a127f/images/ubuntu/scripts/build/install-android-sdk.sh

## Existing serviced flow lifetimes

Pinned media source:
https://github.com/Shermanxwz/Rule-proxy-Web/blob/3e90bb1f129a7d08b85fb816c7c70ba4f346ee66/.github/windows_vm_test.py

- Original official 25H2 Enterprise Evaluation ISO: 7,092,807,680 bytes;
  build 26200.6584; SHA256
  a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9.
- Checkpoint KB5043080: 533,761,740 bytes; target KB5127648:
  4,775,050,195 bytes. Total 5,308,811,935 bytes (4.94 GiB).
- Current full extraction and full remaster coexist with source ISO and host
  MSUs until remaster completes. Extraction and remaster allocated sizes were
  not measured. MSUs are NOT embedded into the DVD; only a manifest and worker.
- Host MSUs remain until teardown. Guest downloads each through a temporary
  file then same-volume rename, retains both, and revalidates them across
  restart before declaring servicing complete. No successful-MSU deletion exists.
- Historical guest allocation 24,953,077,760 bytes already includes retained
  guest MSUs. This observation is NOT a future upper bound, nor is subtracting
  MSU bytes a proved stock-install peak.
- Runtime downloads/build caches, runtime ZIP, payload ZIP, guest copies and
  expanded runtime coexist. These auxiliary sizes were not historically measured.
  NVRAM, TPM, filesystem metadata and guest pagefile/servicing scratch add costs.

Worker source:
https://github.com/Shermanxwz/Rule-proxy-Web/blob/3e90bb1f129a7d08b85fb816c7c70ba4f346ee66/.github/windows-vm-update.ps1

## Disabled stock experiment: exact scope and phases

Use the SAME original pinned 26200.6584 ISO with a tiny separate read-only seed
ISO. This is not the old 26300.9457 test and not serviced 26200.9711. No MSU
fetch, update manifest, servicing task or Compact OS is used. Existing normal
Setup, one ordinary RuleProxyCI Users account, ordinary Startup, inherited
BypassNRO/NoAutoUpdate guest policies and exact zero-network actor are preserved.
The test submits the exact Stage0 deny-only request and reports unsupported or
failure honestly; prior broad hostLoopback=allow rejection proves nothing about
this request. Actual guest registry build/UBR must equal 26200.6584 and are
exported only through the closed projection.

Microsoft documents separate read-only removable media answer-file discovery:
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-setup-automation-overview?view=windows-11
Existing specialize scans D through J for the seed setup script. No third-party
driver ISO is introduced. Original installer remains attached throughout this
first conservative draft; there is NO assumed reclaim from ejecting it.

Proposed phases, subject to final review and separate execution decision:

1. Before checkout, exact frozen recovery helper checks fresh hosted-runner
   context, exact image and fixed provider roots. It remains hard-disabled.
   No generic directory deletion or alternate-target fallback is allowed.
2. Checkout, apt VM tools, pinned G artifact, actor and runtime package build
   complete BEFORE fresh premedia free-space measurement. Package dependencies
   are the existing requirements, not an added tool stack. Pre-existing artifacts
   are already charged against measured free space, not counted twice.
3. Require 32 GiB free. Download exact ISO under its byte-size file limit and
   verify hash. Build payload from size-bounded sources (package <=128 MiB,
   actor <=16 MiB, bundle archive/expansion <=64 MiB); output <=256 MiB.
   Seed ISO is capped at16 MiB. No full ISO extraction/remaster exists.
4. Create qcow2 with explicit preallocation=off, 80 GiB virtual capacity.
   Require a NEW launch sample >=24 GiB. Start QEMU with fixed18 GiB
   RLIMIT_FSIZE and core dumps disabled. This ceiling never increases if media
   later becomes unnecessary. A small-cap installation may abort; fit is not
   asserted. Nominal remaining allocation margin is >=6 GiB, of which4 GiB is
   the measured stop threshold; other files/metadata use the difference.
5. A dedicated0.2-second watcher samples free bytes and SIGKILLs only owned
   QEMU/TPM on reserve breach or measurement failure. Registration is locked:
   a process registered after a trip is immediately killed. Ringbuf serial is
  64 KiB in memory; no screenshots, growing serial log, raw reports or MSUs.
   HTTP has one bounded16 KiB result in memory and writes no guest report files.
6. Stop and wait owned processes; stop watcher before deleting owned work.
   Every capacity trip/file-limit signal/watch uncertainty revokes success,
   including a trip concurrent with result arrival. Report observed minimum
   free bytes, stop cause and cleanup confirmation; no product/privacy acceptance.

## Guard semantics and remaining review limits

RLIMIT_FSIZE is a PER-FILE logical extension limit, not an aggregate filesystem
quota. It covers the owned qcow image and QEMU NVRAM writes, not another process.
The copied NVRAM is fixed firmware-sized; QEMU has no writable snapshots/other
images/logs. TPM has its own8 MiB per-file limit and core0; its expected small
state/lock files remain an independent writer. Reports/seed/payload have explicit
bounds, and apt/build/download work is finished before VM launch.

Linux documented limit behavior:
https://man7.org/linux/man-pages/man2/getrlimit.2.html
https://man7.org/linux/man-pages/man2/fallocate.2.html

Neither file limits nor polling guarantee against external provider writes,
filesystem allocation beyond EOF/preallocation, metadata amplification or delayed
scheduler execution. The code reports reserve_guard_hard_guarantee=false.
Review must accept this conservative abort experiment or require a stronger
verified storage boundary; do not disguise this limitation as a proven quota.
No guest-throughput throttle is claimed to bound qcow metadata allocation.

No fit proof exists at current13.11 GiB free. The hypothetical three-root total
may fail either fresh gate after actual reclamation and tool/package overhead;
then the job stops without a VM. All three roots are only conditional candidates,
not a cleanup authorization or promise of32 GiB. Main/user devices/paid capacity
remain untouched. The serviced55 GiB gate remains unchanged.

## Alternatives not implemented

Phased normal Setup could detach installer only after verified installed-OS and
seed-copy completion, verified QMP backend close, then unlink it; unlinking an
open ISO does not reclaim allocation. Host MSU deletion would need an explicit
verified guest receipt/retry protocol; guest deletion cannot count as host
reclaim without discard evidence. QEMU reference:
https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html

Microsoft supports Compact via Setup OSImage/Compact or DISM /Apply-Image /Compact:
https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/compact-os?view=windows-11
Its published savings table concerns Windows10 1607, not this build. No measured
26200.9711 saving, servicing peak or PSEC equivalence is established. Direct WIM
application would add provisioning variables and is not needed for tiny seed media.

## Review corrections: cancellation and activation

The native workflow starts one absolute deadline in its first step: 6,900 seconds
from that step, leaving five minutes before the 120-minute Actions job limit.
Every preparation step has a fresh remaining-budget check and a timeout no longer
than eight minutes or the remaining deadline minus180 seconds. The host receives
an absolute deadline also shortened to30 seconds before its own step timeout;
its work alarm stops120 seconds before that deadline. The host maximum remains
6,600 seconds but is reduced by time already spent on preparation. Cleanup and
uploads therefore do not rely on a fresh112-minute allowance after preparation.

Finalization catches process-exit/kill races and continues independent teardown.
The watcher is closed once after owned process stop attempts; a still-live watcher
or uncertain watcher stop prevents private-directory deletion. A capacity trip
concurrent with result arrival revokes success. Cleanup uncertainty independently
revokes success and remains visible even if a capacity abort also occurred.

The workflow has exact experimental-branch push/path filters and the distinct
[identity-stock-stage0-runtime] intent marker, but its compile condition remains
false. A later approved activation must preserve branch/event/marker predicates,
not replace the condition with unconditional true. Main is never needed for
branch push activation. Runtime and recovery source enablement remain separate
explicit review decisions. Pure tests patch disabled state rather than demanding
that future approved production source stay disabled forever.
