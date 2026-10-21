# Serviced Stage0 advisory COM2 candidate

Code-only diagnostic instrumentation. Attempt 08 produced no guest HTTP result
before the existing host deadline; cleanup was confirmed. The missing result does
not establish which servicing, startup or login transition stopped. This candidate
is not a servicing fix, runtime success, or evidence that AutoLogon was exhausted.

## Isolation from control and acceptance

COM1 readiness/failure protocol is unchanged. COM2 uses a separate fixed 65,536-byte
QEMU ring buffer and a separately owned local diagnostic QMP monitor. Its records
are unauthenticated, incomplete, advisory observations only. They never enable the
NIC, switch media, establish identity/provenance, satisfy acceptance, or extend a
deadline. Host history retains the first 32 valid records, never overwrites them,
and independently bounds malformed input and later discard accounting.

The exact ASCII record is `RPS2 {v,s,p,m,n,f}` with all six keys and at most 256
bytes. Role/stage pairs are fixed. `m` is 0..7 only when all three existing pending
source observations are strict booleans; otherwise null. `n` is strict integer
0/1 or null. `f` is an existing closed servicing failure label or null. Irrelevant
fields are null. No raw registry contents, boot witness, identity, path, arbitrary
exception or command argument is emitted. `*_reboot_returned` means the restart
API returned, not that a new boot occurred. Ordinary `report_attempt` can retain
closed observed service cause; it does not assert successful HTTP delivery.

## Guest sender and quota

Setup installs a fixed PowerShell helper in the existing protected updater
folder: trusted SYSTEM/Administrators ownership and writes, Users read/execute,
no reparse point. The worker/launcher verifies these protections before loading
or launching it. A same-token child receives only fixed validated arguments; no
new task, account, privilege grant or arbitrary payload path is added. SYSTEM
cannot select the ordinary user's quota root.

The cooperative parent wrapper reserves a zero-byte fixed-name CreateNew slot
before Process.Start: 20 SYSTEM slots in the protected updater directory, 12
ordinary slots in the existing user workspace. Slots persist across boots and are
not refunded on spawn failure. Exhaustion means no child process. This bounds
legitimate wrapper attempts, not malicious direct helper invocations, ordinary
slot deletion, or other serial writers; host ring/history limits are independent.
The child revalidates its role and trusted helper but does not consume a second
quota. No heartbeat or sender retry exists.

Serial Open/Write/Dispose occur only in the child. The parent waits at most 3
seconds, attempts to kill only that exact owned Process handle once if needed,
then waits 1 second to observe exit. Unknown exit/disposal disables subsequent
telemetry in that invocation, not the legitimate servicing operation. The nominal
32 attempts therefore have at most 128 seconds of explicit wait budgets, consumed
within existing absolute deadlines. Process.Start/Kill/Dispose and filesystem OS
calls are not claimed to have hard syscall bounds; the unchanged outer owned-VM
teardown remains the ultimate bound. Pre-restart telemetry precedes a fresh check
of the existing absolute deadline/reserve, never a renewed timer.

## Gate coverage and remaining limits

The dedicated Windows compile fixture executes production projection, role guards,
quota, process-wait and restart-reserve helpers. It tests all pending masks, unknown
redaction, strict field types and actual PS ASCII output through the Python host
parser. Owned temporary ACL/files test trusted ownership, untrusted-write rejection,
reparse rejection, durable exhaustion across local resets, and no quota refund on
spawn failure. Explicit trusted fixture ownership is not proof of SYSTEM's natural
file owner or ordinary-token access.

Port Open/Write/Dispose failures are mocked without accessing serial hardware.
Actual same-token owned child fixtures cover normal exit and timeout followed by
exact-child termination, with an independent retained process handle verifying
exit. No actor, account, task, registry or clock is changed. Child stdout/stderr are
never published. Exact fixture files/processes are cleaned up; diagnostic quota
slots in the disposable guest intentionally survive until VM destruction.

The original optical-media QMP gate remains paused. The separate dual-monitor
gate briefly executes packaged default firmware via cont/stop, without Windows,
installation media, networking or KVM. Malformed/timeout cases inject faults at
the diagnostic receive boundary while an actual second QMP connection exists;
they do not claim QEMU itself emits malformed replies. Neither gate nor Windows
helper fixtures demonstrate actual Windows COM2
mapping/access, guest servicing progress, further login, successful restart, or
native isolation. Those remain runtime-unproven. Policy, acceptance, AutoLogon,
resource limits and the original job/host/guest deadline chain are unchanged.
