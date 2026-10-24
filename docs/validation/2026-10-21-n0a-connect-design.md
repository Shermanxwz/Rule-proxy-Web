# N0a-connect: bounded IPv4 TCP connection diagnostic (candidate)

This is a new, separately named experiment, not a revised Stage0 pass. No native
VM execution is authorized by this document. The original direct attempt04
report remains failed because `capabilities_empty` is false.

## Observed prerequisite, not an authority claim

Run 39556001903 on exact Windows 26300.9457 observed one capability whose SID
matched the native fixed catalog entry `AgenticAppContainer`, attributes 0x4.
The sampled ordinary controller token had no capabilities; all other known,
unknown, invalid and duplicate counts were zero. The pinned G request supplied
no capability string to PSEC. That does not specify the final Windows token's
defaults or the capability's full authority. The fallback backend also adds this
capability, so the label is not a unique BaseContainer witness.

The proposed `psec-agentic-only-26300.9457-observed-v1` prerequisite requires
fresh observations in the actual new network-capable actor, exact native SID
comparison and attributes 0x4, source empty, complete catalog, all non-capability
identity checks, request-aware BaseContainer selection and actual pinned-G tier
without fallback. Prior IdentityOnly execution does not certify this new binary.
The new build binds both the unchanged identity helper source and new actor
source. Ordinary source observations are a snapshot, not continuous inheritance
proof. The existing default-compartment prerequisite is observed by the
controller, not independently re-observed by the new actor. No compartment
mutation or new reserved compartment API is introduced. The build remains below the current 26300.9550 documented support floor.

## Narrow question and controls

Can the contained actor complete a fresh, explicitly bound IPv4 TCP connection
to either of two live owned fixtures under the unchanged deny/deny policy?

- Guest fixture: 127.0.0.1, fresh ephemeral port.
- Runner fixture: owned 127.0.0.1 listener reached through existing 10.0.2.2 NAT alias.
- No DNS, proxy, forwarding, private-network capability, allow rule, firewall
  mutation, extra account, inherited pipe, public destination or user credential.
- Listeners exchange only a bounded fresh nonce/endpoint/role ASCII frame; no
  arbitrary request, redirect or user data is accepted.

Each contained case uses three fresh sockets, starts scheduled at 0/500/1000 ms
from one captured window origin, one-second per-connect cap clipped to the
original three-second absolute deadline. Late/unattempted cases are incomplete,
not presumed denied. The window ends at actual final-attempt completion, never
padded to include later positive controls. Token prerequisite validation occurs
before socket use in that same contained process.

The same binary runs an ordinary sampler: at most 40 fresh connections and nonce
exchanges across one fixed ten-second deadline, at 250 ms cadence. Existing
connections alone are insufficient controls. Successful fresh samples must
finish before the contained window, lie entirely inside it, and start after it,
using strictly validated same-guest QPC intervals/frequency. These controls prove
window overlap, not microsecond syscall simultaneity or continuous availability.
PSEC startup outside sampler coverage is inconclusive; sampling is not renewed.
Both endpoints require their own complete controls.

## Adjudication and limits

- Any provenance-bound contained connection success is a boundary-test failure,
  even if subsequent nonce exchange fails. Cleanup status is separate and must
  not erase this observation.
- Only three actual explicit Winsock WSAEACCES 10013 denials plus all exact-profile,
  freshness, endpoint, positive-control and cleanup prerequisites may yield
  `observed_connect_denial` for that endpoint.
- Pending WSAEWOULDBLOCK is not denial. Refusal, unreachable, timeout, failed
  setup/query, missing report, bad nonce, invalid timing or missing control is
  inconclusive. Missing evidence never becomes negative evidence.
- `packet_egress_tested=false`: this slice has no packet capture. It cannot exclude
  SYN-only or other packet emission. No full N0a, no-egress, network-isolation,
  Linux-equivalence, privacy or product acceptance is claimed.
- Unbound TCP, IPv6, UDP, DNS, proxy identity, child/broker escape, failure after
  proxy death and unrelated-application networking remain untested.

Private actor reports are separately bounded to 32 KiB; public output is a strict
closed N0a projection, not an addition to the nearly full 16 KiB Stage0 transport.
Raw SIDs, local tuples, paths and arbitrary exception text are not published.
Ownership and observed closure/exit are separately recorded; actor-reported
socket closure is distinguished from independently observed owned-process,
thread and VM teardown. Unknown cleanup cannot pass. Existing VM/job deadlines remain outer
containment. `stage0_passed=false`, `product_acceptance=false` and
`psec_cleanup_independently_verified=false` remain distinct from owned VM cleanup.

## Required gates before any runtime decision

Independent architecture and exact-source review; pure evaluator tests covering
all false/inconclusive/success-dominance branches; actual Windows compilation and
ordinary fresh-connect positive controls; native argument, profile-before-socket,
deadline, parser and cleanup negative controls. Fixture substitutions must be
explicitly labeled and cannot be presented as AppContainer enforcement evidence.
Then review minimal direct-host integration and a separately authorized runtime.

Hosted Windows runners may be administrative. The production ordinary-token
gate must reject that context; positive Winsock mechanics may instead be tested
by a separately compiled, explicitly nondeployable fixture binary. Such a seam
is compile-time only, never a production command-line bypass. Its output and
manifest must be distinct and excluded from actor artifacts and guest payloads;
it must not replace the production digest or build outputs. Those fixture
positives are not genuine ordinary-token or PSEC enforcement evidence.

## Opt-in adapter design and explicit runtime gate

The original IdentityOnly executable, original Stage0 result and 16 KiB transport
remain separate. In the opt-in path the launcher starts one 120-second monotonic
work budget before the original child, delivers the original result first, then
runs a separate N0a controller only with remaining work time minus a 20-second
cleanup/transport reserve. It passes the absolute same-guest QPC deadline and
frequency; startup cannot renew the budget. Non-opt-in behavior is unchanged.

The existing original-result POST has its own prior bounded transport behavior.
If work is exhausted, no N0a child or probe starts; one reporting-only POST may
spend at most 10 seconds delivering `work_budget_exhausted`. This is not a new
work budget. The total protocol is therefore not claimed to finish in 120 seconds.
The host retains the original receipt immediately and waits for the independent
N0a receipt only until the earlier of its unchanged outer work deadline or
120 seconds after the original receipt. Missing optional evidence is inconclusive,
not a reason to erase original diagnostics or wait the entire VM budget.

The N0a public transport has a separate 4096-byte cap; private actor reports keep
their 32 KiB cap. Host validation binds the expected fresh case nonce, exact
production executable/manifest/source hashes and build; exported evidence removes
nonce and private identities. The seed/config root is ordinary-user writable,
not SYSTEM-protected. No new ACL or privilege claim is made.

Contained PID correlation uses only the pinned executor's dedicated `--log-file`
structured `mxc.ProcessExited` event. The verified one-shot path waits the actual
child handle, queries its exit code, and writes that JSON event in one logger
call. The exact backend/tier/identity are `processcontainer`, `base-container`,
and `redacted`. Identity is not a per-run nonce. The fresh bounded log lives
outside actor filesystem grants and is not among its explicit inherited stdio
handles. Exactly one valid event must match the fresh native report PID and
must differ from the G launcher PID. No console-parser fallback is permitted.

This is `executor_handle_derived_correlation`, not an independently retained
controller child handle or independent PSEC cleanup proof. Signed nonzero child
exit can still correlate an already observed successful connection; exit zero
is additionally required for `observed_connect_denial`. G's own exit is separate.
Malformed, missing or duplicate correlation cannot be repaired using actor PID
alone. Raw event/log/PID content remains private.

Only the production N0a executable and its two-source build manifest are eligible
for a future explicit opt-in artifact. The current short pure workflow uploads
nothing and starts no VM. Direct N0a runtime/upload branches require the explicit N0a runtime marker;
mixed old-direct and N0a runtime markers are rejected. Activation follows the
reviewed short gates and separate authorization for one bounded experiment.
An enabled opt-in path is not a recorded execution or acceptance result.
