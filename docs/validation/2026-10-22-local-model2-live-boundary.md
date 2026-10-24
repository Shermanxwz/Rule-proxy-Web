# Local Model 2 live boundary (implementation plan)

This is a new, unexecuted C profile. A and B keep their original acceptance.
The first live cell is limited to a real raw-Winsock HTTP chain and a direct TCP
negative to the same still-healthy origin in the same selected container. The
wrong-port, wrong-peer and death cells are subsequent work and cannot be marked
passed by that first cell. Native raw HTTP does not establish WinHTTP/application
proxy configuration compatibility.
Original PSEC Stage 0, system DNS, service brokers, arbitrary application
adapters, and product acceptance remain false. A request-aware probe selects a
candidate backend; it does not create or prove an enforcing security environment.

The intended path is a fixed native selected client in pinned G/PSEC, a native
AppContainer HTTP listener, two held anonymous pipes, an ordinary native relay,
and an ordinary loopback origin. P, Q, and O are distinct ephemeral high TCP
ports on numeric `127.0.0.1`. Profile A owns P and the Q negative fixture.
Profile B owns the wrong-peer fixture at the same P after A's listener has closed.
No wildcard bind, port reuse, loopback exemption, global firewall/default policy,
proxy, DNS, or route change is part of this profile.

## Identity and admission

The listener explicitly receives only the known privateNetworkClientServer
capability. Its actual held token must contain exactly that SID and expected
attributes; internetClient and networkLoopback are not added. Selected PSEC
capabilities are a separate, explicit profile. The first network cell declares
exactly the previously observed Agentic capability plus the policy-derived
privateNetworkClientServer, both with enabled attributes 0x4. The Agentic-only
profile remains a separate identity observation and cannot authorize network GO.
The selected expected profile is fixed before launch. An unknown SID, attribute,
count, or different known profile stops before GO. It cannot adapt to observed
capabilities. If the expected set cannot be justified in advance, run identity
observation only and archive the result before defining another profile.

Pinned G creates a selected child suspended, attaches its security environment,
assigns its private Job, and then resumes it. Its CLI does not transfer the child
creation HANDLE or private Job HANDLE to this harness. C therefore cannot claim
external ownership before the selected child's first resume. The fixed native
client first reports identity and waits for a read-only control file without
initializing Winsock or WinHTTP. The owner holds G's process HANDLE and creation
time, takes two direct-child snapshots, opens query handles, compares creation
times, and then retains a verified stop/query/synchronize HANDLE. It must verify
the expected image path and bytes, actual token, session, creation generation,
and membership in the exact owned outer Job before publishing GO. A self-reported
PID is a discovery hint only. Ambiguous children or inaccessible observations
fail closed. The actual selected HANDLE remains held through all phases.

The outer guard assigns the worker at process creation using JOB_LIST. G has no
breakaway permission, and the selected child must actually be observed in that
same outer Job. PSEC is a kernel security-environment object, not a process or a
Job member. G's private inner Job order is source-bound evidence, not an
independent external observation of that inaccessible HANDLE. Membership in the
outer Job does not establish that service-broker work outside that Job is blocked.

## Runtime policy and barriers

The exact final request uses `egress.default=deny`, `ingress.default=allow`,
`hostLoopback=deny`, runtime proxy `http://127.0.0.1:P`, profile A as
`allowedProxyPeer`, and `allowDaclMutation=false`. It contains no direct egress
allow/deny rules or caller-supplied capabilities. Its final actor, command,
read-only control directory, writable report directory, and timeout are included
in the request-aware probe. The live listener's held SID must equal the OS-derived
profile SID before that probe. The real launch must use the identical request.

Every G probe/launch receives a fresh protected empty MXC_DACL_STATE_DIR via its
five-key child-only environment; CLI orphan-recovery runs even before `--probe`.
No existing state directory is read or repaired. Bundle, executable, manifest,
license, native manifest, source closure, and staged bytes are rechecked before
resume. A single actual QPC epoch bounds setup, probe, work, and cleanup; no
per-stage reset or deadline extension is permitted.

The native client accepts only a bounded fixed binary GO record, monotonically
sequenced and bound to its run, case, frequency, deadline, and fixed ports. The
owner atomically publishes it in a fresh directory that PSEC can only read.
Reports are separate and cannot authorize work. Each phase carries a fresh nonce.
All network initialization remains behind the first admitted GO.

## Independent observations

Positive evidence includes actual HTTP bytes accepted by the PNCS listener,
bounded method/target/Host/nonce validation, canonical pipe request, independently
received origin nonce, response bytes/EOF, and native handle/socket closure.
Generated B frontend bytes are not evidence of this client-to-listener link.
Wrong-port Q keeps A's SID fixed. Wrong-peer B keeps P fixed. The selected client,
G and PSEC remain alive through these changes. Failed bind or absent healthy
receiver is inconclusive, not an isolation pass. SO_REUSEADDR cannot make a failed
exclusive rebind qualify.

Each negative fixture needs independent before/during/after health nonces and a
finite multi-accept listener. Ordinary host-to-AppContainer loopback cannot be
assumed healthy: a firewall allow is not a loopback exemption. A separately held
control G/PSEC client may bind precisely to that live profile/port while retaining
hostLoopback deny. An unhealthy control makes the negative cell inconclusive.
Connect completion or a selected nonce received at a forbidden receiver is a
sticky violation even if later HTTP parsing, timeouts, or cleanup fail.

The death phase must first observe the origin receiving the full request while
withholding its response. The owner then terminates an actually live held relay,
observes its exit, pipe EOF/error at the frontend and selected request failure,
then tries direct egress again in the same selected container. Killing a relay
that already returned/exited is not a death test. B's automatic response fixture
needs a distinct bounded withheld-response mode for this purpose.

## Scoped firewall role and cleanup

An unpackaged AppContainer listener requires an administrator-owned inbound rule.
The separate maintenance helper must be held, have the intended elevated token,
join an exact private maintenance Job, and wait for owner admission before
changing policy. This is distinct from the workload Job, so workload quiescence
can be established while the cleanup helper is still alive. The ordinary owner
keeps the maintenance Job's sole persistent HANDLE. The helper consumes its
temporary self-attachment HANDLE before READY and never passes a Job HANDLE to
its children. The returned ShellExecuteEx process HANDLE supplies query/sync
observation; the held maintenance Job supplies stop authority without assuming
an ordinary process can open a high-integrity process for termination. The held
helper must be the same user and session, a primary high-integrity elevated
non-AppContainer token with zero capabilities and no UIAccess. Another account
entered at a credential prompt cannot qualify.

RunAs/UAC can outlive the synchronous call or the original deadline. An intent
journal marks the spawn unknown before that call. Killing a waiting worker does
not prove a future UAC spawn was cancelled. The fixed bootstrap checks the same
QPC deadline before self-attachment, READY, admission and every operation. A late
launch exits without mutation; an unknown spawn remains a recovery condition.
Its fixed plan permits only a fresh exact rule name, the newly derived package
SID, fixed staged executable, TCP, local address 127.0.0.1, local port P or Q,
remote address 127.0.0.1, inbound allow, no edge traversal or block-rule override.
Creation and effective readback must agree on every field. Existing rules are
never edited. Local-policy/GPO rejection is a failure, not authority to weaken
the policy. The helper cannot alter profiles, defaults, loopback exemptions,
proxy/DNS/routes, or rules selected by a wildcard/prefix.

The owner journals intent before mutation and records partial/uncertain creation.
Removal targets only the exact named owned rule after every scoped field matches
the journal. Mismatch is retained for recovery, never broadly deleted. Readback
must prove absence from both the local persistent and effective policy view.
Rules, grants and profiles are removed only after held exits and exact Job-empty
checks. Unconfirmed closure retains ownership state and makes cleanup false.

Primary sources: [pinned launch order](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L701),
[pinned network contract and firewall requirement](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/docs/backends/process-container/networking.md#L69),
[AppContainer firewall package identifier](https://learn.microsoft.com/windows/win32/api/netfw/nf-netfw-inetfwrule3-put_localapppackageid),
[firewall rule condition fields](https://learn.microsoft.com/powershell/module/netsecurity/new-netfirewallrule),
[independent AppContainer loopback isolation](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall),
[exclusive binding and graceful closure](https://learn.microsoft.com/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse).
