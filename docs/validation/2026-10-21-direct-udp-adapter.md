# Direct UDP adapter — code-only, runtime OFF

This change integrates the separately tested UDP mechanics into a disabled, runner-only diagnostic path. It does not report an actual contained UDP invocation, UDP packet absence, DNS/broker isolation, or a product/Linux-equivalence pass. REQUEST3 remains unresolved and parked.

## Selection and unchanged paths

`--n0a-udp-runner --udp-actor ... --udp-manifest ...` selects UDP instead of the TCP diagnostic; it never appends another experiment to the work window. `EXECUTION_ENABLED=False` in `windows_n0a_udp.py` refuses runtime before media/VM work and before guest executor use. The existing direct runtime workflow is unchanged. Original Stage0 acceptance and its first result POST remain separate; its historically false `capabilities_empty` result is not rewritten. Default direct, TCP, and TCP-capture paths retain their existing predicates and transport schemas.

The production UDP executable and its two-source manifest are verified independently of TCP artifacts. TEST_ONLY outputs are refused. The same contained process must provide its fresh native identity/profile observations and bounded report, correlated to the dedicated pinned executor's unique ProcessExited event. This is executor-handle-derived correlation, not a controller-held actor handle or independent PSEC cleanup proof. The sampled source token is not continuous inheritance evidence.

## Guest and payload boundary

The exact UDP payload has 17 members: the unchanged ten baseline members, `udp/actor.exe`, `udp/build-manifest.json`, the unchanged TCP control/guest modules used only for reviewed generic utilities, and the new UDP control, guest, and flow modules. Host packet decoders, capture adapters, private flows/PCAPs, and TEST_ONLY binaries are excluded. Real ZIP-writer → actual PowerShell AST selector/extractor fixtures use explicitly inert inputs and mocked authentication boundaries; they do not claim executable/pin-valid deployment artifacts.

The UDP subclass overrides initialization, endpoint selection, launch commands, envelope validation, invocation and owned-process closure. It reuses only reviewed generic timing/pinning/spawn/completion/probe/wait/finalization utilities. UDP closure independently attempts observations, exact-owned termination and waits under the original deadline, records one-shot handle/stream closure uncertainty, and retains unknown ownership. Later wait/cleanup errors do not erase an already written, validly attributed positive report.

## Time, transport, and provenance

The original captured 120-second work budget, 20-second reserve, and original outer cleanup deadline remain unchanged. There is no per-case renewed work budget. Original Stage0 is posted first. UDP uses a separate result-first envelope (at most 4096 bytes), followed by at most 64 KiB of private runner flow bytes under the same one 10-second reporting allowance. Missing, late, conflicting, malformed or truncated private data cannot erase the connect-independent UDP receipt and cannot establish packet absence. The existing reporting-only exhausted-work behavior does not launch new work.

Each source report is parsed and hashed from the same bounded byte buffer. The ordinary aggregate is domain-separated by `N0AU-ordinary-reports-v1\0`, ordered role, length and digest. These hashes are controller attestations, not host-independent authentication of token/PID observations. The host owns run/case nonces, binary/source/build pins, VM MAC and runner tuple; it validates the commitment, retains all before/sample/contained/after rows, recomputes controls, and derives the canonical manifest. A pure parser cannot authenticate its inputs.

## UDP conclusions are independent

- `explicit_send_denial` requires all three actual sendto calls to return 10013 with strict fresh selected-actor/profile/provenance/network binding. This independent observed API fact survives unrelated ordinary-control, launcher or cleanup failures; it does not establish selective enforcement or isolation. Wrong profile/provenance, malformed or uninvoked attempts cannot qualify. Setup, bind, receive errors and silence are not send denial.
- A successful sendto is local API acceptance, not delivery. Exact returned echo, owned receiver payload, and captured payload observations are distinct facts.
- `bounded_no_selected_udp_datagram` requires all three actual invocations, fresh binding, complete calibrated capture, valid ordinary controls and cleanup. It can coexist with accepted sends; it is a bounded observation, not API enforcement or general UDP isolation.
- A valid selected payload observation survives later failed ordinary controls or cleanup. Attribution remains conditional on the fresh actor/profile/provenance binding; tuple coincidence alone is not actor attribution. Unavailable uninvoked source ports are null, not invented tuples. Collision, unknown flow, incomplete capture or controls makes absence inconclusive.

No overall isolation pass is produced. DNS, resolver/broker behavior, IPv6, other protocols, unrelated traffic and system-wide privacy are untested.

## Capture and cleanup

Reuse is limited to the reviewed capture lifecycle: header before NIC enable, bounded private capture through observed QEMU exit, then EOF/drain/fsync/final IPC/child exit and receiver closure. Ordinary UDP payloads and a terminal ordinary witness must calibrate the actual runner path; prior tiny ingress and TCP captures are not UDP calibration. The retained cap is 64 MiB with the same 65 MiB admission reserve and actual payload planning admission `2*P + 16 MiB <= 64 MiB` (P <= 24 MiB). This is planning headroom, not a traffic guarantee; overflow is incomplete.

There is one held-QEMU stop owner, original absolute cleanup deadline, and no helper-first premature sink kill. Emergency/forced stops are incomplete. Private parsing precedes work deletion; final qualification follows independently observed teardown, including read-FD uncertainty. Cleanup uncertainty cannot be reported as success or hidden by deleting owned work.

## Gates and limits

The dedicated `[n0a-udp-gates]` workflow remains standard Ubuntu ≤5 minutes and Windows ≤8 minutes, no artifact upload or full guest. It requires UDP and legacy regression suites without missing/zero/skipped success, actual PowerShell transport/ZIP selection fixtures, production compilation, invalid production CLI refusal, and separate TEST_ONLY loopback mechanics/profile-only observation. It never invokes a valid production network CLI on a hosted runner. Hosted mechanics do not prove nonadmin ordinary controls, PSEC enforcement, guest private upload or actual UDP capture behavior. Exact source review and short-gate success precede any separate activation decision.
