# Descendant UDP adapter — explicit activation, runtime evidence pending

## Narrow question

The proposed experiment replaces the root-UDP case with one socket-free parent and the unchanged UDP child. It does not append another network experiment. Existing direct UDP/TCP paths, original Stage0 result, policy and identity acceptance remain distinct and unchanged. No descendant runtime or AppContainer inheritance has been observed by this implementation slice.

## Separate provenance, not PID relabeling

The pinned executor's dedicated ProcessExited event identifies the parent wrapper only; its signed32 exit code is not the child's DWORD exit code. A new nominal parent-chain binding must validate the fresh parent report, returned child PID, pre-resume token comparison, exactly one successful resume, held-child wait and same-buffer child report commitment. It must independently validate both role-specific native identity reports and compare actual parent/child AppContainer SID values privately. Ordinary controls require both non-AppContainer/null-SID reports and never claim AppContainer SID equality.

The child remains the unchanged UDP actor. Its self-profile must pass before sockets. Its source/executable manifest and the new production parent's manifest are independently pinned; TEST_ONLY artifacts are inadmissible. The fixed sibling basenames are windows_n0a_udp_parent.exe and windows_n0a_udp_actor.exe in the existing read-only input grant. Both fresh report paths share the existing writable phase directory. No permission, token, capability, job, breakaway or network-policy change is introduced.

Existing direct UDPBinding and executor-audit predicates must not be fabricated or weakened to fit this chain. Only reusable network parsing, QPC controls and packet decoding are used after separately validating the descendant chain. A canonical, exact-path/source-checked module identity is required for new strict binding classes from the outset.

## Deadlines and cleanup

The controller captures the original same-guest QPC phase/global deadline before launching the executor. The parent verifies the actual frequency and checked integer deadline, then clips its work and internal cleanup reserve to that deadline. Expired, mismatched-frequency, overflowing or insufficient budgets do not create a child. No relative allowance is renewed after executor startup, and the hosted fixture's observation margin is not added to production phase budgets.

The original guest 120-second work budget, existing reporting allowance, host work deadline and original cleanup reserve remain. Child termination/wait/handle closure are separate from parent/executor exit. Unknown child cleanup cannot qualify packet absence; receiver/capture remains through owned QEMU exit. A single authoritative QEMU stop path is retained. These are bounded waits and fail-closed observations, not a guarantee that all OS calls complete before a deadline.

## Exact payload and closed transport

The conservative payload is exactly 22 members: existing UDP 17, production parent executable/manifest 2, and new parent control/guest/flow modules 3. Existing dependency modules remain packaged because the new branch explicitly reuses their generic utilities; it never runs the old root-UDP experiment too.

The parent-only opt-in uses a separately versioned result envelope and routes. The original Stage0 is posted first. The new closed result (at most 4096 bytes) precedes one committed private network bundle (at most 64 KiB), within the existing single reporting allowance. Missing, duplicate, conflicting, malformed or late private bodies cannot erase a valid original result and cannot qualify absence.

Full parent/child native identity reports and raw SIDs remain guest-private. The bundle contains network objects, same-buffer source hashes/lengths and fixed closed chain facts. The host supplies its own expected source/binary/build/nonce/MAC/endpoint pins and recomputes structural and network/QPC controls. Profile, SID and held-handle facts remain guest-controller/parent attestations, not independent host token authentication. No raw PCAP or bundle enters logs, artifacts or public evidence.

## Outcomes remain independent

Creation refusal, token mismatch, loader failure, missing child report or unattempted sends are compatibility/prerequisite outcomes, not child-network passes. Attributed raw send acceptance or all-three sendto10013 remains separate from qualified packet absence. Already bound payload/API observations survive later ordinary-control, exit or cleanup failure; missing provenance cannot be treated as negative evidence.

The private bundle requires all four attributed parent/child chains. If an ordinary chain/report is missing or invalid, no bundle is emitted and no packet observation is recovered from that run; already attributed selected API/echo and receiver observations remain separate. With all chains available, typed ordinary-control or cleanup failures preserve packet-positive observations but prevent qualified absence.

Bounded descendant UDP payload absence would require the fresh chain, all three actual child sends, same-wrapper ordinary before/sample/after controls, complete calibrated capture, unambiguous ports/payloads and all cleanup predicates. It is not universal child isolation, descendant TCP, DNS/broker behavior, grandchildren, browser compatibility, proxy fail-closed, Linux equivalence or product acceptance. Strict Stage0 remains false under its original empty-capability criterion.

## Gate boundary

Before any activation decision, require actual-import producer→commitment→host-normalizer tests; partial-chain and sticky-observation negatives; absolute-QPC expired/frequency/overflow/startup-delay cases; exact 22-member ZIP→PowerShell extraction alongside legacy modes; bounded result/body composition; and cleanup uncertainty tests. The short parent workflow remains no-upload/no-guest. Separately reviewed runtime wiring uses only the exclusive parent marker, production parent and unchanged child manifests, and the exact 22-member payload. Both binaries must be 512 bytes through 8 MiB before upload; actual payload and capture-capacity admission still occur before QEMU. Enabling the opt-in code and wiring is not evidence of an executed descendant run.

## Preflight import boundary

The controlled second workflow attempt passed its instrumented five-second Bash prerequisite but stopped at host preflight before QEMU or a guest. Its closed failure was unclassified; no raw exception was retained. A fresh isolated process using the actual production artifacts reproduced the parent verifier's package import failure when only the script directory, not the repository root, was on the import path. This is a deterministic source defect consistent with that failure, not a recovered runtime stack.

The narrow correction loads the unchanged runtime-pin module by its exact repository-owned path, without adding the repository to `sys.path`, accepting an ambient module, or weakening manifest checks. The short gate additionally compiles the unchanged production child into a distinct output and verifies both production artifacts through the isolated host-loader path. Neither production executable is run by this verifier; TEST_ONLY mechanics remain separate, with no artifact upload or VM. Actual verification on the hosted Windows gate remains required. The earlier Bash timeout cause remains unknown.
