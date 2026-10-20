# Identity-bound PSEC proof, staged experiment

Branch: `dot/windows-isolation-proof`. Starting commit:
`3e90bb1f129a7d08b85fb816c7c70ba4f346ee66`.
No main merge, product default, release, or prior evidence is changed.

## What this slice establishes

- A static native Windows actor records actual token user/AppContainer SID,
  elevation, capabilities, PID and Job membership. Reports use a fresh nonce
  and CREATE_NEW, with bounded JSON and no arbitrary diagnostic text.
- Stage 0 controller builds explicit deny-all policy, verifies the existing
  fixed G executor bytes and manifest, probes that exact request, and requires
  both native actor completion and the executor's actual BaseContainer tier
  diagnostic. Missing, contradictory or fallback evidence fails the gate.
- Stage 0b separately creates a zero-capability unpackaged AppContainer and
  gives it only two inherited anonymous-pipe handles. The parent verifies the
  suspended child's actual SID before resume, tests a 32-byte nonce echo and
  pipe EOF, terminates the owned Job, removes only its fresh directory ACEs
  with DACL readback, and deletes its new profile. No socket is opened.
- Stage 1's policy builder accepts only a strictly shaped observed proxy
  identity record. This is validation, **not proof** that the identity exists.
  No Stage 1 controller or proxy bridge is implemented in this slice.

## Evidence ledger

| Check | Status | Meaning |
|---|---|---|
| Pure Python policy/report/unit tests | 25 passed locally and on GitHub Windows Server 2025 | No native security boundary was exercised |
| Native C++ compilation | MSVC /W4 /WX succeeded, run 39366282291 | Actor was not executed |
| Native Stage 0 deny-all PSEC launch | Not yet run | Neither actor compatibility nor PSEC runtime accepted |
| Native Stage 0b AppContainer pipe transport | Not yet run | Inherited-handle design remains a hypothesis on target host |
| Native proxy identity / negative peer controls | Not implemented | No identity-bound proxy success claim |
| Browser, DNS, broker escape, failure isolation | Not run | No Linux-equivalence or product/privacy qualification |

Compilation evidence is retained in `verification/windows-2026-10-20/identity-proof/compile.json`;
[the successful run](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39366282291)
built source SHA-256 `4f5b398e2341694242009e03ecb96dc1bc7479a2bba3fe76968df7b238406b0b`.
This does not establish native launch, inherited transport, or isolation.

The work-directory retention in Stage 0 is intentional diagnostic preservation.
Stage 0 does not independently certify PSEC kernel cleanup. Stage 0b records
cleanup separately and does not pass if its owned profile/handles/ACEs remain.
Neither stage tests controller death yet. An ordinary non-AppContainer user in
the default network compartment is required. The bounded launcher measures its
current token or uses only an existing verified same-user/session linked limited
token. Missing token/privilege (including error 1314) is a blocker, not a reason
to create an account, lower integrity and claim standard-user status, change UAC,
or grant privileges. No user account or credential is created by these scripts.
The outer 120-second watchdog reports nested cleanup as incomplete until the
matching inner report proves cleanup. The profile ownership journal is written
before creation and updated with the actual SID. Cleanup waits for Job active
process count zero before removing owned ACEs/profile; uncertain exit retains
that state and fails.

## Pinned implementation references

- Existing G runtime pin remains `ruleproxy/windows_runtime_pins.py`, upstream
  `7bf210247986cb73b1b314df60c2f1109c479c0b`. G's direct-egress guard is not an
  identity-proxy implementation and is not presented as one.
- [Pinned networking contract](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/docs/backends/process-container/networking.md)
  permits real AppContainer profile or package-family peer identity while
  denying general host loopback. Model 2 still has the bidirectional private
  network capability; this is an explicit limitation, not complete ingress closure.
- [Pinned AppContainer inherited-handle precedent](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/appcontainer_runner.rs#L980-L1054)
  combines security capabilities and an explicit inherited-handle list. It
  motivates Stage 0b, but does not replace a runtime proof for our transport.
- [Actual tier diagnostic](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/core/mxc_engine/run.rs#L229-L244)
  is consumed only as a closed-value marker, with independent actor evidence.

## CI and authorization boundary

All 19 pre-existing `.github/workflows/*.yml` files were inspected before the
initial `[skip ci]` source commit. `check.yml` included real Windows system-proxy
tests on every push. The deliberate second commit excludes only
`dot/windows-isolation-proof` from that push trigger; main behavior is unchanged. None of the specialist push
branch filters matches `dot/windows-isolation-proof`; the unfiltered recovery
workflow has a path filter not touched by this slice. No workflow_run,
pull_request_target, scheduled, or repository_dispatch trigger was found.
No main ref or workflow definition on main is modified.

The existing `mxc-capability.yml` has an optional, default-false
`identity_proof_compile_only` workflow_dispatch input on this branch. When true,
only one existing standard `windows-2025` job runs, limited to eight minutes:
installed MSVC compilation, these pure unit tests, and an actor artifact. The
old executor/ARM execution path is excluded in that mode. This does **not** run
the actor or create a sandbox. No larger runner, VM matrix, service install,
package signing, real credentials, or billing changes are introduced.

The added `windows-identity-proof.yml` provides the same compile-only job on
pushes to exactly this experimental branch and only proof-source/test/workflow
paths. It has no pull-request or scheduled trigger. A deliberate commit marker
`[identity-pipe-runtime]` enables only the currently approved Stage 0b step, with
a three-minute step cap within the existing eight-minute job. Other pushes
remain compile/unit-only. No PSEC, network, firewall or proxy test is included.
Concurrency cancellation is disabled so a new push cannot interrupt cleanup.
Artifacts contain only bounded reports/ownership journal and compiled actor,
never raw controller stdout/stderr. The initial source
commit remains CI-skipped; the second commit deliberately starts this one
bounded build. The new workflow was structurally checked for one standard
runner job, eight-minute cap, no matrix and no native actor invocation.

Manual dispatch and automatic build execution must still respect the owner's GitHub-only, no-new-paid-resource
instruction. Windows runtime tests need the separately approved disposable
security-test context, not merely a compile success. Existing credentials may
not be logged, uploaded, or replaced. No user PC/OVH/Tianyi access is involved.

## Next gates, in order

1. Native artifact compilation passed. Run Stage 0b first on standard Server
   runner, using the verified ordinary-token launcher. Local pure suite now has
   52 passing tests; the first Windows build ran the earlier 25-test suite.
2. Separately run PSEC Stage 0 on a supported Windows host and independently
   measure controller-death/Job teardown. An AppContainer pipe pass is not PSEC
   acceptance.
3. Add native AppContainer TCP frontend with privateNetworkClientServer and
   only inherited framed pipes to a host relay fixed to owned fixture/Mihomo.
   This capability permits private outbound traffic too, so the frontend is
   trusted code and must not open arbitrary sockets.
4. Positive identity-bound request, wrong peer at the **same endpoint**, wrong
   port, unrelated host loopback, stopped proxy, and host control comparisons.
5. DNS/brokers/IPv6/UDP/descendants and stock-browser compatibility separately.

Do not replace a failed gate with broad ACL grants, host-loopback exemptions,
relaxed actor checks, disabled browser sandbox, or an unsigned-driver bypass.

## First native-run attempt: stopped at unit gate

Run 39366873802 rebuilt successfully but one of 51 unit tests rejected a Windows
short/long parent path spelling mismatch. The native step was skipped, so no
AppContainer or ACL test ran. The attempt is retained in
`verification/windows-2026-10-20/identity-proof/attempt-01-unit-gate.json`.
The correction reconstructs only the fresh destination from its already
validated canonical parent; all per-component reparse and ownership checks
remain. An additional regression brings the pure suite to 52 tests.

## Second attempt: fixed-size token query rejected

Run 39367105347 passed all 52 unit tests and rebuilt the actor. The native
launcher stopped before creating a child/profile because
GetTokenInformation(TokenElevation) rejected the zero-length sizing probe with
ERROR_BAD_LENGTH (24). All opened token handles were closed. The exact bounded
report and source/artifact provenance are retained as attempt-02 files. This is
a launcher API-handling defect, not evidence against AppContainer pipe transport.

## Combined token ABI correction and read-only preflight

The next attempt replaces zero-length sizing probes for fixed DWORD token
classes with direct four-byte buffers and exact returned-size checks. Linked
TOKEN_LINKED_TOKEN remains pointer-sized with explicit handle ownership;
variable user/integrity/AppContainer SID and group data retain bounded sizing
and native pointer containment checks. Native errors are captured immediately
and never interpreted as a default identity. The native actor already used
separate fixed and variable readers; its source/hash is unchanged.

A read-only diagnostic step precedes native launch and queries all independent
current-token fields even if one fails. For observed elevated Default/Full
identity it also inspects the existing linked token, matching the launcher
selection. Reports redact raw SIDs, retain closed per-query error codes, close
all acquired tokens, and make no process/profile/ACL/network changes. Any
incomplete preflight blocks launch. The Stage 0b controller now shares the
strict current-token readers instead of the historical smoke snapshot helper;
its separate suspended-child AppContainer SID reader also checks probe error,
returned size, pointer containment and SID length before conversion.

This is preparatory code and pure-test evidence, not a new native pass. The
previous failed report remains unchanged. No privilege/account/UAC fallback or
ordinary-token acceptance relaxation is introduced.

Combined correction validation: 71 pure tests pass locally. Native runtime
results for this correction remain pending until a separate Actions report.

## Third attempt: ordinary-token source unavailable on this runner

Run [39367860553](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39367860553)
at commit `3f2c0b327fcb3151aabbd74fe5893bdf706086bc` rebuilt the native actor
and passed all 71 pure tests on Windows. Every one of the 11 current-token
queries succeeded. The runner had elevated=true, TokenElevationTypeDefault (1),
high integrity (12288), and an enabled Administrators group. It was not an
ordinary user or an observed split-token Full identity. The attempt to read an
existing linked token returned ERROR_NO_SUCH_LOGON_SESSION (1312).

The preflight stopped native execution as designed. No Stage 0b process,
AppContainer profile or ACL mutation occurred, and all opened token handles
were closed. The bounded report and verified artifact SHA are retained in
attempt-03-preflight.json and attempt-03-source.json. This is a concrete host
identity limitation, not evidence that inherited AppContainer pipes fail.

No account creation, credential use, UAC/privilege policy change, synthetic
medium-integrity token, or alternate process-creation fallback was attempted.
The current ordinary-user acceptance gate remains unchanged. A different
ordinary-token source or a separately labelled non-acceptance diagnostic needs
an explicit next design decision; retries of this exact missing linked-token
path do not provide new evidence.

## R0: separate restricted-caller identity experiment (preparation)

The missing existing linked token is retained as an unsupported genuine
ordinary-user route. The next experiment is explicitly **not** a replacement
ordinary-user test. It derives a transient restricted token only from the
current runner's own primary token, reduces group/privilege authority, and
measures that token and the launched child before allowing a fixed native
actor to run. This synthetic restricted-caller context is reported separately.
It is not an ordinary desktop, an AppContainer, a general desktop sandbox, or
PSEC/browser acceptance.

The initial R0 slice runs only the already compiled/hash-checked native actor
in its identity-reporting mode. It creates no AppContainer profile, ACL grant,
network rule or proxy. No accounts, credentials, UAC/privilege-policy change,
explicit privilege enabling, foreign-user token, service, or alternative logon API is
permitted. CreateProcessAsUser's documented own-restricted-token exception does
not guarantee all required privileges are available; a native failure remains
a blocker, not a reason to grant privileges.

A separate `[identity-restricted-r0-runtime]` marker gates the R0 step in the
same single standard Windows job. Its two-minute step budget is within the
existing eight-minute job limit. Only bounded controller/actor JSON reports
are uploaded. Genuine ordinary-user and pipe-runtime steps are not enabled
by this marker. Successful R0 would establish only this restricted-token
launch mechanism and must be followed by separately labelled pipe integration.

Primary API references:
- [CreateRestrictedToken](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-createrestrictedtoken): new restricted-token ownership, deny-only groups, privilege deletion, and default-desktop limitation.
- [CreateProcessAsUserW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessasuserw): caller-token restriction exception and required existing caller privileges. Windows may temporarily enable an already held required privilege during this API call; this experiment does not grant privileges or call AdjustTokenPrivileges.

R0 implementation uses Flags=0 and explicit deletion of every observed
privilege except optional SeChangeNotifyPrivilege, then reads the full native
privilege array back. Every non-baseline group is made deny-only; the exact
native user, logon and integrity identity is checked, with unchanged user
attributes and authentication LUID. The child is created suspended, assigned
to an owned kill-on-close Job, and verified before resume. Cleanup requires
native Job active-process count zero and closure of all owned handles. Parent
security facts are re-read after the experiment; token bookkeeping IDs are
not substituted for those facts. The expanded pure suite has 92 passing tests
locally. This paragraph records preparation only, not Windows R0 execution.
