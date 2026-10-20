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


### First R0 attempt: source-token scalar contract mismatch

Run [39369029584](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39369029584)
at commit `03808cae03099f6371932932ff2da9c4052e92ff` compiled successfully and
passed all 92 tests on Windows. Source identity collection rejected a returned
scalar size before any reduced token or child was created. The original report
records only `invalid_token_scalar_size`, not which class or returned size, so
that artifact alone does not prove the failing class. All acquired handles
closed; `parent_token_unchanged=false` means not established, not evidence of
mutation. The exact report and artifact provenance are retained as R0 attempt1.

A primary [Microsoft maintainer clarification](https://github.com/microsoft/win32metadata/discussions/2308)
identifies a published-documentation mismatch specifically for class21,
TokenHasRestrictions: the payload is BOOLEAN with DWORD pointer alignment,
and a successful return length of one defines byte0 only. The published enum
reference still describes DWORD. A dedicated class21 reader therefore uses
aligned four-byte storage but requires exactly one returned byte; all other
DWORD readers remain exact four-byte checks. This is a class-specific contract
correction, not permission to accept arbitrary short output. Expanded bounded
per-field diagnostics will retain exact native operation/class and expected
versus returned sizes, without raw user identities, before another R0 launch.

Class21 correction validation: 104 pure tests pass locally, including poisoned
upper bytes and rejection of unexpected lengths/BOOLEAN values. The R0
preflight now independently observes 18 fields using QUERY-only access,
records bounded ABI diagnostics, and blocks restriction/launch if any read is
incomplete. Runtime uses the same readers. Unmeasured parent-token equality is
now null, with explicit reduced-token/process creation markers. Native results
for this correction remain pending.


### Second R0 attempt: verified reduced-token launch, actor DLL startup fails

Run [39369637351](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39369637351)
at commit `1a8cf663d71bf82d55cb62186e93b8e812dbc147` passed native compilation,
104 tests and all18 preflight observations. Class21 actually returned one byte.
CreateRestrictedToken and CreateProcessAsUser succeeded. The suspended child's
native identity matched the derived token: medium integrity, administrator
deny-only, only SeChangeNotify privilege, same user/session/authentication.
Parent security facts were unchanged and Job/handle cleanup completed.

After resume, the actor exited `0xC0000142` (DLL initialization failure) before
its report was created. R0 remains failed; the verified restricted launch is
partial mechanism evidence, not successful actor/pipe/PSEC acceptance. A sanitized
summary with artifact provenance is retained as R0 attempt2; original reports
remain in the existing Actions artifact, not republished in this commit.
An independently downloaded, SHA-verified actor imports ADVAPI32, WINHTTP and
KERNEL32 eagerly. This does not identify the failing DLL or prove a desktop
permission cause. The next diagnostic isolates optional WinHTTP imports in a
separately pinned identity-only build while preserving token restrictions,
process flags, environment and ACLs. No desktop or window-station permissions
will be broadened to make it pass.

### Bounded paired startup controls (preparation)

A missing positive control is addressed before attributing the failure: one
four-cell diagnostic compares the HTTP-capable actor and an explicit
IdentityOnly build, each under the unchanged source token and the verified
restricted token. Both binaries come from the same pinned source and installed
MSVC toolchain. IdentityOnly omits WinHTTP code/imports and rejects actor-http;
actor and actor-pipe report semantics remain unchanged. Installed dumpbin
captures actual dependency/import tables and system WinHTTP dependencies; the
controller records both binary hashes and the dependency-audit file hash.

All four cells use the same fixed actor command shape, minimal environment,
explicit standard handles, suspended launch, owned Job and cleanup rules.
Source controls verify exact source identity, never a weakened restricted
gate. Each cell is independently cleaned before proceeding. An uncertain
cleanup or changed parent stops remaining cells. No source-control result can
count as restricted/ordinary/PSEC acceptance. No profiles, ACL changes,
network configuration, extra accounts or privileges are introduced.

The earlier restricted-primary Python laboratory also recorded 0xC0000142;
that used materially different account/profile, private desktop, DefaultDacl
and restricting-SID choices. The current paired test is dependency/startup
measurement, not a claim to invent a new isolation scheme or to have solved
that historical failure.

Paired-control preparation validation: 119 pure tests pass locally. Both
compile variants passed portable mocked-header C++ checks; actual MSVC/import
checks remain part of the pending Windows run. The paired controller's zero
exit means all four diagnostic records were safely collected, not that any
actor started or isolation passed. Per-cell actor outcomes and every
acceptance flag remain separate and explicit. The original ordinary-user
launcher is unchanged.

Publication minimization: R0 attempt2 is published only as
`r0-attempt-02-summary.json`, containing match booleans, bounded result/error
counts, byte widths and source/build/artifact hashes. Raw report payloads,
account/host identifiers, session/process IDs, SID literals, privilege lists,
handles and authentication LUIDs are excluded from this new repository
publication. Original evidence remains in its existing Actions artifact.


Publication projection hardening: raw native/controller reports remain local
for checks. Workflow artifact paths now name only closed public report,
preflight, build and import projections, plus the synthetic compiled binaries.
No raw actor report, ownership journal or path-bearing build manifest is
uploaded by this workflow. Public import metadata contains DLL basenames and
hashes of actual import tables, not raw tool output or machine file versions.
Full internal security checks and source code are unchanged. The expanded
suite has 132 passing pure tests, including nested-private-field injection
checks. Published projections are marked sanitized=true and byte_exact=false;
the source digest identifies the original data, not a claim that the public
projection is a byte-exact copy.


Paired startup attempt 1 (commit `318c5380`, run `39371248897`): both
MSVC variants compiled successfully. The dumpbin dependency-count guard stopped
the build-metadata step before unit tests, token preflight or actor runtime.
The original guard did not identify which of the three targets failed, so the
record does not attribute the problem to a particular DLL or parser cause.
Closed projections and exact-path artifact uploads completed successfully.

The exact two build artifacts were downloaded and their archive digests
verified, then inspected read-only with GNU objdump without executing them.
Full imports ADVAPI32, WINHTTP and KERNEL32; IdentityOnly imports ADVAPI32 and
KERNEL32. This independently establishes the intended build distinction, not
startup or isolation success. `paired-attempt-01-summary.json` records the
synthetic DLL basenames, artifact/binary hashes and explicit skipped runtime.
The next metadata correction must collect bounded sanitized parser facts for
all targets before rejecting, rather than guessing which dependency failed.

The metadata-only diagnostic correction preserves the 64-DLL gate and collects
all three dependency targets and both actor import tables before any decision.
It emits a closed-schema parser fixture containing DLL basenames, generated
section/line categories, bounded counts and exit statuses only, even on failure.
A rejected metadata gate never creates the audit needed by runtime. Raw import
text remains runner-local; only hashes are published. No token, actor or
launch-policy code changes. The local suite now passes 147 pure tests, including
15 bounded capture/parser/publication tests. This improves diagnosability; the
original dumpbin failure cause remains unknown until native observations arrive.


Paired startup attempt 2 (commit `c50b6d95`, run `39372121986`) identifies
the metadata failure rather than guessing its cause. All five dumpbin commands
succeeded. The sanitized native fixture records 3 Full actor dependencies,
2 IdentityOnly actor dependencies and 76 System32 WinHTTP dependencies, many
being API-set contract DLLs. The system-library list exceeded the harness's
uniform 64-name metadata bound. Token preflight and all actor runtime remained
skipped. This is not evidence that WinHTTP caused the prior DLL initialization
failure. The original rejected fixture is retained unchanged with its source
artifact digest and summary.

The measured correction raises only system-library metadata capacity to 128;
both actor capacities remain 64. Native token/security/launch gates are unchanged.
Regression tests replay the actual sanitized fixture and cover each boundary.
The corrected local suite has 151 passing pure tests.


Paired startup attempt 3 (commit `8901787f`, run `39372510124`) passed both
MSVC builds and every dependency/import metadata gate. Windows ran 151 pure
tests; one fake-process matrix success test failed, and all native token/actor
runtime was skipped. The remaining 150 tests passed. The failure is preserved
separately from runtime outcomes; it supplies no new token or actor evidence.

The test-only correction uses a shared canonical owned-temporary-directory
fixture in the paired, ordinary and restricted fake-process suites. Production
input validation already canonicalizes these directories; the old fixture
bypassed it. A platform-neutral alias simulation reproduces the observed
completed-diagnostic/unsuccessful-startup signature with the closed
path_outside_owned_root error. This is a demonstrated viable cause, not proof
of the original CI cell error, which was not printed. Three regressions cover
the alias, preserved containment rejection and sanitized assertion diagnostics.
All 154 pure tests pass locally; production path and reparse gates are unchanged.


Paired startup attempt 4 (commit `3482b9ca`, run `39373025025`) completed all
four fixed controls after both native builds, import gates, 154 Windows pure
tests and source-token preflight passed. Full/source and IdentityOnly/source
exited 0 and produced reports matching native observations. Full/restricted
and IdentityOnly/restricted both exited 3221225794 (0xC0000142) before actor
reports, despite verified derived/suspended-child identity gates. Every
parent-token check remained unchanged, every job was empty and all owned
process/token handles closed. The workflow success means completed diagnostic
collection, NOT restricted, ordinary, PSEC or product acceptance.

This comparison rules out a general binary/environment/launch-path failure
under the unchanged source token and shows that removing WinHTTP does not
resolve the reduced-token startup failure. It does not identify the failing
DLL or exact reduced-token incompatibility. Preserve this negative result;
stop the synthetic-token detour and prioritize genuine ordinary-user Windows 11
validation. The published report is an already-sanitized closed projection;
its artifact and byte-copy digest are retained separately.

Next opt-in slice: one disposable genuine Windows 11 client at 26200.9711,
one existing-pattern RuleProxyCI Users account, IdentityOnly native actor and
pinned G executor, request-aware and actual BaseContainer Stage0 only. No
proxy, network traffic, extra rpps account or browser matrix. The known guest-
only BypassNRO/NoAutoUpdate baseline comes from the repository's existing
proxifyre setup; no new host policy. A standard Windows compile job and standard
Ubuntu KVM job have fixed caps. Free space and KVM are checked before downloads;
insufficient resources stop without broad cleanup or new paid capacity.
The host reserves 120 seconds for owned-process cleanup, destroys its private
VM/media/password tree only after owned processes exit, and publishes only a
closed report. 11 new local integration tests pass. No native Win11 result yet.


Genuine Win11 Stage0 attempt 1 (commit `fce91982`, run `39373330655`):
native IdentityOnly compile, guest PowerShell syntax and 11 integration tests
passed. Ubuntu stopped at its 55GiB free-space check, before KVM inspection,
lab artifact/media downloads, apt installation, VM or account creation. No
global cleanup or paid-resource fallback occurred. The old check did not print
actual free bytes, so neither its exact storage deficit nor an alternative
existing filesystem is established. Preserve blocked status and inspect only
bounded existing-runner resource facts before selecting an owned workspace.

A separate five-minute preflight-only marker now observes total/free bytes
for four fixed existing runner locations, opaque same-filesystem grouping and
KVM read/write-open/API-version/close facts. Every candidate and KVM is checked
even when storage is insufficient. The closed report contains no raw paths,
host/account names or device identifiers. It creates no VM, account, mount or
permission change and downloads no lab artifacts/media. The 55GiB runtime gate
remains unchanged; a reported alternate location is only a proposal. Fourteen
client integration/preflight tests pass locally.


Read-only resource run `39373913151` (commit `2268966c`) completed successfully.
KVM exists, opens with existing runner authority, returns API 12 and closes. All
four fixed candidate locations share one filesystem: total 76,887,154,688 bytes,
free 14,078,107,648 bytes (about 13.11GiB), below the unchanged 55GiB requirement.
No alternate filesystem, VM, account, artifact/media download or host change
was observed. The closed public evidence and exact artifact digest are retained.

This is a real resource blocker, not a PSEC rejection. The previously measured
serviced guest allocated about 24.95GB alone; eliminating an approximately 7GB
transient ISO duplicate cannot establish feasibility on this runner. Do not
blindly lower the reserve or delete global tools. Continue only with a reviewed
resource plan consistent with the no-new-paid/no-user-device constraints.

Read-only resource-plan preparation now inventories only three provider-defined
unused tool locations: Android SDK, .NET SDK and Swift. Definitions are pinned
to the actual prior runner image release ubuntu24/20261012.334, commit
7e7dc1bcc0ef464e5e315a2b4c33609590c6cffe; the new run separately records whether
its image version matches. Inspection happens before checkout using the exact
reviewed helper and SHA check. It records allocated/logical bytes with inode
deduplication, closed ownership/symlink/mount facts, never file contents or
symlink targets. Unknown ownership, root aliases, nested mounts or special
entries stop measurement. Nothing is removed, mounted or reconfigured.
Nineteen client integration/inventory tests pass; any later removal requires
a separate exact-target review and parent decision, not this diagnostic.


Read-only cache inventory run `39374582044` (commit `556304e0`) completed
without checkout, provisioning or deletion. Measured allocated bytes: Android
11,838,296,064; .NET 6,167,728,128; Swift 3,710,971,904. Sum 21,716,996,096 bytes
(~20.23GiB) is only an optimistic candidate bound, not guaranteed reclaimed
space. Combined with the prior 13.11GiB free observation it would reach only
33.34GiB, still below 55GiB. No subset is sufficient under the current pipeline.
The new observed image is 20261018.339.1, not the reviewed 20261012.334.1; this
provenance mismatch is explicitly retained. All roots are broadly writable;
owner/location checks alone do not establish pristine contents. No removal
is approved or performed. The published freeze had 19 reviewed tests; a later
20th test exists locally only and was not part of this run.

Next work is a bounded design review of lower-peak owned-media provisioning,
not a blind threshold reduction or expansion of deletion targets. Existing
source/extracted/remastered ISO copies and host MSUs can potentially be phased,
but servicing peak and safety margin must be established before provisioning.

### Disabled lower-peak stock-client candidate

The exact observed image release `ubuntu24/20261018.339` resolves to official
runner-images commit `b4067e48bd9bd803e958bfe1503ea0a06a3a127f`. The three
provider installer scripts are byte-identical to the earlier reviewed image;
this repairs definition provenance, not current-content or reclaim guarantees.
A narrowly scoped recovery helper is implemented but hard-disabled. It rejects
insufficient optimistic capacity before removal, snapshots every fixed tree,
uses no-follow descriptor-relative checks, and reconciles final measured free
space. It is not safe against concurrent privileged mutation. Forty-seven
synthetic tests passed without modifying any actual provider tool installation.

The separately disabled stock-client candidate retains normal Setup and the
original pinned 26200.6584 ISO with a tiny separate answer/seed ISO, omitting
servicing and full media extraction/remaster. It does not replace or qualify
26200.9711. Proposed resource gates and per-file process limits are documented
in `2026-10-20-win11-capacity-design.md`; these are a bounded capacity-abort
experiment, not proof of fit or an aggregate filesystem quota. Code review is
still required before any activation. No cache removal or stock VM has run.

The exact bounded activation was approved and published at `4f7d7c7c`.
Stock attempt `39378217171` passed PowerShell syntax and native actor compilation,
but its Windows pure-test job failed before the Ubuntu job could run. The mock
Linux finalizer fixture accessed `signal.SIGXFSZ`, which Windows Python does not
provide. Thirteen tests ran, one errored and the Linux-only primitive test was
skipped. The native job was skipped: no provider recovery, VM, temporary account
or Stage0 execution occurred. The correction is test-only signal injection,
not relaxation of the Linux finalizer or resource limits.

Stock attempt `39378706680` (`4c052e1d`) passed the Windows build and portable
test suite. The Ubuntu image rotated back to `20261012.334.1`; the exact
`20261018.339.1` recovery gate rejected it before snapshots or deletion. The
closed artifact confirms zero attempted removals and no host changes. Checkout,
package provisioning and VM creation were skipped. Workflow diagnostics also
identified string-valued dynamic timeout outputs, requiring explicit numeric
conversion. The next reviewed correction admits only the two already verified
image definitions, not arbitrary future images, and preserves all capacity gates.

Stock attempt `39379467154` (`cf255ba3`) passed compile, tests, numeric timeout
and exact image gates. Recovery then stopped with `writable_entry`, before
any attempted removal, checkout or VM. Measured free bytes were 14,093,033,472.
The blanket group/world-write rejection contradicted the already measured
provider-writable tool trees. This was a validation/design inconsistency, not
a newly discovered environment property or Windows isolation result. No mode
change or automatic guard relaxation was performed; precise provider-mode
handling requires separate source/inventory reconciliation and review.
