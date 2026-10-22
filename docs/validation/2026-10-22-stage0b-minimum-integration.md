# Stage0b minimum integration — activation candidate, runtime unobserved

The implementation flags are enabled in this activation candidate, but the
optional branch requires the exclusive `[identity-stage0b-runtime]` marker and
all runtime prerequisites. No genuine Stage0b guest run is established here.
It replaces, rather than appends to,
other optional network experiments. The original PSEC Stage0 result, its default
runtime path, and product acceptance are unchanged. A false PSEC Stage0 result
and independently qualified Stage0b pipe evidence may coexist; neither is
relabeled as overall success. The host's `stage0b_ipc_qualified` is a separate
conjunction of the strict IPC chain and host-owned timing/cleanup observations,
not a substitute for the original Stage0 pass.

No networking, proxy, DNS, firewall, account, credential, UAC, or global-setting
change is part of this branch. The native identity actor is unchanged. The probe
uses only its existing fresh zero-capability AppContainer profile, exact-SID ACL
grants on its newly owned tree, and two inherited anonymous-pipe handles. This
is not a proof of general IPC availability, proxy access, or network isolation.

## Fixed interface and payload

`windows_identity_stage0b_guest.py` accepts the fixed seed configuration and the
original guest `--deadline-qpc D --qpc-frequency F`. Its private `stage0b` config
has exactly `enabled: true`, a lowercase 32-hex `case_nonce`, and lowercase
64-hex `actor_sha256`. Presence of any optional network/capture configuration key
is rejected, even if its value is malformed or claims to be disabled. Source
trust is the existing exact payload/source handoff, not an incoming self-hash.

The payload is base10 plus the missing ordinary launcher, pipe probe,
`ruleproxy/windows_app_process.py`, and this adapter: **14 members**, with no
second actor ZIP member. The adapter creates a fresh
`windows_identity_actor.exe` copy, verifies its exact bytes and digest, and passes
only this fixed basename to the launcher. The probe independently copies to its
own `inputs/actor.exe`, rehashes that copy, and verifies the held suspended actor
image and AppContainer SID before resume. The fixed launcher/probe commands use
the existing Python runtime with `-I -S -B`; no shell or caller-selected command
is admitted.

The integration launcher requires all of `--current-ordinary-only`,
`--case-nonce`, `--deadline-qpc`, and `--qpc-frequency`. It requires the **current**
observed ordinary token and default compartment before any `choose_mode` or
linked-token path. It never falls back to another token or process-creation API.
The legacy standalone launcher's non-scoped mode remains available with its old
default lifecycle body; an AST regression pins that body. That legacy mode is
not admissible for this new adapter.

## One deadline, nested ownership

The shared QPC helper validates exact positive integers, signed-64-bit D,
F≤1,000,000,000, equality with the actual guest QPC frequency, monotonic readings,
and at most 120 seconds remaining at admission. It does not convert from another
clock epoch or create a fresh relative work budget.

| Owner/phase | Original-domain cutoff |
|---|---|
| Probe active setup, profile/ACL admission and pipe exercise | D−30F |
| Probe cleanup / launcher's probe wait | D−10F |
| Launcher cleanup / adapter's launcher wait | D−5F |
| Adapter cleanup | D |

Existing 15-second and 5-second phase limits shrink against these cutoffs. The
original D/F and one host-generated case nonce are forwarded unchanged through
all layers; late setup cannot borrow a cleanup reserve. Post-wait and post-cleanup
clock observations reject a deadline exceeded while a synchronous API was
running. This is **not** hard cancellation of synchronous kernel/file operations.
The outer held process/Job ownership remains necessary containment.

The adapter owns a kill-on-close supervisory Job. Its fixed launcher is created
suspended, assigned to that Job, and checked for actual image/current identity
before the single resume. The launcher similarly owns the suspended probe; the
probe owns its actor Job. No breakaway or fallback is used. The new scoped
launcher lifecycle independently attempts stop, Job drain, handle observation,
and cleanup after errors. Each close consumes ownership before the API call;
failed close is sticky uncertainty and is never retried by bare handle number.
Private file streams also use a one-shot close ledger; uncertain exact stream
objects are retained rather than surrendered to an immediate destructor retry.
An unconfirmed process exit retains its held process owner. Job close is not
proof that profile/ACL cleanup completed.

## Private evidence and closed public projection

Private native JSON is independently read with an **8192-byte** cap,
strict UTF-8, duplicate/non-finite rejection, and exact comparison with the embedded actor
object. Launcher and probe JSON each have a **128 KiB** read bound. The launcher
and adapter recompute the nested predicates; neither trusts a reported pass
Boolean alone. Binding includes the original nonce and D/F, actual held launcher
and probe PIDs, current user SID, derived/observed child AppContainer SID, actor
nonce/mode/PID, both copied-image digests, suspended image admission, empty actual
capabilities, and independently observed held exits and pipe EOF.

The native pipe object is exact: attempted/inheritance-cleared/nonce-matched and
requires-controller-timeout true, 32 bytes read and written, win32Error 0, failure
null, plus the actor's successful pipe flag. Exit zero, EOF, Job-empty, one-shot
handle closure, exact owned ACE removal and profile deletion are distinct facts.
Valid bound echo evidence survives later cleanup or exit qualification failure;
Stage0b pass requires the entire conjunction. Malformed, replayed, mismatched,
unknown-ownership, or late evidence cannot become a pass.

The adapter writes only `public-stage0b.json`, a schema1 `stage0b-minimum` closed
projection. It contains no raw nonce, SID, PID, path, handle, actor bytes, stdio, or
exception text. `case_nonce_sha256` commits to the ASCII private nonce; the host
recomputes it. Creation-observed flags mean positive held creation evidence, not
a claim that a false flag proves no process ever existed. Identity, fresh actor,
echo, EOF, exit and cleanup flags are separate. Network, proxy and product
acceptance are always false. The fixed `/stage0b-result` transport wrapper also
retains independent launcher lifecycle facts when the report is unavailable;
valid positive facts are not discarded merely to fit a bound.

Both the public report and complete transport envelope remain bounded by 4096
bytes. The independent-field longest-label/false-Boolean composition measured
**895 bytes** for the pretty public report and **1204 bytes** for its pretty
transport envelope, each including its final newline. These are schema size
measurements, not proof that every independent maximum is jointly attainable.

## Disk admission and residual limits

Extra owned staging is **two actual actor copies** (each 512 bytes–8 MiB, hence
2A≤16 MiB), measured added source bytes, and an explicit **1 MiB planning
allowance** for reports, journals and trusted controller streams. The host must
include those bytes in its existing combined 128 MiB admission formula using
actual payload/runtime/actor sizes, not increase that cap or borrow the 65 MiB
capture reserve. The adapter checks remaining filesystem space before staging,
before the second copy can be created, and before public reporting. Failure does
not trigger a retry or reserve increase.

The planning allowance is **not an OS log/file quota**. Bounded parsers and
writers do not make every redirected stream a kernel-enforced bounded file.
Synchronous reads/writes may transiently allocate buffers, and the original outer
guest lifecycle remains responsible for final private-work cleanup. The adapter
does not delete an uncertain owned tree or declare VM destruction itself.

Pure tests compose the actual adapter, scoped launcher, probe checks and native
JSON readers with mock Win32 handles/clock, including current-token refusal,
pre-resume faults, partial creation, close-once failures, unknown exit, late
wait/Job observations, copied-image mismatch, stale nested bindings, duplicate
native JSON, strict public privacy/size, and cleanup downgrade with retained echo.
No VM or Windows runtime result is asserted by this code-only document.

## Activation boundary

The seventh runtime marker is mutually exclusive with all six existing modes;
128 marker subsets and unchanged legacy argument vectors are checked. The
reviewed short marker exercises tests only and cannot select the Stage0b guest
job. Runtime wiring reuses the existing IdentityOnly executable and its digest
artifact, with `httpCompiled=false`, static CRT, and measured 512-byte–8-MiB
admission; it does not introduce a second actor artifact. The 14-member payload,
validated source-SHA handoff, original baseline result and exact closed
`stage0b-public.json` publication remain separate. No private report is uploaded.

The existing five/eight-minute short gate is reused for 51 required suites,
PowerShell AST/mock semantics and seven-mode ZIP extraction. Its results are
not a genuine pipe exchange or target-Windows identity result. The future
runtime prerequisite workflow also retains its existing source-token native
projection control, so that workflow is not described as entirely compile-only.
Actual measured capacity, current ordinary identity, suspended-image/Job/SID,
absolute-deadline, exact echo/EOF and cleanup admission must all succeed in a
separately authorized bounded guest run; an enabled flag does not establish
those observations. Original Stage0 failure is never converted into overall
or product success by independent IPC evidence.

## Schema 2 closed failure diagnostics (code-only follow-up)

The first runtime's schema-1 `failure="report"` did not distinguish missing,
invalid or unbound launcher/probe/native reports. Because the adapter previously
read all three before projecting any, a missing later file could also leave
an earlier identity unverified. This does **not** establish that no child was
created, or identify that runtime's underlying failure. Its archived schema-1
result is unchanged; new public schema **2** is not a relabeling of old evidence.

Schema 2 retains every prior core fact and the same full qualification
conjunction. The extra `diagnostic.v=1` contains:

- `held`: actual launcher creation, resume, exit observation, nullable DWORD
  exit code, and the launch owner's cleanup observation. False means not
  positively observed, not proof that an operation never happened. This cleanup
  observation excludes later adapter report/token closure; the existing
  `adapter_cleanup_verified` includes those later uncertainties.
- `reads[3]` and `bindings[3]`, in launcher/probe/native order. Read states are
  not-attempted, missing, read-error, overbound, invalid UTF-8/JSON, duplicate,
  nonfinite, non-object, close-uncertain, or parsed (the wire uses fixed underscore
  labels). Parsed is not identity verification. Binding records the first failed
  verification stage, unavailable/not-attempted, or verified. Launcher/probe
  verified means their fresh invocation identity binding; native verified also
  covers the existing exact pipe, EOF, exit and nested-cleanup checks. These
  labels do not replace any core acceptance predicate.
- `stdout_reads[2]`, in launcher/probe order, and three `execution` entries for
  the adapter-owned launch, launcher, and probe. Each is null or the fixed tuple
  `[last_stage, first_failed_stage_or_null, category, operation, win32_or_null]`.
  The first error remains sticky through cleanup. `execution_sources` explicitly
  identifies `none`, `owner`, `report`, or `owned_stdout`. A source stage is an
  observation, not proof of actor execution. Only actual captured Win32 errors
  with an allowlisted operation have a numeric code; synthetic, unknown, and
  profile HRESULT errors do not acquire invented Win32 codes.

Launcher and probe scoped entries emit one best-effort diagnostic object to
already-owned redirected `controller.stdout`, at most **1,024 bytes**. There is
no new path, process, network action, permission, deadline, or retry. Original
return/raise behavior survives diagnostic-write failure. No output is emitted
for an invalid nonce/hash/deadline binding. The consumer reads only after the
held child exited and its image/current identity were verified before resume;
then it requires strict UTF-8, one duplicate-free finite JSON object, no surplus
non-whitespace, and the expected actor hash, nonce commitment and original D/F.
This is an **owned-stdio invocation observation**, not successful private-report
identity or successful nonce execution. Interpreter/import failures before the
wrapper, forced termination, or failed emission can still leave it unavailable.
Raw stderr is never parsed. Legacy non-scoped execution does not emit or consume
these records.

Reports are now read independently, so missing or invalid later evidence does
not erase an earlier independently bound identity or exact pipe observation.
A missing/invalid native report still cannot establish native identity or echo.
Every uncertain file close retains its exact one-shot owner and forbids cleanup
qualification; no bare handle/stream retry is introduced. Diagnostic absence or
malformation cannot manufacture success. The same original QPC cutoffs and
post-operation deadline checks remain in force.

The conservative independent-field size composition (longest enums, false
booleans, maximal numeric widths, including the longer signed outer exit code)
measures **1,922 bytes** public, **2,335 bytes** transport envelope, and **2,740
bytes** full host wrapper, each `indent=2` plus newline. This is a serialization
ceiling composition, not a jointly attainable execution. A valid all-fields
composition is separately tested. The diagnostic stdout upper composition is
437 bytes. All remain below their unchanged 4,096/1,024-byte limits; the existing
1 MiB staging planning allowance is not a filesystem or stdout quota. No valid
positive is dropped merely to fit the envelope.

## Single child-environment candidate (schema 3; code-only)

This candidate changes only the scoped probe's actor environment block from
`SystemRoot` alone to exactly **`SystemRoot` and `LOCALAPPDATA`**. It is not a
paired experiment, retry, environment sweep, or an explanation of the previous
CreateProcess error. The caller/launcher environment remains its existing four
keys (`SystemRoot`, `WINDIR`, `TEMP`, `TMP`). No native actor, token, capability,
attribute list, profile policy, deadline, or payload-member change is implied.

Before creating its fresh profile or granting ACLs, the ordinary probe uses one
fixed same-thread `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)` call. Observed
S_OK or S_FALSE permits one `SHGetKnownFolderPath` query for LocalAppData with
flags zero and NULL token; either success requires exactly one balancing
`CoUninitialize` attempt. A failed or unknown COM initialization, including
changed-mode, admits no query, fallback, or uninitialization. No COM security or
global settings are changed. The returned path is private: a bounded UTF-16,
existing local absolute non-reparse path is required; there is no environment
variable fallback. Every non-NULL returned allocation receives one
`CoTaskMemFree` attempt, including failed/unknown lookup or rejected path. Release
attempted/returned records only those calls, **not verified deallocation**.
Original QPC checks bound admission before and after these synchronous operations;
they do not promise hard cancellation of a kernel call.

Public schema **3** adds nullable `child_environment` and an explicit
`child_environment_source` (`none`, `report`, or `owned_stdout`). Its metadata is
exactly:

- `environment_version: 1`, `variant: "systemroot_localappdata_v1"`;
- `lookup_state`: `not_attempted`, `api_failed`, `path_rejected`, or `ready`;
- nullable unsigned-32 `hresult`, distinct from the existing Win32 diagnostic;
- Boolean `release_attempted` and `release_returned`;
- nullable Boolean `exact_child_keyset`, observed from the actual constructed
  child block, not inferred from the declared variant;
- `com: [initialization_attempted, hresult_or_null,
  uninitialize_attempted, uninitialize_returned]`;
- Boolean `deadline_verified`, the helper's final original-cutoff observation.

HRESULTs are the exact signed API result normalized to uint32. `api_failed`
means non-S_OK or an entered lookup with no returned HRESULT; it does not assert
Win32 semantics or necessarily a set HRESULT failure bit. `not_attempted` is
not used for an entered call. `ready` means S_OK plus admitted private path and
remains observable if later release, block construction, or deadline checks
fail. Full admission additionally requires both observed release returns, the
exact two-key block, and the final deadline observation. The old core
qualification conjunction remains required; missing or failed new admission
cannot produce a new-variant pass. Independently verified pipe evidence remains
visible after a later environment/cleanup qualification failure.

The same nested metadata appears in the private probe report (whose existing
outer schema remains 1) and in version **2** of its owned-stdout diagnostic.
Launcher stdout carries null child metadata. A private-report source requires
fresh probe identity binding; an owned-stdout source requires the existing
held-invocation and commitment checks, not successful private-report identity.
Thus observed lookup failure can survive a missing native actor report without
being invented from a requested option. Unavailable metadata is null, not a set
of false observations. Conflicting bound metadata cannot qualify. Historical
public schemas 1/2 and stdout schema 1 are not silently reinterpreted.

The revised conservative independent-field ceiling, `indent=2` plus newline, is
**2,340 bytes** public, **2,787 bytes** wire envelope, **3,226 bytes** host wrapper,
and **809 bytes** owned-stdout record. These are not jointly attainable execution
witnesses. Valid compositions and the conservative ceiling are both tested;
4,096-byte public/wire, 1,024-byte stdout, and 128-KiB private-report limits are
unchanged. The distinct `environment_version` key preserves the existing strict
closed-schema duplicate-key guard. No workflow or runtime authorization is
provided by this candidate.
