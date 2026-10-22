# Stage0b minimum integration — inactive code-only candidate

This optional branch is default **OFF**. It replaces, rather than appends to,
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
