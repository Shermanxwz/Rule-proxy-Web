# Serviced Stage0: pending-source diagnostics and bounded extra-reboot candidate

Status: code-only candidate, not runtime success or product acceptance. Attempt 07
reached `post_reboot_verify` with packages verified and DISM exit 3010, but failed
`reboot_still_pending`. The former aggregate `reboot_observed=false` does not say
which pending indicator was present. No extra restart has been demonstrated by
this candidate's fixtures.

## Diagnostic observations

`pending_reboot` contains only nullable booleans: `c` is CBS RebootPending key
presence, `w` is Windows Update RebootRequired key presence, and `r` is the existing
nonempty PendingFileRenameOperations predicate. These are independent adjacent,
non-atomic observations, with null for unavailable/read failure. The original
short-circuit authoritative registry predicate is unchanged. Diagnostic read
errors never replace that predicate or grant acceptance. Empty destination strings
are not filtered; the original array-count semantics are preserved.

## One additional request, not a retry loop

The mandatory initial reboot checkpoint now explicitly contains integer
`extra_reboots=0` and `latest_reboot_boot=before_boot`. Protected receipt validation
requires exactly integer 0 or 1 (not bool/string/coerced input), a valid boot string,
and consistency: count 0 means latest equals original; count 1 means they differ.
Missing metadata is rejected, not migrated or reset. The original seven-part
prior-state guard remains unchanged and is followed by this separate validator.

After fresh complete optical package verification, exact 26200.9711, and a boot
changed from both original and latest request witness, pending indicators may
trigger one additional request only when count is 0. DISM success/observation
flags remain required for that request. At least 3000 seconds must remain on the
same immutable deadline, both before atomic checkpoint replacement and immediately
before requesting restart. The checkpoint consumes count 1 and records the current
boot as latest before the request. There is no deadline extension, second DISM,
registry deletion, ignored pending indicator, or repeated reboot loop.

An interruption after checkpoint persistence but before restart intentionally
fails closed on a same-boot invocation. The request is not reset or retried.
Write/request/deadline failures enter existing terminal failure handling. After
an actual subsequent changed boot, pending indicators must all clear; count 1 with
pending still present fails. Final exact build, no-pending, task removal and native
identity checks remain mandatory. `extra_reboot` exposes only strict count `n`
and nullable latest-witness-changed observation `b`; no boot identifiers escape.

## Validation and limits

Linux source-contract tests cover production linkage, strict types, write-before-
request ordering and both reserve checks. Windows semantic fixtures execute actual
production helpers and the protected atomic writer/JSON reader with mocked restart
and clock: DISM exits 0/3010, 2999/3000-second admission, write/request failure,
time consumed during the write, duplicate request, same boot, still-pending after
one request, malformed/missing metadata, and simulated interruption after save.
They do not create tasks, change accounts, edit registry, reboot or run a VM.

The owned ACL fixture explicitly assigns a trusted owner; it does not prove the
ordinary-token read or guest SYSTEM's natural ownership behavior. Additional
restart feasibility and actual Windows servicing completion remain unproven.
The fixture prints only closed booleans/counts/fixed labels, never raw registry
values or boot witnesses. Shared policies, native acceptance, host resource caps,
cleanup and absolute deadlines are unchanged.

The Windows fixture also extracts and executes the actual outer production catch
AST after write/request/post-write-deadline failures, uses the real atomic writer,
and requires a rejected terminal failed receipt. The first write-failure fixture
is one-shot so the terminal receipt write remains possible; a persistent-write-failure fixture verifies no request/no success and byte-exact
previous-checkpoint retention. Such failure remains bounded by existing host
teardown, not a promised receipt.
AutoLogon count 3 nominally covers initial plus two restarts, but prior consumption
is unobserved. Exhaustion can prevent ordinary reporting and fails within the host
bound; it is not a guarantee of further login or servicing success.
