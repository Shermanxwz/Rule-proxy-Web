# Native proxy-pipe mechanics — inactive hosted-only slice

This is a separate mechanics experiment, not a proxy or network-isolation test.
The existing bridge codec/model/core, identity actor, Stage0b, workflows and
payloads are unchanged. Code and pure mocked tests do not establish Windows pipe
behavior. Any actual invocation requires a separate approved gate.

## Fixed experiment

The controller admits three fresh cells only: successful exchange, deliberately
mismatched case IDs, and a relay deliberately left suspended. Each cell has one
owned kill-on-close, non-breakaway Job and two children of the same pinned native
image. Both children are created suspended, assigned and verified against their
held process handles before either is resumed. Their inherited handle lists each
contain exactly two disjoint anonymous-pipe endpoints. There is no inherited
stdio third handle, socket, ACL/profile creation, linked-token fallback, or token
mutation. The parent consumes and attempts all four endpoint closes; every close
must be confirmed before either ResumeThread. Each resume must observe prior
suspend count one. The held controller and child tokens are non-AppContainer,
same-user and same-elevation; hosted elevation is an observation, **not** proof of
an ordinary-user profile. Query-token handles remain owned until finalization to
avoid a numeric handle-reuse gap in the unchanged one-shot ownership ledger.

A single suite QPC deadline is captured before owned setup: D = initial + 60F.
Each cell's T0 is captured immediately before its first suspended creation; its
Tb = T0 + 10F must fit D − 30F. Setup consumes the original allowance; slow setup
can prevent later cells. Cleanup uses only the original D, without renewal.
Synchronous native/file APIs are not claimed hard-interruptible by these checks.
Both held children are independently observed or stopped, the Job must be empty,
and all owned handles have one close attempt. Unknown creation without a usable
process handle, uncertain closure or unknown exit prevents qualification and
stops the suite. Files or an empty Job never substitute for held-child exit.

The successful wire uses fixed 48-byte INIT, READY, REQUEST, RESPONSE and DONE
frames. Frontend success is 96 bytes/two frames read and 144 bytes/three frames
written; relay success is the converse. EOF and actual endpoint closure are
independent requirements. The relay request, origin response and client sink are
**synthetic in-memory HTTP**, not a network exchange. A mismatch requires the
bound frontend's frame refusal and the bound relay's actual broken-pipe read
failure; generic failure is not an expected counterexample. Withholding relay
resume tests the controller's bounded owned-Job watchdog, not proof of which
instruction the frontend was blocked in.

## Evidence and bounds

Native reports are fresh CREATE_NEW files, at most 8 KiB each. Only after held
exit does the controller parse strict UTF-8, duplicate-free finite JSON and bind
role, run/case identifiers, PID, held identity/image hash and original QPC inputs.
Parsed data alone is not identity evidence. Typed partial pipe observations are
retained when later cleanup or qualification fails. Native report-close success
is additionally qualified by its held exit code, never inferred from JSON alone.
The aggregate private report is at most 128 KiB. Public output is closed and at
most 4096 bytes; it contains no SID, PID, nonce, handle, argv, path or private error
text. The exact native image digest is public; raw identities stay private.

One image copy is shared by both children in each cell. Admission counts three
actual image copies (each at most 8 MiB), six 8-KiB native reports, a 128-KiB
aggregate, a 4096-byte public allowance and measured new source sizes against a
128-MiB conservative planning boundary, with fresh free-space checks. This is not
a filesystem quota, peak-memory guarantee or guest-payload capacity claim. No
capture reserve is borrowed. Owned private trees are retained for controlled
inspection; no deletion is claimed as process cleanup.

`network_tested`, `proxy_tested` and `product_acceptance` remain false even if all
three cells qualify. Later zero-capability AppContainer frontend/ordinary relay
experiments and any real HTTP/socket integration are separate decisions.

## Final receipt and size witnesses

There is no redundant `public.json`. The sole authoritative public receipt is
one bounded ASCII JSON line on stdout, emitted only after the private aggregate
write and close, process/Job/handle finalization and the final original-deadline
check. A future owner must observe a complete single line, EOF and exit zero;
partial output, write/flush failure, nonzero exit or unknown delivery cannot
certify success. The receipt cannot prove its own delivery. Intentional retention
of the private tree is independent of process/Job/handle cleanup.

Pure tests measure conservative independent-field compositions, not a jointly
valid successful report: the complete admitted native identity shape with maximal
SID/numeric widths is 1,521 bytes, six such reports plus aggregate bindings are
13,254 bytes, and the public receipt is 2,222 bytes (all pretty-printed with a
terminal newline). Native error/capability reports outside the admitted identity
shape are not asserted to fit this witness: the actual native writer and reader
still enforce 8 KiB, and oversized/unbound reports cannot qualify. Aggregate and
public hard bounds remain 128 KiB and 4096 bytes respectively. Tests preserve
pipe observations when final private-file close or QPC qualification fails.

## Dedicated gate ownership

The separate `windows-identity-proxy-pipe-gates.yml` adds only an explicitly
marked hosted gate; existing workflows remain unchanged. Linux runs the required
pure suites. Windows first runs those suites and compiles the pinned actor, then
uses the explicit bounded outer test helper for the same three cells. No actual
Windows mechanics result is established by this source-only revision.

The outer helper starts its absolute 65-second allowance before controller
creation; the inner suite still has its original 60 seconds. A reader retains at
most 4097 bytes to detect overflow against the 4096-byte receipt limit. Timeout
or overflow ends admission and stops the exact held controller, followed by at
most five separate seconds for independent exit, reader-stop and one-shot handle
cleanup. Unknown reader/handle owners are retained. Forced controller termination
leaves descendant cleanup **unknown**, regardless of expected Job behavior or a
previously emitted receipt. No unbounded `communicate` or name-based kill is used.
The final owner requires the strict receipt, EOF, zero controller exit and its own
confirmed cleanup. Its complete nested receipt measures 1793 compact or 2854
pretty-printed bytes including newline in a conservative independent-field
composition; the unchanged final output limit is 4096 bytes.
