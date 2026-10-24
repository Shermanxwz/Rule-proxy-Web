# Serviced receipt snapshot and advisory sender diagnosis

## Observed attempt 09

Run 39530908470 at commit `7c6c0c7e4d0d0f1e530840649ede662985f07e6a` reached the ordinary installed beacon and host servicing admission. The ordinary reader then reported `receipt_read` / `read` with HRESULT `0x80070020` (sharing violation). Setup clock and budget observations succeeded. No servicing receipt, pending-source result, extra-reboot result, probe, or actor result was observed. All owned teardown facts, including the new diagnostic reader and socket, were confirmed; the original failed Stage0 result remains unchanged.

The SYSTEM producer writes a separate temporary file and publishes it with initial Move or subsequent Replace. The exact competing handle responsible for this sharing violation is not known. A sharing-compatible snapshot read is a harness compatibility change, not a filesystem permission grant or acceptance relaxation. Protected ownership, ACL, reparse, size, JSON, state, exact-build and reboot checks remain required.

The COM2 observer remained enabled but accepted zero records and counted seven rejection/discard events. These are not seven identified helper messages: serial-probe noise, actual helper startup/exit, and hardware delivery are not resolved by this result. Raw serial bytes were not retained. Source-generated expected lines pass all fragmentation boundaries and LF/CRLF variants, but that does not establish actual guest transport.

## Candidate scope

The proposed receipt reader opens a bounded shared handle, strictly decodes UTF-8, and retains the existing validation pipeline. Only the specific sharing error receives a finite retry clipped to the unchanged immutable servicing deadline; other failures remain failures. Tests must exercise actual Windows two-process atomic publication and an exclusive-lock counterexample, not merely mocked Get-Content behavior.

Telemetry tests must execute the real child parameter binding and record construction with explicitly test-only guard and private serial-sink substitutions. Untrimmed bytes remain private and go through the production parser. These fixtures do not prove real COM2 hardware delivery or a genuine ordinary guest token. Diagnostic sender exit/timeout observations and fixed rejection categories are not acceptance or authenticated sender evidence. Existing sender waits, quotas, VM deadlines and cleanup boundaries are not widened.

## Separate direct-build option, not activated

The last actual direct 26300.9457 attempt predates the capability classifier. Current shared proof code carries the classifier and same-guest source comparison, but the direct workflow still executes the old provider-cache deletion recovery. It must not be launched unchanged. Any later independent direct diagnostic requires a separately reviewed no-deletion preflight and remains below the documented 26300.9550 support floor, exploratory and non-product acceptance. No direct workflow changes or runtime are part of this candidate.

## API contract references

- [Windows error 32](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) identifies a sharing violation, not the responsible process.
- [ReplaceFileW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-replacefilew) documents distinct target/replacement access and sharing behavior.
- [.NET FileShare](https://learn.microsoft.com/en-us/dotnet/api/system.io.fileshare?view=netframework-4.8.1) controls coexistence of open handles, not file ACL grants.

A successfully opened snapshot may be the old or new complete receipt, not necessarily the newest generation. Existing final state, build, reboot, task and ordinary-user gates continue to decide eligibility. The Windows runtime uses KVM; only the separate tiny QEMU gate uses TCG. A three-second sender startup wait being insufficient in the actual guest remains an unproven hypothesis, not grounds for widening it.

## Closed diagnostic semantics

`sender_stats` is a fixed eight-cell array: SYSTEM four cells followed by ordinary-launcher four cells. Each role is either four nulls (unobserved/unusable) or bounded exact integer counts in the order `[start_attempt, exit_zero, exit_nonzero, first_wait_false]`. Counts are invocation-local snapshots, not cumulative across reboots. The fourth count means the first bounded wait returned false; it does not include exceptions or unknown wait outcomes. It may overlap an observed exit after an exact owned-child kill or race. Exit counts require an observed exit and readable exit code. Receipt snapshots can precede later final telemetry sends; no extra receipt write is introduced solely to refresh diagnostics.

Host-only rejection categories are fixed parser classifications, with independently saturating counters. At saturation, their sum need not equal the separately saturated total. They identify framing/schema rejection reasons, not authenticated SYSTEM/ordinary sender failures or the meaning of unretained input. Neither sender counters nor rejection categories participate in Stage0 acceptance.

The concurrent writer fixture requires the hosted child to create naturally trusted-owner files or fails; it does not relax production owner checks. Its initial controlled file can use an explicitly trusted owner and is not proof of SYSTEM-created ownership. An unconfirmed fixture-child exit retains the owned fixture root. Actual DenyReadData and 4,096/4,097-byte boundary controls must pass on Windows before treating the new reader gate as tested.

## Pure Windows observations after the first candidate

- Run 39535472456 failed the real concurrent receipt fixture with file-not-found (`0x80070002`), with the exact call site then unobserved.
- Run 39536504892 localized a later stress failure to the protected receipt ACL/path admission, not JSON parsing. Its independently scheduled actual-child sender seam passed all 81 checks, including exact twelve CLI-derived records. Real COM2 hardware delivery remained untested.
- Run 39537280067 passed the stable first child-created replacement: owner and write DACL were trusted, the directory protected, and leaf nonreparse. During subsequent rapid replacement, the exact failing predicate was the leaf `update_reparse_point` guard. A later adjacent leaf observation was trusted and nonreparse. The failing FileInfo Attributes value was not captured, so a missing-path `-1` metadata race is a supported hypothesis, not a directly observed value. This does not justify ignoring reparse checks or general ACL/file-missing retries.

All three pure runs preserved failed compile status, skipped native runtime and confirmed owned fixture cleanup. Any next same-handle snapshot design must validate the actual opened leaf's attributes and security before reading, while retaining protected-parent checks and all existing bounds and final acceptance predicates.

## Same-handle follow-on candidate

The follow-on removes leaf pathname metadata/ACL checks from the snapshot sequence, not their security requirements. After validating the protected parent, it opens the fixed leaf with non-inheritable `CreateFileW` / `OPEN_EXISTING` / `FILE_FLAG_OPEN_REPARSE_POINT` and read access with Read/Write/Delete sharing. It rejects non-disk, directory, reparse and oversized objects from that handle, then uses `FileStream.GetAccessControl()` on the same handle for trusted owner, non-null DACL and unchanged untrusted-write-rule rejection. Only then does it read and strictly decode bounded bytes from that same stream. It does not follow a final symlink and inspect its target afterward.

The protected-parent invariant is still required; this does not claim atomic validation of every ancestor. Access denied, missing file, reparse, owner/DACL and malformed data remain failures, not newly retried conditions. The existing four sharing-error-only attempts and immutable deadline remain. The old or new complete generation may be read, but the unchanged downstream state/build/reboot/ordinary proof conditions still decide acceptance. Native handles and streams are owned and disposed on failure paths; no privileges, permissions or account settings are enabled by the reader.

New real Windows fixtures must reject an owned symlink/junction, directory, untrusted owner, untrusted write ACL, null DACL and denied read, and demonstrate that an already-open snapshot remains tied to its original file through a pathname replacement. These are fixture requirements until their actual gate passes, not assumed results.

Directory and junction negatives may be rejected by CreateFile access denial because the reader does not request backup semantics; a passing negative does not assert that a directory handle was opened and inspected. The file-symlink target fixture contains an otherwise valid receipt. Handle ACL failures remain terminal even if an underlying ACL operation reports sharing error 32; only the existing open/read sharing boundary is retried.

## Narrow open-missing follow-on

Run 39538448123 passed stable replacement but failed rapid stress with base error `0x80070002` under `receipt_read`; ownership/ACL was not the reported failure. That diagnostic does not identify CreateFile versus handle metadata or stream operations. The combined follow-on therefore tags the exact native API boundary and permits error 2 only when it originated from CreateFile before a valid handle exists. It does not reinterpret arbitrary receipt-read or metadata errors as open failures.

This supersedes the previous candidate's sharing-only retry description solely at that tagged open boundary. The same total four attempts, existing clipped sleeps and immutable deadline apply; protected parent and each newly opened no-follow handle are fully revalidated. Persistent absence still fails without creating a file. Metadata error 2, all ACL failures, decode errors and untagged missing-file errors remain terminal. Windows controls must cover persistent missing, transient first-open missing, non-open error 2 rejection and real concurrent publication before any runtime decision. No claim is made that the previous untagged error 2 was definitely an open failure.
