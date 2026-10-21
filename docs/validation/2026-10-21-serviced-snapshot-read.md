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
