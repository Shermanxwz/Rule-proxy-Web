# UDP descendant wrapper: standalone mechanism slice

## Question and scope

The next engineering question is whether a normally created descendant retains the selected container identity and network boundary. This first slice does **not** answer it: it builds a socket-free parent wrapper and tests owned loopback mechanics on a hosted Windows runner. There is no Windows guest adapter, runtime marker, packet capture, production network invocation or AppContainer-inheritance acceptance in this slice.

The existing UDP production child, identity source, policy, direct TCP paths and VM harness remain unchanged. REQUEST3 DNS experiments remain parked. Direct UDP is not DNS-client or broker evidence.

## Creation and identity contract

The production parent must satisfy its strict role-specific profile before creating a child. It uses an explicit pinned child application path, bounded fixed arguments, `bInheritHandles=FALSE`, and exactly `CREATE_SUSPENDED`. It does not select another token, enable privileges, create/assign another job, request breakaway, or alter security settings.

The parent retains the returned process and primary-thread handles immediately. It queries primary tokens through its own process handle and the held child process handle, requesting only `TOKEN_QUERY`. Returned token buffers and SID pointers/header/length are bounded before SID validation or comparison. A contained pair requires both AppContainer flags and valid non-null equal AppContainer SIDs. An ordinary pair requires both non-AppContainer flags and null AppContainer SIDs; this is not an AppContainer SID-equality observation.

Failed token queries or mismatches never resume the child. Exactly one `ResumeThread` is allowed; only a returned prior suspend count of one is normal. The child independently executes its unchanged self-profile guard before any socket. Suspended creation prevents a fast child from exiting before the parent's pre-resume token observation, but changes the scheduling shape relative to immediate creation; it does not establish a universal inheritance contract.

## Provenance and lifetime

An eventual pinned executor audit event would bind the wrapper parent only. The returned creation PID, held child handle, fresh child report nonce, same-buffer report digest and pinned executable form a separately labeled **parent-attested child chain**. This is not a controller-held child handle, PPID observation or independent PSEC cleanup proof.

Only a signaled wait on the held child handle permits treating its unsigned DWORD exit code as terminal. Exit code 259 alone is not a liveness test. The executor's signed32 parent exit code is a separate domain.

Every call uses one immutable deadline clipped to its original allowance, with cleanup reserve inside that allowance. Stop/wait/final-observation and one-shot handle closes are independently attempted; failures remain sticky. No bare-handle retry after uncertain closure, PID reopening, new work allowance or timer reset is allowed. Killing a wrapper does not independently prove its descendant exited. Unknown exit or handle ownership prevents a cleanup-complete claim and retains potentially live owned files.

Already attributed raw send acceptance, explicit send-denial or payload observations must survive later control/cleanup failures. Qualified packet absence still requires its separate complete controls/capture/cleanup contract. This standalone slice produces no packet-absence outcome.

## Hosted evidence limits

Production is compiled and invoked only with invalid CLI. Hosted mechanics use separate compile-time TEST_ONLY parent/child artifacts and an owned loopback UDP responder. A profile-only path runs the real profile checks without child creation or sockets. Hosted ordinary null-SID pairs do not prove actual AppContainer SID inheritance, nonadmin positives or a valid production CLI runtime guard.

The token-failure, SID-mismatch and resume-failure negatives are compile-time fixture injections. In particular, the resume-failure case refuses before calling `ResumeThread`; it does not demonstrate an actual failing API call. Positive cases require the real single call to return one. A short-budget sample exercises actual child timeout and held-handle termination/wait, separately from these injected controls.

Public gate output is closed status/count/cleanup data, not raw SIDs, PIDs, handles, paths, nonces or child reports. Compiler diagnostics may contain source paths; they are not the closed mechanism report. No artifacts or full guest runs are enabled by the standalone short workflow.

## Primary API basis

- [CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw)
- [Process creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags)
- [ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)
- [OpenProcessToken](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocesstoken)
- [EqualSid](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-equalsid)
- [TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess)

These describe API mechanics, not empirical PSEC inheritance or network isolation on this build.

## First hosted compile observation

Run 39625534900 (head e2bcbcbe) passed 383 required Linux tests but failed the Windows build under the retained `/WX` setting. The compiler instantiation trace identified an `optional<DWORD>` comparison with a signed literal and an implicit `wchar_t`-to-`char` iterator assignment. Windows unit and mechanism stages did not run. The narrow follow-up uses `DWORD{1}` and maps the four already validated phase names to explicit ASCII literals; it does not suppress warnings, broaden input or establish any native mechanism result before the corrected gate executes.
