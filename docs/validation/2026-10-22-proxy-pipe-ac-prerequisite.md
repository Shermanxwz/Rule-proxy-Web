# Zero-capability AppContainer frontend / ordinary relay pipe prerequisite

## Scope and default-off boundary

This candidate is an explicit, default-OFF IPC prerequisite, not a proxy or network test. It replaces neither the historical IdentityOnly Stage0 result nor its acceptance predicate. It runs one synthetic HTTP protocol pair: a fresh zero-capability AppContainer frontend and an ordinary relay, connected by owned anonymous pipes. There are no sockets, DNS queries, forwarding, proxy configuration, network rules, additional capabilities, or fallback identity paths. A successful result cannot establish Linux equivalence, network isolation, production acceptance, or a private pipe security boundary against arbitrary peers.

The authoritative Python switch is `AC_EXECUTION_ENABLED=False` in the existing controller. Host and adapter consult the same exact-path/source-bound module object before runtime resource setup. This is same-process loader consistency, not tamper-proof authentication. The PowerShell opt-in remains independently off. No runtime is authorized by this document.

## Ownership and immutable deadline

The guest adapter verifies the current ordinary, non-elevated, non-AppContainer, zero-capability token and default compartment. It does not acquire an alternative token. The unchanged ordinary launcher creates the controller suspended, assigns its owned Job and checks the held image and token before a single resume.

The original guest QPC deadline and frequency are forwarded unchanged. Adapter work ends at `D−5F`; its cleanup ends at `D`. The pair deadline is `Tb=T0+10F` and must fit `D−30F`. Pair and ACL/profile cleanup must finish by `D−10F`; controller exit must be observed by `D−5F`. No stage renews the deadline. Synchronous native calls are not claimed individually cancellable; observed late completion cannot qualify.

The controller owns its fresh frontend profile, exact SID-scoped ACL grants, pair processes, handles and cleanup. Grants are limited to owned root RX, inputs RX and frontend-output M; relay output and the journal remain outside those grants. Exact-SID ACL readback is not a claim of universal effective-access denial. The adapter does not take over uncertain controller ACL/profile ownership. It reads only the fixed private report after the held controller exit is observed. Missing reports and uncertain cleanup are failures of qualification, never proof that no child existed. Private roots remain under the original outer guest cleanup lifecycle.

The actor and manifest reside at `bridge/windows_identity_proxy_pipe_actor.exe` and `bridge/identity-proxy-pipe-manifest.json`; the historical Stage0 `actor.exe` remains separate. The exact 17-member payload includes only the reviewed dependency closure. Manifest/executable binding is checked without requiring unpackaged native source files. No TEST_ONLY artifact is substituted. The composed capacity ledger is `P + expandedZIP + 24,405,990 + A0 + E + B + 1 MiB <= 128 MiB`, including the baseline copies and the pair executable copies. `P` is the downloaded payload ZIP, `A0` the original IdentityOnly actor bytes, `E` the executor member bytes and `B` the bridge executable bytes. The expanded ZIP already includes these members and the manifest; the additional `A0+E` accounts for retained payload copies, and `B` for the copied bridge executable. Admission also checks actual free space. This is a conservative disk-space planning bound, not a memory bound or filesystem quota.

## Evidence and privacy

A strict private controller report binds original run/case nonces, executable/manifest hashes, deadline/frequency, held controller PID, user and session. The controller validates its held frontend/relay observations and native report identities, including the fresh frontend SID and zero-capability profile. Private native reports are bounded at 8 KiB; the aggregate private controller report at 128 KiB. Their source hashes are controller attestations, not independent host token authentication.

The public result is bounded at 4 KiB, including its transport wrapper. It contains only four commitments (SHA256 of each ASCII32 nonce plus executable and manifest hashes), twelve fixed boolean facts, a nullable closed pair projection and closed error metadata. It contains no raw SID, PID, path, nonce, handle, environment value, command line, exception text, or native report. `controller_exit_verified` and `outer_cleanup_verified` come from the adapter's held-owner observations, not the child's claims.

Validated partial pair observations survive later controller-exit, cleanup or deadline failures. They do not turn an incomplete chain into a pass. `ac_pipe_passed` requires all twelve facts, the exact successful synthetic pair outcome, and no failure. The host separately requires the transport/VM cleanup conditions for `proxy_pipe_ac_ipc_qualified`; `network_tested`, `proxy_tested` and `product_acceptance` remain false.

## Pure regression boundary

The new tests exercise actual adapter dispatch, immutable argument forwarding, held-owner report binding, closed schema validation, missing/unknown report states, default-off behavior, one-shot token-close uncertainty, and preservation of bound partial observations. Injected Win32/launcher models are explicitly not actual Windows evidence. Controller-specific tests cover the profile/ACL/pair mechanisms separately. Maximum-width public compositions are independent field ceilings, not jointly emitted execution traces.

No publication, VM execution or new network experiment follows automatically from passing these tests. Exact source review and a separately authorized runtime decision remain required.

### Planned short-gate wiring

The candidate short gate explicitly lists 54 required Python test modules (the prior 51 plus the controller, AC guest and AC transport suites). Its new extracted-production PowerShell validator fixture uses 28 Python-produced parity cases, raw duplicate-key refusal, and mocked dispatch/process/HTTP seams. The actual payload generator-to-PowerShell selector/extractor fixture covers eight modes, including the exact 17-member AC payload, and 20 equal-count forbidden substitutions.

These counts describe the reviewed gate candidate, not completed Windows results: the new PowerShell fixtures have not yet executed. No actual AppContainer pair runs in this short-gate slice. Existing hosted non-AppContainer/core prerequisites remain separate mechanism evidence, not AppContainer evidence.
