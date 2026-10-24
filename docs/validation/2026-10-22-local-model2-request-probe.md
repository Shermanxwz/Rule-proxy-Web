# Local model2 candidate request probe

This separate entry is a request-parser and host-tier observation. It does not
change the already measured local AC IPC entry, create a peer/profile, start a
contained workload, configure a proxy, or test networking. Its uncreated peer
name is deliberately a placeholder. A supported candidate is not a live-peer
admission or model2 runtime qualification; the final workload and observed peer
still require their own exact request and actual positive/negative observations.

## Pinned primary sources

All implementation references below use upstream
`7bf210247986cb73b1b314df60c2f1109c479c0b`, the source of the existing G pin.

- [Exact stable 1.0.0 schema](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/schemas/stable/mxc-config.schema.1.0.0.json): the complete one-shot document requires `version` and `process.commandLine`. The candidate supplies an inert command, empty replacement environment and a bounded timeout, with no lifecycle operation.
- [Proxy parser](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/core/mxc_common/network_parser.rs#L225): a runtime proxy requires deny-default egress without direct allow/deny rules. An identity peer requires ingress allow and hostLoopback deny. The parser validates nonblank peer syntax and the reserved-name conflict; it does not establish a live listener or observed peer identity.
- [Request probe](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/core/mxc_engine/request_probe.rs#L20) and [tier decision](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/base_container_runner.rs#L353): policy compatibility and host capabilities are queried without creating a PSEC environment. Actual environment creation occurs later in the launch path, outside this entry.
- [CLI ordering](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/tools/wxc/src/main.rs#L1041): startup recovery runs before the probe arm. Library-probe read-only comments do not make this CLI unconditionally read-only. A successfully serialized detector error still returns from main normally; config-load/serialization errors exit nonzero.
- [DACL recovery](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/core/mxc_common/filesystem_dacl.rs#L522): recovery can restore ACEs, remove/rewrite journals or quarantine corrupt journals. The supported deployment override is `MXC_DACL_STATE_DIR`; an absent state directory returns without creating it.
- [Model2 contract](https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/docs/backends/process-container/networking.md#model-2-proxy-only-egress-recommended): real peer identity, exact endpoint enforcement and proxy inbound firewall authorization are distinct requirements.

## Candidate request

`request_document` creates the exact stable-1.0.0 document. It uses a fresh
`RuleProxy.IdentityProof.<32hex>` placeholder and numeric
`http://127.0.0.1:49183`. It contains egress deny, ingress allow, hostLoopback
deny, allowedProxyPeer, runtimeConfig.networkProxy and allowDaclMutation false.
It contains no direct rules, explicit capabilities, capture settings,
enumeration grants, telemetry opt-in or fallback permission. The unused process
command exits 97 if mistakenly invoked through a different entry; this wrapper
has a fixed four-argument executor command containing `--probe --config`.

The supplied process metadata is not a future actor/browser configuration.
This candidate answers whether this policy shape parses and which tier the
current host would select. It cannot verify placeholder existence, authorize
proxy ingress, connect to the endpoint or establish network enforcement.

## Local owner and reaper isolation

Default invocation does not execute anything. Preparation statically verifies
the pinned bundle, its exact three members, matching extracted files, manifest,
license and x64 image; it writes a request only at the requested destination.
It binds the current ten-source closure with a new hash and leaves old source
manifests unchanged.

The explicit runtime mode requires the prepared source commitment. It samples
one actual QPC epoch before all setup and preserves a 120-second absolute
deadline. Staging must finish while at least 30 seconds remain; executor work
ends at D-15 seconds and outer held cleanup at D. Earlier admission reserves
45 seconds. No layer renews the clock.

Work is confined to an existing repository `private/` directory or one of its
existing descendants. Each run creates a fresh user/SYSTEM-only protected root,
temp directory and empty DACL-state directory. It changes no ancestor ACL.
The possible-residue flag is set before private directory creation because
creation may succeed before readback or descriptor release fails. The state
root and its exact DACL/emptiness are rechecked immediately before process
creation. No caller or default recovery-state contents are read or reaped.

The executor receives exactly five child-only environment keys:
`SystemRoot`, `WINDIR`, `TEMP`, `TMP`, `MXC_DACL_STATE_DIR`. The first four are
the existing native-derived launcher environment. The fifth names only this
run's fresh state root; no global environment variable is changed.

The entry reuses `LocalNativeAPI` and `launch_owned`: creation-time JOB_LIST,
noninheritable kill-on-close non-breakaway Job, suspended image and same-current
ordinary-token checks, then resume. The staged G executable is rehashed before
resume. The wrapper holds the Job; the executor cannot inherit its last handle.
Kernel exit, Job empty and one-shot handle cleanup are required before a
candidate result can qualify. All private files are retained for review; there
is no recursive delete, profile cleanup, rule cleanup or VM-destroyed claim.

## Closed outcomes

- `prepared`: source/artifact/request bindings only; no native execution facts.
- `supported_candidate`: zero CLI exit, complete ownership/cleanup, empty state
  after exit, bounded closed output, base-container tier, API present, no DACL
  augmentation or detector error, and BFS compiled out.
- `unsupported_candidate`: the same complete mechanism evidence, but the
  closed detector result does not qualify for the candidate tier.
- `failed`: incomplete invocation, malformed/unknown output, unexpected stderr,
  nonzero exit, timeout, deadline failure, changed state, source drift or
  uncertain cleanup. A valid already-read detector projection remains sticky
  even if a later CLI/cleanup check fails.

Peer/listener observations, network/proxy tests, model2 runtime qualification,
original strict Stage0 and product acceptance remain false in every outcome.
The new pure suite uses fake APIs and clocks; it is not a native execution
receipt. The primary thread owns any later explicit runtime invocation.
