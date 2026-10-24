# Direct 26300.9457 Stage0: exploratory compatibility only

## Decision and limits

This separate candidate tests the unchanged minimal deny-only request and native
identity actor on the existing, official Windows 11 Enterprise Evaluation 26H2
image. It is **not a supported-version or product-acceptance claim**. The current
MXC support table lists a 26H2 process-isolation floor of **26300.9550**; this
image is **26300.9457**, below that documented floor. A pass establishes only the
exact minimal request/native execution on this exact build. A failure does not
disprove the supported serviced Windows route. Product/privacy/network acceptance
remain false. The stock and serviced implementations and historical failures are
preserved unchanged.

Current support reference:
https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md

## Existing official media and prior evidence

- URL: https://software-static.download.prss.microsoft.com/dbazure/26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso
- Exact bytes: `8225329152`
- SHA-256: `bc3f24086ebadc94489066b5ad78089e2cf5c3491e90e790bb81a2b199c10e38`
- Official hash source: https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/09/verify-the-authenticity-of-a-windows-11-enterprise-evaluation-iso-file
- Prior run: `39220167668`, tested commit `a6a38caece1099babc8e67eb2f7622ae8a232525`.
- Prior closed assessment: `verification/windows-2026-10-19/compartment/psec-smoke-media/assessment.json`.
- Prior artifact: `12172336486`, SHA-256 `6d4ede4ef13874cc9ee8ac03cdb4881c66c2aab7a2a65a0cdcb9a017764bb68b`.

The prior run verified these exact ISO bytes/hash and installed WinNT/AMD64
26300.9457. It used the same unattended file (blob
`cd817822b67481a0f366027dcd5afafcea4feb27`) selecting image index 1. This reuses
the existing evaluation-license/unattended flow; no new account or license flow
is introduced. The old request was rejected for host-loopback ingress **allow**,
and no isolated actor ran. It reported the BaseContainer API present, but that
is not execution or official support evidence. Current pinned-G qualification
and actual actor/token/nonce/BaseContainer/exit checks must all pass afresh for
the narrower deny-only request; optional unrequested capabilities do not become
new required features.

## Unchanged security and execution boundaries

- Same pinned G, native actor source/hash verification, deny-only policy and
  proof checks; no DACL fallback or weaker backend accepted.
- Same ordinary local account, normal startup launcher and fixed installed C:
  identity checks; exact WinNT/AMD64 build 26300, UBR 9457 required.
- No update worker, SYSTEM test task, MSUs, servicing, optical replacement or
  second local account. The ordinary actor still does not run in SYSTEM context.
- Closed early failure diagnostics, bounded setup/OOBE completion wait and
  2100-second installed-beacon admission cutoff are retained.
- Same owned-process cleanup evidence, 22 GiB file ceiling, 4 GiB live free-space
  stop, 24 GiB launch admission and existing preparation constraints.
- Same 120-minute workflow budget and 6900-second absolute deadline with cleanup
  reserve. No new paid capacity, user-device actions, main merge or release.

## Resource uncertainty, not an assumed fit

Relative to the old ISO, the new ISO costs another 1,132,521,472 bytes. Applied to
attempt 02's measured launch space, projected free space is 26,340,235,264 bytes
(24.531 GiB), only 0.531 GiB above the existing launch gate. **Actual preflight
space, not this estimate, decides admission.** At the old measured disk allocation
it would leave approximately 9.573 GiB free, but the new installed footprint is
unknown under this harness. Retaining the larger ISO means the live reserve can
stop allocation near 20.531 GiB, before the nominal 22 GiB file limit. No reserve
or file-cap relaxation is proposed. Historical 26H2 allocation came from another
harness and is not proof of fit here.

The direct ISO transfer is proposed with a bounded 1800-second subprocess cap
(1780-second curl transfer cap), instead of the smaller-image 1220-second cap.
It remains clipped to the existing absolute work deadline, which already excludes
the cleanup reserve. Preparation cannot extend that deadline, and the unchanged
minimum guest-work admission still rejects insufficient remaining time.

## Publication and verification

The new direct workflow is separate and initially has native execution disabled.
Its gates-only marker runs Windows parsing/executable synthetic predicates,
native actor compilation, and required Linux units; no VM or recovery occurs in
those jobs. A separately reviewed activation and one-run decision are required
before any direct-image runtime. There is no automatic replay.
