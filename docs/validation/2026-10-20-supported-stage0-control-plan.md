# Supported-release control: bounded plan, not an isolation result

The direct 26300.9457 diagnostic run 39452582970 executed a fresh native actor
and exited normally. Its sole failed identity predicate was the unchanged
`tokenCapabilities == []` requirement. Every other existing identity conjunct
passed; cleanup was independently confirmed. This remains a failed Stage0,
not proof of network isolation or a reason to silently loosen acceptance.

## Version and request scope

The existing pinned official 26200.6584 installation plus its already-pinned
checkpoint/CU packages targets exactly 26200.9711. Current upstream
[OS support documentation](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md)
(document blob `b40a25d82f9d2dbf0826a10c116902bf66a3b645`) lists the 25H2
Process Isolation floor as 26200.9278. Session Isolation's 26200.9550 floor is
separate. Microsoft's [KB5120998](https://support.microsoft.com/en-us/servicing/os/windows-11/2026/08/kb5120998-windows-11-24h2-25h2-update)
places this feature in a gradual rollout, so a build number alone cannot prove
an enabled contract. The pinned executor's older documentation differs and
requires runtime request-aware qualification. Exact official installation,
post-servicing reboot/build, BaseContainer selection, fresh actor observations
and all original acceptance checks remain necessary.

This route avoids researching new 26H2 packages; it does not avoid the still
unverified full update-media, Windows multi-extent optical reading, DISM growth,
reboot and protected-task cleanup stages. The tiny QEMU gate proves media API
compatibility only. Policy, two-entry environment, executor pin, account and
native actor are unchanged. No network/broker/child/browser acceptance is added.

## Read-only preparation, no provider-cache recovery

This supported-control workflow does not execute provider-cache recovery or
remove provider Android/.NET/Swift installations. Before checkout it only
observes free space and filesystem identity, creates one new owned report
directory, and requires 64 GiB plus the existing 512 MiB preparation allowance.
Insufficient space stops without attempting recovery or changing runner size.
The artifact is explicitly `serviced-capacity-preflight-public` with kind
`read_only_capacity_preflight`; it is not a recovery-success receipt. All preparation checkpoints and the APT-plan validator use the serviced
module and the same 64 GiB floor; an executable integration test feeds the
actual embedded baseline into that production parser and first checkpoint.
The independent host capacity guards stay in force. Other historical workflows and their records are unchanged.

## Proposed storage bounds on the same standard free runner

The latest public run measured 83,539,902,464 bytes (77.803 GiB) free at QEMU
launch, after its installer and payload were already present. This is an
observation, not a promise about the next runner. The proposed serviced limits
are a fixed 48 GiB backing-file cap (80 GiB virtual disk unchanged), 64 GiB
pre-media admission and 54 GiB secondary launch admission. No larger or paid
runner is requested.

A conservative pre-media peak includes the full backing cap even while the
VM is paused: 48 GiB + max(6.606 GiB original installer, 9.904 GiB temporary
MSU-plus-update-ISO duplication after installer reclamation) + 5 GiB projected
reserve + 1 GiB sidecar allowance < 64 GiB. Installer reclamation requires
verified frontend detach and both QMP inventories free of references. Source
MSUs are removed only after full update ISO member verification. Packages are
not copied into the guest.

Independent phase admission still uses actual free/allocated bytes, not this
rounded estimate: free minus temporary media must remain at least 5 GiB; free
minus final additions minus (48 GiB minus currently allocated backing bytes)
must also remain at least 5 GiB. The existing live 4 GiB stop remains. Admission
or capacity failures stop the trial; none establish that servicing will fit.

## Proposed single deadline chain

The native job is bounded to 180 minutes. Its initial absolute deadline is
175 minutes, leaving five minutes for outer artifact/finalizer steps. The
native step is clipped to the remaining deadline and 161 minutes, then gives
the host a further 30-second termination margin. The host is capped at 160
minutes, clipped by that absolute deadline, and reserves 180 seconds for
owned cleanup. At least 9000 seconds must remain at host admission.

The 2100-second no-installed-beacon bound remains unchanged. Media preparation
requires at least 5400 seconds of work budget; servicing resume requires at
least 3000. Guest waits must consume the same protected absolute budget across
reboot, not restart a fresh allowance. Proposed local upper bounds are 45
minutes for optical readiness and 110 minutes from SYSTEM setup for the
overall service task (clipped to the retained host work deadline);
DISM waiting remains bounded to 40 minutes. A wait timeout reports failure;
it does not establish that Windows servicing workers stopped. Confirmed outer
VM teardown is the containment and cleanup boundary. Exact implementation and executable pure
boundary tests are required before any runtime decision. No full run is
cleared by this plan.
