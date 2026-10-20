# Serviced Stage0: preserve an admitted resume checkpoint

Status: code-only candidate. No new VM or runtime success is established by this change.

## Evidence and bounded conclusion

Attempt 06 retained the original closed prior snapshot:
`status=installing`, `phase=verifying_optical`, `failure=none`,
`dism_exit_code=3010`, predicate mask `55`.
The source admits a valid `reboot_pending` receipt, copies its boot witness and
DISM exit code into fresh in-memory state, then writes intermediate progress with
`status=installing` and `packages_verified=false`. Those writes destroy the
previously valid durable checkpoint and reproduce the observed mask: only the
status and package-verification predicates are false.

The cause of the additional invocation/interruption is unknown. Neither this
snapshot nor disk growth proves another reboot, exact build 26200.9711, completed
servicing, or native identity acceptance.

## Minimal change

`Write-ServicedProgress` writes the existing state file only on the initial path.
Its two call sites are `waiting_for_optical` and `verifying_optical`. On a path
whose prior receipt has already passed the unchanged prior guard, these phases
remain in memory and the original `reboot_pending` file remains durable.

No separate checkpoint file, deadline renewal, automatic resume of invalid state,
or acceptance relaxation is introduced. Fresh verification remains required:
both full optical package hashes; a different boot witness; exact build 26200.9711;
no pending reboot; and successful task removal. In-memory package verification
stays false until the current media check succeeds. Final `completed` and terminal
`failed` records still use the original atomic state-file writer.

The ordinary reader consequently sees the durable `reboot_pending` checkpoint
during resumed work, not a live intermediate phase. A terminal failure still
replaces it and fails closed. This change does not promise recovery from every
interruption, including interruption around task removal/final publication.

## Validation and limits

The Windows semantic gate uses actual `Get-ServicedBoot`, `Write-ServicedState`,
`Write-ServicedProgress`, JSON readback and the unchanged prior guard on its exact
owned, ACL-protected temporary fixture. For exit codes 0 and 3010 it simulates
interruption before/after each progress call and requires byte-identical durable
checkpoint data and predicate mask 127. It also checks initial progress writes,
terminal atomic replacement, original mask-55 rejection, and existing tamper and
missing-field negatives. Output is closed fixture facts only; raw boot values
stay private. No real interruption, reboot, servicing or native acceptance occurs
in this gate. The fixture's explicit trusted owner is not proof of guest SYSTEM
ownership or ordinary-token readability.

Local Python verification at candidate freeze: 286 `test_windows_client*.py`
tests passed. Actual Windows execution of the new cases is pending. Independent
source review and pure gates precede any separately authorized VM run.
