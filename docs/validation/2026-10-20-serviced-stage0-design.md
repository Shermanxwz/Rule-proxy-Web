# Bounded serviced Stage0 candidate — not runtime acceptance

## Evidence and purpose

The exact stock Windows 11 26200.6584 diagnostic run
[39400160380](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/39400160380)
completed its ordinary-user harness. The pinned request-aware probe returned a
valid object with `baseContainerApiPresent=false` and
`reported_dacl_fallback_forbidden`. No actor was launched. This establishes the
observed API/detector result on that guest, not that every Windows version is
unsupported. Closed evidence is retained under `stock-stage0-attempt-07-*`.

The candidate returns to the existing exact serviced build 26200.9711, keeping
the same G pin, native actor, deny-only policy, one temporary account and security
acceptance checks. New files isolate the candidate from the completed stock
route. At this document's creation the new workflow is disabled and there is no
serviced runtime result.

## Measured resource basis

At stock result receipt:

| Item | Bytes |
|---|---:|
| Host free space | 11,302,961,152 |
| QCOW logical file length | 16,185,294,848 |
| QCOW allocated bytes | 16,159,727,616 |
| Owned original installer ISO | 7,092,807,680 |
| Two already pinned official MSUs combined | 5,308,811,935 |
| Proposed bounded QCOW file ceiling | 23,622,320,128 (22 GiB) |
| Unchanged free-space stop reserve | 4,294,967,296 (4 GiB) |

If the installed guest is verified and the original DVD backend is proved
released before deleting the exact owned ISO, the observed free space becomes
18,395,768,832 bytes. Two host copies of the MSUs during update-media construction
leave 7,778,144,962 bytes. Removing the verified source copies after media
validation leaves 13,086,956,897 bytes. Allowing the observed QCOW to grow to the
proposed 22 GiB ceiling leaves 5,649,931,617 bytes before optical filesystem
metadata and further sidecar/background growth. These are arithmetic estimates,
not a servicing peak measurement or guaranteed available space.

The previous 18 GiB file limit cannot accommodate both MSUs copied into this
15.074 GiB guest even before servicing extraction. The new candidate avoids
those guest copies. Raising the sizing ceiling to 22 GiB is an explicit design
change; the hard limit is set from process launch rather than silently raising
a running process's 18 GiB hard limit or granting new privilege. Actual
admission must project at least 5 GiB remaining after maximum allowed QCOW growth,
with the independent 4 GiB live stop reserve still active. Failure means a
resource result, never relaxed acceptance.

## Intended sequence and proof obligations

1. Install the original pinned stock ISO with the existing tiny seed and wait
   for genuine ordinary-user installed-OS readiness. No package servicing races
   installation.
2. Detach the known installer optical medium through QMP. Verify both block
   device and named block-node state no longer reference its exact owned path.
   Only then unlink that owned ISO. Unknown state fails closed.
3. Check actual free space and remaining absolute job budget before downloading
   the two exact pinned official MSUs. Enforce byte lengths and SHA-256.
4. Build a read-only update DVD using the existing xorriso dependency, ISO9660
   level 3 multi-extent. This is **not UDF**. The target MSU is over 4 GiB;
   Windows must independently read and hash the complete file before DISM.
   No media readability success is assumed from source tests.
5. Validate media contents, then remove only the exact owned downloaded source
   files. Attach the completed read-only DVD only after this cleanup; attachment
   is the readiness handoff. Keep checkpoint and target packages in one folder.
6. A protected existing-pattern SYSTEM servicing task verifies the DVD/package
   inputs and invokes DISM directly from the DVD. It records a protected
   pre-servicing boot witness, reboots, and requires an observed different boot,
   exact build/UBR 26200.9711, no required reboot and task removal. A successful
   DISM exit alone is not completion.
7. Only after that receipt does the ordinary-user Startup path claim and run
   Stage0. It keeps bounded minimal-Python payload handling and closed causal
   diagnostics. Native actor/token/nonce, actual BaseContainer tier and normal
   exit are still required; missing evidence is failure.
8. Always terminate owned processes, close handles and remove the owned VM
   workspace. Uncertain cleanup independently revokes a pass.

The original 120-minute job and 6,900-second absolute budget remain. Stock result
receipt had about 3,785 work seconds remaining; download/media/servicing/reboot
must fit a newly measured remaining budget while preserving cleanup reserves.
This may be insufficient; no extension or success claim follows from the estimate.

No user device, main merge, release, extra paid machine, broad cleanup, new
account type, security-policy weakening or unpinned executor is introduced.
