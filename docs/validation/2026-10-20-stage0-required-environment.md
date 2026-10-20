# Stage0 required environment correction

## Confirmed cause, not a Windows support verdict

Direct attempt `39440004651` on the existing official 26300.9457 image selected
BaseContainer at qualification, then exited before an actor report existed.
The retained error-message SHA-256
`1def007dc05682ea19f477801c2dfbf46ebaa3b987b2503aed1e89fdbc9260d2`
exactly matches the 544-byte static diagnostic in pinned G commit
`7bf210247986cb73b1b314df60c2f1109c479c0b` for an explicitly empty child environment.
Its validator requires `SYSTEMROOT` and `LOCALAPPDATA` before spawning. Therefore
the backend selection line did not prove a container or process was created.
This result is a request-construction failure, not evidence that the OS creation
API failed. The original failed result and confirmed owned-VM cleanup remain
archived; no historical result is relabeled as a pass.

Source: https://github.com/microsoft/mxc/blob/7bf210247986cb73b1b314df60c2f1109c479c0b/src/mxc-sdk/src/backends/process_container/common/launch_diagnostics.rs

## Narrow correction

After the existing ordinary, non-AppContainer, default-compartment controller
gate, observe exactly the two required values. Compare SYSTEMROOT with
GetWindowsDirectoryW and LOCALAPPDATA with SHGetKnownFolderPath for the current
token. Require canonical absolute DOS directory paths, exact case-insensitive
agreement, existing directories and resolved-path agreement. Missing values,
relative/device/UNC paths, aliases, expansion syntax, malformed values or native
lookup failures stop before executor verification or launch.

The child receives only these two explicit NAME=value entries.
`inheritDefaultEnv` stays false. No PATH, USERPROFILE, full parent environment,
credentials or dummy placeholders are inherited. No filesystem, network, UI,
fallback, actor, tier, nonce or exit acceptance rule is relaxed. Environment
values and policy JSON are not public artifacts; diagnostics retain only closed
phases and error categories, and synthetic gates emit booleans/counts.

## Verification boundary

Local unit tests exercise actual production validators and controller ordering,
including rejection before executor/run_case/subprocess calls. The Windows pure
gate executes fixture cases and requires the actual native current-runner helper
to succeed, without printing paths. Its Server runner is not ordinary Windows 11
acceptance. All runtime checks still require a separately reviewed one-run
execution decision. The 26300.9457 direct path remains exploratory below the
current documented 26300.9550 support floor; fixing this request does not change
that caveat or establish successful native execution.
