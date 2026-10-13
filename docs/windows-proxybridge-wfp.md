# Windows ProxyBridge/WFP candidate — blocked acceptance

This branch is a guarded work in progress. The active Windows path is still
MXC BaseContainer. Linux still uses Bubblewrap and a network namespace. The
candidate profile builder and staging script **do not launch an application,
install a service, or change WFP rules**. `windows-proxybridge-wfp-acceptance`
is deliberately red on a PR until the independent boundary and live tests
exist. Do not merge or advertise ProxyBridge/WFP as protected.

## What has been built

- `ruleproxy.proxybridge_candidate.candidate_profile()` maps explicit Windows
  executable names to ProxyBridge 4.1.1 TCP `PROXY` and UDP `BLOCK` rules. Its
  SOCKS5 endpoint is the project's existing `127.0.0.1` Mihomo listener, whose
  imported config pins allowed destinations to the selected node. This is only
  a candidate profile, not an isolation policy or a complete child-process map.
- `scripts/windows/Stage-ProxyBridge.ps1` downloads the v4.1.1 upstream
  installer and checks its release SHA-256. It does not execute the installer.
  Removing `bin/windows-candidate` completely reverses staging.
- `scripts/windows/Test-ProxyBridgeWfp.ps1` is a disposable Windows CI
  experiment. It extracts the verified installer without running NSIS, runs
  the upstream CLI and WinDivert driver, measures a local SOCKS5 witness, adds
  one program-specific outbound block, and removes its own rule and driver.
  It is not a product installation path or an admission check.
- `.github/windows_candidate_gate.py` emits a JSON failure record on Windows
  CI and exits nonzero. The regular Windows and Linux jobs still test the
  existing product independently.

## Blockers before activation

ProxyBridge's v4.1.1 CLI/engine can use `DIRECT` when it does not identify a
process or a proxy config; unmatched traffic is direct. Its rules match
executable names and do not establish a unique process-tree security identity.
The project Mihomo listener currently has UDP disabled, so this candidate
explicitly blocks UDP in its ProxyBridge rules. A separate WFP guard is still
required for IPv4, IPv6, UDP, DNS, WebRTC, missed process matches, and proxy
failure. A ProxyBridge rule must never be the only containment layer.

WFP `ALE_AUTH_CONNECT` authorizes outgoing TCP connections and first outgoing
non-TCP packets; ProxyBridge opens WinDivert at the network packet layer. A
simple per-app WFP deny-all at ALE can prevent the original connection from
reaching ProxyBridge. Temporarily removing that deny rule while ProxyBridge
runs would leave a crash/restart window. A safe implementation needs a proven
redirection and enforcement ordering with an independent guard, unique
descendant identity, and persistent block semantics. Neither a firewall
exception nor a watchdog alone satisfies this contract.

This conflict was observed on a Windows Server 2025 build 26100 GitHub-hosted VM in
[run #91](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38355503137):
with no program block, a direct `curl` probe got `OK` via ProxyBridge and the
SOCKS witness saw one CONNECT. With a Windows Firewall outbound block for the
same executable, the probe failed immediately and the witness saw zero
CONNECTs. Killing the CLI while keeping the block left the probe unable to
connect. The test uses a Windows kernel and actual WinDivert driver, but a
virtual machine and no external packet capture; it does not meet physical
device or full leak acceptance. See [raw run data](validation/windows-vm-run-91.json).
The expanded [run #93](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38355880088)
also observed a second executable at a different path but with the same
basename being redirected through the same SOCKS listener (one CONNECT), even
while the first path alone had the WFP block. This violates independent
instance scope. Its [measurements](validation/windows-vm-run-93.json) confirm
the experiment's firewall rule and newly loaded WinDivert driver were removed
afterwards. The experimental step itself still exited nonzero because the final
`sc query` reports the expected "service does not exist"; the next revision
explicitly exits zero after recording that cleanup result.

The upstream v4.1.1 NSIS installer is unsuitable for direct product deployment:
it changes machine PATH, installs an automatic LocalSystem service and user
group, removes firewall rules by executable, and stops/deletes a WinDivert
service of the same name. A protected installer must own and verify its exact
resources and reverse partial installation without deleting third-party state.
The disposable experiment extracts binaries and does not run these NSIS actions.

## Native persistent-denial experiment

`scripts/windows/wfp_native_lab.cpp` and
`.github/windows_wfp_native_lab.py` test the independent WFP persistence
primitive on disposable hosted Windows machines. The controller uses the
Windows SDK/BFE APIs directly, not Windows Firewall program rules. It commits
two persistent ALE_AUTH_CONNECT terminating-callout filters for one synthetic
executable's exact app ID. The callouts have no registered driver, and the
filters never set `PERMIT_IF_CALLOUT_UNREGISTERED`.

Real Winsock IPv4/IPv6 TCP and UDP loopback probes must first succeed, then
return `WSAEACCES` with zero peer deliveries after the controller is killed.
A second executable with the same basename at a different path must remain
connected. The experiment also kills an uncommitted installation, reads every
filter property back from BFE, rejects cleanup with the wrong executable,
preserves a separately owned canary policy, and checks idempotent exact-key
removal. System proxy, DNS, routes and firewall profile configuration are
compared by digest. No browser, signed kernel callout, transparent redirect,
descendant identity, external capture or reboot proof is implied. The lab is
not included in the product package and does not enable the candidate.

The jobs explicitly distinguish `windows-2025` x64 from `windows-11-arm`
ARM64. Kernel version `10.0.26100` alone does not identify Windows 11: the
earlier #91/#93/#95 runner setup logs identify **Windows Server 2025
Datacenter**. Earlier wording calling those VMs Windows 11 was incorrect;
the original numeric OS version in the raw JSON is preserved. New evidence
records the product caption, product type, CPU architecture and runner image.

References: [ProxyBridge v4.1.1 source](https://github.com/InterceptSuite/ProxyBridge/tree/v4.1.1/Windows),
[WFP ALE filtering](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers),
[WinDivert documentation](https://github.com/basil00/WinDivert/wiki/WinDivert-Documentation).

## Required live acceptance

Run on a dedicated Windows 11 device with a physical network capture point
and a separate unprotected control app. Record OS build, tool binary hashes,
Mihomo selection, WFP filter identities, packet traces, process tree, timestamps,
and before/after system proxy, DNS, routes, and firewall state. Do not put node
credentials or browser cookies in artifacts.

1. Install a signed WFP guard whose persistent rules are bound to the launched
   instance and every descendant. Verify IPv4/IPv6 TCP and UDP direct attempts
   are blocked **before** the app is resumed, and ProxyBridge still receives
   the intended packets. Explicitly test a child executable with a different
   name and a simultaneous ordinary instance of the same browser.
2. Launch Chrome, Edge, and Firefox through the Web panel. Verify selected
   node exit, real login, cookie persistence after stop/relaunch, and no DNS,
   QUIC, UDP, WebRTC or IPv6 direct packets in the external capture.
3. Kill ProxyBridge, Mihomo, the panel, and their service processes separately;
   unplug the interface and reboot. Prove the target remains blocked throughout
   each failure and startup interval. Confirm no stale rule can strand a normal
   program and that recovery does not create a direct window.
4. Verify unrelated applications retain their baseline connectivity and the
   system proxy, adapter DNS, routes, and unrelated WFP filters remain intact.
   Uninstall only owned rules by identity after every protected descendant has
   exited; demonstrate interrupted install and rollback.

The CI runner can compile and run Windows tests, but it is a virtual machine
and is not a substitute for this device and capture. Until all checks pass,
the candidate status is unsupported and the Draft PR stays unmerged.
