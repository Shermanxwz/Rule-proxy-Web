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
