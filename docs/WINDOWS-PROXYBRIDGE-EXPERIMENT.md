# Experimental Windows: ProxyBridge transport + independent WFP fence

Status: **control-plane contract implemented, production backend NOT implemented,
no verified Windows packet enforcement**. The default Windows backend remains MXC.
This document is a design/acceptance gate, not a claim that ProxyBridge is safe.

## Motivation

The existing MXC BaseContainer on Windows has not passed the real Chrome,
Firefox, and Edge rendering/cookie acceptance. Running the browser normally
and routing its packets with ProxyBridge/WinDivert may improve compatibility,
but original ProxyBridge 4.1.0 is not itself a fail-closed security boundary:

- A missing process identity may choose DIRECT, as may an absent proxy config.
- An HTTP-only proxy may cause UDP to go DIRECT.
- Non-matching process rules are DIRECT by default.
- Loopback has bypass rules; driver/service shutdown closes packet interception.
- Linux's ProxyBridge backend is IPv4-only.

Upstream source: https://github.com/InterceptSuite/ProxyBridge .
Do not vendor or launch its binary until the exact version is pinned, reviewed,
and a real Windows WFP-vs-WinDivert proof-of-operation succeeds.

## Component boundaries

- **Mihomo:** selected node and dedicated 127.0.0.1 port; *not a security gate*.
- **Native WFP fence (TO BE IMPLEMENTED):** persistent, independent of UI,
  Mihomo and ProxyBridge process lifetimes. Bind exact executable identity
  and descendants. Default-deny all outbound including IPv4/IPv6, TCP/UDP, DNS
  and localhost except the explicitly approved proxy endpoint. Unknown PID,
  rules, children or transport must never revert to DIRECT. A WFP app-path
  filter alone is insufficient if child helpers use different binaries.
- **ProxyBridge/WinDivert redirector (TO BE IMPLEMENTED):** only a transport.
  It must not own or remove WFP deny filters.
- **Application launcher (TO BE INTEGRATED):** permitted only when the
  independent fence is installed and *verified*.
- **Existing Linux implementation:** unchanged, netns/bwrap remains default.

**Architecture caveat:** WFP ALE connect authorization can occur before the
WinDivert network-layer redirect. A naive per-app outbound BLOCK firewall rule
can therefore prevent redirection entirely. Do not treat a firewall
`BLOCK all; ALLOW proxy` recipe as proof of compatibility; a native WFP
filter/redirect strategy must be experimentally validated on real Windows 11
with packets captured independently. If exact enforcement conflicts with
WinDivert, prefer a separately verified browser-native proxy transport for
supported browser adapters or reject the candidate. Do not weaken security.

## Implemented in this branch

`ruleproxy/windows_proxybridge.py` provides strict ordering and retention:
1. Require exact protected .exe and exact local proxy endpoint.
2. Install WFP receipt. Demand durable, IPv4+IPv6, TCP+UDP,
   descendant, default-deny and no-DIRECT assertions.
3. Independently verify the installed policy before starting redirector.
4. Start redirector; check readiness; verify policy again.
5. Start app through owned process spawner; verify policy again.
6. Stop only after verified descendant/process exit, stop redirector,
   verify fence, then release the policy.
7. If any phase is uncertain, preserve the fence and reject the action.

Receipts are **not cryptographic or kernel evidence**. An injected fake
provider can claim anything; these are API-level tests only. A native driver
integration must verify WFP filter identities and effective behavior instead
of setting all booleans to True.

`production_probe()` always returns supported=False. No service
installation, host firewall changes, MXC replacement, silent fallback,
automatic enablement, proxy-node requests or proxy-credential reads.

## Acceptance tests required before enabling this backend

### Portable and CI (implemented)

`python -B -m unittest tests.test_windows_proxybridge -v`
(or run the repository's `.github/run_tests.py`). Assertions cover startup
ordering, missing proxy, incorrect WFP proof, mismatched executable, proxy
not ready, app spawn failure, post-spawn fence loss, process-tree cleanup
failure, redirector shutdown failure and release failure.

### Windows native (NOT YET IMPLEMENTED OR PASSED)

These must be executed against the *real* independent WFP implementation,
built WinDivert driver and actual Mihomo; unit mocks cannot certify them:

1. Windows 11 x64, normal non-admin GUI user after one-time helper install;
   Chrome / Edge / Firefox render a local controlled URL through selected
   Mihomo node. Cookies persist across restarts without disabling sandbox.
2. Independent packet capture confirms no target direct IPv4 TCP, IPv6 TCP,
   IPv4 UDP, IPv6 UDP, DNS (53 and encrypted resolver), localhost bypass or
   service/child process egress. The host browser without a protected launch
   must remain unchanged.
3. Verify proxy selection by observing the *real* SOCKS/HTTP handshake and
   upstream exit, not ProxyBridge's connection-event log alone.
4. Kill ProxyBridge, its GUI/CLI/service and Mihomo separately with app alive.
   Restart service, sleep/reboot at each fault point; WFP deny must still be
   installed, and the app must not have direct external reachability.
5. Race test PID lookup failure, source-port reuse, helper processes, new
   processes spawned after a fence install, IPv6 and HTTP3/QUIC.
6. Test Windows Firewall rule coexistence, elevated/unprivileged processes,
   Defender/EDR interference, dual stack, DNS split-horizon and a host with
   no IPv6 route (must explicitly mark that test unverified).
7. Repeated login/session restart and >= 7 days of independent egress
   observation; all unexpected direct packet observations fail the gate.
8. Safe teardown: if descendant termination is not proven, preserve the
   WFP block across UI/service crash; never kill unrelated host processes.

## Merge/release rules

This is a **draft architecture experiment**, not a Windows implementation
that meets RuleProxy's protection guarantee. Do not expose it in settings
as a selectable production backend or replace the existing MXC backend.
No release/green portable CI test may be used to claim Windows native safety.
