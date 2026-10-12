# Windows WFP + ProxyBridge research branch (NOT PRODUCTION READY)

**Current status: fail-closed contract scaffold only. No WFP driver, packet
redirector, or Windows application integration is installed by this branch.**

The existing MXC Windows backend and the existing Linux runtime are not changed.

## Required design

- **Guard, not redirector, is the security boundary.** Install a persistent
  OS-enforced WFP policy for the protected application identity *before*
  launching it. A ProxyBridge/WinDivert process is only a forwarding engine.
- Do not allow an apparent rule installation to count as proof. Independently
  test IPv4, IPv6, UDP, DNS, proxy death and interception death under the
  actual application identity, using network capture outside the forwarding
  process. If a test cannot run, report unsupported and refuse launch.
- Do not trust process basenames or ephemeral ports alone to identify protected
  workloads. Account for process trees, service-mediated requests, PID reuse,
  browser helper processes, and kernel bypass cases.
- WFP block/permit precedence can prevent WinDivert from redirecting. First
  prove that the particular combination of WFP layers, flow ownership and
  redirect/reinjection works before implementing a persistent allowlist.
- The proxy endpoint exception must allow ONLY the authorized forwarding
  process; it must not be a generic hole allowing all protected applications
  to connect directly to an arbitrary destination.
- A privileged service must authenticate callers, track launch and policy
  lifetime atomically, persist the deny rule independently of its own
  process, and recover safely after crash/reboot. Do not remove the deny
  rule until all protected descendants are confirmed terminated.
- Any fallback to DIRECT, permissive PID classification, unknown UDP, failed
  capture, lost driver, or unavailable guard must refuse launch or block.
  Existing upstream ProxyBridge code has several fail-open paths.
- Avoid broad system proxy/DNS/routes changes and unbounded system firewall
  changes. Introduce a separate, auditable installer and uninstaller.
- Keep third-party code and licensing traceable; pin release + hash. Do not
  auto-download or run third-party kernel drivers in the web panel.

## Acceptance gate

1. The strict Windows target app (Chrome/Edge/Firefox + desktop apps) starts
   normally and stays within the protected lifecycle. Persistent login works.
2. Independent captures prove no direct IPv4/IPv6, DNS, UDP/QUIC, localhost
   bypass, or helper child exit under normal and fault conditions.
3. Kill Mihomo, kill ProxyBridge, kill the service, crash the test app,
   restart the controller, change proxy node, and verify blocked-not-direct.
4. Ordinary nonprotected apps keep their original networking.
5. All matrix cases pass on actual Windows 11 x64 hardware, then long-running
   stress testing; Linux regression tests continue to pass.

Current implementation intentionally fails closed:
`UnimplementedWfpGuard.install_before_launch` raises `IsolationNotProven`.
The evidence validator is only a model contract; forged input can trivially
satisfy it. The live Windows adapter must produce hardware-backed evidence,
not accept caller-supplied booleans.
