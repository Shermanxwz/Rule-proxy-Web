# ALE redirect foundation — disabled, not accepted

These files are development inputs and are excluded from the product package.
The Windows panel still uses MXC. No command here installs a driver, admits an
application or makes the ProxyBridge/WFP candidate supported.

The original ProxyBridge 4.1.1 network-layer interception cannot forward the
connection rejected earlier by an ALE guard. The native foundation instead
modifies the connect destination at ALE_CONNECT_REDIRECT, before independent
ALE_AUTH_CONNECT denial. That ordering is an implementation hypothesis until a
legitimately signed/loaded driver and positive forwarding test prove it.

| Component | Implemented | Current proof / limit |
|---|---|---|
| `redirect_driver.c` | IPv4/IPv6 TCP redirect callouts; kernel redirect context; referenced relay identity; process exit invalidation; private admin/SYSTEM device; inline failure rollback; unload leaves guard policy alone | Build-only; no driver load, kernel execution, race, verifier or reboot proof |
| `redirect_protocol.h` | Fixed 64-byte redirect context and 40-byte relay configuration, x64/ARM64 ABI and exact callout/device keys | WDK compile-time size checks; relay parser checks versions, sessions, generation, family and padding |
| `relay.py` | Genuine Winsock context/record queries; records attached before outgoing SOCKS connect; numeric IPv4/IPv6 SOCKS CONNECT; absolute handshake deadline; bounded asynchronous relay and half-close; held core PID/creation time plus real TCP peer ownership checked before SOCKS data | Real TCP protocol tests; real Windows unredirected sockets refused; no positive kernel-redirected socket tested |
| Independent static endpoint guard | SID-specific persistent deny plus higher-priority soft permit only for redirected TCP to the exact IPv4/IPv6 loopback endpoint | Actual BFE readback, killed controller, direct/ordinary-child denial and normal same-path-instance connectivity in the native lab; legitimate redirected exception remains unproved |

The guard template currently lives in `scripts/windows/wfp_native_lab.cpp` and
is exercised by `.github/windows_wfp_native_lab.py`. It is restricted to the
synthetic executable/new logon SID in a disposable runner. It has no production
service, protected policy journal, installation, resume or cleanup lifecycle.
The guard contains no dependence on the redirect driver's running state.

The driver only registers the two exact redirect callout implementations. It
does not create management callout objects or SID-scoped redirect filters. A
future privileged coordinator must create those objects with nonzero session
`rawContext`, prove their exact ownership, and commit independent guard policy
before a target is resumed. By default there is no configured relay, so a
matched redirect callback blocks. An absent callout must never be exempted
with `PERMIT_IF_CALLOUT_UNREGISTERED`.

The relay process itself must issue the versioned configuration IOCTL after it
owns both exclusive numeric loopback listeners. The driver refuses another
process's PID and clamps the PID to the WFP target PID field's width. The relay
CLI does not yet perform that privileged configuration or policy admission.
Its core PID and creation FILETIME must come from the coordinator's held
Mihomo process. The relay checks the actual connected TCP peer's owner before
any SOCKS greeting or destination, and refuses a dead core, changed creation
time or different process at the same port. Installation/privilege integrity
and accepted-socket transfer behavior still need production validation.
Its destination comes solely from kernel Winsock metadata, never an HTTP,
SOCKS or application-supplied header. A destination or SOCKS error has no direct
fallback. The current core endpoint is local no-auth SOCKS; upstream node
credentials remain the core's responsibility.

Build with `scripts/windows/Build-AleRedirect.ps1` in the existing disposable
Windows CI. It restores version-pinned Microsoft WDK/SDK NuGet packages,
verifies their signatures, compiles with `/W4 /WX /kernel`, and retains the
exact unsigned `.sys` plus hashes, package receipts and build logs. Builds are
separate from acceptance and never load the unsigned output or change boot
configuration. The deliberate production gate remains a release dependency.

Still required before activation:

1. Obtain legitimate driver signing/admission, install only owned resources,
   and run Driver Verifier plus positive IPv4/IPv6 redirect/guard coexistence,
   redirector/relay/core kills, in-flight exit/PID reuse and restart/reboot tests.
2. Add privileged coordination, restricted target privileges and process-tree
   containment, broker/IPC/token-change coverage, protected policy ACL/journal,
   exact verified cleanup and interrupted installation recovery. A net-only
   logon retaining the user's elevated privileges is not a hostile-app boundary.
3. Prove DNS-client/service broker behavior, selected Mihomo exit, external
   IPv4/IPv6/DNS/UDP/WebRTC/QUIC capture, and Chrome/Edge/Firefox login and saved
   cookie relaunch through the panel. This transport only relays numeric TCP;
   it does not yet supply isolated DNS resolution.
4. Validate real loadable x64/ARM64 drivers and browser compatibility, then
   wire the tested path to the panel. Preserve unrelated application behavior
   and global proxy, DNS, route and policy state throughout.

Primary contracts: [ALE redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection),
[inline layer-data application](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsapplymodifiedlayerdata0),
[filter arbitration](https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration),
[official WDK NuGet distribution](https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget).
