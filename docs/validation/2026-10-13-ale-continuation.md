# Rule-proxy-Web ALE/relay continuation — 2026-10-13

**Status: this development stage passed; production acceptance is still blocked.**
Draft PR: <https://github.com/Shermanxwz/Rule-proxy-Web/pull/8>.
Branch: `feat/windows-proxybridge-wfp-validation`. Main/releases were unchanged.
Tested source: `e9ff46bbad0b0506499650b74554046dc6603e05`.
[CI run #131](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38391529482).

## Implemented

- Build-only IPv4/IPv6 TCP ALE_CONNECT_REDIRECT callouts in
  `native/windows/redirect_driver.c`: versioned original-destination context,
  stale/missing configuration refusal, self-issued relay PID validation, held
  relay process, exit invalidation, inline rollback, and policy-preserving
  unload. **The driver has not been loaded.**
- Independent persistent SID-scoped static ALE_AUTH_CONNECT denial and a
  higher-weight soft exception only for redirected TCP to the exact IPv4/IPv6
  loopback endpoint. Ordinary connections cannot obtain the exception simply
  by choosing its address/port. The template is restricted to the native lab.
- Winsock context/record queries, ABI/session/generation/address validation,
  pre-connect record association, numeric local SOCKS transport, absolute
  handshake deadline, bounded buffers/backpressure, cancellation and half-close.
  Errors have no direct fallback. Native files stay outside the product package.
- A held core PID **and creation FILETIME**, then actual connected TCP peer
  ownership, are verified before SOCKS greeting/destination. Live Windows
  tests reject another listener process, changed creation time and a dead core.
  A future coordinator must provide identity from its own held core process.
- Version-pinned Microsoft WDK/SDK `10.0.26100.2454`, package signature checks,
  `/kernel /W4 /WX /GS` x64/ARM64 builds and exact binary/provenance artifacts.
  WDK header warnings are scoped separately; source warnings remain errors.

## Executed checks

| Check | Actual result | Limit |
|---|---|---|
| Local Linux, Python 3.12.14 | 160 tests; 0 failed; 14 skipped | Nine Windows checks, four unavailable namespace checks, one ownership fixture; [full log](2026-10-13-ale-tests.txt) |
| Linux 3.10/3.14 and Ubuntu 22.04/24.04 system Python | Each 160 tests; 0 failed; 10 skipped | Real namespace checks required and ran; Windows/ownership checks skipped |
| Windows source, Python 3.13 | 160 tests; 0 failed; 29 skipped | Actual Winsock and core/TCP-ownership tests included |
| Windows embedded package | 145 tests; 0 failed; 37 skipped | Native module deliberately excluded; package/panel/core smoke passed |
| Windows 11 Enterprise ARM64 26200 WFP lab | 38 checks passed; accepted false | Actual kernel/sockets in a VM, loopback peers |
| Windows Server 2025 x64 26100 WFP lab | 38 checks passed; accepted false | Server distinguished from Windows 11 |
| Relay checks on each native OS/architecture | 16 passed; zero skipped | Actual peers, metadata rejection, held identity and TCP ownership |
| x64/ARM64 driver builds | Both passed | Unsigned, never loaded; not kernel redirect execution |
| Four original evidence archives | Downloaded and verified | Archive/binary hashes, PE architecture, imports and source bytes |

Run #131 completed **11 successful jobs, one deliberately failed production
acceptance gate and a skipped release**. Global proxy/DNS/routes/firewall-profile
digests matched and all owned experimental WFP objects were removed.

Eight added endpoint checks first establish IPv4/IPv6 TCP/UDP listeners at the
same exact port. After controller kill, direct and ordinary different-path
children remain denied with zero peer deliveries; normal same-path instances
stay connected. BFE conditions/weights are read back; wrong-endpoint cleanup is
refused. The **legitimate redirected exception** still requires a loaded driver.

## Bytes and failures

Driver archives contain five files each; native lab archives contain 26 each,
including exact binary bytes, build provenance, measurements and receipts.
Four original archives are preserved unchanged in the separate user-facing
evidence bundle, independently of Actions retention.

| Driver | Bytes | PE machine | Kernel imports |
|---|---:|---|---|
| x64 | 27,648 | `0x8664` | `ntoskrnl.exe`, `fwpkclnt.sys` |
| ARM64 | 30,208 | `0xaa64` | `ntoskrnl.exe`, `hal.dll`, `fwpkclnt.sys` |

Both have native subsystem/integrity flags and `NotSigned` status. Binary hashes
match provenance; source/header/build-script hashes match Windows CRLF bytes.
The source commit in provenance is the PR test merge, not the branch head.
See [archive verification](2026-10-13-ale-artifact-verification.json),
[CI summary](2026-10-13-ale-ci-summary.json),
[x64 build](ale-build-run-131-windows-2025.json),
[ARM64 build](ale-build-run-131-windows-11-arm.json),
[x64 measurement](native-wfp-run-131-windows-2025.json), and
[ARM64 measurement](native-wfp-run-131-windows-11-arm.json).

[Failures](ale-build-failures.json) retain #115/#117/#119/#121/#123/#125/#127/#129.
Corrections cover target macros, NDIS/header setup, SDK field types, removing
unavailable process-exit APIs in favor of self-configuration, initialized
rollback and actual architecture libraries. ARM64 links pinned SDK `arm64rt.lib`
and WDK HAL/GS support; GS and source warning checks were never disabled.
Earlier [#119 ARM64](native-wfp-run-119-windows-11-arm.json) and
[x64](native-wfp-run-119-windows-2025.json) measurements are retained.

## Still blocked

1. Legitimate signing/installation and actual kernel execution: positive guarded
   redirect, Driver Verifier, callout/relay/core kills, in-flight exit/PID reuse,
   restarts/reboot and interrupted-install/uninstall recovery.
2. Production privileged coordination, policy ACL/journal, SID-scoped redirect
   management filters/session contexts, restricted target privileges, full
   descendants/brokers/IPC/token boundaries and exit-before-cleanup. Lab net-only
   tokens retain user privileges; relay CLI does not configure the driver.
3. Isolated DNS/service attribution, selected Mihomo exit, external
   IPv4/IPv6/DNS/UDP/QUIC/WebRTC capture, and actual Chrome/Edge/Firefox login and
   cookie relaunch through the panel. No user credentials/cookies were used.

The Windows panel still uses MXC; Linux still uses Bubblewrap/network namespace.
The candidate remains unsupported and the PR stays Draft. **No physical-device,
positive transparent-forwarding or full production leak acceptance is claimed.
The project is not yet 封存级 or 验收完成.**
