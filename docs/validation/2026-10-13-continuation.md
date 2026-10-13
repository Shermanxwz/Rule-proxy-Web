# Rule-proxy-Web continuation — 2026-10-13

Status: **Draft; production ProxyBridge/WFP backend remains disabled.**
PR: <https://github.com/Shermanxwz/Rule-proxy-Web/pull/8>.
Branch: `feat/windows-proxybridge-wfp-validation`. Main was not changed.
Tested native C++/Python source commit:
`4d4940f29c9f54c910ad011cea477a1ed79ad28d`.

## What this continuation implemented

- Native token identity inspection of a real suspended
  `CreateProcessWithLogonW(LOGON_NETCREDENTIALS_ONLY)` child. Fictitious
  credentials are neither authenticated nor used on the network. No local
  account, global proxy, DNS setting or route is created or changed.
- Persistent WFP `ALE_USER_ID` security-descriptor filters scoped to that
  child's logon SID, alongside the existing executable-path experiment.
  Filters are committed and read back from BFE before the thread is resumed.
  Their controller is killed before the real Winsock probes run.
- IPv4/IPv6 TCP and UDP baselines and guarded probes for direct connections,
  ordinary different-path children, and children requesting another net-only
  logon. Each simultaneous ordinary instance of the exact same executable
  must retain connectivity. Held process handles establish probe exit before
  removal of its denial policy.
- Actual nested token inspection before resume. Source, binary hashes and
  compiled user-mode lab bytes are retained with subsequent CI artifacts.
  The lab is excluded from the product package.

## Executed checks

[Run #111](https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38363042665)
completed with nine successful jobs, one intentionally failed production
acceptance job, and release skipped. The four Linux jobs require actual
Bubblewrap/network-namespace tests; those checks did not skip in CI.

| Environment/check | Result | Evidence |
|---|---|---|
| Windows 11 Enterprise ARM64, build 26200 | 30 experimental checks passed; production accepted false | [Raw measurement](native-wfp-run-111-windows-11-arm.json) |
| Windows Server 2025 Datacenter x64, build 26100 | 30 experimental checks passed; production accepted false | [Raw measurement](native-wfp-run-111-windows-2025.json) |
| Local Linux x86-64, Python 3.12.14 | 144 tests run, 0 failures, 9 skipped | [Complete final log](2026-10-13-continued-tests.txt) |
| Linux Python 3.10 and 3.14 | Each: 144 run, 0 failures, 5 skipped | [CI summary](2026-10-13-continued-ci-summary.json) |
| Ubuntu 22.04 and 24.04 system Python | Each: 144 run, 0 failures, 5 skipped | Same CI summary |
| Windows Python 3.13 source checkout | 144 run, 0 failures, 29 skipped; panel/core smoke passed | Same CI summary |
| Windows packaged embedded Python | 144 run, 0 failures, 36 skipped; package build and panel/core smoke passed | Same CI summary |
| Native SDK compilation | x64 and ARM64 `/W4 /WX` compilation passed | Native CI artifacts and job logs |
| Python compilation, workflow parse and release dependencies, whitespace | Passed | Executed locally; gate remains a release dependency |

The local nine skips are four Linux namespace checks prohibited by this
container, four Windows-only checks, and a filesystem ownership test whose
required `chown` operation returns `EINVAL`. CI's five Linux skips are the
four Windows checks plus the unavailable foreign-ownership setup. No namespace
check is claimed as locally passed. Windows's skips include Linux-specific
and source/package-specific checks; the exact reasons are in each job log.

## Observed boundaries

These observations use real Windows kernels and sockets on hosted virtual
machines. They are local loopback measurements, not physical-device tests,
external packet capture, browser login or full production leak acceptance.

| Security property | Executable-path selector | Logon-SID selector |
|---|---|---|
| IPv4/IPv6 TCP/UDP stays denied after controller kill | Observed | Observed |
| Normal instance at the same executable path remains connected | Failed: overblocked | Observed connected |
| Ordinary child at a different executable path remains denied | Failed: escaped | Observed denied |
| Another net-only logon child remains denied | Not applicable | Observed denied for all four protocol/family probes |
| Arbitrary primary-token changes, service brokers, browser IPC | Unproved | Unproved |
| TCP transparency while independent WFP enforcement is active | Failed in ProxyBridge experiment | No forwarding implementation |

The nested child actually acquired a different logon SID and authentication
LUID, while retaining the parent's logon SID as an enabled token group. The
parent SID's descriptor continued to match. The final experiment records
either blocked or connected outcomes and separately reports their security
meaning; it does not assume that changing a logon SID guarantees escape.

All owned experimental objects were verified absent after cleanup. Wrong-app
cleanup was rejected, the separate canary policy survived primary cleanup,
uncommitted transactions rolled back after process kill, and the global
proxy/DNS/routes/firewall-profile digests were unchanged on both systems.

## Retained failures and corrections

| Run | Actual result | Correction/interpretation |
|---|---|---|
| #103 | 18 lab checks per OS passed; path scope overblocking and child escape measured | Preserved as original scope findings |
| #105 | 19 checks per OS passed; initial net-only token had a distinct logon SID | Identity observation alone did not admit a protected launch |
| #107 | New-session ordinary-child helper refused before networking, error 13 at `disposable-github-runner-required` | Launcher now passes its Unicode environment explicitly; [ARM64 failure](native-wfp-run-107-windows-11-arm.json), [x64 failure](native-wfp-run-107-windows-2025.json) retained |
| #109 | Ordinary children denied and normal instances connected; nested net-only TCP also denied, contrary to the test's expected escape | Added nested-token inspection, unguarded baselines and outcome recording; [ARM64 record](native-wfp-run-109-windows-11-arm.json), [x64 record](native-wfp-run-109-windows-2025.json) retained |
| #111 | 30 checks per OS passed, including nested-logon token and network observations | Current tested experiment; production gate still red |

## Remaining work required for the original goal

1. Implement and prove transparent redirection **before** the independent ALE
   guard denies the original external connection. Upstream ProxyBridge's
   network-layer interception plus a blanket ALE block failed this compatibility
   test. Allowing the original external connect during forwarding would undo
   independent fail-closed behavior. Native connect redirection requires an
   actual redirect implementation and a legitimately loadable driver where
   that implementation uses a kernel callout.
2. Define a production security identity across arbitrary child token changes,
   service/IPC brokers and browser handoff. Check the target's privileges and
   policy access control. The session experiment is a useful primitive, not a
   universal process-tree or hostile-process guarantee. ProxyBridge's basename
   matching also redirected an unrelated executable at another path.
3. Wire only the proven implementation into the Web panel and selected Mihomo
   node. Run Chrome, Edge and Firefox, selected exit, real login and saved-cookie
   relaunch, DNS/UDP/QUIC/WebRTC/IPv6 egress capture, process/service kills and
   reboot recovery, partial install rollback and exact owned-resource uninstall.

No signed native redirector, production guard service or guarded launch exists
in this draft. No browser login or cookies were tested under this candidate.
No release was published and nothing was merged into main. Neither successful
lab execution nor the existing product's ordinary tests closes these blockers.
