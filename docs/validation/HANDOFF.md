# Rule-proxy-Web handoff — ALE/relay continuation

Updated 2026-10-13. Original production goal is incomplete. Read the latest
2026-10-13-ale-continuation.md first; the earlier handoff is retained below.

- Draft PR #8, branch feat/windows-proxybridge-wfp-validation; do not merge.
- Checkout: /workspace/scratch/d71bf2368927/Rule-proxy-Web.
- Tested source head: e9ff46bbad0b0506499650b74554046dc6603e05.
- Run #131: https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38391529482
  Eleven jobs passed, only production acceptance gate failed, release skipped.
- Local: 160 tests, 0 failed, 14 skipped. Hosted Linux each 160/0/10 with real
  namespaces required and run; Windows source 160/0/29; package 145/0/37.
- Windows 11 Enterprise ARM64 26200 and Server 2025 x64 26100 each passed 38
  WFP checks and 16 relay/native core-ownership checks. These are real kernels
  on VMs with loopback peers; no physical device or external capture proof.
- native/windows/redirect_driver.c, redirect_protocol.h and relay.py now exist.
  Both /kernel /W4 /WX /GS WDK builds passed. Their .sys bytes are unsigned,
  have never been loaded/executed and do not enable the product backend.
- Independent static guard's real-redirect-only endpoint exception rejects
  ordinary direct/child connections after controller kill; normal same-path
  instances remain connected. Legitimate redirected exception is unproved.
- Relay checks kernel metadata and core held PID/creation time/TCP peer owner
  before SOCKS data. Coordinator must provide trusted identity; no direct retry.
- The driver only registers implementations: production management callouts,
  SID-scoped redirect filters/session contexts, privileged coordination and
  relay self-configuration from its CLI are still missing.
- Target privilege reduction, full broker/IPC/token containment, isolated DNS,
  signing/admission, protected policy lifecycle and install/recovery are pending.
- Four raw #131 archives were downloaded and verified against binary/archive
  SHA-256, PE architecture, native/integrity flags, kernel-only imports and
  Windows CRLF source/header/build-script hashes. Provenance uses PR test merge.
  Exact archives persist separately in RuleProxy-Windows-Evidence-2026-10-13.zip.
- Validation includes latest reports, build receipts, archive verification and
  full test log. Failed build/harness runs #115/#117/#119/#121/#123/#125/#127/#129
  are retained. Existing #107/#109 and original scope/conflict evidence remain.
- The active Windows backend is MXC, Linux is Bubblewrap/network namespace.
  Candidate supported must remain false; gate nonzero and a release dependency.
- Origin is a local mirror; GitHub and local commit IDs differ. Compare all blob
  hashes/modes and inspect the latest PR head before publishing; no force push.

Next: legitimate signed driver/environment, positive redirect/independent guard
proof, then production identity/coordination/DNS and panel/Mihomo integration.
Real browser login/cookies, selected exit, external packet capture, kills, reboot
and installation/recovery remain required. Do not replace with mocks or call
this source build finished production acceptance.

---

# Rule-proxy-Web handoff

Updated 2026-10-13. Read this file and the linked measured reports before
continuing after a conversation/context reset. Preserve the user's original
goal; this is an incomplete implementation, not finished acceptance.

- Repository: `Shermanxwz/Rule-proxy-Web`, Draft PR #8.
- Branch: `feat/windows-proxybridge-wfp-validation`; leave main unchanged.
- Local working checkout:
  `/workspace/scratch/d71bf2368927/Rule-proxy-Web`.
- The local origin is an earlier local mirror. Local and GitHub commit IDs
  differ because commits are published through the GitHub connector. Compare
  all blob hashes and executable modes to the remote tree, rather than assuming
  local commit IDs equal the remote head. Do not force-push or discard changes.
- Native C++/Python source passed both real OS jobs at remote commit
  `4d4940f29c9f54c910ad011cea477a1ed79ad28d`, Actions run #111,
  <https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38363042665>.
  A later evidence packaging revision preserves the compiled native lab binary
  and provenance JSON; inspect the latest head's jobs for that revision.
- Both Windows 11 Enterprise ARM64 26200 and Windows Server 2025 x64 26100
  passed 30 experimental checks. These are real Windows kernels on virtual
  machines, not physical devices, simulated APIs or external capture.
- A new net-only logon SID supports WFP `ALE_USER_ID` descriptor matching.
  Ordinary different-path children and observed nested net-only children stay
  denied after controller death; ordinary same-path instances remain connected.
  The nested child changes its logon SID but retains its parent's SID as an
  enabled group. **Do not assume this case escapes.** Arbitrary primary-token
  changes, browser/broker handoff and full process-tree security remain unproved.
- Original app-ID rules still overblock same-path instances and let different
  paths/children escape. Both observations are retained; a passing experiment
  records negative findings rather than claiming production acceptance.
- ProxyBridge/WinDivert with an ALE deny prevented SOCKS interception in real
  runs #91/#93. Unrelated same-basename executables were also redirected.
  A forwarding/enforcement implementation that solves this is still missing.
- Actual source locations: `scripts/windows/wfp_native_lab.cpp`,
  `.github/windows_wfp_native_lab.py`, `scripts/windows/Build-WfpLab.ps1`.
  All are disposable CI experiments and are excluded from the product package.
- User-facing candidate profile/status lives in
  `ruleproxy/proxybridge_candidate.py`. Supported must remain false; current
  active Windows backend is MXC, Linux is Bubblewrap/network namespace.
- `.github/windows_candidate_gate.py` remains deliberately nonzero and a
  release dependency. The Draft PR must remain unmerged. Do not remove this
  gate just because native denial or ordinary tests pass.
- Full local suite: 144 run, 0 failed, 9 skipped; full CI source/package suites
  passed. See [current results](2026-10-13-continuation.md),
  [CI summary](2026-10-13-continued-ci-summary.json) and raw run #111 JSON.
  Local namespace tests did not run; the four hosted Linux jobs required and
  ran their real namespace checks.
- Failed runs #107 and #109 are retained. #107 lacked explicit CI environment
  propagation into a new logon. #109 assumed a nested net-only child would
  escape, but actual WFP denied it. Both are corrected in the #111 experiment.

Next work: implement actual transparent redirection and a production guard
with safe process identity/privileges, then integrate into the panel/Mihomo.
Native connect-redirection work that uses a kernel callout needs driver source,
build/signing and a Windows environment that can legitimately load it. The
current disposable CI lab has no such driver, installation or admission path.
Real browser login/cookie, external leak/capture and reboot tests are still
outstanding. Never replace those results with mocks or describe this draft as
封存级、完美、验收完成.
