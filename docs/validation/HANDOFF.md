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
