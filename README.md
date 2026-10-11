# Immutable MXC proxy dependency candidate

This is a project-built component, not an official Microsoft SDK or a production RuleProxy application release.

Source: microsoft/mxc@c6f301d53a1430c4c921a05c57af838f7392348f; Rust 1.93, upstream Cargo.lock and hardening flags, static CRT, x86_64-pc-windows-msvc, no optional backends.

Build: https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38134137607

Qualification: https://github.com/Shermanxwz/Rule-proxy-Web/actions/runs/38138494180

Windows 11 25H2 ARM64 26200.9457: native ARM64 and x64-emulated Python proxy data, controlled direct TCP/UDP denial checks, ungranted file rejection, bad proxy rejection, normal/core/wrapper failure cleanup passed. Standard-user transport passed. Native Windows 11 x64 CPU and external IPv6 are unqualified.

Edge 154.0.4258.53, Chrome 155.0.8059.39, Firefox 157.0.1 failed. Browser rendering, persistent login and product release are NOT qualified. Raw passing and failing JSON results are retained in validation/.

The identity-less proxy mapping does not provide full bidirectional host-loopback identity closure or defend against malicious same-user proxy replacement or host IPC. Bit-for-bit source reproducibility is not claimed.

Installer URLs must use the immutable commit SHA and verify SHA-256. Normal source checkouts do not include this archive.
