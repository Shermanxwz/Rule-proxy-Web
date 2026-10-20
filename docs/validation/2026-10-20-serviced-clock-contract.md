# Serviced guest RTC and absolute-budget contract

## Measured failure

Attempt 04, run `39469042223` at `0c35b72955cefcfd8e7f7ca3ebfc3bef4f338ec9`, retained a protected setup diagnostic: `budget_epoch / expired`, remaining seconds `-17216`. The ordinary reader subsequently reported `budget_acl / missing`. This establishes that setup rejected its original host-issued deadline before producing the protected budget. The native probe and actor were not reached. Cleanup was positively confirmed for this attempt.

Host startup was approximately 17:48:39 UTC. Its work deadline is `floor(min(host_start_wall + 9600, 1792528149) - 180)`, approximately 20:25:39 UTC. QEMU launch at 18:03:57 and installed beacon at 18:15:19 bracket setup. The observed negative delta is consistent with a guest UTC clock roughly seven hours ahead: the implied setup instant after subtracting seven hours is approximately 18:12:35 UTC. No exact host timestamp of setup was retained, so this is quantitative consistency, not an exact measured offset. No seven-hour subtraction belongs in the implementation.

## Primary contract evidence

[Microsoft's TimeZone documentation](https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-timezone) states that an en-US installation defaults to Pacific Standard Time. The old seed switched to UTC in specialize, the same pass that ran setup. [QEMU 8.2.2 options](https://github.com/qemu/qemu/blob/v8.2.2/qemu-options.hx) specify UTC RTC by default and localtime for Windows; its [RTC implementation](https://github.com/qemu/qemu/blob/v8.2.2/system/rtc.c) uses the process local-time conversion for localtime mode. Merely adding localtime on a UTC host leaves the same initial civil clock and is not a demonstrated correction.

## Scoped candidate

Use a coherent local RTC convention only on the serviced path: a copied QEMU child environment with `TZ=America/Los_Angeles`, explicit `-rtc base=localtime,clock=host`, and a serviced-only rendered unattended `Pacific Standard Time`. Do not mutate the parent environment, host timezone, shared pinned media template or unrelated paths. Do not set guest time, alter registry/security settings, compensate a fixed offset, rebase an expired deadline or relax a bound.

All host Unix timestamps and monotonic deadlines remain unchanged. The protected guest deadline still uses the original host work deadline, clipped by setup plus 110 minutes, and is not renewed on task restart or reboot. Consistent Windows local timezone across first boot and subsequent reboot avoids deliberately introducing a timezone transition. The host absolute/monotonic teardown remains authoritative even if guest time is incorrect.

Local RTC is ambiguous during the repeated fall-back hour. Refuse ambiguous civil time anywhere in the bounded VM work window, or a window crossing an offset transition; do not guess a fold, wait/retry automatically, or adjust deadlines. A clock-contract rejection is infrastructure failure, not an isolation result.

Before a runtime decision, pure Linux and Windows tests must compare the IANA and Windows Pacific mappings for winter, summer and both DST transitions; verify child-only environment and exact generated XML/argv; and preserve expired/over-bound rejection. Runtime clock observations are harness diagnostics, not native identity or isolation acceptance. A successful pure fixture does not prove initial guest boot or servicing. Exact build, mandatory reboot, ordinary account, native acceptance, resource admission and cleanup gates remain in force.
