# Direct UDP: standalone mechanics and pure evidence contracts

## Scope

This first slice is code and short-gate machinery, not a Windows guest isolation
result. It does not call `DnsQueryEx`, exercise a DNS broker, modify system DNS,
or substitute direct UDP success for a DNS API positive control. The earlier
REQUEST3 assays remain unresolved and parked; their API87 results are retained.

The production UDP actor is a separate, source-pinned executable. It shares the
unchanged identity observation source, but does not replace the existing TCP
actor, TCP evaluator, original IdentityOnly result, or policy. Its endpoint is
the fixed runner address `10.0.2.2` and a supplied owned high port. Identity and
the strict role-specific profile gate precede all socket operations. The old
empty-capability Stage0 criterion is not relaxed by this experiment.

A distinct compile-time TEST_ONLY build uses owned IPv4 loopback for hosted
mechanics. It has a separate name and non-deployable manifest, is not uploaded,
and is not a production payload. The production ordinary-role guard must reject administrative tokens. Hosted
checks do not invoke a valid production network CLI: they test invalid-CLI
refusal and invoke the exact profile helper on the actual host token through a
compile-time TEST_ONLY identity-only entry with no socket path. Source pins and
ordering checks bind the production guard before WSA/socket use; this is not a
runtime proof of the production network CLI guard. TEST_ONLY loopback exchanges prove only
socket mechanics, not genuine ordinary-token, PSEC, guest-to-runner, or isolation
behavior.

## Datagram contract

Each socket is fresh, explicitly bound to an ephemeral port, and uses numeric
IPv4. The fixed bounded frame carries a fresh nonce, phase, and attempt index.
It is one datagram, not a byte stream: no concatenation, stream-EOF inference, or
retransmission after an accepted send. Echo validation requires the exact frame
and expected responder address and port. Wildcard local IPv4 returned by
`getsockname` remains unspecified; it is never invented into an observed source
address. The actual bound source port is recorded privately.

The contained shape has three attempts scheduled against one original bounded
window; late attempts do not renew the budget. Ordinary before, bounded sampler,
and after phases use fresh sockets and exact echo exchanges. Future integrated
controls must establish same-guest QPC ordering and a successful sample fully
inside the actual contained attempt window, not merely concurrent processes.

## Independent observations, not an overall pass

- A successful `sendto` return means local API acceptance, **not delivery**.
- `explicit_send_denial` requires all three actual `sendto` invocations to return
  WSAEACCES10013. Startup, bind, receive, or observation errors do not qualify.
- `bounded_no_selected_udp_datagram` is a separate bounded capture observation.
  It requires all three actual invocations, complete calibrated capture, fresh
  bindings, complete ordinary controls, unambiguous ports, and confirmed cleanup.
  It can coexist with API acceptance; it does not assert API enforcement.
- A validated selected payload observed at the receiver or in capture remains
  an observation even if a later operation or cleanup fails. Tuple coincidence
  alone is not actor attribution. Pure parsers cannot authenticate their inputs.
- Timeout, missing echo, unknown errors, ambiguous ports, missing controls,
  malformed or incomplete capture, and uncertain cleanup cannot establish
  absence. No overall UDP-isolation, DNS-isolation, Linux-equivalence, or product
  acceptance follows from these fields.

Microsoft explicitly distinguishes successful send completion from delivery.
Datagram receive truncation and zero-length messages also differ from streams.
See [sendto](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-sendto)
and [recvfrom](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-recvfrom).

## Pure capture contract

The new UDP decoder and private manifest schema remain separate from the TCP
SYN/connect schema. Fixed VM MAC, runner destination, source ports, and exact
nonce/phase/index payloads are checked. Ordinary packets, including the terminal
control, must calibrate the relevant outbound path. Prior synthetic QEMU ingress
tests do not establish actual Windows UDP egress visibility.

Bounds, truncated records, fragments, unknown relevant flows, collisions, and
missing calibration are fail-closed for absence. A pure function receiving a
digest or a Boolean does not independently establish that value's provenance.
Future integration must derive expected pins and lifecycle facts from the
controller and retain the distinction between attested reports and independently
observed resources. This first slice has no host/guest transport or capture-owner
integration and no private packet or manifest uploads.

## Short-gate boundary

The dedicated marker admits only standard Ubuntu and Windows short jobs, with
5-minute and 8-minute job limits. Hosted mechanics have one finite shared budget
and independently tracked owned child, socket, and thread cleanup. Wait bounds
do not guarantee that every OS operation is interruptible; uncertain cleanup
cannot be reported as complete. Closed gate output excludes private nonce,
tuple, PID, raw packet, and exception data. Ordinary compiler diagnostics remain
separate build output.

No complete Windows guest, additional account, global network setting, firewall
rule, port53 takeover, address search, forwarding, paid resource, or user device
is used. No artifacts are uploaded. Existing TCP and capture workflows retain
their behavior. Actual hosted mechanisms and all pure contracts must pass exact
source review and execution before a separately reviewed integration is proposed.
