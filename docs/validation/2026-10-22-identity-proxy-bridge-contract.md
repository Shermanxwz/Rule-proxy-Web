# Inactive identity proxy bridge v1: pure contract and model

This is a **code-only, deterministic protocol model**, not an installed proxy or an
isolation experiment. It opens no sockets, starts no processes, and calls no Job,
token, profile, ACL, firewall, DNS, or other Windows security API. No existing
runtime, workflow, policy, actor, packet evaluator, or historical result is changed.
A passing model is not evidence of an AppContainer route, frontend admission,
origin delivery, fail-closed enforcement, identity binding, or OS cleanup.

## Fixed inputs and byte contract

`windows_identity_proxy_bridge_codec.py` defines an immutable `BridgeConfig` with
16-byte run and case IDs, distinct frontend and relay ports in 49152–65535, and an
absolute deadline. The configured frontend is fixed at `127.0.0.1`; the relay's
fixture endpoint is fixed at `10.0.2.2`. These are values in a pure contract, not
network access or a statement that either endpoint exists. Caller-supplied clock
values are integer monotonic **milliseconds**. The model requires
`deadline == start + 10000`; no operation renews that deadline.

Each pipe frame is exactly 48 bytes, little-endian
`<4s B 3s 16s 16s I I`: magic `RPB1`, kind, three zero reserved bytes, run ID,
case ID, sequence, status. The fixed order is:

| Frame | Kind | Sequence | Direction | Status |
|---|---:|---:|---|---|
| INIT | 1 | 0 | relay → frontend | 0 |
| READY | 2 | 1 | frontend → relay | 0 |
| REQUEST | 3 | 2 | frontend → relay | 0 |
| RESPONSE | 4 | 3 | relay → frontend | 0–4 |
| DONE | 5 | 4 | frontend → relay | 0 |

RESPONSE status is 0 success, 1 connect failure, 2 I/O failure, 3 fixture-response
failure, or 4 deadline failure. Wrong IDs, reserved bytes, kinds, statuses,
sequences, stale frames, replay, surplus bytes, and partial EOF fail closed. READY
and DONE are protocol assertions, **not** identity or resource-cleanup evidence.

The frontend request grammar is deliberately narrow: one ASCII HTTP/1.1 GET in
absolute form, `http://ruleproxy-identity-proof.invalid/<casehex>` (optional `:80`),
with one matching Host header. The maximum is 8192 bytes, 32 headers, and 1024
bytes per line including CRLF. No request body or pipelining is accepted; an
optional single Content-Length must be exactly zero. Credentials, cookies,
Transfer-Encoding, Upgrade, malformed field names, non-ASCII and disallowed control
bytes (HTAB is permitted in header values, with SP/HTAB trimming),
ambiguous authority, alternate method, path, or scheme are rejected. Accepted
headers do not get forwarded: the relay request is rebuilt from fixed config as
`GET /p1/<casehex>` with the fixed numeric fixture Host and `Connection: close`.
The origin response must be at most 256 bytes and byte-exact canonical HTTP/1.1
200, Content-Length 32, Connection close, and the case's 32 lowercase hexadecimal
characters. Explicit EOF is mandatory; a matching prefix is insufficient.

## Model events and ordering

`windows_identity_proxy_bridge_model.py` initially loads its sibling codec by
explicit path and reuses a private module-cache key. This pure-test import assumes
that cache key is uncontaminated; it is not authenticated source binding.
`BridgeModel(config, start=...)` exposes bounded byte-input, output-progress,
EOF, mock-close, and mock-clock operations. `pending_output(channel)` is a planned
write, not evidence that bytes were sent. `write_progress` records exact positive
progress; zero progress or overcount is failure. The model never calls a clock.

The successful trace is:

1. Relay writes INIT; frontend observes it and writes READY; relay observes READY.
2. Frontend parses its one bounded request and writes REQUEST. Relay observes it
   and writes the codec's canonical request to its mocked upstream stream.
3. Relay validates the exact bounded fixture response **and upstream EOF**. This
   sets the sticky `response_verified` observation, then queues RESPONSE 0.
4. Only after the complete RESPONSE write does the relay request closure of its
   pipe writer. The frontend must observe the RESPONSE and **that pipe's EOF**;
   neither a different stream's EOF nor a close intention substitutes for it.
5. Frontend writes the complete canonical response to its mocked client stream,
   observes client-stream closure, then writes DONE and closes its pipe writer.
6. Relay requires DONE followed by frontend-pipe EOF. Only this completes the
   protocol. Independent positive close observations for every model-owned
   resource are additionally required for `model_complete`.

A nonzero relay result immediately disables further upstream/client success work,
cancels pending upstream request bytes, and allows only its bounded error RESPONSE
to drain. While that error frame drains, the public terminal `failure` may still be null;
this is not success (`model_complete` remains false). Receipt of that response is
terminal failure; there is no DONE wait.
Malformed input, I/O error, zero progress, missing/partial EOF, or deadline expiry
also requests closure of all remaining model resources. Cleanup observations do
not renew the clock or revive protocol work. A second error cannot overwrite an
already queued response. Close failure is sticky and is not retried; unknown
closure never becomes confirmed cleanup.

## Ownership and observation limits

The ledger has six **mock** frontend/relay resources: both ends of both
unidirectional pipes, a frontend client stream, and a relay fixture stream. It
starts from an explicitly assumed owned-resource state; it does not implement
handle creation, inheritance, registration, or real cleanup. A hypothetical
proxy-owned Job would include frontend and relay, not the selected client process;
no Job or descendant-lifetime semantics are implemented here.

A close request is separate from a confirmed mock close. Protocol completion,
validated fixture-response bytes, full client-response write progress, pipe EOFs,
and resource cleanup are reported independently. Already observed response/write
facts survive later timeout, malformed protocol, or cleanup failure. Public
snapshots contain only fixed labels, booleans, and fixed resource names, not run or
case IDs, endpoints, raw bytes, exceptions, or paths. `model_only` is true and
`runtime_acceptance` is always false.

Tests use the actual codec with mock transport and clock events: all frame and
HTTP split points, partial writes, EOF order, stale/replayed frames, malformed and
surplus data, nonzero statuses, early connect failure, zero progress, immutable
deadline expiry, and uncertain cleanup. They perform no actual network/process
mechanics and cannot establish a proxy-positive or proxy-down counterexample.
Those would require a separately reviewed owned-endpoint experiment, fresh exact
origin nonce roundtrip, independent ordinary controls, and explicit admission and
cleanup semantics. No such runtime authority is granted by this document.
