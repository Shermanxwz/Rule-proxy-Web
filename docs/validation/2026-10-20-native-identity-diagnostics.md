# Native identity diagnostics without acceptance changes

Direct attempt 02 (`39447439803`) ran a fresh nonce-bound actor and the executor
exited zero. Its report parsed successfully and every existing Stage0 check
except `native_identity` passed. The original result remains failed. The public
artifact retained only the aggregate identity check, so the exact failed token
predicate cannot be recovered from it. No OS incompatibility, assay mismatch or
successful isolation is inferred from that missing evidence.

The diagnostic extension mirrors each existing identity conjunct into a fixed
boolean field, with separate presence/type observations and the original
recorded check. It does not change `stage0_checks`. No SID, PID, capability value,
nonce or raw actor report is published. Old reports do not acquire retrospective
identity facts. Reprojection preserves the closed schema and never converts the
original failure into success.

To preserve the existing 16 KiB transport limit, diagnostic operation-label
lists were initially bounded to eight per summary/envelope, and are now
bounded to six to accommodate the closed capability classifier. Recognized-label counts and
truncation flags remain explicit, alongside message hashes, byte counts,
categories, native error codes and the primary error envelope. This is bounded
diagnostic metadata, not an acceptance or isolation-policy change.

Before any future VM test, the Windows compile job runs the existing hash-checked
IdentityOnly actor under its current source token. This control performs only
read-only native identity queries, with a fresh nonce and a bounded owned private
report. It requires actual successful queries, normal exit, matching child PID,
non-AppContainer source token and null AppContainer SID; the outside-sandbox
identity must not pass Stage0. Elevation/job/capability fields must be observed
with valid types, but their values are not changed or used as isolation evidence.
The owned process is observed exited and raw report/directory deletion is checked.
Only closed booleans and fixed bounded capability counts enter CI logs. No G executor, container, account, token
mutation, HTTP/pipe test, image download or VM is involved in this control.
