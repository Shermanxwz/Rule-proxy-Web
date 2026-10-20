# Closed token capability diagnostics (schema 1)

This is observation, not a changed Stage0 criterion. The original
`tokenCapabilities == []` predicate and failed direct attempt 03 remain intact.
A recognized capability is not automatically safe, required, supported, enabled
by default, or evidence of a network leak. Token authority and actual WFP
network enforcement are separate questions; no network test is performed here.

Pinned G's deny/deny request supplies no capability names and serializes the
PSEC capability input as absent. Neither that input nor the inspected PSEC
schema guarantees an empty final OS token. The unrelated AppContainer fallback
adds AgenticAppContainer, but that does not establish its presence or default
meaning in the BaseContainer path.

Classification uses a fixed public catalog and native SID derivation/equality
locally. It never invokes a resolver whose unknown fallback returns a SID, nor
enumerates capability registry/private names. The baseline is the same guest's
already-verified ordinary controller token, not the hosted compile runner's
token. Native queries are read-only. Raw SIDs, SID-derived hashes, private names,
PID and raw token values are not published.

The fixed catalog order is:

1. internetClient
2. internetClientServer
3. privateNetworkClientServer
4. networkLoopback
5. picturesLibrary
6. videosLibrary
7. musicLibrary
8. documentsLibrary
9. removableStorage
10. enterpriseAuthentication
11. sharedUserCertificates
12. appointments
13. contacts
14. AgenticAppContainer
15. learningModeLogging
16. permissiveLearningMode

Each fixed row contains ten bounded counts: actor total, enabled,
enabled-by-default, deny-only, other-attribute-bits; then those same five counts
for the ordinary source. The anonymous unknown row uses the same layout.
Counts are at most 16; fixed lengths and exact integer types are checked.
Zero rows are placeholders unless `catalog_complete` and the corresponding
`observed`/`source_observed` flag are true. Catalog completeness currently
requires exactly one derived CapabilitySids entry for every fixed name; the API
returns arrays, so a different count makes this diagnostic catalog unavailable,
not the actor identity failed.
Invalid/duplicate observations and incomplete catalog/query states are explicit,
not reclassified as benign unknowns. Exact SID-set and attribute equality are
computed privately and exposed only as booleans when observations are complete.

Enabled means the observed `SE_GROUP_ENABLED` bit (0x4), enabled-by-default the
0x2 bit, and deny-only the 0x10 bit. Other bits are counted, not interpreted as
permissions. A recognized disabled or deny-only entry is not an isolation pass;
an unknown enabled entry remains unresolved.

To retain the unchanged 16 KiB report ceiling, operation-label diagnostic lists
are now bounded to six entries rather than eight. Their full recognized count,
truncation flag, inspected-message hash/byte count, category, native error code
and primary error envelope remain. The classifier does not truncate its fixed
catalog. Worst-case wire tests and an actual Windows native helper gate must
pass before a separately reviewed runtime. Hosted source-token controls prove
only the helper/control wiring, not Windows guest isolation.
