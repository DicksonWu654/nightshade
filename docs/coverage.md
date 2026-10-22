# Nightshade coverage reference

Start with [limitations](limitations.md) for the current support contract and
[evaluation](evaluation.md) for measured completion. A supported feature is
qualified only within its compiler profile and represented source shape.

The core supports bounded scalar/aggregate values, canonical native identities,
module/call specialization, ordinary and higher-order call transfers, expression
control, provenance, selected ledger/collection transfers and restricted summaries.
Independent paths retain their own effects and guards. Wildcard storage paths are
may-alias sets and cannot establish must-equality. Parameter/local ledger reads
are snapshots; collection refinement applies only to the observed revision.

The [semantic ADRs](adr/0016-casts-and-semantic-profile.md) document qualified
premises. Per-rule pages in the [catalog](detectors.md) narrow engine coverage
further and record not-applicable/incomplete boundaries.

Ordinary JSON schema is **1.6.0**; experimental Counter-query schema is **1.7.0**.
Rule coverage is distinct from `coverage.baselineStatus`. Counter predicate
coverage is distinct from exact entry completion. Source-local formula evidence
does not create completed runtime entries or erase baseline diagnostics.
