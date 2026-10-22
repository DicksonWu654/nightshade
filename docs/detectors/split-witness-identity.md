# split-witness-identity

Availability: opt-in. Severity: low. Confidence: high.

Opt-in low severity, high confidence review of a precise static relationship.
A successful history enforces a canonical native digest of exact witness input
snapshots equal to definite preexisting ledger data. A Map/Set mutation key (or
same-typed scalar Kernel mutation operand) uses entirely independent supplied
witness snapshots. No mandatory scalar equality connects the observed guard
digest or represented input leaves to the effect operand or its represented
input leaves. Output digest equality and transitive scalar equality can bind the
identities. Checks after the mutation count because they constrain the same
successful transaction.

The first implementation observes exact native digest inputs and resolved
collection operation keys, not arbitrary arithmetic dependencies, stored value
taint, wildcard write paths, or unrelated mutations. Aggregate Kernel operands,
shielded-native recipient structures, collection lookups/member guards, and
other protocol-specific authentication remain outside this contract. It does
not interpret equal hash outputs as equal preimages. Fresh invocations of the
same witness declaration remain independent; unchanged aliases retain identity.
Ledger snapshots and revisions are not converted to live storage identities.

Rule-isolated source observation uses all predicates and original histories.
Missing predicate/digest/collection evidence, optional predicate alternatives
that cannot be decoded, and exhausted allowances produce rule-scoped incomplete
coverage and withhold findings. Baseline completion is independent. Experimental
Counter mode has an absence certificate because the closed terminal Counter
grammar excludes witnesses; other entries route to exact source observations.
Both instruction/reference engines and cached/uncached transfers are covered by
focused compiler-backed tests.

Independent witness values can be intentional when the protocol treats the guard
identity and mutation key as separate roles. The rule reports their unlinked
source relationship; it does not infer caller intent or establish an
authorization bypass.
