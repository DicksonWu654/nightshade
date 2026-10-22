# exported-shielded-descriptor

A finding means canonical shielded coin descriptor fields have an unchanged
source route to an exported Compact result. Canonical `sendShielded`,
`sendImmediateShielded`, and `mintShieldedToken` results retain their native
identity. Canonical `ShieldedCoinInfo` and `QualifiedShieldedCoinInfo` inputs,
resolved references, defaults and constructions retain represented descriptor
fields. Import aliases retain canonical identity; user types and circuits with
the same names do not establish this fact.

The output boundary is the Compact/application result, not necessarily a public
ledger. Wallet metadata APIs may deliberately return these values and still
match. The finding establishes neither successful execution nor public ledger
publication, secrecy-policy violation, exploitability or deployed impact.
Existing explicit secrecy policies and native operation sink treatment remain
independent.

The source pass preserves immutable local aliases, disclosure, identity casts,
represented structs and sequences, field selection, literal sequence indexing,
helper arguments and helper result forwarding. It inspects syntactic branches
and returns without claiming path feasibility. Aggregate projection selects the
represented field; an unrelated field or helper argument does not inherit coin
provenance. A `Maybe.is_some` flag alone does not expose a descriptor field.
Known canonical hashes/commitments end the unchanged-field route. Arithmetic,
comparisons and representation-changing casts are outside this contract.

Relevant unresolved forwarding, opaque calls, callbacks, mutations, unsupported
projections, loops in applicable source routes, recursive forwarding, and
exhausted work/depth/layout allowances emit rule-scoped
`shielded-descriptor-provenance-unavailable`. A missing provenance certificate
never substitutes for a finding-free complete relevant route. The pass has one
shared 20,000-work allowance across entries and helper expansion, depth 64, and
represented sequence layouts up to 256 elements; its work is recorded in scan
metrics. These source limits are separate from the ordinary path interpreter's
analysis budgets.

An intentional metadata return can match this rule. Review the recipient and
disclosure policy before treating the result as a defect or suppressing it.
