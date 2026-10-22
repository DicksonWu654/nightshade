# Shielded contract recipient review

Availability: **opt-in**, informational severity. No policy required. Select with
`--detectors shielded-contract-recipient-review`.

This rule reports an exact canonical `sendShielded` or `sendImmediateShielded`
call on a complete modeled successful history whose recipient selects the
`ContractAddress` arm of native `Either<ZswapCoinPublicKey, ContractAddress>` and
has an enforced exact non-self address relation. Its supported applicable scope
is Compact 0.34.0 / ZKIR2. Canonical call and native type identity, exact recipient
operands and immutable byte relations supply the evidence; application names and
shared wildcard paths do not.

Review how the transaction supplies the recipient contract's matching
receive/claim composition. External same-transaction composition is unmodeled.
The finding does not establish a missing claim, transaction rejection, concrete
path feasibility or security impact. Intentional forwarding and testing helpers
can match. Account-only and exact self-recipient controls remain quiet.

The ordinary pass and admitted top-level native recipient-tag specializations
share the unchanged allowances: 40,000 steps, 256 retained paths and 50,000
cumulative abstract values by default. All required passes must finish before
findings are admitted. Unknown or opaque tags, unavailable exact histories,
unsupported applicable profiles, checkpoints, external contract-call composition
and exhausted allowances produce scoped incomplete diagnostics. Structural
absence does not provide an absence guarantee for incomplete baseline semantics.
