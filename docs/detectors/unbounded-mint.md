# unbounded-mint

Availability: **opt-in review**, medium severity, low confidence for monetary-policy risk.

## Description, example and scenario

```compact
mintShieldedToken(domain, disclose(amount), nonce, recipient);
```

A variable native mint amount retains the full 64-bit upper limit on a modeled
successful history, without a recognized public-ledger upper bound. A positive-only
check and an unrelated authorization guard do not establish a per-call quantity
cap. Review whether the application intended a tighter reward or issuance limit.
This is a quantity review, not a claim that every public mint is a vulnerability.

## Recommendation

Constrain the actual minted amount to the intended per-call limit if required by
monetary policy. Protect supply, issuer authorization and public cap integrity
separately. A local amount cap does not establish a cross-transaction supply invariant.

## Evidence and known false positives

Exact shielded/unshielded kernel mint operands, immutable scalar snapshots,
checked narrowing/type ranges and successful assertion constraints retain the
actual amount. Later atomic assertions may constrain it. Constant amounts,
narrower types, proved smaller upper envelopes and public-ledger upper/equality
bounds (including transitive aliases, immutable Map snapshots and public numeric expressions) stay quiet. Numeric operand trees establish bound origins without claiming ledger digest/preimage provenance. A bound computed from the minted amount itself supplies no independent cap. Saved public bounds and pure later proof assertions also constrain checkpoint prefixes; later ledger-dependent checks only constrain the fallible segment. A value compared with itself supplies no extra upper bound. A guard on a different amount, private echo of the amount,
new storage revision or sibling history supplies no cap for this value.
Constructors and rejected histories are excluded. Observation/projection exhaustion
is rule/entry-scoped incomplete and preserves baseline results.

Trusted-issuer minting, intentionally public faucets and unrestricted issuance
and public pending-balance withdrawals are known intent-dependent shapes; the rule remains opt-in. A recognized public
bound is not proof that its storage is protected or its value reasonable. Only
per-call limits are reviewed. Protocol pricing, custom mint effects, global supply
invariants and arbitrary algebraic proofs remain outside scope.
