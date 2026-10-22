# duplicate-shielded-mint

Availability: **default-on**, medium severity, high confidence for operand equality.

## Description, example and scenario

```compact
mintShieldedToken(domain, 1, nonce, recipient);
mintShieldedToken(domain, 1, nonce, recipient);
```

Two canonical library calls on the same modeled successful transaction history
have provably identical token domain, amount, nonce and active recipient. The
contract address is unchanged within that history. The library derives the same
coin commitment, which the ledger rejects as a duplicate. This is a transaction
availability defect; the rule does not establish theft or runtime feasibility.

## Recommendation

Use a different nonce for each minted output. `evolveNonce` derives nonces
from an index and a prior nonce; use distinct indices for different outputs.
Review freshness across separate transactions independently.

## Evidence and known false positives

Resolved canonical mint calls, immutable operand identities/constants and enforced
successful-path equalities establish equality. Re-evaluating `evolveNonce` with
identical inputs also establishes equality. A saved opaque computed nonce retains an observer-only immutable snapshot; separately computed unknown values do not become equal through shared dependencies. Inactive Either payloads are ignored;
active tags and addresses are retained. Separate histories, rejected paths,
independent unknown witnesses, changing ledger revisions, different amounts and
domains, and application namesakes do not create duplicates.

Intentionally rejected test transactions may be review matches. Generic repeated
`persistentCommit` openings are not diagnosed as a vulnerability. Cross-transaction
nonce freshness, custom mint/commitment implementations and symbolic reasoning
are outside scope. Unknown operands do not prove a duplicate; exhausted observation
or equality budgets are rule/entry-scoped incomplete, preserve baseline findings
and keep the overall scan incomplete.
