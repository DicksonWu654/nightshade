# default-recipient-or-owner

Availability: **opt-in**; severity **medium**, confidence **high** for the known
active address. Destination intent and concrete feasibility require review.

## Description, example and scenario

```compact
sendUnshielded(color, 1, right<ContractAddress, UserAddress>(default<UserAddress>));
```

The selected recipient is an all-zero 32-byte address at a modeled successful
output. A nonzero check on an inactive Either payload does not validate that
recipient. The rule also checks the final owner write in the byte-authenticated,
pinned OpenZeppelin Ownable module. It excludes that module's explicit
`renounceOwnership` path and a zero owner overwritten before successful completion.

## Recommendation

Validate the active destination before use. Reserve zero destinations for an
explicit, documented burn or authority-removal path. Ownership validation does not
by itself establish caller authorization.

## Evidence and known false positives

Exact transaction output operands and owner writes retain their individual history,
selected tag and invocation sites. Bounded immutable equality projection includes
aggregate leaves and later atomic assertions; it never borrows constraints from
another history, ledger revision or wildcard region. Direct authenticated owner
assignments are included. Unknown tags/bytes are not inferred to be zero;
inactive defaults, known zero-amount outputs, rejected histories, unrelated ledger
sentinels and namesake application routines are quiet. Imported module trust uses
pinned source hashes and dependency identities, rather than a filename or name.

**Intentional burns, including `shieldedBurnAddress`, are known review matches.**
Custom ownership protocols, commitment-derived identities, default addresses with
unknown tags, cross-invocation setup and arbitrary recipient encodings are outside
the rule. Constructor output operations are reviewed; zero setup sentinels alone
are not security evidence. Exact-observation exhaustion is entry/rule-scoped
incomplete and preserves baseline analysis; a quiet incomplete rule is not clean.
