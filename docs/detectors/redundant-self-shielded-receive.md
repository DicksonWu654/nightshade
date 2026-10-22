# redundant-self-shielded-receive

Availability: **default-on**; severity **info**, confidence **high** for the supported source fact.

This rule reviews an exact returned coin from canonical `mintShieldedToken`, or
`sendShielded` / `sendImmediateShielded` `.sent`, subsequently passed to canonical
`receiveShielded` on one original modeled successful history. It requires a
recipient with `is_left == false` whose right `ContractAddress.bytes` has the
exact immutable identity of an observed `kernel.self().bytes`.

```compact
const coin = mintShieldedToken(default<Bytes<32>>, 1, default<Bytes<32>>,
  right<ZswapCoinPublicKey, ContractAddress>(kernel.self()));
receiveShielded(coin);
```

The owned pinned standard library automatically invokes its receive claim for
this recipient. Review removing the explicit receive of the same returned coin.
Keeping an explicit call for API symmetry or source readability can be intentional;
this rule reports the duplicate call sequence, not a second coin output or a
security defect.
This is a call-sequence fact: ledger rejection, security impact, application
intent, attack and transaction feasibility are not established.

The helper compares represented coin components using immutable identities,
constants and opaque mint-observation snapshots. Aliases and unchanged projections
retain evidence; names, provenance unions and later predicate equalities do not
identify coins. User namesakes are excluded by canonical identity. Change outputs,
external recipients, independent recomputations, unknown recipient tags and
predicate-linked recipient addresses are outside the supported shape. Mutually
exclusive histories never donate a producer to a receipt. Later rejecting
continuations contribute no successful history.

Missing selected invocation or mint snapshot evidence and exhausted query
allowances produce explicit rule-incomplete diagnostics. Reachable canonical
`kernel.checkpoint()` entries are explicitly incomplete because the ordinary
committed prefix observations lack exact returned invocation snapshots. The rule
does not infer atomicity or discard checkpoint boundaries to claim completeness.
