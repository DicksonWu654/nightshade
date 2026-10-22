# resettable-memo-nonce-review

Availability: opt-in. Severity: info. Confidence: high.

The initial scope is `Map<Bytes<32>, List<Bytes<32>>>`. The selected immutable
key must equal the active account recipient's represented
`ZswapCoinPublicKey.bytes`, through source operands or required successful
equalities. Exact immutable lookup operands identify the source and destination
within a history. A shared wildcard storage path never establishes their equality.
Dynamic keys in separate entry histories establish only reset may-overlap;
distinct literal reset selectors do not qualify.
Replacements proven to target an absent slot or already-empty current List do
not establish a restart; unknown initial storage is not assumed empty. An
acknowledged nonzero count can still reset the extent and remains in scope.

Select the rule explicitly:

```json
{"version":1,"detectors":["resettable-memo-nonce-review"]}
```

No memo or encryption purpose is inferred from a List name or stored bytes. The
finding states that the same resettable extent supplies both a canonical coin
nonce and a directly stored evolved payload. Its protocol role requires review.
An opaque payload does not represent memo construction or encryption use. An
arbitrary stored hash,
encoded index, nonce identifier or marker does not establish the paired relation.
Fresh seeds, mixed/arithmetic indices, transformed payloads, noncanonical
namesakes, another append receiver, different source revisions, exclusive
histories and aborted resets do not qualify. Root Lists, nested Maps, contract
recipients and unconstrained recipient relations are outside this narrow review.

Quiet output concerns this paired relation only. In particular, a fresh coin nonce
alongside a resettable length-derived stored payload is quiet because one consumer
is independent; it does not establish memo uniqueness. An independent Counter
used for both consumers avoids this paired resettable-length relationship.

The rule does not establish actual recurrence, successful transactions, one-time
pad use, encryption/decryption, confidentiality impact, authorization intent or
production implementation correspondence. Use of a resettable extent is not by
itself proof that a stored value requires security randomness. Severity remains
informational and default activation is unchanged.
