# merkle-insert-without-dedupe

Availability: **opt-in**; severity **info**, confidence **medium**.

This rule reviews sequential native `MerkleTree` and `HistoricMerkleTree`
`insert`/`insertHash` calls without exact duplicate-prevention evidence. A bounded
tree has a finite number of slots; review whether repeated values should consume
more than one. Indexed replacement and constructor setup are outside this rule.

```compact
assert(!seen.member(value), "already inserted");
tree.insert(value);
seen.insert(value);
```

The analyzer requires an enforced preceding absence check on the actual inserted
value, plus a matching insertion into that same persistent collection which
survives completion. Remembering before the tree insert is also supported.
Required immutable equality can connect aliases and nested receiver keys.
Ignored or unrelated checks, erased records and checks borrowed from an exclusive
history do not suppress review. Reusing one check for another potentially aliasing
tree insertion remains a review candidate.

If duplicates are invalid, use a persistent dedupe collection and retain its
record. If repeated leaves are intentional, document that contract and optionally disable
this informational review. External uniqueness invariants, alternate dedupe schemes,
or independent tree operations can also produce review candidates. This rule
does not establish repeated-insert feasibility, capacity exhaustion, denial of
service, replay or deployed impact.
