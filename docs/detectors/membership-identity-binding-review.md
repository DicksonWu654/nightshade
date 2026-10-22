# Membership identity binding review

Availability: **opt-in** with `--detectors membership-identity-binding-review`.
Findings are informational policy questions, with high confidence limited to the
observed source relationship.

The rule observes a canonical `Map<Bytes<32>, List<Bytes<32>>>` mutation at an exact
key. Imported aliases and nominal container aliases are admitted only when
canonical native identity and recursively resolved argument shapes agree. Required scalar equalities connect that key to a canonical `persistentHash`
of one raw, declared `Bytes<32>` witness snapshot. A required canonical
`Set<Bytes<32>>.member` predicate tests an independent raw witness snapshot in the
same completed atomic history. No required scalar equality connects the digest
or its input to the membership input. A public key parameter is not trusted ledger
data; this equality alone does not establish authentication policy.

One report groups a digest/key snapshot, membership predicate and nested Map root,
retaining a representative mutation and the observed source sites. Different
roots, membership snapshots and digest snapshots remain separate questions.
Source sites can occur on different complete histories; their effects are never
combined into a single executable history. Zero-iteration histories supply no
mutation. Optional membership in an alternative successful history at the same
mutation site suppresses the mandatory composition question. Required Boolean
facts are intersected; exclusive checks never donate equality or membership.

Direct, transitive, aliased and late atomic scalar equalities bind snapshots.
Repeated invocations of one witness declaration remain independent. Equal hash
outputs never establish equal preimages. Query identities retain the exact Set
receiver, operand and ledger revision. Wildcard mutation paths cannot supply exact
key evidence. Unavailable histories, predicate structure, snapshot identities,
checkpoints and exhausted budgets produce diagnostics and incomplete coverage.

The initial boundary excludes other represented container shapes, aggregate or
transformed witness inputs, user collection lookalikes, and cross-entry policy
comparison. Preparation, execution, additional collection retention, matching and
report construction share 40,000 steps per entry, 256 paths per entry and 50,000
cumulative abstract values per selected rule; no retry budget applies.

An application may intentionally use one supplied identity for a stored map key
and an independent witness for membership. That source relationship is an
informational review question, not proof of an authorization defect; confirm the
intended identity-binding policy before changing it.
