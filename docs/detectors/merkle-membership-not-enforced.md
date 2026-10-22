# merkle-membership-not-enforced

Availability: **default**; no policy required. Severity **medium**, confidence **low**.

Owned example: the compiler-qualified [fixture](#example-1)
discards a root-check result before storing proof-dependent data. The
[correction](#example-2) asserts
that exact digest's check. Review a write that is intended to require tree
membership; recommendation: enforce the relationship to the trusted preexisting
root on every successful relevant history.

A default-enabled **medium severity, low confidence** structural review rule. It
reports a successful history where proof-related data influences persistent state
or a canonical token operation without enforcing that exact digest's relationship
to a preexisting ledger root. Whether membership is intended needs application
review; this does not establish an authorization defect or exploitability.

For example, this produces a review finding:

```compact
const proof = suppliedPath();
const digest = merkleTreePathRoot<2,Field>(proof);
tree.checkRoot(disclose(digest));
accepted = disclose(proof.leaf);
```

When membership is required, constrain successful execution:

```compact
assert(tree.checkRoot(disclose(digest)), "member");
accepted = disclose(proof.leaf);
```

A missing constraint can leave a state-changing operation independent of the
intended tree membership. A check of a different digest, an ignored Boolean or an
equality with a newly self-written root does not establish this relationship.
The severity reflects the potential state/token effect; low confidence reflects
unknown application intent and bounded abstract feasibility.

The candidate must be a canonical computed root or private supplied
`MerkleTreeDigest`, including nested wrapper/parameter fields, whose data or control
dependencies reach a persistent write or canonical mint/send operation. Computed
roots retain dependencies on the full path, including private nodes with a public
leaf. Auxiliary path nodes do not independently become supplied-root candidates.
Constructors, digest-only helpers and namesake user functions/types are outside
this rule. An arbitrary Field witness is not presumed to be a digest.

Dependencies also follow a required same-type equality of an exact private input
before the effect. A separately supplied output constrained to equal a
proof-related commitment's hash can therefore retain that relationship when it
is stored. Sharing flow origins, wildcard storage addresses or witness declarations
does not establish equality. Derived identities and cross-type comparisons do
not identify a private input. Late equality cannot create an earlier dependency;
late atomic root checks are assessed separately. This closure and every supplied
digest candidate consume the existing matching allowance; exhaustion exposes no
partial findings. Each immutable history decodes equality once; each effect visits
only reachable dependency edges, filtering both write and operation positions.
Histories without native operations retain ordinary flow provenance without new
equality inference. Missing nonzero operation positions remain incomplete.

Accepted evidence is a required positive result of the exact digest's check against
a definite preexisting ledger tree, or transitive required equality with definite
preexisting ledger root data. Query observations preserve their receiver snapshot,
so dynamic-key checks and saved Booleans work without equating may-alias regions.
Alternate checks, Boolean aliases, checks later in an atomic circuit, repeated
computations and nested calls are supported. A prior required check stays valid
after a later write. A check first made after insertion/reset does not establish
membership in the original tree; equality with a retained original root can.

Proof-identity traversal, predicate decoding, observation matching and path/effect
storage have explicit bounds. Missing evidence or exhaustion emits an incomplete
diagnostic. Detector-query exhaustion discards all partial findings for this rule.
Caller summaries are interpreted while Merkle observations are requested because
existing caller summaries do not replay these observations; leaf summaries remain
available. This does not expand correlated-engine admission or default budgets.

Some state updates intentionally do not require tree membership. The rule reports
only the documented structural relationship and cannot infer whether the
application requires membership, prove a feasible bypass, or establish deployed
impact.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/merkle-membership-not-enforced.compact`).

```compact
import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
export ledger accepted: Field;
witness suppliedPath(): MerkleTreePath<2,Field>;
export circuit accept(): [] {
  const proof = suppliedPath();
  const digest = merkleTreePathRoot<2,Field>(proof);
  tree.checkRoot(disclose(digest));
  accepted = disclose(proof.leaf);
}
```

### Example 2

Correction (source: `tests/corpus/safe/merkle-membership-not-enforced.compact`).

```compact
import CompactStandardLibrary;
ledger tree: MerkleTree<2,Field>;
export ledger accepted: Field;
witness suppliedPath(): MerkleTreePath<2,Field>;
export circuit accept(): [] {
  const proof = suppliedPath();
  const digest = merkleTreePathRoot<2,Field>(proof);
  assert(tree.checkRoot(disclose(digest)), "member");
  accepted = disclose(proof.leaf);
}
```
