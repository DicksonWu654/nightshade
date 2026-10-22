# Merkle leaf binding review

Availability: **default-on**; no policy required. Direct Field/Bytes<32> path-lookup
review is **info/medium**; Field hash-write intent review is **info/low**.

`merkle-leaf-binding-review` is an informational intent review. It finds
modeled successful histories where a canonical checked Merkle root accompanies
an exact recomputed hash candidate influencing a Field ledger write, without a
required equality between that root operation's original Field leaf and candidate.
The operations can be intentionally independent. Root enforcement alone is not a
security flaw or evidence of exploitability.

The narrow candidate scope is a Field `directDigest` snapshot at a write operand,
or within exact `numericExpression` addition/subtraction/multiplication operands.
The final hash of a summarized nonzero-depth canonical Merkle root remains a
candidate through a separate marker; it does not invent a native hash preimage.
Constant hash inputs remain candidates. Successful equality predicates provide
transitive binding, and constructing a path with the exact candidate binds it by
identity. Equality never comes from shared provenance or storage regions.
Whitelist-only histories without a recomputed candidate remain quiet.

Analysis must enable existing Merkle, digest-input and mint-quantity observers,
retain all successful predicates, and disable fold/hash compression. The detector
checks the observer evidence markers, but the caller is responsible for selecting
uncompressed caller histories. The isolated observer can summarize the pure root
helper from the exact pinned 0.30.0, 0.31.1 and 0.34.0 ZKIR2 standard libraries,
for Field/Bytes<32> leaves and depths 0 through 32. The transfer retains the whole
immutable path identity and its represented dependence without enumerating path
directions. It adds no leaf equality, root trust or membership. Argument evaluation,
effects and aborts happen normally; source-work estimates stay unchanged. The
ordinary call-depth allowance includes the entry helper reached by a nonempty
path fold. A zero-depth root does not spend that callback frame.
Other profiles and shapes use ordinary interpretation or explicit incomplete diagnostics.
The ordinary interpreter remains a small-depth oracle, and baseline analysis is
unchanged. Incomplete entries and constructors are excluded. Equality/root decoding
and candidate traversal are bounded; missing required evidence or exhausted budgets
produce diagnostics and discard findings from that run.

Root enforcement reuses the revision-qualified Merkle predicate snapshots. Leaf
matching uses the original root operand, so a later replacement cannot satisfy an
earlier leaf obligation. Separate proof and witness invocation identities remain
distinct; optional bindings only cover histories on which they are enforced.
Aborted histories have no successful effects to report.

The separate hash-write arm excludes Bytes leaves, aggregates, control-only hash dependencies,
commitments, arbitrary derived expressions without numeric snapshots, hashes lost before any observed path lookup/write operand, and effects outside
modeled Field ledger writes except the direct path-lookup input shape. Such
shapes are outside this rule's restricted applicability; it is not an exhaustive
candidate-computation analysis. No application authentication intent is inferred.

Focused tests cover instruction/reference engines with cached/uncached summaries,
optional/transitive checks, independent proofs,
stored operand replacement, constructed paths, constant-input candidates, aborts
and evidence budgets. Compiler validation uses compactc 0.34.0 with `--skip-zk`;
no deployed contracts, runtime execution or proof execution are involved.

Direct canonical `MerkleTreePath` witnesses also retain their lookup operands.
For a checked exact returned path, a Field or Bytes<32> lookup input not required
equal to its leaf on that successful history reports info/medium. The argument
must have the leaf's exact type; original argument positions remain in the report.
Passing a candidate to a
witness never binds the returned leaf. Immutable full-path matching distinguishes
separate invocations, retained snapshots and a rebuilt path. Inputs that are
indices or independently validated values can intentionally differ and require
human review. Type-scoped equality keys distinguish scalar representations.
Byte/Field conversions and round trips supply dependence, not equality with
the original input. Root and leaf checks may occur in either order on the same
successful history; this is not a dominating-before-effect claim.

Direct Bytes<32> leaf lookups also support the canonical NoLeafHash helper.
Paths nested in witness-returned aggregates, arbitrary
commitment computations that leave no retained candidate, custom root helpers
and broader proof intent remain outside this restricted rule. Missing required
observations and exhausted budgets are incomplete, never a quiet completion.
