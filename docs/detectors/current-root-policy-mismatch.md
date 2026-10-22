# current-root-policy-mismatch

Availability: **opt-in policy**. Severity/confidence: **medium/high**. Select with
`--detectors current-root-policy-mismatch` and declare the application requirement:

```json
{"version":1,"policies":{"currentRootMembership":[
  {"circuit":"record","ledger":"permitted"}
]}}
```

The policy applies to positive native `checkRoot` predicates enforced on modeled
successful histories of the selected exported circuit. It requires the checked
root to be current **when that predicate is enforced**. The ledger selector is
an unambiguous canonical ledger ID or name; all native Merkle receivers below
that root are selected, including nested Maps. Helpers retain their actual
invocation operands and sites. This policy does not infer freshness intent.
Equivalent repeated queries list every candidate invocation; the report never
silently identifies an unused call as the saved Boolean's exact occurrence.

```compact
import CompactStandardLibrary;
ledger permitted: HistoricMerkleTree<2,Field>;
export ledger accepted: MerkleTreeDigest;
export circuit record(root: MerkleTreeDigest): [] {
  assert(permitted.checkRoot(disclose(root)), "membership");
  accepted = disclose(root);
}
```

Historic trees accept previous roots. An application that promises latest-snapshot
acknowledgment should use `MerkleTree`, or establish a recognized current-only
invariant with `resetHistory`/`resetToDefault` and perform a fresh query. Query-time
proof alone is insufficient: saving a positive check, inserting into its tree,
then asserting the saved Boolean does not certify the tree at that guard.
Ordered real writes are checked between query and enforcement. Exact sibling
writes preserve certification; possible aliases and ancestor replacements remove
it. No comparison between Merkle epochs and ledger revisions supplies a proof.
Native current trees remain exclusive for dynamic receivers too.

The diagnostic reports a missing guard-time certificate under the explicit
policy. It does **not** establish that historical roots are actually stored, that
an overlapping write changes the root, that a stale root is accepted at runtime,
or that a modeled history is feasible. Intentional historical membership is a
known policy-dependent review shape: leave this policy unset. Negative checks,
mere optional queries, and tautologies do not become required positive membership.
A true branch does enforce membership on its own successful history.

Later-effect freshness is outside this contract: a fresh guard followed by an
insertion is quiet even if an effect happens afterward. Missing membership guards
are also outside this rule; see `merkle-membership-not-enforced`. Independently
bound current roots and unmodeled application invariants can make a reported
certificate gap intentional. Nonliteral Boolean equality chains, lost predicate
structure, unavailable/checkpoint-projected positions and exhausted budgets give
explicit rule/entry-scoped incomplete diagnostics, never clean policy results.
Boolean-to-numeric encodings in enforced predicates are also explicitly
unavailable; conversions cannot erase a native check into apparent clean absence.
Opaque native digest/commitment relations involving observed check Booleans
retain a loss marker and are unavailable too; hashing is not decoded as Boolean
equality or positive membership evidence.
No successful invocation supplies no complete guard evidence.
