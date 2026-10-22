# nullifier-check-without-insert

Availability: **opt-in** with `--detectors nullifier-check-without-insert`; no policy
required. Severity **medium**, confidence **low**. Explicit selection replaces
the default detector set.

## Owned example and review scenario

The compiler-qualified [fixture](#example-1)
requires collection absence before changing state. If the application intends
one-time consumption, the [correction](#example-2)
retains an insertion in the same collection:

```compact
assert(!used.member(disclose(id)), "fresh");
used.insert(disclose(id));
accepted = disclose(id);
```

Recommendation: first confirm nullifier intent, then consume that exact member/key
on every successful relevant history and preserve the insertion. Absence checks
used for ordinary collection administration need not consume a nullifier.

## Evidence and limitations

A candidate is a modeled successful nonconstructor history that requires absence
of an exact value/key in a ledger Set/Map and performs a persistent or canonical
token effect, but does not leave that value/key inserted in the same collection.
This is a structural replay-prevention review, not proof that the value is intended
to be a nullifier or that another transaction can replay it. Read-only membership
helpers and user namesakes do not establish a missing-consumption finding.

The matcher must preserve the actual query Boolean and its value/receiver
snapshots. Ignored queries and tautologies are not guards. Different keys, witness
invocations, collection instances and stale aliases cannot supply insertion
credit. Saved absence results and late atomic assertions remain meaningful;
insert-then-remove/reset does not consume a key. Alternate successful paths and
nested helper calls remain separate. Unknown overlap/equality must not invent
proof of consumption. Unsupported effects and exhausted observation/decoding
budgets must be explicitly incomplete, discarding partial rule findings after
query exhaustion.

The default engine now correlates repeated dynamic membership queries by exact
receiver selectors, member operands and ledger revision, retaining the observation
across local cleanup. It never identifies two reads merely by a wildcard region.
The opt-in observations also retain immutable hash/commitment operands and the
ordered query/write positions. Component equalities rebuild aggregate identities;
bounded Boolean equality/negation propagation handles indirect absence guards.
Inserts survive descendant value updates, but removal, reset or possible ancestor
replacement revokes credit. Each operand traversal is bounded to 4,096 visits and
charged to analysis work; rule matching shares a 1,000,000-work allowance. Any
exhaustion discards partial rule candidates and emits an incomplete diagnostic.

Read-only absence checks can be intentional for collection administration and
need not consume a key. A match is a replay-prevention review prompt; it does not
establish that the checked value is a protocol nullifier or that another
transaction can replay an operation.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/nullifier-check-without-insert.compact`).

```compact
import CompactStandardLibrary;
ledger used: Set<Field>;
export ledger accepted: Field;
witness token(): Field;
export circuit accept(): [] {
  const id = token();
  assert(!used.member(disclose(id)), "fresh");
  accepted = disclose(id);
}
```

### Example 2

Correction (source: `tests/corpus/safe/nullifier-check-without-insert.compact`).

```compact
import CompactStandardLibrary;
ledger used: Set<Field>;
export ledger accepted: Field;
witness token(): Field;
export circuit accept(): [] {
  const id = token();
  assert(!used.member(disclose(id)), "fresh");
  used.insert(disclose(id));
  accepted = disclose(id);
}
```
