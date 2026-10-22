# destructive-list-reset

Availability: **opt-in review**; low severity / medium confidence. A whole persistent List is
replaced with an empty List on a modeled successful nonconstructor history,
without a recognized acknowledgment of that exact list revision. Recognized
checks are a required live length equality to a caller/witness scalar or constant,
a required empty-list check, or absence of that exact Map slot before initialization.

```compact
export ledger changes: List<Field>;
export circuit clearChanges(): [] {
  changes.resetToDefault();
}
```

For count-based acknowledgment, accept the caller's expected count and require
it to equal the same live list's length. A saved immutable count can be asserted
later in the same atomic proof, but an intervening append makes it stale for the
reset revision. Wrong-list/key checks, ignored comparisons, optional checks and
self-equality do not discharge this review. Constructor setup, known empty
lists and exact absent-slot initialization stay quiet.

Prefer pruning the acknowledged segment, or validate an epoch that is correctly
maintained for this list. The rule does **not** infer arbitrary epoch/digest-to-list
relationships. The corrected CFT epoch protocol and intentional purges are known
review matches, so this rule stays opt-in. A count check alone is not proof of
content identity, wallet durability or general concurrency safety.

The engine preserves ordered writes, immutable dynamic-key identity, list revision
and invocation sites. Unknown selectors, missing full predicates and exhausted
matching allowances produce rule-scoped incomplete diagnostics. Unsupported
baseline effects and budgets retain their existing incomplete result.
