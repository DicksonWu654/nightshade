# source-claim-map-getter-review

Availability: **opt-in**, **policy-required**; severity **info**. Select
`--detectors source-claim-map-getter-review` and supply `policies.sourceMapGetters`:

```json
{
  "sourceMapGetters": [{
    "setter": "setAdmin", "getter": "getRoleAdmin", "map": "roleAdmin",
    "setterKey": "role", "setterValue": "admin", "getterKey": "role",
    "quote": "// Documentation claims DEFAULT_ADMIN_ROLE is customizable by roleAdmin entry."
  }]
}
```

An outdated or overbroad documentation quote can produce an intentional policy
mismatch. Verify that the quoted claim is current and that the setter/getter
selectors reflect the actual API before changing code; the rule checks the
configured claim and does not infer user expectations.

This explicit contract says the getter should reflect the selected Map value
configured by the setter for the same key. The analyzer does not infer this
meaning from names or prose. Circuit/Map selectors resolve to unique active
canonical symbols; parameter selectors are ordinary original names or canonical
parameter IDs. Key and value types must agree exactly with the native Map and
getter result, retaining nominal identities.

Activation requires one complete parser-owned comment, including delimiters,
exactly equal to the quote and immediately preceding the exported setter, with
only whitespace between them. Removing the quote and the obsolete setter/Map is
quiet. An exact quote remaining with missing or ambiguous setter identity is an
invalid/incomplete observation. A different quote or nonadjacent comment is
not-applicable. Existing `sourceClaims` policies retain their original semantics.

A finding requires complete original successful setter histories with a surviving
root-Map insertion of the selected original key/value operands, and complete
getter histories returning the same exact default constant. The complete
resolved getter source closure must have no read of this Map, including helpers,
imports, lambdas and syntactically present zero-iteration callbacks. Unsupported
external calls, unresolved effects, checkpoints, unavailable history identity or
exhausted allowances produce rule-scoped incomplete diagnostics.

Experimental Counter mode lacks the selected original setter/getter histories.
Selecting this rule with a configured contract in that mode returns incomplete
coverage and a diagnostic.

Preparation, execution, matching and finding retention share the unchanged
40,000-step per-entry and 50,000-value cumulative rule allowance; histories are
limited to 256. This source/API contract review does not execute a setter followed
by a getter, infer cross-transaction feasibility, or establish deployed behavior
or impact. Findings are informational and require the supplied contract.
