# unguarded-sensitive-state-write

Availability: **policy-required**; selected by default, but needs
`policies.authorization`. Severity **high**, confidence **medium**.

Reports a successful write to policy-protected ledger state without its required
preceding successful void guard call. A write to a state dependency of that guard
invalidates the earlier check. The configured requirement also applies to
constructor writes.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
has `publish` call a storage helper without its configured guard:

```json
{ "authorization": [{ "state": "published", "guard": "authorize" }] }
```

Place this object under `policies` in the [configuration](../configuration.md).
The [correction](#example-2) calls `authorize()`
before `store(value)`. This supports review of a documented requirement shared
by several entrypoints or helper paths.

Recommendation: use a reviewed, constraining circuit returning `[]` before every
protected mutation, and recheck after changing state that the guard reads.

## False positives and limitations

The rule trusts the policy's guard meaning; it does not audit the guard or infer
privilege from its name. A different check or a later atomic check can satisfy
business intent while still violating the configured preceding-call requirement.
An overbroad policy may therefore flag intentional behavior. A helper returning
a witness Boolean alone is not the required successful void guard call. Abstract
paths do not prove concrete feasibility or cross-transaction authorization.
Unknown effects and exhausted budgets remain incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/required-guard.compact`).

```compact
pragma language_version >= 0.26.0;
export ledger allowed: Boolean;
export ledger published: Field;
circuit authorize(): [] { assert(allowed, "permission required"); }
circuit store(value: Field): [] { published = disclose(value); }
export circuit publish(value: Field): [] {
  store(value);
}
```

### Example 2

Correction (source: `tests/corpus/safe/required-guard.compact`).

```compact
pragma language_version >= 0.26.0;
export ledger allowed: Boolean;
export ledger published: Field;
circuit authorize(): [] { assert(allowed, "permission required"); }
circuit store(value: Field): [] { published = disclose(value); }
export circuit publish(value: Field): [] {
  authorize();
  store(value);
}
```
