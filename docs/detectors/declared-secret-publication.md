# declared-secret-publication

Availability: **policy-required**; selected by default, but needs
`policies.secrets`. Severity **high**, confidence **medium**.

Reports a policy-selected witness or entry parameter influencing a real public
sink in a form not approved by `allowedForms`. This includes implicit control
dependencies. `disclose` does not remove the source dependency; exported returns
cross the application-output boundary, while ledger sinks publish ledger data.
Without `sinkKinds`, the policy covers every public sink kind. An optional
nonempty selection scopes it to `ledger-write`, `exported-return`,
`ledger-operation`, or `event`; `allowedForms` still applies within that selection.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
forwards `secret()` through a helper to a ledger write. Its policy is:

```json
{ "secrets": [{ "witness": "secret" }] }
```

Place this object under `policies` in the [configuration](../configuration.md).
The [correction](#example-2) publishes a constant
independent of the witness. Review this finding when an application's privacy
contract says a witness or parameter must not affect public output.

Recommendation: remove the public dependency, including private-controlled
effects, or explicitly approve a transformation after reviewing the disclosure
requirements. Entry-parameter policies use `circuit` and `parameter` selectors.

For an exported-return policy, select `exported-return` in `sinkKinds`. This
scopes the policy to application outputs while leaving other sink kinds outside
that policy selection; it does not establish that those operations hide a source
or that the entire contract is secure.

## False positives and limitations

An outdated or overbroad secrecy policy can flag intentional disclosures. Forms
`raw`, `derived`, `hash` and `commitment` classify tracked transformations; they
are not hiding proofs. Broadly approving `derived` can conceal implicit flows.
No secrecy intent is inferred without policy, and abstract successful paths do
not prove concrete feasibility. Incomplete analysis cannot establish absence of
leaks.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/declared-secret.compact`).

```compact
pragma language_version >= 0.26.0;
export ledger published: Field;
witness secret(): Field;
circuit forward(value: Field): Field { return value; }
export circuit publish(): [] {
  published = disclose(forward(secret()));
}
```

### Example 2

Correction (source: `tests/corpus/safe/declared-secret.compact`).

```compact
pragma language_version >= 0.26.0;
export ledger published: Field;
witness secret(): Field;
circuit forward(value: Field): Field { return value; }
export circuit publish(): [] {
  const unused = secret();
  published = 0 as Field;
}
```
