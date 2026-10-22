# impossible-assertion

Availability: **default**; no policy required. Severity **medium**, confidence
**high** for modeled universal rejection.

Reports a nonliteral-false assertion that fails on every modeled path reaching
its source site, with complete caller coverage. It can also report a completely
analyzed entrypoint with no successful path, without duplicating an entry already
explained by an assertion finding.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
requires `flag` and then its negation. The
[correction](#example-2) keeps compatible
checks. Review contradictory validation when an intended entrypoint appears
unusable; inspect the preceding constraints as well as the reported assertion.

Recommendation: preserve guards that reject invalid inputs while allowing the
intended inputs to succeed. Correct contradictory operands or document an
intentionally disabled entrypoint. Checked arithmetic and casts may also explain
an entrypoint-level rejection.

## False positives and limitations

Deliberately disabled entrypoints can match. Ordinary rejecting guards are quiet
if some reaching invocation passes, even if that caller aborts later. Literal
`assert(false)` revert sites are suppressed as assertion findings; nonliteral
constant-false expressions remain reportable. Incomplete or unselected potential
callers block universal assertion claims. A finding concerns modeled invocation
constraints, not cross-transaction reachability or a successful state change.
Unknown effects and exhausted budgets remain incomplete.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/contradictory-assertion.compact`).

```compact
pragma language_version >= 0.26.0;
export circuit verify(flag: Boolean): [] {
  assert(flag, "flag required");
  assert(!flag, "flag forbidden");
}
```

### Example 2

Correction (source: `tests/corpus/safe/contradictory-assertion.compact`).

```compact
pragma language_version >= 0.26.0;
export circuit verify(flag: Boolean): [] {
  assert(flag, "flag required");
  assert(flag, "flag still required");
}
```
