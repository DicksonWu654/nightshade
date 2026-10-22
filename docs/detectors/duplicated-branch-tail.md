# duplicated-branch-tail

Availability: **default-on**; no policy required.
Severity **info**, confidence **high** for the resolved source observation.
Use `--min-severity low` to hide informational findings.

Reports one to seven expression statements and an explicit return copied between
the end of a terminating branch and its immediate following continuation. Both
copies must resolve to the same symbols, operations, types and expression tree.
This is source duplication across alternative routes, not duplicate execution.

## Example and review scenario

For example:

```compact
if (disclose(flag)) {
  round.increment(1);
  return [];
}
round.increment(1);
return [];
```

Each route increments once. Consider sharing the tail after any branch-specific
work. The finding is a source-quality observation, not an authorization or
monetary defect.

## False positives and limitations

Authors may deliberately keep alternative routes visually independent. Identical
resolved source is the fact reported; removal or hoisting is a review decision.
Preserve return behavior, proof constraints, disclosure and transaction ordering.
No optimized compiler/prover cost reduction is claimed.

Resolved circuit bodies in the compilation unit are examined, including imported
instances and calls in source-excluded code. Unresolved unused library APIs are
outside this observation; this is not a whole-library analysis. Unknown conditions retain
both alternatives; source-constant excluded branches and unreachable suffixes
are quiet. Bindings, callbacks, nested control inside the copied tail, implicit
returns, longer tails and merely value-equivalent expressions are outside the
contract. Same-name references that resolve differently stay quiet. Exhausted
source traversal produces explicit rule-scoped incomplete diagnostics for every
entry. Baseline transfer completion and unrelated rules remain independently
reported. With no entry row, exhaustion retains an explicit root diagnostic.
