# redundant-boolean-branch

Availability: **default-on**, severity **info**, confidence **high**.

The rule identifies an `if` with explicit `else` whose arms contain only
opposite Boolean literal returns. Disclosure and identity casts of the literals,
and single-statement nested blocks, preserve that shape. Conditions reduced to
source constants and statements after definite rejection stay quiet. Physical
generic claims must agree across every materialized instance.

## Example and scenario

```compact
export circuit belowLimit(limit: Uint<64>): Boolean {
  if (disclose(round < limit)) { return true; } else { return false; }
}
```

This view can express its predicate directly with
`return disclose(round < limit);`. Inverse literal returns suggest the negated
predicate. The condition, its effects and its disclosure boundary still matter.

## Recommendation and limits

Consider a direct predicate return when it improves readability. Intentional
explanatory branches can be retained. The rule describes source structure; it
does not claim a security defect, reduced proof cost or compiler equivalence for
an arbitrary rewrite. Validate a proposed rewrite with the project's compiler.

Any additional branch statement, computed result, equal literal returns,
sequence result or missing explicit `else` is excluded. This does not implement
general Boolean optimization or arithmetic algorithm replacement. It addresses
only the literal-return branch class, without analyzing deployed contracts.

## Evidence and known false positives

Typed controls preserve condition effects/constraints across instruction/reference
engines and cached/uncached
modes. Compiler-valid source examples support the observation; intentional
readability choices are factually matching informational reviews. Work/depth
exhaustion emits rule-scoped `source-observation-budget` and never certifies a
clean result. Source facts do not prove successful execution or natural recall.
