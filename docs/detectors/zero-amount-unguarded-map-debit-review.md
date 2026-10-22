# zero-amount-unguarded-map-debit-review

Availability: **opt-in**, no policy required. Severity: **info**. Confidence:
**high** for the supported static source relationship.

Select with `--detectors zero-amount-unguarded-map-debit-review`. The observer
selects actual debit operands from an ordinary successful invocation, then fixes
an unchanged numeric entry parameter to zero. Literal-zero APIs use ordinary
histories. It reports a numeric Map lookup whose exact immutable result is the
minuend of that subtraction and is written to the same exact entry, without an
intervening overlapping mutation, when membership was unknown before the lookup.
Each lookup retains its own occurrence identity and helper arguments retain
their actual values. One complete qualifying history suffices.

Same-entry guards and exact prior insertions are quiet. Parent-only or different
key membership does not establish the selected inner entry. A later guard does
not establish membership before an earlier lookup. Positive-only APIs,
addition, unrelated amounts, transformed debit parameters, different write
keys and intervening may-alias writes do not qualify. An earlier successful
same-entry lookup can establish membership, making a later debit read quiet.

Unknown membership is not missing membership. The rule does not establish
intended zero semantics, initial absence, runtime lookup failure, transaction
feasibility or impact. Initial storage remains unknown; cross-invocation
application invariants are not inferred. Intentional zero APIs can match.

The dedicated observer retains explicit empty operation sequences. Missing
lookup origins, operands, ordered writes or invocation evidence, reached
checkpoints and exhausted budgets produce diagnostics. Ordinary analysis and
the existing zero-membership policy remain unchanged.

Incomplete and rejected inputs provide no absence guarantee.
