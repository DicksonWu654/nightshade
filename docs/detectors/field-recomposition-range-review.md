# Field recomposition range review

Availability: default. Severity: info. Confidence: high.

`field-recomposition-range-review` reports an informational source observation. It reviews an enforced Field equality
(including negated comparisons) whose owned numeric expression is a shallow
`quotient * constant + remainder`, allowing commuted operands. The constant must
be a power of two greater than one. Both scalar operands must preserve an exact
raw entry-parameter or witness source identity, have no ledger dependencies, and
be distinct after successful scalar equality normalization. Names do not establish
quotient/remainder intent. Native results, ledger reads and derived operands are
outside this first shape.

The rule uses existing numeric observation machinery and reconstructs integer
constraints separately for each completed successful history. Equality aliases,
checked numeric casts, retained integer domains, orderings and exclusions can
constrain the exact operand envelopes. It reports when their mathematical
multiply-plus-add upper endpoint reaches the Field modulus. Histories at the same
entry, equality site and matched side share a stable finding with separate retained
envelopes; bounds from sibling histories are never combined.

The report establishes only a retained envelope fact. It does not establish joint
operand feasibility, integer decomposition intent, ambiguity, an invalid execution,
proof failure or deployed impact. Relation matching is shallow: expanded Boolean
formulas, recursive algebra and alternate decompositions
are outside scope. Successful equality against the modular result is not an integer
range certificate. Missing exact evidence, unfinished requested entries,
contradictory constraint reconstruction and allowance exhaustion produce rule-scoped
incomplete diagnostics and no partial finding set.

The rule distinguishes a bounded quotient from a wider value that can wrap during
recomposition. Compiler acceptance is checked separately; no proof or runtime
execution is used. Intentional modular arithmetic can satisfy the same source
shape. Review whether integer reconstruction is intended before changing a bound;
the envelope is not proof the operands jointly reach it or a concrete execution
wraps.
