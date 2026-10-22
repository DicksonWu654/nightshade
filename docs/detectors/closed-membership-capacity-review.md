# closed-membership-capacity-review

Availability: **opt-in** with `--detectors closed-membership-capacity-review`;
no policy required. Severity: **info**.

This opt-in informational rule reports a represented constructor configuration
whose current native Set capacity is smaller than the gate's mandatory,
pairwise-distinct memberships. It also requires complete resolved source evidence
that no post-constructor public callable can write that whole Set root.

The source closure includes every public entry, its helpers, import instances and
callbacks. Any insert, remove or other may-write to the root prevents this
conservative certificate, including a writer callback over a zero-length vector.
An unrelated ledger writer does not prevent certification of the target root.
Unresolved callables, external contract calls, committed checkpoints and exhausted
allowances produce scoped incomplete diagnostics. Nested collection receivers
are outside this rule's whole-Set admission boundary.

The existing `configured-membership-capacity-review` remains separate: its
immediate constructor-state observation allows later configuration writers.
The new rule retains its exact capacity, current-revision, immutable operand and
mandatory pairwise-distinctness requirements. Wildcard regions, possible Boolean
alternatives and unknown storage supply no cardinality proof.

A deliberately fixed registry can match when the application intentionally makes
some operations reject for lack of capacity. The finding describes only the
represented constructor state and complete no-writer certificate; it does not
establish deployment impact or later transaction feasibility.
