# discarded-comparison

Availability: **default-on**, severity **low**, confidence **high**. Select it
alone with `--detectors discarded-comparison`.

The rule reports a resolved comparison (`==`, `!=`, `<`, `<=`, `>`, `>=`) whose
Boolean outcome is discarded, unless typed scalar source folding resolves the
outcome to a constant. It covers expression statements, unused local bindings
and unused immutable identity aliases. Disclosure and identity casts preserve
this relationship. A sequence discards each prefix result and retains only its
tail; prefixes are checked even inside a returned or otherwise consumed sequence.
Only entry-reachable root-source circuits are linted. Source-dead branches,
empty numeric for ranges and components after a definite rejection are excluded.

## Example and scenario

```compact
export circuit increment(limit: Uint<64>): [] {
  Ownable_assertOnlyOwner();
  count < limit; // evaluates the check but discards its Boolean result
  count.increment(1);
}
```

The owner check still enforces authorization. The comparison does not enforce
the intended limit through this use. Replace it with
`assert(count < limit, "limit reached")`, or consume the outcome in the intended
control flow. A Boolean view that returns the comparison is an intentional API
and stays quiet.

## Recommendation and limits

This is a source-use fact. Operand evaluation, proof constraints and side effects
remain; other guards may enforce the same condition. No feasible failure,
absence of authorization or deployed vulnerability is claimed. Any non-alias
reference conservatively retains a binding, including captures, control flow,
computed predicates, aggregates and assignments. One used alias retains an
entire fan-out. General computed-result liveness, arbitrary predicate helper
forwarding and imported-body linting are outside this rule. Source reachability
is structural through the resolved source call graph: a callback used only by a
zero-length map/fold can still be linted. This does not establish callback
execution or successful execution. Constant folding covers typed scalar source
constants, not every tautology or symbolic relationship.

## Evidence and known false positives
