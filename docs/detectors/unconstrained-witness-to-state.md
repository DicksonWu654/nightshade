# unconstrained-witness-to-state

Availability: **opt-in review**, medium severity, low confidence for application risk.

## Description, example and scenario

```compact
const value = rewardAmount(); // witness
allocation = disclose(value);
```

A raw witness leaf reaches surviving ledger state on a modeled successful history
without a circuit assertion using that exact leaf. Disclosure permits publication,
it does not validate the value. If a reward allocation must match an independently
established fact, this is a useful review point. The SDK seed removes an owned
required reward assertion; it is not an upstream vulnerability.

## Recommendation

Assert the intended application relationship using the actual written witness
value, and review the adequacy of that relationship independently. An unrelated
caller guard, a check on another return leaf/call, and a witness Boolean attesting
about the value do not validate that value in the circuit. Document deliberately
prover-chosen metadata, registration and other public input policies.

## Evidence, limitations and known false positives

Exact instruction/reference histories and cached/uncached transfers preserve
witness invocation/leaf identity. Required assertion dependencies are projected
through Boolean alternatives; a branch choice alone is not an assertion.
Self-comparisons/private echoes supply no check. Later atomic assertions count;
later definite overwrites, constructors, rejected histories, parameter-only data,
transformed/hash values and explicit casts are outside this narrow review.
Wildcards cannot establish definite overwrites. Findings group a witness site
within an entry and list affected writes and invocations.

An assertion dependency is not proof that a relation meaningfully restricts the
value, that authentication is sound or that an invariant holds. Custom constraints,
implicit conversions, control-only influence and transfer-only uses are outside
scope. Public registration and prover-chosen application metadata are known
intent-dependent shapes: the rule remains opt-in. Exhausted or missing exact
observations/projections produce rule/entry-scoped incomplete diagnostics; baseline
analysis and independent-entry findings remain available.
