# ignored-validation-result

Availability: **default-on**; select only this rule with `--detectors ignored-validation-result`; severity
**medium**, confidence **high**. Explicit selection replaces the default detector set.

The rule reports a canonical `CompactStandardLibrary.jubjubSchnorrVerify` call
whose Boolean outcome is directly discarded, or assigned to a local whose
identity aliases have no non-alias source use. Unused fan-out and alias chains
report at the original verifier expression (`unused-alias-chain` metadata).
Imported callable aliases retain canonical identity;
same-named application circuits are quiet. A resolved transparent helper chain whose only statement returns this verifier outcome is also recognized, including imported/generic helpers and explicit disclosure/identity casts of that result. The finding stays at the discarding caller; metadata lists the forwarding circuits. Helpers that enforce the result internally, add setup/statements or compute another Boolean are excluded. Only entry-reachable root-source
circuits are linted, excluding source-dead branches, empty static loops and
statements after a literal-false rejection or unconditional return.

## Example and scenario

```compact
export circuit signedIncrement(msg: Vector<1, Field>, sig: JubjubSchnorrSignature, pk: JubjubPoint): [] {
  jubjubSchnorrVerify<1>(msg, sig, pk); // outcome is discarded
  round.increment(1);
}
```

A signed operation may appear to verify its authorization but succeed without
requiring the verifier's outcome. Assert the returned Boolean or reject its false
branch before the transaction succeeds. Rejection after a write also enforces the
check: Compact transaction effects are atomic.

## Recommendation and limits

The finding is a source fact about discarding the outcome, not a proof of absent
authentication or feasible unauthorized execution. Internal verifier constraints
remain, including the RC nonidentity-key assertion. A reference through a simple
local alias, disclosure or identity cast follows the alias's uses. Any other
reference conservatively preserves the result, including assignments, captures,
checker returns, Boolean control, aggregates and computed expressions. A single
used alias preserves the result across fan-out. Complex unused computations, nontransparent application
forwarders, imported helper body linting, custom verifiers and general non-assert uses
are outside this rule. No general validation-enforcement claim is made.

## Evidence and known false positives
