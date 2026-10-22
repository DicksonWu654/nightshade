# identity-signature-key

Availability: **default-on**; severity **medium**, confidence **high**.
No application policy is needed. This rule reports only a statically known identity
key on a modeled successful history, not every unconstrained verification key.

## Example and scenario

```compact
assert(jubjubSchnorrVerify<1>(message, signature, default<JubjubPoint>), "signature");
round.increment(1);
```

An identity verification key does not supply the intended signer authentication.
The known-key diagnosis is factual; the analyzer does not construct a signature,
prove exploitability, or infer a deployed application's intended signer.
## Recommendation

Reject the identity key and bind the verification key to the intended trusted
signer. A nonidentity check alone does not establish trusted ownership or complete
key validity. The pinned stable 0.35.0 and 0.35.0-rc.1 standard-library verifiers
reject identity keys internally; profile support is a ZKIR2 subset, and upgrades
need compatibility review.

## Evidence and known false positives

Canonical resolved stdlib calls retain separate key operands on successful
histories. Aliases, helpers, known zero multiplication and caller equality
refinements are supported. Rejected histories and same-named application circuits
are quiet. No new observation is enabled in projects without the canonical verifier.
Observation exhaustion remains explicitly incomplete.
