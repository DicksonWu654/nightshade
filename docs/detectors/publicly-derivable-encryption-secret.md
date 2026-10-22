# publicly-derivable-encryption-secret

Availability: default-on, **high severity / high confidence in the structural
relationship**. Select with `--detectors publicly-derivable-encryption-secret`.

## Description

A public digest can also determine the scalar used for a registered curve point.
If the application treats that point as an encryption key, review whether its
scalar was intended to remain private. The finding proves the modeled derivation
relationship; it does not establish encryption use or application intent.

## Example

An owned synthetic derivation:

```compact
pure circuit makePoint(seed: Bytes<32>): JubjubPoint {
  const digest = persistentHash<Vector<1, Bytes<32>>>([seed]);
  return ecMulGenerator(degradeToTransient(digest));
}
export circuit register(): [] {
  const seed = keyMaterial();
  accountId = disclose(persistentHash<Vector<1, Bytes<32>>>([seed]));
  registeredPoint = disclose(makePoint(seed));
}
```

The published digest supplies the same `degradeToTransient` input used in the
point derivation. Separating hash domains or using independent secret material
breaks this exact relationship.

## Scenario and evidence

The rule checks canonical resolved native calls, typed operands and straight-line
helper bodies, including immutable local aliases. Provider names, source notices,
commits and file fingerprints confer no role. The supported boundary is compiler
0.31.1, language 0.23.0 and ZKIR2 with its Field-based curve APIs. Different native profiles, unavailable
recipe proofs and exhausted applicability budgets produce rule-scoped incomplete
coverage when reached.

A finding also requires the same exact immutable raw witness operand, a public
`persistentHash<Vector<1, Bytes<32>>>` digest in an on-chain sink, an observed
successful derivation invocation, and its exact result as the last whole-root
`JubjubPoint` ledger write on one complete modeled outcome. Invocation arguments
and results are recorded separately. Provenance sets, declaration names, flow
strings and wildcard storage addresses never prove equality.

Last-write checking rejects overwritten registrations. Committed checkpoint
prefixes are separate outcomes. An impossible entire proof supplies no successful
prefix. The optional observations retain the baseline engine and original budgets;
missing invocation/digest evidence is explicitly incomplete.

## Recommendation

Separate public-identifier and private-key hash domains, or use independent
secret material. Confirm whether the registered point is a cryptographic key
before treating the structural finding as a vulnerability.

## Known false positives and limits

An intentionally public scalar or a curve point used for another purpose can
match. Encryption/ciphertext use, intended secrecy and exploitability are not
proven. Conditional/loop derivation bodies, arbitrary curve arithmetic, transformed
seeds, Map/struct registrations and cross-entry key lifecycles are outside this
proof boundary. Unknown reached recipe bodies are incomplete, not certified safe.
Independent witness invocations, different hash types/domains, discarded points,
exported-return-only digests and known constant-point derivations are quiet.

## Validation

Owned compiler-valid positive, domain-separated and independent-secret controls
exercise instruction/reference and cached/uncached evidence. Tests retain nested
and repeated calls, caller guards, state invalidation, checkpoint prefixes, exact
typed hash distinctions and explicit resource failures. These checks do not
establish independent application recall.
