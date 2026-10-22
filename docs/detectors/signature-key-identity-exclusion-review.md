# signature-key-identity-exclusion-review

Availability: **opt-in**, informational severity, high confidence in the reported
source relationship. No policy required.

Review an unknown caller key or an unknown whole persistent Cell snapshot passed
to the canonical native Jubjub Schnorr or secp256k1 ECDSA verifier. A finding says
that a complete original modeled successful history contains no modeled mandatory
caller or internal check excluding the identity of the exact immutable key on its
own curve. Message-only checks retain the key obligation. An application namesake
verifier is outside scope.

This does not establish that the key is identity, that an identity input could
satisfy the other checks, that enrollment is unsafe, or that a signature is
mandatory. Curve membership, subgroup validity, sole authorization, concrete
feasibility and application impact remain unproved. Trusted initialization or
application policy can make the observation intentional. A check in a separate
enrollment transaction cannot validate an unknown later storage snapshot without
a complete storage invariant.

The observer captures caller-refined arguments in evaluation order before the
callee adds constraints, then retains the invocation only on its successful
history. Imported aliases, ordinary helpers, callbacks and summary replay use the
ordinary transfer engine. Empty callback sequences retain zero-iteration behavior.
Exact key inequalities, mandatory equalities and native identity-to-identity
`ecMul`/`ecNeg` observations are joined only within that history. An enforced
nonidentity cofactor result excludes identity of that exact Jubjub input; it proves
no curve or subgroup property. Native generator nonidentity is evidence about its
output only. Coordinate checks or derived verifier points cannot validate an input
key by inversion. Guards on another key, a different Cell revision or a mutually
exclusive history cannot discharge the obligation.

The supported exact profiles are Compact 0.34.0/ZKIR2 for Schnorr and
0.34.0/ZKIR3 for both families, plus 0.35.0 and 0.35.0-rc.1/ZKIR2 Schnorr. The latter
source-pinned verifiers reject identity internally and are quiet. ZKIR3 is currently
qualified only for 0.34.0; this rule supplies no guessed 0.35 ECDSA model. Unsupported
profiles, relevant opaque predicates, lost provenance, unknown collection or struct
projections, transformed verification operands, checkpoints, external composition,
unfinished histories and exhausted allowances produce incomplete diagnostics.
Known point constants are outside this unknown-key review. The default
`identity-signature-key`, Jubjub enrollment and signed-input rules keep their
existing contracts and observation cost.

Preparation, observation, retained metadata, immutable keys, typed predicate
closure and finding emission share the unchanged **40000 steps per entry,
256 paths per entry, 50000 cumulative abstract values per rule**. There is no
separate proof allowance or retry. Experimental Counter-query mode lacks this
exact observation contract and reports unavailable evidence when selected.

From a built source checkout, select this rule with
`node dist/src/cli.js scan examples/review/contract.compact --detectors signature-key-identity-exclusion-review --zkir-version 3`.
Inspect its CLI metadata with
`node dist/src/cli.js detector show signature-key-identity-exclusion-review --json`.
