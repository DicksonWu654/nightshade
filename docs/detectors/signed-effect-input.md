# signed-effect-input

Availability: **opt-in**; low severity, medium confidence. No policy required.

Opt-in, low severity intent review. On an original modeled successful exported
circuit history, a canonical `jubjubSchnorrVerify` Boolean result is explicitly
enforced before an ordinary scalar ledger assignment. The assigned value has a
caller parameter or witness source absent from the signed message's represented
dependencies. The exact finding is **effect input not among signed message
dependencies**. A known benign pattern is an unsigned effect input constrained by
a separate trusted guard or intentionally left outside the signed statement.
This is neither a sole authorization claim nor an exploitability claim.

The owned rule uses exact canonical signature observations, all successful
predicates, immutable write snapshots, and mandatory Boolean equality closure.
Transparent aliases and transitive Boolean equalities are supported; common source
provenance never establishes value equality. A returned `false` alone does not
abort a history or enforce an unused signature. Later aborts remove the history.
A namesake verifier and an unrelated repeated signature cannot supply enforcement
for another observed result. Aggregate dependency leaves retain their individual
source identities.

Scalar-state scope excludes constructors, nested/aggregate storage, Counter and
collection effects and network/fork/preimage binding claims.
Signatures enforced only after a write are outside this conservative initial
ordering scope. This does not require every effect input to be signed. No key trust
or message protocol interpretation is inferred. A signed message containing the
chosen effect input suppresses this source observation; a constant-only effect
supplies no independent source to report.

Integration: register `signedEffectInput` from
`src/detectors/signed-effect-input.ts` with `defaultEnabled: false`. Select canonical
signature observation (`signatureEvidence` / `observeSignatures`), retain
`predicateScope: "all"`, and use `pathSemantics: "equivalent-states"`. Configure the
ordinary interpreter with fold partitions and hash choices disabled to retain
original histories. The rule has a one-million-unit allowance, and equality
decoding has the shared bounded allowance/depth. Missing evidence or exhausted
work produces rule-scoped incomplete diagnostics through the caller. Baseline
transfer incompleteness prevents findings for the affected entry.

Owned tests use harmless Field assignments and compiler `--skip-zk` acceptance;
no contract execution or proof generation is needed. Tests compare instruction
and expression engines with summaries enabled and disabled.

The same opt-in rule also reviews the input nonce at canonical `sendShielded`
(including the inner call of `sendImmediateShielded`). It retains the full input
argument before the send body and uses only mandatory predicates preceding that
operation boundary. A check after the send cannot donate authorization or operand
binding. Canonical Schnorr and ZKIR3 ECDSA verifications are recognized separately;
missing verifier/send observation markers or ordering boundaries remain incomplete.
Sibling coin fields and repeated calls retain distinct leaf identities. Exact
digest inputs and scalar equality closure allow a separately supplied input nonce
constrained to signed data to stay quiet.

The exact review is **input coin nonce absent from signed message dependencies**.
Coin nonce is not claimed to be a complete coin identity. Dependence is not a
proof of injective serialization, trusted key, signature quorum, sole authorization
or replay resistance. The owned typed ECDSA approval seed covers operation, self
address, approval nonce and amount, then demonstrates the independent input nonce
omission as a static source pattern. Its correction includes the full coin in the
digest. It is not an executable reproduction of the historical approval protocol.
Network/fork, preimage-only and issuer-descriptor findings remain separate misses.
