# operation-intent-policy

Availability: **opt-in**, **explicit policy required**. Severity: **info**.
Confidence: **high** for a represented application-policy mismatch; deployment
impact and globally feasible execution are unproved.

Configuration version 1 accepts this additive optional policy. Report version
1.6.0 retains its existing findings/metadata and rule-coverage shape; this rule
adds no serialized top-level report fields or custom-facts capability.

Select `operation-intent-policy` and declare `policies.operationIntent`. Each
policy selects an exported circuit, ordinary scalar protected Cells, a
`Bytes<32>` registered-controller commitment Cell, an unsigned nonce Cell,
natural numeric operation/version strings, exact signed statement field names,
and exact input bindings. Canonical `kernel.self()` is mandatory. Operation tags
must be distinct for entries sharing controller and nonce. Selectors resolve to
unique canonical symbols; a parameter selector resolves inside its entry.

```json
{
  "operationIntent": [{
    "circuit": "updateDocument",
    "ledgers": ["document"],
    "controllerCommitment": "controllerCommitment",
    "nonce": "authorizationNonce",
    "operation": "1",
    "version": "1",
    "statement": {
      "self": "selfAddress", "operation": "operation",
      "version": "version", "nonce": "nonce"
    },
    "inputs": [{"field": "input", "parameter": "next", "writeValue": "document"}]
  }, {
    "circuit": "revokeDocument",
    "ledgers": ["document"],
    "controllerCommitment": "controllerCommitment",
    "nonce": "authorizationNonce",
    "operation": "2",
    "version": "1",
    "statement": {
      "self": "selfAddress", "operation": "operation",
      "version": "version", "nonce": "nonce"
    },
    "inputs": [{"field": "input", "ledger": "document"}]
  }]
}
```

`parameter` inputs require `writeValue` or explicit `context: true`. `writeValue`
selects the protected Cell whose actual written scalar must equal that signed field
and the declared entry parameter. `context: true` requires exact signing of the
parameter without claiming that it is the protected written value.
Required scalar equalities before the write can connect aliases. `ledger` inputs
select immutable initial-entry snapshots and express signed state context; they
do not stand in for a dynamic write operand. An unsigned dynamic protected value
without a declared write binding is a mismatch. Constants and exact Field
self-subtraction have no independent dynamic write value. Ledger/local snapshots,
shared source provenance and wildcard regions never donate must-equality.

For each complete original successful effect history, one enforced canonical
`secp256k1EcdsaVerify` result must cover the whole declared tuple before the write.
Its actual `keccak256` input must have the declared fields. The exact verifier
point must supply both canonical coordinates of the `persistentHash<Vector<2,
Secp256k1Base>>` enforced equal to the preexisting registered commitment. Distinct
witness calls do not imply equal keys. Signed tuple requirements cannot combine
across separate signatures or exclusive histories. Mandatory scalar Boolean
relays preserve equality/inequality parity and negation, including independently
supplied outcomes: `v != relay` with `!relay` enforces the exact `v` as true,
while the opposite relay truth enforces false. A separate bounded parity pass
tracks these truth requirements without treating complement as scalar equality.
Unanchored relays do not enforce true. Aggregate Boolean comparison projection,
lost Boolean structure and conflicting parity evidence are scoped incomplete.
Later checks remain outside the earlier effect's authorization prefix.
Configured domain storage
alone does not replace canonical self; version and current nonce are independent
requirements. Native verifier semantics remain the compiler-profile model, not
cryptographic protocol verification.

Each successful selected operation with protected effects must have exactly one
nonce write after all protected effects, with retained exact operands proving
`currentNonce + 1` and a value-preserving unsigned result. Earlier nonce/controller
writes, resets, repeated consumption, and controller enrollment in a selected
mutation are mismatches. All exported callable closures are checked for other
successful protected/controller/nonce writers; undeclared writers yield a scoped
incomplete diagnostic. Constructors are the explicit enrollment/initialization
boundary; trust in enrollment remains external. This rule does not establish
nonce exhaustion behavior, trusted configuration, serialization injectivity or
signature protocol security. Checked compiler arithmetic determines the modeled
successful increment semantics.

Preparation, interpretation, scalar closure, proof and retained evidence share
40,000 steps per entry, 256 paths and 50,000 cumulative abstract-value allocation
units for the rule pass. These are the ordinary production limits, not extra
proof budgets. Exact digest input and numeric operand evidence are opt-in and
shared by both interpreter engines and cached/uncached transfers. The ordinary
scan retains no operation-intent carrier, canonical-self marker or extra numeric
operand metadata. Opaque statements/keys, lost identities, unsupported aliases,
unresolved closures, baseline-incomplete entries, checkpoints requiring atomic
linkage and exhausted budgets yield rule-scoped incomplete diagnostics.

A false positive can reflect a stale, overbroad, or incorrect policy rather than a
contract defect. Confirm that the declaration, signed fields, input bindings, and
nonce expectations describe the application's intended protocol before acting on
the finding. The rule checks conformance to configured policy; it does not infer
that policy's correctness or prove signature security.
