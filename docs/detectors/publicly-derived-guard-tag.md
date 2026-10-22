# publicly-derived-guard-tag

Availability: **opt-in**, no policy required. Severity/confidence: **medium/high**.
Select with `--detectors publicly-derived-guard-tag`.

The rule reports a raw supplied tag required equal to an exact native hash recipe
containing definite preexisting public ledger data, with remaining ingredients
limited to constants, unchanged caller-supplied parameter leaves and recursively
supported native hashes. The comparison must precede a ledger or kernel effect
on every modeled successful reach of that exact effect invocation. Findings group
the guard site and entry, listing affected effects and separate history evidence.

```compact
export ledger attestorKey: Bytes<32>;
export ledger accepted: Counter;
export circuit accept(message: Bytes<32>, tag: Bytes<32>): [] {
  assert(tag == persistentHash<Vector<2, Bytes<32>>>([attestorKey, message]), "tag");
  accepted.increment(1);
}
```

If this tag is intended to authenticate an attestor, hashing its public key and
the supplied message does not verify a signature or secret possession. Use the
protocol's reviewed verifier bound to the trusted signer and intended message.
Other proofs can still provide authorization; this rule never establishes a
sole gate, authentication intent, concrete feasibility or deployed vulnerability.
**Caller-supplied does not mean public:** an entry parameter can remain private,
and only its supplier is assumed to know it. A private witness ingredient or
witness-dependent recipe/control excludes the match, including nested hashes.

Intentional checksums and prototype mock attestations are known review shapes.
They are why this rule is opt-in. A correct static match is not a confirmed
authentication defect; source intent and other protocol proofs require review.

Supported hashes are canonical `persistentHash`, `transientHash` and `keccak256`.
Tag operands are unchanged scalar `Bytes<32>` or `Field` sources. Constants must
have no private provenance: an assertion-refined witness is not a public literal.
Exact preexisting ledger provenance is required; may-ledger dependencies, fresh
caller-written keys, wildcard equality and a namesake hash do not suffice.
An immutable old ledger snapshot can remain an ingredient after a later write.
Optional/bypassed, ignored, negative, after-effect, return-only and constructor
comparisons stay quiet. Arithmetic-derived parameter recipes and general custom
crypto are outside this boundary.

Entry-isolated exact observations retain all predicates and typed digest inputs
under the existing 40,000-step/256-path/50,000-value limits. Values share the
rule's pass allowance. Entries whose baseline semantics are incomplete remain
explicitly unavailable for this rule, without an expensive duplicate attempt;
this restriction is not a completion or absence certificate. Consumer
recipe/intersection work is bounded to 200,000
checks per invocation; recursive recipe/Boolean traversal is limited to depth64
and immutable keys to 4,096 nodes/depth32. Missing predicate/invocation evidence,
unsupported exact observations and exhaustion produce rule/entry-scoped incomplete
diagnostics and discard that entry's partial findings. Baseline coverage and other
rules' findings remain independent. No engine admission or budget is expanded.

The family is grounded in Compact's witness/claimed-input trust boundary and
documented public-data mock attestations; no execution or exploit reproduction
is needed. Tests preserve instruction/reference and cached/uncached agreement,
nested summary replay, guard alternatives, storage snapshots and checkpoint prefixes.
