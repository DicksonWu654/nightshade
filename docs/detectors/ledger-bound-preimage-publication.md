# ledger-bound-preimage-publication

Availability: **default**; no policy required. Severity **medium**, confidence
**medium**.

Reports the same raw private source reaching a public sink and having a hash
containing that exact source asserted equal to preexisting ledger data on one
modeled successful path. The hash may include constants or public context such
as a ledger sequence; a second private ingredient is outside this contract.
Ledger writes and ledger-operation arguments are public sinks; exported returns
are application outputs and are not necessarily published on the ledger.

## Example and review scenario

The compiler-qualified owned [direct fixture](#example-1)
checks a witness preimage against `ownerHash` and also publishes that preimage.
Review whether this is a reusable authentication secret or an intentional reveal.
The [correction](#example-2) publishes only the digest:

```compact
assert(persistentHash<Field>(secret) == ownerHash, "not authorized");
published = disclose(persistentHash<Field>(secret));
```

Recommendation: keep reusable preimages private and publish an appropriate
non-secret result. For a reveal protocol, confirm that disclosure grants no
remaining authority and document the intended boundary. A digest alone does not
guarantee secrecy for low-entropy input.

## False positives and limitations

Intentional commit/reveal can match. The rule does not prove concrete feasibility,
reusability, intended authentication, or deployed exploitability. Transformed
preimages, hashes with multiple private sources and cryptographic equivalence
are outside the evidence contract. Identity-preserving numeric casts and full-width
Bytes slices retain raw provenance. `disclose` alone is permission, not a sink;
discarded disclosure is quiet. Unknown effects and exhausted budgets remain
incomplete. Fixture labels concern this detector only; see the
[corpus qualification scope](../evaluation.md).

Real-source regression: the recorded bulletin-board mutation publishes a key bound
by `hash([domain, sequence, secret])`. It is now detected; the hash-only correction
and separate-witness lookalike remain quiet. Private-controlled context, transformed
secrets and may-alias source unions do not establish this single-preimage evidence.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Direct fixture (source: `tests/corpus/vulnerable/direct.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger ownerHash: Bytes<32>;
export ledger published: Field;
witness ownerSecret(): Field;
constructor(initialHash: Bytes<32>) {
  ownerHash = disclose(initialHash);
}
export circuit update(): [] {
  const secret = ownerSecret();
  assert(persistentHash<Field>(secret) == ownerHash, "not authorized");
  published = disclose(secret);
}
```

### Example 2

Correction (source: `tests/corpus/safe/hash-only.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger ownerHash: Bytes<32>;
export ledger published: Bytes<32>;
witness ownerSecret(): Field;
constructor(initialHash: Bytes<32>) {
  ownerHash = disclose(initialHash);
}
export circuit update(): [] {
  const secret = ownerSecret();
  assert(persistentHash<Field>(secret) == ownerHash, "not authorized");
  published = disclose(persistentHash<Field>(secret));
}
```
