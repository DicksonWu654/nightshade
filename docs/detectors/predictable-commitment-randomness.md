# predictable-commitment-randomness

Availability: **default**; no policy required. Severity **medium**, confidence
**high** for the stated constant-randomness observation.

Reports a tracked commitment of private-derived input influencing a public sink
when every modeled component of its randomness is constant. This removes the
protection supplied by secret, unpredictable commitment randomness.

## Example and review scenario

The compiler-qualified owned [fixture](#example-1)
publishes a `persistentCommit` using a fixed byte string as randomness. The
[correction](#example-2) supplies a separate
witness value:

```compact
published = persistentCommit<Field>(secret(), randomness());
```

Review how a private value's commitment obtains its randomness, particularly when
the value has a small set of possible inputs. Recommendation: use independently
generated private randomness with entropy appropriate to the primitive and
protocol. Review protocol compatibility before changing intentional deterministic
commitments.

## False positives and limitations

Deterministic protocols can match intentionally. The authenticated pinned
standard-library `tokenType` declaration uses public domain-separated token
derivation and is excluded; user-defined namesakes are still checked. Unknown
witness randomness is not proven unpredictable, independent or sufficiently
entropic. The rule is a constant-only check, not an entropy estimator or a proof
of concrete feasibility or exploitability. Incomplete analysis is not a clean
result.

## Source examples

These short regression examples are included here for installed-package readers.
Rule-specific policy requirements and limits above still apply.

### Example 1

Fixture (source: `tests/corpus/vulnerable/predictable-randomness.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger published: Bytes<32>;
witness secret(): Field;
export circuit publish(): [] {
  published = persistentCommit<Field>(secret(), pad(32, ""));
}
```

### Example 2

Correction (source: `tests/corpus/safe/predictable-randomness.compact`).

```compact
pragma language_version >= 0.26.0;
import CompactStandardLibrary;
export ledger published: Bytes<32>;
witness secret(): Field;
witness randomness(): Bytes<32>;
export circuit publish(): [] {
  published = persistentCommit<Field>(secret(), randomness());
}
```
