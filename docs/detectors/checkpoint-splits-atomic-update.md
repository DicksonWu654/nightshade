# checkpoint-splits-atomic-update

Availability: **opt-in**, with an explicit `atomicUpdates` application policy.
Severity **low**, confidence **high** for the linked write-occurrence observation.

Compact's canonical `kernel.checkpoint()` marks preceding execution as one atomic
unit and allows partial transaction failures across that boundary. This rule
reviews a declared group of ordinary Cell writes split across those units.
The reference establishes checkpoint semantics; it is not an independent bug
label or evidence that a particular application can fail its later segment.

## Example and review scenario

```compact
import CompactStandardLibrary;
export ledger primary: Field;
export ledger mirror: Field;
export circuit synchronize(value: Field): [] {
  primary = disclose(value);
  kernel.checkpoint();
  mirror = disclose(value);
}
```

```json
{
  "version": 1,
  "detectors": ["checkpoint-splits-atomic-update"],
  "policies": {
    "atomicUpdates": [{"circuit": "synchronize", "ledgers": ["primary", "mirror"]}]
  }
}
```

On a completely analyzed full history that writes every selected field, the rule
reports a linked checkpoint prefix which writes a nonempty proper subset.
It also reports mixed final write occurrences: both fields may have been written
before the boundary, while one receives another write afterward. Values can be
equal; the evidence concerns write occurrences, not numerical inequality.

An example can split related ordinary Cell updates around an explicit checkpoint.
The corrected form writes both snapshots before the boundary. A lookalike writes
both before the boundary and writes unrelated padding afterward.

## Recommendation and known intentional uses

Place coupled writes in the same atomic segment. Intentional staged commits are
normal: omit this policy when the application permits them. Review proof
constraints, privacy and transaction ordering before refactoring.

The group must resolve to two through sixteen distinct canonical ordinary Cells
on an exported entry circuit. Native ledger ADTs are outside this policy.
Projected field writes remain explicitly unavailable. An entry that never has a
complete all-field co-update is outside this rule's matching contract; the policy
does not require every entry invocation to write every field.

The observer links each full proof history directly to its own prefixes before
flat outcome deduplication, retaining repeated/helper/callback invocation sites.
Alternative histories remain separate evidence routes; their effects are never
combined to invent a co-update. Later immutable-input proof checks and saved
pre-boundary ledger-read checks retain the existing proof projection. Unprovable
continuations supply no prefix evidence. Namesakes and unreached boundaries do
not count.

Unsupported effects, incomplete baseline entries, unavailable or truncated links,
unsupported observation modes and exhausted shared step/path/value allowances
remain rule-scoped incomplete. The baseline and other rules retain their separate
completion. No symbolic execution, cross-entry invariant proof, actual partial
failure, permanent loss or deployed impact is established.
