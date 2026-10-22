# checked-digest-narrowing

Availability: **opt-in**. Severity **informational**, confidence **high** for the
resolved source relationship. Select with `--detectors checked-digest-narrowing`.

Compact converts `Bytes<m>` to `Uint` by decoding the entire byte vector as a
little-endian integer and checking the target range. It does not truncate the
value to the target width. A cast of a full hash to `Uint<64>` therefore checks
all 32 bytes against `2^64 - 1`.

## Example, scenario and recommendation

```compact
const digest = persistentHash<Uint<64>>(value);
const narrowed = digest as Uint<64>;
recordedDigest = disclose(narrowed as Bytes<32>);
```

If the application meant to store a full digest identifier, retain `digest`.
If a numeric projection is intended, define the exact byte selection or other
protocol-approved projection before converting it. Preserve deliberate checked
conversions. Altering an existing stored representation requires protocol and
migration review.

## Matching and known intentional cases

The rule follows a canonical `persistentHash` or `keccak256` `Bytes<32>` result
through immutable local identity aliases, disclosure and identity casts. It
reports a cast to a supported `Uint` type when the result, optionally re-encoded
as Bytes, has a direct ordinary Cell assignment or scalar exported return in
that resolved function. Custom exclusive Uint bounds retain their actual maximum.
Findings group source uses per cast and canonical function instance.

This is an entry-referenced source relationship, including syntactic dead branches
and zero-iteration bodies. It does not prove successful execution, a failing input,
every-path rejection, hash-output distribution, funds loss or deployed impact.
Proof-of-work targets and intentional partial checked conversions can match;
these intent-dependent shapes keep the rule opt-in. An explicit equality/bound
elsewhere does not change the reported conversion semantics.

Already bounded numeric encodings, selected/reconstructed/transformed digests,
Field casts, arithmetic uses, aggregate returns, ADT/projected writes, outer
captures and arbitrary helper-result forwarding are outside the matching scope.
Canonical imported aliases and instantiated source modules are distinguished
from application namesakes. A shared private/hash provenance is insufficient
to establish an unchanged digest.

## Evidence and incomplete results

Reference: Compact 0.34.0 source `1f671fc27818df2b2676b3a97f85b2b821756243`,
`doc/compact-reference.mdx:3296–3304` and canonical hash API definitions. The owned
Counter positive emits `convertBytesToUint(18446744073709551615n, 32, digest, …)`
and preserves the original Counter increment. Corrected/full-digest and
lookalike/bounded-encoding controls remain quiet. Compiler-only output inspection
does not execute a runtime or proof and is not an independent bug label.

The owned triplet compiles and retains the expected conversion shape on pinned
0.30.0, 0.31.1, 0.33.0-rc.2, 0.34.0 and 0.35.0. The reported maximum is the
declared source-type maximum. Compiler 0.30.0 emits a Number maximum literal
and an older byte-encoding helper; later profiles emit BigInt. These compile-only
checks do not qualify runtime cutoff equivalence across compiler/runtime versions.

The source query charges traversal, depth, alias copies and entry copies. On
exhaustion it discards partial observations and emits a rule-scoped incomplete
diagnostic. Baseline analysis coverage remains separate; incomplete results are
never clean. No scan budgets or engine transfers are changed by this rule.
