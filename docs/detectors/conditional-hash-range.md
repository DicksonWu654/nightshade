# conditional-hash-range

Availability: **opt-in compiler compatibility review**, no policy required.
Severity/confidence: **low/high**. Select with
`--detectors conditional-hash-range`.

A conditional unsigned subtraction can feed a fixed-width native hash input while
its underflow assertion is guarded. In the qualified **Compact0.34.0/ZKIR2**
output, a direct `Uint<128>` subtraction feeds `persistentHash<Uint<128>>`'s
16-byte input without selecting safe operands when the source branch is inactive.
The generated JavaScript keeps the computation inside the source branch; this
rule does not describe that JavaScript as executing the inactive hash.

```compact
import CompactStandardLibrary;
export ledger digest: Bytes<32>;
export circuit update(enabled: Boolean, a: Uint<128>, b: Uint<128>): [] {
  if (disclose(enabled)) {
    const difference = (a - b) as Uint<128>;
    digest = disclose(persistentHash<Uint<128>>(difference));
  }
}
```

The finding identifies the subtraction, native hash input and controlling source
branch. It is a static review relationship, **not proof of an invalid input,
proof failure, runtime rejection or deployed vulnerability**. Earlier surviving
unconditional ordering evidence and qualified safe inactive operand selections
are quiet controls. A check inside the same conditional establishes only its
active-case constraint.

Select safe operands using the actual controlling condition before computing the
hash preimage, and preserve intended active validation. Merely guarding the ledger
assignment does not supply an inactive-case hash range invariant. Inspect the
project's generated compiler output before relying on version-specific behavior.
A direct hash of an already constrained `Uint<128>` input is a quiet lookalike.
