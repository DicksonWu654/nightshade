# generic-witness-maybe-abi

Availability: **opt-in ABI compatibility review**, no policy required.
Severity/confidence: **low/high**. Select with
`--detectors generic-witness-maybe-abi`.

Under Compact **0.34.0/ZKIR2**, concrete specializations of one generic witness
dispatch to the same host method without a generic type argument. When its result
is the canonical standard-library `Maybe<T>`, the generated wrapper checks
`value` even when `is_some` is false. A bigint payload and a byte-array payload
cannot use one fixed absent-result placeholder. This rule reports the static
signature relationship, with the declaration, conflicting return types and
source reference sites grouped into one finding per canonical witness template.

```compact
import CompactStandardLibrary;
witness lookup<T>(key: Bytes<4>): Maybe<T>;
export circuit getNumber(key: Bytes<4>): Maybe<Uint<64>> {
  return disclose(lookup<Uint<64>>(key));
}
export circuit getBytes(key: Bytes<4>): Maybe<Bytes<32>> {
  return disclose(lookup<Bytes<32>>(key));
}
```

A shared host handler may distinguish keys, private state, call order or other
context and return the correct typed payload. **This is not evidence that the
handler fails.** Review absent-result handling and the generated witness
signatures. Use distinct host witness names when incompatible result
representations should have independent handlers. `Uint<64>` and `Field` are a
quiet lookalike because their ordinary payload guards both accept `0n`.

The rule requires identical concrete parameter types and known disjoint
bigint/byte-array result representations. Resolved import/type aliases retain
identity; separate concrete module instances and different witness declarations
are kept separate. It describes the entry-reachable source/schema graph, including
constant-dead references and zero-iteration callbacks whose wrappers the qualified
compiler retains. It does not assert a successful invocation or proof feasibility.

The compiler-only distinct-module probe also emits one shared host method spelling.
This initial rule groups only one canonical template: a quiet distinct-instance
control is a scope negative, not evidence of separate dispatch or ABI safety.
