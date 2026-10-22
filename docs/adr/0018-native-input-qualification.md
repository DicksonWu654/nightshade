# ADR 0018: Validate native input shapes after call resolution

Status: implemented and locally qualified for compiler 0.34.0 / language 0.26.0.

## Evidence and boundary

For compiler 0.34.0 / language 0.26.0, default ZKIR2, native signatures alone do not
describe every input restriction. At compiler source revision
`b3a90d9524e784a0fe8eb711072b1ab1bfb7cbad`, `midnight-natives.ss` declares generic
hash/commitment inputs. `analysis-passes/infer-types.ss`, `contains-js-opaque?` and
`do-call`, additionally reject JavaScript Opaque-containing first arguments for
persistent hashing/commitments and keccak after selecting a compatible native.
These restrictions do not apply to transient hashing/commitments or user circuits
merely named like a native operation.

The structural walk follows represented types: tuple/vector elements, actual
struct fields and nominal representations. It does not treat a phantom generic
argument as a runtime field. Zero-length vectors and inactive Maybe/Either fields
still participate in static type checks. Native validation must run for map/fold
even when no abstract iteration executes, and must not cause fallback to an outer
otherwise-compatible function after native selection.

Release-compiler checks exposed an important qualification distinction: native
import aliases do not uniformly receive the same source-level exclusion. One
compiler-accepted alias case is retained as an explicit analyzer coverage gap,
not relabeled as a compiler rejection or executed as a runtime experiment. We
do not infer full runtime/cryptographic support from that compiler acceptance.

## Decision

Declare the qualified non-Opaque input requirement in the owned intrinsic
catalogue. Validate ordinary and higher-order calls through one shared check after
canonical target selection and argument compatibility. Traverse only represented
fields, tuple/vector elements and nominal underlying types, with a visited set.
Do not change overload compatibility or treat these checks as detector rules.

Use `unsupported-opaque-intrinsic` for every reached excluded native input. The
diagnostic describes an analysis-model boundary, not a universal assertion of
compiler invalidity. Canonical target identity makes this boundary independent of
import spelling while leaving ordinary user functions unaffected. No Opaque native
path should be reported complete merely because its general arity/subtyping checks
pass. Normal transient and non-Opaque transfer semantics remain unchanged.

## Qualification

`tests/intrinsic-legality.test.ts` has 29 cases: ten complete compiler-valid
applications, 18 compiler rejections and one compiler-valid unsupported alias case.
Accepted cases compare cached/uncached facts, instruction/reference semantic paths,
failed assertions, completion and detector observations. Rejected cases require the
compiler's specific Opaque-input diagnostic when the compiler is supplied; ordinary
errors/timeouts cannot masquerade as matching rejections. An imported Unicode case
checks original byte offsets and UTF-16 columns.

A separate feature root composes transient Opaque hashing with persistent hashing
of a phantom-generic struct. Packed consumers check the explicit native-input
diagnostic through the isolated API. These are language/model conformance tests,
not new vulnerability labels, cryptographic proofs or independent security review.
The existing 29 corpus files and labels remain unchanged.

Full Linux suites pass 1,160 tests on Node 24.15.0 and 22.23.3 with the pinned
compiler, source checkout and official SARIF inputs; no failures or skips. The
59 corpus/feature roots compile. Packed CLI/API/TypeScript consumers and all six
benchmark harnesses are requalified; artifact identities and corpus lineage are
verified separately. The host-local effect gate passes against the preserved
sequence/pattern baseline, not a claim of controlled-runner performance.

Broader native constraints, collection failure/ordering, coin/tree/Kernel models,
other compiler profiles and independent review remain separate work. This bounded
change does not establish a complete primitive or runtime model.
