# shielded-coin-runtime-width

Availability: **opt-in reference-runtime compatibility review**, no policy required.
Severity/confidence: **low/high**. Select with
`--detectors shielded-coin-runtime-width`.

A canonical native `createZswapOutput` receives a definite integer coin value of
at least 18,446,744,073,709,551,616 on a modeled successful history. Compact 0.34.0
declares `ShieldedCoinInfo.value` as `Uint<128>`, while the pinned runtime 0.19.0
descriptor encodes eight bytes, with maximum 18,446,744,073,709,551,615. The finding
expressly assumes that reference runtime. The analyzer does not discover or verify
the project's installed or deployed runtime.

```compact
import CompactStandardLibrary;
export circuit output(): [] {
  const coin = ShieldedCoinInfo {
    nonce: pad(32, "nonce"), color: pad(32, "color"),
    value: 18446744073709551616 as Uint<128>
  };
  createZswapOutput(coin,
    left<ZswapCoinPublicKey, ContractAddress>(
      ZswapCoinPublicKey { bytes: pad(32, "recipient") }));
}
```

Review runtime compatibility and constrain emitted values to its supported range,
or use a separately qualified compatible runtime. This static diagnosis does not
prove funding, proof feasibility, runtime rejection, asset loss or a deployed bug.
An exact source match can be irrelevant to a project using a different runtime;
this is a known benign match when the actual runtime supports a wider descriptor.
Verify the project's runtime version before acting; this version-dependent
applicability keeps the rule opt-in.

The first supported profile is **Compact 0.34.0/ZKIR2 with expressly assumed
runtime 0.19.0**. Relevant entries under other compiler/ZKIR profiles produce
rule-scoped `runtime-width-profile-unavailable` diagnostics; structurally unrelated
entries remain not applicable. Baseline-incomplete entries are withheld explicitly.
JSON, SARIF and the human report distinguish baseline and selected-rule coverage.
The experimental Counter-predicate scan has no certificate for this rule; missing
exact quantity observations remain explicitly incomplete in that mode.

The isolated quantity observation pass preserves exact native operands and
immutable storage snapshots, with all successful predicates and equivalent-state
histories. Legal aggregate widening may retain a narrower unsigned operand domain;
it is accepted only when contained in Uint128, with integer constants checked
against that retained domain. It disables numeric fold compression and retains the ordinary
40,000-step/256-path/50,000-value limits. Canonical source-site traversal and
operand review are bounded; unavailable evidence yields incomplete diagnostics,
with no partial findings for the affected entry. Independent completed entries
remain available. Alternative paths at one output site are grouped with their
amounts and invocation sites.

Unknown quantities, inferred bounds, merely returned coin structs, arbitrary user
namesakes, proof generation and runtime evaluation remain outside this contract.
Quiet unknown quantities are not a general runtime-compatibility guarantee.
False-positive pattern: a project using a runtime whose descriptor accepts a
wider quantity may still match the documented reference-runtime boundary; verify
the actual runtime version before acting.
