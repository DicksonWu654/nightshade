import type { AnalysisFacts } from "../dataflow/index.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { CONDITIONAL_HASH_RANGE_RULE, conditionalHashRanges, type ConditionalHashRangeObservation } from "../semantic/conditional-hash-range.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

/** A source/compiler review relationship; no proof or runtime code is executed. */
export function conditionalHashRangeFindings(facts: AnalysisFacts, allowance = 20000): Finding[] {
  const observed = conditionalHashRanges(facts.program, allowance);
  if (!observed.complete) {
    // A partial source walk cannot establish absence for unvisited entries.
    ruleObservationIssue(facts, CONDITIONAL_HASH_RANGE_RULE, "conditional-hash-range-unavailable",
      `${observed.reason}; conditional hash range review has no complete result for this root`);
    return [];
  }
  const groups = new Map<string, ConditionalHashRangeObservation[]>();
  for (const observation of observed.observations) {
    const key = `${observation.caller}:${spanId(observation.hash)}:${spanId(observation.subtraction)}`;
    const group = groups.get(key) ?? [];
    group.push(observation); groups.set(key, group);
  }
  return [...groups].map(([key, observations]) => {
    const first = observations[0];
    const branches = [...new Map(observations.flatMap(item => item.branches)
      .map(branch => [`${spanId(branch.location)}:${branch.truth}`, branch])).values()];
    const uses = [...new Map(observations.map(item => [spanId(item.sourceUse.location), item.sourceUse])).values()];
    return finding(facts, {
      detectorId: CONDITIONAL_HASH_RANGE_RULE, severity: "low", confidence: "high",
      title: "Conditional subtraction reaches a fixed-width native hash input",
      message: "A conditional Uint<128> subtraction reaches a canonical persistentHash input without a qualified inactive-case range invariant. In the reviewed Compact 0.34.0/ZKIR2 shape, the underflow assertion is guarded while the raw subtraction feeds the hash's 16-byte slot. This source relationship does not establish emitted-slot retention, an invalid input, proof failure, runtime rejection or deployed impact. Review earlier invariants and safe inactive operand selection.",
      location: first.hash,
      trace: [
        { kind: "call", label: "Canonical Uint128 persistent hash input", location: first.hash },
        { kind: "call", label: "Unsigned subtraction source", location: first.subtraction },
        ...branches.map(branch => ({ kind: "call" as const, label: `Source branch (${branch.truth ? "then" : "else"})`, location: branch.location })),
        ...uses.map(use => ({ kind: "call" as const, label: `Source use: ${use.kind}`, location: use.location })),
      ],
      callPath: [],
      remediation: "Select safe inactive operands using the actual controlling condition before computing the hash preimage, while preserving intended active validation. Inspect the project's generated compiler output and earlier unconditional invariants; guarding only the ledger assignment does not establish an inactive hash range.",
      metadata: {
        evidence: "conditional-uint-subtraction-native-hash-range", reviewRequired: true,
        scope: "source-scalar-range-review", compilerVersion: "0.34.0", zkirVersion: 2,
        caller: first.caller, entries: [...new Set(observations.map(item => item.entry))],
        inputType: first.inputType, uintBits: first.uintBits, slotBytes: first.slotBytes,
        subtraction: first.subtraction, branches, sourceUses: uses,
        emittedSlotRetention: "not-proven", proofFailure: "not-proven", runtimeRejection: "not-proven", deployedImpact: "not-proven",
      },
    }, key);
  });
}

export const conditionalHashRange: Detector = {
  id: CONDITIONAL_HASH_RANGE_RULE,
  description: "Conditional Uint128 subtraction reaches a fixed-width native persistent-hash input without a qualified inactive-case range invariant (Compact 0.34.0/ZKIR2 review)",
  defaultEnabled: false,
  requires: ["resolved-source-references", "resolved-types", "canonical-native-calls"],
  run: facts => conditionalHashRangeFindings(facts),
};
