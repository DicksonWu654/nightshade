import type { AnalysisFacts } from "../dataflow/index.js";
import { ruleObservationIssue } from "../analysis/rule-diagnostics.js";
import { GENERIC_WITNESS_ABI_RULE, genericWitnessAbi, type WitnessAbiConflict } from "../semantic/generic-witness-abi.js";
import { finding, type Detector, type Finding } from "./types.js";

/** A source/schema compatibility fact; no witness implementation is executed. */
export function genericWitnessAbiFindings(facts: AnalysisFacts, allowance = 20000): Finding[] {
  const observed = genericWitnessAbi(facts.program, allowance);
  if (!observed.complete) {
    // The obligation spans the selected root's schema. A partial enumeration
    // cannot certify unvisited entries or retain an earlier conflict as complete.
    ruleObservationIssue(facts, GENERIC_WITNESS_ABI_RULE, "generic-witness-abi-unavailable",
      `${observed.reason}; shared generic witness ABI review has no complete result for this root`);
    return [];
  }
  const groups = new Map<string, WitnessAbiConflict[]>();
  for (const conflict of observed.conflicts) {
    const group = groups.get(conflict.template) ?? [];
    group.push(conflict); groups.set(conflict.template, group);
  }
  return [...groups].map(([template, conflicts]) => {
    const symbol = facts.program.symbols.get(template)!;
    const specializations = [...new Map(conflicts.flatMap(conflict => conflict.specializations)
      .map(specialization => [specialization.symbol, specialization])).values()];
    const entries = [...new Set(conflicts.flatMap(conflict => conflict.entries))];
    const sites = specializations.flatMap(specialization => specialization.sites);
    return finding(facts, {
      detectorId: GENERIC_WITNESS_ABI_RULE, severity: "low", confidence: "high",
      title: "Generic optional witness has incompatible required payload guards",
      message: `The generic witness ${symbol.name} has source-reachable Maybe specializations with identical parameter types and disjoint bigint/byte-array payload guards. Under Compact 0.34.0/ZKIR2, they share a host dispatch method without a generic type argument, and the value payload is checked even when is_some is false. A single fixed absence payload cannot satisfy both guards. The host handler may distinguish arguments, private state or call order; actual handler failure and deployed impact are unproved.`,
      location: symbol.span,
      trace: sites.map(site => ({ kind: "call", label: `Source ${site.kind} reference to ${facts.program.symbols.get(site.target)!.name}`, location: site.location })),
      callPath: [],
      remediation: "Use distinct host witness names for incompatible result representations, or review how the shared handler selects the correct typed payload, including absent results. Check the generated witness signatures for the project's compiler before relying on type-independent absence handling; different module instances alone do not establish distinct host dispatch.",
      metadata: {
        evidence: "shared-generic-witness-mandatory-maybe-payload-guards",
        reviewRequired: true, scope: "entry-reachable-source-schema", compilerVersion: "0.34.0", zkirVersion: 2,
        template, witness: symbol.name, entries,
        specializations,
        conflictingPairs: conflicts.map(conflict => conflict.specializations.map(specialization => specialization.symbol)),
        referenceKind: "source-schema-not-successful-invocation", hostFailure: "not-proven", deployedImpact: "not-proven",
      },
    }, template);
  });
}

export const genericWitnessMaybeAbi: Detector = {
  id: GENERIC_WITNESS_ABI_RULE,
  description: "Shared generic optional witness dispatch has incompatible mandatory bigint/byte-array payload guards (Compact 0.34.0/ZKIR2 compatibility review)",
  defaultEnabled: false,
  requires: ["resolved-source-references", "canonical-generic-specializations", "resolved-types"],
  run: facts => genericWitnessAbiFindings(facts),
};
