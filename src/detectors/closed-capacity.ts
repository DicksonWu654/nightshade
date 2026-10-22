import { configuredCapacityConflicts } from "../dataflow/configured-capacity.js";
import { CLOSED_CAPACITY_RULE } from "../semantic/closed-capacity.js";
import { spanId } from "../model.js";
import { finding, type Detector, type Finding } from "./types.js";

export const closedMembershipCapacityReview: Detector = {
  id: CLOSED_CAPACITY_RULE, defaultEnabled: false,
  description: "A represented constructor history contradicts distinct Set memberships under a complete source closure without subsequent writers",
  requires: ["constructor-to-entry-prefixes", "exact-collection-capacity", "complete-post-constructor-effects"],
  run(facts) {
    if (!facts.configuredCapacity || !facts.closedCapacity) return [];
    const result = configuredCapacityConflicts(facts, true); facts.diagnostics.push(...result.diagnostics);
    if (result.diagnostics.length) return [];
    const findings: Finding[] = [], seen = new Set<string>();
    for (const conflict of result.conflicts) {
      const retained = 24 + 8 * conflict.members.length + 4 * conflict.distinctness.length + 4 * conflict.prefix.construction.path.length;
      if (facts.metrics.steps + retained > facts.configuredCapacity.maxSteps || facts.metrics.abstractValues + retained > facts.configuredCapacity.maxValues) {
        facts.diagnostics.push({ code: "closed-capacity-emission-budget", message: "Closed capacity finding retention exhausted the shared allowance",
          location: conflict.prefix.location, scope: { kind: "rule", detectorId: CLOSED_CAPACITY_RULE, entry: facts.configuredCapacity.entry } });
        return [];
      }
      facts.metrics.steps += retained; facts.metrics.abstractValues += retained;
      const key = `${conflict.address}:${conflict.bound}:${conflict.members.map(member => spanId(member.predicate.location)).sort().join(";")}`;
      if (seen.has(key)) continue; seen.add(key);
      findings.push(finding(facts, {
        detectorId: CLOSED_CAPACITY_RULE, severity: "info", confidence: "high",
        title: "Closed configured Set cannot satisfy distinct memberships",
        message: `A represented constructor history bounds this Set to at most ${conflict.bound} members, while this gate prefix requires ${conflict.members.length} pairwise-distinct current members. The complete resolved post-constructor source closure contains no writer to this Set root. This is a contradiction for that represented configuration; other configurations, concrete invocation feasibility and runtime storage immutability are not established.`,
        location: conflict.members.at(-1)!.predicate.location, constraint: conflict.members[0].predicate.location, callPath: [],
        trace: [{ kind: "call", label: "represented constructor boundary", location: facts.program.functions.get(facts.configuredCapacity.constructor)!.declaration.span },
          ...conflict.members.map(member => ({ kind: "constraint" as const, label: "required current Set member", location: member.predicate.location })),
          ...conflict.distinctness.map(predicate => ({ kind: "constraint" as const, label: "required pairwise distinctness", location: predicate.location }))],
        remediation: "Align every intended constructor configuration with the gate's distinct-member requirement, or provide an explicit source configuration transition.",
        metadata: { reviewRequired: true, stateBoundary: "source-closed-constructor-history", closure: "complete-resolved-post-constructor-callables", noPostConstructorWriter: true,
          entryIdentity: facts.configuredCapacity.entry, constructorIdentity: facts.configuredCapacity.constructor,
          address: conflict.address, revision: conflict.revision, upperBound: conflict.bound, requiredDistinct: conflict.members.length,
          constructorBranches: conflict.prefix.construction.path, feasibility: "unproven", runtimeImmutability: "unproven", allConfigurations: "unproven" },
      }, key));
    }
    return findings;
  },
};
