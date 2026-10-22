import { CONFIGURED_CAPACITY_RULE, configuredCapacityConflicts } from "../dataflow/configured-capacity.js";
import { finding, unique, type Detector } from "./types.js";
import { spanId } from "../model.js";
export const configuredMembershipCapacityReview: Detector = {
  id: CONFIGURED_CAPACITY_RULE, defaultEnabled: false,
  description: "Immediate post-constructor collection capacity contradicts required distinct memberships",
  requires: ["constructor-to-entry-prefixes", "exact-collection-capacity", "successful-predicates"],
  run(facts) {
    // Registry consumers can dispatch all rules on ordinary facts. Only the
    // independent observer supplies this optional constructor boundary.
    if (!facts.configuredCapacity) return [];
    const result = configuredCapacityConflicts(facts); facts.diagnostics.push(...result.diagnostics);
    return unique(result.conflicts.map(conflict => finding(facts, {
      detectorId: CONFIGURED_CAPACITY_RULE, severity: "info", confidence: "high",
      title: "Immediate configured state cannot satisfy distinct memberships",
      message: `Immediately after this modeled constructor history, the current collection contains at most ${conflict.bound} members, while the reached gate prefix requires ${conflict.members.length} pairwise-distinct members. Those requirements are inconsistent for this represented state. Later configuration changes, concrete invocation feasibility and cryptographic validity remain unproven; this does not establish permanent unusability.`,
      location: conflict.members.at(-1)!.predicate.location, constraint: conflict.members[0].predicate.location, callPath: [],
      trace: [{ kind: "call", label: "represented constructor boundary", location: facts.program.functions.get(facts.configuredCapacity!.constructor)!.declaration.span },
        ...conflict.members.map(member => ({ kind: "constraint", label: "required current member", location: member.predicate.location })),
        ...conflict.distinctness.map(predicate => ({ kind: "constraint", label: "required signer/key distinctness", location: predicate.location }))],
      remediation: "Align the accepted initial configuration with the gate's distinct-member requirement, or explicitly provide the required members before exposing that operation. Review staged configuration separately.",
      metadata: { reviewRequired: true, stateBoundary: "immediate-post-constructor", feasibility: "unproven", cryptographicValidity: "unproven", permanentUnusability: "unproven",
        entry: facts.program.symbols.get(facts.configuredCapacity!.entry)!.name, entryIdentity: facts.configuredCapacity!.entry,
        constructorIdentity: facts.configuredCapacity!.constructor, address: conflict.address, revision: conflict.revision, upperBound: conflict.bound, requiredDistinct: conflict.members.length,
        construction: { entry: conflict.prefix.construction.entry, branches: conflict.prefix.construction.path,
          writes: conflict.prefix.construction.writes.map(write => ({ ledger: write.ledger, region: write.region, location: write.location, callIdentities: write.callPath, callSites: write.callSites })),
          predicates: conflict.prefix.construction.predicates?.map(predicate => ({ truth: predicate.truth, location: predicate.location, callIdentities: predicate.callPath, callSites: predicate.callSites })) }, gateBranches: conflict.prefix.gate.path,
        members: conflict.members.map(member => ({ key: member.key, query: member.query.location, guard: member.predicate.location, callIdentities: member.predicate.callPath, callSites: member.predicate.callSites })),
        distinctness: conflict.distinctness.map(predicate => ({ location: predicate.location, callIdentities: predicate.callPath, callSites: predicate.callSites })) },
    }, `${facts.configuredCapacity!.entry}:${conflict.address}:${conflict.bound}:${conflict.members.map(member => spanId(member.predicate.location)).sort().join(";")}:${conflict.distinctness.map(predicate => spanId(predicate.location)).sort().join(";")}`)));
  },
};
