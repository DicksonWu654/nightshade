import { zeroMembershipObservations, ZERO_MAP_RULE } from "../analysis/zero-membership.js";
import { spanId } from "../model.js";
import { finding, type Detector } from "./types.js";

export const zeroAmountInitialMembership: Detector = {
  id: ZERO_MAP_RULE,
  description: "Under a declared zero-amount policy, every modeled successful invocation requires the same Map entry to have been present initially",
  policyRequired: true, defaultEnabled: false,
  requires: ["declared-zero-entry", "exact-map-preconditions", "all-successful-predicates", "ordered-writes"],
  run(facts, policies) {
    const result = zeroMembershipObservations(facts, policies);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(({ policy, requirement, histories, zeroSuccesses }) => {
      const circuit = facts.program.symbols.get(policy.circuit)!, amount = facts.program.symbols.get(policy.amount)!, map = facts.program.symbols.get(policy.map)!;
      return finding(facts, {
        detectorId: ZERO_MAP_RULE, severity: "low", confidence: "high",
        title: "Zero-amount success requires initial Map membership",
        message: `With entry input ${amount.name} fixed to zero, every modeled full successful invocation of ${circuit.name} requires the same exact ${map.name} entry to have been present initially. The explicit policy declares that zero operations should not require this membership. This proves a static dependency, not that the entry is missing in deployment or a runtime failure. Helper inputs retain their actual values.`,
        location: requirement.location, source: amount.span, constraint: requirement.location,
        trace: [{ kind: "source", label: `declared entry input ${amount.name} = 0`, location: amount.span },
          { kind: "constraint", label: `required initial ${map.name} membership`, location: requirement.location }],
        callPath: requirement.callPath.map(id => facts.program.symbols.get(id)!.name),
        remediation: "If the declared zero semantics are intended, bypass the balance/allowance lookup and its membership assertions at zero, or explicitly supply the needed entry before lookup. Document intentional rejection instead of enabling this policy.",
        metadata: { reviewRequired: true, evidence: "all-full-zero-successes-initial-membership", entry: circuit.name, entryIdentity: policy.circuit,
          amount: amount.name, amountIdentity: policy.amount, declaredAmount: "0", map: map.name, mapIdentity: policy.map,
          region: requirement.region, keyIdentity: requirement.key, zeroSuccesses, historyEvidence: histories,
          helperAmountZero: "not-claimed", initiallyMissing: "not-proven", runtimeFailure: "not-proven", pathFeasibility: "not-proven" },
      }, JSON.stringify([policy, requirement.region.path, requirement.key, spanId(requirement.location)]));
    });
  },
};
