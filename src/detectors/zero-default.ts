import { zeroDefaultObservations } from "../dataflow/zero-default.js";
import { ZERO_DEFAULT_RULE } from "../semantic/zero-default-targets.js";
import { finding, unique, type Detector } from "./types.js";

export const zeroDefaultGetterMembershipReview: Detector = {
  id: ZERO_DEFAULT_RULE, defaultEnabled: false,
  description: "Review explicit absent-to-zero getter evidence alongside an all-zero-success initial-membership Map decrement",
  requires: ["exact-cross-entry-getter", "source-key-pattern-binding", "all-full-zero-successes", "ordered-initial-membership", "numeric-map-decrement"],
  run(facts) {
    const result = zeroDefaultObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    return unique(result.observations.map(observation => {
      const getter = facts.program.symbols.get(observation.getter.entry)!;
      const entry = facts.program.symbols.get(observation.entry)!;
      const amount = facts.program.symbols.get(observation.amount)!;
      const map = facts.program.symbols.get(observation.getter.pattern.root)!;
      return finding(facts, {
        detectorId: ZERO_DEFAULT_RULE, severity: "info", confidence: "high",
        title: "Review absent-to-zero getter and zero debit membership difference",
        message: `${getter.name} explicitly returns numeric zero on modeled absence of every prefix of this canonical ${map.name} key family. With the actual decrement input ${amount.name} fixed to zero, every modeled full successful invocation of ${entry.name} decrements the corresponding exact numeric Map lookup and requires that entry initially. Review this source behavior difference; intended application semantics are not inferred.`,
        location: observation.location, source: observation.getter.location, constraint: observation.location,
        trace: [{ kind: "source", label: "explicit absence-to-zero getter", location: observation.getter.location },
          ...observation.getter.absences.map(location => ({ kind: "constraint", label: "getter missing-key branch returns zero", location })),
          { kind: "source", label: `${amount.name} = 0`, location: amount.span },
          { kind: "constraint", label: "initial same-entry membership required", location: observation.location },
          { kind: "sink", label: "exact numeric Map decrement", location: observation.write.location }],
        callPath: observation.lookup.callPath.map(id => facts.program.symbols.get(id)!.name),
        remediation: "Review whether the getter and spender should share missing-entry behavior at zero. If intended, bypass the membership-dependent decrement at zero or explicitly handle absence; document intentional rejection otherwise.",
        metadata: { reviewRequired: true, evidence: "explicit-zero-getter-and-all-zero-success-initial-membership",
          getter: getter.name, getterIdentity: getter.id, entry: entry.name, entryIdentity: entry.id,
          amount: amount.name, amountIdentity: amount.id, map: map.name, mapIdentity: map.id,
          keyPattern: observation.getter.pattern.parts,
          sourceKeyBinding: observation.getter.pattern.parameters.map((parameter, index) => ({ getterParameter: parameter, spenderParameter: observation.parameters[index] })),
          getterHistories: observation.getter.histories, zeroSuccesses: observation.zeroSuccesses,
          initialRequirements: observation.initialRequirements, initiallyMissing: "not-proven", runtimeFailure: "not-proven",
          applicationPolicy: "not-inferred", crossInvocationEquality: "not-claimed", pathFeasibility: "not-proven" },
      }, JSON.stringify([getter.id, entry.id, amount.id, observation.getter.pattern.signature]));
    }));
  },
};
