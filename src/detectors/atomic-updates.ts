import { atomicUpdateObservations, ATOMIC_UPDATE_RULE } from "../analysis/atomic-updates.js";
import { finding, type Detector } from "./types.js";

export const checkpointSplitsAtomicUpdate: Detector = {
  id: ATOMIC_UPDATE_RULE, description: "A checkpoint splits a declared ordinary Cell co-update across atomic units",
  policyRequired: true, defaultEnabled: false,
  requires: ["declared-atomic-update-group", "complete-checkpoint-linkage", "ordered-cell-writes"],
  run(facts, policies) {
    const result = atomicUpdateObservations(facts, policies);
    facts.diagnostics.push(...result.diagnostics);
    return result.observations.map(item => {
      const entry = facts.program.symbols.get(item.policy.circuit)!;
      const names = (roots: string[]) => roots.map(root => facts.program.symbols.get(root)!.name);
      return finding(facts, {
        detectorId: ATOMIC_UPDATE_RULE, severity: "low", confidence: "high",
        title: "Checkpoint splits a declared Cell co-update",
        message: `The atomicUpdates policy for ${entry.name} declares writes to ${names(item.policy.ledgers).join(", ")} to commit together. ${item.reason === "partial-group-prefix"
          ? `This checkpoint's linked prefix contains writes to ${names(item.committed).join(", ")} and none to ${names(item.pending).join(", ")}, while the full history writes every selected field.`
          : `This checkpoint's linked prefix contains the full history's final writes to ${names(item.committed).join(", ")}, while ${names(item.pending).join(", ")} receive their final writes later.`} This is a static write-occurrence policy mismatch; transaction failure, unequal values and deployed impact are unproved.`,
        location: item.location, callPath: item.callPath.map(id => facts.program.symbols.get(id)!.name),
        trace: [{ kind: "constraint", label: "canonical kernel checkpoint boundary", location: item.location },
          ...item.writes.map(write => ({ kind: "effect" as const, label: `${item.committed.includes(write.ledger) ? "committed" : "pending"} write: ${facts.program.symbols.get(write.ledger)!.name}`, location: write.location }))],
        remediation: "Place coupled final writes in the same atomic segment. Retain intentional staged commits by omitting or revising this application policy; review proof constraints and transaction effects before refactoring.",
        metadata: { evidence: "linked-full-history-partial-cell-co-update", reviewRequired: true, reason: item.reason,
          entry: entry.name, entryIdentity: item.policy.circuit, ledgerIdentities: item.policy.ledgers,
          committedWrites: item.committed, pendingWrites: item.pending,
          invocationSites: item.invocations.map(route => ({ ordinal: route.ordinal, callSites: route.callSites,
            predicates: route.predicates,
            writes: route.writes.map(write => ({ ledger: write.ledger, location: write.location, callSites: write.callSites, guards: write.guards })) })),
          historyGrouping: "alternative-linked-histories",
          valueInvariant: "not-proven", partialFailure: "not-proven", deployedImpact: "not-proven" },
      }, JSON.stringify([item.policy, item.reason, item.committed, item.pending]));
    });
  },
};
