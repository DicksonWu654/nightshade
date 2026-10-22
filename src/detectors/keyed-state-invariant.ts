import { KEYED_STATE_INVARIANT, keyedStateInvariantObservations } from "../dataflow/keyed-state-invariant.js";
import { finding, unique, type Detector } from "./types.js";

export const inconsistentKeyedStateGuard: Detector = {
  id: KEYED_STATE_INVARIANT,
  description: "Consumer co-membership is checked on only some successful histories of a keyed insert",
  defaultEnabled: false,
  requires: ["collection-observations", "successful-predicates", "successful-histories", "state-writes", "runtime-operations", "completed-entries"],
  run(facts) {
    const result = keyedStateInvariantObservations(facts);
    facts.diagnostics.push(...result.diagnostics);
    facts.metrics.steps += result.work;
    if (facts.keyedStateEvidence) facts.metrics.abstractValues += result.work;
    return unique(result.observations.map(observation => {
      const name = facts.program.symbols.get(observation.entry)?.name ?? observation.entry;
      return finding(facts, {
        detectorId: KEYED_STATE_INVARIANT, severity: "info", confidence: "high",
        title: "Keyed insertion has inconsistent membership checks",
        message: `${name} inserts an exact key with prerequisite membership checked on ${observation.guarded.length} successful histories and bypassed on ${observation.bypassed.length}. A consumer requires both collections to contain the same key on every modeled successful history. Review whether the insertion should preserve that relationship; application invariant intent and exploitability are unproven.`,
        location: observation.insert.location, constraint: observation.guarded[0].guard.predicate.location,
        callPath: observation.insert.callPath.map(id => facts.program.symbols.get(id)?.name ?? id),
        trace: [
          { kind: "constraint", label: "membership required on guarded writer history", location: observation.guarded[0].guard.predicate.location },
          { kind: "effect", label: "keyed insertion also reached without membership requirement", location: observation.insert.location },
          ...observation.consumers.map(consumer => ({ kind: "constraint", label: "consumer requires both memberships for the same key", location: consumer.histories[0].target.predicate.location })),
        ],
        remediation: "Confirm the intended collection relationship. If insertion requires prerequisite membership, enforce it on every successful insertion history; otherwise document why consumers intentionally reject surplus entries.",
        metadata: { reviewRequired: true, invariantIntent: "unknown", exploitability: "unproven", evidence: "consumer-co-membership-and-writer-guard-divergence",
          historyCoverage: "exact-completed-entry-histories", entry: name, entryIdentity: observation.entry,
          prerequisiteAddress: observation.prerequisite, targetAddress: observation.target,
          guardedHistories: observation.guarded.map(({ path, guard }) => ({ branches: path.path, key: guard.key, revision: guard.query.result.collectionPredicate?.revision, guard: guard.predicate.location })),
          bypassedHistories: observation.bypassed.map(path => ({ branches: path.path })),
          consumerEntries: observation.consumers.map(consumer => consumer.entry),
          consumerEvidence: observation.consumers.map(consumer => ({ entry: consumer.entry, histories: consumer.histories.map(history => ({ key: history.target.key, prerequisite: history.prerequisite.predicate.location, target: history.target.predicate.location })) })) },
      }, `${observation.entry}:${observation.prerequisite}:${observation.target}`);
    }));
  },
};
