import type { AnalysisFacts, RuntimeOperation, SuccessfulPredicate } from "../dataflow/index.js";
import { CURRENT_ROOT_RULE, enforcedMerkleChecks, merkleFreshAtEnforcement } from "../dataflow/merkle-freshness.js";
import { type Diagnostic, type Span, spanId } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";
import { parseType } from "../semantic/types.js";

type Policy = NonNullable<ResolvedPolicies["currentRootMembership"]>[number];
export interface CurrentRootObservation {
  policy: Policy; queries: RuntimeOperation[]; guard: SuccessfulPredicate;
  reason: "query-not-current-only" | "overlapping-write-before-enforcement";
  overlappingWrites: Span[];
}

/** Explicit guard-time contract, not effect-time freshness or stale feasibility.
 * Completed histories only; a failed observation withholds this policy's claims. */
export function currentRootObservations(facts: AnalysisFacts, policies?: ResolvedPolicies) {
  const observations: CurrentRootObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0, values = 0;
  const limits = facts.currentRootEvidence;
  const charge = (steps = 1, retained = 0): boolean => {
    work += steps; values += retained;
    return !!limits && facts.metrics.steps + work <= limits.maxSteps && facts.metrics.abstractValues + values <= limits.maxValues;
  };
  class Unavailable extends Error {}
  const unavailable = (message: string): never => { throw new Unavailable(message); };
  for (const policy of policies?.currentRootMembership ?? []) {
    // Rule passes are entry-isolated and retain the same resolved policy set.
    if (limits && limits.entry !== policy.circuit) continue;
    const found = new Map<string, CurrentRootObservation>();
    try {
      if (!charge() || !limits || !facts.completedEntries.includes(policy.circuit) || !facts.merkleEvidence || facts.predicateScope !== "all" || facts.pathSemantics !== "equivalent-states" || facts.diagnostics.length)
        unavailable("Complete uncompressed current-root guard observations are unavailable");
      const paths = facts.paths.filter(path => { if (!charge()) unavailable("Current-root evidence exhausted its work allowance"); return path.entry === policy.circuit; });
      if (!paths.length) unavailable("No modeled successful invocation; current-root policy has no complete guard evidence");
      for (const path of paths) {
        // In certified exact facts, absent arrays mean zero observations. This
        // normalization is unavailable to callers lacking the evidence marker.
        const checks = enforcedMerkleChecks({ ...path, operations: path.operations ?? [], predicates: path.predicates ?? [] }, policy.ledger, charge);
        if (!checks) unavailable("Current-root Boolean relation, history or evidence budget is unavailable");
        for (const check of checks!) {
          const outcomes = check.queries.map(query => {
            if (!charge()) unavailable("Current-root evidence exhausted its work allowance");
            const kind = parseType(facts.program.representationOf(query.operation.args[0].region!.type)).name;
            if (!["MerkleTree", "HistoricMerkleTree"].includes(kind)) unavailable("Selected check lacks canonical native tree identity");
            const freshness = merkleFreshAtEnforcement(path, query, check.predicate, charge);
            if (!freshness.complete) unavailable("Query/enforcement positions are unavailable, including checkpoint-projected histories or exhausted evidence");
            // Native current trees are exclusive even for wildcard receivers,
            // which intentionally have no revision-qualified merklePredicate.
            const exclusive = kind === "MerkleTree" || query.operation.result.merklePredicate?.exclusive === true;
            return { query, freshness, reason: !exclusive ? "query-not-current-only" as const
              : freshness.overlaps.length ? "overlapping-write-before-enforcement" as const : undefined };
          });
          // Equivalent immutable identities may be queried repeatedly. A mix
          // of conflicting certificates cannot identify the saved occurrence.
          if (new Set(outcomes.map(outcome => outcome.reason)).size > 1)
            unavailable("Repeated query identity has ambiguous freshness certificates");
          const outcome = outcomes[0];
          if (!outcome.reason) continue;
          if (!charge(outcomes.length, outcomes.length)) unavailable("Current-root evidence exhausted its value allowance");
          const overlapping = new Map<string, Span>();
          for (const candidate of outcomes) for (const index of candidate.freshness.overlaps) {
            if (!charge(1, 1)) unavailable("Current-root evidence exhausted its write allowance");
            overlapping.set(spanId(path.writes[index].location), path.writes[index].location);
          }
          const observation: CurrentRootObservation = { policy, queries: outcomes.map(candidate => candidate.query.operation),
            guard: check.predicate, reason: outcome.reason, overlappingWrites: [...overlapping.values()] };
          if (!charge(0, 1)) unavailable("Current-root evidence exhausted its value allowance");
          found.set(JSON.stringify([policy, observation.queries.map(query => spanId(query.location)), spanId(observation.guard.location), observation.reason]), observation);
        }
      }
      observations.push(...found.values());
    } catch (error) {
      if (!(error instanceof Unavailable)) throw error;
      diagnostics.push({ code: "current-root-policy-unavailable", message: error.message,
        location: facts.program.functions.get(policy.circuit)!.declaration.span,
        scope: { kind: "rule", detectorId: CURRENT_ROOT_RULE, entry: policy.circuit } });
    }
  }
  facts.metrics.steps += work; facts.metrics.abstractValues += values;
  return { observations, diagnostics };
}
