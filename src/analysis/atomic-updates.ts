import type { AnalysisFacts, StateWrite, SuccessfulPath } from "../dataflow/index.js";
import type { Diagnostic, Span } from "../model.js";
import { spanId } from "../model.js";
import type { ResolvedPolicies } from "../policies.js";

export const ATOMIC_UPDATE_RULE = "checkpoint-splits-atomic-update";
type Policy = NonNullable<ResolvedPolicies["atomicUpdates"]>[number];
export interface AtomicUpdateObservation {
  policy: Policy;
  location: Span;
  callPath: string[];
  invocations: { ordinal: number; callSites: Span[]; writes: StateWrite[];
    predicates: { location: Span; truth: boolean; callSites: Span[] }[] }[];
  committed: string[];
  pending: string[];
  reason: "partial-group-prefix" | "mixed-final-write-prefix";
  writes: StateWrite[];
}

/** Final write-occurrence co-commit policy, not final-value invariant analysis.
 * A full result and each prefix are linked by the interpreter, never by matching
 * source text, trace labels, or effects across mutually exclusive histories. */
export function atomicUpdateObservations(facts: AnalysisFacts, policies?: ResolvedPolicies) {
  const observations: AtomicUpdateObservation[] = [], diagnostics: Diagnostic[] = [];
  const limits = facts.checkpointEvidence;
  let work = 0, retained = 0;
  const charge = (steps = 1, values = 0): boolean => {
    work += steps; retained += values;
    return !!limits && facts.metrics.steps + work <= limits.maxSteps
      && facts.metrics.abstractValues + retained <= limits.maxValues;
  };
  class Unavailable extends Error {}
  const unavailable = (message: string): never => { throw new Unavailable(message); };
  for (const policy of policies?.atomicUpdates ?? []) {
    if (limits && limits.entry !== policy.circuit) continue;
    const found = new Map<string, AtomicUpdateObservation>();
    const routeKeys = new Map<string, Set<string>>();
    try {
      if (!charge() || !limits || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all"
        || !facts.completedEntries.includes(policy.circuit) || facts.diagnostics.length)
        unavailable("Complete exact checkpoint linkage is unavailable for this entry");
      let fullCount = 0;
      for (const path of facts.paths) {
        if (!charge()) unavailable("Atomic update linkage coverage exhausted its allowance");
        if (path.entry === policy.circuit && path.checkpointOutcomes) {
          fullCount++;
          if (path.checkpointCount !== path.checkpointOutcomes.length)
            unavailable("Reached checkpoint linkage is truncated or unavailable");
          for (const [ordinal, boundary] of path.checkpointOutcomes.entries()) {
            if (!charge()) unavailable("Checkpoint ordinal coverage exhausted its allowance");
            if (boundary.ordinal !== ordinal) unavailable("Checkpoint ordinal correspondence is unavailable");
          }
        }
      }
      if (fullCount !== limits!.fullHistories) unavailable("Full-history checkpoint linkage coverage is incomplete");
      const roots = new Set(policy.ledgers);
      const finalWrites = (path: SuccessfulPath): Map<string, StateWrite> => {
        const result = new Map<string, StateWrite>();
        for (const write of path.writes) {
          if (!charge()) unavailable("Atomic update write comparison exhausted its shared allowance");
          if (!roots.has(write.ledger)) continue;
          if (write.region.length) unavailable("Projected Cell writes cannot certify whole-field co-updates");
          result.set(write.ledger, write);
        }
        return result;
      };
      for (const full of facts.paths) {
        if (!charge()) unavailable("Atomic update history traversal exhausted its shared allowance");
        if (full.entry !== policy.circuit || !full.checkpointOutcomes) continue; // Flat prefix outcomes are not full results.
        const final = finalWrites(full);
        // This policy reviews complete co-updates, not every entry's write API.
        if (final.size !== roots.size) continue;
        for (const boundary of full.checkpointOutcomes) {
          if (!charge(1 + boundary.callSites.length, 1)) unavailable("Atomic update checkpoint traversal exhausted its shared allowance");
          const prefix = boundary.history;
          if (prefix.entry !== full.entry || prefix.checkpointOutcomes || prefix.writes.length > full.writes.length
            || prefix.writes.some((write, index) => { if (!charge()) unavailable("Atomic update correspondence exhausted its allowance"); return write !== full.writes[index]; }))
            unavailable("Checkpoint/full-history correspondence is unavailable");
          const atBoundary = finalWrites(prefix), committed: string[] = [], pending: string[] = [];
          for (const root of policy.ledgers) {
            if (!charge()) unavailable("Atomic update field comparison exhausted its shared allowance");
            (atBoundary.get(root) === final.get(root) ? committed : pending).push(root);
          }
          const reason = atBoundary.size > 0 && atBoundary.size < roots.size ? "partial-group-prefix" as const
            : committed.length && pending.length ? "mixed-final-write-prefix" as const : undefined;
          if (!reason) continue;
          if (reason === "partial-group-prefix") {
            committed.splice(0, committed.length, ...policy.ledgers.filter(root => atBoundary.has(root)));
            pending.splice(0, pending.length, ...policy.ledgers.filter(root => !atBoundary.has(root)));
          }
          if (!charge(policy.ledgers.length, policy.ledgers.length + boundary.callSites.length + 1))
            unavailable("Atomic update finding retention exhausted its shared allowance");
          const key = JSON.stringify([spanId(boundary.location), boundary.callPath, reason, committed, pending]);
          const writes = policy.ledgers.map(root => reason === "partial-group-prefix" && atBoundary.has(root) ? atBoundary.get(root)! : final.get(root)!);
          for (const write of writes) if (!charge(1 + write.guards.length + (write.callSites?.length ?? 0)))
            unavailable("Atomic update write provenance exhausted its shared allowance");
          const predicates = (prefix.predicates ?? []).map(predicate => {
            if (!charge(1 + predicate.callSites.length, 1)) unavailable("Atomic update guard provenance exhausted its allowance");
            return { location: predicate.location, truth: predicate.truth, callSites: predicate.callSites };
          });
          const observation = found.get(key) ?? { policy, location: boundary.location,
            callPath: boundary.callPath, invocations: [], committed, pending, reason, writes };
          const invocation = { ordinal: boundary.ordinal, callSites: boundary.callSites, writes, predicates };
          const invocationKey = JSON.stringify([invocation.ordinal, invocation.callSites.map(spanId),
            writes.map(write => [write.ledger, spanId(write.location), write.guards]),
            predicates.map(predicate => [spanId(predicate.location), predicate.truth, predicate.callSites.map(spanId)])]);
          const keys = routeKeys.get(key) ?? new Set<string>();
          if (!keys.has(invocationKey)) { keys.add(invocationKey); observation.invocations.push(invocation); }
          routeKeys.set(key, keys);
          found.set(key, observation);
        }
      }
      observations.push(...found.values());
    } catch (error) {
      if (!(error instanceof Unavailable)) throw error;
      diagnostics.push({ code: "atomic-update-evidence-unavailable", message: error.message,
        location: facts.program.functions.get(policy.circuit)!.declaration.span,
        scope: { kind: "rule", detectorId: ATOMIC_UPDATE_RULE, entry: policy.circuit } });
    }
  }
  if (limits) { facts.metrics.steps += work; facts.metrics.abstractValues += retained; }
  return { observations, diagnostics };
}
