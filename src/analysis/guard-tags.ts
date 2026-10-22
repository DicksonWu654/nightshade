import type { AbstractValue, AnalysisFacts, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { projectEnforcedEqualities } from "../dataflow/predicates.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { nativeHashScope, NATIVE_HASHES } from "../semantic/hash-targets.js";
import { spanId, type Diagnostic, type Span } from "../model.js";

export const GUARD_TAG_RULE = "publicly-derived-guard-tag";
interface Recipe { primitive: string; ledger: string[]; inputs: PrivateSource[] }
interface Guard { predicate: SuccessfulPredicate; supplied: PrivateSource; recipe: Recipe }
interface Effect { kind: "ledger-write" | "kernel-write"; name: string; location: Span; callPath: string[]; callSites: Span[]; index: number; occurrence: number }
interface Reach { path: SuccessfulPath; effect: Effect; guard: Guard }
export interface GuardTagObservation { entry: string; guard: Guard; reaches: Reach[] }

/** Exact raw provenance, never a flow/dependency union or a name heuristic. */
function suppliedLeaf(value: AbstractValue): PrivateSource | undefined {
  if (value.flows.length !== 1 || value.ledger.size || value.fields || value.items || value.directDigest
    || value.negated || value.comparison || value.ordering || value.constant !== undefined) return;
  const flow = value.flows[0];
  if (flow.form === "raw" && value.identity === flow.source.id) return flow.source;
}

/** A required keyed digest relation, not proof that authentication is intended.
 * Caller inputs are known to their supplier; they are not called public/secrecy-free.
 * Every recipe retains its own immutable operands and preexisting provenance. */
export function guardTagObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: GuardTagObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1, depth = 0) => {
    work += amount;
    if (!Number.isSafeInteger(allowance) || allowance < 1 || work > allowance || depth > 64) throw new Exhausted();
  };
  for (const entry of facts.completedEntries) {
    if (facts.program.symbols.get(entry)!.kind === "constructor") continue;
    const location = facts.program.functions.get(entry)!.declaration.span;
    const scope = { kind: "rule" as const, detectorId: GUARD_TAG_RULE, entry };
    const issue = (code: string, message: string) => diagnostics.push({ code, message, location, scope });
    try {
      const applicability = nativeHashScope(facts.program, entry, Math.max(0, Math.min(20000, allowance - work)));
      charge(applicability.work);
      if (!applicability.complete) throw new Exhausted();
      if (!applicability.applicable) continue;
      if (!facts.digestEvidence || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
        issue("guard-tag-evidence-unavailable", "Guard-tag review requires exact typed digest inputs and all successful predicates; this entry has no complete rule result"); continue;
      }
      let unavailable = false;
      const identity = (part: AbstractValue) => {
        const result = immutableOperandKey(part, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
        charge(result.work); if (!result.complete) throw new Exhausted(); return result.key;
      };
      const recipe = (value: AbstractValue): Recipe | undefined => {
        if (!value.directDigest || !NATIVE_HASHES.has(value.directDigest.primitive)) return;
        charge(value.flows.length);
        if (value.flows.some(flow => flow.source.kind === "witness")) return;
        const ledger = new Set<string>(), inputs = new Map<string, PrivateSource>();
        const visit = (part: AbstractValue, depth: number): boolean => {
          charge(1, depth);
          charge(part.flows.length);
          if (part.flows.some(flow => flow.source.kind === "witness")) return false;
          if (part.negated || part.comparison || part.ordering || part.predicateStructureLost || part.predicateAlternatives) return false;
          if (part.directDigest) return NATIVE_HASHES.has(part.directDigest.primitive) && visit(part.directDigest.input, depth + 1);
          if (part.fields || part.items) {
            const children = part.fields ? Object.values(part.fields) : part.items!;
            return children.every(child => visit(child, depth + 1));
          }
          charge(part.flows.length + part.ledger.size);
          const source = suppliedLeaf(part);
          if (source) {
            if (source.kind !== "entry-parameter") return false;
            inputs.set(source.id, source); return true;
          }
          if (part.flows.length) return false;
          if (part.preexistingLedger?.size && part.identity) {
            charge(part.preexistingLedger.size);
            for (const id of part.preexistingLedger) ledger.add(id);
            return true;
          }
          return part.constant !== undefined && part.constantKind !== undefined;
        };
        if (!visit(value.directDigest.input, 0) || !ledger.size) return;
        return { primitive: value.directDigest.primitive, ledger: [...ledger].sort(), inputs: [...inputs.values()] };
      };
      const groups = new Map<string, { path: SuccessfulPath; effect: Effect; guards: Map<string, Guard> }[]>();
      for (const path of facts.paths) {
        charge(); if (path.entry !== entry) continue;
        const guards = new Map<string, Guard>();
        for (const predicate of path.predicates ?? []) {
          charge();
          const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
            if (!equality.equals) return [];
            const matches: { key: string; value: Guard }[] = [];
            for (const [tag, digest] of [[equality.left, equality.right], [equality.right, equality.left]]) {
              charge();
              const supplied = suppliedLeaf(tag);
              if (!supplied || !["Bytes<32>", "Field"].includes(tag.type ?? "")) continue;
              const derivation = recipe(digest);
              if (!derivation || !identity(tag) || !identity(digest)) continue;
              if (!predicate.callSites || predicate.callSites.length !== predicate.callPath.length
                || supplied.kind === "witness" && (!supplied.invocation || !path.witnessCalls
                  || (path.witnessCalls.get(supplied.invocation.site) ?? 0) <= supplied.invocation.occurrence)) { unavailable = true; continue; }
              // Raw allocation ids never stand for universal equality. Group
              // only canonical source/invocation, retaining each path's recipe.
              const origin = [spanId(supplied.location), supplied.kind, supplied.symbol, supplied.declarationLeaf, supplied.invocation];
              const id = JSON.stringify([spanId(predicate.location), predicate.callPath, predicate.callSites.map(spanId), origin, derivation.primitive]);
              matches.push({ key: id, value: { predicate, supplied, recipe: derivation } });
            }
            return matches;
          }, amount => { charge(amount); return true; });
          if (!projected) { unavailable = true; break; }
          for (const [id, guard] of projected.required) { charge(); if (!guards.has(id)) guards.set(id, guard); }
        }
        if (unavailable) break;
        const effects: Effect[] = [
          ...path.writes.map((write, index) => ({ kind: "ledger-write" as const, name: facts.program.symbols.get(write.ledger)!.name,
            location: write.location, callPath: write.callPath, callSites: write.callSites!, index, occurrence: 0 })),
          ...(path.operations ?? []).flatMap((op, index) => op.kind === "kernel-write" ? [{ kind: "kernel-write" as const, name: op.name,
            location: op.location, callPath: op.callPath, callSites: op.callSites!, index, occurrence: 0 }] : []),
        ];
        const occurrences = new Map<string, number>();
        for (const effect of effects) {
          charge();
          if (!effect.callSites || effect.callSites.length !== effect.callPath.length) { unavailable = true; break; }
          const site = JSON.stringify([effect.kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId)]);
          effect.occurrence = occurrences.get(site) ?? 0; occurrences.set(site, effect.occurrence + 1);
          const id = JSON.stringify([site, effect.occurrence]);
          const reaches = groups.get(id) ?? []; reaches.push({ path, effect, guards }); groups.set(id, reaches);
        }
        if (unavailable) break;
      }
      const grouped = new Map<string, GuardTagObservation>();
      for (const reaches of groups.values()) {
        charge();
        for (const [id, guard] of reaches[0].guards) {
          const required = reaches.every(reach => {
            charge(); const match = reach.guards.get(id);
            return !!match && (reach.effect.kind === "ledger-write" ? match.predicate.writesBefore <= reach.effect.index
              : match.predicate.operationsBefore <= reach.effect.index);
          });
          if (!required) continue;
          const groupId = spanId(guard.predicate.location);
          const observation = grouped.get(groupId) ?? { entry, guard, reaches: [] };
          observation.reaches.push(...reaches.map(reach => ({ path: reach.path, effect: reach.effect, guard: reach.guards.get(id)! })));
          grouped.set(groupId, observation);
        }
      }
      if (unavailable) issue("guard-tag-evidence-unavailable", "Guard-tag history is missing predicate structure or exact invocation/effect evidence; this entry has no complete rule result");
      else observations.push(...grouped.values());
    } catch (error) {
      if (!(error instanceof Exhausted)) throw error;
      issue("guard-tag-analysis-budget", "Guard-tag operand/recipe intersection exhausted its bounded allowance; this entry has no complete rule result");
    }
  }
  return { observations, diagnostics, work };
}
