import type { AbstractValue, AnalysisFacts, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { predicateEvidence, predicateSourceKey, projectEnforcedEqualities, trustedPreimageSources } from "../dataflow/predicates.js";
import { spanId, type Diagnostic, type Span } from "../model.js";
import { CALLER_EQUALITY_RULE, callerEqualityScope } from "../semantic/caller-equality-targets.js";

interface Guard { predicate: SuccessfulPredicate; supplied: PrivateSource; ledger: string[]; ledgerIdentity: string }
interface Effect { kind: "ledger-write" | "kernel-write"; name: string; location: Span; callPath: string[]; callSites: Span[]; index: number; occurrence: number }
interface Reach { path: SuccessfulPath; effect: Effect; guard: Guard }
export interface CallerEqualityObservation { entry: string; guard: Guard; reaches: Reach[] }

function suppliedBytes(value: AbstractValue): PrivateSource | undefined {
  if (value.type !== "Bytes<32>" || value.flows.length !== 1 || value.ledger.size || value.fields || value.items
    || value.directDigest || value.negated || value.comparison || value.ordering) return;
  const flow = value.flows[0];
  // Enforced constraints may refine this unchanged input to a constant. The
  // exact origin distinguishes it from a constructed literal, whose flow is absent.
  return flow.source.kind === "entry-parameter" && flow.form === "raw" && flow.source.id === value.identity ? flow.source : undefined;
}

/** Exact must-equality before every successful effect reach. This is a source
 * relationship review, not proof that the application intends authentication. */
export function callerEqualityObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: CallerEqualityObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1) => { work += amount; if (!Number.isSafeInteger(allowance) || work > allowance) throw new Exhausted(); };
  for (const entry of facts.completedEntries) {
    const scope = { kind: "rule" as const, detectorId: CALLER_EQUALITY_RULE, entry };
    const location = facts.program.functions.get(entry)!.declaration.span;
    const issue = (code: string, message: string) => diagnostics.push({ code, message: `${message}; this entry has no complete ${CALLER_EQUALITY_RULE} result`, location, scope });
    try {
      const applicable = callerEqualityScope(facts.program, entry, Math.max(0, allowance - work));
      charge(applicable.work);
      if (!applicable.complete) throw new Exhausted();
      if (!applicable.applicable) continue;
      if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all") {
        issue("caller-equality-evidence-unavailable", "Exact all-predicate histories are unavailable"); continue;
      }
      const groups = new Map<string, { path: SuccessfulPath; effect: Effect; guards: Map<string, Guard>; alternate: boolean }[]>();
      let unavailable = false, uncertainPossession = false;
      for (const path of facts.paths) {
        charge(); if (path.entry !== entry) continue;
        if (!path.predicates) { unavailable = true; break; }
        const evidence = predicateEvidence(path, Math.max(0, allowance - work));
        charge(evidence.work);
        if (!evidence.complete) { unavailable = true; break; }
        const guards = new Map<string, Guard>();
        const privatePreimages = new Map<string, PrivateSource>();
        for (const predicate of path.predicates) {
          charge();
          if (!predicate.callSites || predicate.callSites.length !== predicate.callPath.length) { unavailable = true; break; }
          const projected = projectEnforcedEqualities<Guard | PrivateSource>(predicate.value, predicate.truth, equality => {
            if (!equality.equals) return [];
            const matches: { key: string; value: Guard | PrivateSource }[] = [];
            for (const source of trustedPreimageSources(equality)) {
              charge();
              const stored = equality.left.directHash ? equality.right : equality.left;
              if (!stored.flows.length && !stored.region?.path.includes("key:*")) matches.push({ key: `preimage:${source.id}`, value: source });
            }
            for (const [raw, stored] of [[equality.left, equality.right], [equality.right, equality.left]]) {
              charge(); const supplied = suppliedBytes(raw);
              if (!supplied || stored.type !== "Bytes<32>" || stored.fields || stored.items) continue;
              if (stored.region?.path.includes("key:*")) { unavailable = true; continue; }
              if (!stored.preexistingLedger?.size || stored.negated || stored.comparison || stored.ordering || stored.directDigest) continue;
              if (stored.flows.length) { unavailable = true; continue; }
              const identity = immutableOperandKey(stored, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
              charge(identity.work); if (!identity.complete) throw new Exhausted();
              if (!identity.key) { unavailable = true; continue; }
              const key = JSON.stringify(["guard", spanId(predicate.location), predicate.callPath, predicate.callSites!.map(spanId), supplied.symbol, supplied.declarationLeaf, identity.key]);
              matches.push({ key, value: { predicate, supplied, ledger: [...stored.preexistingLedger], ledgerIdentity: identity.key } });
            }
            return matches;
          }, amount => { charge(amount); return true; });
          if (!projected) { unavailable = true; break; }
          for (const [key, value] of projected.required) {
            charge();
            if (key.startsWith("preimage:")) privatePreimages.set((value as PrivateSource).id, value as PrivateSource);
            else if (!guards.has(key)) guards.set(key, value as Guard);
          }
        }
        if (unavailable) break;
        const possiblePrivate = new Set([...privatePreimages.values()].filter(source => !evidence.publicValues.has(predicateSourceKey(source, path))).map(source => source.id));
        // Scalar public-value propagation cannot certify reconstructed Bytes
        // secrecy. A bytewise or transformed equality may expose the whole
        // preimage without equating its original source identity. Withhold the
        // rule instead of using that uncertain possession evidence to suppress.
        if (guards.size && possiblePrivate.size) for (const { equality } of evidence.equalities) {
          charge();
          for (const operand of [equality.left, equality.right]) for (const flow of operand.flows) {
            charge();
            if (possiblePrivate.has(flow.source.id) && flow.form !== "hash" && flow.form !== "commitment"
              && (operand.identity !== flow.source.id || flow.form !== "raw")) uncertainPossession = unavailable = true;
          }
        }
        if (unavailable) break;
        const alternate = possiblePrivate.size > 0;
        const effects: Effect[] = [
          ...path.writes.map((write, index) => ({ kind: "ledger-write" as const, name: facts.program.symbols.get(write.ledger)!.name,
            location: write.location, callPath: write.callPath, callSites: write.callSites!, index, occurrence: 0 })),
          ...(path.operations ?? []).flatMap((op, index) => op.kind === "kernel-write" ? [{ kind: "kernel-write" as const, name: op.name,
            location: op.location, callPath: op.callPath, callSites: op.callSites!, index, occurrence: 0 }] : []),
        ];
        const occurrences = new Map<string, number>();
        for (const effect of effects) {
          charge(); if (!effect.callSites || effect.callSites.length !== effect.callPath.length) { unavailable = true; break; }
          const site = JSON.stringify([effect.kind, spanId(effect.location), effect.callPath, effect.callSites.map(spanId)]);
          effect.occurrence = occurrences.get(site) ?? 0; occurrences.set(site, effect.occurrence + 1);
          const id = JSON.stringify([site, effect.occurrence]);
          const reaches = groups.get(id) ?? []; reaches.push({ path, effect, guards, alternate }); groups.set(id, reaches);
        }
        if (unavailable) break;
      }
      const grouped = new Map<string, CallerEqualityObservation>();
      for (const reaches of groups.values()) {
        charge(); if (reaches.every(reach => reach.alternate)) continue;
        for (const [id, guard] of reaches[0].guards) {
          if (!reaches.every(reach => {
            charge(); const match = reach.guards.get(id);
            return !!match && (reach.effect.kind === "ledger-write" ? match.predicate.writesBefore <= reach.effect.index : match.predicate.operationsBefore <= reach.effect.index);
          })) continue;
          const groupId = spanId(guard.predicate.location);
          const observation = grouped.get(groupId) ?? { entry, guard, reaches: [] };
          observation.reaches.push(...reaches.map(reach => ({ path: reach.path, effect: reach.effect, guard: reach.guards.get(id)! })));
          grouped.set(groupId, observation);
        }
      }
      if (unavailable) issue(uncertainPossession ? "caller-equality-possession-unavailable" : "caller-equality-evidence-unavailable", uncertainPossession
        ? "A potential alternate possession check has reconstructed or transformed equality dependencies whose private status is unclassified"
        : "Predicate, storage-selector or invocation identity is unavailable");
      else observations.push(...grouped.values());
    } catch (error) {
      if (!(error instanceof Exhausted)) throw error;
      issue("caller-equality-analysis-budget", "Required equality/history intersection exhausted its bounded allowance");
    }
  }
  return { observations, diagnostics, work };
}
