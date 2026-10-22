import type { AbstractValue, AnalysisFacts, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "../dataflow/index.js";
import { immutableOperandKey } from "../dataflow/immutable-key.js";
import { predicateEvidence, predicateSourceKey, projectEnforcedEqualities, trustedPreimageSources } from "../dataflow/predicates.js";
import { spanId, type Diagnostic, type Span } from "../model.js";
import { NATIVE_KEY_RULE, nativeKeyScope } from "../semantic/native-key-targets.js";
import { nativeKeyIngredients } from "../dataflow/native-key.js";

interface Guard { predicate: SuccessfulPredicate; supplied: PrivateSource; ledger: string[]; ledgerIdentity: string; credential: "raw-key-with-private-preimage" | "key-in-credential" }
interface Effect { kind: "ledger-write" | "kernel-write"; name: string; location: Span; callPath: string[]; callSites: Span[]; index: number; occurrence: number }
interface Reach { path: SuccessfulPath; effect: Effect; guard: Guard }
export interface NativeKeyObservation { entry: string; guard: Guard; reaches: Reach[] }

/** Exact must-equality before every successful effect reach. This is a source
 * relationship review, not proof that the application intends authentication. */
export function nativeKeyObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: NativeKeyObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  class Exhausted extends Error {}
  const charge = (amount = 1) => { work += amount; if (!Number.isSafeInteger(allowance) || work > allowance) throw new Exhausted(); };
  for (const entry of facts.completedEntries) {
    const scope = { kind: "rule" as const, detectorId: NATIVE_KEY_RULE, entry };
    const location = facts.program.functions.get(entry)!.declaration.span;
    const issue = (code: string, message: string) => diagnostics.push({ code, message: `${message}; this entry has no complete ${NATIVE_KEY_RULE} result`, location, scope });
    try {
      const applicable = nativeKeyScope(facts.program, entry, Math.max(0, allowance - work));
      charge(applicable.work);
      if (!applicable.complete) throw new Exhausted();
      if (!applicable.applicable) continue;
      if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.digestEvidence || !facts.commitEvidence) {
        issue("native-key-evidence-unavailable", "Exact all-predicate histories and native digest/commitment inputs are unavailable"); continue;
      }
      const groups = new Map<string, { path: SuccessfulPath; effect: Effect; guards: Map<string, Guard>; alternate: boolean }[]>();
      let unavailable = false;
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
              if (!source.symbol || facts.program.symbols.get(source.symbol)?.kind !== "witness") continue;
              const stored = equality.left.directHash ? equality.right : equality.left;
              if (!stored.flows.length && !stored.region?.path.includes("key:*")) matches.push({ key: `preimage:${source.id}`, value: source });
            }
            for (const [raw, stored] of [[equality.left, equality.right], [equality.right, equality.left]]) {
              charge();
              const credentialInput = raw.directDigest?.input ?? raw.directCommit?.input;
              const ingredients = nativeKeyIngredients(credentialInput && raw.directCommit ? { flows: [], ledger: new Set(), items: [credentialInput, raw.directCommit.randomness] } : credentialInput ?? raw, charge);
              if (!ingredients.complete) throw new Exhausted();
              const supplied = ingredients.native[0];
              if (credentialInput && !ingredients.secret.some(source => !evidence.publicValues.has(predicateSourceKey(source, path)))) continue;
              const credential = credentialInput ? "key-in-credential" as const : "raw-key-with-private-preimage" as const;
              if (!supplied || stored.fields || stored.items) continue;
              if (stored.region?.path.includes("key:*")) { unavailable = true; continue; }
              if (!stored.preexistingLedger?.size || stored.negated || stored.comparison || stored.ordering || stored.directDigest) continue;
              if (stored.flows.length) { unavailable = true; continue; }
              const identity = immutableOperandKey(stored, Math.min(4096, Math.max(0, allowance - work)), undefined, undefined, facts.program.meteringIdentity);
              charge(identity.work); if (!identity.complete) throw new Exhausted();
              if (!identity.key) { unavailable = true; continue; }
              const origins = new Map([...ingredients.native, ...ingredients.secret].map(source => [`id:${source.id}`, `source:${predicateSourceKey(source, path)}`]));
              const snapshot = immutableOperandKey(raw.directCommit ? { flows: [], ledger: new Set(), items: [raw.directCommit.input, raw.directCommit.randomness] } : credentialInput ?? raw, Math.min(4096, Math.max(0, allowance - work)), key => origins.get(key) ?? key, undefined, facts.program.meteringIdentity);
              charge(snapshot.work); if (!snapshot.complete) throw new Exhausted();
              if (!snapshot.key) { unavailable = true; continue; }
              const key = JSON.stringify(["guard", spanId(predicate.location), predicate.callPath, predicate.callSites!.map(spanId), predicateSourceKey(supplied, path), identity.key, credential, raw.directDigest?.primitive ?? raw.directCommit?.primitive, snapshot.key]);
              matches.push({ key, value: { predicate, supplied, ledger: [...stored.preexistingLedger], ledgerIdentity: identity.key, credential } });
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
      const grouped = new Map<string, NativeKeyObservation>();
      for (const reaches of groups.values()) {
        charge();
        for (const [id, guard] of reaches[0].guards) {
          if (!reaches.every(reach => {
            charge(); const match = reach.guards.get(id);
            return !!match && (match.credential === "key-in-credential" || reach.alternate) && (reach.effect.kind === "ledger-write" ? match.predicate.writesBefore <= reach.effect.index : match.predicate.operationsBefore <= reach.effect.index);
          })) continue;
          const groupId = spanId(guard.predicate.location);
          const observation = grouped.get(groupId) ?? { entry, guard, reaches: [] };
          observation.reaches.push(...reaches.map(reach => ({ path: reach.path, effect: reach.effect, guard: reach.guards.get(id)! })));
          grouped.set(groupId, observation);
        }
      }
      if (unavailable) issue("native-key-evidence-unavailable", "Predicate, storage-selector or invocation identity is unavailable");
      else observations.push(...grouped.values());
    } catch (error) {
      if (!(error instanceof Exhausted)) throw error;
      issue("native-key-analysis-budget", "Required equality/history intersection exhausted its bounded allowance");
    }
  }
  return { observations, diagnostics, work };
}
