import { keyedStateComponents } from "../semantic/keyed-state-components.js";
import type { AnalysisFacts, RuntimeOperation, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { immutableCollectionAddress, immutableOperandKey } from "./immutable-key.js";
import { projectEnforcedEqualities } from "./predicates.js";
import { spanId, type Diagnostic } from "../model.js";

export const KEYED_STATE_INVARIANT = "inconsistent-keyed-state-guard";
interface Member { address: string; key: string; query: RuntimeOperation; predicate: SuccessfulPredicate }
interface History { path: SuccessfulPath; members: Member[] }
export interface KeyedStateInvariantObservation {
  entry: string; prerequisite: string; target: string; insert: RuntimeOperation;
  guarded: { path: SuccessfulPath; guard: Member }[];
  bypassed: SuccessfulPath[];
  consumers: { entry: string; histories: { path: SuccessfulPath; prerequisite: Member; target: Member }[] }[];
}

/** Structural review obligation, not inferred application policy. A consumer
 * co-requirement does not prove that surplus entries are invalid. Addresses are
 * canonical ledger identities; keys are compared only within a single history.
 * Initial unchanged receivers deliberately exclude mutation/revision inference. */
export function keyedStateInvariantObservations(facts: AnalysisFacts, allowance = 1_000_000) {
  const observations: KeyedStateInvariantObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  if (facts.keyedStateEvidence) allowance = Math.min(allowance, Math.max(0, facts.keyedStateEvidence.maxSteps - facts.metrics.steps), Math.max(0, facts.keyedStateEvidence.maxValues - facts.metrics.abstractValues));
  const plan = keyedStateComponents(facts.program, Math.min(20000, allowance));
  work += plan.work;
  const issue = (entries: readonly string[], message: string) => {
    for (const entry of entries) diagnostics.push({ code: "keyed-state-evidence-unavailable", message,
      location: facts.program.functions.get(entry)!.declaration.span,
      scope: { kind: "rule", detectorId: KEYED_STATE_INVARIANT, entry } });
  };
  if (!plan.complete) {
    // A completed admission pass already certified excluded entries absent.
    // Recheck exhaustion withholds only the admitted exact relations.
    issue(facts.keyedStateEvidence?.entries ?? facts.program.entries, plan.reason ?? "Keyed-state component dependencies are incomplete");
    return { observations, diagnostics, work };
  }
  const entries = new Set(facts.keyedStateEvidence?.entries ?? facts.program.entries);
  const completed = new Set(facts.completedEntries);
  const incomplete = new Set(facts.program.entries.filter(entry => entries.has(entry) && !completed.has(entry)));
  for (const component of plan.components) {
    if (!component.applicable) continue;
    if (work >= allowance) {
      issue(component.entries, "Keyed-state component review exhausted its shared work allowance");
      continue;
    }
    class Unavailable extends Error {}
    const charge = () => { if (++work > allowance) throw new Unavailable(); };
    try {
      // Dataflow completedEntries records every entry with any transfer gap,
      // including a deduplicated diagnostic from a shared helper. Unscoped gaps
      // with no corresponding incomplete entry cannot be localized safely.
      const selected = new Set(component.entries);
      if (component.entries.some(entry => { charge(); return !entries.has(entry) || !completed.has(entry); })
        || facts.diagnostics.some(diagnostic => { charge(); return diagnostic.scope?.entry ? selected.has(diagnostic.scope.entry) : !incomplete.size; })) {
        issue(component.entries, "Excluded entry or incomplete dependency prevents exact keyed-state component histories");
        continue;
      }
      const result = componentObservations({ ...facts, paths: facts.paths.filter(path => { charge(); return selected.has(path.entry); }),
        completedEntries: component.entries, diagnostics: [] }, Math.max(0, allowance - work), component.entries);
      work += result.work; observations.push(...result.observations); diagnostics.push(...result.diagnostics);
    } catch (error) {
      if (!(error instanceof Unavailable)) throw error;
      issue(component.entries, "Keyed-state component review exhausted its shared work allowance");
    }
  }
  return { observations, diagnostics, work };
}

/** Relationship proof only after the semantic may-dependency partition has
 * certified that all potentially related entries belong to this component. */
function componentObservations(facts: AnalysisFacts, allowance: number, entries: readonly string[]) {
  const observations: KeyedStateInvariantObservation[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  class Unavailable extends Error {}
  const charge = (amount = 1) => { if ((work += amount) > allowance) throw new Unavailable("Keyed-state obligation analysis exhausted its work allowance"); return true; };
  const issue = (message: string) => { for (const entry of entries) diagnostics.push({ code: "keyed-state-evidence-unavailable", message,
    location: facts.program.functions.get(entry)!.declaration.span,
    scope: { kind: "rule" as const, detectorId: KEYED_STATE_INVARIANT, entry } }); };
  try {
    charge();
    if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.collectionEvidence
      || facts.diagnostics.length || entries.some(entry => !facts.completedEntries.includes(entry)))
      throw new Unavailable("Keyed-state review requires completed exact entry histories, all predicates and collection observations without analysis gaps");
    const address = (operation: RuntimeOperation) => {
      charge(); const result = immutableCollectionAddress(operation.args[0], Math.max(0, allowance - work)); charge(result.work);
      if (!result.complete) throw new Unavailable("Collection address traversal is incomplete");
      return result.key;
    };
    const key = (operation: RuntimeOperation) => {
      charge(); if (!operation.args[1]) return undefined;
      const result = immutableOperandKey(operation.args[1], Math.max(0, allowance - work)); charge(result.work);
      if (!result.complete) throw new Unavailable("Collection key traversal is incomplete");
      return result.key;
    };
    const containsMembership = (value: import("./index.js").AbstractValue, depth = 0): boolean => {
      charge(); if (depth > 64) throw new Unavailable("Membership relation exceeds its structural depth allowance");
      if (value.collectionPredicate) return true;
      return [...value.negated ? [value.negated] : [], ...value.comparison ? [value.comparison.left, value.comparison.right] : [],
        ...value.predicateAlternatives ?? []].some(part => containsMembership(part, depth + 1));
    };
    const histories: History[] = facts.paths.map(path => {
      charge();
      const members: Member[] = [];
      for (const predicate of path.predicates ?? []) {
        charge();
        const projected = projectEnforcedEqualities<Member>(predicate.value, predicate.truth, equality => {
          if (containsMembership(equality.left) || containsMembership(equality.right))
            throw new Unavailable("Membership related to a nonconstant Boolean operand requires unsupported relation inference");
          return [];
        }, charge, (value, truth) => {
          charge(); if (!truth || value.collectionPredicate?.empty) return [];
          if (!value.identity) throw new Unavailable("Required membership lacks an exact observed query identity");
          const query = (path.operations ?? []).find(operation => { charge(); return operation.kind === "collection-query" && operation.name === "member" && operation.result.identity === value.identity; });
          if (!query || query.writesBefore === undefined) throw new Unavailable("Required membership lacks ordered query evidence");
          if (query.result.collectionPredicate?.revision !== 0) return [];
          const root = query.args[0].region?.root;
          // Any mutation of the prerequisite invalidates initial membership,
          // even a may-alias write or a later remove after the guard.
          if (!root || query.args[0].region?.revision !== 0 || !query.args[0].preexistingLedger?.has(root) || path.writes.some(write => { charge(); return write.ledger === root; })) return [];
          const receiver = address(query), member = key(query);
          if (!receiver || !member) throw new Unavailable("Required membership has no exact immutable receiver/key identity");
          const evidence = { address: receiver, key: member, query, predicate };
          return [{ key: JSON.stringify([receiver, member]), value: evidence }];
        });
        if (!projected) throw new Unavailable("Successful membership predicate structure is incomplete");
        members.push(...projected.required.values());
      }
      return { path, members };
    });
    // Intersect receiver pairs across all successful consumer histories. Key
    // identity need not match across entries: each pair must share its own key.
    const consumers = new Map<string, KeyedStateInvariantObservation["consumers"]>();
    for (const entry of facts.completedEntries) {
      charge(); const selected = histories.filter(history => { charge(); return history.path.entry === entry; });
      if (!selected.length) continue;
      const pairs = (history: History) => {
        const result = new Map<string, { path: SuccessfulPath; prerequisite: Member; target: Member }>();
        for (const prerequisite of history.members) for (const target of history.members) {
          charge(); if (prerequisite.address === target.address || prerequisite.key !== target.key) continue;
          result.set(JSON.stringify([prerequisite.address, target.address]), { path: history.path, prerequisite, target });
        }
        return result;
      };
      const maps = selected.map(pairs);
      for (const pair of maps[0].keys()) {
        charge(); if (!maps.every(map => { charge(); return map.has(pair); })) continue;
        const group = consumers.get(pair) ?? []; group.push({ entry, histories: maps.map(map => { charge(); return map.get(pair)!; }) }); consumers.set(pair, group);
      }
    }
    const writers = new Map<string, { path: SuccessfulPath; insert: RuntimeOperation; target: string; key: string; members: Member[] }[]>();
    for (const history of histories) {
      const occurrences = new Map<string, number>();
      for (const insert of history.path.operations ?? []) {
        charge(); if (insert.kind !== "collection-write" || insert.name !== "insert" || insert.writesBefore === undefined) continue;
        const target = address(insert), member = key(insert), root = insert.args[0].region?.root;
        if (!target || !member || !root) continue;
        if (!insert.callSites || insert.callSites.length !== insert.callPath.length) throw new Unavailable("Insert invocation identity is incomplete");
        const site = JSON.stringify([history.path.entry, spanId(insert.location), insert.callPath, insert.callSites.map(spanId), target]);
        const occurrence = occurrences.get(site) ?? 0; occurrences.set(site, occurrence + 1);
        const invocation = JSON.stringify([site, occurrence]);
        // Retain a final insertion, never an entry removed/replaced later.
        // Count all invocations first so discarded writes do not merge ordinals.
        if (history.path.writes.slice(insert.writesBefore + 1).some(write => { charge(); return write.ledger === root; })) continue;
        const group = writers.get(invocation) ?? [];
        group.push({ path: history.path, insert, target, key: member, members: history.members }); writers.set(invocation, group);
      }
    }
    for (const reaches of writers.values()) for (const [pair, consumer] of consumers) {
      charge(); const [prerequisite, target] = JSON.parse(pair) as [string, string];
      if (reaches[0].target !== target) continue;
      const prerequisiteRoot = (JSON.parse(prerequisite) as [string, string[]])[0];
      if (reaches.some(reach => reach.path.writes.some(write => { charge(); return write.ledger === prerequisiteRoot; }))) continue;
      const guarded: KeyedStateInvariantObservation["guarded"] = [], bypassed: SuccessfulPath[] = [];
      for (const reach of reaches) {
        charge(); const guard = reach.members.find(member => { charge(); return member.address === prerequisite && member.key === reach.key; });
        if (guard) guarded.push({ path: reach.path, guard }); else bypassed.push(reach.path);
      }
      if (guarded.length && bypassed.length) observations.push({ entry: reaches[0].path.entry, prerequisite, target,
        insert: reaches[0].insert, guarded, bypassed, consumers: consumer });
    }
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    observations.length = 0; issue(error.message);
  }
  return { observations, diagnostics, work };
}
