import type { AbstractValue, AnalysisFacts, CapacityPrefix, RuntimeOperation, SuccessfulPredicate } from "./index.js";
import { immutableCollectionAddress, immutableOperandKey } from "./immutable-key.js";
import { projectEnforcedEqualities } from "./predicates.js";
import type { Diagnostic } from "../model.js";

export const CONFIGURED_CAPACITY_RULE = "configured-membership-capacity-review";
interface Member { address: string; key: string; bound: number; revision: number; query: RuntimeOperation; predicate: SuccessfulPredicate }
export interface CapacityConflict { prefix: CapacityPrefix; address: string; bound: number; revision: number; members: Member[]; distinctness: SuccessfulPredicate[] }
/** Cardinality is a property of a current collection, never must-equality from
 * wildcard paths or shared dependencies. Exact pair exclusions alone supply
 * clique edges; absent/possible Boolean atoms are not requirements. */
export function configuredCapacityConflicts(facts: AnalysisFacts, strict = false) {
  const evidence = facts.configuredCapacity, conflicts: CapacityConflict[] = [], diagnostics: Diagnostic[] = [];
  let work = 0;
  class Unavailable extends Error {}
  const charge = (amount = 1, retained = 0) => {
    work += amount + (strict ? retained : 0);
    if (!evidence || facts.metrics.steps + work > evidence.maxSteps || facts.metrics.abstractValues + work > evidence.maxValues)
      throw new Unavailable("Configured capacity operand/constraint review exhausted the shared allowance");
    return true;
  };
  const operand = (value: AbstractValue) => {
    charge(); const result = immutableOperandKey(value, Math.max(0, evidence!.maxSteps - facts.metrics.steps - work), undefined, strict ? (steps, values) => charge(steps + values) : undefined); if (!strict) charge(result.work);
    if (!result.complete || !result.key) throw new Unavailable("Membership/distinctness operand has no complete exact immutable identity");
    return result.key;
  };
  const issue = (message: string) => diagnostics.push({ code: "capacity-constraint-unavailable", message,
    location: facts.program.functions.get(evidence?.entry ?? facts.program.entries[0])!.declaration.span,
    scope: { kind: "rule" as const, detectorId: strict ? "closed-membership-capacity-review" : CONFIGURED_CAPACITY_RULE, entry: evidence?.entry ?? facts.program.entries[0] } });
  try {
    if (!evidence || facts.diagnostics.length || !facts.completedEntries.includes(evidence.entry) || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.collectionEvidence)
      throw new Unavailable("Complete isolated constructor-to-entry capacity evidence is unavailable");
    charge();
    for (const prefix of evidence.prefixes) {
      charge(strict ? 8 : 1); const members: Member[] = [], edges = new Map<string, SuccessfulPredicate>(), equalities: [string,string][] = [];
      for (const predicate of prefix.gate.predicates ?? []) {
        charge();
        // The strict rule describes reached gate prefixes, including an
        // explicitly disabled continuation. A constant Boolean contributes no
        // cardinality atom; it must not erase earlier independent conflicts.
        if (strict && predicate.value.constantKind === "boolean" && predicate.value.constant !== undefined
          && !predicate.value.collectionPredicate && !predicate.value.comparison && !predicate.value.ordering
          && !predicate.value.negated && !predicate.value.predicateAlternatives) continue;
        const projection = projectEnforcedEqualities<{ kind: "member"; member: Member } | { kind: "distinct"; pair: string; predicate: SuccessfulPredicate } | { kind: "equal"; left: string; right: string }>(predicate.value, predicate.truth, equality => {
          charge();
          const containsMember = (value: AbstractValue, depth = 0): boolean => {
            charge(strict ? 4 + (value.predicateAlternatives?.length ?? 0) : 1); if (depth > 64) throw new Unavailable("Membership Boolean relation depth exhausted");
            return !!value.collectionPredicate || [...value.negated ? [value.negated] : [], ...value.comparison ? [value.comparison.left,value.comparison.right] : [], ...value.predicateAlternatives ?? []].some(part => containsMember(part, depth + 1));
          };
          if (containsMember(equality.left) || containsMember(equality.right)) throw new Unavailable("Nonconstant membership Boolean relation is unsupported");
          const left = operand(equality.left), right = operand(equality.right); if (strict) charge(8 + Math.ceil((left.length + right.length) / 64));
          if (equality.equals) return [{ key: JSON.stringify(["equal", ...[left,right].sort()]), value: { kind: "equal", left, right } }];
          return [{ key: JSON.stringify(["distinct", ...[left, right].sort()]), value: { kind: "distinct", pair: JSON.stringify([left, right].sort()), predicate } }];
        }, charge, (value, truth) => {
          charge(); const member = value.collectionPredicate;
          if (!truth || !member || member.empty) return [];
          if (!strict && member.upperBound === undefined) throw new Unavailable("Required collection membership has no current constructor-derived capacity bound");
          const query = (prefix.gate.operations ?? []).find(operation => { charge(); return operation.kind === "collection-query" && operation.name === "member" && operation.result.identity === value.identity; });
          if (!query || query.writesBefore === undefined || !query.args[0].region || !value.identity) throw new Unavailable("Membership query lacks exact receiver/order evidence");
          const root = query.args[0].region.root;
          // All required facts must still describe the same current epoch at
          // this prefix, including a previously saved Boolean assertion.
          if (prefix.gate.writes.slice(query.writesBefore).some(write => { charge(); return write.ledger === root; }))
            throw new Unavailable("Required membership crosses a collection ledger revision change");
          const receiver = immutableCollectionAddress(query.args[0], Math.max(0, evidence.maxSteps - facts.metrics.steps - work), undefined, strict ? (steps, values) => charge(steps + values) : undefined); if (!strict) charge(receiver.work);
          if (!receiver.complete || !receiver.key || query.args[0].region.revision !== member.revision) throw new Unavailable("Membership receiver has no exact current live collection identity");
          if (strict) {
            charge(); const symbol = facts.program.symbols.get(root);
            if (!facts.closedCapacity || !symbol || symbol.kind !== "ledger") throw new Unavailable("Closed Set root certificate is unavailable");
            if (query.args[0].region.path.length || facts.program.nativeTypeOf(symbol.type) !== "Set" || facts.closedCapacity.writers.has(root)) return [];
          }
          if (member.upperBound === undefined) throw new Unavailable("Required collection membership has no current constructor-derived capacity bound");
          const key = operand(query.args[1]);
          const atom: Member = { address: receiver.key, key, bound: member.upperBound, revision: member.revision, query, predicate };
          if (strict) charge(8 + Math.ceil((receiver.key.length + key.length) / 64));
          return [{ key: JSON.stringify(["member", receiver.key, member.revision, key]), value: { kind: "member", member: atom } }];
        });
        if (!projection) throw new Unavailable("Required capacity predicate structure is incomplete");
        for (const atom of projection.required.values()) { charge(strict ? 4 : 1); if (atom.kind === "member") members.push(atom.member); else if (atom.kind === "distinct") edges.set(atom.pair, atom.predicate); else equalities.push([atom.left,atom.right]); }
      }
      if (strict) charge(3);
      const representatives = new Map<string,string>();
      const canonical = (key: string): string => {
        let depth = 0, parent = representatives.get(key);
        while (parent && parent !== key) { charge(); if (++depth > 64) throw new Unavailable("Scalar equality normalization exceeds its depth allowance"); key = parent; parent = representatives.get(key); }
        charge(); return key;
      };
      for (const [left,right] of equalities) { charge(); const a = canonical(left), b = canonical(right); if (a !== b) representatives.set(a < b ? b : a, a < b ? a : b); }
      const normalizedEdges = new Map<string,SuccessfulPredicate>();
      for (const [pair,predicate] of edges) { charge(strict ? 8 + Math.ceil(pair.length / 64) : 1); const [left,right] = JSON.parse(pair) as [string,string]; normalizedEdges.set(JSON.stringify([canonical(left),canonical(right)].sort()),predicate); }
      for (const member of members) { charge(); member.key = canonical(member.key); }
      const groups = new Map<string, Map<string, Member>>();
      for (const member of members) { charge(); const id = JSON.stringify([member.address, member.revision, member.bound]); if (strict) charge(4); const group = groups.get(id) ?? new Map(); group.set(member.key, member); groups.set(id, group); }
      for (const group of groups.values()) {
        charge(strict ? 1 + group.size : 1); const vertices = [...group.values()], bound = vertices[0].bound;
        if (vertices.length <= bound) continue;
        if (vertices.length > 64) throw new Unavailable("Distinct membership capacity graph exceeds its bounded vertex allowance");
        const clique = (selected: Member[], start: number): Member[] | undefined => {
          charge(); if (selected.length > bound) return selected;
          for (let index = start; index < vertices.length; index++) {
            charge(); const next = vertices[index];
            if (selected.every(prior => { charge(); return normalizedEdges.has(JSON.stringify([prior.key, next.key].sort())); })) {
              if (strict) charge(1 + selected.length); const result = clique([...selected, next], index + 1); if (result) return result;
            }
          }
          return;
        };
        const selected = clique([], 0); if (!selected) continue;
        const distinctness: SuccessfulPredicate[] = [];
        for (let first = 0; first < selected.length; first++) for (let second = first + 1; second < selected.length; second++) { charge(strict ? 2 : 1); distinctness.push(normalizedEdges.get(JSON.stringify([selected[first].key, selected[second].key].sort()))!); }
        if (strict) charge(8 + selected.length + distinctness.length); conflicts.push({ prefix, address: selected[0].address, revision: selected[0].revision, bound, members: selected, distinctness });
      }
    }
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    conflicts.length = 0; issue(error.message);
  }
  facts.metrics.steps += work; facts.metrics.abstractValues += work;
  return { conflicts, diagnostics, work };
}
