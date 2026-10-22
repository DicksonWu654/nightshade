import type { AbstractValue, Flow, SuccessfulPredicate } from "./index.js";
import { enforcedEqualities } from "./predicates.js";

type Position = { writes: number; operations: number };
type DependencyResult = { complete: boolean; work: number; dependencies: Set<string> };
const position = (index: number) => Number.isSafeInteger(index) && index >= 0;
const validPosition = (before: Position) => position(before.writes) && position(before.operations);

/** Decode one immutable history once. Edges retain both observation counters;
 * queries traverse only edges reachable from the effect's exact source IDs.
 * No guard/storage snapshot or cross-history cache is retained. */
export function createEqualityDependencyIndex(predicates: readonly SuccessfulPredicate[] | undefined,
  dependency: (flow: Flow) => string, allowance: number, ordered = false, prefix?: Position) {
  let work = 0, complete = !!predicates && (!prefix || validPosition(prefix));
  const edges = new Map<string, { key: string; writes: number; operations: number }[]>();
  const charge = (units = 1) => { work += units; return complete &&= work <= allowance; };
  for (const predicate of predicates ?? []) {
    if (!charge()) break;
    if (ordered && (!position(predicate.writesBefore) || !position(predicate.operationsBefore))) { complete = false; break; }
    if (prefix && (predicate.writesBefore > prefix.writes || predicate.operationsBefore > prefix.operations)) continue;
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    if (!charge(decoded.work) || !decoded.complete) { complete = false; break; }
    for (const equality of decoded.equalities) {
      if (!charge()) break;
      if (!equality.equals || !equality.left.type || equality.left.type !== equality.right.type) continue;
      for (const [input, other] of [[equality.left, equality.right], [equality.right, equality.left]]) {
        if (!charge(input.flows.length + other.flows.length)) break;
        if (input.fields || input.items || input.comparison || input.negated || input.ordering) continue;
        const exact = input.flows.find(flow => flow.source.id === input.identity);
        if (!exact) continue;
        const key = dependency(exact), adjacent = edges.get(key) ?? [];
        for (const flow of other.flows) {
          if (!charge()) break;
          adjacent.push({ key: dependency(flow), writes: predicate.writesBefore, operations: predicate.operationsBefore });
        }
        edges.set(key, adjacent);
      }
      if (!complete) break;
    }
    if (!complete) break;
  }
  const query = (value: AbstractValue, before: Position | undefined, queryAllowance: number): DependencyResult => {
    let queryWork = 0;
    const incomplete = (): DependencyResult => ({ complete: false, work: queryWork, dependencies: new Set() });
    const queryCharge = (units = 1) => (queryWork += units) <= queryAllowance;
    if (!complete || before && !validPosition(before) || ordered && !before) return incomplete();
    if (!queryCharge(value.flows.length)) return incomplete();
    const dependencies = new Set(value.flows.map(dependency)), pending = [...dependencies];
    for (let index = 0; index < pending.length; index++) for (const edge of edges.get(pending[index]) ?? []) {
      if (!queryCharge()) return incomplete();
      if (before && (edge.writes > before.writes || edge.operations > before.operations)) continue;
      if (!dependencies.has(edge.key)) { dependencies.add(edge.key); pending.push(edge.key); }
    }
    return { complete: true, work: queryWork, dependencies };
  };
  return { complete, work, query };
}

/** Derivation through required equality of an exact private input. A flow union
 * is not an operand identity: only the input's own immutable identity can
 * acquire the other operand's dependencies. No storage address is a key.
 * Ordered histories use only relations known before the effect; a conservative
 * observation union omits the position limit and can only propose candidates. */
export function equalityDependencies(value: AbstractValue, predicates: readonly SuccessfulPredicate[] | undefined,
  dependency: (flow: Flow) => string, allowance: number, before?: Position): DependencyResult {
  const index = createEqualityDependencyIndex(predicates, dependency, allowance, before !== undefined, before);
  const result = index.query(value, before, allowance - index.work);
  return { ...result, work: index.work + result.work };
}
