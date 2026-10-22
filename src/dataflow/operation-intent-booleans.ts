import type { AbstractValue, SuccessfulPredicate } from "./index.js";
import { merkleDigestKey } from "./merkle-enforcement.js";
import { constantOf } from "./transfers.js";

interface Relation { result: string; left: string; right: string; equals: boolean; }

/** Mandatory Boolean parity over immutable operands, separate from scalar value equality.
 * Like collection-consumption relays, != and negation reverse truth. Every visit,
 * queue item and retained relation is charged before allocation. No cross-history state. */
export function intentBooleanRequirements(predicates: readonly SuccessfulPredicate[], charge: (work: number, values: number) => void) {
  charge(0, 9);
  const registered = new WeakMap<AbstractValue, string>(), required = new Map<string, boolean>();
  const adjacent = new Map<string, Map<string, boolean>>(), relations = new Map<string, Relation[]>(), pending: string[] = [];
  let cursor = 0;
  const require = (key: string, truth: boolean): void => {
    charge(1, 0);
    const prior = required.get(key);
    if (prior !== undefined) {
      if (prior !== truth) throw new Error("Mandatory Boolean constraints conflict on a modeled successful history");
      return;
    }
    charge(0, 2); required.set(key, truth); pending.push(key);
  };
  const edge = (a: string, b: string, same: boolean): void => {
    charge(1, 0);
    let edges = adjacent.get(a);
    if (!edges) { charge(0, 2); edges = new Map(); adjacent.set(a, edges); }
    const prior = edges.get(b);
    if (prior !== undefined && prior !== same) throw new Error("Mandatory Boolean parity relations conflict");
    if (prior === undefined) { charge(0, 1); edges.set(b, same); }
    const truth = required.get(a);
    if (truth !== undefined) require(b, truth === same);
  };
  const relate = (first: string, second: string, same: boolean): void => {
    charge(1, 0);
    if (first === second) {
      if (!same) throw new Error("Mandatory Boolean inequality relates one immutable value to itself");
      return;
    }
    edge(first, second, same); edge(second, first, same);
  };
  const index = (key: string, relation: Relation): void => {
    charge(1, 0);
    let entries = relations.get(key);
    if (!entries) { charge(0, 2); entries = []; relations.set(key, entries); }
    charge(0, 1); entries.push(relation);
  };
  const register = (value: AbstractValue, depth = 0): string => {
    charge(1, 0);
    if (depth > 64 || value.type !== "Boolean" || value.predicateAlternatives || value.predicateHasAlternatives || value.predicateStructureLost)
      throw new Error("Exact mandatory Boolean structure unavailable");
    const cached = registered.get(value);
    if (cached) return cached;
    charge(1, 1); const key = merkleDigestKey(value);
    if (!key || value.fields || value.items || value.region?.path.some(part => part.startsWith("key:")))
      throw new Error("Exact mandatory Boolean identity unavailable");
    charge(0, 1); registered.set(value, key);
    charge(1, 1); const constant = constantOf(value);
    if (constant?.kind === "boolean") require(key, constant.value === "true");
    if (value.negated) relate(key, register(value.negated, depth + 1), false);
    if (value.comparison) {
      charge(1, 0);
      const { left, right, operator } = value.comparison;
      if (left.fields || left.items || right.fields || right.items)
        throw new Error("Aggregate comparison Boolean enforcement requires unavailable parity projection");
      if (left.type === "Boolean" && right.type === "Boolean") {
        const first = register(left, depth + 1), second = register(right, depth + 1);
        charge(0, 1); const relation = { result: key, left: first, right: second, equals: operator === "==" };
        index(key, relation); index(first, relation); index(second, relation);
        if (required.has(key)) { charge(0, 1); pending.push(key); }
      }
    }
    return key;
  };
  for (const predicate of predicates) { charge(1, 0); require(register(predicate.value), predicate.truth); }
  const propagate = (): void => {
    for (; cursor < pending.length; cursor++) {
      charge(1, 0); const key = pending[cursor], truth = required.get(key)!;
      const edges = adjacent.get(key);
      if (edges) for (const [other, same] of edges) { charge(1, 0); require(other, truth === same); }
      const formulas = relations.get(key);
      if (formulas) for (const relation of formulas) {
        charge(1, 0);
        const result = required.get(relation.result), left = required.get(relation.left), right = required.get(relation.right);
        if (result !== undefined) relate(relation.left, relation.right, result === relation.equals);
        if (left !== undefined && right !== undefined) require(relation.result, (left === right) === relation.equals);
      }
    }
  };
  propagate();
  const trueKeys = (): Set<string> => {
    propagate(); charge(0, 1); const keys = new Set<string>();
    for (const [key, truth] of required) { charge(1, 0); if (truth) { charge(0, 1); keys.add(key); } }
    return keys;
  };
  const sameValues = (value: AbstractValue): Set<string> => {
    const first = register(value); propagate();
    charge(0, 6); const parities = new Map<string, boolean>([[first, true]]), queue = [first];
    for (let position = 0; position < queue.length; position++) {
      charge(1, 0); const key = queue[position], parity = parities.get(key)!;
      const edges = adjacent.get(key);
      if (edges) for (const [other, same] of edges) {
        charge(1, 0); const next = parity === same, prior = parities.get(other);
        if (prior !== undefined && prior !== next) throw new Error("Boolean parity closure conflicts");
        if (prior === undefined) { charge(0, 2); parities.set(other, next); queue.push(other); }
      }
    }
    charge(0, 1); const keys = new Set<string>(), truth = required.get(first);
    for (const [key, same] of parities) { charge(1, 0); if (same) { charge(0, 1); keys.add(key); } }
    if (truth !== undefined) for (const [key, otherTruth] of required) {
      charge(1, 0); if (otherTruth === truth) { charge(0, 1); keys.add(key); }
    }
    return keys;
  };
  const truth = (value: AbstractValue): boolean | undefined => {
    const key = register(value); propagate(); return required.get(key);
  };
  return { trueKeys, sameValues, truth };
}
