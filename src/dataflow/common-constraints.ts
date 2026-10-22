import type { AbstractValue } from "./index.js";
import { scalarRelations } from "./scalar-relations.js";
import { MAX_AGGREGATE_EXCLUSION_LEAVES, MAX_ORDERED_PREDICATES, refineScalar, type ScalarConstraints } from "./transfers.js";

export type CommonConstraints =
  | { status: "available"; constraints: ScalarConstraints }
  | { status: "incomplete"; reason: string };

/** A conservative conjunction, never evidence that a joined history succeeds.
 * Compare equivalence classes, not retained edge syntax: a=b and a=c=b have
 * a=b in common. The original alternatives remain necessary for queries that
 * depend on disjunctions this domain cannot express. */
export function commonScalarConstraints(left: ScalarConstraints, right: ScalarConstraints,
  charge: (work: number, values: number) => boolean): CommonConstraints {
  class Incomplete extends Error {}
  const spend = (work = 1, values = 0): void => { if (!charge(work, values)) throw new Incomplete("Common scalar constraints exhausted the shared allowance"); };
  const incomplete = (reason: string): never => { throw new Incomplete(reason); };
  const empty = (): AbstractValue => ({ flows: [], ledger: new Set() });
  const leaf = (identity: string): AbstractValue => ({ ...empty(), identity });
  // An operand saved after refinement can carry a path-local constant. Its
  // immutable identity is shared; that constant is not automatically shared.
  const unrefined = (value: AbstractValue): AbstractValue => value.identity
    ? { ...value, constant: undefined, constantKind: undefined } : value;
  const operandKey = (value: AbstractValue): string => value.identity ? `identity:${value.identity}`
    : `constant:${value.constantKind}:${value.constant}`;
  try {
    if ([left, right].some(state => state.scalarEqualitiesExhausted || state.orderingsExhausted || state.aggregateExclusionsExhausted || state.hashRecipes?.exhausted))
      incomplete("Cannot join exhausted scalar constraints");
    if (left.hashRecipes && right.hashRecipes && left.hashRecipes !== right.hashRecipes)
      incomplete("Cannot join foreign hash-recipe arenas");
    // Propagation must not mutate either selected input. Other containers are
    // read-only here; scalarRelations.propagate only adds known constants.
    const first = { ...left, known: new Map(left.known) }, second = { ...right, known: new Map(right.known) };
    spend(1 + (first.scalarEqualities?.size ?? 0) + (second.scalarEqualities?.size ?? 0));
    const a = scalarRelations(first), b = scalarRelations(second);
    if (!a.consistent || !b.consistent) incomplete("Cannot join an inconsistent selected constraint state");
    a.propagate(); b.propagate();
    const result: ScalarConstraints = { hashRecipes: left.hashRecipes ?? right.hashRecipes,
      known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(),
      aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false, scalarEqualities: new Map(), orderings: new Map() };
    const operands = new Map<string, AbstractValue>();
    const remember = (value: AbstractValue): void => {
      spend();
      if (!value.items && !value.fields && value.identity) operands.set(value.identity, leaf(value.identity));
    };
    for (const state of [first, second]) {
      for (const identity of state.known.keys()) remember(leaf(identity));
      // assumeScalar and this join record each truth together with a known
      // constant, and propagation only adds known entries, so a truth key is
      // normally already an operand: skip that repeated visit (same operands,
      // same insertion order). A truth without a known constant is still visited.
      for (const identity of state.truths.keys()) if (!state.known.has(identity)) remember(leaf(identity));
      for (const identity of state.excluded.keys()) remember(leaf(identity));
      for (const relation of state.scalarEqualities?.values() ?? []) { remember(relation.left); remember(relation.right); }
      for (const { predicate } of state.orderings?.values() ?? []) { remember(predicate.left); remember(predicate.right); }
    }
    if (operands.size > MAX_AGGREGATE_EXCLUSION_LEAVES) incomplete("Common scalar operand capacity exhausted");
    const retainRelation = (left: AbstractValue, right: AbstractValue, equals: boolean): void => {
      const key = JSON.stringify([operandKey(left), operandKey(right)].sort());
      if (result.scalarEqualities!.has(key)) return;
      if (result.scalarEqualities!.size >= MAX_ORDERED_PREDICATES) incomplete("Common scalar relation capacity exhausted");
      spend(1, 1); result.scalarEqualities!.set(key, { left, right, equals });
    };
    // Intersect partitions in linear space, avoiding all-pairs closure edges.
    const classes = new Map<string, AbstractValue>();
    for (const [identity, value] of operands) {
      spend(2);
      const x = refineScalar(value, first), y = refineScalar(value, second);
      if (x.constant !== undefined && x.constantKind && x.constant === y.constant && x.constantKind === y.constantKind) {
        spend(1, 1); result.known.set(identity, { kind: x.constantKind, value: x.constant });
        if (x.constantKind === "boolean") result.truths.set(identity, x.constant === "true");
        // A class pinned to one shared constant is represented by its members'
        // constants alone: scalarRelations compares constants, so equality edges
        // between them are implied and are not materialized (or re-joined later).
        continue;
      }
      const signature = (refined: AbstractValue, identity: string | undefined): unknown => refined.constant !== undefined && refined.constantKind
        ? ["constant", refined.constantKind, refined.constant] : ["identity", identity ?? value.identity];
      const key = JSON.stringify([signature(x, a.identity(value)), signature(y, b.identity(value))]);
      const previous = classes.get(key);
      if (previous) retainRelation(previous, value, true); else classes.set(key, value);
    }
    const exclusions = (state: ScalarConstraints, relations: ReturnType<typeof scalarRelations>): Map<string, Set<string>> => {
      const grouped = new Map<string, Set<string>>();
      for (const [identity, values] of state.excluded) {
        spend();
        const key = relations.identity(leaf(identity))!;
        const group = grouped.get(key) ?? new Set<string>();
        for (const value of values) { spend(); group.add(value); }
        grouped.set(key, group);
      }
      return grouped;
    };
    const excludedA = exclusions(first, a), excludedB = exclusions(second, b);
    // A common exclusion needs a grouped exclusion in both inputs.
    if (excludedA.size && excludedB.size) for (const [identity, value] of operands) {
      spend(2);
      const x = excludedA.get(a.identity(value)!), y = excludedB.get(b.identity(value)!);
      if (!x || !y) continue;
      const common = new Set<string>();
      for (const constant of x) { spend(); if (y.has(constant)) { spend(0, 1); common.add(constant); } }
      if (common.size) result.excluded.set(identity, common);
    }
    for (const state of [first, second]) for (const relation of state.scalarEqualities?.values() ?? []) {
      spend(2);
      const left = unrefined(relation.left), right = unrefined(relation.right);
      if (!relation.equals && a.equality(left, right) === false && b.equality(left, right) === false) retainRelation(left, right, false);
    }
    for (const state of [first, second]) for (const [key, observation] of state.orderings ?? []) {
      spend();
      if (result.orderings!.has(key)) continue;
      // orderedConstant visits the retained comparisons in both selected states.
      // An ordering retained by both inputs (same immutable predicate identity,
      // e.g. a shared fork prefix or an earlier join) needs no implication
      // query: equal truths hold on every history of either input, and opposite
      // truths are retained by neither. Visit/retention costs remain.
      const firstObservation = first.orderings?.get(key), secondObservation = second.orderings?.get(key);
      if (firstObservation && secondObservation && firstObservation.truth !== secondObservation.truth) continue;
      const shared = !!firstObservation && !!secondObservation;
      if (!shared) spend(2 + (first.orderings?.size ?? 0) + (second.orderings?.size ?? 0));
      const truth = observation.truth, predicate = { ...observation.predicate,
        left: unrefined(observation.predicate.left), right: unrefined(observation.predicate.right),
        ...(observation.predicate.leftBytes ? { leftBytes: observation.predicate.leftBytes.map(unrefined) } : {}) };
      const value: AbstractValue = { ...empty(), ordering: predicate };
      if (!shared && (refineScalar(value, first).constant !== String(truth) || refineScalar(value, second).constant !== String(truth))) continue;
      if (!result.orderings!.has(key)) {
        if (result.orderings!.size >= MAX_ORDERED_PREDICATES) incomplete("Common ordered-predicate capacity exhausted");
        spend(0, 1); result.orderings!.set(key, { predicate, truth });
      }
    }
    for (const [key, leaves] of left.aggregateExclusions) {
      spend(1 + leaves.length);
      const other = right.aggregateExclusions.get(key);
      if (!other || JSON.stringify(leaves) !== JSON.stringify(other)) continue;
      result.aggregateExclusionLeaves += leaves.length;
      if (result.aggregateExclusionLeaves > MAX_AGGREGATE_EXCLUSION_LEAVES) incomplete("Common aggregate-exclusion capacity exhausted");
      spend(0, leaves.length);
      result.aggregateExclusions.set(key, leaves.map(([identity, constant]) => [identity, { ...constant }] as const));
    }
    // Equality/refinement can spend through the shared recipe arena after our
    // last direct charge, including on a relation that is not retained.
    spend(0, 0);
    if (result.hashRecipes?.exhausted) incomplete("Common scalar refinement exhausted the hash-recipe allowance");
    return { status: "available", constraints: result };
  } catch (error) {
    if (!(error instanceof Incomplete)) throw error;
    return { status: "incomplete", reason: error.message };
  }
}
