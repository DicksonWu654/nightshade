import type { AbstractValue, PrivateSource, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { constantOf, valueIdentity } from "./transfers.js";

export interface EnforcedEquality {
  left: AbstractValue;
  right: AbstractValue;
  equals: boolean;
}

/** Bounded decoding is necessary even for compact DAG-shaped aggregate values.
 * A dependency union never supplies cross-component equality evidence. */
export function enforcedEqualities(value: AbstractValue, truth: boolean, meter?: (work: number, values: number) => boolean): { complete: boolean; work: number; equalities: EnforcedEquality[] } {
  if (meter && !meter(0, 2)) return { complete: false, work: 0, equalities: [] };
  const equalities: EnforcedEquality[] = [];
  let work = 0;
  const charge = (depth: number, retained = 0) => {
    work++;
    return (!meter || meter(1, retained)) && work <= 4096 && depth <= 64;
  };
  const condition = (value: AbstractValue, truth: boolean, depth: number): boolean => {
    if (!charge(depth)) return false;
    if (value.negated) return condition(value.negated, !truth, depth + 1);
    if (value.comparison) {
      const { left, right, operator } = value.comparison;
      return pair(left, right, operator === "==" ? truth : !truth, depth + 1);
    }
    if (value.type === "Boolean" && !value.ordering && !value.collectionPredicate && !value.listPredicate && !value.merklePredicate) {
      if (meter && !meter(0, 4)) return false;
      equalities.push({ left: value, right: { flows: [], ledger: new Set(), type: "Boolean", constant: String(truth), constantKind: "boolean" }, equals: true });
    }
    return true;
  };
  const pair = (left: AbstractValue, right: AbstractValue, equals: boolean, depth: number): boolean => {
    if (!charge(depth)) return false;
    if (left.fields || right.fields) {
      if (!equals || !left.fields || !right.fields) return true;
      let leftCount = 0, rightCount = 0;
      for (const name in left.fields) if (Object.hasOwn(left.fields, name)) {
        if (meter && !meter(1, 0)) return false;
        if (!Object.hasOwn(right.fields, name)) return true;
        leftCount++;
      }
      for (const name in right.fields) if (Object.hasOwn(right.fields, name)) {
        if (meter && !meter(1, 0)) return false;
        rightCount++;
      }
      if (leftCount !== rightCount) return true;
      for (const name in left.fields) if (Object.hasOwn(left.fields, name) && !pair(left.fields[name], right.fields[name], true, depth + 1)) return false;
      return true;
    }
    if (left.items || right.items) {
      if (!equals || !left.items || !right.items || left.items.length !== right.items.length) return true;
      return left.items.every((part, index) => pair(part, right.items![index], true, depth + 1));
    }
    if (meter && !meter(0, 2)) return false;
    const rightConstant = constantOf(right), leftConstant = constantOf(left);
    if (rightConstant?.kind === "boolean") return condition(left, equals === (rightConstant.value === "true"), depth + 1);
    if (leftConstant?.kind === "boolean") return condition(right, equals === (leftConstant.value === "true"), depth + 1);
    if (meter && !meter(0, 1)) return false;
    equalities.push({ left, right, equals });
    return true;
  };
  const complete = condition(value, truth, 0);
  return { complete, work, equalities: complete ? equalities : [] };
}

export interface AtomicPredicateProjection<T> {
  possible: ReadonlyMap<string, T>;
  required: ReadonlyMap<string, T>;
}

/** Decode conservative Boolean alternatives without treating their possible facts
 * as a conjunction. Infeasible constant arms differ from feasible empty checks.
 * Every possible atomic check is inspected before intersecting required facts. */
export function projectEnforcedEqualities<T>(value: AbstractValue, truth: boolean,
  atom: (equality: EnforcedEquality) => readonly { key: string; value: T }[] | undefined,
  charge: (work: number, values: number) => boolean,
  collectionAtom?: (value: AbstractValue, truth: boolean) => readonly { key: string; value: T }[] | undefined,
  /** An immutable observed Boolean may carry a refined comparison too. Decode
   * its observation first. null means no match; undefined means unavailable. */
  observedAtom?: (value: AbstractValue, truth: boolean) => readonly { key: string; value: T }[] | null | undefined): AtomicPredicateProjection<T> | undefined {
  type Projection = AtomicPredicateProjection<T> & { feasible: boolean };
  let work = 0;
  const spend = (depth: number, retained = 0) => ++work <= 4096 && depth <= 64 && charge(1, retained);
  const none = (feasible = true): Projection => ({ feasible, possible: new Map(), required: new Map() });
  const memo = new WeakMap<AbstractValue, Map<boolean, Projection>>();
  const merge = (a: Projection | undefined, b: Projection | undefined, alternatives: boolean, depth: number): Projection | undefined => {
    if (!a || !b || !spend(depth)) return;
    if (alternatives && (!a.feasible || !b.feasible)) return a.feasible ? a : b;
    if (!alternatives && (!a.feasible || !b.feasible)) return none(false);
    const possible = new Map(a.possible), required = new Map(a.required);
    if (!charge(a.possible.size + a.required.size, a.possible.size + a.required.size)) return;
    for (const [key, value] of b.possible) {
      if (!spend(depth, 1)) return;
      possible.set(key, value);
    }
    if (alternatives) {
      for (const key of required.keys()) { if (!spend(depth)) return; if (!b.required.has(key)) required.delete(key); }
    } else for (const [key, value] of b.required) {
      if (!spend(depth, 1)) return;
      required.set(key, value);
    }
    return { feasible: true, possible, required };
  };
  const condition = (value: AbstractValue, truth: boolean, depth: number): Projection | undefined => {
    if (!spend(depth)) return;
    const cached = memo.get(value)?.get(truth);
    if (cached) return cached;
    let result: Projection | undefined;
    if (value.predicateStructureLost) return;
    const observed = observedAtom ? observedAtom(value, truth) : null;
    if (value.negated) result = condition(value.negated, !truth, depth + 1);
    else if (observed !== null) result = project(observed, depth + 1);
    else if (value.comparison) {
      const { left, right, operator } = value.comparison;
      result = pair(left, right, operator === "==" ? truth : !truth, depth + 1);
    } else if (value.predicateAlternatives) result = merge(
      condition(value.predicateAlternatives[0], truth, depth + 1),
      condition(value.predicateAlternatives[1], truth, depth + 1), true, depth + 1);
    else if (value.collectionPredicate && collectionAtom) result = project(collectionAtom(value, truth), depth + 1);
    else if (value.type === "Boolean" && !value.ordering && !value.collectionPredicate && !value.listPredicate && !value.merklePredicate) {
      const constant = constantOf(value);
      result = constant?.kind === "boolean" && (constant.value !== String(truth) || !rawWitnessSources(value).length) ? none(constant.value === String(truth))
        : atomic({ left: value, right: { flows: [], ledger: new Set(), type: "Boolean", constant: String(truth), constantKind: "boolean" }, equals: true }, depth + 1);
    } else result = none();
    if (result) {
      if (!charge(0, 1)) return;
      let truths = memo.get(value); if (!truths) memo.set(value, truths = new Map());
      truths.set(truth, result);
    }
    return result;
  };
  const atomic = (equality: EnforcedEquality, depth: number): Projection | undefined => {
    if (!spend(depth)) return;
    return project(atom(equality), depth);
  };
  const project = (projected: readonly { key: string; value: T }[] | undefined, depth: number): Projection | undefined => {
    if (!projected) return;
    const facts = new Map<string, T>();
    for (const { key, value } of projected) { if (!spend(depth, 1)) return; facts.set(key, value); }
    return { feasible: true, possible: facts, required: facts };
  };
  const pair = (left: AbstractValue, right: AbstractValue, equals: boolean, depth: number): Projection | undefined => {
    if (!spend(depth) || left.predicateStructureLost || right.predicateStructureLost) return;
    for (const [subject, other] of [[left, right], [right, left]]) {
      const constant = constantOf(other);
      if (constant?.kind === "boolean") return condition(subject, equals === (constant.value === "true"), depth + 1);
    }
    for (const [subject, other] of [[left, right], [right, left]]) if (subject.predicateAlternatives) return merge(
      pair(subject.predicateAlternatives[0], other, equals, depth + 1),
      pair(subject.predicateAlternatives[1], other, equals, depth + 1), true, depth + 1);
    if (left.fields || right.fields || left.items || right.items) {
      let parts: readonly [AbstractValue, AbstractValue][] | undefined;
      if (equals && left.fields && right.fields && Object.keys(left.fields).length === Object.keys(right.fields).length
        && Object.keys(left.fields).every(name => name in right.fields!))
        parts = Object.entries(left.fields).map(([name, part]) => [part, right.fields![name]]);
      if (equals && left.items && right.items && left.items.length === right.items.length)
        parts = left.items.map((part, index) => [part, right.items![index]]);
      if (!parts) return none();
      let result: Projection | undefined = none();
      for (const [a, b] of parts) { result = merge(result, pair(a, b, true, depth + 1), false, depth + 1); if (!result) return; }
      return result;
    }
    return atomic({ left, right, equals }, depth + 1);
  };
  const result = condition(value, truth, 0);
  return result?.feasible ? result : undefined;
}

/** Preserve distinct sources within a history. Cross-history matching is allowed
 * only for a single invocation at this complete call-site chain. Repeated sites
 * (e.g. conditional loop calls) retain their exact IDs instead of guessing which
 * dynamic invocation corresponds to another history. */
export function predicateOperandKey(value: AbstractValue, path: Pick<SuccessfulPath, "witnessCalls">): string | undefined {
  const source = value.flows.find(flow => flow.source.id === value.identity)?.source;
  if (source) return predicateSourceKey(source, path);
  if (value.identity) return value.identity;
  const constant = constantOf(value);
  if (constant) return JSON.stringify([constant.kind, constant.value]);
  const parts = value.fields ? Object.entries(value.fields).sort(([a], [b]) => a.localeCompare(b)).map(([name, part]) => [name, predicateOperandKey(part, path)])
    : value.items?.map((part, index) => [index, predicateOperandKey(part, path)]);
  return parts?.every(([, key]) => key !== undefined) ? JSON.stringify([value.fields ? "fields" : "items", parts]) : valueIdentity(value);
}

export function predicateSourceKey(source: PrivateSource, path: Pick<SuccessfulPath, "witnessCalls">): string {
  return source.invocation && path.witnessCalls?.get(source.invocation.site) === 1
    ? JSON.stringify(["witness", source.invocation.site, source.invocation.leaf]) : source.id;
}

export function rawWitnessSources(value: AbstractValue): PrivateSource[] {
  if (value.negated || value.comparison || value.ordering || value.fields || value.items) return [];
  // Raw taint can describe only a possible value after a storage alias join.
  // Exact source identity is required for a must-equality claim.
  return value.flows.filter(flow => flow.source.kind === "witness" && flow.source.id === value.identity).map(flow => flow.source);
}

export function publicOperand(value: AbstractValue): boolean {
  if (value.fields) return Object.values(value.fields).every(publicOperand);
  if (value.items) return value.items.every(publicOperand);
  return !!constantOf(value) || value.ledger.size > 0;
}

/** A sufficient, deliberately narrow classification of enforced checks.
 * Unlike publicOperand (may-dependency evidence), a public side here must have
 * no private dependencies. Unclassified conditions never certify a sole gate. */
export function rawPublicPredicate(value: AbstractValue, truth: boolean): { allowed: boolean; complete: boolean; work: number } {
  let work = 0, complete = true;
  const charge = (depth: number): boolean => {
    if (++work > 4096 || depth > 64) { complete = false; return false; }
    return true;
  };
  const condition = (value: AbstractValue, truth: boolean, depth: number): boolean => {
    if (!charge(depth)) return false;
    if (value.constantKind === "boolean" && value.constant !== undefined) return value.constant === String(truth);
    if (value.negated) return condition(value.negated, !truth, depth + 1);
    if (value.comparison) {
      const { left, right, operator } = value.comparison;
      return pair(left, right, operator === "==" ? truth : !truth, depth + 1);
    }
    return value.type === "Boolean" && rawWitnessSources(value).length > 0
      && !value.collectionPredicate && !value.listPredicate && !value.merklePredicate;
  };
  const pair = (left: AbstractValue, right: AbstractValue, equals: boolean, depth: number): boolean => {
    if (!charge(depth)) return false;
    if (left.fields || right.fields) return equals && !!left.fields && !!right.fields
      && Object.keys(left.fields).length === Object.keys(right.fields).length
      && Object.entries(left.fields).every(([key, value]) => right.fields![key] && pair(value, right.fields![key], true, depth + 1));
    if (left.items || right.items) return equals && !!left.items && !!right.items && left.items.length === right.items.length
      && left.items.every((value, index) => pair(value, right.items![index], true, depth + 1));
    for (const [subject, other] of [[left, right], [right, left]]) {
      const constant = constantOf(other);
      if (constant?.kind === "boolean") return condition(subject, equals === (constant.value === "true"), depth + 1);
    }
    const a = constantOf(left), b = constantOf(right);
    if (a && b) return equals === (a.kind === b.kind && a.value === b.value);
    return equals && [[left, right], [right, left]].some(([raw, available]) =>
      rawWitnessSources(raw).length > 0 && !available.flows.length && publicOperand(available));
  };
  const allowed = condition(value, truth, 0);
  return { allowed: allowed && complete, complete, work };
}

export interface PredicateEvidence {
  complete: boolean;
  work: number;
  equalities: { predicate: SuccessfulPredicate; equality: EnforcedEquality }[];
  publicValues: Set<string>;
}

/** Required scalar equalities preserve aggregate components and whole-history
 * public knowledge. Terminal scalar constraints are not a substitute: liveness
 * cleanup can discard an earlier aggregate equality that exposed a hash input. */
export function predicateEvidence(path: Pick<SuccessfulPath, "predicates" | "witnessCalls">, allowance: number): PredicateEvidence {
  let work = 0;
  const equalities: PredicateEvidence["equalities"] = [], publicValues = new Set<string>();
  const adjacent = new Map<string, Set<string>>();
  const incomplete = (): PredicateEvidence => ({ complete: false, work, equalities: [], publicValues: new Set() });
  if (!path.predicates) return incomplete();
  for (const predicate of path.predicates) {
    if (++work > allowance) return incomplete();
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) return incomplete();
    for (const equality of decoded.equalities) {
      if (++work > allowance) return incomplete();
      equalities.push({ predicate, equality });
      if (!equality.equals) continue;
      const first = predicateOperandKey(equality.left, path), second = predicateOperandKey(equality.right, path);
      for (const [value, key] of [[equality.left, first], [equality.right, second]] as const)
        if (key && publicOperand(value)) publicValues.add(key);
      if (first && second) for (const [key, other] of [[first, second], [second, first]]) {
        const neighbors = adjacent.get(key) ?? new Set(); neighbors.add(other); adjacent.set(key, neighbors);
      }
    }
  }
  const pending = [...publicValues];
  for (let index = 0; index < pending.length; index++) for (const other of adjacent.get(pending[index]) ?? []) {
    if (++work > allowance) return incomplete();
    if (!publicValues.has(other)) { publicValues.add(other); pending.push(other); }
  }
  return { complete: true, work, equalities, publicValues };
}

/** A direct private preimage checked against retained preexisting ledger data.
 * Current self-written hashes lack that trusted ledger provenance. */
export function trustedPreimageSources(equality: EnforcedEquality): PrivateSource[] {
  return equality.equals ? [[equality.left, equality.right], [equality.right, equality.left]].flatMap(([hashed, ledger]) =>
    ledger.preexistingLedger?.size && hashed.directHash ? [hashed.directHash.source] : []) : [];
}
