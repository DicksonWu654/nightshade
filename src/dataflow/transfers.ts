import type { AbstractValue, Flow, PrivateSource } from "./index.js";
import type { Span } from "../model.js";
import { binaryConstant, castConstant, type Constant } from "./constants.js";
import { fieldModulus } from "../semantic/fields.js";
import { numericBound } from "../semantic/types.js";
import type { HashRecipes } from "./hash-recipes.js";
import { scalarRelations } from "./scalar-relations.js";
import { payloadDependencies } from "./either-payloads.js";
import { immutableOperandKey } from "./immutable-key.js";
import { transientDependencies } from "./transient-origins.js";

/** An effect phase is dependency metadata, never a value identity. */
export function checkpointDependencies(values: AbstractValue[]): Pick<AbstractValue, "proofLedgerEpoch"> {
  let epoch: number | undefined;
  for (const value of values) if (value.proofLedgerEpoch !== undefined) epoch = Math.max(epoch ?? 0, value.proofLedgerEpoch);
  return epoch === undefined ? {} : { proofLedgerEpoch: epoch };
}

/** Pure value kernels shared by exact execution and correlated current values. */
function combinedFlows(values: readonly AbstractValue[]): Flow[] {
  // Index the two key components separately. Source identities can contain
  // large call paths; concatenating and rehashing them for each union dominates
  // repeated control transfers. Preserve global first insertion order and the
  // last representative (including its trace), as the former flat Map did.
  const positions = new Map<Flow["form"], Map<string, number>>();
  const result: Flow[] = [];
  for (const value of values) for (const flow of value.flows) {
    let sources = positions.get(flow.form);
    if (!sources) positions.set(flow.form, sources = new Map());
    const position = sources.get(flow.source.id);
    if (position === undefined) {
      sources.set(flow.source.id, result.length);
      result.push(flow);
    } else result[position] = flow;
  }
  return result;
}

export function combine(values: AbstractValue[]): AbstractValue {
  let transient: AbstractValue[] | undefined;
  for (const value of values) {
    if (value.transientOrigins?.length || value.transientOriginsUnavailable) (transient ??= []).push(value);
  }
  return { ...(transient ? transientDependencies(transient) : {}), ...checkpointDependencies(values), ...payloadDependencies(values), ...(values.some(value => value.eitherLogicalGate) ? { eitherLogicalGate: true as const } : {}), ...(values.some(value => value.predicateStructureLost || value.predicateHasAlternatives || value.predicateAlternatives) ? { predicateStructureLost: true as const } : {}),
    ...(values.some(value => value.predicateHasAlternatives || value.predicateAlternatives) ? { predicateHasAlternatives: true as const } : {}), flows: combinedFlows(values), ledger: new Set(values.flatMap(value => [...value.ledger])), commitments: [...new Set(values.flatMap(value => value.commitments ?? []))] };
}
export function step(value: AbstractValue, kind: string, label: string, location: Span, form?: Flow["form"]): AbstractValue {
  return { ...value, ...(form && (value.enrollmentSignatureOutcome || value.enrollmentConjunctionInputs) ? { enrollmentSignatureOutcome: undefined, enrollmentConjunctionInputs: undefined } : {}), ...(form && value.kernelSelf ? { kernelSelf: undefined } : {}), ...(form && value.pointIdentityExcluded ? { pointIdentityExcluded: undefined } : {}), ...(form && (value.pointIdentityInput || value.pointIdentityEvidenceLost) ? { pointIdentityInput: undefined, pointIdentityDepth: undefined, pointIdentityEvidenceLost: undefined } : {}), ...(form && (value.listLengthSnapshot || value.listLengthEncoding) ? { listLengthSnapshot: undefined, listLengthEncoding: undefined } : {}), ...(form && (value.nonceEvolution || value.mintSnapshot || value.numericExpression || value.mapDebitLookupOrigin) ? { nonceEvolution: undefined, mintSnapshot: undefined, numericExpression: undefined, mapDebitLookupOrigin: undefined } : {}), ...(form && (value.directHash || value.directDigest || value.directCommit || value.preexistingLedger || value.summarizedMerkleHash) ? { directHash: undefined, directDigest: undefined, directCommit: undefined, preexistingLedger: undefined, summarizedMerkleHash: undefined } : {}), ...(form && (value.fieldArithmetic || value.integerRange || value.uintOrigin) ? { fieldArithmetic: undefined, integerRange: undefined, uintOrigin: undefined } : {}), flows: value.flows.map(flow => ({ ...flow, form: form ?? flow.form, trace: [...flow.trace, { kind, label, location }] })),
    items: value.items?.map(item => step(item, kind, label, location, form)),
    fields: value.fields ? Object.fromEntries(Object.entries(value.fields).map(([name, field]) => [name, step(field, kind, label, location, form)])) : undefined };
}

/** Per-analysis unions of immutable control operands. Validate the entire
 * ordered prefix: a shared final operand cannot identify sibling contexts. */
export class ControlDependencies {
  private readonly latest = new WeakMap<AbstractValue, { inputs: AbstractValue[]; value: AbstractValue }>();

  combine(controls: AbstractValue[]): AbstractValue {
    const last = controls.at(-1);
    if (!last) return combine(controls);
    const previous = this.latest.get(last);
    if (previous && previous.inputs.length === controls.length && previous.inputs.every((value, index) => value === controls[index])) return previous.value;
    const value = combine(controls);
    this.latest.set(last, { inputs: controls.slice(), value });
    return value;
  }
}

export function controlled(value: AbstractValue, controls: AbstractValue[], location: Span, force = false, dependencies?: ControlDependencies): AbstractValue {
  if (!controls.length || !force && value.items?.length === 0) return value;
  const implicit = step(dependencies ? dependencies.combine(controls) : combine(controls), "implicit-flow", "private-dependent control flow", location, "derived");
  const apply = (current: AbstractValue): AbstractValue => ({ ...current, ...checkpointDependencies([current, implicit]), ...payloadDependencies([current, implicit]), flows: combinedFlows([current, implicit]),
    fields: current.fields ? Object.fromEntries(Object.entries(current.fields).map(([name, field]) => [name, apply(field)])) : undefined,
    items: current.items?.map(apply) });
  return apply(value);
}
export const constantOf = (value: AbstractValue): Constant | undefined => value.constant !== undefined && value.constantKind ? { kind: value.constantKind, value: value.constant } : undefined;

/** Exact hash inputs may add public context or repeat one private source.
 * Dependency unions cannot establish this relationship. Charge expanded nodes,
 * including repeated DAG edges, and never return partial origin evidence. */
export function directPreimageSource(value: AbstractValue, maxWork = 4096): { complete: boolean; work: number; source?: PrivateSource } {
  let work = 0, exhausted = false;
  let source: PrivateSource | undefined;
  const visit = (part: AbstractValue, depth: number): boolean => {
    if (++work > Math.min(maxWork, 4096) || depth > 64) { exhausted = true; return false; }
    if (constantOf(part)) return true;
    if (part.fields) return Object.values(part.fields).every(child => visit(child, depth + 1));
    if (part.items) return part.items.every(child => visit(child, depth + 1));
    // Public ledger/native values and expressions over them need not be
    // constant, nor retain a ledger identity after casts. Their lack of private
    // dependencies makes them public context, not another secret ingredient.
    // Traverse aggregates first so a dependency union cannot hide private leaves.
    if (!part.flows.length) return true;
    if (part.negated || part.comparison || part.ordering) return false;
    const exact = part.flows.find(flow => flow.form === "raw" && flow.source.id === part.identity)?.source;
    if (!exact || source && source.id !== exact.id) return false;
    source = exact;
    return true;
  };
  const exact = visit(value, 0);
  return { complete: !exhausted, work, ...(exact && source ? { source } : {}) };
}

export function counterMutation(previous: AbstractValue, amount: AbstractValue, operator: string, location: Span): AbstractValue | undefined {
  const value = step(combine([previous, amount]), "ledger-mutation", operator === "+" ? "increment" : "decrement", location, "derived");
  const computed = binaryConstant(operator, constantOf(previous), constantOf(amount), "Uint<64>");
  if (computed === null) return undefined;
  const constant = computed && castConstant(computed, "Uint<64>");
  if (constant === null) return undefined;
  // A zero update preserves immutable contents, even when they are unknown.
  // Keep the mutation trace; the storage transfer still records a write,
  // advances its revision and invalidates guards independently of this identity.
  const fixed = amount.constantKind === "integer" && amount.constant !== undefined;
  const unchanged = fixed && amount.constant === "0";
  const base = previous.counterOffset ?? (previous.identity ? { identity: previous.identity, offset: "0" } : undefined);
  // On successful checked updates, +n followed by -n restores the original
  // contents. Retain only a bounded scalar offset, never an expression/history.
  const offset = !constant && fixed && base
    ? BigInt(base.offset) + (operator === "+" ? 1n : -1n) * BigInt(amount.constant!) : undefined;
  const counterOffset = offset !== undefined && offset > -(1n << 64n) && offset < (1n << 64n)
    ? { identity: base!.identity, offset: String(offset) } : undefined;
  return { ...value, type: previous.type,
    identity: unchanged ? previous.identity : counterOffset?.offset === "0" ? counterOffset.identity : undefined,
    ...(counterOffset ? { counterOffset } : {}),
    constant: constant?.value, constantKind: constant?.kind };
}

export interface ScalarConstraints {
  /** Optional selected-pass meter; ordinary transfer costs remain unchanged. */
  scalarMeter?: (work: number, values: number) => void;
  /** Shared immutable recipe definitions; constraints remain owned by each state. */
  hashRecipes?: HashRecipes;
  known: Map<string, Constant>;
  truths: Map<string, boolean>;
  excluded: Map<string, Set<string>>;
  /** Each immutable conjunction is forbidden; individual fields may still equal their constants. */
  aggregateExclusions: Map<string, readonly (readonly [string, Constant])[]>;
  aggregateExclusionLeaves: number;
  aggregateExclusionsExhausted: boolean;
  /** Successful checked-cast domains for exact immutable numeric results. */
  integerDomains?: Map<string, { minimum: string; maximum: string }>;
  orderings?: Map<string, { predicate: NonNullable<AbstractValue["ordering"]>; truth: boolean }>;
  orderingsExhausted?: boolean;
  scalarEqualities?: Map<string, { left: AbstractValue; right: AbstractValue; equals: boolean }>;
  scalarEqualitiesExhausted?: boolean;
}

/** A bounded conjunction domain, separate from expression/value expansion. */
export const MAX_AGGREGATE_EXCLUSION_LEAVES = 1024;
export const MAX_ORDERED_PREDICATES = 256;

function aggregateKey(value: AbstractValue, key: (part: AbstractValue) => string | undefined, state?: ScalarConstraints): string | undefined {
  let fields = 0;
  if (state?.scalarMeter) for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { state.scalarMeter(1, 0); fields++; }
  state?.scalarMeter?.(1 + fields * Math.ceil(Math.log2(fields + 1)), 3 + fields * 6 + (value.items?.length ?? 0) * 4);
  const parts = value.fields ? Object.entries(value.fields).sort(([a], [b]) => a.localeCompare(b)).map(([name, part]) => [name, key(part)] as const)
    : value.items?.map((part, index) => [index, key(part)] as const);
  if (state?.scalarMeter && parts) {
    let units = 2;
    for (const [name, part] of parts) { state.scalarMeter(1, 0); units += Math.ceil((String(name).length + (part?.length ?? 0)) / 64); }
    state.scalarMeter(1, units);
  }
  return parts?.every(([, value]) => value !== undefined) ? `${value.fields ? "fields" : "items"}:${JSON.stringify(parts)}` : undefined;
}

/** Structural keys describe immutable values, never a wildcard storage region. */
export function valueIdentity(value: AbstractValue, state?: ScalarConstraints): string | undefined {
  state?.scalarMeter?.(1, 1 + Math.ceil((value.identity?.length ?? 0) / 64));
  return value.identity ?? aggregateKey(value, part => valueIdentity(part, state) ?? constantKey(part, state), state);
}
function constantKey(value: AbstractValue, state?: ScalarConstraints): string | undefined {
  state?.scalarMeter?.(1, 2 + Math.ceil((value.constant?.length ?? 0) / 64));
  const constant = constantOf(value);
  return constant ? `${constant.kind}:${constant.value}` : aggregateKey(value, part => constantKey(part, state), state);
}

/** Retain only scalar identities and constants, never values with histories or live regions. */
function excludeAggregate(subject: AbstractValue, counterpart: AbstractValue, state: ScalarConstraints): void {
  if (!subject.fields && !subject.items) return;
  const leaves: [string, Constant][] = [];
  const collect = (value: AbstractValue, other: AbstractValue): boolean => {
    let fields = 0;
    if (state.scalarMeter) for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { state.scalarMeter(1, 0); fields++; }
    if (state.scalarMeter) for (const name in other.fields) if (Object.hasOwn(other.fields, name)) { state.scalarMeter(1, 0); fields++; }
    state.scalarMeter?.(1, 4 + fields * 6 + (value.items?.length ?? 0) * 2);
    const constant = constantOf(other), actual = constantOf(refineScalar(value, state));
    if (constant) {
      if (actual) return actual.kind === constant.kind && actual.value === constant.value;
      if (!value.identity) return false;
      if (leaves.length >= MAX_AGGREGATE_EXCLUSION_LEAVES) {
        state.aggregateExclusionsExhausted = true;
        return false;
      }
      state.scalarMeter?.(1, 3); leaves.push([value.identity, constant]);
      return true;
    }
    if (value.fields && other.fields && Object.keys(value.fields).length === Object.keys(other.fields).length && Object.keys(value.fields).every(name => name in other.fields!))
      return Object.entries(value.fields).every(([name, part]) => collect(part, other.fields![name]));
    if (value.items && other.items && value.items.length === other.items.length)
      return value.items.every((part, index) => collect(part, other.items![index]));
    return false;
  };
  if (collect(subject, counterpart)) {
    state.scalarMeter?.(1 + leaves.length * Math.ceil(Math.log2(leaves.length + 1)), 3 + leaves.length * 8);
    leaves.sort(([a], [b]) => a.localeCompare(b));
    const key = JSON.stringify(leaves);
    if (!state.aggregateExclusions.has(key)) {
      if (state.aggregateExclusionLeaves + leaves.length > MAX_AGGREGATE_EXCLUSION_LEAVES) state.aggregateExclusionsExhausted = true;
      else {
        state.aggregateExclusions.set(key, leaves);
        state.aggregateExclusionLeaves += leaves.length;
      }
    }
  }
}

function consistentAggregates(state: ScalarConstraints): boolean {
  state.scalarMeter?.(1 + state.aggregateExclusionLeaves, 0);
  for (const leaves of state.aggregateExclusions.values()) {
    if (leaves.every(([identity, expected]) => {
      const actual = state.known.get(identity);
      return actual?.kind === expected.kind && actual.value === expected.value;
    })) return false;
  }
  return true;
}

export function refineScalar(value: AbstractValue, state: ScalarConstraints): AbstractValue {
  state.scalarMeter?.(1, 2);
  value = state.hashRecipes?.refine(value, state) ?? value;
  if (value.ordering) {
    const known = orderedConstant(value.ordering, state);
    if (typeof known === "boolean") return { ...value, constant: String(known), constantKind: "boolean" };
  }
  if (value.comparison) {
    const { left, right, operator } = value.comparison;
    const first = refineScalar(left, state), second = refineScalar(right, state);
    const equality = aggregateEquality(first, second, state) ?? (state.scalarEqualities?.size
      ? relationEquality(first, second, scalarRelations(state).equality, state) : undefined);
    if (equality !== undefined) return { ...value, constant: String(operator === "==" ? equality : !equality), constantKind: "boolean" };
  }
  if (value.identity) {
    const known = state.known.get(value.identity);
    if (known) return { ...value, constant: known.value, constantKind: known.kind };
    const truth = state.truths.get(value.identity);
    if (truth !== undefined) return { ...value, constant: String(truth), constantKind: "boolean" };
  }
  if (value.comparison) {
    const { left, right, operator } = value.comparison;
    for (const [subject, counterpart] of [[left, right], [right, left]]) {
      const identity = valueIdentity(subject, state), key = constantKey(counterpart, state);
      if (identity && key && state.excluded.get(identity)?.has(key)) return { ...value, constant: String(operator !== "=="), constantKind: "boolean" };
    }
  }
  return value;
}

function relationEquality(left: AbstractValue, right: AbstractValue, scalar: (left: AbstractValue, right: AbstractValue) => boolean | undefined, state?: ScalarConstraints): boolean | undefined {
  let fields = 0;
  if (state?.scalarMeter) for (const name in left.fields) if (Object.hasOwn(left.fields, name)) { state.scalarMeter(1, 0); fields++; }
  if (state?.scalarMeter) for (const name in right.fields) if (Object.hasOwn(right.fields, name)) { state.scalarMeter(1, 0); fields++; }
  state?.scalarMeter?.(1, 4 + (left.items?.length ?? 0) * 4 + fields * 6);
  const known = aggregateEquality(left, right, state) ?? scalar(left, right);
  if (known !== undefined) return known;
  const pairs = left.items && right.items && left.items.length === right.items.length ? left.items.map((value, index) => [value, right.items![index]])
    : left.fields && right.fields && Object.keys(left.fields).length === Object.keys(right.fields).length && Object.keys(left.fields).every(key => key in right.fields!)
      ? Object.entries(left.fields).map(([key, value]) => [value, right.fields![key]]) : undefined;
  if (!pairs) return;
  const results = pairs.map(([a, b]) => relationEquality(a, b, scalar, state));
  return results.some(result => result === false) ? false : results.every(result => result === true) ? true : undefined;
}

/** Intersect retained integer comparisons for one immutable operand. */
export function orderedBounds(value: AbstractValue, state: ScalarConstraints, lower: bigint, upper: bigint, numericType?: string): { minimum: bigint; maximum: bigint } | null {
  state.scalarMeter?.(1, 3);
  const relations = state.scalarEqualities?.size ? scalarRelations(state) : undefined;
  const key = (value: AbstractValue) => relations ? relations.identity(value) : constrainedIdentity(value, state);
  const identity = key(value);
  for (const { predicate: other, truth } of state.orderings?.values() ?? []) {
    state.scalarMeter?.(1, 1);
    if (!identity || numericType && other.numericType !== numericType
      && !(numericBound(numericType) !== undefined && numericBound(other.numericType) !== undefined)) continue;
    const reversed = key(other.right) === identity;
    if (!reversed && key(other.left) !== identity) continue;
    const constant = constantOf(refineScalar(reversed ? other.left : other.right, state));
    if (constant?.kind !== "integer") continue;
    const bound = BigInt(constant.value), operator = reversed
      ? ({ "<": ">", "<=": ">=", ">": "<", ">=": "<=" } as Record<string, string>)[other.operator] : other.operator;
    const atMost = operator === "<=" && truth || operator === ">" && !truth;
    const below = operator === "<" && truth || operator === ">=" && !truth;
    const limit = bound + (atMost ? 0n : below ? -1n : operator === ">=" && truth || operator === "<" && !truth ? 0n : 1n);
    if (atMost || below) upper = limit < upper ? limit : upper;
    else lower = limit > lower ? limit : lower;
  }
  const refined = refineScalar(value, state);
  if (refined.constantKind === "integer" && refined.constant !== undefined) {
    const scalar = BigInt(refined.constant);
    if (scalar < lower || scalar > upper) return null;
    lower = upper = scalar;
  }
  return lower > upper ? null : { minimum: lower, maximum: upper };
}

function constrainedIdentity(value: AbstractValue, state: ScalarConstraints): string | undefined {
  return valueIdentity(state.hashRecipes?.refine(value, state) ?? value, state);
}

/** Intersect comparisons of the same immutable operand pair (including
 * reversed operands and scalar aliases). This is a bounded three-way order,
 * not transitive relational solving across arbitrary operands. */
function orderedPair(predicate: NonNullable<AbstractValue["ordering"]>, state: ScalarConstraints): boolean | undefined | null {
  return pairOrder(predicate, state, true);
}

/** Compare the same immutable unsigned integer operands across value-preserving
 * casts. Uses actual retained orders only; never invents Field order syntax,
 * a numeric cast, or transitive inequalities between other operands. */
export function immutableIntegerOrder(left: AbstractValue, right: AbstractValue, operator: string, state: ScalarConstraints): boolean | undefined | null {
  const a = refineScalar(left, state), b = refineScalar(right, state);
  if (a.constantKind === "integer" && b.constantKind === "integer" && a.constant !== undefined && b.constant !== undefined) {
    const x = BigInt(a.constant), y = BigInt(b.constant);
    return operator === ">=" ? x >= y : operator === "<=" ? x <= y : operator === ">" ? x > y : operator === "<" ? x < y : undefined;
  }
  const equality = state.scalarEqualities?.size ? scalarRelations(state).equality(left,right) : valueIdentity(left) && valueIdentity(left) === valueIdentity(right) ? true : undefined;
  if (equality === true) return operator === ">=" || operator === "<=";
  return pairOrder({ left, right, operator, numericType: "" }, state, false);
}

function pairOrder(predicate: NonNullable<AbstractValue["ordering"]>, state: ScalarConstraints, requireCompatibleType: boolean): boolean | undefined | null {
  state.scalarMeter?.(1, 4);
  if (!state.orderings?.size) return;
  const masks: Record<string, number> = { "<": 1, "<=": 3, ">": 4, ">=": 6 };
  const wanted = masks[predicate.operator];
  if (wanted === undefined) return;
  const relations = state.scalarEqualities?.size ? scalarRelations(state) : undefined;
  const key = (value: AbstractValue): string | undefined => {
    const identity = relations ? relations.identity(value) : constrainedIdentity(value, state);
    const constant = constantOf(value);
    return identity ? `operand:${identity}` : constant ? `constant:${constant.kind}:${constant.value}` : undefined;
  };
  const left = key(predicate.left), right = key(predicate.right);
  if (!left || !right) return;
  let possible = relations?.equality(predicate.left, predicate.right) === false ? 5 : 7;
  for (const { predicate: other, truth } of state.orderings.values()) {
    state.scalarMeter?.(1, 4);
    if (requireCompatibleType ? other.numericType !== predicate.numericType
      && !(numericBound(other.numericType) !== undefined && numericBound(predicate.numericType) !== undefined)
      : numericBound(other.numericType) === undefined && fieldModulus(other.numericType) === undefined) continue;
    let mask = masks[other.operator];
    if (mask === undefined) continue;
    const a = key(other.left), b = key(other.right);
    if (left === a && right === b) { /* same orientation */ }
    else if (left === b && right === a) mask = (mask & 1) << 2 | mask & 2 | (mask & 4) >> 2;
    else continue;
    possible &= truth ? mask : 7 ^ mask;
  }
  if (!possible) return null;
  return !(possible & wanted) ? false : !(possible & (7 ^ wanted)) ? true : undefined;
}

/** This bounded transfer only relates a native scalar's exact 32-byte encoding
 * to constant thresholds. It does not introduce general relational solving. */
function encodingBounds(predicate: NonNullable<AbstractValue["ordering"]>, state: ScalarConstraints): { minimum: bigint; maximum: bigint } | null {
  state.scalarMeter?.(1, 1);
  const bytes = predicate.leftBytes!;
  const scalarBounds = orderedBounds(predicate.left, state, 0n, fieldModulus(predicate.numericType)! - 1n, predicate.numericType);
  if (!scalarBounds) return null;
  const domains: { minimum: number; maximum: number; excluded?: Set<string> }[] = [];
  for (const value of bytes) {
    state.scalarMeter?.(1, 2);
    const bounds = orderedBounds(value, state, 0n, 255n);
    if (!bounds) return null;
    domains.push({ minimum: Number(bounds.minimum), maximum: Number(bounds.maximum),
      excluded: state.excluded.get(constrainedIdentity(value, state) ?? "") });
  }
  // At most two memoized states per byte, each considering at most 256 values.
  // This finds actual allowed extrema, including holes from byte exclusions.
  const extremum = (bound: bigint, ascending: boolean): bigint | undefined => {
    state.scalarMeter?.(1, 1); const memo = new Map<number, bigint | undefined>();
    const visit = (index: number, tight: boolean): bigint | undefined => {
      state.scalarMeter?.(1, 1);
      if (index < 0) return 0n;
      const key = index * 2 + Number(tight);
      if (memo.has(key)) return memo.get(key);
      const digit = Number(bound >> BigInt(8 * index) & 255n), domain = domains[index];
      for (let value = tight ? digit : ascending ? 0 : 255; value >= 0 && value <= 255; value += ascending ? 1 : -1) {
        state.scalarMeter?.(1, 0);
        if (value < domain.minimum || value > domain.maximum || domain.excluded?.has(`integer:${value}`)) continue;
        const suffix = visit(index - 1, tight && value === digit);
        if (suffix !== undefined) {
          const result = BigInt(value) << BigInt(8 * index) | suffix;
          memo.set(key, result); return result;
        }
      }
      memo.set(key, undefined); return undefined;
    };
    return visit(bytes.length - 1, true);
  };
  const minimum = extremum(scalarBounds.minimum, true), maximum = extremum(scalarBounds.maximum, false);
  return minimum === undefined || maximum === undefined || minimum > maximum ? null : { minimum, maximum };
}

/** null denotes contradictory representations of the same immutable operand. */
function orderedConstant(predicate: NonNullable<AbstractValue["ordering"]>, state: ScalarConstraints): boolean | undefined | null {
  state.scalarMeter?.(1, 2);
  const left = refineScalar(predicate.left, state), right = refineScalar(predicate.right, state);
  if (predicate.leftBytes && right.constantKind === "integer" && right.constant !== undefined) {
    const bounds = encodingBounds(predicate, state);
    if (!bounds) return null;
    // The bound is an unsigned integer threshold; never reduce it modulo the
    // native scalar field, even when it exceeds the field's maximum value.
    const result = (value: bigint) => binaryConstant(predicate.operator, { kind: "integer", value: String(value) }, constantOf(right), predicate.numericType)!;
    const lower = result(bounds.minimum), upper = result(bounds.maximum);
    return lower.value === upper.value ? lower.value === "true" : undefined;
  }
  if (left.identity && left.identity === right.identity || state.scalarEqualities?.size && scalarRelations(state).equality(left, right) === true) return ["<=", ">="].includes(predicate.operator);
  // Ordinary unsigned guards also share these retained bounds. Previously the
  // intersection was consulted only for native byte/scalar folds, admitting
  // contradictory histories such as amount > 0 followed by 0 >= amount.
  const bound = numericBound(predicate.numericType);
  if (bound !== undefined) {
    const first = orderedBounds(predicate.left, state, 0n, bound - 1n, predicate.numericType);
    const second = orderedBounds(predicate.right, state, 0n, bound - 1n, predicate.numericType);
    if (!first || !second) return null;
    const less = ["<", "<="].includes(predicate.operator), inclusive = ["<=", ">="].includes(predicate.operator);
    const a = less ? first : second, b = less ? second : first;
    if (inclusive ? a.maximum <= b.minimum : a.maximum < b.minimum) return true;
    if (inclusive ? a.minimum > b.maximum : a.minimum >= b.maximum) return false;
  }
  const result = binaryConstant(predicate.operator, constantOf(left), constantOf(right), predicate.numericType);
  return result?.kind === "boolean" ? result.value === "true" : orderedPair(predicate, state);
}

function consistentOrderings(state: ScalarConstraints): boolean {
  let changed: boolean;
  do {
    changed = false;
    for (const { predicate, truth } of state.orderings?.values() ?? []) {
      state.scalarMeter?.(1, 1);
      const actual = orderedConstant(predicate, state);
      if (actual !== undefined && actual !== truth) return false;
      if (!predicate.leftBytes) continue;
      const bounds = encodingBounds(predicate, state);
      if (!bounds) return false;
      const remember = (value: AbstractValue, constant: bigint): boolean => {
        const identity = constrainedIdentity(value, state), text = String(constant);
        if (!identity) return true;
        const known = state.known.get(identity);
        if (known && (known.kind !== "integer" || known.value !== text) || state.excluded.get(identity)?.has(`integer:${text}`)) return false;
        if (!known) { state.known.set(identity, { kind: "integer", value: text }); state.hashRecipes?.invalidate(state, identity); changed = true; }
        return true;
      };
      if (bounds.minimum === bounds.maximum && !remember(predicate.left, bounds.minimum)) return false;
      for (let index = 0; index < predicate.leftBytes.length; index++) {
        state.scalarMeter?.(1, 2);
        const shift = BigInt(8 * index);
        if (bounds.minimum >> shift === bounds.maximum >> shift && !remember(predicate.leftBytes[index], bounds.minimum >> shift & 255n)) return false;
      }
    }
  } while (changed); // Monotone: only constants for the bounded retained operands.
  // The relation checks below do not mutate facts. Build one closure for this
  // pass, after ordered constants stabilize, instead of once per retained edge.
  const relations = scalarRelations(state);
  for (const { left, right, equals } of state.scalarEqualities?.values() ?? []) {
    const first = refineScalar(left, state), second = refineScalar(right, state);
    state.scalarMeter?.(1, 2); const actual = relationEquality(first, second, relations.equality, state);
    if (actual !== undefined && actual !== equals) return false;
  }
  return true;
}
export function aggregateEquality(left: AbstractValue, right: AbstractValue, state?: ScalarConstraints): boolean | undefined {
  let fields = 0;
  if (state?.scalarMeter) for (const key in left.fields) if (Object.hasOwn(left.fields, key)) { state.scalarMeter(1, 0); fields++; }
  if (state?.scalarMeter) for (const key in right.fields) if (Object.hasOwn(right.fields, key)) { state.scalarMeter(1, 0); fields++; }
  state?.scalarMeter?.(1, 2 + fields * 6 + (left.items?.length ?? 0) * 3);
  const first = constantOf(left), second = constantOf(right);
  if (first && second) return first.kind === second.kind && first.value === second.value;
  if (left.identity && left.identity === right.identity) return true;
  let comparisons: (boolean | undefined)[];
  if (left.items && right.items && left.items.length === right.items.length) comparisons = left.items.map((item, index) => aggregateEquality(item, right.items![index], state));
  else if (left.fields && right.fields && Object.keys(left.fields).length === Object.keys(right.fields).length && Object.keys(left.fields).every(name => name in right.fields!)) comparisons = Object.entries(left.fields).map(([name, field]) => aggregateEquality(field, right.fields![name], state));
  else return undefined;
  return comparisons.some(result => result === false) ? false : comparisons.every(result => result === true) ? true : undefined;
}

/** Mutates caller-owned facts. Collection/List refinement stays at the owning
 * engine through the hook, including recursive negation and Boolean comparison.
 */
export function assumeScalar(value: AbstractValue, truth: boolean, state: ScalarConstraints, special: (value: AbstractValue, truth: boolean) => boolean = () => true): boolean {
  state.scalarMeter?.(1, 16);
  if (value.ordering && orderedConstant(value.ordering, state) === null) return false;
  const refined = refineScalar(value, state);
  if (refined.constantKind === "boolean" && refined.constant !== undefined && refined.constant !== String(truth)) return false;
  // Mark the predicate before recursively applying its operands. Alias
  // propagation can revisit the same predicate while that transfer is active.
  if (value.identity) {
    if (state.excluded.get(value.identity)?.has(`boolean:${truth}`)) return false;
    const previous = state.truths.get(value.identity);
    if (previous !== undefined && previous !== truth) return false;
    state.truths.set(value.identity, truth);
    state.known.set(value.identity, { kind: "boolean", value: String(truth) });
    state.hashRecipes?.invalidate(state, value.identity);
  }
  if (value.negated && !assumeScalar(value.negated, !truth, state, special)) return false;
  if (!special(value, truth)) return false;
  if (value.ordering && value.identity) {
    const orderings = state.orderings ??= new Map();
    const previous = orderings.get(value.identity);
    if (previous && previous.truth !== truth) return false;
    if (!previous && orderings.size >= MAX_ORDERED_PREDICATES) state.orderingsExhausted = true;
    else orderings.set(value.identity, { predicate: value.ordering, truth });
  }
  if (value.comparison) {
    const { operator, left, right } = value.comparison, equals = operator === "==" ? truth : !truth;
    state.scalarMeter?.(1, 4 + Math.ceil(((left.identity?.length ?? 0) + (right.identity?.length ?? 0)) / 64));
    const equality = aggregateEquality(refineScalar(left, state), refineScalar(right, state), state);
    if (equality !== undefined && equality !== equals) return false;
    // Retain a scalar relation when neither operand supplies a constant. Later
    // caller constraints can make an earlier equality/disequality impossible.
    const recipeRelation = state.hashRecipes && (state.hashRecipes.contains(left) || state.hashRecipes.contains(right))
      ? state.hashRecipes.relationKey(left, right, equals) : undefined;
    let relation = recipeRelation ?? (left.identity && right.identity && !left.items && !left.fields && !right.items && !right.fields
      && !constantOf(left) && !constantOf(right) ? `scalar-relation:${equals}:${JSON.stringify([left.identity, right.identity].sort())}` : undefined);
    // A disequal aggregate forbids all corresponding leaves being equal; it
    // must not become individual leaf disequalities or disappear before aliases
    // are established later. Positive aggregates use the leaf transfers below.
    if (!relation && !equals && (left.items || left.fields) && (right.items || right.fields)) {
      // Traverse represented leaves even when their containers have identities;
      // the retained compound relation will later compare those leaves.
      const first = immutableOperandKey(left, MAX_AGGREGATE_EXCLUSION_LEAVES, key => key, state.scalarMeter ? (work, values) => { state.scalarMeter!(work, values); return true; } : undefined);
      const second = immutableOperandKey(right, Math.max(0, MAX_AGGREGATE_EXCLUSION_LEAVES - first.work), key => key, state.scalarMeter ? (work, values) => { state.scalarMeter!(work, values); return true; } : undefined);
      state.scalarEqualities ??= new Map();
      if (!first.complete || !second.complete) state.scalarEqualitiesExhausted = true;
      else if (first.key && second.key) relation = `aggregate-relation:${JSON.stringify([first.key, second.key].sort())}`;
    }
    if (relation) {
      const relations = state.scalarEqualities ??= new Map();
      if (!relations.has(relation) && relations.size >= MAX_ORDERED_PREDICATES) state.scalarEqualitiesExhausted = true;
      else relations.set(relation, { left, right, equals });
    }
    for (const [subject, counterpart] of [[left, right], [right, left]]) {
      const other = refineScalar(counterpart, state), constant = constantOf(other);
      const identity = valueIdentity(subject, state), key = constantKey(other, state);
      if (!identity || !key) continue;
      let listSubject = subject;
      while (listSubject.negated) listSubject = listSubject.negated;
      if ((subject.collectionPredicate || listSubject.merklePredicate || listSubject.listPredicate || listSubject.ordering || listSubject.comparison) && constant?.kind === "boolean" && !assumeScalar(subject, equals ? constant.value === "true" : constant.value !== "true", state, special)) return false;
      const excluded = state.excluded.get(identity) ?? new Set<string>();
      if (equals) {
        if (excluded.has(key)) return false;
        if (constant) { state.known.set(identity, constant); state.hashRecipes?.invalidate(state, identity); }
      } else {
        excluded.add(key); state.excluded.set(identity, excluded);
        excludeAggregate(subject, other, state);
      }
    }
    // Equal aggregates have equal corresponding fields. An unequal aggregate
    // need only differ in one field: retain that exclusion as a whole value.
    if (equals) {
      let fields = 0;
      if (state.scalarMeter) for (const name in left.fields) if (Object.hasOwn(left.fields, name)) { state.scalarMeter(1, 0); fields++; }
      state.scalarMeter?.(1, 2 + fields * 5 + (left.items?.length ?? 0) * 4);
      const pairs = left.fields && right.fields && Object.keys(left.fields).every(name => name in right.fields!)
        ? Object.entries(left.fields).map(([name, field]) => [field, right.fields![name]])
        : left.items && right.items && left.items.length === right.items.length ? left.items.map((item, index) => [item, right.items![index]]) : [];
      for (const [first, second] of pairs) if (!assumeScalar({ flows: [], ledger: new Set(), comparison: { operator: "==", left: first, right: second } }, true, state, special)) return false;
    }
  }
  // Constants move monotonically through scalar aliases and selected recipe
  // arms. Recheck all domains until stable; saturation stays explicitly incomplete.
  for (let round = 0; round < MAX_ORDERED_PREDICATES; round++) {
    state.scalarMeter?.(1, 0);
    const before = state.known.size;
    const relations = scalarRelations(state);
    if (!relations.consistent) return false;
    relations.propagate();
    // A Boolean alias carries the original predicate, not just its constant.
    // Apply it through the ordinary transfer/hook once its truth is established.
    for (const { left, right } of state.scalarEqualities?.values() ?? []) {
      state.scalarMeter?.(1, 2);
      for (const operand of [left, right]) {
      if (!operand.identity || !(operand.comparison || operand.ordering || operand.negated || operand.collectionPredicate || operand.merklePredicate || operand.listPredicate)) continue;
      const known = state.known.get(operand.identity);
      if (known?.kind === "boolean" && state.truths.get(operand.identity) !== (known.value === "true")
        && !assumeScalar(operand, known.value === "true", state, special)) return false;
    }
    }
    if (!(state.hashRecipes?.consistent(state) ?? true) || !consistentOrderings(state) || !consistentAggregates(state)) return false;
    if (state.known.size === before) return true;
  }
  state.scalarEqualitiesExhausted = true;
  return true;
}

export function binaryValue(values: AbstractValue[], operator: string, location: Span, numericType: string, checkedArithmetic = false): AbstractValue | undefined {
  const value = step(combine(values), "expression", operator, location, "derived");
  value.ledger = new Set();
  if (operator === "==") {
    value.equalities = [];
    for (const [hashed, ledger] of [[values[0], values[1]], [values[1], values[0]]]) {
      for (const flow of hashed.flows.filter(item => item.form === "hash" && item.directPreimage)) {
        // A dependency union is not proof of a definite preexisting digest.
        if (hashed.directHash?.source.id !== flow.source.id) continue;
        for (const stateId of ledger.preexistingLedger ?? []) value.equalities.push({ source: flow.source, ledger: stateId, location, trace: flow.trace });
      }
    }
  }
  let constant = binaryConstant(operator, constantOf(values[0]), constantOf(values[1]), numericType);
  if (constant && checkedArithmetic) constant = castConstant(constant, numericType);
  if (constant === null) return undefined;
  value.constant = constant?.value; value.constantKind = constant?.kind;
  if (["==", "!="].includes(operator)) {
    value.comparison = { operator, left: values[0], right: values[1] };
    // Both exact operand trees remain available to predicate projection.
    delete value.predicateStructureLost;
    const identities = values.map(item => { const constant = constantOf(item); return constant ? `${constant.kind}:${constant.value}` : item.identity; });
    if (identities.every(Boolean)) value.identity = `${operator}:${JSON.stringify(identities.sort())}`;
    const equality = aggregateEquality(values[0], values[1]);
    if (equality !== undefined) { value.constant = String(operator === "==" ? equality : !equality); value.constantKind = "boolean"; }
  }
  if (["<", "<=", ">", ">="].includes(operator)) {
    value.ordering = { operator, left: values[0], right: values[1], numericType };
    const identities = values.map(item => valueIdentity(item) ?? constantKey(item));
    // Ordered operands must never use the commutative equality key.
    if (identities.every(Boolean)) value.identity = `ordered:${numericType}:${operator}:${JSON.stringify(identities)}`;
  }
  return value;
}
/** Values have already been evaluated in CFG/source order; a single input is
 * the skipped RHS arm. This transfer must not evaluate either operand itself. */
export function logicalValue(values: AbstractValue[], operator: string, selected: boolean, location: Span): AbstractValue {
  if (values.length === 1) {
    const value = { ...step(values[0], "expression", operator, location, "derived"), constant: String(selected), constantKind: "boolean" as const, equalities: undefined };
    if (value.predicateHasAlternatives || value.predicateAlternatives) {
      delete value.predicateAlternatives; delete value.predicateHasAlternatives; delete value.predicateStructureLost;
      delete value.comparison; delete value.negated; delete value.ordering;
    }
    return value;
  }
  // On the evaluated-RHS arm the result equals that immutable RHS. Keep its
  // predicate/identity metadata as well as both operands' dependency flows.
  // In particular, asserting `a && b` must constrain b, not a fresh Boolean.
  const value = { ...values[1], ...step(combine(values), "expression", operator, location, "derived") };
  if (!values[1].predicateStructureLost) delete value.predicateStructureLost;
  value.equalities = operator === "&&" ? [...(values[0].equalities ?? []), ...(values[1].equalities ?? [])] : undefined;
  return value;
}

export function negateValue(input: AbstractValue, location: Span): AbstractValue {
  const value = step(input, "expression", "!", location, "derived");
  return { ...value, ...(value.eitherSelection ? { eitherSelection: undefined } : {}), ledger: new Set(), equalities: undefined, constantKind: "boolean", constant: input.constantKind === "boolean" && input.constant !== undefined ? String(input.constant !== "true") : undefined,
    identity: input.identity ? `!${input.identity}` : undefined, negated: input, ...(input.predicateAlternatives ? { predicateAlternatives: undefined } : {}), comparison: undefined, ordering: undefined, collectionPredicate: undefined, listPredicate: undefined, merklePredicate: undefined };
}
