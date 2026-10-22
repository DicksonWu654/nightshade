import type { AbstractValue, Flow, RuntimeOperation, StateWrite, SuccessfulPath, SuccessfulPredicate } from "./index.js";
import { createEqualityDependencyIndex } from "./equality-dependencies.js";
import { enforcedEqualities } from "./predicates.js";
import { combine, constantOf } from "./transfers.js";
import type { Program } from "../semantic/index.js";
import { VALUE_TRANSFER_CIRCUITS } from "../semantic/value-transfers.js";
import type { Span } from "../model.js";

/** Path-local keys do not normalize distinct dynamic witness invocations or
 * equate different scalar representations that happen to share an identity. */
export function merkleDigestKey(value: AbstractValue): string | undefined {
  if (!value.type || value.fields || value.items) return undefined;
  if (value.identity) return JSON.stringify([value.type, "identity", value.identity]);
  const constant = constantOf(value);
  return constant ? JSON.stringify([value.type, "constant", constant.kind, constant.value]) : undefined;
}

/** Required equality closure to definite preexisting ledger values, plus positive
 * revision-qualified Merkle membership. This reads successful predicates, never
 * terminal storage or a mere call/comparison that was not enforced. */
export function enforcedMerkleDigests(path: SuccessfulPath, allowance: number): { complete: boolean; work: number; keys: Set<string> } {
  let work = 0, complete = true;
  const keys = new Set<string>(), adjacent = new Map<string, Set<string>>(), checks = new Map<string, Set<string>>();
  const charge = () => { if (++work > allowance) complete = false; return complete; };
  // Bind the immutable Boolean actually observed to its exact digest and the
  // receiver snapshot at that call. Wildcard tree regions cannot share current
  // storage facts, but an enforced individual query still proves membership in
  // that preexisting tree. Never borrow trust from a later/earlier tree revision.
  for (const operation of path.operations ?? []) {
    if (!charge()) return { complete: false, work, keys };
    if (operation.kind !== "merkle-check" || !operation.result.identity || !operation.args[0].preexistingLedger?.size) continue;
    const digest = operation.args[1]?.fields?.field, key = digest && merkleDigestKey(digest);
    if (key) {
      const digests = checks.get(operation.result.identity) ?? new Set<string>();
      digests.add(key); checks.set(operation.result.identity, digests);
    }
  }
  const membership = (value: AbstractValue, truth: boolean, depth = 0): void => {
    if (!charge() || depth > 64) { complete = false; return; }
    if (value.negated) { membership(value.negated, !truth, depth + 1); return; }
    if (truth && value.identity) for (const digest of checks.get(value.identity) ?? []) {
      if (!charge()) return;
      keys.add(digest);
    }
    if (value.comparison) {
      const { operator, left, right } = value.comparison;
      const equals = operator === "==" ? truth : !truth;
      for (const [subject, other] of [[left, right], [right, left]]) {
        const constant = constantOf(other);
        if (constant?.kind === "boolean") { membership(subject, equals === (constant.value === "true"), depth + 1); break; }
      }
    }
  };
  if (!path.predicates) return { complete: false, work, keys };
  for (const predicate of path.predicates) {
    membership(predicate.value, predicate.truth);
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!complete || !decoded.complete || work > allowance) return { complete: false, work, keys: new Set() };
    for (const { left, right, equals } of decoded.equalities) {
      if (!charge()) return { complete: false, work, keys: new Set() };
      if (!equals) continue;
      const first = merkleDigestKey(left), second = merkleDigestKey(right);
      for (const [value, key] of [[left, first], [right, second]] as const)
        if (key && value.preexistingLedger?.size) keys.add(key);
      if (first && second) for (const [a, b] of [[first, second], [second, first]]) {
        const neighbors = adjacent.get(a) ?? new Set(); neighbors.add(b); adjacent.set(a, neighbors);
      }
    }
  }
  const pending = [...keys];
  for (let index = 0; index < pending.length; index++) for (const other of adjacent.get(pending[index]) ?? []) {
    if (!charge()) return { complete: false, work, keys: new Set() };
    if (!keys.has(other)) { keys.add(other); pending.push(other); }
  }
  return { complete, work, keys };
}

export interface MerkleRootUse {
  digest: AbstractValue;
  dependencies: Set<string>;
  location: Span;
  callPath: string[];
  origin: "computed-proof" | "supplied-digest";
}
export interface MerkleEffectUse { value: AbstractValue; location: Span; callPath: string[]; name: string; before?: { writes: number; operations: number } }
export type MerkleEffectPairs = { status: "complete"; work: number; pairs: { root: MerkleRootUse; effect: MerkleEffectUse }[] }
  | { status: "grouping" | "matching" | "effect-matching"; work: number };

function suppliedDigests(value: AbstractValue, dependency: (flow: Flow) => string): MerkleRootUse[] {
  return value.flows.flatMap(flow => {
    const source = flow.source;
    return source.merkleDigest ? [{
      digest: { type: "Field", identity: source.id, flows: [flow], ledger: new Set<string>() },
      dependencies: new Set([dependency(flow)]), location: source.location, callPath: [], origin: "supplied-digest" as const,
    }] : [];
  });
}

/** Proof-related roots (computed Merkle roots and supplied digests) whose
 * dependencies influence an observed effect, in the Merkle-membership review's
 * order and with its work accounting. Roots whose digest key is enforced are
 * omitted. `dependency` names a flow's origin: the run-local source identity for
 * one successful history, or a coarser declaration/site class when the
 * observations are a union of conservative may-observations. */
export function merkleEffectPairs(program: Program, observations: { readonly writes: readonly StateWrite[]; readonly operations?: readonly RuntimeOperation[]; readonly predicates?: readonly SuccessfulPredicate[]; readonly entry?: string },
  enforced: ReadonlySet<string>, dependency: (flow: Flow) => string, allowance: number): MerkleEffectPairs {
  let work = observations.writes.length;
  for (const operation of observations.operations ?? []) {
    work += 1 + operation.args.length + operation.control.length;
    for (const value of [...operation.args, ...operation.control]) work += value.flows.length;
  }
  if (work > allowance) return { status: "grouping", work };
  if (observations.entry && !observations.predicates) return { status: "matching", work };
  if (observations.entry && !observations.operations) for (const predicate of observations.predicates ?? []) {
    if (++work > allowance || predicate.operationsBefore !== 0) return { status: "matching", work };
  }
  const effects: MerkleEffectUse[] = [
    ...observations.writes.map((write, index) => ({ value: write.after, location: write.location, callPath: write.callPath, name: program.symbols.get(write.ledger)!.name,
      ...(observations.entry ? { before: { writes: index, operations: observations.operations?.length ?? 0 } } : {}) })),
    ...(observations.operations ?? []).flatMap((operation, index) => ["kernel-write", "native-witness"].includes(operation.kind)
      && operation.callPath.some(id => VALUE_TRANSFER_CIRCUITS.has(id)) ? [{ value: combine([...operation.args, ...operation.control]), location: operation.location, callPath: operation.callPath, name: operation.name,
        ...(observations.entry ? { before: { writes: operation.writesBefore ?? observations.writes.length, operations: index } } : {}) }] : []),
  ];
  const roots: MerkleRootUse[] = (observations.operations ?? []).flatMap(operation => operation.kind === "merkle-root" && operation.result.fields?.field
    ? [{ digest: operation.result.fields.field, dependencies: new Set(operation.args[0].flows.map(dependency)),
      location: operation.location, callPath: operation.callPath, origin: "computed-proof" as const }] : []);
  const pairs: { root: MerkleRootUse; effect: MerkleEffectUse }[] = [];
  // An absent list also represents a legitimate history with no native calls.
  // Preserve its ordinary provenance; do not infer new equality dependencies
  // without an explicit operation history. Nonzero predicate positions above
  // still diagnose an actually missing operation list.
  const equalityPredicates = observations.entry && !observations.operations ? [] : observations.predicates ?? [];
  const equalityIndex = createEqualityDependencyIndex(equalityPredicates, dependency, allowance - work, !!observations.entry);
  work += equalityIndex.work;
  if (!equalityIndex.complete) return { status: "matching", work };
  for (const effect of effects) {
    const expanded = equalityIndex.query(effect.value, effect.before, allowance - work);
    work += expanded.work;
    if (!expanded.complete) return { status: "matching", work };
    const supplied = suppliedDigests(effect.value, dependency);
    // Preserve the existing minimum reservation, but every additional supplied
    // digest also requires a complete dependency comparison allowance.
    work += expanded.dependencies.size * (roots.length + Math.max(1, supplied.length));
    if (work > allowance) return { status: "matching", work };
    for (const root of [...roots, ...supplied]) {
      if (++work > allowance) return { status: "effect-matching", work };
      const key = merkleDigestKey(root.digest);
      if ((key && enforced.has(key)) || ![...expanded.dependencies].some(key => root.dependencies.has(key))) continue;
      pairs.push({ root, effect });
    }
  }
  return { status: "complete", work, pairs };
}
