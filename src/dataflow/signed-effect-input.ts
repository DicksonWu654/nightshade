import type { AbstractValue, SuccessfulPath } from "./index.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";
import { merkleDigestKey } from "./merkle-enforcement.js";

/** Represented signed dependencies, including exact retained digest inputs.
 * These are dependence facts, never cryptographic binding or preimage equality. */
export function signedMessageInputs(message: AbstractValue, allowance: number): {
  complete: boolean; work: number; sources: Set<string>; scalars: AbstractValue[];
} {
  let work = 0;
  const sources = new Set<string>(), scalars: AbstractValue[] = [];
  const pending = [message], visited = new Set<AbstractValue>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, work, sources: new Set(), scalars: [] };
    const value = pending.pop()!;
    if (visited.has(value)) continue;
    visited.add(value);
    if (!value.items && !value.fields) scalars.push(value);
    for (const flow of value.flows) {
      if (++work > allowance) return { complete: false, work, sources: new Set(), scalars: [] };
      sources.add(flow.source.id);
    }
    pending.push(...value.items ?? [], ...Object.values(value.fields ?? {}));
    if (value.directDigest) pending.push(value.directDigest.input);
  }
  return { complete: true, work, sources, scalars };
}

/** Restrict mandatory proof predicates to the pre-invocation operation boundary.
 * Native effects are not ordinary ledger writes: writesBefore cannot order them. */
export function predicatesBeforeOperation(path: SuccessfulPath, boundary: number): SuccessfulPath | undefined {
  if (!path.predicates || !Number.isSafeInteger(boundary) || boundary < 0
    || boundary > (path.operations?.length ?? 0)) return;
  return { ...path, predicates: path.predicates.filter(predicate => predicate.operationsBefore <= boundary) };
}

/** Exact Boolean equality keys. Source provenance is deliberately not equality. */
function key(value: AbstractValue): string | undefined {
  if (value.type === "Boolean" && value.identity) return `identity:${value.identity}`;
  const constant = constantOf(value);
  if (constant?.kind === "boolean") return `boolean:${constant.value}`;
  return undefined;
}

/** Exact scalar equalities required before the write. Allows a separately
 * supplied effect input constrained to a signed scalar without equating hashes,
 * shared provenance, wildcard regions or optional predicate alternatives. */
export function signedScalarEqualityClosure(path: SuccessfulPath, writeIndex: number,
  seeds: readonly AbstractValue[], allowance: number): { complete: boolean; work: number; keys: Set<string> } {
  let work = 0;
  const keys = new Set<string>(), adjacent = new Map<string, Set<string>>();
  const fail = () => ({ complete: false, work, keys: new Set<string>() });
  for (const seed of seeds) {
    if (++work > allowance) return fail();
    const key = !seed.fields && !seed.items && merkleDigestKey(seed);
    if (key) keys.add(key);
  }
  if (!path.predicates) return fail();
  for (const predicate of path.predicates) {
    if (++work > allowance) return fail();
    if (predicate.writesBefore > writeIndex) continue;
    if (predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) return fail();
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) return fail();
    for (const equality of decoded.equalities) {
      if (++work > allowance) return fail();
      if (!equality.equals) continue;
      const first = merkleDigestKey(equality.left), second = merkleDigestKey(equality.right);
      if (!first || !second) continue;
      for (const [a, b] of [[first, second], [second, first]]) {
        const next = adjacent.get(a) ?? new Set<string>(); next.add(b); adjacent.set(a, next);
      }
    }
  }
  const pending = [...keys];
  for (let index = 0; index < pending.length; index++) for (const next of adjacent.get(pending[index]) ?? []) {
    if (++work > allowance) return fail();
    if (!keys.has(next)) { keys.add(next); pending.push(next); }
  }
  return { complete: true, work, keys };
}

/** Only mandatory equality edges before this write can enforce an observed
 * signature. The caller owns the allowance and diagnoses an incomplete result.
 * No ambient guards, provenance unions, optional checks or terminal state are
 * substituted for the original history's predicates and write snapshots. */
export function enforcedSignatureResults(path: SuccessfulPath, writeIndex: number, allowance: number): {
  complete: boolean; work: number; identities: Set<string>; operationsBefore: number;
} {
  let work = 0, operationsBefore = 0;
  const identities = new Set<string>(), adjacent = new Map<string, Set<string>>();
  const failed = () => ({ complete: false, work, identities: new Set<string>(), operationsBefore: 0 });
  if (!path.predicates) return failed();
  for (const predicate of path.predicates) {
    if (++work > allowance) return failed();
    if (predicate.writesBefore > writeIndex) continue;
    operationsBefore = Math.max(operationsBefore, predicate.operationsBefore);
    const observe = (value: AbstractValue, truth: boolean, depth = 0): boolean => {
      if (++work > allowance || depth > 64) return false;
      if (value.predicateAlternatives || value.predicateStructureLost) return false;
      const identity = key(value);
      if (value.type === "Boolean" && identity) {
        const constant = `boolean:${truth}`;
        const neighbors = adjacent.get(identity) ?? new Set<string>(); neighbors.add(constant); adjacent.set(identity, neighbors);
        const reverse = adjacent.get(constant) ?? new Set<string>(); reverse.add(identity); adjacent.set(constant, reverse);
      }
      if (value.negated) return observe(value.negated, !truth, depth + 1);
      if (value.comparison) {
        const { left, right, operator } = value.comparison;
        for (const [subject, other] of [[left, right], [right, left]]) {
          const constant = constantOf(other);
          if (constant?.kind === "boolean") return observe(subject, (operator === "==" ? truth : !truth) === (constant.value === "true"), depth + 1);
        }
      }
      return true;
    };
    if (!observe(predicate.value, predicate.truth)) return failed();
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) return failed();
    for (const equality of decoded.equalities) {
      if (++work > allowance) return failed();
      if (!equality.equals) continue;
      const left = key(equality.left), right = key(equality.right);
      if (!left || !right) continue;
      for (const [a, b] of [[left, right], [right, left]]) {
        const neighbors = adjacent.get(a) ?? new Set<string>(); neighbors.add(b); adjacent.set(a, neighbors);
      }
    }
  }
  const reached = new Set(["boolean:true"]), pending = [...reached];
  for (let index = 0; index < pending.length; index++) {
    for (const next of adjacent.get(pending[index]) ?? []) {
      if (++work > allowance) return failed();
      if (!reached.has(next)) { reached.add(next); pending.push(next); }
    }
  }
  for (const reachedKey of reached) if (reachedKey.startsWith("identity:")) identities.add(reachedKey.slice(9));
  return { complete: true, work, identities, operationsBefore };
}
