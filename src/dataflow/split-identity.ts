import type { AbstractValue, SuccessfulPath } from "./index.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";

/** Immutable supplied snapshots only. Regions (especially wildcard may-alias
 * regions) are never value identities. Distinct witness invocations stay distinct. */
function key(value: AbstractValue): string | undefined {
  if (value.fields || value.items || value.region) return;
  if (value.identity) return value.identity;
  const constant = constantOf(value);
  return constant ? JSON.stringify([constant.kind, constant.value]) : undefined;
}

/** Mandatory scalar binding in this complete proof history, including checks
 * after the effect. Successful transactions must satisfy those checks too.
 * Equal digest outputs do not imply equal preimages. */
export function identityBinding(path: SuccessfulPath, seeds: readonly AbstractValue[], allowance: number): {
  complete: boolean; work: number; bound: (value: AbstractValue) => boolean;
} {
  let work = 0;
  const adjacent = new Map<string, Set<string>>(), reached = new Set<string>();
  const fail = () => ({ complete: false, work, bound: (_: AbstractValue) => false });
  for (const seed of seeds) { if (++work > allowance) return fail(); const id = key(seed); if (id) reached.add(id); }
  if (!path.predicates) return fail();
  for (const predicate of path.predicates) {
    if (++work > allowance || predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) return fail();
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) return fail();
    for (const equality of decoded.equalities) {
      if (++work > allowance) return fail();
      if (!equality.equals) continue;
      const a = key(equality.left), b = key(equality.right);
      if (!a || !b) continue;
      for (const [left, right] of [[a,b], [b,a]]) {
        const neighbors = adjacent.get(left) ?? new Set<string>(); neighbors.add(right); adjacent.set(left, neighbors);
      }
    }
  }
  const pending = [...reached];
  for (let index = 0; index < pending.length; index++) for (const next of adjacent.get(pending[index]) ?? []) {
    if (++work > allowance) return fail();
    if (!reached.has(next)) { reached.add(next); pending.push(next); }
  }
  return { complete: true, work, bound: value => { const id = key(value); return !!id && reached.has(id); } };
}

/** Exact supplied leaves of a retained native digest or scalar. Dependency
 * unions from arbitrary arithmetic/storage are insufficient identity evidence. */
export function identityInputs(value: AbstractValue, allowance: number): { complete: boolean; work: number; leaves: AbstractValue[] } {
  let work = 0;
  const leaves: AbstractValue[] = [], pending = [value], seen = new Set<AbstractValue>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, work, leaves: [] };
    const part = pending.pop()!;
    if (seen.has(part)) continue; seen.add(part);
    if (part.directDigest) pending.push(part.directDigest.input);
    else if (part.fields) pending.push(...Object.values(part.fields));
    else if (part.items) pending.push(...part.items);
    else if (!part.region && part.identity && part.flows.some(flow => flow.source.kind === "witness" && flow.source.id === part.identity)) leaves.push(part);
  }
  return { complete: true, work, leaves };
}
