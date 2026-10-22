import type { AbstractValue, SuccessfulPath } from "./index.js";
import { immutableCollectionAddress, immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";

/** Required equalities over immutable operands on one successful history.
 * Storage wildcard paths and shared dependencies never establish equality. */
export function immutableEqualities(path: SuccessfulPath, allowance = 100000, meter?: (work: number, values: number) => boolean) {
  let work = 0, complete = path.predicates !== undefined;
  const charge = (units = 1, values = 0, alreadyMetered = false) => {
    work += units; return complete &&= work <= allowance && (!meter || alreadyMetered || meter(units, values));
  };
  charge(0, 2);
  const parents = new Map<string, string>();
  const find = (key: string): string => {
    while (parents.has(key)) { if (!charge()) break; key = parents.get(key)!; }
    return key;
  };
  const raw = (value: AbstractValue) => {
    const result = immutableOperandKey(value, Math.min(4096, Math.max(0, allowance - work)), undefined, meter);
    charge(result.work, 0, !!meter); complete &&= result.complete; return result.key;
  };
  for (const predicate of path.predicates ?? []) {
    if (!charge()) break;
    const result = enforcedEqualities(predicate.value, predicate.truth, meter);
    charge(result.work, 0, !!meter); complete &&= result.complete;
    for (const equality of result.equalities) {
      if (!charge()) break;
      if (!equality.equals) continue;
      const a = raw(equality.left), b = raw(equality.right);
      if (a && b) { const x = find(a), y = find(b); if (x !== y) { charge(0, 1); parents.set(y, x); } }
    }
  }
  const key = (value: AbstractValue) => {
    const result = immutableOperandKey(value, Math.min(4096, Math.max(0, allowance - work)), find, meter);
    charge(result.work, 0, !!meter); complete &&= result.complete; return complete ? result.key : undefined;
  };
  const address = (value: AbstractValue) => {
    const result = immutableCollectionAddress(value, Math.min(4096, Math.max(0, allowance - work)), find, meter);
    charge(result.work, 0, !!meter); complete &&= result.complete; return complete ? result.key : undefined;
  };
  return { key, address, get complete() { return complete; }, get work() { return work; } };
}
