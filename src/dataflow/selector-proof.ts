import type { AbstractValue, SuccessfulPredicate } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { projectEnforcedEqualities } from "./predicates.js";

/** Required disequality of exact immutable operands in one successful history.
 * Possible Boolean alternatives and wildcard storage paths supply no proof. */
export function requiredDistinctSelectors(left: AbstractValue, right: AbstractValue,
  predicates: readonly SuccessfulPredicate[], charge: (work: number, values: number) => boolean,
  unavailable: (message: string) => never): boolean {
  const spend = (work: number, values: number) => {
    if (!charge(work, values)) unavailable("Required selector proof allowance exhausted");
    return true;
  };
  const identity = (value: AbstractValue) => {
    // A may-alias storage address cannot identify a selector value, even if
    // some analysis metadata retained an identity alongside that address.
    if (value.region?.path.includes("key:*")) { spend(1, 0); return undefined; }
    const result = immutableOperandKey(value);
    spend(result.work, 0);
    if (!result.complete) unavailable("Selector operand identity allowance exhausted");
    return result.key;
  };
  const a = identity(left), b = identity(right);
  if (!a || !b || a === b) return false;
  const pair = (x: string, y: string) => JSON.stringify([x, y].sort());
  const sought = pair(a, b);
  for (const predicate of predicates) {
    spend(1, 0);
    const projected = projectEnforcedEqualities(predicate.value, predicate.truth, equality => {
      if (equality.equals) return [];
      const x = identity(equality.left), y = identity(equality.right);
      return x && y && x !== y ? [{ key: pair(x, y), value: true }] : [];
    }, spend);
    if (!projected) unavailable("Required selector disequality projection is unavailable");
    if (projected.required.has(sought)) return true;
  }
  return false;
}
