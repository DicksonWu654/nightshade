import type { AbstractValue, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { enforcedEqualities } from "./predicates.js";

/** Mandatory checks on one original successful history. Relations are between
 * immutable operands, never shared storage paths or dependency unions. A
 * nonidentity native output excludes identity of its recorded input because
 * the pinned native transfer maps identity to identity; no inverse, curve or
 * subgroup property is inferred. */
export function signatureKeyIdentityExclusions(path: SuccessfulPath, allowance: number,
  meter?: (work: number, values: number) => boolean,
  curve = "JubjubPoint", point?: (value: AbstractValue) => boolean): { complete: boolean; work: number; excluded: Set<string> } {
  let work = 0;
  const charge = (amount: number, values = 0): boolean => {
    work += amount;
    return work <= allowance && (!meter || meter(amount, values));
  };
  // Precharge every helper container; defaults retain the existing local work cap.
  // A rejected workspace retains only the required empty failure payload.
  if (!charge(0, 4)) return { complete: false, work, excluded: new Set<string>() };
  const excluded = new Set<string>(), adjacent = new Map<string, Set<string>>();
  const keys = new WeakMap<AbstractValue, string | undefined>(), observed = new WeakSet<AbstractValue>();
  const failed = () => ({ complete: false, work, excluded: meter ? excluded : new Set<string>() });
  const key = (value: AbstractValue): string | undefined => {
    if (keys.has(value)) return keys.get(value);
    const result = immutableOperandKey(value, Math.min(4096, Math.max(0, allowance - work)), undefined,
      meter ? (amount, values) => charge(amount, values) : undefined);
    if (!meter) work += result.work;
    if (!result.complete) { work = allowance + 1; if (meter) return; }
    if (!charge(0, 1)) { work = allowance + 1; return; }
    keys.set(value, result.key);
    return result.key;
  };
  const link = (a: string, b: string): boolean => {
    let next = adjacent.get(a);
    if (!next) { if (!charge(0, 2)) return false; next = new Set<string>(); adjacent.set(a, next); }
    if (!charge(0, 1)) return false;
    next.add(b); return true;
  };
  const native = (value: AbstractValue, depth = 0): boolean => {
    if (!charge(1) || depth > 32) return false;
    if (value.pointIdentityEvidenceLost) return false;
    if (observed.has(value)) return true;
    if (!charge(0, 1)) return false;
    observed.add(value);
    if (!value.pointIdentityInput) return true;
    if (point && (!point(value) || !point(value.pointIdentityInput))) return false;
    const output = key(value), input = key(value.pointIdentityInput);
    if (output && input && !link(output, input)) return false;
    return (!meter || work <= allowance) && native(value.pointIdentityInput, depth + 1);
  };
  const identity = (value: AbstractValue) => value.constantKind === "point" && value.constant === `${curve}:identity` && (!point || point(value));
  if (!path.predicates) return failed();
  for (const predicate of path.predicates) {
    if (!charge(1)) return failed();
    if (predicate.value.predicateHasAlternatives || predicate.value.predicateStructureLost) return failed();
    const decoded = enforcedEqualities(predicate.value, predicate.truth, meter ? (amount, values) => charge(amount, values) : undefined);
    if (!meter) work += decoded.work;
    if (!decoded.complete || work > allowance) return failed();
    for (const { left, right, equals } of decoded.equalities) {
      if (!charge(1)) return failed();
      if (point && (!point(left) || !point(right))) continue;
      if (!native(left) || !native(right)) return failed();
      const a = key(left), b = key(right);
      if (work > allowance) return failed();
      if (equals && a && b) { if (!link(a, b) || !link(b, a)) return failed(); }
      else if (!equals) {
        if (a && identity(right)) { if (!charge(0, 1)) return failed(); excluded.add(a); }
        if (b && identity(left)) { if (!charge(0, 1)) return failed(); excluded.add(b); }
      }
    }
  }
  if (!charge(0, 1 + excluded.size)) return failed();
  const pending = [...excluded];
  for (let index = 0; index < pending.length; index++) for (const next of adjacent.get(pending[index]) ?? []) {
    if (!charge(1)) return failed();
    if (!excluded.has(next)) { if (!charge(0, 2)) return failed(); excluded.add(next); pending.push(next); }
  }
  return { complete: true, work, excluded };
}

/** Exact entry-storage snapshot of one whole persistent Cell. A retained region
 * alone never establishes provenance; native transformations and alias joins
 * drop the definite entry-storage origin. Local copies preserve it. */
export function persistentSignatureKeySnapshot(key: AbstractValue): string | undefined {
  const region = key.region;
  if (!region || region.path.length || key.constant !== undefined
    || key.fields || key.items || key.preexistingLedger?.size !== 1) return;
  return [...key.preexistingLedger][0];
}
