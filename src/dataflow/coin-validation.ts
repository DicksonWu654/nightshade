import type { AbstractValue, SuccessfulPath } from "./index.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";

/** Exact, history-local constraints on a received coin. Public disclosure and
 * may-dependencies are not expected payment policies. A constant or unchanged
 * entry-ledger operand anchors equality; value also accepts a lower bound.
 * Later assertions count because Compact circuit effects commit atomically. */
export function receivedCoinValidation(path: SuccessfulPath, coin: AbstractValue, allowance = 100000): {
  complete: boolean; work: number; color: boolean; value: boolean;
} {
  let work = 0, complete = true;
  const result = (color = false, value = false) => ({ complete, work, color, value });
  const charge = () => { if (++work > allowance) complete = false; return complete; };
  const key = (value: AbstractValue): string | undefined => {
    const constant = constantOf(value);
    return value.identity ?? (constant ? JSON.stringify([constant.kind, constant.value]) : undefined);
  };
  const trusted = (value: AbstractValue): boolean => !!constantOf(value) || !!value.preexistingLedger?.size;
  const adjacent = new Map<string, Set<string>>(), anchors = new Set<string>(), anchorValues = new Map<string, AbstractValue>();
  const connect = (left: AbstractValue, right: AbstractValue) => {
    const a = key(left), b = key(right);
    if (!a || !b || a === b) return;
    for (const [value, id] of [[left, a], [right, b]] as const) if (trusted(value)) { anchors.add(id); anchorValues.set(id, value); }
    for (const [id, other] of [[a, b], [b, a]]) {
      const neighbors = adjacent.get(id) ?? new Set(); neighbors.add(other); adjacent.set(id, neighbors);
    }
  };
  if (!path.predicates || !coin.fields?.color || !coin.fields.value) { complete = false; return result(); }
  for (const predicate of path.predicates) {
    if (!charge()) return result();
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) { complete = false; return result(); }
    for (const equality of decoded.equalities) {
      if (!charge()) return result();
      if (equality.equals) connect(equality.left, equality.right);
    }
  }
  const closure = (seeds: Set<string>) => {
    const reached = new Set(seeds), pending = [...seeds];
    for (let index = 0; index < pending.length; index++) for (const neighbor of adjacent.get(pending[index]) ?? []) {
      if (!charge()) return reached;
      if (!reached.has(neighbor)) { reached.add(neighbor); pending.push(neighbor); }
    }
    return reached;
  };
  const anchored = closure(anchors);
  const fixed = (value: AbstractValue, depth = 0): boolean => {
    if (!charge() || depth > 64) { complete = false; return false; }
    if (trusted(value) || (key(value) !== undefined && anchored.has(key(value)!))) return true;
    if (value.fields) return Object.values(value.fields).every(part => fixed(part, depth + 1));
    if (value.items) return value.items.every(part => fixed(part, depth + 1));
    return false;
  };
  const color = fixed(coin.fields.color), amount = coin.fields.value;
  let value = fixed(amount);
  const amountKey = key(amount), amountAliases = closure(new Set(amountKey ? [amountKey] : []));
  const lowerBound = (condition: AbstractValue, truth: boolean, depth = 0): boolean => {
    if (!charge() || depth > 64) { complete = false; return false; }
    if (condition.negated) return lowerBound(condition.negated, !truth, depth + 1);
    if (condition.comparison) {
      const { left, right, operator } = condition.comparison;
      for (const [subject, other] of [[left, right], [right, left]]) {
        const constant = constantOf(other);
        if (constant?.kind === "boolean") return lowerBound(subject, (operator === "==" ? truth : !truth) === (constant.value === "true"), depth + 1);
      }
    }
    if (!condition.ordering) return false;
    let { left, right, operator } = condition.ordering;
    if (!truth) operator = ({ ">": "<=", ">=": "<", "<": ">=", "<=": ">" } as Record<string, string>)[operator];
    if (operator === "<" || operator === "<=") { [left, right] = [right, left]; operator = operator === "<" ? ">" : ">="; }
    if (![">", ">="].includes(operator) || !amountAliases.has(key(left) ?? "") || amountAliases.has(key(right) ?? "") || !fixed(right)) return false;
    // Uint >= 0 and Uint > a negative constant provide no payment constraint.
    const aliases = closure(new Set(key(right) ? [key(right)!] : []));
    const candidates = [right];
    for (const alias of aliases) { if (!charge()) return false; const value = anchorValues.get(alias); if (value) candidates.push(value); }
    // A later equality may prove a ledger term is zero. Inspect the whole
    // equality class before trusting its storage origin, independent of order.
    const constants = candidates.flatMap(value => { const constant = constantOf(value); return constant?.kind === "integer" ? [BigInt(constant.value)] : []; });
    if (constants.length) return constants.every(value => value >= (operator === ">" ? 0n : 1n));
    return candidates.some(value => !!value.preexistingLedger?.size);
  };
  if (!value) for (const predicate of path.predicates) {
    if (lowerBound(predicate.value, predicate.truth)) value = true;
    if (!complete) break;
  }
  return result(color, value);
}
