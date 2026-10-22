import type { AbstractValue, SuccessfulPath } from "./index.js";
import type { Constant } from "./constants.js";
import { enforcedEqualities } from "./predicates.js";
import { constantOf } from "./transfers.js";

/** History-local constants on immutable operands, including later atomic guards.
 * Never use ledger dependency unions or wildcard regions as equality evidence. */
export function successfulConstants(path: SuccessfulPath, allowance = 100000) {
  let work = 0, complete = path.predicates !== undefined;
  const charge = () => { if (++work > allowance) complete = false; return complete; };
  const parents = new Map<string, string>(), constants = new Map<string, Constant>();
  const key = (value: AbstractValue): string | undefined => {
    const constant = constantOf(value);
    if (constant) {
      if (constant.value.length > 65536) { complete = false; return undefined; }
      return `constant:${JSON.stringify(constant)}`;
    }
    if ((value.identity?.length ?? 0) > 65536) { complete = false; return undefined; }
    // Storage allocates a distinct snapshot: identity for each wildcard read;
    // the shared wildcard region itself is never an equality certificate.
    if (value.region?.path.some(part => part === "*" || part === "key:*")
      && !value.identity?.startsWith("snapshot:")) return undefined;
    return value.identity ? `identity:${value.identity}` : value.mintSnapshot ? `snapshot:${value.mintSnapshot}` : undefined;
  };
  const root = (id: string): string => {
    const chain: string[] = [];
    while (parents.has(id) && parents.get(id) !== id) {
      if (!charge()) return id;
      chain.push(id); id = parents.get(id)!;
    }
    for (const member of chain) parents.set(member, id);
    return id;
  };
  const anchor = (value: AbstractValue, id: string) => {
    const constant = constantOf(value);
    if (constant) constants.set(id, constant);
  };
  for (const predicate of path.predicates ?? []) {
    if (!charge()) break;
    const decoded = enforcedEqualities(predicate.value, predicate.truth);
    work += decoded.work;
    if (!decoded.complete || work > allowance) { complete = false; break; }
    for (const equality of decoded.equalities) {
      if (!charge()) break;
      if (!equality.equals) continue;
      const left = key(equality.left), right = key(equality.right);
      if (!left || !right) continue;
      anchor(equality.left, left); anchor(equality.right, right);
      const a = root(left), b = root(right);
      if (a !== b) parents.set(b, a);
    }
  }
  const known = new Map<string, Constant>();
  for (const [id, constant] of constants) {
    if (!charge()) break;
    const member = root(id), prior = known.get(member);
    if (prior && (prior.kind !== constant.kind || prior.value !== constant.value)) { complete = false; break; }
    known.set(member, constant);
  }
  const memo = new WeakMap<AbstractValue, AbstractValue>();
  const refine = (value: AbstractValue, depth = 0): AbstractValue => {
    if (!charge() || depth > 32) { complete = false; return value; }
    const cached = memo.get(value);
    if (cached) return cached;
    const identity = key(value), constant = identity && known.get(root(identity));
    const domain = value.identity && path.integerDomains?.get(value.identity);
    const exact = constant || domain && domain.minimum === domain.maximum && { kind: "integer" as const, value: domain.minimum };
    const result: AbstractValue = { ...value, ...(exact ? { constant: exact.value, constantKind: exact.kind } : {}) };
    if (value.fields) result.fields = Object.fromEntries(Object.entries(value.fields).map(([name, part]) => [name, refine(part, depth + 1)]));
    if (value.items) result.items = value.items.map(part => refine(part, depth + 1));
    memo.set(value, result);
    return result;
  };
  // Scalar equivalence is local to this successful history and immutable
  // snapshot. Container identities and wildcard reads never certify leaves.
  const equalityKey = (value: AbstractValue): string | undefined => {
    if (!charge()) return undefined;
    const id = key(value);
    if (!id) return undefined;
    const member = root(id), constant = known.get(member);
    return constant ? `constant:${JSON.stringify(constant)}` : member;
  };
  return { refine, equalityKey, get complete() { return complete; }, get work() { return work; } };
}
