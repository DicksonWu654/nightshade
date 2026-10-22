import { createHash } from "node:crypto";
import type { AbstractValue } from "./index.js";
import { constantOf } from "./transfers.js";

/** Bounded identity of immutable scalar/aggregate operands. Hash each container
 * separately so repeated DAG edges cannot expand a serialized key exponentially.
 * Unknown leaves stay unknown; dependency unions never identify equal values. */
export function immutableOperandKey(value: AbstractValue, allowance = 4096, canonicalize?: (key: string) => string,
  meter?: (work: number, values: number) => boolean): { key?: string; complete: boolean; work: number } {
  let work = 0, complete = true;
  if (meter && !meter(0, 1)) return { complete: false, work: 0 };
  const memo = new WeakMap<AbstractValue, string | undefined>();
  const retain = (values: number): boolean => {
    if (meter && !meter(0, values)) { complete = false; return false; }
    return true;
  };
  const visit = (part: AbstractValue, depth: number): string | undefined => {
    if (meter && !complete) return undefined;
    if (++work > allowance || depth > 32 || meter && !meter(1, 0)) { complete = false; return undefined; }
    if (memo.has(part)) return memo.get(part);
    if (part.negated || part.comparison || part.ordering) {
      const operation = part.negated ? "!" : part.comparison?.operator ?? part.ordering!.operator;
      if (!retain(6)) return undefined;
      const operands = part.negated ? [part.negated] : part.comparison
        ? [part.comparison.left, part.comparison.right] : [part.ordering!.left, part.ordering!.right];
      const keys = operands.map(operand => visit(operand, depth + 1));
      if (keys.some(key => key === undefined)) return undefined;
      if (part.comparison) keys.sort();
      let encodingUnits = 4;
      for (const key of keys) encodingUnits += Math.ceil((key?.length ?? 0) / 64);
      if (!retain(encodingUnits)) return undefined;
      const raw = `expression:${createHash("sha256").update(JSON.stringify([operation, part.ordering?.numericType, keys])).digest("hex")}`;
      const key = canonicalize?.(raw) ?? raw;
      if (!retain(1)) return undefined;
      memo.set(part, key); return key;
    }
    // Equality evidence is component-wise. Rebuild represented aggregates from
    // canonical leaves even when the aggregate also has a snapshot identity.
    if (part.identity && !(canonicalize && (part.fields || part.items))) {
      if (part.identity.length > 65536) { complete = false; return undefined; }
      if (!retain(1 + Math.ceil(part.identity.length / 64))) return undefined;
      const key = `id:${part.identity}`;
      return canonicalize?.(key) ?? key;
    }
    if (part.constant !== undefined && part.constantKind && !retain(1)) return undefined;
    const constant = constantOf(part);
    if (constant) {
      if (constant.value.length > 65536) { complete = false; return undefined; }
      if (!retain(1 + Math.ceil(constant.value.length / 64))) return undefined;
      const key = `constant:${constant.kind}:${constant.value}`;
      return canonicalize?.(key) ?? key;
    }
    let childCount = part.items?.length ?? 0;
    if (meter && part.fields) {
      childCount = 0;
      for (const name in part.fields) if (Object.hasOwn(part.fields, name)) {
        if (++work > allowance || !meter(1, 0)) { complete = false; return undefined; }
        childCount++;
      }
    }
    if (!retain(1 + childCount * 3)) return undefined;
    const children = part.fields ? Object.entries(part.fields).sort(([a], [b]) => a.localeCompare(b))
      : part.items?.map((item, index) => [String(index), item] as const);
    if (!children) return undefined;
    if (!retain(2)) return undefined;
    const hash = createHash("sha256").update(part.fields ? "fields" : "items");
    for (const [name, child] of children) {
      const key = visit(child, depth + 1);
      if (!key) { if (!meter || complete && retain(1)) memo.set(part, undefined); return undefined; }
      if (!retain(2 + Math.ceil((name.length + key.length) / 64))) return undefined;
      hash.update(JSON.stringify([name, key]));
    }
    if (!retain(2)) return undefined;
    const raw = `aggregate:${hash.digest("hex")}`;
    const key = canonicalize?.(raw) ?? raw;
    if (!retain(1)) return undefined;
    memo.set(part, key); return key;
  };
  const key = visit(value, 0);
  return { key: complete ? key : undefined, complete, work };
}

/** Exact ledger address from immutable lookup operands. Wildcards alone never
 * identify the same collection. Revision is supplied separately by the caller. */
export function immutableCollectionAddress(value: AbstractValue, allowance = 4096, canonicalize?: (key: string) => string, meter?: (work: number, values: number) => boolean): { key?: string; complete: boolean; work: number } {
  if (meter && !meter(1, 3)) return { complete: false, work: 0 };
  const region = value.region;
  if (!region) return { complete: true, work: 1 };
  let work = 1;
  const selectors = new Map<number, AbstractValue>();
  for (const selector of region.collectionSelectors ?? []) {
    if (++work > allowance) return { complete: false, work };
    if (meter && !meter(1, 1)) return { complete: false, work };
    selectors.set(selector.index, selector.value);
  }
  const path: string[] = [];
  for (const [index, part] of region.path.entries()) {
    if (++work > allowance) return { complete: false, work };
    if (meter && !meter(1, 2)) return { complete: false, work };
    const selector = selectors.get(index);
    if (selector) {
      const result = immutableOperandKey(selector, allowance - work, canonicalize, meter);
      work += result.work;
      if (!result.complete || !result.key) return { complete: result.complete, work };
      path.push(result.key);
    } else if (part === "key:*") return { complete: true, work };
    else path.push(part);
  }
  if (meter && !meter(1, 2 + path.length * 2)) return { complete: false, work };
  return { ...(work <= allowance ? { key: JSON.stringify([region.root, path]) } : {}), complete: work <= allowance, work };
}
