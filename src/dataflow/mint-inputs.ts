import { createHash } from "node:crypto";
import type { AbstractValue } from "./index.js";
import type { successfulConstants } from "./successful-constants.js";
import { constantOf } from "./transfers.js";

/** Identical canonical mint operands imply the same commitment in this context.
 * Unknown operands are not equal just because their dependencies overlap. */
export function shieldedMintKey(args: readonly AbstractValue[], facts: ReturnType<typeof successfulConstants>, allowance = 4096) {
  let work = 0, complete = true;
  const memo = new WeakMap<AbstractValue, string | undefined>();
  const digest = (tag: string, keys: readonly string[]) => `${tag}:${createHash("sha256").update(JSON.stringify(keys)).digest("hex")}`;
  const visit = (original: AbstractValue, depth = 0): string | undefined => {
    if (++work > allowance || depth > 32) { complete = false; return undefined; }
    if (memo.has(original)) return memo.get(original);
    const value = facts.refine(original);
    let key: string | undefined;
    if (constantOf(value)) key = facts.equalityKey(value);
    else if (value.nonceEvolution) {
      const index = visit(value.nonceEvolution.index, depth + 1), nonce = visit(value.nonceEvolution.nonce, depth + 1);
      if (index && nonce) key = digest("evolveNonce", [index, nonce]);
    } else if (value.fields || value.items) {
      const children = value.fields ? Object.entries(value.fields).sort(([a], [b]) => a.localeCompare(b))
        : value.items!.map((item, index) => [String(index), item] as const);
      const keys = children.map(([name, part]) => { const key = visit(part, depth + 1); return key && JSON.stringify([name, key]); });
      if (keys.every((key): key is string => key !== undefined)) key = digest(value.fields ? "fields" : "items", keys);
    } else key = facts.equalityKey(value);
    memo.set(original, key);
    return key;
  };
  if (args.length !== 4) return { complete: false, work };
  const recipient = facts.refine(args[3]), tag = recipient.fields?.is_left && facts.refine(recipient.fields.is_left);
  const arm = tag?.constantKind === "boolean" ? tag.constant === "true" ? "left" : "right" : undefined;
  const active = arm && recipient.fields?.[arm];
  const keys = args.slice(0, 3).map(value => visit(value));
  const address = active && visit(active);
  const key = arm && address && keys.every((key): key is string => key !== undefined)
    ? digest("mintShieldedToken", [...keys, arm, address]) : undefined;
  return { key, complete: complete && facts.complete, work };
}
