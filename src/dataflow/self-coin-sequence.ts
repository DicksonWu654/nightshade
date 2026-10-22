import type { RuntimeOperation, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { SELF_COIN_PRODUCERS } from "../semantic/redundant-receive-targets.js";
import { RECEIVE_SHIELDED } from "../semantic/value-transfers.js";

/** Exact returned coin snapshots only. No provenance, name or later predicate
 * equality joins. Ordering comes from one original successful history. */
export function selfCoinSequences(path: SuccessfulPath, allowance = 100000) {
  let work = 0, complete = true;
  const key = (value: Parameters<typeof immutableOperandKey>[0] | undefined) => {
    if (!value) return undefined;
    const memo = new WeakMap<typeof value, typeof value>();
    const snapshotValue = (part: typeof value, depth = 0): typeof value => {
      if (++work > allowance || depth > 32) { complete = false; return part; }
      const cached = memo.get(part); if (cached) return cached;
      const result = { ...part, identity: part.identity ?? part.mintSnapshot };
      if (part.fields) {
        result.fields = {};
        for (const [name, child] of Object.entries(part.fields)) {
          if (!complete) break;
          result.fields[name] = snapshotValue(child, depth + 1);
        }
      }
      if (part.items) {
        result.items = [];
        for (const child of part.items) {
          if (!complete) break;
          result.items.push(snapshotValue(child, depth + 1));
        }
      }
      memo.set(part, result); return result;
    };
    const result = immutableOperandKey(snapshotValue(value), Math.min(4096, Math.max(0, allowance - work)), value => value);
    work += result.work; complete &&= result.complete;
    return result.key;
  };
  const selfs = new Set<string>(), produced = new Map<string, RuntimeOperation>();
  const pairs: { produced: RuntimeOperation; received: RuntimeOperation }[] = [];
  for (const operation of path.operations ?? []) {
    if (++work > allowance) { complete = false; break; }
    if (operation.kind === "kernel-read" && operation.name === "self") {
      const address = key(operation.result.fields?.bytes); if (address) selfs.add(address);
    }
    if (operation.kind !== "circuit-invocation") continue;
    if (operation.name === RECEIVE_SHIELDED) {
      const coin = key(operation.args[0]);
      if (!coin && produced.size) { complete = false; break; }
      const previous = coin && produced.get(coin);
      if (previous) pairs.push({ produced: previous, received: operation });
    } else if (SELF_COIN_PRODUCERS.has(operation.name)) {
      const mint = operation.name.endsWith("::mintShieldedToken");
      const recipient = operation.args[mint ? 3 : 1];
      const tag = recipient?.fields?.is_left;
      if (tag?.constantKind !== "boolean" || tag.constant !== "false") continue;
      const address = key(recipient.fields?.right?.fields?.bytes);
      if (!address || !selfs.has(address)) continue;
      const coin = key(mint ? operation.result : operation.result.fields?.sent);
      if (!coin) { complete = false; break; }
      produced.set(coin, operation);
    }
  }
  return { complete, work, pairs: complete ? pairs : [] };
}
