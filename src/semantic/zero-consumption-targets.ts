import type { Program } from "./index.js";
import { collectionTargets } from "./collection-targets.js";
import { zeroSendScope } from "./zero-send-targets.js";

export const ZERO_CONSUMPTION_RULE = "zero-amount-set-consumption-review";

/** Owned resolved calls and canonical collection types establish applicability;
 * neither collection names nor absence text establish one-use intent. */
export function zeroConsumptionScope(program: Program, entries: readonly string[] = program.entries, allowance = 20000) {
  const send = zeroSendScope(program, entries, allowance);
  if (!send.complete || !send.applicable) return send;
  const collection = collectionTargets(program, allowance - send.work, entries, ["Set"]);
  return { ...collection, work: send.work + collection.work };
}
