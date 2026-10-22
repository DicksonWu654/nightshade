import type { Program } from "./index.js";
import { mayCallCircuits } from "./value-transfers.js";

export const ZERO_SEND_RULE = "zero-amount-unshielded-send";
export const ZERO_SEND_TARGET = "standard-library::sendUnshielded";

/** Resolved callable identities exclude user-defined namesakes and retain aliases. */
export function zeroSendScope(program: Program, entries: readonly string[] = program.entries, allowance = 20000) {
  return mayCallCircuits(program, new Set([ZERO_SEND_TARGET]), allowance, entries);
}
