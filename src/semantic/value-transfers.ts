import type { Program } from "./index.js";

export const VALUE_TRANSFER_CIRCUITS = new Set([
  "mintShieldedToken", "mintUnshieldedToken", "sendShielded", "sendUnshielded", "sendImmediateShielded",
].map(name => `standard-library::${name}`));
export const RECEIVE_SHIELDED = "standard-library::receiveShielded";
const RECEIVE_CIRCUITS = new Set([RECEIVE_SHIELDED]);

/** Whole-program syntax is used only for applicability, never as proof that an
 * operation or guard executes. Callee identity excludes namesake user circuits. */
export function mayTransferValue(program: Program, allowance = 20000): { complete: boolean; applicable: boolean; work: number } {
  return mayCallCircuits(program, VALUE_TRANSFER_CIRCUITS, allowance);
}

export function mayReceiveShielded(program: Program, allowance = 20000): { complete: boolean; applicable: boolean; work: number } {
  return mayCallCircuits(program, RECEIVE_CIRCUITS, allowance);
}

export function mayCallCircuits(program: Program, targets: ReadonlySet<string>, allowance: number, entries: readonly string[] = program.entries): { complete: boolean; applicable: boolean; work: number } {
  let work = 0;
  const visited = new Set<string>(), pending = [...entries];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (visited.has(id)) continue;
    visited.add(id);
    if (targets.has(id)) return { complete: true, applicable: true, work };
    for (const callee of program.functions.get(id)?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, work };
      pending.push(callee);
    }
  }
  return { complete: true, applicable: false, work };
}
