import type { Program } from "./index.js";

export const TRANSIENT_LEDGER_RULE = "transient-digest-to-ledger";
export const TRANSIENT_PRIMITIVES = new Set(["intrinsic::transientHash", "intrinsic::transientCommit"]);

/** Call-graph absence only; does not infer a sink or storage lifetime. */
export function transientScope(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    if (TRANSIENT_PRIMITIVES.has(id)) return { complete: true, applicable: true, work };
    for (const next of program.functions.get(id)?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, work };
      pending.push(next);
    }
  }
  return { complete: true, applicable: false, work };
}
