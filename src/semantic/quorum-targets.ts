import type { Program } from "./index.js";
import { ECDSA_VERIFIER } from "./signed-input-targets.js";
export const QUORUM_RULE = "quorum-signer-uniqueness-review";
/** Entry operands retain the presented sequence independently of helper names. */
export function quorumTargets(program: Program): Set<string> {
  return new Set([...program.entries, ECDSA_VERIFIER]);
}
export function quorumScope(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true };
    const id = pending.pop()!;
    if (id === ECDSA_VERIFIER) return { complete: true, applicable: true };
    if (seen.has(id)) continue;
    seen.add(id);
    for (const next of program.functions.get(id)?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true };
      pending.push(next);
    }
  }
  return { complete: true, applicable: false };
}
