import type { Program } from "./index.js";
export const SHIELDED_MINT = "standard-library::mintShieldedToken";
export const MINT_CIRCUITS = new Set([SHIELDED_MINT, "standard-library::mintUnshieldedToken"]);
export const EVOLVE_NONCE = "standard-library::evolveNonce";

/** Canonical resolved calls only; exhaustion cannot certify structural absence. */
export function hasShieldedMint(program: Program, entry: string, allowance = 20000): boolean {
  return hasMint(program, entry, allowance, false);
}
export function hasTokenMint(program: Program, entry: string, allowance = 20000): boolean {
  return hasMint(program, entry, allowance, true);
}
function hasMint(program: Program, entry: string, allowance: number, any: boolean): boolean {
  const pending = [entry], seen = new Set<string>();
  let work = 0;
  while (pending.length) {
    if (++work > allowance) return true;
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    if (any ? MINT_CIRCUITS.has(id) : id === SHIELDED_MINT) return true;
    const fn = program.functions.get(id);
    for (const callee of fn?.calls ?? []) { if (++work > allowance) return true; pending.push(callee); }
    for (const node of fn?.cfg.nodes ?? []) {
      if (++work > allowance) return true;
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return true;
        const expr = expressions.pop()!;
        if (any && expr.kind === "member" && expr.value === "call" && ["mintShielded", "mintUnshielded"].includes(expr.name ?? "")
          && expr.args[0]?.inferredType && program.nativeTypeOf(expr.args[0].inferredType) === "Kernel") return true;
        if (expr.kind === "lambda" && expr.symbol) pending.push(expr.symbol);
        expressions.push(...expr.args);
      }
    }
  }
  return false;
}
