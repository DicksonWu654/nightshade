import type { Program } from "./index.js";
import { intrinsicModel } from "./intrinsics.js";

/** Applicability only. Witness reachability and a possible ledger write do not
 * prove that witness output reaches that write. Exhaustion supplies no absence. */
export function hasWitnessState(program: Program, entry: string, allowance = 20000): boolean {
  const pending = [entry], seen = new Set<string>();
  let work = 0, witness = false, write = false;
  while (pending.length) {
    if (++work > allowance) return true;
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const symbol = program.symbols.get(id);
    witness ||= symbol?.kind === "witness" || symbol?.kind === "intrinsic" && intrinsicModel(symbol).kind === "witness";
    const fn = program.functions.get(id);
    write ||= !!fn?.writesState.size;
    if (witness && write) return true;
    for (const callee of fn?.calls ?? []) { if (++work > allowance) return true; pending.push(callee); }
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return true;
        const expr = expressions.pop()!;
        if (expr.kind === "lambda" && expr.symbol) pending.push(expr.symbol);
        expressions.push(...expr.args);
      }
    }
  }
  return false;
}
