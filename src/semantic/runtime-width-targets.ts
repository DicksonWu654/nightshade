import { spanId } from "../model.js";
import type { Program } from "./index.js";

export const SHIELDED_WIDTH_RULE = "shielded-coin-runtime-width";
export const SHIELDED_OUTPUT_INTRINSIC = "intrinsic::createZswapOutput";

/** Resolved source sites, not names of user circuits or possible coin values. */
export function runtimeWidthOutputSites(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const sites = new Set<string>(), pending = [entry], seen = new Set<string>();
  const charge = () => Number.isSafeInteger(allowance) && ++work <= allowance;
  const unavailable = () => ({ complete: false, applicable: true, work, sites });
  while (pending.length) {
    if (!charge()) return unavailable();
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const symbol = program.symbols.get(id), fn = program.functions.get(id);
    if (!fn) {
      if (symbol?.kind === "intrinsic" || symbol?.kind === "witness") continue;
      return unavailable();
    }
    for (const node of fn.cfg.nodes) {
      if (!charge()) return unavailable();
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (!charge()) return unavailable();
        const expression = expressions.pop()!;
        // Higher-order native calls retain their canonical callback reference span.
        if ((expression.kind === "call" || expression.kind === "ref") && expression.symbol === SHIELDED_OUTPUT_INTRINSIC
          && program.symbols.get(expression.symbol)?.kind === "intrinsic") sites.add(spanId(expression.span));
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        for (const argument of expression.args) {
          if (!charge()) return unavailable();
          expressions.push(argument);
        }
      }
    }
    for (const callee of fn.calls) {
      if (!charge()) return unavailable();
      pending.push(callee);
    }
  }
  return { complete: true, applicable: sites.size > 0, work, sites };
}

/** Exhaustion never supplies a native-output absence certificate. */
export function runtimeWidthScope(program: Program, entry: string, allowance = 20000): { complete: boolean; applicable: boolean; work: number } {
  const { complete, applicable, work } = runtimeWidthOutputSites(program, entry, allowance);
  return { complete, applicable, work };
}
