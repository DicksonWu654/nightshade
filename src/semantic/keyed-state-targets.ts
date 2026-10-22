import type { Expr } from "../model.js";
import type { Program } from "./index.js";
import { parseType } from "./types.js";

/** Absence only: all resolved callable edges include ordinary and higher-order
 * callbacks. Unresolved represented bodies cannot certify absence. */
export function keyedStateTargets(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const pending = [entry], seen = new Set<string>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || !["intrinsic", "witness"].includes(symbol.kind)) return { complete: false, applicable: true, work };
      continue;
    }
    for (const node of fn.cfg.nodes) {
      const expressions: Expr[] = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "member" && expression.value === "call" && ["member", "insert"].includes(expression.name ?? "")
          && ["Map", "Set"].includes(parseType(program.representationOf(expression.args[0].inferredType ?? "unknown")).name))
          return { complete: true, applicable: true, work };
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn.calls);
  }
  return { complete: true, applicable: false, work };
}
