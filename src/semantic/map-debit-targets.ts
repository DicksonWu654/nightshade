import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";

export const MAP_DEBIT_RULE = "zero-amount-unguarded-map-debit-review";

/** Conservative structural admission; exact operands are selected from an
 * ordinary successful invocation by the dataflow relation. */
export function mapDebitScope(program: Program, entry: string, allowance = 20000) {
  const fn = program.functions.get(entry)!;
  if (fn.symbol.kind !== "circuit") return { complete: true, applicable: false, work: 1 };
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  let lookup = false, insert = false, subtraction = false;
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const current = program.functions.get(id);
    for (const node of current?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "binary" && expression.name === "-") subtraction = true;
        if (expression.kind === "member" && expression.value === "call" && ["lookup", "insert"].includes(expression.name ?? "")) {
          const type = parseType(program.representationOf(expression.args[0].inferredType ?? "unknown"));
          if (type.name === "Map" && type.args[1] && /^(Field|Uint<\d+>)$/.test(printType(type.args[1]))) {
            if (expression.name === "lookup") lookup = true;
            else insert = true;
          }
        }
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...current?.calls ?? []);
  }
  return { complete: true, applicable: lookup && insert && subtraction, work };
}
