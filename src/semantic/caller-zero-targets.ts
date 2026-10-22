import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";

export const CALLER_ZERO_RULE = "caller-key-zero-entry-review";

/** Structural admission only. Names and documentation carry no intent evidence. */
export function callerZeroScope(program: Program, entry: string, allowance = 20000) {
  const fn = program.functions.get(entry)!;
  const amounts = fn.symbol.kind === "circuit" ? fn.declaration.parameters.filter(parameter =>
    /^(Field|Uint<\d+>)$/.test(program.representationOf(parameter.type))).map(parameter => parameter.symbol!) : [];
  if (fn.symbol.kind !== "circuit" || !fn.declaration.parameters.some(parameter => program.representationOf(parameter.type) === "Bytes<32>"))
    return { complete: true, applicable: false, amounts, work: 1 };
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, amounts, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const current = program.functions.get(id);
    for (const node of current?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, amounts, work };
        const expression = expressions.pop()!;
        if (expression.kind === "member" && expression.value === "call" && expression.name === "insert") {
          const type = parseType(program.representationOf(expression.args[0].inferredType ?? "unknown"));
          if (type.name === "Map" && type.args.length === 2 && printType(type.args[0]) === "Bytes<32>"
            && /^(Field|Uint<\d+>)$/.test(printType(type.args[1])))
            return { complete: true, applicable: true, amounts, work };
        }
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...current?.calls ?? []);
  }
  return { complete: true, applicable: false, amounts, work };
}
