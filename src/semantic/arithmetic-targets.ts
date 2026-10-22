import type { Program } from "./index.js";
import { numericBound } from "./types.js";

/** Structural absence only. The quantity rule needs both reachable Field
 * arithmetic and a value-preserving conversion from Uint. Calls and lambdas
 * are traversed; operand/guard/publication evidence remains dataflow's job. */
export function arithmeticTargets(program: Program, allowance = 20000, entries: readonly string[] = program.entries): { complete: boolean; applicable: boolean; work: number } {
  let work = 0, arithmetic = false, quantity = false;
  const pending = [...entries], seen = new Set<string>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "binary" && expression.numericType === "Field" && ["+","-","*"].includes(expression.name ?? "")) {
          arithmetic = true;
          // Compact also coerces a Uint operand implicitly in mixed arithmetic.
          quantity ||= expression.args.some(argument => argument.kind !== "literal" && numericBound(program.representationOf(argument.inferredType ?? "unknown")) !== undefined);
        }
        if (expression.kind === "cast" && expression.castKind === "numeric" && expression.args[0]?.kind !== "literal"
          && numericBound(program.representationOf(expression.args[0]?.inferredType ?? "unknown")) !== undefined) quantity = true;
        if (arithmetic && quantity) return { complete: true, applicable: true, work };
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn?.calls ?? []);
  }
  return { complete: true, applicable: false, work };
}
