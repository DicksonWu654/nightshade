import type { Program } from "./index.js";

export const FIELD_RECOMPOSITION_RULE = "field-recomposition-range-review";
/** Structural candidate only. Enforcement and immutable identities come from
 * exact successful predicates; absence never depends on source names. */
export function recompositionTargets(program: Program, allowance = 20000, entries: readonly string[] = program.entries) {
  let work = 0, addition = false, multiplication = false;
  const pending = [...entries], seen = new Set<string>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true };
        const expression = expressions.pop()!;
        addition ||= expression.kind === "binary" && expression.numericType === "Field" && expression.name === "+";
        // An owned multiply-plus-add needs both operators in reachable source.
        // Keep integer multiplication as a candidate too: a checked cast can
        // preserve its owned expression when it becomes a Field operand.
        multiplication ||= expression.kind === "binary" && expression.name === "*";
        if (addition && multiplication) return { complete: true, applicable: true };
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn?.calls ?? []);
  }
  return { complete: true, applicable: false };
}
