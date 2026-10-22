import type { Expr } from "../model.js";
import type { Program } from "./index.js";
import { parseType } from "./types.js";

/** Bounded applicability only: canonical collection queries, never name-based
 * replay intent or evidence that a query executes. */
export function collectionTargets(program: Program, allowance = 20000, entries: readonly string[] = program.entries,
  receiverTypes: readonly string[] = ["Map", "Set"]): { complete: boolean; applicable: boolean; work: number } {
  let work = 0;
  const seen = new Set<string>(), pending = [...entries];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions: Expr[] = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "member" && expression.value === "call" && expression.name === "member"
          && receiverTypes.includes(parseType(program.representationOf(expression.args[0].inferredType ?? "unknown")).name))
          return { complete: true, applicable: true, work };
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn?.calls ?? []);
  }
  return { complete: true, applicable: false, work };
}
