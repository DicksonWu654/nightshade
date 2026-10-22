import type { Pattern } from "../model.js";
import type { Program } from "./index.js";
import { parseType, printType, TUPLE_TYPE } from "./types.js";

/** Whole-program inapplicability only, never proof of a selection or its tag.
 * Match the member and pattern projections used by the ordinary transfer. Passing
 * or constructing an Either without selecting a payload needs no observer. */
export function eitherTargets(program: Program, allowance = 20000, entries: readonly string[] = program.entries): { complete: boolean; applicable: boolean; work: number } {
  let work = 0, exhausted = false;
  const seen = new Set<string>(), pending = [...entries];
  const charge = (): boolean => { if (++work > allowance) exhausted = true; return !exhausted; };
  const selection = (type: string | undefined, field: string | undefined): boolean =>
    (field === "left" || field === "right") && (!type || type === "unknown" || program.nativeTypeOf(type) === "Either");
  const patternSelects = (pattern: Pattern, type: string | undefined, depth = 0): boolean => {
    if (!charge() || depth > 16) { exhausted = true; return true; }
    if (pattern.kind === "name" || pattern.kind === "skip") return false;
    const fields = type ? program.fieldsOf(type) : undefined;
    const term = parseType(type ? program.representationOf(type) : "unknown");
    return pattern.children.some((child, index) => {
      if (child.kind === "skip") return false;
      if (pattern.kind === "struct" && selection(type, pattern.fields?.[index])) return true;
      const projected = pattern.kind === "struct" ? fields?.[pattern.fields![index]]
        : term.name === TUPLE_TYPE ? term.args[index] && printType(term.args[index])
        : term.name === "Vector" ? term.args[1] && printType(term.args[1]) : undefined;
      return patternSelects(child, projected, depth + 1);
    });
  };
  while (pending.length) {
    if (!charge()) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    if (fn?.declaration.parameters.some(parameter => parameter.pattern && patternSelects(parameter.pattern, parameter.type)))
      return { complete: !exhausted, applicable: true, work };
    for (const node of fn?.cfg.nodes ?? []) {
      if (node.pattern && patternSelects(node.pattern, node.expr?.inferredType)) return { complete: !exhausted, applicable: true, work };
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (!charge()) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "member" && selection(expression.args[0]?.inferredType, expression.name))
          return { complete: !exhausted, applicable: true, work };
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn?.calls ?? []);
  }
  return { complete: !exhausted, applicable: exhausted, work };
}
