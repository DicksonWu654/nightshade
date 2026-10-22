import type { Expr } from "../model.js";
import type { FunctionInfo } from "../semantic/index.js";

/** A total, effect-free recurrence: equal items forward the accumulator;
 * otherwise a scalar comparison replaces it. No source-name recognition. */
export interface OverwriteFoldPlan {
  condition: Expr;
  replacement: Expr;
  left: number;
  right: number;
}

export function overwriteFoldPlan(fn: FunctionInfo): OverwriteFoldPlan | undefined {
  const declaration = fn.declaration, parameters = declaration.parameters;
  if (!declaration.pure || declaration.type !== "Boolean" || parameters.length !== 3
    || parameters[0].type !== "Boolean" || parameters.some(parameter => parameter.pattern && parameter.pattern.kind !== "name")
    || !parameters.slice(1).every(parameter => /^Uint<\d+>$/.test(parameter.type))
    || fn.calls.size || fn.readsState.size || fn.writesState.size || fn.emitsEvent) return;
  const body = declaration.body;
  if (body?.kind !== "block" || body.body.length !== 1 || body.body[0].kind !== "return") return;
  const expression = body.body[0].expr;
  if (expression.kind !== "conditional" || expression.args[1].kind !== "ref"
    || expression.args[1].symbol !== parameters[0].symbol) return;
  const [condition, , replacement] = expression.args;
  const item = (value: Expr): number => value.kind === "ref" ? parameters.findIndex(parameter => parameter.symbol === value.symbol) : -1;
  if (condition.kind !== "binary" || condition.name !== "==" || condition.args.some(value => item(value) < 1)
    || replacement.kind !== "binary" || !["<", "<=", ">", ">="].includes(replacement.name!)
    || replacement.args.some(value => item(value) < 1)) return;
  return { condition, replacement, left: item(condition.args[0]), right: item(condition.args[1]) };
}
