import { Expr, Statement, fail } from "../model.js";

export interface ReturnFlow {
  fallsThrough: boolean;
  returns: Expr[];
}

export function returnFlow(statement: Statement, inLoop = false): ReturnFlow {
  const nested = (expression: Expr): void => {
    if (expression.body) returnFlow(expression.body);
    expression.args.forEach(nested);
  };
  if ("expr" in statement) nested(statement.expr);
  if (statement.kind === "if") nested(statement.condition);
  if (statement.kind === "for" && statement.sequence) nested(statement.sequence);
  if (statement.kind === "return") {
    if (inLoop) fail("invalid-loop-return", "Compact does not permit returning out of a for loop", statement.span);
    return { fallsThrough: false, returns: [statement.expr] };
  }
  if (statement.kind === "block" || statement.kind === "bindings") {
    const result: ReturnFlow = { fallsThrough: true, returns: [] };
    for (const child of statement.body) {
      if (!result.fallsThrough) fail("unreachable-statement", "Statement follows an unconditional return", child.span);
      const flow = returnFlow(child, inLoop);
      result.fallsThrough = flow.fallsThrough;
      result.returns.push(...flow.returns);
    }
    return result;
  }
  if (statement.kind === "if") {
    const first = returnFlow(statement.then, inLoop);
    const second = statement.otherwise ? returnFlow(statement.otherwise, inLoop) : { fallsThrough: true, returns: [] };
    return { fallsThrough: first.fallsThrough || second.fallsThrough, returns: [...first.returns, ...second.returns] };
  }
  if (statement.kind === "for") returnFlow(statement.body, true);
  return { fallsThrough: true, returns: [] };
}
