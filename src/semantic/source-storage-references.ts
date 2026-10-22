import type { Expr, Span, Statement } from "../model.js";

/** Inspect every owned source statement, including CFG-pruned empty bodies. */
export function sourceStorageReferences(body: Statement, storage: ReadonlySet<string>, charge: (depth?: number) => boolean) {
  let complete = true, unresolvedCall = false;
  const references: Span[] = [];
  const visit = (depth: number) => charge(depth) || (complete = false);
  const expression = (expr: Expr, depth: number): void => {
    if (!visit(depth)) return;
    if (expr.kind === "call" && !expr.symbol) { complete = false; unresolvedCall = true; return; }
    if (storage.has(expr.symbol ?? "") || storage.has(expr.ledgerRoot ?? "")) references.push(expr.span);
    for (const child of expr.args) { if (!complete) break; expression(child, depth + 1); }
    if (complete && expr.body) statement(expr.body, depth + 1);
  };
  const statement = (item: Statement, depth: number): void => {
    if (!visit(depth)) return;
    if (item.kind === "block" || item.kind === "bindings") {
      for (const child of item.body) { if (!complete) break; statement(child, depth + 1); }
    } else if (item.kind === "if") {
      expression(item.condition, depth + 1);
      if (complete) statement(item.then, depth + 1);
      if (complete && item.otherwise) statement(item.otherwise, depth + 1);
    } else if (item.kind === "for") {
      if (item.sequence) expression(item.sequence, depth + 1);
      if (complete) statement(item.body, depth + 1);
    } else expression(item.expr, depth + 1);
  };
  statement(body, 0);
  return { complete, unresolvedCall, references: complete ? references : [] };
}

