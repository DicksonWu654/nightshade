import type { Expr, Statement } from "../model.js";
import { literalConstant } from "../dataflow/constants.js";

/** Strict source-shape fact: no statements, computations or branch effects may
 * be removed. The condition (and all its effects) is still evaluated once. */
function booleanReturn(statement: Statement, charge: (depth?: number) => boolean, depth: number): boolean | undefined {
  if (!charge(depth)) return;
  if (statement.kind === "block" && statement.body.length === 1) return booleanReturn(statement.body[0], charge, depth + 1);
  if (statement.kind !== "return") return;
  let expr: Expr | undefined = statement.expr;
  while (expr && charge(++depth)) {
    if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") { expr = expr.args[0]; continue; }
    const constant = expr.kind === "literal" ? literalConstant(expr) : undefined;
    return constant?.kind === "boolean" ? constant.value === "true" : undefined;
  }
}

export function redundantBooleanBranch(node: Extract<Statement, { kind: "if" }>,
  charge: (depth?: number) => boolean, depth = 0): { negated: boolean } | undefined {
  if (!node.otherwise || !charge(depth)) return;
  const yes = booleanReturn(node.then, charge, depth + 1), no = booleanReturn(node.otherwise, charge, depth + 1);
  if (yes === undefined || no === undefined || yes === no) return;
  return { negated: !yes };
}
