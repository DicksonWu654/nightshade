import type { Expr, Span, Statement } from "../model.js";

/** An exact source constraint/transfer pair. Every operand is inspected; no
 * message evaluation, local snapshot, hidden call or extra operand is erased. */
export function onceGateShape(body: Statement | undefined, ledger: string): { guard: Span; write: Span } | undefined {
  if (body?.kind !== "block" || body.body.length !== 2) return;
  const [first, second] = body.body;
  if (first.kind !== "expr" || second.kind !== "expr") return;
  const assertion = first.expr, assignment = second.expr;
  if (assertion.kind !== "assert" || assertion.args.length !== 1 || assertion.assertionMessageLiteral !== true) return;
  const condition = assertion.args[0];
  if (condition.kind !== "unary" || condition.name !== "!" || condition.args.length !== 1) return;
  const reference = (value: Expr | undefined) => value?.kind === "ref" && value.args.length === 0 && value.symbol === ledger && value.ledgerRoot === ledger;
  if (!reference(condition.args[0]) || assignment.kind !== "assign" || assignment.args.length !== 2 || !reference(assignment.args[0])) return;
  const literal = assignment.args[1];
  if (literal.kind !== "literal" || literal.args.length !== 0 || literal.value !== "true" || literal.inferredType !== "Boolean") return;
  return { guard: assertion.span, write: assignment.span };
}
