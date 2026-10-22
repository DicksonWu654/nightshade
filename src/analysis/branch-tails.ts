import type { Expr, Span, Statement } from "../model.js";

export interface DuplicatedBranchTail {
  location: Span;
  continuation: Span;
  returnLocation: Span;
  statements: number;
  arm: "then" | "else";
}

/** Resolved source equality, not value equality or execution equivalence.
 * No binding, callback body or nested control is compared. Every recursive
 * edge consumes the surrounding source-observation allowance. */
function sameExpression(left: Expr, right: Expr, charge: (depth?: number) => boolean, depth: number): boolean {
  if (!charge(depth) || left.kind !== right.kind || ["lambda", "map", "fold"].includes(left.kind)
    || left.body || right.body || left.parameters || right.parameters) return false;
  if ((left.kind === "ref" || left.kind === "call") && (!left.symbol || !right.symbol)) return false;
  if (left.symbol !== right.symbol || left.ledgerRoot !== right.ledgerRoot
    || left.type !== right.type || left.inferredType !== right.inferredType || left.numericType !== right.numericType
    || left.checkedArithmetic !== right.checkedArithmetic || left.castKind !== right.castKind
    || left.generics !== right.generics || left.ledgerType !== right.ledgerType
    || left.value !== right.value || left.literalString !== right.literalString || left.paddingSize !== right.paddingSize) return false;
  // Canonical call/ref symbols distinguish aliases and same-name shadowing.
  // Field names, operators and native member names remain structural operands.
  if (left.kind !== "call" && left.kind !== "ref" && left.name !== right.name) return false;
  if (left.event?.name !== right.event?.name || left.event?.version !== right.event?.version || left.event?.tag !== right.event?.tag) return false;
  if (!!left.fields !== !!right.fields || left.fields?.length !== right.fields?.length || left.args.length !== right.args.length) return false;
  for (let i = 0; i < (left.fields?.length ?? 0); i++) if (!charge(depth + 1) || left.fields![i] !== right.fields![i]) return false;
  return left.args.every((arg, index) => sameExpression(arg, right.args[index], charge, depth + 1));
}

/** One to seven expression statements plus an explicit return, copied between
 * a terminating branch suffix and its immediate following continuation. These
 * are alternative routes, never evidence of a twice-executed operation. */
export function duplicatedBranchTails(node: Extract<Statement, { kind: "if" }>, continuation: readonly Statement[],
  charge: (depth?: number) => boolean, depth = 0): DuplicatedBranchTail[] {
  const observations: DuplicatedBranchTail[] = [];
  for (const [arm, branch] of [["then", node.then], ["else", node.otherwise]] as const) {
    if (!branch || branch.kind !== "block") continue;
    const statements = branch.body;
    if (statements.at(-1)?.kind !== "return") continue;
    // Do not describe a suffix already excluded by an earlier direct stop.
    if (statements.slice(0, -1).some(item => item.kind === "return"
      || item.kind === "expr" && item.expr.kind === "assert" && item.expr.args[0]?.kind === "literal" && item.expr.args[0].value === "false")) continue;
    let matched = 0;
    for (let length = 2; length <= Math.min(8, statements.length, continuation.length); length++) {
      if (!charge(depth) || continuation[length - 1].kind !== "return") continue;
      const suffix = statements.slice(-length);
      if (!suffix.slice(0, -1).every(item => item.kind === "expr")
        || !continuation.slice(0, length - 1).every(item => item.kind === "expr")) continue;
      if (suffix.every((item, index) => {
        const other = continuation[index];
        return (item.kind === "expr" || item.kind === "return") && other.kind === item.kind
          && sameExpression(item.expr, other.expr, charge, depth + 1);
      })) matched = length;
    }
    if (matched) observations.push({ location: statements[statements.length - matched].span,
      continuation: continuation[0].span, returnLocation: statements.at(-1)!.span, statements: matched, arm });
  }
  return observations;
}
