import type { Expr, Span, Statement } from "../model.js";
import { spanId } from "../model.js";
import type { Program } from "./index.js";
import { compatible } from "./types.js";

export const BALANCE_THRESHOLD_RULE = "exact-balance-threshold";
const GETTER = "standard-library::unshieldedBalance";
type Comparison = "<" | "<=" | ">" | ">=";
export interface BalanceThresholdObservation {
  location: Span;
  getter: Span;
  caller: string;
  entries: string[];
  comparison: Comparison;
  replacement: "unshieldedBalanceLt" | "unshieldedBalanceLte" | "unshieldedBalanceGt" | "unshieldedBalanceGte";
}
interface Origin { getter: Span; thresholds: Omit<BalanceThresholdObservation, "entries">[]; otherUse: boolean }

/** Entry-referenced source review, not a successful-path or transaction-failure
 * proof. Only identity aliases and a single direct assertion comparison qualify.
 * Any other use, including a closure capture or dead-source use, retains the
 * exact getter conservatively. Semantic symbol identity excludes namesakes. */
export function balanceThresholds(program: Program, allowance = 20000): {
  complete: boolean; observations: BalanceThresholdObservation[]; work: number;
} {
  let work = 0;
  class Exhausted extends Error {}
  const charge = (depth = 0): void => { if (++work > allowance || depth > 128) throw new Exhausted(); };
  const observations: BalanceThresholdObservation[] = [];
  try {
    charge();
    if (!program.functions.has(GETTER)) return { complete: true, observations, work };
    const callers = new Map<string, Set<string>>();
    for (const entry of program.entries) {
      charge();
      const pending = [entry], seen = new Set<string>();
      while (pending.length) {
        charge();
        const id = pending.pop()!;
        if (seen.has(id)) continue;
        seen.add(id);
        const entries = callers.get(id) ?? new Set<string>(); entries.add(entry); callers.set(id, entries);
        for (const callee of program.functions.get(id)?.calls ?? []) { charge(); pending.push(callee); }
      }
    }
    // Direct anonymous calls replace their lambda operand with a resolved call.
    // Inspect the materialized callee as well: a captured local reference is a
    // retained use even when no lambda body remains on the caller expression.
    const referenceOwners = new Map<string, Set<string>>();
    const references = (expr: Expr, owner: string, depth: number): void => {
      charge(depth);
      if (expr.kind === "ref" && expr.symbol) {
        const owners = referenceOwners.get(expr.symbol) ?? new Set<string>(); owners.add(owner); referenceOwners.set(expr.symbol, owners);
      }
      for (const arg of expr.args) references(arg, owner, depth + 1);
      if (expr.body) statementReferences(expr.body, expr.kind === "lambda" && expr.symbol ? expr.symbol : owner, depth + 1);
    };
    const statementReferences = (statement: Statement, owner: string, depth: number): void => {
      charge(depth);
      if (statement.kind === "block" || statement.kind === "bindings") for (const child of statement.body) statementReferences(child, owner, depth + 1);
      else if (statement.kind === "if") {
        references(statement.condition, owner, depth + 1); statementReferences(statement.then, owner, depth + 1);
        if (statement.otherwise) statementReferences(statement.otherwise, owner, depth + 1);
      } else if (statement.kind === "for") {
        if (statement.sequence) references(statement.sequence, owner, depth + 1);
        statementReferences(statement.body, owner, depth + 1);
      } else references(statement.expr, owner, depth + 1);
    };
    for (const caller of callers.keys()) {
      charge(); const body = program.functions.get(caller)?.declaration.body;
      if (body) statementReferences(body, caller, 0);
    }
    for (const [caller, entries] of callers) {
      charge();
      const body = program.functions.get(caller)?.declaration.body;
      if (!body) continue; // Native/witness calls have no source body to review.
      const aliases = new Map<string, Origin>(), direct = new Map<Expr, Origin>();
      const identity = (expr: Expr, depth = 0): Expr => {
        charge(depth);
        if ((expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") && expr.args.length === 1)
          return identity(expr.args[0], depth + 1);
        return expr;
      };
      const origin = (expression: Expr): Origin | undefined => {
        const expr = identity(expression);
        if (expr.kind === "ref" && expr.symbol) return aliases.get(expr.symbol);
        if (expr.kind !== "call" || expr.symbol !== GETTER) return;
        let result = direct.get(expr);
        if (!result) { result = { getter: expr.span, thresholds: [], otherUse: false }; direct.set(expr, result); }
        return result;
      };
      const visitExpression = (expr: Expr, depth: number, ignored?: Expr, captured = false): void => {
        charge(depth);
        if (expr === ignored) {
          // An identity alias's value is not a terminal use. Its call arguments
          // can still use a different retained getter and must be visited.
          if (expr.kind === "call") for (const arg of expr.args) visitExpression(arg, depth + 1, undefined, captured);
          return;
        }
        if (!captured && expr.kind === "assert") {
          const condition = identity(expr.args[0]);
          if (condition.kind === "binary" && ["<", "<=", ">", ">="].includes(condition.name!)) {
            const left = origin(condition.args[0]), right = origin(condition.args[1]);
            const opposite = condition.args[left ? 1 : 0];
            if (!!left !== !!right && compatible(opposite.inferredType ?? "unknown", "Uint<128>")) {
              const selected = left ?? right!, selectedExpr = identity(condition.args[left ? 0 : 1]);
              const comparison = (left ? condition.name : ({ "<": ">", "<=": ">=", ">": "<", ">=": "<=" } as const)[condition.name as Comparison]) as Comparison;
              const replacement = ({ "<": "unshieldedBalanceLt", "<=": "unshieldedBalanceLte", ">": "unshieldedBalanceGt", ">=": "unshieldedBalanceGte" } as const)[comparison];
              selected.thresholds.push({ location: expr.span, getter: selected.getter, caller, comparison, replacement });
              visitExpression(condition.args[left ? 0 : 1], depth + 1, selectedExpr);
              visitExpression(opposite, depth + 1);
              for (const arg of expr.args.slice(1)) visitExpression(arg, depth + 1);
              return;
            }
          }
        }
        const retained = ignored && identity(expr) === ignored ? undefined : origin(expr);
        if (retained) retained.otherUse = true;
        for (const arg of expr.args) visitExpression(arg, depth + 1, ignored, captured);
        if (expr.body) visitStatement(expr.body, depth + 1, true);
      };
      const visitStatement = (statement: Statement, depth = 0, captured = false): void => {
        charge(depth);
        if (statement.kind === "block" || statement.kind === "bindings") {
          for (const child of statement.body) visitStatement(child, depth + 1, captured);
        } else if (statement.kind === "if") {
          visitExpression(statement.condition, depth + 1, undefined, captured);
          visitStatement(statement.then, depth + 1, captured);
          if (statement.otherwise) visitStatement(statement.otherwise, depth + 1, captured);
        } else if (statement.kind === "for") {
          if (statement.sequence) visitExpression(statement.sequence, depth + 1, undefined, captured);
          visitStatement(statement.body, depth + 1, captured);
        } else {
          const bound = statement.kind === "bind" && !captured && statement.symbol
            && (!statement.pattern || statement.pattern.kind === "name") ? origin(statement.expr) : undefined;
          if (bound) aliases.set((statement as Extract<Statement, { kind: "bind" }>).symbol!, bound);
          visitExpression(statement.expr, depth + 1, bound ? identity(statement.expr) : undefined, captured);
        }
      };
      visitStatement(body);
      for (const [alias, item] of aliases) {
        charge();
        for (const owner of referenceOwners.get(alias) ?? []) { charge(); if (owner !== caller) item.otherUse = true; }
      }
      for (const item of direct.values()) {
        charge();
        if (!item.otherUse && item.thresholds.length === 1)
          observations.push({ ...item.thresholds[0], entries: [...entries] });
      }
    }
    // Keep canonical instances explicit rather than intersecting or merging
    // their unrelated binding/value histories at a shared physical source site.
    const unique = new Map(observations.map(item => [JSON.stringify([spanId(item.location), item.caller, item.getter, item.replacement]), item]));
    return { complete: true, observations: [...unique.values()], work };
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    return { complete: false, observations: [], work };
  }
}
