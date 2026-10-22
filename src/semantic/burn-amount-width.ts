import type { Expr, Parameter, Span, Statement } from "../model.js";
import type { Program } from "./index.js";

export const BURN_AMOUNT_WIDTH_RULE = "shielded-burn-amount-width";
const SENDS = new Set(["standard-library::sendShielded", "standard-library::sendImmediateShielded"]);
const BURN = "standard-library::shieldedBurnAddress";
type Origin = { kind: "parameter"; parameter: Parameter } | { kind: "burn" };
export interface BurnAmountWidthObservation { entry: string; parameter: Parameter; location: Span; primitive: string }

/** Owned, bounded syntactic relationship. This does not establish successful reach.
 * Only immutable aliases, disclosure, widening casts and linear pure forwarding
 * returns preserve identity. No arithmetic or user-named recipient is a certificate. */
export function burnAmountWidths(program: Program, allowance = 20000) {
  let work = 0;
  const observations: BurnAmountWidthObservation[] = [];
  class Exhausted extends Error {}
  const charge = (depth: number) => { if (++work > allowance || depth > 100) throw new Exhausted(); };
  const copy = (env: Map<string, Origin>) => { work += env.size; charge(0); return new Map(env); };
  try {
    for (const entry of program.entries) {
      charge(0);
      const fn = program.functions.get(entry);
      if (!fn?.declaration.body) continue;
      const mutated = new Set<string>();
      const mutations = (s: Statement, depth: number): void => {
        charge(depth);
        const expression = (e: Expr, expressionDepth = depth): void => { charge(expressionDepth); if (e.kind === "assign") { let target = e.args[0]; while (target && ["member", "index"].includes(target.kind)) { charge(depth); target = target.args[0]; } if (target?.symbol) mutated.add(target.symbol); } for (const a of e.args) expression(a, expressionDepth + 1); };
        if (s.kind === "block" || s.kind === "bindings") s.body.forEach(c => mutations(c, depth + 1));
        else if (s.kind === "if") { expression(s.condition); mutations(s.then, depth + 1); if (s.otherwise) mutations(s.otherwise, depth + 1); }
        else if (s.kind === "for") { if (s.sequence) expression(s.sequence); mutations(s.body, depth + 1); }
        else expression(s.expr);
      };
      mutations(fn.declaration.body, 0);
      const origin = (e: Expr, env: Map<string, Origin>, depth: number): Origin | undefined => {
        charge(depth);
        if (e.kind === "ref") return e.symbol && !mutated.has(e.symbol) ? env.get(e.symbol) : undefined;
        if (e.kind === "disclose") return origin(e.args[0], env, depth + 1);
        if (e.kind === "cast" && e.args[0].inferredType && e.inferredType && ["Uint<64>", "Uint<128>"].includes(program.representationOf(e.inferredType))) {
          const from = program.representationOf(e.args[0].inferredType), to = program.representationOf(e.inferredType);
          if (from === to || from === "Uint<64>" && to === "Uint<128>") return origin(e.args[0], env, depth + 1);
        }
        if (e.kind !== "call") return undefined;
        if (e.symbol === BURN) return { kind: "burn" };
        const helper = e.symbol && program.functions.get(e.symbol);
        if (!helper || !helper.declaration.pure || helper.readsState.size || helper.writesState.size || helper.emitsEvent || helper.declaration.body?.kind !== "block") return undefined;
        const local = new Map<string, Origin>();
        for (const [index, parameter] of helper.declaration.parameters.entries()) { charge(depth); const value = e.args[index] && origin(e.args[index], env, depth + 1); if (parameter.symbol && value) local.set(parameter.symbol, value); }
        for (const statement of helper.declaration.body.body) {
          charge(depth);
          if (statement.kind === "bind" && statement.symbol) { const value = origin(statement.expr, local, depth + 1); if (value) local.set(statement.symbol, value); }
          else if (statement.kind === "return") return origin(statement.expr, local, depth + 1);
          else return undefined;
        }
        return undefined;
      };
      const visitExpr = (e: Expr, env: Map<string, Origin>, depth: number): void => {
        charge(depth);
        if (e.kind === "call" && e.symbol && SENDS.has(e.symbol)) {
          const recipient = origin(e.args[1], env, depth + 1), amount = origin(e.args[2], env, depth + 1);
          const coinType = e.args[0]?.inferredType;
          const api = program.symbols.get(e.symbol)?.declaration;
          if (recipient?.kind === "burn" && amount?.kind === "parameter" && program.representationOf(amount.parameter.type) === "Uint<64>"
            && coinType && program.representationOf(program.fieldsOf(coinType)?.value ?? "unknown") === "Uint<128>"
            && api?.parameters[2] && program.representationOf(api.parameters[2].type) === "Uint<128>")
            observations.push({ entry, parameter: amount.parameter, location: e.span, primitive: e.symbol });
        }
        for (const arg of e.args) visitExpr(arg, env, depth + 1);
      };
      const visit = (s: Statement, env: Map<string, Origin>, depth: number): void => {
        charge(depth);
        if (s.kind === "block" || s.kind === "bindings") for (const child of s.body) visit(child, env, depth + 1);
        else if (s.kind === "if") { visitExpr(s.condition, env, depth + 1); visit(s.then, copy(env), depth + 1); if (s.otherwise) visit(s.otherwise, copy(env), depth + 1); }
        else if (s.kind === "for") { if (s.sequence) visitExpr(s.sequence, env, depth + 1); visit(s.body, copy(env), depth + 1); }
        else { visitExpr(s.expr, env, depth + 1); if (s.kind === "bind" && s.symbol && !mutated.has(s.symbol)) { const value = origin(s.expr, env, depth + 1); if (value) env.set(s.symbol, value); } }
      };
      const env = new Map<string, Origin>();
      for (const parameter of fn.declaration.parameters) { charge(0); if (parameter.symbol) env.set(parameter.symbol, { kind: "parameter", parameter }); }
      visit(fn.declaration.body, env, 0);
    }
    return { complete: true, observations, work };
  } catch (error) { if (!(error instanceof Exhausted)) throw error; return { complete: false, observations: [], work }; }
}
