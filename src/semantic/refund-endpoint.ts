import type { Expr, Span, Statement } from "../model.js";
import type { Program } from "./index.js";
import { numericBound } from "./types.js";
import { ZERO_SEND_TARGET } from "./zero-send-targets.js";
export const REFUND_ENDPOINT_RULE = "unshielded-refund-endpoint-review";
export type EndpointCharge = (steps?: number, values?: number) => void;
/** This observer supports already resolved concrete Uint carriers only; it
 * never traverses a nominal/type graph outside its charged local proof. */
export function endpointUnsignedBound(type: string, charge: EndpointCharge): bigint | undefined {
  charge(1 + Math.ceil(type.length / 32), 1);
  if (type.length > 100 || !/^Uint<(?:\d+|0\.\.\d+)>$/.test(type)) return undefined;
  return numericBound(type);
}
export interface EndpointCandidate {
  entry: string; send: Span; subtraction: Expr; validator: string; assertion: Span;
  roles: readonly [number, number, number, number]; guards: Expr[]; loopExpressions: Expr[]; bindingRoles: readonly [string, string]; actualRoles: readonly string[]; bindings: ReadonlyMap<string, Expr>; mutable: ReadonlySet<string>; selectedCallStart: number; validatorArgs: readonly Expr[];
}
const discoveredCandidates = new WeakMap<EndpointCandidate, { program: Program; inputs: EndpointCandidate }>();
export function isDiscoveredRefundEndpoint(candidate: EndpointCandidate, program: Program): boolean { return discoveredCandidates.get(candidate)?.program === program; }
/** Public handles never expose the private discovery snapshot. Each evaluator
 * receives its own maps; their typed expression values are immutable copies
 * retaining the original source spans and resolved symbols. */
export function refundEndpointInputs(candidate: EndpointCandidate, program: Program, charge: EndpointCharge): EndpointCandidate {
  const discovered = discoveredCandidates.get(candidate);
  if (!discovered || discovered.program !== program) throw new Error("Refund candidate lacks its source-discovery attestation");
  const inputs = discovered.inputs;
  charge(1 + inputs.bindings.size + inputs.mutable.size, 16 + inputs.bindings.size * 2 + inputs.mutable.size);
  return { ...inputs, bindings: new Map(inputs.bindings), mutable: new Set(inputs.mutable) };
}
function snapshotRefundInputs(candidate: EndpointCandidate, charge: EndpointCharge): EndpointCandidate {
  charge(1, 2); const memo = new WeakMap<Expr, Expr>();
  const copy = (expr: Expr, depth = 0): Expr => {
    charge(); if (depth > 64) throw new Error("Refund private input snapshot depth exhausted");
    const prior = memo.get(expr); if (prior) return prior;
    charge(1, 24 + expr.args.length);
    const retained: Expr = { ...expr, span: Object.freeze({ ...expr.span }), args: expr.args.map(arg => copy(arg, depth + 1)) };
    Object.freeze(retained.args); Object.freeze(retained); memo.set(expr, retained); return retained;
  };
  charge(1 + candidate.bindings.size, 16 + candidate.bindings.size * 2 + candidate.mutable.size
    + candidate.guards.length + candidate.loopExpressions.length + candidate.validatorArgs.length);
  const bindings = new Map<string, Expr>();
  for (const [symbol, expr] of candidate.bindings) bindings.set(symbol, copy(expr));
  return Object.freeze({ ...candidate, bindings, mutable: new Set(candidate.mutable),
    send: Object.freeze({ ...candidate.send }), assertion: Object.freeze({ ...candidate.assertion }),
    subtraction: copy(candidate.subtraction), guards: Object.freeze(candidate.guards.map(expr => copy(expr))) as unknown as Expr[],
    loopExpressions: Object.freeze(candidate.loopExpressions.map(expr => copy(expr))) as unknown as Expr[],
    validatorArgs: Object.freeze(candidate.validatorArgs.map(expr => copy(expr))) });
}
export function unwrapEndpoint(expr: Expr, bindings: ReadonlyMap<string, Expr>, charge: EndpointCharge, depth = 0): Expr {
  charge(); if (depth > 32) throw new Error("Refund operand provenance depth exhausted");
  if (expr.kind === "disclose" || expr.kind === "cast" && ["numeric", "identity"].includes(expr.castKind ?? "")) return unwrapEndpoint(expr.args[0], bindings, charge, depth + 1);
  if (expr.kind === "ref" && expr.symbol && bindings.has(expr.symbol)) return unwrapEndpoint(bindings.get(expr.symbol)!, bindings, charge, depth + 1);
  return expr;
}
/** Exact lexical snapshots only: a fresh expression/read is never the same
 * operand merely because it addresses the same storage region. */
function operand(expr: Expr, bindings: ReadonlyMap<string, Expr>, charge: EndpointCharge): string {
  const value = unwrapEndpoint(expr, bindings, charge);
  if (value.kind !== "ref" || !value.symbol) throw new Error("Refund operand is not an exact lexical snapshot");
  return value.symbol;
}
export function discoverRefundEndpoints(program: Program, entry: string, charge: EndpointCharge): EndpointCandidate[] {
  const fn = program.functions.get(entry); if (!fn?.declaration.body) return [];
  const bindings = new Map<string, Expr>(), assertions: { call: Expr; span: Span }[] = [], result: EndpointCandidate[] = [];
  const mutable = new Set<string>(); const allBindings = new Map<string, Expr>(); let sends = false, checkpoint = false, unknownLoopBounds = false;
  const lateAssertions: Expr[] = [], allPureCalls: Expr[] = [], loopExpressions: Expr[] = [];
  const reserve = (expr: Expr, depth = 0) => { charge(1, 1); if (depth > 64) throw new Error("Refund source expression depth exhausted"); sends ||= expr.kind === "call" && expr.symbol === ZERO_SEND_TARGET; checkpoint ||= expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel"; if (expr.kind === "assign" && expr.args[0]?.symbol) mutable.add(expr.args[0].symbol); for (const arg of expr.args) reserve(arg, depth + 1); };
  const inventory = (statement: Statement, inLoop = false, depth = 0): void => {
    charge(); if (depth > 64) throw new Error("Refund source inventory depth exhausted");
    if (statement.kind === "block" || statement.kind === "bindings") for (const child of statement.body) inventory(child, inLoop, depth + 1);
    else if (statement.kind === "if") { reserve(statement.condition); if (inLoop) { charge(1, 1); loopExpressions.push(statement.condition); } inventory(statement.then, inLoop, depth + 1); if (statement.otherwise) inventory(statement.otherwise, inLoop, depth + 1); }
    else if (statement.kind === "for") {
      if (statement.sequence) { reserve(statement.sequence); charge(1, 1); loopExpressions.push(statement.sequence); }
      if (typeof statement.start !== "number" || typeof statement.end !== "number") unknownLoopBounds = true;
      inventory(statement.body, statement.start !== statement.end, depth + 1);
    } else { reserve(statement.expr); if (inLoop) { charge(1, 1); loopExpressions.push(statement.expr); } }
  };
  inventory(fn.declaration.body);
  if (!sends) return [];
  const walk = (statement: Statement, guards: Expr[], conditional = false, conditions: Expr[] = []): void => {
    charge();
    if (statement.kind === "block" || statement.kind === "bindings") { for (const child of statement.body) walk(child, guards, conditional, conditions); return; }
    if (statement.kind === "if") {
      // A bounded branch controls the selected source send. Keep its exact
      // predicate; exclusive branches never donate a validator assertion.
      charge(1, bindings.size * 2); const saved = new Map(bindings); const n = assertions.length;
      charge(1, guards.length + conditions.length + 2); walk(statement.then, [...guards, statement.condition], true, [...conditions, statement.condition]);
      bindings.clear(); for (const [key, value] of saved) { charge(1, 2); bindings.set(key, value); } assertions.length = n;
      if (statement.otherwise) {
        const not: Expr = { kind: "unary", name: "!", args: [statement.condition], span: statement.condition.span };
        charge(1, guards.length + conditions.length + 2); walk(statement.otherwise, [...guards, not], true, [...conditions, not]);
        bindings.clear(); for (const [key, value] of saved) { charge(1, 2); bindings.set(key, value); } assertions.length = n;
      }
      return;
    }
    if (statement.kind === "for") {
      const containsSend = (part: Statement): boolean => {
        charge(); if (part.kind === "block" || part.kind === "bindings") return part.body.some(containsSend);
        if (part.kind === "if") return containsSend(part.then) || !!part.otherwise && containsSend(part.otherwise);
        if (part.kind === "for") return containsSend(part.body);
        const expressionHasSend = (expr: Expr): boolean => { charge(); return expr.symbol === ZERO_SEND_TARGET || expr.args.some(expressionHasSend); };
        return expressionHasSend(part.expr);
      };
      if (containsSend(statement.body)) throw new Error("Refund source-local loop sends are unsupported");
      return;
    }
    if (statement.kind === "bind") {
      if (statement.pattern?.kind === "tuple") {
        for (const leaf of statement.pattern.children) { charge(1, 1); if (leaf.kind !== "name" || !leaf.symbol || endpointUnsignedBound(program.symbols.get(leaf.symbol)?.type ?? "unknown", charge) === undefined) throw new Error("Refund tuple snapshot binding is unsupported"); }
        return;
      }
      if (!statement.symbol || statement.pattern && statement.pattern.kind !== "name") throw new Error("Refund parameter patterns are unsupported");
      // Retain refs/casts/arithmetic only; opaque initializers are snapshot
      // leaves identified by their local binding, never projected storage.
      const expr = statement.expr;
      const inner = unwrapEndpoint(expr, bindings, charge);
      if (["ref", "binary"].includes(inner.kind) && !(inner.kind === "ref" && program.symbols.get(inner.symbol!)?.kind === "ledger")) { charge(1, 4); bindings.set(statement.symbol, expr); allBindings.set(statement.symbol, expr); }
      return;
    }
    const expr = statement.expr;
    if (expr.kind === "assert") {
      const condition = unwrapEndpoint(expr.args[0], bindings, charge);
      if (condition.kind === "call" && condition.symbol && program.functions.get(condition.symbol)?.declaration.pure)
        { charge(1, 3); assertions.push({ call: condition, span: expr.span }); allPureCalls.push(condition); }
      else {
        charge(1, 2); guards.push(condition);
        let guarded = condition;
        for (const branch of conditions) {
          charge(1, 3); guarded = { kind: "binary", name: "||", args: [{ kind: "unary", name: "!", args: [branch], span: branch.span }, guarded], span: condition.span };
        }
        lateAssertions.push(guarded);
      }
      return;
    }
    if (expr.kind !== "call" || expr.symbol !== ZERO_SEND_TARGET) return;
    const amount = unwrapEndpoint(expr.args[1], bindings, charge);
    if (amount.kind !== "binary" || amount.name !== "-"
      || endpointUnsignedBound(amount.numericType ?? "unknown", charge) === undefined) return;
    if (!assertions.some(assertion => { charge(); return assertion.call.args.length === 4; })) return;
    const left = unwrapEndpoint(amount.args[0], bindings, charge), right = unwrapEndpoint(amount.args[1], bindings, charge);
    if (left.kind === "literal" || right.kind === "literal") return;
    const b = operand(amount.args[0], bindings, charge), q = operand(amount.args[1], bindings, charge);
    if (program.symbols.get(b)?.kind === "ledger" || program.symbols.get(q)?.kind === "ledger") throw new Error("Refund arithmetic uses a live ledger operand rather than a local snapshot");
    if (mutable.has(b) || mutable.has(q)) throw new Error("Refund operands are assigned within the source entry");
    for (const assertion of assertions) {
      charge(); const call = assertion.call; if (call.args.length !== 4) continue;
      charge(1, 12);
      const keys = call.args.map(arg => { const value = unwrapEndpoint(arg, bindings, charge); return value.kind === "ref" && value.symbol ? value.symbol : undefined; });
      charge(1 + Math.ceil((b.length + q.length + keys.reduce((total, value) => total + (value?.length ?? 0), 0)) / 64));
      const bi = keys.indexOf(b), qi = keys.indexOf(q); if (bi < 0 || qi < 0 || bi === qi) { if (keys.some(key => !key)) throw new Error("Refund validator argument snapshot mapping is unavailable"); continue; }
      if (keys.some(key => !key) || new Set(keys).size !== 4) throw new Error("Refund validator requires four distinct exact source operands");
      const rest = [0, 1, 2, 3].filter(i => i !== bi && i !== qi);
      // Both possible numerator/divisor mappings are certified by the complete
      // validator expression, rather than parameter names.
      for (const [pi, ai] of [rest, [...rest].reverse()]) {
        charge(1, 12 + guards.length); result.push({ entry, send: expr.span, subtraction: amount, validator: call.symbol!, assertion: assertion.span,
          roles: [bi, pi, ai, qi], guards, loopExpressions, bindingRoles: [b, q], actualRoles: keys as string[], bindings: allBindings, mutable, selectedCallStart: call.span.start, validatorArgs: call.args });
      }
    }
  };
  walk(fn.declaration.body, []);
  if (result.length && unknownLoopBounds) throw new Error("Refund source loop bound is unsupported");
  if (result.length && checkpoint) throw new Error("Refund source certificate crosses a checkpoint");
  for (const candidate of result) { charge(1 + allPureCalls.length + candidate.guards.length, candidate.guards.length + lateAssertions.length + allPureCalls.length); candidate.guards = [...candidate.guards, ...lateAssertions, ...allPureCalls.filter(call => call.span.start !== candidate.selectedCallStart)]; }
  return result.map(candidate => {
    charge(1, 12 + candidate.guards.length + candidate.roles.length + candidate.actualRoles.length + candidate.loopExpressions.length + candidate.validatorArgs.length);
    const retained = Object.freeze({ ...candidate, roles: Object.freeze([...candidate.roles]) as typeof candidate.roles,
      actualRoles: Object.freeze([...candidate.actualRoles]), validatorArgs: Object.freeze([...candidate.validatorArgs]),
      guards: Object.freeze([...candidate.guards]) as unknown as Expr[], loopExpressions: Object.freeze([...candidate.loopExpressions]) as unknown as Expr[] });
    const inputs = snapshotRefundInputs(retained, charge);
    discoveredCandidates.set(retained, { program, inputs }); return retained;
  });
}
