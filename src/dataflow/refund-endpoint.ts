import type { Expr, Statement } from "../model.js";
import type { Program } from "../semantic/index.js";
import { endpointUnsignedBound, isDiscoveredRefundEndpoint, refundEndpointInputs, type EndpointCandidate, type EndpointCharge } from "../semantic/refund-endpoint.js";
export interface RefundEndpointCertificate { candidate: EndpointCandidate; formula: string; witness: readonly bigint[]; scope: "source-local-formula" }
const issuedCertificates = new WeakMap<RefundEndpointCertificate, Program>();
export function isRefundEndpointCertificate(certificate: RefundEndpointCertificate, program: Program): boolean { return issuedCertificates.get(certificate) === program; }
// Keep raw formula/equality keys beside their accounting representation: caller
// symbols contain physical paths, and nested arithmetic must retain only the
// location-independent size while preserving every operator/source character.
type Key = { key: string; keyText: string };
type Value = Key & { value: bigint | boolean };
const atom = (key: string, keyText = key): Key => ({ key, keyText });
/** Complete evaluation of the pure owned body. Every checked intermediate,
 * assertion and return is retained; unsupported syntax cannot be dropped. */
export function certifyRefundEndpoint(program: Program, candidate: EndpointCandidate, charge: EndpointCharge): RefundEndpointCertificate | undefined {
  charge(); if (!isDiscoveredRefundEndpoint(candidate, program)) throw new Error("Refund candidate lacks its source-discovery attestation");
  candidate = refundEndpointInputs(candidate, program, charge);
  const declaration = program.functions.get(candidate.validator)?.declaration;
  if (!declaration?.pure || !declaration.body || declaration.parameters.length !== 4) throw new Error("Refund validator body is unavailable");
  charge(1, 2); const env = new Map<string, Value>(); const [bi, pi, ai, qi] = candidate.roles;
  charge(1, 12); const labels = new Map([[bi, "B"], [pi, "P"], [ai, "A"], [qi, "Q"]]);
  for (let i = 0; i < 4; i++) {
    charge(1, 2); const p = declaration.parameters[i];
    if (!p.symbol || p.pattern && p.pattern.kind !== "name" || endpointUnsignedBound(p.type, charge) === undefined) throw new Error("Refund validator parameter is not an unsigned scalar");
    if (endpointUnsignedBound(p.type, charge)! <= 1n) return undefined;
    env.set(p.symbol, { value: 1n, ...atom(labels.get(i)!) });
  }
  const uint = (value: bigint, type: string) => {
    charge(1, 1); const bound = endpointUnsignedBound(type, charge);
    if (bound === undefined) throw new Error("Refund arithmetic is not unsigned");
    if (value < 0n || value >= bound) throw new Error("Refund endpoint fails a checked unsigned width");
  };
  const key = (op: string, a: Key, b: Key): Key => {
    charge(1 + Math.ceil((a.keyText.length + b.keyText.length) / 64), 1 + Math.ceil((a.keyText.length + b.keyText.length) / 64));
    if (["*", "+", "=="].includes(op) && a.key > b.key) [a, b] = [b, a];
    return atom(`(${a.key}${op}${b.key})`, `(${a.keyText}${op}${b.keyText})`);
  };
  const evaluate = (expr: Expr, depth = 0): Value => {
    charge(1, 2); if (depth > 32) throw new Error("Refund arithmetic depth exhausted");
    if (expr.kind === "literal" && expr.value) {
      charge(Math.ceil(expr.value.length / 32)); if (expr.value.length > 75) throw new Error("Refund literal exceeds bounded unsigned evidence");
      if (/^\d+$/.test(expr.value)) return { value: BigInt(expr.value), ...atom(expr.value) };
      if (["true", "false"].includes(expr.value)) return { value: expr.value === "true", ...atom(expr.value) };
    }
    if (expr.kind === "ref" && expr.symbol && env.has(expr.symbol)) return env.get(expr.symbol)!;
    if (expr.kind === "disclose") return evaluate(expr.args[0], depth + 1);
    if (expr.kind === "cast" && ["numeric", "identity"].includes(expr.castKind ?? "")) {
      const value = evaluate(expr.args[0], depth + 1); if (typeof value.value !== "bigint") throw new Error("Refund cast is not integer");
      uint(value.value, expr.type ?? expr.inferredType ?? "unknown"); return value;
    }
    if (expr.kind === "unary" && expr.name === "!") { const a = evaluate(expr.args[0], depth + 1); if (typeof a.value !== "boolean") throw new Error("Refund negated guard is not Boolean"); charge(1 + Math.ceil(a.keyText.length / 64), 1 + Math.ceil(a.keyText.length / 64)); return {value: !a.value, ...atom(`!${a.key}`, `!${a.keyText}`)}; }
    if (expr.kind !== "binary" || expr.args.length !== 2) throw new Error("Refund pure validator contains unsupported syntax");
    const a = evaluate(expr.args[0], depth + 1), b = evaluate(expr.args[1], depth + 1), op = expr.name!;
    let value: bigint | boolean;
    if (op === "&&" || op === "||") {
      if (typeof a.value !== "boolean" || typeof b.value !== "boolean") throw new Error("Refund Boolean operands unavailable");
      value = op === "&&" ? a.value && b.value : a.value || b.value;
    } else {
      if (typeof a.value !== "bigint" || typeof b.value !== "bigint") throw new Error("Refund integer operands unavailable");
      if (["+", "-", "*"].includes(op)) {
        if (endpointUnsignedBound(expr.numericType ?? "unknown", charge) === undefined) throw new Error("Refund arithmetic lacks unsigned semantics");
        value = op === "+" ? a.value + b.value : op === "-" ? a.value - b.value : a.value * b.value;
        uint(value, expr.numericType ?? "unknown");
      } else if (op === "<=") value = a.value <= b.value;
      else if (op === "<") value = a.value < b.value;
      else if (op === ">") value = a.value > b.value;
      else if (op === ">=") value = a.value >= b.value;
      else if (op === "==") value = a.value === b.value;
      else if (op === "!=") value = a.value !== b.value;
      else throw new Error("Refund validator operator unsupported");
    }
    return { value, ...key(op, a, b) };
  };
  let returned: Value | undefined, rejected = false;
  const body = (statement: Statement): void => {
    charge(); if (returned) throw new Error("Refund validator has statements after return");
    if (statement.kind === "block" || statement.kind === "bindings") { for (const part of statement.body) body(part); return; }
    if (statement.kind === "bind") {
      if (!statement.symbol || statement.pattern && statement.pattern.kind !== "name" || env.has(statement.symbol)) throw new Error("Refund pure bindings unavailable");
      env.set(statement.symbol, evaluate(statement.expr)); return;
    }
    if (statement.kind === "return") { returned = evaluate(statement.expr); return; }
    if (statement.kind === "expr" && statement.expr.kind === "assert") {
      const condition = evaluate(statement.expr.args[0]); if (typeof condition.value !== "boolean") throw new Error("Refund assertion is not Boolean");
      rejected ||= !condition.value; return;
    }
    throw new Error("Refund pure validator is not a complete supported straight-line body");
  };
  body(declaration.body);
  if (!returned) throw new Error("Refund pure validator return unavailable");
  const qa = key("*", atom("Q"), atom("A")), bp = key("*", atom("B"), atom("P")), sum = key("+", qa, atom("A"));
  const expected = key("&&", key("<=", qa, bp), key("<", bp, sum));
  const factored = key("*", key("+", atom("Q"), atom("1")), atom("A"));
  const expectedFactored = key("&&", key("<=", qa, bp), key("<", bp, factored));
  charge(1 + Math.ceil((returned.keyText.length + expected.keyText.length + expectedFactored.keyText.length) / 64));
  if (returned.key !== expected.key && returned.key !== expectedFactored.key || returned.value !== true || rejected) return undefined;
  // Full local caller guards require a separate certificate. Opaque unrelated
  // predicates do not prove feasibility and are not silently assumed true.
  env.clear();
  for (const symbol of candidate.actualRoles) { charge(1, 2); const bound = endpointUnsignedBound(program.symbols.get(symbol)?.type ?? "unknown", charge); if (bound === undefined || bound <= 1n) throw new Error("Refund source argument unsigned witness domain is unavailable"); env.set(symbol, { value: 1n, ...atom(symbol, program.meteringIdentity(symbol)) }); }
  const relevant = (expr: Expr, depth = 0): boolean => {
    charge(); if (depth > 32) throw new Error("Refund caller relevance depth exhausted"); return expr.kind === "ref" && !!expr.symbol && env.has(expr.symbol) || expr.args.some(arg => relevant(arg, depth + 1));
  };
  const expand = (expr: Expr, depth = 0): Expr => {
    charge(1, 1); if (depth > 32) throw new Error("Refund caller constraint provenance exhausted");
    if (expr.kind === "ref" && expr.symbol && candidate.mutable.has(expr.symbol)) throw new Error("Refund caller guard has a mutable operand");
    if (expr.kind === "ref" && expr.symbol && candidate.bindings.has(expr.symbol)) return expand(candidate.bindings.get(expr.symbol)!, depth + 1);
    return { ...expr, args: expr.args.map(arg => expand(arg, depth + 1)) };
  };
  for (const expression of candidate.loopExpressions) if (relevant(expand(expression))) throw new Error("Refund relevant loop constraints are outside the source-local certificate");
  for (const argument of candidate.validatorArgs) { const value = evaluate(expand(argument)); if (value.value !== 1n) throw new Error("Refund exact argument cast does not retain the formal witness"); }
  const remainder = evaluate(expand(candidate.subtraction));
  if (remainder.value !== 0n) throw new Error("Refund exact subtraction does not produce the selected zero witness");
  for (const original of candidate.guards) {
    const guard = expand(original);
    charge(); if (!relevant(guard)) continue;
    const liveRole = (expr: Expr, depth = 0): boolean => { charge(); if (depth > 32) throw new Error("Refund live guard provenance exhausted"); return expr.kind === "ref" && !!expr.symbol && env.has(expr.symbol) && program.symbols.get(expr.symbol)?.kind === "ledger" || expr.args.some(arg => liveRole(arg, depth + 1)); };
    if (liveRole(guard)) throw new Error("Refund caller guard rereads a live ledger role rather than the selected argument snapshot");
    const value = evaluate(guard);
    if (typeof value.value !== "boolean") throw new Error("Refund caller constraint is not Boolean");
    if (!value.value) return undefined;
  }
  charge(1, 16 + candidate.roles.length + candidate.actualRoles.length + candidate.guards.length + candidate.loopExpressions.length);
  const retained = Object.freeze({ ...candidate, send: Object.freeze({ ...candidate.send }), assertion: Object.freeze({ ...candidate.assertion }),
    roles: Object.freeze([...candidate.roles]) as typeof candidate.roles, actualRoles: Object.freeze([...candidate.actualRoles]),
    guards: Object.freeze([...candidate.guards]) as unknown as Expr[], loopExpressions: Object.freeze([...candidate.loopExpressions]) as unknown as Expr[] });
  const certificate: RefundEndpointCertificate = Object.freeze({ candidate: retained, formula: returned.key, witness: Object.freeze([1n, 1n, 1n, 1n]), scope: "source-local-formula" });
  issuedCertificates.set(certificate, program); return certificate;
}
