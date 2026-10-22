import type { Expr, Statement } from "../model.js";
import type { FunctionInfo, Program } from "./index.js";
import { standardType } from "./intrinsics.js";
import { parseType, printType, typeArguments } from "./types.js";

type Recipe = "seed" | "singleton" | "digest" | "scalar" | "point" | "other" | "unavailable";
interface Targets { targets: Set<string>; unsupported: Set<string>; complete: boolean; work: number }
const DEFAULT_ALLOWANCE = 20000;
const cache = new WeakMap<Program, Targets>();

/** Prove the resolved native recipe independently of provider names or bytes.
 * Observe direct generator producers; ordinary callers retain shared transfers. */
export function encryptionTargets(program: Program, allowance = DEFAULT_ALLOWANCE): Targets {
  const saved = allowance === DEFAULT_ALLOWANCE ? cache.get(program) : undefined;
  if (saved) return saved;
  const targets = new Set<string>(), unsupported = new Set<string>();
  let work = 0, complete = true;
  class Exhausted extends Error {}
  const charge = () => { if (++work > allowance || !Number.isSafeInteger(allowance) || allowance < 1) throw new Exhausted(); };
  const normalized = (type: string) => printType(parseType(program.representationOf(type)));
  const active = new Set<string>();
  const invoke = (fn: FunctionInfo, args: Recipe[], depth: number): Recipe => {
    charge();
    if (depth > 64 || active.has(fn.symbol.id) || !fn.declaration.body
      || fn.declaration.parameters.some(parameter => !parameter.symbol || parameter.pattern && parameter.pattern.kind !== "name")) return "unavailable";
    const environment = new Map<string, Recipe>(fn.declaration.parameters.map((parameter, index) => [parameter.symbol!, args[index] ?? "unavailable"]));
    const expression = (expr: Expr, nesting = 0): Recipe => {
      charge();
      if (nesting > 64) return "unavailable";
      const child = (input: Expr) => expression(input, nesting + 1);
      if (expr.kind === "ref") return environment.get(expr.symbol ?? "") ?? "unavailable";
      if (expr.kind === "literal" || expr.kind === "bytes" || expr.kind === "default") return "other";
      if (expr.kind === "disclose" || expr.kind === "cast" && expr.castKind === "identity") return child(expr.args[0]);
      if (expr.kind === "tuple") {
        if (expr.args.length !== 1) return "unavailable";
        const item = child(expr.args[0]);
        return item === "seed" ? "singleton" : item === "unavailable" ? item : "other";
      }
      if (expr.kind !== "call") return "unavailable";
      // The explicit hash type distinguishes a vector from a tuple.
      if (expr.symbol === "intrinsic::persistentHash") {
        const type = typeArguments(expr.generics)[0];
        if (!type || normalized(type) !== "Vector<1,Bytes<32>>" || expr.args.length !== 1) return "other";
        const input = child(expr.args[0]);
        return input === "singleton" ? "digest" : input === "unavailable" ? input : "other";
      }
      const values = expr.args.map(child);
      if (expr.symbol === "intrinsic::degradeToTransient" || expr.symbol === "intrinsic::ecMulGenerator") {
        if (values.length !== 1) return "unavailable";
        if (values[0] === "unavailable") return "unavailable";
        return expr.symbol === "intrinsic::degradeToTransient"
          ? values[0] === "digest" ? "scalar" : "other"
          : values[0] === "scalar" ? "point" : "other";
      }
      const callee = expr.symbol && program.functions.get(expr.symbol);
      return callee ? invoke(callee, values, depth + 1) : expr.symbol?.startsWith("intrinsic::") ? "other" : "unavailable";
    };
    const statement = (body: Statement, nesting = 0): Recipe | undefined => {
      charge();
      if (nesting > 64) return "unavailable";
      if (body.kind === "block" || body.kind === "bindings") {
        for (const child of body.body) {
          const result = statement(child, nesting + 1);
          if (result !== undefined) return result;
        }
        return;
      }
      if (body.kind === "bind" && body.symbol && (!body.pattern || body.pattern.kind === "name")) {
        environment.set(body.symbol, expression(body.expr));
        return;
      }
      if (body.kind === "return") return expression(body.expr);
      return "unavailable";
    };
    active.add(fn.symbol.id);
    try { return statement(fn.declaration.body) ?? "unavailable"; }
    finally { active.delete(fn.symbol.id); }
  };
  try {
    for (const fn of program.functions.values()) {
      charge();
      if (fn.symbol.type !== standardType("JubjubPoint") || fn.declaration.parameters.length !== 1
        || normalized(fn.declaration.parameters[0].type) !== "Bytes<32>"
        || !fn.calls.has("intrinsic::ecMulGenerator")) continue;
      const recipe = invoke(fn, ["seed"], 0);
      if (recipe === "point") {
        (program.zkirVersion === 2 && program.compilerVersion === "0.31.1" ? targets : unsupported).add(fn.symbol.id);
      } else if (recipe === "unavailable") unsupported.add(fn.symbol.id);
    }
  } catch (error) {
    if (!(error instanceof Exhausted)) throw error;
    complete = false;
  }
  const result = { targets, unsupported, complete, work };
  if (allowance === DEFAULT_ALLOWANCE) cache.set(program, result);
  return result;
}

/** Bounded reachable applicability; exhausted discovery is never an absence. */
export function encryptionScope(program: Program, entry: string, allowance = 20000) {
  const roles = encryptionTargets(program), seen = new Set<string>(), pending = [entry];
  if (!roles.complete) return { complete: false, applicable: true, unsupported: true, work: roles.work };
  if (!roles.targets.size && !roles.unsupported.size) return { complete: true, applicable: false, unsupported: false, work: 0 };
  let work = 0, applicable = false, unsupported = false;
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, unsupported, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    applicable ||= roles.targets.has(id);
    unsupported ||= roles.unsupported.has(id);
    for (const callee of program.functions.get(id)?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, unsupported, work };
      pending.push(callee);
    }
  }
  return { complete: true, applicable: applicable || unsupported, unsupported, work };
}
