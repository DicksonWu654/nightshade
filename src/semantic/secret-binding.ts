import type { Program } from "./index.js";
import type { PrivateSource } from "../dataflow/index.js";

export const SECRET_BINDING_RULE = "secret-binding-divergence-review";

/** Runtime aggregate expansion has an analysis limit. A missing items/fields
 * array is not evidence that a source declaration has scalar representation. */
export function scalarSecretKeySource(program: Program, source: PrivateSource,
  charge: (work: number, values: number) => boolean, observedType?: string): boolean {
  charge(1, 0);
  const symbol = source.symbol && program.symbols.get(source.symbol);
  if (!symbol) return false;
  charge(1, 1 + Math.ceil(program.meteringIdentity(symbol.type).length / 64));
  const represented = program.representationOf(symbol.type);
  charge(1, 1 + Math.ceil(program.meteringIdentity(represented).length / 64));
  const primitive = /^(Boolean|Field|Bytes<\d+>|Uint<\d+(?:\.\.\d+)?>)$/;
  if (!primitive.test(represented)) return false;
  if (observedType !== undefined) {
    charge(1, 1 + Math.ceil(program.meteringIdentity(observedType).length / 64));
    const observed = program.representationOf(observedType);
    charge(1, 1 + Math.ceil(program.meteringIdentity(observed).length / 64));
    if (!primitive.test(observed)) return false;
  }
  return true;
}
/** One metered resolved-call walk supplies applicability and rejects committed
 * prefixes outside this initial atomic-history observer. */
export function secretBindingScope(program: Program, entry: string, charge: (work: number, values: number) => boolean): boolean {
  charge(0, 3);
  const seen = new Set<string>(), pending = [entry];
  let applicable = false;
  while (pending.length) {
    charge(1, 0);
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    if (id === "intrinsic::persistentHash") applicable = true;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness")
        throw new Error("Secret binding callable closure is unresolved; structural absence is unavailable");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1);
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(1, 0);
        const expr = expressions.pop()!;
        if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel")
          throw new Error("Reachable canonical kernel checkpoint is outside the atomic secret-binding review");
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("Secret binding call target is unresolved; structural absence is unavailable");
        if (expr.symbol === "intrinsic::persistentHash") applicable = true;
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const arg of expr.args) { charge(1, 1); expressions.push(arg); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return applicable;
}

/** Declaration families are comparison labels, never equality of inputs. */
export function secretWitnessDeclaration(program: Program, source: PrivateSource): string | undefined {
  if (source.kind !== "witness" || !source.symbol) return;
  const symbol = program.symbols.get(source.symbol);
  if (symbol?.kind !== "witness" || program.representationOf(symbol.type) !== "Bytes<32>") return;
  return symbol.id;
}
