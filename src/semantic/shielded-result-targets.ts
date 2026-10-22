import type { Expr } from "../model.js";
import type { Program } from "./index.js";
import { SHIELDED_MINT } from "./mint-targets.js";

const producers = new Set([
  "standard-library::sendImmediateShielded", "standard-library::sendShielded", SHIELDED_MINT,
]);

/** A producer or a transparent helper returning exactly its native descriptor.
 * Setup, branches, partial projections and computed returns remain outside this
 * source-use contract. Resolution and recursion consume the source allowance. */
export function returnedShieldedResult(program: Program, expression: Expr,
  charge: (depth: number) => boolean, depth = 0, seen = new Set<string>()): { target: string; forwarders: string[] } | undefined {
  if (!charge(depth)) return;
  if (expression.kind === "disclose" || expression.kind === "cast" && expression.castKind === "identity")
    return expression.args[0] && returnedShieldedResult(program, expression.args[0], charge, depth + 1, seen);
  if (expression.kind !== "call" || !expression.symbol) return;
  if (producers.has(expression.symbol)) return { target: expression.symbol, forwarders: [] };
  if (seen.has(expression.symbol)) return;
  const body = program.functions.get(expression.symbol)?.declaration.body;
  const returned = body?.kind === "block" && body.body.length === 1 ? body.body[0] : body;
  if (returned?.kind !== "return") return;
  const next = new Set(seen); next.add(expression.symbol);
  const result = returnedShieldedResult(program, returned.expr, charge, depth + 1, next);
  return result && { ...result, forwarders: [expression.symbol, ...result.forwarders] };
}
