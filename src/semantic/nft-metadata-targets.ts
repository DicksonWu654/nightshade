import type { Expr, Span } from "../model.js";
import type { Program } from "./index.js";

/** PublicSink has no general effect ordinal. A flat entry body ending in this
 * effect-free live lookup executes the observation after all preceding effects.
 * Saved reads, helper returns, earlier returns and effectful keys are excluded. */
export function terminalMetadataLookup(program: Program, consumer: string, metadata: string,
  charge: (depth?: number) => boolean): { location: Span } | undefined {
  const body = program.functions.get(consumer)?.declaration.body;
  if (!charge() || body?.kind !== "block") return undefined;
  for (const statement of body.body.slice(0, -1)) {
    if (!charge() || !["expr", "bind"].includes(statement.kind)) return undefined;
  }
  const tail = body.body.at(-1);
  if (!charge() || tail?.kind !== "return") return undefined;
  const expr = tail.expr;
  if (expr.kind !== "member" || expr.value !== "call" || expr.name !== "lookup" || expr.args.length !== 2
    || expr.args[0].kind !== "ref" || expr.args[0].symbol !== metadata || expr.args[0].ledgerRoot !== metadata) return undefined;
  const simple = (part: Expr, depth = 0): boolean => {
    if (!charge(depth)) return false;
    if (["ref", "literal", "default"].includes(part.kind)) return !part.args.length;
    return ["cast", "disclose"].includes(part.kind) && part.args.length === 1 && simple(part.args[0], depth + 1);
  };
  return simple(expr.args[1]) ? { location: expr.span } : undefined;
}
