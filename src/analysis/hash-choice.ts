import type { Expr } from "../model.js";
import type { SymbolInfo } from "../semantic/index.js";

/** An admission candidate, not a proof that alternatives can be combined.
 * Runtime admission also requires the same dependency/preimage metadata and a
 * selector independent of both hash inputs. Effectful/aborting calls stay split.
 */
export function hashChoiceCandidate(expr: Expr, symbols: ReadonlyMap<string, SymbolInfo>): boolean {
  if (expr.kind !== "conditional") return false;
  let work = 0;
  const read = (part: Expr): boolean => {
    if (++work > 128) return false;
    if (part.kind === "ref") return ["local", "parameter", "ledger"].includes(symbols.get(part.symbol!)?.kind ?? "");
    if (["literal", "default"].includes(part.kind)) return true;
    if (["disclose", "tuple", "index"].includes(part.kind)) return part.args.every(read);
    return part.kind === "member" && part.value === "field" && part.args.every(read);
  };
  const [condition, yes, no] = expr.args;
  const target = symbols.get(yes.symbol!);
  return read(condition) && yes.kind === "call" && no.kind === "call" && yes.symbol === no.symbol
    && target?.kind === "intrinsic" && target.type === "hash"
    && yes.args.every(read) && no.args.every(read);
}
