import type { Program } from "./index.js";
import type { AbstractValue } from "../dataflow/index.js";
import { parseType, printType } from "./types.js";
import { ZERO_SEND_TARGET } from "./zero-send-targets.js";

export const LIST_GROWTH_RULE = "zero-transfer-retained-list-review";
export const LIST_GROWTH_APPEND = "observer::retained-list-append";
export type ListGrowthCharge = (work?: number, values?: number) => boolean;

/** Canonical represented recipient projection, independent of source spelling. */
export function unshieldedUserRecipient(program: Program, value: AbstractValue,
  isUser: (tag: AbstractValue) => boolean | undefined, charge: ListGrowthCharge): AbstractValue | undefined {
  charge(2, 3);
  const type = value.type;
  if (!type) throw new Error("Unshielded recipient type is unavailable");
  const term = parseType(program.representationOf(type));
  if (program.nativeTypeOf(type) !== "Either" || term.args.length !== 2
    || program.nativeTypeOf(printType(term.args[0])) !== "ContractAddress"
    || program.nativeTypeOf(printType(term.args[1])) !== "UserAddress")
    throw new Error("Canonical unshielded recipient representation is unavailable");
  const tag = value.fields?.is_left;
  if (!tag) throw new Error("Unshielded recipient tag snapshot is unavailable");
  const user = isUser(tag);
  if (user !== true) {
    if (user === false) return undefined;
    throw new Error("Unshielded recipient arm is not fixed to a user on this history");
  }
  const bytes = value.fields?.right?.fields?.bytes;
  if (!bytes || program.representationOf(bytes.type ?? "unknown") !== "Bytes<32>")
    throw new Error("Canonical user recipient bytes snapshot is unavailable");
  return bytes;
}

/** Source inventory only admits observation; pairing always uses actual history
 * operands. External/checkpoint composition has no complete atomic history. */
export function listGrowthScope(program: Program, entry: string, charge: ListGrowthCharge): boolean {
  charge(0, 3); const pending = [entry], seen = new Set<string>();
  let applicable = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    applicable ||= id === ZERO_SEND_TARGET;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("List-growth callable identity is unresolved");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("List-growth external call identity is unavailable");
        if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel")
          throw new Error("List-growth checkpoint composition is unavailable");
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const child of expr.args) { charge(1, 1); expressions.push(child); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return applicable;
}
