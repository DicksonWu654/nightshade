import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";
import type { AbstractValue } from "../dataflow/index.js";

export const CONTRACT_RECIPIENT_RULE = "shielded-contract-recipient-review";
export const CONTRACT_RECIPIENT_SENDS = new Set(["standard-library::sendShielded", "standard-library::sendImmediateShielded"]);
export type RecipientCharge = (work?: number, values?: number) => boolean;

export function contractRecipientType(program: Program, type: string): boolean {
  const term = parseType(program.representationOf(type));
  return program.nativeTypeOf(type) === "Either" && term.args.length === 2
    && program.nativeTypeOf(printType(term.args[0])) === "ZswapCoinPublicKey" && program.nativeTypeOf(printType(term.args[1])) === "ContractAddress";
}

/** Exact raw tag operand, never provenance overlap or source spelling. */
export function recipientTagParameter(program: Program, entry: string, tag: AbstractValue): string | undefined {
  if (!tag.identity || tag.constant !== undefined || tag.ledger.size || tag.fields || tag.items
    || tag.negated || tag.comparison || tag.ordering || tag.flows.length !== 1) return;
  const flow = tag.flows[0], source = flow.source;
  if (flow.form !== "raw" || source.kind !== "entry-parameter" || source.id !== tag.identity || !source.symbol) return;
  const parameter = program.functions.get(entry)?.declaration.parameters.find(item => item.symbol === source.symbol);
  return parameter && contractRecipientType(program, parameter.type) ? source.symbol : undefined;
}

/** Meter the owned callable closure before absence/applicability certification.
 * Checkpoints and external composition have no complete history in this scope. */
export function contractRecipientScope(program: Program, entry: string, charge: RecipientCharge) {
  charge(0, 3);
  const pending = [entry], seen = new Set<string>();
  let applicable = false;
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    if (CONTRACT_RECIPIENT_SENDS.has(id)) applicable = true;
    const fn = program.functions.get(id);
    if (!fn) {
      const symbol = program.symbols.get(id);
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Recipient callable closure is unresolved");
      continue;
    }
    for (const node of fn.cfg.nodes) {
      charge(1, 1); const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && (!expr.symbol || !program.symbols.has(expr.symbol)))
          throw new Error("Recipient call target or external composition is unavailable");
        if (expr.kind === "member" && expr.name === "checkpoint" && expr.ledgerRoot === "standard-library::kernel")
          throw new Error("Recipient checkpoint prefix composition is unavailable");
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
        for (const child of expr.args) { charge(1, 1); expressions.push(child); }
      }
    }
    for (const callee of fn.calls) { charge(1, 1); pending.push(callee); }
  }
  return applicable;
}
