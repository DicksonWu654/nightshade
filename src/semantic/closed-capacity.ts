import type { Expr } from "../model.js";
import type { Program } from "./index.js";

export const CLOSED_CAPACITY_RULE = "closed-membership-capacity-review";
export type ClosureCharge = (steps?: number, values?: number) => void;
export interface ClosedCapacityScope { entries: Set<string>; writers: Set<string> }
/** Syntactic may-effects deliberately include unused exports and zero-iteration
 * callbacks. No attempt is made to prove that a writer cannot grow a Set. */
export function closedCapacityScope(program: Program, charge: ClosureCharge): ClosedCapacityScope {
  charge(0, 2); const entries = new Set<string>(), writers = new Set<string>();
  for (const entry of program.entries) {
    charge(); const fn = program.functions.get(entry);
    if (!fn) throw new Error("Public callable effect identity is unavailable");
    if (fn.symbol.kind === "constructor") continue;
    for (const root of fn.readsState) {
      charge(); const symbol = program.symbols.get(root);
      if (symbol?.kind === "ledger" && program.nativeTypeOf(symbol.type) === "Set") {
        charge(0, 1); entries.add(entry); break;
      }
    }
  }
  if (!entries.size) return { entries, writers };
  charge(0, 4); const pending: string[] = [], seen = new Set<string>(), members = new Set<string>(), callers = new Map<string, string[]>();
  for (const entry of program.entries) {
    charge(); if (program.symbols.get(entry)?.kind !== "constructor") { charge(0, 1); pending.push(entry); }
  }
  while (pending.length) {
    charge(); const id = pending.pop()!;
    if (seen.has(id)) continue;
    charge(0, 1); seen.add(id);
    const fn = program.functions.get(id), symbol = program.symbols.get(id);
    if (!fn) {
      if (!symbol || symbol.kind !== "intrinsic" && symbol.kind !== "witness") throw new Error("Post-constructor callable closure is unresolved");
      continue;
    }
    if (fn.symbol.kind === "constructor") throw new Error("Post-constructor closure includes a constructor call");
    for (const root of fn.writesState) { charge(1, 1); writers.add(root); }
    for (const node of fn.cfg.nodes) {
      charge(); if (!node.expr) continue;
      charge(0, 1); const expressions: Expr[] = [node.expr];
      while (expressions.length) {
        charge(); const expr = expressions.pop()!;
        if (expr.contractCall || expr.kind === "call" && !expr.symbol) throw new Error("Post-constructor source closure includes an unresolved external call");
        if (expr.kind === "member" && expr.name === "checkpoint" && program.nativeTypeOf(expr.args[0]?.inferredType ?? "") === "Kernel")
          throw new Error("Committed checkpoint histories are outside the closed capacity certificate");
        if (expr.kind === "member" && expr.value === "call" && expr.name === "member"
          && program.nativeTypeOf(expr.args[0]?.inferredType ?? "") === "Set") { charge(0, 1); members.add(id); }
        for (const arg of expr.args) { charge(1, 1); expressions.push(arg); }
        if (expr.kind === "lambda" && expr.symbol) { charge(0, 1); pending.push(expr.symbol); }
      }
    }
    for (const callee of fn.calls) {
      charge(1, 3); pending.push(callee);
      const parents = callers.get(callee) ?? []; parents.push(id); callers.set(callee, parents);
    }
  }
  charge(0, members.size); const reached = [...members];
  while (reached.length) {
    charge(); const id = reached.pop()!;
    for (const caller of callers.get(id) ?? []) {
      charge(); if (!members.has(caller)) { charge(0, 2); members.add(caller); reached.push(caller); }
    }
  }
  for (const entry of entries) { charge(); if (!members.has(entry)) entries.delete(entry); }
  return { entries, writers };
}
