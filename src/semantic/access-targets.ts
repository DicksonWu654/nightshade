import type { Program } from "./index.js";
import { intrinsicModel } from "./intrinsics.js";

export interface AccessTargets {
  complete: boolean;
  work: number;
  applicable: boolean;
  entries: Map<string, { ledgers: Set<string>; transaction: boolean; authentication: boolean }>;
}

/** An overapproximation used only to prove inapplicability or block an incomplete
 * writer. Syntactic writers never enter a successful-writer majority. */
export function accessTargets(program: Program, allowance = 20000): AccessTargets {
  const result: AccessTargets = { complete: true, work: 0, applicable: false, entries: new Map() };
  const charge = () => ++result.work <= allowance;
  const groups = new Map<string, { writers: number; callers: number }>();
  for (const entry of program.entries) {
    const fn = program.functions.get(entry)!;
    if (fn.symbol.kind === "constructor") continue;
    const target = { ledgers: new Set<string>(), transaction: false, authentication: false };
    result.entries.set(entry, target);
    for (const ledger of fn.writesState) {
      if (!charge()) { result.complete = false; return result; }
      if (program.representationOf(program.symbols.get(ledger)!.type) === "Kernel") target.transaction = true;
      else target.ledgers.add(ledger);
    }
    const pending = [entry], visited = new Set<string>();
    while (pending.length) {
      if (!charge()) { result.complete = false; return result; }
      const id = pending.pop()!;
      if (visited.has(id)) continue;
      visited.add(id);
      const symbol = program.symbols.get(id)!;
      if (symbol.kind === "witness") target.authentication = true;
      if (symbol.kind === "intrinsic") {
        const model = intrinsicModel(symbol);
        if (model.kind === "witness" || model.kind === "hash") target.authentication = true;
        if (model.nativeEffect) target.transaction = true;
      }
      for (const callee of program.functions.get(id)?.calls ?? []) {
        if (!charge()) { result.complete = false; return result; }
        pending.push(callee);
      }
    }
    for (const key of [...target.ledgers, ...(target.transaction ? ["transaction"] : [])]) {
      if (!charge()) { result.complete = false; return result; }
      const count = groups.get(key) ?? { writers: 0, callers: 0 };
      count.writers++; if (target.authentication) count.callers++;
      groups.set(key, count);
    }
  }
  result.applicable = [...groups.values()].some(group => group.writers >= 3 && group.callers >= 2);
  return result;
}
