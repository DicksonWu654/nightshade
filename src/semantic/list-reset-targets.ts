import type { Program } from "./index.js";
import { parseType, printType } from "./types.js";

/** Conservative applicability, not evidence of a reset or execution. Missing
 * work cannot certify absence. Query-only and constructor entries are excluded. */
export function hasListWrites(program: Program, entry: string, allowance = 20000): boolean {
  if (program.functions.get(entry)?.symbol.kind === "constructor") return false;
  let work = 0;
  const containsList = (type: string, depth = 0): boolean => {
    if (++work > allowance || depth > 32) return true;
    const parsed = parseType(program.representationOf(type));
    return parsed.name === "List" || parsed.args.some(arg => containsList(printType(arg), depth + 1));
  };
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return true;
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const ledger of fn?.writesState ?? []) {
      if (++work > allowance) return true;
      const type = program.symbols.get(ledger)?.type;
      if (!type || containsList(type)) return true;
    }
    for (const call of fn?.calls ?? []) {
      if (++work > allowance) return true;
      pending.push(call);
    }
  }
  return false;
}
