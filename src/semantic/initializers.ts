import type { Program } from "./index.js";

/** Names select review candidates only; they never establish one-time intent. */
export function initializerEntries(program: Program): string[] {
  return program.entries.filter(id => {
    const fn = program.functions.get(id)!;
    return fn.symbol.kind !== "constructor" && /^(?:initialize|initializer)(?:$|_)/.test(fn.symbol.name)
      && fn.writesState.size > 0;
  });
}
