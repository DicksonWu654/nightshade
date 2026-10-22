import type { Program } from "./index.js";

export const NATIVE_HASHES = new Set(["persistentHash", "transientHash", "keccak256"]);
const nativeHash = (id: string) => id.startsWith("intrinsic::") && NATIVE_HASHES.has(id.slice("intrinsic::".length));

/** Call-graph absence only. This says nothing about inputs, secrecy or use. */
export function nativeHashScope(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    if (nativeHash(id)) return { complete: true, applicable: true, work };
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expr = expressions.pop()!;
        if (expr.symbol && nativeHash(expr.symbol)) return { complete: true, applicable: true, work };
        if (expr.kind === "lambda" && expr.symbol) pending.push(expr.symbol);
        expressions.push(...expr.args);
      }
    }
    for (const callee of fn?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, work };
      pending.push(callee);
    }
  }
  return { complete: true, applicable: false, work };
}
