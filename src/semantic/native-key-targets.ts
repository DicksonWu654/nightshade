import type { Program } from "./index.js";
export const NATIVE_KEY_RULE = "native-key-authentication-review";
export const OWN_PUBLIC_KEY = "intrinsic::ownPublicKey";
/** Canonical call identity, including reachable helpers; names never establish applicability. */
export function nativeKeyScope(program: Program, entry: string, allowance = 20000) {
  let work = 0;
  const pending = [entry], seen = new Set<string>();
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (id === OWN_PUBLIC_KEY) return { complete: true, applicable: true, work };
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    for (const target of fn?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, work };
      pending.push(target);
    }
  }
  return { complete: true, applicable: false, work };
}
