import type { Program } from "./index.js";
import { parseType, printType, sequenceLength, TUPLE_TYPE } from "./types.js";

export const CALLER_EQUALITY_RULE = "caller-supplied-ledger-equality";

/** Applicability only. An unchanged root argument, a reachable equality and
 * ledger data may coexist without any required relationship between them. */
export function callerEqualityScope(program: Program, entry: string, allowance = 20000) {
  const fn = program.functions.get(entry)!;
  if (fn.symbol.kind === "constructor" || !fn.declaration.parameters.length)
    return { complete: true, applicable: false, work: 1 };
  let work = 0, equality = false, ledger = false;
  const containsBytes = (type: string, depth = 0): boolean => {
    if (++work > allowance || depth > 32) return true; // exhaustion never certifies absence
    const representation = program.representationOf(type), parsed = parseType(representation);
    if (parsed.name === "Bytes") return sequenceLength(representation) === 32;
    if (parsed.name === "Vector") return sequenceLength(representation) !== 0 && containsBytes(printType(parsed.args[1]), depth + 1);
    const components = parsed.name === TUPLE_TYPE ? parsed.args.map(printType) : Object.values(program.fieldsOf(type) ?? {});
    return components.some(component => containsBytes(component, depth + 1));
  };
  if (!fn.declaration.parameters.some(parameter => containsBytes(parameter.type)))
    return { complete: work <= allowance, applicable: work > allowance, work };
  if (work > allowance) return { complete: false, applicable: true, work };
  const seen = new Set<string>(), pending = [entry];
  while (pending.length) {
    if (++work > allowance) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const current = program.functions.get(id);
    ledger ||= !!current?.readsState.size;
    for (const node of current?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (++work > allowance) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        equality ||= expression.kind === "binary" && ["==", "!="].includes(expression.name ?? "");
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    if (ledger && equality) return { complete: true, applicable: true, work };
    for (const next of current?.calls ?? []) {
      if (++work > allowance) return { complete: false, applicable: true, work };
      pending.push(next);
    }
  }
  return { complete: true, applicable: false, work };
}
