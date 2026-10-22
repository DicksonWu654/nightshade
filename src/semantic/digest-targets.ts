import type { Program } from "./index.js";
import { finiteDomain } from "./domains.js";
import { parseType, printType, sequenceLength, TUPLE_TYPE } from "./types.js";

/** Whole-program inapplicability only: a native hash needs a represented input
 * leaf with a small declared domain. This does not classify privacy/publication,
 * guards, salts or protocol intent; exact histories provide that evidence. */
export function digestTargets(program: Program, allowance = 20000, entries: readonly string[] = program.entries): { complete: boolean; applicable: boolean; work: number } {
  let work = 0, exhausted = false;
  const seen = new Set<string>(), pending = [...entries], types = new Map<string, boolean>();
  const charge = (): boolean => { if (++work > allowance) exhausted = true; return !exhausted; };
  const relevant = (type: string, depth = 0): boolean => {
    if (!charge() || depth > 16) { exhausted = true; return true; }
    if (types.has(type)) return types.get(type)!;
    const domain = finiteDomain(program,type,65536,Math.min(4096,allowance-work));
    work += domain.work;
    if (!domain.complete || work > allowance) { exhausted = true; return true; }
    if (domain.upperBound !== undefined && domain.upperBound >= 2) { types.set(type,true); return true; }
    const representation = program.representationOf(type), term = parseType(representation), fields = program.fieldsOf(type);
    const result = fields ? Object.values(fields).some(field => relevant(field,depth+1))
      : term.name === TUPLE_TYPE ? term.args.some(child => relevant(printType(child),depth+1))
      : term.name === "Vector" && sequenceLength(representation) !== 0 ? relevant(printType(term.args[1]),depth+1)
      // Bytes constructors/copies can retain raw Uint8 leaves even when the
      // whole Bytes domain is large. Type size alone cannot prove absence.
      : term.name === "Bytes" && sequenceLength(representation) !== 0;
    types.set(type,result); return result;
  };
  while (pending.length) {
    if (!charge()) return { complete: false, applicable: true, work };
    const id = pending.pop()!;
    if (seen.has(id)) continue;
    seen.add(id);
    const fn = program.functions.get(id);
    for (const node of fn?.cfg.nodes ?? []) {
      const expressions = node.expr ? [node.expr] : [];
      while (expressions.length) {
        if (!charge()) return { complete: false, applicable: true, work };
        const expression = expressions.pop()!;
        if (["intrinsic::persistentHash","intrinsic::transientHash","intrinsic::keccak256"].includes(expression.symbol ?? "")
          // A native higher-order callback has no ordinary body to traverse.
          // Its instantiated element type need not be the ref's result type.
          && (expression.kind !== "call" || relevant(expression.args[0]?.inferredType ?? "unknown")))
          return { complete: !exhausted, applicable: true, work };
        if (expression.kind === "lambda" && expression.symbol) pending.push(expression.symbol);
        expressions.push(...expression.args);
      }
    }
    pending.push(...fn?.calls ?? []);
  }
  return { complete: !exhausted, applicable: exhausted, work };
}
