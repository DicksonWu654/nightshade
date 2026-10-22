import type { Program } from "./index.js";
import { numericBound, parseType, printType, sequenceLength, TUPLE_TYPE } from "./types.js";

/** Declared domain upper bound, never an estimate of actual entropy. Saturate
 * above the review threshold; unknown/large representations are ineligible. */
export function finiteDomain(program: Program, type: string, limit = 65536, allowance = 4096): { complete: boolean; upperBound?: number; work: number } {
  let work = 0, exhausted = false;
  const large = limit + 1;
  const visit = (type: string, depth = 0): number => {
    if (++work > allowance || depth > 32) { exhausted = true; return large; }
    const representation = program.representationOf(type), term = parseType(representation);
    if (term.name === "Boolean") return 2;
    const bound = numericBound(representation);
    if (bound !== undefined) return Number(bound > BigInt(limit) ? BigInt(large) : bound);
    const enumeration = program.symbols.get(term.name)?.declaration;
    if (enumeration?.typeKind === "enum") return Math.min(large, enumeration.variants!.length);
    if (term.name === "Bytes") {
      const length = sequenceLength(representation);
      return length !== undefined && length <= 2 ? Math.min(large, 256 ** length) : large;
    }
    if (term.name === "Vector") {
      const length = sequenceLength(representation);
      if (length === undefined) return large;
      if (!length) return 1;
      const element = visit(printType(term.args[1]), depth + 1);
      if (element === 1) return 1;
      // Avoid expanding large layouts or enormous exponentiation.
      return element >= large || length > 16 ? large : Math.min(large, element ** length);
    }
    const components = term.name === TUPLE_TYPE ? term.args.map(printType) : Object.values(program.fieldsOf(type) ?? {});
    if (!components.length) return term.name === TUPLE_TYPE ? 1 : large;
    let result = 1;
    for (const component of components) {
      result *= visit(component, depth + 1);
      if (result > limit) return large;
    }
    return result;
  };
  if (!Number.isSafeInteger(limit) || limit < 1 || !Number.isSafeInteger(allowance) || allowance < 1) return { complete: false, work: 0 };
  const result = visit(type);
  return { complete: !exhausted, ...(result <= limit ? { upperBound: result } : {}), work };
}
