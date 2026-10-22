import type { AbstractValue, SuccessfulPredicate } from "./index.js";
import { assumeScalar, immutableIntegerOrder, type ScalarConstraints } from "./transfers.js";
import { integerEnvelope } from "./integer-envelope.js";
import { FIELD_MODULUS } from "../semantic/types.js";

/** Reconstruct a fresh bounded conjunction for one successful atomic history.
 * Refined Boolean constants cannot replace retained comparison operands. */
export function successfulIntegerConstraints(predicates: readonly SuccessfulPredicate[], charge: (work?: number) => void, integerDomains?: ReadonlyMap<string, { minimum: string; maximum: string }>, scalarMeter?: ScalarConstraints["scalarMeter"]): { status: "complete"; state: ScalarConstraints } | { status: "inconsistent" } | { status: "budget" } {
  scalarMeter?.(1, 8 + (integerDomains?.size ?? 0));
  const state: ScalarConstraints = { ...(scalarMeter ? { scalarMeter } : {}), known: new Map(), truths: new Map(), excluded: new Map(), aggregateExclusions: new Map(), aggregateExclusionLeaves: 0, aggregateExclusionsExhausted: false };
  charge(integerDomains?.size ?? 0);
  if ((integerDomains?.size ?? 0) > 256) return { status: "budget" };
  state.integerDomains = integerDomains ? new Map(integerDomains) : undefined;
  for (const predicate of predicates) {
    charge();
    const value = predicate.value;
    scalarMeter?.(1, 1);
    const condition = value.ordering || value.comparison || value.negated ? { ...value, constant: undefined, constantKind: undefined } : value;
    if (!assumeScalar(condition,predicate.truth,state)) return { status: "inconsistent" };
    if (state.orderingsExhausted || state.scalarEqualitiesExhausted || state.aggregateExclusionsExhausted) return { status: "budget" };
    charge(state.known.size + state.truths.size + (state.orderings?.size ?? 0) + (state.scalarEqualities?.size ?? 0) + state.aggregateExclusionLeaves);
    for (const values of state.excluded.values()) charge(values.size);
  }
  return { status: "complete", state };
}

export type ArithmeticSafety = { status: "safe" | "possible-wrap" | "always-wrap"; operands: readonly { minimum: bigint; maximum: bigint }[] };

/** Unsigned interval and same-pair safety only. No feasibility/path solver or
 * inference that a modular result is an application balance. */
export function fieldArithmeticSafety(value: AbstractValue, state: ScalarConstraints): ArithmeticSafety | undefined {
  const operation = value.fieldArithmetic;
  if (!operation || operation.operands.length !== 2) return;
  const operands = operation.operands.map(operand => integerEnvelope("Field",operand,state));
  if (operands.some(operand => !operand)) return;
  const [left,right] = operands as { minimum: bigint; maximum: bigint }[];
  let minimum: bigint, maximum: bigint;
  if (operation.operator === "-") {
    const order = immutableIntegerOrder(operation.operands[0],operation.operands[1],">=",state);
    if (order === null) return;
    if (order === true || left.minimum >= right.maximum) return { status: "safe", operands: [left,right] };
    minimum = left.minimum - right.maximum; maximum = left.maximum - right.minimum;
  } else if (operation.operator === "+") {
    minimum = left.minimum + right.minimum; maximum = left.maximum + right.maximum;
  } else {
    minimum = left.minimum * right.minimum; maximum = left.maximum * right.maximum;
  }
  if (minimum >= 0n && maximum < FIELD_MODULUS) return { status: "safe", operands: [left,right] };
  // A checked result domain can reject all wrapping residues. For subtraction
  // this often rejects underflow; addition/multiplication can wrap to small
  // residues, so a checked cast alone is never a safety certificate.
  const result = integerEnvelope("Field",value,state);
  if (!result) return;
  const wrapped: { minimum: bigint; maximum: bigint }[] = [];
  if (minimum < 0n) wrapped.push({ minimum: FIELD_MODULUS + minimum, maximum: FIELD_MODULUS + (maximum < -1n ? maximum : -1n) });
  if (maximum >= FIELD_MODULUS) {
    const first = minimum > FIELD_MODULUS ? minimum : FIELD_MODULUS;
    wrapped.push(first / FIELD_MODULUS === maximum / FIELD_MODULUS
      ? { minimum: first % FIELD_MODULUS, maximum: maximum % FIELD_MODULUS }
      : { minimum: 0n, maximum: FIELD_MODULUS - 1n });
  }
  if (wrapped.every(range => range.maximum < result.minimum || range.minimum > result.maximum)) return { status: "safe", operands: [left,right] };
  return { status: maximum < 0n || minimum >= FIELD_MODULUS ? "always-wrap" : "possible-wrap", operands: [left,right] };
}
