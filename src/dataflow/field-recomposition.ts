import type { AbstractValue } from "./index.js";
import { integerEnvelope } from "./integer-envelope.js";
import { scalarRelations } from "./scalar-relations.js";
import type { ScalarConstraints } from "./transfers.js";

function supplied(value: AbstractValue): boolean {
  return value.flows.some(flow => flow.form === "raw" && flow.source.id === value.identity) && value.ledger.size === 0;
}

/** Shallow owned expression match only; no recursive algebra or feasibility. */
export function fieldRecomposition(value: AbstractValue, state: ScalarConstraints, charge: (work?: number) => void) {
  charge();
  const sum = value.numericExpression;
  if (value.type !== "Field" || sum?.operator !== "+" || sum.operands.length !== 2) return;
  for (const [product, remainder] of [sum.operands, [...sum.operands].reverse()]) {
    charge();
    const multiply = product.numericExpression;
    if (product.type !== "Field" || multiply?.operator !== "*" || multiply.operands.length !== 2) continue;
    for (const [constant, quotient] of [multiply.operands, [...multiply.operands].reverse()]) {
      charge();
      if (constant.constantKind !== "integer" || constant.constant === undefined) continue;
      const scale = BigInt(constant.constant);
      if (scale < 2n || (scale & (scale - 1n)) !== 0n) continue;
      // Independently supplied scalar snapshots, never derived quantities or
      // dependency unions. Equality aliases constrain ranges without rebinding.
      if (!supplied(quotient) || !supplied(remainder) || !quotient.identity || !remainder.identity || quotient.numericExpression || remainder.numericExpression
        || quotient.items || quotient.fields || remainder.items || remainder.fields
        || quotient.constant !== undefined || remainder.constant !== undefined) continue;
      charge((state.scalarEqualities?.size ?? 0) + (state.orderings?.size ?? 0) + (state.integerDomains?.size ?? 0) + state.excluded.size + 1);
      for (const values of state.excluded.values()) charge(values.size);
      const relations = scalarRelations(state);
      if (relations.identity(quotient) === relations.identity(remainder)) continue;
      const q = integerEnvelope("Field", quotient, state), r = integerEnvelope("Field", remainder, state);
      if (!q || !r) throw new Error("Recomposition operand envelopes unavailable or contradictory");
      return { scale, quotient, remainder, q, r, minimum: q.minimum * scale + r.minimum, maximum: q.maximum * scale + r.maximum };
    }
  }
}
