import type { AbstractValue } from "./index.js";
import { fieldModulus } from "../semantic/fields.js";
import { numericBound } from "../semantic/types.js";
import { orderedBounds, valueIdentity, type ScalarConstraints } from "./transfers.js";
import { scalarRelations } from "./scalar-relations.js";

/** A conservative unsigned envelope of an immutable value on a successful
 * history. It is not a feasibility certificate or a relationship solver.
 * Numeric casts preserve value; their successful target domain intersects the
 * prior domain. Derived transfers must discard the prior envelope. Null
 * denotes an empty numeric intersection; undefined denotes a nonnumeric type. */
export function integerEnvelope(type: string, value: AbstractValue, state: ScalarConstraints): { minimum: bigint; maximum: bigint } | null | undefined {
  state.scalarMeter?.(1, 3);
  const bound = numericBound(type) ?? fieldModulus(type);
  if (bound === undefined || bound <= 0n) return;
  let minimum = 0n, maximum = bound - 1n;
  if (value.integerRange) {
    const lower = BigInt(value.integerRange.minimum), upper = BigInt(value.integerRange.maximum);
    if (lower > minimum) minimum = lower;
    if (upper < maximum) maximum = upper;
  }
  // Unsigned comparisons on an identity-preserving cast constrain the same
  // mathematical value. No Field ordering syntax or subtyping is invented.
  const relations = state.scalarEqualities?.size ? scalarRelations(state) : undefined;
  const identity = relations ? relations.identity(value) : valueIdentity(value);
  if (identity) for (const [key, range] of state.integerDomains ?? []) {
    state.scalarMeter?.(1, 4);
    if ((relations ? relations.identity({ identity: key, flows: [], ledger: new Set() }) : key) !== identity) continue;
    if (BigInt(range.minimum) > minimum) minimum = BigInt(range.minimum);
    if (BigInt(range.maximum) < maximum) maximum = BigInt(range.maximum);
  }
  // Equality to a preserved, narrower typed scalar constrains this result as
  // well. Read the actual immutable alias snapshots, never dependency unions.
  if (relations && identity) for (const relation of state.scalarEqualities!.values()) {
    state.scalarMeter?.(1, 2);
    if (!relation.equals) continue;
    for (const part of [relation.left,relation.right]) {
      if (relations.identity(part) !== identity) continue;
      const domain = numericBound(part.type ?? "unknown") ?? fieldModulus(part.type ?? "unknown");
      if (domain !== undefined && domain - 1n < maximum) maximum = domain - 1n;
      if (part.integerRange) {
        if (BigInt(part.integerRange.minimum) > minimum) minimum = BigInt(part.integerRange.minimum);
        if (BigInt(part.integerRange.maximum) < maximum) maximum = BigInt(part.integerRange.maximum);
      }
    }
  }
  const bounds = orderedBounds(value, state, minimum, maximum);
  if (!bounds) return null;
  // Exclusions belong to immutable values, including proven scalar aliases.
  // Each endpoint advance consumes a distinct excluded integer, so work is
  // bounded by retained exclusions rather than by the integer domain width.
  state.scalarMeter?.(1, 1);
  const excluded = relations ? new Set<string>() : state.excluded.get(identity ?? "") ?? new Set<string>();
  if (relations && identity) for (const [key, values] of state.excluded) {
    state.scalarMeter?.(1, 4 + values.size);
    if (relations.identity({ identity: key, flows: [], ledger: new Set() }) === identity)
      for (const value of values) excluded.add(value);
  }
  while (bounds.minimum <= bounds.maximum && excluded.has(`integer:${bounds.minimum}`)) { state.scalarMeter?.(1, 1); bounds.minimum++; }
  while (bounds.maximum >= bounds.minimum && excluded.has(`integer:${bounds.maximum}`)) { state.scalarMeter?.(1, 1); bounds.maximum--; }
  return bounds.minimum > bounds.maximum ? null : bounds;
}
