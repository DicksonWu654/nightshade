import type { AbstractValue, SuccessfulPath } from "./index.js";
import { successfulIntegerConstraints } from "./arithmetic-safety.js";
import { integerEnvelope } from "./integer-envelope.js";
import { scalarRelations } from "./scalar-relations.js";

export const MINT_MAXIMUM = (1n << 64n) - 1n;

/** Reconstruct only this history's numeric constraints. Observer snapshots can
 * identify one saved computed scalar, never equal independently computed data. */
export function mintQuantityEvidence(path: SuccessfulPath, charge: (work?: number) => void, meter?: (work: number, values: number) => boolean) {
  const reserve = (work: number, values: number) => {
    if (meter && !meter(work, values)) throw new Error("Mint numeric projection exhausted its shared allocation allowance");
  };
  reserve(0, 4);
  const memo = new WeakMap<AbstractValue, AbstractValue>();
  const project = (value: AbstractValue, depth = 0): AbstractValue => {
    charge();
    if (depth > 32) throw new Error("Mint numeric snapshot projection exceeds 32 levels");
    const prior = memo.get(value);
    if (prior) return prior;
    let fields = 0;
    if (meter) for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { reserve(1, 0); fields++; }
    reserve(0, 25 + fields * 4 + (value.items?.length ?? 0) * 4 + (value.numericExpression?.operands.length ?? 0) * 2);
    const result: AbstractValue = { ...value, identity: value.identity ?? value.mintSnapshot };
    memo.set(value, result);
    if (value.comparison) result.comparison = { ...value.comparison, left: project(value.comparison.left,depth+1), right: project(value.comparison.right,depth+1) };
    if (value.ordering) result.ordering = { ...value.ordering, left: project(value.ordering.left,depth+1), right: project(value.ordering.right,depth+1) };
    if (value.negated) result.negated = project(value.negated,depth+1);
    if (value.numericExpression) result.numericExpression = { ...value.numericExpression, operands: value.numericExpression.operands.map(part=>project(part,depth+1)) };
    if (value.fields) result.fields = Object.fromEntries(Object.entries(value.fields).map(([name,part])=>[name,project(part,depth+1)]));
    if (value.items) result.items = value.items.map(part=>project(part,depth+1));
    return result;
  };
  if (!path.predicates) throw new Error("Mint quantity review requires successful predicates");
  reserve(0, 12 + path.predicates.length * 6 + (path.integerDomains?.size ?? 0) * 4);
  const reconstructed = successfulIntegerConstraints(path.predicates.map(predicate=>({ ...predicate,value:project(predicate.value) })),charge,path.integerDomains,meter ? (work, values) => reserve(work, values) : undefined);
  if (reconstructed.status !== "complete") throw new Error(`Mint numeric constraints are ${reconstructed.status}`);
  const state = reconstructed.state, relations = scalarRelations(state);
  reserve(0, 4);
  const publicLimits = new Set<string>();
  const publicOperand = (part: AbstractValue, depth = 0): boolean => {
    charge();
    if (depth > 32) throw new Error("Mint public-bound projection exceeds 32 levels");
    if (part.constant !== undefined) return false;
    // An exact numeric expression can establish an independently public bound.
    // Its dependency union cannot establish a ledger digest/preimage relation.
    if (part.numericExpression) return part.numericExpression.operands.every(input =>
      input.constantKind === "integer" && input.constant !== undefined || publicOperand(input,depth+1));
    return part.ledger.size > 0 && (!part.flows.length || !!part.preexistingLedger?.size && !!part.identity);
  };
  const dependsOn = (part: AbstractValue, subject: AbstractValue, depth = 0): boolean => {
    charge();
    if (depth > 32) throw new Error("Mint public-bound dependency projection exceeds 32 levels");
    return !!part.identity && part.identity === subject.identity || !!part.numericExpression?.operands.some(input=>dependsOn(input,subject,depth+1));
  };
  const remember = (part: AbstractValue) => {
    charge();
    if (!publicOperand(part)) return;
    const identity = relations.identity(part);
    if (identity) { reserve(0, 1); publicLimits.add(identity); }
  };
  for (const { predicate } of state.orderings?.values() ?? []) { remember(predicate.left); remember(predicate.right); }
  for (const equality of state.scalarEqualities?.values() ?? []) if (equality.equals) { remember(equality.left); remember(equality.right); }
  const bounds = (original: AbstractValue, type: string) => {
    const value = project(original), identity = relations.identity(value);
    charge(state.excluded.size + (state.orderings?.size ?? 0) + (state.scalarEqualities?.size ?? 0) + (state.integerDomains?.size ?? 0) + 1);
    reserve(0, 2);
    const range = integerEnvelope(type,value,state);
    if (!range) throw new Error("Mint quantity has unavailable or contradictory numeric bounds");
    let publicCap = false;
    const publicLimit = (other: AbstractValue) => {
      const key = relations.identity(other);
      return !!key && !!identity && !dependsOn(other,value) && publicLimits.has(key);
    };
    for (const { predicate,truth } of state.orderings?.values() ?? []) {
      charge();
      if (!identity) continue;
      const left = relations.identity(predicate.left), right = relations.identity(predicate.right);
      const upperLeft = truth ? ["<","<="].includes(predicate.operator) : [">",">="].includes(predicate.operator);
      const upperRight = truth ? [">",">="].includes(predicate.operator) : ["<","<="].includes(predicate.operator);
      if (left === identity && upperLeft && publicLimit(predicate.right) || right === identity && upperRight && publicLimit(predicate.left)) publicCap = true;
    }
    for (const equality of state.scalarEqualities?.values() ?? []) {
      charge();
      if (!identity || !equality.equals) continue;
      for (const [subject,other] of [[equality.left,equality.right],[equality.right,equality.left]]) {
        if (relations.identity(subject) === identity && publicOperand(other) && other.identity !== value.identity
          && other.identity !== subject.identity && !dependsOn(other,value)) publicCap = true;
      }
    }
    return { range, publicCap };
  };
  return { bounds };
}
