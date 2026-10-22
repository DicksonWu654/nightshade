import type { AnalysisFacts, AbstractValue } from "./index.js";

/** Deliberately narrow: an unconditional direct nonzero input guard. Neither
 * dependency unions nor missing successful paths establish this boundary. */
export function directZeroRejection(facts: AnalysisFacts): boolean {
  const zero = facts.zeroEntry;
  if (!zero || facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all"
    || !facts.collectionEvidence || facts.diagnostics.length || !facts.completedEntries.includes(zero.entry)
    || facts.paths.length || facts.failedAssertions.length !== 1) return false;
  const failure = facts.failedAssertions[0];
  if (failure.path.length || failure.callPath.length !== 1 || failure.callPath[0] !== zero.entry
    || failure.condition.constantKind !== "boolean" || failure.condition.constant !== "false") return false;
  const order = failure.condition.ordering;
  if (!order || !/^Uint<\d+>$/.test(order.numericType)) return false;
  const input = (value: AbstractValue) => value.identity !== undefined && value.constantKind === "integer"
    && value.constant === "0" && !value.ledger.size && value.flows.length === 1
    && value.flows[0].form === "raw" && value.flows[0].source.kind === "entry-parameter"
    && value.flows[0].source.symbol === zero.parameter && value.identity === value.flows[0].source.id;
  const literalZero = (value: AbstractValue) => value.constantKind === "integer" && value.constant === "0"
    && !value.flows.length && !value.ledger.size;
  return order.operator === ">" && input(order.left) && literalZero(order.right)
    || order.operator === "<" && literalZero(order.left) && input(order.right);
}
