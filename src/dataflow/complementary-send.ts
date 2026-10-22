import { pathLength, identityLength } from "../semantic/metering.js";
import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { immutableOperandKey } from "./immutable-key.js";
import { successfulIntegerConstraints } from "./arithmetic-safety.js";
import { integerEnvelope } from "./integer-envelope.js";
import { numericBound } from "../semantic/types.js";
import { COMPLEMENTARY_SEND_RULE, COMPLEMENTARY_SEND_TARGET, complementarySendProfile,
  type ComplementaryCharge } from "../semantic/complementary-send-targets.js";
import type { Diagnostic } from "../model.js";

type Range = { minimum: bigint; maximum: bigint };
export interface ComplementarySendObservation {
  entry: string; partSend: RuntimeOperation; remainderSend: RuntimeOperation; pairKey: string;
  part: Range; remainder: Range; total: Range;
}

/** Source endpoints plus the original invocation sites identify a reportable
 * pair across sibling histories, without depending on unrelated effect order. */
export function complementaryPairKey(entry: string, part: RuntimeOperation, remainder: RuntimeOperation, charge: ComplementaryCharge): string {
  let units = 12 + Math.ceil(identityLength(entry, charge) / 64);
  for (const operation of [part, remainder]) {
    charge(); units += 4 + Math.ceil(pathLength(operation.location.file, charge) / 64);
    for (const site of operation.callSites ?? []) { charge(); units += 4 + Math.ceil(pathLength(site.file, charge) / 64); }
  }
  charge(0, units);
  return JSON.stringify([entry, part.location.file, part.location.start, remainder.location.file, remainder.location.start,
    part.callSites?.map(site => [site.file, site.start]), remainder.callSites?.map(site => [site.file, site.start])]);
}

/** Rebuild immutable numeric snapshots and one conjunction of all mandatory
 * predicates, including late checks. Reserve projection and constraint storage
 * before allocation; the bound covers scalar closure maps and envelope copies. */
function numericHistory(path: SuccessfulPath, charge: ComplementaryCharge, representation: (value: AbstractValue) => string) {
  charge(0, 8);
  const memo = new WeakMap<AbstractValue, AbstractValue>();
  const project = (value: AbstractValue, depth = 0): AbstractValue => {
    charge();
    if (depth > 32) throw new Error("Complementary numeric operand depth is unavailable");
    const prior = memo.get(value); if (prior) return prior;
    let fieldCount = 0;
    for (const name in value.fields) if (Object.hasOwn(value.fields, name)) { charge(); fieldCount++; }
    charge(0, 25 + fieldCount * 4 + (value.items?.length ?? 0) * 4);
    const fields = value.fields ? Object.keys(value.fields) : [];
    const result = { ...value, identity: value.identity ?? value.mintSnapshot };
    memo.set(value, result);
    if (value.comparison) result.comparison = { ...value.comparison, left: project(value.comparison.left, depth + 1), right: project(value.comparison.right, depth + 1) };
    if (value.ordering) result.ordering = { ...value.ordering, left: project(value.ordering.left, depth + 1), right: project(value.ordering.right, depth + 1) };
    if (value.negated) result.negated = project(value.negated, depth + 1);
    if (value.numericExpression) {
      if (value.numericExpression.operands.length !== 2) throw new Error("Complementary numeric expression operands are incomplete");
      charge(0, 2 + value.numericExpression.operands.length);
      result.numericExpression = { ...value.numericExpression, operands: value.numericExpression.operands.map(part => project(part, depth + 1)) };
    }
    if (value.fields) result.fields = Object.fromEntries(fields.map(name => [name, project(value.fields![name], depth + 1)]));
    if (value.items) result.items = value.items.map(part => project(part, depth + 1));
    return result;
  };
  if (!path.predicates) throw new Error("Complementary send predicate history is missing");
  charge(0, 12 + path.predicates.length * 6 + (path.integerDomains?.size ?? 0) * 4);
  const predicates = path.predicates.map(item => ({ ...item, value: project(item.value) }));
  // Each projected relation has reserved scalar state/closure storage above.
  const constraints = successfulIntegerConstraints(predicates, charge, path.integerDomains, charge);
  if (constraints.status !== "complete") throw new Error(`Complementary numeric constraints are ${constraints.status}`);
  const bounds = (value: AbstractValue, type: string, depth = 0): Range => {
    if (depth > 32) throw new Error("Complementary arithmetic envelope depth is unavailable");
    const projected = project(value), state = constraints.state;
    const size = 1 + state.excluded.size + (state.orderings?.size ?? 0) + (state.scalarEqualities?.size ?? 0) + (state.integerDomains?.size ?? 0);
    let exclusions = 0;
    for (const values of state.excluded.values()) { charge(); exclusions += values.size; }
    charge(size + exclusions, 2);
    const range = integerEnvelope(type, projected, state);
    if (!range) throw new Error("Complementary send exact scalar bounds are unavailable or contradictory");
    const expression = projected.numericExpression;
    if (expression?.operands.length === 2 && numericBound(expression.numericType ?? "unknown") !== undefined) {
      charge(2, 4);
      const [left, right] = expression.operands.map(operand => bounds(operand, representation(operand), depth + 1));
      let minimum: bigint, maximum: bigint;
      if (expression.operator === "-") { minimum = left.minimum - right.maximum; maximum = left.maximum - right.minimum; }
      else if (expression.operator === "+") { minimum = left.minimum + right.minimum; maximum = left.maximum + right.maximum; }
      else { minimum = left.minimum * right.minimum; maximum = left.maximum * right.maximum; }
      // Forward envelopes only. Unsigned checked subtraction rejects negative
      // results; widening arithmetic and checked casts retain their value.
      if (minimum > range.minimum) range.minimum = minimum;
      if (maximum < range.maximum) range.maximum = maximum;
      if (range.minimum > range.maximum) throw new Error("Complementary arithmetic range intersection is empty");
    }
    return range;
  };
  return { bounds, project };
}

/** Equality is only an exact immutable operand key. No wildcard region,
 * dependency overlap or independently recomputed arithmetic identifies data. */
export function complementarySendObservations(facts: AnalysisFacts) {
  const evidence = facts.complementarySendEvidence;
  const entry = evidence?.entry ?? facts.program.entries[0];
  const observations: ComplementarySendObservation[] = [], diagnostics: Diagnostic[] = [];
  const charge: ComplementaryCharge = (work = 1, values = 0) => {
    facts.metrics.steps += work; facts.metrics.abstractValues += values;
    if (!evidence || facts.metrics.steps > evidence.maxSteps || facts.metrics.abstractValues > evidence.maxValues)
      throw new Error("Complementary send proof exhausted the shared preparation/execution allowance");
    return true;
  };
  Object.assign(charge, { identityText: facts.program.meteringIdentity });
  const type = (value: AbstractValue) => { charge(); return facts.program.representationOf(value.type ?? "unknown"); };
  const unsigned = (value: AbstractValue, maximum = 1n << 248n) => {
    const bound = numericBound(type(value)); return bound !== undefined && bound <= maximum;
  };
  const key = (value: AbstractValue) => {
    charge(0, 1);
    const exact = immutableOperandKey(value.identity || !value.mintSnapshot ? value : { ...value, identity: value.mintSnapshot },
      Math.min(4096, evidence!.maxSteps - facts.metrics.steps), undefined, charge);
    if (!exact.complete || !exact.key) throw new Error("Complementary send immutable operand provenance is unavailable");
    return exact.key;
  };
  try {
    if (!evidence || !complementarySendProfile(facts.program) || facts.predicateScope !== "all"
      || facts.pathSemantics !== "equivalent-states" || facts.diagnostics.length
      || !facts.completedEntries.includes(evidence.entry) || evidence.histories !== facts.paths.length
      || facts.paths.length > evidence.maxPaths || !facts.invocationEvidence?.includes(COMPLEMENTARY_SEND_TARGET))
      throw new Error("Complete original complementary send histories or supported compiler profile are unavailable");
    charge(0, 3); const reported = new Set<string>();
    for (const path of facts.paths) {
      charge();
      if (path.entry !== evidence.entry || !path.complementaryHistory || path.checkpointOutcomes
        || path.complementaryHistory.operations !== (path.operations?.length ?? 0)
        || path.complementaryHistory.predicates !== path.predicates?.length || path.complementaryHistory.writes !== path.writes.length)
        throw new Error("Complementary send original history rows are missing or inconsistent");
      charge(0, 1); const sends: RuntimeOperation[] = [];
      for (const operation of path.operations ?? []) {
        charge();
        if (operation.kind !== "circuit-invocation" || operation.name !== COMPLEMENTARY_SEND_TARGET) continue;
        if (operation.args.length !== 3 || !unsigned(operation.args[1], 1n << 128n)) throw new Error("Complementary send exact unsigned sent operands are unavailable");
        if (operation.args[1].numericExpression && (operation.args[1].numericExpression.operands.length !== 2
          || !operation.args[1].numericExpression.numericType)) throw new Error("Complementary send numeric operand carrier is incomplete");
        if (operation.args[1].complementaryLineageLost) throw new Error("Complementary send arithmetic operand lineage was lost at a may-alias join");
        key(operation.args[0]); key(operation.args[1]);
        charge(0, 1); sends.push(operation);
      }
      if (sends.length < 2) continue;
      let history: ReturnType<typeof numericHistory> | undefined;
      for (let i = 0; i < sends.length; i++) for (let j = 0; j < sends.length; j++) {
        charge(); if (i === j) continue;
        const partSend = sends[i], remainderSend = sends[j], part = partSend.args[1], remainder = remainderSend.args[1];
        const difference = remainder.numericExpression;
        if (!difference || difference.operator !== "-" || difference.operands.length !== 2) continue;
        const [total, subtrahend] = difference.operands;
        // Subtraction has ordinary checked unsigned semantics. Field arithmetic
        // and casts cannot create an unsigned operand relationship.
        if (numericBound(difference.numericType ?? "unknown") === undefined || !unsigned(total) || !unsigned(subtrahend)) continue;
        if (key(part) !== key(subtrahend) || key(partSend.args[0]) !== key(remainderSend.args[0])) continue;
        const pairKey = complementaryPairKey(path.entry, partSend, remainderSend, charge);
        if (reported.has(pairKey)) continue;
        history ??= numericHistory(path, charge, type);
        const totalRange = history.bounds(total, type(total));
        if (totalRange.minimum <= 0n) continue;
        const partRange = history.bounds(part, type(part)), remainderRange = history.bounds(remainder, type(remainder));
        if (partRange.minimum !== 0n || remainderRange.minimum !== 0n) continue;
        // Reserve the complete emitted finding, pair identity, traces, report
        // strings and uniqueness arrays before retaining its operands.
        let siteUnits = 4;
        for (const sites of [partSend.callSites, remainderSend.callSites]) for (const site of sites ?? []) {
          charge(); siteUnits += 8 + Math.ceil(pathLength(site.file, charge) / 64) * 4;
        }
        charge(facts.program.files.size + partSend.callPath.length + remainderSend.callPath.length,
          160 + siteUnits + facts.program.files.size * 4 + (partSend.callPath.length + remainderSend.callPath.length) * 8
          + Math.ceil((pathLength(partSend.location.file, charge) + pathLength(remainderSend.location.file, charge) + identityLength(path.entry, charge)) / 64) * 8);
        charge(0, 1); reported.add(pairKey);
        observations.push({ entry: path.entry, partSend, remainderSend, pairKey, part: partRange, remainder: remainderRange, total: totalRange });
      }
    }
  } catch (error) {
    observations.length = 0;
    diagnostics.push({ code: "complementary-send-proof-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.functions.get(entry)?.declaration.span ?? facts.program.rootSource.ast.span,
      ...(entry ? { scope: { kind: "rule" as const, detectorId: COMPLEMENTARY_SEND_RULE, entry } } : {}) });
  }
  return { observations, diagnostics };
}
