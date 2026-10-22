import type { AbstractValue, AnalysisFacts, RuntimeOperation, SuccessfulPath } from "./index.js";
import { mayOverlap, regionKey, type Region } from "./regions.js";
import { parseType, printType } from "../semantic/types.js";
import { MAP_DEBIT_RULE } from "../semantic/map-debit-targets.js";
import { directZeroRejection } from "./zero-rejection.js";
import { immutableOperandKey } from "./immutable-key.js";
import { spanId, type Diagnostic } from "../model.js";

export interface Debit { lookup: RuntimeOperation; write: RuntimeOperation; amount?: string }
export interface MapDebitObservation { entry: string; lookup: RuntimeOperation; write: RuntimeOperation; amount?: string; zeroSuccesses: number }

type DebitCharge = (amount?: number, retained?: number) => void;
/** Preflight the bounded immutable-key DAG before the shared key builder owns
 * memo entries, operand arrays or serialized scalar keys. Reserve conservatively
 * for every inspected edge; repeated references do not bypass the walk budget.
 * This is allocation accounting, not an alternate equality/key algorithm. */
function reserveImmutableKey(value: AbstractValue, charge: DebitCharge): void {
  charge(0, 2);
  const seen = new WeakSet<AbstractValue>();
  let visited = 0;
  const visit = (part: AbstractValue, depth: number) => {
    charge(1, 2);
    if (++visited > 4096 || depth > 32) throw new Error("Collection key identity reservation is incomplete");
    if (seen.has(part)) return;
    seen.add(part);
    if (part.negated) { charge(0, 8); visit(part.negated, depth + 1); return; }
    if (part.comparison || part.ordering) {
      charge(0, 12);
      const operation = part.comparison ?? part.ordering!;
      visit(operation.left, depth + 1); visit(operation.right, depth + 1); return;
    }
    if (part.identity) { charge(1 + Math.ceil(part.identity.length / 64), 1 + Math.ceil(part.identity.length / 64)); return; }
    if (part.constant !== undefined) { charge(1 + Math.ceil(part.constant.length / 64), 1 + Math.ceil(part.constant.length / 64)); return; }
    charge(0, 8);
    if (part.fields) {
      let fields = 0;
      for (const name in part.fields) {
        if (!Object.hasOwn(part.fields, name)) continue;
        charge(1 + Math.ceil(name.length / 64), 5 + Math.ceil(name.length / 64));
        fields++; visit(part.fields[name], depth + 1);
      }
      // The shared builder sorts field names; reserve comparison work too.
      charge(fields * Math.ceil(Math.log2(fields + 1)));
    } else for (const item of part.items ?? []) { charge(1, 5); visit(item, depth + 1); }
  };
  visit(value, 0);
}
function exactKey(value: AbstractValue, charge: DebitCharge): string | undefined {
  if (value.constant !== undefined) {
    if (!value.constantKind) throw new Error("Collection key constant lacks its kind");
    const units = 6 * (2 + Math.ceil(value.constant.length / 64));
    charge(units, units);
    return `${value.constantKind}:${value.constant}`;
  }
  reserveImmutableKey(value, charge);
  const operand = immutableOperandKey(value);
  charge(operand.work);
  if (!operand.complete) throw new Error("Collection key identity traversal is incomplete");
  if (!operand.key) return;
  const units = 1 + Math.ceil(operand.key.length / 64);
  charge(units, units);
  return `identity:${operand.key}`;
}

/** Reserve all helper-local snapshot/serialization dimensions before deriving
 * them. Each region key serializes one path; call-site relays use two arrays.
 * Six chunks cover worst-case JSON escaping without treating source bytes as
 * newly owned values. Consumers supply both work and value accounting. */
function snapshotReservation(operation: RuntimeOperation, path: SuccessfulPath, charge: DebitCharge): void {
  charge(0, 4);
  let retained = 16 + 2 * (operation.args?.length ?? 0);
  for (const region of [operation.args?.[0]?.region, operation.membership?.region, operation.result?.region]) {
    if (!region) continue;
    let chunks = 1 + Math.ceil(region.root.length / 64);
    for (const part of region.path) { charge(); chunks += 1 + Math.ceil(part.length / 64); }
    retained += region.path.length + 6 * chunks;
  }
  const position = operation.writesBefore;
  const write = position === undefined ? undefined : path.writes[position];
  if (write) {
    let chunks = 1 + Math.ceil(write.ledger.length / 64);
    for (const part of write.region) { charge(); chunks += 1 + Math.ceil(part.length / 64); }
    retained += write.region.length + 6 * chunks;
  }
  for (const id of operation.callPath) { charge(); retained += 6 * (1 + Math.ceil(id.length / 64)); }
  for (const site of operation.callSites ?? []) { charge(); retained += 2 + 12 * (1 + Math.ceil(site.file.length / 64)); }
  for (const id of write?.callPath ?? []) { charge(); retained += 6 * (1 + Math.ceil(id.length / 64)); }
  for (const site of write?.callSites ?? []) { charge(); retained += 2 + 12 * (1 + Math.ceil(site.file.length / 64)); }
  charge(retained, retained);
}

/** Dedicated histories make an empty operation sequence explicit. Every
 * recorded Map lookup and collection mutation must retain its own operands
 * and ordered effect snapshot, regardless of whether this debit uses it. */
function retainedOperations(facts: AnalysisFacts, path: SuccessfulPath, charge: DebitCharge): RuntimeOperation[] {
  if (!Array.isArray(path.operations) || !Array.isArray(path.writes))
    throw new Error("Successful Map debit history lacks explicit operations or ordered writes");
  for (const operation of path.operations) {
    snapshotReservation(operation, path, charge);
    if (operation.kind === "map-lookup") {
      const membership = operation.membership, receiver = operation.args?.[0]?.region, result = operation.result;
      if (!Array.isArray(operation.args) || operation.args.length < 2 || !operation.args[1] || !receiver || !membership?.region
        || !Array.isArray(membership.region.path) || regionKey(receiver) !== regionKey(membership.region)
        || !result?.region || !Number.isSafeInteger(membership.revision) || membership.revision < 0
        || !Number.isSafeInteger(operation.writesBefore) || operation.writesBefore! < 0
        || operation.writesBefore! > path.writes.length)
        throw new Error("Recorded Map lookup lacks exact receiver, result or ordered membership snapshot");
      const numeric = /^(Field|Uint<\d+>)$/.test(facts.program.representationOf(result.type ?? "unknown"));
      if (numeric && (!result.identity || !result.mapDebitLookupOrigin))
        throw new Error("Numeric Map lookup lacks its immutable result or observer occurrence origin");
      const cell = { ...membership.region, path: [...membership.region.path, `key:${membership.key ?? "*"}`] };
      if (regionKey(cell) !== regionKey(result.region))
        throw new Error("Map lookup result disagrees with its recorded entry snapshot");
    } else if (operation.kind === "collection-write") {
      const position = operation.writesBefore;
      if (!Array.isArray(operation.args) || !operation.args[0]?.region || !Number.isSafeInteger(position)
        || position! < 0 || position! >= path.writes.length)
        throw new Error("Recorded collection mutation lacks exact operands or ordered write position");
      const receiver = operation.args[0]?.region;
      if (operation.name === "insert" && receiver) {
        const representation = facts.program.representationOf(receiver.type);
        charge(representation.length, representation.length);
        const type = parseType(representation);
        if (type.name === "Map" && type.args[1] && /^(Field|Uint<\d+>)$/.test(printType(type.args[1]))
          && (!operation.args[1] || !operation.args[2]))
          throw new Error("Numeric Map insert lacks its exact key or amount operand");
      }
      const write = path.writes[position!];
      if (!write || !Array.isArray(write.region) || write.ledger !== receiver?.root
        || !receiver.path.every((part, index) => write.region[index] === part)
        || spanId(write.location) !== spanId(operation.location)
        || JSON.stringify(write.callPath) !== JSON.stringify(operation.callPath)
        || !Array.isArray(write.callSites) || !Array.isArray(operation.callSites)
        || JSON.stringify(write.callSites.map(spanId)) !== JSON.stringify(operation.callSites.map(spanId)))
        throw new Error("Collection mutation disagrees with its retained write occurrence");
    }
  }
  return path.operations;
}

function directEntryAmount(value: AbstractValue, facts: AnalysisFacts, entry: string, charge: DebitCharge): string | undefined {
  if (!value.identity || value.flows.length !== 1 || value.ledger.size || value.fields || value.items
    || value.numericExpression || value.negated || value.comparison || value.ordering) return;
  const flow = value.flows[0];
  if (flow.form !== "raw" || flow.source.kind !== "entry-parameter" || flow.source.id !== value.identity) return;
  for (const parameter of facts.program.functions.get(entry)!.declaration.parameters) {
    charge(); if (parameter.symbol === flow.source.symbol) return flow.source.symbol;
  }
}

function literalZero(value: AbstractValue): boolean {
  return value.constantKind === "integer" && value.constant === "0" && !value.flows.length && !value.ledger.size
    && !value.fields && !value.items && !value.numericExpression;
}

/** A lookup must be the exact immutable minuend of the selected subtraction.
 * Its result must be written to that same exact numeric entry before any
 * intervening may-alias mutation. A shared wildcard/dependency is insufficient. */
export function exactMapDebits(facts: AnalysisFacts, path: SuccessfulPath, zero: string | undefined, charge: DebitCharge,
  retain: () => void, requireUnguarded = true): Debit[] {
  charge(0, 1);
  const result: Debit[] = [], operations = retainedOperations(facts, path, charge);
  for (const [writeIndex, operation] of operations.entries()) {
    charge();
    if (operation.kind !== "collection-write" || operation.name !== "insert" || operation.writesBefore === undefined) continue;
    const receiver = operation.args[0]?.region, expression = operation.args[2]?.numericExpression;
    if (!receiver || !expression || expression.operator !== "-" || expression.operands.length !== 2) continue;
    const representation = facts.program.representationOf(receiver.type);
    charge(representation.length, representation.length);
    const map = parseType(representation);
    if (map.name !== "Map" || !map.args[1] || !/^(Field|Uint<\d+>)$/.test(printType(map.args[1]))) continue;
    const minuend = expression.operands[0], amountValue = expression.operands[1];
    const amount = directEntryAmount(amountValue, facts, path.entry, charge);
    if (zero ? amount !== zero || amountValue.constant !== "0" || amountValue.constantKind !== "integer"
      : !amount && !literalZero(amountValue)) continue;
    if (!minuend.identity || !minuend.mapDebitLookupOrigin || !minuend.region || minuend.region.path.includes("key:*")) continue;
    const position = operation.writesBefore;
    if (!Number.isSafeInteger(position) || position < 0 || position >= path.writes.length) continue;
    snapshotReservation(operation, path, charge);
    charge(receiver.path.length + minuend.region.path.length + path.writes[position].region.length,
      3 + receiver.path.length);
    const target = { root: path.writes[position].ledger, path: path.writes[position].region, type: "unknown" };
    const writeKey = exactKey(operation.args[1], charge);
    if (!writeKey || receiver.path.includes("key:*") || target.path.includes("key:*"))
      throw new Error("Candidate Map debit write lacks an exact key or receiver");
    const writtenCell = { root: receiver.root, path: [...receiver.path, `key:${writeKey}`], type: "unknown" };
    if (regionKey(writtenCell) !== regionKey(target))
      throw new Error("Map debit write operands disagree with the retained write cell");
    for (let lookupIndex = 0; lookupIndex < writeIndex; lookupIndex++) {
      charge();
      const lookup = operations[lookupIndex];
      if (lookup.kind !== "map-lookup" || lookup.result.mapDebitLookupOrigin !== minuend.mapDebitLookupOrigin) continue;
      if (lookup.result.identity !== minuend.identity || !lookup.membership
        || lookup.membership.key !== exactKey(lookup.args[1], charge))
        throw new Error("Candidate lookup origin or key operands disagree with the immutable debit minuend");
      if (requireUnguarded && lookup.membership.before !== undefined) continue;
      snapshotReservation(lookup, path, charge);
      charge(lookup.membership.region.path.length, 2 + lookup.membership.region.path.length);
      if (!lookup.membership.key || lookup.membership.region.path.includes("key:*"))
        throw new Error("Candidate lookup lacks an exact key or receiver");
      const cell: Region = { ...lookup.membership.region, path: [...lookup.membership.region.path, `key:${lookup.membership.key}`], type: "unknown" };
      if (regionKey(cell) !== regionKey(target) || regionKey(cell) !== regionKey(minuend.region!)) continue;
      if (lookup.writesBefore === undefined || lookup.writesBefore > position) continue;
      let current = true;
      for (let index = lookup.writesBefore; index < position; index++) {
        charge(1 + cell.path.length + path.writes[index].region.length, 1);
        if (mayOverlap(cell, { root: path.writes[index].ledger, path: path.writes[index].region, type: "unknown" })) { current = false; break; }
      }
      if (current) { charge(0, 4); retain(); result.push({ lookup, write: operation, amount }); }
    }
  }
  return result;
}

/** Ordinary candidate discovery sees real call operands before specializing
 * entry inputs. It admits only exact numeric decrements of a Map lookup. */
export function mapDebitAmountCandidates(facts: AnalysisFacts, entry: string, allowance: number) {
  let work = 0, values = 0;
  const charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (values + facts.metrics.abstractValues > facts.mapDebitEvidence!.maxValues) throw new Error("Map debit candidate value allowance exhausted");
    if (work > allowance) throw new Error("Map debit candidate traversal exhausted its allowance");
  };
  const retain = () => {
    if (++values + facts.metrics.abstractValues > facts.mapDebitEvidence!.maxValues)
      throw new Error("Map debit candidate value allowance exhausted");
  };
  try {
    if (!facts.mapDebitEvidence || facts.mapDebitEvidence.entry !== entry || !facts.completedEntries.includes(entry)
      || facts.diagnostics.length || !facts.collectionEvidence || facts.predicateScope !== "all"
      || facts.pathSemantics !== "equivalent-states" || !facts.paths.length)
      throw new Error("Complete ordinary debit operands are unavailable");
    charge(0, 1);
    const amounts = new Set<string>();
    for (const path of facts.paths) {
      charge(); if (path.entry !== entry) continue;
      // Candidate discovery still needs the exact relation; membership is
      // deliberately ignored until the amount-zero invocation is observed.
      for (const debit of exactMapDebits(facts, path, undefined, charge, retain, false)) if (debit.amount && !amounts.has(debit.amount)) {
        retain();
        amounts.add(debit.amount);
      }
    }
    charge(amounts.size, amounts.size + 1);
    return [...amounts];
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
}

export function mapDebitObservations(facts: AnalysisFacts, allowance = 200000) {
  const observations: MapDebitObservation[] = [], diagnostics: Diagnostic[] = [];
  const evidence = facts.mapDebitEvidence, zero = facts.zeroEntry;
  if (!evidence) return { observations, diagnostics };
  let work = 0, values = 0;
  const charge = (amount = 1, retained = 0) => {
    work += amount; values += retained;
    if (facts.metrics.abstractValues + values > evidence.maxValues) throw new Error("Map debit relation value allowance exhausted");
    if (work > allowance || facts.metrics.steps + work > evidence.maxSteps)
      throw new Error("Map debit relation traversal exhausted its shared allowance");
  };
  const retain = () => {
    if (++values + facts.metrics.abstractValues > evidence.maxValues)
      throw new Error("Map debit relation value allowance exhausted");
  };
  try {
    if (facts.pathSemantics !== "equivalent-states" || facts.predicateScope !== "all" || !facts.collectionEvidence
      || !facts.completedEntries.includes(evidence.entry) || facts.diagnostics.length)
      throw new Error("Complete exact Map debit histories are unavailable");
    if (!facts.paths.length && !(zero && directZeroRejection(facts)))
      throw new Error("No modeled full successful amount-zero invocation supplies debit evidence");
    charge(0, 1);
    const seen = new Set<string>();
    let zeroSuccesses = 0;
    for (const path of facts.paths) { charge(); if (path.entry === evidence.entry) zeroSuccesses++; }
    for (const path of facts.paths) {
      charge(); if (path.entry !== evidence.entry) continue;
      for (const debit of exactMapDebits(facts, path, zero?.parameter, charge, retain)) {
        if (!zero && debit.amount) continue;
        const key = `${debit.lookup.location.file}:${debit.lookup.location.start}:${debit.amount ?? "literal"}`;
        if (seen.has(key)) continue;
        charge(0, 6); retain();
        seen.add(key);
        observations.push({ entry: evidence.entry, lookup: debit.lookup, write: debit.write, amount: debit.amount,
          zeroSuccesses });
      }
    }
  } catch (error) {
    diagnostics.push({ code: "map-debit-evidence-unavailable", message: error instanceof Error ? error.message : String(error),
      location: facts.program.functions.get(evidence.entry)!.declaration.span,
      scope: { kind: "rule", detectorId: MAP_DEBIT_RULE, entry: evidence.entry } });
  } finally { facts.metrics.steps += work; facts.metrics.abstractValues += values; }
  return { observations, diagnostics };
}
