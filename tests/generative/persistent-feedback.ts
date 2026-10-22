/** Test-only feedback for the unchanged owned Counter/witness fixture.
 * Qualification uses the existing oracle; feature values use measured rows only.
 * Saved data validation is not attestation that the runtime actually executed. */
import { validatePersistentResult } from "./persistent-artifacts.js";
import { PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentOperation, type PersistentRow, type PersistentSnapshot } from "./persistent-model.js";

export const PERSISTENT_FEATURE_SET = "persistent-snapshot-features-1";
export const PERSISTENT_FEEDBACK_COVERAGE = "observed-persistent-snapshot-transitions";
export const PERSISTENT_COVERAGE_KIND = PERSISTENT_FEEDBACK_COVERAGE;
export const PERSISTENT_FEEDBACK_LIMITS = Object.freeze({ maxRows: 32, maxRowFeatures: 8, maxFeatureEmissions: 257, maxFeatures: 257, maxDescriptorBytes: 512, maxBytes: 262144 });
export const PERSISTENT_FEEDBACK_DIAGNOSTICS = ["persistent-protocol", "persistent-sequence-budget", "persistent-observation-budget", "persistent-unqualified-rejection", "persistent-input-identity", "worker-input-budget", "worker-interrupted", "worker-timeout", "worker-output-budget", "worker-launch", "worker-failed", "worker-input", "persistent-feedback-budget", "persistent-feedback-protocol"] as const;
export type PersistentFeedbackDiagnostic = typeof PERSISTENT_FEEDBACK_DIAGNOSTICS[number];
type Operation = PersistentOperation["kind"];
type Outcome = PersistentRow["outcome"];
type Origin = "circuit" | "adapter";
type Count = "zero" | "one" | "many";
type Delta = "negative-many" | "negative-one" | "zero" | "positive-one" | "positive-many";
type Comparison = "less" | "equal" | "greater";
type AvailableBoolean = boolean | "unavailable";
export type PersistentFeatureDescriptor =
  | ["initial", Count]
  | ["operation-outcome", Origin, Operation, Outcome]
  | ["snapshot-transition", Origin, Operation, Delta, Delta, boolean]
  | ["post-state", Operation, Count, Count, boolean]
  | ["schedule-adjacency", Operation, Outcome, Operation, Outcome, boolean]
  | ["slot-shape", Operation, number, number]
  | ["rejection", "owned-persistent-assertion", boolean, number]
  | ["save", boolean, AvailableBoolean, boolean, number | "unavailable"]
  | ["restore", boolean, AvailableBoolean, Comparison, Comparison, boolean, boolean]
  | ["witness", Operation, Outcome, Comparison, Comparison | "absent"]
  | ["witness-history", Operation, Outcome, Operation, Outcome, Comparison, boolean, boolean];

export interface PersistentFeedback {
  schemaVersion: "nightshade-persistent-feedback-1";
  featureSet: typeof PERSISTENT_FEATURE_SET;
  coverageKind: typeof PERSISTENT_FEEDBACK_COVERAGE;
  fixture: "owned-persistent-counter-witness";
  sourceSha256: string;
  compiledJavaScriptSha256: string;
  runtimeLockSha256: string;
  sequenceSha256: string;
  operationsSha256: string;
  observationSha256: string;
  initialFeatureIds: string[];
  rows: { index: number; operation: Operation; slot: number | null; featureIds: string[] }[];
  features: { id: string; descriptor: PersistentFeatureDescriptor }[];
  counts: { operationRows: number; circuitEvaluations: number; adapterOperations: number; featureEmissions: number; distinctFeatures: number };
}
export type PersistentFeedbackOutcome = { status: "complete"; feedback: PersistentFeedback }
  | { status: "property-failed"; diagnostic: "persistent-model-disagreement"; signature: string; observationSha256: string }
  | { status: "incomplete"; diagnostic: PersistentFeedbackDiagnostic; message: string };

class FeedbackError extends Error {
  constructor(readonly diagnostic: "persistent-feedback-protocol" | "persistent-feedback-budget", message: string) { super(`${diagnostic}: ${message}`); }
}
function invalid(message: string): never { throw new FeedbackError("persistent-feedback-protocol", message); }
function budget(message: string): never { throw new FeedbackError("persistent-feedback-budget", message); }
function record(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return invalid("Expected plain data object");
  const own = Reflect.ownKeys(value);
  if (own.length !== keys.length || own.some(key => typeof key !== "string" || !keys.includes(key))) return invalid("Unexpected or missing feedback fields");
  for (const key of keys) {
    const property = Object.getOwnPropertyDescriptor(value, key)!;
    if (!("value" in property) || !property.enumerable) return invalid("Feedback fields must be enumerable data, not accessors");
  }
  return value as Record<string, unknown>;
}
function array(value: unknown, maximum: number): unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return invalid("Expected dense ordinary array");
  if (value.length > maximum) return budget(`Feedback array exceeds ${maximum}`);
  if (Reflect.ownKeys(value).length !== value.length + 1) return invalid("Unexpected array fields or holes");
  for (let index = 0; index < value.length; index++) {
    const property = Object.getOwnPropertyDescriptor(value, index);
    if (!property || !("value" in property) || !property.enumerable) return invalid("Array entries must be enumerable data");
  }
  return value;
}
function integer(value: unknown, maximum: number, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum || value > maximum) return invalid(`Expected integer ${minimum}..${maximum}`);
  return value;
}
function hash(value: unknown): string {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) return invalid("Invalid feedback digest");
  return value;
}
const operations = ["accept", "reject", "inspect", "save", "restore"] as const;
const outcomes = ["evaluation-success", "evaluation-rejection", "saved", "restored"] as const;
const deltas = ["negative-many", "negative-one", "zero", "positive-one", "positive-many"] as const;
const comparisons = ["less", "equal", "greater"] as const;
const counts = ["zero", "one", "many"] as const;
const choose = <const T extends string>(value: unknown, choices: readonly T[]): T => typeof value === "string" && choices.includes(value as T) ? value as T : invalid("Unknown feedback enum");
const bool = (value: unknown): boolean => typeof value === "boolean" ? value : invalid("Expected Boolean feedback");
const availableBoolean = (value: unknown): AvailableBoolean => value === "unavailable" ? value : bool(value);
const origin = (operation: Operation): Origin => operation === "save" || operation === "restore" ? "adapter" : "circuit";
const featureId = (descriptor: PersistentFeatureDescriptor): string => persistentDigest(JSON.stringify(descriptor));
function descriptor(value: unknown): PersistentFeatureDescriptor {
  const tuple = array(value, 8);
  const length = (wanted: number): void => { if (tuple.length !== wanted) invalid("Wrong feature tuple length"); };
  let result: PersistentFeatureDescriptor;
  switch (tuple[0]) {
    case "initial": length(2); result = ["initial", choose(tuple[1], counts)]; break;
    case "operation-outcome": length(4); result = ["operation-outcome", choose(tuple[1], ["circuit", "adapter"]), choose(tuple[2], operations), choose(tuple[3], outcomes)]; break;
    case "snapshot-transition": length(6); result = ["snapshot-transition", choose(tuple[1], ["circuit", "adapter"]), choose(tuple[2], operations), choose(tuple[3], deltas), choose(tuple[4], deltas), bool(tuple[5])]; break;
    case "post-state": length(5); result = ["post-state", choose(tuple[1], operations), choose(tuple[2], counts), choose(tuple[3], counts), bool(tuple[4])]; break;
    case "schedule-adjacency": length(6); result = ["schedule-adjacency", choose(tuple[1], operations), choose(tuple[2], outcomes), choose(tuple[3], operations), choose(tuple[4], outcomes), bool(tuple[5])]; break;
    case "slot-shape": length(4); result = ["slot-shape", choose(tuple[1], operations), integer(tuple[2], 4, 1), integer(tuple[3], 4)]; break;
    case "rejection": length(4); result = ["rejection", choose(tuple[1], ["owned-persistent-assertion"]), bool(tuple[2]), integer(tuple[3], 2)]; break;
    case "save": length(5); result = ["save", bool(tuple[1]), availableBoolean(tuple[2]), bool(tuple[3]), tuple[4] === "unavailable" ? tuple[4] : integer(tuple[4], 3)]; break;
    case "restore": length(7); result = ["restore", bool(tuple[1]), availableBoolean(tuple[2]), choose(tuple[3], comparisons), choose(tuple[4], comparisons), bool(tuple[5]), bool(tuple[6])]; break;
    case "witness": length(5); result = ["witness", choose(tuple[1], operations), choose(tuple[2], outcomes), choose(tuple[3], comparisons), choose(tuple[4], [...comparisons, "absent"])]; break;
    case "witness-history": length(8); result = ["witness-history", choose(tuple[1], operations), choose(tuple[2], outcomes), choose(tuple[3], operations), choose(tuple[4], outcomes), choose(tuple[5], comparisons), bool(tuple[6]), bool(tuple[7])]; break;
    default: return invalid("Unknown feature family");
  }
  if (Buffer.byteLength(JSON.stringify(result)) > PERSISTENT_FEEDBACK_LIMITS.maxDescriptorBytes) return budget("Feature descriptor byte allowance exhausted");
  return result;
}
function ids(value: unknown, maximum: number): string[] {
  const values = array(value, maximum).map(hash);
  if (values.some((id, index) => index > 0 && values[index - 1] >= id)) return invalid("Feature IDs must be sorted and unique");
  return values;
}

/** Decode a bounded data-only shape. Regeneration still needs original evidence. */
function decodeFeedback(value: unknown): PersistentFeedback {
  const raw = record(value, ["schemaVersion", "featureSet", "coverageKind", "fixture", "sourceSha256", "compiledJavaScriptSha256", "runtimeLockSha256", "sequenceSha256", "operationsSha256", "observationSha256", "initialFeatureIds", "rows", "features", "counts"]);
  if (raw.schemaVersion !== "nightshade-persistent-feedback-1" || raw.featureSet !== PERSISTENT_FEATURE_SET || raw.coverageKind !== PERSISTENT_FEEDBACK_COVERAGE || raw.fixture !== "owned-persistent-counter-witness" || raw.sourceSha256 !== PERSISTENT_SOURCE_SHA256 || raw.runtimeLockSha256 !== PERSISTENT_LOCK_SHA256) return invalid("Unqualified feedback schema/scope/fixture");
  const initialFeatureIds = ids(raw.initialFeatureIds, 1);
  if (initialFeatureIds.length !== 1) return invalid("Missing constructor feedback");
  let emissions = initialFeatureIds.length;
  const rows = array(raw.rows, PERSISTENT_FEEDBACK_LIMITS.maxRows).map((value, index): PersistentFeedback["rows"][number] => {
    const row = record(value, ["index", "operation", "slot", "featureIds"]);
    if (integer(row.index, 31) !== index) return invalid("Feedback row order mismatch");
    const operation = choose(row.operation, operations);
    const slot = origin(operation) === "adapter" ? integer(row.slot, 3) : row.slot === null ? null : invalid("Circuit operation has a slot");
    const featureIds = ids(row.featureIds, PERSISTENT_FEEDBACK_LIMITS.maxRowFeatures);
    if (!featureIds.length) return invalid("Missing measured row feedback");
    emissions += featureIds.length;
    return { index, operation, slot, featureIds };
  });
  if (emissions > PERSISTENT_FEEDBACK_LIMITS.maxFeatureEmissions) return budget("Feature emission allowance exhausted");
  const features = array(raw.features, PERSISTENT_FEEDBACK_LIMITS.maxFeatures).map(value => {
    const entry = record(value, ["id", "descriptor"]), id = hash(entry.id), tuple = descriptor(entry.descriptor);
    if (id !== featureId(tuple)) return invalid("Feature descriptor/ID mismatch");
    return { id, descriptor: tuple };
  });
  if (features.some((entry, index) => index > 0 && features[index - 1].id >= entry.id)) return invalid("Features must be sorted and unique");
  const mapped = new Map(features.map(entry => [entry.id, entry.descriptor]));
  if (mapped.get(initialFeatureIds[0])?.[0] !== "initial" || features.filter(entry => entry.descriptor[0] === "initial").length !== 1) return invalid("Constructor feature association mismatch");
  for (const row of rows) if (row.featureIds.some(id => !mapped.has(id) || mapped.get(id)![0] === "initial")) return invalid("Missing/incorrect row feature association");
  const referenced = [...new Set([...initialFeatureIds, ...rows.flatMap(row => row.featureIds)])].sort();
  if (JSON.stringify(referenced) !== JSON.stringify(features.map(entry => entry.id))) return invalid("Unreferenced or missing feature");
  const count = record(raw.counts, ["operationRows", "circuitEvaluations", "adapterOperations", "featureEmissions", "distinctFeatures"]);
  const expected = { operationRows: rows.length, circuitEvaluations: rows.filter(row => origin(row.operation) === "circuit").length, adapterOperations: rows.filter(row => origin(row.operation) === "adapter").length, featureEmissions: emissions, distinctFeatures: features.length };
  for (const key of Object.keys(expected) as (keyof typeof expected)[]) if (integer(count[key], PERSISTENT_FEEDBACK_LIMITS.maxFeatureEmissions) !== expected[key]) return invalid("Feedback count mismatch");
  const result: PersistentFeedback = { schemaVersion: "nightshade-persistent-feedback-1", featureSet: PERSISTENT_FEATURE_SET, coverageKind: PERSISTENT_FEEDBACK_COVERAGE, fixture: "owned-persistent-counter-witness", sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: hash(raw.compiledJavaScriptSha256), runtimeLockSha256: PERSISTENT_LOCK_SHA256, sequenceSha256: hash(raw.sequenceSha256), operationsSha256: hash(raw.operationsSha256), observationSha256: hash(raw.observationSha256), initialFeatureIds, rows, features, counts: expected };
  if (Buffer.byteLength(JSON.stringify(result)) > PERSISTENT_FEEDBACK_LIMITS.maxBytes) return budget("Feedback byte allowance exhausted");
  return result;
}

/** Hash canonical, strictly decoded feedback, not arbitrary caller JSON. */
export function persistentFeedbackDigest(feedback: unknown): string { return persistentDigest(JSON.stringify(decodeFeedback(feedback))); }

const sameSnapshot = (left: PersistentSnapshot, right: PersistentSnapshot): boolean => left.count === right.count && left.next === right.next && left.publicSha256 === right.publicSha256;
const compare = (left: string, right: string): Comparison => BigInt(left) < BigInt(right) ? "less" : BigInt(left) > BigInt(right) ? "greater" : "equal";
const delta = (before: string, after: string): Delta => {
  const value = BigInt(after) - BigInt(before);
  return value < -1n ? "negative-many" : value === -1n ? "negative-one" : value === 0n ? "zero" : value === 1n ? "positive-one" : "positive-many";
};
const countClass = (value: bigint): Count => value < 0n ? invalid("Negative qualified count bucket") : value === 0n ? "zero" : value === 1n ? "one" : "many";
function incomplete(error: unknown): Extract<PersistentFeedbackOutcome, { status: "incomplete" }> {
  if (error instanceof FeedbackError) return { status: "incomplete", diagnostic: error.diagnostic, message: error.message.slice(0, 4000) };
  if (error && typeof error === "object") {
    const code = Object.getOwnPropertyDescriptor(error, "code"), message = Object.getOwnPropertyDescriptor(error, "message");
    if (code && "value" in code && typeof code.value === "string" && PERSISTENT_FEEDBACK_DIAGNOSTICS.includes(code.value as PersistentFeedbackDiagnostic)
      && message && "value" in message && typeof message.value === "string") return { status: "incomplete", diagnostic: code.value as PersistentFeedbackDiagnostic, message: message.value.slice(0, 4000) || "Incomplete persistent evidence" };
  }
  return { status: "incomplete", diagnostic: "persistent-feedback-protocol", message: "Invalid persistent sequence, result or feedback evidence" };
}

export function extractPersistentFeedback(sequence: unknown, result: unknown): PersistentFeedbackOutcome {
  try {
    const model = validatePersistentSequence(sequence);
    const checked = validatePersistentResult(model, result);
    if (checked.status === "incomplete") return { status: "incomplete", diagnostic: choose(checked.diagnostic, PERSISTENT_FEEDBACK_DIAGNOSTICS), message: checked.message };
    const observed = checked.observation;
    const observationSha256 = persistentDigest(JSON.stringify(observed));
    if (checked.status === "failed") return { status: "property-failed", diagnostic: "persistent-model-disagreement", signature: checked.signature, observationSha256 };
    const features = new Map<string, PersistentFeatureDescriptor>();
    const add = (tuple: PersistentFeatureDescriptor): string => {
      const bounded = descriptor(tuple), id = featureId(bounded), previous = features.get(id);
      if (previous && JSON.stringify(previous) !== JSON.stringify(bounded)) return invalid("Distinct feature descriptors share a digest");
      if (!previous && features.size === PERSISTENT_FEEDBACK_LIMITS.maxFeatures) return budget("Distinct feature allowance exhausted");
      features.set(id, bounded); return id;
    };
    const initialFeatureIds = [add(["initial", countClass(BigInt(observed.initial.count))])];
    const savedSlots = new Set<number>();
    let previousWitness: { row: PersistentRow; value: string } | undefined;
    let restoredSinceWitness = false;
    const rows = observed.rows.map((row, index): PersistentFeedback["rows"][number] => {
      const previous = observed.rows[index - 1];
      const previousSlots = previous?.slots;
      const tuples: PersistentFeatureDescriptor[] = [
        ["operation-outcome", origin(row.operation), row.operation, row.outcome],
        ["snapshot-transition", origin(row.operation), row.operation, delta(row.before.count, row.after.count), delta(row.before.next, row.after.next), row.before.publicSha256 === row.after.publicSha256],
        ["post-state", row.operation, countClass(BigInt(row.after.count)), countClass(BigInt(row.after.next) - BigInt(observed.initial.next)), sameSnapshot(row.after, observed.initial)],
      ];
      if (previous) tuples.push(["schedule-adjacency", previous.operation, previous.outcome, row.operation, row.outcome, sameSnapshot(previous.after, row.before)]);
      const distinctSlots = new Set(row.slots.map(slot => JSON.stringify([slot.count, slot.next, slot.publicSha256]))).size;
      tuples.push(["slot-shape", row.operation, distinctSlots, row.slots.filter(slot => sameSnapshot(slot, row.after)).length]);
      if (row.outcome === "evaluation-rejection") tuples.push(["rejection", "owned-persistent-assertion", sameSnapshot(row.before, row.after), row.witnesses.length]);
      if (row.operation === "save") {
        const slot = row.slot!;
        tuples.push(["save", savedSlots.has(slot), previousSlots ? sameSnapshot(previousSlots[slot], row.before) : "unavailable", sameSnapshot(row.slots[slot], row.after), previousSlots ? row.slots.filter((value, index) => index !== slot && !sameSnapshot(value, previousSlots[index])).length : "unavailable"]);
        savedSlots.add(slot);
      }
      if (row.operation === "restore") {
        const slot = row.slot!;
        tuples.push(["restore", savedSlots.has(slot), previousSlots ? sameSnapshot(row.after, previousSlots[slot]) : "unavailable", compare(row.after.count, row.before.count), compare(row.after.next, row.before.next), row.before.publicSha256 === row.after.publicSha256, sameSnapshot(row.after, observed.initial)]);
        restoredSinceWitness = true;
      }
      if (row.witnesses.length) {
        // Existing successful qualification admits exactly one witness here.
        if (row.witnesses.length !== 1) return invalid("Unexpected qualified witness cardinality");
        const value = row.witnesses[0];
        tuples.push(["witness", row.operation, row.outcome, compare(value, row.before.next), row.result === null ? "absent" : compare(row.result, value)]);
        if (previousWitness) tuples.push(["witness-history", previousWitness.row.operation, previousWitness.row.outcome, row.operation, row.outcome, compare(value, previousWitness.value), restoredSinceWitness, sameSnapshot(previousWitness.row.after, row.before)]);
        previousWitness = { row, value }; restoredSinceWitness = false;
      }
      return { index: row.index, operation: row.operation, slot: row.slot, featureIds: [...new Set(tuples.map(add))].sort() };
    });
    const feedback: PersistentFeedback = { schemaVersion: "nightshade-persistent-feedback-1", featureSet: PERSISTENT_FEATURE_SET, coverageKind: PERSISTENT_FEEDBACK_COVERAGE, fixture: "owned-persistent-counter-witness", sourceSha256: observed.sourceSha256, compiledJavaScriptSha256: observed.compiledJavaScriptSha256, runtimeLockSha256: observed.runtimeLockSha256, sequenceSha256: observed.sequenceSha256, operationsSha256: persistentDigest(JSON.stringify(model.operations)), observationSha256, initialFeatureIds, rows, features: [...features].sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0).map(([id, descriptor]) => ({ id, descriptor })), counts: { operationRows: rows.length, circuitEvaluations: rows.filter(row => origin(row.operation) === "circuit").length, adapterOperations: rows.filter(row => origin(row.operation) === "adapter").length, featureEmissions: 1 + rows.reduce((sum, row) => sum + row.featureIds.length, 0), distinctFeatures: features.size } };
    return { status: "complete", feedback: decodeFeedback(feedback) };
  } catch (error) { return incomplete(error); }
}

/** Saved novelty is accepted only when regenerated from the original evidence. */
export function validatePersistentFeedback(sequence: unknown, result: unknown, stored: unknown): PersistentFeedbackOutcome {
  const expected = extractPersistentFeedback(sequence, result);
  if (expected.status !== "complete") return expected;
  try {
    const actual = decodeFeedback(stored);
    if (JSON.stringify(actual) !== JSON.stringify(expected.feedback)) return invalid("Stored feedback differs from measured evidence");
    return expected;
  } catch (error) { return incomplete(error); }
}
