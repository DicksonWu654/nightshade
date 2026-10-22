import assert from "node:assert/strict";
import test from "node:test";
import { checkPersistentObservation, expectedPersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_REJECTION, PERSISTENT_SOURCE_SHA256, persistentDigest, validatePersistentSequence, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";
import { comparePersistentResults, incompletePersistentResult, runPersistentSequenceIsolated, type PersistentResult } from "./generative/persistent-artifacts.js";
import { extractPersistentFeedback, persistentFeedbackDigest, PERSISTENT_FEEDBACK_LIMITS, validatePersistentFeedback, type PersistentFeedback, type PersistentFeatureDescriptor } from "./generative/persistent-feedback.js";

const sequence = (operations: PersistentOperation[], seed = 1): PersistentSequence => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed, operations });
const lifecycle = sequence([
  { kind: "restore", slot: 3 }, { kind: "accept" }, { kind: "reject" }, { kind: "accept" },
  { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "save", slot: 1 },
  { kind: "restore", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 3 },
  { kind: "restore", slot: 1 }, { kind: "restore", slot: 1 }, { kind: "save", slot: 0 },
  { kind: "inspect" },
]);

/** Synthetic schema-only evidence, not an assertion that compiled code ran. */
function synthetic(input: PersistentSequence, salt = "schema-only") {
  const expected = expectedPersistentSequence(input);
  const view = (state: { count: string; next: string }) => ({ ...state, publicSha256: persistentDigest(`${salt}:${state.count}`) });
  const wire: PersistentObservation = { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(input)), initial: view(expected.initial), rows: expected.rows.map(row => ({ ...row, before: view(row.before), after: view(row.after), slots: row.slots.map(view) })), final: view(expected.final) };
  return { wire, result: checkPersistentObservation(input, wire, PERSISTENT_SOURCE_SHA256) };
}
function complete(input: PersistentSequence, result: unknown): PersistentFeedback {
  const extracted = extractPersistentFeedback(input, result);
  assert.equal(extracted.status, "complete", JSON.stringify(extracted));
  if (extracted.status !== "complete") throw new Error("Expected complete feedback");
  return extracted.feedback;
}
const id = (tuple: PersistentFeatureDescriptor) => persistentDigest(JSON.stringify(tuple));
const tuples = (feedback: PersistentFeedback, index: number): PersistentFeatureDescriptor[] => feedback.rows[index].featureIds.map(value => feedback.features.find(feature => feature.id === value)!.descriptor);
const has = (feedback: PersistentFeedback, index: number, tuple: PersistentFeatureDescriptor) => assert.ok(feedback.rows[index].featureIds.includes(id(tuple)), `Missing literal row ${index} tuple ${JSON.stringify(tuple)}`);

test("constructor-only measured feedback has one canonical feature and zero operation coverage", () => {
  const input = sequence([]), result = synthetic(input).result;
  const observed = complete(input, result);
  assert.deepEqual(observed.features, [{ id: id(["initial", "zero"]), descriptor: ["initial", "zero"] }]);
  assert.deepEqual(observed.initialFeatureIds, [id(["initial", "zero"])]);
  assert.deepEqual(observed.rows, []);
  assert.deepEqual(observed.counts, { operationRows: 0, circuitEvaluations: 0, adapterOperations: 0, featureEmissions: 1, distinctFeatures: 1 });
  assert.equal(observed.coverageKind, "observed-persistent-snapshot-transitions");
  assert.equal(observed.operationsSha256, persistentDigest("[]"));
  assert.equal(persistentFeedbackDigest(observed), persistentDigest(JSON.stringify(observed)));
  assert.deepEqual(validatePersistentFeedback(input, result, JSON.parse(JSON.stringify(observed))), { status: "complete", feedback: observed });
});

test("first operation has measured before/after but no fabricated prior slots, witness or adjacency", () => {
  const input = sequence([{ kind: "restore", slot: 3 }]);
  const observed = complete(input, synthetic(input).result);
  const expected: PersistentFeatureDescriptor[] = [
    ["operation-outcome", "adapter", "restore", "restored"],
    ["snapshot-transition", "adapter", "restore", "zero", "zero", true],
    ["post-state", "restore", "zero", "zero", true],
    ["slot-shape", "restore", 1, 4],
    ["restore", false, "unavailable", "equal", "equal", true, true],
  ];
  assert.deepEqual(observed.rows, [{ index: 0, operation: "restore", slot: 3, featureIds: expected.map(id).sort() }]);
  assert.deepEqual(observed.features, [["initial", "zero"] as PersistentFeatureDescriptor, ...expected].map(descriptor => ({ id: id(descriptor), descriptor })).sort((a, b) => a.id < b.id ? -1 : 1));
  assert.deepEqual(observed.counts, { operationRows: 1, circuitEvaluations: 0, adapterOperations: 1, featureEmissions: 6, distinctFeatures: 6 });
  const save = sequence([{ kind: "save", slot: 2 }]);
  has(complete(save, synthetic(save).result), 0, ["save", false, "unavailable", true, "unavailable"]);
  const accept = sequence([{ kind: "accept" }]);
  const firstWitness = complete(accept, synthetic(accept).result);
  assert.ok(!tuples(firstWitness, 0).some(tuple => tuple[0] === "witness-history" || tuple[0] === "schedule-adjacency"));
});

function checkLiteralLifecycle(observed: PersistentFeedback): void {
  assert.equal(observed.rows.length, 14);
  assert.equal(observed.counts.operationRows, 14);
  assert.equal(observed.counts.circuitEvaluations, 6);
  assert.equal(observed.counts.adapterOperations, 8);
  has(observed, 0, ["restore", false, "unavailable", "equal", "equal", true, true]);
  has(observed, 1, ["snapshot-transition", "circuit", "accept", "positive-one", "positive-one", false]);
  has(observed, 1, ["witness", "accept", "evaluation-success", "equal", "equal"]);
  has(observed, 2, ["rejection", "owned-persistent-assertion", true, 1]);
  has(observed, 2, ["witness", "reject", "evaluation-rejection", "equal", "absent"]);
  has(observed, 2, ["witness-history", "accept", "evaluation-success", "reject", "evaluation-rejection", "greater", false, true]);
  has(observed, 3, ["witness-history", "reject", "evaluation-rejection", "accept", "evaluation-success", "equal", false, true]);
  has(observed, 4, ["save", false, false, true, 0]);
  has(observed, 6, ["slot-shape", "save", 3, 1]);
  has(observed, 7, ["restore", true, true, "less", "less", false, false]);
  has(observed, 8, ["witness-history", "accept", "evaluation-success", "accept", "evaluation-success", "equal", true, false]);
  has(observed, 9, ["restore", false, true, "less", "less", false, true]);
  has(observed, 10, ["restore", true, true, "greater", "greater", false, false]);
  has(observed, 11, ["restore", true, true, "equal", "equal", true, false]);
  has(observed, 12, ["save", true, false, true, 0]);
  assert.ok(!tuples(observed, 13).some(tuple => tuple[0] === "witness" || tuple[0] === "witness-history"));
  assert.ok(observed.rows.every(row => row.featureIds.length <= PERSISTENT_FEEDBACK_LIMITS.maxRowFeatures));
  assert.equal(observed.counts.featureEmissions, 1 + observed.rows.reduce((sum, row) => sum + row.featureIds.length, 0));
  for (const feature of observed.features) assert.equal(feature.id, id(feature.descriptor));
}

test("literal lifecycle categories distinguish rejection, reused witnesses and backward/forward saved histories", () => {
  checkLiteralLifecycle(complete(lifecycle, synthetic(lifecycle).result));
});

test("seed, raw snapshot hashes and global injective slot renaming do not manufacture novelty", () => {
  const original = complete(lifecycle, synthetic(lifecycle).result);
  const seeded = sequence(lifecycle.operations, 42), reseeded = complete(seeded, synthetic(seeded).result);
  assert.deepEqual(reseeded.features, original.features);
  assert.equal(reseeded.operationsSha256, original.operationsSha256);
  assert.notEqual(reseeded.sequenceSha256, original.sequenceSha256);
  const changedHashes = complete(lifecycle, synthetic(lifecycle, "different-synthetic-bytes").result);
  assert.deepEqual(changedHashes.features, original.features);
  assert.notEqual(changedHashes.observationSha256, original.observationSha256);
  const renamed = sequence(lifecycle.operations.map(op => "slot" in op ? { ...op, slot: [2, 3, 0, 1][op.slot] } : op));
  const renamedFeedback = complete(renamed, synthetic(renamed).result);
  assert.deepEqual(renamedFeedback.features, original.features);
  assert.deepEqual(renamedFeedback.rows.map(row => row.featureIds), original.rows.map(row => row.featureIds));
  assert.notEqual(renamedFeedback.operationsSha256, original.operationsSha256);
  assert.notDeepEqual(renamedFeedback.rows.map(row => row.slot), original.rows.map(row => row.slot));
  const differentHistory = sequence([{ kind: "accept" }, { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 1 }]);
  const savedHistory = sequence([{ kind: "accept" }, { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "restore", slot: 0 }]);
  assert.notDeepEqual(complete(differentHistory, synthetic(differentHistory).result).features, complete(savedHistory, synthetic(savedHistory).result).features);
});

test("feedback is detached and strict regeneration rejects forged fields, associations and digests", () => {
  const input = structuredClone(lifecycle), checked = synthetic(input).result;
  const observed = complete(input, checked), frozen = structuredClone(observed);
  input.operations.length = 0;
  if (checked.status !== "incomplete") checked.observation.rows.length = 0;
  assert.deepEqual(observed, frozen);
  const result = synthetic(lifecycle).result;
  const mutate: ((value: any) => void)[] = [
    value => { value.extra = true; }, value => { delete value.rows; },
    value => { value.coverageKind = "executed-edges"; }, value => { value.featureSet = "unknown"; },
    value => { value.sourceSha256 = "b".repeat(64); }, value => { value.runtimeLockSha256 = "b".repeat(64); },
    value => { value.sequenceSha256 = "b".repeat(64); }, value => { value.observationSha256 = "b".repeat(64); },
    value => { value.compiledJavaScriptSha256 = "b".repeat(64); },
    value => { value.rows[0].index = 1; }, value => { value.rows[0].slot = -0; },
    value => { value.rows[0].slot = 2; },
    value => { [value.rows[7].featureIds, value.rows[11].featureIds] = [value.rows[11].featureIds, value.rows[7].featureIds]; },
    value => { value.rows[0].featureIds.reverse(); }, value => { value.rows[0].featureIds.push(value.rows[0].featureIds[0]); },
    value => { value.features[0].descriptor = ["invented"]; }, value => { value.features[0].id = "b".repeat(64); },
    value => { value.counts.circuitEvaluations++; }, value => { value.counts.operationRows = NaN; },
    value => { value.features.push({ ...value.features[0] }); }, value => { value.rows = Array(2); },
    value => { value.features[0].descriptor.extra = 1; }, value => { value.rows[0].featureIds.extra = 1; },
    value => { Object.defineProperty(value.counts, "operationRows", { value: 14, enumerable: false }); },
    value => { value.rows[0][Symbol("hidden")] = true; },
  ];
  for (const change of mutate) {
    const changed = structuredClone(frozen); change(changed);
    assert.equal(validatePersistentFeedback(lifecycle, result, changed).status, "incomplete");
  }
  const reordered = Object.fromEntries(Object.entries(frozen).reverse());
  assert.deepEqual(validatePersistentFeedback(lifecycle, result, reordered), { status: "complete", feedback: frozen });
  assert.equal(persistentFeedbackDigest(reordered), persistentFeedbackDigest(frozen));
  const copied = validatePersistentFeedback(lifecycle, result, frozen);
  assert.equal(copied.status, "complete");
  if (copied.status === "complete") { copied.feedback.rows.length = 0; assert.equal(frozen.rows.length, 14); }
});

test("getters never run; malformed or exhausted representations produce explicit incomplete feedback", () => {
  const result = synthetic(lifecycle).result, observed = complete(lifecycle, result);
  let getterCalls = 0;
  for (const target of ["top", "row", "tuple", "ids", "counts"] as const) {
    const value = structuredClone(observed);
    const pair: [object, PropertyKey] = target === "top" ? [value, "rows"] : target === "row" ? [value.rows[0], "operation"] : target === "tuple" ? [value.features[0].descriptor, "0"] : target === "ids" ? [value.rows[0].featureIds, "0"] : [value.counts, "featureEmissions"];
    Object.defineProperty(pair[0], pair[1], { enumerable: true, get() { getterCalls++; return "forged"; } });
    assert.equal(validatePersistentFeedback(lifecycle, result, value).status, "incomplete");
    assert.throws(() => persistentFeedbackDigest(value));
  }
  const badSequence = structuredClone(lifecycle);
  Object.defineProperty(badSequence, "operations", { enumerable: true, get() { getterCalls++; return []; } });
  assert.equal(extractPersistentFeedback(badSequence, result).status, "incomplete");
  const badResult = structuredClone(result);
  Object.defineProperty(badResult, "observation", { enumerable: true, get() { getterCalls++; return {}; } });
  assert.equal(extractPersistentFeedback(lifecycle, badResult).status, "incomplete");
  assert.equal(getterCalls, 0);
  for (const change of [(value: any) => { value.rows = Array(33).fill(value.rows[0]); }, (value: any) => { value.features = Array(258).fill(value.features[0]); }, (value: any) => { value.rows[0].featureIds = Array(9).fill(value.rows[0].featureIds[0]); }]) {
    const changed = structuredClone(observed); change(changed);
    const checked = validatePersistentFeedback(lifecycle, result, changed);
    assert.equal(checked.status, "incomplete");
    if (checked.status === "incomplete") assert.equal(checked.diagnostic, "persistent-feedback-budget");
  }
  const oversized = extractPersistentFeedback({ ...lifecycle, operations: Array(33).fill({ kind: "accept" }) }, result);
  assert.equal(oversized.status, "incomplete");
  if (oversized.status === "incomplete") assert.equal(oversized.diagnostic, "persistent-sequence-budget");
});

test("qualification failures and incomplete runtime outcomes earn no novelty, including predicted-only cases", () => {
  for (const change of [
    (wire: PersistentObservation) => { wire.rows[1].witnesses = ["99"]; },
    (wire: PersistentObservation) => { wire.rows[2].after.next = "99"; },
    (wire: PersistentObservation) => { wire.rows[4].slots[0].count = "99"; },
    (wire: PersistentObservation) => { wire.rows[7].after.publicSha256 = "b".repeat(64); },
    (wire: PersistentObservation) => { wire.rows[1].index = 0; },
  ]) {
    const wire = synthetic(lifecycle).wire; change(wire);
    const result = checkPersistentObservation(lifecycle, wire, PERSISTENT_SOURCE_SHA256);
    assert.equal(result.status, "failed");
    const feedback = extractPersistentFeedback(lifecycle, result);
    assert.deepEqual(feedback, { status: "property-failed", diagnostic: "persistent-model-disagreement", signature: result.signature, observationSha256: persistentDigest(JSON.stringify(result.observation)) });
    assert.equal("feedback" in feedback, false);
  }
  const wrongError = synthetic(lifecycle).wire;
  wrongError.rows[2].error = { name: "Error", message: PERSISTENT_REJECTION } as never;
  const unqualified = extractPersistentFeedback(lifecycle, checkPersistentObservation(lifecycle, wrongError, PERSISTENT_SOURCE_SHA256));
  assert.equal(unqualified.status, "incomplete");
  if (unqualified.status === "incomplete") assert.equal(unqualified.diagnostic, "persistent-unqualified-rejection");
  for (const diagnostic of ["worker-timeout", "worker-output-budget", "worker-interrupted", "persistent-observation-budget"]) {
    const outcome = extractPersistentFeedback(lifecycle, incompletePersistentResult(diagnostic, "Explicitly synthetic incomplete test"));
    assert.equal(outcome.status, "incomplete");
    if (outcome.status === "incomplete") assert.equal(outcome.diagnostic, diagnostic);
    assert.equal("feedback" in outcome, false);
  }
  assert.equal(extractPersistentFeedback(lifecycle, expectedPersistentSequence(lifecycle)).status, "incomplete");
  assert.equal(extractPersistentFeedback(lifecycle, { status: "passed", diagnostic: "persistent-model-checked", signature: "persistent-model-checked" }).status, "incomplete");
  const forged = synthetic(lifecycle).result;
  if (forged.status !== "incomplete") forged.observation.rows[1].result = "99";
  assert.equal(extractPersistentFeedback(lifecycle, forged).status, "incomplete", "Saved passed label cannot conceal changed evidence");
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() {
  assert.ok(process.env.COMPACT_RUNTIME_TEST);
  assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST requires pinned COMPACTC_TEST");
  return { compiler: process.env.COMPACTC_TEST, runtime: process.env.COMPACT_RUNTIME_TEST };
}
async function measured(input: PersistentSequence): Promise<PersistentResult> {
  const { compiler, runtime } = inputs();
  const result = await runPersistentSequenceIsolated(input, compiler, runtime);
  assert.equal(result.status, "passed", JSON.stringify(result));
  return result;
}

test("compiled fixed lifecycle yields literal measured categories and exact replay feedback", qualified, async () => {
  const first = await measured(lifecycle), second = await measured(lifecycle);
  const feedback = complete(lifecycle, first);
  checkLiteralLifecycle(feedback);
  assert.deepEqual(complete(lifecycle, second), feedback);
  const comparison = comparePersistentResults(first, second);
  assert.equal(comparison.sameObservation, true);
  assert.equal(comparison.sameCompiledJavaScript, true);
  assert.deepEqual(validatePersistentFeedback(lifecycle, second, feedback), { status: "complete", feedback });
  if (first.status === "passed") {
    assert.deepEqual(first.observation.rows.flatMap(row => row.witnesses), ["7", "8", "8", "9", "9"]);
    const corrupt = structuredClone(first.observation); corrupt.rows[7].after.next = "99";
    assert.equal(extractPersistentFeedback(lifecycle, checkPersistentObservation(lifecycle, corrupt, PERSISTENT_SOURCE_SHA256)).status, "property-failed", "Deliberately corrupted measured evidence is a harness test, not a discovered runtime issue");
  }
});

test("compiled boundary schedules preserve constructor-only, rejection and maximum row distinctions", qualified, async () => {
  const empty = sequence([]), accepts = sequence(Array.from({ length: 32 }, () => ({ kind: "accept" }))), rejects = sequence(Array.from({ length: 32 }, () => ({ kind: "reject" }))), inspections = sequence([{ kind: "inspect" }, { kind: "inspect" }]);
  const none = complete(empty, await measured(empty));
  assert.deepEqual(none.counts, { operationRows: 0, circuitEvaluations: 0, adapterOperations: 0, featureEmissions: 1, distinctFeatures: 1 });
  const accepting = complete(accepts, await measured(accepts));
  assert.equal(accepting.rows.length, 32); assert.equal(accepting.counts.circuitEvaluations, 32);
  has(accepting, 31, ["post-state", "accept", "many", "many", false]);
  const rejecting = complete(rejects, await measured(rejects));
  assert.equal(rejecting.rows.length, 32); assert.equal(rejecting.counts.circuitEvaluations, 32);
  has(rejecting, 31, ["witness-history", "reject", "evaluation-rejection", "reject", "evaluation-rejection", "equal", false, true]);
  assert.equal(rejecting.counts.featureEmissions, 255);
  const inspecting = complete(inspections, await measured(inspections));
  assert.ok(inspecting.features.every(feature => !["witness", "witness-history", "rejection"].includes(feature.descriptor[0])));
});

test("[timing] a real supervised timeout is incomplete and cannot produce measured feedback", qualified, async () => {
  const { compiler, runtime } = inputs();
  const timed = await runPersistentSequenceIsolated(lifecycle, compiler, runtime, { ...PERSISTENT_LIMITS, timeoutMs: 1 });
  assert.equal(timed.status, "incomplete"); assert.equal(timed.diagnostic, "worker-timeout");
  const result = extractPersistentFeedback(lifecycle, timed);
  assert.equal(result.status, "incomplete");
  if (result.status === "incomplete") assert.equal(result.diagnostic, "worker-timeout");
  assert.equal("feedback" in result, false);
});
