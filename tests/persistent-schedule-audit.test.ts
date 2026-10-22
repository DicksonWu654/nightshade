import assert from "node:assert/strict";
import test from "node:test";
import { auditPersistentSchedule, foldPersistentSchedule, type PersistentScheduleTranscript } from "./generative/persistent-schedule-audit.js";
import { PersistentSchedule, type PersistentDecision, type PersistentScheduleOptions, type PersistentScheduleRow } from "./generative/persistent-schedule.js";
import { incompletePersistentResult, makePersistentArtifact, type PersistentIdentity, type PersistentResult } from "./generative/persistent-artifacts.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentSequence } from "./generative/persistent-model.js";

const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const options: PersistentScheduleOptions = { seed: 7, mutations: 8, maxEvaluations: 12 };
const jsonBytes = (value: unknown) => Buffer.from(JSON.stringify(value));

/** Synthetic schema-only evidence; no runtime execution or defect is claimed. */
function synthetic(sequence: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(sequence);
  const snapshot = (value: { count: string; next: string }) => ({ ...value, publicSha256: persistentDigest(`synthetic-public:${value.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000,
    runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(sequence)),
    initial: snapshot(expected.initial), rows: expected.rows.map(row => ({ ...row, before: snapshot(row.before), after: snapshot(row.after), slots: row.slots.map(snapshot) })), final: snapshot(expected.final) };
}
const result = (sequence: PersistentSequence, wire = synthetic(sequence)) => checkPersistentObservation(sequence, wire, PERSISTENT_SOURCE_SHA256);
const artifact = (decision: PersistentDecision, checked: PersistentResult = result(decision.sequence)) => jsonBytes(makePersistentArtifact(decision.sequence, identity, limits, checked));

/** Produce only original test bytes with the real scheduler; no duplicate scheduling or mutation rules. */
function originals(config: Partial<PersistentScheduleOptions> = {}, corpusBudgets = {}, stopAfter?: number) {
  const settings = { ...options, ...config }, schedule = new PersistentSchedule(identity, limits, settings, corpusBudgets);
  const artifacts: Buffer[] = [], decisions: PersistentDecision[] = [], rows: PersistentScheduleRow[] = [];
  while (stopAfter === undefined || artifacts.length < stopAfter) {
    const decision = schedule.next(); if (!decision) break;
    const bytes = artifact(decision); artifacts.push(bytes); decisions.push(decision); rows.push(schedule.record(bytes));
  }
  return { artifacts, decisions, rows, snapshot: schedule.snapshot(), settings };
}
function folded(config: Partial<PersistentScheduleOptions> = {}, corpusBudgets = {}) {
  const generated = originals(config, corpusBudgets);
  const rebuilt = foldPersistentSchedule(identity, limits, generated.settings, corpusBudgets, generated.artifacts);
  assert.deepEqual(rebuilt.transcript.decisions, generated.decisions);
  assert.deepEqual(rebuilt.transcript.rows, generated.rows);
  assert.deepEqual(rebuilt.transcript.snapshot, generated.snapshot);
  return { ...generated, ...rebuilt };
}
function rejectMutation(transcript: PersistentScheduleTranscript, artifacts: unknown, mutate: (value: any) => void) {
  const changed = structuredClone(transcript); mutate(changed);
  assert.throws(() => auditPersistentSchedule(changed, artifacts), /persistent-schedule-audit-protocol/);
}

test("complete schedule folds and finalized audits reconstruct every original byte association", () => {
  const { transcript, artifacts, decisions } = folded();
  assert.equal(transcript.snapshot.outcome.status, "passed"); assert.equal(transcript.snapshot.pending, null);
  assert.equal(transcript.decisions.length, 12); assert.equal(transcript.rows.length, 12);
  assert.deepEqual(Object.keys(transcript), ["schemaVersion", "identity", "workerLimits", "options", "corpusBudgets", "decisions", "rows", "stopReason", "snapshot"]);
  const audit = auditPersistentSchedule(transcript, artifacts);
  assert.equal(audit.scope, "offline-evidence-consistency-only"); assert.deepEqual(audit.transcript, transcript);
  for (const [index, row] of transcript.rows.entries()) {
    assert.deepEqual(row.artifact, { sha256: persistentDigest(artifacts[index]), bytes: artifacts[index].length });
    assert.equal(row.ordinal, index + 1); assert.equal(row.admission!.ordinal, index + 1);
    assert.equal(transcript.decisions[index].sequenceSha256, persistentDigest(JSON.stringify(decisions[index].sequence)));
  }
  audit.transcript.decisions[0].sequence.seed++; audit.transcript.snapshot.corpus.features.length = 0;
  assert.deepEqual(auditPersistentSchedule(transcript, artifacts).transcript, transcript, "Returned data must not become restoration authority");
});

test("null-prototype metadata is accepted and reconstructed as detached plain data", () => {
  const { transcript, artifacts } = folded({ mutations: 0, maxEvaluations: 4 });
  const saved = structuredClone(transcript);
  function clearRecordPrototypes(value: unknown): void {
    if (!value || typeof value !== "object") return;
    if (!Array.isArray(value)) Object.setPrototypeOf(value, null);
    for (const child of Object.values(value)) clearRecordPrototypes(child);
  }
  clearRecordPrototypes(saved);
  const rebuilt = auditPersistentSchedule(saved, artifacts);
  assert.deepEqual(rebuilt.transcript, transcript);
  assert.equal(Object.getPrototypeOf(saved), null); assert.equal(Object.getPrototypeOf(saved.identity), null);
  assert.equal(Object.getPrototypeOf(rebuilt.transcript), Object.prototype);
  assert.equal(Object.getPrototypeOf(rebuilt.transcript.identity), Object.prototype);
  rebuilt.transcript.identity.node = "v22.23.3";
  assert.equal(saved.identity.node, identity.node);
});

test("running prefixes remain composable but cannot pass finalized audit or hide a pending proposal", () => {
  const generated = originals({}, {}, 2);
  const prefix = foldPersistentSchedule(identity, limits, generated.settings, {}, generated.artifacts);
  assert.equal(prefix.transcript.snapshot.outcome.status, "running"); assert.equal(prefix.transcript.snapshot.pending, null);
  assert.throws(() => auditPersistentSchedule(prefix.transcript, generated.artifacts), /terminal/);
  const empty = foldPersistentSchedule(identity, limits, generated.settings, {}, []);
  assert.equal(empty.transcript.snapshot.recorded, 0); assert.throws(() => auditPersistentSchedule(empty.transcript, []), /terminal/);
  const complete = folded({ mutations: 0, maxEvaluations: 4 });
  rejectMutation(complete.transcript, complete.artifacts, transcript => { transcript.snapshot.pending = transcript.decisions[0]; });
  rejectMutation(complete.transcript, complete.artifacts, transcript => { transcript.snapshot.outcome = { status: "running", diagnostic: "running" }; });
});

test("closed external stops apply only between proposals on running prefixes", () => {
  const generated = originals({}, {}, 2);
  for (const reason of ["persistent-campaign-interrupted", "persistent-campaign-time-budget", "persistent-campaign-evidence-budget"]) {
    const stopped = foldPersistentSchedule(identity, limits, generated.settings, {}, generated.artifacts, reason);
    assert.deepEqual(stopped.transcript.snapshot.outcome, { status: "incomplete", diagnostic: reason });
    assert.equal(stopped.transcript.stopReason, reason); assert.equal(stopped.transcript.snapshot.pending, null);
    assert.deepEqual(auditPersistentSchedule(stopped.transcript, generated.artifacts), stopped);
    rejectMutation(stopped.transcript, generated.artifacts, transcript => { transcript.stopReason = null; });
    rejectMutation(stopped.transcript, generated.artifacts, transcript => { transcript.snapshot.outcome.diagnostic = "persistent-evaluation-budget"; });
  }
  const beforeAny = foldPersistentSchedule(identity, limits, generated.settings, {}, [], "persistent-campaign-interrupted");
  assert.equal(beforeAny.transcript.snapshot.proposed, 0); assert.equal(auditPersistentSchedule(beforeAny.transcript, []).transcript.rows.length, 0);
  for (const reason of [undefined, false, 1, {}, "worker-timeout", "persistent-corpus-budget", "running", ""]) {
    if (reason === undefined) continue; // Omitted optional parameter means null by contract.
    assert.throws(() => foldPersistentSchedule(identity, limits, generated.settings, {}, generated.artifacts, reason), /stop reason/);
  }
  const complete = folded({ mutations: 0, maxEvaluations: 4 });
  assert.throws(() => foldPersistentSchedule(identity, limits, complete.settings, {}, complete.artifacts, "persistent-campaign-interrupted"), /cannot replace/);
});

test("tampering bootstrap decisions, canonical hashes and RNG records cannot survive reconstruction", () => {
  const { transcript, artifacts } = folded();
  for (const mutate of [
    (value: any) => { value.schemaVersion = "nightshade-owned-persistent-guided-1"; },
    (value: any) => { value.decisions[0].schemaVersion = "invented"; },
    (value: any) => { value.decisions[0].scheduler = "owned-checkpoint-lcg-1"; },
    (value: any) => { value.decisions[0].ordinal = 2; },
    (value: any) => { value.decisions[0].phase = "mutation"; },
    (value: any) => { value.decisions[0].bootstrap = 2; },
    (value: any) => { value.decisions[0].sequence.seed++; },
    (value: any) => { value.decisions[0].sequence.operations.push({ kind: "accept" }); },
    (value: any) => { value.decisions[0].sequenceSha256 = "0".repeat(64); },
    (value: any) => { value.decisions[0].operationsSha256 = "0".repeat(64); },
    (value: any) => { value.decisions[0].random.before++; },
    (value: any) => { value.decisions[0].random.after++; },
    (value: any) => { value.decisions[0].random.words[3]++; },
    (value: any) => { value.decisions[0].random.words.push(0); },
    (value: any) => { value.decisions.reverse(); },
  ]) rejectMutation(transcript, artifacts, mutate);
});

test("tampering mutation operands or retained-parent provenance cannot promote an arbitrary parent", () => {
  const { transcript, artifacts } = folded();
  const index = transcript.decisions.findIndex(decision => decision.phase === "mutation"); assert.ok(index >= 4);
  assert.ok(transcript.decisions[index].parent); assert.ok(transcript.decisions[index].mutation);
  for (const mutate of [
    (value: any) => { value.decisions[index].mutation.index++; },
    (value: any) => { value.decisions[index].mutation = { kind: "insert", index: 99, operation: { kind: "accept" } }; },
    (value: any) => { value.decisions[index].parent = null; },
    (value: any) => { value.decisions[index].parent.retainedIndex++; },
    (value: any) => { value.decisions[index].parent.ordinal++; },
    (value: any) => { value.decisions[index].parent.artifactSha256 = "0".repeat(64); },
    (value: any) => { value.decisions[index].parent.sequenceSha256 = "0".repeat(64); },
    (value: any) => { value.decisions[index].parent.operationsSha256 = "0".repeat(64); },
    (value: any) => { value.decisions[index].bootstrap = 1; },
  ]) rejectMutation(transcript, artifacts, mutate);
  for (const [operandIndex, decision] of transcript.decisions.entries()) {
    const mutation = decision.mutation;
    if (mutation?.kind === "insert" || mutation?.kind === "replace") {
      rejectMutation(transcript, artifacts, value => {
        value.decisions[operandIndex].mutation.operation = mutation.operation.kind === "accept" ? { kind: "reject" } : { kind: "accept" };
      });
    } else if (mutation?.kind === "slot-edit") {
      rejectMutation(transcript, artifacts, value => { value.decisions[operandIndex].mutation.before = (mutation.before + 1) % 4; });
      rejectMutation(transcript, artifacts, value => { value.decisions[operandIndex].mutation.after = (mutation.after + 1) % 4; });
    }
  }
});

test("every row, summary count, corpus decision and feature union comes from original evidence", () => {
  const { transcript, artifacts } = folded();
  for (const mutate of [
    (value: any) => { value.rows[0].status = "failed"; },
    (value: any) => { value.rows[0].diagnostic = "persistent-model-disagreement"; },
    (value: any) => { value.rows[0].artifact.sha256 = "0".repeat(64); },
    (value: any) => { value.rows[0].artifact.bytes++; },
    (value: any) => { value.rows[0].caseStatus = null; },
    (value: any) => { value.rows[0].signature = "invented"; },
    (value: any) => { value.rows[0].admission = null; },
    (value: any) => { value.rows[0].admission.admittedFeatureIds = []; },
    (value: any) => { value.rows[0].admission.feedbackSha256 = "f".repeat(64); },
    (value: any) => { value.snapshot.counts.passed--; },
    (value: any) => { value.snapshot.recorded--; },
    (value: any) => { value.snapshot.proposed++; },
    (value: any) => { value.snapshot.planned++; },
    (value: any) => { value.snapshot.rows[0].signature = "different"; },
    (value: any) => { value.snapshot.corpus.entries[0].ordinal = 2; },
    (value: any) => { value.snapshot.corpus.entries[0].artifactSha256 = "0".repeat(64); },
    (value: any) => { value.snapshot.corpus.entries[0].sequence.seed++; },
    (value: any) => { value.snapshot.corpus.features[0].descriptor[0] = "execution-edge"; },
    (value: any) => { value.snapshot.corpus.features = []; },
    (value: any) => { value.snapshot.corpus.evidenceBytes++; },
    (value: any) => { value.snapshot.corpus.compiledJavaScriptSha256 = "0".repeat(64); },
  ]) rejectMutation(transcript, artifacts, mutate);
});

test("changed, reordered, truncated or appended original bytes cannot authenticate a saved transcript", () => {
  const { transcript, artifacts } = folded({ mutations: 0, maxEvaluations: 4 });
  assert.throws(() => auditPersistentSchedule(transcript, artifacts.slice(0, -1)), /terminal|differs/);
  assert.throws(() => auditPersistentSchedule(transcript, [...artifacts, artifacts[0]]), /Trailing|differs/);
  assert.throws(() => auditPersistentSchedule(transcript, [artifacts[1], artifacts[0], ...artifacts.slice(2)]), /Trailing|differs/);
  const formatted = [Buffer.from(JSON.stringify(JSON.parse(artifacts[0].toString()), null, 2)), ...artifacts.slice(1)];
  assert.throws(() => auditPersistentSchedule(transcript, formatted), /differs/);
  const damaged = [Buffer.from("{"), ...artifacts.slice(1)];
  assert.throws(() => auditPersistentSchedule(transcript, damaged), /Trailing|differs/);
  const last = JSON.parse(artifacts.at(-1)!.toString()); last.result.signature = "forged";
  assert.throws(() => auditPersistentSchedule(transcript, [...artifacts.slice(0, -1), jsonBytes(last)]), /differs/);
});

test("wrong proposal association fails before corpus admission and remains an auditable terminal row", () => {
  const schedule = new PersistentSchedule(identity, limits, options), first = schedule.next()!;
  const different = { ...first, sequence: { ...first.sequence, seed: 99 } };
  const original = artifact(different);
  const rebuilt = foldPersistentSchedule(identity, limits, options, {}, [original]);
  const row = rebuilt.transcript.rows[0];
  assert.equal(row.status, "incomplete"); assert.equal(row.diagnostic, "persistent-schedule-protocol");
  assert.equal(row.admission, null); assert.equal(row.caseStatus, null); assert.equal(row.signature, null);
  assert.deepEqual(row.artifact, { sha256: persistentDigest(original), bytes: original.length });
  assert.equal(rebuilt.transcript.snapshot.corpus.considered, 0); assert.deepEqual(rebuilt.transcript.snapshot.corpus.features, []);
  assert.deepEqual(auditPersistentSchedule(rebuilt.transcript, [original]), rebuilt);
  assert.throws(() => foldPersistentSchedule(identity, limits, options, {}, [original, original]), /Trailing/);
  assert.throws(() => foldPersistentSchedule(identity, limits, options, {}, [original], "persistent-campaign-time-budget"), /cannot replace/);
});

test("schedule-level malformed and oversized refusal is reconstructed without pretending corpus consideration", () => {
  for (const original of [Buffer.from("{"), new Uint8Array([0xff]), new Uint8Array(1048577)]) {
    const rebuilt = foldPersistentSchedule(identity, limits, options, {}, [original]);
    const row = rebuilt.transcript.rows[0]; assert.equal(row.status, "incomplete"); assert.equal(row.admission, null);
    assert.equal(row.diagnostic, original.length > 1048576 ? "persistent-schedule-input-budget" : "persistent-schedule-protocol");
    assert.equal(row.artifact === null, original.length > 1048576);
    assert.equal(rebuilt.transcript.snapshot.corpus.considered, 0); assert.equal(rebuilt.transcript.snapshot.corpus.evidenceBytes, 0);
    assert.deepEqual(auditPersistentSchedule(rebuilt.transcript, [original]), rebuilt);
  }
});

test("corpus feature/case/consideration/evidence terminals retain their final original trigger", () => {
  const generated = originals({ mutations: 0, maxEvaluations: 4 });
  const cases = [
    { budgets: { maxCases: 1 }, diagnostic: "persistent-corpus-budget", captured: true },
    { budgets: { maxFeatures: 1 }, diagnostic: "persistent-corpus-budget", captured: true },
    { budgets: { maxConsiderations: 1 }, diagnostic: "persistent-corpus-consideration-budget", captured: false },
    { budgets: { maxEvidenceBytes: generated.artifacts[0].length }, diagnostic: "persistent-corpus-evidence-budget", captured: false },
  ];
  for (const { budgets, diagnostic, captured } of cases) {
    const originals = generated.artifacts.slice(0, 2), rebuilt = foldPersistentSchedule(identity, limits, generated.settings, budgets, originals);
    const final = rebuilt.transcript.rows[1]; assert.equal(final.status, "incomplete"); assert.equal(final.diagnostic, diagnostic);
    assert.deepEqual(final.artifact, { sha256: persistentDigest(originals[1]), bytes: originals[1].length });
    assert.equal(final.admission!.artifact !== null, captured); assert.equal(final.admission!.ordinal !== null, captured);
    assert.equal(rebuilt.transcript.snapshot.corpus.entries.length, 1);
    assert.deepEqual(auditPersistentSchedule(rebuilt.transcript, originals), rebuilt);
    assert.throws(() => auditPersistentSchedule(rebuilt.transcript, originals.slice(0, 1)), /terminal|differs/);
    assert.throws(() => foldPersistentSchedule(identity, limits, generated.settings, budgets, [...originals, generated.artifacts[2]]), /Trailing/);
  }
});

test("evaluation ceilings and final property failures cannot become successful prefixes", () => {
  const limited = folded({ mutations: 0, maxEvaluations: 3 });
  assert.deepEqual(limited.transcript.snapshot.outcome, { status: "incomplete", diagnostic: "persistent-evaluation-budget" });
  assert.equal(auditPersistentSchedule(limited.transcript, limited.artifacts).transcript.rows.length, 3);
  const complete = folded({ mutations: 0, maxEvaluations: 4 });
  assert.equal(complete.transcript.snapshot.outcome.status, "passed");
  const finalDecision = complete.decisions[3], wire = synthetic(finalDecision.sequence);
  wire.rows[0].after.next = "999"; // Deliberate schema-only property failure, not a discovered runtime defect.
  const failed = result(finalDecision.sequence, wire); assert.equal(failed.status, "failed");
  for (const lastResult of [failed, incompletePersistentResult("worker-timeout", "Synthetic supervised timeout evidence")]) {
    const originals = [...complete.artifacts.slice(0, 3), artifact(finalDecision, lastResult)];
    const rebuilt = foldPersistentSchedule(identity, limits, complete.settings, {}, originals);
    assert.equal(rebuilt.transcript.snapshot.outcome.status, lastResult.status);
    assert.equal(rebuilt.transcript.rows[3].signature, lastResult.signature);
    assert.equal(rebuilt.transcript.rows[3].caseStatus, lastResult.status);
    assert.equal(rebuilt.transcript.snapshot.corpus.entries.length, 3);
    assert.deepEqual(auditPersistentSchedule(rebuilt.transcript, originals), rebuilt);
    assert.throws(() => foldPersistentSchedule(identity, limits, complete.settings, {}, originals, "persistent-campaign-interrupted"), /cannot replace/);
    rejectMutation(rebuilt.transcript, originals, transcript => { transcript.snapshot.outcome = { status: "passed", diagnostic: "scheduled-slots-complete" }; });
  }
});

test("exact identity, worker limits and compiled-JavaScript refusal survive schedule reconstruction", () => {
  const generated = originals({ mutations: 0, maxEvaluations: 4 });
  for (const change of [
    (value: any) => { value.identity.node = "v22.23.3"; },
    (value: any) => { value.limits.timeoutMs--; },
    (value: any) => { value.result.observation.compiledJavaScriptSha256 = "b".repeat(64); },
  ]) {
    const artifact = JSON.parse(generated.artifacts[1].toString()); change(artifact);
    const originals = [generated.artifacts[0], jsonBytes(artifact)];
    const rebuilt = foldPersistentSchedule(identity, limits, generated.settings, {}, originals);
    assert.equal(rebuilt.transcript.snapshot.outcome.status, "incomplete");
    assert.ok(["persistent-corpus-identity", "persistent-corpus-compiled-build-drift"].includes(rebuilt.transcript.rows[1].diagnostic!));
    assert.equal(rebuilt.transcript.snapshot.corpus.entries.length, 1);
    assert.deepEqual(auditPersistentSchedule(rebuilt.transcript, originals), rebuilt);
  }
});

test("saved getter, hidden/symbol fields and sparse/decorated arrays are rejected without invocation", () => {
  const { transcript, artifacts } = folded({ mutations: 0, maxEvaluations: 4 });
  let invocations = 0;
  for (const mutate of [
    (value: any) => { Object.defineProperty(value, "options", { enumerable: true, get() { invocations++; return options; } }); },
    (value: any) => { Object.defineProperty(value.decisions[0].random, "before", { enumerable: true, get() { invocations++; return 7; } }); },
    (value: any) => { Object.defineProperty(value.rows[0].artifact, "sha256", { enumerable: true, get() { invocations++; return "a".repeat(64); } }); },
    (value: any) => { Object.defineProperty(value.snapshot.corpus.entries[0], "sequence", { enumerable: true, get() { invocations++; return transcript.decisions[0].sequence; } }); },
    (value: any) => { Object.defineProperty(value.snapshot, "rows", { enumerable: true, get() { invocations++; return []; } }); },
    (value: any) => { Object.defineProperty(value.decisions, 0, { enumerable: true, get() { invocations++; return transcript.decisions[0]; } }); },
    (value: any) => { Object.defineProperty(value.rows[0], "ordinal", { value: 1, enumerable: false }); },
    (value: any) => { value.decisions[0][Symbol("extra")] = true; },
    (value: any) => { value.rows.extra = true; },
    (value: any) => { delete value.decisions[0].random.words[0]; },
    (value: any) => { value.decisions[0].random.before = -0; },
    (value: any) => { value.snapshot.counts.passed = NaN; },
    (value: any) => { Object.setPrototypeOf(value.snapshot.corpus, { inherited: true }); },
  ]) {
    invocations = 0; rejectMutation(transcript, artifacts, mutate);
    assert.equal(invocations, 0, "Untrusted saved getter invoked");
  }
});

test("original evidence array shape is bounded before values are visited", () => {
  let invocations = 0;
  const accessor = [null]; Object.defineProperty(accessor, 0, { enumerable: true, get() { invocations++; return Buffer.from("{}"); } });
  const decorated = [] as unknown[] & { extra?: boolean }; decorated.extra = true;
  for (const inputs of [accessor, Array(1), decorated, Array(69), Object.create([]), null, {}]) {
    invocations = 0;
    assert.throws(() => foldPersistentSchedule(identity, limits, options, {}, inputs), /persistent-schedule-audit-protocol/);
    assert.equal(invocations, 0, "Evidence array getter invoked");
  }
  const byteGetter = Buffer.from("{}"); Object.defineProperty(byteGetter, "extra", { get() { invocations++; return null; } });
  invocations = 0;
  const rejected = foldPersistentSchedule(identity, limits, options, {}, [byteGetter]);
  assert.equal(rejected.transcript.rows[0].status, "incomplete"); assert.equal(invocations, 0);
  assert.deepEqual(auditPersistentSchedule(rejected.transcript, [byteGetter]), rejected); assert.equal(invocations, 0);
});
