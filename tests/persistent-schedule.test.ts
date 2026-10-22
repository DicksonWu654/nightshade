import assert from "node:assert/strict";
import test from "node:test";
import { comparePersistentResults, incompletePersistentResult, makePersistentArtifact, persistentBuildIdentity, PERSISTENT_FILE_BYTES, runPersistentSequenceIsolated, type PersistentIdentity, type PersistentResult } from "./generative/persistent-artifacts.js";
import { extractPersistentFeedback } from "./generative/persistent-feedback.js";
import { checkPersistentObservation, expectedPersistentSequence, persistentDigest, validatePersistentSequence, PERSISTENT_LIMITS, PERSISTENT_LOCK_SHA256, PERSISTENT_SOURCE_SHA256, type PersistentObservation, type PersistentOperation, type PersistentSequence } from "./generative/persistent-model.js";
import { mutatePersistentSequence, PersistentSchedule, PERSISTENT_SCHEDULE_DEFAULTS, PERSISTENT_SCHEDULE_STOP_REASONS, validatePersistentScheduleOptions, type PersistentDecision, type PersistentScheduleOptions } from "./generative/persistent-schedule.js";

const identity: PersistentIdentity = { analyzerSourceSha256: "a".repeat(64), harnessSourceSha256: "b".repeat(64), builtJavaScriptSha256: "c".repeat(64), parserRuntimeSha256: "d".repeat(64), compilerSha256: "e".repeat(64), compilerDistributionSha256: "f".repeat(64), semanticProfile: "compact-0.34.0-zkir2", node: "v24.15.0", platform: "linux", arch: "x64", runtimeLockSha256: PERSISTENT_LOCK_SHA256, runtimeInputsManifestSha256: "1".repeat(64), persistentWorkerSourceSha256: "2".repeat(64), persistentWorkerBuildSha256: "3".repeat(64), persistentFixtureSha256: PERSISTENT_SOURCE_SHA256 };
const limits = { timeoutMs: 1000, heapMiB: 64, maxOutputBytes: 16384 };
const sequence = (operations: PersistentOperation[] = [], seed = 1) => validatePersistentSequence({ schemaVersion: "nightshade-persistent-sequence-1", seed, operations });
const options = (overrides: Partial<PersistentScheduleOptions> = {}) => ({ ...PERSISTENT_SCHEDULE_DEFAULTS, ...overrides });
const create = (settings = options(), budgets = {}) => new PersistentSchedule(identity, limits, settings, budgets);
const lifecycle: PersistentOperation[] = [
  { kind: "restore", slot: 3 }, { kind: "accept" }, { kind: "reject" }, { kind: "accept" },
  { kind: "save", slot: 0 }, { kind: "accept" }, { kind: "save", slot: 1 }, { kind: "restore", slot: 0 },
  { kind: "accept" }, { kind: "restore", slot: 3 }, { kind: "restore", slot: 1 },
  { kind: "restore", slot: 1 }, { kind: "save", slot: 0 }, { kind: "inspect" },
];

/** Schema-only synthetic evidence; the concrete oracle here does not attest execution. */
function synthetic(model: PersistentSequence): PersistentObservation {
  const expected = expectedPersistentSequence(model);
  const view = (state: { count: string; next: string }) => ({ ...state, publicSha256: persistentDigest(`synthetic:${state.count}`) });
  return { schemaVersion: "nightshade-persistent-observation-1", layer: "compiled-evaluation-only", fixture: "owned-persistent-counter-witness", compiler: "0.34.0", language: "0.26.0", runtime: "0.19.0", onchainRuntime: "4.0.0-rc.3", fixedTime: 1700000000, runtimeLockSha256: PERSISTENT_LOCK_SHA256, sourceSha256: PERSISTENT_SOURCE_SHA256, compiledJavaScriptSha256: "a".repeat(64), sequenceSha256: persistentDigest(JSON.stringify(model)), initial: view(expected.initial), rows: expected.rows.map(row => ({ ...row, before: view(row.before), after: view(row.after), slots: row.slots.map(view) })), final: view(expected.final) };
}
const checked = (model: PersistentSequence, wire = synthetic(model)) => checkPersistentObservation(model, wire, PERSISTENT_SOURCE_SHA256);
const bytes = (model: PersistentSequence, result: PersistentResult = checked(model), expectedIdentity = identity, workerLimits = limits) => Buffer.from(JSON.stringify(makePersistentArtifact(model, expectedIdentity, workerLimits, result)));
function transcript(settings = options(), budgets = {}) {
  const schedule = create(settings, budgets), decisions: PersistentDecision[] = [], artifacts: Buffer[] = [];
  for (;;) {
    const decision = schedule.next();
    if (!decision) break;
    decisions.push(decision);
    const artifact = bytes(decision.sequence); artifacts.push(artifact); schedule.record(artifact);
  }
  return { decisions, artifacts, snapshot: schedule.snapshot() };
}

test("persistent bootstraps and two independent literal PRNG blocks define exact proposals", () => {
  const schedule = create(options({ mutations: 0, maxEvaluations: 4 }));
  const blocks = [
    [1015568748, 1586005467, 2165703038, 3027450565, 217083232, 1587069247],
    [3327581586, 2388811721, 70837908, 2745540835, 1075679462, 1814098701],
  ]; // Independently calculated using integer arithmetic modulo 2^32.
  const bootstraps: PersistentOperation[][] = [[], [{ kind: "accept" }, { kind: "inspect" }], [{ kind: "reject" }, { kind: "accept" }], lifecycle];
  let previous = 1;
  for (let index = 0; index < 4; index++) {
    const decision = schedule.next()!;
    const model = sequence(bootstraps[index], index + 1);
    assert.deepEqual(Object.keys(decision), ["schemaVersion", "scheduler", "ordinal", "phase", "bootstrap", "parent", "random", "mutation", "sequence", "sequenceSha256", "operationsSha256"]);
    assert.equal(decision.schemaVersion, "nightshade-persistent-decision-1");
    assert.equal(decision.scheduler, "owned-persistent-snapshot-lcg-1");
    assert.equal(decision.ordinal, index + 1); assert.equal(decision.bootstrap, index + 1);
    assert.equal(decision.phase, "bootstrap"); assert.equal(decision.parent, null); assert.equal(decision.mutation, null);
    assert.deepEqual(decision.sequence, model);
    assert.equal(decision.sequenceSha256, persistentDigest(JSON.stringify(model)));
    assert.equal(decision.operationsSha256, persistentDigest(JSON.stringify(model.operations)));
    assert.equal(decision.random.before, previous); assert.equal(decision.random.words.length, 6);
    assert.equal(decision.random.after, decision.random.words[5]);
    if (index < 2) assert.deepEqual(decision.random.words, blocks[index]);
    previous = decision.random.after;
    const row = schedule.record(bytes(model)); assert.equal(row.status, "passed");
    if (!index) { assert.equal(row.admission?.status, "retained"); assert.equal(schedule.snapshot().corpus.features.length, 1); }
  }
  assert.deepEqual(schedule.snapshot().outcome, { status: "passed", diagnostic: "scheduled-slots-complete" });
  assert.equal(lifecycle.filter(op => op.kind !== "save" && op.kind !== "restore").length, 6);
  assert.equal(lifecycle.filter(op => op.kind === "save" || op.kind === "restore").length, 8);
});

test("bounded persistent edits have literal family/operand results and no retries", () => {
  const parent = sequence([{ kind: "save", slot: 3 }], 99);
  const vectors = [
    { words: [0, 0, 1 << 16, 4 << 16, 2 << 16, 0], mutation: { kind: "insert", index: 1, operation: { kind: "restore", slot: 2 } }, operations: [{ kind: "save", slot: 3 }, { kind: "restore", slot: 2 }] },
    { words: [0, 1 << 16, 0, 0, 0, 0], mutation: { kind: "delete", index: 0 }, operations: [] },
    { words: [0, 2 << 16, 0, 0, 0, 0], mutation: { kind: "replace", index: 0, operation: { kind: "accept" } }, operations: [{ kind: "accept" }] },
    { words: [0, 3 << 16, 0, 0, 0, 0], mutation: { kind: "slot-edit", index: 0, before: 3, after: 0 }, operations: [{ kind: "save", slot: 0 }] },
  ];
  for (const vector of vectors) {
    assert.deepEqual(mutatePersistentSequence(parent, vector.words), { sequence: sequence(vector.operations as PersistentOperation[], 99), mutation: vector.mutation });
  }
  assert.deepEqual(parent, sequence([{ kind: "save", slot: 3 }], 99));
  const same = mutatePersistentSequence(parent, [0, 2 << 16, 0, 3 << 16, 3 << 16, 0]);
  assert.equal(same.mutation.kind, "replace"); assert.deepEqual(same.sequence, parent, "No-op replacements consume their slot");
  for (const base of [sequence(), sequence(Array.from({ length: 32 }, () => ({ kind: "restore", slot: 0 })))]) {
    for (const high of [0, 1, 2, 3, 0xffff]) {
      const result = mutatePersistentSequence(base, Array(6).fill(high * 65536));
      assert.deepEqual(validatePersistentSequence(result.sequence), result.sequence);
      assert.ok(result.sequence.operations.length <= 32);
      assert.equal(result.mutation.kind === "insert", base.operations.length === 0);
      if (result.mutation.kind === "slot-edit") assert.notEqual(result.mutation.before, result.mutation.after);
    }
  }
});

test("full synthetic transcripts reproduce and only retained measured-evidence descendants become parents", () => {
  const settings = options({ mutations: 64, maxEvaluations: 68 });
  const budgets = { maxCases: 128, maxFeatures: 4096, maxConsiderations: 68 };
  const first = transcript(settings, budgets);
  assert.deepEqual(transcript(settings, budgets), first);
  assert.equal(first.snapshot.outcome.status, "passed"); assert.equal(first.snapshot.recorded, 68);
  assert.equal(first.snapshot.proposed, 68); assert.equal(first.snapshot.pending, null);
  const retained: { decision: PersistentDecision; artifact: Buffer }[] = [];
  for (let index = 0; index < first.decisions.length; index++) {
    const decision = first.decisions[index], parent = decision.parent;
    if (parent) {
      const selected = retained[parent.retainedIndex];
      assert.ok(selected); assert.equal(parent.retainedIndex, (decision.random.words[0] >>> 16) % retained.length);
      assert.deepEqual(parent, { retainedIndex: parent.retainedIndex, ordinal: selected.decision.ordinal, artifactSha256: persistentDigest(selected.artifact), sequenceSha256: selected.decision.sequenceSha256, operationsSha256: selected.decision.operationsSha256 });
      assert.equal(decision.sequence.seed, selected.decision.sequence.seed);
    }
    if (first.snapshot.rows[index].admission?.status === "retained") retained.push({ decision, artifact: first.artifacts[index] });
  }
  assert.ok(first.decisions.some(decision => (decision.parent?.ordinal ?? 0) > 4));
  assert.ok(first.snapshot.rows.some(row => row.admission?.status === "redundant"));
  assert.notDeepEqual(transcript({ ...settings, seed: 2 }, budgets).decisions.slice(4), first.decisions.slice(4));
});

test("pending proposals, caller inputs, admitted bytes and snapshots stay detached", () => {
  const suppliedIdentity = structuredClone(identity), suppliedLimits = { ...limits }, suppliedOptions = options();
  const schedule = new PersistentSchedule(suppliedIdentity, suppliedLimits, suppliedOptions);
  suppliedIdentity.node = "v22.0.0"; suppliedLimits.timeoutMs = 1; suppliedOptions.mutations = 0;
  const first = schedule.next()!, pending = schedule.snapshot();
  assert.deepEqual(schedule.next(), first); assert.deepEqual(schedule.snapshot(), pending);
  first.sequence.operations.push({ kind: "reject" }); first.random.words.length = 0;
  pending.pending!.ordinal = 9; pending.options.seed = 2;
  assert.equal(schedule.next()!.ordinal, 1); assert.deepEqual(schedule.next()!.sequence.operations, []);
  const original = bytes(schedule.next()!.sequence), hash = persistentDigest(original);
  const row = schedule.record(original); original.fill(0); row.admission!.admittedFeatureIds.length = 0;
  const accepted = schedule.snapshot(), changed = schedule.snapshot();
  changed.corpus.entries[0].sequence.operations.push({ kind: "accept" }); changed.rows.length = 0;
  assert.deepEqual(schedule.snapshot(), accepted); assert.equal(accepted.corpus.entries[0].artifactSha256, hash);
  assert.deepEqual(accepted.corpus.identity, identity); assert.deepEqual(accepted.corpus.workerLimits, limits);
  assert.throws(() => schedule.record(Buffer.alloc(0)), /pending/); assert.deepEqual(schedule.snapshot(), accepted);
  for (const [maxEvaluations, shadowPlanned] of [[3, 1], [4, 99]]) {
    const fixed = options({ mutations: 0, maxEvaluations }), replaced = create(fixed);
    Object.defineProperty(replaced, "options", { value: options({ seed: 99, mutations: 64, maxEvaluations: 68 }) });
    Object.defineProperty(replaced, "planned", { value: shadowPlanned });
    const decisions: PersistentDecision[] = [];
    for (;;) { const decision = replaced.next(); if (!decision) break; decisions.push(decision); replaced.record(bytes(decision.sequence)); }
    const reference = transcript(fixed);
    assert.deepEqual(decisions, reference.decisions); assert.deepEqual(replaced.snapshot(), reference.snapshot);
    assert.equal(replaced.snapshot().planned, 4); assert.deepEqual(replaced.snapshot().options, fixed);
  }
});

test("strict option, word and artifact boundaries never execute caller accessors", () => {
  assert.deepEqual(validatePersistentScheduleOptions(Object.assign(Object.create(null), options())), options());
  for (const invalid of [{ ...options(), seed: -0 }, { ...options(), seed: 0x100000000 }, { ...options(), mutations: 65 }, { ...options(), maxEvaluations: 0 }, { ...options(), adapter: "saved" }, { ...options(), mutations: NaN }]) assert.throws(() => validatePersistentScheduleOptions(invalid));
  let calls = 0;
  const invalidOptions = options(); Object.defineProperty(invalidOptions, "seed", { enumerable: true, get() { calls++; return 1; } });
  assert.throws(() => validatePersistentScheduleOptions(invalidOptions));
  const invalidWords = [0, 0, 0, 0, 0, 0]; Object.defineProperty(invalidWords, "3", { enumerable: true, get() { calls++; return 0; } });
  assert.throws(() => mutatePersistentSequence(sequence(), invalidWords));
  const invalidSequence = sequence(); Object.defineProperty(invalidSequence, "operations", { enumerable: true, get() { calls++; return []; } });
  assert.throws(() => mutatePersistentSequence(invalidSequence, [0, 0, 0, 0, 0, 0]));
  for (const vector of [Array(6), [0, 0, 0, 0, 0, -0], [0, 0, 0, 0, 0, Infinity], [0, 0, 0, 0, 0, 0x100000000], Object.assign([0, 0, 0, 0, 0, 0], { extra: true })]) assert.throws(() => mutatePersistentSequence(sequence(), vector));
  const schedule = create(), decision = schedule.next()!, decorated = bytes(decision.sequence);
  Object.defineProperty(decorated, "toJSON", { enumerable: true, get() { calls++; return () => ({}); } });
  const row = schedule.record(decorated);
  assert.equal(row.diagnostic, "persistent-schedule-protocol"); assert.equal(row.artifact, null);
  const stopped = schedule.snapshot();
  const hostile = new Proxy({}, { getPrototypeOf() { calls++; return Object.prototype; }, ownKeys() { calls++; return []; } });
  assert.throws(() => schedule.record(hostile), /pending/);
  assert.equal(calls, 0); assert.deepEqual(schedule.snapshot(), stopped); assert.equal(schedule.next(), undefined);
});

test("unassociated, malformed and identity-drifted artifacts stop before becoming parents", () => {
  for (const corrupt of [
    (model: PersistentSequence) => bytes({ ...model, seed: 99 }),
    (_model: PersistentSequence) => Buffer.from("{"),
    (_model: PersistentSequence) => Buffer.from([0xff]),
    (model: PersistentSequence) => { const artifact = JSON.parse(bytes(model).toString()); artifact.result.signature = "forged"; return Buffer.from(JSON.stringify(artifact)); },
  ]) {
    const schedule = create(), model = schedule.next()!.sequence, original = corrupt(model);
    const row = schedule.record(original);
    assert.equal(row.status, "incomplete"); assert.equal(row.diagnostic, "persistent-schedule-protocol");
    assert.equal(row.admission, null); assert.equal(row.caseStatus, null); assert.equal(row.signature, null);
    assert.deepEqual(row.artifact, { sha256: persistentDigest(original), bytes: original.length });
    assert.equal(schedule.snapshot().corpus.considered, 0); assert.equal(schedule.snapshot().corpus.entries.length, 0);
  }
  for (const change of ["identity", "limits", "compiled"] as const) {
    const schedule = create(); schedule.record(bytes(schedule.next()!.sequence));
    const model = schedule.next()!.sequence, before = schedule.snapshot().corpus;
    const wire = synthetic(model); if (change === "compiled") wire.compiledJavaScriptSha256 = "b".repeat(64);
    const row = schedule.record(bytes(model, checked(model, wire), change === "identity" ? { ...identity, node: "v22.23.3" } : identity, change === "limits" ? { ...limits, timeoutMs: 999 } : limits));
    assert.equal(row.status, "incomplete"); assert.equal(row.caseStatus, "passed");
    assert.equal(row.diagnostic, change === "compiled" ? "persistent-corpus-compiled-build-drift" : "persistent-corpus-identity");
    assert.deepEqual(schedule.snapshot().corpus.entries, before.entries); assert.deepEqual(schedule.snapshot().corpus.features, before.features);
  }
  const oversized = create(); oversized.next();
  const refusal = oversized.record(new Uint8Array(PERSISTENT_FILE_BYTES + 1));
  assert.equal(refusal.diagnostic, "persistent-schedule-input-budget"); assert.equal(refusal.artifact, null);
  assert.equal(oversized.snapshot().corpus.considered, 0);
});

test("first property failure and incomplete evidence beat final-slot completion and evaluation budgets", () => {
  for (const last of [1, 4]) {
    for (const kind of ["failed", "worker-timeout", "worker-output-budget"] as const) {
      const schedule = create(options({ mutations: 0, maxEvaluations: last }));
      for (let ordinal = 1; ordinal < last; ordinal++) schedule.record(bytes(schedule.next()!.sequence));
      const decision = schedule.next()!, before = schedule.snapshot().corpus;
      let result: PersistentResult;
      if (kind === "failed") { const wire = synthetic(decision.sequence); wire.initial.next = "99"; result = checked(decision.sequence, wire); assert.equal(result.status, "failed"); }
      else result = incompletePersistentResult(kind, "Synthetic nonexecution for terminal scheduling tests");
      const row = schedule.record(bytes(decision.sequence, result));
      assert.equal(row.status, kind === "failed" ? "failed" : "incomplete");
      assert.equal(row.signature, result.signature); assert.equal(row.diagnostic, kind === "failed" ? "persistent-model-disagreement" : kind);
      const final = schedule.snapshot(); assert.equal(final.recorded, last); assert.equal(final.pending, null);
      assert.equal(final.outcome.status, row.status); assert.deepEqual(final.corpus.entries, before.entries);
      assert.deepEqual(final.corpus.features, before.features); assert.equal(schedule.next(), undefined);
      schedule.stop("persistent-campaign-interrupted"); assert.deepEqual(schedule.snapshot(), final);
      assert.throws(() => schedule.record(bytes(decision.sequence, result)), /pending/); assert.deepEqual(schedule.snapshot(), final);
    }
  }
  const complete = transcript(options({ mutations: 0, maxEvaluations: 4 })); assert.equal(complete.snapshot.outcome.status, "passed");
  const capped = transcript(options({ mutations: 0, maxEvaluations: 3 }));
  assert.deepEqual(capped.snapshot.outcome, { status: "incomplete", diagnostic: "persistent-evaluation-budget" });
  assert.equal(capped.snapshot.proposed, 3); assert.equal(capped.snapshot.recorded, 3);
});

test("capacity refuses novel admission atomically and distinguishes captured evidence from corpus refusal", () => {
  for (const budgets of [{ maxCases: 1 }, { maxFeatures: 1 }, { maxConsiderations: 1 }]) {
    const schedule = create(options(), budgets); schedule.record(bytes(schedule.next()!.sequence));
    const before = schedule.snapshot().corpus, original = bytes(schedule.next()!.sequence), row = schedule.record(original);
    assert.equal(row.status, "incomplete"); assert.equal(row.diagnostic, "maxConsiderations" in budgets ? "persistent-corpus-consideration-budget" : "persistent-corpus-budget");
    assert.deepEqual(row.artifact, { sha256: persistentDigest(original), bytes: original.length });
    assert.deepEqual(schedule.snapshot().corpus.entries, before.entries); assert.deepEqual(schedule.snapshot().corpus.features, before.features);
    if ("maxConsiderations" in budgets) { assert.equal(row.admission!.ordinal, null); assert.equal(row.admission!.artifact, null); assert.equal(row.caseStatus, null); }
    else { assert.equal(row.admission!.ordinal, 2); assert.equal(row.caseStatus, "passed"); }
  }
  const first = bytes(sequence());
  const budgeted = create(options(), { maxEvidenceBytes: first.length });
  const initial = budgeted.next()!; assert.deepEqual(initial.sequence, sequence()); budgeted.record(first);
  const refusedBytes = bytes(budgeted.next()!.sequence), row = budgeted.record(refusedBytes);
  assert.equal(row.diagnostic, "persistent-corpus-evidence-budget"); assert.equal(row.admission!.artifact, null);
  assert.deepEqual(row.artifact, { sha256: persistentDigest(refusedBytes), bytes: refusedBytes.length });
  assert.equal(budgeted.snapshot().corpus.considered, 1); assert.equal(budgeted.snapshot().corpus.evidenceBytes, first.length);
});

test("redundant mutations remain allowed at exact parent capacity and external stops are closed and sticky", () => {
  const settings = options({ mutations: 64, maxEvaluations: 68 }), budgets = { maxCases: 128, maxFeatures: 4096, maxConsiderations: 68 };
  const complete = transcript(settings, budgets);
  const index = complete.snapshot.rows.findIndex(row => row.admission?.status === "redundant"); assert.ok(index >= 4);
  const retainedCount = complete.snapshot.rows.slice(0, index).filter(row => row.admission?.status === "retained").length;
  const schedule = create(settings, { ...budgets, maxCases: retainedCount });
  for (let ordinal = 0; ordinal <= index; ordinal++) { assert.deepEqual(schedule.next(), complete.decisions[ordinal]); schedule.record(complete.artifacts[ordinal]); }
  assert.equal(schedule.snapshot().rows[index].admission?.status, "redundant"); assert.equal(schedule.snapshot().corpus.entries.length, retainedCount);
  assert.equal(schedule.snapshot().outcome.status, "running");
  assert.throws(() => (PERSISTENT_SCHEDULE_STOP_REASONS as unknown as string[]).push("invented-stop"), TypeError);
  const beforeRefusal = schedule.snapshot();
  assert.throws(() => schedule.stop("invented-stop" as never), /invalid external stop/);
  assert.deepEqual(schedule.snapshot(), beforeRefusal);
  for (const reason of PERSISTENT_SCHEDULE_STOP_REASONS) {
    const stopped = create(); stopped.stop(reason); const final = stopped.snapshot();
    assert.deepEqual(final.outcome, { status: "incomplete", diagnostic: reason }); assert.equal(final.proposed, 0); assert.equal(final.recorded, 0);
    stopped.stop("persistent-campaign-interrupted"); assert.deepEqual(stopped.snapshot(), final); assert.equal(stopped.next(), undefined);
    assert.throws(() => stopped.stop("passed" as never)); assert.deepEqual(stopped.snapshot(), final);
  }
  const pending = create(); pending.next(); const state = pending.snapshot();
  assert.throws(() => pending.stop("persistent-campaign-interrupted"), /Pending/);
  let conversions = 0;
  assert.throws(() => pending.stop({ toString() { conversions++; return "persistent-campaign-interrupted"; } } as never));
  assert.equal(conversions, 0);
  assert.deepEqual(pending.snapshot(), state);
});

const qualified = { skip: !process.env.COMPACT_RUNTIME_TEST ? "Requires pinned COMPACT_RUNTIME_TEST" : false };
function inputs() { assert.ok(process.env.COMPACT_RUNTIME_TEST); assert.ok(process.env.COMPACTC_TEST, "COMPACT_RUNTIME_TEST requires pinned COMPACTC_TEST"); return { compiler: process.env.COMPACTC_TEST, runtime: process.env.COMPACT_RUNTIME_TEST }; }

test("actual fixed-fixture schedule repeats full observations, decisions and measured admissions", qualified, async () => {
  const { compiler, runtime } = inputs(), measuredIdentity = persistentBuildIdentity(compiler, runtime);
  async function run() {
    const schedule = new PersistentSchedule(measuredIdentity, PERSISTENT_LIMITS, options({ mutations: 2, maxEvaluations: 6 }));
    const decisions: PersistentDecision[] = [], artifacts: Buffer[] = [], results: PersistentResult[] = [];
    for (;;) {
      const decision = schedule.next(); if (!decision) break;
      decisions.push(decision);
      const result = await runPersistentSequenceIsolated(decision.sequence, compiler, runtime); results.push(result);
      assert.equal(result.status, "passed", JSON.stringify(result));
      const original = bytes(decision.sequence, result, measuredIdentity, PERSISTENT_LIMITS); artifacts.push(original);
      assert.equal(schedule.record(original).status, "passed");
    }
    return { decisions, artifacts, results, snapshot: schedule.snapshot() };
  }
  const first = await run(), second = await run();
  assert.equal(first.snapshot.outcome.status, "passed"); assert.equal(first.snapshot.recorded, 6);
  assert.deepEqual(second, first);
  for (let index = 0; index < first.results.length; index++) {
    const compared = comparePersistentResults(first.results[index], second.results[index]);
    assert.equal(compared.sameObservation, true); assert.equal(compared.sameCompiledJavaScript, true);
  }
  const lifecycleResult = first.results[3]; assert.equal(lifecycleResult.status, "passed");
  if (lifecycleResult.status === "passed") assert.deepEqual(lifecycleResult.observation.rows.flatMap(row => row.witnesses), ["7", "8", "8", "9", "9"]);
  const feedback = extractPersistentFeedback(first.decisions[3].sequence, lifecycleResult); assert.equal(feedback.status, "complete");
  if (feedback.status === "complete") {
    assert.equal(feedback.feedback.counts.circuitEvaluations, 6); assert.equal(feedback.feedback.counts.adapterOperations, 8);
    assert.ok(feedback.feedback.rows[8].featureIds.includes(persistentDigest(JSON.stringify(["witness-history", "accept", "evaluation-success", "accept", "evaluation-success", "equal", true, false]))));
  }
  assert.deepEqual(persistentBuildIdentity(compiler, runtime), measuredIdentity);
});

test("[timing] actual supervised timeout at a pending proposal stops without feedback or a parent", qualified, async () => {
  const { compiler, runtime } = inputs(), measuredIdentity = persistentBuildIdentity(compiler, runtime), tiny = { ...PERSISTENT_LIMITS, timeoutMs: 1 };
  const schedule = new PersistentSchedule(measuredIdentity, tiny), decision = schedule.next()!;
  const result = await runPersistentSequenceIsolated(decision.sequence, compiler, runtime, tiny);
  assert.equal(result.status, "incomplete"); assert.equal(result.diagnostic, "worker-timeout");
  const row = schedule.record(bytes(decision.sequence, result, measuredIdentity, tiny));
  assert.equal(row.diagnostic, "worker-timeout"); assert.equal(row.status, "incomplete");
  assert.equal(row.admission!.feedbackSha256, null); assert.equal(schedule.snapshot().corpus.entries.length, 0);
  assert.equal(schedule.snapshot().corpus.features.length, 0); assert.equal(schedule.next(), undefined);
});
